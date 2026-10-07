/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Designating one layout-writer site in a federation (#442).
//
// A GarageCluster with layoutManagement.siteRole: Follower never stages,
// applies, reverts, or removes Garage layout roles. Enforcement is layered:
//
//  1. The garage.Client refuses all six layout-writing methods when the context
//     carries the marker installed by withLayoutSiteGuard (the backstop).
//  2. Explicit pre-checks at the call sites that would otherwise produce noisy
//     errors or half-finished state report AwaitingLayoutWriter and skip cleanly.
//  3. layout_site_role_inventory_test.go fails when a new call to any of the six
//     methods appears outside its allow-list.

const (
	eventReasonLayoutWriteBlocked   = "LayoutWriteBlocked"
	eventReasonLayoutChangesDropped = "LayoutChangesDropped"
	layoutMetricsNamespace          = "garage_operator"
	layoutMetricsSubsystem          = "layout"
)

var (
	layoutWriteBlockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: layoutMetricsNamespace,
			Subsystem: layoutMetricsSubsystem,
			Name:      "write_blocked_total",
			Help:      "Layout-writing Garage Admin API calls refused because the site's layoutManagement.siteRole is Follower.",
		},
		[]string{"cluster", "operation"},
	)
	layoutSiteRoleGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: layoutMetricsNamespace,
			Subsystem: layoutMetricsSubsystem,
			Name:      "site_role",
			Help:      "1 for the layout role (Writer or Follower) this GarageCluster site currently enforces; 0 for the other.",
		},
		[]string{"cluster", "role"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(layoutWriteBlockedTotal, layoutSiteRoleGauge)
}

// layoutSiteLabel is the metrics/log identity of a site.
func layoutSiteLabel(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Namespace + "/" + cluster.Name
}

// layoutWritesBlocked reports whether ctx forbids Garage layout writes.
func layoutWritesBlocked(ctx context.Context) bool {
	return garage.LayoutWritesDisabled(ctx)
}

// withLayoutSiteGuard returns ctx carrying the follower marker when cluster, or
// the canonical layout owner it resolves to through connectTo.clusterRef
// chains, is a layout Follower. Otherwise ctx is returned unchanged.
//
// A resolution error is deliberately not fatal here: every layout write also
// needs a Garage client resolved through the same chain, so a chain that cannot
// be resolved cannot write either, and the reconcile reports that error itself.
func withLayoutSiteGuard(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
) context.Context {
	if cluster == nil {
		return ctx
	}
	var owner *garagev1beta2.GarageCluster
	if !cluster.IsLayoutFollower() && reader != nil && cluster.Spec.ConnectTo != nil {
		if resolved, err := resolveGarageLayoutOwnerForCleanup(ctx, reader, cluster); err == nil {
			owner = resolved
		}
	}
	return withLayoutSiteGuardForOwner(ctx, cluster, owner)
}

// withLayoutSiteGuardForOwner is withLayoutSiteGuard for callers that already
// resolved the canonical layout owner (nil means cluster owns its own layout).
func withLayoutSiteGuardForOwner(
	ctx context.Context,
	cluster, owner *garagev1beta2.GarageCluster,
) context.Context {
	if cluster == nil {
		return ctx
	}
	site := cluster
	reason := "layoutManagement.siteRole is Follower"
	if !cluster.IsLayoutFollower() && owner != nil && owner.IsLayoutFollower() {
		site = owner
		reason = fmt.Sprintf("layout owner %s/%s has layoutManagement.siteRole Follower", owner.Namespace, owner.Name)
	}
	if !site.IsLayoutFollower() {
		return ctx
	}
	label := layoutSiteLabel(site)
	return garage.WithLayoutWritesDisabled(ctx, garage.LayoutWriteGuard{
		Cluster: label,
		Reason:  reason,
		OnBlocked: func(operation string) {
			layoutWriteBlockedTotal.WithLabelValues(label, operation).Inc()
		},
	})
}

// awaitingLayoutWriterError is the pending state of work only the Writer site
// may do. It matches garage.ErrLayoutWritesDisabled and errLayoutMutationPending
// under errors.Is, so existing pending branches requeue it instead of failing
// the resource, and a finalizer is never released on it.
type awaitingLayoutWriterError struct {
	reason string
	detail string
}

func (e *awaitingLayoutWriterError) Error() string {
	return fmt.Sprintf("awaiting the layout writer site (%s): %s", e.reason, e.detail)
}

func (e *awaitingLayoutWriterError) Is(target error) bool {
	return target == garage.ErrLayoutWritesDisabled || target == errLayoutMutationPending
}

func newAwaitingLayoutWriterError(reason, format string, args ...any) error {
	return &awaitingLayoutWriterError{reason: reason, detail: fmt.Sprintf(format, args...)}
}

// layoutWriterAwaitReason extracts the AwaitingLayoutWriter reason from err, or
// "" when err is not an awaiting-writer error.
func layoutWriterAwaitReason(err error) string {
	var awaiting *awaitingLayoutWriterError
	if stderrors.As(err, &awaiting) {
		return awaiting.reason
	}
	return ""
}

// layoutWriterRoleLabel is the role name used in status and metrics.
func layoutWriterRoleLabel(cluster *garagev1beta2.GarageCluster) garagev1beta2.LayoutSiteRole {
	return cluster.EffectiveLayoutSiteRole()
}

// emitLayoutEvent records a Kubernetes Event when a recorder is configured.
func emitLayoutEvent(recorder record.EventRecorder, object runtime.Object, eventType, reason, format string, args ...any) {
	if recorder == nil || object == nil {
		return
	}
	recorder.Eventf(object, eventType, reason, format, args...)
}

// layoutWriterAwaiting is the summary of work a Follower is waiting for the
// Writer to do.
type layoutWriterAwaiting struct {
	reasons  []string
	messages map[string]string
}

func (a *layoutWriterAwaiting) add(reason, message string) {
	if a.messages == nil {
		a.messages = map[string]string{}
	}
	if _, exists := a.messages[reason]; !exists {
		a.reasons = append(a.reasons, reason)
	}
	a.messages[reason] = message
}

// primary returns the reason reported on the condition. Removing a role is the
// most consequential wait, so it wins; the message lists every reason.
func (a *layoutWriterAwaiting) primary() string {
	order := []string{
		garagev1beta1.ReasonPendingRoleRemoval,
		garagev1beta1.ReasonNodesWithoutRole,
		garagev1beta1.ReasonPendingTombstones,
		garagev1beta1.ReasonReplicationChange,
	}
	for _, reason := range order {
		if _, ok := a.messages[reason]; ok {
			return reason
		}
	}
	return ""
}

func (a *layoutWriterAwaiting) message() string {
	parts := make([]string, 0, len(a.reasons))
	for _, reason := range []string{
		garagev1beta1.ReasonPendingRoleRemoval,
		garagev1beta1.ReasonNodesWithoutRole,
		garagev1beta1.ReasonPendingTombstones,
		garagev1beta1.ReasonReplicationChange,
	} {
		if message, ok := a.messages[reason]; ok {
			parts = append(parts, message)
		}
	}
	return strings.Join(parts, "; ")
}

// computeLayoutWriterAwaiting derives what a Follower is waiting for from
// observed state only; it performs no Garage call. liveParameters may be nil
// when the layout could not be read.
func computeLayoutWriterAwaiting(
	cluster *garagev1beta2.GarageCluster,
	nodes []garagev1beta1.GarageNode,
	liveParameters *garage.LayoutParameters,
	liveParametersKnown bool,
) layoutWriterAwaiting {
	var awaiting layoutWriterAwaiting
	var withoutRole, leaving []string
	for i := range nodes {
		node := &nodes[i]
		if node.Spec.ClusterRef.Name != cluster.Name {
			continue
		}
		if !node.DeletionTimestamp.IsZero() {
			if node.Status.InLayout || node.Status.Phase == PhaseDeleting {
				leaving = append(leaving, node.Name)
			}
			continue
		}
		// A node that has not discovered its identity yet is still starting; only
		// a node with a Garage identity and no role is waiting for the writer.
		if canonicalGarageNodeID(node.Status.NodeID) != "" && !node.Status.InLayout {
			withoutRole = append(withoutRole, node.Name)
		}
	}
	sort.Strings(leaving)
	sort.Strings(withoutRole)
	if len(leaving) > 0 {
		awaiting.add(garagev1beta1.ReasonPendingRoleRemoval, fmt.Sprintf(
			"%d node(s) are leaving (%s) but only the layout writer site may remove their roles",
			len(leaving), strings.Join(leaving, ", ")))
	}
	if len(withoutRole) > 0 {
		awaiting.add(garagev1beta1.ReasonNodesWithoutRole, fmt.Sprintf(
			"%d node(s) hold no layout role (%s); declare them as external GarageNodes on the layout writer site",
			len(withoutRole), strings.Join(withoutRole, ", ")))
	}
	if n := len(cluster.Status.PendingGatewayTombstones); n > 0 {
		awaiting.add(garagev1beta1.ReasonPendingTombstones, fmt.Sprintf(
			"%d stale gateway layout entr(ies) await removal by the layout writer site", n))
	}
	if liveParametersKnown && zoneRedundancyDiffers(buildZoneRedundancy(cluster.Spec.Replication), liveParameters) {
		awaiting.add(garagev1beta1.ReasonReplicationChange,
			"spec.replication zone redundancy differs from the shared layout parameters; change it on the layout writer site")
	}
	return awaiting
}

// zoneRedundancyDiffers reports whether a non-nil desired zone redundancy
// differs from the live layout parameters. An unset desired value never differs:
// the site then expresses no opinion.
func zoneRedundancyDiffers(desired *garage.ZoneRedundancy, live *garage.LayoutParameters) bool {
	if desired == nil {
		return false
	}
	if live == nil || live.ZoneRedundancy == nil {
		return true
	}
	current := live.ZoneRedundancy
	if desired.Maximum != current.Maximum {
		return true
	}
	if (desired.AtLeast == nil) != (current.AtLeast == nil) {
		return true
	}
	return desired.AtLeast != nil && *desired.AtLeast != *current.AtLeast
}

// layoutSiteRoleInUse reports whether layoutManagement.siteRole is set. Status
// and conditions are only written for such clusters, and cleared otherwise, so
// existing objects stay byte-identical until the field is used.
func layoutSiteRoleInUse(cluster *garagev1beta2.GarageCluster) bool {
	return cluster.Spec.LayoutManagement != nil && cluster.Spec.LayoutManagement.SiteRole != ""
}

// applyLayoutWriterRole records status.layoutWriter, the LayoutWriter condition
// and the site-role gauge. It is a pure function of the spec, so every status
// write path may call it.
func applyLayoutWriterRole(cluster *garagev1beta2.GarageCluster) {
	if !layoutSiteRoleInUse(cluster) {
		cluster.Status.LayoutWriter = nil
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionLayoutWriter)
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter)
		return
	}
	role := layoutWriterRoleLabel(cluster)
	cluster.Status.LayoutWriter = &garagev1beta2.LayoutWriterStatus{Role: role}
	label := layoutSiteLabel(cluster)
	for _, candidate := range []garagev1beta2.LayoutSiteRole{
		garagev1beta2.LayoutSiteRoleWriter, garagev1beta2.LayoutSiteRoleFollower,
	} {
		value := 0.0
		if candidate == role {
			value = 1
		}
		layoutSiteRoleGauge.WithLabelValues(label, string(candidate)).Set(value)
	}
	if role == garagev1beta2.LayoutSiteRoleWriter {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionLayoutWriter,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonWriterSite,
			Message:            "this site is the layout writer: it may stage, apply, revert and remove Garage layout roles",
			ObservedGeneration: cluster.Generation,
		})
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter)
		return
	}
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionLayoutWriter,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonFollowerSite,
		Message:            "this site is a layout follower: it performs no Garage layout writes; roles are assigned and removed by the layout writer site",
		ObservedGeneration: cluster.Generation,
	})
}

// applyAwaitingLayoutWriter records the AwaitingLayoutWriter condition of a
// Follower from the computed awaiting summary and reports the previous and new
// primary reason ("" when nothing is awaited) so the caller can emit an Event on
// change. It never touches Ready: a follower's pods and connectivity are
// healthy while it awaits the writer.
func applyAwaitingLayoutWriter(
	cluster *garagev1beta2.GarageCluster,
	awaiting layoutWriterAwaiting,
) (previous, current string) {
	if !layoutSiteRoleInUse(cluster) || !cluster.IsLayoutFollower() {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter)
		return "", ""
	}
	if existing := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter); existing != nil &&
		existing.Status == metav1.ConditionTrue {
		previous = existing.Reason
	}
	current = awaiting.primary()
	if current == "" {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionAwaitingLayoutWriter,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonNothingPending,
			Message:            "no work is waiting for the layout writer site",
			ObservedGeneration: cluster.Generation,
		})
		return previous, ""
	}
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionAwaitingLayoutWriter,
		Status:             metav1.ConditionTrue,
		Reason:             current,
		Message:            awaiting.message(),
		ObservedGeneration: cluster.Generation,
	})
	return previous, current
}

// layoutAdministrationAnnotations are the one-shot annotations that request a
// Garage layout write. A Follower refuses them.
var layoutAdministrationAnnotations = []struct {
	operation string
	key       string
	// companions are removed together with key.
	companions []string
}{
	{"RevertLayout", garagev1beta1.AnnotationRevertLayout, nil},
	{"SkipDeadNodes", garagev1beta1.AnnotationSkipDeadNodes, []string{garagev1beta1.AnnotationAllowMissingData}},
	{"PurgeClusterLayout", garagev1beta1.AnnotationPurgeClusterLayout, nil},
}

// blockLayoutAnnotationsOnFollower consumes revert-layout, skip-dead-nodes and
// purge-cluster-layout requests on a layout Follower. Each is reported through a
// LayoutWriteBlocked Warning event and status.lastOperation, then removed:
// leaving it in place would silently execute against the shared layout if this
// site were later promoted. It reports whether any annotation was consumed.
func (r *GarageClusterReconciler) blockLayoutAnnotationsOnFollower(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	var blocked []string
	for _, entry := range layoutAdministrationAnnotations {
		if _, requested := cluster.Annotations[entry.key]; requested {
			blocked = append(blocked, entry.operation)
		}
	}
	if len(blocked) == 0 {
		return false, nil
	}
	message := fmt.Sprintf(
		"layoutManagement.siteRole is Follower: %s is not allowed on this site because a Follower performs no Garage layout writes; run it on the layout writer site, or promote this site first",
		strings.Join(blocked, ", "))
	now := metav1.Now()
	apply := func() {
		cluster.Status.LastOperation = &garagev1beta2.LastOperationStatus{
			Type:        strings.Join(blocked, ","),
			TriggeredAt: &now,
			Succeeded:   false,
			Error:       message,
		}
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		return false, fmt.Errorf("recording blocked layout administration request: %w", err)
	}
	emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeWarning, eventReasonLayoutWriteBlocked, "%s", message)
	for _, operation := range blocked {
		layoutWriteBlockedTotal.WithLabelValues(layoutSiteLabel(cluster), "annotation:"+operation).Inc()
	}
	for _, entry := range layoutAdministrationAnnotations {
		delete(cluster.Annotations, entry.key)
		for _, companion := range entry.companions {
			delete(cluster.Annotations, companion)
		}
	}
	if err := r.Update(ctx, cluster); err != nil {
		return false, fmt.Errorf("removing blocked layout administration annotations: %w", err)
	}
	return true, nil
}
