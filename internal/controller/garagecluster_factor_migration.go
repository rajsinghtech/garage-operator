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
	"fmt"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Factor-migration phases.
const (
	fmPhaseValidating       = "Validating"
	fmPhaseScalingDown      = "ScalingDown"
	fmPhasePurging          = "Purging"
	fmPhaseVerifying        = "Verifying"
	fmPhaseRebuildingLayout = "RebuildingLayout"
	fmPhaseConverging       = "Converging"
	fmPhaseCompleted        = "Completed"
	fmPhaseFailed           = "Failed"
)

// fmPurgeInitContainerName is the name of the busybox init container that deletes
// the on-disk cluster_layout exactly once per migration (guarded by a marker file).
const fmPurgeInitContainerName = "purge-cluster-layout"

// fmStuckTimeout bounds each individual wait phase (ScalingDown, Purging,
// Verifying, RebuildingLayout) so a single stuck step can't hang the migration
// forever — past this the migration fails and tears the tier back down. The
// clock is per-phase (status.factorMigration.phaseStartedAt), not the overall
// migration duration, so an early phase consuming time doesn't shorten the
// budget of a later one.
const fmStuckTimeout = 15 * time.Minute

// fmValidateGrace is how long Validating tolerates an annotation factor that
// doesn't yet match spec.replication.factor (propagation race) before failing.
const fmValidateGrace = 2 * time.Minute

// factorMigrationActive reports whether a coordinated factor migration is in
// flight or has been requested via the purge-cluster-layout annotation.
func factorMigrationActive(cluster *garagev1beta2.GarageCluster) bool {
	if cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] != "" {
		return true
	}
	fm := cluster.Status.FactorMigration
	return fm != nil && fm.Phase != "" && fm.Phase != fmPhaseCompleted && fm.Phase != fmPhaseFailed
}

// reconcileFactorMigration drives the coordinated replication-factor migration
// state machine. It is invoked from Reconcile (after the ConfigMap is refreshed
// with the new factor, before the tier workloads) whenever a migration is active,
// and returns early so the normal per-tier reconciliation does not race the purge.
func (r *GarageClusterReconciler) reconcileFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Abort: clear suspension + status, remove annotations. Does NOT roll back a
	// purge that already deleted cluster_layout.
	if cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayoutAbort] == annotationTrue {
		log.Info("Factor migration: abort requested")
		// Full teardown (strip purge init container, scale STSes back to 1, clear
		// suspension) rather than only clearing suspension — don't rely solely on
		// the per-node controllers' hash-diff self-heal to undo the scale-down and
		// remove the init container. A purge already applied to disk cannot be
		// rolled back, but the workloads are restored.
		if err := r.teardownFactorMigration(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		r.setFactorMigration(ctx, cluster, func(fm *garagev1beta2.FactorMigrationStatus) {
			fm.Phase = fmPhaseFailed
			fm.Message = "aborted by operator"
			now := metav1.Now()
			fm.CompletedAt = &now
		})
		return ctrl.Result{}, r.removeAnnotations(ctx, cluster,
			garagev1beta1.AnnotationPurgeClusterLayout, garagev1beta1.AnnotationPurgeClusterLayoutAbort)
	}

	fm := cluster.Status.FactorMigration
	ann := cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayout]

	// A terminal migration (Completed/Failed) must NEVER restart from a lingering
	// trigger annotation. This is the regression guard for the destructive
	// re-trigger loop: if the annotation removal at start/finish ever loses a
	// race, just clear the annotation and stay terminal. Re-running a migration
	// requires clearing status.factorMigration first.
	if fm != nil && (fm.Phase == fmPhaseCompleted || fm.Phase == fmPhaseFailed) {
		if ann != "" {
			return ctrl.Result{}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
		}
		return ctrl.Result{}, nil
	}

	inFlight := fm != nil && fm.Phase != ""

	// Fresh start: a present annotation is a new request. Capture its intent into
	// status and CONSUME (remove) the annotation immediately so it can't re-trigger.
	if !inFlight {
		if ann == "" {
			return ctrl.Result{}, nil
		}
		toFactor, force, perr := parsePurgeAnnotation(ann)
		now := metav1.Now()
		if perr != nil {
			r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
				*m = garagev1beta2.FactorMigrationStatus{Phase: fmPhaseFailed, Message: perr.Error(), StartedAt: &now, CompletedAt: &now}
			})
			return ctrl.Result{}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
		}
		r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
			*m = garagev1beta2.FactorMigrationStatus{Phase: fmPhaseValidating, ToFactor: toFactor, Force: force, StartedAt: &now}
		})
		return ctrl.Result{Requeue: true}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
	}

	// In-flight: the annotation should already be consumed; remove it defensively
	// if a crash left it behind (idempotent).
	if ann != "" {
		if err := r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout); err != nil {
			return ctrl.Result{}, err
		}
	}

	switch fm.Phase {
	case fmPhaseValidating:
		return r.fmValidate(ctx, cluster)
	case fmPhaseScalingDown:
		return r.fmScaleDown(ctx, cluster)
	case fmPhasePurging:
		return r.fmPurge(ctx, cluster)
	case fmPhaseVerifying:
		return r.fmVerify(ctx, cluster)
	case fmPhaseRebuildingLayout:
		return r.fmRebuildLayout(ctx, cluster)
	case fmPhaseConverging:
		return r.fmConverge(ctx, cluster)
	}
	return ctrl.Result{}, nil
}

// fmValidate runs all hard safety guards before any destructive action. The
// target factor + force flag were captured into status when the annotation was
// consumed, so it reads them from status rather than the (now-removed) annotation.
func (r *GarageClusterReconciler) fmValidate(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	fm := cluster.Status.FactorMigration
	toFactor := fm.ToFactor
	force := fm.Force

	if cluster.Spec.Replication == nil || cluster.Spec.Replication.Factor != toFactor {
		// The annotation and the spec.replication.factor edit are usually two
		// separate API operations; the operator may briefly observe the request
		// before the factor change propagates. Tolerate that race by requeueing
		// within a short grace window before failing.
		if fm != nil && fm.StartedAt != nil && time.Since(fm.StartedAt.Time) < fmValidateGrace {
			r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
				m.Message = fmt.Sprintf("waiting for spec.replication.factor to match annotation factor=%d (currently %d)",
					toFactor, replicationFactorOf(cluster))
			})
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return r.failFactorMigration(ctx, cluster,
			fmt.Sprintf("annotation factor=%d must match spec.replication.factor (%d)", toFactor, replicationFactorOf(cluster)))
	}
	if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		return r.failFactorMigration(ctx, cluster, "factor migration is only supported in Auto layout mode")
	}
	if len(cluster.Spec.RemoteClusters) > 0 {
		return r.failFactorMigration(ctx, cluster,
			"factor migration is refused while spec.remoteClusters is set (federated factor change requires a separate coordinated rollout)")
	}
	if !cluster.HasStorageTier() {
		return r.failFactorMigration(ctx, cluster, "factor migration requires a storage tier")
	}
	if !force && cluster.Spec.Replication.ConsistencyMode == "dangerous" {
		return r.failFactorMigration(ctx, cluster, "consistencyMode 'dangerous' requires ,force on the purge annotation")
	}
	if !force && len(cluster.Status.PendingGatewayTombstones) > 0 {
		return r.failFactorMigration(ctx, cluster,
			"pending gateway tombstones exist; clean them up (autoApply) or add ,force to the annotation")
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	// nongateway_nodes() >= factor is enforced by Garage at apply time; reject an
	// unappliable reduction up front (validated: src/rpc/layout/version.rs:328).
	if len(nodes) < toFactor {
		return r.failFactorMigration(ctx, cluster,
			fmt.Sprintf("%d storage nodes < requested factor %d — layout would be unappliable", len(nodes), toFactor))
	}
	// A node with per-node config overrides consumes its own <node>-config
	// ConfigMap, which ONLY the per-node controller rewrites — and the migration
	// suspends that controller before purging. The migration cannot refresh the
	// new replication_factor into those ConfigMaps, so the purged pod would boot
	// at the OLD factor and wedge the cluster in a mixed-factor state (a
	// lower-factor node std::process::exit(1)s, or the layout is discarded —
	// src/rpc/system.rs, src/rpc/layout/manager.rs). Refuse rather than corrupt.
	for name, n := range nodes {
		if nodeHasConfigOverrides(n) {
			return r.failFactorMigration(ctx, cluster, fmt.Sprintf(
				"storage node %q has per-node config overrides (e.g. multi-HDD dataPaths, fsync, network, publicEndpoint, or logging); "+
					"coordinated factor migration cannot refresh the new factor into per-node ConfigMaps yet — "+
					"remove the overrides or migrate the factor manually", name))
		}
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseScalingDown
		m.PurgeID = purgeIDFromStart(m)
		m.Message = fmt.Sprintf("validated; reducing/setting replication factor to %d across %d storage nodes", toFactor, len(nodes))
	})
	return ctrl.Result{Requeue: true}, nil
}

// fmScaleDown suspends the per-node controllers and scales every storage
// StatefulSet to 0, confirming zero old-factor pods remain before proceeding.
// This is the simultaneous-restart guarantee: a surviving higher-factor pod would
// std::process::exit(1) any new lower-factor pod (validated: src/rpc/system.rs).
func (r *GarageClusterReconciler) fmScaleDown(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	fm := cluster.Status.FactorMigration

	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for name, n := range nodes {
		// Suspend the per-node controller so it won't fight our STS edits.
		if n.Annotations[garagev1beta1.AnnotationOperatorSuspended] != fm.PurgeID {
			if n.Annotations == nil {
				n.Annotations = map[string]string{}
			}
			n.Annotations[garagev1beta1.AnnotationOperatorSuspended] = fm.PurgeID
			if err := r.Update(ctx, n); err != nil {
				return ctrl.Result{}, fmt.Errorf("suspending GarageNode %s: %w", name, err)
			}
		}
		if err := r.scaleStorageSTS(ctx, cluster, name, 0); err != nil {
			return ctrl.Result{}, err
		}
	}

	remaining, err := r.countStoragePods(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if remaining > 0 {
		log.Info("Factor migration: waiting for all storage pods to terminate", "remaining", remaining)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhasePurging
		m.Message = "all storage pods terminated; deleting on-disk cluster_layout"
	})
	return ctrl.Result{Requeue: true}, nil
}

// fmPurge patches each storage StatefulSet with the marker-guarded busybox init
// container that deletes cluster_layout, then scales it back to 1. The new pod
// boots with the new factor (from the refreshed ConfigMap) and an empty layout.
func (r *GarageClusterReconciler) fmPurge(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}
	fm := cluster.Status.FactorMigration
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for name := range nodes {
		if err := r.patchSTSPurgeInitContainer(ctx, cluster, name, fm.PurgeID, true); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.scaleStorageSTS(ctx, cluster, name, 1); err != nil {
			return ctrl.Result{}, err
		}
	}
	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseVerifying
		m.Message = "storage pods restarting with purged layout at the new factor"
	})
	return ctrl.Result{Requeue: true}, nil
}

// fmVerify waits for every storage pod to become Ready at the new factor. A pod
// that crash-loops (factor/layout mismatch) never becomes Ready, so all-Ready is
// a sufficient proxy for "booted cleanly at the new factor".
func (r *GarageClusterReconciler) fmVerify(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	ready, err := r.countReadyStoragePods(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ready < len(nodes) {
		log.Info("Factor migration: waiting for storage pods to become Ready", "ready", ready, "want", len(nodes))
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseRebuildingLayout
		m.Message = "all storage pods Ready; rebuilding the layout from scratch"
	})
	return ctrl.Result{Requeue: true}, nil
}

// fmRebuildLayout re-stages EVERY node role (purging cluster_layout wiped them
// all) and applies once, then strips the purge init containers. Node identity
// survives (the metadata PVC's node_key was untouched), so status.nodeId is still
// valid.
func (r *GarageClusterReconciler) fmRebuildLayout(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Bound this phase: every path below requeues (admin not up, node identity
	// not yet observed, staging/apply failure). Without a per-phase guard a node
	// whose status.nodeId never repopulates after the purge restart would loop
	// here forever with the tier still suspended.
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	gc, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil //nolint:nilerr // admin not up yet; retry
	}

	changes, err := r.buildRebuildRoleChanges(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(changes) == 0 {
		// Node IDs not yet discoverable (pods still settling); retry.
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if err := gc.UpdateClusterLayout(ctx, changes); err != nil {
		log.V(1).Info("Factor migration: staging rebuilt roles failed, will retry", "error", err)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil //nolint:nilerr
	}
	if err := gc.ApplyStagedLayoutChanges(ctx); err != nil {
		log.V(1).Info("Factor migration: applying rebuilt layout failed, will retry", "error", err)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil //nolint:nilerr
	}

	// Strip the purge init containers so future restarts are clean (the marker
	// file also guards against re-deletion).
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for name := range nodes {
		if err := r.patchSTSPurgeInitContainer(ctx, cluster, name, "", false); err != nil {
			return ctrl.Result{}, err
		}
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseConverging
		m.Message = fmt.Sprintf("layout rebuilt at factor %d with %d storage roles", m.ToFactor, len(changes))
	})
	return ctrl.Result{Requeue: true}, nil
}

// fmConverge resumes the per-node controllers and finalizes. A Tables repair is
// triggered best-effort to cover the metadata-lag caveat after a layout rebuild.
func (r *GarageClusterReconciler) fmConverge(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if err := r.clearStorageSuspension(ctx, cluster); err != nil {
		return ctrl.Result{}, err
	}

	if gc, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain); err == nil {
		if err := gc.LaunchRepair(ctx, "*", garagev1beta1.RepairTypeTables); err != nil {
			log.V(1).Info("Factor migration: best-effort Tables repair failed", "error", err)
		}
	}

	now := metav1.Now()
	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseCompleted
		m.CompletedAt = &now
		m.Message = fmt.Sprintf("replication factor migrated to %d; full re-replication proceeds in the background", m.ToFactor)
	})
	log.Info("Factor migration completed", "factor", cluster.Status.FactorMigration.ToFactor)
	// The trigger annotation was consumed at start, so there's nothing to remove
	// here — the terminal Completed phase prevents any re-trigger.
	return ctrl.Result{}, nil
}

// --- helpers ---------------------------------------------------------------

// parsePurgeAnnotation parses "factor=N" or "factor=N,force".
func parsePurgeAnnotation(val string) (factor int, force bool, err error) {
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "force":
			force = true
		case strings.HasPrefix(part, "factor="):
			f, perr := strconv.Atoi(strings.TrimPrefix(part, "factor="))
			if perr != nil || f < 1 {
				return 0, false, fmt.Errorf("invalid purge annotation %q: factor must be a positive integer", val)
			}
			factor = f
		default:
			return 0, false, fmt.Errorf("invalid purge annotation %q (expected \"factor=N[,force]\")", val)
		}
	}
	if factor == 0 {
		return 0, false, fmt.Errorf("invalid purge annotation %q: missing factor=N", val)
	}
	return factor, force, nil
}

func replicationFactorOf(cluster *garagev1beta2.GarageCluster) int {
	if cluster.Spec.Replication != nil {
		return cluster.Spec.Replication.Factor
	}
	return 0
}

func purgeIDFromStart(fm *garagev1beta2.FactorMigrationStatus) string {
	if fm != nil && fm.StartedAt != nil {
		return fmt.Sprintf("p%d", fm.StartedAt.Unix())
	}
	return "p0"
}

// fmCheckStuck transitions to Failed if the CURRENT phase has been running
// longer than fmStuckTimeout. The deadline is measured from phaseStartedAt
// (reset on every transition by setFactorMigration); it falls back to startedAt
// for a migration that began before phaseStartedAt was tracked.
func (r *GarageClusterReconciler) fmCheckStuck(ctx context.Context, cluster *garagev1beta2.GarageCluster) (bool, ctrl.Result, error) {
	fm := cluster.Status.FactorMigration
	if fm == nil {
		return false, ctrl.Result{}, nil
	}
	since := fm.PhaseStartedAt
	if since == nil {
		since = fm.StartedAt
	}
	if since == nil || time.Since(since.Time) <= fmStuckTimeout {
		return false, ctrl.Result{}, nil
	}
	res, err := r.failFactorMigration(ctx, cluster,
		fmt.Sprintf("phase %q exceeded %s; aborting — inspect pods then re-trigger or set the abort annotation", fm.Phase, fmStuckTimeout))
	return true, res, err
}

// buildRebuildRoleChanges produces the full set of role assignments to rebuild
// the wiped layout: every storage node's capacity role plus every gateway node's
// capacity=nil role.
func (r *GarageClusterReconciler) buildRebuildRoleChanges(ctx context.Context, cluster *garagev1beta2.GarageCluster) ([]garage.NodeRoleChange, error) {
	var changes []garage.NodeRoleChange

	storage, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return nil, err
	}
	capacity := r.calculateNodeCapacity(cluster)
	reserve := 0
	if cluster.HasStorageTier() {
		reserve = cluster.Spec.Storage.CapacityReservePercent
	}
	effective := calculateEffectiveCapacity(capacity, reserve)
	for _, n := range storage {
		if n.Status.NodeID == "" {
			return nil, nil // identity not yet observed; caller retries
		}
		zone := n.Spec.Zone
		tags := n.Spec.Tags
		if tags == nil {
			tags = []string{}
		}
		changes = append(changes, garage.NodeRoleChange{ID: n.Status.NodeID, Zone: zone, Capacity: ptr.To(effective), Tags: tags})
	}

	gateway, err := r.listAutoModeGatewayNodes(ctx, cluster)
	if err != nil {
		return nil, err
	}
	for _, n := range gateway {
		if n.Status.NodeID == "" {
			continue // gateway identity may lag; tombstone cleanup re-adds it later
		}
		tags := n.Spec.Tags
		if tags == nil {
			tags = []string{}
		}
		changes = append(changes, garage.NodeRoleChange{ID: n.Status.NodeID, Zone: n.Spec.Zone, Capacity: nil, Tags: tags})
	}
	return changes, nil
}

// scaleStorageSTS sets the replica count on a per-node storage StatefulSet.
func (r *GarageClusterReconciler) scaleStorageSTS(ctx context.Context, cluster *garagev1beta2.GarageCluster, name string, replicas int32) error {
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if sts.Spec.Replicas != nil && *sts.Spec.Replicas == replicas {
		return nil
	}
	sts.Spec.Replicas = ptr.To(replicas)
	return r.Update(ctx, sts)
}

// patchSTSPurgeInitContainer adds (add=true) or removes (add=false) the
// marker-guarded busybox init container that deletes cluster_layout. The marker
// (/data/metadata/.purged-<purgeID>) ensures the delete happens exactly once even
// across extra restarts.
func (r *GarageClusterReconciler) patchSTSPurgeInitContainer(ctx context.Context, cluster *garagev1beta2.GarageCluster, name, purgeID string, add bool) error {
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Drop any existing purge init container first (idempotent).
	hadPurge := false
	filtered := sts.Spec.Template.Spec.InitContainers[:0]
	for _, c := range sts.Spec.Template.Spec.InitContainers {
		if c.Name == fmPurgeInitContainerName {
			hadPurge = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !add {
		// Removal is a no-op when no purge container is present — avoids a
		// spurious StatefulSet rollout when teardown runs on an untouched tier.
		if !hadPurge {
			return nil
		}
		sts.Spec.Template.Spec.InitContainers = filtered
		return r.Update(ctx, sts)
	}

	sts.Spec.Template.Spec.InitContainers = filtered
	marker := fmt.Sprintf("%s/.purged-%s", metadataPath, purgeID)
	// set -e so a failed rm (e.g. EACCES) surfaces as a non-zero init exit
	// instead of being masked — the pod then visibly stalls in Init with the
	// error rather than the migration silently never purging.
	script := fmt.Sprintf("set -e\nif [ ! -f %q ]; then\n  rm -f %s/cluster_layout\n  touch %q\nfi", marker, metadataPath, marker)
	init := corev1.Container{
		Name:    fmPurgeInitContainerName,
		Image:   "busybox:1.37",
		Command: []string{"/bin/sh", "-c", script},
		VolumeMounts: []corev1.VolumeMount{
			{Name: metadataVolName, MountPath: metadataPath},
		},
		SecurityContext: purgeInitSecurityContext(sts),
	}
	sts.Spec.Template.Spec.InitContainers = append([]corev1.Container{init}, sts.Spec.Template.Spec.InitContainers...)
	return r.Update(ctx, sts)
}

// purgeInitSecurityContext builds the SecurityContext for the purge init
// container. cluster_layout on the metadata volume is owned by whatever user
// the Garage container runs as — root by default, since the official image is
// FROM scratch with no USER. Hardcoding RunAsUser=1000/RunAsNonRoot would make
// `rm` fail with EACCES on a root-owned file and stall the pod in Init, so the
// init container must run as the same user as the storage pod (its effective
// RunAsUser, or the image default = root when unset).
func purgeInitSecurityContext(sts *appsv1.StatefulSet) *corev1.SecurityContext {
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if uid := purgeInitRunAsUser(sts); uid != nil {
		sc.RunAsUser = uid
		sc.RunAsNonRoot = ptr.To(*uid != 0)
	}
	return sc
}

// purgeInitRunAsUser returns the UID the storage pod runs as: the pod-level
// RunAsUser if set, else the first container's RunAsUser, else nil (image
// default — root for the FROM-scratch Garage image).
func purgeInitRunAsUser(sts *appsv1.StatefulSet) *int64 {
	ps := sts.Spec.Template.Spec
	if ps.SecurityContext != nil && ps.SecurityContext.RunAsUser != nil {
		return ps.SecurityContext.RunAsUser
	}
	for i := range ps.Containers {
		if c := ps.Containers[i].SecurityContext; c != nil && c.RunAsUser != nil {
			return c.RunAsUser
		}
	}
	return nil
}

// countStoragePods / countReadyStoragePods count pods of the cluster's storage tier.
func (r *GarageClusterReconciler) countStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) (int, error) {
	pods, err := r.listStoragePods(ctx, cluster)
	if err != nil {
		return 0, err
	}
	return len(pods), nil
}

func (r *GarageClusterReconciler) countReadyStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) (int, error) {
	pods, err := r.listStoragePods(ctx, cluster)
	if err != nil {
		return 0, err
	}
	ready := 0
	for i := range pods {
		for _, c := range pods[i].Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready++
			}
		}
	}
	return ready, nil
}

func (r *GarageClusterReconciler) listStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) ([]corev1.Pod, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// teardownFactorMigration reverses every destructive mutation a migration may
// have applied so the storage tier recovers without manual intervention: it
// strips the purge init container, scales each storage StatefulSet back to 1,
// and clears the per-node suspension so the GarageNode controllers resume. It
// is idempotent and safe to call from any phase (including before scale-down,
// where it is a no-op). Used by both the abort path and the failure path — a
// failed destructive migration must never leave the tier suspended and scaled
// to zero with no way back.
func (r *GarageClusterReconciler) teardownFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name := range nodes {
		if err := r.patchSTSPurgeInitContainer(ctx, cluster, name, "", false); err != nil {
			return err
		}
		if err := r.scaleStorageSTS(ctx, cluster, name, 1); err != nil {
			return err
		}
	}
	return r.clearStorageSuspension(ctx, cluster)
}

// clearStorageSuspension removes the operator-suspended annotation from every
// operator-owned storage GarageNode so the per-node controllers resume.
func (r *GarageClusterReconciler) clearStorageSuspension(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range nodes {
		if _, ok := n.Annotations[garagev1beta1.AnnotationOperatorSuspended]; !ok {
			continue
		}
		delete(n.Annotations, garagev1beta1.AnnotationOperatorSuspended)
		if err := r.Update(ctx, n); err != nil {
			return fmt.Errorf("resuming GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// setFactorMigration mutates status.factorMigration and persists it with retry.
// It auto-stamps PhaseStartedAt whenever the mutation advances Phase, so every
// transition site gets a per-phase deadline clock for free (and can't forget to
// reset it). The stamping is computed against the phase observed at entry, so it
// stays correct across UpdateStatusWithRetry's conflict re-fetch + re-apply.
func (r *GarageClusterReconciler) setFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, mutate func(*garagev1beta2.FactorMigrationStatus)) {
	log := logf.FromContext(ctx)
	apply := func() {
		if cluster.Status.FactorMigration == nil {
			cluster.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{}
		}
		fm := cluster.Status.FactorMigration
		prevPhase := fm.Phase
		mutate(fm)
		if fm.Phase != prevPhase {
			now := metav1.Now()
			fm.PhaseStartedAt = &now
		}
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		log.Error(err, "Failed to update factorMigration status")
	}
}

// failFactorMigration records a terminal Failed phase. The trigger annotation
// was consumed when the migration started, so the terminal phase alone prevents
// any re-trigger — re-running requires the user to re-apply the annotation.
func (r *GarageClusterReconciler) failFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, message string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Factor migration failed", "message", message)
	// Reverse any destructive mutations so the storage tier self-heals rather
	// than being stranded suspended-and-scaled-to-zero. Only commit the terminal
	// Failed phase once teardown succeeds; if it errors (transient API failure),
	// requeue so it retries — the phase stays non-terminal and the migration path
	// keeps driving recovery.
	if err := r.teardownFactorMigration(ctx, cluster); err != nil {
		log.Error(err, "Factor migration: teardown after failure incomplete, will retry")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil //nolint:nilerr // retry teardown, don't wedge
	}
	now := metav1.Now()
	r.setFactorMigration(ctx, cluster, func(fm *garagev1beta2.FactorMigrationStatus) {
		fm.Phase = fmPhaseFailed
		fm.Message = message
		fm.CompletedAt = &now
	})
	return ctrl.Result{}, nil
}

// removeAnnotations deletes the given annotations from the cluster with conflict retry.
func (r *GarageClusterReconciler) removeAnnotations(ctx context.Context, cluster *garagev1beta2.GarageCluster, keys ...string) error {
	changed := false
	for _, k := range keys {
		if _, ok := cluster.Annotations[k]; ok {
			delete(cluster.Annotations, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.Update(ctx, cluster)
}
