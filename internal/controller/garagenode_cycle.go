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
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// cycleSiblingSuffix is appended to a GarageNode name to derive its cycle
// sibling's name. The sibling is a transient replacement that takes over the
// original's layout slot; once the swap completes the original is deleted and
// the sibling lives on under this name (it is NOT renamed back — renaming a
// GarageNode would churn its StatefulSet identity and PVCs).
const cycleSiblingSuffix = "-cycle"

// promotedCycleDescendantNames returns every completed-cycle descendant of one
// canonical Auto ordinal (for example, -cycle and -cycle-cycle), plus the sole
// non-deleting descendant that currently occupies the ordinal. More than one
// live descendant is ambiguous and must fail closed: choosing one would let the
// parent silently create or retire a durable Garage identity.
func promotedCycleDescendantNames(
	existing map[string]*garagev1beta1.GarageNode,
	canonicalName string,
) ([]string, *garagev1beta1.GarageNode, error) {
	var (
		names  []string
		active []*garagev1beta1.GarageNode
	)
	for name, node := range existing {
		if name == canonicalName || node == nil || isCycleSibling(node) {
			continue
		}
		slot := node.Labels[labelAutoNodeSlot]
		legacyNameMatch := slot == "" && cycleCanonicalAncestorName(name) == canonicalName
		if slot != canonicalName && !legacyNameMatch {
			continue
		}
		names = append(names, name)
		if node.DeletionTimestamp.IsZero() {
			active = append(active, node)
		}
	}
	sort.Strings(names)
	sort.Slice(active, func(i, j int) bool { return active[i].Name < active[j].Name })
	if len(active) > 1 {
		activeNames := make([]string, 0, len(active))
		for _, node := range active {
			activeNames = append(activeNames, node.Name)
		}
		return names, nil, fmt.Errorf(
			"canonical GarageNode %s has ambiguous promoted cycle descendants: %s",
			canonicalName, strings.Join(activeNames, ", "),
		)
	}
	if len(active) == 1 {
		return names, active[0], nil
	}
	return names, nil, nil
}

// resolveAutoModeCycleSlot returns the durable object currently satisfying a
// canonical Auto ordinal. A deleting canonical is a historical ancestor and a
// live promoted descendant is the current identity. Two simultaneously live
// objects fail closed. Callers may then compare the returned object against the
// canonical desired profile without renaming or recreating its durable state.
func resolveAutoModeCycleSlot(
	existing map[string]*garagev1beta1.GarageNode,
	canonicalName string,
) ([]string, *garagev1beta1.GarageNode, error) {
	descendantNames, promoted, err := promotedCycleDescendantNames(existing, canonicalName)
	if err != nil {
		return descendantNames, nil, err
	}
	canonical, found := existing[canonicalName]
	if promoted != nil {
		if found && canonical != nil && canonical.DeletionTimestamp.IsZero() {
			return descendantNames, nil, fmt.Errorf(
				"canonical GarageNode %s and promoted cycle descendant %s are both live",
				canonicalName, promoted.Name,
			)
		}
		return descendantNames, promoted, nil
	}
	if found {
		return descendantNames, canonical, nil
	}
	return descendantNames, nil, nil
}

// cycleCanonicalAncestorName strips one or more exact -cycle suffixes. Auto
// ordinal names end in a decimal index, so the suffix cannot be part of a
// canonical generated name. An empty return means name is not a descendant.
func cycleCanonicalAncestorName(name string) string {
	ancestor := name
	count := 0
	for strings.HasSuffix(ancestor, cycleSiblingSuffix) {
		ancestor = strings.TrimSuffix(ancestor, cycleSiblingSuffix)
		count++
	}
	if count == 0 || ancestor == "" {
		return ""
	}
	return ancestor
}

func cycleSuffixDepth(name string) int {
	depth := 0
	for strings.HasSuffix(name, cycleSiblingSuffix) {
		name = strings.TrimSuffix(name, cycleSiblingSuffix)
		depth++
	}
	return depth
}

// hasExactGarageClusterControllerReference proves the complete controller
// identity, not only the UID comparison performed by metav1.IsControlledBy.
// Cycle promotion and legacy adoption are persistent-identity transitions, so
// a stale/wrong-name or wrong-API owner reference must fail closed even if a
// malformed object happens to reuse the expected UID.
func hasExactGarageClusterControllerReference(object metav1.Object, cluster *garagev1beta2.GarageCluster) bool {
	if object == nil || cluster == nil || object.GetNamespace() != cluster.Namespace {
		return false
	}
	owner := metav1.GetControllerOf(object)
	return owner != nil &&
		owner.APIVersion == garagev1beta2.GroupVersion.String() &&
		owner.Kind == kindGarageCluster &&
		owner.Name == cluster.Name &&
		owner.UID == cluster.UID
}

// ensureAutoModeCycleOwnership migrates the one released promoted-cycle shape
// that predates labelAutoNodeSlot and direct GarageCluster ownership. It adopts
// only an exact depth-one legacy name with controller-written identity/layout
// status. Every other matching managed label without the exact parent UID fails
// closed instead of being selected or deleted as a durable member.
func (r *GarageClusterReconciler) ensureAutoModeCycleOwnership(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	existing map[string]*garagev1beta1.GarageNode,
	tier string,
) (bool, error) {
	names := make([]string, 0, len(existing))
	for name := range existing {
		names = append(names, name)
	}
	sort.Strings(names)
	var adoptionCandidates []*garagev1beta1.GarageNode
	// Validate the complete managed-label set before mutating anything. In
	// particular, never adopt a legacy promoted object and only then discover
	// that its canonical slot was already occupied by another live identity.
	for _, name := range names {
		node := existing[name]
		if hasExactGarageClusterControllerReference(node, cluster) {
			continue
		}
		if owner := metav1.GetControllerOf(node); owner != nil {
			return false, fmt.Errorf(
				"GarageNode %s carries Auto-managed labels but is controlled by %s %s instead of GarageCluster %s/%s",
				node.Name, owner.Kind, owner.Name, cluster.Namespace, cluster.Name,
			)
		}
		if !legacyPromotedCycleNodeCanBeAdopted(node, cluster, tier) {
			return false, fmt.Errorf(
				"GarageNode %s carries Auto-managed %s labels without the exact GarageCluster controller UID; refusing to trust or retire a possibly forged durable identity",
				node.Name, tier,
			)
		}
		adoptionCandidates = append(adoptionCandidates, node)
	}
	for _, candidate := range adoptionCandidates {
		slot := autoNodeSlotForCycle(candidate)
		for _, otherName := range names {
			other := existing[otherName]
			if other == nil || other.Name == candidate.Name || !other.DeletionTimestamp.IsZero() {
				continue
			}
			if other.Name == slot || autoNodeSlotForCycle(other) == slot {
				return false, fmt.Errorf(
					"legacy promoted GarageNode %s cannot be adopted because Auto slot %s is also occupied by live GarageNode %s",
					candidate.Name, slot, other.Name,
				)
			}
		}
	}
	if len(adoptionCandidates) == 0 {
		return false, nil
	}
	node := adoptionCandidates[0]
	if err := controllerutil.SetControllerReference(cluster, node, r.Scheme); err != nil {
		return false, fmt.Errorf("adopting legacy promoted cycle GarageNode %s: %w", node.Name, err)
	}
	if node.Labels == nil {
		node.Labels = make(map[string]string)
	}
	node.Labels[labelAutoNodeSlot] = autoNodeSlotForCycle(node)
	if err := r.Update(ctx, node); err != nil {
		return false, fmt.Errorf("persisting legacy promoted cycle GarageNode adoption %s: %w", node.Name, err)
	}
	return true, nil
}

func legacyPromotedCycleNodeCanBeAdopted(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	tier string,
) bool {
	if node == nil || cluster == nil || node.Labels[labelAutoNodeSlot] != "" ||
		cycleSuffixDepth(node.Name) != 1 || node.Spec.External != nil ||
		isNodeLocalPoolBacked(node) || node.Status.NodeID == "" ||
		(!node.Status.InLayout && node.DeletionTimestamp.IsZero()) ||
		node.Labels[labelCluster] != cluster.Name || node.Labels[labelTier] != tier ||
		node.Labels[labelAppManagedBy] != managedByOperatorValue ||
		node.Spec.ClusterRef.Name != cluster.Name {
		return false
	}
	refNamespace := node.Spec.ClusterRef.Namespace
	if refNamespace == "" {
		refNamespace = node.Namespace
	}
	if refNamespace != cluster.Namespace || node.Namespace != cluster.Namespace {
		return false
	}
	slot := autoNodeSlotForCycle(node)
	if tier == tierGateway {
		_, valid := parseAutoModeGatewayOrdinal(slot, cluster.Name)
		return node.Spec.Gateway && valid
	}
	_, valid := parseAutoModeOrdinal(slot, cluster.Name)
	return !node.Spec.Gateway && valid
}

// isCycleRequested reports whether the garage.rajsingh.info/cycle annotation is
// set to "true" on this node.
func isCycleRequested(node *garagev1beta1.GarageNode) bool {
	return node.Annotations[garagev1beta1.AnnotationCycle] == annotationTrue
}

// isCycleSibling reports whether this GarageNode is itself a cycle sibling
// (provisioned by reconcileCycle for another node). Sibling nodes must never
// start their own cycle, and the cluster's Auto-mode loop must not manage them
// as ordinals — both are enforced by the dedicated name suffix + the absence of
// the operator managed-by/tier labels carried by Auto-owned ordinals.
func isCycleSibling(node *garagev1beta1.GarageNode) bool {
	return node.Labels[labelCycleSibling] == annotationTrue
}

// reconcileCycle drives the add-before-remove node replacement state machine for
// a GarageNode carrying the garage.rajsingh.info/cycle annotation. It is
// resumable and idempotent: progress lives on status.cyclePhase + the existence
// of the sibling GarageNode, so a requeue mid-cycle continues from where it left
// off rather than re-provisioning.
//
// Phases:
//
//	(start) -> Provisioning : create the sibling GarageNode (fresh node ID and
//	                          fresh same-template storage). Wait for its exact
//	                          owned Pod and Garage identity.
//	Provisioning -> Syncing : require the sibling Ready, connected, in-layout,
//	                          and a settled Garage layout. No per-node tracker is
//	                          treated as a replication proof.
//	Syncing -> Draining     : request the ordinary reversible positive-capacity
//	                          drain. Promote/delete only after its exact durable
//	                          source/destination block proof is terminal.
//
// A cycle sibling never cycles itself (guarded by the caller resolving the
// annotation only on non-sibling nodes plus the isCycleSibling check here).
func (r *GarageNodeReconciler) reconcileCycle(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster, layoutOwner *garagev1beta2.GarageCluster,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// A sibling node must never run a cycle of its own — that would recurse
	// endlessly. Clear any stray annotation and fall back to normal reconcile.
	if isCycleSibling(node) {
		if isCycleRequested(node) {
			delete(node.Annotations, garagev1beta1.AnnotationCycle)
			if err := r.Update(ctx, node); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
	}

	siblingName := boundedGarageNodeName(node.Name + cycleSiblingSuffix)
	if node.Status.CycleSiblingName != "" {
		siblingName = node.Status.CycleSiblingName
	}
	if !isCycleRequested(node) && node.Status.CyclePhase != "" &&
		node.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue {
		return r.reconcileCycleCancellation(ctx, node, cluster, siblingName)
	}

	// Storage profile eligibility is rechecked even for a persisted phase. This
	// is the controller-bypass boundary for legacy requests that silently stripped
	// existingClaim or attempted a gateway cycle. Preserve both identities and
	// publish a specific blocked condition; never infer replacement storage.
	if err := node.ValidateCycleStorageProfile(); err != nil {
		return r.cycleSetBlocked(ctx, node, err)
	}
	if err := node.ValidateCycleParentNetworkProfile(cluster); err != nil {
		return r.cycleSetBlocked(ctx, node, err)
	}

	// Once Draining is durable, the ordinary drain state machine is the sole
	// replication proof. Rechecking source/sibling readiness or ephemeral layout
	// trackers here would deadlock restart recovery after the source role is
	// intentionally absent. Before Draining, revalidate every start prerequisite
	// immediately before provisioning or advancing.
	if node.Status.CyclePhase != garagev1beta1.CyclePhaseDraining {
		if err := node.ValidateCycleSourceReadiness(); err != nil {
			return r.cycleSetBlocked(ctx, node, err)
		}
		if err := requireConsistentStorageDrain(layoutOwner); err != nil {
			return r.cycleSetBlocked(ctx, node, err)
		}
		if _, err := requireStorageDrainStartReady(layoutOwner); err != nil {
			return r.cycleSetBlocked(ctx, node, err)
		}
		sourcePod, err := r.statefulSetPodForNode(ctx, node)
		if err != nil {
			return r.cycleSetBlocked(ctx, node, fmt.Errorf("proving established source StatefulSet Pod: %w", err))
		}
		if !garageNodeLayoutReadyForPod(node, sourcePod) {
			return r.cycleSetBlocked(ctx, node, fmt.Errorf(
				"source StatefulSet Pod %s/%s UID %s is not the exact Ready Pod bound to status.observedPodUid %q and current Garage layout evidence",
				sourcePod.Namespace, sourcePod.Name, sourcePod.UID, node.Status.ObservedPodUID,
			))
		}
	}

	// Look up the sibling; absent means we are at the start of the cycle (or a
	// first provision attempt has not occurred. A persisted phase with no sibling
	// is ambiguous: the deleted object may already have introduced a Garage role,
	// so it must never be silently replaced by a third identity.
	sibling := &garagev1beta1.GarageNode{}
	err := r.Get(ctx, types.NamespacedName{Name: siblingName, Namespace: node.Namespace}, sibling)
	switch {
	case errors.IsNotFound(err):
		if node.Status.CyclePhase != "" {
			return r.cycleSetBlocked(ctx, node, fmt.Errorf(
				"persisted cycle phase %s references missing sibling %s; refusing to provision another identity until the prior role is explicitly accounted for",
				node.Status.CyclePhase, siblingName,
			))
		}
		return r.cycleProvisionSibling(ctx, node, cluster, siblingName)
	case err != nil:
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("getting cycle sibling %s: %w", siblingName, err))
	}
	if err := validateCycleSiblingActor(node, sibling, cluster); err != nil {
		return r.cycleSetBlocked(ctx, node, err)
	}
	if err := sibling.ValidateCycleStorageProfile(); err != nil {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("cycle sibling %s has an ineligible storage profile: %w", siblingName, err))
	}

	if node.Status.CyclePhase == garagev1beta1.CyclePhaseDraining {
		// Draining status and the ordinary drain annotation use separate API
		// writes. A manager can stop after the status update but before the
		// annotation update succeeds, so make the persisted phase an idempotent
		// instruction to reassert that side effect before consulting any terminal
		// proof. Without this boundary a status-only restart can wait forever for a
		// drain that was never requested.
		updated, err := r.ensureCycleDrainRequested(ctx, node)
		if err != nil {
			return ctrl.Result{}, err
		}
		if updated {
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		return r.completeCycleAfterDrainProof(ctx, node, sibling, cluster, layoutOwner)
	}

	// Sibling exists. Require its exact owned Pod incarnation and current status,
	// not a stale NodeID copied from a prior Pod.
	siblingPod, err := r.statefulSetPodForNode(ctx, sibling)
	if err != nil || !garageNodeLayoutReadyForPod(sibling, siblingPod) {
		message := fmt.Sprintf("sibling %s provisioning; waiting for its exact Ready StatefulSet Pod and current Garage layout evidence", siblingName)
		if err != nil {
			message = fmt.Sprintf("sibling %s provisioning: %v", siblingName, err)
		}
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseProvisioning, siblingName, "",
			garagev1beta1.ReasonCycleProvisioning,
			message)
	}
	siblingNodeID := garagev1beta1.CanonicalGarageNodeID(sibling.Status.NodeID)
	if len(siblingNodeID) != 64 {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("sibling %s reported an invalid Garage node ID", siblingName))
	}
	if persisted := garagev1beta1.CanonicalGarageNodeID(node.Status.CycleSiblingNodeID); persisted != "" && persisted != siblingNodeID {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf(
			"cycle sibling %s changed Garage identity from %s to %s; refusing to advance an ambiguous replacement",
			siblingName, persisted, siblingNodeID,
		))
	}

	// A settled history is a conservative join boundary. It is not the data-loss
	// proof: the subsequent ordinary drain launches exact repair workers and
	// covers every current destination, including this sibling.
	history, err := r.getCycleLayoutHistory(ctx, cluster)
	if err != nil {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("cycle: failed to get layout history: %w", err))
	}
	if err := requireCycleSettledLayoutHistory(history); err != nil {
		log.V(1).Info("Cycle sibling is waiting for a settled Garage layout",
			"node", node.Name, "sibling", siblingName, "siblingNodeID", siblingNodeID,
			"error", err)
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseSyncing, siblingName, siblingNodeID,
			garagev1beta1.ReasonCycleSyncing,
			fmt.Sprintf("sibling %s is Ready and in layout; waiting for a settled Garage layout: %v", siblingName, err))
	}

	log.Info("Cycle sibling is Ready in a settled layout; requesting durable source drain",
		"node", node.Name, "sibling", siblingName, "siblingNodeID", siblingNodeID)

	if _, err := r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseDraining, siblingName, siblingNodeID,
		garagev1beta1.ReasonCycleDraining,
		fmt.Sprintf("sibling %s is Ready in settled layout version %d; proving the ordinary source drain", siblingName, history.CurrentVersion)); err != nil {
		return ctrl.Result{}, err
	}
	if _, err := r.ensureCycleDrainRequested(ctx, node); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

// ensureCycleDrainRequested bridges the durable CyclePhaseDraining status to
// the ordinary drain state machine. It is deliberately safe to call after every
// restart: completion is never evaluated until the source object itself carries
// the exact reversible drain request.
func (r *GarageNodeReconciler) ensureCycleDrainRequested(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
) (bool, error) {
	if node.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue {
		return false, nil
	}
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
	if err := r.Update(ctx, node); err != nil {
		return false, fmt.Errorf("cycle: requesting reversible drain preparation: %w", err)
	}
	return true, nil
}

func (r *GarageNodeReconciler) completeCycleAfterDrainProof(
	ctx context.Context,
	node, sibling *garagev1beta1.GarageNode,
	cluster, layoutOwner *garagev1beta2.GarageCluster,
) (ctrl.Result, error) {
	siblingNodeID := garagev1beta1.CanonicalGarageNodeID(sibling.Status.NodeID)
	persistedNodeID := garagev1beta1.CanonicalGarageNodeID(node.Status.CycleSiblingNodeID)
	if siblingNodeID == "" || persistedNodeID == "" || siblingNodeID != persistedNodeID {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf(
			"draining cycle is not bound to one exact sibling identity: status=%q live=%q",
			persistedNodeID, siblingNodeID,
		))
	}
	authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, layoutOwner)
	if err != nil {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("validating terminal source drain proof: %w", err))
	}
	if !authorized {
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseDraining, sibling.Name, siblingNodeID,
			garagev1beta1.ReasonCycleDraining,
			fmt.Sprintf("waiting for the exact durable source drain and block-resync proof before promoting sibling %s", sibling.Name))
	}
	proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain)
	if proof == nil || !containsCanonicalGarageNodeID(proof.VerificationNodeIDs, siblingNodeID) {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf(
			"terminal source drain proof does not include exact sibling destination %s",
			siblingNodeID,
		))
	}
	// The terminal proof is bound to the sibling Garage identity, but the
	// identity-bearing process can still restart between proof completion and
	// promotion. Re-read the current StatefulSet and Pod from the API server and
	// require status to bind that exact Ready Pod UID. This is especially
	// important for explicit EmptyDir profiles, where a replacement Pod can have
	// a fresh node_key and no copy of the blocks the proof named.
	siblingPod, err := r.statefulSetPodForNode(ctx, sibling)
	if err != nil || !garageNodeLayoutReadyForPod(sibling, siblingPod) {
		message := fmt.Sprintf(
			"terminal drain proof names sibling %s, but its exact current StatefulSet Pod is not Ready and bound to status.observedPodUid",
			sibling.Name,
		)
		if err != nil {
			message = fmt.Sprintf("%s: %v", message, err)
		}
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("%s", message))
	}
	sourcePVCsReady, err := r.prepareCycleSourcePVCIdentityHandoff(ctx, node)
	if err != nil {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("retaining source PVC identities before terminal cycle promotion: %w", err))
	}
	if !sourcePVCsReady {
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseDraining, sibling.Name, siblingNodeID,
			garagev1beta1.ReasonCycleDraining,
			fmt.Sprintf("terminal drain proof is complete; waiting for source StatefulSet PVC retention and owner-reference convergence before promoting sibling %s", sibling.Name))
	}

	// Promote the sibling out of cycle-sibling status so the cluster Auto-mode
	// loop (or a human, for Manual nodes) treats it as a first-class node going
	// forward, and so it never gets mistaken for an orphaned sibling.
	if err := r.cyclePromoteSibling(ctx, node, sibling, cluster); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cycle: promoting sibling %s: %w", sibling.Name, err))
	}

	uid := node.UID
	if uid == "" {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("cycle source GarageNode %s/%s has no durable UID at terminal deletion", node.Namespace, node.Name))
	}
	if err := r.Delete(ctx, node, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("cycle: deleting drained node %s: %w", node.Name, err)
	}
	return ctrl.Result{}, nil
}

func containsCanonicalGarageNodeID(nodeIDs []string, want string) bool {
	want = garagev1beta1.CanonicalGarageNodeID(want)
	for _, nodeID := range nodeIDs {
		if garagev1beta1.CanonicalGarageNodeID(nodeID) == want && want != "" {
			return true
		}
	}
	return false
}

func requireCycleSettledLayoutHistory(history *garage.LayoutHistoryResponse) error {
	if err := requireSettledLayoutHistoryResponse(history); err != nil {
		return err
	}
	if history.CurrentVersion == 0 {
		return fmt.Errorf("Garage layout history has no current version") //nolint:staticcheck // Garage is a proper noun
	}
	currentEntries := 0
	for i := range history.Versions {
		version := history.Versions[i]
		if version.Status != garage.LayoutVersionStatusCurrent {
			continue
		}
		if version.Version != history.CurrentVersion {
			return fmt.Errorf("Garage layout history marks version %d Current while currentVersion is %d", version.Version, history.CurrentVersion) //nolint:staticcheck // Garage is a proper noun
		}
		currentEntries++
	}
	if currentEntries != 1 {
		return fmt.Errorf("Garage layout history must contain exactly one Current entry for version %d; got %d", history.CurrentVersion, currentEntries) //nolint:staticcheck // Garage is a proper noun
	}
	return nil
}

func (r *GarageNodeReconciler) cycleSetBlocked(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	blocked error,
) (ctrl.Result, error) {
	if blocked == nil {
		blocked = fmt.Errorf("cycle is blocked")
	}
	apply := func() {
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionCycling,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonCycleBlocked,
			Message:            blocked.Error(),
			ObservedGeneration: node.Generation,
		})
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
}

func (r *GarageNodeReconciler) reconcileCycleCancellation(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	siblingName string,
) (ctrl.Result, error) {
	sibling := &garagev1beta1.GarageNode{}
	err := r.Get(ctx, types.NamespacedName{Name: siblingName, Namespace: node.Namespace}, sibling)
	if err == nil {
		if actorErr := validateCycleSiblingActor(node, sibling, cluster); actorErr != nil {
			return r.cycleSetBlocked(ctx, node, actorErr)
		}
		apply := func() {
			meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionCycling,
				Status:             metav1.ConditionFalse,
				Reason:             garagev1beta1.ReasonCycleCancellationBlocked,
				Message:            fmt.Sprintf("cycle request was removed before source drain; explicitly drain and delete sibling %s, then cancellation can clear", siblingName),
				ObservedGeneration: node.Generation,
			})
		}
		apply()
		if statusErr := UpdateStatusWithRetry(ctx, r.Client, node, apply); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}
	if !errors.IsNotFound(err) {
		return r.cycleSetBlocked(ctx, node, fmt.Errorf("checking cycle sibling during cancellation: %w", err))
	}
	apply := func() {
		node.Status.CyclePhase = ""
		node.Status.CycleSiblingName = ""
		node.Status.CycleSiblingNodeID = ""
		meta.RemoveStatusCondition(&node.Status.Conditions, garagev1beta1.ConditionCycling)
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

func validateCycleSiblingActor(
	node, sibling *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) error {
	if node == nil || sibling == nil || cluster == nil {
		return fmt.Errorf("cycle sibling ownership proof is incomplete")
	}
	claimsAutoMembership := node.Labels[labelAppManagedBy] == managedByOperatorValue ||
		node.Labels[labelAutoNodeSlot] != ""
	if owner := metav1.GetControllerOf(node); (owner != nil || claimsAutoMembership) &&
		!hasExactGarageClusterControllerReference(node, cluster) {
		ownerDescription := "no controller"
		if owner != nil {
			ownerDescription = fmt.Sprintf("%s %s (%s)", owner.Kind, owner.Name, owner.APIVersion)
		}
		return fmt.Errorf(
			"cycle source GarageNode %s claims Auto membership but has %s rather than the exact resolved GarageCluster %s/%s UID %s",
			node.Name, ownerDescription,
			cluster.Namespace, cluster.Name, cluster.UID,
		)
	}
	if isCycleSibling(sibling) {
		owner := metav1.GetControllerOf(sibling)
		if node.UID == "" || owner == nil ||
			owner.APIVersion != garagev1beta1.GroupVersion.String() ||
			owner.Kind != kindGarageNode || owner.Name != node.Name || owner.UID != node.UID {
			return fmt.Errorf(
				"cycle sibling %s is not controlled by the exact GarageNode UID %s; refusing to trust a replacement identity",
				sibling.Name, node.UID,
			)
		}
		if hasExactGarageClusterControllerReference(node, cluster) {
			slot, err := canonicalAutoCycleSlot(node, sibling, cluster)
			if err != nil {
				return err
			}
			if sibling.Labels[labelAutoNodeSlot] != slot {
				return fmt.Errorf("cycle sibling %s does not carry exact Auto slot %s", sibling.Name, slot)
			}
		}
		return nil
	}

	// Promotion is persisted before DELETE. If DELETE transiently fails, the
	// next reconcile sees an already-promoted sibling and must retry safely.
	if hasExactGarageClusterControllerReference(node, cluster) {
		slot, err := canonicalAutoCycleSlot(node, sibling, cluster)
		if err != nil {
			return err
		}
		tier := tierStorage
		if node.Spec.Gateway {
			tier = tierGateway
		}
		if !hasExactGarageClusterControllerReference(sibling, cluster) ||
			sibling.Labels[labelAutoNodeSlot] != slot ||
			sibling.Labels[labelAppManagedBy] != managedByOperatorValue ||
			sibling.Labels[labelTier] != tier ||
			sibling.Labels[labelCluster] != cluster.Name {
			return fmt.Errorf("promoted cycle sibling %s is not bound to the exact Auto membership slot and GarageCluster UID", sibling.Name)
		}
		return nil
	}
	if metav1.GetControllerOf(sibling) != nil {
		return fmt.Errorf("promoted Manual cycle sibling %s unexpectedly has a controller owner", sibling.Name)
	}
	return nil
}

func (r *GarageNodeReconciler) getCycleLayoutHistory(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*garage.LayoutHistoryResponse, error) {
	if r.cycleLayoutHistoryGetter != nil {
		return r.cycleLayoutHistoryGetter(ctx, cluster)
	}
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return nil, fmt.Errorf("create Garage client: %w", err)
	}
	return garageClient.GetClusterLayoutHistory(ctx)
}

// cycleProvisionSibling creates the sibling GarageNode that will replace this
// node. The sibling clones the layout-relevant spec (zone, capacity, tags,
// storage) but gets a fresh node ID and fresh PVCs (no existingClaim / no
// NodeID), so it re-replicates into the cluster cleanly. It is owned by the
// original node (controller ref) so a stuck cycle is garbage-collected with the
// original, and it is labelled as a cycle sibling so the cluster's Auto-mode
// scale loop leaves it alone.
func (r *GarageNodeReconciler) cycleProvisionSibling(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	siblingName string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	spec, err := cloneCycleNodeSpec(node)
	if err != nil {
		return r.cycleSetBlocked(ctx, node, err)
	}
	applyInheritedManagedPVCSelectors(&spec, node, cluster)
	labels, err := cycleSiblingLabelsForCluster(node, cluster)
	if err != nil {
		return r.cycleSetBlocked(ctx, node, err)
	}

	sibling := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      siblingName,
			Namespace: node.Namespace,
			Labels:    labels,
		},
		Spec: spec,
	}
	if err := controllerutil.SetControllerReference(node, sibling, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("cycle: setting owner ref on sibling %s: %w", siblingName, err)
	}

	if err := r.Create(ctx, sibling); err != nil && !errors.IsAlreadyExists(err) {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cycle: creating sibling %s: %w", siblingName, err))
	}
	log.Info("Provisioned cycle sibling GarageNode", "node", node.Name, "sibling", siblingName)

	return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseProvisioning, siblingName, "",
		garagev1beta1.ReasonCycleProvisioning,
		fmt.Sprintf("provisioned sibling %s; waiting for it to join and sync", siblingName))
}

// cyclePromoteSibling rewrites the sibling so it survives as a first-class node
// once the original is gone. It strips the cycle-sibling marker label, replaces
// the controller owner ref to the (about-to-be-deleted) original node with the
// original's exact GarageCluster controller reference for Auto-owned cycles,
// and stamps the Auto-mode managed-by/tier labels. For Manual cycles the sibling
// becomes a standalone node.
func (r *GarageNodeReconciler) cyclePromoteSibling(
	ctx context.Context,
	node, sibling *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) error {
	changed := false
	autoOwned := hasExactGarageClusterControllerReference(node, cluster)
	var autoSlot string
	if autoOwned {
		var err error
		autoSlot, err = canonicalAutoCycleSlot(node, sibling, cluster)
		if err != nil {
			return err
		}
	}

	if sibling.Labels != nil && sibling.Labels[labelCycleSibling] != "" {
		delete(sibling.Labels, labelCycleSibling)
		changed = true
	}

	// Drop the owner ref to the original so deleting the original doesn't cascade
	// to the sibling.
	if owner := metav1.GetControllerOf(sibling); owner != nil && owner.Name == node.Name && owner.Kind == kindGarageNode {
		filtered := sibling.OwnerReferences[:0]
		for _, ref := range sibling.OwnerReferences {
			if ref.Kind == kindGarageNode && ref.Name == node.Name {
				continue
			}
			filtered = append(filtered, ref)
		}
		sibling.OwnerReferences = filtered
		changed = true
	}
	// Preserve exact parent ownership for garbage collection and for bounded
	// compatibility profile inheritance on a later StatefulSet recreation.
	if autoOwned && metav1.GetControllerOf(sibling) == nil {
		if err := controllerutil.SetControllerReference(cluster, sibling, r.Scheme); err != nil {
			return fmt.Errorf("setting exact GarageCluster owner on promoted sibling %s: %w", sibling.Name, err)
		}
		changed = true
	}

	// Exact GarageCluster controller ownership, rather than mutable source
	// labels, proves Auto membership. Restore the complete canonical label set so
	// a mid-cycle label edit cannot hide the promoted identity and make the
	// parent create a third member for the same ordinal.
	if autoOwned {
		if sibling.Labels == nil {
			sibling.Labels = map[string]string{}
		}
		tier := tierStorage
		if node.Spec.Gateway {
			tier = tierGateway
		}
		if sibling.Labels[labelAppManagedBy] != managedByOperatorValue {
			sibling.Labels[labelAppManagedBy] = managedByOperatorValue
			changed = true
		}
		if sibling.Labels[labelTier] != tier {
			sibling.Labels[labelTier] = tier
			changed = true
		}
		if sibling.Labels[labelCluster] != cluster.Name {
			sibling.Labels[labelCluster] = cluster.Name
			changed = true
		}
		if sibling.Labels[labelAutoNodeSlot] != autoSlot {
			sibling.Labels[labelAutoNodeSlot] = autoSlot
			changed = true
		}
	}

	if !changed {
		return nil
	}
	return r.Update(ctx, sibling)
}

// cycleSetPhase records cycle progress on status (phase + sibling identity) and
// sets the Cycling condition, then requeues so the state machine advances on the
// next reconcile.
func (r *GarageNodeReconciler) cycleSetPhase(ctx context.Context, node *garagev1beta1.GarageNode, phase, siblingName, siblingNodeID, reason, message string) (ctrl.Result, error) {
	apply := func() {
		node.Status.CyclePhase = phase
		node.Status.CycleSiblingName = siblingName
		if siblingNodeID != "" {
			node.Status.CycleSiblingNodeID = siblingNodeID
		}
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionCycling,
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: node.Generation,
		})
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

// cloneCycleNodeSpec returns a GarageNodeSpec for a cycle sibling: the same
// layout and repeatable storage-template fields as the source, but with a fresh
// node ID. Existing claims are rejected rather than stripped because neither a
// claim's access mode nor an unrelated size field expresses safe destination
// allocation intent.
func cloneCycleNodeSpec(node *garagev1beta1.GarageNode) (garagev1beta1.GarageNodeSpec, error) {
	if err := node.ValidateCycleStorageProfile(); err != nil {
		return garagev1beta1.GarageNodeSpec{}, fmt.Errorf("cycle source has no safely repeatable storage profile: %w", err)
	}
	spec := *node.Spec.DeepCopy()
	// Fresh identity with the same explicit templates. Kubernetes provisions new
	// claim names under the sibling StatefulSet; the source claims remain owned by
	// the source and are never copied, reused, or deleted by this helper.
	spec.NodeID = ""
	return spec, nil
}

// cycleSiblingLabelsForCluster binds an Auto-owned cycle to the ordinal derived
// from exact GarageCluster ownership. Source labels are user-mutable and cannot
// be the authority for durable membership during a replacement.
func cycleSiblingLabelsForCluster(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (map[string]string, error) {
	labels := cycleSiblingLabels(node)
	if !hasExactGarageClusterControllerReference(node, cluster) {
		return labels, nil
	}
	slot, err := canonicalAutoCycleSlot(node, nil, cluster)
	if err != nil {
		return nil, err
	}
	labels[labelCluster] = cluster.Name
	labels[labelAutoNodeSlot] = slot
	return labels, nil
}

// canonicalAutoCycleSlot resolves an Auto ordinal from two controller-bound
// facts: the exact parent GarageCluster and either the persisted sibling slot or
// the canonical ancestor of the source name. If both are present they must
// agree. Mutable cluster/tier/managed-by labels on the source are deliberately
// ignored.
func canonicalAutoCycleSlot(
	node, sibling *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (string, error) {
	if node == nil || cluster == nil || !hasExactGarageClusterControllerReference(node, cluster) {
		return "", fmt.Errorf("cannot resolve an Auto cycle slot without exact GarageCluster ownership")
	}
	valid := func(slot string) bool {
		if slot == "" {
			return false
		}
		if node.Spec.Gateway {
			_, ok := parseAutoModeGatewayOrdinal(slot, cluster.Name)
			return ok
		}
		_, ok := parseAutoModeOrdinal(slot, cluster.Name)
		return ok
	}

	nameSlot := node.Name
	if ancestor := cycleCanonicalAncestorName(node.Name); ancestor != "" {
		nameSlot = ancestor
	}
	if !valid(nameSlot) {
		nameSlot = ""
	}
	// Before a new sibling exists, a hash-bounded promoted source name no longer
	// embeds the canonical ordinal. Its persisted slot label is the only durable
	// bridge across repeated cycles. Once a sibling exists, that separately owned
	// object's slot becomes the authority and source-label drift is ignored.
	if sibling == nil {
		sourceSlot := node.Labels[labelAutoNodeSlot]
		if sourceSlot != "" && !valid(sourceSlot) {
			return "", fmt.Errorf("auto-owned cycle source %s carries invalid persisted Auto slot %q for GarageCluster %s", node.Name, sourceSlot, cluster.Name)
		}
		if sourceSlot != "" && nameSlot != "" && sourceSlot != nameSlot {
			return "", fmt.Errorf("auto-owned cycle source %s persisted Auto slot %s conflicts with canonical name slot %s", node.Name, sourceSlot, nameSlot)
		}
		if sourceSlot != "" {
			return sourceSlot, nil
		}
	}
	siblingSlot := ""
	if sibling != nil && sibling.Labels != nil {
		siblingSlot = sibling.Labels[labelAutoNodeSlot]
		if siblingSlot != "" && !valid(siblingSlot) {
			return "", fmt.Errorf("cycle sibling %s carries invalid Auto slot %q for GarageCluster %s", sibling.Name, siblingSlot, cluster.Name)
		}
	}
	if siblingSlot != "" && nameSlot != "" && siblingSlot != nameSlot {
		return "", fmt.Errorf("cycle sibling %s Auto slot %s conflicts with source canonical slot %s", sibling.Name, siblingSlot, nameSlot)
	}
	if siblingSlot != "" {
		return siblingSlot, nil
	}
	if nameSlot != "" {
		return nameSlot, nil
	}
	return "", fmt.Errorf("auto-owned cycle source %s has no canonical ordinal for GarageCluster %s", node.Name, cluster.Name)
}

// cycleSiblingLabels builds the baseline label set for a cycle sibling. It is
// explicitly marked as a sibling and withheld the Auto-mode managed-by label so
// the cluster's Auto-mode scale loop does not manage it as an ordinal mid-cycle.
// Production provisioning additionally calls cycleSiblingLabelsForCluster.
func cycleSiblingLabels(node *garagev1beta1.GarageNode) map[string]string {
	labels := map[string]string{
		labelCycleSibling: annotationTrue,
	}
	if c := node.Labels[labelCluster]; c != "" {
		labels[labelCluster] = c
	}
	if slot := autoNodeSlotForCycle(node); slot != "" {
		labels[labelAutoNodeSlot] = slot
	}
	return labels
}

// autoNodeSlotForCycle returns the stable canonical Auto ordinal for a source
// node. Released pre-slot promoted nodes are recognized only through their
// exact legacy `canonical-cycle...` name; new replacements carry the explicit
// label and no longer depend on reversible name parsing.
func autoNodeSlotForCycle(node *garagev1beta1.GarageNode) string {
	if node == nil {
		return ""
	}
	if slot := node.Labels[labelAutoNodeSlot]; slot != "" {
		return slot
	}
	clusterName := node.Labels[labelCluster]
	if clusterName == "" {
		return ""
	}
	name := node.Name
	if ancestor := cycleCanonicalAncestorName(name); ancestor != "" {
		name = ancestor
	}
	if node.Spec.Gateway {
		if _, ok := parseAutoModeGatewayOrdinal(name, clusterName); ok {
			return name
		}
		return ""
	}
	if _, ok := parseAutoModeOrdinal(name, clusterName); ok {
		return name
	}
	return ""
}
