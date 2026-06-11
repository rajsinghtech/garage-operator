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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// cycleSiblingSuffix is appended to a GarageNode name to derive its cycle
// sibling's name. The sibling is a transient replacement that takes over the
// original's layout slot; once the swap completes the original is deleted and
// the sibling lives on under this name (it is NOT renamed back — renaming a
// GarageNode would churn its StatefulSet identity and PVCs).
const cycleSiblingSuffix = "-cycle"

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
//	(start) -> Provisioning : create the sibling GarageNode (fresh node ID + PVCs,
//	                          same zone/capacity/tags/storage). Wait for it to come
//	                          up and discover its node ID.
//	Provisioning -> Syncing : sibling has a node ID and is in the layout; wait for
//	                          its layout sync tracker to reach the current version
//	                          (all partitions it owns are in sync).
//	Syncing -> Draining     : sibling is fully synced; delete this node, whose
//	                          finalizer drains + removes it from the layout and
//	                          reaps its StatefulSet/PVCs. The sibling lives on.
//
// A cycle sibling never cycles itself (guarded by the caller resolving the
// annotation only on non-sibling nodes plus the isCycleSibling check here).
func (r *GarageNodeReconciler) reconcileCycle(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
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
		return ctrl.Result{Requeue: true}, nil
	}

	siblingName := node.Name + cycleSiblingSuffix
	if node.Status.CycleSiblingName != "" {
		siblingName = node.Status.CycleSiblingName
	}

	// Look up the sibling; absent means we are at the start of the cycle (or a
	// prior provision attempt was lost) and must (re)create it.
	sibling := &garagev1beta1.GarageNode{}
	err := r.Get(ctx, types.NamespacedName{Name: siblingName, Namespace: node.Namespace}, sibling)
	switch {
	case errors.IsNotFound(err):
		return r.cycleProvisionSibling(ctx, node, siblingName)
	case err != nil:
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("getting cycle sibling %s: %w", siblingName, err))
	}

	// Sibling exists. Resume the state machine from its observed state. If the
	// sibling has not yet discovered its node ID, it is still coming up.
	if sibling.Status.NodeID == "" {
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseProvisioning, siblingName, "",
			garagev1beta1.ReasonCycleProvisioning,
			fmt.Sprintf("sibling %s provisioning; waiting for node ID", siblingName))
	}

	// Sibling has a node ID — check whether it has synced to the current layout
	// version. We need the cluster admin API for the layout history.
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cycle: failed to create garage client: %w", err))
	}

	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cycle: failed to get layout history: %w", err))
	}

	if !history.NodeSyncedToCurrent(sibling.Status.NodeID) {
		log.V(1).Info("Cycle sibling not yet synced to current layout version",
			"node", node.Name, "sibling", siblingName, "siblingNodeID", sibling.Status.NodeID,
			"currentVersion", history.CurrentVersion)
		return r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseSyncing, siblingName, sibling.Status.NodeID,
			garagev1beta1.ReasonCycleSyncing,
			fmt.Sprintf("sibling %s syncing to layout version %d", siblingName, history.CurrentVersion))
	}

	// Sibling is fully synced. The cluster is now safe to lose this node without
	// dipping replication. Record the Draining phase, then delete this node — its
	// finalizer drains + removes it from the layout and reaps its StatefulSet/PVCs.
	log.Info("Cycle sibling synced; draining and removing original node",
		"node", node.Name, "sibling", siblingName, "siblingNodeID", sibling.Status.NodeID)

	if node.Status.CyclePhase != garagev1beta1.CyclePhaseDraining {
		if _, err := r.cycleSetPhase(ctx, node, garagev1beta1.CyclePhaseDraining, siblingName, sibling.Status.NodeID,
			garagev1beta1.ReasonCycleDraining,
			fmt.Sprintf("sibling %s synced; draining and removing this node", siblingName)); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Promote the sibling out of cycle-sibling status so the cluster Auto-mode
	// loop (or a human, for Manual nodes) treats it as a first-class node going
	// forward, and so it never gets mistaken for an orphaned sibling.
	if err := r.cyclePromoteSibling(ctx, node, sibling); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cycle: promoting sibling %s: %w", siblingName, err))
	}

	if err := r.Delete(ctx, node); err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("cycle: deleting drained node %s: %w", node.Name, err)
	}
	return ctrl.Result{}, nil
}

// cycleProvisionSibling creates the sibling GarageNode that will replace this
// node. The sibling clones the layout-relevant spec (zone, capacity, tags,
// storage) but gets a fresh node ID and fresh PVCs (no existingClaim / no
// NodeID), so it re-replicates into the cluster cleanly. It is owned by the
// original node (controller ref) so a stuck cycle is garbage-collected with the
// original, and it is labelled as a cycle sibling so the cluster's Auto-mode
// scale loop leaves it alone.
func (r *GarageNodeReconciler) cycleProvisionSibling(ctx context.Context, node *garagev1beta1.GarageNode, siblingName string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	sibling := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      siblingName,
			Namespace: node.Namespace,
			Labels:    cycleSiblingLabels(node),
		},
		Spec: cloneCycleNodeSpec(node),
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
// once the original is gone. It strips the cycle-sibling marker label, drops the
// controller owner ref to the (about-to-be-deleted) original node, and — for
// Auto-owned cycles — stamps the Auto-mode managed-by/tier labels so the cluster
// loop adopts it. For Manual cycles the sibling simply becomes a standalone node.
func (r *GarageNodeReconciler) cyclePromoteSibling(ctx context.Context, node, sibling *garagev1beta1.GarageNode) error {
	changed := false

	if sibling.Labels != nil && sibling.Labels[labelCycleSibling] != "" {
		delete(sibling.Labels, labelCycleSibling)
		changed = true
	}

	// Drop the owner ref to the original so deleting the original doesn't cascade
	// to the sibling.
	if owner := metav1.GetControllerOf(sibling); owner != nil && owner.Name == node.Name && owner.Kind == "GarageNode" {
		filtered := sibling.OwnerReferences[:0]
		for _, ref := range sibling.OwnerReferences {
			if ref.Kind == "GarageNode" && ref.Name == node.Name {
				continue
			}
			filtered = append(filtered, ref)
		}
		sibling.OwnerReferences = filtered
		changed = true
	}

	// If the original was an Auto-owned ordinal, hand the sibling the same
	// managed-by/tier labels so the cluster loop sees it as a managed storage
	// node. (Auto-owned nodes carry labelAppManagedBy=operator + labelTier.)
	if node.Labels[labelAppManagedBy] == managedByOperatorValue && node.Labels[labelTier] != "" {
		if sibling.Labels == nil {
			sibling.Labels = map[string]string{}
		}
		if sibling.Labels[labelAppManagedBy] != managedByOperatorValue {
			sibling.Labels[labelAppManagedBy] = managedByOperatorValue
			changed = true
		}
		if sibling.Labels[labelTier] != node.Labels[labelTier] {
			sibling.Labels[labelTier] = node.Labels[labelTier]
			changed = true
		}
		if sibling.Labels[labelCluster] != node.Labels[labelCluster] {
			sibling.Labels[labelCluster] = node.Labels[labelCluster]
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
// layout-relevant + pod-config fields as the original, but with a fresh node ID
// (empty) and freshly provisioned storage (existingClaim stripped) so the
// sibling re-replicates rather than adopting the original's data. The cycle
// annotation is intentionally NOT carried over.
func cloneCycleNodeSpec(node *garagev1beta1.GarageNode) garagev1beta1.GarageNodeSpec {
	spec := *node.Spec.DeepCopy()
	// Fresh identity + storage: the whole point of a cycle is a new node ID and
	// new PVCs (hardware swap, storageClass migration, etc.).
	spec.NodeID = ""
	if spec.Storage != nil {
		if spec.Storage.Metadata != nil {
			spec.Storage.Metadata.ExistingClaim = ""
		}
		if spec.Storage.Data != nil {
			spec.Storage.Data.ExistingClaim = ""
		}
		for i := range spec.Storage.DataPaths {
			spec.Storage.DataPaths[i].ExistingClaim = ""
		}
	}
	return spec
}

// cycleSiblingLabels builds the label set for a cycle sibling: it inherits the
// original's cluster label for selector/observability parity but is explicitly
// marked as a cycle sibling and withheld the Auto-mode managed-by label so the
// cluster's Auto-mode scale loop does not manage it as an ordinal mid-cycle.
func cycleSiblingLabels(node *garagev1beta1.GarageNode) map[string]string {
	labels := map[string]string{
		labelCycleSibling: annotationTrue,
	}
	if c := node.Labels[labelCluster]; c != "" {
		labels[labelCluster] = c
	}
	return labels
}
