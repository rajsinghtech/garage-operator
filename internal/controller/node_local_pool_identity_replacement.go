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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// The old ID is part of the public request. A stale GitOps request cannot
// authorize replacing a later identity on the same Kubernetes Node.
func nodeLocalIdentityReplacementRequested(cluster *garagev1beta2.GarageCluster, node *garagev1beta1.GarageNode, oldID string) bool {
	if cluster == nil || node == nil || !isNodeLocalPoolBacked(node) || !isValidGarageNodeID(oldID) {
		return false
	}
	pool, name, id, ok := garagev1beta2.ParseNodeLocalReplaceIdentityAnnotation(cluster.Annotations[AnnotationNodeLocalReplaceIdentity])
	return ok && pool == node.Spec.NodeLocalPoolName && name == node.Spec.KubernetesNodeName &&
		canonicalGarageNodeID(id) == canonicalGarageNodeID(oldID)
}

// swapNodeLocalIdentity commits one role removal and one role assignment in a
// single Garage layout version. Removing the old role on its own would violate
// replication.factor at fixed-size sites. This is only reachable while the
// canonical layout mutex and settled-history gate are held by reconcileNode.
func (r *GarageNodeReconciler) swapNodeLocalIdentity(
	ctx context.Context, node *garagev1beta1.GarageNode, cluster, owner *garagev1beta2.GarageCluster,
	admin *garage.Client, layout *garage.ClusterLayout, process *managedPodIdentity,
	oldID, newID string, desired garage.NodeRoleChange,
) error {
	if owner == nil || owner.UID != cluster.UID || layoutWritesBlocked(ctx) ||
		len(cluster.Spec.RemoteClusters) != 0 || cluster.Spec.ConnectTo != nil || cluster.IsLayoutFollower() ||
		cluster.Status.StorageDrain != nil || factorMigrationActive(cluster) || storageRolloutMutationBoundaryActive(cluster) {
		return fmt.Errorf("%w: node-local identity replacement requires an idle single-site layout writer", errLayoutMutationPending)
	}
	if !nodeLocalIdentityReplacementRequested(cluster, node, oldID) || process == nil ||
		canonicalGarageNodeID(process.nodeID) != newID || oldID == newID ||
		!hasExactGarageClusterControllerReference(node, cluster) {
		return fmt.Errorf("%w: node-local replacement request or exact managed Pod identity changed", errLayoutMutationPending)
	}
	if len(layout.StagedRoleChanges) != 0 || layout.StagedParameters != nil {
		return fmt.Errorf("%w: Garage layout staging is not empty before node-local identity replacement", errLayoutMutationPending)
	}
	factor := replicationFactorOf(cluster)
	var oldRole *garage.LayoutNodeRole
	var newRole *garage.LayoutNodeRole
	storageRoles := 0
	for i := range layout.Roles {
		role := &layout.Roles[i]
		if role.Capacity != nil && *role.Capacity > 0 {
			storageRoles++
		}
		if canonicalGarageNodeID(role.ID) == oldID {
			oldRole = role
		}
		if canonicalGarageNodeID(role.ID) == newID {
			newRole = role
		}
	}
	if newRole != nil && oldRole == nil && newRole.Capacity != nil && desired.Capacity != nil &&
		*newRole.Capacity == *desired.Capacity && newRole.Zone == desired.Zone &&
		tagSetEqual(newRole.Tags, desired.Tags) {
		return fmt.Errorf("%w: combined node-local role replacement already committed; waiting to pin the new identity", errLayoutMutationPending)
	}
	if newRole != nil {
		return fmt.Errorf("%w: replacement identity %s already owns a layout role", errLayoutMutationPending, shortID(newID))
	}
	if factor < 2 || storageRoles != factor || oldRole == nil || oldRole.Capacity == nil || *oldRole.Capacity == 0 ||
		desired.Capacity == nil || *desired.Capacity == 0 {
		return fmt.Errorf("%w: replacement requires exactly replication.factor positive-capacity roles including the old identity", errUnsafeLayoutRoleRemoval)
	}
	if err := r.requireNodeLocalIdentitySwapSafety(ctx, node, cluster, admin, oldID, factor); err != nil {
		return err
	}
	if err := r.revalidateManagedPodIdentity(ctx, node, cluster, process); err != nil {
		return fmt.Errorf("%w: replacement Pod changed before layout swap: %v", errLayoutMutationPending, err)
	}
	updates := []garage.NodeRoleChange{desired, {ID: oldID, Remove: true}}
	_, err := stageAndApplyExclusiveLayoutWithCheck(ctx, admin, layout, updates, nil, func() error {
		return admin.UpdateClusterLayout(ctx, updates)
	}, func(*garage.ClusterLayout) error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != cluster.UID || fresh.Generation != cluster.Generation ||
			!nodeLocalIdentityReplacementRequested(fresh, node, oldID) ||
			fresh.Status.StorageDrain != nil || factorMigrationActive(fresh) || storageRolloutMutationBoundaryActive(fresh) {
			return fmt.Errorf("%w: node-local identity replacement intent or storage transition changed before Apply", errLayoutMutationPending)
		}
		if err := r.revalidateManagedPodIdentity(ctx, node, fresh, process); err != nil {
			return err
		}
		return r.requireNodeLocalIdentitySwapSafety(ctx, node, fresh, admin, oldID, factor)
	})
	if err != nil {
		return fmt.Errorf("%w: combined node-local role replacement was not confirmed: %v", errLayoutMutationPending, err)
	}
	return fmt.Errorf("%w: combined node-local role replacement applied; waiting to pin the new identity", errLayoutMutationPending)
}

func (r *GarageNodeReconciler) requireNodeLocalIdentitySwapSafety(
	ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster,
	admin *garage.Client, oldID string, factor int,
) error {
	if err := requireConsistentStorageDrain(cluster); err != nil {
		return err
	}
	if err := requireGarageNodeLostSourceDown(ctx, node, cluster, admin, oldID); err != nil {
		return err
	}
	getter := r.clusterHealthGetter
	if getter == nil {
		getter = func(ctx context.Context, c *garage.Client) (*garage.ClusterHealth, error) {
			return c.GetClusterHealth(ctx)
		}
	}
	health, err := getter(ctx, admin)
	if err != nil {
		return fmt.Errorf("%w: reading live Garage health before node-local identity replacement: %v", errLayoutMutationPending, err)
	}
	if health == nil || health.StorageNodes != factor || health.StorageNodesUp != factor-1 ||
		health.Partitions == 0 || health.PartitionsQuorum != health.Partitions {
		return fmt.Errorf("%w: node-local identity replacement requires exactly the old storage role down and quorum on every partition", errUnsafeLayoutRoleRemoval)
	}
	return nil
}

// The role swap may leave a draining layout version waiting for explicit
// skip-dead-nodes recovery. Repair identity records independently of settled
// history so a restart cannot strand the new committed role behind old pins.
func (r *GarageNodeReconciler) finalizeNodeLocalIdentityReplacement(
	ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster,
	admin *garage.Client, owner *garagev1beta2.GarageCluster,
) (bool, error) {
	oldID := canonicalGarageNodeID(node.Status.NodeID)
	if !nodeLocalIdentityReplacementRequested(cluster, node, oldID) || owner.UID != cluster.UID {
		return false, nil
	}
	completed := false
	err := runLayoutAdministrativeMutation(r.layoutMutationCoordinator(), owner, func() error {
		freshCluster := &garagev1beta2.GarageCluster{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
			return err
		}
		freshNode := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
			return err
		}
		if freshCluster.UID != cluster.UID || freshNode.UID != node.UID ||
			canonicalGarageNodeID(freshNode.Status.NodeID) != oldID ||
			!nodeLocalIdentityReplacementRequested(freshCluster, freshNode, oldID) {
			return fmt.Errorf("%w: exact replacement actor changed while repairing identity pins", errLayoutMutationPending)
		}
		layout, err := admin.GetClusterLayout(ctx)
		if err != nil {
			return err
		}
		for _, role := range layout.Roles {
			if canonicalGarageNodeID(role.ID) == oldID {
				return nil // swap has not committed yet
			}
		}
		process, err := r.discoverNodeLocalPoolRecoveryNodeIdentity(ctx, freshNode, freshCluster)
		if err != nil {
			return fmt.Errorf("%w: discovering exact replacement Pod before pin repair: %v", errLayoutMutationPending, err)
		}
		newID := canonicalGarageNodeID(process.nodeID)
		if !isValidGarageNodeID(newID) || newID == oldID {
			return fmt.Errorf("%w: exact replacement Pod has no distinct valid Garage identity", errLayoutMutationPending)
		}
		desired, err := r.desiredGarageNodeRoleChange(ctx, freshNode, freshCluster, newID)
		if err != nil {
			return err
		}
		committed := false
		for _, role := range layout.Roles {
			if canonicalGarageNodeID(role.ID) == newID && role.Capacity != nil && desired.Capacity != nil &&
				*role.Capacity == *desired.Capacity && role.Zone == desired.Zone && tagSetEqual(role.Tags, desired.Tags) {
				committed = true
			}
		}
		if !committed {
			return fmt.Errorf("%w: old role is absent but exact replacement role is not committed", errLayoutMutationPending)
		}
		if err := r.revalidateManagedPodIdentity(ctx, freshNode, freshCluster, process); err != nil {
			return err
		}
		if err := r.pinNodeLocalReplacement(ctx, freshCluster, freshNode, oldID, newID); err != nil {
			return err
		}
		completed = true
		return nil
	})
	return completed, err
}

func (r *GarageNodeReconciler) pinNodeLocalReplacement(
	ctx context.Context, cluster *garagev1beta2.GarageCluster, node *garagev1beta1.GarageNode, oldID, newID string,
) error {
	var pool *garagev1beta2.NodeLocalPoolSpec
	if cluster.Spec.Storage != nil {
		for i := range cluster.Spec.Storage.NodeLocalPools {
			if cluster.Spec.Storage.NodeLocalPools[i].Name == node.Spec.NodeLocalPoolName {
				pool = &cluster.Spec.Storage.NodeLocalPools[i]
				break
			}
		}
	}
	if pool == nil {
		return fmt.Errorf("%w: replacement pool was removed before identity pin repair", errLayoutMutationPending)
	}
	k8sNode := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: node.Spec.KubernetesNodeName}, k8sNode); err != nil {
		return err
	}
	selector, err := metav1.LabelSelectorAsSelector(&pool.Selector)
	if err != nil || !selector.Matches(labels.Set(k8sNode.Labels)) {
		return fmt.Errorf("%w: replacement Kubernetes Node no longer matches its pool", errLayoutMutationPending)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	recoveryKey := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
	claim, err := decodeNodeLocalPoolHostPathClaim(k8sNode.Annotations[claimKey])
	if err != nil || claim.Retiring || !nodeLocalPoolHostPathClaimCanTransition(claim, cluster, pool.Name, nodeLocalPoolHostPaths(pool)) ||
		(canonicalGarageNodeID(claim.GarageNodeID) != oldID && canonicalGarageNodeID(claim.GarageNodeID) != newID) ||
		(canonicalGarageNodeID(k8sNode.Annotations[recoveryKey]) != oldID && canonicalGarageNodeID(k8sNode.Annotations[recoveryKey]) != newID) {
		return fmt.Errorf("%w: replacement HostPath claim or recovery pin changed", errLayoutMutationPending)
	}
	claim.GarageNodeID = newID
	value, err := encodeNodeLocalPoolHostPathClaim(*claim)
	if err != nil {
		return err
	}
	if k8sNode.Annotations[claimKey] != value || k8sNode.Annotations[recoveryKey] != newID {
		k8sNode.Annotations[claimKey] = value
		k8sNode.Annotations[recoveryKey] = newID
		if err := r.Update(ctx, k8sNode); err != nil {
			return err
		}
	}
	if current := canonicalGarageNodeID(node.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID]); current != oldID && current != newID {
		return fmt.Errorf("%w: GarageNode recovery pin changed", errLayoutMutationPending)
	}
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	if node.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID] != newID {
		node.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID] = newID
		if err := r.Update(ctx, node); err != nil {
			return err
		}
	}
	apply := func() {
		node.Status.NodeID = newID
		node.Status.Connected = false
		node.Status.InLayout = false
		node.Status.ObservedPodUID = ""
		node.Status.ObservedGeneration = 0
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, node, apply)
}
