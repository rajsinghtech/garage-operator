package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// cancelReselectedNodeLocalPoolRetirements lets a Kubernetes Node that is
// selected again rejoin with its retained identity when its persisted
// retirement can no longer make progress (#470).
//
// A retiring HostPath claim is released only after Garage's committed layout
// proves the old role absent. When no GarageNode exists for the pair, nothing
// in the operator removes that role, and with members == replication factor
// Garage has nowhere to move its partitions anyway; the pool then stays in
// Draining forever even though the user has re-added the Node. The retirement
// bit is cleared, so the ordinary recovery activation re-enrolls the same
// identity, only when every one of these holds:
//
//   - the claim belongs to this exact cluster and pool, is retiring, still
//     covers the pool's HostPaths, and pins one valid Garage node ID;
//   - no GarageNode (live or deleting) exists for the pair, so no ordinary
//     drain was prepared and the one-way GarageNode drain stays one-way;
//   - the pool DaemonSet carries no in-flight membership staging bridge, so
//     cancellation happens only at a committed fence boundary (#479);
//   - under the canonical layout mutex, one settled Garage layout (no draining
//     versions, no staged changes, history == layout version) still commits
//     that exact role;
//   - a fresh read of the parent and Node (same UID/generation, not deleting,
//     no storage drain, Node selected by the pool and no other) precedes the
//     resourceVersion-CAS Node Update.
//
// Anything else leaves the claim retiring and the existing cleanup path in
// charge. The function mutates membership only by refreshing the in-memory
// Node it cancelled, so the caller's retirement projection observes the new
// claim in the same pass.
func (r *GarageClusterReconciler) cancelReselectedNodeLocalPoolRetirements(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	membership *nodeLocalPoolMembership,
	existing map[string]*garagev1beta1.GarageNode,
) ([]string, error) {
	if cluster == nil || membership == nil || cluster.Spec.Storage == nil ||
		!cluster.DeletionTimestamp.IsZero() || cluster.Status.StorageDrain != nil ||
		cluster.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue {
		return nil, nil
	}
	existingPairs := make(map[string]bool, len(existing))
	for _, node := range existing {
		existingPairs[nodeLocalPoolKey(node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)] = true
	}

	type candidate struct {
		pool   *garagev1beta2.NodeLocalPoolSpec
		node   *corev1.Node
		nodeID string
	}
	var candidates []candidate
	for i := range cluster.Spec.Storage.NodeLocalPools {
		pool := &cluster.Spec.Storage.NodeLocalPools[i]
		desired := membership.desiredNodesByPool[pool.Name]
		for _, nodeName := range sortedNodeNames(desired) {
			node := desired[nodeName]
			if existingPairs[nodeLocalPoolKey(pool.Name, nodeName)] {
				continue
			}
			nodeID, ok := reselectedRetiringClaimIdentity(cluster, pool, node)
			if !ok {
				continue
			}
			candidates = append(candidates, candidate{pool: pool, node: node, nodeID: nodeID})
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	log := logf.FromContext(ctx)
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return nil, fmt.Errorf("resolving canonical Garage layout owner before cancelling a reselected node-local-pool retirement: %w", err)
	}
	release, lockErr := acquireLayoutMutation(r.layoutMutationCoordinator(), layoutOwner)
	if lockErr != nil {
		// Another layout writer owns the mutex. Keep the retirement; the next
		// pass re-evaluates it.
		log.V(1).Info("Deferring cancellation of reselected node-local-pool retirements", "reason", lockErr.Error())
		return nil, nil
	}
	defer release()

	committedRoles, proofErr := r.settledNodeLocalPoolCommittedRoles(ctx, cluster)
	if proofErr != nil {
		log.V(1).Info("Keeping reselected node-local-pool retirements until Garage layout is settled", "reason", proofErr.Error())
		return nil, nil
	}

	var cancelled []string
	for _, c := range candidates {
		if _, committed := committedRoles[c.nodeID]; !committed {
			// The role is gone (or never committed): the ordinary cleanup path
			// releases the claim and a fresh enrollment follows.
			continue
		}
		staged, err := r.nodeLocalPoolMembershipStagingInFlight(ctx, cluster, c.pool.Name)
		if err != nil {
			return cancelled, err
		}
		if staged {
			continue
		}
		fresh, done, err := r.clearReselectedNodeLocalPoolRetirement(ctx, cluster, c.pool.Name, c.node.Name, c.nodeID)
		if err != nil {
			return cancelled, err
		}
		if !done {
			continue
		}
		membership.desiredNodesByPool[c.pool.Name][c.node.Name] = fresh
		cancelled = append(cancelled, c.pool.Name+"/"+c.node.Name)
		log.Info("Cancelled persisted node-local-pool retirement for a reselected Kubernetes Node; re-enrolling its retained Garage identity",
			"nodeLocalPool", c.pool.Name, "kubernetesNode", c.node.Name, "garageNodeID", shortID(c.nodeID))
	}
	sort.Strings(cancelled)
	return cancelled, nil
}

// reselectedRetiringClaimIdentity returns the single Garage identity pinned by
// a retiring claim of this exact cluster/pool on node, or false when the claim
// is not retiring, foreign, path-incompatible, or carries no/ambiguous identity.
func reselectedRetiringClaimIdentity(
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	node *corev1.Node,
) (string, bool) {
	if node == nil || pool == nil {
		return "", false
	}
	claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)])
	if err != nil || !claim.Retiring ||
		!nodeLocalPoolHostPathClaimCanTransition(claim, cluster, pool.Name, nodeLocalPoolHostPaths(pool)) {
		return "", false
	}
	claimed := canonicalGarageNodeID(claim.GarageNodeID)
	pinned := canonicalGarageNodeID(node.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)])
	switch {
	case claimed != "" && pinned != "" && claimed != pinned:
		return "", false
	case claimed == "":
		claimed = pinned
	}
	if !isValidGarageNodeID(claimed) {
		return "", false
	}
	return claimed, true
}

// settledNodeLocalPoolCommittedRoles returns the role IDs of one settled
// committed Garage layout: no draining versions, no staged role changes, and
// a history version equal to the layout version.
func (r *GarageClusterReconciler) settledNodeLocalPoolCommittedRoles(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]struct{}, error) {
	layout, err := r.getNodeLocalPoolCommittedLayout(ctx, cluster)
	if err != nil {
		return nil, err
	}
	history, err := r.getClusterLayoutHistory(ctx, cluster)
	if err != nil {
		return nil, err
	}
	if layout == nil || history == nil {
		return nil, fmt.Errorf("garage layout or history is unavailable")
	}
	if draining := history.GetDrainingVersions(); len(draining) > 0 {
		return nil, fmt.Errorf("garage layout history still has %d draining version(s)", len(draining))
	}
	if history.CurrentVersion != layout.Version {
		return nil, fmt.Errorf("garage layout/history versions differ (%d != %d)", layout.Version, history.CurrentVersion)
	}
	if len(layout.StagedRoleChanges) > 0 {
		return nil, fmt.Errorf("garage layout has %d staged role change(s)", len(layout.StagedRoleChanges))
	}
	roles := make(map[string]struct{}, len(layout.Roles))
	for i := range layout.Roles {
		if layout.Roles[i].Capacity == nil {
			continue
		}
		roles[canonicalGarageNodeID(layout.Roles[i].ID)] = struct{}{}
	}
	return roles, nil
}

func (r *GarageClusterReconciler) nodeLocalPoolMembershipStagingInFlight(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
) (bool, error) {
	daemonSet := &appsv1.DaemonSet{}
	err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: cluster.Namespace,
	}, daemonSet)
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading node-local pool %q DaemonSet before cancelling a retirement: %w", nodeLocalPoolName, err)
	}
	return daemonSet.Annotations[annotationNodeLocalPoolMembershipStaging] != "", nil
}

// clearReselectedNodeLocalPoolRetirement is the durable cancellation CAS. It
// re-reads the parent last-but-one and the Node last, then updates the Node by
// resourceVersion. It returns done=false without error when a fresh read no
// longer supports cancellation.
func (r *GarageClusterReconciler) clearReselectedNodeLocalPoolRetirement(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName, kubernetesNodeName, nodeID string,
) (*corev1.Node, bool, error) {
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		return nil, false, fmt.Errorf("refreshing GarageCluster before cancelling a node-local-pool retirement: %w", err)
	}
	if freshCluster.UID != cluster.UID || freshCluster.Generation != cluster.Generation ||
		!freshCluster.DeletionTimestamp.IsZero() || freshCluster.Status.StorageDrain != nil ||
		freshCluster.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue || freshCluster.Spec.Storage == nil {
		return nil, false, nil
	}
	var freshPool *garagev1beta2.NodeLocalPoolSpec
	for i := range freshCluster.Spec.Storage.NodeLocalPools {
		if freshCluster.Spec.Storage.NodeLocalPools[i].Name == nodeLocalPoolName {
			freshPool = &freshCluster.Spec.Storage.NodeLocalPools[i]
		}
	}
	if freshPool == nil {
		return nil, false, nil
	}
	node := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: kubernetesNodeName}, node); err != nil {
		return nil, false, fmt.Errorf("refreshing Kubernetes Node %q before cancelling a node-local-pool retirement: %w", kubernetesNodeName, err)
	}
	if !node.DeletionTimestamp.IsZero() {
		return nil, false, nil
	}
	for i := range freshCluster.Spec.Storage.NodeLocalPools {
		other := &freshCluster.Spec.Storage.NodeLocalPools[i]
		selector, err := metav1.LabelSelectorAsSelector(&other.Selector)
		if err != nil {
			return nil, false, fmt.Errorf("parsing current selector for node-local pool %q: %w", other.Name, err)
		}
		if selector.Matches(labels.Set(node.Labels)) != (other.Name == nodeLocalPoolName) {
			return nil, false, nil
		}
	}
	freshID, ok := reselectedRetiringClaimIdentity(freshCluster, freshPool, node)
	if !ok || freshID != nodeID {
		return nil, false, nil
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(freshCluster, nodeLocalPoolName)
	claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[claimKey])
	if err != nil {
		return nil, false, err
	}
	claim.Retiring = false
	if strings.TrimSpace(claim.GarageNodeID) == "" {
		claim.GarageNodeID = nodeID
	}
	encoded, err := encodeNodeLocalPoolHostPathClaim(*claim)
	if err != nil {
		return nil, false, err
	}
	node.Annotations[claimKey] = encoded
	if err := r.Update(ctx, node); err != nil {
		return nil, false, fmt.Errorf("cancelling node-local pool %q retirement on Kubernetes Node %q by resourceVersion CAS: %w", nodeLocalPoolName, kubernetesNodeName, err)
	}
	return node, true, nil
}
