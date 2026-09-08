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
	"crypto/sha256"
	"fmt"
	"maps"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func sortedNodeNames(nodes map[string]*corev1.Node) []string {
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *GarageClusterReconciler) ensureNodeLocalPoolActivation(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	node *corev1.Node,
	labelKey, labelValue, recoveryAnnotationKey, recoveryNodeID string,
) error {
	if cluster == nil || pool == nil || node == nil {
		return fmt.Errorf("node-local-pool activation requires an exact cluster, pool, and Kubernetes Node")
	}
	if err := r.assertNodeLocalPoolPrerequisites(ctx, cluster); err != nil {
		return err
	}
	if labelValue == "" || labelValue == nodeLocalPoolActivationFenceValue || labelValue == nodeLocalPoolActivationQuarantineValue {
		return fmt.Errorf("invalid active node-local-pool scheduling value %q", labelValue)
	}
	recoveryNodeID = canonicalGarageNodeID(recoveryNodeID)
	if recoveryNodeID != "" && !isValidGarageNodeID(recoveryNodeID) {
		return fmt.Errorf("invalid node-local-pool recovery node ID %q", recoveryNodeID)
	}
	if errs := utilvalidation.IsQualifiedName(recoveryAnnotationKey); len(errs) > 0 {
		return fmt.Errorf("invalid node-local-pool recovery annotation key %q: %s", recoveryAnnotationKey, strings.Join(errs, "; "))
	}

	// Share the canonical Garage-layout mutex with drain publication. This
	// closes the interval after the final status read but before the Node CAS: a
	// drain writer cannot persist its target inventory while a new HostPath
	// process is being authorized, and vice versa.
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before node-local-pool activation: %w", err)
	}
	coordinator := r.layoutMutationCoordinator()
	release, lockErr := acquireLayoutMutationDuringStorageRolloutPrepare(coordinator, layoutOwner)
	if lockErr != nil {
		// A replacement DaemonSet Pod is born behind a scheduling gate. During
		// its exact persisted rollout, ordinary pool reconciliation must still
		// be able to prove that the Node's existing activation token and HostPath
		// claim already match the desired workload; otherwise it returns before
		// releaseNodeLocalPoolPodSchedulingGates and deadlocks its own replacement.
		// This path is read-only: any required Node mutation remains blocked by
		// the rollout exclusion below. Requiring this source's confirmed marker
		// prevents a different GarageCluster sharing the layout from bypassing it.
		owned, confirmed := coordinator.NodeLocalPoolRolloutSourceActive(
			layoutOwnerKey(layoutOwner), cluster.UID,
		)
		rollout, rolloutErr := nodeLocalPoolRolloutRecordForCluster(cluster)
		if !owned || !confirmed || rolloutErr != nil || rollout == nil {
			return fmt.Errorf("serializing node-local-pool activation with Garage layout mutations: %w", lockErr)
		}
	} else {
		defer release()
	}

	// Re-read both the owning spec and the Node at the last possible moment.
	// The following Update uses this Node's resourceVersion as the serialization
	// point shared by every GarageCluster controller.
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		return fmt.Errorf("refreshing GarageCluster before node-local-pool activation: %w", err)
	}
	if freshCluster.UID != cluster.UID || freshCluster.Generation != cluster.Generation {
		return fmt.Errorf("garageCluster changed before node-local-pool activation; restarting selector and HostPath preflight")
	}
	if !freshCluster.DeletionTimestamp.IsZero() ||
		freshCluster.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue ||
		freshCluster.Status.StorageDrain != nil {
		return fmt.Errorf("garageCluster entered deletion or storage-drain preparation before node-local-pool activation; refusing to start another HostPath process")
	}
	freshLayoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), freshCluster)
	if err != nil {
		return fmt.Errorf("refreshing canonical Garage layout owner before node-local-pool activation: %w", err)
	}
	if !freshLayoutOwner.DeletionTimestamp.IsZero() || freshLayoutOwner.Status.StorageDrain != nil {
		return fmt.Errorf("canonical Garage layout owner entered deletion or storage-drain preparation before node-local-pool activation")
	}
	var freshPool *garagev1beta2.NodeLocalPoolSpec
	if freshCluster.Spec.Storage != nil {
		for i := range freshCluster.Spec.Storage.NodeLocalPools {
			if freshCluster.Spec.Storage.NodeLocalPools[i].Name == pool.Name {
				freshPool = &freshCluster.Spec.Storage.NodeLocalPools[i]
				break
			}
		}
	}
	if freshPool == nil {
		return fmt.Errorf("node-local pool %q no longer exists; restarting activation preflight", pool.Name)
	}

	freshNode := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: node.Name}, freshNode); err != nil {
		return fmt.Errorf("refreshing Kubernetes Node %q before node-local-pool activation: %w", node.Name, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&freshPool.Selector)
	if err != nil {
		return fmt.Errorf("parsing current selector for node-local pool %q: %w", freshPool.Name, err)
	}
	if !selector.Matches(labels.Set(freshNode.Labels)) {
		return fmt.Errorf("kubernetes node %q no longer matches node-local pool %q; restarting activation preflight", freshNode.Name, freshPool.Name)
	}
	for i := range freshCluster.Spec.Storage.NodeLocalPools {
		otherPool := &freshCluster.Spec.Storage.NodeLocalPools[i]
		if otherPool.Name == freshPool.Name {
			continue
		}
		otherSelector, err := metav1.LabelSelectorAsSelector(&otherPool.Selector)
		if err != nil {
			return fmt.Errorf("parsing current selector for node-local pool %q: %w", otherPool.Name, err)
		}
		if otherSelector.Matches(labels.Set(freshNode.Labels)) {
			return fmt.Errorf("kubernetes node %q now matches node-local pools %q and %q; restarting activation preflight", freshNode.Name, freshPool.Name, otherPool.Name)
		}
	}
	preflightState := &nodeLocalPoolState{
		pool:         freshPool,
		desiredNodes: map[string]*corev1.Node{freshNode.Name: freshNode},
	}
	conflicts, err := r.nodeLocalPoolHostPathConflicts(
		ctx, freshCluster, map[string]*nodeLocalPoolState{freshPool.Name: preflightState},
	)
	if err != nil {
		return fmt.Errorf("rechecking HostPath ownership on Kubernetes Node %q: %w", freshNode.Name, err)
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("kubernetes node %q failed final HostPath ownership preflight: %s", freshNode.Name, strings.Join(conflicts, ", "))
	}

	existingRecoveryNodeID := canonicalGarageNodeID(freshNode.Annotations[recoveryAnnotationKey])
	if existingRecoveryNodeID != "" && !isValidGarageNodeID(existingRecoveryNodeID) {
		return fmt.Errorf("kubernetes node %q carries invalid node-local-pool recovery node ID %q", freshNode.Name, existingRecoveryNodeID)
	}
	if recoveryNodeID != "" && existingRecoveryNodeID != "" &&
		recoveryNodeID != existingRecoveryNodeID {
		return fmt.Errorf(
			"kubernetes node %q is already pinned to Garage identity %s, refusing recovery as %s",
			freshNode.Name, shortID(existingRecoveryNodeID), shortID(recoveryNodeID),
		)
	}
	if recoveryNodeID == "" {
		recoveryNodeID = existingRecoveryNodeID
	}

	claimKey := nodeLocalPoolHostPathClaimAnnotation(freshCluster, freshPool.Name)
	if errs := utilvalidation.IsQualifiedName(claimKey); len(errs) > 0 {
		return fmt.Errorf("invalid node-local-pool HostPath claim annotation key %q: %s", claimKey, strings.Join(errs, "; "))
	}
	if existingClaimValue := freshNode.Annotations[claimKey]; existingClaimValue != "" {
		existingClaim, err := decodeNodeLocalPoolHostPathClaim(existingClaimValue)
		if err != nil {
			return fmt.Errorf("kubernetes node %q carries invalid current HostPath claim: %w", freshNode.Name, err)
		}
		if !nodeLocalPoolHostPathClaimCanTransition(
			existingClaim, freshCluster, freshPool.Name, nodeLocalPoolHostPaths(freshPool),
		) {
			return fmt.Errorf(
				"kubernetes node %q HostPath claim is owned by another pool or would lose a previously claimed path",
				freshNode.Name,
			)
		}
		if existingClaim.Retiring {
			return fmt.Errorf(
				"kubernetes node %q node-local pool %q is completing a persisted retirement before it may be enrolled again",
				freshNode.Name, freshPool.Name,
			)
		}
		if existingClaim.GarageNodeID != "" {
			if recoveryNodeID != "" && recoveryNodeID != existingClaim.GarageNodeID {
				return fmt.Errorf(
					"kubernetes node %q HostPath claim is pinned to Garage identity %s, refusing recovery as %s",
					freshNode.Name, shortID(existingClaim.GarageNodeID), shortID(recoveryNodeID),
				)
			}
			recoveryNodeID = existingClaim.GarageNodeID
		}
	}
	claim, err := newNodeLocalPoolHostPathClaim(freshCluster, freshPool, recoveryNodeID)
	if err != nil {
		return err
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		return err
	}
	if freshNode.Labels == nil {
		freshNode.Labels = make(map[string]string)
	}
	if freshNode.Annotations == nil {
		freshNode.Annotations = make(map[string]string)
	}
	changed := freshNode.Labels[labelKey] != labelValue || freshNode.Annotations[claimKey] != claimValue
	freshNode.Labels[labelKey] = labelValue
	freshNode.Annotations[claimKey] = claimValue
	if recoveryNodeID != "" && freshNode.Annotations[recoveryAnnotationKey] != recoveryNodeID {
		freshNode.Annotations[recoveryAnnotationKey] = recoveryNodeID
		changed = true
	}
	if !changed {
		*node = *freshNode
		return nil
	}
	if lockErr != nil {
		return fmt.Errorf(
			"node-local-pool activation requires a Node mutation while its exact managed Pod handoff is active: %w",
			lockErr,
		)
	}
	if recoveryNodeID == "" {
		if err := r.requireNodeLocalPoolActivationHeadroom(
			ctx, freshCluster, freshPool.Name, freshNode.Name,
		); err != nil {
			return err
		}
	}
	if err := r.Update(ctx, freshNode); err != nil {
		if errors.IsConflict(err) {
			return fmt.Errorf("kubernetes node %q changed at the node-local-pool activation CAS; restarting full preflight: %w", freshNode.Name, err)
		}
		return err
	}
	*node = *freshNode
	return nil
}

func (r *GarageClusterReconciler) markNodeLocalPoolClaimRetiring(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName, kubernetesNodeName string,
) error {
	if cluster == nil {
		return fmt.Errorf("persisting node-local-pool retirement requires an exact GarageCluster")
	}
	// Read the Node first and the parent spec last. The Node Update below is the
	// CAS for label changes; the immediately preceding uncached parent read
	// narrows the cross-object boundary and refuses an irreversible retirement
	// selected by an older GarageCluster generation.
	node := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: kubernetesNodeName}, node); err != nil {
		return fmt.Errorf("reading Kubernetes Node %q before persisting node-local-pool retirement: %w", kubernetesNodeName, err)
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		return fmt.Errorf("refreshing GarageCluster before persisting node-local-pool retirement: %w", err)
	}
	if freshCluster.UID != cluster.UID || freshCluster.Generation != cluster.Generation {
		return fmt.Errorf("garageCluster changed before node-local-pool retirement; restarting selector and drain preflight")
	}
	if !freshCluster.DeletionTimestamp.IsZero() {
		return fmt.Errorf("garageCluster entered deletion before node-local-pool retirement; restarting through the cluster deletion state machine")
	}
	var freshPool *garagev1beta2.NodeLocalPoolSpec
	if freshCluster.Spec.Storage != nil {
		for i := range freshCluster.Spec.Storage.NodeLocalPools {
			if freshCluster.Spec.Storage.NodeLocalPools[i].Name == nodeLocalPoolName {
				freshPool = &freshCluster.Spec.Storage.NodeLocalPools[i]
				break
			}
		}
	}
	if freshPool != nil {
		selector, err := metav1.LabelSelectorAsSelector(&freshPool.Selector)
		if err != nil {
			return fmt.Errorf("parsing current selector for node-local pool %q before retirement: %w", nodeLocalPoolName, err)
		}
		if selector.Matches(labels.Set(node.Labels)) {
			return fmt.Errorf(
				"kubernetes node %q again matches node-local pool %q before retirement became durable; restarting membership preflight",
				kubernetesNodeName, nodeLocalPoolName,
			)
		}
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(freshCluster, nodeLocalPoolName)
	claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[claimKey])
	if err != nil {
		return fmt.Errorf("node-local pool %q on Kubernetes Node %q has no valid durable HostPath claim to retire: %w", nodeLocalPoolName, kubernetesNodeName, err)
	}
	if claim.ClusterNamespace != freshCluster.Namespace || claim.ClusterName != freshCluster.Name || claim.NodeLocalPoolName != nodeLocalPoolName {
		return fmt.Errorf("node-local pool %q on Kubernetes Node %q carries a HostPath claim owned by %s/%s pool %q",
			nodeLocalPoolName, kubernetesNodeName, claim.ClusterNamespace, claim.ClusterName, claim.NodeLocalPoolName)
	}
	if claim.Retiring {
		return nil
	}
	claim.Retiring = true
	encoded, err := encodeNodeLocalPoolHostPathClaim(*claim)
	if err != nil {
		return err
	}
	node.Annotations[claimKey] = encoded
	if err := r.Update(ctx, node); err != nil {
		return fmt.Errorf("persisting node-local pool %q retirement on Kubernetes Node %q by resourceVersion CAS: %w", nodeLocalPoolName, kubernetesNodeName, err)
	}
	return nil
}

// ensureNodeLocalPoolPodNodeLabel repairs the routing identity on a scheduled
// node-local-pool Pod. The DaemonSet template cannot carry this value because
// it is different for every Node selected by the same DaemonSet; the operator
// therefore owns both the selector label and its audit annotation.
//
// Return whether a patch was needed so callers that run outside the cluster
// lifecycle can make the repair visible without turning an idempotent check
// into a noisy log on every reconcile.
func ensureNodeLocalPoolPodNodeLabel(ctx context.Context, c client.Client, pod *corev1.Pod) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("node-local-pool Pod label repair requires a Kubernetes client")
	}
	if pod == nil {
		return false, fmt.Errorf("node-local-pool Pod label repair requires a Pod")
	}
	if pod.Spec.NodeName == "" {
		return false, fmt.Errorf("node-local-pool Pod %s/%s is not scheduled", pod.Namespace, pod.Name)
	}
	value := kubernetesNodeLabelValue(pod.Spec.NodeName)
	if pod.Labels[labelKubernetesNode] == value && pod.Annotations[annotationKubernetesNode] == pod.Spec.NodeName {
		return false, nil
	}
	before := pod.DeepCopy()
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Labels[labelKubernetesNode] = value
	pod.Annotations[annotationKubernetesNode] = pod.Spec.NodeName
	if err := c.Patch(ctx, pod, client.MergeFrom(before)); err != nil {
		return false, err
	}
	return true, nil
}

func (r *GarageClusterReconciler) ensureDaemonSetPodNodeLabel(ctx context.Context, pod *corev1.Pod) error {
	_, err := ensureNodeLocalPoolPodNodeLabel(ctx, r.Client, pod)
	return err
}

func kubernetesNodeLabelValue(nodeName string) string {
	if len(nodeName) <= 63 && len(utilvalidation.IsValidLabelValue(nodeName)) == 0 {
		return nodeName
	}
	sum := sha256.Sum256([]byte(nodeName))
	return "sha256-" + fmt.Sprintf("%x", sum[:12])
}

func (r *GarageClusterReconciler) countSurvivingStorageNodes(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	excludeName string,
) (int, error) {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return 0, fmt.Errorf("listing GarageNodes for replication safety: %w", err)
	}
	nodeIDs := make(map[string]struct{})
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Name == excludeName || node.Spec.ClusterRef.Name != cluster.Name || node.Spec.Gateway ||
			!node.DeletionTimestamp.IsZero() || node.Spec.Capacity == nil || node.Spec.Capacity.Sign() <= 0 ||
			node.Status.NodeID == "" || !node.Status.Connected || !node.Status.InLayout {
			continue
		}
		nodeIDs[node.Status.NodeID] = struct{}{}
	}
	return len(nodeIDs), nil
}

func nodeLocalPoolPodTargetNodeNames(pod *corev1.Pod) (map[string]struct{}, bool) {
	if pod == nil {
		return nil, false
	}
	if pod.Spec.NodeName != "" {
		return map[string]struct{}{pod.Spec.NodeName: {}}, true
	}
	required := pod.Spec.Affinity
	if required == nil || required.NodeAffinity == nil ||
		required.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return nil, false
	}
	terms := required.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 {
		return nil, false
	}
	names := make(map[string]struct{})
	for i := range terms {
		boundedTerm := false
		for j := range terms[i].MatchFields {
			requirement := &terms[i].MatchFields[j]
			if requirement.Key != kubernetesNodeNameFieldPath || requirement.Operator != corev1.NodeSelectorOpIn || len(requirement.Values) == 0 {
				continue
			}
			boundedTerm = true
			for _, name := range requirement.Values {
				if name != "" {
					names[name] = struct{}{}
				}
			}
		}
		if !boundedTerm {
			// NodeSelectorTerms are ORed. One unbounded term means the Pod may
			// still target any Node, so claim cleanup must fail closed.
			return names, false
		}
	}
	return names, len(names) > 0
}

func nodeLocalPoolPodHasSchedulingGate(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for i := range pod.Spec.SchedulingGates {
		if pod.Spec.SchedulingGates[i].Name == nodeLocalPoolSchedulingGateName {
			return true
		}
	}
	return false
}

func removeNodeLocalPoolPodSchedulingGate(pod *corev1.Pod) bool {
	if !nodeLocalPoolPodHasSchedulingGate(pod) {
		return false
	}
	gates := pod.Spec.SchedulingGates[:0]
	for i := range pod.Spec.SchedulingGates {
		if pod.Spec.SchedulingGates[i].Name != nodeLocalPoolSchedulingGateName {
			gates = append(gates, pod.Spec.SchedulingGates[i])
		}
	}
	pod.Spec.SchedulingGates = gates
	return true
}

type nodeLocalPoolSchedulingGateWorkload struct {
	pool                *garagev1beta2.NodeLocalPoolSpec
	activationLabel     string
	activationValue     string
	daemonSet           *appsv1.DaemonSet
	expectedWorkloadUID types.UID
	expectedPodSpecHash string
	expectedConfigHash  string
	expectedHostPaths   []string
	expectedNodeIDs     map[string]string
	desiredNodeUIDs     map[string]types.UID
}

// releaseStorageRolloutActorPodSchedulingGate reconstructs the one persisted
// node-local rollout actor before delegating to the ordinary scheduling-gate
// authorization point. Recovery must never infer that every gated Pod in a
// pool is part of the active handoff: a spec change, retired DaemonSet, or late
// controller create can leave unrelated Pods visible while status still names
// one exact Kubernetes Node and durable Garage identity.
func (r *GarageClusterReconciler) releaseStorageRolloutActorPodSchedulingGate(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) ([]string, []string, error) {
	if record.NodeLocalPoolName == "" {
		return nil, nil, nil
	}
	// Avoid imposing replacement-template preconditions on an already-scheduled
	// actor. This preliminary read never authorizes a Pod; it only decides
	// whether the strict, shared gate-release path is needed at all.
	daemonSet := &appsv1.DaemonSet{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Namespace: cluster.Namespace,
		Name:      storageDaemonSetName(cluster, record.NodeLocalPoolName),
	}, daemonSet); err != nil {
		return nil, nil, fmt.Errorf("reading exact persisted DaemonSet before replacement gate preflight: %w", err)
	}
	if string(daemonSet.UID) != record.WorkloadUID || !metav1.IsControlledBy(daemonSet, cluster) {
		return nil, nil, fmt.Errorf("current DaemonSet is not exact persisted workload UID %s", record.WorkloadUID)
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: record.NodeLocalPoolName,
		}),
	); err != nil {
		return nil, nil, fmt.Errorf("listing exact persisted DaemonSet Pods before replacement gate preflight: %w", err)
	}
	currentActorGatePresent := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != daemonSetKind || owner.UID != daemonSet.UID ||
			!nodeLocalPoolPodHasSchedulingGate(pod) {
			continue
		}
		targetsActor := pod.Spec.NodeName == record.KubernetesNodeName
		if pod.Spec.NodeName == "" {
			targets, bounded := nodeLocalPoolPodTargetNodeNames(pod)
			if !bounded {
				return nil, nil, fmt.Errorf("current gated DaemonSet Pod %s has no exact Kubernetes Node target", pod.Name)
			}
			_, targetsActor = targets[record.KubernetesNodeName]
		}
		if targetsActor {
			currentActorGatePresent = true
			break
		}
	}
	if !currentActorGatePresent {
		return nil, nil, nil
	}
	if cluster.Generation != record.ClusterGeneration {
		return nil, nil, fmt.Errorf(
			"persisted node-local-pool rollout belongs to GarageCluster generation %d, current generation is %d",
			record.ClusterGeneration, cluster.Generation,
		)
	}
	snapshot, err := r.readStorageRolloutActorSnapshot(ctx, cluster, record)
	if err != nil {
		return nil, nil, fmt.Errorf("reconstructing exact node-local-pool rollout actor before scheduling its replacement: %w", err)
	}
	if snapshot.node.Generation != record.GarageNodeGeneration {
		return nil, nil, fmt.Errorf(
			"persisted node-local-pool rollout belongs to GarageNode generation %d, current generation is %d",
			record.GarageNodeGeneration, snapshot.node.Generation,
		)
	}
	if snapshot.desiredPodSpecHash != record.DesiredPodSpecHash ||
		snapshot.desiredConfigHash != record.DesiredConfigHash {
		return nil, nil, fmt.Errorf("exact node-local-pool rollout workload no longer publishes the persisted desired revision")
	}
	if snapshot.currentPod == nil || !nodeLocalPoolPodHasSchedulingGate(snapshot.currentPod) {
		return nil, nil, nil
	}
	if string(snapshot.currentPod.UID) == record.PreviousPodUID {
		return nil, []string{fmt.Sprintf(
			"%s/%s:previous Pod %s still owns the persisted rollout actor",
			record.NodeLocalPoolName, record.KubernetesNodeName, snapshot.currentPod.Name,
		)}, nil
	}
	if snapshot.currentPod.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
		snapshot.currentPod.Annotations[annotationConfigHash] != record.DesiredConfigHash {
		return nil, nil, fmt.Errorf("gated replacement Pod %s does not publish the persisted rollout revision", snapshot.currentPod.Name)
	}
	if snapshot.kubernetesNode == nil || snapshot.kubernetesNode.UID != types.UID(record.KubernetesNodeUID) {
		return nil, nil, fmt.Errorf("exact Kubernetes Node rollout actor changed before replacement gate release")
	}
	pool := nodeLocalPoolSpecByName(cluster, record.NodeLocalPoolName)
	if pool == nil {
		return nil, nil, fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
	}
	claim, err := decodeNodeLocalPoolHostPathClaim(
		snapshot.kubernetesNode.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, record.NodeLocalPoolName)],
	)
	if err != nil {
		return nil, nil, fmt.Errorf("reading exact persisted rollout HostPath claim: %w", err)
	}
	if canonicalGarageNodeID(claim.GarageNodeID) != record.GarageNodeID ||
		canonicalGarageNodeID(snapshot.kubernetesNode.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, record.NodeLocalPoolName)]) != record.GarageNodeID {
		return nil, nil, fmt.Errorf(
			"kubernetes Node %q no longer pins the exact persisted Garage identity %s",
			record.KubernetesNodeName, shortID(record.GarageNodeID),
		)
	}
	state := &nodeLocalPoolState{
		pool:               pool,
		activationLabel:    snapshot.activationLabel,
		activationValue:    snapshot.activationValue,
		configHash:         record.DesiredConfigHash,
		desiredPodSpecHash: record.DesiredPodSpecHash,
		workloadUID:        types.UID(record.WorkloadUID),
		expectedNodeIDs: map[string]string{
			record.KubernetesNodeName: record.GarageNodeID,
		},
		desiredNodes: map[string]*corev1.Node{
			record.KubernetesNodeName: snapshot.kubernetesNode,
		},
	}
	return r.releaseNodeLocalPoolPodSchedulingGates(
		ctx, cluster, map[string]*nodeLocalPoolState{record.NodeLocalPoolName: state},
	)
}

// releaseNodeLocalPoolPodSchedulingGates is the final authorization point before
// a pool process can mount node-local HostPaths. DaemonSet Pods are created
// behind an immutable-at-creation scheduling gate. Only a Pod from the exact
// current DaemonSet UID is released, and only after live API reads prove that
// its one target Node still matches the pool, carries the workload's activation
// token and durable HostPath claim, and has no older ungated Pod that could
// mount the same disk. A create request completed by a retired DaemonSet after
// these reads keeps its gate forever, closing the controller/scheduler race.
func (r *GarageClusterReconciler) releaseNodeLocalPoolPodSchedulingGates(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	states map[string]*nodeLocalPoolState,
) ([]string, []string, error) {
	if len(states) == 0 {
		return nil, nil, nil
	}
	reader := r.nodeLocalPoolReader()
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		return nil, nil, fmt.Errorf("refreshing GarageCluster before scheduling pool Pods: %w", err)
	}
	if freshCluster.UID != cluster.UID || freshCluster.Generation != cluster.Generation ||
		!freshCluster.DeletionTimestamp.IsZero() {
		return nil, nil, fmt.Errorf("garageCluster changed before scheduling pool Pods")
	}

	freshPools := make(map[string]*garagev1beta2.NodeLocalPoolSpec)
	if freshCluster.Spec.Storage != nil {
		for i := range freshCluster.Spec.Storage.NodeLocalPools {
			pool := &freshCluster.Spec.Storage.NodeLocalPools[i]
			freshPools[pool.Name] = pool
		}
	}
	nodeLocalPoolNames := make([]string, 0, len(states))
	for nodeLocalPoolName := range states {
		nodeLocalPoolNames = append(nodeLocalPoolNames, nodeLocalPoolName)
	}
	sort.Strings(nodeLocalPoolNames)

	workloads := make(map[string]*nodeLocalPoolSchedulingGateWorkload, len(states))
	for _, nodeLocalPoolName := range nodeLocalPoolNames {
		state := states[nodeLocalPoolName]
		pool := freshPools[nodeLocalPoolName]
		if state == nil || state.pool == nil || pool == nil {
			return nil, nil, fmt.Errorf("node-local pool %q changed before scheduling its Pods", nodeLocalPoolName)
		}
		if _, err := metav1.LabelSelectorAsSelector(&pool.Selector); err != nil {
			return nil, nil, fmt.Errorf("parsing current selector for node-local pool %q: %w", nodeLocalPoolName, err)
		}
		daemonSet := &appsv1.DaemonSet{}
		key := types.NamespacedName{
			Name: storageDaemonSetName(freshCluster, nodeLocalPoolName), Namespace: freshCluster.Namespace,
		}
		if err := reader.Get(ctx, key, daemonSet); err != nil {
			return nil, nil, fmt.Errorf("reading current DaemonSet for node-local pool %q: %w", nodeLocalPoolName, err)
		}
		activationLabel := nodeLocalPoolActivationLabel(freshCluster, nodeLocalPoolName)
		activationValue := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
		if daemonSet.UID == "" || !metav1.IsControlledBy(daemonSet, freshCluster) ||
			!daemonSet.DeletionTimestamp.IsZero() || activationLabel != state.activationLabel ||
			activationValue != state.activationValue ||
			daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] != activationValue {
			return nil, nil, fmt.Errorf("node-local pool %q current workload identity changed before scheduling its Pods", nodeLocalPoolName)
		}
		if !nodeLocalPoolPodHasSchedulingGate(&corev1.Pod{Spec: daemonSet.Spec.Template.Spec}) {
			return nil, nil, fmt.Errorf("node-local pool %q current DaemonSet template has no operator scheduling gate", nodeLocalPoolName)
		}
		if state.workloadUID == "" || state.desiredPodSpecHash == "" || state.configHash == "" {
			return nil, nil, fmt.Errorf("node-local pool %q has no exact workload UID and desired revision for scheduling-gate authorization", nodeLocalPoolName)
		}
		if daemonSet.UID != state.workloadUID ||
			daemonSet.Spec.Template.Annotations[annotationPodSpecHash] != state.desiredPodSpecHash ||
			daemonSet.Spec.Template.Annotations[annotationConfigHash] != state.configHash {
			return nil, nil, fmt.Errorf("node-local pool %q workload UID or desired revision changed before scheduling its Pods", nodeLocalPoolName)
		}
		expectedHostPaths := nodeLocalPoolHostPaths(pool)
		if len(expectedHostPaths) == 0 {
			return nil, nil, fmt.Errorf("node-local pool %q has no exact HostPath set for scheduling-gate authorization", nodeLocalPoolName)
		}
		desiredNodeUIDs := make(map[string]types.UID, len(state.desiredNodes))
		for nodeName, node := range state.desiredNodes {
			if node == nil || node.Name != nodeName || node.UID == "" {
				return nil, nil, fmt.Errorf("node-local pool %q has no exact Kubernetes Node UID for desired member %q", nodeLocalPoolName, nodeName)
			}
			desiredNodeUIDs[nodeName] = node.UID
		}
		workloads[nodeLocalPoolName] = &nodeLocalPoolSchedulingGateWorkload{
			pool:                pool,
			activationLabel:     activationLabel,
			activationValue:     activationValue,
			daemonSet:           daemonSet,
			expectedWorkloadUID: state.workloadUID,
			expectedPodSpecHash: state.desiredPodSpecHash,
			expectedConfigHash:  state.configHash,
			expectedHostPaths:   expectedHostPaths,
			expectedNodeIDs:     maps.Clone(state.expectedNodeIDs),
			desiredNodeUIDs:     desiredNodeUIDs,
		}
	}

	pods := &corev1.PodList{}
	if err := reader.List(ctx, pods,
		client.InNamespace(freshCluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: freshCluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, nil, fmt.Errorf("listing scheduler-gated node-local-pool Pods: %w", err)
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	type candidate struct {
		pod               *corev1.Pod
		nodeLocalPoolName string
		nodeName          string
	}
	candidates := make([]candidate, 0)
	blocked := make([]string, 0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		workload := workloads[nodeLocalPoolName]
		if workload == nil || !isStorageDaemonSetPodForPoolUID(
			freshCluster, nodeLocalPoolName, workload.daemonSet.UID, pod,
		) {
			continue
		}
		if pod.Labels[labelStorageGroup] != storageGroupNodeLocal ||
			pod.Labels[labelAppManagedBy] != operatorName {
			blocked = append(blocked, fmt.Sprintf("%s/%s:current Pod %s has incomplete ownership labels", nodeLocalPoolName, pod.Spec.NodeName, pod.Name))
			continue
		}
		if pod.Spec.NodeName != "" {
			// Already scheduled Pods are either established members or evidence
			// considered by each pending candidate's final conflict scan.
			continue
		}
		if !pod.DeletionTimestamp.IsZero() {
			blocked = append(blocked, fmt.Sprintf("%s:current Pod %s is terminating", nodeLocalPoolName, pod.Name))
			continue
		}
		if !nodeLocalPoolPodHasSchedulingGate(pod) {
			blocked = append(blocked, fmt.Sprintf("%s:current pending Pod %s lost its scheduling gate", nodeLocalPoolName, pod.Name))
			continue
		}
		if pod.Annotations[annotationNodeLocalPoolActivationValue] != workload.activationValue ||
			pod.Spec.NodeSelector[workload.activationLabel] != workload.activationValue ||
			pod.Annotations[annotationPodSpecHash] != workload.expectedPodSpecHash ||
			pod.Annotations[annotationConfigHash] != workload.expectedConfigHash {
			blocked = append(blocked, fmt.Sprintf("%s:current Pod %s has a stale activation token", nodeLocalPoolName, pod.Name))
			continue
		}
		targets, bounded := nodeLocalPoolPodTargetNodeNames(pod)
		if !bounded || len(targets) != 1 {
			blocked = append(blocked, fmt.Sprintf("%s:current Pod %s has no exact Kubernetes Node target", nodeLocalPoolName, pod.Name))
			continue
		}
		for nodeName := range targets {
			if _, desired := workload.desiredNodeUIDs[nodeName]; !desired {
				continue
			}
			candidates = append(candidates, candidate{pod: pod.DeepCopy(), nodeLocalPoolName: nodeLocalPoolName, nodeName: nodeName})
		}
	}

	released := make([]string, 0, len(candidates))
	for _, item := range candidates {
		workload := workloads[item.nodeLocalPoolName]
		freshPod := &corev1.Pod{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(item.pod), freshPod); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, nil, fmt.Errorf("refreshing node-local pool Pod %s/%s: %w", item.pod.Namespace, item.pod.Name, err)
		}
		if freshPod.UID != item.pod.UID || !freshPod.DeletionTimestamp.IsZero() || freshPod.Spec.NodeName != "" ||
			!nodeLocalPoolPodHasSchedulingGate(freshPod) ||
			!isStorageDaemonSetPodForPoolUID(freshCluster, item.nodeLocalPoolName, workload.daemonSet.UID, freshPod) ||
			freshPod.Annotations[annotationNodeLocalPoolActivationValue] != workload.activationValue ||
			freshPod.Spec.NodeSelector[workload.activationLabel] != workload.activationValue ||
			freshPod.Annotations[annotationPodSpecHash] != workload.expectedPodSpecHash ||
			freshPod.Annotations[annotationConfigHash] != workload.expectedConfigHash {
			blocked = append(blocked, fmt.Sprintf("%s/%s:current Pod %s changed before gate release", item.nodeLocalPoolName, item.nodeName, item.pod.Name))
			continue
		}
		targets, bounded := nodeLocalPoolPodTargetNodeNames(freshPod)
		if _, exact := targets[item.nodeName]; !bounded || !exact || len(targets) != 1 {
			blocked = append(blocked, fmt.Sprintf("%s/%s:current Pod %s lost its exact Node target", item.nodeLocalPoolName, item.nodeName, item.pod.Name))
			continue
		}

		// Re-list immediately before the Pod patch. Any retired DaemonSet Pod
		// created after this list is still safe: every template carries the same
		// scheduler-enforced gate, and this function never releases an old UID.
		livePods := &corev1.PodList{}
		if err := reader.List(ctx, livePods,
			client.InNamespace(freshCluster.Namespace),
			client.MatchingLabels(map[string]string{labelCluster: freshCluster.Name, labelTier: tierStorage}),
		); err != nil {
			return nil, nil, fmt.Errorf("rechecking node-local-pool Pods before releasing %s/%s: %w", item.nodeLocalPoolName, item.nodeName, err)
		}
		conflict := ""
		for i := range livePods.Items {
			other := &livePods.Items[i]
			if other.UID == freshPod.UID || other.Labels[labelNodeLocalPool] == "" ||
				other.Labels[labelStorageGroup] != storageGroupNodeLocal ||
				other.Labels[labelAppManagedBy] != operatorName {
				continue
			}
			otherTargets, otherBounded := nodeLocalPoolPodTargetNodeNames(other)
			if !otherBounded {
				conflict = other.Name + " has no exact Node target"
				break
			}
			if _, targetsSameNode := otherTargets[item.nodeName]; !targetsSameNode {
				continue
			}
			if other.Spec.NodeName != "" || !nodeLocalPoolPodHasSchedulingGate(other) {
				conflict = other.Name
				break
			}
		}
		if conflict != "" {
			blocked = append(blocked, fmt.Sprintf("%s/%s:%s", item.nodeLocalPoolName, item.nodeName, conflict))
			continue
		}

		// The persisted rollout snapshot and the first shared read are only
		// preconditions. Repeat every mutable workload and durable-identity check
		// at the one authorization point immediately before removing the gate.
		finalCluster := &garagev1beta2.GarageCluster{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(freshCluster), finalCluster); err != nil {
			return nil, nil, fmt.Errorf("rechecking GarageCluster before releasing node-local pool %q gate: %w", item.nodeLocalPoolName, err)
		}
		if finalCluster.UID != freshCluster.UID || finalCluster.Generation != freshCluster.Generation ||
			!finalCluster.DeletionTimestamp.IsZero() {
			blocked = append(blocked, fmt.Sprintf("%s/%s:GarageCluster generation or lifetime changed", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		finalPool := nodeLocalPoolSpecByName(finalCluster, item.nodeLocalPoolName)
		if finalPool == nil || !equality.Semantic.DeepEqual(finalPool.Selector, workload.pool.Selector) {
			blocked = append(blocked, fmt.Sprintf("%s/%s:node-local pool selector changed", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		finalSelector, err := metav1.LabelSelectorAsSelector(&finalPool.Selector)
		if err != nil {
			blocked = append(blocked, fmt.Sprintf("%s/%s:node-local pool selector is invalid", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		finalHostPaths := nodeLocalPoolHostPaths(finalPool)
		if !equality.Semantic.DeepEqual(finalHostPaths, workload.expectedHostPaths) {
			blocked = append(blocked, fmt.Sprintf("%s/%s:node-local pool HostPaths changed", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		finalDaemonSet := &appsv1.DaemonSet{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(workload.daemonSet), finalDaemonSet); err != nil {
			return nil, nil, fmt.Errorf("rechecking current DaemonSet for node-local pool %q before gate release: %w", item.nodeLocalPoolName, err)
		}
		if finalDaemonSet.UID != workload.expectedWorkloadUID ||
			!metav1.IsControlledBy(finalDaemonSet, finalCluster) ||
			!finalDaemonSet.DeletionTimestamp.IsZero() ||
			finalDaemonSet.Spec.Template.Spec.NodeSelector[workload.activationLabel] != workload.activationValue ||
			!nodeLocalPoolPodHasSchedulingGate(&corev1.Pod{Spec: finalDaemonSet.Spec.Template.Spec}) ||
			finalDaemonSet.Spec.Template.Annotations[annotationPodSpecHash] != workload.expectedPodSpecHash ||
			finalDaemonSet.Spec.Template.Annotations[annotationConfigHash] != workload.expectedConfigHash {
			blocked = append(blocked, fmt.Sprintf("%s/%s:DaemonSet UID or desired revision changed", item.nodeLocalPoolName, item.nodeName))
			continue
		}

		node := &corev1.Node{}
		if err := reader.Get(ctx, types.NamespacedName{Name: item.nodeName}, node); err != nil {
			return nil, nil, fmt.Errorf("refreshing Kubernetes Node %q before releasing node-local pool %q Pod: %w", item.nodeName, item.nodeLocalPoolName, err)
		}
		if node.UID != workload.desiredNodeUIDs[item.nodeName] ||
			!finalSelector.Matches(labels.Set(node.Labels)) ||
			node.Labels[workload.activationLabel] != workload.activationValue {
			blocked = append(blocked, fmt.Sprintf("%s/%s:Node UID, selector, or activation token changed", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		claim, err := decodeNodeLocalPoolHostPathClaim(
			node.Annotations[nodeLocalPoolHostPathClaimAnnotation(finalCluster, item.nodeLocalPoolName)],
		)
		if err != nil || claim.Retiring ||
			claim.ClusterNamespace != finalCluster.Namespace || claim.ClusterName != finalCluster.Name ||
			claim.NodeLocalPoolName != item.nodeLocalPoolName ||
			!equality.Semantic.DeepEqual(claim.HostPaths, finalHostPaths) {
			blocked = append(blocked, fmt.Sprintf("%s/%s:Node has no exact non-retiring HostPath claim", item.nodeLocalPoolName, item.nodeName))
			continue
		}
		claimNodeID := canonicalGarageNodeID(claim.GarageNodeID)
		recoveryNodeID := canonicalGarageNodeID(
			node.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(finalCluster, item.nodeLocalPoolName)],
		)
		if claimNodeID != "" || recoveryNodeID != "" {
			if !isValidGarageNodeID(claimNodeID) || !isValidGarageNodeID(recoveryNodeID) || claimNodeID != recoveryNodeID {
				blocked = append(blocked, fmt.Sprintf("%s/%s:Node HostPath claim and recovery identity disagree", item.nodeLocalPoolName, item.nodeName))
				continue
			}
		}
		if expectedNodeID, pinned := workload.expectedNodeIDs[item.nodeName]; pinned &&
			(claimNodeID != expectedNodeID || recoveryNodeID != expectedNodeID) {
			blocked = append(blocked, fmt.Sprintf("%s/%s:Node no longer pins the exact persisted Garage identity", item.nodeLocalPoolName, item.nodeName))
			continue
		}

		before := freshPod.DeepCopy()
		removeNodeLocalPoolPodSchedulingGate(freshPod)
		if err := r.Patch(ctx, freshPod, client.MergeFromWithOptions(
			before, client.MergeFromWithOptimisticLock{},
		)); err != nil {
			return nil, nil, fmt.Errorf("releasing node-local pool Pod %s/%s scheduling gate: %w", freshPod.Namespace, freshPod.Name, err)
		}
		released = append(released, item.nodeLocalPoolName+"/"+item.nodeName)
	}
	sort.Strings(released)
	sort.Strings(blocked)
	return released, blocked, nil
}

func nodeLocalPoolMembershipFenceTarget(nodeNames []string) string {
	nodeNames = append([]string(nil), nodeNames...)
	sort.Strings(nodeNames)
	sum := sha256.Sum256([]byte(strings.Join(nodeNames, "\x00")))
	return fmt.Sprintf("%x", sum[:16])
}

func nodeLocalPoolMembershipActivationValue(daemonSet *appsv1.DaemonSet, target string) string {
	current := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
	sum := sha256.Sum256([]byte(string(daemonSet.UID) + "\x00" + current + "\x00" + target))
	return "membership-" + fmt.Sprintf("%x", sum[:16])
}

// ensureNodeLocalPoolMembershipFenceObserved rotates an active pool to a token
// the retiring Node has never carried. Once the DaemonSet reports that exact
// generation observed, every old-token create request has completed and is
// visible in the API; new-template Pods can only target surviving Nodes that
// later receive the new token. This turns an otherwise unobservable
// DaemonSet-controller/scheduler race into a deterministic cleanup barrier.
func (r *GarageClusterReconciler) ensureNodeLocalPoolMembershipFenceObserved(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
	nodeNames []string,
) (string, bool, error) {
	if len(nodeNames) == 0 {
		return "", false, nil
	}
	daemonSet := &appsv1.DaemonSet{}
	key := types.NamespacedName{Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: cluster.Namespace}
	if err := r.nodeLocalPoolReader().Get(ctx, key, daemonSet); err != nil {
		if errors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading node-local pool %q membership fence: %w", nodeLocalPoolName, err)
	}
	if !metav1.IsControlledBy(daemonSet, cluster) {
		return "", false, fmt.Errorf("refusing to rotate unowned node-local pool DaemonSet %s", key)
	}
	target := nodeLocalPoolMembershipFenceTarget(nodeNames)
	if daemonSet.Annotations[annotationNodeLocalPoolMembershipFence] != target {
		activationLabel := nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName)
		activationValue := nodeLocalPoolMembershipActivationValue(daemonSet, target)
		if daemonSet.Spec.Template.Spec.NodeSelector == nil {
			daemonSet.Spec.Template.Spec.NodeSelector = make(map[string]string)
		}
		if daemonSet.Annotations == nil {
			daemonSet.Annotations = make(map[string]string)
		}
		if daemonSet.Spec.Template.Annotations == nil {
			daemonSet.Spec.Template.Annotations = make(map[string]string)
		}
		daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] = activationValue
		daemonSet.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
		daemonSet.Annotations[annotationNodeLocalPoolMembershipFence] = target
		daemonSet.Spec.Template.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
		if err := r.Update(ctx, daemonSet); err != nil {
			return "", false, fmt.Errorf("rotating node-local pool %q membership fence: %w", nodeLocalPoolName, err)
		}
		return activationValue, true, nil
	}
	return nodeLocalPoolActivationValueForDaemonSet(daemonSet),
		daemonSet.Status.ObservedGeneration < daemonSet.Generation, nil
}

// migrateNodeLocalPoolMembershipActivation moves an already-authorized member
// to a DaemonSet membership token without creating a new storage process. The
// durable, non-retiring HostPath claim and the old activation label must both
// exist. This narrower CAS is allowed during terminal drain preparation: it
// keeps surviving members schedulable while the retiring member is fenced.
func (r *GarageClusterReconciler) migrateNodeLocalPoolMembershipActivation(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	nodeName, labelKey, labelValue string,
) (bool, error) {
	if cluster == nil || pool == nil || nodeName == "" || labelKey == "" || labelValue == "" {
		return false, fmt.Errorf("node-local-pool membership migration requires an exact cluster, pool, Node, label, and token")
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		return false, fmt.Errorf("refreshing GarageCluster before node-local-pool membership migration: %w", err)
	}
	if freshCluster.UID != cluster.UID || freshCluster.Generation != cluster.Generation || !freshCluster.DeletionTimestamp.IsZero() {
		return false, fmt.Errorf("garageCluster changed before node-local-pool membership migration")
	}
	var freshPool *garagev1beta2.NodeLocalPoolSpec
	if freshCluster.Spec.Storage != nil {
		for i := range freshCluster.Spec.Storage.NodeLocalPools {
			if freshCluster.Spec.Storage.NodeLocalPools[i].Name == pool.Name {
				freshPool = &freshCluster.Spec.Storage.NodeLocalPools[i]
				break
			}
		}
	}
	if freshPool == nil {
		return false, fmt.Errorf("node-local pool %q disappeared before membership migration", pool.Name)
	}
	node := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return false, fmt.Errorf("refreshing Kubernetes Node %q before node-local-pool membership migration: %w", nodeName, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&freshPool.Selector)
	if err != nil {
		return false, fmt.Errorf("parsing current selector for node-local pool %q: %w", freshPool.Name, err)
	}
	if !selector.Matches(labels.Set(node.Labels)) {
		return false, fmt.Errorf("kubernetes node %q stopped matching node-local pool %q before membership migration", nodeName, freshPool.Name)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(freshCluster, freshPool.Name)
	claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[claimKey])
	if err != nil {
		return false, fmt.Errorf("kubernetes node %q has no valid HostPath claim for surviving node-local pool %q: %w", nodeName, freshPool.Name, err)
	}
	if claim.Retiring || !nodeLocalPoolHostPathClaimCanTransition(
		claim, freshCluster, freshPool.Name, nodeLocalPoolHostPaths(freshPool),
	) {
		return false, fmt.Errorf("kubernetes node %q does not carry the exact non-retiring HostPath claim for surviving node-local pool %q", nodeName, freshPool.Name)
	}
	current := node.Labels[labelKey]
	if current == labelValue {
		return false, nil
	}
	if current == "" || current == nodeLocalPoolActivationFenceValue || current == nodeLocalPoolActivationQuarantineValue {
		return false, fmt.Errorf("kubernetes node %q has no established active token for surviving node-local pool %q", nodeName, freshPool.Name)
	}
	node.Labels[labelKey] = labelValue
	if err := r.Update(ctx, node); err != nil {
		return false, fmt.Errorf("migrating node-local pool %q membership token on Kubernetes Node %q by resourceVersion CAS: %w", freshPool.Name, nodeName, err)
	}
	return true, nil
}
