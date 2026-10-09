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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// holdOutOfService stops exactly one selected node-local process without
// removing its positive-capacity Garage role. Garage rejects a layout with
// fewer storage roles than replication.factor, so ordinary retirement cannot
// implement a service hold when the node count equals the factor. The durable
// HostPath claim and GarageNode remain in place for same-identity recovery.
func (t *nodeLocalPoolLifecycleTransition) holdOutOfService() nodeLocalPoolLifecyclePhaseResult {
	request := strings.TrimSpace(t.cluster.Annotations[AnnotationNodeLocalOutOfService])
	if request == "" {
		return nodeLocalPoolPhaseContinue()
	}
	r := t.reconciler
	stop := func(reason, message string) nodeLocalPoolLifecyclePhaseResult {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(
			t.ctx, t.cluster, metav1.ConditionFalse, reason, message))
	}
	poolName, nodeName, valid := garagev1beta2.ParseNodeLocalOutOfServiceAnnotation(request)
	if !valid {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("%s must name one selected pool and Kubernetes Node as pool/node", AnnotationNodeLocalOutOfService))
	}
	if strings.TrimSpace(t.cluster.Annotations[AnnotationNodeLocalReplaceIdentity]) != "" {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("%s and %s cannot run together", AnnotationNodeLocalOutOfService, AnnotationNodeLocalReplaceIdentity))
	}
	state := t.states[poolName]
	if state == nil || state.desiredNodes[nodeName] == nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("%s names %s, which is not selected by a declared node-local pool", AnnotationNodeLocalOutOfService, request))
	}
	if len(t.cluster.Spec.RemoteClusters) != 0 || t.cluster.Spec.ConnectTo != nil || t.cluster.IsLayoutFollower() {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			"node-local service hold currently requires a single-site Garage layout")
	}
	var source *garagev1beta1.GarageNode
	for _, candidate := range t.existing {
		if candidate.Spec.NodeLocalPoolName == poolName && candidate.Spec.KubernetesNodeName == nodeName {
			source = candidate
			break
		}
	}
	if source == nil || source.Status.NodeID == "" || !source.DeletionTimestamp.IsZero() {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("waiting for the retained GarageNode identity for %s before taking storage out of service", request))
	}
	// The layout mutex serializes two rapid annotation changes with every
	// layout writer. Re-read both intent and Node labels under the mutex.
	release, err := acquireLayoutMutation(r.layoutMutationCoordinator(), t.cluster)
	if err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, err.Error())
	}
	defer release()
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(t.ctx, client.ObjectKeyFromObject(t.cluster), freshCluster); err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("refreshing GarageCluster before node-local service hold: %w", err))
	}
	if freshCluster.UID != t.cluster.UID || freshCluster.Generation != t.cluster.Generation ||
		freshCluster.Annotations[AnnotationNodeLocalOutOfService] != request ||
		!freshCluster.DeletionTimestamp.IsZero() || freshCluster.Status.StorageDrain != nil ||
		factorMigrationActive(freshCluster) || storageRolloutMutationBoundaryActive(freshCluster) {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			"node-local service hold intent or another storage transition changed; waiting for a fresh reconcile")
	}
	node := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(t.ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("refreshing Kubernetes Node %q before service hold: %w", nodeName, err))
	}
	if node.DeletionTimestamp != nil || node.UID != state.desiredNodes[nodeName].UID {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("Kubernetes Node %q changed before its service hold; waiting for a fresh reconcile", nodeName))
	}
	freshSource := &garagev1beta1.GarageNode{}
	if err := r.nodeLocalPoolReader().Get(t.ctx, client.ObjectKeyFromObject(source), freshSource); err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("refreshing GarageNode %s before service hold: %w", source.Name, err))
	}
	if freshSource.UID != source.UID || freshSource.Status.NodeID != source.Status.NodeID ||
		!freshSource.DeletionTimestamp.IsZero() {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("GarageNode %s changed during its service hold", source.Name))
	}
	claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[nodeLocalPoolHostPathClaimAnnotation(freshCluster, poolName)])
	if err != nil || claim.Retiring || canonicalGarageNodeID(claim.GarageNodeID) != canonicalGarageNodeID(source.Status.NodeID) {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("node-local pool %s on Kubernetes Node %s has no matching active HostPath identity claim", poolName, nodeName))
	}
	if node.Labels[state.activationLabel] == "" {
		pods := &corev1.PodList{}
		if err := r.nodeLocalPoolReader().List(t.ctx, pods, client.InNamespace(freshCluster.Namespace),
			client.MatchingLabels(map[string]string{labelCluster: freshCluster.Name, labelNodeLocalPool: poolName})); err != nil {
			return nodeLocalPoolPhaseFail(fmt.Errorf("listing Pods during node-local service hold: %w", err))
		}
		for i := range pods.Items {
			if pods.Items[i].Spec.NodeName == nodeName {
				return stop(garagev1beta1.ReasonNodeLocalPoolStopping,
					fmt.Sprintf("waiting for node-local pool %s Pod %s on Kubernetes Node %s to terminate before servicing its disk", poolName, pods.Items[i].Name, nodeName))
			}
		}
		// Keep the hold in place and let the rest of the lifecycle run so
		// surviving members can stay current. projectReadiness reports
		// OutOfService until the request is removed.
		return nodeLocalPoolPhaseContinue()
	}
	if !freshSource.Status.Connected || !freshSource.Status.InLayout || freshSource.Status.ObservedGeneration < freshSource.Generation {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("GarageNode %s is not settled before its Pod can stop", source.Name))
	}
	deployed := &appsv1.DaemonSet{}
	if err := r.nodeLocalPoolReader().Get(t.ctx, types.NamespacedName{
		Namespace: freshCluster.Namespace, Name: storageDaemonSetName(freshCluster, poolName),
	}, deployed); err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, fmt.Sprintf("reading current node-local DaemonSet: %v", err))
	}
	if !metav1.IsControlledBy(deployed, freshCluster) ||
		node.Labels[state.activationLabel] != nodeLocalPoolActivationValueForDaemonSet(deployed) ||
		deployed.Spec.Template.Spec.NodeSelector[state.activationLabel] != node.Labels[state.activationLabel] {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("node-local pool %s on Kubernetes Node %s has no matching current DaemonSet activation", poolName, nodeName))
	}
	// A stale FullyReplicated=True status alone is insufficient. Read all
	// selected Nodes again, and require every other managed role active so a
	// second service hold cannot start during the first Pod's shutdown window.
	membership, err := r.readNodeLocalPoolMembership(t.ctx, freshCluster)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if membership.desiredNodesByPool[poolName][nodeName] == nil ||
		membership.desiredNodesByPool[poolName][nodeName].UID != node.UID || len(membership.selectorConflicts) > 0 {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			"node-local pool selector or Kubernetes Node labels changed before the service hold")
	}
	for pool, nodes := range membership.desiredNodesByPool {
		otherDeployed := &appsv1.DaemonSet{}
		if err := r.nodeLocalPoolReader().Get(t.ctx, types.NamespacedName{
			Namespace: freshCluster.Namespace, Name: storageDaemonSetName(freshCluster, pool),
		}, otherDeployed); err != nil {
			return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
				fmt.Sprintf("reading node-local DaemonSet for pool %s: %v", pool, err))
		}
		activeValue := nodeLocalPoolActivationValueForDaemonSet(otherDeployed)
		for name, other := range nodes {
			if pool == poolName && name == nodeName {
				continue
			}
			if other.Labels[nodeLocalPoolActivationLabel(freshCluster, pool)] != activeValue {
				return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
					fmt.Sprintf("another node-local member %s/%s is not active; refusing a second service hold", pool, name))
			}
		}
	}
	proof := meta.FindStatusCondition(freshCluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated)
	if proof == nil || proof.Status != metav1.ConditionTrue ||
		proof.Reason != garagev1beta1.ReasonRedundancyVerified || proof.ObservedGeneration != freshCluster.Generation {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			"a current FullyReplicated=True/Verified proof is required before stopping a node-local storage Pod")
	}
	if err := requireConsistentStorageDrain(freshCluster); err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, err.Error())
	}
	if _, err := requireStorageDrainStartReady(freshCluster); err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, err.Error())
	}
	ready, _, message, err := r.clusterLayoutReadyForMutation(t.ctx, freshCluster, false)
	if err != nil || !ready {
		if err != nil {
			message = err.Error()
		}
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, message)
	}
	layout, err := r.getNodeLocalPoolCommittedLayout(t.ctx, freshCluster)
	if err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, err.Error())
	}
	committed := false
	if layout != nil {
		for _, role := range layout.Roles {
			if canonicalGarageNodeID(role.ID) == canonicalGarageNodeID(source.Status.NodeID) &&
				role.Capacity != nil && *role.Capacity > 0 {
				committed = true
				break
			}
		}
	}
	if !committed {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("GarageNode %s has no positive-capacity role in the committed layout", source.Name))
	}
	if err := r.requireLiveNodeLocalServiceHoldHealth(t.ctx, freshCluster); err != nil {
		return stop(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, err.Error())
	}
	delete(node.Labels, state.activationLabel)
	if err := r.Update(t.ctx, node); err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("stopping node-local pool %s on Kubernetes Node %s by resourceVersion CAS: %w", poolName, nodeName, err))
	}
	return stop(garagev1beta1.ReasonNodeLocalPoolStopping,
		fmt.Sprintf("stopping node-local pool %s on Kubernetes Node %s; wait for its Pod to terminate before servicing its disk", poolName, nodeName))
}

func (r *GarageClusterReconciler) requireLiveNodeLocalServiceHoldHealth(
	ctx context.Context, cluster *garagev1beta2.GarageCluster,
) error {
	if r.nodeLocalServiceHoldHealthCheck != nil {
		return r.nodeLocalServiceHoldHealthCheck(ctx, cluster)
	}
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return fmt.Errorf("creating Garage Admin client before node-local service hold: %w", err)
	}
	return requireLiveStorageDrainHealth(ctx, garageClient, r.clusterHealthGetter)
}

func nodeLocalServiceHoldTarget(cluster *garagev1beta2.GarageCluster) (poolName, nodeName string, ok bool) {
	if cluster == nil {
		return "", "", false
	}
	return garagev1beta2.ParseNodeLocalOutOfServiceAnnotation(cluster.Annotations[AnnotationNodeLocalOutOfService])
}
