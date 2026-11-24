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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// reconcileNodeLocalPoolRollout implements a cluster-wide OnDelete rollout. Updating
// multiple ordinary DaemonSets would otherwise let every singleton pool stop at
// once. We replace one pod in the entire GarageCluster, then wait for a Ready
// pod, the same (or safely replaced) Garage identity, live connectivity, layout
// membership, and settled history before deleting another.
func (r *GarageClusterReconciler) reconcileNodeLocalPoolRollout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	states map[string]*nodeLocalPoolState,
	existingByPair map[string]*garagev1beta1.GarageNode,
) (bool, string, error) {
	type rolloutMember struct {
		nodeLocalPoolName         string
		nodeName                  string
		garageNodeName            string
		workloadUID               types.UID
		kubernetesNodeUID         types.UID
		desiredPodSpecHash        string
		desiredConfigHash         string
		persistentVolumeClaims    []garagev1beta2.StorageRolloutPersistentVolumeClaimStatus
		statefulSetRecreationSafe bool
		pod                       *corev1.Pod
		node                      *garagev1beta1.GarageNode
	}

	nodeLocalPoolNames := make([]string, 0, len(states))
	for nodeLocalPoolName := range states {
		nodeLocalPoolNames = append(nodeLocalPoolNames, nodeLocalPoolName)
	}
	sort.Strings(nodeLocalPoolNames)
	var allMembers []rolloutMember
	var outdated []rolloutMember
	for _, nodeLocalPoolName := range nodeLocalPoolNames {
		state := states[nodeLocalPoolName]
		if state.desiredPodSpecHash == "" || state.configHash == "" {
			return false, "", fmt.Errorf("node-local pool %q workload template is missing exact desired pod/config revision hashes", nodeLocalPoolName)
		}
		for _, nodeName := range sortedNodeNames(state.desiredNodes) {
			node := existingByPair[nodeLocalPoolKey(nodeLocalPoolName, nodeName)]
			if state.desiredNodes[nodeName] == nil || state.desiredNodes[nodeName].UID == "" {
				return false, fmt.Sprintf("waiting for exact Kubernetes Node UID for node-local pool %q actor %q; acknowledge the GarageNode's exact lost source if that Node is permanently gone", nodeLocalPoolName, nodeName), nil
			}
			if terminating := state.terminatingPods[nodeName]; terminating != nil {
				return false, fmt.Sprintf("waiting for node-local-pool pod %s to terminate before continuing the cluster-wide rollout", terminating.Name), nil
			}
			pod := state.activePods[nodeName]
			if pod == nil {
				return false, fmt.Sprintf("waiting for node-local pool %q pod on Kubernetes Node %q", nodeLocalPoolName, nodeName), nil
			}
			if !podReady(pod) {
				return false, fmt.Sprintf("waiting for node-local-pool pod %s to become Ready before continuing the cluster-wide rollout", pod.Name), nil
			}
			if !garageNodeLayoutReadyForPod(node, pod) {
				return false, fmt.Sprintf("waiting for GarageNode for node-local pool %q on Kubernetes Node %q to rediscover pod %s and report that identity Connected and InLayout", nodeLocalPoolName, nodeName, pod.Name), nil
			}
			owner := metav1.GetControllerOf(pod)
			if owner == nil || owner.Kind != daemonSetKind || owner.UID == "" {
				return false, fmt.Sprintf("waiting for node-local-pool pod %s to be controlled by its exact DaemonSet", pod.Name), nil
			}
			member := rolloutMember{
				nodeLocalPoolName: nodeLocalPoolName, nodeName: nodeName,
				workloadUID:        owner.UID,
				kubernetesNodeUID:  state.desiredNodes[nodeName].UID,
				desiredPodSpecHash: state.desiredPodSpecHash,
				desiredConfigHash:  state.configHash,
				pod:                pod, node: node,
			}
			allMembers = append(allMembers, member)
			if pod.Annotations[annotationPodSpecHash] != state.desiredPodSpecHash ||
				pod.Annotations[annotationConfigHash] != state.configHash {
				outdated = append(outdated, member)
			}
		}
	}

	// GarageNode-owned StatefulSets in a mixed cluster use OnDelete too. This
	// includes operator-managed default PVC nodes, user-managed/SMB nodes, and
	// unified gateway nodes, so a shared config/image edit cannot stop them in
	// parallel with node-local-pool identities.
	garageNodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, garageNodes, client.InNamespace(cluster.Namespace)); err != nil {
		return false, "", fmt.Errorf("listing GarageNodes for mixed-storage rollout: %w", err)
	}
	sort.Slice(garageNodes.Items, func(i, j int) bool { return garageNodes.Items[i].Name < garageNodes.Items[j].Name })
	for i := range garageNodes.Items {
		node := &garageNodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			isNodeLocalPoolBacked(node) ||
			node.Spec.External != nil || !node.DeletionTimestamp.IsZero() {
			continue
		}
		// #544: drain/suspended nodes already out of the layout must not block
		// StorageRolloutReady; otherwise DrainPrepared can never start.
		if garageNodeExemptFromAdminAndRolloutProof(node) {
			continue
		}
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Name: node.Name, Namespace: cluster.Namespace,
		}, statefulSet); err != nil {
			if errors.IsNotFound(err) {
				return false, fmt.Sprintf("waiting for GarageNode %s to recreate its StatefulSet during the cluster-wide rollout", node.Name), nil
			}
			return false, "", fmt.Errorf("reading GarageNode StatefulSet %s: %w", node.Name, err)
		}
		if !metav1.IsControlledBy(statefulSet, node) {
			return false, "", fmt.Errorf("StatefulSet %s is not controlled by GarageNode %s", statefulSet.Name, node.Name)
		}
		// A pre-upgrade StatefulSet may already be replacing or terminating its
		// pod under RollingUpdate. Treat the entire cluster rollout as waiting
		// until the GarageNode controller atomically converts this workload to
		// OnDelete; skipping it could let the parent stop a second identity.
		if statefulSet.Spec.UpdateStrategy.Type != appsv1.OnDeleteStatefulSetStrategyType {
			return false, fmt.Sprintf("waiting for GarageNode %s to convert its legacy StatefulSet update strategy to OnDelete before the cluster-wide rollout", node.Name), nil
		}
		desiredPodSpecHash := statefulSet.Spec.Template.Annotations[annotationPodSpecHash]
		desiredConfigHash := statefulSet.Spec.Template.Annotations[annotationConfigHash]
		if desiredPodSpecHash == "" || desiredConfigHash == "" {
			return false, "", fmt.Errorf("garageNode StatefulSet %s is missing exact desired pod/config revision hashes", statefulSet.Name)
		}
		expectedInput := storageRolloutInputToken(cluster, node, desiredPodSpecHash, desiredConfigHash)
		if expectedInput == "" || statefulSet.Annotations[annotationStorageRolloutInput] != expectedInput {
			return false, fmt.Sprintf("waiting for GarageNode %s to publish its exact cluster/node generation and template revision acknowledgment before evaluating the StatefulSet rollout", node.Name), nil
		}
		configName, configSecretBacked, mountErr := mountedGarageConfigResource(statefulSet.Spec.Template.Spec)
		if mountErr != nil {
			return false, "", fmt.Errorf("reading GarageNode %s desired config mount: %w", node.Name, mountErr)
		}
		if configSecretBacked != garageConfigUsesSecret(cluster) {
			return false, "", fmt.Errorf("garageNode %s desired template mounts the wrong config resource kind", node.Name)
		}
		config, _, err := readGarageConfigResource(
			ctx, r.nodeLocalPoolReader(), cluster.Namespace, configName, configSecretBacked,
		)
		if err != nil {
			return false, fmt.Sprintf("waiting to read exact Garage config resource %s for GarageNode %s before evaluating its rollout: %v", configName, node.Name, err), nil
		}
		configBaseName := cluster.Name + "-config"
		if nodeHasConfigOverrides(node) {
			configBaseName = garageNodeConfigBaseName(cluster, node)
		}
		configRevision, err := garageConfigRevision(ctx, r.nodeLocalPoolReader(), cluster, config)
		if err != nil {
			return false, "", fmt.Errorf("deriving GarageNode %s mounted config revision: %w", node.Name, err)
		}
		if expectedName := garageConfigRevisionName(configBaseName, configRevision); configName != expectedName {
			return false, "", fmt.Errorf("garageNode %s desired template mounts config resource %s, expected immutable revision %s", node.Name, configName, expectedName)
		}
		liveConfigHash, err := garageConfigAnnotationRevision(ctx, r.nodeLocalPoolReader(), cluster, config)
		if err != nil {
			return false, "", fmt.Errorf("deriving GarageNode %s mounted config annotation revision: %w", node.Name, err)
		}
		if liveConfigHash != desiredConfigHash {
			return false, fmt.Sprintf("waiting for GarageNode %s StatefulSet to acknowledge live config resource %s revision %s (template still has %s)", node.Name, configName, liveConfigHash, desiredConfigHash), nil
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Name: node.Name + "-0", Namespace: cluster.Namespace,
		}, pod); err != nil {
			if errors.IsNotFound(err) {
				return false, fmt.Sprintf("waiting for pod for GarageNode %s during the cluster-wide rollout", node.Name), nil
			}
			return false, "", fmt.Errorf("reading GarageNode pod %s-0: %w", node.Name, err)
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
			return false, fmt.Sprintf("waiting for GarageNode pod %s to be adopted by its current StatefulSet", pod.Name), nil
		}
		if !pod.DeletionTimestamp.IsZero() {
			return false, fmt.Sprintf("waiting for GarageNode pod %s to terminate during the cluster-wide rollout", pod.Name), nil
		}
		if !garageNodeLayoutReadyForPod(node, pod) {
			return false, fmt.Sprintf("waiting for GarageNode %s to observe its exact Ready pod identity during the cluster-wide rollout", node.Name), nil
		}
		member := rolloutMember{
			garageNodeName: node.Name, workloadUID: statefulSet.UID,
			desiredPodSpecHash:        desiredPodSpecHash,
			desiredConfigHash:         desiredConfigHash,
			statefulSetRecreationSafe: statefulSetWorkloadRecreationSafe(statefulSet),
			pod:                       pod, node: node,
		}
		allMembers = append(allMembers, member)
		if pod.Annotations[annotationPodSpecHash] != desiredPodSpecHash ||
			pod.Annotations[annotationConfigHash] != desiredConfigHash {
			outdated = append(outdated, member)
		}
	}
	if len(outdated) == 0 {
		return true, "", nil
	}
	candidate := outdated[0]

	// Share the same coordinator as every layout writer. A pod deletion is not
	// itself a layout mutation, but it must not take an identity offline between
	// another writer's history check and Apply.
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return false, "waiting to resolve the canonical Garage layout owner before a managed Pod handoff: " + err.Error(), nil
	}
	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(
		r.layoutMutationCoordinator(),
		layoutOwner,
	)
	if err != nil {
		return false, "waiting to roll a node-local-pool pod while another Garage layout mutation owns the cluster", nil
	}
	defer release()
	liveCluster := &garagev1beta2.GarageCluster{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(cluster), liveCluster); err != nil {
		return false, "waiting to re-read GarageCluster under the storage rollout coordinator: " + err.Error(), nil
	}
	if liveCluster.UID != cluster.UID || liveCluster.Generation != cluster.Generation ||
		liveCluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout] != cluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout] {
		return false, "GarageCluster generation or recovery request changed while acquiring the storage rollout coordinator; re-evaluating desired publications", nil
	}

	// Re-list and re-read every member only after exclusivity is held. A Manual
	// GarageNode delete or an involuntary pod replacement can race the earlier
	// informer snapshot; starting a second outage from that stale view would
	// violate the one-member-at-a-time contract.
	expectedGarageNodes := make(map[string]struct{}, len(allMembers))
	for i := range allMembers {
		expectedGarageNodes[allMembers[i].node.Name] = struct{}{}
	}
	freshGarageNodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, freshGarageNodes, client.InNamespace(cluster.Namespace)); err != nil {
		return false, "waiting to re-list managed GarageNodes under the storage rollout coordinator: " + err.Error(), nil
	}
	for i := range freshGarageNodes.Items {
		node := &freshGarageNodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			node.Spec.External != nil {
			continue
		}
		if !node.DeletionTimestamp.IsZero() {
			return false, fmt.Sprintf("refusing to replace a managed pod while GarageNode %s is deleting", node.Name), nil
		}
		if _, expected := expectedGarageNodes[node.Name]; !expected {
			return false, fmt.Sprintf("waiting for newly observed GarageNode %s to settle before replacing another managed pod", node.Name), nil
		}
	}
	for i := range allMembers {
		member := &allMembers[i]
		freshNode := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(member.node), freshNode); err != nil {
			return false, fmt.Sprintf("waiting to re-read GarageNode %s under the storage rollout coordinator: %v", member.node.Name, err), nil
		}
		freshPod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(member.pod), freshPod); err != nil {
			return false, fmt.Sprintf("waiting to re-read exact pod for GarageNode %s under the storage rollout coordinator: %v", member.node.Name, err), nil
		}
		if freshNode.UID != member.node.UID || freshNode.Generation != member.node.Generation ||
			!freshNode.DeletionTimestamp.IsZero() || freshPod.UID != member.pod.UID ||
			!garageNodeLayoutReadyForPod(freshNode, freshPod) {
			return false, fmt.Sprintf("managed member %s changed while acquiring the storage rollout coordinator; revalidating before any pod deletion", member.node.Name), nil
		}
		if err := r.validateStorageRolloutPublication(
			ctx, liveCluster, freshNode,
			member.nodeLocalPoolName, member.nodeName, member.workloadUID, member.kubernetesNodeUID,
			member.desiredPodSpecHash, member.desiredConfigHash,
		); err != nil {
			return false, fmt.Sprintf("managed member %s desired publication changed while acquiring the storage rollout coordinator: %v", member.node.Name, err), nil
		}
		if member.nodeLocalPoolName == "" {
			freshStatefulSet := &appsv1.StatefulSet{}
			if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
				Namespace: cluster.Namespace, Name: member.garageNodeName,
			}, freshStatefulSet); err != nil {
				return false, fmt.Sprintf("waiting to re-read StatefulSet for managed member %s under the storage rollout coordinator: %v", member.node.Name, err), nil
			}
			if freshStatefulSet.UID != member.workloadUID || !freshStatefulSet.DeletionTimestamp.IsZero() ||
				!metav1.IsControlledBy(freshStatefulSet, freshNode) {
				return false, fmt.Sprintf("StatefulSet for managed member %s changed while acquiring the storage rollout coordinator", member.node.Name), nil
			}
			claims, err := r.storageRolloutPersistentVolumeClaimsForPod(ctx, freshPod)
			if err != nil {
				return false, fmt.Sprintf("waiting to capture exact persistent storage identity for managed member %s: %v", member.node.Name, err), nil
			}
			member.persistentVolumeClaims = claims
			member.statefulSetRecreationSafe = statefulSetWorkloadRecreationSafe(freshStatefulSet)
		}
		member.node = freshNode
		member.pod = freshPod
		if candidate.node.Name == freshNode.Name {
			candidate.node = freshNode
			candidate.pod = freshPod
			candidate.persistentVolumeClaims = append(
				[]garagev1beta2.StorageRolloutPersistentVolumeClaimStatus(nil),
				member.persistentVolumeClaims...,
			)
			candidate.statefulSetRecreationSafe = member.statefulSetRecreationSafe
		}
	}
	if candidate.pod.Annotations[annotationPodSpecHash] == candidate.desiredPodSpecHash &&
		candidate.pod.Annotations[annotationConfigHash] == candidate.desiredConfigHash {
		return false, fmt.Sprintf("managed pod %s converged while the rollout coordinator was acquired; re-evaluating members", candidate.pod.Name), nil
	}

	garageState, err := r.getNodeLocalPoolRolloutGarageState(ctx, cluster)
	if err != nil {
		return false, "refusing to roll a node-local-pool pod until live Garage state can be verified: " + err.Error(), nil
	}
	if err := requireSettledLayoutHistoryResponse(garageState.history); err != nil {
		return false, "refusing to roll a node-local-pool pod until Garage layout history is settled: " + err.Error(), nil
	}
	health := garageState.health
	if health == nil {
		return false, "refusing to roll a node-local-pool pod because Garage returned no health response", nil
	}
	if health.Status != healthStatusHealthy ||
		health.StorageNodesUp != health.StorageNodes ||
		health.PartitionsQuorum != health.Partitions ||
		health.PartitionsAllOK != health.Partitions {
		return false, fmt.Sprintf(
			"refusing to roll a node-local-pool pod until Garage is fully healthy (status=%q storage=%d/%d quorum=%d/%d all-ok=%d/%d)",
			health.Status, health.StorageNodesUp, health.StorageNodes,
			health.PartitionsQuorum, health.Partitions, health.PartitionsAllOK, health.Partitions,
		), nil
	}
	status := garageState.status
	if status == nil {
		return false, "refusing to roll a node-local-pool pod because Garage returned no cluster status response", nil
	}
	identityUp := false
	for i := range status.Nodes {
		info := &status.Nodes[i]
		if info.ID == candidate.node.Status.NodeID && info.IsUp && info.Role != nil {
			identityUp = true
			break
		}
	}
	if !identityUp {
		return false, fmt.Sprintf("refusing to roll managed pod %s: Garage identity %s is not live with a committed role", candidate.pod.Name, shortID(candidate.node.Status.NodeID)), nil
	}
	target := "GarageNode " + candidate.garageNodeName
	if candidate.nodeLocalPoolName != "" {
		target = fmt.Sprintf("node-local pool %s on Kubernetes Node %s", candidate.nodeLocalPoolName, candidate.nodeName)
	}
	rolloutMessage := fmt.Sprintf("replacing managed pod %s for %s; no other Garage pod or layout mutation will proceed until its identity is Ready, Connected, InLayout, and layout history is settled", candidate.pod.Name, target)
	record := nodeLocalPoolRolloutRecord{
		GarageNodeName:       candidate.garageNodeName,
		NodeLocalPoolName:    candidate.nodeLocalPoolName,
		KubernetesNodeName:   candidate.nodeName,
		GarageNodeUID:        string(candidate.node.UID),
		GarageNodeID:         candidate.node.Status.NodeID,
		WorkloadUID:          string(candidate.workloadUID),
		KubernetesNodeUID:    string(candidate.kubernetesNodeUID),
		PreviousPodUID:       string(candidate.pod.UID),
		DesiredPodSpecHash:   candidate.desiredPodSpecHash,
		DesiredConfigHash:    candidate.desiredConfigHash,
		ClusterGeneration:    cluster.Generation,
		GarageNodeGeneration: candidate.node.Generation,
		RecoveryRequest:      cluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout],
		PersistentVolumeClaims: append(
			[]garagev1beta2.StorageRolloutPersistentVolumeClaimStatus(nil),
			candidate.persistentVolumeClaims...,
		),
		StatefulSetWorkloadRecreationSafe: candidate.statefulSetRecreationSafe,
	}
	if err := r.ensureNodeLocalPoolRolloutExclusion(ctx, cluster, record, rolloutMessage); err != nil {
		return false, "", fmt.Errorf("recording cluster-wide storage rollout exclusion before deleting pod %s: %w", candidate.pod.Name, err)
	}
	// A GarageNode delete admitted just before status.storageRollout became
	// visible must win over the rollout. Cancel without touching its pod; after
	// the durable state is visible, the GarageNode delete webhook rejects new
	// concurrent deletes until this handoff completes.
	freshCandidate := &garagev1beta1.GarageNode{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(candidate.node), freshCandidate); err != nil {
		return false, rolloutMessage, nil
	}
	if !freshCandidate.DeletionTimestamp.IsZero() {
		if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
			return false, "", err
		}
		return true, fmt.Sprintf("canceled managed pod replacement because GarageNode %s is deleting", freshCandidate.Name), nil
	}
	if freshCandidate.UID != candidate.node.UID || freshCandidate.Generation != candidate.node.Generation {
		if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
			return false, "", err
		}
		return false, fmt.Sprintf("canceled managed pod replacement because GarageNode %s generation changed after actor selection", freshCandidate.Name), nil
	}
	if freshCandidate.Status.NodeID != record.GarageNodeID {
		if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
			return false, "", err
		}
		return false, fmt.Sprintf("canceled managed pod replacement because GarageNode %s changed Garage identity after actor selection", freshCandidate.Name), nil
	}
	if err := r.validateStorageRolloutPublication(
		ctx, cluster, freshCandidate,
		candidate.nodeLocalPoolName, candidate.nodeName, candidate.workloadUID, candidate.kubernetesNodeUID,
		candidate.desiredPodSpecHash, candidate.desiredConfigHash,
	); err != nil {
		if clearErr := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); clearErr != nil {
			return false, "", clearErr
		}
		return false, fmt.Sprintf("canceled managed pod replacement because its desired publication changed after actor selection: %v", err), nil
	}
	if err := r.protectStorageRolloutPersistentVolumeClaims(ctx, cluster, record); err != nil {
		if clearErr := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); clearErr != nil {
			return false, "", clearErr
		}
		return false, fmt.Sprintf("canceled managed pod replacement because its persistent storage identity or transaction protection changed after actor selection: %v", err), nil
	}
	exactCandidatePod := &corev1.Pod{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(candidate.pod), exactCandidatePod); err != nil ||
		exactCandidatePod.UID != candidate.pod.UID || !exactCandidatePod.DeletionTimestamp.IsZero() ||
		!garageNodeLayoutReadyForPod(freshCandidate, exactCandidatePod) ||
		exactCandidatePod.Annotations[annotationPodSpecHash] == candidate.desiredPodSpecHash &&
			exactCandidatePod.Annotations[annotationConfigHash] == candidate.desiredConfigHash {
		if clearErr := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); clearErr != nil {
			return false, "", clearErr
		}
		return false, fmt.Sprintf("canceled managed pod replacement because exact Pod %s changed after actor selection", candidate.pod.Name), nil
	}
	candidate.pod = exactCandidatePod
	if candidate.nodeLocalPoolName == "" {
		claims, err := r.storageRolloutPersistentVolumeClaimsForPod(ctx, exactCandidatePod)
		if err != nil || !equality.Semantic.DeepEqual(claims, record.PersistentVolumeClaims) {
			if clearErr := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); clearErr != nil {
				return false, "", clearErr
			}
			return false, fmt.Sprintf("canceled managed pod replacement because Pod %s PVC references changed after actor selection", candidate.pod.Name), nil
		}
	}

	logf.FromContext(ctx).Info("Deleting one outdated managed pod for parent-controlled OnDelete rollout",
		"pod", candidate.pod.Name, "pool", candidate.nodeLocalPoolName, "kubernetesNode", candidate.nodeName, "garageNode", candidate.garageNodeName)
	uid := candidate.pod.UID
	if err := r.Delete(ctx, candidate.pod, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
		return false, "", fmt.Errorf("deleting outdated node-local-pool pod %s: %w", candidate.pod.Name, err)
	}
	return false, rolloutMessage, nil
}

func (r *GarageClusterReconciler) getNodeLocalPoolRolloutGarageState(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*nodeLocalPoolRolloutGarageState, error) {
	if r.nodeLocalPoolRolloutStateGetter != nil {
		return r.nodeLocalPoolRolloutStateGetter(ctx, cluster)
	}
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return nil, fmt.Errorf("building Garage Admin client: %w", err)
	}
	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage layout history: %w", err)
	}
	health, err := garageClient.GetClusterHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage health: %w", err)
	}
	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage cluster status: %w", err)
	}
	return &nodeLocalPoolRolloutGarageState{history: history, health: health, status: status}, nil
}

// recoverNodeLocalPoolRolloutExclusion re-establishes the durable boundary after an
// OnDelete replacement (including after a manager restart). Every existing
// node-local-pool Garage identity must be backed by its exact current Ready pod, be
// live in Garage, and observe a fully healthy, settled layout before ordinary
// layout writers are unblocked. Returning blocked=true is a safe wait whose
// explanation is persisted in StorageRolloutReady.
func (r *GarageClusterReconciler) recoverNodeLocalPoolRolloutExclusion(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	existing map[string]*garagev1beta1.GarageNode,
) (bool, error) {
	type recoveryMember struct {
		key         string
		description string
		node        *garagev1beta1.GarageNode
		workloadUID types.UID
		pods        []*corev1.Pod
	}

	coordinator := r.layoutMutationCoordinator()
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return true, fmt.Errorf("resolving canonical Garage layout owner while recovering managed Pod handoff: %w", err)
	}
	key := layoutOwnerKey(layoutOwner)
	if !coordinator.NodeLocalPoolRolloutActive(key) && !nodeLocalPoolRolloutConditionActive(cluster) {
		return false, nil
	}

	wait := func(message string) error {
		if err := r.setStorageRolloutCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageRollingOut, message); err != nil {
			return err
		}
		return nil
	}
	record, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil {
		return true, wait("waiting for a valid persisted node-local-pool rollout actor: " + err.Error())
	}
	if record == nil {
		// This can only be the tiny same-process tail after the atomic durable
		// state was cleared and before the in-memory marker was released. A
		// persisted RollingOut condition without an actor is not recoverable: the
		// previous pod UID is the evidence that prevents accepting the old process.
		if nodeLocalPoolRolloutConditionActive(cluster) {
			return true, wait("persisted RollingOut condition is missing status.storageRollout actor state")
		}
		if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
			return true, err
		}
		coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
		return false, nil
	}
	markerOwnedBySource, markerStatusConfirmed := coordinator.NodeLocalPoolRolloutSourceActive(key, cluster.UID)
	if !markerOwnedBySource || !markerStatusConfirmed {
		return true, wait("waiting to rehydrate and confirm the exact persisted storage-rollout coordinator marker before recovering a managed Pod")
	}

	// DaemonSet replacements are intentionally born behind a scheduling gate so
	// they cannot race an older Pod onto the same node-local HostPaths. Ordinary
	// node-local-pool reconciliation releases that gate, but a persisted rollout
	// returns above that path until its exact actor is Ready. Redrive the same
	// final authorization for only the persisted actor after reconstructing all
	// of its durable identities. Unrelated and retired DaemonSet Pods remain
	// gated while this cluster-wide handoff owns the layout coordinator.
	released, gateBlocked, gateErr := r.releaseStorageRolloutActorPodSchedulingGate(ctx, cluster, *record)
	if gateErr != nil {
		return true, wait("waiting to safely release node-local-pool replacement scheduling gates: " + gateErr.Error())
	}
	if len(gateBlocked) > 0 {
		return true, wait(summarizeNodeLocalPoolItems(
			"keeping node-local-pool replacement Pods scheduler-gated while an older or ambiguous Pod could still mount the same HostPaths",
			gateBlocked,
		))
	}
	if len(released) > 0 {
		return true, wait(summarizeNodeLocalPoolItems(
			"released validated node-local-pool replacement scheduling gates; waiting for exact Pods to schedule and become Ready",
			released,
		))
	}

	members := make(map[string]*recoveryMember)
	for _, node := range existing {
		memberKey := "node-local-pool:" + nodeLocalPoolKey(node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)
		members[memberKey] = &recoveryMember{
			key:         memberKey,
			description: fmt.Sprintf("node-local pool %q on Kubernetes Node %q", node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName),
			node:        node,
		}
	}

	daemonSetUIDs, err := r.ownedNodeLocalPoolDaemonSetUIDs(ctx, cluster)
	if err != nil {
		return true, wait("waiting to verify node-local-pool workloads before releasing the rollout exclusion: " + err.Error())
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return true, wait("waiting to list node-local-pool pods before releasing the rollout exclusion: " + err.Error())
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		if pod.Spec.NodeName == "" ||
			!isStorageDaemonSetPodForPoolUID(cluster, nodeLocalPoolName, daemonSetUIDs[nodeLocalPoolName], pod) {
			continue
		}
		member := members["node-local-pool:"+nodeLocalPoolKey(nodeLocalPoolName, pod.Spec.NodeName)]
		if member != nil {
			member.pods = append(member.pods, pod)
		}
	}

	// A cluster with node-local pools also places every GarageNode-owned StatefulSet
	// under the same parent-controlled OnDelete sequence. Reconstruct those
	// actors from live ownership, rather than trusting labels alone, so restart
	// recovery covers PVC, SMB, and unified gateway pods as well as node-local pools.
	garageNodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, garageNodes, client.InNamespace(cluster.Namespace)); err != nil {
		return true, wait("waiting to list GarageNodes before releasing the storage rollout exclusion: " + err.Error())
	}
	for i := range garageNodes.Items {
		node := &garageNodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			isNodeLocalPoolBacked(node) || node.Spec.External != nil {
			continue
		}
		memberKey := "garage-node:" + node.Name

		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Name: node.Name, Namespace: node.Namespace,
		}, statefulSet); err != nil {
			if errors.IsNotFound(err) {
				// A newly admitted Manual GarageNode has no process or layout role
				// to protect and is held by the rollout gate. An established identity
				// losing its StatefulSet is an outage and must keep recovery blocked.
				if node.Status.NodeID == "" && record.GarageNodeName != node.Name {
					continue
				}
				members[memberKey] = &recoveryMember{
					key: memberKey, description: "GarageNode " + node.Name, node: node,
				}
				continue
			}
			return true, wait(fmt.Sprintf("waiting to read StatefulSet for GarageNode %s during rollout recovery: %v", node.Name, err))
		}
		member := &recoveryMember{
			key:         memberKey,
			description: "GarageNode " + node.Name,
			node:        node,
			workloadUID: statefulSet.UID,
		}
		members[memberKey] = member
		if !metav1.IsControlledBy(statefulSet, node) {
			return true, wait(fmt.Sprintf("StatefulSet %s is not controlled by GarageNode %s", statefulSet.Name, node.Name))
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Name: node.Name + "-0", Namespace: node.Namespace,
		}, pod); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return true, wait(fmt.Sprintf("waiting to read pod for GarageNode %s during rollout recovery: %v", node.Name, err))
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
			return true, wait(fmt.Sprintf("pod %s is not controlled by the current StatefulSet %s", pod.Name, statefulSet.Name))
		}
		member.pods = append(member.pods, pod)
	}

	candidateKey := ""
	if record.GarageNodeName != "" {
		candidateKey = "garage-node:" + record.GarageNodeName
	} else {
		candidateKey = "node-local-pool:" + nodeLocalPoolKey(record.NodeLocalPoolName, record.KubernetesNodeName)
	}
	candidate := members[candidateKey]
	if candidate == nil {
		return true, wait("waiting for persisted rollout actor " + candidateKey)
	}
	if string(candidate.node.UID) != record.GarageNodeUID {
		return true, wait(fmt.Sprintf("persisted rollout actor %s was recreated; expected GarageNode UID %s, got %s", candidate.description, record.GarageNodeUID, candidate.node.UID))
	}
	if candidate.node.Status.NodeID != record.GarageNodeID {
		return true, wait(fmt.Sprintf("persisted rollout actor %s changed Garage identity; expected %s, got %s", candidate.description, shortID(record.GarageNodeID), shortID(candidate.node.Status.NodeID)))
	}
	if err := r.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, *record); err != nil {
		return true, wait("waiting for exact StatefulSet claim protection before recovering the storage rollout: " + err.Error())
	}
	if record.GarageNodeName != "" {
		if string(candidate.workloadUID) != record.WorkloadUID {
			return true, wait(fmt.Sprintf("persisted rollout actor %s no longer has exact StatefulSet UID %s", candidate.description, record.WorkloadUID))
		}
	} else {
		if string(daemonSetUIDs[record.NodeLocalPoolName]) != record.WorkloadUID {
			return true, wait(fmt.Sprintf("persisted rollout pool %q no longer has exact DaemonSet UID %s", record.NodeLocalPoolName, record.WorkloadUID))
		}
		kubernetesNode := &corev1.Node{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: record.KubernetesNodeName}, kubernetesNode); err != nil {
			return true, wait(fmt.Sprintf("waiting to verify persisted Kubernetes Node actor %q: %v", record.KubernetesNodeName, err))
		}
		if string(kubernetesNode.UID) != record.KubernetesNodeUID {
			return true, wait(fmt.Sprintf("persisted HostPath actor Kubernetes Node %q was recreated; expected UID %s, got %s", record.KubernetesNodeName, record.KubernetesNodeUID, kubernetesNode.UID))
		}
	}
	oldCandidateStillLive := false
	for _, pod := range candidate.pods {
		if string(pod.UID) == record.PreviousPodUID && pod.DeletionTimestamp.IsZero() {
			oldCandidateStillLive = true
			break
		}
	}
	if !candidate.node.DeletionTimestamp.IsZero() && oldCandidateStillLive {
		release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(coordinator, layoutOwner)
		if err != nil {
			return true, wait("waiting to cancel a storage rollout whose GarageNode actor is deleting")
		}
		defer release()
		if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
			return true, err
		}
		return true, nil
	}

	memberKeys := make([]string, 0, len(members))
	for memberKey := range members {
		memberKeys = append(memberKeys, memberKey)
	}
	sort.Strings(memberKeys)

	nodeIDs := make(map[string]struct{}, len(members))
	matchedPods := make(map[string]*corev1.Pod, len(members))
	var oldCandidatePod *corev1.Pod
	for _, memberKey := range memberKeys {
		member := members[memberKey]
		node := member.node
		var matched *corev1.Pod
		for _, pod := range member.pods {
			if memberKey == candidateKey && string(pod.UID) == record.PreviousPodUID {
				if !pod.DeletionTimestamp.IsZero() {
					return true, wait(fmt.Sprintf("waiting for previous storage pod %s to terminate before validating its replacement", pod.Name))
				}
				// The durable record means Delete was prepared, but the manager may
				// have restarted before the request reached Kubernetes. OnDelete
				// cannot create a replacement while this exact UID exists. Re-drive
				// it even if the old pod subsequently became Unready; every other
				// member is still proved Ready below.
				oldCandidatePod = pod
				matched = pod
				continue
			}
			if memberKey == candidateKey {
				if record.PreviousPodUID != "" && string(pod.UID) == record.PreviousPodUID {
					continue
				}
				if pod.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
					pod.Annotations[annotationConfigHash] != record.DesiredConfigHash {
					continue
				}
			}
			if garageNodeRolloutReadyForPod(node, pod) {
				matched = pod
				break
			}
		}
		if matched == nil || matched.UID != types.UID(record.PreviousPodUID) {
			if !garageNodeRolloutReady(node) {
				return true, wait(fmt.Sprintf("waiting for %s to report a fresh Connected and InLayout identity before releasing the storage rollout exclusion", member.description))
			}
		}
		if matched == nil {
			return true, wait(fmt.Sprintf("waiting for the exact Ready pod observed by %s before releasing the storage rollout exclusion", member.description))
		}
		matchedPods[memberKey] = matched
		if memberKey != candidateKey || matched.UID != types.UID(record.PreviousPodUID) {
			nodeIDs[node.Status.NodeID] = struct{}{}
		}
	}

	// Serialize the final health proof with both the candidate GarageNode and
	// every ordinary layout writer. This also prevents a second cluster
	// reconcile from clearing the exclusion between persisting it and Delete.
	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(coordinator, layoutOwner)
	if err != nil {
		return true, wait("waiting to validate storage rollout recovery behind another layout operation")
	}
	defer release()

	// Re-read every exact handoff while holding the coordinator. A pod may have
	// died after the first list, and StatefulSet pod names are reused; UID
	// equality is what prevents deleting or accepting the wrong incarnation.
	for _, memberKey := range memberKeys {
		member := members[memberKey]
		matched := matchedPods[memberKey]
		freshNode := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(member.node), freshNode); err != nil {
			return true, wait(fmt.Sprintf("waiting to re-read %s under the rollout coordinator: %v", member.description, err))
		}
		if memberKey == candidateKey && freshNode.Status.NodeID != record.GarageNodeID {
			return true, wait(fmt.Sprintf("persisted rollout actor %s changed Garage identity under the rollout coordinator; expected %s, got %s", member.description, shortID(record.GarageNodeID), shortID(freshNode.Status.NodeID)))
		}
		freshPod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(matched), freshPod); err != nil {
			return true, wait(fmt.Sprintf("waiting to re-read exact pod for %s under the rollout coordinator: %v", member.description, err))
		}
		preparedOldCandidate := memberKey == candidateKey && freshPod.UID == types.UID(record.PreviousPodUID)
		if memberKey == candidateKey && !freshNode.DeletionTimestamp.IsZero() && preparedOldCandidate {
			if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
				return true, err
			}
			return true, nil
		}
		if freshPod.UID != matched.UID || !freshPod.DeletionTimestamp.IsZero() ||
			(!preparedOldCandidate && !garageNodeRolloutReadyForPod(freshNode, freshPod)) {
			return true, wait(fmt.Sprintf("waiting for fresh exact pod-UID evidence for %s under the rollout coordinator", member.description))
		}
		if memberKey == candidateKey && freshPod.UID != types.UID(record.PreviousPodUID) &&
			(freshPod.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
				freshPod.Annotations[annotationConfigHash] != record.DesiredConfigHash) {
			return true, wait(fmt.Sprintf("waiting for desired pod and config revisions on %s", member.description))
		}
		matchedPods[memberKey] = freshPod
		member.node = freshNode
		if !preparedOldCandidate {
			nodeIDs[freshNode.Status.NodeID] = struct{}{}
		}
		if preparedOldCandidate {
			oldCandidatePod = freshPod
		}
	}

	state, err := r.getNodeLocalPoolRolloutGarageState(ctx, cluster)
	if err != nil {
		return true, wait("waiting for live Garage state before releasing the rollout exclusion: " + err.Error())
	}
	if err := requireSettledLayoutHistoryResponse(state.history); err != nil {
		return true, wait("waiting for settled Garage layout history before releasing the rollout exclusion: " + err.Error())
	}
	if state.health == nil {
		return true, wait("waiting for Garage health before releasing the storage rollout exclusion")
	}
	// A prepared old UID may have become Unready after the transaction was
	// persisted. Requiring global Healthy in that state deadlocks OnDelete: no
	// replacement can exist until the unavailable old pod is deleted. All other
	// exact members and live identities are still required. When validating an
	// actual replacement, retain the stronger full-health proof.
	if oldCandidatePod == nil && (state.health.Status != healthStatusHealthy ||
		state.health.StorageNodesUp != state.health.StorageNodes ||
		state.health.PartitionsQuorum != state.health.Partitions ||
		state.health.PartitionsAllOK != state.health.Partitions) {
		return true, wait("waiting for Garage to become fully healthy before releasing the node-local-pool rollout exclusion")
	}
	if state.status == nil {
		return true, wait("waiting for Garage cluster status before releasing the node-local-pool rollout exclusion")
	}
	live := make(map[string]bool, len(state.status.Nodes))
	for i := range state.status.Nodes {
		info := &state.status.Nodes[i]
		if info.IsUp && info.Role != nil {
			live[info.ID] = true
		}
	}
	for nodeID := range nodeIDs {
		if !live[nodeID] {
			return true, wait(fmt.Sprintf("waiting for Garage identity %s to be live with a committed role before releasing the node-local-pool rollout exclusion", shortID(nodeID)))
		}
	}

	if oldCandidatePod != nil {
		uid := oldCandidatePod.UID
		if err := r.Delete(ctx, oldCandidatePod, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
			return true, fmt.Errorf("re-driving persisted storage pod deletion %s: %w", oldCandidatePod.Name, err)
		}
		return true, wait(fmt.Sprintf("replacing persisted storage rollout pod %s for %s", oldCandidatePod.Name, candidate.description))
	}

	if err := r.clearNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
		return true, err
	}
	return false, nil
}

func podReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning || !pod.DeletionTimestamp.IsZero() {
		return false
	}
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			return pod.Status.Conditions[i].Status == corev1.ConditionTrue
		}
	}
	return false
}

// garageNodeExemptFromAdminAndRolloutProof reports whether a GarageNode must be
// omitted from the operator Admin Pod-set proof and from StorageRolloutReady
// membership waits. A drain-annotated or maintenance-suspended node that has
// left the layout (or is DrainPrepared) drops FullReplication tables and answers
// Admin/S3 with 403; requiring it deadlocks retirement (#544).
func garageNodeExemptFromAdminAndRolloutProof(node *garagev1beta1.GarageNode) bool {
	if node == nil || node.Spec.External != nil {
		return false
	}
	drain := node.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue
	userSuspended := node.Spec.Maintenance != nil && node.Spec.Maintenance.Suspended
	_, operatorSuspended := node.Annotations[garagev1beta1.AnnotationOperatorSuspended]
	if !drain && !userSuspended && !operatorSuspended {
		return false
	}
	if !node.Status.InLayout {
		return true
	}
	condition := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionDrainPrepared)
	return drain && condition != nil && condition.Status == metav1.ConditionTrue
}

func garageNodeLayoutReady(node *garagev1beta1.GarageNode) bool {
	return node != nil && node.DeletionTimestamp.IsZero() && node.Status.NodeID != "" &&
		node.Status.Connected && node.Status.InLayout && node.Status.ObservedGeneration >= node.Generation
}

func garageNodeLayoutReadyForPod(node *garagev1beta1.GarageNode, pod *corev1.Pod) bool {
	return garageNodeLayoutReady(node) && podReady(pod) && pod.UID != "" &&
		node.Status.ObservedPodUID == string(pod.UID)
}

// garageNodeRolloutReady deliberately ignores DeletionTimestamp. A
// non-candidate Manual GarageNode delete that races an already-persisted pod
// handoff is held by its layout finalizer; its exact pod remains online and may
// be counted long enough to finish the active handoff. The recorded candidate
// is handled separately and cancels instead of deleting its pod.
func garageNodeRolloutReady(node *garagev1beta1.GarageNode) bool {
	return node != nil && node.Status.NodeID != "" && node.Status.Connected &&
		node.Status.InLayout && node.Status.ObservedGeneration >= node.Generation
}

func garageNodeRolloutReadyForPod(node *garagev1beta1.GarageNode, pod *corev1.Pod) bool {
	return garageNodeRolloutReady(node) && podReady(pod) && pod.UID != "" &&
		node.Status.ObservedPodUID == string(pod.UID)
}

func (r *GarageClusterReconciler) ownedNodeLocalPoolDaemonSetUIDs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]types.UID, error) {
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, fmt.Errorf("listing owned node-local pool DaemonSets: %w", err)
	}
	out := make(map[string]types.UID)
	for i := range daemonSets.Items {
		daemonSet := &daemonSets.Items[i]
		nodeLocalPoolName := daemonSet.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || daemonSet.Name != storageDaemonSetName(cluster, nodeLocalPoolName) ||
			!metav1.IsControlledBy(daemonSet, cluster) {
			continue
		}
		out[nodeLocalPoolName] = daemonSet.UID
	}
	return out, nil
}

func (r *GarageClusterReconciler) setNodeLocalPoolsCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	message = limitStatusConditionMessage(message)
	apply := func() {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionNodeLocalPoolsReady,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: cluster.Generation,
		})
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}

func nodeLocalPoolRolloutRecordForCluster(cluster *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutRecord, error) {
	if cluster == nil || cluster.Status.StorageRollout == nil {
		return nil, nil
	}
	record := *cluster.Status.StorageRollout
	record.GarageNodeID = canonicalGarageNodeID(record.GarageNodeID)
	statefulSetActor := record.GarageNodeName != ""
	nodeLocalPoolActor := record.NodeLocalPoolName != "" && record.KubernetesNodeName != ""
	if statefulSetActor == nodeLocalPoolActor {
		return nil, fmt.Errorf("status.storageRollout must identify exactly one garageNodeName or nodeLocalPoolName plus kubernetesNodeName actor")
	}
	if record.GarageNodeUID == "" || record.WorkloadUID == "" {
		return nil, fmt.Errorf("status.storageRollout must record exact garageNodeUid and workloadUid actor incarnations")
	}
	if record.GarageNodeID == "" {
		return nil, fmt.Errorf("status.storageRollout must record the exact pre-delete garageNodeId")
	}
	if nodeLocalPoolActor && record.KubernetesNodeUID == "" {
		return nil, fmt.Errorf("status.storageRollout node-local-pool actor must record exact kubernetesNodeUid for HostPath ownership")
	}
	if statefulSetActor && record.KubernetesNodeUID != "" {
		return nil, fmt.Errorf("status.storageRollout StatefulSet actor must not record kubernetesNodeUid")
	}
	if record.PreviousPodUID == "" {
		return nil, fmt.Errorf("status.storageRollout must record the exact previousPodUid before deletion")
	}
	if record.DesiredPodSpecHash == "" {
		return nil, fmt.Errorf("status.storageRollout must record desiredPodSpecHash")
	}
	if record.DesiredConfigHash == "" {
		return nil, fmt.Errorf("status.storageRollout must record desiredConfigHash")
	}
	if len(record.RetiredWorkloadUIDs) > maximumStorageRolloutRetiredWorkloadUIDs {
		return nil, fmt.Errorf(
			"status.storageRollout retiredWorkloadUids contains %d controller incarnations, above the supported maximum of %d; retain the transaction and recover it under supervision",
			len(record.RetiredWorkloadUIDs), maximumStorageRolloutRetiredWorkloadUIDs,
		)
	}
	seenRetired := make(map[string]struct{}, len(record.RetiredWorkloadUIDs))
	for _, uid := range record.RetiredWorkloadUIDs {
		if uid == "" || uid == record.WorkloadUID {
			return nil, fmt.Errorf("status.storageRollout retiredWorkloadUids must be nonempty and exclude current workloadUid")
		}
		if _, duplicate := seenRetired[uid]; duplicate {
			return nil, fmt.Errorf("status.storageRollout retiredWorkloadUids contains duplicate UID %s", uid)
		}
		seenRetired[uid] = struct{}{}
	}
	if nodeLocalPoolActor && len(record.PersistentVolumeClaims) != 0 {
		return nil, fmt.Errorf("status.storageRollout node-local-pool actor must not record persistentVolumeClaims")
	}
	if nodeLocalPoolActor && record.StatefulSetWorkloadRecreationSafe {
		return nil, fmt.Errorf("status.storageRollout node-local-pool actor must not record StatefulSet workload recreation safety")
	}
	seenClaims := make(map[string]struct{}, len(record.PersistentVolumeClaims))
	previousClaimName := ""
	for i := range record.PersistentVolumeClaims {
		claim := &record.PersistentVolumeClaims[i]
		if claim.Name == "" || claim.UID == "" {
			return nil, fmt.Errorf("status.storageRollout persistentVolumeClaims entries require nonempty name and uid")
		}
		if _, duplicate := seenClaims[claim.Name]; duplicate {
			return nil, fmt.Errorf("status.storageRollout persistentVolumeClaims contains duplicate name %s", claim.Name)
		}
		if previousClaimName != "" && claim.Name < previousClaimName {
			return nil, fmt.Errorf("status.storageRollout persistentVolumeClaims must be sorted by name")
		}
		seenClaims[claim.Name] = struct{}{}
		previousClaimName = claim.Name
	}
	if (record.RecoveryPodName == "") != (record.RecoveryPodUID == "") {
		return nil, fmt.Errorf("status.storageRollout recoveryPodName and recoveryPodUid must be recorded or cleared together")
	}
	return &record, nil
}

func nodeLocalPoolRolloutCandidateMatches(
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) bool {
	if node == nil {
		return false
	}
	record, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil || record == nil {
		return false
	}
	if record.GarageNodeName != "" {
		return record.GarageNodeName == node.Name && record.GarageNodeUID == string(node.UID)
	}
	return isNodeLocalPoolBacked(node) && record.NodeLocalPoolName == node.Spec.NodeLocalPoolName &&
		record.KubernetesNodeName == node.Spec.KubernetesNodeName && record.GarageNodeUID == string(node.UID)
}

func (r *GarageClusterReconciler) ensureNodeLocalPoolRolloutExclusion(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
	message string,
) error {
	coordinator := r.layoutMutationCoordinator()
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before persisting rollout actor: %w", err)
	}
	key := layoutOwnerKey(layoutOwner)
	sourceKey := client.ObjectKeyFromObject(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(key, layoutRolloutOwnerID(layoutOwner), sourceKey, cluster.UID) {
		return fmt.Errorf("another GarageCluster already owns the managed-Pod handoff for canonical Garage layout %s/%s", key.Namespace, key.Name)
	}
	keepMarker := cluster.Status.StorageRollout != nil
	cleanupProtections := cluster.Status.StorageRollout == nil && len(record.PersistentVolumeClaims) > 0
	defer func() {
		if !keepMarker {
			if cleanupProtections {
				if err := r.releaseStorageRolloutPersistentVolumeClaims(ctx, cluster, record); err != nil {
					logf.FromContext(ctx).Error(err, "Failed to release PVC protection after storage rollout publication aborted")
				}
			}
			coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
		}
	}()

	current, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil {
		return err
	}
	if current != nil && !equality.Semantic.DeepEqual(*current, record) {
		return fmt.Errorf("another storage rollout actor is already persisted in status")
	}
	if err := r.protectStorageRolloutPersistentVolumeClaims(ctx, cluster, record); err != nil {
		return fmt.Errorf("protecting exact StatefulSet claims before publishing storage rollout actor: %w", err)
	}
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	var updated *garagev1beta2.GarageCluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster changed generation while selecting the exact storage rollout actor")
		}
		freshRecord, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil {
			if freshRecord != nil {
				return fmt.Errorf("another storage rollout actor was persisted while selecting this actor")
			}
		} else if freshRecord == nil || !equality.Semantic.DeepEqual(*freshRecord, *current) {
			return fmt.Errorf("storage rollout actor changed while refreshing its exclusion")
		}
		copy := record
		fresh.Status.StorageRollout = &copy
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRollingOut,
			Message:            limitStatusConditionMessage(message),
			ObservedGeneration: expectedGeneration,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting storage rollout actor and exclusion: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	// Once status is durable, both the marker and exact PVC protection belong to
	// recovery even if the in-process marker confirmation unexpectedly fails.
	keepMarker = true
	if !coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) {
		return fmt.Errorf("durable storage rollout actor lost its canonical in-memory exclusion before publication completed")
	}
	return nil
}

// clearNodeLocalPoolRolloutExclusion atomically completes one durable handoff while
// retaining the broader parent-controlled rollout boundary. The caller's same
// reconcile either starts the next actor, marks the pools converged, or clears
// NodeLocalPoolsReady after the final retired-pool StatefulSet is current.
func (r *GarageClusterReconciler) clearNodeLocalPoolRolloutExclusion(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before clearing rollout actor: %w", err)
	}
	expected, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil {
		return err
	}
	if expected == nil {
		return fmt.Errorf("cannot clear storage rollout exclusion without an exact persisted actor")
	}
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	var updated *garagev1beta2.GarageCluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster changed generation before the storage rollout actor could be cleared")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, *expected) {
			return fmt.Errorf("storage rollout actor changed before its exclusion could be cleared")
		}
		fresh.Status.StorageRollout = nil
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRolloutWaiting,
			Message:            "managed storage pod handoff completed; evaluating the next cluster-wide rollout member",
			ObservedGeneration: expectedGeneration,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing storage rollout actor and exclusion: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	if err := r.releaseStorageRolloutPersistentVolumeClaims(ctx, cluster, *expected); err != nil {
		return fmt.Errorf("releasing exact StatefulSet claim protection after clearing storage rollout actor: %w", err)
	}
	r.layoutMutationCoordinator().EndNodeLocalPoolRollout(layoutOwnerKey(layoutOwner), cluster.UID)
	return nil
}

func (r *GarageClusterReconciler) finishNodeLocalPoolRolloutExclusion(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	hadLocalActor := cluster.Status.StorageRollout != nil
	if hadLocalActor {
		return fmt.Errorf("cannot finish a storage rollout while an exact actor is still persisted")
	}
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before finishing rollout exclusion: %w", err)
	}
	if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
		return err
	}
	// Marker ownership includes the durable source UID, so this source can safely
	// clear only its own post-status tail without disturbing a referenced
	// storage owner or another gateway cluster's transaction.
	r.layoutMutationCoordinator().EndNodeLocalPoolRollout(layoutOwnerKey(layoutOwner), cluster.UID)
	return nil
}

func (r *GarageClusterReconciler) clearNodeLocalPoolsCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady) == nil {
		return nil
	}
	apply := func() {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}

func (r *GarageClusterReconciler) setStorageRolloutCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	expectedRecord, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil {
		return err
	}
	var updated *garagev1beta2.GarageCluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster changed generation before the storage rollout condition decision was persisted")
		}
		freshRecord, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if (expectedRecord == nil) != (freshRecord == nil) ||
			(expectedRecord != nil && !equality.Semantic.DeepEqual(*expectedRecord, *freshRecord)) {
			return fmt.Errorf("storage rollout actor changed before its condition decision was persisted")
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             status,
			Reason:             reason,
			Message:            limitStatusConditionMessage(message),
			ObservedGeneration: expectedGeneration,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return err
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}
