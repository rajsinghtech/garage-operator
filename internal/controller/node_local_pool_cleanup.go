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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

type nodeLocalPoolActivationCleanup struct {
	pending                 bool
	blocksActivation        bool
	workloadTeardownBlocked bool
}

// cleanupNodeLocalPoolActivationLabels preserves the historical test/helper
// contract. Reconciliation uses cleanupNodeLocalPoolActivationState so it can
// distinguish a phase that must stop new activation from a passive old-Pod
// hold that should flow through to the more specific move condition.
func (r *GarageClusterReconciler) cleanupNodeLocalPoolActivationLabels(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	states map[string]*nodeLocalPoolState,
	existingByPair map[string]*garagev1beta1.GarageNode,
) (bool, error) {
	cleanup, err := r.cleanupNodeLocalPoolActivationState(ctx, cluster, states, existingByPair)
	return cleanup.pending, err
}

func (r *GarageClusterReconciler) cleanupNodeLocalPoolActivationState(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	states map[string]*nodeLocalPoolState,
	existingByPair map[string]*garagev1beta1.GarageNode,
) (nodeLocalPoolActivationCleanup, error) {
	nodes := &corev1.NodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes); err != nil {
		return nodeLocalPoolActivationCleanup{}, fmt.Errorf("listing Kubernetes Nodes for node-local-pool label cleanup: %w", err)
	}
	clusterPrefix := nodeLocalPoolActivationClusterPrefix(cluster)
	retainedAnnotationPrefix := nodeLocalPoolRetainedAnnotationClusterPrefix(cluster)
	knownPools := make(map[string]struct{})
	poolByActivationLabel := make(map[string]string)
	for nodeLocalPoolName, state := range states {
		knownPools[nodeLocalPoolName] = struct{}{}
		poolByActivationLabel[state.activationLabel] = nodeLocalPoolName
	}
	for _, garageNode := range existingByPair {
		knownPools[garageNode.Spec.NodeLocalPoolName] = struct{}{}
		poolByActivationLabel[nodeLocalPoolActivationLabel(cluster, garageNode.Spec.NodeLocalPoolName)] = garageNode.Spec.NodeLocalPoolName
	}

	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nodeLocalPoolActivationCleanup{}, fmt.Errorf("listing node-local-pool DaemonSets for claim cleanup: %w", err)
	}
	daemonSetPresent := make(map[string]bool)
	daemonSetUIDs := make(map[string]types.UID)
	for i := range daemonSets.Items {
		daemonSet := &daemonSets.Items[i]
		nodeLocalPoolName := daemonSet.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || daemonSet.Name != storageDaemonSetName(cluster, nodeLocalPoolName) {
			continue
		}
		knownPools[nodeLocalPoolName] = struct{}{}
		daemonSetPresent[nodeLocalPoolName] = true
		daemonSetUIDs[nodeLocalPoolName] = daemonSet.UID
		if labelKey := daemonSet.Annotations[annotationNodeLocalPoolActivationLabel]; strings.HasPrefix(labelKey, clusterPrefix) {
			poolByActivationLabel[labelKey] = nodeLocalPoolName
		}
	}

	poolPods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, poolPods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nodeLocalPoolActivationCleanup{}, fmt.Errorf("listing node-local-pool Pods for claim cleanup: %w", err)
	}
	podTargets := make(map[string]bool)
	podTargetUnknown := make(map[string]bool)
	for i := range poolPods.Items {
		pod := &poolPods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || !isStorageDaemonSetPodForPool(cluster, nodeLocalPoolName, pod) {
			continue
		}
		knownPools[nodeLocalPoolName] = struct{}{}
		nodeNames, exact := nodeLocalPoolPodTargetNodeNames(pod)
		if !exact {
			podTargetUnknown[nodeLocalPoolName] = true
		}
		for nodeName := range nodeNames {
			podTargets[nodeLocalPoolKey(nodeLocalPoolName, nodeName)] = true
		}
	}

	// Claims reveal stable pool names even after both desired state and the
	// retired DaemonSet have disappeared.
	retiringPairs := make(map[string]bool)
	for i := range nodes.Items {
		for key, value := range nodes.Items[i].Annotations {
			if !strings.HasPrefix(key, retainedAnnotationPrefix) || !isNodeLocalPoolHostPathClaimAnnotation(key) {
				continue
			}
			claim, err := decodeNodeLocalPoolHostPathClaim(value)
			if err == nil && claim.ClusterNamespace == cluster.Namespace && claim.ClusterName == cluster.Name &&
				key == nodeLocalPoolHostPathClaimAnnotation(cluster, claim.NodeLocalPoolName) {
				knownPools[claim.NodeLocalPoolName] = struct{}{}
				if claim.Retiring {
					retiringPairs[nodeLocalPoolKey(claim.NodeLocalPoolName, nodes.Items[i].Name)] = true
				}
			}
		}
	}
	poolByRecoveryAnnotation := make(map[string]string, len(knownPools))
	for nodeLocalPoolName := range knownPools {
		poolByRecoveryAnnotation[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, nodeLocalPoolName)] = nodeLocalPoolName
		poolByActivationLabel[nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName)] = nodeLocalPoolName
	}

	// Active-pool membership removal needs a fresh scheduling token before the
	// old label can be released. A removed pool instead deletes its DaemonSet and
	// waits for that controller and all of its Pods below.
	retiringNodesByPool := make(map[string]map[string]struct{})
	addRetiring := func(nodeLocalPoolName, nodeName string, persisted bool) {
		pair := nodeLocalPoolKey(nodeLocalPoolName, nodeName)
		state := states[nodeLocalPoolName]
		if existingByPair[pair] != nil ||
			(state != nil && !persisted && state.desiredNodes[nodeName] != nil) {
			return
		}
		if retiringNodesByPool[nodeLocalPoolName] == nil {
			retiringNodesByPool[nodeLocalPoolName] = make(map[string]struct{})
		}
		retiringNodesByPool[nodeLocalPoolName][nodeName] = struct{}{}
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		for labelKey := range node.Labels {
			if nodeLocalPoolName := poolByActivationLabel[labelKey]; nodeLocalPoolName != "" {
				addRetiring(nodeLocalPoolName, node.Name, retiringPairs[nodeLocalPoolKey(nodeLocalPoolName, node.Name)])
			}
		}
		for key, value := range node.Annotations {
			if !isNodeLocalPoolHostPathClaimAnnotation(key) {
				continue
			}
			claim, err := decodeNodeLocalPoolHostPathClaim(value)
			if err == nil && claim.ClusterNamespace == cluster.Namespace && claim.ClusterName == cluster.Name {
				addRetiring(claim.NodeLocalPoolName, node.Name, claim.Retiring)
			}
		}
	}
	nodeLocalPoolNames := make([]string, 0, len(retiringNodesByPool))
	for nodeLocalPoolName := range retiringNodesByPool {
		nodeLocalPoolNames = append(nodeLocalPoolNames, nodeLocalPoolName)
	}
	sort.Strings(nodeLocalPoolNames)
	for _, nodeLocalPoolName := range nodeLocalPoolNames {
		nodeNames := make([]string, 0, len(retiringNodesByPool[nodeLocalPoolName]))
		for nodeName := range retiringNodesByPool[nodeLocalPoolName] {
			nodeNames = append(nodeNames, nodeName)
		}
		activationValue, pending, err := r.ensureNodeLocalPoolMembershipFenceObserved(ctx, cluster, nodeLocalPoolName, nodeNames)
		if err != nil {
			return nodeLocalPoolActivationCleanup{}, err
		}
		if pending {
			return nodeLocalPoolActivationCleanup{
				pending:                 true,
				blocksActivation:        true,
				workloadTeardownBlocked: true,
			}, nil
		}
		state := states[nodeLocalPoolName]
		if state == nil || activationValue == "" {
			continue
		}
		var survivingNodeNames []string
		for _, nodeName := range sortedNodeNames(state.desiredNodes) {
			if _, retiring := retiringNodesByPool[nodeLocalPoolName][nodeName]; retiring {
				continue
			}
			survivingNodeNames = append(survivingNodeNames, nodeName)
			changed, err := r.migrateNodeLocalPoolMembershipActivation(
				ctx, cluster, state.pool, nodeName, state.activationLabel, activationValue,
			)
			if err != nil {
				return nodeLocalPoolActivationCleanup{}, err
			}
			if changed {
				return nodeLocalPoolActivationCleanup{
					pending:                 true,
					blocksActivation:        true,
					workloadTeardownBlocked: true,
				}, nil
			}
		}
		committed, err := r.commitNodeLocalPoolMembershipFence(
			ctx, cluster, nodeLocalPoolName, nodeNames, survivingNodeNames,
		)
		if err != nil {
			return nodeLocalPoolActivationCleanup{}, err
		}
		if committed {
			return nodeLocalPoolActivationCleanup{
				pending: true, blocksActivation: true, workloadTeardownBlocked: true,
			}, nil
		}
		// A Pod created from the temporary bridge template can remain gated
		// after the final selector is published. It carries the old token and
		// cannot be authorized; remove it so OnDelete can create a fresh Pod.
		stalePodsPending := false
		for i := range poolPods.Items {
			pod := &poolPods.Items[i]
			if pod.Labels[labelNodeLocalPool] != nodeLocalPoolName || pod.Spec.NodeName != "" ||
				!nodeLocalPoolPodHasSchedulingGate(pod) ||
				pod.Annotations[annotationNodeLocalPoolActivationValue] == activationValue ||
				!isStorageDaemonSetPodForPoolUID(cluster, nodeLocalPoolName, daemonSetUIDs[nodeLocalPoolName], pod) {
				continue
			}
			stalePodsPending = true
			if pod.DeletionTimestamp.IsZero() {
				if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
					return nodeLocalPoolActivationCleanup{}, fmt.Errorf("removing stale gated node-local pool %q Pod %s: %w", nodeLocalPoolName, pod.Name, err)
				}
			}
		}
		if stalePodsPending {
			return nodeLocalPoolActivationCleanup{
				pending: true, blocksActivation: true, workloadTeardownBlocked: true,
			}, nil
		}
	}

	// Recovery annotations are the only durable bridge from retained HostPath
	// metadata to a same-name GarageCluster recreated with a new Kubernetes UID.
	// Load one settled Garage snapshot lazily and remove a pin only when that
	// snapshot proves the exact role absent. If the Admin API/history is
	// unavailable, keep the pin while still allowing scheduling-label cleanup.
	var (
		recoveryProofLoaded bool
		recoveryProofErr    error
		recoveryRoleIDs     map[string]struct{}
		recoveryProofLogged bool
	)
	loadRecoveryCleanupProof := func() {
		if recoveryProofLoaded {
			return
		}
		recoveryProofLoaded = true
		layout, err := r.getNodeLocalPoolCommittedLayout(ctx, cluster)
		if err != nil {
			recoveryProofErr = fmt.Errorf("reading committed Garage layout before retained identity-pin cleanup: %w", err)
			return
		}
		history, err := r.getClusterLayoutHistory(ctx, cluster)
		if err != nil {
			recoveryProofErr = fmt.Errorf("reading Garage layout history before retained identity-pin cleanup: %w", err)
			return
		}
		if history == nil || layout == nil {
			recoveryProofErr = fmt.Errorf("garage layout or history is unavailable before retained identity-pin cleanup")
			return
		}
		if draining := history.GetDrainingVersions(); len(draining) > 0 {
			recoveryProofErr = fmt.Errorf("garage layout history still has %d draining version(s)", len(draining))
			return
		}
		if history.CurrentVersion != layout.Version {
			recoveryProofErr = fmt.Errorf(
				"garage layout/history versions differ (%d != %d)", layout.Version, history.CurrentVersion,
			)
			return
		}
		if len(layout.StagedRoleChanges) > 0 {
			recoveryProofErr = fmt.Errorf("garage layout has %d staged role change(s)", len(layout.StagedRoleChanges))
			return
		}
		recoveryRoleIDs = make(map[string]struct{}, len(layout.Roles))
		for i := range layout.Roles {
			recoveryRoleIDs[strings.ToLower(strings.TrimSpace(layout.Roles[i].ID))] = struct{}{}
		}
	}
	cleanupPending := false
	blocksActivation := false
	workloadTeardownBlocked := false
	keepPair := func(nodeLocalPoolName, nodeName string) bool {
		pair := nodeLocalPoolKey(nodeLocalPoolName, nodeName)
		state := states[nodeLocalPoolName]
		if !retiringPairs[pair] && state != nil && state.desiredNodes[nodeName] != nil {
			return true
		}
		if existingByPair[pair] != nil {
			return true
		}
		if state == nil && daemonSetPresent[nodeLocalPoolName] {
			return true
		}
		return podTargetUnknown[nodeLocalPoolName] || podTargets[pair]
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		claimMarkedRetiring := false
		for key, value := range node.Annotations {
			if !isNodeLocalPoolHostPathClaimAnnotation(key) {
				continue
			}
			claim, err := decodeNodeLocalPoolHostPathClaim(value)
			if err != nil || claim.ClusterNamespace != cluster.Namespace || claim.ClusterName != cluster.Name ||
				retiringNodesByPool[claim.NodeLocalPoolName] == nil {
				continue
			}
			if _, retiring := retiringNodesByPool[claim.NodeLocalPoolName][node.Name]; !retiring || claim.Retiring {
				continue
			}
			claim.Retiring = true
			encoded, err := encodeNodeLocalPoolHostPathClaim(*claim)
			if err != nil {
				return nodeLocalPoolActivationCleanup{}, err
			}
			node.Annotations[key] = encoded
			retiringPairs[nodeLocalPoolKey(claim.NodeLocalPoolName, node.Name)] = true
			claimMarkedRetiring = true
			cleanupPending = true
			blocksActivation = true
		}
		var removeLabels []string
		for key := range node.Labels {
			if !strings.HasPrefix(key, clusterPrefix) {
				continue
			}
			nodeLocalPoolName := poolByActivationLabel[key]
			if nodeLocalPoolName != "" {
				pair := nodeLocalPoolKey(nodeLocalPoolName, node.Name)
				state := states[nodeLocalPoolName]
				if (!retiringPairs[pair] && state != nil && state.desiredNodes[node.Name] != nil) ||
					existingByPair[pair] != nil {
					continue
				}
			}
			removeLabels = append(removeLabels, key)
		}
		var removeAnnotations []string
		// Never release the durable claim in the same API transaction that
		// removes its scheduling label. One subsequent direct read must observe
		// the fence before claim cleanup can proceed.
		deferAnnotations := len(removeLabels) > 0
		for key, pinnedNodeID := range node.Annotations {
			if !strings.HasPrefix(key, retainedAnnotationPrefix) {
				continue
			}
			if deferAnnotations {
				cleanupPending = true
				continue
			}
			if isNodeLocalPoolHostPathClaimAnnotation(key) {
				claim, err := decodeNodeLocalPoolHostPathClaim(pinnedNodeID)
				if err != nil || claim.ClusterNamespace != cluster.Namespace || claim.ClusterName != cluster.Name ||
					key != nodeLocalPoolHostPathClaimAnnotation(cluster, claim.NodeLocalPoolName) {
					logf.FromContext(ctx).Info("Retaining malformed or foreign node-local-pool HostPath claim for explicit recovery",
						"kubernetesNode", node.Name, "annotation", key, "error", err)
					cleanupPending = true
					continue
				}
				pair := nodeLocalPoolKey(claim.NodeLocalPoolName, node.Name)
				if keepPair(claim.NodeLocalPoolName, node.Name) {
					if existingByPair[pair] != nil {
						continue
					}
					if retiringPairs[pair] || states[claim.NodeLocalPoolName] == nil || states[claim.NodeLocalPoolName].desiredNodes[node.Name] == nil {
						cleanupPending = true
					}
					if retiringPairs[pair] || (states[claim.NodeLocalPoolName] == nil && daemonSetPresent[claim.NodeLocalPoolName]) {
						blocksActivation = true
					}
					continue
				}
				claimNodeID := canonicalGarageNodeID(claim.GarageNodeID)
				if claimNodeID == "" {
					claimNodeID = canonicalGarageNodeID(
						node.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, claim.NodeLocalPoolName)],
					)
				}
				if claimNodeID == "" {
					// No identity was ever durably attached to this activation and
					// no child remains, so the scheduling claim can be retired.
					removeAnnotations = append(removeAnnotations, key)
					cleanupPending = true
					blocksActivation = true
					continue
				}
				if !isValidGarageNodeID(claimNodeID) {
					logf.FromContext(ctx).Info("Retaining HostPath claim with malformed identity for explicit recovery",
						"kubernetesNode", node.Name, "annotation", key)
					cleanupPending = true
					if retiringPairs[pair] {
						blocksActivation = true
					}
					continue
				}
				loadRecoveryCleanupProof()
				if recoveryProofErr != nil {
					if !recoveryProofLogged {
						logf.FromContext(ctx).Info("Retaining node-local-pool claims until settled Garage layout proves their roles absent",
							"error", recoveryProofErr)
						recoveryProofLogged = true
					}
					cleanupPending = true
					if retiringPairs[pair] {
						blocksActivation = true
					}
					continue
				}
				if _, roleStillCommitted := recoveryRoleIDs[claimNodeID]; roleStillCommitted {
					cleanupPending = true
					if retiringPairs[pair] {
						blocksActivation = true
					}
					continue
				}
				removeAnnotations = append(removeAnnotations, key)
				cleanupPending = true
				blocksActivation = true
				continue
			}
			nodeLocalPoolName := poolByRecoveryAnnotation[key]
			pair := nodeLocalPoolKey(nodeLocalPoolName, node.Name)
			if nodeLocalPoolName != "" && keepPair(nodeLocalPoolName, node.Name) {
				if existingByPair[pair] != nil {
					continue
				}
				if retiringPairs[pair] || states[nodeLocalPoolName] == nil || states[nodeLocalPoolName].desiredNodes[node.Name] == nil {
					cleanupPending = true
				}
				if retiringPairs[pair] || (states[nodeLocalPoolName] == nil && daemonSetPresent[nodeLocalPoolName]) {
					blocksActivation = true
				}
				continue
			}
			pinnedNodeID = strings.ToLower(strings.TrimSpace(pinnedNodeID))
			if !isValidGarageNodeID(pinnedNodeID) {
				logf.FromContext(ctx).Info("Retaining malformed node-local-pool identity pin for explicit recovery",
					"kubernetesNode", node.Name, "annotation", key)
				cleanupPending = true
				if retiringPairs[pair] {
					blocksActivation = true
				}
				continue
			}
			loadRecoveryCleanupProof()
			if recoveryProofErr != nil {
				if !recoveryProofLogged {
					logf.FromContext(ctx).Info("Retaining node-local-pool identity pins until settled Garage layout proves their roles absent",
						"error", recoveryProofErr)
					recoveryProofLogged = true
				}
				cleanupPending = true
				if retiringPairs[pair] {
					blocksActivation = true
				}
				continue
			}
			if _, roleStillCommitted := recoveryRoleIDs[pinnedNodeID]; roleStillCommitted {
				cleanupPending = true
				if retiringPairs[pair] {
					blocksActivation = true
				}
				continue
			}
			removeAnnotations = append(removeAnnotations, key)
			cleanupPending = true
			blocksActivation = true
		}
		if len(removeLabels) == 0 && len(removeAnnotations) == 0 && !claimMarkedRetiring {
			continue
		}
		for _, key := range removeLabels {
			delete(node.Labels, key)
		}
		for _, key := range removeAnnotations {
			delete(node.Annotations, key)
		}
		if err := r.Update(ctx, node); err != nil {
			return nodeLocalPoolActivationCleanup{}, fmt.Errorf("removing retired node-local-pool activation and identity record(s) from Kubernetes Node %q by resourceVersion CAS: %w", node.Name, err)
		}
		if len(removeLabels) > 0 {
			cleanupPending = true
			blocksActivation = true
			// Observe a subsequent direct Node read without the old scheduling
			// token before deleting the retired DaemonSet. This prevents a
			// same-reconcile delete from bypassing the membership-generation
			// barrier above.
			workloadTeardownBlocked = true
		}
	}
	return nodeLocalPoolActivationCleanup{
		pending:                 cleanupPending,
		blocksActivation:        blocksActivation,
		workloadTeardownBlocked: workloadTeardownBlocked,
	}, nil
}

func (r *GarageClusterReconciler) cleanupRetiredNodeLocalPoolResources(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	states map[string]*nodeLocalPoolState,
	existing map[string]*garagev1beta1.GarageNode,
) (bool, error) {
	log := logf.FromContext(ctx)
	hasNodes := make(map[string]bool)
	for _, node := range existing {
		hasNodes[node.Spec.NodeLocalPoolName] = true
	}

	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return false, fmt.Errorf("listing storage DaemonSets for retired-pool cleanup: %w", err)
	}
	sort.Slice(daemonSets.Items, func(i, j int) bool { return daemonSets.Items[i].Name < daemonSets.Items[j].Name })
	for i := range daemonSets.Items {
		ds := &daemonSets.Items[i]
		nodeLocalPoolName := ds.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || states[nodeLocalPoolName] != nil || hasNodes[nodeLocalPoolName] || !metav1.IsControlledBy(ds, cluster) {
			continue
		}
		log.Info("Deleting retired node-local pool DaemonSet", "name", ds.Name, "pool", nodeLocalPoolName)
		uid := ds.UID
		if err := r.Delete(ctx, ds, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
			return false, fmt.Errorf("deleting retired DaemonSet %s: %w", ds.Name, err)
		}
		// Do not delete any mounted config in the same reconciliation. Wait for
		// a direct read to prove this exact controller is gone, then for every
		// old or orphaned pool Pod to disappear below.
		return true, nil
	}

	poolPods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, poolPods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return false, fmt.Errorf("listing node-local-pool Pods for retired-pool cleanup: %w", err)
	}
	retiredPoolHasPods := make(map[string]bool)
	for i := range poolPods.Items {
		pod := &poolPods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || states[nodeLocalPoolName] != nil || hasNodes[nodeLocalPoolName] {
			continue
		}
		if isStorageDaemonSetPodForPool(cluster, nodeLocalPoolName, pod) ||
			(pod.Labels[labelAppManagedBy] == operatorName && pod.Labels[labelStorageGroup] == storageGroupNodeLocal) {
			retiredPoolHasPods[nodeLocalPoolName] = true
		}
	}

	// A config resource can outlive a manually deleted DaemonSet. Pool-labelled
	// ConfigMaps and Secrets remain discoverable once the pool has neither
	// desired state nor a GarageNode role. The deletion helper additionally
	// retains every exact resource still mounted by a lingering Pod.
	retiredPools := make(map[string]struct{})
	configMaps := &corev1.ConfigMapList{}
	if err := r.nodeLocalPoolReader().List(ctx, configMaps,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return false, fmt.Errorf("listing ConfigMaps for retired-pool cleanup: %w", err)
	}
	for i := range configMaps.Items {
		cm := &configMaps.Items[i]
		nodeLocalPoolName := cm.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || states[nodeLocalPoolName] != nil || hasNodes[nodeLocalPoolName] || !metav1.IsControlledBy(cm, cluster) {
			continue
		}
		retiredPools[nodeLocalPoolName] = struct{}{}
	}
	secrets := &corev1.SecretList{}
	if err := r.nodeLocalPoolReader().List(ctx, secrets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return false, fmt.Errorf("listing Secrets for retired-pool cleanup: %w", err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		nodeLocalPoolName := secret.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || states[nodeLocalPoolName] != nil || hasNodes[nodeLocalPoolName] || !metav1.IsControlledBy(secret, cluster) {
			continue
		}
		retiredPools[nodeLocalPoolName] = struct{}{}
	}
	nodeLocalPoolNames := make([]string, 0, len(retiredPools))
	for nodeLocalPoolName := range retiredPools {
		nodeLocalPoolNames = append(nodeLocalPoolNames, nodeLocalPoolName)
	}
	sort.Strings(nodeLocalPoolNames)
	pending := len(retiredPoolHasPods) > 0
	for _, nodeLocalPoolName := range nodeLocalPoolNames {
		if retiredPoolHasPods[nodeLocalPoolName] {
			continue
		}
		if err := r.deleteNodeLocalPoolConfigMap(ctx, cluster, nodeLocalPoolName); err != nil {
			return false, err
		}
		pending = true
	}
	return pending, nil
}

func (r *GarageClusterReconciler) deleteNodeLocalPoolConfigMap(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
) error {
	referenced, err := garageConfigResourcesReferencedByPods(ctx, r.nodeLocalPoolReader(), cluster.Namespace)
	if err != nil {
		return fmt.Errorf("listing Pods before deleting node-local pool %q config resources: %w", nodeLocalPoolName, err)
	}
	configMaps := &corev1.ConfigMapList{}
	if err := r.nodeLocalPoolReader().List(ctx, configMaps, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing node-local pool %q ConfigMaps: %w", nodeLocalPoolName, err)
	}
	for i := range configMaps.Items {
		configMap := &configMaps.Items[i]
		if !isStorageDaemonSetConfigMapName(cluster, nodeLocalPoolName, configMap.Name) ||
			!metav1.IsControlledBy(configMap, cluster) {
			continue
		}
		if _, inUse := referenced[garageConfigResourceReference{name: configMap.Name}]; inUse {
			continue
		}
		uid := configMap.UID
		if err := r.Delete(ctx, configMap, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
			return fmt.Errorf(
				"deleting node-local pool %q ConfigMap %s: %w",
				nodeLocalPoolName,
				configMap.Name,
				err,
			)
		}
	}
	secrets := &corev1.SecretList{}
	if err := r.nodeLocalPoolReader().List(ctx, secrets, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing node-local pool %q Secrets: %w", nodeLocalPoolName, err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if !isStorageDaemonSetConfigMapName(cluster, nodeLocalPoolName, secret.Name) ||
			!metav1.IsControlledBy(secret, cluster) {
			continue
		}
		if _, inUse := referenced[garageConfigResourceReference{name: secret.Name, secretBacked: true}]; inUse {
			continue
		}
		uid := secret.UID
		if err := r.Delete(ctx, secret, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
			return fmt.Errorf("deleting node-local pool %q Secret %s: %w", nodeLocalPoolName, secret.Name, err)
		}
	}
	return nil
}

// deleteStorageDaemonSet is the cluster-finalization cleanup path. Layout
// roles have already been removed by the cluster finalizer, so all activation
// labels and owned pool resources may now be deleted together. HostPath data
// is deliberately left on the Kubernetes Nodes.
func (r *GarageClusterReconciler) deleteStorageDaemonSet(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	if !r.ClusterScoped {
		daemonSets := &appsv1.DaemonSetList{}
		if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
			client.InNamespace(cluster.Namespace),
			client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
		); err != nil {
			return err
		}
		hasOwnedPoolDaemonSet := false
		for i := range daemonSets.Items {
			if daemonSets.Items[i].Labels[labelNodeLocalPool] != "" &&
				metav1.IsControlledBy(&daemonSets.Items[i], cluster) {
				hasOwnedPoolDaemonSet = true
				break
			}
		}
		if hasNodeLocalPools(cluster) || hasOwnedPoolDaemonSet ||
			meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady) != nil {
			return fmt.Errorf(
				"cannot finalize a GarageCluster that has used storage.nodeLocalPools from a namespace-scoped operator: cluster-scoped Node patch permission is required to remove drain-safety activation labels",
			)
		}
		return nil
	}

	nodes := &corev1.NodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes); err != nil {
		return err
	}
	prefix := nodeLocalPoolActivationClusterPrefix(cluster)
	retainedAnnotationPrefix := nodeLocalPoolRetainedAnnotationClusterPrefix(cluster)
	removedActivation := false
	for i := range nodes.Items {
		node := &nodes.Items[i]
		changed := false
		for key := range node.Labels {
			if strings.HasPrefix(key, prefix) {
				delete(node.Labels, key)
				changed = true
			}
		}
		if !changed {
			continue
		}
		if err := r.Update(ctx, node); err != nil {
			return fmt.Errorf("fencing node-local-pool scheduling on Kubernetes Node %q by resourceVersion CAS: %w", node.Name, err)
		}
		removedActivation = true
	}
	if removedActivation {
		return fmt.Errorf("%w: waiting for node-local-pool activation-label fences to become observable before deleting their DaemonSets", errLayoutMutationPending)
	}

	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return err
	}
	deletedDaemonSet := false
	for i := range daemonSets.Items {
		ds := &daemonSets.Items[i]
		if !metav1.IsControlledBy(ds, cluster) || ds.Labels[labelNodeLocalPool] == "" {
			continue
		}
		if err := r.Delete(ctx, ds); err != nil && !errors.IsNotFound(err) {
			return err
		}
		deletedDaemonSet = true
	}

	// Defensive cleanup for the unreleased prototype's singular resource name.
	legacy := &appsv1.DaemonSet{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: cluster.Name + "-storage", Namespace: cluster.Namespace}, legacy); err == nil {
		if metav1.IsControlledBy(legacy, cluster) {
			if err := r.Delete(ctx, legacy); err != nil && !errors.IsNotFound(err) {
				return err
			}
			deletedDaemonSet = true
		}
	} else if !errors.IsNotFound(err) {
		return err
	}
	if deletedDaemonSet {
		return fmt.Errorf("%w: waiting for deleted node-local-pool DaemonSets and their Pods to disappear", errLayoutMutationPending)
	}

	// A background DaemonSet deletion can make the controller object disappear
	// before its bound or Pending Pods. Pending Pods are included because the
	// scheduler may already have accepted an exact target-node affinity from the
	// old controller generation.
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return err
	}
	var pendingPods []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		owner := metav1.GetControllerOf(pod)
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		poolPod := nodeLocalPoolName != "" && isStorageDaemonSetPodForPool(cluster, nodeLocalPoolName, pod)
		legacyPod := owner != nil && owner.Kind == daemonSetKind && owner.Name == cluster.Name+"-storage"
		if poolPod || legacyPod {
			pendingPods = append(pendingPods, pod.Name)
		}
	}
	if len(pendingPods) > 0 {
		sort.Strings(pendingPods)
		return fmt.Errorf("%w: waiting for node-local-pool Pods to disappear before releasing durable HostPath claims: %s",
			errLayoutMutationPending, strings.Join(pendingPods, ", "))
	}

	for i := range nodes.Items {
		node := &nodes.Items[i]
		// Refresh after all workload deletions. The Node resourceVersion CAS
		// serializes claim release against every other GarageCluster activation.
		fresh := &corev1.Node{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return err
		}
		changed := false
		for key := range fresh.Annotations {
			if strings.HasPrefix(key, retainedAnnotationPrefix) {
				delete(fresh.Annotations, key)
				changed = true
			}
		}
		if changed {
			if err := r.Update(ctx, fresh); err != nil {
				return fmt.Errorf("releasing node-local-pool identity records from Kubernetes Node %q by resourceVersion CAS: %w", fresh.Name, err)
			}
		}
	}
	return nil
}
