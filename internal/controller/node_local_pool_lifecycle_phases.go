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

// nodeLocalPoolLifecyclePhaseResult makes every lifecycle boundary explicit:
// a phase either advances, stops after publishing a durable condition, or
// fails. A successful status write can return a nil error, so Stop cannot be
// inferred from Err alone.
type nodeLocalPoolLifecyclePhaseResult struct {
	Stop bool
	Err  error
}

func nodeLocalPoolPhaseContinue() nodeLocalPoolLifecyclePhaseResult {
	return nodeLocalPoolLifecyclePhaseResult{}
}

func nodeLocalPoolPhaseStop(err error) nodeLocalPoolLifecyclePhaseResult {
	return nodeLocalPoolLifecyclePhaseResult{Stop: true, Err: err}
}

func nodeLocalPoolPhaseFail(err error) nodeLocalPoolLifecyclePhaseResult {
	return nodeLocalPoolLifecyclePhaseResult{Err: err}
}

// nodeLocalPoolLifecycleTransition is the one-reconcile snapshot passed
// between phases. Each phase owns only the fields named by its result type;
// live API revalidation remains inside the safety boundaries that perform a
// mutation.
type nodeLocalPoolLifecycleTransition struct {
	reconciler   *GarageClusterReconciler
	ctx          context.Context
	cluster      *garagev1beta2.GarageCluster
	configHashes map[string]string

	states     map[string]*nodeLocalPoolState
	emptyPools []string
	// persistedRetirements is the one-way membership boundary read from each
	// Kubernetes Node's durable HostPath claim. Selector restoration does not
	// cancel a retirement after this bit is written: the existing GarageNode stays
	// online as a stale member until its ordinary drain completes, then cleanup
	// may release the activation and claim before a fresh identity is allowed.
	persistedRetirements     map[string]bool
	existing                 map[string]*garagev1beta1.GarageNode
	existingByPair           map[string]*garagev1beta1.GarageNode
	existingByKubernetesNode map[string]*garagev1beta1.GarageNode
	actors                   *nodeLocalPoolActorObservation
	activationPlan           *nodeLocalPoolActivationPlan
	activation               *nodeLocalPoolActivationResult
	members                  *nodeLocalPoolMaterializationResult
}

type nodeLocalPoolActorObservation struct {
	recoveryPins   *nodeLocalPoolRecoveryPins
	daemonSetUIDs  map[string]types.UID
	poolPodsByNode map[string][]*corev1.Pod
}

type nodeLocalPoolActivationAction struct {
	nodeLocalPoolName string
	state             *nodeLocalPoolState
	node              *corev1.Node
	recoveryNodeID    string
	operation         string
}

type nodeLocalPoolActivationPlan struct {
	immediateActions       []nodeLocalPoolActivationAction
	newActions             []nodeLocalPoolActivationAction
	blockedMoves           []string
	waitingForPreviousPods []string
}

type nodeLocalPoolActivationResult struct {
	activatedMembers []string
	waitingMessage   string
}

type nodeLocalPoolMaterializationResult struct {
	desiredPairs  map[string]bool
	unreadyByPool map[string][]string
	allUnready    []string
}

// preflight snapshots desired membership and durable generated identities. It
// fails before claim, workload, or Node activation mutation when selectors,
// scale bounds, identities, or cross-cluster HostPaths are ambiguous.
func (t *nodeLocalPoolLifecycleTransition) preflight() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster

	required, err := r.nodeLocalPoolPrerequisitesRequired(ctx, cluster)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if required {
		if err := r.assertNodeLocalPoolPrerequisites(ctx, cluster); err != nil {
			return nodeLocalPoolPhaseFail(err)
		}
	}
	if hasNodeLocalPools(cluster) && !r.ClusterScoped {
		return nodeLocalPoolPhaseFail(fmt.Errorf(
			"spec.storage.nodeLocalPools requires a cluster-scoped operator install (Node labels are the drain-safe membership boundary and cannot be managed by a namespace-scoped Role); redeploy without --watch-namespaces/WATCH_NAMESPACE",
		))
	}
	existing, identityCollisions, err := r.listNodeLocalPoolStorageNodes(ctx, cluster)
	if err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("listing node-local-pool-backed GarageNodes: %w", err))
	}
	t.existing = existing
	if len(identityCollisions) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(
			ctx,
			cluster,
			metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolIdentityCollision,
			summarizeNodeLocalPoolItems(
				"multiple GarageNodes report one durable Garage node ID; stop the duplicate process and provision a unique metadata directory before continuing",
				identityCollisions,
			),
		))
	}

	t.states = make(map[string]*nodeLocalPoolState)
	if cluster.Spec.Storage != nil && len(cluster.Spec.Storage.NodeLocalPools) > 0 {
		membership, err := r.readNodeLocalPoolMembership(ctx, cluster)
		if err != nil {
			return nodeLocalPoolPhaseFail(err)
		}
		if len(membership.selectorConflicts) > 0 {
			return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeLocalPoolSelectorConflict,
				summarizeNodeLocalPoolItems(
					"Kubernetes Nodes match more than one node-local pool; change selectors so every Node belongs to at most one pool",
					membership.selectorConflicts,
				)))
		}
		if membership.selectedMembers > maxNodeLocalPoolMembers {
			return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeLocalPoolMemberLimitExceeded,
				fmt.Sprintf(
					"node-local pool selectors choose %d Kubernetes Nodes, above the supported per-GarageCluster maximum of %d; no HostPath claim, DaemonSet, or Node activation was changed",
					membership.selectedMembers, maxNodeLocalPoolMembers,
				)))
		}
		t.emptyPools = membership.emptyPools
		t.persistedRetirements = excludePersistedNodeLocalPoolRetirements(cluster, membership)
		for i := range cluster.Spec.Storage.NodeLocalPools {
			pool := &cluster.Spec.Storage.NodeLocalPools[i]
			hash, found := t.configHashes[pool.Name]
			if !found {
				return nodeLocalPoolPhaseFail(fmt.Errorf("node-local pool %q config hash was not generated", pool.Name))
			}
			t.states[pool.Name] = &nodeLocalPoolState{
				pool:            pool,
				activationLabel: nodeLocalPoolActivationLabel(cluster, pool.Name),
				activationValue: nodeLocalPoolActivationLabelValue,
				configHash:      hash,
				desiredNodes:    membership.desiredNodesByPool[pool.Name],
				activePods:      make(map[string]*corev1.Pod),
				terminatingPods: make(map[string]*corev1.Pod),
			}
		}
	}

	hostPathConflicts, err := r.nodeLocalPoolHostPathConflicts(ctx, cluster, t.states)
	if err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("checking node-local-pool HostPath ownership across GarageClusters: %w", err))
	}
	if len(hostPathConflicts) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolHostPathConflict,
			summarizeNodeLocalPoolItems(
				"refusing to activate overlapping node-local storage owned by another GarageCluster",
				hostPathConflicts,
			)))
	}
	return nodeLocalPoolPhaseContinue()
}

// excludePersistedNodeLocalPoolRetirements projects the user selector through
// the durable one-way retirement boundary. It mutates only the in-memory
// membership snapshot: the Kubernetes Node remains selected in user intent,
// while activation/materialization treat this exact pair as stale until the
// old identity and retained claim have completed ordered cleanup.
func excludePersistedNodeLocalPoolRetirements(
	cluster *garagev1beta2.GarageCluster,
	membership *nodeLocalPoolMembership,
) map[string]bool {
	retirements := make(map[string]bool)
	if cluster == nil || membership == nil {
		return retirements
	}
	for nodeLocalPoolName, desiredNodes := range membership.desiredNodesByPool {
		claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, nodeLocalPoolName)
		for nodeName, node := range desiredNodes {
			claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[claimKey])
			if err != nil || !claim.Retiring ||
				claim.ClusterNamespace != cluster.Namespace || claim.ClusterName != cluster.Name ||
				claim.NodeLocalPoolName != nodeLocalPoolName {
				continue
			}
			key := nodeLocalPoolKey(nodeLocalPoolName, nodeName)
			retirements[key] = true
			delete(desiredNodes, nodeName)
		}
	}
	return retirements
}

// publishWorkloads serializes append-only claims before publishing any
// DaemonSet/config revision, then records the exact workload inputs consumed by
// later actor and gate phases.
func (t *nodeLocalPoolLifecycleTransition) publishWorkloads() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster

	if cluster.Status.StorageDrain == nil {
		for nodeLocalPoolName, state := range t.states {
			deployed := &appsv1.DaemonSet{}
			err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
				Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: cluster.Namespace,
			}, deployed)
			if errors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nodeLocalPoolPhaseFail(fmt.Errorf("reading node-local-pool workload %q before HostPath claim publication: %w", nodeLocalPoolName, err))
			}
			if !metav1.IsControlledBy(deployed, cluster) {
				return nodeLocalPoolPhaseFail(fmt.Errorf("existing DaemonSet %s/%s is not owned by GarageCluster %s/%s",
					deployed.Namespace, deployed.Name, cluster.Namespace, cluster.Name))
			}
			activationValue := nodeLocalPoolActivationValueForDaemonSet(deployed)
			if activationValue == nodeLocalPoolActivationFenceValue || activationValue == nodeLocalPoolActivationQuarantineValue {
				continue
			}
			for _, nodeName := range sortedNodeNames(state.desiredNodes) {
				node := state.desiredNodes[nodeName]
				if node.Labels[state.activationLabel] != activationValue {
					continue
				}
				if value := node.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, nodeLocalPoolName)]; value != "" {
					claim, claimErr := decodeNodeLocalPoolHostPathClaim(value)
					if claimErr != nil {
						return nodeLocalPoolPhaseFail(fmt.Errorf("decoding node-local pool %q HostPath claim on Kubernetes Node %q: %w", nodeLocalPoolName, nodeName, claimErr))
					}
					if claim.Retiring {
						continue
					}
				}
				if err := r.ensureNodeLocalPoolActivation(
					ctx, cluster, state.pool, node,
					state.activationLabel, activationValue,
					nodeLocalPoolRecoveryNodeIDAnnotation(cluster, nodeLocalPoolName), "",
				); err != nil {
					return nodeLocalPoolPhaseFail(fmt.Errorf(
						"publishing node-local pool %q HostPath claim on Kubernetes Node %q before workload update: %w",
						nodeLocalPoolName, nodeName, err,
					))
				}
			}
		}
	}

	var activationMoves []string
	clusterActivationPrefix := nodeLocalPoolActivationClusterPrefix(cluster)
	for nodeLocalPoolName, state := range t.states {
		for _, nodeName := range sortedNodeNames(state.desiredNodes) {
			node := state.desiredNodes[nodeName]
			for key := range node.Labels {
				if strings.HasPrefix(key, clusterActivationPrefix) && key != state.activationLabel {
					activationMoves = append(activationMoves,
						fmt.Sprintf("%s:existing-activation=%s->%s", nodeName, key, nodeLocalPoolName))
				}
			}
		}
	}
	sort.Strings(activationMoves)
	if len(activationMoves) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolMoveBlocked,
			summarizeNodeLocalPoolItems(
				"refusing a direct Kubernetes Node move between node-local pools; remove the node from every pool, wait for its activation label and old pool pod to disappear, then select the new pool",
				activationMoves,
			)))
	}

	nodeLocalPoolNames := make([]string, 0, len(t.states))
	for nodeLocalPoolName := range t.states {
		nodeLocalPoolNames = append(nodeLocalPoolNames, nodeLocalPoolName)
	}
	sort.Strings(nodeLocalPoolNames)
	for _, nodeLocalPoolName := range nodeLocalPoolNames {
		state := t.states[nodeLocalPoolName]
		if err := r.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, state.pool, state.activationLabel, state.configHash,
		); err != nil {
			return nodeLocalPoolPhaseFail(fmt.Errorf("reconciling node-local-pool workload %q: %w", nodeLocalPoolName, err))
		}
		deployed := &appsv1.DaemonSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: cluster.Namespace,
		}, deployed); err != nil {
			return nodeLocalPoolPhaseFail(fmt.Errorf("reading desired workload revision for node-local pool %q: %w", nodeLocalPoolName, err))
		}
		state.desiredPodSpecHash = deployed.Spec.Template.Annotations[annotationPodSpecHash]
		if state.desiredPodSpecHash == "" {
			return nodeLocalPoolPhaseFail(fmt.Errorf("node-local pool %q workload template has no operator pod-spec-hash", nodeLocalPoolName))
		}
		if deployed.Spec.Template.Annotations[annotationConfigHash] != state.configHash {
			return nodeLocalPoolPhaseFail(fmt.Errorf("node-local pool %q workload template does not publish desired config hash %s", nodeLocalPoolName, state.configHash))
		}
		state.workloadUID = deployed.UID
		state.activationValue = nodeLocalPoolActivationValueForDaemonSet(deployed)
		if state.activationValue == nodeLocalPoolActivationFenceValue {
			return nodeLocalPoolPhaseFail(fmt.Errorf("node-local pool %q workload is still behind a rollout-adoption fence", nodeLocalPoolName))
		}
	}

	if len(t.states) == 0 && len(t.existing) == 0 {
		daemonSets := &appsv1.DaemonSetList{}
		if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
			client.InNamespace(cluster.Namespace),
			client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
		); err != nil {
			return nodeLocalPoolPhaseFail(err)
		}
		hasRetiredPool := false
		for i := range daemonSets.Items {
			if daemonSets.Items[i].Labels[labelNodeLocalPool] != "" && metav1.IsControlledBy(&daemonSets.Items[i], cluster) {
				hasRetiredPool = true
				break
			}
		}
		usedNodeLocalPools := meta.FindStatusCondition(
			cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady,
		) != nil
		if !hasRetiredPool && !usedNodeLocalPools {
			return nodeLocalPoolPhaseStop(r.clearNodeLocalPoolsCondition(ctx, cluster))
		}
		if !r.ClusterScoped {
			return nodeLocalPoolPhaseFail(fmt.Errorf("retired node-local pools still require a cluster-scoped operator to finish Node-label cleanup"))
		}
	}

	t.existingByPair = make(map[string]*garagev1beta1.GarageNode, len(t.existing))
	t.existingByKubernetesNode = make(map[string]*garagev1beta1.GarageNode, len(t.existing))
	for _, node := range t.existing {
		key := nodeLocalPoolKey(node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)
		if previous := t.existingByPair[key]; previous != nil && previous.Name != node.Name {
			return nodeLocalPoolPhaseFail(fmt.Errorf("multiple node-local-pool-backed GarageNodes claim pool %q on Kubernetes Node %q: %s and %s",
				node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName, previous.Name, node.Name))
		}
		t.existingByPair[key] = node
		if previous := t.existingByKubernetesNode[node.Spec.KubernetesNodeName]; previous != nil &&
			previous.Spec.NodeLocalPoolName != node.Spec.NodeLocalPoolName {
			return nodeLocalPoolPhaseFail(fmt.Errorf(
				"kubernetes node %q is still claimed by node-local pools %q and %q; drain one identity before activating another",
				node.Spec.KubernetesNodeName, previous.Spec.NodeLocalPoolName, node.Spec.NodeLocalPoolName,
			))
		}
		t.existingByKubernetesNode[node.Spec.KubernetesNodeName] = node
	}
	return nodeLocalPoolPhaseContinue()
}

// observeActors retires obsolete scheduling state before taking one exact Pod
// and durable-identity snapshot for activation and GarageNode materialization.
func (t *nodeLocalPoolLifecycleTransition) observeActors() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster

	cleanup, err := r.cleanupNodeLocalPoolActivationState(ctx, cluster, t.states, t.existingByPair)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if cleanup.workloadTeardownBlocked {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			"waiting for retired node-local-pool workload generations and Node scheduling fences to be observed in order"))
	}
	if cleanup.blocksActivation {
		// Membership retirement can rotate the DaemonSet activation token and
		// replace a surviving Pod before retained HostPath claims are eligible
		// for deletion. Claim cleanup may need the Garage Admin API, whose exact
		// managed-Pod proof in turn needs that replacement process online. Let
		// the ordinary final authorization point release only replacements that
		// still satisfy every current-DaemonSet, target-Node, selector, token,
		// HostPath-claim, persisted-identity, and old-Pod exclusion check. Any
		// ambiguous or retired-controller Pod remains gated, and cleanup still
		// stops this reconciliation below.
		if _, _, err := r.releaseNodeLocalPoolPodSchedulingGates(ctx, cluster, t.states); err != nil {
			return nodeLocalPoolPhaseFail(fmt.Errorf(
				"releasing safe surviving node-local-pool replacement Pods during retirement cleanup: %w", err,
			))
		}
	}
	retiredResourcesPending, err := r.cleanupRetiredNodeLocalPoolResources(ctx, cluster, t.states, t.existing)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if retiredResourcesPending {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			"waiting for retired node-local-pool DaemonSets and Pods to disappear before deleting their immutable config revisions"))
	}
	if cleanup.blocksActivation {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			"waiting for retired node-local-pool scheduling fences, Pods, and durable HostPath claims to be released in order"))
	}

	recoveryPins, err := r.resolveNodeLocalPoolRecoveryPins(ctx, cluster, t.states, t.existingByPair)
	if err != nil {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(
			ctx,
			cluster,
			metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolIdentityCollision,
			"refusing node-local-pool recovery because its durable identity evidence is ambiguous: "+err.Error(),
		))
	}
	daemonSetUIDs, err := r.ownedNodeLocalPoolDaemonSetUIDs(ctx, cluster)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	observation := &nodeLocalPoolActorObservation{
		recoveryPins:   recoveryPins,
		daemonSetUIDs:  daemonSetUIDs,
		poolPodsByNode: make(map[string][]*corev1.Pod),
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("listing node-local-pool pods: %w", err))
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		if pod.Spec.NodeName == "" || nodeLocalPoolName == "" ||
			pod.Labels[labelStorageGroup] != storageGroupNodeLocal ||
			pod.Labels[labelAppManagedBy] != operatorName {
			continue
		}
		// A Pod whose DaemonSet was deleted out of band still owns a running
		// Garage process. Keep it in the per-Node move fence; only an exact live
		// DaemonSet UID may materialize or update generated GarageNode state.
		observation.poolPodsByNode[pod.Spec.NodeName] = append(observation.poolPodsByNode[pod.Spec.NodeName], pod)
		if !isStorageDaemonSetPodForPoolUID(cluster, nodeLocalPoolName, daemonSetUIDs[nodeLocalPoolName], pod) {
			continue
		}
		state := t.states[nodeLocalPoolName]
		if state == nil {
			continue
		}
		if !pod.DeletionTimestamp.IsZero() {
			state.terminatingPods[pod.Spec.NodeName] = pod
			continue
		}
		if err := r.ensureDaemonSetPodNodeLabel(ctx, pod); err != nil {
			return nodeLocalPoolPhaseFail(fmt.Errorf("labelling node-local pool %q pod %s: %w", nodeLocalPoolName, pod.Name, err))
		}
		if current := state.activePods[pod.Spec.NodeName]; current == nil ||
			current.CreationTimestamp.Before(&pod.CreationTimestamp) {
			state.activePods[pod.Spec.NodeName] = pod
		}
	}
	t.actors = observation
	return nodeLocalPoolPhaseContinue()
}

// planActivations observes exact current Nodes and records every mutation the
// execution phase may perform. No Node activation is changed in this phase.
func (t *nodeLocalPoolLifecycleTransition) planActivations() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster
	plan := &nodeLocalPoolActivationPlan{}

	for nodeLocalPoolName, state := range t.states {
		for _, nodeName := range sortedNodeNames(state.desiredNodes) {
			if owner := t.existingByKubernetesNode[nodeName]; owner != nil && owner.Spec.NodeLocalPoolName != nodeLocalPoolName {
				plan.blockedMoves = append(plan.blockedMoves,
					fmt.Sprintf("%s:%s->%s", nodeName, owner.Spec.NodeLocalPoolName, nodeLocalPoolName))
				continue
			}
			previousPod := ""
			for _, pod := range t.actors.poolPodsByNode[nodeName] {
				owner := metav1.GetControllerOf(pod)
				if pod.Labels[labelNodeLocalPool] != nodeLocalPoolName || owner == nil ||
					owner.Kind != daemonSetKind || owner.UID != t.actors.daemonSetUIDs[nodeLocalPoolName] {
					previousPod = pod.Name
					break
				}
			}
			if previousPod != "" {
				plan.waitingForPreviousPods = append(plan.waitingForPreviousPods,
					fmt.Sprintf("%s:%s", nodeName, previousPod))
				continue
			}

			k8sNode := &corev1.Node{}
			if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: nodeName}, k8sNode); err != nil {
				return nodeLocalPoolPhaseFail(fmt.Errorf("getting Kubernetes Node %q for node-local pool %q activation: %w", nodeName, nodeLocalPoolName, err))
			}
			state.desiredNodes[nodeName] = k8sNode
			key := nodeLocalPoolKey(nodeLocalPoolName, nodeName)
			recoveryNodeID := t.actors.recoveryPins.nodeIDs[key]
			action := nodeLocalPoolActivationAction{
				nodeLocalPoolName: nodeLocalPoolName,
				state:             state,
				node:              k8sNode,
				recoveryNodeID:    recoveryNodeID,
			}
			if k8sNode.Labels[state.activationLabel] == state.activationValue {
				if cluster.Status.StorageDrain == nil {
					action.operation = "revalidate"
					plan.immediateActions = append(plan.immediateActions, action)
				}
				continue
			}
			if t.existingByPair[key] == nil {
				action.operation = "new"
				plan.newActions = append(plan.newActions, action)
				continue
			}
			resolvedNodeID, resolveErr := t.existingByPair[key].ResolvedGarageNodeID()
			if resolveErr != nil {
				return nodeLocalPoolPhaseFail(fmt.Errorf(
					"resolving retained identity for GarageNode %s/%s before node-local pool %q activation: %w",
					t.existingByPair[key].Namespace, t.existingByPair[key].Name, nodeLocalPoolName, resolveErr,
				))
			}
			if garageNodeAcknowledgesLostSource(t.existingByPair[key], resolvedNodeID) {
				// Lost-source acknowledgement is an immutable recovery fence. It
				// wins over ordinary desired-pool restoration until the explicit
				// recovery transaction completes.
				continue
			}
			action.operation = "restore"
			plan.immediateActions = append(plan.immediateActions, action)
		}
	}
	t.activationPlan = plan
	return nodeLocalPoolPhaseContinue()
}

// executeActivations applies the explicit plan. Cold recovery may authorize
// all already-committed identities together; genuinely new topology remains
// serialized through the cluster-wide layout barrier.
func (t *nodeLocalPoolLifecycleTransition) executeActivations() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster
	plan := t.activationPlan
	outcome := &nodeLocalPoolActivationResult{}

	for _, action := range plan.immediateActions {
		if err := r.ensureNodeLocalPoolActivation(
			ctx,
			cluster,
			action.state.pool,
			action.node,
			action.state.activationLabel,
			action.state.activationValue,
			nodeLocalPoolRecoveryNodeIDAnnotation(cluster, action.nodeLocalPoolName),
			action.recoveryNodeID,
		); err != nil {
			if action.operation == "revalidate" {
				return nodeLocalPoolPhaseFail(fmt.Errorf("revalidating active node-local pool %q on Kubernetes Node %q: %w",
					action.nodeLocalPoolName, action.node.Name, err))
			}
			return nodeLocalPoolPhaseFail(fmt.Errorf("activating Kubernetes Node %q for node-local pool %q: %w",
				action.node.Name, action.nodeLocalPoolName, err))
		}
	}

	sort.Strings(plan.blockedMoves)
	if len(plan.blockedMoves) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolMoveBlocked,
			summarizeNodeLocalPoolItems(
				"refusing a direct Kubernetes Node move between node-local pools; remove the node from every pool, wait for its GarageNode and old pool pod to disappear, then select the new pool",
				plan.blockedMoves,
			)))
	}
	sort.Strings(plan.waitingForPreviousPods)
	if len(plan.waitingForPreviousPods) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForPreviousPod,
			summarizeNodeLocalPoolItems(
				"waiting for the previous pool pod to terminate before activating another pool on the same Kubernetes Node",
				plan.waitingForPreviousPods,
			)))
	}

	if len(plan.newActions) > 0 {
		sort.Slice(plan.newActions, func(i, j int) bool {
			if plan.newActions[i].nodeLocalPoolName != plan.newActions[j].nodeLocalPoolName {
				return plan.newActions[i].nodeLocalPoolName < plan.newActions[j].nodeLocalPoolName
			}
			return plan.newActions[i].node.Name < plan.newActions[j].node.Name
		})
		freshActivations := make([]nodeLocalPoolActivationAction, 0, len(plan.newActions))
		for _, action := range plan.newActions {
			if action.recoveryNodeID == "" {
				freshActivations = append(freshActivations, action)
				continue
			}
			// These are already committed identities whose processes are
			// unavailable. Recover the exact pinned batch together so layout
			// convergence cannot deadlock on a withheld historical peer.
			if err := r.ensureNodeLocalPoolActivation(
				ctx,
				cluster,
				action.state.pool,
				action.node,
				action.state.activationLabel,
				action.state.activationValue,
				nodeLocalPoolRecoveryNodeIDAnnotation(cluster, action.nodeLocalPoolName),
				action.recoveryNodeID,
			); err != nil {
				return nodeLocalPoolPhaseFail(fmt.Errorf("recovering Kubernetes Node %q for node-local pool %q: %w",
					action.node.Name, action.nodeLocalPoolName, err))
			}
			outcome.activatedMembers = append(outcome.activatedMembers, action.nodeLocalPoolName+"/"+action.node.Name)
		}

		// Never mix genuinely new topology with cold recovery. Recovered roles
		// must first make their old layout observable and settled.
		if len(freshActivations) > 0 && len(outcome.activatedMembers) == 0 {
			ready, storageBootstrap, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, true)
			if barrierErr != nil {
				waitingMessage = "refusing to activate new node-local-pool identities until Garage layout convergence can be verified: " + barrierErr.Error()
			}
			if barrierErr != nil || !ready {
				outcome.waitingMessage = waitingMessage
				if t.actors.recoveryPins.layoutErr != nil {
					outcome.waitingMessage += "; committed node-local-pool recovery roles could not be read: " + t.actors.recoveryPins.layoutErr.Error()
				}
			} else {
				if !storageBootstrap {
					freshActivations = freshActivations[:1]
				}
				for _, action := range freshActivations {
					if err := r.ensureNodeLocalPoolActivation(
						ctx,
						cluster,
						action.state.pool,
						action.node,
						action.state.activationLabel,
						action.state.activationValue,
						nodeLocalPoolRecoveryNodeIDAnnotation(cluster, action.nodeLocalPoolName),
						"",
					); err != nil {
						if stderrors.Is(err, errNodeLocalPoolGarageRoleLimit) {
							return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(
								ctx, cluster, metav1.ConditionFalse,
								garagev1beta1.ReasonNodeLocalPoolGarageRoleLimitExceeded,
								err.Error(),
							))
						}
						return nodeLocalPoolPhaseFail(fmt.Errorf("activating Kubernetes Node %q for node-local pool %q: %w",
							action.node.Name, action.nodeLocalPoolName, err))
					}
					outcome.activatedMembers = append(outcome.activatedMembers, action.nodeLocalPoolName+"/"+action.node.Name)
				}
			}
		}
	}

	releasedMembers, gateBlocked, err := r.releaseNodeLocalPoolPodSchedulingGates(ctx, cluster, t.states)
	if err != nil {
		return nodeLocalPoolPhaseFail(fmt.Errorf("releasing node-local-pool Pod scheduling gates: %w", err))
	}
	outcome.activatedMembers = append(outcome.activatedMembers, releasedMembers...)
	if len(gateBlocked) > 0 {
		sort.Strings(gateBlocked)
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForPreviousPod,
			summarizeNodeLocalPoolItems(
				"keeping current node-local-pool Pods scheduler-gated while an older or ambiguous Pod could still mount the same HostPaths",
				gateBlocked,
			)))
	}
	t.activation = outcome
	return nodeLocalPoolPhaseContinue()
}

// materializeMembers creates or updates generated GarageNodes only for exact
// current DaemonSet Pods, then returns the desired/readiness inventory consumed
// by retirement and final status projection.
func (t *nodeLocalPoolLifecycleTransition) materializeMembers() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster
	log := logf.FromContext(ctx)
	result := &nodeLocalPoolMaterializationResult{desiredPairs: make(map[string]bool)}

	for nodeLocalPoolName, state := range t.states {
		for _, nodeName := range sortedNodeNames(state.desiredNodes) {
			k8sNode := state.desiredNodes[nodeName]
			key := nodeLocalPoolKey(nodeLocalPoolName, nodeName)
			result.desiredPairs[key] = true
			current := t.existingByPair[key]
			pod := state.activePods[nodeName]
			if pod == nil {
				continue
			}
			desired, err := r.buildNodeLocalPoolStorageNode(cluster, state.pool, k8sNode, pod)
			if err != nil {
				return nodeLocalPoolPhaseFail(fmt.Errorf("building GarageNode for pool %q Kubernetes Node %q: %w", nodeLocalPoolName, nodeName, err))
			}
			if current != nil {
				currentPin := strings.TrimSpace(current.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID])
				desiredPin := strings.TrimSpace(desired.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID])
				if currentPin != "" && desiredPin != "" && !strings.EqualFold(currentPin, desiredPin) {
					return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(
						ctx,
						cluster,
						metav1.ConditionFalse,
						garagev1beta1.ReasonNodeLocalPoolIdentityCollision,
						fmt.Sprintf(
							"GarageNode %s is pinned to Garage identity %s but Kubernetes Node %s now records %s; refusing to replace either durable identity",
							current.Name, shortID(currentPin), nodeName, shortID(desiredPin),
						),
					))
				}
				if currentPin != "" && desiredPin == "" {
					desired.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID] = currentPin
				}
			}
			if current == nil {
				log.Info("Creating node-local-pool-backed GarageNode", "name", desired.Name, "pool", nodeLocalPoolName, "kubernetesNode", nodeName)
				if err := r.Create(ctx, desired); err != nil {
					if errors.IsAlreadyExists(err) {
						return nodeLocalPoolPhaseFail(fmt.Errorf(
							"cannot create node-local-pool-backed GarageNode %s: that name already exists but is not an operator-owned child for pool %q on Kubernetes Node %q",
							desired.Name, nodeLocalPoolName, nodeName,
						))
					}
					return nodeLocalPoolPhaseFail(fmt.Errorf("creating GarageNode %s: %w", desired.Name, err))
				}
				t.existingByPair[key] = desired
				t.existing[desired.Name] = desired
				continue
			}

			if desired.Spec.Network == nil && current.Spec.Network != nil {
				network := *current.Spec.Network
				desired.Spec.Network = &network
			}
			if nodeLocalPoolCapacityIncreaseWaitsForPodRevision(
				current, desired, pod, state.desiredPodSpecHash, state.configHash,
			) {
				// Capacity is a layout publication. Preserve the committed value
				// until the exact Ready Pod revision proves it mounts the storage
				// and config that can satisfy the increased role.
				desired.Spec.Capacity = current.Spec.Capacity
			}
			if nodeLocalPoolStorageNodeNeedsUpdate(current, desired) {
				log.Info("Updating node-local-pool-backed GarageNode", "name", desired.Name, "pool", nodeLocalPoolName)
				updated, err := r.updateNodeLocalPoolGarageNode(ctx, cluster, current, desired)
				if err != nil {
					return nodeLocalPoolPhaseFail(fmt.Errorf("updating GarageNode %s: %w", current.Name, err))
				}
				current = updated
				t.existingByPair[key] = current
				t.existing[current.Name] = current
			}
		}
	}

	result.unreadyByPool = make(map[string][]string)
	for key := range result.desiredPairs {
		node := t.existingByPair[key]
		if node != nil && node.Status.NodeID != "" && node.Status.Connected &&
			node.Status.InLayout && node.DeletionTimestamp.IsZero() {
			continue
		}
		nodeLocalPoolName, nodeName, _ := strings.Cut(key, "\x00")
		member := nodeLocalPoolName + "/" + nodeName
		result.unreadyByPool[nodeLocalPoolName] = append(result.unreadyByPool[nodeLocalPoolName], member)
		result.allUnready = append(result.allUnready, member)
	}
	for nodeLocalPoolName := range result.unreadyByPool {
		sort.Strings(result.unreadyByPool[nodeLocalPoolName])
	}
	sort.Strings(result.allUnready)
	t.members = result
	return nodeLocalPoolPhaseContinue()
}

// retireOneMember selects at most one stale generated GarageNode after all
// desired replacements are settled. The source process stays online until its
// claim, drain proof, and layout removal transaction are durable.
func (t *nodeLocalPoolLifecycleTransition) retireOneMember() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster
	log := logf.FromContext(ctx)

	if t.activation.waitingMessage != "" {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, t.activation.waitingMessage))
	}

	var stale []*garagev1beta1.GarageNode
	var deleting []*garagev1beta1.GarageNode
	for _, node := range t.existing {
		key := nodeLocalPoolKey(node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)
		if t.members.desiredPairs[key] {
			continue
		}
		stale = append(stale, node)
		if !node.DeletionTimestamp.IsZero() {
			deleting = append(deleting, node)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].Name < stale[j].Name })

	if len(t.activation.activatedMembers) > 0 {
		sort.Strings(t.activation.activatedMembers)
		reason := garagev1beta1.ReasonNodeLocalPoolWaitingForMembers
		purpose := "identities"
		if len(stale) > 0 {
			reason = garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement
			purpose = "replacement identities"
		}
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			reason,
			summarizeNodeLocalPoolItems(
				"waiting for newly activated node-local-pool "+purpose+" to schedule, connect, and enter a settled Garage layout before another topology change",
				t.activation.activatedMembers,
			)))
	}

	if len(deleting) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			fmt.Sprintf("waiting for node-local-pool-backed GarageNode %s to leave the committed layout before stopping its pod", deleting[0].Name)))
	}

	if len(stale) == 0 {
		return nodeLocalPoolPhaseContinue()
	}
	candidate := stale[0]
	waiting := t.members.unreadyByPool[candidate.Spec.NodeLocalPoolName]
	if len(waiting) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement,
			summarizeNodeLocalPoolItems(
				fmt.Sprintf("waiting for replacement members of node-local pool %q to reach the committed Garage layout before draining %s",
					candidate.Spec.NodeLocalPoolName, candidate.Name),
				waiting,
			)))
	}
	if state := t.states[candidate.Spec.NodeLocalPoolName]; state != nil && len(state.desiredNodes) == 0 {
		if !t.persistedRetirements[nodeLocalPoolKey(candidate.Spec.NodeLocalPoolName, candidate.Spec.KubernetesNodeName)] {
			return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement,
				fmt.Sprintf("node-local pool %q is still declared but its selector matches no Kubernetes Nodes; retaining %s until a replacement is selected or the pool is removed from spec",
					candidate.Spec.NodeLocalPoolName, candidate.Name)))
		}
	}
	persistedRetirement := t.persistedRetirements[nodeLocalPoolKey(candidate.Spec.NodeLocalPoolName, candidate.Spec.KubernetesNodeName)]

	if len(cluster.Spec.RemoteClusters) == 0 {
		surviving, err := r.countSurvivingStorageNodes(ctx, cluster, candidate.Name)
		if err != nil {
			return nodeLocalPoolPhaseFail(err)
		}
		factor := replicationFactorOf(cluster)
		if factor > 0 && surviving < factor {
			return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeLocalPoolReplicationUnsafe,
				fmt.Sprintf("refusing to drain node-local-pool-backed GarageNode %s: only %d confirmed storage role(s) would survive, below replication.factor %d", candidate.Name, surviving, factor)))
		}
	}
	ready, _, waitingMessage, err := r.clusterLayoutReadyForMutation(ctx, cluster, false, candidate.Name)
	if err != nil {
		waitingMessage = fmt.Sprintf(
			"refusing to drain node-local-pool-backed GarageNode %s until Garage layout convergence can be verified: %v",
			candidate.Name,
			err,
		)
	}
	if err != nil || !ready {
		if persistedRetirement {
			waitingMessage = fmt.Sprintf(
				"persisted HostPath retirement for %s is one-way and overrides selector reselection; keeping its existing process online while Garage layout convergence remains unproven: %s",
				candidate.Name, waitingMessage,
			)
		}
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, waitingMessage))
	}
	if err := requireConsistentStorageDrain(cluster); err != nil {
		message := fmt.Sprintf("refusing to persist retirement for node-local-pool-backed GarageNode %s before storage-drain consistency preflight succeeds: %v", candidate.Name, err)
		if persistedRetirement {
			message = fmt.Sprintf(
				"persisted HostPath retirement for %s is one-way and overrides selector reselection; its existing process remains online and is not reactivated while literal consistent mode is unproven: %v",
				candidate.Name, err,
			)
		}
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, message))
	}
	if _, err := requireStorageDrainStartReady(cluster); err != nil {
		message := fmt.Sprintf("refusing to persist retirement for node-local-pool-backed GarageNode %s before storage rollout and health preflight succeeds: %v", candidate.Name, err)
		if persistedRetirement {
			message = fmt.Sprintf(
				"persisted HostPath retirement for %s is one-way and overrides selector reselection; its existing process remains online and is not reactivated while rollout/health preflight is blocked: %v",
				candidate.Name, err,
			)
		}
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety, message))
	}
	if err := r.markNodeLocalPoolClaimRetiring(
		ctx, cluster, candidate.Spec.NodeLocalPoolName, candidate.Spec.KubernetesNodeName,
	); err != nil {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			fmt.Sprintf("refusing to begin node-local-pool-backed GarageNode %s retirement without a durable, cancel-safe HostPath claim: %v", candidate.Name, err)))
	}
	if err := r.prepareGarageNodeDeletionDrain(ctx, cluster, candidate); err != nil {
		message := fmt.Sprintf("refusing to mark node-local-pool-backed GarageNode %s terminating until storage-drain preflight succeeds: %v", candidate.Name, err)
		if persistedRetirement {
			message = fmt.Sprintf(
				"persisted HostPath retirement for %s is one-way and overrides selector reselection; its existing process remains online and is not reactivated while storage-drain preflight is blocked: %v",
				candidate.Name, err,
			)
		}
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety,
			message))
	}
	log.Info("Draining stale node-local-pool-backed GarageNode", "name", candidate.Name,
		"pool", candidate.Spec.NodeLocalPoolName, "kubernetesNode", candidate.Spec.KubernetesNodeName)
	if err := r.Delete(ctx, candidate); err != nil && !errors.IsNotFound(err) {
		return nodeLocalPoolPhaseFail(fmt.Errorf("deleting GarageNode %s: %w", candidate.Name, err))
	}
	return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
		garagev1beta1.ReasonNodeLocalPoolDraining,
		fmt.Sprintf("draining node-local-pool-backed GarageNode %s before its pool pod is stopped", candidate.Name)))
}

// projectReadiness performs terminal cleanup only after no role needs the old
// activation and projects the single parent condition from bounded summaries.
func (t *nodeLocalPoolLifecycleTransition) projectReadiness() nodeLocalPoolLifecyclePhaseResult {
	r := t.reconciler
	ctx := t.ctx
	cluster := t.cluster

	// No Garage role needs a retired activation now. Remove Node scheduling
	// fences before deleting stale DaemonSets so Pod shutdown cannot race role
	// retirement or expose a second workload incarnation.
	cleanup, err := r.cleanupNodeLocalPoolActivationState(ctx, cluster, t.states, t.existingByPair)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if cleanup.workloadTeardownBlocked {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			"waiting for retired node-local-pool workload generations and Node scheduling fences to be observed in order"))
	}
	retiredResourcesPending, err := r.cleanupRetiredNodeLocalPoolResources(ctx, cluster, t.states, t.existing)
	if err != nil {
		return nodeLocalPoolPhaseFail(err)
	}
	if retiredResourcesPending || cleanup.pending {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolDraining,
			"waiting for retired node-local-pool scheduling fences, Pods, and durable HostPath claims to be released in order"))
	}
	if len(t.states) == 0 {
		return nodeLocalPoolPhaseStop(r.clearNodeLocalPoolsCondition(ctx, cluster))
	}
	if len(t.members.allUnready) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForMembers,
			summarizeNodeLocalPoolItems(
				"waiting for desired node-local-pool members to schedule, connect, and enter the committed Garage layout",
				t.members.allUnready,
			)))
	}
	if len(t.emptyPools) > 0 {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForMembers,
			summarizeNodeLocalPoolItems(
				"node-local-pool selectors currently match no Kubernetes Nodes",
				t.emptyPools,
			)))
	}

	ready, _, waitingMessage, err := r.clusterLayoutReadyForMutation(ctx, cluster, false)
	if err != nil {
		waitingMessage = "desired node-local-pool identities are in the current layout, but its synchronization state cannot be verified: " + err.Error()
	}
	if err != nil || !ready {
		return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync, waitingMessage))
	}
	return nodeLocalPoolPhaseStop(r.setNodeLocalPoolsCondition(ctx, cluster, metav1.ConditionTrue,
		garagev1beta1.ReasonNodeLocalPoolsConverged, "node-local-pool members are connected and Garage reports no active data migration"))
}
