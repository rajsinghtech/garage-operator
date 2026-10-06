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
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestNodeLocalPoolActivationPlanningIsReadOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("phase-plan", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   testKubernetesWorkerA,
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	scheme := deletionTestScheme(t)
	reconciler, kubeClient := deletionTestReconciler(scheme, kubernetesNode)
	state := &nodeLocalPoolState{
		pool:            pool,
		activationLabel: nodeLocalPoolActivationLabel(cluster, pool.Name),
		activationValue: nodeLocalPoolActivationLabelValue,
		desiredNodes: map[string]*corev1.Node{
			kubernetesNode.Name: kubernetesNode.DeepCopy(),
		},
	}
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler:               reconciler,
		ctx:                      ctx,
		cluster:                  cluster,
		states:                   map[string]*nodeLocalPoolState{pool.Name: state},
		existingByPair:           map[string]*garagev1beta1.GarageNode{},
		existingByKubernetesNode: map[string]*garagev1beta1.GarageNode{},
		actors: &nodeLocalPoolActorObservation{
			recoveryPins:   &nodeLocalPoolRecoveryPins{nodeIDs: map[string]string{}},
			daemonSetUIDs:  map[string]types.UID{},
			poolPodsByNode: map[string][]*corev1.Pod{},
		},
	}

	result := transition.planActivations()
	if result.Err != nil || result.Stop {
		t.Fatalf("planActivations() = %+v", result)
	}
	if transition.activationPlan == nil || len(transition.activationPlan.newActions) != 1 {
		t.Fatalf("activation plan = %#v, want one new action", transition.activationPlan)
	}
	fresh := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Name: kubernetesNode.Name}, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Labels[state.activationLabel] != "" ||
		fresh.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)] != "" {
		t.Fatalf("planning mutated durable Node activation state: labels=%#v annotations=%#v", fresh.Labels, fresh.Annotations)
	}
}

func TestPersistedNodeLocalPoolRetirementOverridesReselectionAcrossRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("phase-persisted-retirement", "a")
	cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{Factor: 1, ConsistencyMode: testDegradedMode}
	markGarageClusterDrainReady(cluster)
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claim.Retiring = true
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	recoveryKey := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA, UID: types.UID("persisted-retirement-node-uid"),
		Labels: map[string]string{
			testStorageOwnerLabelKey: "a", // selector was restored
			activationLabel:          nodeLocalPoolActivationLabelValue,
		},
		Annotations: map[string]string{claimKey: claimValue, recoveryKey: testTerminalNodeID},
	}}
	candidate := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "persisted-retirement-member", Namespace: cluster.Namespace,
			UID: types.UID("persisted-retirement-member-uid"), Generation: 1,
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:        garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:           garagev1beta1.NodeBackingNodeLocalPool,
			NodeLocalPoolName: pool.Name, KubernetesNodeName: kubernetesNode.Name,
			Zone: testZone, Capacity: ptr.To(pool.Capacity.DeepCopy()),
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testTerminalNodeID, Connected: true, InLayout: true, ObservedGeneration: 1,
		},
	}
	survivor := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "persisted-retirement-survivor", Namespace: cluster.Namespace, UID: "survivor-uid", Generation: 1},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Zone:       testZone, Capacity: ptr.To(pool.Capacity.DeepCopy()),
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Connected: true, InLayout: true, ObservedGeneration: 1,
		},
	}
	reconciler, kubeClient := deletionTestReconciler(
		deletionTestScheme(t), cluster, kubernetesNode, candidate, survivor,
	)
	reconciler.APIReader = kubeClient
	reconciler.layoutHistoryGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
		return &garage.LayoutHistoryResponse{
			CurrentVersion: 9,
			Versions: []garage.LayoutVersion{{
				Version: 9, Status: garage.LayoutVersionStatusCurrent, StorageNodes: 2,
			}},
		}, nil
	}

	// Both a first manager observation and a fresh post-restart observation must
	// project the same selector match into retirement, never desired activation.
	var membership *nodeLocalPoolMembership
	for attempt := 0; attempt < 2; attempt++ {
		freshNode := &corev1.Node{}
		if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(kubernetesNode), freshNode); err != nil {
			t.Fatal(err)
		}
		membership, err = evaluateNodeLocalPoolMembership(cluster.Spec.Storage.NodeLocalPools, []corev1.Node{*freshNode})
		if err != nil {
			t.Fatal(err)
		}
		persisted := excludePersistedNodeLocalPoolRetirements(cluster, membership)
		key := nodeLocalPoolKey(pool.Name, kubernetesNode.Name)
		if !persisted[key] || membership.desiredNodesByPool[pool.Name][kubernetesNode.Name] != nil {
			t.Fatalf("attempt %d reactivated persisted retirement: persisted=%v desired=%v", attempt, persisted, membership.desiredNodesByPool)
		}
	}

	key := nodeLocalPoolKey(pool.Name, kubernetesNode.Name)
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler: reconciler,
		ctx:        ctx,
		cluster:    cluster,
		states: map[string]*nodeLocalPoolState{pool.Name: {
			pool: pool, activationLabel: activationLabel, activationValue: nodeLocalPoolActivationLabelValue,
			desiredNodes: membership.desiredNodesByPool[pool.Name],
		}},
		persistedRetirements: map[string]bool{key: true},
		// listNodeLocalPoolStorageNodes would include only the pool-backed
		// candidate. The ordinary survivor remains in the fake API so the
		// cluster-wide drain-safety count can observe it independently.
		existing:                 map[string]*garagev1beta1.GarageNode{candidate.Name: candidate},
		existingByPair:           map[string]*garagev1beta1.GarageNode{key: candidate},
		existingByKubernetesNode: map[string]*garagev1beta1.GarageNode{kubernetesNode.Name: candidate},
		activation:               &nodeLocalPoolActivationResult{},
		members:                  &nodeLocalPoolMaterializationResult{desiredPairs: map[string]bool{}},
	}
	result := transition.retireOneMember()
	if result.Err != nil || !result.Stop {
		t.Fatalf("retireOneMember() = %+v, want a clean fail-closed stop", result)
	}

	freshCandidate := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(candidate), freshCandidate); err != nil {
		t.Fatal(err)
	}
	if !freshCandidate.DeletionTimestamp.IsZero() || freshCandidate.Annotations[garagev1beta1.AnnotationDrain] != "" ||
		freshCandidate.Status.ParentDeletionRequestGeneration != 0 {
		t.Fatalf("unsupported consistency partially advanced retirement: metadata=%+v status=%+v", freshCandidate.ObjectMeta, freshCandidate.Status)
	}
	freshNode := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(kubernetesNode), freshNode); err != nil {
		t.Fatal(err)
	}
	if freshNode.Labels[activationLabel] != nodeLocalPoolActivationLabelValue || freshNode.Annotations[claimKey] != claimValue {
		t.Fatalf("blocked retirement stopped the live source or rewrote its durable claim: labels=%v annotations=%v", freshNode.Labels, freshNode.Annotations)
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(freshCluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety ||
		!strings.Contains(condition.Message, "one-way and overrides selector reselection") ||
		!strings.Contains(condition.Message, "literal consistent mode is unproven") {
		t.Fatalf("persisted retirement condition = %+v", condition)
	}
}

func TestNodeLocalPoolEarlyReselectCompletesRetirementBeforeFreshActivation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("phase-retiring-reselect", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claim.Retiring = true
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	recoveryKey := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   testKubernetesWorkerA,
		UID:    types.UID("retiring-reselect-kubernetes-node-uid"),
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
		Annotations: map[string]string{
			claimKey:    claimValue,
			recoveryKey: testTerminalNodeID,
		},
	}}
	const desiredPodSpecHash = "retiring-reselect-pod-spec-hash"
	const desiredConfigHash = "retiring-reselect-config-hash"
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace,
			UID: types.UID("retiring-reselect-daemonset-uid"), Generation: 1,
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
			},
			Annotations: map[string]string{
				annotationNodeLocalPoolActivationValue: nodeLocalPoolActivationLabelValue,
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
			)},
		},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				annotationPodSpecHash: desiredPodSpecHash,
				annotationConfigHash:  desiredConfigHash,
			}},
			Spec: corev1.PodSpec{
				NodeSelector:    map[string]string{activationLabel: nodeLocalPoolActivationLabelValue},
				SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
			},
		}},
		Status: appsv1.DaemonSetStatus{ObservedGeneration: 1},
	}
	reconciler, kubeClient := deletionTestReconciler(
		deletionTestScheme(t), cluster, kubernetesNode, daemonSet,
	)
	reconciler.APIReader = kubeClient
	layout := &garage.ClusterLayout{Version: 7}
	history := &garage.LayoutHistoryResponse{
		CurrentVersion: 7,
		Versions: []garage.LayoutVersion{
			{Version: 7, Status: garage.LayoutVersionStatusCurrent},
			{Version: 6, Status: garage.LayoutVersionStatusDraining},
		},
	}
	reconciler.nodeLocalPoolLayoutGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
		return layout, nil
	}
	reconciler.layoutHistoryGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
		return history, nil
	}
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler: reconciler,
		ctx:        ctx,
		cluster:    cluster,
		states: map[string]*nodeLocalPoolState{pool.Name: {
			pool: pool, activationLabel: activationLabel, activationValue: nodeLocalPoolActivationLabelValue,
			workloadUID: daemonSet.UID, desiredPodSpecHash: desiredPodSpecHash, configHash: desiredConfigHash,
			desiredNodes: map[string]*corev1.Node{kubernetesNode.Name: kubernetesNode},
		}},
		existing:                 map[string]*garagev1beta1.GarageNode{},
		existingByPair:           map[string]*garagev1beta1.GarageNode{},
		existingByKubernetesNode: map[string]*garagev1beta1.GarageNode{},
	}

	result := transition.observeActors()
	if result.Err != nil || !result.Stop {
		t.Fatalf("observeActors() while publishing the membership fence = %+v, want a clean stop", result)
	}
	freshDaemonSet := &appsv1.DaemonSet{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), freshDaemonSet); err != nil {
		t.Fatal(err)
	}
	transition.states[pool.Name].activationValue = nodeLocalPoolActivationValueForDaemonSet(freshDaemonSet)
	result = transition.observeActors()
	if result.Err != nil || !result.Stop {
		t.Fatalf("observeActors() during draining history = %+v, want a clean stop", result)
	}
	fresh := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(kubernetesNode), fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Annotations[claimKey] != claimValue || fresh.Annotations[recoveryKey] != testTerminalNodeID {
		t.Fatalf("early reselect changed retirement evidence while history was draining: %#v", fresh.Annotations)
	}
	if _, active := fresh.Labels[activationLabel]; active {
		t.Fatal("early reselect restored activation while history was draining")
	}

	history = &garage.LayoutHistoryResponse{
		CurrentVersion: 7,
		Versions:       []garage.LayoutVersion{{Version: 7, Status: garage.LayoutVersionStatusCurrent}},
	}
	// observeActors is normally preceded by publishWorkloads on each reconcile.
	// Mirror its activation-value refresh after the staged selector commits.
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), freshDaemonSet); err != nil {
		t.Fatal(err)
	}
	transition.states[pool.Name].activationValue = nodeLocalPoolActivationValueForDaemonSet(freshDaemonSet)
	result = transition.observeActors()
	if result.Err != nil || !result.Stop {
		t.Fatalf("observeActors() at retirement cleanup boundary = %+v, want a clean stop", result)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(kubernetesNode), fresh); err != nil {
		t.Fatal(err)
	}
	if _, claimed := fresh.Annotations[claimKey]; claimed {
		t.Fatalf("settled role absence retained retiring HostPath claim: %#v", fresh.Annotations)
	}
	if _, pinned := fresh.Annotations[recoveryKey]; pinned {
		t.Fatalf("settled role absence retained recovery pin: %#v", fresh.Annotations)
	}
	if _, active := fresh.Labels[activationLabel]; active {
		t.Fatal("retirement cleanup and fresh activation occurred in the same reconcile")
	}

	transition.states[pool.Name].desiredNodes[kubernetesNode.Name] = fresh.DeepCopy()
	result = transition.observeActors()
	if result.Err != nil || result.Stop {
		t.Fatalf("observeActors() after the cleanup fence = %+v, want activation planning to continue", result)
	}
	result = transition.planActivations()
	if result.Err != nil || result.Stop {
		t.Fatalf("planActivations() after settled retirement = %+v", result)
	}
	if transition.activationPlan == nil || len(transition.activationPlan.newActions) != 1 {
		t.Fatalf("activation plan = %#v, want exactly one fresh action", transition.activationPlan)
	}
	action := transition.activationPlan.newActions[0]
	if action.nodeLocalPoolName != pool.Name || action.node.Name != kubernetesNode.Name || action.recoveryNodeID != "" {
		t.Fatalf("post-retirement action = %+v, want a fresh empty-ID activation", action)
	}
}

func TestNodeLocalPoolCleanupReleasesOnlySafeSurvivingReplacementGates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name             string
		clusterName      string
		ambiguousOldPod  bool
		wantGateReleased bool
	}{
		{name: "exact current replacement is released", clusterName: "cleanup-gate-safe", wantGateReleased: true},
		{name: "ungated retired workload keeps replacement gated", clusterName: "cleanup-gate-ambiguous", ambiguousOldPod: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			cluster := nodeLocalPoolActivationTestCluster(test.clusterName, "a")
			pool := &cluster.Spec.Storage.NodeLocalPools[0]
			activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
			activationValue := "membership-cleanup-token"
			daemonSetUID := types.UID("cleanup-current-daemonset-uid")
			desiredPodSpecHash := "cleanup-current-pod-spec-hash"
			desiredConfigHash := "cleanup-current-config-hash"
			desiredNodeName := testKubernetesWorkerA
			retiredNodeName := testKubernetesNodeB

			currentClaim, err := newNodeLocalPoolHostPathClaim(cluster, pool, "")
			if err != nil {
				t.Fatal(err)
			}
			currentClaimValue, err := encodeNodeLocalPoolHostPathClaim(currentClaim)
			if err != nil {
				t.Fatal(err)
			}
			retiredClaim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
			if err != nil {
				t.Fatal(err)
			}
			retiredClaim.Retiring = true
			retiredClaimValue, err := encodeNodeLocalPoolHostPathClaim(retiredClaim)
			if err != nil {
				t.Fatal(err)
			}

			owner := *metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))
			daemonSet := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace,
					UID: daemonSetUID, Generation: 3,
					Labels: map[string]string{
						labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
					},
					Annotations: map[string]string{
						annotationNodeLocalPoolActivationLabel: activationLabel,
						annotationNodeLocalPoolActivationValue: activationValue,
						annotationNodeLocalPoolMembershipFence: nodeLocalPoolMembershipFenceTarget([]string{retiredNodeName}),
					},
					OwnerReferences: []metav1.OwnerReference{owner},
				},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
						annotationNodeLocalPoolActivationValue: activationValue,
						annotationPodSpecHash:                  desiredPodSpecHash,
						annotationConfigHash:                   desiredConfigHash,
					}},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{activationLabel: activationValue},
						SchedulingGates: []corev1.PodSchedulingGate{{
							Name: nodeLocalPoolSchedulingGateName,
						}},
					},
				}},
				Status: appsv1.DaemonSetStatus{ObservedGeneration: 3},
			}
			desiredNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: desiredNodeName, UID: types.UID("cleanup-desired-node-uid"),
				Labels: map[string]string{
					testStorageOwnerLabelKey: "a",
					activationLabel:          activationValue,
				},
				Annotations: map[string]string{
					nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name): currentClaimValue,
				},
			}}
			retiredNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: retiredNodeName, UID: types.UID("cleanup-retired-node-uid"),
				Annotations: map[string]string{
					nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name):  retiredClaimValue,
					nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name): testTerminalNodeID,
				},
			}}
			podLabels := map[string]string{
				labelCluster:       cluster.Name,
				labelTier:          tierStorage,
				labelNodeLocalPool: pool.Name,
				labelStorageGroup:  storageGroupNodeLocal,
				labelAppManagedBy:  operatorName,
			}
			targetAffinity := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
						Key: kubernetesNodeNameFieldPath, Operator: corev1.NodeSelectorOpIn, Values: []string{desiredNodeName},
					}}}},
				},
			}}
			currentPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cleanup-current-pod", Namespace: cluster.Namespace, UID: types.UID("cleanup-current-pod-uid"),
					Labels: podLabels,
					Annotations: map[string]string{
						annotationNodeLocalPoolActivationValue: activationValue,
						annotationPodSpecHash:                  desiredPodSpecHash,
						annotationConfigHash:                   desiredConfigHash,
					},
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
						daemonSet, appsv1.SchemeGroupVersion.WithKind(daemonSetKind),
					)},
				},
				Spec: corev1.PodSpec{
					NodeSelector:    map[string]string{activationLabel: activationValue},
					Affinity:        targetAffinity,
					SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
				},
			}

			objects := []client.Object{cluster, daemonSet, desiredNode, retiredNode, currentPod}
			if test.ambiguousOldPod {
				objects = append(objects, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cleanup-retired-pod", Namespace: cluster.Namespace,
						UID: types.UID("cleanup-retired-pod-uid"), Labels: podLabels,
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
							Name: daemonSet.Name, UID: types.UID("cleanup-retired-daemonset-uid"),
							Controller: ptr.To(true),
						}},
					},
					Spec: corev1.PodSpec{NodeName: desiredNodeName},
				})
			}

			reconciler, kubeClient := deletionTestReconciler(deletionTestScheme(t), objects...)
			reconciler.APIReader = kubeClient
			reconciler.nodeLocalPoolLayoutGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return nil, errors.New("admin client requires the gated replacement Pod")
			}
			transition := &nodeLocalPoolLifecycleTransition{
				reconciler: reconciler,
				ctx:        ctx,
				cluster:    cluster,
				states: map[string]*nodeLocalPoolState{pool.Name: {
					pool: pool, activationLabel: activationLabel, activationValue: activationValue,
					workloadUID: daemonSetUID, desiredPodSpecHash: desiredPodSpecHash, configHash: desiredConfigHash,
					desiredNodes: map[string]*corev1.Node{desiredNodeName: desiredNode},
				}},
				existing:       map[string]*garagev1beta1.GarageNode{},
				existingByPair: map[string]*garagev1beta1.GarageNode{},
			}
			result := transition.observeActors()
			if result.Err != nil || !result.Stop {
				t.Fatalf("observeActors() = %+v, want cleanup stop without error", result)
			}
			freshPod := &corev1.Pod{}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(currentPod), freshPod); err != nil {
				t.Fatal(err)
			}
			if got := !nodeLocalPoolPodHasSchedulingGate(freshPod); got != test.wantGateReleased {
				t.Fatalf("surviving replacement gate released = %v, want %v", got, test.wantGateReleased)
			}
			freshRetiredNode := &corev1.Node{}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(retiredNode), freshRetiredNode); err != nil {
				t.Fatal(err)
			}
			if freshRetiredNode.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)] != retiredClaimValue ||
				freshRetiredNode.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)] != testTerminalNodeID {
				t.Fatalf("cleanup removed the retiring HostPath identity proof before a settled layout: %#v", freshRetiredNode.Annotations)
			}
		})
	}
}
