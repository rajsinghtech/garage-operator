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
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestNodeLocalServiceHoldWaitsForExactPodTermination(t *testing.T) {
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("hold-at-factor", "a")
	cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	cluster.Annotations = map[string]string{AnnotationNodeLocalOutOfService: pool.Name + "/worker-a"}
	markGarageClusterDrainReady(cluster)
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type: garagev1beta1.ConditionFullyReplicated, Status: metav1.ConditionTrue,
		Reason: garagev1beta1.ReasonRedundancyVerified, ObservedGeneration: cluster.Generation,
		LastTransitionTime: metav1.Now(),
	})
	activation := nodeLocalPoolActivationLabel(cluster, pool.Name)
	workloadUID := types.UID("hold-daemonset-uid")
	activationValue := nodeLocalPoolActivationValueForWorkloadUID(workloadUID)
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace, UID: workloadUID,
			Annotations:     map[string]string{annotationNodeLocalPoolActivationValue: activationValue},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
		},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			NodeSelector: map[string]string{activation: activationValue},
		}}},
	}
	objects := []client.Object{cluster, daemonSet}
	states := map[string]*nodeLocalPoolState{pool.Name: {
		pool: pool, activationLabel: activation, desiredNodes: map[string]*corev1.Node{},
	}}
	existing := map[string]*garagev1beta1.GarageNode{}
	roles := []garage.LayoutNodeRole{}
	capacity := uint64(100 << 30)
	for i, name := range []string{"worker-a", "worker-b", "worker-c"} {
		id := strings.Repeat(string(rune('a'+i)), 64)
		claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, id)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeNodeLocalPoolHostPathClaim(claim)
		if err != nil {
			t.Fatal(err)
		}
		k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: name, UID: types.UID(name + "-uid"),
			Labels: map[string]string{testStorageOwnerLabelKey: "a", activation: activationValue},
			Annotations: map[string]string{
				nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name):  encoded,
				nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name): id,
			},
		}}
		member := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "member-" + name, Namespace: cluster.Namespace, UID: types.UID("member-" + name), Generation: 1,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				Backing:    garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: pool.Name,
				KubernetesNodeName: name,
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: id, Connected: true, InLayout: true, ObservedGeneration: 1,
			},
		}
		objects = append(objects, k8sNode, member)
		states[pool.Name].desiredNodes[name] = k8sNode
		existing[member.Name] = member
		roles = append(roles, garage.LayoutNodeRole{ID: id, Zone: testZone, Capacity: &capacity})
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "held-pod", Namespace: cluster.Namespace,
		Labels: map[string]string{labelCluster: cluster.Name, labelNodeLocalPool: pool.Name},
	}, Spec: corev1.PodSpec{NodeName: "worker-a"}}
	objects = append(objects, pod)
	r, kube := deletionTestReconciler(deletionTestScheme(t), objects...)
	r.APIReader = kube
	r.ClusterScoped = true
	r.LayoutMutations = NewLayoutMutationCoordinator()
	r.nodeLocalPoolLayoutGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
		return &garage.ClusterLayout{Version: 7, Roles: roles}, nil
	}
	r.layoutHistoryGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
		return &garage.LayoutHistoryResponse{CurrentVersion: 7, Versions: []garage.LayoutVersion{{
			Version: 7, Status: garage.LayoutVersionStatusCurrent, StorageNodes: 3,
		}}}, nil
	}
	r.nodeLocalServiceHoldHealthCheck = func(context.Context, *garagev1beta2.GarageCluster) error { return nil }
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler: r, ctx: ctx, cluster: cluster, states: states, existing: existing,
	}
	assertReason := func(want string) {
		t.Helper()
		result := transition.holdOutOfService()
		if result.Err != nil || !result.Stop {
			t.Fatalf("holdOutOfService() = %+v", result)
		}
		fresh := &garagev1beta2.GarageCluster{}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			t.Fatal(err)
		}
		condition := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		if condition == nil || condition.Reason != want {
			t.Fatalf("hold condition = %+v, want reason %s", condition, want)
		}
	}
	assertReason(garagev1beta1.ReasonNodeLocalPoolStopping)
	first := &corev1.Node{}
	if err := kube.Get(ctx, client.ObjectKey{Name: "worker-a"}, first); err != nil {
		t.Fatal(err)
	}
	if first.Labels[activation] != "" || first.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)] == "" {
		t.Fatalf("service hold did not retain claim while removing only activation: %+v", first.ObjectMeta)
	}
	for _, name := range []string{"worker-b", "worker-c"} {
		other := &corev1.Node{}
		if err := kube.Get(ctx, client.ObjectKey{Name: name}, other); err != nil {
			t.Fatal(err)
		}
		if other.Labels[activation] != activationValue {
			t.Fatalf("service hold stopped surviving member %s", name)
		}
	}
	assertReason(garagev1beta1.ReasonNodeLocalPoolStopping)
	if err := kube.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	result := transition.holdOutOfService()
	if result.Err != nil || result.Stop {
		t.Fatalf("completed service hold should continue lifecycle: %+v", result)
	}
}

func TestNodeLocalServiceHoldSkipsActivationRestore(t *testing.T) {
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("hold-restore", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	cluster.Annotations = map[string]string{AnnotationNodeLocalOutOfService: pool.Name + "/worker-a"}
	activation := nodeLocalPoolActivationLabel(cluster, pool.Name)
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-a", UID: "worker-a-uid",
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	member := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "member-worker-a", Namespace: cluster.Namespace, UID: "member-uid",
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:    garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: pool.Name,
			KubernetesNodeName: k8sNode.Name,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: strings.Repeat("a", 64)},
	}
	r, _ := deletionTestReconciler(deletionTestScheme(t), cluster, k8sNode, member)
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler: r, ctx: ctx, cluster: cluster,
		states: map[string]*nodeLocalPoolState{pool.Name: {
			pool: pool, activationLabel: activation, activationValue: nodeLocalPoolActivationLabelValue,
			desiredNodes: map[string]*corev1.Node{k8sNode.Name: k8sNode},
		}},
		existingByPair: map[string]*garagev1beta1.GarageNode{
			nodeLocalPoolKey(pool.Name, k8sNode.Name): member,
		},
		existingByKubernetesNode: map[string]*garagev1beta1.GarageNode{k8sNode.Name: member},
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
	if transition.activationPlan == nil || len(transition.activationPlan.immediateActions) != 0 ||
		len(transition.activationPlan.newActions) != 0 {
		t.Fatalf("service hold planned activations %#v", transition.activationPlan)
	}
}
