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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestNodeLocalIdentitySwapRecoversLostApplyResponse(t *testing.T) {
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("replace-at-factor", "a")
	cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	oldID := strings.Repeat("a", 64)
	newID := strings.Repeat("d", 64)
	secondID := strings.Repeat("b", 64)
	thirdID := strings.Repeat("c", 64)
	cluster.Annotations = map[string]string{AnnotationNodeLocalReplaceIdentity: pool.Name + "/worker-a/" + oldID}
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, oldID)
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-a", UID: "worker-a-uid",
		Labels: map[string]string{testStorageOwnerLabelKey: "a", nodeLocalPoolActivationLabel(cluster, pool.Name): nodeLocalPoolActivationLabelValue},
		Annotations: map[string]string{
			nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name):  claimValue,
			nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name): oldID,
		},
	}}
	member := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "replace-member", Namespace: cluster.Namespace, UID: "replace-member-uid", Generation: 1,
			Annotations:     map[string]string{garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID: oldID},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:    garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: pool.Name,
			KubernetesNodeName: k8sNode.Name, Zone: testZone, Capacity: pool.Capacity,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: oldID, InLayout: true, ObservedGeneration: 1},
	}
	daemonSet := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace, UID: "replace-daemonset-uid",
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "new-pod", Namespace: cluster.Namespace, UID: "new-pod-uid",
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
				labelKubernetesNode: kubernetesNodeLabelValue(k8sNode.Name),
			},
			Annotations:     map[string]string{annotationKubernetesNode: k8sNode.Name},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(daemonSet, appsv1.SchemeGroupVersion.WithKind(daemonSetKind))},
		},
		Spec:   corev1.PodSpec{NodeName: k8sNode.Name},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.10.10.10"},
	}
	_, kube := deletionTestReconciler(deletionTestScheme(t), cluster, k8sNode, member, daemonSet, pod)
	fake := newFakeGarageLayout(
		garage.LayoutNodeRole{ID: oldID, Zone: testZone, Capacity: func() *uint64 { n := uint64(100 << 30); return &n }()},
		garage.LayoutNodeRole{ID: secondID, Zone: testZone, Capacity: func() *uint64 { n := uint64(100 << 30); return &n }()},
		garage.LayoutNodeRole{ID: thirdID, Zone: testZone, Capacity: func() *uint64 { n := uint64(100 << 30); return &n }()},
	)
	fake.statusNodes = []garage.NodeInfo{{ID: oldID, IsUp: false}, {ID: secondID, IsUp: true}, {ID: thirdID, IsUp: true}}
	fake.applyResponseLostOnce = true
	server := fake.server()
	defer server.Close()
	admin := garage.NewClient(server.URL, "test-token")
	up := 1
	nodeReconciler := &GarageNodeReconciler{
		Client: kube, APIReader: kube, LayoutMutations: NewLayoutMutationCoordinator(),
		clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
			return &garage.ClusterHealth{StorageNodes: 3, StorageNodesUp: up,
				Partitions: 256, PartitionsQuorum: 256}, nil
		},
		nodeLocalPoolRecoveryNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster, []string) (string, error) {
			return newID, nil
		},
	}
	desired, err := nodeReconciler.desiredGarageNodeRoleChange(ctx, member, cluster, newID)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := admin.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	process := &managedPodIdentity{nodeID: newID, podIP: pod.Status.PodIP, podUID: pod.UID}
	if err := nodeReconciler.swapNodeLocalIdentity(ctx, member, cluster, cluster, admin, initial, process,
		oldID, newID, desired); !errors.Is(err, errUnsafeLayoutRoleRemoval) {
		t.Fatalf("one surviving role unexpectedly authorized swap: %v", err)
	}
	if len(fake.appliedChanges()) != 0 {
		t.Fatal("unsafe swap mutated Garage layout")
	}
	up = 2
	err = nodeReconciler.swapNodeLocalIdentity(ctx, member, cluster, cluster, admin, initial, process,
		oldID, newID, desired)
	if !errors.Is(err, errLayoutMutationPending) || !fake.hasRole(newID) || fake.hasRole(oldID) {
		t.Fatalf("atomic swap after lost Apply response: err=%v new=%v old=%v", err, fake.hasRole(newID), fake.hasRole(oldID))
	}
	changes := fake.appliedChanges()
	if len(changes) != 1 || len(changes[0]) != 2 {
		t.Fatalf("swap applied %v, want one version with assignment and removal", changes)
	}
	completed, err := nodeReconciler.finalizeNodeLocalIdentityReplacement(ctx, member, cluster, admin, cluster)
	if err != nil || !completed {
		t.Fatalf("repair after lost Apply response: completed=%v err=%v", completed, err)
	}
	freshMember := &garagev1beta1.GarageNode{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(member), freshMember); err != nil {
		t.Fatal(err)
	}
	if freshMember.Status.NodeID != newID || freshMember.Status.InLayout ||
		freshMember.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID] != newID {
		t.Fatalf("replacement GarageNode pins/status = %+v %+v", freshMember.Annotations, freshMember.Status)
	}
	freshKubernetesNode := &corev1.Node{}
	if err := kube.Get(ctx, types.NamespacedName{Name: k8sNode.Name}, freshKubernetesNode); err != nil {
		t.Fatal(err)
	}
	updatedClaim, err := decodeNodeLocalPoolHostPathClaim(freshKubernetesNode.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)])
	if err != nil || updatedClaim.GarageNodeID != newID ||
		freshKubernetesNode.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)] != newID {
		t.Fatalf("replacement Kubernetes Node pin = %+v, err=%v", freshKubernetesNode.Annotations, err)
	}
	if len(fake.appliedChanges()) != 1 {
		t.Fatal("pin repair repeated Garage layout Apply")
	}
}

func TestNodeLocalIdentitySwapRefusesLayoutFollower(t *testing.T) {
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("replace-follower", "a")
	cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
	cluster.Spec.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleFollower}
	cluster.Spec.RemoteClusters = []garagev1beta2.RemoteClusterConfig{{Name: "writer"}}
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	oldID := strings.Repeat("a", 64)
	newID := strings.Repeat("d", 64)
	cluster.Annotations = map[string]string{AnnotationNodeLocalReplaceIdentity: pool.Name + "/worker-a/" + oldID}
	member := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "replace-member", Namespace: cluster.Namespace, UID: "replace-member-uid",
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:    garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: pool.Name,
			KubernetesNodeName: "worker-a", Zone: testZone, Capacity: pool.Capacity,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: oldID, InLayout: true, ObservedGeneration: 1},
	}
	nodeReconciler := &GarageNodeReconciler{}
	capacity := uint64(100 << 30)
	desired := garage.NodeRoleChange{ID: newID, Zone: testZone, Capacity: &capacity, Tags: []string{"tier:storage"}}
	layout := &garage.ClusterLayout{Version: 3, Roles: []garage.LayoutNodeRole{
		{ID: oldID, Zone: testZone, Capacity: &capacity},
		{ID: strings.Repeat("b", 64), Zone: testZone, Capacity: &capacity},
		{ID: strings.Repeat("c", 64), Zone: testZone, Capacity: &capacity},
	}}
	err := nodeReconciler.swapNodeLocalIdentity(ctx, member, cluster, cluster, nil, layout,
		&managedPodIdentity{nodeID: newID, podIP: "10.10.10.10", podUID: "pod"}, oldID, newID, desired)
	if !errors.Is(err, errLayoutMutationPending) || !strings.Contains(err.Error(), "idle single-site layout writer") {
		t.Fatalf("follower site authorized identity replacement: %v", err)
	}
}
