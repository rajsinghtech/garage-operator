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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const expectedDrainVerificationLaunchNodeIDs = "removed-a,storage-a"

func uint64Pointer(value uint64) *uint64 { return &value }

func testDrainActor() storageDrainActor {
	return storageDrainActor{
		APIVersion: "garage.rajsingh.info/v1beta1", Kind: kindGarageNode,
		Namespace: testGarageValue, Name: testStorageNodeName, UID: types.UID(testNodeUID),
	}
}

func testDrainIntent(t *testing.T, removed string, now time.Time) *blockResyncProof {
	t.Helper()
	proof, err := storageDrainRemovalIntent(nil, testDrainActor(), []string{removed}, []string{removed}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func completedNodeDrainFixture(t *testing.T) (*garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) {
	t.Helper()
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: testGarageValue, UID: testNodeUID,
			// Generation intentionally exceeds observedGeneration. DELETE may
			// cross that cache/status boundary after the terminal proof, and the
			// finalizer handoff must remain bound to identities rather than stall.
			Generation:  4,
			Annotations: map[string]string{garagev1beta1.AnnotationDrain: annotationTrue},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:         garagev1beta1.ClusterReference{Name: testGarageValue},
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			KubernetesNodeName: testKubernetesWorkerA,
			NodeLocalPoolName:  testTagLocal,
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:             testTerminalNodeID,
			ObservedPodUID:     testSourcePodUID,
			ObservedGeneration: 3,
		},
	}
	proof, err := storageDrainRemovalIntent(
		nil, storageDrainActorForNode(node),
		[]string{testTerminalNodeID}, []string{testTerminalNodeID}, time.Now().Add(-time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof.ManagedPodUIDs = map[string]string{testTerminalNodeID: testSourcePodUID}
	completedAt := metav1.Now()
	proof.CompletedAt = &completedAt
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			LayoutPolicy: LayoutPolicyManual,
		}},
		Status: garagev1beta2.GarageClusterStatus{StorageDrain: v1beta2StorageDrainStatus(proof)},
	}
	return node, cluster
}

func TestCompletedGarageNodeDrainAuthorizesFinalizationAcrossGenerationDrift(t *testing.T) {
	node, cluster := completedNodeDrainFixture(t)
	authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, cluster)
	if err != nil || !authorized {
		t.Fatalf("exact terminal handoff was not authorized: authorized=%v err=%v", authorized, err)
	}
}

func TestCompletedGarageNodeDrainFinalizationHandoffFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*garagev1beta1.GarageNode, *garagev1beta2.GarageCluster)
	}{
		{
			name: "invalid target hash",
			mutate: func(_ *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) {
				cluster.Status.StorageDrain.TargetHash = "sha256:corrupt"
			},
		},
		{
			name: "missing source target",
			mutate: func(_ *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) {
				proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
				proof.RoleRemovalNodeIDs = []string{testStorageNodeName}
				proof.RemovedStorageNodeIDs = []string{testStorageNodeName}
				proof.TargetHash = storageDrainProofTargetHash(proof)
				cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
			},
		},
		{
			name: "missing drain request",
			mutate: func(node *garagev1beta1.GarageNode, _ *garagev1beta2.GarageCluster) {
				delete(node.Annotations, garagev1beta1.AnnotationDrain)
			},
		},
		{
			name: "missing managed pod fingerprint",
			mutate: func(_ *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) {
				cluster.Status.StorageDrain.ManagedPodUIDs = nil
			},
		},
		{
			name: "completion predates transaction",
			mutate: func(_ *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) {
				completedAt := metav1.NewTime(cluster.Status.StorageDrain.StartedAt.Add(-time.Second))
				cluster.Status.StorageDrain.CompletedAt = &completedAt
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, cluster := completedNodeDrainFixture(t)
			test.mutate(node, cluster)
			if authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, cluster); err == nil || authorized {
				t.Fatalf("malformed terminal handoff was accepted: authorized=%v err=%v", authorized, err)
			}
		})
	}
}

func TestCompletedLostSourceDrainAuthorizesFinalizationWithoutManagedPod(t *testing.T) {
	node, cluster := completedNodeDrainFixture(t)
	node.Annotations[garagev1beta1.AnnotationAcknowledgeLostSource] = testTerminalNodeID
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	proof.UnavailableSourceNodeIDs = []string{testTerminalNodeID}
	proof.ManagedPodUIDs = nil
	proof.TargetHash = storageDrainProofTargetHash(proof)
	cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
	if authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, cluster); err != nil || !authorized {
		t.Fatalf("exact lost-source terminal handoff was not authorized: authorized=%v err=%v", authorized, err)
	}
}

func TestCompletedGarageNodeDrainIgnoresMutablePostProofPodStatus(t *testing.T) {
	node, cluster := completedNodeDrainFixture(t)
	node.Status.ObservedPodUID = testReplacementPodUID
	if authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, cluster); err != nil || !authorized {
		t.Fatalf("mutable post-proof Pod status invalidated the terminal handoff: authorized=%v err=%v", authorized, err)
	}
}

func TestLostSourceFenceRemovesUIDValuedNodeLocalPoolActivation(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testNodeUID},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:         garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			NodeLocalPoolName:  testPoolA,
			KubernetesNodeName: testKubernetesWorkerA,
		},
	}
	activationLabel := nodeLocalPoolActivationLabel(cluster, node.Spec.NodeLocalPoolName)
	activationValue := nodeLocalPoolActivationValueForWorkloadUID("replacement-daemonset-uid")
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA,
		Labels: map[string]string{
			activationLabel: activationValue,
		},
	}}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubernetesNode).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient}
	fenced, err := reconciler.fenceManagedGarageNodeLostSource(context.Background(), node, cluster)
	if err != nil || fenced {
		t.Fatalf("first fencing pass = (%v, %v), want activation removal and retry", fenced, err)
	}
	fresh := &corev1.Node{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(kubernetesNode), fresh); err != nil {
		t.Fatal(err)
	}
	if _, exists := fresh.Labels[activationLabel]; exists {
		t.Fatalf("UID-valued activation survived lost-source fencing: %q", fresh.Labels[activationLabel])
	}
}

func TestLayoutBarrierRecognizesUIDValuedPendingNodeLocalPoolActivation(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	activationLabel := nodeLocalPoolActivationLabel(cluster, testPoolA)
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA,
		Labels: map[string]string{
			activationLabel: nodeLocalPoolActivationValueForWorkloadUID("adopted-daemonset-uid"),
		},
	}}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubernetesNode).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, ClusterScoped: true,
		layoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
			return &garage.LayoutHistoryResponse{
				CurrentVersion: 1,
				Versions:       []garage.LayoutVersion{{Version: 1, Status: garage.LayoutVersionStatusCurrent}},
			}, nil
		},
	}
	ready, bootstrap, message, err := reconciler.clusterLayoutReadyForMutation(
		context.Background(), cluster, false,
	)
	if err != nil || ready || bootstrap || !strings.Contains(message, "activated node-local-pool identity") {
		t.Fatalf("UID-valued activation was not serialized: ready=%v bootstrap=%v message=%q err=%v", ready, bootstrap, message, err)
	}
}

func TestLayoutBarrierAllowsBookkeepingOnlyDrainingHistory(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, ClusterScoped: true,
		layoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
			return &garage.LayoutHistoryResponse{
				CurrentVersion: 2,
				Versions: []garage.LayoutVersion{
					{Version: 2, Status: garage.LayoutVersionStatusCurrent},
					{Version: 1, Status: garage.LayoutVersionStatusDraining},
				},
				UpdateTrackers: map[string]garage.NodeUpdateTrackers{
					testTerminalNodeID: {Ack: 2, Sync: 2, SyncAck: 1},
				},
			}, nil
		},
	}

	ready, bootstrap, message, err := reconciler.clusterLayoutReadyForMutation(
		context.Background(), cluster, false,
	)
	if err != nil || !ready || bootstrap || message != "" {
		t.Fatalf("bookkeeping-only layout drain blocked mutation: ready=%v bootstrap=%v message=%q err=%v", ready, bootstrap, message, err)
	}
}

func TestLayoutBarrierStillBlocksLaggingDrainingHistory(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, ClusterScoped: true,
		layoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
			return &garage.LayoutHistoryResponse{
				CurrentVersion: 2,
				Versions: []garage.LayoutVersion{
					{Version: 2, Status: garage.LayoutVersionStatusCurrent},
					{Version: 1, Status: garage.LayoutVersionStatusDraining},
				},
				UpdateTrackers: map[string]garage.NodeUpdateTrackers{
					testTerminalNodeID: {Ack: 2, Sync: 1, SyncAck: 1},
				},
			}, nil
		},
	}

	ready, bootstrap, message, err := reconciler.clusterLayoutReadyForMutation(
		context.Background(), cluster, false,
	)
	if err != nil || ready || bootstrap || !strings.Contains(message, "version(s) 1") {
		t.Fatalf("lagging layout drain was not retained as a barrier: ready=%v bootstrap=%v message=%q err=%v", ready, bootstrap, message, err)
	}
}

func TestStorageDrainRequiredArraysMarshalAsArrays(t *testing.T) {
	proof := &blockResyncProof{
		Actor: storageDrainActor{
			APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
			Namespace: testGarageValue, Name: testGarageValue, UID: testClusterUID,
		},
		TransactionID:      "role-only-drain",
		StartedAt:          metav1.Now(),
		RoleRemovalNodeIDs: []string{testGatewayNodeID},
		// A role-only drain has no positive-capacity source IDs. The required
		// wire field must still be [] rather than Kubernetes-invalid null.
		RemovedStorageNodeIDs: nil,
	}
	proof.TargetHash = storageDrainProofTargetHash(proof)
	payload, err := json.Marshal(v1beta2StorageDrainStatus(proof))
	if err != nil {
		t.Fatal(err)
	}
	wire := string(payload)
	if !strings.Contains(wire, `"roleRemovalNodeIds":["`+testGatewayNodeID+`"]`) ||
		!strings.Contains(wire, `"removedStorageNodeIds":[]`) {
		t.Fatalf("required storage-drain arrays did not marshal as arrays: %s", wire)
	}
}

func TestNodeLocalPoolRecoveryPinCleanupRequiresSettledRoleAbsence(t *testing.T) {
	const pinnedNodeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name             string
		layoutAvailable  bool
		historyAvailable bool
		rolePresent      bool
		stagedChange     bool
		historyDraining  bool
		historyVersion   uint64
		wantEvidence     bool
	}{
		{name: "layout unavailable", wantEvidence: true},
		{name: "history unavailable", layoutAvailable: true, wantEvidence: true},
		{name: "role still committed", layoutAvailable: true, historyAvailable: true, rolePresent: true, historyVersion: 7, wantEvidence: true},
		{name: "staged mutation remains", layoutAvailable: true, historyAvailable: true, stagedChange: true, historyVersion: 7, wantEvidence: true},
		{name: "history still draining", layoutAvailable: true, historyAvailable: true, historyDraining: true, historyVersion: 7, wantEvidence: true},
		{name: "layout history version mismatch", layoutAvailable: true, historyAvailable: true, historyVersion: 6, wantEvidence: true},
		{name: "settled role absence", layoutAvailable: true, historyAvailable: true, historyVersion: 7, wantEvidence: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
				Name: testGarageValue, Namespace: testGarageValue, UID: "recreated-cluster-uid",
			}}
			pool := &garagev1beta2.NodeLocalPoolSpec{
				Name:     testPoolA,
				Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/meta"},
				Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/data"},
			}
			activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
			recoveryAnnotation := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
			claimAnnotation := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
			claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, pinnedNodeID)
			if err != nil {
				t.Fatal(err)
			}
			claim.Retiring = true
			claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
			if err != nil {
				t.Fatal(err)
			}
			kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: testKubernetesWorkerA,
				Labels: map[string]string{
					testStorageOwnerLabelKey: "a",
					activationLabel:          nodeLocalPoolActivationValueForWorkloadUID("old-daemonset-uid"),
				},
				Annotations: map[string]string{
					recoveryAnnotation: pinnedNodeID,
					claimAnnotation:    claimValue,
				},
			}}
			scheme := deletionTestScheme(t)
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubernetesNode).Build()
			reconciler := &GarageClusterReconciler{
				Client: kubeClient, APIReader: kubeClient,
				nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
					if !test.layoutAvailable {
						return nil, fmt.Errorf("Admin API unavailable")
					}
					layout := &garage.ClusterLayout{Version: 7}
					if test.rolePresent {
						layout.Roles = []garage.LayoutNodeRole{{ID: pinnedNodeID}}
					}
					if test.stagedChange {
						layout.StagedRoleChanges = []garage.NodeRoleChange{{ID: pinnedNodeID, Remove: true}}
					}
					return layout, nil
				},
				layoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
					if !test.historyAvailable {
						return nil, fmt.Errorf("layout history unavailable")
					}
					versions := []garage.LayoutVersion{{Version: test.historyVersion, Status: garage.LayoutVersionStatusCurrent}}
					if test.historyDraining {
						versions = append(versions, garage.LayoutVersion{Version: test.historyVersion - 1, Status: garage.LayoutVersionStatusDraining})
					}
					return &garage.LayoutHistoryResponse{CurrentVersion: test.historyVersion, Versions: versions}, nil
				},
			}
			states := map[string]*nodeLocalPoolState{pool.Name: {
				pool: pool, activationLabel: activationLabel,
				desiredNodes: map[string]*corev1.Node{kubernetesNode.Name: kubernetesNode.DeepCopy()},
			}}
			for attempt := 0; attempt < 3; attempt++ {
				pending, err := reconciler.cleanupNodeLocalPoolActivationLabels(
					context.Background(), cluster, states, map[string]*garagev1beta1.GarageNode{},
				)
				if err != nil {
					t.Fatal(err)
				}
				if !pending {
					break
				}
			}
			fresh := &corev1.Node{}
			if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(kubernetesNode), fresh); err != nil {
				t.Fatal(err)
			}
			_, hasPin := fresh.Annotations[recoveryAnnotation]
			_, hasClaim := fresh.Annotations[claimAnnotation]
			if hasPin != test.wantEvidence || hasClaim != test.wantEvidence {
				t.Fatalf("retirement evidence present = pin:%v claim:%v, want %v; annotations=%#v",
					hasPin, hasClaim, test.wantEvidence, fresh.Annotations)
			}
			if _, hasActivation := fresh.Labels[activationLabel]; hasActivation {
				t.Fatal("retiring activation label was not removed after the scheduling fence")
			}
		})
	}
}

func TestDeletingGarageNodeConsumesTerminalDrainWithoutAdminAPI(t *testing.T) {
	node, cluster := completedNodeDrainFixture(t)
	now := metav1.Now()
	node.DeletionTimestamp = &now
	node.Finalizers = []string{garageNodeFinalizer}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).Build()
	reconciler := &GarageNodeReconciler{
		Client: kubeClient, APIReader: kubeClient, LayoutMutations: NewLayoutMutationCoordinator(),
	}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(node),
	})
	if err != nil {
		t.Fatalf("terminal handoff unexpectedly needed a live Garage Admin API: %v", err)
	}
	freshNode := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(node), freshNode); client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	} else if err == nil && controllerutil.ContainsFinalizer(freshNode, garageNodeFinalizer) {
		t.Fatalf("exact terminal handoff retained the GarageNode finalizer: result=%+v status=%+v", result, freshNode.Status)
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		t.Fatal(err)
	}
	if freshCluster.Status.StorageDrain != nil {
		t.Fatalf("consumed terminal handoff was not cleared: %+v", freshCluster.Status.StorageDrain)
	}
}

func TestDeletingGarageNodeConsumesGenerationBoundNoLayoutHandoffWithoutAdminAPI(t *testing.T) {
	node, cluster := completedNodeDrainFixture(t)
	cluster.Status.StorageDrain = nil
	// PreparedNotInLayout is valid only for an object that never acquired a
	// durable Garage identity or identity-bearing managed process.
	node.Status.NodeID = ""
	node.Status.ObservedPodUID = ""
	node.Status.Connected = false
	node.Status.InLayout = false
	node.Status.LayoutVersion = 0
	node.Status.Conditions = []metav1.Condition{{
		Type:               garagev1beta1.ConditionDrainPrepared,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonNodeDrainPreparedNotInLayout,
		ObservedGeneration: node.Generation,
	}}
	now := metav1.Now()
	node.DeletionTimestamp = &now
	node.Finalizers = []string{garageNodeFinalizer}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).Build()
	reconciler := &GarageNodeReconciler{
		Client: kubeClient, APIReader: kubeClient, LayoutMutations: NewLayoutMutationCoordinator(),
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(node),
	}); err != nil {
		t.Fatalf("no-layout handoff unexpectedly needed a live Garage Admin API: %v", err)
	}
	fresh := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(node), fresh); client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	} else if err == nil && controllerutil.ContainsFinalizer(fresh, garageNodeFinalizer) {
		t.Fatal("generation-bound no-layout handoff retained the GarageNode finalizer")
	}
}

func testDrainObservation(queue uint64) *blockResyncObservation {
	zero := uint64(0)
	workers := func() []garage.WorkerInfo {
		return []garage.WorkerInfo{{
			ID: 4, Name: testBlockResyncWorkerName, State: garage.WorkerState{State: "idle"},
			QueueLength: &queue, PersistentErrors: &zero,
		}}
	}
	return &blockResyncObservation{
		LayoutVersion:         7,
		CurrentRoleNodeIDs:    []string{testStorageNodeName},
		CurrentRoleTags:       map[string][]string{testStorageNodeName: {"cluster-uid:cluster-uid"}},
		CurrentStorageNodeIDs: []string{testStorageNodeName},
		VerificationNodeIDs:   []string{testRemovedNodeID, testStorageNodeName},
		QueueLength:           2 * queue,
		Nodes: map[string]blockResyncNodeObservation{
			testRemovedNodeID: {
				IsUp: true, WorkersObserved: true, BlockErrorsObserved: true,
				Workers: workers(), QueueLength: queue,
			},
			testStorageNodeName: {
				IsUp: true, WorkersObserved: true, BlockErrorsObserved: true,
				Workers: workers(), QueueLength: queue,
			},
		},
	}
}

func TestBlockResyncObservationUsesOneSharedCounterPerStorageNode(t *testing.T) {
	capacity := uint64(1024)
	history := &garage.LayoutHistoryResponse{
		CurrentVersion: 4,
		Versions:       []garage.LayoutVersion{{Version: 4, Status: garage.LayoutVersionStatusCurrent}},
	}
	layout := &garage.ClusterLayout{Version: 4, Roles: []garage.LayoutNodeRole{
		{ID: testStorageNodeName, Capacity: &capacity, Tags: []string{"cluster-uid:a"}},
		{ID: tierGateway},
		{ID: testSecondStorageNodeID, Capacity: &capacity, Tags: []string{"cluster-uid:b"}},
	}}
	status := &garage.ClusterStatus{LayoutVersion: 4, Nodes: []garage.NodeInfo{
		{ID: testStorageNodeName, IsUp: true, Role: &garage.NodeAssignedRole{Capacity: &capacity}},
		{ID: tierGateway, Role: &garage.NodeAssignedRole{}},
		{ID: testSecondStorageNodeID, IsUp: true, Role: &garage.NodeAssignedRole{Capacity: &capacity}},
		{ID: testRemovedNodeID, IsUp: true},
	}}
	workers := &garage.ListWorkersResponse{Success: map[string][]garage.WorkerInfo{
		testStorageNodeName: {
			{Name: testBlockResyncWorkerName, QueueLength: uint64Pointer(3), PersistentErrors: uint64Pointer(1)},
			{Name: "Block resync worker #2", QueueLength: uint64Pointer(3), PersistentErrors: uint64Pointer(1)},
			{Name: "table worker", QueueLength: uint64Pointer(99)},
		},
		testSecondStorageNodeID: {{Name: testBlockResyncWorkerName, QueueLength: uint64Pointer(5), PersistentErrors: uint64Pointer(2)}},
		testRemovedNodeID:       {{Name: testBlockResyncWorkerName, QueueLength: uint64Pointer(11), PersistentErrors: uint64Pointer(0)}},
	}}
	blockErrors := &garage.ListBlockErrorsResponse{Success: map[string][]garage.BlockError{
		testStorageNodeName: {}, testSecondStorageNodeID: {}, testRemovedNodeID: {},
	}}

	observation, err := blockResyncObservationFromResponses(history, layout, status, workers, blockErrors)
	if err != nil {
		t.Fatal(err)
	}
	if observation.QueueLength != 8 || observation.ErrorCount != 3 {
		t.Fatalf("duplicate workers were summed or structured counters were missed: %+v", observation)
	}
	if got := strings.Join(observation.CurrentStorageNodeIDs, ","); got != "storage-a,storage-b" {
		t.Fatalf("storage node fingerprint = %q", got)
	}
	scoped, err := scopeBlockResyncObservation(testDrainIntent(t, testRemovedNodeID, time.Now()), observation)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(scoped.VerificationNodeIDs, ","); got != "removed-a,storage-a,storage-b" {
		t.Fatalf("source/destination verification fingerprint = %q", got)
	}
	if scoped.QueueLength != 19 {
		t.Fatalf("source queue was not included in scoped proof: %+v", scoped)
	}
}

func TestBlockResyncObservationRequiresRemovedSourceToRemainLive(t *testing.T) {
	proof := testDrainIntent(t, testRemovedNodeID, time.Now())
	observation := testDrainObservation(0)
	node := observation.Nodes[testRemovedNodeID]
	node.IsUp = false
	observation.Nodes[testRemovedNodeID] = node
	if _, err := scopeBlockResyncObservation(proof, observation); err == nil || !strings.Contains(err.Error(), "must remain live") {
		t.Fatalf("down removed source was accepted: %v", err)
	}

	node.IsUp = true
	node.WorkersObserved = false
	observation.Nodes[testRemovedNodeID] = node
	if _, err := scopeBlockResyncObservation(proof, observation); err == nil || !strings.Contains(err.Error(), "ListWorkers") {
		t.Fatalf("removed source without worker evidence was accepted: %v", err)
	}
}

func TestStorageDrainPeerAssessmentRetainsRemovedSourcePodUID(t *testing.T) {
	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testRemovedNodeID, Namespace: testGarageValue, UID: testNodeUID, Generation: 2},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:         garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			KubernetesNodeName: testKubernetesWorkerA,
			NodeLocalPoolName:  testTagLocal,
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testRemovedNodeID, ObservedPodUID: testSourcePodUID, ObservedGeneration: 2,
			Connected: true, InLayout: false,
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "garage-storage-local-abcde", Namespace: testGarageValue, UID: testSourcePodUID,
			Labels: map[string]string{labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: testTagLocal},
		},
		Spec: corev1.PodSpec{NodeName: testKubernetesWorkerA},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, pod).Build()
	assessment, err := assessStorageDrainPeers(
		context.Background(), reader, cluster, nil, []string{testRemovedNodeID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.ManagedPodUIDs[testRemovedNodeID] != testSourcePodUID {
		t.Fatalf("removed source process was not fingerprinted: %+v", assessment)
	}

	restartedPod := pod.DeepCopy()
	restartedPod.UID = testReplacementPodUID
	restartedReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster.DeepCopy(), node.DeepCopy(), restartedPod).Build()
	if _, err := assessStorageDrainPeers(
		context.Background(), restartedReader, cluster, nil, []string{testRemovedNodeID},
	); err == nil || !strings.Contains(err.Error(), "unverified Garage processes") {
		t.Fatalf("removed source Pod replacement was accepted: %v", err)
	}
}

func TestLostSourcePreflightNeverFencesGarageIdentityStillUp(t *testing.T) {
	const lostNodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != pathGetClusterStatus {
			http.NotFound(w, request)
			return
		}
		_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{
			ID: lostNodeID, IsUp: true,
		}}})
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testGarageNodeUID,
			Annotations: map[string]string{
				garagev1beta1.AnnotationDrain:                 annotationTrue,
				garagev1beta1.AnnotationAcknowledgeLostSource: lostNodeID,
			},
		},
		Spec:   garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status: garagev1beta1.GarageNodeStatus{NodeID: lostNodeID},
	}
	replicas := int32(1)
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name, Namespace: node.Namespace, UID: testStatefulSetUID,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: node.Name, UID: node.UID, Controller: ptrTo(true),
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: &replicas},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, statefulSet).Build()
	reconciler := &GarageNodeReconciler{Client: fakeClient}
	fenced, err := reconciler.preflightAndFenceManagedGarageNodeLostSource(
		context.Background(), node, cluster, cluster, garage.NewClient(server.URL, "token"), lostNodeID,
	)
	if err == nil || fenced || !strings.Contains(err.Error(), "still up") {
		t.Fatalf("live lost-source identity was not rejected before fencing: fenced=%v err=%v", fenced, err)
	}
	stored := &appsv1.StatefulSet{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(statefulSet), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Spec.Replicas == nil || *stored.Spec.Replicas != 1 {
		t.Fatalf("live lost-source preflight mutated the StatefulSet: replicas=%v", stored.Spec.Replicas)
	}
}

func TestLostSourcePreflightRequiresReplacementIdentityToBeUnassigned(t *testing.T) {
	const (
		lostNodeID        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		replacementNodeID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	)
	capacity := uint64(1024)
	for _, assigned := range []bool{false, true} {
		name := "unassigned"
		if assigned {
			name = "assigned"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case pathGetClusterStatus:
					_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{
						{ID: lostNodeID, IsUp: false},
						{ID: replacementNodeID, IsUp: true, Address: ptrTo("10.0.0.9:3901")},
					}})
				case pathGetClusterLayout:
					roles := []garage.LayoutNodeRole{{ID: lostNodeID, Capacity: &capacity}}
					if assigned {
						roles = append(roles, garage.LayoutNodeRole{ID: replacementNodeID, Capacity: &capacity})
					}
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 4, Roles: roles})
				default:
					http.NotFound(w, request)
				}
			}))
			defer server.Close()

			scheme := deletionTestScheme(t)
			cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
				Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
			}}
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testGarageNodeUID,
					Annotations: map[string]string{
						garagev1beta1.AnnotationDrain:                 annotationTrue,
						garagev1beta1.AnnotationAcknowledgeLostSource: lostNodeID,
					},
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				},
				Status: garagev1beta1.GarageNodeStatus{NodeID: lostNodeID},
			}
			replicas := int32(1)
			statefulSet := &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: node.Name, Namespace: node.Namespace, UID: testStatefulSetUID,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
						Name: node.Name, UID: node.UID, Controller: ptrTo(true),
					}},
				},
				Spec: appsv1.StatefulSetSpec{Replicas: &replicas},
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: node.Name + "-0", Namespace: node.Namespace, UID: testOldPodUID,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
						Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
					}},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9"},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, statefulSet, pod).Build()
			reconciler := &GarageNodeReconciler{Client: fakeClient, APIReader: fakeClient}
			fenced, err := reconciler.preflightAndFenceManagedGarageNodeLostSource(
				context.Background(), node, cluster, cluster, garage.NewClient(server.URL, "token"), lostNodeID,
			)
			stored := &appsv1.StatefulSet{}
			if getErr := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(statefulSet), stored); getErr != nil {
				t.Fatal(getErr)
			}
			if assigned {
				if err == nil || fenced || !strings.Contains(err.Error(), "dual-identity recovery") {
					t.Fatalf("assigned replacement identity was not rejected: fenced=%v err=%v", fenced, err)
				}
				if stored.Spec.Replicas == nil || *stored.Spec.Replicas != 1 {
					t.Fatalf("assigned replacement was fenced before rejection: replicas=%v", stored.Spec.Replicas)
				}
				return
			}
			if err != nil || fenced {
				t.Fatalf("unassigned replacement did not enter the fencing sequence: fenced=%v err=%v", fenced, err)
			}
			if stored.Spec.Replicas == nil || *stored.Spec.Replicas != 0 {
				t.Fatalf("unassigned replacement workload was not fenced: replicas=%v", stored.Spec.Replicas)
			}
		})
	}
}

func TestLostStorageRolloutActorTransfersDurableBoundaryBeforeFencing(t *testing.T) {
	const lostNodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	capacityBytes := uint64(1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 4, Nodes: []garage.NodeInfo{{
				ID: lostNodeID, IsUp: false,
			}}})
		case pathGetLayoutHistory:
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: 4,
				Versions:       []garage.LayoutVersion{{Version: 4, Status: garage.LayoutVersionStatusCurrent}},
			})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 4, Roles: []garage.LayoutNodeRole{{
				ID: lostNodeID, Capacity: &capacityBytes,
			}}})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID, Generation: 3},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				GarageNodeName: testStorageNodeName, GarageNodeUID: testNodeUID, GarageNodeID: lostNodeID,
				WorkloadUID: testStatefulSetUID, PreviousPodUID: "old-pod-uid",
				DesiredPodSpecHash: "desired-spec", DesiredConfigHash: "desired-config",
				ClusterGeneration: 3, GarageNodeGeneration: 2,
				StatefulSetWorkloadRecreationSafe: true,
				PersistentVolumeClaims: []garagev1beta2.StorageRolloutPersistentVolumeClaimStatus{{
					Name: testStorageMetadataPVC, UID: testPVCUID,
				}},
			},
			Conditions: []metav1.Condition{{
				Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
				Reason: garagev1beta1.ReasonStorageRollingOut, ObservedGeneration: 3,
			}},
		},
	}
	capacity := resource.MustParse("1Ti")
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testNodeUID, Generation: 2,
			Annotations: map[string]string{
				garagev1beta1.AnnotationDrain:                 annotationTrue,
				garagev1beta1.AnnotationAcknowledgeLostSource: lostNodeID,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Capacity: &capacity,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: lostNodeID},
	}
	replicas := int32(1)
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name, Namespace: node.Namespace, UID: testStatefulSetUID,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: node.Name, UID: node.UID, Controller: ptrTo(true),
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: &replicas},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: testStorageMetadataPVC, Namespace: cluster.Namespace, UID: testPVCUID,
		Finalizers: []string{storageRolloutPVCFinalizer(cluster)},
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, node, statefulSet, claim).Build()
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	coordinator := NewLayoutMutationCoordinator()
	key := layoutOwnerKey(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(key, cluster.UID, client.ObjectKeyFromObject(cluster), cluster.UID) ||
		!coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) {
		t.Fatal("failed to establish exact rollout marker")
	}
	reconciler := &GarageNodeReconciler{
		Client: fakeClient, APIReader: fakeClient, LayoutMutations: coordinator,
		lostSourceGarageClientGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.Client, error) {
			return garage.NewClient(server.URL, "token"), nil
		},
	}
	transferred, err := reconciler.recoverOrTransferStorageRolloutLostSource(
		context.Background(), node, cluster, cluster,
	)
	if err != nil || !transferred {
		t.Fatalf("exact lost rollout actor did not transfer: transferred=%v err=%v", transferred, err)
	}
	storedCluster := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), storedCluster); err != nil {
		t.Fatal(err)
	}
	proof := clusterStorageDrainProof(storedCluster.Status.StorageDrain)
	if storedCluster.Status.StorageRollout != nil || proof == nil ||
		!sameStorageDrainActor(proof.Actor, storageDrainActorForNode(node)) ||
		!storageDrainUnavailableSourceIncludes(proof, lostNodeID) {
		t.Fatalf("status boundary was not atomically transferred: rollout=%+v drain=%+v", storedCluster.Status.StorageRollout, proof)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) || !coordinator.StorageDrainActive(key) {
		t.Fatalf("in-memory boundary was not transferred: rollout=%v drain=%v", coordinator.NodeLocalPoolRolloutActive(key), coordinator.StorageDrainActive(key))
	}
	storedStatefulSet := &appsv1.StatefulSet{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(statefulSet), storedStatefulSet); err != nil {
		t.Fatal(err)
	}
	if storedStatefulSet.Spec.Replicas == nil || *storedStatefulSet.Spec.Replicas != 1 {
		t.Fatalf("workload was fenced before durable status transfer completed: replicas=%v", storedStatefulSet.Spec.Replicas)
	}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(claim), claim); err != nil {
		t.Fatal(err)
	}
	if len(claim.Finalizers) != 0 {
		t.Fatalf("rollout PVC protection was not released after durable drain transfer: %v", claim.Finalizers)
	}
}

func TestLostStorageRolloutTransferCrashTailReleasesProtection(t *testing.T) {
	const nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
	}}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testNodeUID},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	proof, err := storageDrainRemovalIntent(
		nil, storageDrainActorForNode(node), []string{nodeID}, []string{nodeID}, time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof.UnavailableSourceNodeIDs = []string{nodeID}
	proof.TargetHash = storageDrainProofTargetHash(proof)
	cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: testStorageMetadataPVC, Namespace: cluster.Namespace, UID: testPVCUID,
		Finalizers: []string{storageRolloutPVCFinalizer(cluster)},
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, claim).Build()
	coordinator := NewLayoutMutationCoordinator()
	key := layoutOwnerKey(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(key, cluster.UID, client.ObjectKeyFromObject(cluster), cluster.UID) ||
		!coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) ||
		!coordinator.BeginStorageDrain(key, cluster.UID, node.UID, proof.TransactionID, proof.TargetHash) {
		t.Fatal("failed to establish transfer crash-tail markers")
	}
	reconciler := &GarageNodeReconciler{Client: fakeClient, APIReader: fakeClient, LayoutMutations: coordinator}
	handled, err := reconciler.recoverOrTransferStorageRolloutLostSource(
		context.Background(), node, cluster, cluster,
	)
	if err != nil || handled {
		t.Fatalf("transfer tail recovery failed: handled=%v err=%v", handled, err)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) || !coordinator.StorageDrainActive(key) {
		t.Fatalf("tail recovery changed the wrong boundary: rollout=%v drain=%v", coordinator.NodeLocalPoolRolloutActive(key), coordinator.StorageDrainActive(key))
	}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(claim), claim); err != nil {
		t.Fatal(err)
	}
	if len(claim.Finalizers) != 0 {
		t.Fatalf("tail recovery retained stale rollout PVC finalizer: %v", claim.Finalizers)
	}
}

func TestLostNodeLocalPoolRolloutTransfersAfterKubernetesNodeDisappears(t *testing.T) {
	const nodeID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	capacityBytes := uint64(1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{ID: nodeID}}})
		case pathGetLayoutHistory:
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: 2,
				Versions:       []garage.LayoutVersion{{Version: 2, Status: garage.LayoutVersionStatusCurrent}},
			})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 2, Roles: []garage.LayoutNodeRole{{
				ID: nodeID, Capacity: &capacityBytes,
			}}})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID, Generation: 1},
		Status: garagev1beta2.GarageClusterStatus{StorageRollout: &garagev1beta2.StorageRolloutStatus{
			NodeLocalPoolName: testTagLocal, KubernetesNodeName: "worker-gone", KubernetesNodeUID: "deleted-k8s-node-uid",
			GarageNodeUID: testNodeUID, GarageNodeID: nodeID, WorkloadUID: testDaemonSetUID,
			PreviousPodUID: "old-pod-uid", DesiredPodSpecHash: "desired-spec", DesiredConfigHash: "desired-config",
			ClusterGeneration: 1, GarageNodeGeneration: 1,
		}},
	}
	capacity := resource.MustParse("1Ti")
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pool-worker-gone", Namespace: cluster.Namespace, UID: testNodeUID, Generation: 1,
			Annotations: map[string]string{
				garagev1beta1.AnnotationDrain:                 annotationTrue,
				garagev1beta1.AnnotationAcknowledgeLostSource: nodeID,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:    garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: testTagLocal,
			KubernetesNodeName: "worker-gone", Capacity: &capacity,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	// Deliberately omit the Kubernetes Node, DaemonSet Pod, and every HostPath
	// process: their permanent loss is the reason this explicit transition exists.
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, node).Build()
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	coordinator := NewLayoutMutationCoordinator()
	key := layoutOwnerKey(cluster)
	coordinator.BeginNodeLocalPoolRollout(key, cluster.UID, client.ObjectKeyFromObject(cluster), cluster.UID)
	coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID)
	reconciler := &GarageNodeReconciler{
		Client: fakeClient, APIReader: fakeClient, LayoutMutations: coordinator,
		lostSourceGarageClientGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.Client, error) {
			return garage.NewClient(server.URL, "token"), nil
		},
	}
	transferred, err := reconciler.recoverOrTransferStorageRolloutLostSource(
		context.Background(), node, cluster, cluster,
	)
	if err != nil || !transferred {
		t.Fatalf("lost HostPath actor did not transfer after Kubernetes Node loss: transferred=%v err=%v", transferred, err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.StorageRollout != nil ||
		!storageDrainUnavailableSourceIncludes(clusterStorageDrainProof(stored.Status.StorageDrain), nodeID) {
		t.Fatalf("lost HostPath actor transfer was not durable: %+v", stored.Status)
	}
}

func TestBlockResyncObservationFailsClosedOnStagingOrMixedSnapshot(t *testing.T) {
	capacity := uint64(1)
	history := &garage.LayoutHistoryResponse{
		CurrentVersion: 1,
		Versions:       []garage.LayoutVersion{{Version: 1, Status: garage.LayoutVersionStatusCurrent}},
	}
	layout := &garage.ClusterLayout{Version: 1, Roles: []garage.LayoutNodeRole{{ID: testStorageNodeName, Capacity: &capacity}}}
	status := &garage.ClusterStatus{LayoutVersion: 1, Nodes: []garage.NodeInfo{{
		ID: testStorageNodeName, Role: &garage.NodeAssignedRole{Capacity: &capacity},
	}}}
	workers := &garage.ListWorkersResponse{Success: map[string][]garage.WorkerInfo{testStorageNodeName: {}}}
	errors := &garage.ListBlockErrorsResponse{Success: map[string][]garage.BlockError{testStorageNodeName: {}}}

	layout.StagedRoleChanges = []garage.NodeRoleChange{{ID: testForeignValue, Remove: true}}
	_, err := blockResyncObservationFromResponses(history, layout, status, workers, errors)
	if err == nil || !strings.Contains(err.Error(), "staging area") {
		t.Fatalf("non-empty global staging was accepted: %v", err)
	}
	layout.StagedRoleChanges = nil
	status.LayoutVersion = 2
	_, err = blockResyncObservationFromResponses(history, layout, status, workers, errors)
	if err == nil || !strings.Contains(err.Error(), "snapshots disagree") {
		t.Fatalf("mixed layout snapshots were accepted: %v", err)
	}
}

func TestBlockResyncProgressCoordinatesRepairAndResync(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	queue := uint64(99) // future GC; local consistent mode need not force zero
	observation := testDrainObservation(queue)
	proof := testDrainIntent(t, testRemovedNodeID, now)

	decision := evaluateBlockResyncProgress(proof, observation, now, time.Minute, false)
	if decision.Ready || decision.Proof.RepairBaselines[testStorageNodeName] != 4 || decision.Proof.RepairBaselines[testRemovedNodeID] != 4 {
		t.Fatalf("first observation did not persist the pre-repair worker baseline: %+v", decision)
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if got := strings.Join(decision.LaunchNodeIDs, ","); got != expectedDrainVerificationLaunchNodeIDs {
		t.Fatalf("Blocks repair launch targets = %q", got)
	}

	repair := garage.WorkerInfo{ID: 5, Name: blockRepairWorkerName, State: garage.WorkerState{State: "busy"}}
	for _, nodeID := range observation.VerificationNodeIDs {
		node := observation.Nodes[nodeID]
		node.Workers = append(node.Workers, repair)
		observation.Nodes[nodeID] = node
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if decision.Proof.RepairWorkerIDs[testStorageNodeName] != 5 || decision.Proof.RepairWorkerIDs[testRemovedNodeID] != 5 || decision.Ready {
		t.Fatalf("post-baseline repair worker was not adopted: %+v", decision)
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if decision.Ready || !strings.Contains(decision.Message, "waiting for block repair") {
		t.Fatalf("busy repair was accepted: %+v", decision)
	}

	for _, nodeID := range observation.VerificationNodeIDs {
		node := observation.Nodes[nodeID]
		node.Workers[1].State.State = "done"
		observation.Nodes[nodeID] = node
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if decision.Ready || decision.Proof.QuietSince == nil || decision.Proof.ResyncErrorBaselines == nil {
		t.Fatalf("clean repair did not start the delayed-resync window: %+v", decision)
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now.Add(time.Minute), time.Minute, false)
	if !decision.Ready || decision.Proof.CompletedAt == nil {
		t.Fatalf("clean repair/resync evidence did not complete: %+v", decision)
	}
	readyProof := decision.Proof

	decision = evaluateBlockResyncProgress(decision.Proof, observation, now.Add(2*time.Minute), time.Minute, true)
	if decision.Ready || !strings.Contains(decision.Message, "recorded pre-Blocks-repair") {
		t.Fatalf("changing the queue-bound mode did not reset the proof snapshot: %+v", decision)
	}
	strictProof := copyBlockResyncProof(readyProof)
	strictProof.RequiresEmptyQueue = true
	decision = evaluateBlockResyncProgress(strictProof, observation, now.Add(2*time.Minute), time.Minute, true)
	if decision.Ready || !strings.Contains(decision.Message, "queue to become empty") {
		t.Fatalf("an unverifiable survivor timeout accepted a non-empty queue: %+v", decision)
	}
	observation.QueueLength = 0
	observation.Nodes[testStorageNodeName].Workers[0].QueueLength = uint64Pointer(0)
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now.Add(2*time.Minute), time.Minute, true)
	if !decision.Ready {
		t.Fatalf("empty terminal queue did not complete the strict fallback: %+v", decision)
	}
}

func TestBlockResyncProgressRestartsCleanProofWhenPersistentErrorsChangeDuringQuietWindow(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	observation := testDrainObservation(0)
	proof := testDrainIntent(t, testRemovedNodeID, now)

	decision := evaluateBlockResyncProgress(proof, observation, now, time.Minute, false)
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if got := strings.Join(decision.LaunchNodeIDs, ","); got != expectedDrainVerificationLaunchNodeIDs {
		t.Fatalf("Blocks repair launch targets = %q", got)
	}

	repair := garage.WorkerInfo{ID: 5, Name: blockRepairWorkerName, State: garage.WorkerState{State: "done"}}
	for _, nodeID := range observation.VerificationNodeIDs {
		node := observation.Nodes[nodeID]
		node.Workers = append(node.Workers, repair)
		observation.Nodes[nodeID] = node
	}
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now, time.Minute, false)
	if decision.Proof.QuietSince == nil || decision.Proof.ResyncErrorBaselines == nil {
		t.Fatalf("clean repairs did not begin the quiet window: %+v", decision)
	}
	originalQuietSince := decision.Proof.QuietSince.DeepCopy()

	// A persistent resync error can be repaired and disappear from the next
	// observation. Seeing it at any point during the quiet window must invalidate
	// the whole clean proof; otherwise the old QuietSince could later make the
	// transaction terminal without a full clean interval.
	node := observation.Nodes[testRemovedNodeID]
	node.Workers[0].PersistentErrors = uint64Pointer(1)
	node.ErrorCount = 1
	observation.Nodes[testRemovedNodeID] = node
	observation.ErrorCount = 1
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now.Add(30*time.Second), time.Minute, false)
	if decision.Ready || decision.Proof.QuietSince != nil || decision.Proof.ResyncErrorBaselines != nil ||
		len(decision.Proof.RepairWorkerIDs) != 0 {
		t.Fatalf("persistent error change retained terminal quiet evidence from %s: %+v", originalQuietSince, decision)
	}
	if !strings.Contains(decision.Message, "persistent error counter") {
		t.Fatalf("persistent error change did not explain the clean-proof restart: %+v", decision)
	}

	node = observation.Nodes[testRemovedNodeID]
	node.Workers[0].PersistentErrors = uint64Pointer(0)
	node.ErrorCount = 0
	observation.Nodes[testRemovedNodeID] = node
	observation.ErrorCount = 0
	decision = evaluateBlockResyncProgress(decision.Proof, observation, now.Add(2*time.Minute), time.Minute, false)
	if decision.Ready || decision.Proof.QuietSince != nil {
		t.Fatalf("cleared persistent error reused the prior quiet window: %+v", decision)
	}
	if got := strings.Join(decision.LaunchNodeIDs, ","); got != expectedDrainVerificationLaunchNodeIDs {
		t.Fatalf("cleared persistent error did not restart a full clean repair transaction; launch targets = %q", got)
	}
}

func TestBlockResyncProgressRejectsReappearedTargetAndLostRepair(t *testing.T) {
	now := time.Now()
	intent := testDrainIntent(t, testRemovedNodeID, now)
	observation := testDrainObservation(0)
	observation.CurrentRoleNodeIDs = []string{testRemovedNodeID, testStorageNodeName}
	decision := evaluateBlockResyncProgress(intent, observation, now, time.Minute, false)
	if decision.Ready || !strings.Contains(decision.Message, "present in the current") || decision.Proof.LayoutVersion != 0 {
		t.Fatalf("reappeared removal target was accepted: %+v", decision)
	}

	completed := testDrainIntent(t, testRemovedNodeID, now)
	completed.LayoutVersion = 7
	completed.VerificationNodeIDs = []string{testRemovedNodeID, testStorageNodeName}
	completed.RepairBaselines = map[string]uint64{testRemovedNodeID: 4, testStorageNodeName: 4}
	completed.RepairWorkerIDs = map[string]uint64{testRemovedNodeID: 5, testStorageNodeName: 5}
	completed.ResyncErrorBaselines = map[string]uint64{"removed-a/4": 0, "storage-a/4": 0}
	quiet := metav1.NewTime(now.Add(-time.Hour))
	completed.QuietSince = &quiet
	completedAt := metav1.NewTime(now.Add(-time.Minute))
	completed.CompletedAt = &completedAt
	decision = evaluateBlockResyncProgress(completed, testDrainObservation(0), now, time.Minute, false)
	if decision.Ready || decision.Proof.CompletedAt != nil || len(decision.Proof.RepairWorkerIDs) != 0 {
		t.Fatalf("lost exact repair worker evidence reused CompletedAt: %+v", decision)
	}
}

func TestStorageDrainRequiresLiteralConsistentMode(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{}
	if err := requireConsistentStorageDrain(cluster); err != nil {
		t.Fatalf("default consistency mode should be consistent: %v", err)
	}
	cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{Factor: 2, ConsistencyMode: testDegradedMode}
	if err := requireConsistentStorageDrain(cluster); err == nil || !strings.Contains(err.Error(), "requires spec.replication.consistencyMode: consistent") {
		t.Fatalf("RF2 degraded mode bypassed the upstream layout-history gate: %v", err)
	}
	cluster.Spec.Replication.ConsistencyMode = consistencyModeDangerous
	if err := requireConsistentStorageDrain(cluster); err == nil {
		t.Fatal("dangerous mode bypassed the upstream layout-history gate")
	}
}

func TestCapacitylessClusterCleanupDoesNotStartStorageDrainWithoutExplicitPreparation(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{}
	actor := storageDrainActor{Kind: kindGarageCluster}
	if err := ensureClusterStorageDrainIntent(
		context.Background(), nil, nil, nil, cluster, nil, actor, []string{testGatewayNodeID}, nil,
	); err != nil {
		t.Fatalf("routine capacity-less cleanup entered storage-drain validation: %v", err)
	}

	cluster.Annotations = map[string]string{garagev1beta1.AnnotationDrain: annotationTrue}
	err := ensureClusterStorageDrainIntent(
		context.Background(), nil, nil, nil, cluster, nil, actor, []string{testGatewayNodeID}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "GarageCluster UID") {
		t.Fatalf("explicit role-only Drain did not enter durable intent validation: %v", err)
	}
}

func TestManagementHandleUsesLayoutWideDrainReadiness(t *testing.T) {
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Spec: garagev1beta2.GarageClusterSpec{
			ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "https://garage.example"},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{
				Drain: &garagev1beta2.StorageDrainConfig{
					UnverifiedPeersPolicy: garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent,
				},
			},
		},
		Status: garagev1beta2.GarageClusterStatus{Conditions: []metav1.Condition{{
			Type: garagev1beta1.ConditionManagementHandleReady, Status: metav1.ConditionTrue,
			Reason: garagev1beta1.ReasonReconcileSuccess, ObservedGeneration: 3,
		}}},
	}
	if reason, err := requireStorageDrainStartReady(handle); err != nil || reason != "" {
		t.Fatalf("ready management handle was forced through a nonexistent storage rollout: reason=%q err=%v", reason, err)
	}
	if got := effectiveStorageDrainUnverifiedPeersPolicy(handle); got != garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent {
		t.Fatalf("layout-wide drain policy was not read from management handle: %q", got)
	}
	handle.Status.Conditions[0].ObservedGeneration = 2
	if _, err := requireStorageDrainStartReady(handle); err == nil || !strings.Contains(err.Error(), "ManagementHandleReady") {
		t.Fatalf("stale management-handle readiness was accepted: %v", err)
	}
}

func TestStorageDrainTargetsAreMonotonicAndObservationResetPreservesIntent(t *testing.T) {
	now := time.Now()
	previous := testDrainIntent(t, "removed-b", now)
	quietSince := metav1.NewTime(now)
	previous.QuietSince = &quietSince
	next, err := storageDrainRemovalIntent(
		previous, testDrainActor(),
		[]string{testGatewayNodeID, testRemovedNodeID, "removed-b"},
		[]string{testRemovedNodeID, "removed-b"}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(next.RoleRemovalNodeIDs, ","); got != "gateway-a,removed-a,removed-b" {
		t.Fatalf("authorized removal targets = %q", got)
	}
	if got := strings.Join(next.RemovedStorageNodeIDs, ","); got != "removed-a,removed-b" {
		t.Fatalf("positive-capacity targets = %q", got)
	}
	if next.QuietSince != nil || next.LayoutVersion != 0 {
		t.Fatalf("new removal target reused old evidence: %+v", next)
	}
	next.LayoutVersion = 7
	next.RepairBaselines = map[string]uint64{testRemovedNodeID: 58}
	next.RepairWorkerIDs = map[string]uint64{testRemovedNodeID: 59}
	next.ResyncErrorBaselines = map[string]uint64{testRemovedNodeID + "/1": 0}
	next.QueueLength = 123
	next.ErrorCount = 4
	next.QuietSince = &quietSince
	next.CompletedAt = &quietSince
	reset := resetBlockResyncObservation(next)
	if got := strings.Join(reset.RemovedStorageNodeIDs, ","); got != "removed-a,removed-b" {
		t.Fatalf("observation failure erased removal intent: %q", got)
	}
	if reset.LayoutVersion != 7 || reset.RepairBaselines[testRemovedNodeID] != 58 ||
		reset.RepairWorkerIDs[testRemovedNodeID] != 59 ||
		reset.ResyncErrorBaselines[testRemovedNodeID+"/1"] != 0 {
		t.Fatalf("observation retry discarded exact durable worker evidence: %+v", reset)
	}
	if reset.QueueLength != 123 || reset.ErrorCount != 4 {
		t.Fatalf("observation retry rewrote the last durable counters: %+v", reset)
	}
	if reset.QuietSince != nil || reset.CompletedAt != nil {
		t.Fatalf("observation retry retained terminal timing evidence: %+v", reset)
	}
}

func TestStorageDrainObservationRetryRetainsExactRepairWorkers(t *testing.T) {
	now := time.Now()
	proof := testDrainIntent(t, testRemovedNodeID, now.Add(-time.Minute))
	proof.LayoutVersion = 7
	proof.VerificationNodeIDs = []string{testRemovedNodeID}
	proof.RepairBaselines = map[string]uint64{testRemovedNodeID: 58}
	proof.RepairWorkerIDs = map[string]uint64{testRemovedNodeID: 59}
	proof.ResyncErrorBaselines = map[string]uint64{testRemovedNodeID + "/1": 0}
	quietSince := metav1.NewTime(now.Add(-time.Second))
	proof.QuietSince = &quietSince
	proof.CompletedAt = &quietSince

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID, Generation: 1,
		},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{}},
		Status: garagev1beta2.GarageClusterStatus{
			StorageDrain: v1beta2StorageDrainStatus(proof),
		},
	}
	markGarageClusterDrainReady(cluster)
	scheme := deletionTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}

	err := requireClusterStorageDrainSafety(
		context.Background(), fakeClient, fakeClient, NewLayoutMutationCoordinator(),
		cluster, testDrainActor(), nil,
		func(context.Context, *garage.Client) (*blockResyncObservation, error) {
			return nil, fmt.Errorf("temporary federated ListWorkers timeout")
		},
		nil,
		func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
			return &garage.ClusterHealth{
				Status: healthStatusHealthy, StorageNodes: 1, StorageNodesUp: 1,
				Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
			}, nil
		},
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "cannot prove Garage object-block migration complete") {
		t.Fatalf("temporary observation failure did not keep the drain pending: %v", err)
	}

	fresh := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), fresh); err != nil {
		t.Fatal(err)
	}
	retried := clusterStorageDrainProof(fresh.Status.StorageDrain)
	if retried == nil || retried.LayoutVersion != 7 ||
		retried.RepairBaselines[testRemovedNodeID] != 58 ||
		retried.RepairWorkerIDs[testRemovedNodeID] != 59 ||
		retried.ResyncErrorBaselines[testRemovedNodeID+"/1"] != 0 {
		t.Fatalf("temporary observation failure discarded exact worker evidence: %+v", retried)
	}
	if retried.QuietSince != nil || retried.CompletedAt != nil {
		t.Fatalf("temporary observation failure retained terminal timing evidence: %+v", retried)
	}
}

func TestNormalizedNodeIDsKeepsEmptyAPIRoundTripsStable(t *testing.T) {
	for name, input := range map[string][]string{
		"nil":              nil,
		"empty":            {},
		"empty values":     {"", "  "},
		"duplicate blanks": {" ", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizedNodeIDs(input); got != nil {
				t.Fatalf("normalized empty node IDs must use the API-stable nil representation, got %#v", got)
			}
		})
	}

	// Model the exact normal-drain round trip: unavailable sources are absent,
	// the API omits the empty field, and recomputing the combined intent must not
	// manufacture [] and invalidate already-recorded worker baselines.
	proof := testDrainIntent(t, testRemovedNodeID, time.Now())
	proof.LayoutVersion = 7
	proof.RepairBaselines = map[string]uint64{testRemovedNodeID: 4}
	roundTripped := clusterStorageDrainProof(v1beta2StorageDrainStatus(proof))
	combinedUnavailable := normalizedNodeIDs(append(
		append([]string(nil), roundTripped.UnavailableSourceNodeIDs...),
		[]string(nil)...,
	))
	if combinedUnavailable != nil {
		t.Fatalf("omitted unavailable-source intent changed across API round trip: %#v", combinedUnavailable)
	}
	if roundTripped.LayoutVersion != 7 || len(roundTripped.RepairBaselines) != 1 {
		t.Fatalf("API round trip lost existing drain evidence: %+v", roundTripped)
	}
}

func TestStorageDrainProofCASRejectsStaleSameTransactionWriter(t *testing.T) {
	ctx := context.Background()
	initial := testDrainIntent(t, testRemovedNodeID, time.Now())
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID,
		},
		Status: garagev1beta2.GarageClusterStatus{
			StorageDrain: v1beta2StorageDrainStatus(initial),
		},
	}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()

	stale := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stale); err != nil {
		t.Fatal(err)
	}
	expected := storageDrainRevisionFromStatus(stale.Status.StorageDrain)

	concurrent := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), concurrent); err != nil {
		t.Fatal(err)
	}
	advanced := copyBlockResyncProof(initial)
	advanced.LayoutVersion = 7
	advanced.VerificationNodeIDs = []string{testRemovedNodeID, testStorageNodeName}
	advanced.RepairBaselines = map[string]uint64{
		testRemovedNodeID: 4, testStorageNodeName: 4,
	}
	concurrent.Status.StorageDrain = v1beta2StorageDrainStatus(advanced)
	if err := kubeClient.Status().Update(ctx, concurrent); err != nil {
		t.Fatal(err)
	}
	if sameStorageDrainRevision(
		expected,
		storageDrainRevisionFromStatus(concurrent.Status.StorageDrain),
	) {
		t.Fatal("evolving proof evidence did not change the storage-drain CAS revision")
	}

	// The stale writer has the same actor, transaction, and target hash as the
	// advanced proof. Its first status update must conflict on resourceVersion;
	// after re-read, the proof hash must stop the retry from erasing progress.
	if err := updateClusterStorageDrainProof(
		ctx, kubeClient, stale, expected, initial, "stale writer",
	); err == nil || !strings.Contains(err.Error(), "storage-drain revision changed") {
		t.Fatalf("stale same-transaction writer was not rejected: %v", err)
	}

	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	proof := clusterStorageDrainProof(stored.Status.StorageDrain)
	if proof == nil || proof.LayoutVersion != 7 || len(proof.RepairBaselines) != 2 {
		t.Fatalf("stale writer regressed persisted repair evidence: %+v", proof)
	}
}

func TestFailedPreparedDrainRevertsStagingAndReleasesTransaction(t *testing.T) {
	capacity := uint64(1024)
	layout := newFakeGarageLayout(
		garage.LayoutNodeRole{ID: testRemovedNodeID, Capacity: &capacity},
		garage.LayoutNodeRole{ID: testStorageNodeName, Capacity: &capacity},
	)
	layout.staged = []garage.NodeRoleChange{{ID: testRemovedNodeID, Remove: true}}
	server := layout.server()
	defer server.Close()
	garageClient := garage.NewClient(server.URL, "token")

	now := time.Now()
	proof := testDrainIntent(t, testRemovedNodeID, now)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID},
		Status: garagev1beta2.GarageClusterStatus{
			StorageDrain: v1beta2StorageDrainStatus(proof),
		},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: testGarageValue, UID: testNodeUID},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: testTerminalNodeID},
	}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, LayoutMutations: NewLayoutMutationCoordinator()}
	err := reconciler.recoverNodeDrainApplyFailure(
		context.Background(), node, cluster, garageClient,
		[]garage.NodeRoleChange{{ID: testRemovedNodeID, Remove: true}}, fmt.Errorf("apply rejected"),
	)
	if err == nil || !strings.Contains(err.Error(), "reverted failed") {
		t.Fatalf("failed Apply was not reported after recovery: %v", err)
	}
	if !layout.hasRole(testRemovedNodeID) {
		t.Fatal("failed preparation removed the source role")
	}
	layout.mu.Lock()
	stagedCount := len(layout.staged)
	layout.mu.Unlock()
	if stagedCount != 0 {
		t.Fatalf("failed preparation left %d staged Garage changes", stagedCount)
	}
	fresh := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.StorageDrain != nil {
		t.Fatalf("reverted role-present preparation retained a blocking transaction: %+v", fresh.Status.StorageDrain)
	}
}

func TestParentDrainPreparationAnnotatesBeforeDeletion(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: testClusterUID},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: testGarageValue, UID: testNodeUID},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: testTerminalNodeID},
	}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient}
	err := reconciler.prepareGarageNodeDeletionDrain(context.Background(), cluster, node)
	if err == nil || !strings.Contains(err.Error(), "ConditionDrainPrepared") {
		t.Fatalf("parent did not stop after requesting reversible preparation: %v", err)
	}
	freshNode := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if freshNode.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue || !freshNode.DeletionTimestamp.IsZero() {
		t.Fatalf("parent crossed the deletion boundary before preparation: %+v", freshNode.ObjectMeta)
	}

	proof := testDrainIntent(t, testTerminalNodeID, time.Now())
	proof.ManagedPodUIDs = map[string]string{testTerminalNodeID: testSourcePodUID}
	completedAt := metav1.Now()
	proof.CompletedAt = &completedAt
	cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
	if err := reconciler.prepareGarageNodeDeletionDrain(context.Background(), cluster, freshNode); err != nil {
		t.Fatalf("terminal exact proof did not authorize the later Delete step: %v", err)
	}
}
