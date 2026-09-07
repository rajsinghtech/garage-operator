/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testEdgeClusterUID          = "edge-uid"
	testStorageClusterUID       = "storage-uid"
	testSkipDeadNodesPath       = "/v2/ClusterLayoutSkipDeadNodes"
	testExternalAdminSecretName = "external-admin"
	testEdgeOwnershipTag        = "cluster:edge/garage"
)

func deletionTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		policyv1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func deletionTestReconciler(scheme *runtime.Scheme, objects ...client.Object) (*GarageClusterReconciler, client.Client) {
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).
		WithObjects(objects...).Build()
	return &GarageClusterReconciler{
		Client:          fakeClient,
		Scheme:          scheme,
		ClusterScoped:   true,
		LayoutMutations: NewLayoutMutationCoordinator(),
	}, fakeClient
}

func markGarageClusterDrainReady(cluster *garagev1beta2.GarageCluster) {
	cluster.Status.Conditions = []metav1.Condition{{
		Type:               garagev1beta1.ConditionStorageRolloutReady,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonStorageRolloutConverged,
		ObservedGeneration: cluster.Generation,
		LastTransitionTime: metav1.Now(),
	}}
	cluster.Status.Health = &garagev1beta2.ClusterHealth{
		Status: healthStatusHealthy, Healthy: true, Available: true,
		StorageNodes: 4, StorageNodesOK: 4,
		Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
	}
}

func TestFinalizeDestroySkipsImpossibleEmptyLayoutForAnyReplicationFactor(t *testing.T) {
	t.Parallel()
	for _, factor := range []int{1, 3} {
		t.Run(string(rune('0'+factor)), func(t *testing.T) {
			t.Parallel()
			scheme := deletionTestScheme(t)
			reconciler, _ := deletionTestReconciler(scheme)
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "destroy", Namespace: testGarageValue, UID: "destroy-uid"},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:          &garagev1beta2.StorageSpec{},
					Replication:      &garagev1beta2.ReplicationConfig{Factor: factor},
					DeletionPolicy:   garagev1beta2.DeletionPolicyDestroy,
					LayoutManagement: &garagev1beta2.LayoutManagementConfig{AutoApply: true},
				},
			}
			// There is deliberately no Admin token or reachable Garage endpoint.
			// Destroy must complete without attempting either one.
			if err := reconciler.finalize(context.Background(), cluster); err != nil {
				t.Fatalf("Destroy with RF=%d attempted layout cleanup: %v", factor, err)
			}
		})
	}
}

func TestFinalizeDestroyCancelsActiveStorageRollout(t *testing.T) {
	t.Parallel()
	scheme := deletionTestScheme(t)
	now := metav1.Now()
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "destroy-rollout", Namespace: testGarageValue, UID: "destroy-rollout-uid",
			DeletionTimestamp: &now, Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage:        &garagev1beta2.StorageSpec{},
			DeletionPolicy: garagev1beta2.DeletionPolicyDestroy,
		},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				GarageNodeName: "rollout-node", PreviousPodUID: "old-pod",
			},
			Conditions: []metav1.Condition{{
				Type:   garagev1beta1.ConditionStorageRolloutReady,
				Status: metav1.ConditionFalse, Reason: garagev1beta1.ReasonStorageRollingOut,
			}},
		},
	}
	reconciler, fakeClient := deletionTestReconciler(scheme, cluster)
	coordinator := reconciler.LayoutMutations
	key := layoutOwnerKey(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(
		key, layoutRolloutOwnerID(cluster), client.ObjectKeyFromObject(cluster), cluster.UID,
	) || !coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) {
		t.Fatal("could not establish the active rollout marker")
	}

	if err := reconciler.finalize(context.Background(), cluster); err != nil {
		t.Fatalf("Destroy finalization remained behind active storage rollout: %v", err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.StorageRollout != nil {
		t.Fatalf("Destroy finalization retained storage rollout state: %+v", stored.Status.StorageRollout)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) {
		t.Fatal("Destroy finalization retained the in-memory rollout marker")
	}
}

func TestFinalizeDrainWithoutAdminTokenKeepsStorageWorkload(t *testing.T) {
	t.Parallel()
	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "drain", Namespace: testGarageValue, UID: "drain-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage:        &garagev1beta2.StorageSpec{},
			Replication:    &garagev1beta2.ReplicationConfig{Factor: 3},
			DeletionPolicy: garagev1beta2.DeletionPolicyDrain,
		},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: cluster.Name, Namespace: cluster.Namespace}}
	reconciler, fakeClient := deletionTestReconciler(scheme, statefulSet)

	err := reconciler.finalize(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "Drain requires a configured, readable Admin API token") {
		t.Fatalf("Drain without token error = %v", err)
	}
	if getErr := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(statefulSet), &appsv1.StatefulSet{}); getErr != nil {
		t.Fatalf("Drain removed storage workload before proving layout safety: %v", getErr)
	}
}

func TestRemoveNodesFromLayoutUsesExactIDsAndClusterUID(t *testing.T) {
	t.Parallel()
	const (
		knownID      = "known-local-id"
		uidOwnedID   = "uid-owned-local-id"
		otherSiteID  = "same-name-other-site-id"
		unrelatedID  = "unrelated-id"
		localUID     = "site-a-uid"
		canonicalTag = "cluster:garage/garage"
		storageTier  = "tier:storage"
	)
	capacity := uint64(1 << 30)
	roles := []garage.LayoutNodeRole{
		{ID: knownID, Zone: testSiteA, Capacity: &capacity, Tags: []string{canonicalTag, storageTier}},
		{ID: uidOwnedID, Zone: testSiteA, Capacity: &capacity, Tags: []string{canonicalTag, "cluster-uid:" + localUID, storageTier}},
		{ID: otherSiteID, Zone: "site-b", Capacity: &capacity, Tags: []string{canonicalTag, "cluster-uid:site-b-uid", storageTier}},
		{ID: unrelatedID, Zone: "site-c", Capacity: &capacity, Tags: []string{"cluster:other/garage", storageTier}},
	}
	var staged []garage.NodeRoleChange
	var requested []garage.NodeRoleChange
	version := uint64(8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 9})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: version, Roles: roles, StagedRoleChanges: staged})
		case pathUpdateLayout:
			var req garage.UpdateClusterLayoutRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			staged = req.Roles
			requested = append([]garage.NodeRoleChange(nil), req.Roles...)
			w.WriteHeader(http.StatusOK)
		case pathApplyLayout:
			version++
			staged = nil
			w.WriteHeader(http.StatusOK)
		case pathGetLayoutHistory:
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions:       []garage.LayoutVersion{{Version: version, Status: garage.LayoutVersionStatusCurrent}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageValue, Namespace: testGarageValue, UID: types.UID(localUID), Generation: 1},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{
				Drain: &garagev1beta2.StorageDrainConfig{UnverifiedPeersPolicy: garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent},
			},
		},
	}
	markGarageClusterDrainReady(cluster)
	scheme := deletionTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{
		Client:          fakeClient,
		LayoutMutations: NewLayoutMutationCoordinator(),
		clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
			return &garage.ClusterHealth{Status: healthStatusHealthy, StorageNodes: 4, StorageNodesUp: 4, Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256}, nil
		},
		blockResyncObservationGetter: func(context.Context, *garage.Client) (*blockResyncObservation, error) {
			return nil, fmt.Errorf("proof intentionally pending")
		},
	}
	drainErr := reconciler.removeNodesFromLayoutLocked(
		context.Background(), cluster, map[string]bool{knownID: true}, garage.NewClient(server.URL, "token"),
	)
	if !stderrors.Is(drainErr, errLayoutMutationPending) {
		t.Fatalf("removal did not reach the expected post-Apply proof wait: %v", drainErr)
	}
	if version != 9 {
		t.Fatalf("layout version = %d, want one exact removal apply; drain error: %v", version, drainErr)
	}
	gotIDs := make([]string, 0, len(requested))
	for i := range requested {
		if !requested[i].Remove {
			t.Fatalf("non-removal staged during Drain: %#v", requested[i])
		}
		gotIDs = append(gotIDs, requested[i].ID)
	}
	sort.Strings(gotIDs)
	wantIDs := []string{knownID, uidOwnedID}
	sort.Strings(wantIDs)
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("Drain staged IDs %v, want exact known/UID-owned IDs %v", gotIDs, wantIDs)
	}
}

func TestRemoveNodesFromLayoutReplicationConstraintBlocksDrain(t *testing.T) {
	t.Parallel()
	const nodeID = "last-storage-node"
	capacity := uint64(1 << 30)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
				Version: 1,
				Roles:   []garage.LayoutNodeRole{{ID: nodeID, Zone: "only", Capacity: &capacity}},
			})
		case pathUpdateLayout:
			http.Error(w, "The number of nodes with positive capacity (0) is smaller than the replication factor (3)", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testSiteName, Namespace: testGarageValue, UID: "site-uid", Generation: 1},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{
				Drain: &garagev1beta2.StorageDrainConfig{UnverifiedPeersPolicy: garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent},
			},
		},
	}
	markGarageClusterDrainReady(cluster)
	scheme := deletionTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	err := (&GarageClusterReconciler{Client: fakeClient, LayoutMutations: NewLayoutMutationCoordinator()}).removeNodesFromLayoutLocked(
		context.Background(), cluster, map[string]bool{nodeID: true}, garage.NewClient(server.URL, "token"),
	)
	if err == nil || !strings.Contains(err.Error(), "replication constraints") {
		t.Fatalf("replication-constrained Drain error = %v", err)
	}
}

func TestFinalizeDestroyDeletesEveryReferencingGarageNodeAndNeverDeletesUnownedConfigCollision(t *testing.T) {
	t.Parallel()
	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "manual", Namespace: testGarageValue, UID: "manual-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage:        &garagev1beta2.StorageSpec{},
			LayoutPolicy:   LayoutPolicyManual,
			DeletionPolicy: garagev1beta2.DeletionPolicyDestroy,
		},
	}
	operatorNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "operator-node", Namespace: cluster.Namespace, Labels: map[string]string{labelAppManagedBy: managedByOperatorValue}},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
	}
	manualSMBNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-smb", Namespace: cluster.Namespace},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
	}
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cluster.Name + "-config", Namespace: cluster.Namespace}}
	reconciler, fakeClient := deletionTestReconciler(scheme, operatorNode, manualSMBNode, config)

	err := reconciler.finalize(context.Background(), cluster)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("first finalize = %v, want wait for GarageNode foreground deletion", err)
	}
	if getErr := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(config), &corev1.ConfigMap{}); getErr != nil {
		t.Fatalf("shared config was deleted before GarageNodes: %v", getErr)
	}
	remaining := &garagev1beta1.GarageNodeList{}
	if listErr := fakeClient.List(context.Background(), remaining, client.InNamespace(cluster.Namespace)); listErr != nil {
		t.Fatal(listErr)
	}
	if len(remaining.Items) != 0 {
		names := make([]string, 0, len(remaining.Items))
		for i := range remaining.Items {
			names = append(names, remaining.Items[i].Name)
		}
		sort.Strings(names)
		t.Fatalf("Destroy left referencing GarageNodes behind: %v", names)
	}
	if err := reconciler.finalize(context.Background(), cluster); err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	if getErr := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(config), &corev1.ConfigMap{}); getErr != nil {
		t.Fatalf("finalizer deleted unowned fixed-name config collision: %v", getErr)
	}
}

func TestReconcileDeletionToleratesMissingReferencedStorageCluster(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		gateway *garagev1beta2.GatewaySpec
	}{
		{name: "management handle"},
		{name: "edge gateway", gateway: &garagev1beta2.GatewaySpec{Replicas: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scheme := deletionTestScheme(t)
			now := metav1.Now()
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dependent", Namespace: testGarageValue, UID: types.UID(strings.ReplaceAll(tc.name, " ", "-")),
					Finalizers: []string{garageClusterFinalizer}, DeletionTimestamp: &now,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: tc.gateway,
					ConnectTo: &garagev1beta2.ConnectToConfig{
						ClusterRef: &garagev1beta2.ClusterReference{Name: "already-deleted-storage"},
					},
				},
			}
			reconciler, _ := deletionTestReconciler(scheme, cluster)
			if _, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)}); err != nil {
				t.Fatalf("deletion wedged behind missing clusterRef: %v", err)
			}
		})
	}
}

func TestCollectLiveEdgeGatewayNodeIDsUsesExactOwnedPod(t *testing.T) {
	t.Parallel()
	const nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != pathGetClusterStatus {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{ID: nodeID, IsUp: true}}})
	}))
	defer server.Close()
	adminPort := int32(server.Listener.Addr().(*net.TCPAddr).Port)

	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-edge", Namespace: testGarageValue, UID: testEdgeClusterUID},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			Admin: &garagev1beta2.AdminConfig{
				BindPort: adminPort,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "local-admin"},
				},
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "local-admin", Namespace: cluster.Namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: gatewayWorkloadName(cluster), Namespace: cluster.Namespace, UID: "edge-sts-uid",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
			Name: cluster.Name, UID: cluster.UID, Controller: ptrTo(true),
		}},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: cluster.Name + "-gateway-0", Namespace: cluster.Namespace,
			Labels: map[string]string{
				labelAppName: defaultAppName, labelAppInstance: cluster.Name, labelTier: tierGateway,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testLoopbackPodIP},
	}
	reconciler, _ := deletionTestReconciler(scheme, secret, statefulSet, pod)

	ids, err := reconciler.collectLiveEdgeGatewayNodeIDs(context.Background(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || !ids[nodeID] {
		t.Fatalf("discovered edge IDs = %v, want exact live pod identity %s", ids, nodeID)
	}
}

func TestGatewayLayoutRemovalAdvancesDrainingHistoryWithoutBypassingExclusions(t *testing.T) {
	t.Parallel()
	const nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	version := uint64(3)
	roles := []garage.LayoutNodeRole{{
		ID: nodeID, Zone: testZone, Tags: []string{"tier:" + tierGateway},
	}}
	var staged []garage.NodeRoleChange
	historyReadBeforeApply := false
	historyReadsAfterApply := 0
	removalSettled := false
	applyCalls := 0
	skipCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: version})
		case pathGetLayoutHistory:
			if applyCalls == 0 {
				historyReadBeforeApply = true
			} else {
				historyReadsAfterApply++
			}
			history := garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions:       []garage.LayoutVersion{{Version: version, Status: garage.LayoutVersionStatusCurrent}},
			}
			if !removalSettled {
				history.Versions = append([]garage.LayoutVersion{{
					Version: version - 1, Status: garage.LayoutVersionStatusDraining,
				}}, history.Versions...)
			}
			_ = json.NewEncoder(w).Encode(history)
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
				Version: version, Roles: roles, StagedRoleChanges: staged,
			})
		case pathUpdateLayout:
			var req garage.UpdateClusterLayoutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			staged = append([]garage.NodeRoleChange(nil), req.Roles...)
			w.WriteHeader(http.StatusOK)
		case pathApplyLayout:
			applyCalls++
			version++
			roles = nil
			staged = nil
			w.WriteHeader(http.StatusOK)
		case testSkipDeadNodesPath:
			skipCalls++
			http.Error(w, "gateway retirement must not call the global force-ACK API", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testExternalAdminSecretName, Namespace: testGarageValue},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testEdgeValue, Namespace: testGarageValue, UID: testEdgeClusterUID,
			Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
					Key:                  DefaultAdminTokenKey,
				},
			},
		},
	}
	reconciler, kubeClient := deletionTestReconciler(scheme, secret, cluster)
	if err := kubeClient.Delete(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatalf("reading deleting gateway test object: %v", err)
	}
	err := reconciler.removeNodesFromLayout(
		context.Background(), cluster, map[string]bool{nodeID: true},
	)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("capacity-less gateway workload was released before removal history settled: %v", err)
	}
	if historyReadBeforeApply {
		t.Fatal("gateway removal incorrectly waited on layout history before the mutation allowed to advance it")
	}
	if historyReadsAfterApply == 0 {
		t.Fatal("gateway removal did not keep the workload online for post-Apply history settlement")
	}
	if applyCalls != 1 || len(roles) != 0 {
		t.Fatalf("gateway removal apply calls=%d remaining roles=%v, want one apply and no role", applyCalls, roles)
	}
	if skipCalls != 0 {
		t.Fatalf("gateway retirement called global skip-dead-nodes %d times", skipCalls)
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil || proof.CompletedAt != nil || len(proof.RoleRemovalNodeIDs) != 1 ||
		proof.RoleRemovalNodeIDs[0] != nodeID || len(proof.RemovedStorageNodeIDs) != 0 {
		t.Fatalf("pre-Apply gateway retirement proof = %+v, want exact pending role-only target %s", proof, nodeID)
	}
	removalSettled = true
	if err := reconciler.removeNodesFromLayout(
		context.Background(), cluster, map[string]bool{},
	); err != nil {
		t.Fatalf("settled capacity-less gateway removal did not recover with an empty post-restart inventory: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("settled capacity-less gateway removal applied %d times, want 1", applyCalls)
	}
	if skipCalls != 0 {
		t.Fatalf("gateway retirement recovery called global skip-dead-nodes %d times", skipCalls)
	}
	proof = clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil || proof.CompletedAt == nil {
		t.Fatalf("settled gateway retirement did not persist a terminal crash-recovery handoff: %+v", proof)
	}

	roles = []garage.LayoutNodeRole{{ID: nodeID, Zone: testZone}}
	key := layoutOwnerKey(cluster)
	if !reconciler.LayoutMutations.BeginNodeLocalPoolRollout(
		key, layoutRolloutOwnerID(cluster), client.ObjectKeyFromObject(cluster), cluster.UID,
	) {
		t.Fatal("could not establish rollout exclusion for gateway-removal test")
	}
	err = reconciler.removeNodesFromLayout(
		context.Background(), cluster, map[string]bool{nodeID: true},
	)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("gateway removal crossed active rollout exclusion: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("gateway removal applied %d times across active rollout exclusion, want 1", applyCalls)
	}
}

func TestReconcileDeletingGatewayRefreshesDurableRetirementIntent(t *testing.T) {
	t.Parallel()
	const nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	version := uint64(3)
	historyCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: version})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: version})
		case pathGetLayoutHistory:
			historyCalls++
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions: []garage.LayoutVersion{
					{Version: version - 1, Status: garage.LayoutVersionStatusDraining},
					{Version: version, Status: garage.LayoutVersionStatusCurrent},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	now := metav1.Now()
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stale-cache-edge", Namespace: testGarageValue, UID: "stale-cache-edge-uid",
			Finalizers: []string{garageClusterFinalizer}, DeletionTimestamp: &now,
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: testExternalAdminSecretName},
					Key:                  DefaultAdminTokenKey,
				},
			},
		},
	}
	proof, err := storageDrainRemovalIntent(
		nil, storageDrainActorForCluster(cluster), []string{nodeID}, nil, time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testExternalAdminSecretName, Namespace: cluster.Namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, secret).Build()
	staleCache := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, object, opts...); err != nil {
				return err
			}
			if stale, ok := object.(*garagev1beta2.GarageCluster); ok && key == client.ObjectKeyFromObject(cluster) {
				stale.Status.StorageDrain = nil
			}
			return nil
		},
	})
	reconciler := &GarageClusterReconciler{
		Client: staleCache, APIReader: base, Scheme: scheme, ClusterScoped: true,
		LayoutMutations: NewLayoutMutationCoordinator(),
	}

	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)})
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("stale-cache deletion reconcile = %v, want pending layout-history settlement", err)
	}
	if historyCalls == 0 {
		t.Fatal("deletion reconcile forgot the durable gateway-retirement intent from the authoritative API read")
	}
	remaining := &garagev1beta2.GarageCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(cluster), remaining); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(remaining.Finalizers, garageClusterFinalizer) {
		t.Fatal("deletion reconcile released the finalizer while gateway role-removal history was draining")
	}
}

func TestNeverJoinedGatewayDeletionDoesNotTouchUnrelatedLayoutHistory(t *testing.T) {
	t.Parallel()
	historyCalls := 0
	skipCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 9})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 9})
		case pathGetLayoutHistory:
			historyCalls++
			http.Error(w, "never-joined gateway must not wait on unrelated history", http.StatusInternalServerError)
		case testSkipDeadNodesPath:
			skipCalls++
			http.Error(w, "never-joined gateway must not force ACK unrelated history", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "never-joined-admin", Namespace: testGarageValue},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "never-joined-edge", Namespace: testGarageValue, UID: "never-joined-edge-uid",
			Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name}, Key: DefaultAdminTokenKey,
				},
			},
		},
	}
	reconciler, kubeClient := deletionTestReconciler(scheme, secret, cluster)
	if err := kubeClient.Delete(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.removeNodesFromLayout(context.Background(), cluster, nil); err != nil {
		t.Fatalf("never-joined gateway deletion was blocked by unrelated history: %v", err)
	}
	if historyCalls != 0 || skipCalls != 0 || cluster.Status.StorageDrain != nil {
		t.Fatalf("never-joined gateway touched unrelated recovery state: history=%d skip=%d drain=%+v", historyCalls, skipCalls, cluster.Status.StorageDrain)
	}
}

func TestGatewayGarageNodeFinalizerPersistsRoleIntentAndWaitsForNormalHistory(t *testing.T) {
	t.Parallel()
	const nodeID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	version := uint64(7)
	roles := []garage.LayoutNodeRole{{ID: nodeID, Zone: testZone}}
	var staged []garage.NodeRoleChange
	settled := false
	loseFirstApplyResponse := true
	applyCalls := 0
	skipCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: version, Roles: roles, StagedRoleChanges: staged})
		case pathGetLayoutHistory:
			history := garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions:       []garage.LayoutVersion{{Version: version, Status: garage.LayoutVersionStatusCurrent}},
			}
			if !settled {
				history.Versions = append([]garage.LayoutVersion{{Version: version - 1, Status: garage.LayoutVersionStatusDraining}}, history.Versions...)
			}
			_ = json.NewEncoder(w).Encode(history)
		case pathUpdateLayout:
			var req garage.UpdateClusterLayoutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			staged = append([]garage.NodeRoleChange(nil), req.Roles...)
		case pathApplyLayout:
			applyCalls++
			version++
			roles = nil
			staged = nil
			if loseFirstApplyResponse {
				loseFirstApplyResponse = false
				http.Error(w, "response lost after commit", http.StatusInternalServerError)
			}
		case testSkipDeadNodesPath:
			skipCalls++
			http.Error(w, "automatic global skip is forbidden", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := deletionTestScheme(t)
	owner := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-node-owner", Namespace: testGarageValue, UID: "gateway-node-owner-uid"},
		Spec:       garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{}},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-gateway", Namespace: testGarageValue, UID: "manual-gateway-uid"},
		Spec: garagev1beta1.GarageNodeSpec{
			Gateway:    true,
			ClusterRef: garagev1beta1.ClusterReference{Name: owner.Name},
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	_, kubeClient := deletionTestReconciler(scheme, owner, node)
	reconciler := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient, LayoutMutations: NewLayoutMutationCoordinator()}
	garageClient := garage.NewClient(server.URL, "token")

	err := reconciler.finalize(context.Background(), node, owner, garageClient)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("gateway finalizer released after an ambiguous committed Apply: %v", err)
	}
	proof := clusterStorageDrainProof(owner.Status.StorageDrain)
	if proof == nil || proof.CompletedAt != nil || !sameStorageDrainActor(proof.Actor, storageDrainActorForNode(node)) ||
		len(proof.RoleRemovalNodeIDs) != 1 || proof.RoleRemovalNodeIDs[0] != nodeID || len(proof.RemovedStorageNodeIDs) != 0 {
		t.Fatalf("ambiguous-Apply gateway GarageNode proof = %+v, want exact pending role-only intent", proof)
	}
	if applyCalls != 1 || skipCalls != 0 {
		t.Fatalf("gateway GarageNode apply=%d skip=%d, want apply=1 skip=0", applyCalls, skipCalls)
	}

	settled = true
	if err := reconciler.finalize(context.Background(), node, owner, garageClient); err != nil {
		t.Fatalf("settled gateway GarageNode finalization: %v", err)
	}
	proof = clusterStorageDrainProof(owner.Status.StorageDrain)
	if proof == nil || proof.CompletedAt == nil {
		t.Fatalf("settled gateway GarageNode did not persist terminal handoff: %+v", proof)
	}
	authorized, err := completedGarageNodeDrainAuthorizesFinalization(node, owner)
	if err != nil || !authorized {
		t.Fatalf("terminal gateway GarageNode handoff was not finalizer-authoritative: authorized=%v err=%v", authorized, err)
	}
	if applyCalls != 1 || skipCalls != 0 {
		t.Fatalf("gateway GarageNode recovery reapplied or skipped globally: apply=%d skip=%d", applyCalls, skipCalls)
	}
}

func TestCapacitylessRoleRetirementIgnoresOnlyReferringGatewayGenerationBoundary(t *testing.T) {
	t.Parallel()
	scheme := deletionTestScheme(t)
	now := metav1.Now()
	owner := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage", Namespace: testGarageValue, UID: testStorageClusterUID, Generation: 1,
		},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{}},
	}
	edge := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testEdgeValue, Namespace: testGarageValue, UID: testEdgeClusterUID, Generation: 2,
			DeletionTimestamp: &now, Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{ClusterRef: &garagev1beta2.ClusterReference{
				Name: owner.Name,
			}},
		},
		Status: garagev1beta2.GarageClusterStatus{Conditions: []metav1.Condition{{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonStorageRolloutConverged,
			ObservedGeneration: 1,
		}}},
	}
	reconciler, reader := deletionTestReconciler(scheme, owner, edge)
	mutations := 0
	var mutationErr error
	mutate := func() error {
		mutations++
		return mutationErr
	}

	if err := runResolvedCapacitylessRoleRetirementMutation(
		context.Background(), reader, reconciler.LayoutMutations, edge, mutate,
	); err != nil {
		t.Fatalf("stale referring gateway generation blocked capacity-less retirement: %v", err)
	}
	if mutations != 1 {
		t.Fatalf("capacity-less retirement mutations = %d, want 1", mutations)
	}

	for _, tc := range []struct {
		name      string
		connectTo *garagev1beta2.ConnectToConfig
	}{
		{
			name: "direct endpoint",
			connectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: "http://garage.example:3903",
			},
		},
		{
			name: "self admin via bootstrap peers",
			connectTo: &garagev1beta2.ConnectToConfig{
				BootstrapPeers: []string{testBootstrapPeer},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			direct := edge.DeepCopy()
			direct.Name = strings.ReplaceAll(tc.name, " ", "-")
			direct.UID = types.UID(direct.Name + "-uid")
			direct.Spec.ConnectTo = tc.connectTo
			before := mutations
			if err := runResolvedCapacitylessRoleRetirementMutation(
				context.Background(), reader, reconciler.LayoutMutations, direct, mutate,
			); err != nil {
				t.Fatalf("stale generation blocked %s capacity-less retirement: %v", tc.name, err)
			}
			if mutations != before+1 {
				t.Fatalf("%s retirement mutations = %d, want %d", tc.name, mutations, before+1)
			}
		})
	}

	direct := edge.DeepCopy()
	direct.Name = "direct-excluded"
	direct.UID = "direct-excluded-uid"
	direct.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://excluded.example:3903"}
	directKey := layoutOwnerKey(direct)
	if !reconciler.LayoutMutations.BeginNodeLocalPoolRollout(
		directKey, layoutRolloutOwnerID(direct), client.ObjectKeyFromObject(direct), direct.UID,
	) {
		t.Fatal("could not establish direct-endpoint rollout exclusion")
	}
	beforeDirectExclusion := mutations
	if err := runResolvedCapacitylessRoleRetirementMutation(
		context.Background(), reader, reconciler.LayoutMutations, direct, mutate,
	); !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("direct-endpoint retirement crossed its canonical rollout marker: %v", err)
	}
	if mutations != beforeDirectExclusion {
		t.Fatalf("excluded direct-endpoint retirement ran mutate %d times, want %d", mutations, beforeDirectExclusion)
	}

	key := layoutOwnerKey(owner)
	if !reconciler.LayoutMutations.BeginNodeLocalPoolRollout(
		key, layoutRolloutOwnerID(owner), client.ObjectKeyFromObject(owner), owner.UID,
	) {
		t.Fatal("could not establish canonical owner rollout exclusion")
	}
	beforeCanonicalExclusion := mutations
	err := runResolvedCapacitylessRoleRetirementMutation(
		context.Background(), reader, reconciler.LayoutMutations, edge, mutate,
	)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("capacity-less retirement crossed canonical owner rollout exclusion: %v", err)
	}
	if mutations != beforeCanonicalExclusion {
		t.Fatalf("excluded capacity-less retirement ran mutate %d times, want %d", mutations, beforeCanonicalExclusion)
	}
}
