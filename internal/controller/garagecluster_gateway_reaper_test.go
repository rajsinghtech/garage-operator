package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Federated regions may share name, namespace, and zone. The globally unique
// cluster UID is the ownership boundary; zone remains an additional guard.
func TestStaleGatewayRoles_UIDAndZoneScoped(t *testing.T) {
	ownTag := testOwnedClusterTag
	ownUID := testOwnedClusterUIDTag
	tierTag := testTierGatewayTag
	roles := []garage.LayoutNodeRole{
		// local zone, not live/claimed -> stale, must be returned
		{ID: testLocalDeadNodeID, Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
		// remote region zone, same ownership+tier tags, not live/claimed ->
		// must be SKIPPED (belongs to another federated region)
		{ID: "remote-dead", Zone: "eu-west-1", Tags: []string{ownTag, ownUID, tierTag}},
		// Even in the same zone with the same name/namespace, another site UID
		// can never be removed.
		{ID: "other-site", Zone: testZone, Tags: []string{ownTag, "cluster-uid:other", tierTag}},
		// Legacy ownership is ambiguous and therefore not auto-reaped.
		{ID: "legacy", Zone: testZone, Tags: []string{ownTag, tierTag}},
	}
	live := map[string]bool{}
	claimed := map[string]bool{}
	sustained := map[string]bool{testLocalDeadNodeID: true, "remote-dead": true, "other-site": true, "legacy": true}

	got := staleGatewayRoles(roles, testZone, "local-uid", live, claimed, sustained, nil)
	want := []string{testLocalDeadNodeID}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles zone scoping: got %v, want %v", got, want)
	}
}

// Within the local zone, live and operator-claimed roles are preserved; only a
// genuinely orphaned role is reaped. A storage-tier role in the same zone (no
// tier:gateway tag) is never touched.
func TestStaleGatewayRoles_LivePreservedTierFiltered(t *testing.T) {
	ownTag := testOwnedClusterTag
	ownUID := testOwnedClusterUIDTag
	tierTag := testTierGatewayTag
	roles := []garage.LayoutNodeRole{
		{ID: "gw-live", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
		{ID: "gw-claimed", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
		{ID: "gw-blip", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
		{ID: testOrphanGatewayID, Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
		{ID: "storage-role", Zone: testZone, Tags: []string{ownTag, ownUID, testTierStorageTag}},
	}
	live := map[string]bool{"gw-live": true}
	claimed := map[string]bool{"gw-claimed": true}
	sustained := map[string]bool{testOrphanGatewayID: true}

	got := staleGatewayRoles(roles, testZone, "local-uid", live, claimed, sustained, nil)
	want := []string{testOrphanGatewayID}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles: got %v, want %v", got, want)
	}
}

func TestStaleGatewayRoles_EdgeScaleDownBypassesDwellOnlyForRetiredOrdinal(t *testing.T) {
	ownTag := testOwnedClusterTag
	ownUID := testOwnedClusterUIDTag
	tierTag := testTierGatewayTag
	roles := []garage.LayoutNodeRole{
		{ID: "desired-restarting", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag, "gc-gateway-0"}},
		{ID: "retired", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag, "gc-gateway-2"}},
		{ID: "unparseable", Zone: testZone, Tags: []string{ownTag, ownUID, tierTag}},
	}
	desired := int32(1)
	got := staleGatewayRoles(roles, testZone, "local-uid", nil, nil, nil, &desired)
	want := []string{"retired"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles edge scale-down: got %v, want %v", got, want)
	}
}

func TestReconcileGatewayTombstones_ForwardOnlyEdgeStillRetiresScaledDownOrdinal(t *testing.T) {
	t.Parallel()

	const (
		namespace  = testGarageValue
		clusterUID = "local-uid"
		desiredID  = "desired-gateway-id"
		retiredID  = "retired-gateway-id"
	)
	downFor := uint64(peerUnreachableThreshold.Seconds()) + 3600
	var updateCalls, applyCalls, skipCalls int32
	roles := []garage.LayoutNodeRole{
		{ID: desiredID, Zone: testZone, Tags: []string{testEdgeOwnershipTag, "cluster-uid:" + clusterUID, testTierGatewayTag, "edge-gateway-0"}},
		{ID: retiredID, Zone: testZone, Tags: []string{testEdgeOwnershipTag, "cluster-uid:" + clusterUID, testTierGatewayTag, "edge-gateway-1"}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{
				{ID: desiredID, IsUp: false, LastSeenSecsAgo: &downFor},
				{ID: retiredID, IsUp: false, LastSeenSecsAgo: &downFor},
			}})
		case pathGetLayoutHistory:
			_ = json.NewEncoder(w).Encode(settledLayoutHistoryResponse())
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 4, Roles: roles})
		case pathUpdateLayout:
			atomic.AddInt32(&updateCalls, 1)
		case pathApplyLayout:
			atomic.AddInt32(&applyCalls, 1)
		case testSkipDeadNodesPath:
			atomic.AddInt32(&skipCalls, 1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testExternalAdminSecretName, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testEdgeValue, Namespace: namespace, UID: types.UID(clusterUID), Generation: 7,
			Annotations: map[string]string{garagev1beta1.AnnotationForceLayoutApply: annotationTrue},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Zone:    testZone,
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
				},
			},
		},
	}
	if !edgeGatewayReverseUnroutable(cluster) {
		t.Fatal("test fixture must exercise the forward-only edge topology")
	}
	reconciler := &GarageClusterReconciler{
		Client:          fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build(),
		Scheme:          scheme,
		LayoutMutations: NewLayoutMutationCoordinator(),
	}

	reconciler.reconcileGatewayTombstones(context.Background(), cluster)

	if got, want := cluster.Status.PendingGatewayTombstones, []string{retiredID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("forward-only 2->1 pending tombstones = %v, want %v", got, want)
	}
	if cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones); cond == nil || cond.ObservedGeneration != 7 {
		t.Fatalf("GatewayTombstones condition = %+v, want ObservedGeneration 7", cond)
	}
	if atomic.LoadInt32(&updateCalls) != 0 || atomic.LoadInt32(&applyCalls) != 0 || atomic.LoadInt32(&skipCalls) != 0 {
		t.Fatalf("autoApply=false plus force-layout-apply mutated tombstones: update=%d apply=%d skip=%d",
			updateCalls, applyCalls, skipCalls)
	}
}

func TestReconcileGatewayTombstones_AutoApplyPersistsAndWaitsWithoutGlobalSkip(t *testing.T) {
	t.Parallel()
	const (
		namespace  = testGarageValue
		clusterUID = "auto-reaper-uid"
		retiredID  = "retired-auto-gateway-id"
	)
	version := uint64(4)
	roles := []garage.LayoutNodeRole{{
		ID: retiredID, Zone: testZone,
		Tags: []string{testEdgeOwnershipTag, "cluster-uid:" + clusterUID, testTierGatewayTag, "edge-gateway-1"},
	}}
	var staged []garage.NodeRoleChange
	var skipCalls int32
	applyCalls := 0
	historySettled := true
	downFor := uint64(peerUnreachableThreshold.Seconds()) + 3600
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: version, Nodes: []garage.NodeInfo{{
				ID: retiredID, IsUp: false, LastSeenSecsAgo: &downFor,
			}}})
		case pathGetLayoutHistory:
			history := garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions:       []garage.LayoutVersion{{Version: version, Status: garage.LayoutVersionStatusCurrent}},
			}
			if !historySettled {
				history.Versions = append([]garage.LayoutVersion{{Version: version - 1, Status: garage.LayoutVersionStatusDraining}}, history.Versions...)
			}
			_ = json.NewEncoder(w).Encode(history)
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: version, Roles: roles, StagedRoleChanges: staged})
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
			historySettled = false
		case testSkipDeadNodesPath:
			atomic.AddInt32(&skipCalls, 1)
			http.Error(w, "automatic global skip is forbidden", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testExternalAdminSecretName, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testEdgeValue, Namespace: namespace, UID: types.UID(clusterUID)},
		Spec: garagev1beta2.GarageClusterSpec{
			Zone: testZone, Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{AutoApply: true},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
				},
			},
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(secret, cluster).Build()
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, LayoutMutations: NewLayoutMutationCoordinator()}
	reconciler.reconcileGatewayTombstones(context.Background(), cluster)
	if applyCalls != 1 || atomic.LoadInt32(&skipCalls) != 0 {
		t.Fatalf("tombstone apply=%d skip=%d, want apply=1 skip=0", applyCalls, skipCalls)
	}
	if got := cluster.Status.PendingGatewayTombstones; !reflect.DeepEqual(got, []string{retiredID}) {
		t.Fatalf("post-Apply pending tombstones = %v, want exact target", got)
	}

	reconciler.reconcileGatewayTombstones(context.Background(), cluster)
	if len(cluster.Status.PendingGatewayTombstones) != 1 || applyCalls != 1 {
		t.Fatalf("draining history lost or reapplied durable tombstone state: pending=%v apply=%d", cluster.Status.PendingGatewayTombstones, applyCalls)
	}
	historySettled = true
	reconciler.reconcileGatewayTombstones(context.Background(), cluster)
	if len(cluster.Status.PendingGatewayTombstones) != 0 || applyCalls != 1 || atomic.LoadInt32(&skipCalls) != 0 {
		t.Fatalf("settled tombstone completion = pending=%v apply=%d skip=%d", cluster.Status.PendingGatewayTombstones, applyCalls, skipCalls)
	}
}
