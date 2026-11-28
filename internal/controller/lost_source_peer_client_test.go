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
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Issue #659: a GarageNode whose disk died is annotated drain=true plus
// acknowledge-lost-source=<old ID>. The first preflight fences the slot by
// scaling its StatefulSet to zero. Every later reconcile then needs a Garage
// client, and the operator Admin Pod-set proof used to demand that the lost
// slot's StatefulSet desire exactly one Pod, which the fence itself prevents:
// DrainPrepared stayed PreparationBlocked forever and the immutable ack made the
// node undeletable. The preflight must go through a healthy proven peer.

const (
	lostSourceTestLostID = "b0a68f0aac754cb1586d7bd9dca2fa4fa6ecf4681835313fe86577acb1b6a6ed"
	lostSourceTestPeerID = "ff5410c45eef807c0123456789abcdef0123456789abcdef0123456789abcdef"
	lostSourceTestOther  = "5a82e61f6a3917df0123456789abcdef0123456789abcdef0123456789abcdef"
	lostSourceTestThird  = "e5c748ec6bad8b4a0123456789abcdef0123456789abcdef0123456789abcdef"
)

type lostSourceLayoutState int

const (
	lostRoleCommitted lostSourceLayoutState = iota
	lostRoleStagedRemoved
	lostRoleRemovedByHand
	// lostRoleRemovedStillDraining is lostRoleRemovedByHand while Garage still
	// keeps the previous layout version active because the dead node never acked.
	lostRoleRemovedStillDraining
)

// lostSourceGarage is the Admin API of the surviving peers: the lost ID is
// down, the dynamic operator token is accepted, and any layout write is
// recorded so tests can prove the operator never mutated a hand-edited layout.
type lostSourceGarage struct {
	mu     sync.Mutex
	state  lostSourceLayoutState
	writes []string
	port   int32
}

func newLostSourceGarage(t interface {
	Helper()
	Cleanup(func())
}, cluster *garagev1beta2.GarageCluster, state lostSourceLayoutState) *lostSourceGarage {
	t.Helper()
	g := &lostSourceGarage{state: state}
	id := servingTestDynamicID
	capacity := uint64(200 << 30)
	role := func(nodeID, pod string) garage.LayoutNodeRole {
		return garage.LayoutNodeRole{ID: nodeID, Zone: "main", Capacity: &capacity, Tags: []string{"tier:storage", pod}}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		auth := request.Header.Get("Authorization")
		if auth != "Bearer "+servingTestDynamicToken && auth != "Bearer "+servingTestStaticToken {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		roles := []garage.LayoutNodeRole{
			role(lostSourceTestPeerID, "storage-0-0"), role(lostSourceTestOther, "storage-3-0"), role(lostSourceTestThird, "storage-2-0"),
		}
		version := uint64(3)
		var staged []garage.NodeRoleChange
		draining := g.state == lostRoleRemovedStillDraining
		switch g.state {
		case lostRoleCommitted:
			version = 2
			roles = append(roles, role(lostSourceTestLostID, "storage-1-0"))
		case lostRoleStagedRemoved:
			version = 2
			roles = append(roles, role(lostSourceTestLostID, "storage-1-0"))
			staged = []garage.NodeRoleChange{{ID: lostSourceTestLostID, Remove: true}}
		}
		switch request.URL.Path {
		case "/v2/GetAdminTokenInfo":
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{ID: &id, Name: operatorAdminTokenName(cluster), Scope: []string{"*"}})
		case pathGetClusterStatus:
			nodes := []garage.NodeInfo{
				{ID: lostSourceTestLostID, IsUp: false},
				{ID: lostSourceTestPeerID, IsUp: true, Address: ptr.To("127.0.0.1:3901")},
				{ID: lostSourceTestOther, IsUp: true},
				{ID: lostSourceTestThird, IsUp: true},
			}
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: version, Nodes: nodes})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: version, Roles: roles, StagedRoleChanges: staged})
		case pathGetLayoutHistory:
			history := garage.LayoutHistoryResponse{
				CurrentVersion: version,
				Versions:       []garage.LayoutVersion{{Version: version, Status: garage.LayoutVersionStatusCurrent}},
			}
			if draining {
				history.MinAck = 2
				history.Versions = append(history.Versions, garage.LayoutVersion{Version: 2, Status: garage.LayoutVersionStatusDraining})
				history.UpdateTrackers = map[string]garage.NodeUpdateTrackers{
					lostSourceTestLostID: {Ack: 2, Sync: 2, SyncAck: 2},
					lostSourceTestPeerID: {Ack: 3, Sync: 2, SyncAck: 2},
				}
			}
			_ = json.NewEncoder(w).Encode(history)
		case pathUpdateLayout, pathApplyLayout:
			g.writes = append(g.writes, request.URL.Path)
			http.Error(w, "layout writes are not expected in this test", http.StatusConflict)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	g.port = int32(server.Listener.Addr().(*net.TCPAddr).Port)
	cluster.Spec.Admin.BindPort = g.port
	return g
}

func (g *lostSourceGarage) layoutWrites() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.writes...)
}

// lostSourceFixture models the reporter's cluster: storage-0 is a healthy
// in-layout peer with a Ready Pod; storage-1 lost its disk, carries the
// atomic drain+ack annotations, still reports InLayout from before the loss,
// has no DrainPrepared=True yet, and has already been fenced (STS replicas 0,
// no Pod). The dynamic token's recorded proof predates the fence.
func lostSourceFixture(ack string) (*garagev1beta2.GarageCluster, *garagev1beta1.GarageNode, []client.Object) {
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nvme", Namespace: testOperatorPodSetNamespace, UID: types.UID("cluster-uid"), Generation: 1,
			Annotations: map[string]string{annotationOperatorAdminTokenID: servingTestDynamicID},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage:     &garagev1beta2.StorageSpec{},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: consistencyModeConsistent},
			Admin: &garagev1beta2.AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
				Key:                  DefaultAdminTokenKey,
			}},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{Drain: &garagev1beta2.StorageDrainConfig{
				UnverifiedPeersPolicy: garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent,
			}},
		},
		Status: garagev1beta2.GarageClusterStatus{Phase: PhaseRunning},
	}
	markGarageClusterDrainReady(cluster)
	clusterOwner := []metav1.OwnerReference{{
		APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
		Name: cluster.Name, UID: cluster.UID, Controller: &controller,
	}}
	capacity := resource.MustParse("200Gi")
	objects := []client.Object{cluster,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: testStaticRevisionSecret, Namespace: cluster.Namespace},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte(servingTestStaticToken)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace,
				Labels: map[string]string{labelOperatorAdminToken: operatorAdminTokenReadyValue},
				Annotations: map[string]string{
					annotationOperatorAdminTokenName:   operatorAdminTokenName(cluster),
					annotationOperatorAdminTokenReady:  operatorAdminTokenReadyValue,
					annotationOperatorAdminTokenPodSet: "proof-from-before-the-lost-slot-was-fenced",
				},
				OwnerReferences: clusterOwner,
			},
			Immutable: ptr.To(true),
			Data: map[string][]byte{
				operatorAdminTokenIDKey: []byte(servingTestDynamicID),
				DefaultAdminTokenKey:    []byte(servingTestDynamicToken),
			},
		},
	}
	var lost *garagev1beta1.GarageNode
	for _, slot := range []struct {
		name, id string
		lost     bool
	}{{"nvme-storage-0", lostSourceTestPeerID, false}, {"nvme-storage-1", lostSourceTestLostID, true}} {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: slot.name, Namespace: cluster.Namespace, UID: types.UID("uid-" + slot.name),
				Generation: 1, OwnerReferences: clusterOwner, Annotations: map[string]string{},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Zone: "main", Capacity: &capacity,
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: slot.id, InLayout: true, Connected: !slot.lost, ObservedGeneration: 1},
		}
		replicas := int32(1)
		if slot.lost {
			node.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
			node.Annotations[garagev1beta1.AnnotationAcknowledgeLostSource] = ack
			node.Status.Conditions = []metav1.Condition{{
				Type: garagev1beta1.ConditionDrainPrepared, Status: metav1.ConditionFalse,
				Reason: garagev1beta1.ReasonNodeDrainBlocked, Message: "fenced", ObservedGeneration: 1,
				LastTransitionTime: metav1.Now(),
			}}
			replicas = 0
			lost = node
		}
		sts := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: slot.name, Namespace: cluster.Namespace, UID: types.UID("sts-" + slot.name),
				Labels: map[string]string{labelCluster: cluster.Name},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
					Name: node.Name, UID: node.UID, Controller: &controller,
				}},
			},
			Spec: appsv1.StatefulSetSpec{Replicas: &replicas},
		}
		objects = append(objects, node, sts)
		if slot.lost {
			continue
		}
		objects = append(objects, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: slot.name + "-0", Namespace: cluster.Namespace, UID: types.UID("pod-" + slot.name),
				Labels: map[string]string{labelCluster: cluster.Name},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
					Name: sts.Name, UID: sts.UID, Controller: &controller,
				}},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: defaultAppName, Image: "dxflrs/garage:v2.5.0",
				Env: []corev1.EnvVar{{
					Name: envGarageAdminToken,
					ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
						Key:                  DefaultAdminTokenKey,
					}},
				}},
			}}},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning, PodIP: "127.0.0.1",
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		})
	}
	return cluster, lost, objects
}

func lostSourceTestReconciler(t *testing.T, objects []client.Object) (*GarageNodeReconciler, client.Client) {
	t.Helper()
	kube := fake.NewClientBuilder().WithScheme(deletionTestScheme(t)).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).Build()
	return &GarageNodeReconciler{
		Client: kube, APIReader: kube, LayoutMutations: NewLayoutMutationCoordinator(),
		clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
			return &garage.ClusterHealth{
				Status: healthStatusHealthy, StorageNodes: 3, StorageNodesUp: 3,
				Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
			}, nil
		},
		blockResyncObservationGetter: func(context.Context, *garage.Client) (*blockResyncObservation, error) {
			return nil, fmt.Errorf("%w: block-resync proof intentionally pending", errLayoutMutationPending)
		},
	}, kube
}

func TestGarageNodeExemptFromAdminProofForAcknowledgedLostSource(t *testing.T) {
	t.Parallel()
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Annotations: map[string]string{
			garagev1beta1.AnnotationDrain:                 annotationTrue,
			garagev1beta1.AnnotationAcknowledgeLostSource: lostSourceTestLostID,
		}},
		Status: garagev1beta1.GarageNodeStatus{NodeID: lostSourceTestLostID, InLayout: true},
	}
	if !garageNodeExemptFromAdminAndRolloutProof(node) {
		t.Fatal("acknowledged lost source still in the layout must be exempt (#659)")
	}
	wrongID := node.DeepCopy()
	wrongID.Annotations[garagev1beta1.AnnotationAcknowledgeLostSource] = lostSourceTestPeerID
	if garageNodeExemptFromAdminAndRolloutProof(wrongID) {
		t.Fatal("an ack for a different Garage ID must not exempt an in-layout node")
	}
	noDrain := node.DeepCopy()
	delete(noDrain.Annotations, garagev1beta1.AnnotationDrain)
	if garageNodeExemptFromAdminAndRolloutProof(noDrain) {
		t.Fatal("an ack without drain=true must not exempt an in-layout node")
	}
	external := node.DeepCopy()
	external.Spec.External = &garagev1beta1.ExternalNodeConfig{}
	if garageNodeExemptFromAdminAndRolloutProof(external) {
		t.Fatal("external nodes are never part of the managed Pod-set proof")
	}
}

func TestOperatorAdminPodSetExcludesFencedAcknowledgedLostSource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _, objects := lostSourceFixture(lostSourceTestLostID)
	kube := fake.NewClientBuilder().WithScheme(deletionTestScheme(t)).WithObjects(objects...).Build()
	for name, scope := range map[string]func(context.Context, client.Reader, *garagev1beta2.GarageCluster) (*operatorAdminPodSet, error){
		"complete": expectedOperatorAdminPodSet, "serving": servingOperatorAdminPodSet,
	} {
		set, err := scope(ctx, kube, cluster)
		if err != nil {
			t.Fatalf("%s Pod set rejected a fenced acknowledged lost source: %v", name, err)
		}
		if got := podSetUIDs(set); len(got) != 1 || got[0] != "pod-nvme-storage-0" {
			t.Fatalf("%s Pod set = %v, want only the healthy peer", name, got)
		}
	}

	// A mismatched ack keeps the strict contract: the node is not exempt and its
	// zero-replica StatefulSet still blocks the complete proof.
	cluster, _, objects = lostSourceFixture(lostSourceTestPeerID)
	kube = fake.NewClientBuilder().WithScheme(deletionTestScheme(t)).WithObjects(objects...).Build()
	if _, err := expectedOperatorAdminPodSet(ctx, kube, cluster); err == nil ||
		!strings.Contains(err.Error(), "must desire exactly one Pod") {
		t.Fatalf("mismatched lost-source ack weakened the complete proof: %v", err)
	}
	// The serving proof only covers routable processes: a StatefulSet scaled
	// to zero with no Pod cannot answer, so it no longer withholds the client.
	if _, err := servingOperatorAdminPodSet(ctx, kube, cluster); err != nil {
		t.Fatalf("serving proof rejected a zero-replica StatefulSet with no Pod: %v", err)
	}
}

func TestGetGarageClientReachesPeerAfterLostSourceFence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _, objects := lostSourceFixture(lostSourceTestLostID)
	newLostSourceGarage(t, cluster, lostRoleRemovedByHand)
	kube := fake.NewClientBuilder().WithScheme(deletionTestScheme(t)).WithObjects(objects...).Build()
	garageClient, err := GetGarageClient(ctx, kube, cluster, "cluster.local")
	if err != nil {
		t.Fatalf("cluster Admin client still deadlocked on the fenced lost slot: %v", err)
	}
	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil || status.LayoutVersion != 3 {
		t.Fatalf("client did not reach the healthy peer: status=%+v err=%v", status, err)
	}
}

func TestPrepareDrainForLostSourceUsesPeerAndHandlesHandEditedLayout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		state lostSourceLayoutState
		want  string
	}{
		{name: "role removed and applied by hand", state: lostRoleRemovedByHand, want: "block-resync proof intentionally pending"},
		{name: "removal staged by hand", state: lostRoleStagedRemoved, want: "staged but not applied"},
		{name: "role still committed", state: lostRoleCommitted, want: "still present in the Garage layout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			cluster, lost, objects := lostSourceFixture(lostSourceTestLostID)
			g := newLostSourceGarage(t, cluster, tc.state)
			r, kube := lostSourceTestReconciler(t, objects)
			if err := kube.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
				t.Fatal(err)
			}
			cluster.Spec.Admin.BindPort = g.port
			_, _, err := r.prepareGarageNodeDrain(ctx, lost, cluster, cluster)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("prepare error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "must desire exactly one Pod") {
				t.Fatalf("preflight still required the fenced lost slot's own Pod: %v", err)
			}
			if writes := g.layoutWrites(); len(writes) != 0 {
				t.Fatalf("operator wrote a hand-edited layout: %v", writes)
			}
			sts := &appsv1.StatefulSet{}
			if err := kube.Get(ctx, types.NamespacedName{Namespace: lost.Namespace, Name: lost.Name}, sts); err != nil {
				t.Fatal(err)
			}
			if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 0 {
				t.Fatalf("lost slot fence was undone: replicas=%v", sts.Spec.Replicas)
			}
			stored := &garagev1beta2.GarageCluster{}
			if err := kube.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
				t.Fatal(err)
			}
			proof := clusterStorageDrainProof(stored.Status.StorageDrain)
			if tc.state != lostRoleRemovedByHand {
				if proof != nil {
					t.Fatalf("a still-assigned lost role must not open a destination-only proof: %+v", proof)
				}
				return
			}
			if proof == nil || !storageDrainUnavailableSourceIncludes(proof, lostSourceTestLostID) ||
				len(proof.RemovedStorageNodeIDs) != 1 || proof.RemovedStorageNodeIDs[0] != lostSourceTestLostID {
				t.Fatalf("hand-removed lost role did not record the exact destination-only proof: %+v", stored.Status.StorageDrain)
			}
		})
	}
}

// Upstream Garage keeps a removed node's previous layout version Draining until
// that node acks, and a dead node never does; only skip-dead-nodes raises its
// tracker. While the version drains the operator must keep waiting (it must not
// record a proof or fence anything new), and tell the administrator why and how.
func TestLostSourceDrainWaitNamesSkipDeadNodesWhileHistoryDrains(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, lost, objects := lostSourceFixture(lostSourceTestLostID)
	g := newLostSourceGarage(t, cluster, lostRoleRemovedStillDraining)
	r, kube := lostSourceTestReconciler(t, objects)
	if err := kube.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	cluster.Spec.Admin.BindPort = g.port
	_, _, err := r.prepareGarageNodeDrain(ctx, lost, cluster, cluster)
	if !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("draining history was not reported as a pending layout mutation: %v", err)
	}
	for _, want := range []string{
		"still draining", shortID(lostSourceTestLostID) + "(sync=2)",
		garagev1beta1.AnnotationSkipDeadNodes, "garage layout history",
		"do not add " + garagev1beta1.AnnotationAllowMissingData,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("draining message %q does not mention %q", err, want)
		}
	}
	if writes := g.layoutWrites(); len(writes) != 0 {
		t.Fatalf("operator wrote the layout while waiting for history to drain: %v", writes)
	}
}
