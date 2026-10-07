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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// fakeGarageLayout is a tiny stateful in-memory Garage admin API serving the
// layout endpoints reconcileNode + removeStaleNodeRole exercise: it tracks the
// committed roles, staged changes and applies them on ApplyClusterLayout. This
// lets the test assert what the operator does to the layout (adds, removes)
// rather than just counting calls.
type fakeGarageLayout struct {
	mu        sync.Mutex
	version   uint64
	roles     map[string]garage.LayoutNodeRole
	staged    []garage.NodeRoleChange
	applies   [][]garage.NodeRoleChange
	skipCalls int32
	// statusNodes, when set, is served on /v2/GetClusterStatus — used by the
	// DaemonSet-backed discovery tests that resolve a node_id by pod IP.
	statusNodes []garage.NodeInfo
	applyStatus int
	applyError  string
	// applyResponseLostOnce commits one Apply but returns an error, modelling a
	// controller/network failure after Garage made the version durable.
	applyResponseLostOnce bool
	selfStatus            int
	selfNodeID            string
	// holdRemovedInHistory keeps removed roles in the active layout-history
	// tracker until completeDrain is called, modelling Garage's real
	// post-apply block synchronization.
	holdRemovedInHistory bool
	drainingNodeIDs      map[string]bool
	// stagingLostBeforeApply empties the staging area at the start of the
	// next N Applies, modelling real Garage when gossip from an independently
	// bootstrapped peer (newer staging timestamp) replaces it between the
	// client's re-read and Apply. Like Garage, the Apply still commits a new
	// version.
	stagingLostBeforeApply int
	// stagedAfterLostApply is what a lost Apply leaves in the staging area: a
	// peer site's changes that arrived with its newer staging timestamp.
	stagedAfterLostApply []garage.NodeRoleChange
}

func newFakeGarageLayout(initial ...garage.LayoutNodeRole) *fakeGarageLayout {
	f := &fakeGarageLayout{
		version:         1,
		roles:           map[string]garage.LayoutNodeRole{},
		drainingNodeIDs: map[string]bool{},
	}
	for _, r := range initial {
		f.roles[r.ID] = r
	}
	return f
}

func (f *fakeGarageLayout) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/GetClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		roles := make([]garage.LayoutNodeRole, 0, len(f.roles))
		for _, r := range f.roles {
			roles = append(roles, r)
		}
		_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
			Version:           f.version,
			Roles:             roles,
			StagedRoleChanges: f.staged,
		})
	})
	mux.HandleFunc("/v2/UpdateClusterLayout", func(w http.ResponseWriter, r *http.Request) {
		var req garage.UpdateClusterLayoutRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		// Garage's staging area is a last-writer-wins map keyed by node ID, so
		// re-staging a node replaces its pending change instead of duplicating it.
		for _, change := range req.Roles {
			replaced := false
			for i := range f.staged {
				if f.staged[i].ID == change.ID {
					f.staged[i], replaced = change, true
					break
				}
			}
			if !replaced {
				f.staged = append(f.staged, change)
			}
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/ApplyClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		if f.applyStatus != 0 {
			status := f.applyStatus
			message := f.applyError
			f.mu.Unlock()
			http.Error(w, message, status)
			return
		}
		lost := f.stagingLostBeforeApply > 0
		if lost {
			f.stagingLostBeforeApply--
			f.staged = nil
		}
		f.applies = append(f.applies, append([]garage.NodeRoleChange(nil), f.staged...))
		for _, c := range f.staged {
			if c.Remove {
				delete(f.roles, c.ID)
				if f.holdRemovedInHistory {
					f.drainingNodeIDs[c.ID] = true
				}
				continue
			}
			f.roles[c.ID] = garage.LayoutNodeRole{ID: c.ID, Zone: c.Zone, Tags: c.Tags, Capacity: c.Capacity}
		}
		f.staged = nil
		if lost && len(f.stagedAfterLostApply) > 0 {
			f.staged = append([]garage.NodeRoleChange(nil), f.stagedAfterLostApply...)
		}
		f.version++
		responseLost := f.applyResponseLostOnce
		f.applyResponseLostOnce = false
		f.mu.Unlock()
		if responseLost {
			http.Error(w, "committed but response was lost", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/RevertClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.staged = nil
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/GetClusterLayoutHistory", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		history := garage.LayoutHistoryResponse{
			CurrentVersion: f.version,
			Versions: []garage.LayoutVersion{{
				Version: f.version,
				Status:  garage.LayoutVersionStatusCurrent,
			}},
		}
		if len(f.drainingNodeIDs) > 0 {
			history.Versions = append([]garage.LayoutVersion{{
				Version: f.version - 1,
				Status:  garage.LayoutVersionStatusDraining,
			}}, history.Versions...)
			history.UpdateTrackers = make(map[string]garage.NodeUpdateTrackers, len(f.drainingNodeIDs))
			for nodeID := range f.drainingNodeIDs {
				history.UpdateTrackers[nodeID] = garage.NodeUpdateTrackers{Sync: f.version - 1}
			}
		}
		_ = json.NewEncoder(w).Encode(history)
	})
	mux.HandleFunc("/v2/ClusterLayoutSkipDeadNodes", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&f.skipCalls, 1)
		_ = json.NewEncoder(w).Encode(garage.SkipDeadNodesResponse{})
	})
	mux.HandleFunc("/v2/GetClusterStatus", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: f.version, Nodes: f.statusNodes})
	})
	mux.HandleFunc(testGetNodeInfoPath, func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.selfStatus != 0 {
			http.Error(w, "self identity temporarily unavailable", f.selfStatus)
			return
		}
		if f.selfNodeID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			testHTTPSuccessKey: map[string]any{f.selfNodeID: map[string]any{testNodeIDJSONKey: f.selfNodeID}},
			testHTTPErrorKey:   map[string]string{},
		})
	})
	return httptest.NewServer(mux)
}

func (f *fakeGarageLayout) hasRole(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.roles[id]
	return ok
}

func (f *fakeGarageLayout) appliedChanges() [][]garage.NodeRoleChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]garage.NodeRoleChange, len(f.applies))
	for i := range f.applies {
		out[i] = append([]garage.NodeRoleChange(nil), f.applies[i]...)
	}
	return out
}

func (f *fakeGarageLayout) completeDrain(nodeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.drainingNodeIDs, nodeID)
}

var _ = Describe("GarageNode stale-role reaping on in-place identity change", func() {
	const (
		oldID    = "0f6e73e52a9c7441d0d260e6ff09073a4bf9b963a0489ff1794df111eb9c7bf1"
		newID    = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
		liveID   = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		localUID = "local-cluster-uid"
	)

	var bctx context.Context
	BeforeEach(func() { bctx = context.Background() })

	storageRole := func(id string) garage.LayoutNodeRole {
		cap := uint64(700 << 30)
		return garage.LayoutNodeRole{ID: id, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cap}
	}
	desiredTags := []string{
		"cluster:" + fmGarageContainer + "/" + fmGarageContainer,
		nodeClusterUIDTagPrefix + localUID,
		testTierStorageTag,
	}

	drainReadyReconciler := func(node *garagev1beta1.GarageNode, assumeUnverified bool) (*GarageNodeReconciler, *garagev1beta2.GarageCluster) {
		if node.Name == "" {
			node.Name = testStorageNodeName
		}
		if node.Namespace == "" {
			node.Namespace = fmGarageContainer
		}
		if node.UID == "" {
			node.UID = types.UID(testNodeUID)
		}
		node.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: fmGarageContainer}
		policy := garagev1beta2.StorageDrainUnverifiedPeersBlock
		if assumeUnverified {
			policy = garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent
		}
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmGarageContainer, Namespace: fmGarageContainer,
				UID: types.UID(localUID), Generation: 1,
			},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1, ConsistencyMode: consistencyModeConsistent},
				LayoutManagement: &garagev1beta2.LayoutManagementConfig{Drain: &garagev1beta2.StorageDrainConfig{
					UnverifiedPeersPolicy: policy,
				}},
			},
			Status: garagev1beta2.GarageClusterStatus{
				Conditions: []metav1.Condition{{
					Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
					Reason: garagev1beta1.ReasonStorageRolloutConverged, ObservedGeneration: 1,
				}},
				Health: &garagev1beta2.ClusterHealth{
					Status: healthStatusHealthy, Healthy: true, Available: true,
					StorageNodes: 2, StorageNodesOK: 2,
					Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				},
			},
		}
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
		kubeClient := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).
			WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).Build()
		Expect(kubeClient.Get(bctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		Expect(kubeClient.Get(bctx, client.ObjectKeyFromObject(node), node)).To(Succeed())
		return &GarageNodeReconciler{
			Client:          kubeClient,
			LayoutMutations: NewLayoutMutationCoordinator(),
			managedNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error) {
				return node.Spec.NodeID, nil
			},
			clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
				return &garage.ClusterHealth{
					Status: healthStatusHealthy, StorageNodes: 2, StorageNodesUp: 2,
					Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				}, nil
			},
		}, cluster
	}

	// A wiped metadata volume produces a new live identity but leaves the old
	// positive-capacity process permanently unavailable. The replacement must not
	// receive a role before the old identity is explicitly retired: otherwise one
	// GarageNode owns two storage roles and a failed recovery can orphan the new one.
	It("retains the previous storage identity and leaves the replacement unassigned", func() {
		fake := newFakeGarageLayout(storageRole(oldID), storageRole(liveID))
		srv := fake.server()
		defer srv.Close()

		client := garage.NewClient(srv.URL, "test-token")

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ottawa-garage-localpath-asuka", Namespace: fmGarageContainer, Generation: 2},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID:   newID, // set so reconcileNode skips pod discovery
				Zone:     testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
				Tags:     []string{testTierStorageTag},
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: oldID, Connected: true, InLayout: true,
				ObservedPodUID: testOldPodUID, ObservedGeneration: 2,
			},
		}
		r, cluster := drainReadyReconciler(node, false)
		err := r.reconcileNode(bctx, node, cluster, client, cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue(), "unexpected mismatch error: %v", err)
		Expect(err.Error()).To(ContainSubstring(garagev1beta1.AnnotationAcknowledgeLostSource))
		Expect(err.Error()).To(ContainSubstring(oldID))
		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, client, cluster), errLayoutMutationPending)).To(BeTrue(),
			"retries must remain idempotently fenced before any replacement role Apply")

		Expect(fake.hasRole(oldID)).To(BeTrue(), "lost pre-wipe identity needs explicit dead-node recovery")
		Expect(fake.hasRole(newID)).To(BeFalse(), "fresh identity must remain unassigned until the old actor is retired")
		Expect(fake.hasRole(liveID)).To(BeTrue(), "unrelated live node must be untouched")
		Expect(fake.appliedChanges()).To(BeEmpty(), "identity detection must not mutate the layout")
		Expect(cluster.Status.StorageDrain).To(BeNil(), "identity detection must not create a live-source drain")
		storedNode := &garagev1beta1.GarageNode{}
		Expect(r.Get(bctx, types.NamespacedName{Name: node.Name, Namespace: node.Namespace}, storedNode)).To(Succeed())
		Expect(storedNode.Status.NodeID).To(Equal(oldID))
		Expect(storedNode.Status.ObservedPodUID).To(BeEmpty(), "old Pod UID must not remain bound to the replacement identity")
		Expect(storedNode.Status.Connected).To(BeFalse(), "old identity must not retain live-source evidence")
		Expect(storedNode.Status.ObservedGeneration).To(BeZero())
	})

	It("continues automatic replacement for capacity-less gateway identities", func() {
		gatewayRole := garage.LayoutNodeRole{ID: oldID, Zone: testZone, Tags: []string{testTierGatewayTag}}
		fake := newFakeGarageLayout(gatewayRole, storageRole(liveID))
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway-replacement", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone, Gateway: true, Tags: []string{testTierGatewayTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		r, cluster := drainReadyReconciler(node, false)
		client := garage.NewClient(srv.URL, "test-token")

		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, client, cluster), errLayoutMutationPending)).To(BeTrue())
		Expect(fake.hasRole(newID)).To(BeTrue(), "capacity-less replacement can join without a block migration")
		Expect(fake.hasRole(oldID)).To(BeFalse(), "replacement join and stale capacity-less removal must commit atomically")

		Expect(r.reconcileNode(bctx, node, cluster, client, cluster)).To(Succeed())
		Expect(fake.hasRole(newID)).To(BeTrue())
		Expect(node.Status.NodeID).To(Equal(newID))
		Expect(fake.appliedChanges()).To(HaveLen(1))
		Expect(fake.appliedChanges()[0]).To(HaveLen(2))
	})

	It("recovers an atomic gateway replacement after the Apply response is lost and the controller restarts", func() {
		gatewayRole := garage.LayoutNodeRole{ID: oldID, Zone: testZone, Tags: []string{testTierGatewayTag}}
		fake := newFakeGarageLayout(gatewayRole, storageRole(liveID))
		fake.holdRemovedInHistory = true
		fake.applyResponseLostOnce = true
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway-response-loss", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone, Gateway: true, Tags: []string{testTierGatewayTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		r, cluster := drainReadyReconciler(node, false)
		garageClient := garage.NewClient(srv.URL, "test-token")

		err := r.reconcileNode(bctx, node, cluster, garageClient, cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("Apply did not confirm"))
		Expect(fake.hasRole(newID)).To(BeTrue(), "Garage committed the replacement despite the lost response")
		Expect(fake.hasRole(oldID)).To(BeFalse(), "the same committed version must remove the predecessor")
		Expect(fake.appliedChanges()).To(HaveLen(1))
		Expect(node.Status.NodeID).To(Equal(oldID), "unconfirmed Apply must not advance durable node ownership")

		// Rehydrate both durable Kubernetes objects into a fresh reconciler. It
		// must observe the committed new role, retain the old ID in status while
		// Garage's prior version drains, and never issue a second Apply.
		storedNode := &garagev1beta1.GarageNode{}
		storedOwner := &garagev1beta2.GarageCluster{}
		Expect(r.Get(bctx, client.ObjectKeyFromObject(node), storedNode)).To(Succeed())
		Expect(r.Get(bctx, client.ObjectKeyFromObject(cluster), storedOwner)).To(Succeed())
		restarted := &GarageNodeReconciler{
			Client: r.Client, LayoutMutations: NewLayoutMutationCoordinator(),
			managedNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error) {
				return newID, nil
			},
		}
		err = restarted.reconcileNode(bctx, storedNode, storedOwner, garageClient, storedOwner)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("still draining"))
		Expect(fake.appliedChanges()).To(HaveLen(1), "restart recovery must be observation-only while history drains")
		Expect(storedNode.Status.NodeID).To(Equal(oldID))

		fake.completeDrain(oldID)
		Expect(restarted.reconcileNode(bctx, storedNode, storedOwner, garageClient, storedOwner)).To(Succeed())
		Expect(storedNode.Status.NodeID).To(Equal(newID))
		Expect(fake.appliedChanges()).To(HaveLen(1), "settled recovery must not repeat the topology transaction")
		Expect(atomic.LoadInt32(&fake.skipCalls)).To(BeZero(), "gateway replacement must never globally skip dead peers")
	})

	It("does not touch the layout when the identity is unchanged", func() {
		current := storageRole(newID)
		current.Tags = desiredTags
		fake := newFakeGarageLayout(current, storageRole(liveID))
		srv := fake.server()
		defer srv.Close()
		client := garage.NewClient(srv.URL, "test-token")

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "asuka", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
				Tags:     []string{testTierStorageTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: newID},
		}
		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: fmGarageContainer, Namespace: fmGarageContainer, UID: types.UID(localUID)}}

		r := &GarageNodeReconciler{managedNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error) {
			return newID, nil
		}}
		Expect(r.reconcileNode(bctx, node, cluster, client, cluster)).To(Succeed())
		Expect(fake.hasRole(newID)).To(BeTrue())
		Expect(fake.hasRole(liveID)).To(BeTrue())
	})

	It("treats managed spec.nodeId as a live-verified expected pin", func() {
		fake := newFakeGarageLayout(storageRole(liveID))
		srv := fake.server()
		defer srv.Close()
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "pinned", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
			},
		}
		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: fmGarageContainer, Namespace: fmGarageContainer}}
		r := &GarageNodeReconciler{managedNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error) {
			return oldID, nil
		}}

		err := r.reconcileNode(bctx, node, cluster, garage.NewClient(srv.URL, "test-token"), cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("exact live process reports"))
		Expect(fake.appliedChanges()).To(BeEmpty())
		Expect(node.Status.NodeID).To(BeEmpty())
	})

	It("rejects a copied node-local-pool identity already committed for another member", func() {
		conflicting := storageRole(newID)
		conflicting.Tags = []string{
			"cluster:" + fmGarageContainer + "/" + fmGarageContainer,
			nodeClusterUIDTagPrefix + localUID,
			testTierStorageTag,
			nodeLocalPoolLayoutTagPrefix + "other-pool",
			"kubernetes-node:other-worker",
		}
		fake := newFakeGarageLayout(conflicting, storageRole(liveID))
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "copied-pool-metadata", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone, Backing: garagev1beta1.NodeBackingNodeLocalPool,
				NodeLocalPoolName: "expected-pool", KubernetesNodeName: "expected-worker",
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
			},
		}
		r, cluster := drainReadyReconciler(node, false)
		err := r.reconcileNode(bctx, node, cluster, garage.NewClient(srv.URL, "test-token"), cluster)
		Expect(err).To(MatchError(ContainSubstring("IdentityCollision")))
		Expect(node.Status.NodeID).To(BeEmpty(), "foreign identity must not become durable child status")
		Expect(fake.appliedChanges()).To(BeEmpty(), "foreign role tags must not be repaired in place")
	})

	It("rejects two GarageNodes claiming the same discovered identity", func() {
		first := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "first-owner", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: fmGarageContainer},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: newID},
		}
		second := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "second-owner", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: fmGarageContainer},
			},
		}
		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
			Name: fmGarageContainer, Namespace: fmGarageContainer,
		}}
		scheme := runtime.NewScheme()
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
		kubeClient := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, first, second).Build()
		r := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient}
		err := r.validateGarageNodeIdentityOwner(bctx, second, cluster, newID)
		Expect(err).To(MatchError(ContainSubstring("IdentityCollision")))
		Expect(err.Error()).To(ContainSubstring(first.Name))
	})

	It("refuses to remove the stale role if it is the last storage node", func() {
		// Only the stale storage role exists (plus a gateway). Dropping it would
		// leave zero storage nodes. The error keeps reconcileNode from replacing
		// status.nodeId and forgetting which stale role still needs removal.
		gw := garage.LayoutNodeRole{ID: "gw", Zone: testZone, Tags: []string{testTierGatewayTag}}
		fake := newFakeGarageLayout(storageRole(oldID), gw)
		srv := fake.server()
		defer srv.Close()
		client := garage.NewClient(srv.URL, "test-token")

		r := &GarageNodeReconciler{}
		node := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		cluster := &garagev1beta2.GarageCluster{}
		err := r.removeStaleNodeRole(bctx, node, client, oldID, cluster)
		Expect(err).To(HaveOccurred())
		Expect(stderrors.Is(err, errUnsafeLayoutRoleRemoval)).To(BeTrue())
		Expect(fake.hasRole(oldID)).To(BeTrue(), "last storage node must not be removed")
	})

	It("marks last-role finalization as retryable instead of orphaning the layout role", func() {
		fake := newFakeGarageLayout(storageRole(oldID))
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		err := (&GarageNodeReconciler{}).finalize(bctx, node, &garagev1beta2.GarageCluster{}, garage.NewClient(srv.URL, "test-token"))
		Expect(err).To(HaveOccurred())
		Expect(stderrors.Is(err, errUnsafeLayoutRoleRemoval)).To(BeTrue())
		Expect(fake.hasRole(oldID)).To(BeTrue())
	})

	It("marks an upstream replication-constraint rejection as retryable", func() {
		fake := newFakeGarageLayout(storageRole(oldID), storageRole(liveID))
		fake.applyStatus = http.StatusInternalServerError
		fake.applyError = "The number of nodes with positive capacity (1) is smaller than the replication factor (2)"
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		r, cluster := drainReadyReconciler(node, true)
		err := r.finalize(bctx, node, cluster, garage.NewClient(srv.URL, "test-token"))
		Expect(err).To(HaveOccurred())
		Expect(stderrors.Is(err, errUnsafeLayoutRoleRemoval)).To(BeTrue())
		Expect(fake.hasRole(oldID)).To(BeTrue())
	})

	It("retains a storage finalizer until Garage retires the old layout version", func() {
		fake := newFakeGarageLayout(storageRole(oldID), storageRole(liveID))
		fake.holdRemovedInHistory = true
		srv := fake.server()
		defer srv.Close()

		node := &garagev1beta1.GarageNode{
			Spec:   garagev1beta1.GarageNodeSpec{Gateway: false},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		client := garage.NewClient(srv.URL, "test-token")
		r, cluster := drainReadyReconciler(node, true)

		err := r.finalize(bctx, node, cluster, client)
		Expect(err).To(HaveOccurred())
		Expect(stderrors.Is(err, errLayoutRoleDraining)).To(BeTrue())
		Expect(fake.hasRole(oldID)).To(BeFalse(), "the role should already be absent from the current layout")
		Expect(fake.appliedChanges()).To(HaveLen(1))

		fake.completeDrain(oldID)
		Expect(stderrors.Is(r.finalize(bctx, node, cluster, client), errLayoutMutationPending)).To(BeTrue(),
			"settled layout history is necessary but source/destination block proof must still complete")
		Expect(fake.appliedChanges()).To(HaveLen(1), "the removal must not be staged twice while waiting")
	})

	It("fails storage finalization closed on generic Admin API errors", func() {
		transient := stderrors.New("temporary Admin API outage")
		storageNode := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{Gateway: false},
		}
		gatewayNode := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{Gateway: true},
		}

		Expect(requiresDurableLayoutFinalization(storageNode, transient)).To(BeTrue(),
			"a storage role must not be orphaned when the generic retry budget expires")
		Expect(requiresDurableLayoutFinalization(gatewayNode, transient)).To(BeTrue(),
			"a gateway role and its metadata history must not be orphaned when the generic retry budget expires")
		Expect(requiresDurableLayoutFinalization(gatewayNode, errUnsafeLayoutRoleRemoval)).To(BeTrue(),
			"an explicit unsafe-removal signal always retains the finalizer")
	})
})
