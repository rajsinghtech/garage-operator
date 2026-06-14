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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	skipCalls int32
}

func newFakeGarageLayout(initial ...garage.LayoutNodeRole) *fakeGarageLayout {
	f := &fakeGarageLayout{version: 1, roles: map[string]garage.LayoutNodeRole{}}
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
		f.staged = append(f.staged, req.Roles...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/ApplyClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		for _, c := range f.staged {
			if c.Remove {
				delete(f.roles, c.ID)
				continue
			}
			f.roles[c.ID] = garage.LayoutNodeRole{ID: c.ID, Zone: c.Zone, Tags: c.Tags, Capacity: c.Capacity}
		}
		f.staged = nil
		f.version++
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/ClusterLayoutSkipDeadNodes", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&f.skipCalls, 1)
		_ = json.NewEncoder(w).Encode(garage.SkipDeadNodesResponse{})
	})
	return httptest.NewServer(mux)
}

func (f *fakeGarageLayout) hasRole(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.roles[id]
	return ok
}

var _ = Describe("GarageNode stale-role reaping on in-place identity change", func() {
	const (
		oldID  = "0f6e73e52a9c7441d0d260e6ff09073a4bf9b963a0489ff1794df111eb9c7bf1"
		newID  = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	var bctx context.Context
	BeforeEach(func() { bctx = context.Background() })

	storageRole := func(id string) garage.LayoutNodeRole {
		cap := uint64(700 << 30)
		return garage.LayoutNodeRole{ID: id, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cap}
	}

	// This is the bug: asuka's data PVC was wiped, Garage minted a fresh node_id
	// (newID), but the dead pre-wipe identity (oldID) kept its storage role in
	// the layout — holding partitions Garage will never rebalance. reconcileNode
	// must drop the stale role once it observes the node's identity changed.
	It("removes the previous identity's role when the discovered node_id changed", func() {
		fake := newFakeGarageLayout(storageRole(oldID), storageRole(liveID))
		srv := fake.server()
		defer srv.Close()

		client := garage.NewClient(srv.URL, "test-token")

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ottawa-garage-localpath-asuka", Namespace: fmGarageContainer},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID:   newID, // set so reconcileNode skips pod discovery
				Zone:     testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
				Tags:     []string{testTierStorageTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: fmGarageContainer, Namespace: fmGarageContainer},
		}

		r := &GarageNodeReconciler{}
		Expect(r.reconcileNode(bctx, node, cluster, client)).To(Succeed())

		Expect(fake.hasRole(oldID)).To(BeFalse(), "stale pre-wipe identity must be removed from layout")
		Expect(fake.hasRole(newID)).To(BeTrue(), "fresh identity must be added to layout")
		Expect(fake.hasRole(liveID)).To(BeTrue(), "unrelated live node must be untouched")
	})

	It("does not touch the layout when the identity is unchanged", func() {
		fake := newFakeGarageLayout(storageRole(newID), storageRole(liveID))
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
		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: fmGarageContainer, Namespace: fmGarageContainer}}

		r := &GarageNodeReconciler{}
		Expect(r.reconcileNode(bctx, node, cluster, client)).To(Succeed())
		Expect(fake.hasRole(newID)).To(BeTrue())
		Expect(fake.hasRole(liveID)).To(BeTrue())
	})

	It("refuses to remove the stale role if it is the last storage node", func() {
		// Only the stale storage role exists (plus a gateway). Dropping it would
		// leave zero storage nodes — removeStaleNodeRole must no-op instead.
		gw := garage.LayoutNodeRole{ID: "gw", Zone: testZone, Tags: []string{testTierGatewayTag}}
		fake := newFakeGarageLayout(storageRole(oldID), gw)
		srv := fake.server()
		defer srv.Close()
		client := garage.NewClient(srv.URL, "test-token")

		r := &GarageNodeReconciler{}
		Expect(r.removeStaleNodeRole(bctx, client, oldID)).To(Succeed())
		Expect(fake.hasRole(oldID)).To(BeTrue(), "last storage node must not be removed")
	})
})
