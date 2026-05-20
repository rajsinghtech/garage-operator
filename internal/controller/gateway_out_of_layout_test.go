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
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testGatewayNodeID1 = "2222222222222222222222222222222222222222222222222222222222222222"
	testGatewayNodeID2 = "3333333333333333333333333333333333333333333333333333333333333333"
)

// layoutTestServer is a minimal mock Garage admin API used by the
// gateway-out-of-layout tests. It serves a configurable initial layout and
// records every UpdateClusterLayout/ApplyClusterLayout request.
type layoutTestServer struct {
	t              *testing.T
	server         *httptest.Server
	layout         garage.ClusterLayout
	updateRequests []garage.UpdateClusterLayoutRequest
	applyRequests  []garage.ApplyLayoutRequest
	skipRequests   []garage.SkipDeadNodesRequest
}

func newLayoutTestServer(t *testing.T, initial garage.ClusterLayout) *layoutTestServer {
	t.Helper()
	s := &layoutTestServer{t: t, layout: initial}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/GetClusterLayout":
			_ = json.NewEncoder(w).Encode(s.layout)
		case "/v2/UpdateClusterLayout":
			var req garage.UpdateClusterLayoutRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.updateRequests = append(s.updateRequests, req)
			// Stage the requested changes on the layout the next GET returns.
			s.layout.StagedRoleChanges = append(s.layout.StagedRoleChanges, req.Roles...)
			w.WriteHeader(http.StatusOK)
		case "/v2/ApplyClusterLayout":
			var req garage.ApplyLayoutRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.applyRequests = append(s.applyRequests, req)
			// Promote staged removals out of the role list, drop staged additions
			// into roles. Simulate version bump and clear staged.
			remaining := make([]garage.LayoutNodeRole, 0, len(s.layout.Roles))
			toRemove := make(map[string]bool)
			toAdd := make([]garage.NodeRoleChange, 0)
			for _, c := range s.layout.StagedRoleChanges {
				if c.Remove {
					toRemove[c.ID] = true
				} else {
					toAdd = append(toAdd, c)
				}
			}
			for _, role := range s.layout.Roles {
				if !toRemove[role.ID] {
					remaining = append(remaining, role)
				}
			}
			for _, a := range toAdd {
				remaining = append(remaining, garage.LayoutNodeRole{
					ID: a.ID, Zone: a.Zone, Capacity: a.Capacity, Tags: a.Tags,
				})
			}
			s.layout.Roles = remaining
			s.layout.StagedRoleChanges = nil
			s.layout.Version = req.Version
			w.WriteHeader(http.StatusOK)
		case "/v2/ClusterLayoutSkipDeadNodes":
			var req garage.SkipDeadNodesRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.skipRequests = append(s.skipRequests, req)
			// Single-version layout: return 400 like real Garage.
			http.Error(w, `{"code":"InvalidRequest","message":"This command cannot be called when there is only one live cluster layout version"}`, http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *layoutTestServer) client() *garage.Client {
	return garage.NewClient(s.server.URL, "test-admin-token")
}

// TestAssignNewNodesToLayout_SkipsGatewayTier verifies that gateway-tier pods
// are never added to the cluster layout. Storage-tier pods continue to be
// staged as before.
func TestAssignNewNodesToLayout_SkipsGatewayTier(t *testing.T) {
	srv := newLayoutTestServer(t, garage.ClusterLayout{Version: 1})

	nodes := []bootstrapNodeInfo{
		{
			id:      "1111111111111111111111111111111111111111111111111111111111111111",
			podIP:   "10.0.0.1",
			podName: "test-0",
			tier:    tierStorage,
		},
		{
			id:      testGatewayNodeID1,
			podIP:   "10.0.0.2",
			podName: "test-gateway-abc",
			tier:    tierGateway,
		},
		{
			id:      testGatewayNodeID2,
			podIP:   "10.0.0.3",
			podName: "test-gateway-def",
			tier:    tierGateway,
		},
	}

	cfg := layoutConfig{
		zone:               "zone-a",
		capacity:           10 * 1024 * 1024 * 1024,
		replicationFactor:  1,
		clusterName:        "test",
		namespace:          testNamespace,
		skipStaleDetection: true, // we don't care about stale detection here
	}

	if err := assignNewNodesToLayout(context.Background(), srv.client(), nodes, cfg); err != nil {
		t.Fatalf("assignNewNodesToLayout: %v", err)
	}

	// Exactly one UpdateClusterLayout request, staging only the storage node.
	if len(srv.updateRequests) != 1 {
		t.Fatalf("expected 1 UpdateClusterLayout call, got %d", len(srv.updateRequests))
	}
	staged := srv.updateRequests[0].Roles
	if len(staged) != 1 {
		t.Fatalf("expected 1 staged role, got %d: %+v", len(staged), staged)
	}
	if staged[0].ID != nodes[0].id {
		t.Errorf("expected storage node %s staged, got %s", nodes[0].id, staged[0].ID)
	}
	for _, role := range staged {
		for _, tag := range role.Tags {
			if tag == gatewayTierTag {
				t.Errorf("staged role carries tier:gateway tag: %+v", role)
			}
		}
	}
}

// TestAssignNewNodesToLayout_GatewayOnlyEmptyLayout verifies edge-gateway
// behavior: when the only pods discovered are gateway-tier, nothing is staged
// in the (remote) layout. The remote cluster's node_id_vec stays storage-only.
func TestAssignNewNodesToLayout_GatewayOnlyEmptyLayout(t *testing.T) {
	srv := newLayoutTestServer(t, garage.ClusterLayout{
		Version: 1,
		// A remote storage cluster has its own roles already; the edge gateway
		// must not touch them.
		Roles: []garage.LayoutNodeRole{
			{
				ID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Zone: "remote-zone",
				Tags: []string{"cluster:storage/default", "tier:" + tierStorage},
			},
		},
	})

	nodes := []bootstrapNodeInfo{
		{
			id:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			podIP:   "10.0.0.10",
			podName: "edge-gateway-1",
			tier:    tierGateway,
		},
	}

	cfg := layoutConfig{
		zone:               "edge-zone",
		isGateway:          true,
		replicationFactor:  1,
		clusterName:        "edge",
		namespace:          testNamespace,
		skipStaleDetection: true,
	}

	if err := assignNewNodesToLayout(context.Background(), srv.client(), nodes, cfg); err != nil {
		t.Fatalf("assignNewNodesToLayout: %v", err)
	}

	if len(srv.updateRequests) != 0 {
		t.Errorf("expected 0 UpdateClusterLayout calls for edge gateway, got %d: %+v",
			len(srv.updateRequests), srv.updateRequests)
	}
	if len(srv.applyRequests) != 0 {
		t.Errorf("expected 0 ApplyClusterLayout calls for edge gateway, got %d", len(srv.applyRequests))
	}
}

// TestMigrateGatewayOutOfLayout verifies the one-shot migration: existing
// gateway-tier role entries are removed; subsequent calls are no-ops.
func TestMigrateGatewayOutOfLayout(t *testing.T) {
	ownership := "cluster:my-cluster/my-ns"
	srv := newLayoutTestServer(t, garage.ClusterLayout{
		Version: 5,
		Roles: []garage.LayoutNodeRole{
			{
				ID:   "1111111111111111111111111111111111111111111111111111111111111111",
				Zone: "z",
				Tags: []string{ownership, "tier:" + tierStorage, "my-cluster-0"},
			},
			{
				ID:   testGatewayNodeID1,
				Zone: "z",
				Tags: []string{ownership, gatewayTierTag, "my-cluster-gateway-xyz"},
			},
			{
				ID:   testGatewayNodeID2,
				Zone: "z",
				Tags: []string{ownership, gatewayTierTag, "my-cluster-gateway-abc"},
			},
			// Belongs to another cluster — must be left alone even if gateway-tagged.
			{
				ID:   "4444444444444444444444444444444444444444444444444444444444444444",
				Zone: "z",
				Tags: []string{"cluster:other/elsewhere", gatewayTierTag},
			},
		},
	})

	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	_ = garagev1beta2.AddToScheme(s)
	r := &GarageClusterReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).Build(),
		Scheme: s,
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "my-ns", Generation: 7},
		Status: garagev1beta2.GarageClusterStatus{
			//nolint:staticcheck // SA1019: deprecated field intentionally seeded
			PendingGatewayTombstones: []string{"left-over-from-old-operator"},
		},
	}

	r.migrateGatewayOutOfLayout(context.Background(), srv.client(), cluster)

	// First pass: exactly one UpdateClusterLayout call, removing both
	// gateway-tier roles owned by this cluster.
	if len(srv.updateRequests) != 1 {
		t.Fatalf("expected 1 UpdateClusterLayout call, got %d", len(srv.updateRequests))
	}
	got := srv.updateRequests[0].Roles
	if len(got) != 2 {
		t.Fatalf("expected 2 staged removals, got %d: %+v", len(got), got)
	}
	want := map[string]bool{
		testGatewayNodeID1: true,
		testGatewayNodeID2: true,
	}
	for _, change := range got {
		if !change.Remove {
			t.Errorf("expected Remove=true on %s, got %+v", change.ID, change)
		}
		if !want[change.ID] {
			t.Errorf("unexpected ID removed: %s", change.ID)
		}
		delete(want, change.ID)
	}
	if len(want) > 0 {
		t.Errorf("missing removals: %v", want)
	}

	// Exactly one ApplyClusterLayout call.
	if len(srv.applyRequests) != 1 {
		t.Errorf("expected 1 ApplyClusterLayout, got %d", len(srv.applyRequests))
	}

	// Status: deprecated PendingGatewayTombstones cleared, migration condition set.
	//nolint:staticcheck // SA1019: deprecated field intentionally inspected
	if cluster.Status.PendingGatewayTombstones != nil {
		//nolint:staticcheck // SA1019
		t.Errorf("PendingGatewayTombstones should be cleared, got %v", cluster.Status.PendingGatewayTombstones)
	}
	cond := findCond(cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones)
	if cond == nil {
		t.Fatalf("expected GatewayTombstones condition to be set after migration")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("migration condition status = %q, want %q", cond.Status, metav1.ConditionFalse)
	}
	if cond.Message == "" || !contains(cond.Message, "Migrated gateway tier out of layout") {
		t.Errorf("migration condition message = %q, want it to mention the migration", cond.Message)
	}

	// Second pass: layout no longer contains tier:gateway entries owned by us,
	// so no further removals are staged.
	prevUpdates := len(srv.updateRequests)
	prevApplies := len(srv.applyRequests)
	r.migrateGatewayOutOfLayout(context.Background(), srv.client(), cluster)
	if len(srv.updateRequests) != prevUpdates {
		t.Errorf("second migrate added UpdateClusterLayout call(s): %+v", srv.updateRequests[prevUpdates:])
	}
	if len(srv.applyRequests) != prevApplies {
		t.Errorf("second migrate added ApplyClusterLayout call(s)")
	}

	// The other cluster's gateway entry must remain untouched.
	foundOther := false
	for _, role := range srv.layout.Roles {
		if role.ID == "4444444444444444444444444444444444444444444444444444444444444444" {
			foundOther = true
		}
	}
	if !foundOther {
		t.Errorf("migration removed a gateway entry belonging to another cluster")
	}
}

func findCond(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
