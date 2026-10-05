package controller

import (
	"context"
	"testing"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// A stale-node removal is staged before Apply. If Apply then fails, the next
// reconcile sees its own removal in Garage's staging area. It must keep claiming
// that removal; treating it as foreign wedged the layout forever with
// "contains a change not owned by this operation".
func TestAssignNewNodesToLayout_RetryAfterFailedApplyKeepsStaleRemoval(t *testing.T) {
	const (
		liveID  = "aa00000000000000000000000000000000000000000000000000000000000001"
		staleID = "dd00000000000000000000000000000000000000000000000000000000000004"
		uid     = "local-cluster-uid"
	)
	cp := uint64(100 << 30)
	fake := newFakeGarageLayout(
		garage.LayoutNodeRole{ID: liveID, Zone: "z1", Capacity: &cp, Tags: buildNodeTags("gc", "tenant", tierStorage, nil, "gc-0", uid)},
		garage.LayoutNodeRole{ID: staleID, Zone: "z1", Capacity: &cp, Tags: buildNodeTags("gc", "tenant", tierStorage, nil, "gc-9", uid)},
	)
	srv := fake.server()
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "t")
	nodes := []bootstrapNodeInfo{{id: liveID, podName: "gc-0", tier: tierStorage}}
	cfg := layoutConfig{
		zone: "z1", capacity: 100 << 30, replicationFactor: 1,
		clusterName: "gc", namespace: "tenant", clusterUID: uid,
	}

	fake.mu.Lock()
	fake.applyStatus, fake.applyError = 500, "injected apply failure"
	fake.mu.Unlock()
	if err := assignNewNodesToLayout(context.Background(), gc, nodes, cfg); err == nil {
		t.Fatal("expected the failed Apply to surface as an error")
	}
	fake.mu.Lock()
	fake.applyStatus, fake.applyError = 0, ""
	staged := len(fake.staged)
	fake.mu.Unlock()
	if staged == 0 {
		t.Fatal("test setup: the stale removal should be left staged after the failed Apply")
	}

	if err := assignNewNodesToLayout(context.Background(), gc, nodes, cfg); err != nil {
		t.Fatalf("retry after a failed Apply must converge, got: %v", err)
	}
	if fake.hasRole(staleID) {
		t.Fatal("stale role was not removed on retry")
	}
	if !fake.hasRole(liveID) {
		t.Fatal("live role must survive")
	}
}
