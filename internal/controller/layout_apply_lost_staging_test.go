package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Real Garage (v2.0–v2.4) keeps its staging area in one last-writer-wins
// register whose timestamp only moves on Apply/Revert. When two independently
// bootstrapped sites first connect, the site whose last Apply is older has its
// staging replaced by the other site's newer, empty one on the next gossip;
// if that lands between the client's re-read and Apply, Garage commits a new
// version without the staged changes. The other site then adopts that version
// and loses its own roles, so the importer's in-memory intent is the only
// copy left. Multi-Cluster E2E run 37511577978 failed exactly this way.

// TestFederationImportRecommitsWhenGarageDropsStagedRoles is the regression
// test for that run: the first import Apply commits nothing, and the import
// must still end with the remote role committed in the same pass.
func TestFederationImportRecommitsWhenGarageDropsStagedRoles(t *testing.T) {
	ctx := context.Background()
	e := newFedEnv(t, fedOldAddr, fedOldAddr, false)
	e.local.mu.Lock()
	e.local.stagingLostBeforeApply = 1
	startVersion := e.local.version
	e.local.mu.Unlock()

	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatalf("import pass: %v", err)
	}
	if !e.local.hasRole(fedRemoteID) {
		t.Fatal("remote role must be committed even though Garage dropped the first staged import")
	}
	applies := e.local.appliedChanges()
	if len(applies) != 2 || len(applies[0]) != 0 || len(applies[1]) != 1 || applies[1][0].ID != fedRemoteID {
		t.Fatalf("want an empty commit followed by the re-staged import, got %+v", applies)
	}
	e.local.mu.Lock()
	gotVersion, staged := e.local.version, len(e.local.staged)
	e.local.mu.Unlock()
	if gotVersion != startVersion+2 || staged != 0 {
		t.Fatalf("want version %d with nothing staged, got version %d with %d staged", startVersion+2, gotVersion, staged)
	}

	// Steady state: the next pass neither writes the layout nor re-imports.
	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatalf("steady-state pass: %v", err)
	}
	if n := len(e.local.appliedChanges()); n != 2 {
		t.Fatalf("steady state must not Apply again, got %d applies", n)
	}
}

// TestStageAndApplyGivesUpAfterSecondLostCommit bounds the recovery: one
// re-stage, then a pending error rather than an Apply loop.
func TestStageAndApplyGivesUpAfterSecondLostCommit(t *testing.T) {
	ctx := context.Background()
	f := newFakeGarageLayout(fedLocalRole())
	f.stagingLostBeforeApply = 2
	srv := f.server()
	defer srv.Close()
	client := garage.NewClient(srv.URL, "token")

	layout, err := client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	role := fedRemoteRole(fedOldAddr)
	intended := []garage.NodeRoleChange{{ID: role.ID, Zone: role.Zone, Capacity: role.Capacity, Tags: role.Tags}}
	_, err = stageAndApplyExclusiveLayout(ctx, client, layout, intended, nil, func() error {
		return client.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{Roles: intended})
	})
	if !errors.Is(err, errLayoutMutationPending) {
		t.Fatalf("want errLayoutMutationPending after two lost commits, got %v", err)
	}
	if n := len(f.appliedChanges()); n != 2 {
		t.Fatalf("want exactly two Applies (original + one retry), got %d", n)
	}
	if f.hasRole(role.ID) {
		t.Fatal("fake must not have committed the role")
	}
}

// TestStageAndApplyRecommitsRemovalGarageDropped covers the removal path,
// which every drain and stale-role cleanup goes through.
func TestStageAndApplyRecommitsRemovalGarageDropped(t *testing.T) {
	ctx := context.Background()
	stale := fedRemoteRole(fedOldAddr)
	f := newFakeGarageLayout(fedLocalRole(), stale)
	f.stagingLostBeforeApply = 1
	srv := f.server()
	defer srv.Close()
	client := garage.NewClient(srv.URL, "token")

	layout, err := client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	intended := []garage.NodeRoleChange{{ID: stale.ID, Remove: true, Tags: []string{}}}
	if _, err := stageAndApplyExclusiveLayout(ctx, client, layout, intended, nil, func() error {
		return client.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{Roles: intended})
	}); err != nil {
		t.Fatalf("stage and apply: %v", err)
	}
	if f.hasRole(stale.ID) {
		t.Fatal("removal must be re-committed after Garage dropped it")
	}
	if !f.hasRole(fedLocalID) {
		t.Fatal("unrelated role must be untouched")
	}
}
