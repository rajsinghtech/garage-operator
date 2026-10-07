package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/client-go/tools/record"

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
	if !errors.Is(err, errLayoutMutationPending) || !errors.Is(err, errLayoutChangesDropped) {
		t.Fatalf("want errLayoutMutationPending+errLayoutChangesDropped after two lost commits, got %v", err)
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

// TestStageAndApplyDoesNotCommitForeignStagingAfterLostApply: when the lost
// Apply leaves a peer's change in the staging area, the bounded re-stage must
// refuse to commit it (security: the retry never widens what this operation
// is authorized to apply) and report pending without a second Apply.
func TestStageAndApplyDoesNotCommitForeignStagingAfterLostApply(t *testing.T) {
	ctx := context.Background()
	local := fedLocalRole()
	f := newFakeGarageLayout(local)
	f.stagingLostBeforeApply = 1
	f.stagedAfterLostApply = []garage.NodeRoleChange{{ID: local.ID, Remove: true, Tags: []string{}}}
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
		t.Fatalf("want errLayoutMutationPending when a foreign change is staged, got %v", err)
	}
	if n := len(f.appliedChanges()); n != 1 {
		t.Fatalf("the foreign staged change must not be applied: got %d Applies", n)
	}
	if !f.hasRole(local.ID) {
		t.Fatal("the peer's staged removal must not have been committed")
	}
	f.mu.Lock()
	staged := append([]garage.NodeRoleChange(nil), f.staged...)
	f.mu.Unlock()
	if len(staged) != 1 || !staged[0].Remove || staged[0].ID != local.ID {
		t.Fatalf("the peer's staging must be left untouched, got %+v", staged)
	}
}

// TestStageAndApplyHappyPathMakesNoExtraWrites: verification is read-only
// when Garage committed what was staged.
func TestStageAndApplyHappyPathMakesNoExtraWrites(t *testing.T) {
	ctx := context.Background()
	f := newFakeGarageLayout(fedLocalRole())
	srv := f.server()
	defer srv.Close()
	client := garage.NewClient(srv.URL, "token")
	layout, err := client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	role := fedRemoteRole(fedOldAddr)
	intended := []garage.NodeRoleChange{{ID: role.ID, Zone: role.Zone, Capacity: role.Capacity, Tags: role.Tags}}
	if _, err := stageAndApplyExclusiveLayout(ctx, client, layout, intended, nil, func() error {
		return client.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{Roles: intended})
	}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.appliedChanges()); n != 1 || !f.hasRole(role.ID) {
		t.Fatalf("want exactly one Apply committing the role, got %d applies", n)
	}
}

// TestFederationImportReportsPersistentlyDroppedChanges: when Garage drops the
// import twice in one pass, the pass stops after its single re-stage, emits a
// LayoutChangesDropped warning event (the import path otherwise only logs),
// and the next pass completes the import.
func TestFederationImportReportsPersistentlyDroppedChanges(t *testing.T) {
	ctx := context.Background()
	e := newFedEnv(t, fedOldAddr, fedOldAddr, false)
	e.local.mu.Lock()
	e.local.stagingLostBeforeApply = 2
	e.local.mu.Unlock()

	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatalf("import pass: %v", err)
	}
	if e.local.hasRole(fedRemoteID) {
		t.Fatal("fake dropped both commits; the remote role cannot be committed yet")
	}
	if n := len(e.local.appliedChanges()); n != 2 {
		t.Fatalf("want the original Apply plus exactly one retry, got %d", n)
	}
	recorder := e.r.EventRecorder.(*record.FakeRecorder)
	select {
	case ev := <-recorder.Events:
		if !strings.Contains(ev, eventReasonLayoutChangesDropped) || !strings.Contains(ev, "remote-a") {
			t.Fatalf("unexpected event %q", ev)
		}
	default:
		t.Fatal("want a LayoutChangesDropped warning event")
	}

	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatalf("retry pass: %v", err)
	}
	if !e.local.hasRole(fedRemoteID) {
		t.Fatal("the next pass must complete the import once Garage stops dropping changes")
	}
}
