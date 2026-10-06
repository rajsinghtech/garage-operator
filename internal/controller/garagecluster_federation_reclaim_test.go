package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	reclaimLocalID  = "aa00000000000000000000000000000000000000000000000000000000000001"
	reclaimRemoteID = "bb00000000000000000000000000000000000000000000000000000000000002"
	reclaimUID      = "local-cluster-uid"
	reclaimZone     = "z-remote"
)

type reclaimEnv struct {
	r        *GarageClusterReconciler
	cluster  *garagev1beta2.GarageCluster
	remote   garagev1beta2.RemoteClusterConfig
	recorder *record.FakeRecorder
}

func newReclaimEnv(t *testing.T) *reclaimEnv {
	t.Helper()
	recorder := record.NewFakeRecorder(16)
	return &reclaimEnv{
		r: &GarageClusterReconciler{
			Client:        fake.NewClientBuilder().WithScheme(testSchemeForFault(t)).Build(),
			EventRecorder: recorder,
		},
		cluster:  &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "gc", Namespace: "tenant", UID: reclaimUID}},
		remote:   garagev1beta2.RemoteClusterConfig{Name: "remote-a", Zone: reclaimZone},
		recorder: recorder,
	}
}

func reclaimCapacity() *uint64 { c := uint64(100 << 30); return &c }

func newReclaimLayout() *fakeGarageLayout {
	return newFakeGarageLayout(garage.LayoutNodeRole{
		ID: reclaimLocalID, Zone: "z-local", Capacity: reclaimCapacity(),
		Tags: buildNodeTags("gc", "tenant", tierStorage, nil, "gc-0", reclaimUID),
	})
}

// remoteStatusFor reports the remote node with a committed role; up toggles
// liveness and absent drops the node from the status entirely.
func remoteStatusFor(up, absent bool) *garage.ClusterStatus {
	if absent {
		return &garage.ClusterStatus{}
	}
	return &garage.ClusterStatus{Nodes: []garage.NodeInfo{{
		ID: reclaimRemoteID, IsUp: up,
		Role: &garage.NodeAssignedRole{Zone: reclaimZone, Capacity: reclaimCapacity(), Tags: []string{"tier:storage", "site:remote-a"}},
	}}}
}

func (e *reclaimEnv) importOnce(ctx context.Context, gc *garage.Client, status *garage.ClusterStatus) error {
	return e.r.addRemoteNodesToLayoutLocked(ctx, e.cluster, gc, nil, status, status, e.remote)
}

// stageImportThenFailApply reproduces the first half of #468: the import stages
// the remote node, then Garage rejects the Apply (the federated-bootstrap
// replication-constraint case), leaving the role staged.
func stageImportThenFailApply(t *testing.T, e *reclaimEnv, fk *fakeGarageLayout, gc *garage.Client) {
	t.Helper()
	fk.mu.Lock()
	fk.applyStatus, fk.applyError = 500, "The number of nodes with positive capacity (1) is smaller than the replication factor (2)"
	fk.mu.Unlock()
	if err := e.importOnce(context.Background(), gc, remoteStatusFor(true, false)); err == nil {
		t.Fatal("setup: the rejected Apply must surface")
	}
	fk.mu.Lock()
	fk.applyStatus, fk.applyError = 0, ""
	staged := len(fk.staged)
	fk.mu.Unlock()
	if staged != 1 {
		t.Fatalf("setup: want the remote import left staged, got %d staged", staged)
	}
}

func assertReclaimConverged(t *testing.T, fk *fakeGarageLayout, gc *garage.Client) {
	t.Helper()
	if !fk.hasRole(reclaimRemoteID) {
		t.Fatal("re-claimed import was not applied")
	}
	fk.mu.Lock()
	staged := len(fk.staged)
	fk.mu.Unlock()
	if staged != 0 {
		t.Fatalf("staging area must be empty after the re-claimed Apply, got %d", staged)
	}
	// Other layout writers are no longer wedged by a foreign staged change.
	nodes := []bootstrapNodeInfo{{id: reclaimLocalID, podName: "gc-0", tier: tierStorage}}
	cfg := layoutConfig{zone: "z-local", capacity: 100 << 30, replicationFactor: 1, clusterName: "gc", namespace: "tenant", clusterUID: reclaimUID, skipStaleDetection: true}
	if err := assignNewNodesToLayout(context.Background(), gc, nodes, cfg); err != nil {
		t.Fatalf("a later local layout mutation is still blocked: %v", err)
	}
}

func TestFederatedImportReclaimsOwnStagedRoleWhenRemoteNodeGoesDown(t *testing.T) {
	e := newReclaimEnv(t)
	fk := newReclaimLayout()
	srv := fk.server()
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "t")
	stageImportThenFailApply(t, e, fk, gc)

	if err := e.importOnce(context.Background(), gc, remoteStatusFor(false, false)); err != nil {
		t.Fatalf("re-claiming the staged import for a down node must apply, got %v", err)
	}
	assertReclaimConverged(t, fk, gc)
}

func TestFederatedImportReclaimsOwnStagedRoleWhenRemoteNodeIsAbsent(t *testing.T) {
	e := newReclaimEnv(t)
	fk := newReclaimLayout()
	srv := fk.server()
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "t")
	stageImportThenFailApply(t, e, fk, gc)

	if err := e.importOnce(context.Background(), gc, remoteStatusFor(false, true)); err != nil {
		t.Fatalf("re-claiming the staged import for an absent node must apply, got %v", err)
	}
	assertReclaimConverged(t, fk, gc)
}

func TestFederatedImportDoesNotStartNewImportForDownNode(t *testing.T) {
	e := newReclaimEnv(t)
	fk := newReclaimLayout()
	srv := fk.server()
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "t")
	if err := e.importOnce(context.Background(), gc, remoteStatusFor(false, false)); err != nil {
		t.Fatalf("down node without a staged import: %v", err)
	}
	fk.mu.Lock()
	staged := len(fk.staged)
	fk.mu.Unlock()
	if staged != 0 || fk.hasRole(reclaimRemoteID) {
		t.Fatalf("a down remote node must not be newly imported (staged=%d)", staged)
	}
}

func TestFederatedImportSurfacesMismatchedStagedRoleWithoutMutating(t *testing.T) {
	e := newReclaimEnv(t)
	fk := newReclaimLayout()
	// A staged role in this remote's zone that this import would not produce:
	// the down node's reported capacity differs from what is staged.
	other := uint64(7 << 30)
	fk.staged = []garage.NodeRoleChange{{ID: reclaimRemoteID, Zone: reclaimZone, Capacity: &other, Tags: []string{"tier:storage", "site:remote-a"}}}
	srv := fk.server()
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "t")

	err := e.importOnce(context.Background(), gc, remoteStatusFor(false, false))
	if err == nil || !stderrors.Is(err, errLayoutMutationPending) {
		t.Fatalf("a mismatched staged role must be surfaced as a pending layout error, got %v", err)
	}
	if !strings.Contains(err.Error(), shortID(reclaimRemoteID)) {
		t.Fatalf("error must name the node: %v", err)
	}
	select {
	case ev := <-e.recorder.Events:
		if !strings.Contains(ev, eventReasonLayoutWriteBlocked) || !strings.Contains(ev, shortID(reclaimRemoteID)) {
			t.Fatalf("unexpected event: %s", ev)
		}
	default:
		t.Fatal("want a LayoutWriteBlocked warning event")
	}
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if len(fk.applies) != 0 || len(fk.staged) != 1 || *fk.staged[0].Capacity != other {
		t.Fatalf("a mismatched staged role must not be mutated or applied: applies=%d staged=%+v", len(fk.applies), fk.staged)
	}
}

// TestFaultSweep_FederatedImportRemoteGoesDown injects one Admin API fault
// (before Garage, or after commit with the response lost) at every call of an
// import whose remote node is up, then retries with the remote node down or
// absent. Every position must converge without an error and with an empty
// staging area: either the staged import is re-claimed and applied, or the
// fault hit before anything was staged and the down node is (by policy) not
// newly imported.
func TestFaultSweep_FederatedImportRemoteGoesDown(t *testing.T) {
	type outcome struct {
		snap  string
		err   error
		calls int
		hit   bool
	}
	run := func(failAt int, after, absent bool) outcome {
		e := newReclaimEnv(t)
		fk := newReclaimLayout()
		srv := fk.server()
		defer srv.Close()
		proxy := newFaultProxy(t, srv.URL)
		gc := garage.NewClient(proxy.srv.URL, "t")
		ctx := context.Background()
		proxy.mu.Lock()
		proxy.failAt, proxy.after = failAt, after
		proxy.mu.Unlock()
		_ = e.importOnce(ctx, gc, remoteStatusFor(true, false))
		proxy.mu.Lock()
		proxy.failAt = 0
		proxy.mu.Unlock()
		var lastErr error
		for i := 0; i < 4; i++ {
			if lastErr = e.importOnce(ctx, gc, remoteStatusFor(false, absent)); lastErr == nil {
				break
			}
		}
		return outcome{snap: layoutSnapshot(fk), err: lastErr, calls: proxy.calls, hit: proxy.hit}
	}
	base := run(0, false, false)
	if base.err != nil || !strings.Contains(base.snap, reclaimRemoteID[:8]) || !strings.Contains(base.snap, "staged=0") {
		t.Fatalf("baseline did not import: %v %s", base.err, base.snap)
	}
	pristine := layoutSnapshot(newReclaimLayout())
	for _, absent := range []bool{false, true} {
		for i := 1; i <= base.calls; i++ {
			for _, after := range []bool{false, true} {
				got := run(i, after, absent)
				if !got.hit {
					continue
				}
				label := fmt.Sprintf("call #%d afterCommit=%v absent=%v", i, after, absent)
				if got.err != nil {
					t.Errorf("[%s] did not converge: %v (%s)", label, got.err, got.snap)
				} else if got.snap != base.snap && got.snap != pristine {
					t.Errorf("[%s] end state is neither the applied import nor untouched\n  baseline: %s\n  pristine: %s\n  faulted:  %s", label, base.snap, pristine, got.snap)
				}
			}
		}
	}
}
