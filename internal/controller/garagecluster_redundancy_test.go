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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// redundancyDriver runs advanceRedundancy against the Garage model the way the
// controller does: launch the requested repairs, persist through a JSON round
// trip (API-server time precision), then let Garage do one tick of work.
type redundancyDriver struct {
	t     *testing.T
	g     *redundancyGarage
	now   time.Time
	step  time.Duration
	quiet time.Duration

	prev       *garagev1beta2.RedundancyStatus
	pods       []string
	token      string
	follower   bool
	drain      bool
	observed   bool
	failLaunch bool

	last     redundancyResult
	writes   int
	launched []redundancyLaunch
}

func newRedundancyDriver(t *testing.T, storageNodes int) *redundancyDriver {
	t.Helper()
	return &redundancyDriver{
		t:        t,
		g:        newRedundancyGarage(storageNodes),
		now:      time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		step:     30 * time.Second,
		quiet:    5 * time.Minute,
		pods:     []string{"pod-a/0", "pod-b/0", "pod-c/0"},
		observed: true,
	}
}

func roundTripRedundancy(t *testing.T, status *garagev1beta2.RedundancyStatus) *garagev1beta2.RedundancyStatus {
	t.Helper()
	if status == nil {
		return nil
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	out := &garagev1beta2.RedundancyStatus{}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (d *redundancyDriver) input() redundancyInput {
	in := d.g.input()
	in.Now = d.now
	in.QuietPeriod = d.quiet
	in.Follower = d.follower
	in.DrainActive = d.drain
	in.RequestToken = d.token
	in.Observed = d.observed
	in.MembershipHash = redundancyMembershipHash(redundancyStorageNodeIDs(in.Status), d.pods)
	return in
}

func (d *redundancyDriver) pass() redundancyResult {
	d.t.Helper()
	result := advanceRedundancy(d.prev, d.input())
	status := result.Status
	d.launched = nil
	for _, launch := range result.Launches {
		if d.failLaunch {
			if result.OnLaunchFailure != nil {
				status = result.OnLaunchFailure
			}
			break
		}
		if err := d.g.launch(launch.NodeID, launch.RepairType); err != nil {
			d.t.Fatalf("launch %v: %v", launch, err)
		}
		d.launched = append(d.launched, launch)
	}
	persisted := roundTripRedundancy(d.t, status)
	if !equality.Semantic.DeepEqual(persisted, d.prev) {
		d.writes++
	}
	d.prev = persisted
	d.last = result
	d.now = d.now.Add(d.step)
	d.g.tick(d.now)
	return result
}

func (d *redundancyDriver) runUntil(t *testing.T, max int, done func(redundancyResult) bool) redundancyResult {
	t.Helper()
	for i := 0; i < max; i++ {
		result := d.pass()
		if done(result) {
			return result
		}
	}
	t.Fatalf("not done after %d passes; last condition %s/%s %q phase=%s", max,
		d.last.Condition.Status, d.last.Condition.Reason, d.last.Condition.Message, d.phase())
	return redundancyResult{}
}

func (d *redundancyDriver) phase() garagev1beta2.RedundancyPhase {
	if d.prev == nil || d.prev.Verification == nil {
		return ""
	}
	return d.prev.Verification.Phase
}

func verified(result redundancyResult) bool {
	return result.Condition.Status == metav1.ConditionTrue
}

func TestRedundancyProofHappyPath(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	phases := map[garagev1beta2.RedundancyPhase]bool{}
	var messages []string
	result := d.runUntil(t, 60, func(r redundancyResult) bool {
		phases[d.phase()] = true
		messages = append(messages, r.Condition.Reason+": "+r.Condition.Message)
		return verified(r)
	})
	for _, phase := range []garagev1beta2.RedundancyPhase{
		garagev1beta2.RedundancyPhaseSyncingMetadata, garagev1beta2.RedundancyPhaseScanningBlocks,
		garagev1beta2.RedundancyPhaseSettling, garagev1beta2.RedundancyPhaseVerified,
	} {
		if !phases[phase] {
			t.Errorf("phase %s never observed; messages:\n%s", phase, strings.Join(messages, "\n"))
		}
	}
	if result.Condition.Reason != garagev1beta1.ReasonRedundancyVerified ||
		result.Condition.Message != "Full redundancy verified on layout version 3 for 3 storage nodes" {
		t.Fatalf("condition = %+v", result.Condition)
	}
	verification := d.prev.Verification
	if verification.Trigger != garagev1beta2.RedundancyTriggerInitial || verification.VerifiedAt == nil ||
		verification.Evidence != nil || verification.LayoutVersion != 3 || verification.MembershipHash == "" {
		t.Fatalf("verification = %+v", verification)
	}
	tables, blocks := d.g.totalLaunches()
	if tables != 3 || blocks != 3 {
		t.Fatalf("launches tables=%d blocks=%d, want one of each per storage node", tables, blocks)
	}
	if len(d.prev.Nodes) != 3 || !d.prev.Nodes[0].Observed || d.prev.Nodes[0].ResyncQueueLength == nil {
		t.Fatalf("nodes = %+v", d.prev.Nodes)
	}

	// A verified, idle cluster is a fixed point: no writes, no repairs.
	writes := d.writes
	for i := 0; i < 20; i++ {
		r := d.pass()
		if len(r.Launches) != 0 || !verified(r) || r.Active {
			t.Fatalf("pass %d after Verified: %+v", i, r)
		}
	}
	if d.writes != writes {
		t.Fatalf("idle Verified cluster wrote status %d times", d.writes-writes)
	}
}

func TestRedundancyLayoutChangeSkipsMetadataStage(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.runUntil(t, 60, verified)
	tables, _ := d.g.totalLaunches()
	d.g.layoutVersion++
	r := d.pass()
	if d.prev.Verification.Trigger != garagev1beta2.RedundancyTriggerLayoutChanged {
		t.Fatalf("trigger = %s", d.prev.Verification.Trigger)
	}
	if d.phase() != garagev1beta2.RedundancyPhaseScanningBlocks || r.Condition.Reason != garagev1beta1.ReasonRedundancyVerifying {
		t.Fatalf("phase=%s condition=%+v", d.phase(), r.Condition)
	}
	d.runUntil(t, 60, verified)
	if after, _ := d.g.totalLaunches(); after != tables {
		t.Fatalf("a layout change launched %d more tables repairs; the settled history already proves metadata", after-tables)
	}
}

func TestRedundancyInvalidationTriggers(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(d *redundancyDriver)
		trigger garagev1beta2.RedundancyTrigger
		tables  bool
	}{
		{"pod replaced", func(d *redundancyDriver) { d.pods[1] = "pod-b2/0" }, garagev1beta2.RedundancyTriggerNodeChanged, true},
		{"container restarted", func(d *redundancyDriver) { d.pods[2] = "pod-c/1" }, garagev1beta2.RedundancyTriggerNodeChanged, true},
		{"requested", func(d *redundancyDriver) { d.token = "2026-10-06" }, garagev1beta2.RedundancyTriggerRequested, true},
		{"block errors", func(d *redundancyDriver) {
			d.g.blockErrors[redundancyNodeID(0)] = []garage.BlockError{{BlockHash: strings.Repeat("b", 64), ErrorCount: 1}}
		}, garagev1beta2.RedundancyTriggerBlockErrors, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newRedundancyDriver(t, 3)
			d.runUntil(t, 60, verified)
			tables, _ := d.g.totalLaunches()
			verifiedAt := d.prev.Verification.VerifiedAt.DeepCopy()
			tc.mutate(d)
			r := d.pass()
			if verified(r) || d.prev.Verification.Trigger != tc.trigger {
				t.Fatalf("condition=%+v trigger=%s", r.Condition, d.prev.Verification.Trigger)
			}
			if !d.prev.Verification.VerifiedAt.Equal(verifiedAt) {
				t.Fatalf("verifiedAt must survive invalidation")
			}
			after, _ := d.g.totalLaunches()
			if tc.tables && after != tables+3 {
				t.Fatalf("expected a fresh tables repair on every node, got %d", after-tables)
			}
		})
	}
}

func TestRedundancyRequestTokenIsHandledOnce(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.token = "first"
	d.runUntil(t, 60, verified)
	if d.prev.Verification.RequestToken != "first" || d.prev.Verification.Trigger != garagev1beta2.RedundancyTriggerInitial {
		t.Fatalf("verification = %+v", d.prev.Verification)
	}
	for i := 0; i < 5; i++ {
		if r := d.pass(); !verified(r) {
			t.Fatalf("an already handled token restarted the proof: %+v", r.Condition)
		}
	}
	d.token = ""
	if r := d.pass(); !verified(r) || d.prev.Verification.RequestToken != "first" {
		t.Fatalf("removing the annotation must not reset or forget the token")
	}
}

func TestRedundancyNodeDownAndPreconditions(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.runUntil(t, 60, verified)
	d.g.nodes[1].up = false
	r := d.pass()
	if r.Condition.Status != metav1.ConditionUnknown || r.Condition.Reason != garagev1beta1.ReasonRedundancyPreconditionsNotMet ||
		!strings.Contains(r.Condition.Message, "is down") {
		t.Fatalf("condition = %+v", r.Condition)
	}
	if d.prev.Verification.Trigger != garagev1beta2.RedundancyTriggerNodeDown || d.phase() != garagev1beta2.RedundancyPhasePending {
		t.Fatalf("verification = %+v", d.prev.Verification)
	}
	if d.prev.Nodes[1].Observed {
		t.Fatalf("down node must be observed=false")
	}
	startedAt := d.prev.Verification.StartedAt.DeepCopy()
	writes := d.writes
	for i := 0; i < 5; i++ {
		if r := d.pass(); len(r.Launches) != 0 {
			t.Fatalf("launched repairs while a node is down")
		}
	}
	if !d.prev.Verification.StartedAt.Equal(startedAt) || d.writes != writes {
		t.Fatalf("a node staying down must not rewrite status (writes=%d)", d.writes-writes)
	}
	d.g.nodes[1].up = true
	d.runUntil(t, 60, verified)
}

func TestRedundancyPreconditionMessages(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(d *redundancyDriver)
		want   string
	}{
		{"drain", func(d *redundancyDriver) { d.drain = true }, "storage drain"},
		{"staged", func(d *redundancyDriver) { d.g.staged = true }, "staged changes"},
		{"workers", func(d *redundancyDriver) { d.g.nodes[2].workersFail = true }, "did not report"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newRedundancyDriver(t, 3)
			tc.mutate(d)
			for i := 0; i < 3; i++ {
				r := d.pass()
				if len(r.Launches) != 0 || r.Condition.Reason != garagev1beta1.ReasonRedundancyPreconditionsNotMet ||
					!strings.Contains(r.Condition.Message, tc.want) {
					t.Fatalf("pass %d: launches=%v condition=%+v", i, r.Launches, r.Condition)
				}
			}
		})
	}
}

func TestRedundancyFollowerMirrorsProgressOnly(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.follower = true
	for i := 0; i < 5; i++ {
		r := d.pass()
		if len(r.Launches) != 0 || r.Active || r.Condition.Reason != garagev1beta1.ReasonRedundancyPreconditionsNotMet ||
			r.Condition.Message != redundancyFollowerMessage {
			t.Fatalf("follower pass %d: %+v", i, r)
		}
	}
	if d.prev.Verification != nil || len(d.prev.Nodes) != 3 {
		t.Fatalf("follower status = %+v", d.prev)
	}
}

func TestRedundancyNotObservedKeepsStatus(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.runUntil(t, 60, verified)
	before := d.prev.DeepCopy()
	d.observed = false
	r := d.pass()
	if r.Condition.Status != metav1.ConditionUnknown || r.Condition.Reason != garagev1beta1.ReasonRedundancyNotObserved ||
		!strings.Contains(r.Condition.Message, "last verified 2026-10-06T") {
		t.Fatalf("condition = %+v", r.Condition)
	}
	if !equality.Semantic.DeepEqual(before, d.prev) {
		t.Fatalf("an unobserved pass changed status")
	}
	d.observed = true
	if r := d.pass(); !verified(r) {
		t.Fatalf("observation returned but condition = %+v", r.Condition)
	}
}

func TestRedundancyGarageRestartDuringMetadataRelaunches(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.g.syncTicks = 4
	d.g.nodes[0].worker("object sync").Errors = 3 // errors from before the proof
	d.pass()                                      // launch
	if tables, _ := d.g.totalLaunches(); tables != 3 {
		t.Fatalf("tables = %d", tables)
	}
	d.g.restart(0, d.now) // the process restarts: the full sync and its counters are lost
	r := d.pass()
	if len(r.Launches) != 3 {
		t.Fatalf("restart must relaunch the tables repair, launches=%v", sortedLaunchKeys(r.Launches))
	}
	d.runUntil(t, 80, verified)
}

func TestRedundancyGarageRestartWithIdenticalWorkersWaitsForStartupSync(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.step = 10 * time.Second
	d.pass() // launch; the one-tick syncs finish before the next observation
	// Node 0 restarts with the same worker IDs and zero counters, so nothing
	// distinguishes it, but its own startup full sync (20 s after start)
	// must still be observed finishing before the metadata stage is accepted.
	d.g.restart(0, d.now)
	startupSyncObserved := false
	for i := 0; ; i++ {
		if i == 80 {
			t.Fatalf("not verified after %d passes", i)
		}
		// What the engine is about to observe on the restarted node.
		if d.g.nodes[0].syncLeft > 0 {
			startupSyncObserved = true
		}
		r := d.pass()
		if phase := d.phase(); (phase == garagev1beta2.RedundancyPhaseScanningBlocks ||
			phase == garagev1beta2.RedundancyPhaseSettling) && !startupSyncObserved {
			t.Fatalf("metadata accepted before the restarted node's startup sync was observed")
		}
		if verified(r) {
			break
		}
	}
}

func TestRedundancyGarageRestartDuringBlocksRebaselines(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.g.repairTicks = 6
	d.runUntil(t, 60, func(redundancyResult) bool {
		ev := d.prev.Verification.Evidence
		return ev != nil && len(ev.RepairWorkerIDs) == 3
	})
	d.g.restart(2, d.now)
	_, blocks := d.g.totalLaunches()
	d.runUntil(t, 80, verified)
	if _, after := d.g.totalLaunches(); after <= blocks {
		t.Fatalf("a restarted node must get a new blocks repair")
	}
}

func TestRedundancyRepairErrorsStall(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.g.repairErrors[redundancyNodeID(1)] = 2
	stalled := false
	d.runUntil(t, 80, func(r redundancyResult) bool {
		if r.Condition.Reason == garagev1beta1.ReasonRedundancyStalled && strings.Contains(r.Condition.Message, "reported errors") {
			stalled = true
		}
		return verified(r)
	})
	if !stalled {
		t.Fatalf("an errored repair worker must surface as Stalled before the clean retry")
	}
}

func TestRedundancyNoProgressStalls(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.g.syncTicks = 1 << 20 // the table sync never finishes and never shrinks
	d.step = 5 * time.Minute
	r := d.runUntil(t, 20, func(r redundancyResult) bool {
		return r.Condition.Reason == garagev1beta1.ReasonRedundancyStalled
	})
	if !strings.HasPrefix(r.Condition.Message, "no progress since ") {
		t.Fatalf("condition = %+v", r.Condition)
	}
}

func TestRedundancyGrowingBlockErrorsStall(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.g.syncTicks = 1 << 20
	d.pass()
	d.pass()
	d.g.blockErrors[redundancyNodeID(0)] = []garage.BlockError{{BlockHash: strings.Repeat("c", 64), ErrorCount: 1}}
	r := d.pass()
	if r.Condition.Reason != garagev1beta1.ReasonRedundancyStalled || !strings.Contains(r.Condition.Message, "growing") {
		t.Fatalf("condition = %+v", r.Condition)
	}
}

func TestRedundancyLaunchFailureIsRetried(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.failLaunch = true
	r := d.pass()
	if len(r.Launches) != 3 || d.prev.Verification.Evidence == nil || d.prev.Verification.Evidence.MetadataLaunchedAt != nil {
		t.Fatalf("a failed launch must not be recorded: %+v", d.prev.Verification.Evidence)
	}
	d.failLaunch = false
	if r := d.pass(); len(r.Launches) != 3 {
		t.Fatalf("next pass must relaunch, got %v", sortedLaunchKeys(r.Launches))
	}
	d.runUntil(t, 60, verified)
}

func TestRedundancyProgressWritesAreThrottled(t *testing.T) {
	d := newRedundancyDriver(t, 3)
	d.step = 10 * time.Second
	d.runUntil(t, 200, func(redundancyResult) bool { return d.phase() == garagev1beta2.RedundancyPhaseSettling })
	// While settling, the resync queue keeps changing (delayed rechecks), but
	// nodes[] may be rewritten at most once a minute and messages stay stable.
	writes := d.writes
	message := d.last.Condition.Message
	for i := 0; i < 12; i++ {
		d.g.mu.Lock()
		for _, node := range d.g.nodes {
			node.worker("Block resync worker #1").QueueLength = ptr.To(uint64(100 + i))
		}
		d.g.mu.Unlock()
		r := d.pass()
		if d.phase() != garagev1beta2.RedundancyPhaseSettling {
			break
		}
		if r.Condition.Message != message {
			t.Fatalf("settling message changed: %q -> %q", message, r.Condition.Message)
		}
	}
	if got := d.writes - writes; got > 3 {
		t.Fatalf("%d status writes in two minutes of ticking counters; want at most one per minute", got)
	}
}

func TestRedundancyCASKeepsFreshEvidence(t *testing.T) {
	base := redundancySnapshot{Status: &garagev1beta2.RedundancyStatus{
		Verification: &garagev1beta2.RedundancyVerificationStatus{Phase: garagev1beta2.RedundancyPhasePending},
	}}
	fresh := redundancySnapshot{
		Status: &garagev1beta2.RedundancyStatus{Verification: &garagev1beta2.RedundancyVerificationStatus{
			Phase: garagev1beta2.RedundancyPhaseScanningBlocks,
		}},
		Condition: &metav1.Condition{Type: garagev1beta1.ConditionFullyReplicated, Status: metav1.ConditionFalse, Reason: "Verifying"},
	}
	merged := garagev1beta2.GarageClusterStatus{
		Redundancy: &garagev1beta2.RedundancyStatus{Verification: &garagev1beta2.RedundancyVerificationStatus{
			Phase: garagev1beta2.RedundancyPhaseSyncingMetadata,
		}},
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue},
			{Type: garagev1beta1.ConditionFullyReplicated, Status: metav1.ConditionUnknown, Reason: "PreconditionsNotMet"},
		},
	}
	out := keepFreshRedundancyOnConflict(*merged.DeepCopy(), base, fresh)
	if out.Redundancy.Verification.Phase != garagev1beta2.RedundancyPhaseScanningBlocks || len(out.Conditions) != 2 ||
		out.Conditions[1].Reason != "Verifying" {
		t.Fatalf("stale pass overwrote fresh evidence: %+v", out)
	}
	unchanged := keepFreshRedundancyOnConflict(*merged.DeepCopy(), base, base)
	if unchanged.Redundancy.Verification.Phase != garagev1beta2.RedundancyPhaseSyncingMetadata {
		t.Fatalf("unchanged fresh value must keep this pass's result")
	}
}

func TestRedundancyMembershipHashIsOrderIndependent(t *testing.T) {
	a := redundancyMembershipHash([]string{"b", "a"}, []string{"p2/0", "p1/0"})
	b := redundancyMembershipHash([]string{"a", "b"}, []string{"p1/0", "p2/0"})
	if a != b || len(a) != 64 {
		t.Fatalf("hash %q vs %q", a, b)
	}
	if a == redundancyMembershipHash([]string{"a", "b"}, []string{"p1/1", "p2/0"}) {
		t.Fatalf("a restart count change must change the hash")
	}
}
