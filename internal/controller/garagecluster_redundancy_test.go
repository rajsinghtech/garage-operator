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
	"sigs.k8s.io/controller-runtime/pkg/event"

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
	token      string
	follower   bool
	siteRole   bool
	remote     bool
	drain      bool
	observed   bool
	failLaunch bool

	last     redundancyResult
	writes   int
	launched []redundancyLaunch
}

func newRedundancyDriver(t *testing.T) *redundancyDriver {
	t.Helper()
	return &redundancyDriver{
		t:        t,
		g:        newRedundancyGarage(3),
		now:      time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		step:     30 * time.Second,
		quiet:    5 * time.Minute,
		observed: true,
	}
}

// newRequestedDriver is a driver whose cluster carries a verify-redundancy
// request, the only way a proof starts without a topology change.
func newRequestedDriver(t *testing.T) *redundancyDriver {
	d := newRedundancyDriver(t)
	d.token = "2026-10-06"
	return d
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
	in.ClusterUID = redundancyTestClusterUID
	in.ClusterName = "garage"
	in.Namespace = "garage"
	in.HasRemoteClusters = d.remote
	in.SiteRoleSet = d.siteRole || d.follower
	in.Follower = d.follower
	in.DrainActive = d.drain
	in.RequestToken = d.token
	in.Observed = d.observed
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

func reason(want string) func(redundancyResult) bool {
	return func(r redundancyResult) bool { return r.Condition.Reason == want }
}

// --- A1: no automatic proof on upgrade or first adoption ------------------

func TestRedundancyUpgradeRecordsBaselineOnly(t *testing.T) {
	d := newRedundancyDriver(t)
	r := d.pass()
	if r.Condition.Status != metav1.ConditionUnknown || r.Condition.Reason != garagev1beta1.ReasonRedundancyNotVerified ||
		!strings.Contains(r.Condition.Message, "never starts one on upgrade") || r.Active {
		t.Fatalf("first pass condition = %+v active=%v", r.Condition, r.Active)
	}
	v := d.prev.Verification
	if v.Phase != garagev1beta2.RedundancyPhaseIdle || v.Trigger != "" || v.LayoutVersion != 3 || len(v.TopologyHash) != 64 || v.Evidence != nil {
		t.Fatalf("baseline = %+v", v)
	}
	writes := d.writes
	// Garage restarts (a rolling upgrade) and tag-only layout changes are no
	// topology change.
	for i := 0; i < 30; i++ {
		switch i {
		case 3:
			d.g.restart(0, d.now)
		case 6:
			d.g.restart(1, d.now)
		case 9:
			d.g.mu.Lock()
			d.g.nodes[2].extraTags = []string{"rack:r9"}
			d.g.layoutVersion++
			d.g.mu.Unlock()
		}
		r := d.pass()
		if len(r.Launches) != 0 || r.Condition.Reason != garagev1beta1.ReasonRedundancyNotVerified || r.Active {
			t.Fatalf("pass %d after the baseline: launches=%v condition=%+v", i, sortedLaunchKeys(r.Launches), r.Condition)
		}
	}
	if tables, blocks := d.g.totalLaunches(); tables != 0 || blocks != 0 {
		t.Fatalf("baseline launched tables=%d blocks=%d", tables, blocks)
	}
	if d.prev.Verification.LayoutVersion != 4 || d.phase() != garagev1beta2.RedundancyPhaseIdle {
		t.Fatalf("a tag-only change must only rebind the layout version: %+v", d.prev.Verification)
	}
	// Besides the layout version, only the throttled nodes[] mirror may move
	// (the restarted nodes' startup syncs change their counters).
	want := v.DeepCopy()
	want.LayoutVersion = 4
	if !equality.Semantic.DeepEqual(want, d.prev.Verification) {
		t.Fatalf("verification moved beyond the layout version:\nwant %+v\ngot  %+v", want, d.prev.Verification)
	}
	if got := d.writes - writes; got > 4 {
		t.Fatalf("idle baseline wrote status %d times", got)
	}
}

func TestRedundancyEmptyLayoutIsNoBaseline(t *testing.T) {
	d := newRedundancyDriver(t)
	d.g = newRedundancyGarage(0)
	d.pass()
	if v := d.prev.Verification; v == nil || v.Phase != garagev1beta2.RedundancyPhaseIdle || v.TopologyHash != "" {
		t.Fatalf("empty layout baseline = %+v", v)
	}
	// The new cluster's first layout assignment is recorded, not verified.
	for i := 0; i < 3; i++ {
		d.g.addNode(redundancyTestClusterUID)
	}
	for i := 0; i < 4; i++ {
		if r := d.pass(); len(r.Launches) != 0 || r.Condition.Reason != garagev1beta1.ReasonRedundancyNotVerified {
			t.Fatalf("first assignment started a proof: %+v %v", r.Condition, r.Launches)
		}
	}
	if v := d.prev.Verification; v.Phase != garagev1beta2.RedundancyPhaseIdle || len(v.TopologyHash) != 64 {
		t.Fatalf("baseline after first assignment = %+v", v)
	}
}

func TestRedundancyNodeDownAfterVerifiedStartsNothing(t *testing.T) {
	d := newRequestedDriver(t)
	d.runUntil(t, 150, verified)
	verifiedAt := d.prev.Verification.VerifiedAt.DeepCopy()
	tables, blocks := d.g.totalLaunches()
	d.g.nodes[1].up = false
	r := d.pass()
	if r.Condition.Reason != garagev1beta1.ReasonRedundancyNotVerified || d.phase() != garagev1beta2.RedundancyPhaseIdle ||
		!strings.Contains(r.Condition.Message, "was down after the last proof") {
		t.Fatalf("condition = %+v phase=%s", r.Condition, d.phase())
	}
	d.g.nodes[1].up = true
	for i := 0; i < 20; i++ {
		if r := d.pass(); len(r.Launches) != 0 || r.Active {
			t.Fatalf("a returning node started repairs: %v", sortedLaunchKeys(r.Launches))
		}
	}
	if t2, b2 := d.g.totalLaunches(); t2 != tables || b2 != blocks {
		t.Fatalf("launches moved after the outage")
	}
	if !d.prev.Verification.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("verifiedAt must survive the outage")
	}
}

func TestRedundancyTopologyChangeStartsBlocksOnlyProof(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(g *redundancyGarage)
		trigger garagev1beta2.RedundancyTrigger
		nodes   int
	}{
		{"node added", func(g *redundancyGarage) { g.addNode(redundancyTestClusterUID) }, garagev1beta2.RedundancyTriggerNodeChanged, 4},
		{"capacity changed", func(g *redundancyGarage) {
			g.mu.Lock()
			g.nodes[1].capacity = 2 << 30
			g.layoutVersion++
			g.mu.Unlock()
		}, garagev1beta2.RedundancyTriggerLayoutChanged, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newRedundancyDriver(t)
			d.pass() // baseline
			tc.mutate(d.g)
			d.pass()
			if d.prev.Verification.Trigger != tc.trigger {
				t.Fatalf("trigger = %q", d.prev.Verification.Trigger)
			}
			d.runUntil(t, 200, verified)
			tables, blocks := d.g.totalLaunches()
			if tables != 0 || blocks != tc.nodes || d.g.maxConcurrent != 1 {
				t.Fatalf("tables=%d blocks=%d maxConcurrent=%d; want blocks only, one node at a time", tables, blocks, d.g.maxConcurrent)
			}
		})
	}
}

func TestRedundancyRequestTokenIsHandledOnce(t *testing.T) {
	d := newRequestedDriver(t)
	d.runUntil(t, 150, verified)
	if d.prev.Verification.RequestToken != "2026-10-06" || d.prev.Verification.Trigger != garagev1beta2.RedundancyTriggerRequested {
		t.Fatalf("verification = %+v", d.prev.Verification)
	}
	for i := 0; i < 5; i++ {
		if r := d.pass(); !verified(r) {
			t.Fatalf("an already handled token restarted the proof: %+v", r.Condition)
		}
	}
	d.token = ""
	if r := d.pass(); !verified(r) || d.prev.Verification.RequestToken != "2026-10-06" {
		t.Fatalf("removing the annotation must not reset or forget the token")
	}
	d.token = "again"
	d.pass()
	if d.phase() != garagev1beta2.RedundancyPhaseSyncingMetadata || d.prev.Verification.Trigger != garagev1beta2.RedundancyTriggerRequested {
		t.Fatalf("a new token must start a full proof: %+v", d.prev.Verification)
	}
}

// --- A2: one storage node at a time --------------------------------------

func TestRedundancyRequestedProofRunsOneNodeAtATime(t *testing.T) {
	d := newRequestedDriver(t)
	phases := map[garagev1beta2.RedundancyPhase]bool{}
	var messages []string
	result := d.runUntil(t, 150, func(r redundancyResult) bool {
		phases[d.phase()] = true
		messages = append(messages, r.Condition.Reason+": "+r.Condition.Message)
		if len(r.Launches) > 1 {
			t.Fatalf("one pass launched %v", sortedLaunchKeys(r.Launches))
		}
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
	want := []string{}
	for i := 0; i < 3; i++ {
		want = append(want, shortID(redundancyNodeID(i))+":tables", shortID(redundancyNodeID(i))+":blocks")
	}
	if strings.Join(d.g.launchLog, ",") != strings.Join(want, ",") || d.g.maxConcurrent != 1 {
		t.Fatalf("launch order %v (maxConcurrent %d), want %v", d.g.launchLog, d.g.maxConcurrent, want)
	}
	if result.Condition.Message != "Full redundancy verified on layout version 3 for the 3 storage nodes this site owns" {
		t.Fatalf("condition = %+v", result.Condition)
	}
	joined := strings.Join(messages, "\n")
	for _, fragment := range []string{"(1 of 3)", "(3 of 3)", "pausing until"} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("no message with %q:\n%s", fragment, joined)
		}
	}
	v := d.prev.Verification
	if v.VerifiedAt == nil || v.Evidence != nil || v.CurrentNodeID != "" || len(v.CompletedNodeIDs) != 3 {
		t.Fatalf("verification = %+v", v)
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

func TestRedundancyNodesPauseBetweenTurns(t *testing.T) {
	d := newRequestedDriver(t)
	var firstDone, secondLaunch time.Time
	d.runUntil(t, 150, func(r redundancyResult) bool {
		if firstDone.IsZero() && len(d.prev.Verification.CompletedNodeIDs) == 1 {
			firstDone = d.now
		}
		for _, launch := range r.Launches {
			if launch.NodeID == redundancyNodeID(1) && secondLaunch.IsZero() {
				secondLaunch = d.now
			}
		}
		return verified(r)
	})
	if gap := secondLaunch.Sub(firstDone); gap < redundancyNodePause {
		t.Fatalf("node 2 started %s after node 1 finished; want at least %s", gap, redundancyNodePause)
	}
}

func TestRedundancyPreconditionsPauseInPlace(t *testing.T) {
	d := newRequestedDriver(t)
	d.g.repairTicks = 6
	d.runUntil(t, 60, func(redundancyResult) bool {
		ev := d.prev.Verification.Evidence
		return ev != nil && ev.RepairWorkerID != 0
	})
	before := d.prev.Verification.DeepCopy()
	d.drain = true
	for i := 0; i < 4; i++ {
		r := d.pass()
		if len(r.Launches) != 0 || r.Condition.Reason != garagev1beta1.ReasonRedundancyPreconditionsNotMet ||
			!strings.Contains(r.Condition.Message, "storage drain") {
			t.Fatalf("pass %d: launches=%v condition=%+v", i, r.Launches, r.Condition)
		}
	}
	if d.prev.Verification.CurrentNodeID != before.CurrentNodeID || d.prev.Verification.Evidence.RepairWorkerID != before.Evidence.RepairWorkerID {
		t.Fatalf("a precondition must not discard the node's turn")
	}
	d.drain = false
	_, blocks := d.g.totalLaunches()
	d.runUntil(t, 150, verified)
	if _, after := d.g.totalLaunches(); after != 3 || blocks != 1 {
		t.Fatalf("resuming relaunched: blocks before=%d after=%d", blocks, after)
	}
}

func TestRedundancyGarageRestartDuringTablesRelaunchesThatNode(t *testing.T) {
	d := newRequestedDriver(t)
	d.g.syncTicks = 4
	d.g.nodes[0].worker("object sync").Errors = 3 // errors from before the proof
	d.pass()                                      // launch on node 0
	d.g.restart(0, d.now)                         // the full sync and its counters are lost
	r := d.pass()
	if len(r.Launches) != 1 || r.Launches[0].NodeID != redundancyNodeID(0) || r.Launches[0].RepairType != redundancyRepairTypeTables {
		t.Fatalf("restart must relaunch node 0's tables repair, launches=%v", sortedLaunchKeys(r.Launches))
	}
	d.runUntil(t, 200, verified)
}

func TestRedundancyGarageRestartWithIdenticalWorkersWaitsForStartupSync(t *testing.T) {
	d := newRequestedDriver(t)
	d.step = 10 * time.Second
	d.pass() // launch on node 0; the one-tick sync finishes before the next observation
	// Node 0 restarts with the same worker IDs and zero counters, so nothing
	// distinguishes it, but its own startup full sync (20 s after start)
	// must still be observed finishing before its tables stage is accepted.
	d.g.restart(0, d.now)
	startupSyncObserved := false
	for i := 0; ; i++ {
		if i == 400 {
			t.Fatalf("not verified after %d passes", i)
		}
		if d.g.nodes[0].syncLeft > 0 {
			startupSyncObserved = true
		}
		r := d.pass()
		if d.phase() == garagev1beta2.RedundancyPhaseScanningBlocks && !startupSyncObserved {
			t.Fatalf("tables accepted before the restarted node's startup sync was observed")
		}
		if verified(r) {
			break
		}
	}
}

func TestRedundancyGarageRestartDuringBlocksRelaunchesThatNode(t *testing.T) {
	d := newRequestedDriver(t)
	d.g.repairTicks = 6
	d.runUntil(t, 60, func(redundancyResult) bool {
		ev := d.prev.Verification.Evidence
		return ev != nil && ev.RepairWorkerID != 0
	})
	d.g.restart(0, d.now)
	d.runUntil(t, 300, verified)
	if got := d.g.blocksLaunches[redundancyNodeID(0)]; got != 2 {
		t.Fatalf("node 0 got %d blocks repairs, want 2", got)
	}
}

func TestRedundancyRepairErrorsStallThenRetry(t *testing.T) {
	d := newRequestedDriver(t)
	d.g.repairErrors[redundancyNodeID(1)] = 2
	stalled := false
	d.runUntil(t, 200, func(r redundancyResult) bool {
		if r.Condition.Reason == garagev1beta1.ReasonRedundancyStalled && strings.Contains(r.Condition.Message, "reported errors") {
			stalled = true
		}
		return verified(r)
	})
	if !stalled || d.g.blocksLaunches[redundancyNodeID(1)] != 2 {
		t.Fatalf("stalled=%v node 1 blocks=%d", stalled, d.g.blocksLaunches[redundancyNodeID(1)])
	}
}

func TestRedundancyNoProgressStalls(t *testing.T) {
	d := newRequestedDriver(t)
	d.g.syncTicks = 1 << 20 // the table sync never finishes and never shrinks
	d.step = 5 * time.Minute
	r := d.runUntil(t, 20, reason(garagev1beta1.ReasonRedundancyStalled))
	if !strings.HasPrefix(r.Condition.Message, "no progress since ") {
		t.Fatalf("condition = %+v", r.Condition)
	}
}

func TestRedundancyGrowingBlockErrorsStall(t *testing.T) {
	d := newRequestedDriver(t)
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
	d := newRequestedDriver(t)
	d.failLaunch = true
	r := d.pass()
	ev := d.prev.Verification.Evidence
	if len(r.Launches) != 1 || ev == nil || ev.StageLaunchedAt != nil || ev.Launches != 0 {
		t.Fatalf("a failed launch must not be recorded: %+v", ev)
	}
	d.failLaunch = false
	if r := d.pass(); len(r.Launches) != 1 {
		t.Fatalf("next pass must relaunch, got %v", sortedLaunchKeys(r.Launches))
	}
	d.runUntil(t, 150, verified)
}

func TestRedundancyProgressWritesAreThrottled(t *testing.T) {
	d := newRequestedDriver(t)
	d.step = 10 * time.Second
	d.runUntil(t, 600, func(redundancyResult) bool { return d.phase() == garagev1beta2.RedundancyPhaseSettling })
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

// --- A3: only the layout-writer site, only its own nodes ------------------

func TestRedundancyFederatedSiteWithoutSiteRoleRunsNothing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(d *redundancyDriver)
	}{
		{"remoteClusters set", func(d *redundancyDriver) { d.remote = true }},
		{"foreign UID in layout", func(d *redundancyDriver) { d.g.addNode("other-site-uid") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newRequestedDriver(t)
			tc.mutate(d)
			for i := 0; i < 10; i++ {
				r := d.pass()
				if len(r.Launches) != 0 || r.Active || r.Condition.Status != metav1.ConditionUnknown ||
					r.Condition.Reason != garagev1beta1.ReasonRedundancySiteRoleUnset ||
					!strings.Contains(r.Condition.Message, "siteRole is unset") {
					t.Fatalf("pass %d: launches=%v condition=%+v", i, r.Launches, r.Condition)
				}
			}
			if d.prev.Verification != nil || len(d.prev.Nodes) == 0 {
				t.Fatalf("status = %+v", d.prev)
			}
		})
	}
}

func TestRedundancyWriterVerifiesOnlyOwnedNodes(t *testing.T) {
	d := newRequestedDriver(t)
	d.siteRole = true
	foreign := d.g.addNode("other-site-uid")
	r := d.runUntil(t, 200, verified)
	if d.g.tablesLaunches[foreign.id] != 0 || d.g.blocksLaunches[foreign.id] != 0 {
		t.Fatalf("the writer launched repairs on another site's node")
	}
	if tables, blocks := d.g.totalLaunches(); tables != 3 || blocks != 3 {
		t.Fatalf("tables=%d blocks=%d", tables, blocks)
	}
	if !strings.Contains(r.Condition.Message, "for the 3 storage nodes this site owns; 1 storage nodes of other sites are not covered") {
		t.Fatalf("condition = %+v", r.Condition)
	}
}

func TestRedundancyNameTagIsNotOwnershipAcrossSites(t *testing.T) {
	d := newRequestedDriver(t)
	d.siteRole = true
	d.remote = true
	unattributed := d.g.addNode("") // same cluster:garage/garage tag, no UID
	d.runUntil(t, 200, verified)
	if d.g.tablesLaunches[unattributed.id] != 0 || d.g.blocksLaunches[unattributed.id] != 0 {
		t.Fatalf("a name-tagged role without a UID tag must not count as owned on a federated site")
	}
}

func TestRedundancyFollowerMirrorsProgressOnly(t *testing.T) {
	d := newRequestedDriver(t)
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

// --- A4: unreachable nodes are deferred, not blocking ---------------------

func TestRedundancyDownNodeIsDeferredThenRetried(t *testing.T) {
	d := newRequestedDriver(t)
	down := d.g.nodes[1]
	down.up = false
	r := d.runUntil(t, 200, reason(garagev1beta1.ReasonRedundancyPartial))
	if d.phase() != garagev1beta2.RedundancyPhasePartial || len(d.prev.DeferredNodes) != 1 ||
		d.prev.DeferredNodes[0].NodeID != down.id || d.prev.DeferredNodes[0].Reason != garagev1beta2.RedundancyDeferDown ||
		d.prev.DeferredNodes[0].RetryAfter == nil {
		t.Fatalf("phase=%s deferred=%+v", d.phase(), d.prev.DeferredNodes)
	}
	if !strings.Contains(r.Condition.Message, "2 of 3 owned storage nodes finished; deferred: "+shortID(down.id)+" (Down)") ||
		!r.Active || r.Condition.Status != metav1.ConditionFalse {
		t.Fatalf("condition = %+v active=%v", r.Condition, r.Active)
	}
	// While it stays down nothing more is launched and status is quiet.
	writes := d.writes
	for i := 0; i < 10; i++ {
		if r := d.pass(); len(r.Launches) != 0 || r.Condition.Message != d.last.Condition.Message {
			t.Fatalf("Partial launched or churned: %v %q", sortedLaunchKeys(r.Launches), r.Condition.Message)
		}
	}
	if d.writes != writes {
		t.Fatalf("Partial with a node down wrote status %d times", d.writes-writes)
	}
	down.up = true
	d.runUntil(t, 300, verified)
	if d.g.tablesLaunches[down.id] != 1 || d.g.blocksLaunches[down.id] != 1 {
		t.Fatalf("returned node got tables=%d blocks=%d", d.g.tablesLaunches[down.id], d.g.blocksLaunches[down.id])
	}
	// The other nodes synced tables while a peer was down: each gets exactly
	// one tables-only recheck, no second blocks repair.
	for _, node := range []*redundancyGarageNode{d.g.nodes[0], d.g.nodes[2]} {
		if d.g.tablesLaunches[node.id] != 2 || d.g.blocksLaunches[node.id] != 1 {
			t.Fatalf("node %s tables=%d blocks=%d", shortID(node.id), d.g.tablesLaunches[node.id], d.g.blocksLaunches[node.id])
		}
	}
	if d.g.maxConcurrent != 1 || d.prev.DeferredNodes != nil {
		t.Fatalf("maxConcurrent=%d deferred=%+v", d.g.maxConcurrent, d.prev.DeferredNodes)
	}
}

func TestRedundancyFlappingNodeIsRetriedAtMostEveryRetryDelay(t *testing.T) {
	d := newRequestedDriver(t)
	flapping := d.g.nodes[2]
	flapping.up = false
	d.runUntil(t, 200, reason(garagev1beta1.ReasonRedundancyPartial))
	deferredAt := d.now
	// Up for one pass, down again, before retryAfter: no turn.
	flapping.up = true
	if r := d.pass(); len(r.Launches) != 0 {
		t.Fatalf("launched before retryAfter (rechecks must wait for the deferred node's turn): %v", r.Launches)
	}
	flapping.up = false
	d.pass()
	flapping.up = true
	var retriedAt time.Time
	d.runUntil(t, 100, func(r redundancyResult) bool {
		for _, launch := range r.Launches {
			if launch.NodeID == flapping.id {
				retriedAt = d.now
				return true
			}
		}
		return false
	})
	if retriedAt.Sub(deferredAt) < redundancyDeferredRetryDelay-d.step {
		t.Fatalf("retried %s after deferral, want at least %s", retriedAt.Sub(deferredAt), redundancyDeferredRetryDelay)
	}
}

func TestRedundancyRepairFailureDefersNodeAndIsBounded(t *testing.T) {
	d := newRequestedDriver(t)
	failing := redundancyNodeID(1)
	d.g.repairErrors[failing] = 1
	d.g.repairsAlwaysFail = true
	r := d.runUntil(t, 300, reason(garagev1beta1.ReasonRedundancyPartial))
	if d.g.blocksLaunches[failing] != redundancyMaxLaunches || len(d.prev.DeferredNodes) != 1 ||
		d.prev.DeferredNodes[0].Reason != garagev1beta2.RedundancyDeferRepairFailed || d.prev.DeferredNodes[0].RetryAfter != nil ||
		!strings.Contains(r.Condition.Message, "annotation to a new value to retry failed nodes") || r.Active {
		t.Fatalf("blocks=%d deferred=%+v condition=%+v active=%v", d.g.blocksLaunches[failing], d.prev.DeferredNodes, r.Condition, r.Active)
	}
	writes := d.writes
	for i := 0; i < 30; i++ {
		if r := d.pass(); len(r.Launches) != 0 {
			t.Fatalf("a RepairFailed node was retried on its own: %v", sortedLaunchKeys(r.Launches))
		}
	}
	if d.writes != writes {
		t.Fatalf("Partial wrote status %d times", d.writes-writes)
	}
	d.g.repairsAlwaysFail = false
	delete(d.g.repairErrors, failing)
	d.token = "retry"
	d.runUntil(t, 300, verified)
}

func TestRedundancyTableSyncErrorsWithEveryPeerUpAreBounded(t *testing.T) {
	d := newRequestedDriver(t)
	for i := 0; i < 60; i++ {
		d.pass()
		d.g.nodes[0].worker("object sync").Errors++ // a partition fails again
	}
	if got := d.g.tablesLaunches[redundancyNodeID(0)]; got != redundancyMaxLaunches {
		t.Fatalf("node 0 got %d tables repairs, want %d", got, redundancyMaxLaunches)
	}
	if deferred := d.prev.DeferredNodes; len(deferred) != 1 || deferred[0].Reason != garagev1beta2.RedundancyDeferRepairFailed {
		t.Fatalf("deferred = %+v", deferred)
	}
}

func TestRedundancyNotObservedKeepsStatus(t *testing.T) {
	d := newRequestedDriver(t)
	d.runUntil(t, 150, verified)
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

func TestRedundancyTopologyHashIgnoresTagsAndOrder(t *testing.T) {
	in := func(roles ...garage.LayoutNodeRole) redundancyInput {
		return redundancyInput{ClusterUID: "u", Layout: &garage.ClusterLayout{Roles: roles}}
	}
	a := garage.LayoutNodeRole{ID: "a", Zone: "z1", Capacity: ptr.To(uint64(1)), Tags: []string{"cluster-uid:u"}}
	b := garage.LayoutNodeRole{ID: "b", Zone: "z1", Capacity: ptr.To(uint64(1)), Tags: []string{"cluster-uid:u"}}
	gw := garage.LayoutNodeRole{ID: "g", Zone: "z1", Tags: []string{"cluster-uid:u"}}
	_, _, _, h1 := redundancyLayoutOwnership(in(a, b, gw))
	b2 := b
	b2.Tags = []string{"cluster-uid:u", "rack:9"}
	_, _, _, h2 := redundancyLayoutOwnership(in(b2, a))
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("tags, order or gateways changed the hash: %s vs %s", h1, h2)
	}
	b3 := b
	b3.Zone = "z2"
	_, _, _, h3 := redundancyLayoutOwnership(in(a, b3))
	if h3[:32] != h1[:32] || h3[32:] == h1[32:] {
		t.Fatalf("a zone change must change only the role half: %s vs %s", h1, h3)
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

// TestRedundancyWatchContract pins what #482's status-only watch filter means
// for the proof: its own status writes never wake the controller (a running
// proof continues on its own redundancyActiveRequeue), while a new
// verify-redundancy token does.
func TestRedundancyWatchContract(t *testing.T) {
	p := garageClusterPrimaryPredicate()
	oldCluster := predicateTestCluster()

	statusOnly := oldCluster.DeepCopy()
	statusOnly.Status.Redundancy = &garagev1beta2.RedundancyStatus{
		Verification: &garagev1beta2.RedundancyVerificationStatus{Phase: garagev1beta2.RedundancyPhaseScanningBlocks},
	}
	statusOnly.Status.Conditions = []metav1.Condition{{Type: garagev1beta1.ConditionFullyReplicated, Status: metav1.ConditionFalse}}
	if p.Update(event.UpdateEvent{ObjectOld: oldCluster, ObjectNew: statusOnly}) {
		t.Fatal("a status.redundancy write must not re-enter Reconcile")
	}
	if redundancyActiveRequeue <= 0 || redundancyActiveRequeue > RequeueAfterShort {
		t.Fatalf("redundancyActiveRequeue = %s; a running proof needs its own prompt requeue", redundancyActiveRequeue)
	}

	requested := oldCluster.DeepCopy()
	requested.Annotations[garagev1beta1.AnnotationVerifyRedundancy] = "2026-10-06"
	if !p.Update(event.UpdateEvent{ObjectOld: oldCluster, ObjectNew: requested}) {
		t.Fatal("a new verify-redundancy token must wake Reconcile")
	}
}
