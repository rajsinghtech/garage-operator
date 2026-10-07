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

// Full-redundancy verification (#474). See
// docs/design/2026-10-06-full-redundancy-status-design.md.
//
// advanceRedundancy is a pure function of the previously persisted
// status.redundancy and one pass of Garage observations. It returns the next
// status, the FullyReplicated condition, and the repairs to launch. All proof
// state lives in status, so an operator restart resumes from the last write.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	// redundancyStallThreshold is D6's fixed no-progress window.
	redundancyStallThreshold = 30 * time.Minute
	// redundancyBlockErrorWindow is D6's window for a growing block-error count.
	redundancyBlockErrorWindow = 30 * time.Minute
	// redundancyProgressWriteInterval bounds how often nodes[] is rewritten
	// and how far lastProgressAt must move before it is rewritten.
	redundancyProgressWriteInterval = time.Minute
	// redundancyMetadataSettleGap is the minimum time between the two passes
	// that must both see the node's table sync workers idle and empty.
	redundancyMetadataSettleGap = 30 * time.Second
	// redundancyMaxLaunches bounds the launches of one node's stage: the
	// first launch plus two retries after a Garage restart or a scan that
	// reported errors. Then the node is deferred as RepairFailed.
	redundancyMaxLaunches = 3
	// redundancyNodePause separates two storage nodes' repairs.
	redundancyNodePause = 2 * time.Minute
	// redundancyDeferredRetryDelay is the earliest retry of a node that was
	// down or not reporting, so a flapping node does not get repeated repairs.
	redundancyDeferredRetryDelay = 10 * time.Minute
	// redundancyActiveRequeue is the longest status-pass interval while a
	// proof is running, so it never depends on status-only watch events.
	redundancyActiveRequeue = RequeueAfterShort
	// redundancyRemoteHoldDown is how long a federated site waits after the
	// last blocks repair it saw on a remote storage node before it starts a
	// proof. It covers the gap between two blocks repairs of one remote proof
	// (tables stage, settle gap and pause) for tables stages up to ~12 min.
	redundancyRemoteHoldDown = 15 * time.Minute
	// redundancyFollowerOffsetSlots spreads followers' hold-downs over
	// 1..10 extra minutes so two followers do not resume together.
	redundancyFollowerOffsetSlots = 10
	// redundancyRemoteBumpInterval limits lastRemoteRepairAt writes while a
	// remote repair runs.
	redundancyRemoteBumpInterval = time.Minute

	redundancyMaxNodes           = 256
	redundancyMaxProgressLength  = 64
	redundancyRepairTypeTables   = "Tables"
	redundancyRepairTypeBlocks   = garagev1beta1.RepairTypeBlocks
	redundancyTableSyncSuffix    = " sync"
	redundancyTableMerkleSuffix  = " Merkle"
	redundancyTableQueueSuffix   = " queue"
	redundancyNotObservedMessage = "Garage Admin API did not answer; redundancy cannot be observed"
)

// redundancyMetadataTables are the tables a Garage "tables" repair fully
// syncs (src/api/admin/repair.rs, unchanged from the floor release to main-v2).
var redundancyMetadataTables = []string{"block_ref", "bucket_v2", "key", "object", "version"}

// redundancyInput is one status pass worth of observations.
type redundancyInput struct {
	Now         time.Time
	QuietPeriod time.Duration

	// Cluster identity, for deciding which storage roles run at this site.
	ClusterUID        string
	ClusterName       string
	Namespace         string
	HasRemoteClusters bool
	// LocalNodeIDs are the Garage node IDs of this GarageCluster's
	// non-external, non-gateway GarageNodes: the processes at this site.
	LocalNodeIDs []string
	// ExternalNodeIDs are the IDs of this GarageCluster's external
	// GarageNodes (on a writer, typically the follower sites' nodes).
	ExternalNodeIDs []string
	// SiteRoleSet is true when spec.layoutManagement.siteRole is set.
	SiteRoleSet bool
	// TopologyAutoProof is
	// spec.layoutManagement.redundancyVerification.onTopologyChange.
	TopologyAutoProof bool

	Follower              bool
	DrainActive           bool
	FactorMigrationActive bool
	RequestToken          string

	// Observed is false when any Admin API read below failed.
	Observed    bool
	Health      *garage.ClusterHealth
	Status      *garage.ClusterStatus
	History     *garage.LayoutHistoryResponse
	Layout      *garage.ClusterLayout
	Workers     *garage.ListWorkersResponse
	BlockErrors *garage.ListBlockErrorsResponse
}

type redundancyLaunch struct {
	NodeID     string
	RepairType string
}

type redundancyResult struct {
	// Status is the next status.redundancy (nil keeps it absent).
	Status *garagev1beta2.RedundancyStatus
	// OnLaunchFailure replaces Status when the launch fails.
	OnLaunchFailure *garagev1beta2.RedundancyStatus
	Launches        []redundancyLaunch
	Condition       metav1.Condition
	// Active is true while the proof has work it checks for every pass.
	Active bool
}

// redundancyObservation is the per-pass digest of the Garage responses.
type redundancyObservation struct {
	LayoutVersion  int64
	StorageNodeIDs []string
	DownNodeIDs    []string
	// OwnedNodeIDs are the local storage nodes (they run at this site),
	// sorted. Only they are ever repaired.
	OwnedNodeIDs []string
	// RemoteNodeIDs are the other storage roles of the layout, sorted.
	RemoteNodeIDs []string
	// OtherNodes is len(RemoteNodeIDs).
	OtherNodes int
	// Federated is true when spec.remoteClusters is set or the layout holds
	// a storage role tagged with another GarageCluster's UID.
	Federated bool
	// TopologyHash fingerprints storage role IDs (first half) and their
	// zones and capacities (second half). Empty without a layout.
	TopologyHash  string
	Workers       map[string][]garage.WorkerInfo
	WorkersOK     map[string]bool
	BlockErrors   map[string][]garage.BlockError
	BlockErrorsOK map[string]bool
	// BlockErrorTotal is the number of distinct block hashes with errors.
	BlockErrorTotal int64
}

func newRedundancyObservation(in redundancyInput) redundancyObservation {
	obs := redundancyObservation{
		Workers:       map[string][]garage.WorkerInfo{},
		WorkersOK:     map[string]bool{},
		BlockErrors:   map[string][]garage.BlockError{},
		BlockErrorsOK: map[string]bool{},
		Federated:     in.HasRemoteClusters,
	}
	if in.History != nil {
		obs.LayoutVersion = int64(in.History.CurrentVersion)
	} else if in.Status != nil {
		obs.LayoutVersion = int64(in.Status.LayoutVersion)
	}
	if in.Status != nil {
		for i := range in.Status.Nodes {
			node := &in.Status.Nodes[i]
			if node.Role == nil || node.Role.Capacity == nil || *node.Role.Capacity == 0 {
				continue
			}
			obs.StorageNodeIDs = append(obs.StorageNodeIDs, node.ID)
			if !node.IsUp {
				obs.DownNodeIDs = append(obs.DownNodeIDs, node.ID)
			}
		}
	}
	obs.StorageNodeIDs = normalizedNodeIDs(obs.StorageNodeIDs)
	obs.DownNodeIDs = normalizedNodeIDs(obs.DownNodeIDs)
	if in.Layout != nil {
		obs.OwnedNodeIDs, obs.RemoteNodeIDs, obs.Federated, obs.TopologyHash = redundancyLayoutOwnership(in)
		obs.OtherNodes = len(obs.RemoteNodeIDs)
	}
	if in.Workers != nil {
		for nodeID, workers := range in.Workers.Success {
			obs.Workers[nodeID] = workers
			obs.WorkersOK[nodeID] = true
		}
	}
	hashes := map[string]struct{}{}
	if in.BlockErrors != nil {
		for nodeID, records := range in.BlockErrors.Success {
			obs.BlockErrors[nodeID] = records
			obs.BlockErrorsOK[nodeID] = true
			for i := range records {
				hashes[records[i].BlockHash] = struct{}{}
			}
		}
	}
	obs.BlockErrorTotal = int64(len(hashes))
	return obs
}

// redundancyLayoutOwnership splits the storage roles of the current layout
// into the local ones (they run at this site) and the remote ones, and
// fingerprints the storage topology.
//
// On a federated site (remoteClusters set, or a storage role tagged with
// another GarageCluster's UID) a role is local only when its ID belongs to a
// non-external GarageNode of this cluster. Tags are not used there: a writer
// declares follower nodes as external GarageNodes, so they carry the
// writer's UID tag. On a non-federated cluster a role is local when it
// carries this cluster's UID tag (or, without any UID tag, its name tag) and
// is not an external GarageNode of this cluster.
func redundancyLayoutOwnership(in redundancyInput) (local, remote []string, federated bool, topology string) {
	federated = in.HasRemoteClusters
	uidTag := nodeClusterUIDTagPrefix + in.ClusterUID
	ids := sha256.New()
	roles := sha256.New()
	storage := make([]garage.LayoutNodeRole, 0, len(in.Layout.Roles))
	for _, role := range in.Layout.Roles {
		if role.Capacity == nil || *role.Capacity == 0 {
			continue
		}
		storage = append(storage, role)
		for _, tag := range role.Tags {
			if strings.HasPrefix(tag, nodeClusterUIDTagPrefix) && (in.ClusterUID == "" || tag != uidTag) {
				federated = true
			}
		}
	}
	localIDs := make(map[string]struct{}, len(in.LocalNodeIDs))
	for _, id := range in.LocalNodeIDs {
		localIDs[canonicalGarageNodeID(id)] = struct{}{}
	}
	externalIDs := make(map[string]struct{}, len(in.ExternalNodeIDs))
	for _, id := range in.ExternalNodeIDs {
		externalIDs[canonicalGarageNodeID(id)] = struct{}{}
	}
	sort.Slice(storage, func(i, j int) bool { return storage[i].ID < storage[j].ID })
	for _, role := range storage {
		_, _ = fmt.Fprintf(ids, "%s\n", role.ID)
		_, _ = fmt.Fprintf(roles, "%s|%s|%d\n", role.ID, role.Zone, *role.Capacity)
		id := canonicalGarageNodeID(role.ID)
		_, isLocal := localIDs[id]
		if !federated && !isLocal {
			_, external := externalIDs[id]
			ownUID, anyUID := false, false
			for _, tag := range role.Tags {
				ownUID = ownUID || (in.ClusterUID != "" && tag == uidTag)
				anyUID = anyUID || strings.HasPrefix(tag, nodeClusterUIDTagPrefix)
			}
			isLocal = !external && (ownUID || (!anyUID && nodeBelongsToCluster(role.Tags, in.ClusterName, in.Namespace)))
		}
		if isLocal {
			local = append(local, role.ID)
		} else {
			remote = append(remote, role.ID)
		}
	}
	// A layout without storage roles (a new cluster before its first
	// assignment) is no baseline: its first assignment starts nothing.
	if len(storage) > 0 {
		topology = hex.EncodeToString(ids.Sum(nil))[:32] + hex.EncodeToString(roles.Sum(nil))[:32]
	}
	return normalizedNodeIDs(local), normalizedNodeIDs(remote), federated, topology
}

func redundancyCondition(status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    garagev1beta1.ConditionFullyReplicated,
		Status:  status,
		Reason:  reason,
		Message: limitStatusConditionMessage(message),
	}
}

func redundancyTime(t *metav1.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func redundancySiteRoleUnsetMessage(others int) string {
	return fmt.Sprintf(
		"this GarageCluster federates with other sites (%d storage nodes run elsewhere) but spec.layoutManagement.siteRole is unset, "+
			"so no site runs the verification; set siteRole Writer on exactly one site and Follower on the others", others)
}

// advanceRedundancy runs one step of the proof. It never performs I/O.
func advanceRedundancy(prev *garagev1beta2.RedundancyStatus, in redundancyInput) redundancyResult {
	if !in.Observed {
		message := redundancyNotObservedMessage
		if prev != nil && prev.Verification != nil && prev.Verification.VerifiedAt != nil {
			message += " (last verified " + redundancyTime(prev.Verification.VerifiedAt) + ")"
		}
		return redundancyResult{
			Status:    prev.DeepCopy(),
			Condition: redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyNotObserved, message),
		}
	}
	obs := newRedundancyObservation(in)
	next := prev.DeepCopy()
	if next == nil {
		next = &garagev1beta2.RedundancyStatus{}
	}

	if obs.Federated && !in.SiteRoleSet {
		condition := redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancySiteRoleUnset, redundancySiteRoleUnsetMessage(obs.OtherNodes))
		next.Verification = nil
		next.LastProgressAt = nil
		next.DeferredNodes = nil
		next.Scope = ""
		next.StorageNodes = nil
		next.Coordination = nil
		applyRedundancyProgress(prev, next, obs, in.Now, !equalRedundancyIgnoringProgress(prev, next))
		return redundancyResult{Status: next, Condition: condition}
	}

	step := &redundancyStep{in: in, obs: obs, now: metav1.NewTime(in.Now), next: next}
	step.observeRemoteRepairs()
	step.invalidate()
	condition := step.run()
	verification := next.Verification
	step.applyScope()
	running := redundancyRunning(verification.Phase)
	if running {
		step.trackProgress(prev)
		if condition.Reason == garagev1beta1.ReasonRedundancyVerifying {
			condition = step.stallOrErrors(condition)
		}
	} else if verification.Phase != garagev1beta2.RedundancyPhasePartial {
		verification.Evidence = nil
		verification.CurrentNodeID = ""
	}
	normalizeRedundancyEvidence(verification)
	if len(next.DeferredNodes) == 0 {
		next.DeferredNodes = nil
	}

	applyRedundancyProgress(prev, next, obs, in.Now, !equalRedundancyIgnoringProgress(prev, next))
	result := redundancyResult{
		Status: next, Launches: step.launches, Condition: condition,
		Active: running || (verification.Phase == garagev1beta2.RedundancyPhasePartial && step.retryPending()),
	}
	if step.onLaunchFailure != nil {
		failure := next.DeepCopy()
		failure.Verification = step.onLaunchFailure
		failure.DeferredNodes = step.onLaunchFailureDeferred
		normalizeRedundancyEvidence(failure.Verification)
		result.OnLaunchFailure = failure
	}
	return result
}

// redundancyRunning reports the phases in which a node's turn or the final
// quiet period is in progress.
func redundancyRunning(phase garagev1beta2.RedundancyPhase) bool {
	switch phase {
	case garagev1beta2.RedundancyPhasePending, garagev1beta2.RedundancyPhaseSyncingMetadata,
		garagev1beta2.RedundancyPhaseScanningBlocks, garagev1beta2.RedundancyPhaseSettling:
		return true
	}
	return false
}

type redundancyStep struct {
	in   redundancyInput
	obs  redundancyObservation
	now  metav1.Time
	next *garagev1beta2.RedundancyStatus

	launches                []redundancyLaunch
	onLaunchFailure         *garagev1beta2.RedundancyVerificationStatus
	onLaunchFailureDeferred []garagev1beta2.RedundancyDeferredNode
	// advanced records that the proof moved forward this pass (a step was
	// entered, a repair was launched or adopted); it counts as progress.
	advanced          bool
	repairErrorNodeID string
	syncErrorNodeID   string
}

func (s *redundancyStep) now64() time.Time { return s.now.Time }

// invalidate records the baseline on first sight, and starts a proof on a new
// request token, or on a storage topology change seen after the baseline when
// onTopologyChange is set (never on a Follower). Without the flag a topology
// change only voids the last proof. Pod restarts, node outages and tag-only
// layout changes never start one.
func (s *redundancyStep) invalidate() {
	v := s.next.Verification
	token := s.in.RequestToken
	if v == nil {
		now := s.now
		v = &garagev1beta2.RedundancyVerificationStatus{Phase: garagev1beta2.RedundancyPhaseIdle, PhaseStartedAt: &now}
		s.next.Verification = v
		v.LayoutVersion = s.obs.LayoutVersion
		v.TopologyHash = s.obs.TopologyHash
		s.advanced = true
		if token != "" {
			// An explicit request is never automatic, even on first sight.
			s.start(garagev1beta2.RedundancyTriggerRequested)
		}
		v.RequestToken = token
		return
	}
	switch {
	case token != "" && token != v.RequestToken:
		s.start(garagev1beta2.RedundancyTriggerRequested)
	case v.TopologyHash != "" && s.obs.TopologyHash != "" && v.TopologyHash != s.obs.TopologyHash:
		switch {
		case s.in.TopologyAutoProof && !s.in.Follower && v.TopologyHash[:32] != s.obs.TopologyHash[:32]:
			s.start(garagev1beta2.RedundancyTriggerNodeChanged)
		case s.in.TopologyAutoProof && !s.in.Follower:
			s.start(garagev1beta2.RedundancyTriggerLayoutChanged)
		case v.Phase != garagev1beta2.RedundancyPhaseIdle:
			// The last or running proof no longer covers the layout. Stop
			// instead of restarting: no repair repeats without a request.
			s.stop()
		}
	}
	v.LayoutVersion = s.obs.LayoutVersion
	if s.obs.TopologyHash != "" {
		v.TopologyHash = s.obs.TopologyHash
	}
	if token != "" {
		v.RequestToken = token
	}
}

func (s *redundancyStep) start(trigger garagev1beta2.RedundancyTrigger) {
	v := s.next.Verification
	now := s.now
	v.Phase = garagev1beta2.RedundancyPhasePending
	v.Trigger = trigger
	v.StartedAt = &now
	v.PhaseStartedAt = now.DeepCopy()
	v.CurrentNodeID = ""
	v.CompletedNodeIDs = nil
	// A layout change already made every node fully sync its tables before
	// the history settled (design fact 2), so only blocks are scanned.
	v.Evidence = &garagev1beta2.RedundancyProofEvidence{SkipTables: trigger != garagev1beta2.RedundancyTriggerRequested}
	s.next.DeferredNodes = nil
	s.next.LastProgressAt = now.DeepCopy()
	s.advanced = true
}

// stop ends a running or finished proof without starting another.
func (s *redundancyStep) stop() {
	v := s.next.Verification
	v.Phase = garagev1beta2.RedundancyPhaseIdle
	v.PhaseStartedAt = s.now.DeepCopy()
	v.CurrentNodeID = ""
	v.CompletedNodeIDs = nil
	v.Evidence = nil
	s.next.DeferredNodes = nil
	s.advanced = true
}

func (s *redundancyStep) enter(phase garagev1beta2.RedundancyPhase) {
	v := s.next.Verification
	if v.Phase == phase {
		return
	}
	v.Phase = phase
	v.PhaseStartedAt = s.now.DeepCopy()
	s.advanced = true
}

func (s *redundancyStep) verifying(message string) metav1.Condition {
	return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyVerifying, message)
}

func (s *redundancyStep) owned(nodeID string) bool {
	return containsString(s.obs.OwnedNodeIDs, nodeID)
}

func (s *redundancyStep) down(nodeID string) bool {
	return containsString(s.obs.DownNodeIDs, nodeID)
}

func (s *redundancyStep) reporting(nodeID string) bool {
	return s.obs.WorkersOK[nodeID] && s.obs.BlockErrorsOK[nodeID]
}

// unavailable returns the defer reason for a node that cannot take its turn.
func (s *redundancyStep) unavailable(nodeID string) garagev1beta2.RedundancyDeferReason {
	switch {
	case s.down(nodeID) || !containsString(s.obs.StorageNodeIDs, nodeID):
		return garagev1beta2.RedundancyDeferDown
	case !s.reporting(nodeID):
		return garagev1beta2.RedundancyDeferNotReporting
	}
	return ""
}

func (s *redundancyStep) run() metav1.Condition {
	v := s.next.Verification
	switch v.Phase {
	case garagev1beta2.RedundancyPhaseIdle:
		return s.notVerified()
	case garagev1beta2.RedundancyPhaseVerified:
		for _, nodeID := range v.CompletedNodeIDs {
			if s.unavailable(nodeID) != "" {
				// An outage after the proof voids it, but it is not a
				// topology change: no repairs start on their own.
				s.enter(garagev1beta2.RedundancyPhaseIdle)
				return s.notVerified()
			}
		}
		if s.obs.BlockErrorTotal > 0 {
			return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyBlockErrors,
				fmt.Sprintf("%d blocks have persistent resync errors", s.obs.BlockErrorTotal))
		}
		return s.verified()
	}
	if message := s.preconditionFailure(); message != "" {
		// Wait in place: Garage keeps running a launched repair, and the
		// node's turn continues from its persisted evidence. A drain or
		// factor migration moves data, so the final quiet period restarts;
		// dropping its per-worker baselines also keeps status small while
		// status.storageDrain is large.
		if (s.in.DrainActive || s.in.FactorMigrationActive) && v.Evidence != nil {
			v.Evidence.ResyncErrorBaselines = nil
			v.Evidence.QuietSince = nil
		}
		return redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyPreconditionsNotMet, message)
	}
	if v.Evidence == nil {
		v.Evidence = &garagev1beta2.RedundancyProofEvidence{}
	}
	for range len(s.obs.OwnedNodeIDs)*2 + 2 {
		if v.CurrentNodeID == "" {
			if s.peekNextNode() {
				if condition, wait := s.waitForOtherSite(); wait {
					return condition
				}
			}
			if !s.pickNextNode() {
				return s.finish()
			}
		}
		condition, done := s.driveNode()
		if !done {
			return condition
		}
	}
	return s.verifying("Verifying: waiting for the next pass")
}

func (s *redundancyStep) notVerified() metav1.Condition {
	v := s.next.Verification
	var message string
	if v.VerifiedAt != nil {
		message = fmt.Sprintf(
			"the last proof (verified %s) no longer holds: a storage node was down or the storage layout changed; no repair starts on its own: set the %s annotation to a new value to re-verify",
			redundancyTime(v.VerifiedAt), garagev1beta1.AnnotationVerifyRedundancy)
	} else {
		message = fmt.Sprintf(
			"no full-redundancy proof has completed; the operator never starts one on upgrade: set the %s annotation to a new value to run one",
			garagev1beta1.AnnotationVerifyRedundancy)
	}
	if s.in.Follower {
		message += fmt.Sprintf(" on this site; it verifies only the %d storage nodes that run here", len(s.obs.OwnedNodeIDs))
	}
	return redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyNotVerified, message)
}

// siteLabel names the site kind in VerifiedLocal messages.
func (s *redundancyStep) siteLabel() string {
	switch {
	case s.in.Follower:
		return "follower-local"
	case s.in.SiteRoleSet:
		return "writer-local"
	}
	return "site-local"
}

func (s *redundancyStep) verified() metav1.Condition {
	v := s.next.Verification
	if len(s.obs.RemoteNodeIDs) == 0 {
		return redundancyCondition(metav1.ConditionTrue, garagev1beta1.ReasonRedundancyVerified, fmt.Sprintf(
			"Full redundancy verified on layout version %d for all %d storage nodes", v.LayoutVersion, len(v.CompletedNodeIDs)))
	}
	total := len(s.obs.OwnedNodeIDs) + len(s.obs.RemoteNodeIDs)
	return redundancyCondition(metav1.ConditionTrue, garagev1beta1.ReasonRedundancyVerifiedLocal, fmt.Sprintf(
		"%d/%d federated storage nodes verified (%s) on layout version %d; the other %d run at other sites and are not covered",
		len(v.CompletedNodeIDs), total, s.siteLabel(), v.LayoutVersion, len(s.obs.RemoteNodeIDs)))
}

func (s *redundancyStep) preconditionFailure() string {
	in := s.in
	switch {
	case in.DrainActive:
		return "a storage drain owns the cluster (status.storageDrain); verification runs after it completes"
	case in.FactorMigrationActive:
		return "a replication-factor migration is in progress; verification runs after it completes"
	case len(s.obs.OwnedNodeIDs) == 0:
		return "no storage role in the current Garage layout runs at this site"
	case in.History == nil || requireSettledLayoutHistoryResponse(in.History) != nil:
		return "the Garage layout history is still migrating data to the current version"
	case in.Layout == nil || len(in.Layout.StagedRoleChanges) > 0 || in.Layout.StagedParameters != nil:
		return "the Garage layout has staged changes that are not applied"
	case in.Status == nil || in.Layout.Version != in.History.CurrentVersion || in.Status.LayoutVersion != in.History.CurrentVersion:
		return "Garage layout snapshots disagree; waiting for them to converge"
	}
	return ""
}

// pickNextNode starts the next owned node's turn: first nodes not yet done,
// then deferred nodes that are back and due, then tables rechecks once every
// storage node is up. A node that is unavailable when its turn comes is
// deferred. It returns false when no node has work.
func (s *redundancyStep) pickNextNode() bool {
	v := s.next.Verification
	for _, nodeID := range s.obs.OwnedNodeIDs {
		if containsString(v.CompletedNodeIDs, nodeID) || s.deferred(nodeID) != nil {
			continue
		}
		if reason := s.unavailable(nodeID); reason != "" {
			s.deferNode(nodeID, reason)
			continue
		}
		s.beginTurn(nodeID, false)
		return true
	}
	for i := range s.next.DeferredNodes {
		entry := s.next.DeferredNodes[i]
		if entry.Reason == garagev1beta2.RedundancyDeferRepairFailed || !s.owned(entry.NodeID) ||
			entry.RetryAfter == nil || s.now64().Before(entry.RetryAfter.Time) || s.unavailable(entry.NodeID) != "" {
			continue
		}
		s.next.DeferredNodes = append(s.next.DeferredNodes[:i:i], s.next.DeferredNodes[i+1:]...)
		s.beginTurn(entry.NodeID, false)
		return true
	}
	// Rechecks wait until every storage node is up and every retryable
	// deferred node has had its own turn.
	retryableDeferred := false
	for _, entry := range s.next.DeferredNodes {
		retryableDeferred = retryableDeferred || entry.Reason != garagev1beta2.RedundancyDeferRepairFailed
	}
	if len(s.obs.DownNodeIDs) == 0 && !retryableDeferred {
		for _, nodeID := range v.Evidence.TablesRecheckNodeIDs {
			if s.owned(nodeID) && s.reporting(nodeID) {
				s.beginTurn(nodeID, true)
				return true
			}
		}
	}
	return false
}

// peekNextNode reports, without changing anything, whether pickNextNode
// would begin a turn on an available node.
func (s *redundancyStep) peekNextNode() bool {
	v := s.next.Verification
	for _, nodeID := range s.obs.OwnedNodeIDs {
		if !containsString(v.CompletedNodeIDs, nodeID) && s.deferred(nodeID) == nil && s.unavailable(nodeID) == "" {
			return true
		}
	}
	retryableDeferred := false
	for _, entry := range s.next.DeferredNodes {
		if entry.Reason == garagev1beta2.RedundancyDeferRepairFailed {
			continue
		}
		retryableDeferred = true
		if s.owned(entry.NodeID) && entry.RetryAfter != nil && !s.now64().Before(entry.RetryAfter.Time) && s.unavailable(entry.NodeID) == "" {
			return true
		}
	}
	if len(s.obs.DownNodeIDs) == 0 && !retryableDeferred && v.Evidence != nil {
		for _, nodeID := range v.Evidence.TablesRecheckNodeIDs {
			if s.owned(nodeID) && s.reporting(nodeID) {
				return true
			}
		}
	}
	return false
}

// redundancyHoldDown is this site's wait after the last remote repair: the
// base hold-down, plus 1..10 minutes on a Follower, fixed per cluster UID.
func redundancyHoldDown(in redundancyInput) time.Duration {
	if !in.Follower {
		return redundancyRemoteHoldDown
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(in.ClusterUID))
	return redundancyRemoteHoldDown + time.Duration(1+hash.Sum32()%redundancyFollowerOffsetSlots)*time.Minute
}

// waitForOtherSite holds the next node turn while a remote blocks repair ran
// within the hold-down (B3). A Writer only waits before its first turn; a
// Follower waits before every turn. A launched turn always finishes.
func (s *redundancyStep) waitForOtherSite() (metav1.Condition, bool) {
	c := s.next.Coordination
	if !s.obs.Federated || c == nil || c.LastRemoteRepairAt == nil {
		return metav1.Condition{}, false
	}
	v := s.next.Verification
	if !s.in.Follower && v.Phase != garagev1beta2.RedundancyPhasePending {
		return metav1.Condition{}, false
	}
	until := c.LastRemoteRepairAt.Add(redundancyHoldDown(s.in))
	if !s.now64().Before(until) {
		return metav1.Condition{}, false
	}
	untilTime := metav1.NewTime(until)
	seen := "another site's storage node"
	if c.LastRemoteRepairNodeID != "" {
		seen = "remote storage node " + shortID(c.LastRemoteRepairNodeID)
	}
	return redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyWaitingForOtherSite, fmt.Sprintf(
		"waiting for other sites' repairs: a blocks repair on %s was last seen at %s; this site starts its next storage node at %s",
		seen, redundancyTime(c.LastRemoteRepairAt), redundancyTime(&untilTime))), true
}

// observeRemoteRepairs records blocks repair activity on remote storage nodes
// (B3). Activity is a Block repair worker that is not Done, or a remote
// node's highest repair worker ID going up. A lower ID is a Garage restart
// and only rebaselines. The first federated pass counts as activity, so a
// site watches for one hold-down before its first proof.
func (s *redundancyStep) observeRemoteRepairs() {
	if !s.obs.Federated {
		s.next.Coordination = nil
		return
	}
	c := s.next.Coordination
	if c == nil {
		c = &garagev1beta2.RedundancyCoordinationStatus{LastRemoteRepairAt: s.now.DeepCopy()}
		s.next.Coordination = c
	}
	seen := make(map[string]uint64, len(s.obs.RemoteNodeIDs))
	activeNode := ""
	for _, nodeID := range s.obs.RemoteNodeIDs {
		previous, known := c.RemoteRepairWorkerIDs[nodeID]
		if !s.obs.WorkersOK[nodeID] {
			if known {
				seen[nodeID] = previous
			}
			continue
		}
		var newest uint64
		running := false
		for _, worker := range s.obs.Workers[nodeID] {
			if worker.Name != blockRepairWorkerName {
				continue
			}
			newest = max(newest, worker.ID)
			running = running || !worker.State.IsDone()
		}
		if running || (known && newest > previous) {
			if activeNode == "" {
				activeNode = nodeID
			}
		}
		if newest > 0 {
			seen[nodeID] = newest
		}
	}
	if len(seen) == 0 {
		seen = nil
	}
	c.RemoteRepairWorkerIDs = seen
	if activeNode != "" && (c.LastRemoteRepairAt == nil || s.now64().Sub(c.LastRemoteRepairAt.Time) >= redundancyRemoteBumpInterval) {
		c.LastRemoteRepairAt = s.now.DeepCopy()
		c.LastRemoteRepairNodeID = activeNode
	}
}

// applyScope writes status.redundancy.scope and storageNodes.
func (s *redundancyStep) applyScope() {
	scope := garagev1beta2.RedundancyScopeCluster
	if len(s.obs.RemoteNodeIDs) > 0 {
		scope = garagev1beta2.RedundancyScopeLocal
	}
	s.next.Scope = scope
	verified := 0
	if v := s.next.Verification; v != nil && v.Phase != garagev1beta2.RedundancyPhaseIdle {
		for _, nodeID := range v.CompletedNodeIDs {
			if s.owned(nodeID) {
				verified++
			}
		}
	}
	s.next.StorageNodes = &garagev1beta2.RedundancyStorageNodeCounts{
		Total:    int32(len(s.obs.OwnedNodeIDs) + len(s.obs.RemoteNodeIDs)),
		Local:    int32(len(s.obs.OwnedNodeIDs)),
		Remote:   int32(len(s.obs.RemoteNodeIDs)),
		Verified: int32(verified),
	}
}

func (s *redundancyStep) deferred(nodeID string) *garagev1beta2.RedundancyDeferredNode {
	for i := range s.next.DeferredNodes {
		if s.next.DeferredNodes[i].NodeID == nodeID {
			return &s.next.DeferredNodes[i]
		}
	}
	return nil
}

func (s *redundancyStep) deferNode(nodeID string, reason garagev1beta2.RedundancyDeferReason) {
	entry := garagev1beta2.RedundancyDeferredNode{NodeID: nodeID, Reason: reason, Since: s.now}
	if reason != garagev1beta2.RedundancyDeferRepairFailed {
		retry := metav1.NewTime(s.now64().Add(redundancyDeferredRetryDelay))
		entry.RetryAfter = &retry
	}
	s.next.DeferredNodes = append(s.next.DeferredNodes, entry)
	sort.Slice(s.next.DeferredNodes, func(i, j int) bool { return s.next.DeferredNodes[i].NodeID < s.next.DeferredNodes[j].NodeID })
	v := s.next.Verification
	v.CompletedNodeIDs = removeString(v.CompletedNodeIDs, nodeID)
	if v.CurrentNodeID == nodeID {
		s.endTurn()
	}
	s.advanced = true
}

func (s *redundancyStep) beginTurn(nodeID string, tablesRecheck bool) {
	v := s.next.Verification
	evidence := v.Evidence
	v.CurrentNodeID = nodeID
	s.clearStage()
	switch {
	case tablesRecheck || !evidence.SkipTables:
		evidence.NodeStage = garagev1beta2.RedundancyNodeStageTables
		s.enter(garagev1beta2.RedundancyPhaseSyncingMetadata)
	default:
		evidence.NodeStage = garagev1beta2.RedundancyNodeStageBlocks
		s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
	}
	s.advanced = true
}

func (s *redundancyStep) clearStage() {
	evidence := s.next.Verification.Evidence
	evidence.StageLaunchedAt = nil
	evidence.WorkerBaseline = 0
	evidence.SyncErrorBaselines = nil
	evidence.IdleSince = nil
	evidence.PeerDownSeen = false
	evidence.RepairWorkerID = 0
	evidence.Launches = 0
	evidence.PauseUntil = nil
}

func (s *redundancyStep) endTurn() {
	s.clearStage()
	s.next.Verification.Evidence.NodeStage = ""
	s.next.Verification.CurrentNodeID = ""
}

// position renders "k of n" for the current node.
func (s *redundancyStep) position() string {
	v := s.next.Verification
	done := len(v.CompletedNodeIDs)
	if !containsString(v.CompletedNodeIDs, v.CurrentNodeID) {
		done++
	}
	return fmt.Sprintf("%d of %d", min(done, len(s.obs.OwnedNodeIDs)), len(s.obs.OwnedNodeIDs))
}

// driveNode advances the current node's turn. done is true when the turn
// ended (completed, paused out, or deferred) and the next node may start in
// the same pass.
func (s *redundancyStep) driveNode() (metav1.Condition, bool) {
	v := s.next.Verification
	evidence := v.Evidence
	nodeID := v.CurrentNodeID
	if !s.owned(nodeID) {
		s.endTurn()
		return metav1.Condition{}, true
	}
	if evidence.NodeStage == garagev1beta2.RedundancyNodeStagePause {
		if evidence.PauseUntil != nil && s.now64().Before(evidence.PauseUntil.Time) {
			return s.verifying(fmt.Sprintf("storage node %s finished; pausing until %s before the next storage node",
				shortID(nodeID), redundancyTime(evidence.PauseUntil))), false
		}
		s.endTurn()
		return metav1.Condition{}, true
	}
	if reason := s.unavailable(nodeID); reason != "" {
		s.deferNode(nodeID, reason)
		return metav1.Condition{}, true
	}
	if evidence.NodeStage == garagev1beta2.RedundancyNodeStageTables {
		return s.syncTables()
	}
	evidence.NodeStage = garagev1beta2.RedundancyNodeStageBlocks
	return s.scanBlocks()
}

// launch records the launch of the current node's stage, or defers the node
// after redundancyMaxLaunches. The failure snapshot has no recorded launch,
// so a failed launch is retried next pass without counting.
func (s *redundancyStep) launch(repairType string, record func()) (metav1.Condition, bool) {
	v := s.next.Verification
	evidence := v.Evidence
	nodeID := v.CurrentNodeID
	if evidence.Launches >= redundancyMaxLaunches {
		s.deferNode(nodeID, garagev1beta2.RedundancyDeferRepairFailed)
		return metav1.Condition{}, true
	}
	s.onLaunchFailure = v.DeepCopy()
	s.onLaunchFailureDeferred = append([]garagev1beta2.RedundancyDeferredNode(nil), s.next.DeferredNodes...)
	evidence.Launches++
	launchedAt := s.now
	evidence.StageLaunchedAt = &launchedAt
	evidence.WorkerBaseline = maxWorkerID(s.obs.Workers[nodeID])
	record()
	s.launches = append(s.launches, redundancyLaunch{NodeID: nodeID, RepairType: repairType})
	s.advanced = true
	if repairType == redundancyRepairTypeTables {
		return s.verifying(fmt.Sprintf("Syncing metadata on storage node %s (%s): launched a full table sync", shortID(nodeID), s.position())), false
	}
	return s.verifying(fmt.Sprintf("Scanning blocks on storage node %s (%s): launched a blocks repair", shortID(nodeID), s.position())), false
}

func (s *redundancyStep) launchTables() (metav1.Condition, bool) {
	nodeID := s.next.Verification.CurrentNodeID
	workers := s.obs.Workers[nodeID]
	baselines := make(map[string]uint64, len(redundancyMetadataTables))
	for _, table := range redundancyMetadataTables {
		worker := workerByName(workers, table+redundancyTableSyncSuffix)
		if worker == nil {
			return s.verifying(fmt.Sprintf("Syncing metadata: storage node %s does not report the %s sync worker", shortID(nodeID), table)), false
		}
		baselines[redundancyWorkerKey(nodeID, worker.ID)] = worker.Errors
	}
	evidence := s.next.Verification.Evidence
	peerDown := evidence.PeerDownSeen
	return s.launch(redundancyRepairTypeTables, func() {
		evidence.SyncErrorBaselines = baselines
		evidence.IdleSince = nil
		evidence.PeerDownSeen = peerDown || len(s.obs.DownNodeIDs) > 0
	})
}

func (s *redundancyStep) relaunchTables() (metav1.Condition, bool) {
	evidence := s.next.Verification.Evidence
	evidence.StageLaunchedAt = nil
	return s.launchTables()
}

func (s *redundancyStep) syncTables() (metav1.Condition, bool) {
	v := s.next.Verification
	evidence := v.Evidence
	nodeID := v.CurrentNodeID
	if evidence.StageLaunchedAt == nil {
		return s.launchTables()
	}
	workers := s.obs.Workers[nodeID]
	// A Garage restart drops the full-sync request with the process.
	if maxWorkerID(workers) < evidence.WorkerBaseline || len(evidence.SyncErrorBaselines) != len(redundancyMetadataTables) {
		return s.relaunchTables()
	}
	if len(s.obs.DownNodeIDs) > 0 {
		evidence.PeerDownSeen = true
	}
	busy, errored := false, false
	for _, key := range sortedKeysOf(evidence.SyncErrorBaselines) {
		keyNode, workerID, ok := splitRedundancyWorkerKey(key)
		if !ok || keyNode != nodeID {
			return s.relaunchTables()
		}
		worker := workerByID(workers, workerID)
		baseline := evidence.SyncErrorBaselines[key]
		if worker == nil || !strings.HasSuffix(worker.Name, redundancyTableSyncSuffix) || worker.Errors < baseline {
			// The worker is gone or its counters went backwards: the process
			// restarted. A restart that keeps identical worker IDs and zero
			// counters is still safe: Garage starts its own full sync 20 s
			// after process start, which is inside redundancyMetadataSettleGap,
			// so the two clean observations cannot both precede it.
			return s.relaunchTables()
		}
		if !worker.State.IsIdle() || worker.QueueLength == nil || *worker.QueueLength != 0 {
			busy = true
		}
		if worker.Errors > baseline {
			errored = true
		}
	}
	if !busy {
		for _, worker := range workers {
			if redundancyMetadataQueueWorker(worker.Name) && worker.QueueLength != nil && *worker.QueueLength > 0 {
				busy = true
				break
			}
		}
	}
	if errored && !evidence.PeerDownSeen {
		s.syncErrorNodeID = nodeID
		if !busy {
			// The pass finished, but a partition failed at least once with
			// every peer up; only a clean pass counts.
			return s.relaunchTables()
		}
	}
	if busy {
		evidence.IdleSince = nil
		return s.verifying(fmt.Sprintf("Syncing metadata on storage node %s (%s): waiting for the table sync", shortID(nodeID), s.position())), false
	}
	if evidence.IdleSince == nil {
		idleSince := s.now
		evidence.IdleSince = &idleSince
	}
	if s.now64().Sub(evidence.IdleSince.Time) < redundancyMetadataSettleGap {
		return s.verifying(fmt.Sprintf("Syncing metadata on storage node %s (%s): table sync finished; confirming it stays idle", shortID(nodeID), s.position())), false
	}
	recheck := containsString(v.CompletedNodeIDs, nodeID)
	if recheck {
		if !errored {
			evidence.TablesRecheckNodeIDs = removeString(evidence.TablesRecheckNodeIDs, nodeID)
		}
		// A peer that went down again keeps the node on the recheck list.
		s.pause()
		return metav1.Condition{}, true
	}
	if errored {
		// Errors while a peer was down are expected; recheck once all are up.
		evidence.TablesRecheckNodeIDs = addString(evidence.TablesRecheckNodeIDs, nodeID)
	}
	s.clearStage()
	evidence.NodeStage = garagev1beta2.RedundancyNodeStageBlocks
	s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
	return metav1.Condition{}, true
}

func (s *redundancyStep) pause() {
	v := s.next.Verification
	s.clearStage()
	v.Evidence.NodeStage = garagev1beta2.RedundancyNodeStagePause
	until := metav1.NewTime(s.now64().Add(redundancyNodePause))
	v.Evidence.PauseUntil = &until
	s.advanced = true
}

// scanBlocks drives one blocks repair on the current node: persist the
// worker-ID baseline with the launch, adopt the exact post-baseline repair
// worker, and wait for it to finish without errors.
func (s *redundancyStep) scanBlocks() (metav1.Condition, bool) {
	v := s.next.Verification
	evidence := v.Evidence
	nodeID := v.CurrentNodeID
	relaunch := func() (metav1.Condition, bool) {
		evidence.StageLaunchedAt = nil
		evidence.RepairWorkerID = 0
		return s.launch(redundancyRepairTypeBlocks, func() {})
	}
	if evidence.StageLaunchedAt == nil {
		return relaunch()
	}
	s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
	workers := s.obs.Workers[nodeID]
	if evidence.RepairWorkerID == 0 {
		if maxWorkerID(workers) < evidence.WorkerBaseline {
			return relaunch()
		}
		worker := newestBlockRepairWorkerAfter(workers, evidence.WorkerBaseline)
		if worker == nil {
			// Garage spawns the worker before answering the launch, so a
			// missing worker means the launch never reached it.
			return relaunch()
		}
		evidence.RepairWorkerID = worker.ID
		s.advanced = true
	}
	worker := blockRepairWorker(workers, evidence.RepairWorkerID)
	if worker == nil {
		return relaunch()
	}
	if worker.Errors > 0 {
		s.repairErrorNodeID = nodeID
		if worker.State.IsDone() {
			return relaunch()
		}
	}
	if !worker.State.IsDone() || worker.Errors > 0 {
		return s.verifying(fmt.Sprintf("Scanning blocks on storage node %s (%s): waiting for the blocks repair", shortID(nodeID), s.position())), false
	}
	v.CompletedNodeIDs = addString(v.CompletedNodeIDs, nodeID)
	s.pause()
	return metav1.Condition{}, true
}

// retryPending reports deferred nodes or tables rechecks the operator still
// retries on its own.
func (s *redundancyStep) retryPending() bool {
	for _, entry := range s.next.DeferredNodes {
		if entry.Reason != garagev1beta2.RedundancyDeferRepairFailed {
			return true
		}
	}
	evidence := s.next.Verification.Evidence
	return evidence != nil && len(evidence.TablesRecheckNodeIDs) > 0
}

// finish runs once no node has work: Partial with deferred nodes or pending
// rechecks, otherwise the final quiet period over the owned nodes.
func (s *redundancyStep) finish() metav1.Condition {
	v := s.next.Verification
	evidence := v.Evidence
	if len(s.next.DeferredNodes) > 0 || len(evidence.TablesRecheckNodeIDs) > 0 {
		s.enter(garagev1beta2.RedundancyPhasePartial)
		evidence.ResyncErrorBaselines = nil
		evidence.QuietSince = nil
		return s.partial()
	}
	s.enter(garagev1beta2.RedundancyPhaseSettling)
	baselines := map[string]uint64{}
	idle := true
	for _, nodeID := range s.obs.OwnedNodeIDs {
		found := false
		for _, worker := range s.obs.Workers[nodeID] {
			if !isBlockResyncWorkerName(worker.Name) || worker.QueueLength == nil || worker.PersistentErrors == nil {
				continue
			}
			found = true
			baselines[redundancyWorkerKey(nodeID, worker.ID)] = *worker.PersistentErrors
			if !worker.State.IsIdle() {
				idle = false
			}
		}
		if !found {
			return s.verifying(fmt.Sprintf("Settling: storage node %s exposes no block resync worker with counters", shortID(nodeID)))
		}
	}
	if evidence.QuietSince == nil || !equality.Semantic.DeepEqual(evidence.ResyncErrorBaselines, baselines) {
		// A changed resync error counter restarts only the quiet period;
		// no repair is launched again.
		quietSince := s.now
		evidence.QuietSince = &quietSince
		evidence.ResyncErrorBaselines = baselines
	}
	end := metav1.NewTime(evidence.QuietSince.Add(s.in.QuietPeriod))
	if s.now64().Before(end.Time) {
		return s.verifying(fmt.Sprintf(
			"Settling: every local storage node finished its repairs; block resync workers must stay idle and error-free until %s", redundancyTime(&end)))
	}
	for _, nodeID := range s.obs.OwnedNodeIDs {
		if len(s.obs.BlockErrors[nodeID]) > 0 {
			return s.verifying("Settling: waiting for block resync errors on the local storage nodes to clear")
		}
	}
	if !idle {
		return s.verifying("Settling: quiet period finished; waiting for every block resync worker to become idle")
	}
	verifiedAt := s.now
	v.VerifiedAt = &verifiedAt
	s.enter(garagev1beta2.RedundancyPhaseVerified)
	v.Evidence = nil
	return s.verified()
}

func (s *redundancyStep) partial() metav1.Condition {
	v := s.next.Verification
	parts := make([]string, 0, len(s.next.DeferredNodes))
	retry, failed := false, false
	for _, entry := range s.next.DeferredNodes {
		parts = append(parts, fmt.Sprintf("%s (%s)", shortID(entry.NodeID), entry.Reason))
		if entry.Reason == garagev1beta2.RedundancyDeferRepairFailed {
			failed = true
		} else {
			retry = true
		}
	}
	message := fmt.Sprintf("%d of %d local storage nodes finished", len(v.CompletedNodeIDs), len(s.obs.OwnedNodeIDs))
	if len(parts) > 0 {
		message += "; deferred: " + strings.Join(parts, ", ")
	}
	if recheck := len(v.Evidence.TablesRecheckNodeIDs); recheck > 0 {
		message += fmt.Sprintf("; %d nodes synced tables while a peer was down and are rechecked once every storage node is up", recheck)
	}
	if retry {
		message += fmt.Sprintf("; down or silent nodes are retried when they are back, at most every %s", redundancyDeferredRetryDelay)
	}
	if failed {
		message += fmt.Sprintf("; set the %s annotation to a new value to retry failed nodes", garagev1beta1.AnnotationVerifyRedundancy)
	}
	return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyPartial, message)
}

func redundancyWorkerKey(nodeID string, workerID uint64) string {
	return fmt.Sprintf("%s/%d", nodeID, workerID)
}

func splitRedundancyWorkerKey(key string) (string, uint64, bool) {
	nodeID, rawID, found := strings.Cut(key, "/")
	if !found {
		return "", 0, false
	}
	var workerID uint64
	if _, err := fmt.Sscanf(rawID, "%d", &workerID); err != nil {
		return "", 0, false
	}
	return nodeID, workerID, true
}

func workerByID(workers []garage.WorkerInfo, id uint64) *garage.WorkerInfo {
	for i := range workers {
		if workers[i].ID == id {
			return &workers[i]
		}
	}
	return nil
}

func workerByName(workers []garage.WorkerInfo, name string) *garage.WorkerInfo {
	for i := range workers {
		if workers[i].Name == name {
			return &workers[i]
		}
	}
	return nil
}

func redundancyMetadataQueueWorker(name string) bool {
	for _, table := range redundancyMetadataTables {
		if name == table+redundancyTableMerkleSuffix || name == table+redundancyTableQueueSuffix {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func addString(values []string, value string) []string {
	if containsString(values, value) {
		return values
	}
	out := append(append([]string(nil), values...), value)
	sort.Strings(out)
	return out
}

func removeString(values []string, value string) []string {
	var out []string
	for _, candidate := range values {
		if candidate != value {
			out = append(out, candidate)
		}
	}
	return out
}

func sortedKeysOf(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// redundancyTotals sums the remaining work reported by observed nodes.
func redundancyTotals(nodes []garagev1beta2.NodeRedundancyStatus) (queue int64, partitions int64, repairProgress string) {
	var progress []string
	for i := range nodes {
		node := &nodes[i]
		if !node.Observed {
			continue
		}
		if node.ResyncQueueLength != nil {
			queue += *node.ResyncQueueLength
		}
		if node.MetadataSyncPartitions != nil {
			partitions += int64(*node.MetadataSyncPartitions)
		}
		if node.BlockRepairProgress != "" {
			progress = append(progress, node.NodeID+"="+node.BlockRepairProgress)
		}
	}
	return queue, partitions, strings.Join(progress, ",")
}

// trackProgress moves lastProgressAt forward when remaining work decreased,
// in steps of at least redundancyProgressWriteInterval.
func (s *redundancyStep) trackProgress(prev *garagev1beta2.RedundancyStatus) {
	progressed := s.advanced
	if prev != nil && len(prev.Nodes) > 0 {
		current := redundancyProgressNodes(prev.Nodes, s.obs, s.next.Verification)
		prevQueue, prevPartitions, prevRepair := redundancyTotals(prev.Nodes)
		queue, partitions, repair := redundancyTotals(current)
		if queue < prevQueue || partitions < prevPartitions || (repair != "" && repair != prevRepair) {
			progressed = true
		}
	}
	last := s.next.LastProgressAt
	switch {
	case last == nil:
		s.next.LastProgressAt = s.now.DeepCopy()
	case progressed && s.now64().Sub(last.Time) >= redundancyProgressWriteInterval:
		s.next.LastProgressAt = s.now.DeepCopy()
	}
}

// stallOrErrors applies D6 to a running proof.
func (s *redundancyStep) stallOrErrors(condition metav1.Condition) metav1.Condition {
	evidence := s.next.Verification.Evidence
	growing := false
	var baselineAt *metav1.Time
	var baseline int64
	if evidence != nil {
		switch {
		case evidence.BlockErrorsBaseline == nil || evidence.BlockErrorsBaselineAt == nil ||
			s.now64().Sub(evidence.BlockErrorsBaselineAt.Time) >= redundancyBlockErrorWindow:
			evidence.BlockErrorsBaseline = ptr.To(s.obs.BlockErrorTotal)
			evidence.BlockErrorsBaselineAt = s.now.DeepCopy()
		case s.obs.BlockErrorTotal > *evidence.BlockErrorsBaseline:
			growing = true
			baseline = *evidence.BlockErrorsBaseline
			baselineAt = evidence.BlockErrorsBaselineAt
		}
	}
	stalled := func(message string) metav1.Condition {
		return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyStalled, message)
	}
	last := s.next.LastProgressAt
	switch {
	case s.repairErrorNodeID != "":
		return stalled(fmt.Sprintf("the blocks repair on storage node %s reported errors; a clean repair will be launched", shortID(s.repairErrorNodeID)))
	case s.syncErrorNodeID != "":
		return stalled(fmt.Sprintf("the table sync on storage node %s reported errors", shortID(s.syncErrorNodeID)))
	case growing:
		return stalled(fmt.Sprintf("block errors are growing (%d at %s)", baseline, redundancyTime(baselineAt)))
	case last != nil && s.now64().Sub(last.Time) > redundancyStallThreshold:
		return stalled("no progress since " + redundancyTime(last))
	case s.obs.BlockErrorTotal > 0:
		return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyBlockErrors,
			fmt.Sprintf("%d blocks have persistent resync errors", s.obs.BlockErrorTotal))
	}
	return condition
}

// redundancyProgressNodes builds nodes[] for every current storage node and
// every other node reporting block errors. A node that did not answer keeps
// its previous counters with observed=false.
func redundancyProgressNodes(
	prevNodes []garagev1beta2.NodeRedundancyStatus,
	obs redundancyObservation,
	verification *garagev1beta2.RedundancyVerificationStatus,
) []garagev1beta2.NodeRedundancyStatus {
	ids := append([]string(nil), obs.StorageNodeIDs...)
	for nodeID, records := range obs.BlockErrors {
		if len(records) > 0 {
			ids = append(ids, nodeID)
		}
	}
	ids = normalizedNodeIDs(ids)
	if len(ids) > redundancyMaxNodes {
		ids = ids[:redundancyMaxNodes]
	}
	previous := make(map[string]garagev1beta2.NodeRedundancyStatus, len(prevNodes))
	for i := range prevNodes {
		previous[prevNodes[i].NodeID] = prevNodes[i]
	}
	repairWorkerIDs := map[string]uint64{}
	if verification != nil && verification.Evidence != nil && verification.Evidence.RepairWorkerID != 0 {
		repairWorkerIDs[verification.CurrentNodeID] = verification.Evidence.RepairWorkerID
	}
	nodes := make([]garagev1beta2.NodeRedundancyStatus, 0, len(ids))
	for _, nodeID := range ids {
		if !obs.WorkersOK[nodeID] || !obs.BlockErrorsOK[nodeID] {
			prevEntry := previous[nodeID]
			entry := *prevEntry.DeepCopy()
			entry.NodeID = nodeID
			entry.Observed = false
			nodes = append(nodes, entry)
			continue
		}
		workers := obs.Workers[nodeID]
		entry := garagev1beta2.NodeRedundancyStatus{NodeID: nodeID, Observed: true}
		var resyncQueue, syncPartitions, metadataQueue uint64
		resyncIdle, resyncSeen, syncSeen, metadataSeen := true, false, false, false
		for i := range workers {
			worker := &workers[i]
			if worker.QueueLength == nil {
				continue
			}
			switch {
			case isBlockResyncWorkerName(worker.Name):
				resyncSeen = true
				resyncQueue = max(resyncQueue, *worker.QueueLength)
				if !worker.State.IsIdle() {
					resyncIdle = false
				}
			case strings.HasSuffix(worker.Name, redundancyTableSyncSuffix):
				syncSeen = true
				syncPartitions += *worker.QueueLength
			case strings.HasSuffix(worker.Name, redundancyTableMerkleSuffix), strings.HasSuffix(worker.Name, redundancyTableQueueSuffix):
				metadataSeen = true
				metadataQueue += *worker.QueueLength
			}
		}
		if resyncSeen {
			entry.ResyncQueueLength = ptr.To(clampInt64(resyncQueue))
			entry.ResyncIdle = ptr.To(resyncIdle)
		}
		entry.BlockErrors = ptr.To(int32(min(len(obs.BlockErrors[nodeID]), 1<<31-1)))
		if syncSeen {
			entry.MetadataSyncPartitions = ptr.To(int32(min(syncPartitions, 1<<31-1)))
		}
		if metadataSeen {
			entry.MetadataQueueLength = ptr.To(clampInt64(metadataQueue))
		}
		if workerID, adopted := repairWorkerIDs[nodeID]; adopted {
			if worker := blockRepairWorker(workers, workerID); worker != nil && !worker.State.IsDone() && worker.Progress != nil {
				progress := *worker.Progress
				if len(progress) > redundancyMaxProgressLength {
					progress = progress[:redundancyMaxProgressLength]
				}
				entry.BlockRepairProgress = progress
			}
		}
		nodes = append(nodes, entry)
	}
	if len(nodes) == 0 {
		return nil
	}
	return nodes
}

func clampInt64(value uint64) int64 {
	if value > 1<<63-1 {
		return 1<<63 - 1
	}
	return int64(value)
}

// applyRedundancyProgress rewrites nodes[] only when a value changed, and then
// at most once per redundancyProgressWriteInterval unless force is set
// (another redundancy field changes in this write anyway).
func applyRedundancyProgress(
	prev, next *garagev1beta2.RedundancyStatus,
	obs redundancyObservation,
	now time.Time,
	force bool,
) {
	var prevNodes []garagev1beta2.NodeRedundancyStatus
	var prevObservedAt *metav1.Time
	if prev != nil {
		prevNodes = prev.Nodes
		prevObservedAt = prev.ProgressObservedAt
	}
	fresh := redundancyProgressNodes(prevNodes, obs, next.Verification)
	if equality.Semantic.DeepEqual(fresh, prevNodes) {
		return
	}
	if force || prevObservedAt == nil || now.Sub(prevObservedAt.Time) >= redundancyProgressWriteInterval {
		next.Nodes = fresh
		observedAt := metav1.NewTime(now)
		next.ProgressObservedAt = &observedAt
	}
}

// equalRedundancyIgnoringProgress compares everything except the throttled
// progress fields.
func equalRedundancyIgnoringProgress(a, b *garagev1beta2.RedundancyStatus) bool {
	strip := func(status *garagev1beta2.RedundancyStatus) *garagev1beta2.RedundancyStatus {
		if status == nil {
			return nil
		}
		copied := status.DeepCopy()
		copied.Nodes = nil
		copied.ProgressObservedAt = nil
		return copied
	}
	return equality.Semantic.DeepEqual(strip(a), strip(b))
}

// normalizeRedundancyEvidence turns empty maps and slices into nil, matching
// what a round trip through the API server returns, so an unchanged proof
// compares equal to its persisted form and causes no write.
func normalizeRedundancyEvidence(verification *garagev1beta2.RedundancyVerificationStatus) {
	if verification == nil {
		return
	}
	if len(verification.CompletedNodeIDs) == 0 {
		verification.CompletedNodeIDs = nil
	}
	if verification.Evidence == nil {
		return
	}
	evidence := verification.Evidence
	for _, values := range []*map[string]uint64{&evidence.SyncErrorBaselines, &evidence.ResyncErrorBaselines} {
		if len(*values) == 0 {
			*values = nil
		}
	}
	if len(evidence.TablesRecheckNodeIDs) == 0 {
		evidence.TablesRecheckNodeIDs = nil
	}
}

// ---------------------------------------------------------------------------
// Controller glue
// ---------------------------------------------------------------------------

// redundancyResponses are the Admin API reads the status pass already made.
type redundancyResponses struct {
	Health      *garage.ClusterHealth
	Status      *garage.ClusterStatus
	History     *garage.LayoutHistoryResponse
	Workers     *garage.ListWorkersResponse
	BlockErrors *garage.ListBlockErrorsResponse
}

// redundancyApplies reports whether this GarageCluster owns storage it can
// verify. Gateway-only, connectTo and management-handle clusters do not.
func redundancyApplies(cluster *garagev1beta2.GarageCluster) bool {
	return cluster.HasStorageTier() && cluster.Spec.ConnectTo == nil
}

type redundancySnapshot struct {
	Status    *garagev1beta2.RedundancyStatus
	Condition *metav1.Condition
}

func redundancyStatusSnapshot(cluster *garagev1beta2.GarageCluster) redundancySnapshot {
	snapshot := redundancySnapshot{Status: cluster.Status.Redundancy.DeepCopy()}
	if condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated); condition != nil {
		snapshot.Condition = condition.DeepCopy()
	}
	return snapshot
}

// keepFreshRedundancyOnConflict is the redundancy CAS. After a status-update
// conflict, if another writer already changed status.redundancy since this
// pass read it, the fresh value and its condition win: a pass that started
// from a stale cache must never roll persisted proof evidence back.
func keepFreshRedundancyOnConflict(
	merged garagev1beta2.GarageClusterStatus,
	base, fresh redundancySnapshot,
) garagev1beta2.GarageClusterStatus {
	if equality.Semantic.DeepEqual(base.Status, fresh.Status) {
		return merged
	}
	merged.Redundancy = fresh.Status.DeepCopy()
	meta.RemoveStatusCondition(&merged.Conditions, garagev1beta1.ConditionFullyReplicated)
	if fresh.Condition != nil {
		merged.Conditions = append(merged.Conditions, *fresh.Condition.DeepCopy())
	}
	return merged
}

func (r *GarageClusterReconciler) redundancyNow() time.Time {
	if r.redundancyClock != nil {
		return r.redundancyClock()
	}
	return time.Now()
}

// applyRedundancyStatus advances the proof, performs the requested repairs,
// and writes status.redundancy and the FullyReplicated condition into the
// in-memory status. It returns true while a proof is running.
func (r *GarageClusterReconciler) applyRedundancyStatus(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	responses redundancyResponses,
) bool {
	if !redundancyApplies(cluster) {
		cluster.Status.Redundancy = nil
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated)
		return false
	}
	log := logf.FromContext(ctx)
	in := redundancyInput{
		Now:               r.redundancyNow(),
		QuietPeriod:       effectiveBlockResyncQuietPeriod(r.blockResyncQuietPeriod, cluster),
		ClusterUID:        string(cluster.UID),
		ClusterName:       cluster.Name,
		Namespace:         cluster.Namespace,
		HasRemoteClusters: len(cluster.Spec.RemoteClusters) > 0,
		SiteRoleSet:       cluster.Spec.LayoutManagement != nil && cluster.Spec.LayoutManagement.SiteRole != "",
		TopologyAutoProof: cluster.Spec.LayoutManagement != nil && cluster.Spec.LayoutManagement.RedundancyVerification != nil &&
			cluster.Spec.LayoutManagement.RedundancyVerification.OnTopologyChange,
		Follower:              cluster.IsLayoutFollower(),
		DrainActive:           cluster.Status.StorageDrain != nil,
		FactorMigrationActive: factorMigrationActive(cluster),
		RequestToken:          strings.TrimSpace(cluster.Annotations[garagev1beta1.AnnotationVerifyRedundancy]),
		Health:                responses.Health,
		Status:                responses.Status,
		History:               responses.History,
		Workers:               responses.Workers,
		BlockErrors:           responses.BlockErrors,
	}
	observed := garageClient != nil && responses.Health != nil && responses.Status != nil &&
		responses.History != nil && responses.Workers != nil && responses.BlockErrors != nil
	if observed {
		layout, err := garageClient.GetClusterLayout(ctx)
		if err != nil {
			log.V(1).Info("Failed to read the Garage layout for redundancy verification", "error", err)
			observed = false
		} else {
			in.Layout = layout
		}
	}
	if observed {
		local, external, err := r.redundancySiteNodeIDs(ctx, cluster)
		if err != nil {
			// Never fall back to tags: a federated writer would treat the
			// follower sites' nodes as its own.
			log.V(1).Info("Failed to list GarageNodes for redundancy verification", "error", err)
			observed = false
		}
		in.LocalNodeIDs, in.ExternalNodeIDs = local, external
	}
	in.Observed = observed

	result := advanceRedundancy(cluster.Status.Redundancy, in)
	status := result.Status
	for _, launch := range result.Launches {
		if err := garageClient.LaunchRepair(ctx, launch.NodeID, launch.RepairType); err != nil {
			log.Info("Launching a repair for redundancy verification failed; it is retried next pass",
				"node", shortID(launch.NodeID), "repairType", launch.RepairType, "error", err)
			if result.OnLaunchFailure != nil {
				status = result.OnLaunchFailure
			}
			break
		}
	}
	cluster.Status.Redundancy = status

	previous := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated)
	var previousReason string
	if previous != nil {
		previousReason = previous.Reason
	}
	condition := result.Condition
	condition.ObservedGeneration = cluster.Generation
	meta.SetStatusCondition(&cluster.Status.Conditions, condition)
	if condition.Reason != previousReason {
		switch condition.Reason {
		case garagev1beta1.ReasonRedundancyVerified:
			emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeNormal, "FullyReplicated", "%s", condition.Message)
		case garagev1beta1.ReasonRedundancyStalled:
			emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeWarning, "RedundancyStalled", "%s", condition.Message)
		}
	}
	return result.Active
}

// redundancySiteNodeIDs returns the Garage node IDs of this GarageCluster's
// GarageNodes: local (non-external, non-gateway, the processes at this site)
// and external. GarageNode references are namespace-local.
func (r *GarageClusterReconciler) redundancySiteNodeIDs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (local, external []string, err error) {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, nil, err
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) {
			continue
		}
		id := canonicalGarageNodeID(node.Status.NodeID)
		if id == "" {
			id = canonicalGarageNodeID(node.Spec.NodeID)
		}
		if id == "" {
			continue
		}
		switch {
		case node.Spec.External != nil:
			external = append(external, id)
		case !node.Spec.Gateway:
			local = append(local, id)
		}
	}
	return normalizedNodeIDs(local), normalizedNodeIDs(external), nil
}
