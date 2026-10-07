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
	// that must both see every table sync worker idle and empty.
	redundancyMetadataSettleGap = 30 * time.Second
	// redundancyMaxLaunchRounds bounds the repairs one proof attempt may
	// launch per stage: the first round plus two retries after a Garage
	// restart or a scan that reported errors. Each round launches at most one
	// repair per storage node.
	redundancyMaxLaunchRounds = 3
	// redundancyActiveRequeue is the longest status-pass interval while a
	// proof is running, so it never depends on status-only watch events.
	redundancyActiveRequeue = RequeueAfterShort

	redundancyMaxNodes           = 256
	redundancyMaxProgressLength  = 64
	redundancyRepairTypeTables   = "Tables"
	redundancyRepairTypeBlocks   = garagev1beta1.RepairTypeBlocks
	redundancyTableSyncSuffix    = " sync"
	redundancyTableMerkleSuffix  = " Merkle"
	redundancyTableQueueSuffix   = " queue"
	redundancyFollowerMessage    = "this site is a layout Follower; the layout-writer site's GarageCluster runs the verification and reports FullyReplicated"
	redundancyNotObservedMessage = "Garage Admin API did not answer; redundancy cannot be observed"
)

// redundancyMetadataTables are the tables a Garage "tables" repair fully
// syncs (src/api/admin/repair.rs, unchanged from the floor release to main-v2).
var redundancyMetadataTables = []string{"block_ref", "bucket_v2", "key", "object", "version"}

// redundancyInput is one status pass worth of observations.
type redundancyInput struct {
	Now         time.Time
	QuietPeriod time.Duration

	Follower              bool
	DrainActive           bool
	FactorMigrationActive bool
	RequestToken          string
	MembershipHash        string

	// Observed is false when any Admin API read below failed or the managed
	// storage Pods could not be listed.
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
	// OnLaunchFailure replaces Status when any launch fails.
	OnLaunchFailure *garagev1beta2.RedundancyStatus
	Launches        []redundancyLaunch
	Condition       metav1.Condition
	// Active is true while a proof is running (not Verified, not Follower).
	Active bool
}

// redundancyObservation is the per-pass digest of the Garage responses.
type redundancyObservation struct {
	LayoutVersion  int64
	StorageNodeIDs []string
	DownNodeIDs    []string
	Workers        map[string][]garage.WorkerInfo
	WorkersOK      map[string]bool
	BlockErrors    map[string][]garage.BlockError
	BlockErrorsOK  map[string]bool
	// BlockErrorTotal is the number of distinct block hashes with errors.
	BlockErrorTotal int64
}

func newRedundancyObservation(in redundancyInput) redundancyObservation {
	obs := redundancyObservation{
		Workers:       map[string][]garage.WorkerInfo{},
		WorkersOK:     map[string]bool{},
		BlockErrors:   map[string][]garage.BlockError{},
		BlockErrorsOK: map[string]bool{},
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

// redundancyMembershipHash fingerprints the storage membership and the exact
// managed Pod incarnations (UID and garage container restart count).
func redundancyMembershipHash(storageNodeIDs []string, podIncarnations []string) string {
	hash := sha256.New()
	for _, nodeID := range normalizedNodeIDs(storageNodeIDs) {
		_, _ = fmt.Fprintf(hash, "node:%s\n", nodeID)
	}
	pods := append([]string(nil), podIncarnations...)
	sort.Strings(pods)
	for _, pod := range pods {
		_, _ = fmt.Fprintf(hash, "pod:%s\n", pod)
	}
	return hex.EncodeToString(hash.Sum(nil))
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

	if in.Follower {
		next.Verification = nil
		next.LastProgressAt = nil
		applyRedundancyProgress(prev, next, obs, in.Now, !equalRedundancyIgnoringProgress(prev, next))
		return redundancyResult{
			Status:    next,
			Condition: redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyPreconditionsNotMet, redundancyFollowerMessage),
		}
	}

	step := &redundancyStep{in: in, obs: obs, now: metav1.NewTime(in.Now), next: next}
	step.invalidate()
	condition := step.run()
	verification := next.Verification
	active := verification.Phase != garagev1beta2.RedundancyPhaseVerified
	if active {
		step.trackProgress(prev)
		if condition.Reason == garagev1beta1.ReasonRedundancyVerifying {
			condition = step.stallOrErrors(condition)
		}
	} else {
		verification.Evidence = nil
	}
	normalizeRedundancyEvidence(verification)

	applyRedundancyProgress(prev, next, obs, in.Now, !equalRedundancyIgnoringProgress(prev, next))
	result := redundancyResult{Status: next, Launches: step.launches, Condition: condition, Active: active}
	if step.onLaunchFailure != nil {
		failure := next.DeepCopy()
		failure.Verification = step.onLaunchFailure
		normalizeRedundancyEvidence(failure.Verification)
		result.OnLaunchFailure = failure
	}
	return result
}

type redundancyStep struct {
	in   redundancyInput
	obs  redundancyObservation
	now  metav1.Time
	next *garagev1beta2.RedundancyStatus

	launches        []redundancyLaunch
	onLaunchFailure *garagev1beta2.RedundancyVerificationStatus
	// advanced records that the proof moved forward this pass (a phase was
	// entered, a repair was launched or adopted); it counts as progress.
	advanced          bool
	repairErrorNodeID string
	syncErrorNodeID   string
}

func (s *redundancyStep) now64() time.Time { return s.now.Time }

// invalidate applies the design's invalidating events, in order, and binds
// the proof to the current layout version, membership and request token.
func (s *redundancyStep) invalidate() {
	v := s.next.Verification
	var trigger garagev1beta2.RedundancyTrigger
	switch {
	case v == nil:
		trigger = garagev1beta2.RedundancyTriggerInitial
	case s.in.RequestToken != "" && s.in.RequestToken != v.RequestToken:
		trigger = garagev1beta2.RedundancyTriggerRequested
	case s.obs.LayoutVersion != v.LayoutVersion:
		trigger = garagev1beta2.RedundancyTriggerLayoutChanged
	case s.in.MembershipHash != v.MembershipHash:
		trigger = garagev1beta2.RedundancyTriggerNodeChanged
	case len(s.obs.DownNodeIDs) > 0 && v.Phase != garagev1beta2.RedundancyPhasePending:
		trigger = garagev1beta2.RedundancyTriggerNodeDown
	case v.Phase == garagev1beta2.RedundancyPhaseVerified && s.obs.BlockErrorTotal > 0:
		trigger = garagev1beta2.RedundancyTriggerBlockErrors
	}
	if trigger != "" {
		s.reset(trigger)
	}
	v = s.next.Verification
	v.LayoutVersion = s.obs.LayoutVersion
	v.MembershipHash = s.in.MembershipHash
	if s.in.RequestToken != "" {
		v.RequestToken = s.in.RequestToken
	}
}

func (s *redundancyStep) reset(trigger garagev1beta2.RedundancyTrigger) {
	v := s.next.Verification
	if v == nil {
		v = &garagev1beta2.RedundancyVerificationStatus{}
		s.next.Verification = v
	}
	if v.Phase == garagev1beta2.RedundancyPhasePending && v.Evidence == nil && v.StartedAt != nil {
		// Already waiting to start: refine the trigger without restarting the
		// attempt, so repeated events do not rewrite timestamps every pass.
		v.Trigger = trigger
		return
	}
	now := s.now
	v.Phase = garagev1beta2.RedundancyPhasePending
	v.Trigger = trigger
	v.StartedAt = &now
	v.PhaseStartedAt = now.DeepCopy()
	v.Evidence = nil
	s.next.LastProgressAt = now.DeepCopy()
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

func (s *redundancyStep) run() metav1.Condition {
	v := s.next.Verification
	if v.Phase == garagev1beta2.RedundancyPhaseVerified {
		return s.verified()
	}
	if message := s.preconditionFailure(); message != "" {
		if v.Phase != garagev1beta2.RedundancyPhasePending || v.Evidence != nil {
			v.Phase = garagev1beta2.RedundancyPhasePending
			v.PhaseStartedAt = s.now.DeepCopy()
			v.Evidence = nil
		}
		return redundancyCondition(metav1.ConditionUnknown, garagev1beta1.ReasonRedundancyPreconditionsNotMet, message)
	}
	if v.Phase == garagev1beta2.RedundancyPhasePending {
		v.Evidence = &garagev1beta2.RedundancyProofEvidence{}
		if v.Trigger == garagev1beta2.RedundancyTriggerLayoutChanged {
			// The settled-history precondition proves every node's sync
			// tracker reached this version after the change (design fact 2).
			s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
		} else {
			s.enter(garagev1beta2.RedundancyPhaseSyncingMetadata)
		}
	}
	if v.Evidence == nil {
		v.Evidence = &garagev1beta2.RedundancyProofEvidence{}
	}
	if v.Phase == garagev1beta2.RedundancyPhaseSyncingMetadata {
		condition, done := s.syncMetadata()
		if !done {
			return condition
		}
		evidence := v.Evidence
		evidence.MetadataLaunchedAt = nil
		evidence.MetadataWorkerBaselines = nil
		evidence.MetadataErrorBaselines = nil
		evidence.MetadataIdleSince = nil
		s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
	}
	return s.scanBlocks()
}

func (s *redundancyStep) verified() metav1.Condition {
	v := s.next.Verification
	return redundancyCondition(metav1.ConditionTrue, garagev1beta1.ReasonRedundancyVerified, fmt.Sprintf(
		"Full redundancy verified on layout version %d for %d storage nodes", v.LayoutVersion, len(s.obs.StorageNodeIDs),
	))
}

func (s *redundancyStep) preconditionFailure() string {
	in := s.in
	switch {
	case in.DrainActive:
		return "a storage drain owns the cluster (status.storageDrain); verification runs after it completes"
	case in.FactorMigrationActive:
		return "a replication-factor migration is in progress; verification runs after it completes"
	case len(s.obs.StorageNodeIDs) == 0:
		return "Garage reports no storage nodes with capacity in the current layout"
	case len(s.obs.DownNodeIDs) > 0:
		return fmt.Sprintf("storage node %s is down", shortID(s.obs.DownNodeIDs[0]))
	case in.Health == nil || in.Health.StorageNodesUp != in.Health.StorageNodes:
		return "not every storage node is connected"
	case in.Health.PartitionsAllOK != in.Health.Partitions:
		return "not every partition has all of its replicas connected"
	case in.History == nil || requireSettledLayoutHistoryResponse(in.History) != nil:
		return "the Garage layout history is still migrating data to the current version"
	case in.Layout == nil || len(in.Layout.StagedRoleChanges) > 0 || in.Layout.StagedParameters != nil:
		return "the Garage layout has staged changes that are not applied"
	case in.Status == nil || in.Layout.Version != in.History.CurrentVersion || in.Status.LayoutVersion != in.History.CurrentVersion:
		return "Garage layout snapshots disagree; waiting for them to converge"
	}
	for _, nodeID := range s.obs.StorageNodeIDs {
		if !s.obs.WorkersOK[nodeID] || !s.obs.BlockErrorsOK[nodeID] {
			return fmt.Sprintf("storage node %s did not report its workers or block errors", shortID(nodeID))
		}
	}
	return ""
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

// launchMetadata records the pre-launch baselines and requests a tables repair
// on every storage node. If any launch fails, the caller keeps
// onLaunchFailure, which has no recorded launch, so the next pass retries.
// redundancyExhausted reports a stage that used all its launch rounds. The
// proof launches nothing more until a new attempt starts (a new
// verify-redundancy token, a layout or membership change, or a node outage).
func redundancyExhausted(repair string) metav1.Condition {
	return redundancyCondition(metav1.ConditionFalse, garagev1beta1.ReasonRedundancyStalled, fmt.Sprintf(
		"the %s repair was launched %d times without a clean pass; fix the node and set the %s annotation to a new value to retry",
		repair, redundancyMaxLaunchRounds, garagev1beta1.AnnotationVerifyRedundancy,
	))
}

func (s *redundancyStep) launchMetadata() metav1.Condition {
	v := s.next.Verification
	failure := v.DeepCopy()
	failure.Evidence.MetadataLaunchedAt = nil
	failure.Evidence.MetadataWorkerBaselines = nil
	failure.Evidence.MetadataErrorBaselines = nil
	failure.Evidence.MetadataIdleSince = nil

	workerBaselines := make(map[string]uint64, len(s.obs.StorageNodeIDs))
	errorBaselines := make(map[string]uint64, len(s.obs.StorageNodeIDs)*len(redundancyMetadataTables))
	for _, nodeID := range s.obs.StorageNodeIDs {
		workers := s.obs.Workers[nodeID]
		workerBaselines[nodeID] = maxWorkerID(workers)
		for _, table := range redundancyMetadataTables {
			worker := workerByName(workers, table+redundancyTableSyncSuffix)
			if worker == nil {
				*v = *failure
				return s.verifying(fmt.Sprintf(
					"Syncing metadata: storage node %s does not report the %s sync worker", shortID(nodeID), table,
				))
			}
			errorBaselines[redundancyWorkerKey(nodeID, worker.ID)] = worker.Errors
		}
	}
	evidence := v.Evidence
	if evidence.MetadataLaunches >= redundancyMaxLaunchRounds {
		*v = *failure
		return redundancyExhausted("tables")
	}
	evidence.MetadataLaunches++
	launchedAt := s.now
	evidence.MetadataLaunchedAt = &launchedAt
	evidence.MetadataWorkerBaselines = workerBaselines
	evidence.MetadataErrorBaselines = errorBaselines
	evidence.MetadataIdleSince = nil
	for _, nodeID := range s.obs.StorageNodeIDs {
		s.launches = append(s.launches, redundancyLaunch{NodeID: nodeID, RepairType: redundancyRepairTypeTables})
	}
	s.onLaunchFailure = failure
	s.advanced = true
	return s.verifying("Syncing metadata: launched a full table sync on every storage node")
}

func (s *redundancyStep) syncMetadata() (metav1.Condition, bool) {
	evidence := s.next.Verification.Evidence
	if evidence.MetadataLaunchedAt == nil {
		return s.launchMetadata(), false
	}
	// A Garage restart drops the full-sync request with the process.
	for _, nodeID := range s.obs.StorageNodeIDs {
		baseline, found := evidence.MetadataWorkerBaselines[nodeID]
		if !found || maxWorkerID(s.obs.Workers[nodeID]) < baseline {
			return s.launchMetadata(), false
		}
	}
	keys := make([]string, 0, len(evidence.MetadataErrorBaselines))
	for key := range evidence.MetadataErrorBaselines {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pendingNodeID := ""
	relaunch := false
	for _, key := range keys {
		nodeID, workerID, ok := splitRedundancyWorkerKey(key)
		if !ok {
			return s.launchMetadata(), false
		}
		worker := workerByID(s.obs.Workers[nodeID], workerID)
		if worker == nil || !strings.HasSuffix(worker.Name, redundancyTableSyncSuffix) ||
			worker.Errors < evidence.MetadataErrorBaselines[key] {
			// The worker is gone or its counters went backwards: the process
			// restarted. A restart that keeps identical worker IDs and zero
			// counters is still safe: Garage starts its own full sync 20 s
			// after process start, which is inside redundancyMetadataSettleGap,
			// so the two clean observations cannot both precede it.
			return s.launchMetadata(), false
		}
		idleAndEmpty := worker.State.IsIdle() && worker.QueueLength != nil && *worker.QueueLength == 0
		if worker.Errors > evidence.MetadataErrorBaselines[key] {
			if s.syncErrorNodeID == "" {
				s.syncErrorNodeID = nodeID
			}
			if idleAndEmpty {
				// The pass finished, but a partition failed at least once;
				// only a clean pass counts.
				relaunch = true
			}
		}
		if !idleAndEmpty && pendingNodeID == "" {
			pendingNodeID = nodeID
		}
	}
	if relaunch && pendingNodeID == "" {
		return s.launchMetadata(), false
	}
	if pendingNodeID == "" {
		for _, nodeID := range s.obs.StorageNodeIDs {
			for _, worker := range s.obs.Workers[nodeID] {
				if redundancyMetadataQueueWorker(worker.Name) && worker.QueueLength != nil && *worker.QueueLength > 0 {
					pendingNodeID = nodeID
					break
				}
			}
			if pendingNodeID != "" {
				break
			}
		}
	}
	if pendingNodeID != "" || s.syncErrorNodeID != "" {
		evidence.MetadataIdleSince = nil
		if pendingNodeID == "" {
			pendingNodeID = s.syncErrorNodeID
		}
		return s.verifying(fmt.Sprintf("Syncing metadata: waiting for the table sync on storage node %s", shortID(pendingNodeID))), false
	}
	confirming := s.verifying("Syncing metadata: table sync finished on every storage node; confirming it stays idle")
	if evidence.MetadataIdleSince == nil {
		idleSince := s.now
		evidence.MetadataIdleSince = &idleSince
		return confirming, false
	}
	if s.now64().Sub(evidence.MetadataIdleSince.Time) < redundancyMetadataSettleGap {
		return confirming, false
	}
	return metav1.Condition{}, true
}

// scanBlocks drives the shared storage-drain engine with an empty removal
// set: every current storage node must complete a clean blocks repair and
// stay idle and error-free through the quiet period.
func (s *redundancyStep) scanBlocks() metav1.Condition {
	v := s.next.Verification
	evidence := v.Evidence
	observation, err := blockResyncObservationFromResponses(s.in.History, s.in.Layout, s.in.Status, s.in.Workers, s.in.BlockErrors)
	if err != nil {
		return s.verifying("Scanning blocks: waiting for a consistent Garage observation of every storage node")
	}
	proof := &blockResyncProof{
		LayoutVersion:        uint64(v.LayoutVersion),
		VerificationNodeIDs:  append([]string(nil), evidence.VerificationNodeIDs...),
		RepairBaselines:      copyUint64Map(evidence.RepairBaselines),
		RepairWorkerIDs:      copyUint64Map(evidence.RepairWorkerIDs),
		ResyncErrorBaselines: copyUint64Map(evidence.ResyncErrorBaselines),
		QuietSince:           evidence.QuietSince.DeepCopy(),
	}
	if len(proof.VerificationNodeIDs) == 0 {
		proof.VerificationNodeIDs = nil
	}
	proof.TargetHash = storageDrainProofTargetHash(proof)
	decision := evaluateBlockResyncProgress(proof, observation, s.now64(), s.in.QuietPeriod, false)
	result := decision.Proof
	if result == nil {
		return s.verifying("Scanning blocks: waiting for a consistent Garage observation of every storage node")
	}
	if len(result.RepairWorkerIDs) > len(evidence.RepairWorkerIDs) {
		s.advanced = true
	}
	evidence.VerificationNodeIDs = append([]string(nil), result.VerificationNodeIDs...)
	evidence.RepairBaselines = copyUint64Map(result.RepairBaselines)
	evidence.RepairWorkerIDs = copyUint64Map(result.RepairWorkerIDs)
	evidence.ResyncErrorBaselines = copyUint64Map(result.ResyncErrorBaselines)
	evidence.QuietSince = result.QuietSince.DeepCopy()

	for _, nodeID := range sortedKeysOf(evidence.RepairWorkerIDs) {
		worker := blockRepairWorker(observation.Nodes[nodeID].Workers, evidence.RepairWorkerIDs[nodeID])
		if worker != nil && worker.Errors > 0 {
			s.repairErrorNodeID = nodeID
			break
		}
	}
	if len(decision.LaunchNodeIDs) > 0 {
		if evidence.BlocksLaunches >= redundancyMaxLaunchRounds {
			return redundancyExhausted("blocks")
		}
		s.onLaunchFailure = v.DeepCopy()
		evidence.BlocksLaunches++
		for _, nodeID := range decision.LaunchNodeIDs {
			s.launches = append(s.launches, redundancyLaunch{NodeID: nodeID, RepairType: redundancyRepairTypeBlocks})
		}
		s.advanced = true
	}

	if decision.Ready {
		verifiedAt := s.now
		v.VerifiedAt = &verifiedAt
		s.enter(garagev1beta2.RedundancyPhaseVerified)
		v.Evidence = nil
		return s.verified()
	}
	if evidence.QuietSince != nil {
		s.enter(garagev1beta2.RedundancyPhaseSettling)
		end := metav1.NewTime(evidence.QuietSince.Add(s.in.QuietPeriod))
		if s.now64().Before(end.Time) {
			return s.verifying(fmt.Sprintf(
				"Settling: repair scans finished; block resync workers must stay idle and error-free until %s", redundancyTime(&end),
			))
		}
		return s.verifying("Settling: quiet period finished; waiting for every block resync worker to become idle")
	}
	s.enter(garagev1beta2.RedundancyPhaseScanningBlocks)
	for _, nodeID := range evidence.VerificationNodeIDs {
		workerID, adopted := evidence.RepairWorkerIDs[nodeID]
		if !adopted {
			return s.verifying(fmt.Sprintf("Scanning blocks: waiting for the blocks repair on storage node %s to start", shortID(nodeID)))
		}
		worker := blockRepairWorker(observation.Nodes[nodeID].Workers, workerID)
		if worker == nil || !worker.State.IsDone() || worker.Errors > 0 {
			return s.verifying(fmt.Sprintf("Scanning blocks: waiting for the blocks repair on storage node %s", shortID(nodeID)))
		}
	}
	return s.verifying("Scanning blocks: every blocks repair finished")
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
	var repairWorkerIDs map[string]uint64
	if verification != nil && verification.Evidence != nil {
		repairWorkerIDs = verification.Evidence.RepairWorkerIDs
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
	if verification == nil || verification.Evidence == nil {
		return
	}
	evidence := verification.Evidence
	for _, values := range []*map[string]uint64{
		&evidence.MetadataWorkerBaselines, &evidence.MetadataErrorBaselines,
		&evidence.RepairBaselines, &evidence.RepairWorkerIDs, &evidence.ResyncErrorBaselines,
	} {
		if len(*values) == 0 {
			*values = nil
		}
	}
	if len(evidence.VerificationNodeIDs) == 0 {
		evidence.VerificationNodeIDs = nil
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

// redundancyPodIncarnations lists "uid/restartCount" for every managed,
// non-terminating storage Pod of this cluster.
func (r *GarageClusterReconciler) redundancyPodIncarnations(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) ([]string, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, err
	}
	incarnations := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.UID == "" {
			continue
		}
		var restarts int32
		for j := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[j].Name == defaultAppName {
				restarts = pod.Status.ContainerStatuses[j].RestartCount
			}
		}
		incarnations = append(incarnations, fmt.Sprintf("%s/%d", pod.UID, restarts))
	}
	return incarnations, nil
}

func redundancyStorageNodeIDs(status *garage.ClusterStatus) []string {
	return newRedundancyObservation(redundancyInput{Status: status}).StorageNodeIDs
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
		Now:                   r.redundancyNow(),
		QuietPeriod:           effectiveBlockResyncQuietPeriod(r.blockResyncQuietPeriod, cluster),
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
	if observed && !in.Follower {
		layout, err := garageClient.GetClusterLayout(ctx)
		if err != nil {
			log.V(1).Info("Failed to read the Garage layout for redundancy verification", "error", err)
			observed = false
		} else {
			in.Layout = layout
		}
	}
	if observed && !in.Follower {
		incarnations, err := r.redundancyPodIncarnations(ctx, cluster)
		if err != nil {
			log.V(1).Info("Failed to list storage Pods for redundancy verification", "error", err)
			observed = false
		} else {
			in.MembershipHash = redundancyMembershipHash(redundancyStorageNodeIDs(responses.Status), incarnations)
		}
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
