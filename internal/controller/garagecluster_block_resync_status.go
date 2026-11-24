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
	"maps"
	"math"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	maximumReportedBlockErrors = 32

	// maximumListedBlockErrors bounds the error set a requested
	// verify-redundancy pass lists by hash for blockErrorDetails.topErrors.
	// Garage builds ListBlockErrors synchronously, with one refcount lookup
	// per errored block; at ~250k errors it runs for minutes on a Garage
	// executor thread and slows the resync drain (#604). The regular status
	// pass never lists: counts come from each node's block resync worker
	// (persistentErrors).
	maximumListedBlockErrors = 4096

	// Garage reports block-error times relative to its own clock, so the
	// derived absolute times jitter by about a second between passes. Reusing
	// the previous value inside this window keeps a steady error set from
	// rewriting status, which would immediately re-trigger reconcile.
	blockErrorTimestampTolerance = 2 * time.Second
)

// observeBlockResyncStatus refreshes ResyncQueueLength and the block-error
// fields from every node Garage can address. A field is left unobserved (nil)
// unless every node that can hold blocks answered: a sum that skips a down
// node holding the backlog must not look drained. Nodes in
// ignorableNodeIDs (current capacityless gateway roles, see
// capacitylessGatewayNodeIDs) store no blocks, so their silence is tolerated;
// otherwise one unreachable remote gateway would blank these fields on every
// federated or edge-gateway cluster.
//
// Block-error counts come only from ListWorkers (each block resync worker's
// persistentErrors). ListBlockErrors is called only when listDetails is set
// (a requested verify-redundancy proof, see blockErrorDetailsRequested) and
// the error set is at most maximumListedBlockErrors records; its hashes fill
// blockErrorDetails.topErrors. The returned block-error response always
// carries the counts, so the redundancy proof reads the same numbers on
// every pass whether or not hashes were listed.
func observeBlockResyncStatus(
	ctx context.Context,
	garageClient *garage.Client,
	status *garagev1beta2.GarageClusterStatus,
	now time.Time,
	ignorableNodeIDs map[string]struct{},
	listDetails bool,
) (*garage.ListWorkersResponse, *garage.ListBlockErrorsResponse) {
	log := logf.FromContext(ctx)

	workers, err := listWorkersWithBackoff(ctx, garageClient)
	if err != nil {
		log.V(1).Info("Failed to list Garage workers for resync status", "error", err)
		clearBlockResyncStatus(status)
		return nil, nil
	}
	partial := logPartialNodeErrors(ctx, "ListWorkers", workers.Error, ignorableNodeIDs)
	counts, countsOK := resyncPersistentErrorCounts(workers, ignorableNodeIDs)
	var countOnly *garage.ListBlockErrorsResponse
	if countsOK {
		// The redundancy proof reads the answering nodes' counts even when
		// another node is silent; it defers that node as NotReporting.
		nodeErrors := make(map[string]string, len(workers.Error))
		maps.Copy(nodeErrors, workers.Error)
		countOnly = &garage.ListBlockErrorsResponse{
			Success: map[string][]garage.BlockError{}, Error: nodeErrors, Counts: counts,
		}
	}
	if partial {
		clearBlockResyncStatus(status)
		return workers, countOnly
	}
	status.ResyncQueueLength = ptr.To(resyncQueueLength(workers))
	if !countsOK {
		log.V(1).Info("A Garage storage node reported no block resync error counter; block errors are unobserved")
		clearBlockErrorStatus(status)
		return workers, nil
	}
	var total uint64
	for _, count := range counts {
		total += count
	}
	if listDetails && total > 0 {
		if total > maximumListedBlockErrors {
			log.V(1).Info("Too many Garage block errors to list for blockErrorDetails; reporting counts only",
				"persistentErrors", total, "limit", maximumListedBlockErrors)
		} else if listed := listBlockErrorDetails(ctx, garageClient, ignorableNodeIDs); listed != nil {
			applyBlockErrorStatus(status, listed, now)
			return workers, countOnly
		}
	}
	applyBlockErrorCountStatus(status, counts)
	return workers, countOnly
}

// listBlockErrorDetails lists block errors by hash for blockErrorDetails. It
// returns nil when the call is backing off, failed, or a node that can hold
// blocks did not answer; the caller then reports counts only.
func listBlockErrorDetails(
	ctx context.Context,
	garageClient *garage.Client,
	ignorableNodeIDs map[string]struct{},
) *garage.ListBlockErrorsResponse {
	blockErrors, err := listBlockErrorsWithBackoff(ctx, garageClient)
	switch {
	case err != nil:
		logf.FromContext(ctx).V(1).Info("Failed to list Garage block errors for blockErrorDetails; reporting counts only", "error", err)
		return nil
	case logPartialNodeErrors(ctx, "ListBlockErrors", blockErrors.Error, ignorableNodeIDs):
		return nil
	}
	return blockErrors
}

// blockErrorDetailsRequested reports whether this pass may list block hashes:
// a verify-redundancy request not yet handled, or a proof started by one
// that is still running. Topology-triggered proofs and idle clusters report
// counts only.
func blockErrorDetailsRequested(cluster *garagev1beta2.GarageCluster) bool {
	token := strings.TrimSpace(cluster.Annotations[garagev1beta1.AnnotationVerifyRedundancy])
	var verification *garagev1beta2.RedundancyVerificationStatus
	if cluster.Status.Redundancy != nil {
		verification = cluster.Status.Redundancy.Verification
	}
	if verification == nil {
		return token != ""
	}
	if token != "" && token != verification.RequestToken {
		return true
	}
	if verification.Trigger != garagev1beta2.RedundancyTriggerRequested {
		return false
	}
	switch verification.Phase {
	case garagev1beta2.RedundancyPhasePending, garagev1beta2.RedundancyPhaseSyncingMetadata,
		garagev1beta2.RedundancyPhaseScanningBlocks, garagev1beta2.RedundancyPhaseSettling:
		return true
	}
	return false
}

// resyncPersistentErrorCounts returns each answering node's persistent
// block-resync error count, taken from its block resync worker. ok is false
// when a node that can hold blocks exposes no such counter; block errors are
// then unobserved.
func resyncPersistentErrorCounts(workers *garage.ListWorkersResponse, ignorableNodeIDs map[string]struct{}) (map[string]uint64, bool) {
	counts := make(map[string]uint64, len(workers.Success))
	for nodeID, nodeWorkers := range workers.Success {
		found := false
		var count uint64
		for i := range nodeWorkers {
			worker := &nodeWorkers[i]
			if isBlockResyncWorkerName(worker.Name) && worker.PersistentErrors != nil {
				found = true
				count = max(count, *worker.PersistentErrors)
			}
		}
		if !found {
			if _, ignorable := ignorableNodeIDs[nodeID]; ignorable {
				continue
			}
			return nil, false
		}
		counts[nodeID] = count
	}
	return counts, true
}

// blockErrorCountLowerBound is the largest per-node count. Replicas of one
// block report it on each node, so the per-node maximum is a lower bound on
// the distinct blocks and never overstates them.
func blockErrorCountLowerBound(counts map[string]uint64) uint64 {
	var lowerBound uint64
	for _, count := range counts {
		lowerBound = max(lowerBound, count)
	}
	return lowerBound
}

// blockErrorCountIsExact reports whether blockErrorCountLowerBound is the
// exact number of distinct blocks: at most one node reports any error.
func blockErrorCountIsExact(counts map[string]uint64) bool {
	nonZero := 0
	for _, count := range counts {
		if count > 0 {
			nonZero++
		}
	}
	return nonZero <= 1
}

// applyBlockErrorCountStatus records a count-only observation: blockErrors
// is a lower bound and no per-block details are listed.
func applyBlockErrorCountStatus(status *garagev1beta2.GarageClusterStatus, counts map[string]uint64) {
	count := clampInt32(blockErrorCountLowerBound(counts))
	status.BlockErrors = ptr.To(count)
	if count == 0 {
		status.BlockErrorDetails = nil
		return
	}
	var lastErrorAt *metav1.Time
	if status.BlockErrorDetails != nil {
		lastErrorAt = status.BlockErrorDetails.LastErrorAt.DeepCopy()
	}
	status.BlockErrors = ptr.To(count)
	status.BlockErrorDetails = &garagev1beta2.BlockErrorsStatus{Count: count, LastErrorAt: lastErrorAt}
}

func clearBlockResyncStatus(status *garagev1beta2.GarageClusterStatus) {
	status.ResyncQueueLength = nil
	clearBlockErrorStatus(status)
}

func clearBlockErrorStatus(status *garagev1beta2.GarageClusterStatus) {
	status.BlockErrors = nil
	status.BlockErrorDetails = nil
}

// logPartialNodeErrors reports whether any node that can hold blocks failed
// to answer. Silence from an ignorable (capacityless gateway) node is logged
// but does not make the observation partial.
func logPartialNodeErrors(ctx context.Context, operation string, nodeErrors map[string]string, ignorableNodeIDs map[string]struct{}) bool {
	partial := false
	for nodeID, message := range nodeErrors {
		_, ignorable := ignorableNodeIDs[nodeID]
		logf.FromContext(ctx).V(1).Info("Garage node did not answer for resync status",
			"operation", operation, "node", shortID(nodeID), "capacitylessGateway", ignorable, "error", message)
		if !ignorable {
			partial = true
		}
	}
	return partial
}

// capacitylessGatewayNodeIDs returns the nodes whose current layout role has
// no storage capacity and which are not draining an older layout version.
// Such nodes never hold object blocks. A draining node may still be the
// source of a block transfer, and a node absent from status is unknown, so
// neither is ignorable. A nil status (GetClusterStatus failed) ignores
// nothing, keeping the observation strict.
func capacitylessGatewayNodeIDs(clusterStatus *garage.ClusterStatus) map[string]struct{} {
	if clusterStatus == nil {
		return nil
	}
	ids := make(map[string]struct{})
	for i := range clusterStatus.Nodes {
		node := &clusterStatus.Nodes[i]
		if node.Draining || node.Role == nil {
			continue
		}
		if node.Role.Capacity == nil || *node.Role.Capacity == 0 {
			ids[node.ID] = struct{}{}
		}
	}
	return ids
}

// resyncQueueLength sums the per-node resync queue. Every resync worker on a
// node reports the same node-wide queue (src/block/resync.rs), so take one
// value per node rather than summing workers.
func resyncQueueLength(workers *garage.ListWorkersResponse) int64 {
	var total int64
	for _, nodeWorkers := range workers.Success {
		var nodeQueue uint64
		for i := range nodeWorkers {
			worker := &nodeWorkers[i]
			if isBlockResyncWorkerName(worker.Name) && worker.QueueLength != nil && *worker.QueueLength > nodeQueue {
				nodeQueue = *worker.QueueLength
			}
		}
		total += int64(nodeQueue)
	}
	return total
}

// applyBlockErrorStatus counts distinct block hashes: a block missing on every
// replica is one broken block, not one per node reporting it.
func applyBlockErrorStatus(status *garagev1beta2.GarageClusterStatus, resp *garage.ListBlockErrorsResponse, now time.Time) {
	byHash := make(map[string]garage.BlockError)
	var mostRecentTrySecsAgo uint64 = math.MaxUint64
	for _, nodeErrors := range resp.Success {
		for _, blockErr := range nodeErrors {
			mostRecentTrySecsAgo = min(mostRecentTrySecsAgo, blockErr.LastTrySecsAgo)
			existing, seen := byHash[blockErr.BlockHash]
			if !seen || blockErr.ErrorCount > existing.ErrorCount ||
				(blockErr.ErrorCount == existing.ErrorCount && blockErr.LastTrySecsAgo < existing.LastTrySecsAgo) {
				byHash[blockErr.BlockHash] = blockErr
			}
		}
	}
	if len(byHash) == 0 {
		status.BlockErrors = ptr.To[int32](0)
		status.BlockErrorDetails = nil
		return
	}

	merged := make([]garage.BlockError, 0, len(byHash))
	for _, blockErr := range byHash {
		merged = append(merged, blockErr)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].ErrorCount != merged[j].ErrorCount {
			return merged[i].ErrorCount > merged[j].ErrorCount
		}
		return merged[i].BlockHash < merged[j].BlockHash
	})

	previous := status.BlockErrorDetails
	if previous == nil {
		previous = &garagev1beta2.BlockErrorsStatus{}
	}
	previousByHash := make(map[string]garagev1beta2.BlockErrorDetail, len(previous.TopErrors))
	for _, detail := range previous.TopErrors {
		previousByHash[detail.BlockHash] = detail
	}

	count := clampInt32(uint64(len(byHash)))
	details := &garagev1beta2.BlockErrorsStatus{
		Count:       count,
		LastErrorAt: stableBlockErrorTime(previous.LastErrorAt, now.Add(-secondsDuration(mostRecentTrySecsAgo))),
		TopErrors:   make([]garagev1beta2.BlockErrorDetail, 0, min(len(merged), maximumReportedBlockErrors)),
	}
	for _, blockErr := range merged[:min(len(merged), maximumReportedBlockErrors)] {
		prev := previousByHash[blockErr.BlockHash]
		nextRetry := stableBlockErrorTime(prev.NextRetry, now.Add(secondsDuration(blockErr.NextTryInSecs)))
		// Garage saturates an overdue retry at 0s, which would otherwise move
		// NextRetry to "now" on every pass.
		if blockErr.NextTryInSecs == 0 && prev.NextRetry != nil && !prev.NextRetry.After(now) {
			nextRetry = prev.NextRetry.DeepCopy()
		}
		details.TopErrors = append(details.TopErrors, garagev1beta2.BlockErrorDetail{
			BlockHash:   blockErr.BlockHash,
			ErrorCount:  clampInt32(blockErr.ErrorCount),
			LastAttempt: stableBlockErrorTime(prev.LastAttempt, now.Add(-secondsDuration(blockErr.LastTrySecsAgo))),
			NextRetry:   nextRetry,
		})
	}
	status.BlockErrors = ptr.To(count)
	status.BlockErrorDetails = details
}

func stableBlockErrorTime(previous *metav1.Time, observed time.Time) *metav1.Time {
	if previous != nil {
		delta := previous.Sub(observed)
		if delta <= blockErrorTimestampTolerance && delta >= -blockErrorTimestampTolerance {
			return previous.DeepCopy()
		}
	}
	t := metav1.NewTime(observed.Truncate(time.Second))
	return &t
}

func secondsDuration(secs uint64) time.Duration {
	return time.Duration(secs) * time.Second
}

func clampInt32(v uint64) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v)
}
