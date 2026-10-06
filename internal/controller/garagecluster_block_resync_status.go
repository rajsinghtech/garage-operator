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
	"math"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	maximumReportedBlockErrors = 32

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
func observeBlockResyncStatus(
	ctx context.Context,
	garageClient *garage.Client,
	status *garagev1beta2.GarageClusterStatus,
	now time.Time,
	ignorableNodeIDs map[string]struct{},
) {
	log := logf.FromContext(ctx)

	workers, err := garageClient.ListWorkers(ctx, "*", false, false)
	switch {
	case err != nil:
		log.V(1).Info("Failed to list Garage workers for resync status", "error", err)
		status.ResyncQueueLength = nil
	case logPartialNodeErrors(ctx, "ListWorkers", workers.Error, ignorableNodeIDs):
		status.ResyncQueueLength = nil
	default:
		status.ResyncQueueLength = ptr.To(resyncQueueLength(workers))
	}

	blockErrors, err := garageClient.ListBlockErrors(ctx, "*")
	switch {
	case err != nil:
		log.V(1).Info("Failed to list Garage block errors for status", "error", err)
		clearBlockErrorStatus(status)
	case logPartialNodeErrors(ctx, "ListBlockErrors", blockErrors.Error, ignorableNodeIDs):
		clearBlockErrorStatus(status)
	default:
		applyBlockErrorStatus(status, blockErrors, now)
	}
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
