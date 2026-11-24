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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/storagecontract"
)

const (
	// Garage defaults rpc_timeout to five minutes. A delayed block-incref check
	// can be scheduled for twice that value.
	defaultGarageRPCTimeout = 5 * time.Minute
	// Upstream schedules block garbage collection at BLOCK_GC_DELAY + 10s.
	garageBlockGCDelay    = 610 * time.Second
	blockRepairWorkerName = "Block repair worker"
)

type blockResyncNodeObservation struct {
	IsUp            bool
	WorkersObserved bool
	// BlockErrorsObserved is true when a block resync worker reported its
	// persistentErrors counter.
	BlockErrorsObserved bool
	WorkersError        string
	Workers             []garage.WorkerInfo
	QueueLength         uint64
	ErrorCount          uint64
}

type blockResyncObservation struct {
	LayoutVersion         uint64
	CurrentRoleNodeIDs    []string
	CurrentRoleTags       map[string][]string
	CurrentStorageNodeIDs []string
	VerificationNodeIDs   []string
	Nodes                 map[string]blockResyncNodeObservation
	// QueueLength includes future delayed work and is normally diagnostic only.
	QueueLength uint64
	// ErrorCount sums each node's persistent block-resync error count.
	ErrorCount uint64
}

type blockResyncProof struct {
	Actor                    storageDrainActor
	TransactionID            string
	TargetHash               string
	StartedAt                metav1.Time
	RoleRemovalNodeIDs       []string
	RemovedStorageNodeIDs    []string
	UnavailableSourceNodeIDs []string
	LayoutVersion            uint64
	VerificationNodeIDs      []string
	ManagedPodUIDs           map[string]string
	RepairBaselines          map[string]uint64
	RepairWorkerIDs          map[string]uint64
	ResyncErrorBaselines     map[string]uint64
	QueueLength              uint64
	ErrorCount               uint64
	RequiresEmptyQueue       bool
	QuietSince               *metav1.Time
	CompletedAt              *metav1.Time
}

type blockResyncDecision struct {
	Proof         *blockResyncProof
	LaunchNodeIDs []string
	Ready         bool
	Message       string
}

type storageDrainRevision struct {
	Exists          bool
	ActorAPIVersion string
	ActorKind       string
	ActorNamespace  string
	ActorName       string
	ActorUID        string
	TransactionID   string
	TargetHash      string
	IntentHash      string
	// ProofHash fingerprints the complete evolving storage-drain proof. Actor,
	// transaction, and target identify the authorization boundary, but they do
	// not change while worker baselines, repair IDs, or quiet-period evidence
	// advance. Including the proof itself in the compare-and-swap revision keeps
	// a stale same-actor reconcile from regressing already-persisted evidence
	// after a Kubernetes status-update conflict.
	ProofHash string
}

func normalizedNodeIDs(nodeIDs []string) []string {
	return storagecontract.NormalizeNodeIDs(nodeIDs)
}

func shortNodeIDs(nodeIDs []string) []string {
	result := make([]string, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		result = append(result, shortID(nodeID))
	}
	return result
}

func storageDrainTargetHash(roleRemovalNodeIDs, removedStorageNodeIDs []string, unavailableSourceNodeIDs ...[]string) string {
	return storagecontract.TargetHash(roleRemovalNodeIDs, removedStorageNodeIDs, unavailableSourceNodeIDs...)
}

func storageDrainProofTargetHash(proof *blockResyncProof) string {
	if proof == nil {
		return ""
	}
	return storageDrainTargetHash(
		proof.RoleRemovalNodeIDs, proof.RemovedStorageNodeIDs, proof.UnavailableSourceNodeIDs,
	)
}

func storageContractActor(actor storageDrainActor) storagecontract.Actor {
	return storagecontract.Actor{
		APIVersion: actor.APIVersion,
		Kind:       actor.Kind,
		Namespace:  actor.Namespace,
		Name:       actor.Name,
		UID:        string(actor.UID),
	}
}

func storageContractTerminalToken(proof *blockResyncProof) *storagecontract.TerminalToken {
	if proof == nil {
		return nil
	}
	var completedAt *time.Time
	if proof.CompletedAt != nil {
		completed := proof.CompletedAt.Time
		completedAt = &completed
	}
	return &storagecontract.TerminalToken{
		Actor:                    storageContractActor(proof.Actor),
		TransactionID:            proof.TransactionID,
		TargetHash:               proof.TargetHash,
		StartedAt:                proof.StartedAt.Time,
		CompletedAt:              completedAt,
		RoleRemovalNodeIDs:       proof.RoleRemovalNodeIDs,
		RemovedStorageNodeIDs:    proof.RemovedStorageNodeIDs,
		UnavailableSourceNodeIDs: proof.UnavailableSourceNodeIDs,
	}
}

func validateTerminalStorageDrain(
	proof *blockResyncProof,
	actor storageDrainActor,
	requiredRoleRemovalNodeIDs []string,
	requiredRemovedStorageNodeIDs []string,
) error {
	if err := storagecontract.ValidateTerminal(
		storageContractTerminalToken(proof),
		storageContractActor(actor),
		requiredRoleRemovalNodeIDs,
		requiredRemovedStorageNodeIDs,
	); err != nil {
		return fmt.Errorf("%w: %v", errLayoutMutationPending, err)
	}
	return nil
}

func copyUint64Map(input map[string]uint64) map[string]uint64 {
	if input == nil {
		return nil
	}
	result := make(map[string]uint64, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func copyStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func copyRequiredStringSlice(input []string) []string {
	result := make([]string, len(input))
	copy(result, input)
	return result
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func copyBlockResyncProof(previous *blockResyncProof) *blockResyncProof {
	if previous == nil {
		return nil
	}
	return &blockResyncProof{
		Actor:                    previous.Actor,
		TransactionID:            previous.TransactionID,
		TargetHash:               previous.TargetHash,
		StartedAt:                previous.StartedAt,
		RoleRemovalNodeIDs:       append([]string(nil), previous.RoleRemovalNodeIDs...),
		RemovedStorageNodeIDs:    append([]string(nil), previous.RemovedStorageNodeIDs...),
		UnavailableSourceNodeIDs: append([]string(nil), previous.UnavailableSourceNodeIDs...),
		LayoutVersion:            previous.LayoutVersion,
		VerificationNodeIDs:      append([]string(nil), previous.VerificationNodeIDs...),
		ManagedPodUIDs:           copyStringMap(previous.ManagedPodUIDs),
		RepairBaselines:          copyUint64Map(previous.RepairBaselines),
		RepairWorkerIDs:          copyUint64Map(previous.RepairWorkerIDs),
		ResyncErrorBaselines:     copyUint64Map(previous.ResyncErrorBaselines),
		QueueLength:              previous.QueueLength,
		ErrorCount:               previous.ErrorCount,
		RequiresEmptyQueue:       previous.RequiresEmptyQueue,
		QuietSince:               previous.QuietSince.DeepCopy(),
		CompletedAt:              previous.CompletedAt.DeepCopy(),
	}
}

func sameStorageDrainActor(left, right storageDrainActor) bool {
	return left.APIVersion == right.APIVersion && left.Kind == right.Kind &&
		left.Namespace == right.Namespace && left.Name == right.Name &&
		left.UID != "" && left.UID == right.UID
}

func storageDrainRemovalIntent(
	previous *blockResyncProof,
	actor storageDrainActor,
	roleRemovalNodeIDs []string,
	removedStorageNodeIDs []string,
	now time.Time,
) (*blockResyncProof, error) {
	if actor.UID == "" {
		return nil, fmt.Errorf("storage-drain actor %s %s/%s has no Kubernetes UID", actor.Kind, actor.Namespace, actor.Name)
	}
	combinedRoles := normalizedNodeIDs(roleRemovalNodeIDs)
	combinedStorage := normalizedNodeIDs(removedStorageNodeIDs)
	if previous == nil && len(combinedStorage) == 0 && actor.Kind != kindGarageCluster {
		return previous, nil
	}
	roleSet := make(map[string]struct{}, len(combinedRoles))
	for _, nodeID := range combinedRoles {
		roleSet[nodeID] = struct{}{}
	}
	for _, nodeID := range combinedStorage {
		if _, authorized := roleSet[nodeID]; !authorized {
			return nil, fmt.Errorf("positive-capacity storage target %s is missing from the authorized role-removal set", shortID(nodeID))
		}
	}
	if previous == nil {
		startedAt := metav1.NewTime(now)
		return &blockResyncProof{
			Actor:                 actor,
			TransactionID:         string(uuid.NewUUID()),
			TargetHash:            storageDrainTargetHash(combinedRoles, combinedStorage),
			StartedAt:             startedAt,
			RoleRemovalNodeIDs:    combinedRoles,
			RemovedStorageNodeIDs: combinedStorage,
		}, nil
	}
	if !sameStorageDrainActor(previous.Actor, actor) {
		return nil, fmt.Errorf(
			"%w: storage drain %s is owned by %s %s/%s UID %s",
			errLayoutMutationPending, previous.TransactionID, previous.Actor.Kind,
			previous.Actor.Namespace, previous.Actor.Name, previous.Actor.UID,
		)
	}
	combinedRoles = normalizedNodeIDs(append(append([]string(nil), previous.RoleRemovalNodeIDs...), combinedRoles...))
	combinedStorage = normalizedNodeIDs(append(append([]string(nil), previous.RemovedStorageNodeIDs...), combinedStorage...))
	combinedUnavailable := normalizedNodeIDs(previous.UnavailableSourceNodeIDs)
	if reflect.DeepEqual(previous.RoleRemovalNodeIDs, combinedRoles) &&
		reflect.DeepEqual(previous.RemovedStorageNodeIDs, combinedStorage) {
		return previous, nil
	}
	// Targets are monotonic within one transaction. Changing the target hash is
	// a compare-and-swap revision and invalidates every prior observation.
	return &blockResyncProof{
		Actor:                    previous.Actor,
		TransactionID:            previous.TransactionID,
		TargetHash:               storageDrainTargetHash(combinedRoles, combinedStorage, combinedUnavailable),
		StartedAt:                previous.StartedAt,
		RoleRemovalNodeIDs:       combinedRoles,
		RemovedStorageNodeIDs:    combinedStorage,
		UnavailableSourceNodeIDs: combinedUnavailable,
	}, nil
}

func resetBlockResyncObservation(previous *blockResyncProof) *blockResyncProof {
	next := copyBlockResyncProof(previous)
	if next == nil {
		return nil
	}
	next.QuietSince = nil
	next.CompletedAt = nil
	return next
}

func resetBlockResyncEvidence(previous *blockResyncProof) *blockResyncProof {
	if previous == nil {
		return nil
	}
	return &blockResyncProof{
		Actor:                    previous.Actor,
		TransactionID:            previous.TransactionID,
		TargetHash:               previous.TargetHash,
		StartedAt:                previous.StartedAt,
		RoleRemovalNodeIDs:       append([]string(nil), previous.RoleRemovalNodeIDs...),
		RemovedStorageNodeIDs:    append([]string(nil), previous.RemovedStorageNodeIDs...),
		UnavailableSourceNodeIDs: append([]string(nil), previous.UnavailableSourceNodeIDs...),
		ManagedPodUIDs:           copyStringMap(previous.ManagedPodUIDs),
	}
}

func blockResyncIntentIncludes(proof *blockResyncProof, nodeID string) bool {
	if proof == nil {
		return false
	}
	for _, removedNodeID := range proof.RemovedStorageNodeIDs {
		if canonicalGarageNodeID(removedNodeID) == canonicalGarageNodeID(nodeID) {
			return true
		}
	}
	return false
}

func storageDrainUnavailableSourceIncludes(proof *blockResyncProof, nodeID string) bool {
	if proof == nil {
		return false
	}
	for _, unavailableNodeID := range proof.UnavailableSourceNodeIDs {
		if canonicalGarageNodeID(unavailableNodeID) == canonicalGarageNodeID(nodeID) {
			return true
		}
	}
	return false
}

func storageDrainLiveSourceNodeIDs(proof *blockResyncProof) []string {
	if proof == nil {
		return nil
	}
	result := make([]string, 0, len(proof.RemovedStorageNodeIDs))
	for _, nodeID := range proof.RemovedStorageNodeIDs {
		if !storageDrainUnavailableSourceIncludes(proof, nodeID) {
			result = append(result, nodeID)
		}
	}
	return normalizedNodeIDs(result)
}

func storageDrainRoleIntentIncludes(proof *blockResyncProof, nodeID string) bool {
	if proof == nil {
		return false
	}
	for _, removedNodeID := range proof.RoleRemovalNodeIDs {
		if canonicalGarageNodeID(removedNodeID) == canonicalGarageNodeID(nodeID) {
			return true
		}
	}
	return false
}

func garageNodeStoresBlocks(node *garagev1beta1.GarageNode) bool {
	return node != nil && !node.Spec.Gateway && node.Spec.Capacity != nil && node.Spec.Capacity.Sign() > 0
}

func readBlockResyncObservation(ctx context.Context, garageClient *garage.Client) (*blockResyncObservation, error) {
	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage layout history before storage-drain proof: %w", err)
	}
	if err := requireSettledLayoutHistoryResponse(history); err != nil {
		return nil, err
	}
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage layout before storage-drain proof: %w", err)
	}
	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage cluster status before storage-drain proof: %w", err)
	}
	// Error counts come from the block resync workers' persistentErrors, the
	// same records ListBlockErrors would list. Listing them by hash on every
	// drain pass runs for minutes on a large error set and slows the resync
	// drain this proof waits for (#604).
	workers, err := listWorkersWithBackoff(ctx, garageClient)
	if err != nil {
		return nil, fmt.Errorf("reading Garage background workers before storage-drain proof: %w", err)
	}
	return blockResyncObservationFromResponses(history, layout, status, workers)
}

func blockResyncObservationFromResponses(
	history *garage.LayoutHistoryResponse,
	layout *garage.ClusterLayout,
	status *garage.ClusterStatus,
	workers *garage.ListWorkersResponse,
) (*blockResyncObservation, error) {
	if history == nil || layout == nil || status == nil || workers == nil {
		return nil, fmt.Errorf("garage returned incomplete layout, status, or worker evidence")
	}
	if err := requireSettledLayoutHistoryResponse(history); err != nil {
		return nil, err
	}
	if len(layout.StagedRoleChanges) > 0 || layout.StagedParameters != nil {
		return nil, fmt.Errorf("%w: Garage's global staging area is not empty during storage-drain proof", errLayoutMutationPending)
	}
	if layout.Version != history.CurrentVersion || status.LayoutVersion != history.CurrentVersion {
		return nil, fmt.Errorf(
			"garage layout snapshots disagree while proving block migration (history=%d layout=%d status=%d)",
			history.CurrentVersion, layout.Version, status.LayoutVersion,
		)
	}

	currentRoleNodeIDs := make([]string, 0, len(layout.Roles))
	storageNodeIDs := make([]string, 0, len(layout.Roles))
	currentRoleTags := make(map[string][]string, len(layout.Roles))
	for i := range layout.Roles {
		role := &layout.Roles[i]
		currentRoleNodeIDs = append(currentRoleNodeIDs, role.ID)
		currentRoleTags[role.ID] = append([]string(nil), role.Tags...)
		if role.Capacity != nil && *role.Capacity > 0 {
			storageNodeIDs = append(storageNodeIDs, role.ID)
		}
	}
	currentRoleNodeIDs = normalizedNodeIDs(currentRoleNodeIDs)
	storageNodeIDs = normalizedNodeIDs(storageNodeIDs)
	if len(storageNodeIDs) == 0 {
		return nil, fmt.Errorf("garage reports no current positive-capacity storage roles to receive object blocks")
	}
	statusStorageNodeIDs := make([]string, 0, len(status.Nodes))
	for i := range status.Nodes {
		node := &status.Nodes[i]
		if node.Role != nil && node.Role.Capacity != nil && *node.Role.Capacity > 0 {
			statusStorageNodeIDs = append(statusStorageNodeIDs, node.ID)
		}
	}
	statusStorageNodeIDs = normalizedNodeIDs(statusStorageNodeIDs)
	if !reflect.DeepEqual(statusStorageNodeIDs, storageNodeIDs) {
		return nil, fmt.Errorf("garage layout and status disagree on current storage membership")
	}

	observedNodes := make(map[string]blockResyncNodeObservation, len(status.Nodes))
	for i := range status.Nodes {
		node := &status.Nodes[i]
		evidence := observedNodes[node.ID]
		evidence.IsUp = node.IsUp
		observedNodes[node.ID] = evidence
	}
	for nodeID, nodeWorkers := range workers.Success {
		evidence := observedNodes[nodeID]
		evidence.WorkersObserved = true
		evidence.Workers = append([]garage.WorkerInfo(nil), nodeWorkers...)
		var persistentErrors uint64
		for i := range nodeWorkers {
			worker := &nodeWorkers[i]
			if !isBlockResyncWorkerName(worker.Name) ||
				worker.QueueLength == nil || worker.PersistentErrors == nil {
				continue
			}
			if *worker.QueueLength > evidence.QueueLength {
				evidence.QueueLength = *worker.QueueLength
			}
			evidence.BlockErrorsObserved = true
			if *worker.PersistentErrors > persistentErrors {
				persistentErrors = *worker.PersistentErrors
			}
		}
		evidence.ErrorCount += persistentErrors
		observedNodes[nodeID] = evidence
	}
	for nodeID, message := range workers.Error {
		evidence := observedNodes[nodeID]
		evidence.WorkersError = message
		observedNodes[nodeID] = evidence
	}

	observation := &blockResyncObservation{
		LayoutVersion:         history.CurrentVersion,
		CurrentRoleNodeIDs:    currentRoleNodeIDs,
		CurrentRoleTags:       currentRoleTags,
		CurrentStorageNodeIDs: storageNodeIDs,
		VerificationNodeIDs:   append([]string(nil), storageNodeIDs...),
		Nodes:                 observedNodes,
	}
	for _, nodeID := range storageNodeIDs {
		evidence := observation.Nodes[nodeID]
		if evidence.WorkersError != "" {
			return nil, fmt.Errorf("current storage node %s did not return worker state: %s", shortID(nodeID), evidence.WorkersError)
		}
		if !evidence.WorkersObserved {
			return nil, fmt.Errorf("current storage node %s is missing from Garage's ListWorkers response", shortID(nodeID))
		}
		if !evidence.BlockErrorsObserved {
			return nil, fmt.Errorf("current storage node %s reported no block resync persistent-error count", shortID(nodeID))
		}
		observation.QueueLength += evidence.QueueLength
		observation.ErrorCount += evidence.ErrorCount
	}
	return observation, nil
}

// scopeBlockResyncObservation binds the proof to both sides of the transfer:
// every current positive-capacity destination and every removed-but-live
// source. Garage's `node=*` Admin API includes processes that are either in the
// layout or currently up, so a source remains addressable after Apply while it
// scans its local blocks and pushes unique data to the new assignment.
func scopeBlockResyncObservation(
	proof *blockResyncProof,
	observation *blockResyncObservation,
) (*blockResyncObservation, error) {
	if proof == nil || observation == nil {
		return nil, fmt.Errorf("storage-drain proof or Garage observation is missing")
	}
	for _, nodeID := range normalizedNodeIDs(proof.UnavailableSourceNodeIDs) {
		if evidence, found := observation.Nodes[nodeID]; found && evidence.IsUp {
			return nil, fmt.Errorf(
				"acknowledged unavailable source %s is up again; discarded destination-only proof until the exact source is stopped or the drain is recovered manually",
				shortID(nodeID),
			)
		}
	}
	verificationNodeIDs := normalizedNodeIDs(append(
		append([]string(nil), observation.CurrentStorageNodeIDs...),
		storageDrainLiveSourceNodeIDs(proof)...,
	))
	if len(verificationNodeIDs) == 0 {
		return nil, fmt.Errorf("garage reports no source or destination process for storage-drain verification")
	}

	scoped := *observation
	scoped.VerificationNodeIDs = verificationNodeIDs
	scoped.QueueLength = 0
	scoped.ErrorCount = 0
	for _, nodeID := range verificationNodeIDs {
		evidence, found := observation.Nodes[nodeID]
		if !found {
			return nil, fmt.Errorf("verification node %s is missing from Garage cluster status and Admin API evidence", shortID(nodeID))
		}
		if !evidence.IsUp {
			return nil, fmt.Errorf("verification node %s is not up; a removed source must remain live until its local blocks have been offloaded", shortID(nodeID))
		}
		if evidence.WorkersError != "" {
			return nil, fmt.Errorf("verification node %s did not return worker state: %s", shortID(nodeID), evidence.WorkersError)
		}
		if !evidence.WorkersObserved {
			return nil, fmt.Errorf("verification node %s is missing from Garage's ListWorkers response", shortID(nodeID))
		}
		if !evidence.BlockErrorsObserved {
			return nil, fmt.Errorf("verification node %s reported no block resync persistent-error count", shortID(nodeID))
		}
		scoped.QueueLength += evidence.QueueLength
		scoped.ErrorCount += evidence.ErrorCount
	}
	return &scoped, nil
}

func maxWorkerID(workers []garage.WorkerInfo) uint64 {
	var maximum uint64
	for i := range workers {
		if workers[i].ID > maximum {
			maximum = workers[i].ID
		}
	}
	return maximum
}

func isBlockResyncWorkerName(name string) bool {
	ordinal, found := strings.CutPrefix(name, "Block resync worker #")
	if !found || ordinal == "" {
		return false
	}
	_, err := strconv.ParseUint(ordinal, 10, 64)
	return err == nil
}

func blockRepairWorker(workers []garage.WorkerInfo, id uint64) *garage.WorkerInfo {
	for i := range workers {
		if workers[i].ID == id && workers[i].Name == blockRepairWorkerName {
			return &workers[i]
		}
	}
	return nil
}

func newestBlockRepairWorkerAfter(workers []garage.WorkerInfo, baseline uint64) *garage.WorkerInfo {
	var newest *garage.WorkerInfo
	for i := range workers {
		worker := &workers[i]
		if worker.Name != blockRepairWorkerName || worker.ID <= baseline {
			continue
		}
		if newest == nil || worker.ID > newest.ID {
			newest = worker
		}
	}
	return newest
}

func newBlockResyncSnapshotProof(
	previous *blockResyncProof,
	observation *blockResyncObservation,
	requiresEmptyQueue bool,
) *blockResyncProof {
	next := &blockResyncProof{
		Actor:                    previous.Actor,
		TransactionID:            previous.TransactionID,
		TargetHash:               previous.TargetHash,
		StartedAt:                previous.StartedAt,
		RoleRemovalNodeIDs:       append([]string(nil), previous.RoleRemovalNodeIDs...),
		RemovedStorageNodeIDs:    append([]string(nil), previous.RemovedStorageNodeIDs...),
		UnavailableSourceNodeIDs: append([]string(nil), previous.UnavailableSourceNodeIDs...),
		LayoutVersion:            observation.LayoutVersion,
		VerificationNodeIDs:      append([]string(nil), observation.VerificationNodeIDs...),
		ManagedPodUIDs:           copyStringMap(previous.ManagedPodUIDs),
		RepairBaselines:          make(map[string]uint64, len(observation.VerificationNodeIDs)),
		RepairWorkerIDs:          make(map[string]uint64, len(observation.VerificationNodeIDs)),
		QueueLength:              observation.QueueLength,
		ErrorCount:               observation.ErrorCount,
		RequiresEmptyQueue:       requiresEmptyQueue,
	}
	for _, nodeID := range observation.VerificationNodeIDs {
		next.RepairBaselines[nodeID] = maxWorkerID(observation.Nodes[nodeID].Workers)
	}
	return next
}

// evaluateBlockResyncProgress is side-effect free. The caller persists Proof
// before launching any requested repair, closing the crash window between the
// worker-ID baseline and the external Admin API action.
func evaluateBlockResyncProgress(
	previous *blockResyncProof,
	observation *blockResyncObservation,
	now time.Time,
	quietPeriod time.Duration,
	requiresEmptyQueue bool,
) blockResyncDecision {
	if previous == nil {
		return blockResyncDecision{Message: "no durable storage-drain transaction exists"}
	}
	if previous.TargetHash != storageDrainProofTargetHash(previous) {
		return blockResyncDecision{Proof: resetBlockResyncEvidence(previous), Message: "storage-drain target hash is inconsistent"}
	}
	currentRoles := make(map[string]struct{}, len(observation.CurrentRoleNodeIDs))
	for _, nodeID := range observation.CurrentRoleNodeIDs {
		currentRoles[nodeID] = struct{}{}
	}
	for _, removedNodeID := range previous.RoleRemovalNodeIDs {
		if _, present := currentRoles[removedNodeID]; present {
			return blockResyncDecision{
				Proof: resetBlockResyncEvidence(previous),
				Message: fmt.Sprintf(
					"recorded removal target %s is present in the current Garage layout; it must be removed again before proof can continue",
					shortID(removedNodeID),
				),
			}
		}
	}
	snapshotChanges := make([]string, 0, 4)
	if previous.LayoutVersion != observation.LayoutVersion {
		snapshotChanges = append(snapshotChanges, fmt.Sprintf(
			"layout version changed from %d to %d", previous.LayoutVersion, observation.LayoutVersion,
		))
	}
	if !reflect.DeepEqual(previous.VerificationNodeIDs, observation.VerificationNodeIDs) {
		snapshotChanges = append(snapshotChanges, fmt.Sprintf(
			"verification membership changed from %v to %v",
			shortNodeIDs(previous.VerificationNodeIDs), shortNodeIDs(observation.VerificationNodeIDs),
		))
	}
	if len(previous.RepairBaselines) != len(observation.VerificationNodeIDs) {
		snapshotChanges = append(snapshotChanges, fmt.Sprintf(
			"repair-baseline cardinality changed from %d to %d",
			len(previous.RepairBaselines), len(observation.VerificationNodeIDs),
		))
	}
	if previous.RequiresEmptyQueue != requiresEmptyQueue {
		snapshotChanges = append(snapshotChanges, fmt.Sprintf(
			"queue-bound mode changed from %t to %t", previous.RequiresEmptyQueue, requiresEmptyQueue,
		))
	}
	if len(snapshotChanges) > 0 {
		return blockResyncDecision{
			Proof: newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
			Message: fmt.Sprintf(
				"recorded pre-Blocks-repair worker baselines for Garage layout version %d after %s",
				observation.LayoutVersion, strings.Join(snapshotChanges, "; "),
			),
		}
	}

	next := copyBlockResyncProof(previous)
	next.QueueLength = observation.QueueLength
	next.ErrorCount = observation.ErrorCount
	next.RequiresEmptyQueue = requiresEmptyQueue

	if next.RepairWorkerIDs == nil {
		next.RepairWorkerIDs = make(map[string]uint64, len(observation.VerificationNodeIDs))
	}

	adoptedWorker := false
	launchNodeIDs := make([]string, 0)
	for _, nodeID := range observation.VerificationNodeIDs {
		nodeWorkers := observation.Nodes[nodeID].Workers
		baseline, found := previous.RepairBaselines[nodeID]
		if !found {
			return blockResyncDecision{Proof: newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue), Message: "verification membership changed while recording block-repair baselines"}
		}
		workerID, recorded := previous.RepairWorkerIDs[nodeID]
		if !recorded {
			if currentMaximum := maxWorkerID(nodeWorkers); currentMaximum < baseline {
				return blockResyncDecision{
					Proof:   newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
					Message: fmt.Sprintf("verification node %s restarted before its repair worker was recorded; refreshing worker-ID baselines", shortID(nodeID)),
				}
			}
			if worker := newestBlockRepairWorkerAfter(nodeWorkers, baseline); worker != nil {
				next.RepairWorkerIDs[nodeID] = worker.ID
				adoptedWorker = true
				continue
			}
			launchNodeIDs = append(launchNodeIDs, nodeID)
			continue
		}

		worker := blockRepairWorker(nodeWorkers, workerID)
		if worker == nil {
			return blockResyncDecision{
				Proof:   newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
				Message: fmt.Sprintf("verification node %s restarted or lost repair worker %d; recording new baselines", shortID(nodeID), workerID),
			}
		}
		if worker.Errors > 0 {
			next.QuietSince = nil
			next.CompletedAt = nil
			if worker.State.IsDone() {
				return blockResyncDecision{
					Proof:   newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
					Message: fmt.Sprintf("block repair worker %d on verification node %s completed with %d error(s); a clean repair will be launched", workerID, shortID(nodeID), worker.Errors),
				}
			}
			return blockResyncDecision{Proof: next, Message: fmt.Sprintf("waiting for errored block repair worker %d on verification node %s to finish before retrying", workerID, shortID(nodeID))}
		}
		if !worker.State.IsDone() {
			next.QuietSince = nil
			next.CompletedAt = nil
			return blockResyncDecision{Proof: next, Message: fmt.Sprintf("waiting for block repair worker %d on verification node %s (state=%s)", workerID, shortID(nodeID), worker.State.State)}
		}
	}
	if adoptedWorker {
		return blockResyncDecision{Proof: next, Message: "recorded exact post-baseline block repair workers"}
	}
	if len(launchNodeIDs) > 0 {
		sort.Strings(launchNodeIDs)
		return blockResyncDecision{Proof: next, LaunchNodeIDs: launchNodeIDs, Message: "launching transaction-specific Blocks repair on removed sources and current destinations"}
	}

	allResyncIdle := true
	currentErrorBaselines := make(map[string]uint64)
	for _, nodeID := range observation.VerificationNodeIDs {
		nodeWorkers := observation.Nodes[nodeID].Workers
		foundEnabled := false
		for i := range nodeWorkers {
			worker := &nodeWorkers[i]
			if !isBlockResyncWorkerName(worker.Name) ||
				worker.QueueLength == nil || worker.PersistentErrors == nil {
				continue
			}
			foundEnabled = true
			currentErrorBaselines[fmt.Sprintf("%s/%d", nodeID, worker.ID)] = *worker.PersistentErrors
			if !worker.State.IsIdle() {
				allResyncIdle = false
			}
		}
		if !foundEnabled {
			return blockResyncDecision{Proof: resetBlockResyncObservation(next), Message: fmt.Sprintf("verification node %s exposed no enabled block-resync worker with structured counters", shortID(nodeID))}
		}
	}
	if previous.ResyncErrorBaselines == nil {
		next.ResyncErrorBaselines = currentErrorBaselines
		quietSince := metav1.NewTime(now)
		next.QuietSince = &quietSince
		next.CompletedAt = nil
		return blockResyncDecision{Proof: next, Message: "recorded exact block-resync worker error baselines after all repair scans completed"}
	}
	if !reflect.DeepEqual(mapKeys(previous.ResyncErrorBaselines), mapKeys(currentErrorBaselines)) {
		return blockResyncDecision{
			Proof:   newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
			Message: "the exact enabled block-resync worker set changed; restarting a full repair transaction",
		}
	}
	for workerKey, currentErrors := range currentErrorBaselines {
		if currentErrors != previous.ResyncErrorBaselines[workerKey] {
			return blockResyncDecision{
				Proof:   newBlockResyncSnapshotProof(previous, observation, requiresEmptyQueue),
				Message: fmt.Sprintf("block-resync worker %s changed its persistent error counter; restarting a clean repair transaction", workerKey),
			}
		}
	}
	next.ResyncErrorBaselines = copyUint64Map(previous.ResyncErrorBaselines)

	if previous.QuietSince == nil {
		quietSince := metav1.NewTime(now)
		next.QuietSince = &quietSince
		next.CompletedAt = nil
		if quietPeriod > 0 {
			return blockResyncDecision{Proof: next, Message: fmt.Sprintf("all exact block repairs completed; waiting %s through Garage's delayed-resync interval", quietPeriod)}
		}
	} else {
		next.QuietSince = previous.QuietSince.DeepCopy()
		elapsed := now.Sub(previous.QuietSince.Time)
		if elapsed < quietPeriod {
			next.CompletedAt = nil
			return blockResyncDecision{Proof: next, Message: fmt.Sprintf("waiting %s more through Garage's delayed-resync interval", (quietPeriod - elapsed).Round(time.Second))}
		}
	}

	if next.ErrorCount > 0 {
		next.CompletedAt = nil
		return blockResyncDecision{Proof: next, Message: fmt.Sprintf("waiting for Garage block-resync errors to be repaired on removed sources and current destinations (errors=%d)", next.ErrorCount)}
	}
	if requiresEmptyQueue && observation.QueueLength > 0 {
		next.CompletedAt = nil
		return blockResyncDecision{Proof: next, Message: fmt.Sprintf("one or more verification nodes have no authoritative RPC-timeout bound; waiting for the block-resync queue to become empty (queue=%d)", observation.QueueLength)}
	}
	if !allResyncIdle {
		next.CompletedAt = nil
		return blockResyncDecision{Proof: next, Message: "delayed-resync interval elapsed; waiting for every exact enabled block-resync worker to become idle"}
	}
	if previous.CompletedAt == nil {
		completedAt := metav1.NewTime(now)
		next.CompletedAt = &completedAt
	} else {
		next.CompletedAt = previous.CompletedAt.DeepCopy()
	}
	return blockResyncDecision{
		Proof:   next,
		Ready:   true,
		Message: fmt.Sprintf("Garage repair workers completed cleanly and exact resync workers are idle/error-free after %s on layout version %d", quietPeriod, observation.LayoutVersion),
	}
}

func mapKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func effectiveBlockResyncQuietPeriod(configured time.Duration, cluster *garagev1beta2.GarageCluster) time.Duration {
	if configured < 0 {
		return 0
	}
	if configured > 0 {
		return configured
	}
	rpcTimeout := defaultGarageRPCTimeout
	if cluster != nil && cluster.Spec.Network.RPCTimeout != nil && cluster.Spec.Network.RPCTimeout.Duration > rpcTimeout {
		rpcTimeout = cluster.Spec.Network.RPCTimeout.Duration
	}
	quiet := 2 * rpcTimeout
	minimumKnownDelay := garageBlockGCDelay + RequeueAfterShort
	if quiet < minimumKnownDelay {
		return minimumKnownDelay
	}
	return quiet
}

func effectiveStorageDrainConsistencyMode(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil || cluster.Spec.Replication == nil || cluster.Spec.Replication.ConsistencyMode == "" {
		return consistencyModeConsistent
	}
	return strings.ToLower(cluster.Spec.Replication.ConsistencyMode)
}

// requireConsistentStorageDrain enforces the only upstream mode whose layout
// history is a durable data-migration barrier. In degraded and dangerous
// modes LayoutHelper discards the old active version before every registered
// sharded table (including block_ref) has reached quorum-safe convergence.
// The Admin API exposes no alternative transaction generation that could make
// an automatic positive-capacity removal safe in those modes.
func requireConsistentStorageDrain(cluster *garagev1beta2.GarageCluster) error {
	mode := effectiveStorageDrainConsistencyMode(cluster)
	if mode == consistencyModeConsistent {
		return nil
	}
	return fmt.Errorf(
		"%w: automatic positive-capacity drain requires spec.replication.consistencyMode: consistent; Garage mode %q discards historical layouts before block_ref migration is a durable quorum barrier. Roll every Garage process and federated site to consistent, wait for managed storage rollout and cluster health to converge, then retry",
		errUnsafeLayoutRoleRemoval, mode,
	)
}

// requireStorageDrainStartReady closes the desired-vs-running configuration
// race. A spec update renders consistent mode immediately, but OnDelete storage
// pods keep the old Garage process until the parent-controlled rollout has
// replaced every exact pod. The generation-bound condition is durable proof of
// that local handoff; live health is a second conservative start gate. External
// and federated peers remain an explicit operational contract and therefore use
// the stricter terminal queue-empty fallback.
func requireStorageDrainStartReady(cluster *garagev1beta2.GarageCluster) (string, error) {
	if cluster == nil {
		return garagev1beta1.ReasonStorageDrainWaitingForRollout,
			fmt.Errorf("%w: storage-drain layout owner is missing", errLayoutMutationPending)
	}
	if cluster.IsManagementHandle() {
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionManagementHandleReady)
		if condition == nil || condition.Status != metav1.ConditionTrue ||
			condition.ObservedGeneration != cluster.Generation {
			return garagev1beta1.ReasonStorageDrainWaitingForHealth, fmt.Errorf(
				"%w: management-handle layout owner must report ManagementHandleReady=True at generation %d before preparing an external GarageNode drain",
				errLayoutMutationPending, cluster.Generation,
			)
		}
		// A handle owns no local pod template or rollout. Live Garage health and
		// the layout-wide unverified-peer policy are checked separately against
		// the external Admin API; requiring StorageRolloutReady here would make a
		// connection-only topology impossible to manage.
		return "", nil
	}
	if factorMigrationActive(cluster) {
		return garagev1beta1.ReasonStorageDrainWaitingForRollout,
			fmt.Errorf("%w: replication-factor migration must finish before storage drain", errLayoutMutationPending)
	}
	if proof := clusterStorageDrainProof(cluster.Status.StorageDrain); proof != nil &&
		len(proof.UnavailableSourceNodeIDs) > 0 {
		// A lost rollout actor transfers directly into this exact durable drain.
		// The pre-transfer rollout record is the generation-bound convergence
		// baseline; requiring the now-cleared rollout condition again would make
		// destination-only recovery impossible. Live Garage health and exact
		// destination evidence remain mandatory below/at callers.
		return "", nil
	}
	if cluster.Status.StorageRollout != nil {
		return garagev1beta1.ReasonStorageDrainWaitingForRollout,
			fmt.Errorf("%w: managed pod replacement is still active", errLayoutMutationPending)
	}
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
	if condition == nil || condition.Status != metav1.ConditionTrue ||
		condition.ObservedGeneration != cluster.Generation {
		return garagev1beta1.ReasonStorageDrainWaitingForRollout, fmt.Errorf(
			"%w: wait for StorageRolloutReady=True at GarageCluster generation %d before removing positive capacity",
			errLayoutMutationPending, cluster.Generation,
		)
	}
	health := cluster.Status.Health
	if health == nil || health.Status != healthStatusHealthy || !health.Healthy || !health.Available ||
		health.StorageNodesOK != health.StorageNodes ||
		health.PartitionsQuorum != health.Partitions || health.PartitionsAllOK != health.Partitions {
		return garagev1beta1.ReasonStorageDrainWaitingForHealth,
			fmt.Errorf("%w: Garage must report every storage node and partition fully healthy before storage drain", errLayoutMutationPending)
	}
	return "", nil
}

func recordStorageDrainBlocked(
	ctx context.Context,
	kubeClient client.Client,
	cluster *garagev1beta2.GarageCluster,
	reason string,
	blocked error,
) error {
	if kubeClient == nil || cluster == nil || blocked == nil {
		return blocked
	}
	apply := func() {
		setStorageDrainCondition(cluster, metav1.ConditionFalse, reason, blocked.Error())
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, kubeClient, cluster, apply); err != nil {
		return fmt.Errorf("%v; additionally failed to publish StorageDrainReady: %w", blocked, err)
	}
	return blocked
}

func effectiveStorageDrainUnverifiedPeersPolicy(
	cluster *garagev1beta2.GarageCluster,
) garagev1beta2.StorageDrainUnverifiedPeersPolicy {
	if cluster == nil || cluster.Spec.LayoutManagement == nil || cluster.Spec.LayoutManagement.Drain == nil ||
		cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy == "" {
		return garagev1beta2.StorageDrainUnverifiedPeersBlock
	}
	return cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy
}

func storageDrainRoleTagsFromLayout(layout *garage.ClusterLayout) map[string][]string {
	if layout == nil {
		return nil
	}
	roles := make(map[string][]string, len(layout.Roles))
	for i := range layout.Roles {
		role := &layout.Roles[i]
		roles[role.ID] = append([]string(nil), role.Tags...)
	}
	return roles
}

type storageDrainPeerAssessment struct {
	RequiresEmptyQueue bool
	ManagedPodUIDs     map[string]string
}

func liveManagedGarageNodePodUID(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) (string, bool, error) {
	if node.Spec.External != nil || node.Status.ObservedPodUID == "" ||
		node.Status.ObservedGeneration != node.Generation || !node.Status.Connected {
		return "", false, nil
	}
	if isNodeLocalPoolBacked(node) {
		pods := &corev1.PodList{}
		if err := reader.List(ctx, pods,
			client.InNamespace(node.Namespace),
			client.MatchingLabels(map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: node.Spec.NodeLocalPoolName,
			}),
		); err != nil {
			return "", false, err
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.Spec.NodeName == node.Spec.KubernetesNodeName && string(pod.UID) == node.Status.ObservedPodUID &&
				pod.DeletionTimestamp.IsZero() && podReady(pod) {
				return string(pod.UID), true, nil
			}
		}
		return "", false, nil
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name + "-0"}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if string(pod.UID) != node.Status.ObservedPodUID || !pod.DeletionTimestamp.IsZero() || !podReady(pod) {
		return "", false, nil
	}
	return string(pod.UID), true, nil
}

// assessStorageDrainPeers maps every current layout process and every exact
// removed source required by the proof to the live Kubernetes Pod observed by
// its GarageNode. A removed source is intentionally allowed to report
// InLayout=false: after Apply that is the process which must remain alive long
// enough to scan and offload its local blocks. A cluster-uid tag proves who
// authored a role, but not which process incarnation is serving it, so an
// orphaned/tag-only role remains unverified. External GarageNodes,
// foreign/federated processes, and a declared remote topology are also
// unverified: Garage's Admin API does not expose their running consistency mode
// or provide a cross-control-plane transaction lock.
//
// Block is the fail-closed default. AssumeConsistent is an explicit operator
// maintenance assertion; it never weakens the terminal queue-empty fallback.
func assessStorageDrainPeers(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	roleTags map[string][]string,
	requiredNodeIDs []string,
) (storageDrainPeerAssessment, error) {
	if cluster == nil || cluster.UID == "" || reader == nil {
		return storageDrainPeerAssessment{}, fmt.Errorf("%w: cannot classify Garage layout processes without the layout-owner UID and Kubernetes reader", errUnsafeLayoutRoleRemoval)
	}
	managedPodUIDs := make(map[string]string)
	ambiguousManagedIDs := make(map[string]struct{})
	claimCounts := make(map[string]int)
	externalIDs := make(map[string]struct{})
	requiredIDs := make(map[string]struct{}, len(requiredNodeIDs))
	for _, nodeID := range normalizedNodeIDs(requiredNodeIDs) {
		requiredIDs[nodeID] = struct{}{}
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := reader.List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return storageDrainPeerAssessment{}, fmt.Errorf("%w: listing GarageNodes before storage drain: %v", errUnsafeLayoutRoleRemoval, err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		clusterNamespace := node.Namespace
		if node.Spec.ClusterRef.Namespace != "" {
			clusterNamespace = node.Spec.ClusterRef.Namespace
		}
		if node.Spec.ClusterRef.Name != cluster.Name || clusterNamespace != cluster.Namespace {
			continue
		}
		objectClaims := make(map[string]struct{}, 3)
		for _, nodeID := range []string{node.Status.NodeID, node.Spec.NodeID} {
			nodeID = canonicalGarageNodeID(nodeID)
			if nodeID == "" {
				continue
			}
			if _, duplicateWithinObject := objectClaims[nodeID]; duplicateWithinObject {
				continue
			}
			objectClaims[nodeID] = struct{}{}
		}
		pinnedNodeID, err := node.TrustedNodeLocalPoolRecoveryNodeID()
		if err != nil {
			return storageDrainPeerAssessment{}, fmt.Errorf("%w: validating GarageNode %s retained identity pin: %v", errUnsafeLayoutRoleRemoval, node.Name, err)
		}
		if pinnedNodeID != "" {
			objectClaims[pinnedNodeID] = struct{}{}
		}
		if len(objectClaims) > 1 {
			for nodeID := range objectClaims {
				ambiguousManagedIDs[nodeID] = struct{}{}
			}
		}
		podUID, locallyVerified, err := liveManagedGarageNodePodUID(ctx, reader, cluster, node)
		if err != nil {
			return storageDrainPeerAssessment{}, fmt.Errorf("%w: verifying GarageNode %s process incarnation: %v", errUnsafeLayoutRoleRemoval, node.Name, err)
		}
		for nodeID := range objectClaims {
			claimCounts[nodeID]++
			if node.Spec.External != nil {
				externalIDs[nodeID] = struct{}{}
			} else if _, required := requiredIDs[nodeID]; locallyVerified && (node.Status.InLayout || required) {
				if previous, duplicate := managedPodUIDs[nodeID]; duplicate && previous != podUID {
					ambiguousManagedIDs[nodeID] = struct{}{}
					delete(managedPodUIDs, nodeID)
				} else if _, ambiguous := ambiguousManagedIDs[nodeID]; !ambiguous {
					managedPodUIDs[nodeID] = podUID
				}
			}
		}
	}
	for nodeID, claims := range claimCounts {
		if claims > 1 {
			ambiguousManagedIDs[nodeID] = struct{}{}
			delete(managedPodUIDs, nodeID)
		}
	}
	currentManagedPodUIDs := make(map[string]string)
	unverified := make([]string, 0)
	processIDs := make(map[string]struct{}, len(roleTags)+len(requiredIDs))
	for nodeID := range roleTags {
		processIDs[canonicalGarageNodeID(nodeID)] = struct{}{}
	}
	for nodeID := range requiredIDs {
		processIDs[nodeID] = struct{}{}
	}
	for nodeID := range processIDs {
		if _, external := externalIDs[nodeID]; external {
			unverified = append(unverified, shortID(nodeID)+" (external GarageNode)")
			continue
		}
		if _, ambiguous := ambiguousManagedIDs[nodeID]; ambiguous {
			unverified = append(unverified, shortID(nodeID)+" (ambiguous managed identity)")
			continue
		}
		if podUID, managed := managedPodUIDs[nodeID]; managed {
			currentManagedPodUIDs[nodeID] = podUID
			continue
		}
		unverified = append(unverified, shortID(nodeID)+" (foreign, orphaned, or unmapped process)")
	}
	if len(cluster.Spec.RemoteClusters) > 0 {
		unverified = append(unverified, "spec.remoteClusters (no cross-control-plane lock)")
	}
	if len(unverified) == 0 {
		return storageDrainPeerAssessment{ManagedPodUIDs: currentManagedPodUIDs}, nil
	}
	sort.Strings(unverified)
	if effectiveStorageDrainUnverifiedPeersPolicy(cluster) != garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent {
		return storageDrainPeerAssessment{}, fmt.Errorf(
			"%w: automatic positive-capacity drain is blocked by unverified Garage processes: %s; the safe default is spec.layoutManagement.drain.unverifiedPeersPolicy: Block. Use AssumeConsistent only as an explicit assertion that every external/federated process runs literal consistencyMode=consistent and all topology/Admin operations are serialized across sites",
			errUnsafeLayoutRoleRemoval, strings.Join(unverified, ", "),
		)
	}
	return storageDrainPeerAssessment{RequiresEmptyQueue: true, ManagedPodUIDs: currentManagedPodUIDs}, nil
}

func requireLiveStorageDrainHealth(
	ctx context.Context,
	garageClient *garage.Client,
	getter func(context.Context, *garage.Client) (*garage.ClusterHealth, error),
) error {
	if getter == nil {
		getter = func(ctx context.Context, client *garage.Client) (*garage.ClusterHealth, error) {
			return client.GetClusterHealth(ctx)
		}
	}
	health, err := getter(ctx, garageClient)
	if err != nil {
		return fmt.Errorf("%w: reading live Garage health immediately before storage-drain mutation: %v", errLayoutMutationPending, err)
	}
	if health == nil || health.Status != healthStatusHealthy || health.StorageNodes == 0 ||
		health.StorageNodesUp != health.StorageNodes || health.Partitions == 0 ||
		health.PartitionsQuorum != health.Partitions || health.PartitionsAllOK != health.Partitions {
		return fmt.Errorf(
			"%w: live Garage health must be healthy with every storage node up and every partition fully replicated before storage drain",
			errLayoutMutationPending,
		)
	}
	return nil
}

func storageDrainRevisionFromStatus(status *garagev1beta2.StorageDrainStatus) storageDrainRevision {
	if status == nil {
		return storageDrainRevision{}
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		// StorageDrainStatus contains only JSON-native Kubernetes API fields, so
		// this is defensive. A non-empty sentinel still fails the revision check
		// closed instead of silently reducing it to the authorization boundary.
		encoded = []byte("unmarshalable-storage-drain-status")
	}
	proofDigest := sha256.Sum256(encoded)
	return storageDrainRevision{
		Exists:          true,
		ActorAPIVersion: status.Actor.APIVersion,
		ActorKind:       status.Actor.Kind,
		ActorNamespace:  status.Actor.Namespace,
		ActorName:       status.Actor.Name,
		ActorUID:        status.Actor.UID,
		TransactionID:   status.TransactionID,
		TargetHash:      status.TargetHash,
		IntentHash:      storageDrainTargetHash(status.RoleRemovalNodeIDs, status.RemovedStorageNodeIDs, status.UnavailableSourceNodeIDs),
		ProofHash:       fmt.Sprintf("sha256:%x", proofDigest[:]),
	}
}

func sameStorageDrainRevision(left, right storageDrainRevision) bool {
	return left == right
}

func updateClusterStorageDrainProof(
	ctx context.Context,
	kubeClient client.Client,
	cluster *garagev1beta2.GarageCluster,
	expected storageDrainRevision,
	proof *blockResyncProof,
	message string,
) error {
	if kubeClient == nil {
		return fmt.Errorf("persisting Garage storage-drain safety proof: Kubernetes client is not configured")
	}
	originalUID := cluster.UID
	for attempt := 0; attempt < StatusUpdateMaxRetries; attempt++ {
		if originalUID != "" && cluster.UID != originalUID {
			return fmt.Errorf("refusing to update storage drain across GarageCluster recreation")
		}
		currentRevision := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
		if !sameStorageDrainRevision(currentRevision, expected) {
			return fmt.Errorf("%w: storage-drain revision changed from %+v to %+v", errLayoutMutationPending, expected, currentRevision)
		}
		cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
		conditionStatus := metav1.ConditionFalse
		reason := garagev1beta1.ReasonStorageDraining
		if proof == nil {
			conditionStatus = metav1.ConditionTrue
			reason = garagev1beta1.ReasonStorageDrainIdle
		} else if proof.CompletedAt != nil {
			conditionStatus = metav1.ConditionTrue
			reason = garagev1beta1.ReasonStorageDrainCompleted
		}
		// meta.SetStatusCondition preserves unrelated condition writers while this
		// field-scoped CAS owns only StorageDrainReady.
		setStorageDrainCondition(cluster, conditionStatus, reason, message)
		if err := kubeClient.Status().Update(ctx, cluster); err != nil {
			if !apierrors.IsConflict(err) || attempt == StatusUpdateMaxRetries-1 {
				return fmt.Errorf("persisting Garage storage-drain safety proof: %w", err)
			}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
				return fmt.Errorf("re-reading GarageCluster after storage-drain status conflict: %w", err)
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("persisting Garage storage-drain safety proof exhausted retries")
}

func setStorageDrainCondition(
	cluster *garagev1beta2.GarageCluster,
	status metav1.ConditionStatus,
	reason, message string,
) {
	if cluster == nil {
		return
	}
	condition := metav1.Condition{
		Type:               garagev1beta1.ConditionStorageDrainReady,
		Status:             status,
		Reason:             reason,
		Message:            limitStatusConditionMessage(message),
		ObservedGeneration: cluster.Generation,
	}
	for i := range cluster.Status.Conditions {
		if cluster.Status.Conditions[i].Type == condition.Type {
			if cluster.Status.Conditions[i].Status == condition.Status {
				condition.LastTransitionTime = cluster.Status.Conditions[i].LastTransitionTime
			} else {
				condition.LastTransitionTime = metav1.Now()
			}
			cluster.Status.Conditions[i] = condition
			return
		}
	}
	condition.LastTransitionTime = metav1.Now()
	cluster.Status.Conditions = append(cluster.Status.Conditions, condition)
}

func (r *GarageClusterReconciler) requireBlockResyncQuiet(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
) error {
	return requireClusterStorageDrainSafety(
		ctx, r.Client, r.safetyReader(), r.layoutMutationCoordinator(), cluster, storageDrainActorForCluster(cluster),
		garageClient, r.blockResyncObservationGetter, r.blockRepairLauncher, r.clusterHealthGetter,
		r.blockResyncQuietPeriod,
	)
}

func (r *GarageNodeReconciler) requireBlockResyncQuiet(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
) error {
	return requireClusterStorageDrainSafety(
		ctx, r.Client, r.nodeLocalPoolReader(), r.layoutMutationCoordinator(), cluster, storageDrainActorForNode(node),
		garageClient, r.blockResyncObservationGetter, r.blockRepairLauncher, r.clusterHealthGetter,
		r.blockResyncQuietPeriod,
	)
}

func requireClusterStorageDrainSafety(
	ctx context.Context,
	kubeClient client.Client,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	actor storageDrainActor,
	garageClient *garage.Client,
	getter func(context.Context, *garage.Client) (*blockResyncObservation, error),
	launcher func(context.Context, *garage.Client, string) error,
	healthGetter func(context.Context, *garage.Client) (*garage.ClusterHealth, error),
	configuredQuietPeriod time.Duration,
) error {
	if err := requireConsistentStorageDrain(cluster); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, garagev1beta1.ReasonStorageDrainUnsupportedConsistency, err)
	}
	if reason, err := requireStorageDrainStartReady(cluster); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, reason, err)
	}
	if err := requireLiveStorageDrainHealth(ctx, garageClient, healthGetter); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, garagev1beta1.ReasonStorageDrainWaitingForHealth, err)
	}
	previous := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if previous == nil || len(previous.RemovedStorageNodeIDs) == 0 || !sameStorageDrainActor(previous.Actor, actor) {
		return fmt.Errorf("%w: no exact durable positive-capacity role-removal transaction belongs to this actor", errLayoutMutationPending)
	}
	if previous.TargetHash != storageDrainProofTargetHash(previous) {
		return fmt.Errorf("%w: status.storageDrain target hash does not match removedNodeIds", errLayoutMutationPending)
	}
	if getter == nil {
		getter = readBlockResyncObservation
	}
	observation, err := getter(ctx, garageClient)
	if err != nil {
		// A federated Admin API read can fail transiently while every exact
		// process and repair worker remains unchanged. Preserve those durable
		// worker IDs and retry the observation; clearing only the quiet/completed
		// timestamps prevents stale evidence from authorizing deletion. A real
		// process restart is still detected by the managed-Pod fingerprint below
		// or by the recorded worker ID disappearing on the next successful read.
		retry := resetBlockResyncObservation(previous)
		if updateErr := updateClusterStorageDrainProof(
			ctx, kubeClient, cluster, storageDrainRevisionFromStatus(cluster.Status.StorageDrain), retry,
			"Garage block-proof observation is temporarily unavailable; retained exact repair workers and will retry: "+err.Error(),
		); updateErr != nil {
			return updateErr
		}
		return fmt.Errorf("%w: cannot prove Garage object-block migration complete: %v", errLayoutMutationPending, err)
	}
	observation, err = scopeBlockResyncObservation(previous, observation)
	if err != nil {
		// Keep the exact worker evidence while a source or destination is
		// temporarily unobservable. Once it returns, UID and worker-ID checks
		// below distinguish the same live process from a real restart.
		retry := resetBlockResyncObservation(previous)
		if updateErr := updateClusterStorageDrainProof(
			ctx, kubeClient, cluster, storageDrainRevisionFromStatus(cluster.Status.StorageDrain), retry,
			"Garage source-to-destination proof is temporarily unobservable; retained exact repair workers and will retry: "+err.Error(),
		); updateErr != nil {
			return updateErr
		}
		return fmt.Errorf("%w: cannot prove Garage source-to-destination block migration complete: %v", errLayoutMutationPending, err)
	}
	assessment, err := assessStorageDrainPeers(
		ctx, reader, cluster, observation.CurrentRoleTags, storageDrainLiveSourceNodeIDs(previous),
	)
	if err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, garagev1beta1.ReasonStorageDrainUnverifiedPeers, err)
	}
	if !sameStringMap(previous.ManagedPodUIDs, assessment.ManagedPodUIDs) {
		reset := resetBlockResyncEvidence(previous)
		reset.ManagedPodUIDs = copyStringMap(assessment.ManagedPodUIDs)
		if err := updateClusterStorageDrainProof(
			ctx, kubeClient, cluster, storageDrainRevisionFromStatus(cluster.Status.StorageDrain), reset,
			"A managed Garage process incarnation changed; discarded all worker-ID evidence before restarting the proof",
		); err != nil {
			return err
		}
		return fmt.Errorf("%w: a managed Garage process restarted; storage-drain worker evidence was reset", errLayoutMutationPending)
	}
	decision := evaluateBlockResyncProgress(
		previous, observation, time.Now(), effectiveBlockResyncQuietPeriod(configuredQuietPeriod, cluster), assessment.RequiresEmptyQueue,
	)
	if err := updateClusterStorageDrainProof(
		ctx, kubeClient, cluster, storageDrainRevisionFromStatus(cluster.Status.StorageDrain), decision.Proof, decision.Message,
	); err != nil {
		return err
	}
	if len(decision.LaunchNodeIDs) > 0 {
		if launcher == nil {
			launcher = func(ctx context.Context, client *garage.Client, nodeID string) error {
				return client.LaunchRepair(ctx, nodeID, garagev1beta1.RepairTypeBlocks)
			}
		}
		for _, nodeID := range decision.LaunchNodeIDs {
			if err := launcher(ctx, garageClient, nodeID); err != nil {
				return fmt.Errorf("%w: launching Blocks repair on verification node %s: %v", errLayoutMutationPending, shortID(nodeID), err)
			}
		}
		return fmt.Errorf("%w: %s", errLayoutMutationPending, decision.Message)
	}
	if !decision.Ready {
		return fmt.Errorf("%w: %s", errLayoutMutationPending, decision.Message)
	}
	// Keep the marker synchronized with the freshly persisted proof. It remains
	// active until the actor completes its Kubernetes handoff.
	key := layoutOwnerKey(cluster)
	ownerID := layoutRolloutOwnerID(cluster)
	if !coordinator.BeginStorageDrain(
		key, ownerID, actor.UID, decision.Proof.TransactionID, decision.Proof.TargetHash,
	) || !coordinator.ConfirmStorageDrain(
		key, ownerID, actor.UID, decision.Proof.TransactionID, decision.Proof.TargetHash,
	) {
		return fmt.Errorf("%w: durable storage-drain proof lost its in-memory exclusion", errLayoutMutationPending)
	}
	return nil
}

func (r *GarageClusterReconciler) ensureClusterBlockResyncIntent(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	roleRemovalNodeIDs []string,
	removedStorageNodeIDs []string,
) error {
	return ensureClusterStorageDrainIntent(
		ctx, r.Client, r.safetyReader(), r.layoutMutationCoordinator(), cluster, layout,
		storageDrainActorForCluster(cluster), roleRemovalNodeIDs, removedStorageNodeIDs,
	)
}

// ensureCapacitylessGatewayRetirementIntent persists the exact gateway role
// IDs before Garage Apply. It reuses the role-only shape of StorageDrainStatus
// as a UID-bound crash-recovery record, but deliberately does not run storage
// health, peer, or block-resync gates because every target is capacity-less.
// The matching coordinator marker serializes this multi-reconcile retirement
// against every other writer to the same canonical layout key.
func (r *GarageClusterReconciler) ensureCapacitylessGatewayRetirementIntent(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	roleRemovalNodeIDs []string,
) error {
	if cluster == nil || cluster.UID == "" || cluster.DeletionTimestamp.IsZero() ||
		!cluster.HasGatewayTier() || cluster.HasStorageTier() || cluster.HasNodeLocalPools() {
		return fmt.Errorf("capacity-less gateway retirement intent requires a deleting gateway-only GarageCluster")
	}
	actor := storageDrainActorForCluster(cluster)
	previous := clusterStorageDrainProof(cluster.Status.StorageDrain)
	base := previous
	if base != nil && base.CompletedAt != nil {
		base = resetBlockResyncEvidence(base)
	}
	next, err := storageDrainRemovalIntent(base, actor, roleRemovalNodeIDs, nil, time.Now())
	if err != nil {
		return err
	}
	if next == nil || len(next.RoleRemovalNodeIDs) == 0 || len(next.RemovedStorageNodeIDs) != 0 {
		return fmt.Errorf("capacity-less gateway retirement did not produce an exact role-only intent")
	}

	owner, err := resolveGarageLayoutOwner(ctx, r.safetyReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before recording gateway retirement: %w", err)
	}
	coordinator := r.layoutMutationCoordinator()
	key := layoutOwnerKey(owner)
	markerOwnerID := layoutRolloutOwnerID(owner)
	if previous == nil {
		if !coordinator.BeginStorageDrain(key, markerOwnerID, actor.UID, next.TransactionID, next.TargetHash) {
			return fmt.Errorf("%w: another storage-drain marker owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
		}
	} else if !coordinator.StorageDrainActorActive(
		key, markerOwnerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, markerOwnerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) {
		return fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}

	if previous == next {
		if !coordinator.ConfirmStorageDrain(key, markerOwnerID, actor.UID, next.TransactionID, next.TargetHash) {
			return fmt.Errorf("%w: durable gateway-retirement status lost its in-memory marker", errLayoutMutationPending)
		}
		return nil
	}
	expected := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
	if err := updateClusterStorageDrainProof(
		ctx, r.Client, cluster, expected, next,
		fmt.Sprintf("Capacity-less gateway retirement %s authorized %d exact role removal(s)", next.TransactionID, len(next.RoleRemovalNodeIDs)),
	); err != nil {
		if previous == nil {
			coordinator.EndStorageDrain(key, markerOwnerID, actor.UID, next.TransactionID, next.TargetHash)
		}
		return fmt.Errorf("recording capacity-less gateway retirement intent before Garage Apply: %w", err)
	}
	if previous != nil && previous.TargetHash != next.TargetHash {
		if !coordinator.AdvanceStorageDrain(
			key, markerOwnerID, actor.UID, next.TransactionID, previous.TargetHash, next.TargetHash,
		) {
			coordinator.EndStorageDrain(key, markerOwnerID, actor.UID, previous.TransactionID, previous.TargetHash)
			if !coordinator.BeginStorageDrain(key, markerOwnerID, actor.UID, next.TransactionID, next.TargetHash) {
				return fmt.Errorf("%w: persisted a new gateway-retirement target revision but could not advance its process marker", errLayoutMutationPending)
			}
		}
	}
	if !coordinator.ConfirmStorageDrain(key, markerOwnerID, actor.UID, next.TransactionID, next.TargetHash) {
		return fmt.Errorf("%w: persisted gateway-retirement intent lost its in-memory marker", errLayoutMutationPending)
	}
	return nil
}

func (r *GarageNodeReconciler) ensureNodeBlockResyncIntent(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	removedNodeIDs []string,
) error {
	return ensureClusterStorageDrainIntent(
		ctx, r.Client, r.nodeLocalPoolReader(), r.layoutMutationCoordinator(), cluster, layout,
		storageDrainActorForNode(node), removedNodeIDs, removedNodeIDs,
	)
}

func roleOnlyStorageDrainRemovalIntent(
	previous *blockResyncProof,
	actor storageDrainActor,
	roleRemovalNodeIDs []string,
	now time.Time,
) (*blockResyncProof, error) {
	if previous != nil {
		return storageDrainRemovalIntent(previous, actor, roleRemovalNodeIDs, nil, now)
	}
	if actor.UID == "" {
		return nil, fmt.Errorf("role-retirement actor %s %s/%s has no Kubernetes UID", actor.Kind, actor.Namespace, actor.Name)
	}
	roles := normalizedNodeIDs(roleRemovalNodeIDs)
	if len(roles) == 0 {
		return nil, fmt.Errorf("role-only retirement requires at least one exact Garage node ID")
	}
	startedAt := metav1.NewTime(now)
	return &blockResyncProof{
		Actor:              actor,
		TransactionID:      string(uuid.NewUUID()),
		TargetHash:         storageDrainTargetHash(roles, nil),
		StartedAt:          startedAt,
		RoleRemovalNodeIDs: roles,
	}, nil
}

// ensureCapacitylessGarageNodeRetirementIntent records a Manual or unified
// gateway GarageNode's exact role ID on the canonical layout owner before
// Apply. Unlike a storage drain this needs no health, peer, or block-resync
// proof, but it still needs a durable actor/target boundary so a restart cannot
// mistake an absent role for completed metadata retirement.
func (r *GarageNodeReconciler) ensureCapacitylessGarageNodeRetirementIntent(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	owner *garagev1beta2.GarageCluster,
	roleRemovalNodeIDs []string,
) error {
	if node == nil || owner == nil || !node.Spec.Gateway || node.UID == "" || owner.UID == "" {
		return fmt.Errorf("capacity-less GarageNode retirement requires a gateway actor and canonical layout owner")
	}
	actor := storageDrainActorForNode(node)
	previous := clusterStorageDrainProof(owner.Status.StorageDrain)
	base := previous
	if base != nil && base.CompletedAt != nil {
		base = resetBlockResyncEvidence(base)
	}
	next, err := roleOnlyStorageDrainRemovalIntent(base, actor, roleRemovalNodeIDs, time.Now())
	if err != nil {
		return err
	}
	if next == nil || len(next.RoleRemovalNodeIDs) == 0 || len(next.RemovedStorageNodeIDs) != 0 {
		return fmt.Errorf("capacity-less GarageNode retirement did not produce an exact role-only intent")
	}

	coordinator := r.layoutMutationCoordinator()
	key := layoutOwnerKey(owner)
	ownerID := layoutRolloutOwnerID(owner)
	if previous == nil {
		if !coordinator.BeginStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
			return fmt.Errorf("%w: another storage-drain marker owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
		}
	} else if !coordinator.StorageDrainActorActive(
		key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) {
		return fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if previous == next {
		if !coordinator.ConfirmStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
			return fmt.Errorf("%w: durable GarageNode retirement status lost its in-memory marker", errLayoutMutationPending)
		}
		return nil
	}
	expected := storageDrainRevisionFromStatus(owner.Status.StorageDrain)
	if err := updateClusterStorageDrainProof(
		ctx, r.Client, owner, expected, next,
		fmt.Sprintf("Capacity-less GarageNode retirement %s authorized %d exact role removal(s)", next.TransactionID, len(next.RoleRemovalNodeIDs)),
	); err != nil {
		if previous == nil {
			coordinator.EndStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash)
		}
		return fmt.Errorf("recording capacity-less GarageNode retirement intent before Garage Apply: %w", err)
	}
	if previous != nil && previous.TargetHash != next.TargetHash {
		if !coordinator.AdvanceStorageDrain(
			key, ownerID, actor.UID, next.TransactionID, previous.TargetHash, next.TargetHash,
		) {
			coordinator.EndStorageDrain(key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash)
			if !coordinator.BeginStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
				return fmt.Errorf("%w: persisted a new GarageNode role-retirement revision but could not advance its process marker", errLayoutMutationPending)
			}
		}
	}
	if !coordinator.ConfirmStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
		return fmt.Errorf("%w: persisted GarageNode retirement intent lost its in-memory marker", errLayoutMutationPending)
	}
	return nil
}

func (r *GarageNodeReconciler) ensureNodeLostSourceIntent(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	garageClient *garage.Client,
	lostNodeID string,
) error {
	if err := requireGarageNodeLostSourceUnavailable(ctx, r.nodeLocalPoolReader(), node, cluster, garageClient, lostNodeID); err != nil {
		return err
	}
	return ensureClusterStorageDrainIntent(
		ctx, r.Client, r.nodeLocalPoolReader(), r.layoutMutationCoordinator(), cluster, layout,
		storageDrainActorForNode(node), []string{lostNodeID}, []string{lostNodeID}, []string{lostNodeID},
	)
}

// recoverOrTransferStorageRolloutLostSource performs the only automatic escape
// from an exact managed-Pod handoff whose process is permanently lost. The
// administrator must atomically add drain=true and acknowledge-lost-source with
// the persisted pre-delete Garage ID. Under the canonical layout mutex, Garage
// must already report that ID down; the parent status then swaps rollout actor
// state for a destination-only storage-drain intent in one status update. The
// workload is deliberately fenced only on a later reconcile, after that new
// durable boundary is observable.
func (r *GarageNodeReconciler) recoverOrTransferStorageRolloutLostSource(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layoutOwner *garagev1beta2.GarageCluster,
) (bool, error) {
	if node == nil || cluster == nil || layoutOwner == nil {
		return false, nil
	}
	coordinator := r.layoutMutationCoordinator()
	key := layoutOwnerKey(layoutOwner)
	actor := storageDrainActorForNode(node)
	if cluster.Status.StorageRollout == nil {
		proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain)
		if proof == nil || !sameStorageDrainActor(proof.Actor, actor) ||
			!storageDrainUnavailableSourceIncludes(proof, node.Status.NodeID) {
			return false, nil
		}
		// Recover the status-swap -> PVC-release -> marker-swap crash tail. The
		// storage-drain marker is already durable/rehydrated, so clearing only this
		// source's rollout marker never opens an unprotected layout window.
		pvcReconciler := &GarageClusterReconciler{Client: r.Client, APIReader: r.APIReader}
		if err := pvcReconciler.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
			return true, fmt.Errorf("releasing stale rollout PVC protection after lost-source transfer: %w", err)
		}
		coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
		return false, nil
	}
	record, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil {
		return true, fmt.Errorf("validating active storage rollout before lost-source transfer: %w", err)
	}
	if record == nil || !garageNodeAcknowledgesLostSource(node, record.GarageNodeID) {
		return false, nil
	}
	if cluster.UID != layoutOwner.UID || client.ObjectKeyFromObject(cluster) != client.ObjectKeyFromObject(layoutOwner) {
		return true, fmt.Errorf("%w: automatic lost-source transfer requires the rollout source to be the canonical in-cluster Garage layout owner", errLayoutMutationPending)
	}
	if !nodeLocalPoolRolloutCandidateMatches(cluster, node) || node.Status.NodeID != record.GarageNodeID ||
		string(node.UID) != record.GarageNodeUID {
		return true, fmt.Errorf("%w: lost-source request does not match the exact persisted rollout GarageNode UID and Garage ID", errLayoutMutationPending)
	}
	if !garageNodeStoresBlocks(node) {
		return true, fmt.Errorf("%w: only a positive-capacity storage rollout actor may transfer to destination-only recovery", errLayoutMutationPending)
	}
	if layoutOwner.Status.StorageDrain != nil {
		return true, fmt.Errorf("%w: a storage-drain transaction already exists while the rollout actor is still active", errLayoutMutationPending)
	}

	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(coordinator, layoutOwner)
	if err != nil {
		return true, err
	}
	defer release()

	freshNode := &garagev1beta1.GarageNode{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		return true, fmt.Errorf("re-reading exact lost rollout actor under the layout mutex: %w", err)
	}
	if freshNode.UID != node.UID || freshNode.Generation != record.GarageNodeGeneration ||
		freshNode.Status.NodeID != record.GarageNodeID ||
		!garageNodeAcknowledgesLostSource(freshNode, record.GarageNodeID) {
		return true, fmt.Errorf("%w: lost rollout actor changed before durable storage-drain transfer", errLayoutMutationPending)
	}
	pvcReconciler := &GarageClusterReconciler{Client: r.Client, APIReader: r.APIReader}
	if err := pvcReconciler.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, *record); err != nil {
		return true, fmt.Errorf("%w: exact StatefulSet storage is unavailable before lost-source transfer: %v", errLayoutMutationPending, err)
	}
	if err := requireConsistentStorageDrain(layoutOwner); err != nil {
		return true, err
	}
	if factorMigrationActive(layoutOwner) {
		return true, fmt.Errorf("%w: replication-factor migration must finish before lost-source transfer", errLayoutMutationPending)
	}
	var garageClient *garage.Client
	if r.lostSourceGarageClientGetter != nil {
		garageClient, err = r.lostSourceGarageClientGetter(ctx, cluster)
	} else {
		garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	}
	if err != nil {
		return true, fmt.Errorf("creating Garage client for lost rollout actor transfer: %w", err)
	}
	if err := requireGarageNodeLostSourceDown(ctx, freshNode, layoutOwner, garageClient, record.GarageNodeID); err != nil {
		return true, err
	}
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return true, fmt.Errorf("%w: lost-source transfer requires settled Garage layout history: %v", errLayoutMutationPending, err)
	}
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return true, fmt.Errorf("%w: reading Garage staging before lost-source transfer: %v", errLayoutMutationPending, err)
	}
	if err := requireExclusiveStagedLayoutChanges(layout, nil, nil, false); err != nil {
		return true, err
	}

	proof, err := storageDrainRemovalIntent(
		nil, actor, []string{record.GarageNodeID}, []string{record.GarageNodeID}, time.Now(),
	)
	if err != nil {
		return true, err
	}
	proof.UnavailableSourceNodeIDs = []string{record.GarageNodeID}
	proof.TargetHash = storageDrainProofTargetHash(proof)
	ownerID := layoutRolloutOwnerID(layoutOwner)
	if !coordinator.BeginStorageDrain(key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash) {
		return true, fmt.Errorf("%w: another storage-drain marker owns the canonical Garage layout", errLayoutMutationPending)
	}
	drainDurable := false
	defer func() {
		if !drainDurable {
			coordinator.EndStorageDrain(key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash)
		}
	}()

	expectedClusterUID := cluster.UID
	expectedGeneration := record.ClusterGeneration
	var updated *garagev1beta2.GarageCluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedClusterUID || fresh.Generation != expectedGeneration || fresh.Status.StorageDrain != nil {
			return fmt.Errorf("garageCluster UID, generation, or storage-drain state changed before lost-source transfer")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, *record) {
			return fmt.Errorf("storage rollout actor changed before lost-source transfer")
		}
		currentNode := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(freshNode), currentNode); err != nil {
			return err
		}
		if currentNode.UID != freshNode.UID || currentNode.Generation != record.GarageNodeGeneration ||
			currentNode.Status.NodeID != record.GarageNodeID ||
			!garageNodeAcknowledgesLostSource(currentNode, record.GarageNodeID) {
			return fmt.Errorf("exact GarageNode lost-source acknowledgment changed before status transfer")
		}
		if err := requireGarageNodeLostSourceDown(ctx, currentNode, fresh, garageClient, record.GarageNodeID); err != nil {
			return err
		}
		fresh.Status.StorageRollout = nil
		fresh.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRolloutWaiting,
			Message:            fmt.Sprintf("exact rollout actor %s UID %s was acknowledged permanently lost; ownership transferred to storage drain %s", shortID(record.GarageNodeID), record.GarageNodeUID, proof.TransactionID),
			ObservedGeneration: fresh.Generation,
		})
		setStorageDrainCondition(
			fresh, metav1.ConditionFalse, garagev1beta1.ReasonStorageDraining,
			fmt.Sprintf("destination-only recovery for exact unavailable rollout actor %s", shortID(record.GarageNodeID)),
		)
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return true, fmt.Errorf("atomically transferring storage rollout actor to lost-source drain: %w", err)
	}
	drainDurable = true
	if !coordinator.ConfirmStorageDrain(key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash) {
		return true, fmt.Errorf("%w: durable lost-source storage drain lost its in-memory marker", errLayoutMutationPending)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
		adoptGarageClusterSnapshot(layoutOwner, updated)
	}
	if err := pvcReconciler.releaseStorageRolloutPersistentVolumeClaims(ctx, cluster, *record); err != nil {
		return true, fmt.Errorf("releasing rollout PVC protection after durable lost-source transfer: %w", err)
	}
	coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
	return true, nil
}

// requireGarageNodeLostSourceDown is the non-destructive preflight for explicit
// lost-source recovery. Garage status is the identity authority: the operator
// must observe the exact acknowledged ID down before it may scale, deactivate,
// or delete a managed process. This prevents the acknowledgment itself from
// manufacturing the outage it claims already happened.
func requireGarageNodeLostSourceDown(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	lostNodeID string,
) error {
	if node == nil || cluster == nil || garageClient == nil || strings.TrimSpace(lostNodeID) == "" {
		return fmt.Errorf("%w: lost-source recovery requires the exact GarageNode, layout owner, Admin client, and node ID", errLayoutMutationPending)
	}
	lostNodeID = canonicalGarageNodeID(lostNodeID)
	knownNodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return fmt.Errorf("%w: resolving the exact GarageNode identity for lost-source recovery: %v", errLayoutMutationPending, err)
	}
	if knownNodeID == "" || knownNodeID != lostNodeID {
		return fmt.Errorf("%w: lost-source recovery ID %s does not match the exact GarageNode identity %s", errLayoutMutationPending, shortID(lostNodeID), shortID(knownNodeID))
	}
	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return fmt.Errorf("%w: checking whether acknowledged lost source %s is down: %v", errLayoutMutationPending, shortID(lostNodeID), err)
	}
	if status == nil {
		return fmt.Errorf("%w: Garage returned no cluster status while checking lost source %s", errLayoutMutationPending, shortID(lostNodeID))
	}
	for i := range status.Nodes {
		if canonicalGarageNodeID(status.Nodes[i].ID) == lostNodeID && status.Nodes[i].IsUp {
			return fmt.Errorf("%w: acknowledged lost source %s is still up in Garage cluster status", errLayoutMutationPending, shortID(lostNodeID))
		}
	}
	if node.Spec.External != nil {
		if effectiveStorageDrainUnverifiedPeersPolicy(cluster) != garagev1beta2.StorageDrainUnverifiedPeersAssumeConsistent {
			return fmt.Errorf(
				"%w: external lost-source recovery requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent in addition to Garage reporting %s down",
				errUnsafeLayoutRoleRemoval, shortID(lostNodeID),
			)
		}
	}
	return nil
}

// requireGarageNodeLostSourceUnavailable binds the irreversible, destination-
// only proof to both the exact Garage-down observation and physical absence of
// a managed process. A replacement Pod could reload the same metadata/node ID
// or create a second positive-capacity identity that this deletion would
// orphan; adopting or jointly draining such a replacement is intentionally
// outside this recovery transaction.
func requireGarageNodeLostSourceUnavailable(
	ctx context.Context,
	reader client.Reader,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	lostNodeID string,
) error {
	if err := requireGarageNodeLostSourceDown(ctx, node, cluster, garageClient, lostNodeID); err != nil {
		return err
	}
	if node.Spec.External != nil {
		return nil
	}
	absent, err := managedGarageNodePodAbsent(ctx, reader, node)
	if err != nil {
		return fmt.Errorf("%w: checking the managed process incarnation for lost source %s: %v", errLayoutMutationPending, shortID(lostNodeID), err)
	}
	if !absent {
		return fmt.Errorf(
			"%w: a managed Pod is still present for acknowledged lost source %s; stop or remove that workload before destination-only recovery so a replacement identity cannot be orphaned",
			errLayoutMutationPending, shortID(lostNodeID),
		)
	}
	return nil
}

func managedGarageNodePodAbsent(
	ctx context.Context,
	reader client.Reader,
	node *garagev1beta1.GarageNode,
) (bool, error) {
	if node == nil || node.Spec.External != nil || reader == nil {
		return false, nil
	}
	if isNodeLocalPoolBacked(node) {
		pods := &corev1.PodList{}
		if err := reader.List(ctx, pods,
			client.InNamespace(node.Namespace),
			client.MatchingLabels(map[string]string{
				labelCluster:       node.Spec.ClusterRef.Name,
				labelTier:          tierStorage,
				labelNodeLocalPool: node.Spec.NodeLocalPoolName,
			}),
		); err != nil {
			return false, err
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.Spec.NodeName == node.Spec.KubernetesNodeName {
				return false, nil
			}
		}
		return true, nil
	}
	pod := &corev1.Pod{}
	err := reader.Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name + "-0"}, pod)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func ensureClusterStorageDrainIntent(
	ctx context.Context,
	kubeClient client.Client,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	actor storageDrainActor,
	roleRemovalNodeIDs []string,
	removedStorageNodeIDs []string,
	unavailableSourceNodeIDs ...[]string,
) error {
	previous := clusterStorageDrainProof(cluster.Status.StorageDrain)
	requestedUnavailable := []string(nil)
	if len(unavailableSourceNodeIDs) > 0 {
		requestedUnavailable = normalizedNodeIDs(unavailableSourceNodeIDs[0])
	}
	removedSet := make(map[string]struct{})
	for _, nodeID := range normalizedNodeIDs(removedStorageNodeIDs) {
		removedSet[nodeID] = struct{}{}
	}
	for _, nodeID := range requestedUnavailable {
		if _, removed := removedSet[nodeID]; !removed {
			return fmt.Errorf("unavailable source %s is not an exact positive-capacity removal target", shortID(nodeID))
		}
	}
	if len(normalizedNodeIDs(removedStorageNodeIDs)) == 0 && previous == nil {
		// Capacity-less role cleanup has no object blocks to migrate. Only an
		// explicitly prepared GarageCluster Drain needs a durable role-only proof
		// for DELETE admission; routine gateway finalization must be able to remove
		// its role without satisfying storage health/rollout prerequisites.
		if cluster == nil || cluster.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue {
			return nil
		}
	}
	if cluster == nil || cluster.UID == "" {
		return fmt.Errorf("recording storage-drain intent requires the layout-owner GarageCluster UID")
	}
	if err := requireConsistentStorageDrain(cluster); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, garagev1beta1.ReasonStorageDrainUnsupportedConsistency, err)
	}
	if reason, err := requireStorageDrainStartReady(cluster); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, reason, err)
	}
	if layout == nil {
		return fmt.Errorf("%w: Garage layout is unavailable while recording storage-drain intent", errUnsafeLayoutRoleRemoval)
	}
	assessment, err := assessStorageDrainPeers(
		ctx, reader, cluster, storageDrainRoleTagsFromLayout(layout),
		normalizedNodeIDsWithout(removedStorageNodeIDs, requestedUnavailable),
	)
	if err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, cluster, garagev1beta1.ReasonStorageDrainUnverifiedPeers, err)
	}
	next, err := storageDrainRemovalIntent(previous, actor, roleRemovalNodeIDs, removedStorageNodeIDs, time.Now())
	if err != nil {
		return err
	}
	combinedUnavailable := requestedUnavailable
	if previous != nil {
		combinedUnavailable = normalizedNodeIDs(append(append([]string(nil), previous.UnavailableSourceNodeIDs...), requestedUnavailable...))
	}
	if !reflect.DeepEqual(next.UnavailableSourceNodeIDs, combinedUnavailable) {
		if next == previous {
			next = resetBlockResyncEvidence(previous)
		}
		next.UnavailableSourceNodeIDs = combinedUnavailable
		next.TargetHash = storageDrainProofTargetHash(next)
	}
	statusUnchanged := next == previous && sameStringMap(previous.ManagedPodUIDs, assessment.ManagedPodUIDs)
	if next == previous && !statusUnchanged {
		next = resetBlockResyncEvidence(previous)
	}
	next.ManagedPodUIDs = copyStringMap(assessment.ManagedPodUIDs)
	key := layoutOwnerKey(cluster)
	ownerID := layoutRolloutOwnerID(cluster)
	expected := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
	if previous == nil {
		if !coordinator.BeginStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
			return fmt.Errorf("%w: another storage-drain marker owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
		}
	} else if !coordinator.StorageDrainActorActive(
		key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash,
	) {
		return fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if !statusUnchanged {
		if err := updateClusterStorageDrainProof(
			ctx, kubeClient, cluster, expected, next,
			fmt.Sprintf("Storage drain %s authorized %d role removal(s), including %d positive-capacity target(s)", next.TransactionID, len(next.RoleRemovalNodeIDs), len(next.RemovedStorageNodeIDs)),
		); err != nil {
			if previous == nil {
				coordinator.EndStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash)
			}
			return fmt.Errorf("recording storage-drain intent before Garage role removal: %w", err)
		}
	}
	if previous != nil && previous.TargetHash != next.TargetHash {
		if !coordinator.AdvanceStorageDrain(
			key, ownerID, actor.UID, next.TransactionID, previous.TargetHash, next.TargetHash,
		) {
			coordinator.EndStorageDrain(key, ownerID, actor.UID, previous.TransactionID, previous.TargetHash)
			if !coordinator.BeginStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
				return fmt.Errorf("%w: persisted a new storage-drain target revision but could not advance its process marker", errLayoutMutationPending)
			}
		}
	}
	if !coordinator.ConfirmStorageDrain(key, ownerID, actor.UID, next.TransactionID, next.TargetHash) {
		return fmt.Errorf("%w: persisted storage-drain intent lost its in-memory marker", errLayoutMutationPending)
	}
	return nil
}

func normalizedNodeIDsWithout(nodeIDs, excludedNodeIDs []string) []string {
	excluded := make(map[string]struct{}, len(excludedNodeIDs))
	for _, nodeID := range normalizedNodeIDs(excludedNodeIDs) {
		excluded[nodeID] = struct{}{}
	}
	result := make([]string, 0, len(nodeIDs))
	for _, nodeID := range normalizedNodeIDs(nodeIDs) {
		if _, skip := excluded[nodeID]; !skip {
			result = append(result, nodeID)
		}
	}
	return result
}

// completeRoleOnlyClusterDrain records the terminal prepared state for a site
// that owned no positive-capacity role. The caller holds the layout coordinator
// and has re-read a settled layout in which every exact RoleRemovalNodeID is
// absent. There are no source blocks to scan, but DELETE still needs a durable
// UID-bound admission token so preparation and termination remain two phases.
func completeRoleOnlyDrain(
	ctx context.Context,
	kubeClient client.Client,
	cluster *garagev1beta2.GarageCluster,
	actor storageDrainActor,
	layout *garage.ClusterLayout,
	message string,
) error {
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) ||
		len(proof.RemovedStorageNodeIDs) != 0 {
		return fmt.Errorf("%w: no exact role-only drain transaction belongs to this actor", errLayoutMutationPending)
	}
	if layout == nil {
		return fmt.Errorf("%w: Garage layout is unavailable while completing role-only site drain", errLayoutMutationPending)
	}
	currentRoles := make(map[string]struct{}, len(layout.Roles))
	for i := range layout.Roles {
		currentRoles[layout.Roles[i].ID] = struct{}{}
	}
	for _, nodeID := range proof.RoleRemovalNodeIDs {
		if _, present := currentRoles[nodeID]; present {
			return fmt.Errorf("%w: role-only drain target %s is still present in the settled Garage layout", errLayoutMutationPending, shortID(nodeID))
		}
	}
	next := copyBlockResyncProof(proof)
	next.LayoutVersion = layout.Version
	next.VerificationNodeIDs = nil
	next.RepairBaselines = nil
	next.RepairWorkerIDs = nil
	next.ResyncErrorBaselines = nil
	next.QueueLength = 0
	next.ErrorCount = 0
	next.RequiresEmptyQueue = false
	next.QuietSince = nil
	if next.CompletedAt == nil {
		completedAt := metav1.Now()
		next.CompletedAt = &completedAt
	}
	return updateClusterStorageDrainProof(
		ctx, kubeClient, cluster, storageDrainRevisionFromStatus(cluster.Status.StorageDrain), next,
		message,
	)
}

func completeRoleOnlyClusterDrain(
	ctx context.Context,
	kubeClient client.Client,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
) error {
	return completeRoleOnlyDrain(
		ctx, kubeClient, cluster, storageDrainActorForCluster(cluster), layout,
		"GarageCluster owns no positive-capacity source role and every exact role-removal target is absent from the settled layout; prepared deletion is complete",
	)
}

func completeRoleOnlyGarageNodeDrain(
	ctx context.Context,
	kubeClient client.Client,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
) error {
	return completeRoleOnlyDrain(
		ctx, kubeClient, cluster, storageDrainActorForNode(node), layout,
		"Capacity-less GarageNode role is absent and its normal metadata layout history settled; terminal role-retirement handoff is complete",
	)
}

func requireStorageDrainAuthorizedTargets(
	cluster *garagev1beta2.GarageCluster,
	actor storageDrainActor,
	roleRemovalNodeIDs []string,
	removedStorageNodeIDs []string,
) error {
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) {
		return fmt.Errorf("%w: no exact durable storage-drain transaction belongs to this actor", errLayoutMutationPending)
	}
	if proof.TargetHash != storageDrainProofTargetHash(proof) {
		return fmt.Errorf("%w: status.storageDrain target hash is invalid", errLayoutMutationPending)
	}
	for _, nodeID := range normalizedNodeIDs(roleRemovalNodeIDs) {
		if !storageDrainRoleIntentIncludes(proof, nodeID) {
			return fmt.Errorf("%w: storage-drain transaction %s does not authorize role removal %s", errLayoutMutationPending, proof.TransactionID, shortID(nodeID))
		}
	}
	for _, nodeID := range normalizedNodeIDs(removedStorageNodeIDs) {
		if !blockResyncIntentIncludes(proof, nodeID) {
			return fmt.Errorf("%w: storage-drain transaction %s does not authorize positive-capacity removal %s", errLayoutMutationPending, proof.TransactionID, shortID(nodeID))
		}
	}
	return nil
}

// requireStorageDrainBeforeApply revalidates every safety assumption against
// live state after Garage's staging area has been re-read and immediately
// before Apply. Cached status is useful for reconciliation UX, but it is never
// the final authority to remove positive capacity.
func requireStorageDrainBeforeApply(
	ctx context.Context,
	kubeClient client.Client,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	staged *garage.ClusterLayout,
	healthGetter func(context.Context, *garage.Client) (*garage.ClusterHealth, error),
) error {
	if reader == nil || cluster == nil {
		return fmt.Errorf("%w: cannot re-read the durable storage-drain owner immediately before Apply", errLayoutMutationPending)
	}
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	expectedRevision := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
	fresh := &garagev1beta2.GarageCluster{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
		return fmt.Errorf("%w: re-reading GarageCluster immediately before Apply: %v", errLayoutMutationPending, err)
	}
	if fresh.UID != expectedUID || fresh.Generation != expectedGeneration ||
		!sameStorageDrainRevision(storageDrainRevisionFromStatus(fresh.Status.StorageDrain), expectedRevision) {
		return fmt.Errorf("%w: GarageCluster UID, generation, or exact storage-drain revision changed after staging; refusing Apply", errLayoutMutationPending)
	}
	if err := requireConsistentStorageDrain(fresh); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, fresh, garagev1beta1.ReasonStorageDrainUnsupportedConsistency, err)
	}
	if reason, err := requireStorageDrainStartReady(fresh); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, fresh, reason, err)
	}
	proof := clusterStorageDrainProof(fresh.Status.StorageDrain)
	if proof == nil || proof.TargetHash != storageDrainProofTargetHash(proof) {
		return fmt.Errorf("%w: fresh status.storageDrain actor or target intent is invalid immediately before Apply", errLayoutMutationPending)
	}
	assessment, err := assessStorageDrainPeers(
		ctx, reader, fresh, storageDrainRoleTagsFromLayout(staged), proof.RemovedStorageNodeIDs,
	)
	if err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, fresh, garagev1beta1.ReasonStorageDrainUnverifiedPeers, err)
	}
	stagedRoleRemovals := make([]string, 0)
	stagedStorageRemovals := make([]string, 0)
	capacityByNodeID := make(map[string]uint64, len(staged.Roles))
	for i := range staged.Roles {
		role := &staged.Roles[i]
		if role.Capacity != nil {
			capacityByNodeID[role.ID] = *role.Capacity
		}
	}
	for i := range staged.StagedRoleChanges {
		change := &staged.StagedRoleChanges[i]
		if !change.Remove {
			continue
		}
		stagedRoleRemovals = append(stagedRoleRemovals, change.ID)
		if capacityByNodeID[change.ID] > 0 {
			stagedStorageRemovals = append(stagedStorageRemovals, change.ID)
		}
	}
	if err := requireStorageDrainAuthorizedTargets(
		fresh, proof.Actor, stagedRoleRemovals, stagedStorageRemovals,
	); err != nil {
		return err
	}
	if !sameStringMap(proof.ManagedPodUIDs, assessment.ManagedPodUIDs) {
		return fmt.Errorf("%w: a managed Garage process incarnation changed after drain intent was recorded; refusing Apply until the durable proof is reset", errLayoutMutationPending)
	}
	if err := requireLiveStorageDrainHealth(ctx, garageClient, healthGetter); err != nil {
		return recordStorageDrainBlocked(ctx, kubeClient, fresh, garagev1beta1.ReasonStorageDrainWaitingForHealth, err)
	}
	return nil
}

func (r *GarageClusterReconciler) prepareGarageClusterDrain(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if cluster == nil || !cluster.HasStorageTier() ||
		cluster.EffectiveDeletionPolicy() != garagev1beta2.DeletionPolicyDrain {
		return false, fmt.Errorf(
			"annotation %s requires a storage GarageCluster with explicit spec.deletionPolicy: Drain",
			garagev1beta1.AnnotationDrain,
		)
	}
	actor := storageDrainActorForCluster(cluster)
	if proof := clusterStorageDrainProof(cluster.Status.StorageDrain); proof != nil &&
		!sameStorageDrainActor(proof.Actor, actor) {
		return false, fmt.Errorf(
			"%w: storage-drain transaction %s is owned by %s %s/%s",
			errLayoutMutationPending, proof.TransactionID, proof.Actor.Kind,
			proof.Actor.Namespace, proof.Actor.Name,
		)
	}

	knownNodeIDs, err := r.collectGarageNodeIDs(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("building exact local identity inventory for prepared Drain: %w", err)
	}
	legacyStorageNodeIDs, err := r.collectLiveLegacyStorageNodeIDs(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("building exact legacy storage identity inventory for prepared Drain: %w", err)
	}
	for nodeID := range legacyStorageNodeIDs {
		knownNodeIDs[nodeID] = true
	}
	if err := r.removeNodesFromLayout(ctx, cluster, knownNodeIDs); err != nil {
		return false, err
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) || proof.CompletedAt == nil {
		return false, fmt.Errorf("%w: cluster-wide source-to-destination proof has not reached its terminal state", errLayoutMutationPending)
	}
	return true, nil
}

// prepareGarageNodeDeletionDrain requests and waits for the GarageNode
// controller's reversible prepare operation. It never removes a role and calls
// Delete in one parent reconcile: the drain annotation first keeps ordinary
// node reconciliation from re-adding the role, and DELETE admission later
// requires this exact actor's terminal proof.
func (r *GarageClusterReconciler) prepareGarageNodeDeletionDrain(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) error {
	if node == nil || node.Spec.Gateway {
		return nil
	}
	if node.Status.ParentDeletionRequestGeneration != cluster.Generation {
		apply := func() {
			node.Status.ParentDeletionRequestGeneration = cluster.Generation
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
			return fmt.Errorf("recording parent-owned deletion intent for GarageNode %s: %w", node.Name, err)
		}
	}
	needsUpdate := false
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	if node.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue {
		node.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
		needsUpdate = true
	}
	if needsUpdate {
		if err := r.Update(ctx, node); err != nil {
			return fmt.Errorf("requesting reversible drain preparation for GarageNode %s: %w", node.Name, err)
		}
		return fmt.Errorf(
			"%w: requested reversible drain preparation for GarageNode %s; waiting for ConditionDrainPrepared=True",
			errLayoutMutationPending, node.Name,
		)
	}
	if garageNodePreparedWithoutLayout(node) {
		return nil
	}

	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return fmt.Errorf("resolving durable GarageNode identity before parent deletion handoff: %w", err)
	}
	if nodeID == "" {
		return fmt.Errorf("%w: waiting for GarageNode %s to prove that no identity-bearing process exists", errLayoutMutationPending, node.Name)
	}
	prepared, err := completedGarageNodeDrainAuthorizesFinalization(node, cluster)
	if err != nil {
		return fmt.Errorf("validating GarageNode %s terminal deletion handoff: %w", node.Name, err)
	}
	if !prepared {
		message := fmt.Sprintf("waiting for GarageNode %s to complete reversible source-to-destination drain preparation", node.Name)
		if condition := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionDrainPrepared); condition != nil && condition.Message != "" {
			message += ": " + condition.Message
		}
		return fmt.Errorf("%w: %s", errLayoutMutationPending, message)
	}
	return nil
}

func garageNodePreparedWithoutLayout(node *garagev1beta1.GarageNode) bool {
	if node == nil || node.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue {
		return false
	}
	// PreparedNotInLayout is reserved for an object that never acquired any
	// durable Garage identity and whose managed workload was proved absent. A
	// known ID can have a committed role even when one asynchronously updated
	// Admin endpoint temporarily omits it, so every non-empty identity must use
	// the full terminal storage-drain proof.
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil || nodeID != "" {
		return false
	}
	condition := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionDrainPrepared)
	return condition != nil && condition.Status == metav1.ConditionTrue &&
		condition.Reason == garagev1beta1.ReasonNodeDrainPreparedNotInLayout &&
		condition.ObservedGeneration == node.Generation
}

func garageNodeAcknowledgesLostSource(node *garagev1beta1.GarageNode, nodeID string) bool {
	return node != nil && node.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue &&
		canonicalGarageNodeID(node.Annotations[garagev1beta1.AnnotationAcknowledgeLostSource]) == canonicalGarageNodeID(nodeID) &&
		canonicalGarageNodeID(nodeID) != ""
}

func unavailableNodeIDIncludes(nodeIDs []string, nodeID string) bool {
	nodeID = canonicalGarageNodeID(nodeID)
	for _, candidate := range nodeIDs {
		if canonicalGarageNodeID(candidate) == nodeID && nodeID != "" {
			return true
		}
	}
	return false
}

func (r *GarageNodeReconciler) managedGarageNodeProcessAbsent(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if node == nil || cluster == nil || node.Spec.External != nil {
		return false, nil
	}
	if isNodeLocalPoolBacked(node) {
		pods := &corev1.PodList{}
		if err := r.nodeLocalPoolReader().List(ctx, pods,
			client.InNamespace(node.Namespace),
			client.MatchingLabels(map[string]string{
				labelCluster:       cluster.Name,
				labelTier:          tierStorage,
				labelNodeLocalPool: node.Spec.NodeLocalPoolName,
			}),
		); err != nil {
			return false, err
		}
		for i := range pods.Items {
			if pods.Items[i].Spec.NodeName == node.Spec.KubernetesNodeName {
				return false, nil
			}
		}
		return true, nil
	}
	pod := &corev1.Pod{}
	err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name + "-0"}, pod)
	if apierrors.IsNotFound(err) {
		// A missing pod alone is not proof that this identity never existed: an
		// earlier process may have committed a Garage role before disappearing.
		// Only the absence of both the pod and its identity-bearing StatefulSet
		// proves that a managed process was never provisioned. Once an STS has
		// existed, status.nodeId (persisted before Apply) is the required identity
		// evidence; old-version ambiguity remains fail-closed.
		statefulSet := &appsv1.StatefulSet{}
		stsErr := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name}, statefulSet)
		if apierrors.IsNotFound(stsErr) {
			return true, nil
		}
		if stsErr != nil {
			return false, stsErr
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func (r *GarageNodeReconciler) preflightAndFenceManagedGarageNodeLostSource(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layoutOwner *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	nodeID string,
) (bool, error) {
	if err := requireGarageNodeLostSourceDown(ctx, node, layoutOwner, garageClient, nodeID); err != nil {
		return false, err
	}
	if err := r.requireManagedLostSourceReplacementUnassigned(ctx, node, cluster, garageClient, nodeID); err != nil {
		return false, err
	}
	return r.fenceManagedGarageNodeLostSource(ctx, node, cluster)
}

// requireManagedLostSourceReplacementUnassigned closes the dual-identity
// boundary for an in-place metadata wipe. Before fencing the current Pod, use
// its live IP-to-Garage-ID mapping to prove that any replacement identity has
// neither a committed nor staged role. If it already has a role, safely
// retiring both identities requires an explicit dual-source plan outside the
// single lost-source transaction.
func (r *GarageNodeReconciler) requireManagedLostSourceReplacementUnassigned(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	lostNodeID string,
) error {
	if node == nil || node.Spec.External != nil {
		return nil
	}
	absent, err := managedGarageNodePodAbsent(ctx, r.nodeLocalPoolReader(), node)
	if err != nil {
		return fmt.Errorf("%w: checking for a replacement process before lost-source fencing: %v", errLayoutMutationPending, err)
	}
	if absent {
		return nil
	}
	podIPs, err := r.getPodIPs(ctx, node, cluster)
	if err != nil {
		return fmt.Errorf("%w: identifying the current managed process before lost-source fencing: %v", errLayoutMutationPending, err)
	}
	currentNodeID, err := r.discoverNodeIDFromAdminAPI(ctx, garageClient, podIPs)
	if err != nil {
		return fmt.Errorf("%w: proving the current managed process has no replacement role before lost-source fencing: %v", errLayoutMutationPending, err)
	}
	if strings.TrimSpace(currentNodeID) == strings.TrimSpace(lostNodeID) {
		return nil
	}
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: checking replacement identity %s before lost-source fencing: %v", errLayoutMutationPending, shortID(currentNodeID), err)
	}
	for i := range layout.Roles {
		if layout.Roles[i].ID == currentNodeID {
			return fmt.Errorf(
				"%w: current managed process serves replacement Garage identity %s, which already has a committed role; refusing to fence it as part of lost-source recovery for %s because both roles require an explicit dual-identity recovery plan",
				errUnsafeLayoutRoleRemoval, shortID(currentNodeID), shortID(lostNodeID),
			)
		}
	}
	for i := range layout.StagedRoleChanges {
		if layout.StagedRoleChanges[i].ID == currentNodeID {
			return fmt.Errorf(
				"%w: current managed process serves replacement Garage identity %s, which has a staged layout change; revert or complete the global staging transaction before lost-source recovery for %s",
				errLayoutMutationPending, shortID(currentNodeID), shortID(lostNodeID),
			)
		}
	}
	return nil
}

func (r *GarageNodeReconciler) prepareGarageNodeDrain(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	layoutOwner *garagev1beta2.GarageCluster,
) (bool, bool, error) {
	if node == nil || cluster == nil || layoutOwner == nil || node.Spec.Gateway {
		return false, false, fmt.Errorf("positive-capacity GarageNode drain preparation requires a node and canonical layout owner")
	}
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return false, false, fmt.Errorf("resolving durable GarageNode identity before drain preparation: %w", err)
	}
	if nodeID == "" {
		absent, err := r.managedGarageNodeProcessAbsent(ctx, node, cluster)
		if err != nil {
			return false, false, fmt.Errorf("checking whether GarageNode %s has an identity-bearing process: %w", node.Name, err)
		}
		if absent {
			return true, true, nil
		}
		return false, false, fmt.Errorf("%w: GarageNode %s has a live or externally managed process but has not discovered its durable Garage node ID", errLayoutMutationPending, node.Name)
	}
	var garageClient *garage.Client
	if garageNodeAcknowledgesLostSource(node, nodeID) && node.Spec.External == nil {
		garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
		if err != nil {
			return false, false, fmt.Errorf("creating Garage client to preflight acknowledged lost source: %w", err)
		}
		fenced, err := r.preflightAndFenceManagedGarageNodeLostSource(
			ctx, node, cluster, layoutOwner, garageClient, nodeID,
		)
		if err != nil {
			return false, false, err
		}
		if !fenced {
			return false, false, fmt.Errorf(
				"%w: fencing the managed workload for acknowledged lost source %s before destination-only recovery",
				errLayoutMutationPending, shortID(nodeID),
			)
		}
	}
	actor := storageDrainActorForNode(node)
	if proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain); proof != nil &&
		sameStorageDrainActor(proof.Actor, actor) && proof.CompletedAt != nil {
		authorized, authorizeErr := completedGarageNodeDrainAuthorizesFinalization(node, layoutOwner)
		if authorizeErr != nil {
			return false, false, authorizeErr
		}
		if !authorized {
			return false, false, fmt.Errorf("%w: completed storage-drain token did not authorize this GarageNode", errLayoutMutationPending)
		}
		if unavailableNodeIDIncludes(proof.UnavailableSourceNodeIDs, nodeID) {
			if garageClient == nil {
				garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
				if err != nil {
					return false, false, fmt.Errorf("creating Garage client to revalidate completed lost-source recovery: %w", err)
				}
			}
			if err := requireGarageNodeLostSourceUnavailable(ctx, r.nodeLocalPoolReader(), node, layoutOwner, garageClient, nodeID); err != nil {
				return false, false, err
			}
			if err := r.requireBlockResyncQuiet(ctx, node, layoutOwner, garageClient); err != nil {
				return false, false, err
			}
		}
		return true, false, nil
	}

	if garageClient == nil {
		if node.Spec.External == nil {
			garageClient, err = r.exactManagedGarageNodeAdminClient(ctx, node, cluster, nodeID)
		} else {
			garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
		}
		if err != nil {
			return false, false, fmt.Errorf("creating Garage client for reversible drain preparation: %w", err)
		}
	}
	captureAdminEndpoint(node, cluster, r.ClusterDomain)
	mutate := func() error {
		return r.finalize(ctx, node, layoutOwner, garageClient)
	}
	if storageDrainActorMatches(layoutOwner.Status.StorageDrain, actor) {
		err = runLayoutMutationIgnoringStorageDrain(
			ctx, r.layoutMutationCoordinator(), layoutOwner, actor, garageClient, mutate,
		)
	} else {
		err = runLayoutMutation(ctx, r.layoutMutationCoordinator(), layoutOwner, garageClient, mutate)
	}
	if err != nil {
		return false, false, err
	}
	proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) || proof.CompletedAt == nil {
		return false, false, fmt.Errorf("%w: source-to-destination block proof has not reached its terminal state", errLayoutMutationPending)
	}
	authorized, authorizeErr := completedGarageNodeDrainAuthorizesFinalization(node, layoutOwner)
	if authorizeErr != nil {
		return false, false, authorizeErr
	}
	if !authorized {
		return false, false, fmt.Errorf("%w: terminal source-to-destination proof did not authorize this GarageNode", errLayoutMutationPending)
	}
	return true, false, nil
}

func setGarageNodeDrainPreparedCondition(
	ctx context.Context,
	kubeClient client.Client,
	node *garagev1beta1.GarageNode,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	if kubeClient == nil || node == nil {
		return nil
	}
	apply := func() {
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionDrainPrepared,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: node.Generation,
		})
	}
	apply()
	return UpdateStatusWithRetry(ctx, kubeClient, node, apply)
}

func (r *GarageNodeReconciler) clearCompletedNodeStorageDrain(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) error {
	actor := storageDrainActorForNode(node)
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil {
		return nil
	}
	if !sameStorageDrainActor(proof.Actor, actor) {
		return fmt.Errorf("%w: another actor owns status.storageDrain", errLayoutMutationPending)
	}
	if proof.CompletedAt == nil {
		return fmt.Errorf("%w: storage-drain proof is not complete", errLayoutMutationPending)
	}
	return clearCompletedStorageDrain(ctx, r.Client, r.layoutMutationCoordinator(), cluster, proof)
}

// completedGarageNodeDrainAuthorizesFinalization validates the durable handoff
// between reversible drain preparation and Kubernetes deletion. It deliberately
// does not require status.observedGeneration to equal metadata.generation: once
// DELETE has been accepted, ordinary reconciliation cannot refresh that status,
// and the terminal proof is bound to immutable Garage/Kubernetes identities
// rather than to mutable presentation status.
//
// A terminal proof is the point of no return. Its exact actor, target hash, and
// source-process fingerprint were persisted only after the role was absent and
// every required repair/resync observation completed. Re-proving those facts
// during finalization would incorrectly make the expected source teardown a new
// safety prerequisite.
func completedGarageNodeDrainAuthorizesFinalization(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if node == nil || cluster == nil {
		return false, nil
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	actor := storageDrainActorForNode(node)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) || proof.CompletedAt == nil {
		return false, nil
	}
	if node.Spec.Gateway {
		nodeID, err := node.ResolvedGarageNodeID()
		if err != nil {
			return false, fmt.Errorf("resolving durable gateway GarageNode identity from terminal role-retirement actor: %w", err)
		}
		if nodeID == "" {
			return false, fmt.Errorf("%w: terminal gateway role-retirement actor has no exact Garage node ID", errLayoutMutationPending)
		}
		if len(proof.RemovedStorageNodeIDs) != 0 {
			return false, fmt.Errorf("%w: gateway terminal proof unexpectedly authorizes positive-capacity removal", errLayoutMutationPending)
		}
		if err := validateTerminalStorageDrain(proof, actor, []string{nodeID}, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	if node.Annotations[garagev1beta1.AnnotationDrain] != annotationTrue {
		return false, fmt.Errorf("%w: terminal storage-drain actor no longer carries the immutable drain request", errLayoutMutationPending)
	}
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return false, fmt.Errorf("resolving durable GarageNode identity from terminal drain actor: %w", err)
	}
	if nodeID == "" {
		return false, fmt.Errorf("%w: terminal storage-drain actor has no exact Garage node ID", errLayoutMutationPending)
	}
	if err := validateTerminalStorageDrain(proof, actor, []string{nodeID}, []string{nodeID}); err != nil {
		return false, err
	}

	if storageDrainUnavailableSourceIncludes(proof, nodeID) {
		if !garageNodeAcknowledgesLostSource(node, nodeID) {
			return false, fmt.Errorf("%w: unavailable-source proof is missing the exact immutable lost-source acknowledgement", errLayoutMutationPending)
		}
		return true, nil
	}
	if node.Spec.External == nil {
		// The exact Pod UID was a live pre-completion invariant. Preserve that
		// fingerprint in the terminal proof, but do not compare it with mutable
		// GarageNode status after the point of no return: a stale status writer or
		// same-disk Pod restart must not make an already-safe DELETE impossible.
		if strings.TrimSpace(proof.ManagedPodUIDs[nodeID]) == "" {
			return false, fmt.Errorf("%w: terminal storage-drain proof has no exact managed source Pod UID", errLayoutMutationPending)
		}
	}
	return true, nil
}

// completedGarageClusterDrainAuthorizesFinalization validates the same durable
// DELETE/finalizer handoff for a cluster-wide Drain. A valid terminal token is
// intentionally sufficient after admission: finalization must continue when
// the already-retired local Admin endpoint and source workloads disappear.
func completedGarageClusterDrainAuthorizesFinalization(
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if cluster == nil {
		return false, nil
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	actor := storageDrainActorForCluster(cluster)
	if proof == nil || !sameStorageDrainActor(proof.Actor, actor) || proof.CompletedAt == nil {
		return false, nil
	}
	if err := validateTerminalStorageDrain(proof, actor, nil, nil); err != nil {
		return false, err
	}
	return true, nil
}

func clearCompletedStorageDrain(
	ctx context.Context,
	kubeClient client.Client,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	proof *blockResyncProof,
) error {
	if proof == nil || proof.CompletedAt == nil {
		return fmt.Errorf("%w: storage-drain proof is not complete", errLayoutMutationPending)
	}
	expected := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
	if err := updateClusterStorageDrainProof(
		ctx, kubeClient, cluster, expected, nil,
		fmt.Sprintf("Storage drain %s completed", proof.TransactionID),
	); err != nil {
		return err
	}
	coordinator.EndStorageDrain(
		layoutOwnerKey(cluster), layoutRolloutOwnerID(cluster), proof.Actor.UID, proof.TransactionID, proof.TargetHash,
	)
	return nil
}

// abortStorageDrain clears an incomplete transaction only after its caller has
// proved that the target role is still present and Garage's staging area no
// longer contains the attempted removal. That invariant makes a failed prepare
// reversible: replacement capacity/spec changes are not held behind a drain
// lock for a role that never left the layout.
func abortStorageDrain(
	ctx context.Context,
	kubeClient client.Client,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	proof *blockResyncProof,
	message string,
) error {
	if proof == nil {
		return nil
	}
	expected := storageDrainRevisionFromStatus(cluster.Status.StorageDrain)
	if err := updateClusterStorageDrainProof(ctx, kubeClient, cluster, expected, nil, message); err != nil {
		return err
	}
	coordinator.EndStorageDrain(
		layoutOwnerKey(cluster), layoutRolloutOwnerID(cluster), proof.Actor.UID, proof.TransactionID, proof.TargetHash,
	)
	return nil
}

func (r *GarageNodeReconciler) recoverNodeDrainApplyFailure(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	intended []garage.NodeRoleChange,
	cause error,
) error {
	if node == nil || cluster == nil || len(intended) != 1 {
		return cause
	}
	fresh, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf(
			"%w: Garage returned an error while applying removal and the committed role could not be re-read; keeping the live node and durable transaction for recovery: %v (re-read: %v)",
			errLayoutMutationPending, cause, err,
		)
	}
	targetPresent := false
	for i := range fresh.Roles {
		if fresh.Roles[i].ID == intended[0].ID {
			targetPresent = true
			break
		}
	}
	if !targetPresent {
		// The HTTP response may have been lost after Garage committed Apply. Do
		// not revert or clear the durable intent; the next reconcile resumes the
		// block proof while the source remains live.
		return fmt.Errorf(
			"%w: Garage removal appears committed despite an Apply error; keeping the durable transaction and continuing proof: %v",
			errLayoutMutationPending, cause,
		)
	}
	if err := requireExclusiveStagedLayoutChanges(fresh, intended, nil, false); err != nil {
		return fmt.Errorf(
			"%w: target role is still present after Apply failed, but Garage's global staging area is no longer exclusively owned; keeping the node live for explicit recovery: %v (apply: %v)",
			errLayoutMutationPending, err, cause,
		)
	}
	if len(fresh.StagedRoleChanges) > 0 || fresh.StagedParameters != nil {
		if err := garageClient.RevertClusterLayout(ctx); err != nil {
			return fmt.Errorf(
				"%w: target role is still present but reverting its failed staged removal failed; keeping the node live: %v (apply: %v)",
				errLayoutMutationPending, err, cause,
			)
		}
	}
	verified, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: verifying reverted Garage drain preparation: %v", errLayoutMutationPending, err)
	}
	targetPresent = false
	for i := range verified.Roles {
		if verified.Roles[i].ID == intended[0].ID {
			targetPresent = true
			break
		}
	}
	if !targetPresent || len(verified.StagedRoleChanges) > 0 || verified.StagedParameters != nil {
		return fmt.Errorf(
			"%w: failed drain preparation did not return to an exact role-present, staging-empty state; keeping the node live for explicit recovery",
			errLayoutMutationPending,
		)
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof != nil && sameStorageDrainActor(proof.Actor, storageDrainActorForNode(node)) {
		if err := abortStorageDrain(
			ctx, r.Client, r.layoutMutationCoordinator(), cluster, proof,
			fmt.Sprintf("Reverted failed storage-drain preparation for GarageNode %s while its role remained active", node.Name),
		); err != nil {
			return fmt.Errorf("%w: reverted Garage staging but could not release the durable drain transaction: %v", errLayoutMutationPending, err)
		}
	}
	return fmt.Errorf("reverted failed GarageNode drain preparation while the role remained live: %w", cause)
}

func (r *GarageClusterReconciler) recoverClusterDrainApplyFailure(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	intended []garage.NodeRoleChange,
	cause error,
) error {
	if cluster == nil || len(intended) == 0 {
		return cause
	}
	fresh, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf(
			"%w: Garage returned an error while applying the site removal and committed roles could not be re-read; keeping every process live and the transaction durable: %v (re-read: %v)",
			errLayoutMutationPending, cause, err,
		)
	}
	present := make(map[string]struct{}, len(fresh.Roles))
	for i := range fresh.Roles {
		present[fresh.Roles[i].ID] = struct{}{}
	}
	for i := range intended {
		if _, stillPresent := present[intended[i].ID]; !stillPresent {
			return fmt.Errorf(
				"%w: Garage site removal appears committed despite an Apply error; keeping the durable transaction and continuing proof: %v",
				errLayoutMutationPending, cause,
			)
		}
	}
	if err := requireExclusiveStagedLayoutChanges(fresh, intended, nil, false); err != nil {
		return fmt.Errorf(
			"%w: all target roles remain after Apply failed, but Garage's staging area is no longer exclusively owned; keeping site processes live: %v (apply: %v)",
			errLayoutMutationPending, err, cause,
		)
	}
	if len(fresh.StagedRoleChanges) > 0 || fresh.StagedParameters != nil {
		if err := garageClient.RevertClusterLayout(ctx); err != nil {
			return fmt.Errorf("%w: reverting failed staged site removal: %v (apply: %v)", errLayoutMutationPending, err, cause)
		}
	}
	verified, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: verifying reverted Garage site drain preparation: %v", errLayoutMutationPending, err)
	}
	present = make(map[string]struct{}, len(verified.Roles))
	for i := range verified.Roles {
		present[verified.Roles[i].ID] = struct{}{}
	}
	for i := range intended {
		if _, stillPresent := present[intended[i].ID]; !stillPresent {
			return fmt.Errorf("%w: a site role disappeared while verifying failed-Apply recovery", errLayoutMutationPending)
		}
	}
	if len(verified.StagedRoleChanges) > 0 || verified.StagedParameters != nil {
		return fmt.Errorf("%w: Garage staging was not empty after reverting failed site drain preparation", errLayoutMutationPending)
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof != nil && sameStorageDrainActor(proof.Actor, storageDrainActorForCluster(cluster)) {
		if err := abortStorageDrain(
			ctx, r.Client, r.layoutMutationCoordinator(), cluster, proof,
			fmt.Sprintf("Reverted failed prepared Drain for GarageCluster %s/%s while every role remained active", cluster.Namespace, cluster.Name),
		); err != nil {
			return fmt.Errorf("%w: reverted Garage staging but could not release the site drain transaction: %v", errLayoutMutationPending, err)
		}
	}
	return fmt.Errorf("reverted failed GarageCluster drain preparation while every role remained live: %w", cause)
}

// recoverOrphanedStorageDrain clears the narrow crash window in which a
// deleting GarageNode successfully releases its finalizer and then disappears
// before status.storageDrain can be cleared. CompletedAt is the durable point
// of no return: it was written only after the exact target had left the layout
// and source/destination repair-resync evidence completed. Once the actor finalizer is
// gone, its pod may already be disappearing, so trying to re-prove against that
// expected teardown would itself make recovery impossible. An incomplete
// orphan remains fail-closed because no surviving Kubernetes object is
// authorized to re-remove a target.
func (r *GarageClusterReconciler) recoverOrphanedStorageDrain(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if proof == nil {
		return false, nil
	}
	if cluster.Status.StorageRollout == nil {
		if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
			return true, fmt.Errorf("releasing stale rollout PVC protection behind durable storage drain: %w", err)
		}
	}
	if proof.Actor.Kind != kindGarageNode {
		return true, nil
	}

	actorNode := &garagev1beta1.GarageNode{}
	err := r.Get(ctx, types.NamespacedName{Namespace: proof.Actor.Namespace, Name: proof.Actor.Name}, actorNode)
	actorOwnsFinalizer := false
	if err == nil && actorNode.UID == proof.Actor.UID {
		for _, finalizer := range actorNode.Finalizers {
			if finalizer == garageNodeFinalizer {
				actorOwnsFinalizer = true
				break
			}
		}
		if actorOwnsFinalizer {
			if proof.CompletedAt != nil && actorNode.DeletionTimestamp.IsZero() &&
				actorNode.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue &&
				actorNode.Status.ParentDeletionRequestGeneration == cluster.Generation {
				for _, lostNodeID := range proof.UnavailableSourceNodeIDs {
					if !blockResyncIntentIncludes(proof, lostNodeID) {
						continue
					}
					garageClient, clientErr := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
					if clientErr != nil {
						return true, fmt.Errorf("revalidating completed lost-source drain before automatic GarageNode deletion: %w", clientErr)
					}
					if unavailableErr := requireGarageNodeLostSourceUnavailable(
						ctx, r.safetyReader(), actorNode, cluster, garageClient, lostNodeID,
					); unavailableErr != nil {
						return true, unavailableErr
					}
					if proofErr := requireClusterStorageDrainSafety(
						ctx, r.Client, r.safetyReader(), r.layoutMutationCoordinator(), cluster,
						proof.Actor, garageClient, r.blockResyncObservationGetter, r.blockRepairLauncher,
						r.clusterHealthGetter, r.blockResyncQuietPeriod,
					); proofErr != nil {
						return true, proofErr
					}
				}
				// The status handoff distinguishes a parent-owned Auto/node-local-pool
				// scale-down from a user's prepare-only drain and cannot be forged or
				// removed through ordinary metadata updates. The terminal proof was
				// persisted before this DELETE, so admission can verify the exact
				// actor, targets, and CompletedAt without a deletionTimestamp race.
				if err := r.Delete(ctx, actorNode); err != nil && !apierrors.IsNotFound(err) {
					return true, fmt.Errorf("deleting automatically prepared GarageNode %s/%s: %w", actorNode.Namespace, actorNode.Name, err)
				}
			}
			return true, nil
		}
	} else if err != nil && !apierrors.IsNotFound(err) {
		return true, fmt.Errorf("checking storage-drain actor before recovery: %w", err)
	}

	if proof.CompletedAt == nil {
		message := fmt.Sprintf(
			"Storage drain %s is orphaned: GarageNode %s/%s UID %s no longer owns its finalizer before terminal proof; manual recovery is required",
			proof.TransactionID, proof.Actor.Namespace, proof.Actor.Name, proof.Actor.UID,
		)
		apply := func() {
			setStorageDrainCondition(cluster, metav1.ConditionFalse, garagev1beta1.ReasonStorageDraining, message)
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
			return true, err
		}
		return true, nil
	}

	if err := clearCompletedStorageDrain(ctx, r.Client, r.layoutMutationCoordinator(), cluster, proof); err != nil {
		return true, err
	}
	return false, nil
}

func clusterStorageDrainProof(status *garagev1beta2.StorageDrainStatus) *blockResyncProof {
	if status == nil {
		return nil
	}
	return &blockResyncProof{
		Actor: storageDrainActor{
			APIVersion: status.Actor.APIVersion,
			Kind:       status.Actor.Kind,
			Namespace:  status.Actor.Namespace,
			Name:       status.Actor.Name,
			UID:        types.UID(status.Actor.UID),
		},
		TransactionID:            status.TransactionID,
		TargetHash:               status.TargetHash,
		StartedAt:                status.StartedAt,
		RoleRemovalNodeIDs:       append([]string(nil), status.RoleRemovalNodeIDs...),
		RemovedStorageNodeIDs:    append([]string(nil), status.RemovedStorageNodeIDs...),
		UnavailableSourceNodeIDs: append([]string(nil), status.UnavailableSourceNodeIDs...),
		LayoutVersion:            status.LayoutVersion,
		VerificationNodeIDs:      append([]string(nil), status.VerificationNodeIDs...),
		ManagedPodUIDs:           copyStringMap(status.ManagedPodUIDs),
		RepairBaselines:          copyUint64Map(status.RepairBaselines),
		RepairWorkerIDs:          copyUint64Map(status.RepairWorkerIDs),
		ResyncErrorBaselines:     copyUint64Map(status.ResyncErrorBaselines),
		QueueLength:              status.QueueLength,
		ErrorCount:               status.ErrorCount,
		RequiresEmptyQueue:       status.RequiresEmptyQueue,
		QuietSince:               status.QuietSince.DeepCopy(),
		CompletedAt:              status.CompletedAt.DeepCopy(),
	}
}

func v1beta2StorageDrainStatus(proof *blockResyncProof) *garagev1beta2.StorageDrainStatus {
	if proof == nil {
		return nil
	}
	return &garagev1beta2.StorageDrainStatus{
		Actor: garagev1beta2.StorageDrainActorStatus{
			APIVersion: proof.Actor.APIVersion,
			Kind:       proof.Actor.Kind,
			Namespace:  proof.Actor.Namespace,
			Name:       proof.Actor.Name,
			UID:        string(proof.Actor.UID),
		},
		TransactionID: proof.TransactionID,
		TargetHash:    proof.TargetHash,
		StartedAt:     proof.StartedAt,
		// These are required array fields in both served CRD versions. Preserve
		// internal nil canonicalization while always emitting [] (never null) at
		// the Kubernetes API boundary, including gateway-only/role-only drains.
		RoleRemovalNodeIDs:       copyRequiredStringSlice(proof.RoleRemovalNodeIDs),
		RemovedStorageNodeIDs:    copyRequiredStringSlice(proof.RemovedStorageNodeIDs),
		UnavailableSourceNodeIDs: append([]string(nil), proof.UnavailableSourceNodeIDs...),
		LayoutVersion:            proof.LayoutVersion,
		VerificationNodeIDs:      append([]string(nil), proof.VerificationNodeIDs...),
		ManagedPodUIDs:           copyStringMap(proof.ManagedPodUIDs),
		RepairBaselines:          copyUint64Map(proof.RepairBaselines),
		RepairWorkerIDs:          copyUint64Map(proof.RepairWorkerIDs),
		ResyncErrorBaselines:     copyUint64Map(proof.ResyncErrorBaselines),
		QueueLength:              proof.QueueLength,
		ErrorCount:               proof.ErrorCount,
		RequiresEmptyQueue:       proof.RequiresEmptyQueue,
		QuietSince:               proof.QuietSince.DeepCopy(),
		CompletedAt:              proof.CompletedAt.DeepCopy(),
	}
}
