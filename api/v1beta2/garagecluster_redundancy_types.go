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

package v1beta2

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// RedundancyPhase is a step of the full-redundancy proof.
// +kubebuilder:validation:Enum=Idle;Pending;SyncingMetadata;ScanningBlocks;Settling;Partial;Verified
type RedundancyPhase string

const (
	// RedundancyPhaseIdle: the operator recorded a baseline and runs no proof.
	// A proof starts only on a verify-redundancy request or on a storage
	// topology change seen after the baseline.
	RedundancyPhaseIdle            RedundancyPhase = "Idle"
	RedundancyPhasePending         RedundancyPhase = "Pending"
	RedundancyPhaseSyncingMetadata RedundancyPhase = "SyncingMetadata"
	RedundancyPhaseScanningBlocks  RedundancyPhase = "ScanningBlocks"
	RedundancyPhaseSettling        RedundancyPhase = "Settling"
	// RedundancyPhasePartial: every reachable owned storage node finished,
	// and at least one node is in status.redundancy.deferredNodes.
	RedundancyPhasePartial  RedundancyPhase = "Partial"
	RedundancyPhaseVerified RedundancyPhase = "Verified"
)

// RedundancyTrigger names the event that started the current proof.
// +kubebuilder:validation:Enum=Requested;LayoutChanged;NodeChanged
type RedundancyTrigger string

const (
	// RedundancyTriggerRequested: a new verify-redundancy annotation value.
	RedundancyTriggerRequested RedundancyTrigger = "Requested"
	// RedundancyTriggerLayoutChanged: the zone or capacity of a storage role
	// changed after the baseline.
	RedundancyTriggerLayoutChanged RedundancyTrigger = "LayoutChanged"
	// RedundancyTriggerNodeChanged: the set of storage node IDs changed after
	// the baseline.
	RedundancyTriggerNodeChanged RedundancyTrigger = "NodeChanged"
)

// RedundancyNodeStage is the step of the storage node whose turn it is.
// +kubebuilder:validation:Enum=Tables;Blocks;Pause
type RedundancyNodeStage string

const (
	RedundancyNodeStageTables RedundancyNodeStage = "Tables"
	RedundancyNodeStageBlocks RedundancyNodeStage = "Blocks"
	RedundancyNodeStagePause  RedundancyNodeStage = "Pause"
)

// RedundancyDeferReason says why a storage node was skipped.
// +kubebuilder:validation:Enum=Down;NotReporting;RepairFailed
type RedundancyDeferReason string

const (
	// RedundancyDeferDown: Garage reported the node down.
	RedundancyDeferDown RedundancyDeferReason = "Down"
	// RedundancyDeferNotReporting: the node did not answer ListWorkers or
	// ListBlockErrors.
	RedundancyDeferNotReporting RedundancyDeferReason = "NotReporting"
	// RedundancyDeferRepairFailed: a repair on the node failed three times.
	// Only a new verify-redundancy value retries it.
	RedundancyDeferRepairFailed RedundancyDeferReason = "RepairFailed"
)

// RedundancyStatus groups progress and verification for full redundancy.
type RedundancyStatus struct {
	// Verification is the proof state. Absent on a layout Follower and on a
	// federated site without spec.layoutManagement.siteRole.
	// +optional
	Verification *RedundancyVerificationStatus `json:"verification,omitempty"`

	// ProgressObservedAt is when nodes[] was last rewritten. Progress is
	// rewritten at most once per minute unless another redundancy field
	// changes in the same pass, and only when a value changed.
	// +optional
	ProgressObservedAt *metav1.Time `json:"progressObservedAt,omitempty"`

	// LastProgressAt is the last time remaining work decreased (a resync or
	// table sync queue shrank, a repair scan advanced, or the proof moved to
	// a later step). It moves forward in steps of at least one minute.
	// +optional
	LastProgressAt *metav1.Time `json:"lastProgressAt,omitempty"`

	// Nodes holds per-node progress for every current storage node and every
	// other node that reports block errors, sorted by nodeId.
	// +optional
	// +listType=map
	// +listMapKey=nodeId
	// +kubebuilder:validation:MaxItems=256
	Nodes []NodeRedundancyStatus `json:"nodes,omitempty"`

	// DeferredNodes lists owned storage nodes the current proof skipped.
	// Down and NotReporting nodes are retried once they are back, no sooner
	// than retryAfter.
	// +optional
	// +listType=map
	// +listMapKey=nodeId
	// +kubebuilder:validation:MaxItems=256
	DeferredNodes []RedundancyDeferredNode `json:"deferredNodes,omitempty"`
}

// RedundancyDeferredNode is an owned storage node the proof skipped.
type RedundancyDeferredNode struct {
	// NodeID is the full Garage node ID.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	NodeID string `json:"nodeId"`
	// Reason says why the node was skipped.
	Reason RedundancyDeferReason `json:"reason"`
	// Since is when the node was skipped.
	Since metav1.Time `json:"since"`
	// RetryAfter is the earliest time the operator retries the node. Absent
	// for RepairFailed, which only a new verify-redundancy value retries.
	// +optional
	RetryAfter *metav1.Time `json:"retryAfter,omitempty"`
}

// RedundancyVerificationStatus is the durable state of the proof, kept so it
// survives operator restarts.
type RedundancyVerificationStatus struct {
	// Phase is the proof step.
	Phase RedundancyPhase `json:"phase"`

	// Trigger is what started the current proof. Absent while Idle.
	// +optional
	Trigger RedundancyTrigger `json:"trigger,omitempty"`

	// StartedAt is when the current proof attempt began.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// PhaseStartedAt is when Phase was entered.
	// +optional
	PhaseStartedAt *metav1.Time `json:"phaseStartedAt,omitempty"`

	// VerifiedAt is when the last proof completed. It survives later proofs
	// and outages, so it records the last time full redundancy was proven.
	// +optional
	VerifiedAt *metav1.Time `json:"verifiedAt,omitempty"`

	// LayoutVersion is the Garage layout version last observed.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LayoutVersion int64 `json:"layoutVersion,omitempty"`

	// TopologyHash fingerprints the ID, zone and capacity of every storage
	// role in the current layout. A change after the baseline starts a proof;
	// tag-only layout changes and Pod restarts do not change it.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	TopologyHash string `json:"topologyHash,omitempty"`

	// RequestToken is the last handled value of the
	// garage.rajsingh.info/verify-redundancy annotation.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	RequestToken string `json:"requestToken,omitempty"`

	// CurrentNodeID is the owned storage node whose turn it is. Repairs run
	// on one storage node at a time.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	CurrentNodeID string `json:"currentNodeId,omitempty"`

	// CompletedNodeIDs are the owned storage nodes that finished this proof,
	// sorted.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	CompletedNodeIDs []string `json:"completedNodeIds,omitempty"`

	// Evidence is the internal proof state. Its shape may change between
	// operator releases; an unrecognized shape restarts the current node.
	// +optional
	Evidence *RedundancyProofEvidence `json:"evidence,omitempty"`
}

// RedundancyProofEvidence holds the state of the current node's turn and of
// the final quiet period. Map keys are "<nodeId>/<workerId>".
type RedundancyProofEvidence struct {
	// SkipTables is true for a proof started by a layout change: Garage's
	// settled layout history already proves a full table sync on every node.
	// +optional
	SkipTables bool `json:"skipTables,omitempty"`

	// NodeStage is the current node's step.
	// +optional
	NodeStage RedundancyNodeStage `json:"nodeStage,omitempty"`

	// StageLaunchedAt is when the current node's repair was launched.
	// +optional
	StageLaunchedAt *metav1.Time `json:"stageLaunchedAt,omitempty"`

	// WorkerBaseline is the current node's highest worker ID at the launch.
	// A lower maximum later means Garage restarted.
	// +optional
	WorkerBaseline uint64 `json:"workerBaseline,omitempty"`

	// SyncErrorBaselines is the errors counter of each of the five
	// "<table> sync" workers of the current node at the tables launch.
	// +optional
	SyncErrorBaselines map[string]uint64 `json:"syncErrorBaselines,omitempty"`

	// IdleSince is the first pass, after the tables launch, at which the
	// current node's sync workers were idle and its metadata queues empty.
	// +optional
	IdleSince *metav1.Time `json:"idleSince,omitempty"`

	// PeerDownSeen is true when some storage node was down during the
	// current node's table sync. Sync errors are then expected; the node is
	// rechecked with a tables-only pass once every node is up.
	// +optional
	PeerDownSeen bool `json:"peerDownSeen,omitempty"`

	// RepairWorkerID is the blocks repair worker adopted on the current node.
	// +optional
	RepairWorkerID uint64 `json:"repairWorkerId,omitempty"`

	// Launches counts the launches of the current node's stage. After three
	// the node is deferred as RepairFailed.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3
	// +optional
	Launches int32 `json:"launches,omitempty"`

	// PauseUntil ends the pause after the current node finished.
	// +optional
	PauseUntil *metav1.Time `json:"pauseUntil,omitempty"`

	// TablesRecheckNodeIDs are completed nodes whose table sync ran while a
	// peer was down; each gets a tables-only pass once every node is up.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	TablesRecheckNodeIDs []string `json:"tablesRecheckNodeIds,omitempty"`

	// ResyncErrorBaselines is the persistent-error counter of every block
	// resync worker on the owned nodes when the quiet period started.
	// +optional
	ResyncErrorBaselines map[string]uint64 `json:"resyncErrorBaselines,omitempty"`

	// QuietSince starts the final quiet period.
	// +optional
	QuietSince *metav1.Time `json:"quietSince,omitempty"`

	// BlockErrorsBaseline is the block-error count at the start of the
	// current 30-minute window used to detect a growing count.
	// +optional
	BlockErrorsBaseline *int64 `json:"blockErrorsBaseline,omitempty"`

	// BlockErrorsBaselineAt is when the current block-error window opened.
	// +optional
	BlockErrorsBaselineAt *metav1.Time `json:"blockErrorsBaselineAt,omitempty"`
}

// NodeRedundancyStatus is the progress of one Garage node.
type NodeRedundancyStatus struct {
	// NodeID is the full Garage node ID.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	NodeID string `json:"nodeId"`

	// Observed is false when the node did not answer this pass; the counters
	// then keep their previous values.
	Observed bool `json:"observed"`

	// ResyncQueueLength is the node's block resync queue, including delayed
	// rechecks.
	// +optional
	ResyncQueueLength *int64 `json:"resyncQueueLength,omitempty"`

	// ResyncIdle is true when every enabled resync worker is idle.
	// +optional
	ResyncIdle *bool `json:"resyncIdle,omitempty"`

	// BlockErrors is the node's number of blocks with resync errors.
	// +optional
	BlockErrors *int32 `json:"blockErrors,omitempty"`

	// MetadataSyncPartitions is the sum over tables of partitions left in the
	// current full-sync pass. It is 0 between passes.
	// +optional
	MetadataSyncPartitions *int32 `json:"metadataSyncPartitions,omitempty"`

	// MetadataQueueLength is the sum of the Merkle-updater and insert queues.
	// +optional
	MetadataQueueLength *int64 `json:"metadataQueueLength,omitempty"`

	// BlockRepairProgress is Garage's progress string for the exact
	// verification repair worker on this node while it runs.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	BlockRepairProgress string `json:"blockRepairProgress,omitempty"`
}
