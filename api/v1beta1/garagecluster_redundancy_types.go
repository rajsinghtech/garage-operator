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

package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// RedundancyPhase is a step of the full-redundancy proof.
// +kubebuilder:validation:Enum=Pending;SyncingMetadata;ScanningBlocks;Settling;Verified
type RedundancyPhase string

const (
	RedundancyPhasePending         RedundancyPhase = "Pending"
	RedundancyPhaseSyncingMetadata RedundancyPhase = "SyncingMetadata"
	RedundancyPhaseScanningBlocks  RedundancyPhase = "ScanningBlocks"
	RedundancyPhaseSettling        RedundancyPhase = "Settling"
	RedundancyPhaseVerified        RedundancyPhase = "Verified"
)

// RedundancyTrigger names the event that started the current proof.
// +kubebuilder:validation:Enum=Initial;Requested;LayoutChanged;NodeChanged;NodeDown;BlockErrors
type RedundancyTrigger string

const (
	RedundancyTriggerInitial       RedundancyTrigger = "Initial"
	RedundancyTriggerRequested     RedundancyTrigger = "Requested"
	RedundancyTriggerLayoutChanged RedundancyTrigger = "LayoutChanged"
	RedundancyTriggerNodeChanged   RedundancyTrigger = "NodeChanged"
	RedundancyTriggerNodeDown      RedundancyTrigger = "NodeDown"
	RedundancyTriggerBlockErrors   RedundancyTrigger = "BlockErrors"
)

// RedundancyStatus groups progress and verification for full redundancy.
type RedundancyStatus struct {
	// Verification is the active full-redundancy proof. Absent on a layout
	// Follower, where the layout-writer site runs the proof.
	// +optional
	Verification *RedundancyVerificationStatus `json:"verification,omitempty"`

	// ProgressObservedAt is when nodes[] was last rewritten. Progress is
	// rewritten at most once per minute unless another redundancy field
	// changes in the same pass, and only when a value changed.
	// +optional
	ProgressObservedAt *metav1.Time `json:"progressObservedAt,omitempty"`

	// LastProgressAt is the last time remaining work decreased (a resync or
	// table sync queue shrank, a repair scan advanced, or the proof entered a
	// later phase). It moves forward in steps of at least one minute.
	// +optional
	LastProgressAt *metav1.Time `json:"lastProgressAt,omitempty"`

	// Nodes holds per-node progress for every current storage node and every
	// other node that reports block errors, sorted by nodeId.
	// +optional
	// +listType=map
	// +listMapKey=nodeId
	// +kubebuilder:validation:MaxItems=256
	Nodes []NodeRedundancyStatus `json:"nodes,omitempty"`
}

// RedundancyVerificationStatus is the durable state of the proof, kept so it
// survives operator restarts.
type RedundancyVerificationStatus struct {
	// Phase is the proof step.
	Phase RedundancyPhase `json:"phase"`

	// Trigger is what started the current proof.
	// +optional
	Trigger RedundancyTrigger `json:"trigger,omitempty"`

	// StartedAt is when the current proof attempt began.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// PhaseStartedAt is when Phase was entered.
	// +optional
	PhaseStartedAt *metav1.Time `json:"phaseStartedAt,omitempty"`

	// VerifiedAt is when the last proof completed. It survives invalidation,
	// so it records the last time the cluster was proven fully replicated.
	// +optional
	VerifiedAt *metav1.Time `json:"verifiedAt,omitempty"`

	// LayoutVersion is the Garage layout version the proof is bound to.
	// +optional
	// +kubebuilder:validation:Minimum=0
	LayoutVersion int64 `json:"layoutVersion,omitempty"`

	// MembershipHash fingerprints the sorted current storage node IDs and the
	// UID and garage container restart count of every managed storage Pod.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	MembershipHash string `json:"membershipHash,omitempty"`

	// RequestToken is the last handled value of the
	// garage.rajsingh.info/verify-redundancy annotation.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	RequestToken string `json:"requestToken,omitempty"`

	// Evidence is the internal proof state. Its shape may change between
	// operator releases; an unrecognized shape restarts the proof.
	// +optional
	Evidence *RedundancyProofEvidence `json:"evidence,omitempty"`
}

// RedundancyProofEvidence holds worker-ID baselines and timers. Map keys are
// full Garage node IDs, or "<nodeId>/<workerId>" for per-worker counters.
type RedundancyProofEvidence struct {
	// MetadataLaunchedAt is when the tables repair was launched on every
	// storage node. Set in the same status write that follows the launch.
	// +optional
	MetadataLaunchedAt *metav1.Time `json:"metadataLaunchedAt,omitempty"`

	// MetadataWorkerBaselines is each storage node's highest worker ID at the
	// tables-repair launch. A lower maximum later means Garage restarted.
	// +optional
	MetadataWorkerBaselines map[string]uint64 `json:"metadataWorkerBaselines,omitempty"`

	// MetadataErrorBaselines is the errors counter of each of the five
	// "<table> sync" workers at the tables-repair launch.
	// +optional
	MetadataErrorBaselines map[string]uint64 `json:"metadataErrorBaselines,omitempty"`

	// MetadataIdleSince is the first pass, after the launch, at which every
	// sync worker was idle and every metadata queue empty.
	// +optional
	MetadataIdleSince *metav1.Time `json:"metadataIdleSince,omitempty"`

	// VerificationNodeIDs is the sorted storage membership the blocks stage
	// is bound to.
	// +optional
	VerificationNodeIDs []string `json:"verificationNodeIds,omitempty"`

	// RepairBaselines is each storage node's highest worker ID before the
	// blocks repair, persisted before the launch (as in status.storageDrain).
	// +optional
	RepairBaselines map[string]uint64 `json:"repairBaselines,omitempty"`

	// RepairWorkerIDs is the exact post-baseline blocks repair worker adopted
	// on each storage node.
	// +optional
	RepairWorkerIDs map[string]uint64 `json:"repairWorkerIds,omitempty"`

	// ResyncErrorBaselines is the persistent-error counter of every enabled
	// block resync worker once all repair scans completed.
	// +optional
	ResyncErrorBaselines map[string]uint64 `json:"resyncErrorBaselines,omitempty"`

	// QuietSince starts the quiet period after every repair scan completed.
	// +optional
	QuietSince *metav1.Time `json:"quietSince,omitempty"`

	// BlockErrorsBaseline is the cluster block-error count at the start of
	// the current 30-minute window used to detect a growing count.
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
