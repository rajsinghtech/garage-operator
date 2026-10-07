# Reporting resync progress and full redundancy on the GarageCluster

**Status:** Accepted — design for
[#474](https://github.com/rajsinghtech/garage-operator/issues/474) (part 2).
All eleven items in [Decisions](#decisions) were decided by Raj Singh on
2026-10-06 (every recommended option was accepted). Part 1, which populates the
existing `resyncQueueLength`, `blockErrors` and `blockErrorDetails` fields,
shipped in [#477](https://github.com/rajsinghtech/garage-operator/pull/477)
(`6290b6c`). It is fail-closed: silent capacityless gateways are ignored, and
values are pointers so an observed `0` is distinct from "not observed".
Differences between this record and the shipped code are listed under
[Implementation notes / deviations](#implementation-notes-deviations).

## Problem

Users who take a storage node out of service and bring it back with empty
storage ([#475](https://github.com/rajsinghtech/garage-operator/issues/475)),
or lose a disk unexpectedly, need to know when every object is fully
replicated again before they touch the next node. Today they run
`garage stats` in each pod and look at three heuristics: table item counts
match, the block resync queue is near 0, and there are no block errors. The
reporter points out that the heuristic is unreliable: right after a node
returns, its resync queue is small because metadata has not synced yet, so
Garage does not know which blocks are missing.

They asked for four things, all from Kubernetes resources:

1. one reliable "fully redundant again" signal a runbook or automation can
   wait on;
2. progress while it isn't: how much is left, how fast, roughly when done;
3. a distinction between slow and stuck or failing;
4. no `kubectl exec` into Garage pods.

## What Garage exposes (verified in source)

Checked against the operator's Garage floor (the first v2 release), the
current default Garage release, and `main-v2` at `adaf85c9` (unreleased).
"Floor" and "default" below refer to those two releases.

| Signal | Admin API v2 | Floor | Default | main-v2 |
| --- | --- | --- | --- | --- |
| Partitions with all replicas connected | `GetClusterHealth.partitionsAllOk` / `partitions` | yes | yes | yes |
| Storage nodes connected | `GetClusterHealth.storageNodesOk` (floor) / `storageNodesUp` (later) | `…Ok` | `…Up` | `…Up` |
| Layout history with per-node `ack` / `sync` / `syncAck` trackers | `GetClusterLayoutHistory.updateTrackers` | yes | yes | yes |
| Per-worker `queueLength`, `persistentErrors`, `errors`, `consecutiveErrors`, `state`, `progress` | `ListWorkers?node=*` | yes | yes | yes |
| Block resync queue (per node) | `Block resync worker #N` `queueLength` | yes | yes | yes |
| Table sync progress (partitions left in the current full-sync pass) | `<table> sync` worker `queueLength` | yes | yes | yes |
| Merkle updater / insert / GC queues | `<table> Merkle`, `<table> queue`, `<table> GC` worker `queueLength` | yes | yes | yes |
| Blocks with resync errors (hash, count, last/next try) | `ListBlockErrors?node=*` | yes | yes | yes |
| Start a full table sync | `LaunchRepairOperation{repairType: tables}` | yes | yes | yes |
| Scan block refs and queue missing blocks | `LaunchRepairOperation{repairType: blocks}` | yes | yes | yes |
| Structured table and block-manager counters | `GetNodeStatistics.tableStats[]`, `blockManagerStats` | freeform text | yes | yes |
| Per-node resync queue in one call (gossiped, no fan-out) | `GetClusterStatus.nodes[].resyncQueueLen` | no | no | yes ([Garage #1556](https://git.deuxfleurs.fr/Deuxfleurs/garage/pulls/1556)) |
| Prometheus gauges and counters | `block_resync_queue_length`, `block_resync_errored_blocks`, `block_resync_counter`, `table_merkle_updater_todo_queue_length`, `table_sync_items_received` | yes | yes | yes |

A `tables` repair calls `add_full_sync()` on exactly five tables in every
release checked: `bucket_v2`, `object`, `version`, `block_ref` and `key`
(`src/api/admin/repair.rs`). Their sync workers are named
`bucket_v2 sync`, `object sync`, `version sync`, `block_ref sync` and
`key sync` (`src/table/sync.rs`, `format!("{} sync", TABLE_NAME)`).

Facts that drive the design:

1. **No Garage v2 release has a "fully replicated" API.** Nothing reports
   that every block is present on every node that should hold it.
2. **Layout `sync` trackers are a native signal, for layout changes only.** A
   node's `sync` tracker reaches version *v* only after its table sync workers
   finish a full pass for *v* (`src/table/sync.rs`, `sync_table_until`). When
   every node's `sync` ≥ the current version, all metadata has reached the new
   assignment, and Garage retires the old version from reads. The operator
   already uses this test (`LayoutHistoryResponse.DataMigrationSettled`,
   `requireSettledLayoutHistoryResponse`). It says nothing about blocks, and
   nothing at all when the layout did not change.
3. **The table sync queue is 0 between passes.** `<table> sync` reports the
   partitions left in the *current* full-sync pass, and its state is `Busy`
   while a pass is pending and `Idle` otherwise. Sharded tables start a pass
   20 s after process start, every 10 minutes (`ANTI_ENTROPY_INTERVAL`), on
   every layout change, and on a `tables` repair. A 0 seen at a random moment
   proves nothing. A 0 seen after a `tables` repair started proves that pass
   finished, because the repair queues every partition, and a failed partition
   goes back into the queue and bumps the worker's `errors`.
4. **The resync queue only holds blocks Garage already knows are missing.**
   Blocks are queued when a block reference arrives (metadata sync), when a
   `blocks` repair scans the refs, or when the monthly scrub finds damage. So
   the queue is low before metadata has synced (the reporter's pitfall). It is
   also 0 when only the **data** disk was lost and metadata survived: block
   refs are intact, nothing re-queues the missing files, and every passive
   check reads "healthy" until a `blocks` repair or scrub runs. That is a
   false "fully redundant".
5. **The resync queue also counts delayed work.** Rechecks scheduled for later
   (deletes after the ~10-minute block GC delay, retries with exponential
   backoff) stay in the queue, so it can stay above 0 on a busy cluster. The
   resync worker's `state` is `idle` when nothing is due now
   (`ResyncIterResult::IdleFor`), which is the better "caught up" test.
6. **Comparing item counts across nodes only works when every storage node
   holds every partition**, and counts include tombstones that differ while GC
   runs, so they can hint but cannot prove anything.
7. **Node identity tracks the metadata disk.** `node_key` lives in
   `metadata_dir`. A node whose metadata disk was wiped comes back as a new
   member, which needs a layout change, so fact 2 applies. A node that kept
   its identity but lost data, metadata (identity restored), or both, has no
   layout change and no native signal.

Conclusion: **a reliable signal exists only as an active proof, not as a
passive reading.** The proof is: layout settled, a full table sync completed
cleanly on every storage node after the disruption, a `blocks` repair scan
completed cleanly on every storage node after that, and then resync workers
idle with no persistent errors and no new error records through a quiet
period. Every part of that is available from the floor release on; later
releases only make the progress *display* cheaper.

## Current code: the storage-drain proof

`internal/controller/block_resync_barrier.go` already proves "blocks moved" for
a storage drain and is the shared engine for this design:

- `blockResyncObservationFromResponses`: settled layout history, empty staging
  area, layout/status/history versions agree, `ListWorkers(*)` and
  `ListBlockErrors(*)` answered by every storage node (fail closed).
- `evaluateBlockResyncProgress` (side-effect free): records the highest worker
  ID per node as a baseline, requests `LaunchRepairOperation{blocks}` on every
  verification node whose baseline is already persisted, adopts the exact new
  `Block repair worker`, waits until it is done with 0 errors, records each
  `Block resync worker #N` persistent-error counter, then requires every resync
  worker idle, unchanged error counters and 0 block errors, held for
  `effectiveBlockResyncQuietPeriod` (`max(2 × rpcTimeout, 610 s + 60 s)`). Any
  restart, membership change, layout change or error resets the proof.
- The drain persists the proof in `status.storageDrain`, which is also the
  drain's mutual-exclusion record.

With an empty removal set, `evaluateBlockResyncProgress` proves exactly "every
current positive-capacity storage node completed a clean `blocks` scan and its
resync workers stayed idle and error-free through the quiet period". The
redundancy verification calls it unchanged with a proof value built from
`status.redundancy.verification.evidence` (decision D9). It never reads or
writes `status.storageDrain`.

## Decision

Two layers:

- **Progress (passive, always on, cheap).** Per-node counters read on every
  status pass from responses the status pass already fetches, written at most
  once per minute.
- **Verification (active, event-triggered).** A state machine that runs the
  proof and owns one condition, `FullyReplicated`. Only a completed proof sets
  it `True`.

### Verification state machine

Stored in `status.redundancy.verification`.

| Phase | Entered when | Leaves when |
| --- | --- | --- |
| `Pending` | invalidated, never verified, or a precondition broke mid-proof | preconditions hold → `SyncingMetadata`, or straight to `ScanningBlocks` when the trigger is `LayoutChanged` (the settled-history precondition already proves every `sync` tracker is current: fact 2) |
| `SyncingMetadata` | the operator records per-node worker-ID baselines and the `errors` counter of each of the five `<table> sync` workers, launches a `tables` repair on every current storage node, then records `metadataLaunchedAt` in the same status write | on every storage node, each of the five sync workers is `Idle` with `queueLength` 0 and `errors` equal to its baseline, and the `Merkle` and `queue` workers of those tables have `queueLength` 0, observed on two passes at least 30 s apart, both after the launch |
| `ScanningBlocks` | metadata stage done (or skipped); the shared engine records repair baselines, then launches and adopts one `blocks` repair worker per storage node | every adopted repair worker is `Done` with 0 errors |
| `Settling` | scans done; the engine records resync error baselines and `quietSince` | the quiet period elapsed with every resync worker idle, persistent-error counters unchanged and `ListBlockErrors` empty → `Verified` |
| `Verified` | the engine reported the proof complete | an invalidating event |

**Preconditions** (checked whenever the phase is not `Verified`; a break
returns the proof to `Pending` and clears its evidence):

- this `GarageCluster` has a storage tier, no `connectTo`, and is not a layout
  `Follower` (D10);
- every current storage node is up (`GetClusterHealth.storageNodesUp ==
  storageNodes`) and `partitionsAllOk == partitions`;
- the layout history is settled (`requireSettledLayoutHistoryResponse`) and
  Garage's staging area is empty;
- neither `status.storageDrain` nor an in-flight factor migration
  (`factorMigrationActive`) exists (D9);
- every current storage node answered `ListWorkers` and `ListBlockErrors`.

**Invalidating events** (→ `Pending`, with the named trigger; `verifiedAt` is
kept):

| Event | Trigger |
| --- | --- |
| `status.redundancy` absent (new cluster or operator upgrade) | `Initial` |
| the request annotation carries a value different from `verification.requestToken` | `Requested` |
| the Garage layout version differs from `verification.layoutVersion` | `LayoutChanged` |
| `membershipHash` changes: the sorted current storage node IDs, or the UID or `garage` container restart count of a managed storage Pod of this cluster | `NodeChanged` |
| a current storage node is reported down | `NodeDown` |
| `Verified`, and `ListBlockErrors` reports any record | `BlockErrors` |

Events are evaluated in that order; the first match names the trigger. There
is no periodic re-verification (D4): a `blocks` repair reads every block ref
and stats every file, which is too expensive for a timer.

### Request annotation

`garage.rajsingh.info/verify-redundancy: "<token>"`. Any value different from
the last handled one (`status.redundancy.verification.requestToken`) resets
the proof with `Trigger=Requested`, then the token is recorded in the same
status write. The annotation is **not** removed, so a GitOps tool that keeps
re-applying it does not cause a loop; change the value to request another
proof. An empty value is ignored.

### API (v1beta2, hub; v1beta1 carries identical types)

```go
// GarageClusterStatus (both versions, after LayoutWriter):

	// Redundancy reports block-resync progress and the last full-redundancy
	// proof. Absent on clusters without a storage tier, on connectTo clusters,
	// and until the controller first observes Garage.
	// +optional
	Redundancy *RedundancyStatus `json:"redundancy,omitempty"`

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
```

No CEL is added: every field is controller-written status, the enums and
patterns are enforced by the schema, and there is no spec change (D6 keeps the
stall threshold in code).

Size: 256 nodes × ~230 B is about 60 KiB in the worst case; a 3–12 node cluster
adds well under 3 KiB.

### Condition

`FullyReplicated` on `GarageCluster` (constant in
`api/v1beta1/condition_types.go`). Reasons, in priority order (the first that
applies wins):

| Status | Reason | When | Message (stable; no raw error text, no counters that tick every pass) |
| --- | --- | --- | --- |
| `Unknown` | `NotObserved` | the Admin API did not answer the status reads | "Garage Admin API did not answer; redundancy cannot be observed" (+ " (last verified <RFC3339>)" when known) |
| `Unknown` | `PreconditionsNotMet` | Follower site, storage node down, layout unsettled or staged, drain or factor migration active, a storage node did not answer | names the first failing precondition and, when relevant, the short node ID |
| `False` | `Stalled` | proof active and: `lastProgressAt` older than 30 min, or an adopted repair worker or a `<table> sync` worker reported errors in the current attempt, or the cluster block-error count grew within the current 30-minute window | names the rule and the node |
| `False` | `BlockErrors` | proof active, or invalidated by block errors, and block errors are present but not growing | "<n> blocks have resync errors" |
| `False` | `Verifying` | proof active | names the phase and the first (sorted) node not yet done in that phase; in `Settling`, the time the quiet period ends |
| `True` | `Verified` | phase `Verified` | "Full redundancy verified on layout version <v> for <n> storage nodes" |

The condition is informational and does **not** gate `Ready` (D8).
`kubectl wait --for=condition=FullyReplicated` is the runbook primitive.

### Status write churn

- Everything is computed into the in-memory status before the single status
  write at the end of `updateStatusFromCluster`. The verification adds no
  extra write.
- Messages contain no timestamps that move, no raw error strings and no
  counters that change on every pass. The `Settling` message carries the
  fixed end of the quiet period.
- `nodes[]` and `progressObservedAt` are rewritten only when a value changed,
  and then at most once per 60 s, unless another redundancy field changes in
  the same pass. An idle `Verified` cluster performs no redundancy writes.
- `lastProgressAt` moves forward only in steps of at least 60 s.
- Garage worker progress strings are only stored for the exact repair worker
  the proof owns, and only through the 60 s throttle.
- Conflict safety: on a status-update conflict the merge keeps the fresh
  object's `redundancy` when it differs from the value this pass started
  from, so a reconcile working from a stale cache can never roll back
  persisted proof evidence (the drain uses a CAS revision for the same
  reason).
- While a proof is active, the status pass requeues after at most 60 s, so the
  proof advances without depending on status-only watch events (see the
  status-predicate change in flight for the primary watch).

### Interaction with drains, maintenance (#475) and Ready

- A storage drain or factor migration runs its own proof and holds
  `status.storageDrain` / `status.factorMigration`. While either is active,
  verification sits in `Pending` with `PreconditionsNotMet`. Its layout change
  then invalidates any earlier proof (`LayoutChanged`), so verification runs
  once after the drain and skips the metadata stage.
- #475 maintenance (take one node out, bring it back empty): taking the node
  out makes the condition `Unknown`/`PreconditionsNotMet` (node down)
  immediately. The returning node is a `NodeChanged` trigger (a new identity
  is also `LayoutChanged`). A future maintenance API uses `FullyReplicated`
  as the gate before the next node and as its "done" signal; #475 must not add
  a second redundancy signal.
- A rolling Pod replacement changes Pod UIDs, so every rollout ends with one
  verification. During the rollout the proof waits in `Pending` (node down).

### Federation (D10)

Garage's `node=*` covers every site, so one proof covers the whole Garage
cluster. Only a site that may write the layout runs it: a
`layoutManagement.siteRole: Follower` site never launches repairs. It still
fills `nodes[]` and `lastProgressAt` from its own reads (the counters are the
same cluster-wide data), omits `verification`, and reports
`Unknown`/`PreconditionsNotMet` with a message pointing at the layout-writer
site's `GarageCluster`. Sites share no Kubernetes API, so the Follower cannot
copy the writer's condition; mirroring means the same progress view plus a
pointer. A federation that has not designated a writer (every site is a
Writer by default) runs one proof per site; the repairs are idempotent but
duplicated, so the federation guide recommends setting `siteRole`.

## Compatibility and upgrade

- All additions are optional status fields plus a new condition type. Old
  clients ignore them. No spec changes.
- v1beta1 gets identical Go types. Conversion copies status through JSON
  (`copyViaJSON`), so no conversion code is needed; a round-trip test pins it.
- **Upgrade cost.** On upgrade `status.redundancy` is absent, so verification
  starts with `Trigger=Initial`: one `tables` repair and one `blocks` repair
  per storage node, run by Garage at its normal tranquility. Release notes
  say so.
- Works on every supported Garage v2 release. Using `GetNodeStatistics` or
  `GetClusterStatus.nodes[].resyncQueueLen` for cheaper progress reads is a
  later optimization behind a version check.
- D11 deprecations change only field descriptions; the fields stay in the
  schema until the next API version removes them.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Storage node down mid-proof | `Unknown`/`PreconditionsNotMet`; the proof restarts from `Pending` (`NodeDown`) when it is back |
| Operator restart mid-proof | the proof resumes from `status.redundancy.verification.evidence`; nothing is held in memory |
| Garage restart mid-proof (same Pod) | the `garage` container restart count changes the membership hash (`NodeChanged`); for remote sites, a lower worker-ID maximum or a lost adopted worker restarts the stage |
| `tables` launch fails or its response is lost | `metadataLaunchedAt` is not recorded; the next pass launches again (a full sync is idempotent) |
| `blocks` launch fails or its response is lost | baselines were persisted first; the next pass adopts the worker if it exists, otherwise launches again |
| Status write fails after a launch | the next pass sees no recorded launch and repeats it; Garage only gains one more full sync or scan |
| Repair worker finishes with errors | `False`/`Stalled`; the engine launches a clean repair (existing logic) |
| Block missing on every replica | `ListBlockErrors` never clears; `False`/`BlockErrors`, or `Stalled` if growing; needs human action (`garage block info`, `purge`) |
| Table sync cannot reach a partition | sync `errors` rise and its queue stays above 0; `Stalled` immediately (worker errors) |
| Admin API unreachable | `Unknown`/`NotObserved`; `nodes[]` keep their last values and their old `progressObservedAt` |

## Alternatives considered

- **Passive heuristic only** (queue near 0 + no errors + equal item counts).
  Wrong in the reporter's cases: early low queue (fact 4), data-only loss
  (fact 4), and sync queue 0 between passes (fact 3). Its counters are kept as
  progress.
- **Scrub instead of a `blocks` repair.** Scrub reads and hashes every block,
  which is far more expensive, and proves integrity rather than placement.
- **Item-count equality.** Only valid when every storage node holds every
  partition. Deferred.
- **ETA computed by the operator.** The queue is not monotonic: it grows as
  metadata arrives (fact 4), so an early ETA is wrong by orders of magnitude.
  Rate and ETA belong in Prometheus (D5).
- **Removing the request annotation after handling it**, like the older
  one-shot annotations. That is a metadata write per request, and a GitOps
  tool re-applying the annotation would re-trigger the proof forever. A token
  compared with status avoids both.

## Test plan

- **Unit, state machine** (fake Admin API responses, fake clock): every
  phase transition; every invalidation and its trigger; metadata-stage skip
  on `LayoutChanged`; restart detection in both stages (worker-ID regression,
  lost adopted worker); repair errors → `Stalled`; growing block errors →
  `Stalled`; 30-minute no-progress → `Stalled`; precondition breaks; Follower
  and `connectTo` clusters; request token handling.
- **Unit, churn**: identical inputs produce an identical status (no write);
  the 60 s progress throttle; `lastProgressAt` step; stable messages across
  passes with ticking Garage counters; conflict merge keeps fresh evidence.
- **Fault injection** (the #469 harness, extended with a Garage repair model):
  sweep every Kubernetes write (error and conflict) and every Admin API call
  (failed before and after commit) across a full proof, plus double faults;
  every run converges to `Verified` with the same condition, and the converged
  state is quiet (no further repairs, no writes). Operator restarts mid-proof
  are simulated by a fresh reconciler between passes.
- **Envtest**: the generated CRD accepts the full status, rejects a bad phase
  enum and node ID pattern, and keeps the condition through a status update;
  v1beta1 round trip.
- **E2E** (single cluster, real Garage): after the cluster becomes ready,
  `status.redundancy.verification` reaches at least `Settling` (proving the
  real `tables` and `blocks` repairs were launched, adopted and completed) and
  `FullyReplicated` is present with a known reason. Waiting for `Verified`
  needs the full quiet period (more than ten minutes) and is left to a
  scheduled lane.

## Documentation

`docs/reference/custom-resources.md` (fields, condition, annotation,
deprecations), `docs/operations/maintenance-and-recovery.md` runbook "Wait for
full redundancy" with `kubectl wait --for=condition=FullyReplicated`, a PromQL
example for rate and ETA, the federation note, and the release-note line about
the one-time verification after upgrade.

PromQL for rate and ETA (D5):

```promql
# blocks still queued for resync, cluster-wide
sum(block_resync_queue_length)
# resync throughput, blocks per second
sum(rate(block_resync_counter[15m]))
# rough ETA in seconds (meaningless until metadata has synced, fact 4)
sum(block_resync_queue_length) / clamp_min(sum(rate(block_resync_counter[15m])), 0.001)
```

## Deferred

- Item-count comparison hint.
- Periodic re-verification.
- Per-bucket or per-object redundancy.
- Reading the cheaper progress endpoints of newer Garage releases.
- Removing the D11 fields (next API version).

## Decisions

Decided by Raj Singh on 2026-10-06. Each entry states the chosen option; the
options that were not chosen are kept as rationale.

**D1. How many conditions?**
**Decision: (a).** One condition, `FullyReplicated`, with reasons `Verified`,
`Verifying`, `Stalled`, `BlockErrors`, `PreconditionsNotMet`, `NotObserved`.
*Not chosen:* (b) two, adding `ResyncStalled`; (c) three, adding `Resyncing`
and `ResyncStalled`.

**D2. Condition name?**
**Decision: (a).** `FullyReplicated`. *Not chosen:* (b) `FullyRedundant`;
(c) `RedundancyRestored` (reads as an event, odd on a cluster that never lost
anything).

**D3. What may set it `True`?**
**Decision: (a).** Only the active proof: layout settled, a clean full table
sync on every storage node, a clean `blocks` repair scan, and resync workers
idle through the quiet period. *Not chosen:* (b) a passive heuristic (false
`True` after data-only loss); (c) both, with two meanings for one `True`.

**D4. When does verification run?**
**Decision: (a).** Automatically on invalidating events (node identity or Pod
change, layout change, node down, new block errors, upgrade) plus the request
annotation. *Not chosen:* (b) annotation only; (c) (a) plus periodic
re-verification.

**D5. Progress, rate and ETA?**
**Decision: (a).** Per-node counters plus `lastProgressAt`; rate and ETA from
Prometheus over Garage's own metrics. *Not chosen:* (b) operator-computed rate
and ETA (misleading early, churn); (c) rate only.

**D6. Stuck detection?**
**Decision: (a).** `Stalled` when `lastProgressAt` is older than 30 min while
the proof is active, or a repair or sync worker reported errors, or the block
error count grew within the last 30 min. Fixed in code; no spec field.
*Not chosen:* (b) a `spec.redundancy.stallThreshold` field; (c) error-based
only.

**D7. Where does per-node detail live?**
**Decision: (a).** A new `GarageCluster.status.redundancy.nodes[]`
(`listType=map`, key `nodeId`), covering remote federated and StatefulSet nodes
without a `GarageNode`. *Not chosen:* (b) the never-written
`status.nodes[]`; (c) `GarageNode.status`.

**D8. Gate `Ready`?**
**Decision: (a).** No; informational only. *Not chosen:* (b) gate after the
first proof; (c) configurable.

**D9. Drains and #475 maintenance?**
**Decision: (a).** One shared proof engine (`evaluateBlockResyncProgress`).
Verification pauses (`PreconditionsNotMet`) while `status.storageDrain` or a
factor migration is active, then runs once afterwards. #475 maintenance uses
`FullyReplicated` as its next-node gate. *Not chosen:* (b) independent
engines; (c) drain completion sets `FullyReplicated=True`.

**D10. Federation scope?**
**Decision: (a).** The layout-writer site runs the proof for the whole Garage
cluster; other sites mirror progress and report `Unknown`/`PreconditionsNotMet`
pointing at the writer. *Not chosen:* (b) per-site proofs (not meaningful,
replicas span sites); (c) every site runs the full proof.

**D11. The other never-written status fields?**
**Decision: (a).** Mark them deprecated ("never populated") now, drop them in
the next API version, and populate none as part of #474: `GarageCluster`
`status.nodes[]`, `activeRepairs`, `workers`, `workerCount`, `workersFailed`,
`scrubStatus`, `lifecycleStatus`, `totalNodes`; `GarageNode`
`status.blockErrors`, `repairInProgress`, `repairType`, `repairProgress`,
`storedData`. *Not chosen:* (b) populate the overlapping ones; (c) leave them.

## Release note

> Adds the `FullyReplicated` condition and `status.redundancy` to
> `GarageCluster` (#474). After upgrading, the operator verifies every
> storage cluster once: it runs one tables repair and one blocks repair per
> storage node, at Garage's normal repair tranquility, and sets
> `FullyReplicated=True` when the proof completes. A stage is retried at most
> twice, and only if a scan reports errors or Garage restarts. After that the
> operator stops and reports `Stalled`. The condition is informational and
> does not affect `Ready`. Replacing a storage pod or restarting Garage later
> triggers one more verification.

## Implementation notes / deviations

Recorded by the implementation PR (branch `feat/474-fully-replicated`).

- **Restart detection in the metadata stage.** Besides a lower worker-ID
  maximum and a missing worker, a table sync worker whose `errors` counter is
  below its baseline also counts as a Garage restart and relaunches the tables
  repair. A restart that keeps identical worker IDs and zero counters is not
  detectable from `ListWorkers`. It is still safe: Garage starts its own full
  sync 20 s after process start (fact 3), which is shorter than the 30 s gap
  between the two clean observations the stage requires, so both observations
  cannot precede that sync. A unit test
  (`TestRedundancyGarageRestartWithIdenticalWorkersWaitsForStartupSync`) fails
  if the gap drops below 20 s.
- **Shared write helper.** The single status write moved into
  `writeComputedClusterStatus` (merge with fresh fields owned by other writers,
  plus the redundancy CAS), so the fault-injection scenario drives the same
  write path as the controller.
- **Status budget test.** `TestNodeLocalPoolProjectedSafetyStatusBudget` now
  projects `status.redundancy` with 256 nodes and checks both evidence shapes
  (metadata, blocks) against the drain transaction's 512 KiB budget, because a
  proof drops its evidence while a drain runs. The D11 fields are no longer
  projected: the operator never writes them, so they are always empty.
  Measured worst cases: blocks evidence 286 KB, metadata evidence 162 KB, full
  status with drain and redundancy 707 KB (budget 1 MiB).
- **Bounded double-fault sweep.** The proof's double-fault test limits the
  first fault to the calls and writes of the warmup and first pass, and the
  second to one retry pass, which are the only positions that can fire. The
  generic `sweepDoubleFaults` would take about 2 minutes here for the same
  coverage.
- **Bounded repairs (added for the v0.8.2 no-regression condition).** One
  proof attempt launches at most three rounds per stage: the first round plus
  two retries after a Garage restart or a scan with errors. Each round
  launches at most one repair per storage node. Evidence records
  `metadataLaunches` and `blocksLaunches` (CRD maximum 3). After the third
  round the condition is `False/Stalled` with a stable message and nothing
  more is launched until a new attempt starts: a new `verify-redundancy`
  token, a layout or membership change, or a node outage. Upgrading with
  healthy nodes runs exactly one tables repair and one blocks repair per
  storage node. Tests: `TestRedundancyRepairRoundsAreBounded` and
  `TestRedundancyMetadataRoundsAreBounded`.
- **Status-only watch filter (#482, on main since this design).** The proof's
  own status writes no longer wake the controller. While a proof runs, the
  status pass returns `RequeueAfter: redundancyActiveRequeue` (one minute)
  itself, and `TestRedundancyWatchContract` pins that a `status.redundancy`
  write does not pass the primary predicate while a new `verify-redundancy`
  token does.
- **`BlockErrors` reason message** carries the distinct block count, so it
  changes only when that count changes.
- **e2e** asserts that the storage cluster in the gateway suite reaches
  `ScanningBlocks`, `Settling` or `Verified` with every storage node observed.
  `Verified` needs the quiet period (about 11 minutes) and is not awaited.

### Work log (for interrupted sessions)

- Design record: PR #485, squash-merged as 3413331 on 2026-10-06. Decisions posted on #474.
- 2026-10-06 evening: Raj moved #474 into v0.8.2; merge on green. Branch updated by merging main (#483, #484 upgrade e2e, #487, #488, #489), with no force-push.
- Implementation: PR #486, rebased onto main with #476 (`OperatorAdminTokenReady`), #481 and #482 (status-only watch filter).
- Implementation branch: `feat/474-fully-replicated`.
- Done on the implementation branch: API types, CRDs and schemas, deprecations,
  proof engine (`garagecluster_redundancy.go`), controller wiring, unit tests
  with a Garage model, fault-injection sweeps (single, double, Garage
  restarts), envtest CRD validation, v1beta1 round trip, budget test, docs,
  e2e assertion. Full `go test` (non-e2e) and golangci-lint pass locally.
- Evening: bounded repair rounds (028b48a), fault sweeps assert Ready is untouched, PR body updated with the no-regression notes. Next: CI green, then squash-merge #486. Do not tag.
