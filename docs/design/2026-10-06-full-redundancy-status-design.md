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

## Amendment: upgrade-safe rollout (2026-10-06, after the dry-check)

The dry-check of three production federations (12 storage nodes, about
71.7 TiB, `siteRole` unset on every site, one site's disks shared with
flapping Ceph OSDs) found three blockers in the design above:

- an automatic `Initial` proof right after the upgrade, running a tables
  repair and a blocks repair on every storage node at once;
- every site acting as layout writer and repeating those repairs;
- one unreachable node blocking `Verified` forever.

This amendment replaces the sections it contradicts (the state machine, D3's
triggers, D4, D10 and the failure modes). Decisions D1, D2, D5–D8 and D11
stand. D9 is narrowed: the proof keeps the drain engine's primitives
(worker-ID baselines, exact repair-worker adoption, resync quiet period) but
not its all-nodes-at-once launcher.

### A1. No automatic proof on upgrade or first adoption

The first status pass on a layout-writer site records a **baseline** and
starts nothing. Phase `Idle`, condition `Unknown`/`NotVerified`. The baseline
is `verification.layoutVersion` plus `verification.topologyHash`. The hash
covers the ID, zone and capacity of every storage role. Its first 32 hex
characters cover the IDs alone, its last 32 the full roles.

After the baseline, a proof starts only on:

| Event | Trigger |
| --- | --- |
| a new `garage.rajsingh.info/verify-redundancy` value (also on first sight) | `Requested` |
| the set of storage node IDs changed | `NodeChanged` |
| the zone or capacity of a storage role changed | `LayoutChanged` |

These no longer start a proof:

- Pod rollouts and garage container restarts. The membership hash is gone;
  every rolling upgrade would otherwise re-verify.
- Tag-only layout changes. The operator rewrites tags, and those changes
  move no data.
- Node outages. A node that comes back does not start a proof.
- New block errors.

`Initial`, `NodeDown` and `BlockErrors` are removed from the trigger enum.

A layout with no storage roles (a new cluster before its first assignment)
has an empty `topologyHash` and is no baseline, so the first assignment is
recorded, not verified. Nodes the operator adds after that first assignment
are a real `NodeChanged`.

A storage node going down after `Verified` voids the proof without starting a
new one. The phase becomes `Idle` with `verifiedAt` kept, and the condition is
`Unknown`/`NotVerified` with a message to set the annotation.

A topology change after the baseline is a deliberate data move by the user.
Garage already resyncs during that move. The proof after it skips the tables
stage (the settled history proves the table syncs, fact 2) and runs blocks
repairs one node at a time, under A2. This is the only automatic repair
source left. If that is still too much, the fallback is annotation-only:
drop the two topology triggers and change nothing else.

### A2. One storage node at a time

The proof walks the owned storage nodes in node-ID order. Each node gets a
turn:

1. `Tables`: launch a tables repair on that node only, then wait until its
   five sync workers and its Merkle and insert queues are idle and empty,
   and stay so for 30 s.
2. `Blocks`: persist the worker-ID baseline, launch a blocks repair on that
   node only, adopt the exact post-baseline `Block repair worker`, and wait
   for it to be `Done` with 0 errors.
3. `Pause` for 2 minutes (`redundancyNodePause`).

After the pause the next node starts. Exactly one repair runs at a time.

- **Retries are bounded per stage.** A stage is relaunched after a Garage
  restart (lower worker-ID maximum, lost worker, counters going backwards), a
  lost launch, or a scan that finished with errors. After 3 launches
  (`evidence.launches`) the node is deferred as `RepairFailed` and the proof
  moves on. Only a new annotation value retries a `RepairFailed` node.
- **Settling.** When every owned node has finished, there is one cluster-wide
  quiet period over the owned nodes. Their resync workers must stay idle with
  unchanged persistent-error counters, and they must report no block errors,
  for `blockResyncQuietPeriod`. A changed counter restarts only the quiet
  period; nothing is relaunched.
- **Progress is persisted.** Everything above lives in status:
  - `verification.currentNodeId` and `verification.completedNodeIds`;
  - `evidence.nodeStage`, `stageLaunchedAt`, `workerBaseline`,
    `syncErrorBaselines`, `idleSince`, `repairWorkerId`, `launches` and
    `pauseUntil`.

  An operator restart resumes the current node's stage instead of starting
  over.
- **Preconditions pause in place.** If a precondition fails, the turn waits
  where it is and launches nothing; Garage keeps running a repair it already
  started. The preconditions are: a drain, a factor migration, an unsettled
  layout, staged changes, or layout snapshots that disagree. A drain or
  factor migration moves data, so it also drops the quiet-period baselines
  (`resyncErrorBaselines`, `quietSince`); Settling restarts its quiet period
  afterwards. This also keeps status small while `status.storageDrain` is
  large: the budget test projects 256 completed, deferred and recheck nodes
  next to a full drain.

Throttling: the operator has no rate limit of its own. Beyond the one-node
sequencing and the pause, only Garage's tranquility settings slow repairs
down. `spec.workers.resyncTranquility` (Garage `resync-tranquility`) throttles
the block resync that a blocks repair queues. The table sync and the
block-ref scan run at Garage's own pace. The docs recommend raising
`resyncTranquility` above 0 before requesting a proof on busy disks.

### A3. Only the layout-writer site, only its own nodes

- A Follower site runs no proof. It reports `Unknown`/`PreconditionsNotMet`
  and mirrors `nodes[]`, as before.
- A site is **federated** when `spec.remoteClusters` is set, or when the
  layout holds a storage role tagged `cluster-uid:` with another UID. A
  federated site whose `spec.layoutManagement.siteRole` is unset runs no
  proof. It reports `Unknown`/**`SiteRoleUnset`** with a message saying to set
  `Writer` on exactly one site and `Follower` on the others. It is not
  treated as a writer.
- The writer verifies only the storage roles it **owns**:
  - roles tagged `cluster-uid:<this UID>`;
  - on a site without `remoteClusters`, also roles with no UID tag that carry
    this cluster's `cluster:<name>/<namespace>` tag.

  Name tags are not trusted across sites, because every site may use the
  same name.
- The `Verified` message says how many storage nodes of other sites it does
  not cover. With no owned role, the proof waits on `PreconditionsNotMet`.

### A4. Unreachable nodes are deferred, not blocking

When a node's turn comes, or during its turn, it may be down in Garage's
`GetClusterStatus` or missing from `ListWorkers`/`ListBlockErrors`. It is
then skipped and listed in **`status.redundancy.deferredNodes[]`**
(`nodeId`, `reason` `Down`|`NotReporting`|`RepairFailed`, `since`,
`retryAfter`), and the next node starts.

When no node has work left and some are deferred, the phase is `Partial` and
the condition is `False`/**`Partial`**. The message lists
`k of n owned storage nodes finished` and the deferred nodes with their
reasons.

A `Down` or `NotReporting` node is retried once it is up and reporting, no
sooner than `retryAfter` (10 minutes after it was deferred), so a flapping
node gets at most one turn per 10 minutes. A completed node that goes down
during `Settling` is deferred again.

Table syncs that run while some storage node is down report sync errors
against that peer. When a peer was down during a node's tables stage
(`evidence.peerDownSeen`), errors do not fail the stage. The node is added to
`evidence.tablesRecheckNodeIds` and gets a tables-only turn once every
storage node is up and every `Down`/`NotReporting` deferred node has had its
own turn. A recheck whose sync again saw errors (a peer went down again)
keeps the node on the list. Settling, and with it `Verified`, needs no
deferred nodes and no pending rechecks.

### Status and reasons (exact)

| Phase | Condition | When |
| --- | --- | --- |
| `Idle` | `Unknown`/`NotVerified` | baseline recorded, or a node was down after the last proof |
| `Pending`, `SyncingMetadata`, `ScanningBlocks`, `Settling` | `False`/`Verifying` (or `Stalled`, `BlockErrors`) | a proof is running |
| `Partial` | `False`/`Partial` | every reachable owned node finished; some deferred or rechecks pending |
| `Verified` | `True`/`Verified`, or `False`/`BlockErrors` while block errors exist | proof complete |
| (no `verification`) | `Unknown`/`PreconditionsNotMet` | Follower site |
| (no `verification`) | `Unknown`/`SiteRoleUnset` | federated site without `siteRole` |
| any | `Unknown`/`NotObserved` | Admin API reads failed |

New API, all additive (v0.8.1 has no `status.redundancy` at all, so the whole
subtree is new in this release):

- phases `Idle` and `Partial`;
- reasons `NotVerified`, `Partial` and `SiteRoleUnset`;
- in `verification`: `topologyHash` (replaces the unreleased
  `membershipHash`), `currentNodeId` and `completedNodeIds`;
- `deferredNodes[]`;
- the per-node evidence fields listed in A2.

The unreleased all-nodes evidence fields are removed: `metadata*`,
`verificationNodeIds`, `repairBaselines`, `repairWorkerIds`,
`metadataLaunches` and `blocksLaunches`.

`Ready` and GitOps health are unchanged (D8).

### Tests for A1–A5

Each point has a unit test against the Garage model, and an envtest spec
that runs the real status pass against the API server:

- A1: the baseline starts nothing; Pod restarts and tag changes start nothing;
  the annotation and a topology change do start a proof.
- A2: at most one repair runs at a time, and in node order; a resume after
  an operator restart re-launches nothing.
- A3: a federated site without `siteRole` gets `SiteRoleUnset`; the writer
  launches only on owned nodes.
- A4: a down node is deferred, the proof reaches `Partial`, and the node is
  retried and finishes when it is back.
- A5: the docs.

## Amendment 2: opt-in topology proofs, explicit scope, follower proofs (2026-10-07, after the re-check)

bhaiya-cos re-checked #486 at 718cf24: go-with-concerns. Raj decided two
changes. This section supersedes A1 (topology triggers) and A3 (writer only,
ownership by tag) where they differ.

### B1. Automatic proofs on a topology change are opt-in (default off)

New spec field, on both `v1beta2` (hub) and `v1beta1`, identical:

```go
// LayoutManagementConfig (existing struct, spec.layoutManagement)
	// RedundancyVerification configures the FullyReplicated proof (#474).
	// +optional
	RedundancyVerification *RedundancyVerificationConfig `json:"redundancyVerification,omitempty"`

// RedundancyVerificationConfig configures when the operator proves full
// redundancy on its own. A proof always runs when the
// garage.rajsingh.info/verify-redundancy annotation gets a new value.
type RedundancyVerificationConfig struct {
	// OnTopologyChange starts a blocks-only proof, one local storage node at a
	// time, when the storage nodes, zones or capacities of the layout change
	// after the operator recorded its baseline. Off by default: proofs then run
	// only from the annotation. Ignored on a Follower site.
	// +optional
	OnTopologyChange bool `json:"onTopologyChange,omitempty"`
}
```

- Location: `spec.layoutManagement`, because the trigger is a layout change
  and the block already holds the layout policies (`autoApply`, `drain`,
  `siteRole`). `spec.workers` maps to Garage worker variables, which this is
  not.
- No `+kubebuilder:default` marker (same convention as `siteRole`): absent
  and `false` mean off, and the API server never rewrites existing objects.
- Compatibility: additive, optional, pointer struct with an omitempty bool.
  v0.8.x objects have no such field and keep the default (off).
  `v1beta1`↔`v1beta2` conversion already copies `layoutManagement` as JSON,
  so the field round-trips; a conversion test pins it. A v0.8.x operator
  running against the new CRD ignores the unknown field (structural pruning
  only drops it on write by an old client, which cannot set it anyway).
- Behavior with the flag off (default): a topology change after the baseline
  starts nothing. A `Verified`/`VerifiedLocal` proof becomes stale: phase
  `Idle`, condition `Unknown`/`NotVerified` ("the layout changed after the
  last proof"). A running requested proof is stopped the same way (its
  completed turns no longer prove the new layout) instead of being
  restarted, so no repair is repeated without a new request.
- With the flag on, on a Writer site or a non-federated cluster: as in A1, a
  blocks-only proof (triggers `NodeChanged`/`LayoutChanged`) over this site's
  local storage nodes. Followers never start a proof on their own.

### B2. Explicit scope, local nodes, follower proofs

**Local storage nodes.** A1–A4 owned roles by the `cluster-uid:` tag. That is
wrong in a writer/follower federation: the writer declares every follower
node as an external `GarageNode`, so the follower's roles carry the
*writer's* UID tag, and the writer would have repaired them. The proof now
covers only **local** storage nodes:

- Federated site (`spec.remoteClusters` set, or a storage role tagged with
  another cluster's UID): a storage role is local only if its ID is the
  discovered `status.nodeId` (or `spec.nodeId`) of a **non-external, non-
  gateway `GarageNode` of this GarageCluster** (same namespace,
  `spec.clusterRef.name` = the cluster). Those are the Garage processes
  running at this site. Tags are not used.
- Non-federated cluster: a storage role is local if it carries this
  cluster's UID tag (or, without a UID tag, its `cluster:<name>/<namespace>`
  tag) and is not an external `GarageNode` of this cluster.
- If the `GarageNode` list cannot be read, the pass is `NotObserved` and the
  previous status is kept: the proof never falls back to tags in a
  federation.
- A remote storage node is never repaired by this site.

**Scope and counts.** New `status.redundancy` fields (both versions):

```go
// RedundancyScope says which storage nodes this site's proof covers.
// +kubebuilder:validation:Enum=Cluster;Local
type RedundancyScope string

const (
	// Every storage role of the layout is local to this site.
	RedundancyScopeCluster RedundancyScope = "Cluster"
	// Other sites run some storage roles; the proof covers the local ones.
	RedundancyScopeLocal RedundancyScope = "Local"
)

// RedundancyStorageNodeCounts counts storage roles of the current layout.
type RedundancyStorageNodeCounts struct {
	// Total is the number of storage roles across all sites.
	// +kubebuilder:validation:Minimum=0
	Total int32 `json:"total"`
	// Local is the number of storage roles that run at this site.
	// +kubebuilder:validation:Minimum=0
	Local int32 `json:"local"`
	// Remote is the number of storage roles that run at other sites.
	// +kubebuilder:validation:Minimum=0
	Remote int32 `json:"remote"`
	// Verified is the number of local storage nodes the current or last
	// proof has completed.
	// +kubebuilder:validation:Minimum=0
	Verified int32 `json:"verified"`
}

// in RedundancyStatus:
	// Scope is Cluster when every storage role runs at this site, Local otherwise.
	// +optional
	Scope RedundancyScope `json:"scope,omitempty"`
	// StorageNodes counts the layout's storage roles for this site.
	// +optional
	StorageNodes *RedundancyStorageNodeCounts `json:"storageNodes,omitempty"`
```

Scope and counts are written on every observed pass of a writer or follower
(not under `SiteRoleUnset`). They change only on a layout change or a
completed turn, so they add no churn.

**Reasons.** A finished proof with scope `Cluster` is `True`/`Verified`
("Full redundancy verified on layout version N for all K storage nodes").
With scope `Local` it is `True`/**`VerifiedLocal`** with the message
"5/12 federated storage nodes verified (writer-local)" (`follower-local` on a
follower). `True` means every storage node this site runs is proven; the
reason, `scope` and `storageNodes` say that remote nodes are not. A site
cannot see another site's result, so no site reports a federation-wide
`Verified`.

**Follower proofs.** A Follower runs the same one-node-at-a-time proof
(tables, then blocks, per local node) for its own local nodes, only when
`garage.rajsingh.info/verify-redundancy` gets a new value on its own
GarageCluster. It never starts one on a topology change, and never on
upgrade. An idle follower reports `Unknown`/`NotVerified` with a message to
set the annotation on this site. `PreconditionsNotMet` is no longer used for
followers. `SiteRoleUnset` is unchanged: a federated site with `siteRole`
unset runs nothing.

### B3. Serializing proofs across sites

**Why not the layout lock.** `LayoutMutationCoordinator` is an in-process
mutex of one controller-manager. Its own doc says it is not a lock across
Kubernetes clusters, and sites share no Kubernetes API. A follower cannot
write the layout either, so layout tags cannot carry a lease. Every Garage
table (buckets, keys, admin tokens) is last-writer-wins without
compare-and-swap, and putting a lease there would create user-visible
objects. The one thing every site already reads, and that a proof changes,
is Garage's cluster-wide worker list: `ListWorkers` with `node=*` answers for
every node of the shared layout, at every site.

**Mechanism: observed repair activity, no lock holder.** A site treats
another site's proof as active while a blocks repair on a **remote** storage
node is running or has started recently:

- every pass on a federated site records, per remote storage node, the
  highest `Block repair worker` ID it has seen;
- a remote repair counts as activity when a `Block repair worker` is not
  `Done`, or a remote node's highest repair worker ID went up since the last
  pass. A lower ID is a Garage restart and only rebaselines;
- `coordination.lastRemoteRepairAt` and `lastRemoteRepairNodeId` record the
  last activity. On the first federated pass `lastRemoteRepairAt` is set to
  now, so a site watches for one hold-down before its first proof.

```go
// in RedundancyStatus:
	// Coordination is what this site last saw of other sites' repairs; it
	// serializes proofs across a federation.
	// +optional
	Coordination *RedundancyCoordinationStatus `json:"coordination,omitempty"`

// RedundancyCoordinationStatus records remote repair activity.
type RedundancyCoordinationStatus struct {
	// RemoteRepairWorkerIDs maps each remote storage node ID to the highest
	// Block repair worker ID seen on it.
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	RemoteRepairWorkerIDs map[string]uint64 `json:"remoteRepairWorkerIds,omitempty"`
	// LastRemoteRepairAt is when a blocks repair on a remote storage node was
	// last seen starting or running, or when this site started watching.
	// +optional
	LastRemoteRepairAt *metav1.Time `json:"lastRemoteRepairAt,omitempty"`
	// LastRemoteRepairNodeID is the remote node of that repair.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	// +optional
	LastRemoteRepairNodeID string `json:"lastRemoteRepairNodeId,omitempty"`
}
```

**Rules.**

- Hold-down `H` = 15 minutes on a Writer; on a Follower 15 minutes plus a
  fixed per-site offset of 1–10 minutes (from a hash of its cluster UID).
  15 minutes covers the gap between two blocks repairs of one proof (the
  tables stage, the 30 s settle gap and the 2 minute pause) for tables
  stages up to about 12 minutes.
- A site never **starts** a proof (its first node turn) until
  `now - lastRemoteRepairAt >= H`. Meanwhile the phase stays `Pending` and the
  condition is `Unknown`/**`WaitingForOtherSite`** ("a blocks repair on remote
  storage node X was seen at T; this site starts H after the last one").
- Once started, a Writer never yields. A Follower re-checks the rule before
  each node turn; a turn already launched always finishes. So if two sites
  started together, the follower yields at its next turn boundary, and two
  followers separate through their different offsets.
- Non-federated clusters skip all of this; `coordination` is absent.

**Crashed or stale holder.** No holder record exists, so nothing goes stale:
the "lock" is the repair activity itself. A crashed operator launches
nothing more. Its in-flight Garage repair finishes by itself, and the other
sites start `H` after the last activity they saw. A Garage restart on a remote
node lowers its worker IDs; that rebaselines and is not activity. A remote
node that is down reports nothing and holds nothing.

**Limits (stated in the docs).** Table repairs are not visible, because
Garage's own anti-entropy syncs look the same. Two sites whose annotations are
bumped within the same few minutes can therefore overlap for one node turn
before the follower yields. A remote proof with a tables stage longer than
about 12 minutes can let another site start in that gap. Then the same
one-turn bound applies. A manual `garage repair blocks` on a remote node
also counts as activity and delays proofs here. That is the conservative
direction.

### Status and reasons (B, exact)

| Phase | Condition | When |
| --- | --- | --- |
| `Idle` | `Unknown`/`NotVerified` | baseline; a node was down after the last proof; the layout changed with `onTopologyChange` off; an idle follower |
| `Pending` | `Unknown`/`WaitingForOtherSite` | requested, but a remote blocks repair was active within `H` |
| `Pending`…`Settling` | `False`/`Verifying` (or `Stalled`, `BlockErrors`), `Unknown`/`PreconditionsNotMet`, `Unknown`/`WaitingForOtherSite` (follower at a turn boundary) | running |
| `Partial` | `False`/`Partial` | as A4 |
| `Verified` | `True`/`Verified` (scope `Cluster`) or `True`/`VerifiedLocal` (scope `Local`); `False`/`BlockErrors` | proof complete |
| (no `verification`) | `Unknown`/`SiteRoleUnset` | federated, `siteRole` unset |
| any | `Unknown`/`NotObserved` | Admin API or GarageNode reads failed |

New API in B, all additive: `spec.layoutManagement.redundancyVerification.onTopologyChange`,
`status.redundancy.scope`, `status.redundancy.storageNodes{total,local,remote,verified}`,
`status.redundancy.coordination{remoteRepairWorkerIds,lastRemoteRepairAt,lastRemoteRepairNodeId}`,
reasons `VerifiedLocal` and `WaitingForOtherSite`.

### Tests for B

- Unit, Garage model:
  - flag off: a topology change starts nothing and staleness goes to `Idle`;
  - flag on: a topology change starts a blocks-only proof on the writer;
  - a follower ignores the flag;
  - a federated writer never touches follower nodes declared as external `GarageNode`s;
  - `VerifiedLocal` with its counts;
  - a follower runs a proof for its local nodes on request;
  - a requested site waits while a remote repair is active, then starts after `H`;
  - a follower yields at a turn boundary;
  - a remote Garage restart is not activity;
  - `SiteRoleUnset` is unchanged.
- Envtest (real status pass against the API server, GarageNode objects for locality):
  - flag default off, then on;
  - writer/follower scope and counts with `VerifiedLocal`;
  - follower proof on request;
  - waiting while a remote repair runs.
- CRD validation: scope enum, counts minimum, coordination pattern and
  limits, and the spec flag.
- Conversion: the round trip of the spec flag and the new status fields.
- Upgrade e2e: still `Idle||NotVerified` after the upgrade.
- e2e: the annotation-driven proof, with scope `Cluster` and `verified` counted.

## Release note

> Adds the `FullyReplicated` condition and `status.redundancy` to
> `GarageCluster` (#474). Upgrading starts no repairs: the operator only
> records a baseline and reports `FullyReplicated=Unknown` (`NotVerified`).
> To verify, set the `garage.rajsingh.info/verify-redundancy` annotation; the
> operator then runs one tables repair and one blocks repair per local
> storage node, one node at a time, throttled only by Garage's tranquility
> settings (raise `spec.workers.resyncTranquility` above 0 first on busy
> disks). Unreachable nodes are deferred and retried, not waited on. Proofs
> after a topology change are opt-in
> (`spec.layoutManagement.redundancyVerification.onTopologyChange`, default
> off). In a federation each site, writer or follower, verifies only its own
> storage nodes on request (`VerifiedLocal`, with `status.redundancy.scope`
> and counts), and sites wait for each other's repairs; federated sites must
> set `spec.layoutManagement.siteRole`, otherwise they report
> `SiteRoleUnset` and run nothing. The condition is informational and does
> not affect `Ready`.

## Implementation notes / deviations

Recorded by the implementation PR (branch `feat/474-fully-replicated`). The
amendment above supersedes the notes on bounded repair rounds, the
all-nodes evidence and the e2e assertion: rounds are now per node and stage
(`evidence.launches`, deferral as `RepairFailed`), and the e2e requests the
proof with the annotation. The upgrade e2e (`hack/e2e-upgrade.sh`) asserts
`Idle||NotVerified` (phase, trigger, reason) after upgrading from the
released chart.

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
- **Bounded repairs (added for the no-regression condition; superseded by the amendment).** One
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
- CI on e4d0b91: Multi-Cluster failed at `test_gateway_cleanup` (storage node dc21f2b8 never reached sync_until 4 after the gateway role removal; it was the only storage node connected to the unroutable gateway). The proof launched exactly 2 repairs per storage node (1 tables, 1 blocks) about 40 s before the gateway existed. Judged unrelated; rerunning the failed job. Upgrade E2E passed.
- 23:27 CT: merged main with #479 (9698d33), no force-push. The #486 merge is on hold for the bhaiya-cos dry-check (Ottawa, St. Pete, Robbinsdale); stagger or skip-on-upgrade may follow (Raj decides). Do not merge or tag without the go.
- 23:36 CT: bhaiya-cos dry-check verdict BLOCKERS. Reworking on the same branch per the amendment above (A1–A5). Do not merge or tag.
- 2026-10-07 00:05 CT: rework A1–A5 done on the branch (engine, API, docs, unit/envtest/fault-inject tests, e2e and upgrade-e2e assertions). Local `go test ./internal/... ./api/...` and golangci-lint pass (except the two pre-existing gofmt findings in files left untouched). Next: CI green, then report. Do not merge or tag.
- 2026-10-07 00:26 CT: Raj decided #474 is NOT in v0.8.2; it targets the next release. v0.8.2 is tagged from main by another worker: do not touch tags or main, do not merge #486. The API stays additive against the last release (v0.8.1/v0.8.2 have no `status.redundancy`); the upgrade e2e checks the upgrade from the released chart.
- 2026-10-07 01:15 CT: bhaiya-cos re-check at 718cf24: go-with-concerns. Raj decided B1 (opt-in topology proofs) and B2/B3 (explicit scope, follower proofs, cross-site serialization). Design written first (Amendment 2). Do not merge or tag.
- 2026-10-07 01:36 CT: B1–B3 implemented and pushed: design (fdc36c0), API (adfb52f), engine (5497c35), unit tests (505f4ad), envtest/CRD/conversion/budget (0fe2478), docs and e2e (e4b2f81); merged main (v0.8.2 release, #493). Locally green: `go test ./internal/... ./api/...` with envtest (23 #474/redundancy envtest specs), golangci-lint clean except the two pre-existing gofmt findings in files left alone on purpose, generators produce no diff. Correctness note for the report: under A3 the writer decided ownership by `cluster-uid:` tags, but the writer tags the follower roles it declares with its own UID, so it would have repaired follower nodes. B2 decides locality from this cluster's non-external, non-gateway GarageNodes instead (a list error means not observed, never a tag fallback). Next: PR body, CI, final API report for bhaiya-cos. Do not merge or tag.
