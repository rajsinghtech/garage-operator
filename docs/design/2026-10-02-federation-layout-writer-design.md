# Designating one layout-writer site in a federation

**Status:** Accepted — design for
[#442](https://github.com/rajsinghtech/garage-operator/issues/442). All ten
items in [Decisions](#decisions) were decided by Raj Singh on 2026-10-02
(every recommended option was accepted). The API shape (D1) and the answer to
"how do follower identities get roles" (D2) are the load-bearing ones.

## Problem

In a federated Garage deployment every site's operator is a layout writer: each
`GarageCluster` stages and applies roles for its own nodes, imports remote
roles (`addRemoteNodesToLayoutLocked`), removes departed nodes, and runs
drains, factor migrations, reverts and skip-dead-node recovery. Garage has a
single layout history shared by all sites. Garage's own federation guide says
to "choose one layout writer and serialize all other writers"; the operator
cannot be told which site that is, so with several operators active the
sites race.

The issue asks for a per-site flag under `layoutManagement` that makes a site a
**non-writer**: it still heals its own nodes (connects them, keeps workloads
running, reports status) but never stages or applies layout changes. Roles are
assigned by the designated writer site.

## What Garage guarantees (verified in the `main-v2` source)

These facts decide which designs are safe.

| Garage behavior | Consequence |
| --- | --- |
| `apply_staged_changes(version)` only checks `version == current.version + 1`, against the **local** copy of the layout | Two sites can each commit "version N+1" with different content; there is no cluster-wide compare-and-swap. |
| `LayoutHistory::merge` logs *"Inconsistent layout histories … Your cluster will be broken"* when two different version N+1 layouts meet | Concurrent writers are a data-integrity hazard, not just a nuisance. This is the failure the flag exists to prevent. |
| The staging area is `Lww<LayoutStaging>`; `Lww::merge` with a newer timestamp **replaces the whole staging area** | A site that stages even one role change can wipe staged changes another site made seconds earlier. |

Conclusion that shapes the whole design: a "follower that only *stages*, with
the writer applying" is **unsafe** (the follower's later stage clobbers the
writer's staged roles) and is rejected as an option below. A follower must
perform **zero** layout writes.

## Current code: where layout writes happen

All writes go through six `garage.Client` methods:
`UpdateClusterLayout`, `UpdateClusterLayoutWithParams`, `ApplyClusterLayout`,
`ApplyStagedLayoutChanges`, `RevertClusterLayout`, `ClusterLayoutSkipDeadNodes`.
There are 26 `garage.NewClient` construction sites, so gating at construction
is impractical. The call sites that matter:

| Area | Examples |
| --- | --- |
| Bootstrap and node assignment | `bootstrapCluster`, `assignNewNodesToLayout` |
| Federation import | `addRemoteNodesToLayoutLocked` |
| Removal / drain / scale-down | `removeNodesFromLayoutLocked`, drain barrier (`block_resync_barrier.go`) |
| Operator annotations | `handleOperationalAnnotations` (revert, skip-dead-nodes) |
| Factor migration | `garagecluster_factor_migration.go` |
| Gateway tombstones | `autoApply`-gated stage/apply of gateway role removal |
| `GarageNode` controller | several stage/apply paths |

The layout mutation coordinator (`layout_mutation_coordinator.go`, `acquire*`)
serializes writers **within one operator**; it is also used for non-write
exclusion such as pod rollouts, so the follower gate cannot live in `acquire`.
It must be at the write.

## Prior art

| Project | Shape | Notes |
| --- | --- | --- |
| CloudNativePG | `spec.replica.enabled` plus `spec.replica.primary` (name of the cluster that is primary) and `spec.replica.self`, so the same manifest set can be applied to every site and each site derives its role by comparing names. | Name-based designation; one source of truth for "who is primary", flipping it is the promotion. Closest analogue (D1 option c). |
| Rook | Object-store multisite: one zone in the realm/zonegroup is `master`; other zones pull realm state. Secondary zones cannot change realm-level config. | Master-zone designation is a property of the shared realm object, not of each site's own CR. |
| Strimzi | No multi-site metadata-writer concept (MirrorMaker is data replication). | Not comparable. |

(From each project's documentation; field names/semantics not audited in
source.)

## Decision

### API: `layoutManagement.siteRole`

```go
// LayoutSiteRole is the part this site plays in Garage layout changes.
// +kubebuilder:validation:Enum=Writer;Follower
type LayoutSiteRole string

const (
	LayoutSiteRoleWriter   LayoutSiteRole = "Writer"
	LayoutSiteRoleFollower LayoutSiteRole = "Follower"
)

// LayoutManagementConfig (v1beta2 hub and v1beta1; identical field)
type LayoutManagementConfig struct {
	// ... existing AutoApply, MinNodesHealthy, Drain unchanged ...

	// SiteRole selects whether this GarageCluster may change the shared Garage
	// layout. Absent is equivalent to Writer, the behavior of every release
	// before this field existed. A Follower never stages, applies, reverts,
	// or removes roles; it only reconciles its own workloads and reports
	// status. Exactly one site in a federation should be the Writer.
	// +optional
	SiteRole LayoutSiteRole `json:"siteRole,omitempty"`
}
```

- No CRD default: an unset field must remain byte-identical to today so
  upgrade does not rewrite stored objects, and so "unset" stays
  distinguishable from "explicitly Writer".
- The same field with the same enum is added to the **v1beta1**
  `LayoutManagementConfig`, because conversion of this struct is a JSON copy
  (`copyJSON`) in both directions; a missing mirror would silently drop the
  value on any v1beta1 write.
- Mutable. Changing the role is a deliberate operator action (promotion,
  demotion), guarded below.

### Spec-level CEL (on `GarageClusterSpec`, both versions)

```go
// +kubebuilder:validation:XValidation:rule="!has(self.layoutManagement) || !has(self.layoutManagement.siteRole) || self.layoutManagement.siteRole != 'Follower' || (has(self.remoteClusters) && size(self.remoteClusters) > 0)",message="layoutManagement.siteRole: Follower requires at least one remoteClusters entry (a Follower with nothing to follow is a cluster nobody can assign roles to)"
// +kubebuilder:validation:XValidation:rule="!has(self.layoutManagement) || !has(self.layoutManagement.siteRole) || self.layoutManagement.siteRole != 'Follower' || !has(self.connectTo)",message="layoutManagement.siteRole: Follower is not supported with connectTo; edge gateways and management handles act on their layout owner"
```

Verified: these exact rules, generated by `controller-gen` v0.22.0 into both
the v1beta2 and v1beta1 schemas, were exercised against kube-apiserver 1.36.2
(envtest). Accepted: Follower with `remoteClusters`; Writer without
`remoteClusters`; `layoutManagement` without `siteRole`; `siteRole` absent.
Rejected with the rule message: Follower without `remoteClusters`; Follower with
`connectTo`; an unknown value (`Leader`) by the enum. The same cases pass and fail
identically on v1beta1. They become part of the permanent envtest CRD suite in
the implementation PR.

### Status

```go
// LayoutWriterStatus reports this site's effective layout role.
type LayoutWriterStatus struct {
	// Role is the role the controller is currently enforcing.
	// +kubebuilder:validation:Enum=Writer;Follower
	Role LayoutSiteRole `json:"role"`

	// Phase 2 (decision D8) adds, additively and without a version bump,
	// LastAppliedVersion *int64 `json:"lastAppliedVersion,omitempty"`
	// for foreign-writer detection. It is deliberately absent from phase 1.
}

// GarageClusterStatus (both versions, beside StorageRollout):
// +optional
LayoutWriter *LayoutWriterStatus `json:"layoutWriter,omitempty"`
```

`status.layoutWriter` is a pointer so existing objects convert byte-identically
until the controller first writes it. It is mirrored on v1beta1 (status is part
of the JSON-copied conversion surface, as `storageRollout` is).

Conditions (constants in `api/v1beta1/condition_types.go`):

| Condition | When | Reasons |
| --- | --- | --- |
| `LayoutWriter` | always set once the field is in use | `True/WriterSite`; `False/FollowerSite` |
| `AwaitingLayoutWriter` | `True` on a Follower with work only a writer may do | `NodesWithoutRole`, `PendingRoleRemoval`, `PendingTombstones`, `ReplicationChange` |

On a follower, `Ready` is **not** driven false by awaiting; it is a degraded
informational state, because pods and connectivity are healthy. A node that
stays unassigned for a long time is surfaced by `AwaitingLayoutWriter` with an
event, and by the new metric below. Metrics (`internal/` metrics package):
`garage_operator_layout_write_blocked_total{cluster,operation}` and
`garage_operator_layout_site_role{cluster,role}` gauge.

### Enforcement (layered)

1. **Primary: a context guard in `garage.Client`.** The six write methods call
   `guardLayoutWrite(ctx)` first and return `ErrLayoutWritesDisabled` if the
   context carries the follower marker. The marker is set at the top of the
   `GarageCluster` and `GarageNode` `Reconcile` functions.
   - It is computed from the cluster being reconciled **and** the resolved
     canonical layout owner (`resolveGarageLayoutOwner`, which follows
     `connectTo.clusterRef` chains). If either is `Follower`, writes are
     blocked, so an edge gateway or `GarageNode` pointed at a follower owner
     cannot write through the back door.
   - No constructor changes are needed; the 26 construction sites are
     unaffected.
2. **Secondary: explicit pre-checks** in the paths that would otherwise produce
   noisy errors or half-finished state. They set `AwaitingLayoutWriter` with
   the right reason and skip the work cleanly.
3. **Static inventory test** (below): a test that fails when a new call to any
   of the six methods appears outside an allow-list, so a new feature cannot
   bypass the guard.

`ErrLayoutWritesDisabled` is mapped like `errLayoutMutationPending`: a pending
state with a normal requeue, never `Failed`, and it never removes a finalizer
or advances a state machine.

### Behavior matrix

| Operation | Writer | Follower |
| --- | --- | --- |
| Connect nodes (`ConnectNode`), reads, status, metrics | yes | **yes** |
| Pod / StatefulSet / PVC / Service reconcile, rollouts | yes | **yes** |
| Bootstrap (first layout) | yes | no; `AwaitingLayoutWriter=NodesWithoutRole` |
| Assign roles to own new nodes | yes | no; same condition |
| Federation import of remote roles | yes | no (the writer's roles arrive through Garage gossip) |
| Remove roles on scale-down / drain / delete | yes | no; waits for the writer to remove the role (`PendingRoleRemoval`); finalizer is held until the role is gone |
| Gateway tombstone removal | yes | no; recorded in `PendingGatewayTombstones`, `autoApply` is treated as off |
| `revert` / `skip-dead-nodes` annotations | yes | blocked with an event (`LayoutWriteBlocked`) |
| Factor (replication) migration | yes | the purge/scale choreography runs only on the writer; a follower reports `ReplicationChange` |
| `layoutManagement.autoApply` | honored | ignored (forced off) |

### How do follower identities get roles?

This is the real design problem. Without follower staging, something else must
tell the writer each follower node's ID, zone, capacity and tags, and today
the federation import copies roles that the *source site staged itself*.
Options (decision D2):

- **A (decided for the first slice).** The writer site declares follower
  nodes explicitly as existing `GarageNode` resources with `external: true`
  (`nodeId`, `zone`, `capacity`, `tags`). No new API. The node ID is stable
  (derived from the node key), so a user can read it once. Unambiguous, and
  fully reviewable in the writer's GitOps repo.
- **B.** A new declarative role template on `remoteClusters[]` (`roleDefaults`:
  capacity + tags) applied by the writer to RPC-connected nodes in that zone
  that have no role. Hands-off, but reverses today's explicit stance that
  `defaultCapacity` is unsupported (capacity must not be invented by the
  importing site) and gives all nodes in a zone the same capacity.
- **C. Follower stages, writer applies.** Rejected: the LWW staging area is
  replaced wholesale by the later writer (see Garage facts).
- **D. Follower only for sites whose identities are already in the layout**
  (post-bootstrap handoff). Cheapest, but cannot add a node at a follower site
  afterwards.

### Immutability and transitions

- `siteRole` is mutable; the following transitions are guarded in the webhook
  against **old status**:
  - Writer → Follower is rejected while `status.storageDrain`,
    `status.storageRollout`, or `status.factorMigration` is non-nil on this
    cluster: those are multi-step layout transactions that a follower could
    not finish.
  - Follower → Writer (promotion) is always allowed (failover must work when the
    old writer is gone) but emits a warning that the previous writer must be
    demoted first; no automatic acknowledgement protocol (D6).
  - Changing `spec.replication` (factor or `consistencyMode`) on a Follower
    produces an admission **warning** (not a rejection) to change it on the
    writer; the controller reports `AwaitingLayoutWriter/ReplicationChange`.
- Foreign-writer detection is **phase 2** (D8) and is not part of the first
  implementation. When added, the Writer records
  `status.layoutWriter.lastAppliedVersion` and a Follower raises a
  `ForeignLayoutWriter` condition if the live layout version advances without a
  known writer action — a detective control, not a lock. Adding that field is
  additive.

### Webhook vs CEL split

| Rule | CEL | Webhook | Controller |
| --- | --- | --- | --- |
| enum value | ✔ | | |
| Follower needs `remoteClusters` | ✔ | | ✔ (defensive) |
| Follower incompatible with `connectTo` | ✔ | | ✔ |
| Writer → Follower during drain/rollout/migration | | ✔ (needs old status) | ✔ (guard still blocks writes) |
| replication change on a Follower (warning only) | | ✔ (needs old spec) | ✔ |
| role enforcement | | | ✔ (guard + pre-checks) |

CEL cannot read status or the previous spec of other objects, so transition
rules live in the webhook; every CEL/webhook rule is re-checked in the
controller because webhooks can be disabled.

## Compatibility and upgrade

- Absent `siteRole` ≡ `Writer`: reconcile behavior and stored objects are
  byte-identical to today. No existing field changes.
- **Rollback hazard.** An older operator ignores `siteRole` (the schema prunes
  or preserves it) and will write to the layout again. Release notes and the
  federation how-to must say: remove follower configuration (return the site to
  Writer intent *and* confirm exactly one writer elsewhere) **before**
  downgrading the operator.
- Deferred: an edge gateway currently writes capacity-less roles into its
  owner's layout; that is a second-writer vector for a follower-owned
  layout and remains blocked by CEL (`connectTo` is incompatible with
  `Follower`) rather than redesigned.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Writer site down | Followers keep serving data; new nodes at follower sites stay `AwaitingLayoutWriter`; promote a follower by setting `Writer` (after confirming the old writer is gone). |
| Two Writers declared | Same as today (the hazard this feature mitigates, not creates); `ForeignLayoutWriter` detection is phase 2. |
| Follower scale-down | Pod can be retired only after the writer removes the role; until then the StatefulSet is held and the finalizer waits (`PendingRoleRemoval`). Same fail-closed rule as `StorageScaleDownBlocked`. |
| Guard misses a call path | The static inventory test is the control; the guard is on the client so all existing constructors are covered. |

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| `layoutManagement.nonWriter: bool` | Smallest change, but a bool cannot grow to a third role (e.g. `Observer` that also skips tombstone conflicts) without a breaking change. |
| `layoutManagement.writer: *bool` | Tri-state with ambiguous "false". |
| `layoutManagement.writerZone: string` (CNPG-style) | The same manifest applies at every site and each derives its role by comparing to its own zone; elegant for GitOps, but `spec.zone` vs `remoteClusters[].zone` naming is already confusing in this API, and a typo silently makes **no** site (or every site) the writer. |
| Follower stages, writer applies | Unsafe (LWW staging replacement). |
| Lease/lock object (Kubernetes `Lease` or Garage-side) | No shared Kubernetes API between sites; a Garage-side lock would be one more writer to coordinate. |
| Type-level refactor (`LayoutWriteLease` required to call writes) | The strongest enforcement; a large mechanical change across 26 sites. Kept as later hardening (D4). |

## Test plan

**Unit / guard**
- `httptest` server recording requests: for each of the six write methods with
  a follower context, **zero** POSTs and `errors.Is(err, ErrLayoutWritesDisabled)`;
  the same methods with a normal context behave exactly as today.
- Static inventory test (AST) listing every call site of the six methods and
  failing on additions outside an allow-list.

**Controller scenario matrix** against a recording fake admin API:
bootstrap, new node, scale-down, drain, tombstones, federation import,
revert/skip-dead annotations, factor migration, `GarageNode` deletion — each
for Writer (unchanged) and Follower (no layout writes, correct condition/
reason, finalizer held, requeue). Include the `connectTo` chain that resolves
to a follower owner.

**Webhook / CEL**: CEL cases against the real CRD in envtest (Follower without
`remoteClusters`; Follower with `connectTo`; invalid enum); webhook cases for the
transition guards using old status.

**Conversion** (`api/v1beta1`): round trip `layoutManagement.siteRole` and
`status.layoutWriter` in both directions; v1beta1 write that omits the field
does not clear it on the hub; absent stays absent (no spurious `Writer`).

**e2e** (`make test-e2e-multicluster`, two sites): the follower never issues a
layout write; the writer assigns the follower's declared roles; follower
scale-down waits for the writer; failover promotion.

## Documentation

`docs/how-to/federation.md` (designating the writer, declaring follower nodes
as external nodes on the writer, promotion/failover and the downgrade warning),
`docs/reference/custom-resources.md`, `docs/concepts/storage-and-layout.md`,
`compatibility.md`, generated CRD/Helm/schema copies.

## Deferred

- Declarative role templates (D2-B) and any capacity inference.
- `ForeignLayoutWriter` detective control (D8).
- Type-level write lease refactor.
- Edge gateways writing capacity-less roles into a follower-owned layout.

## Decisions

Decided by Raj Singh on 2026-10-02. Each entry states the chosen option; the
options that were not chosen are kept as rationale.

**D1. API shape.**
**Decision: (a).** `layoutManagement.siteRole: Writer|Follower` (enum, absent =
Writer). *Not chosen:* (b) `layoutManagement.nonWriter: bool` (the issue's wording; smaller,
cannot grow). (c) `layoutManagement.writerZone: <zone>` compared with the
site's own zone (CNPG-style; same YAML at every site, but a typo has silent
split-brain risk). (d) `layoutManagement.writer: *bool`.

**D2. How do follower node identities receive roles?**
**Decision: (a).** the writer declares them as `external` `GarageNode`s (no new
API). *Not chosen:* (b) New `remoteClusters[].roleDefaults` template applied by the writer.
(c) Follower stage-only — **rejected, unsafe**. (d) Follower only for already
assigned identities.

**D3. Follower scale-down / delete.**
**Decision: (a).** wait for the writer to remove the role; hold the finalizer
and the workload, report `PendingRoleRemoval`. *Not chosen:* (b) Let the follower pod go
immediately and leave a dead role for the writer to clean — leaves quorum
risk and an unreachable role. (c) Allow a follower to remove its own role
(violates "zero layout writes").

**D4. Enforcement layering.**
**Decision: (a).** client context guard + explicit pre-checks + static
inventory test. *Not chosen:* (b) Pre-checks only (easy to miss a path). (c) Type-level
write-lease refactor in this PR (strongest; large and risky now).

**D5. Demotion guard.**
**Decision: (a).** reject Writer → Follower while drain/rollout/factor
migration is active. *Not chosen:* (b) Allow and let the guard fail the in-flight
transaction into `Pending` forever. (c) Allow with a warning only.

**D6. Promotion acknowledgement.**
**Decision: (a).** none (promotion is a spec edit; docs say to demote the old
writer first). *Not chosen:* (b) Require an annotation naming the previous writer for
`Follower → Writer` while the old writer is reachable.

**D7. Follower without `remoteClusters`, or with `connectTo`.**
**Decision: (a).** reject both via CEL. *Not chosen:* (b) Allow and treat as permanently
awaiting.

**D8. Foreign-writer detection (`lastAppliedVersion`).**
**Decision: (a).** phase 2, after the enforcement lands. *Not chosen:* (b) Include now.
(c) Never.

**D9. `revert` and `skip-dead-nodes` annotations on a follower.**
**Decision: (a).** blocked with an event. *Not chosen:* (b) Allow (breaks the single-writer
invariant when recovery is needed — then promote that site instead).

**D10. Default.**
**Decision: (a).** absent = Writer, no CRD default (byte-identical upgrades).
*Not chosen:* (b) Default `Writer` in the CRD (rewrites stored objects on upgrade).
(c) Require the field once `remoteClusters` is non-empty (breaking).
