# Taking a node-local member's storage out of service and refilling it when members == replication factor

**Status:** Proposed, needs a direction decision. Design options for
[#475](https://github.com/rajsinghtech/garage-operator/issues/475). Nothing here
is implemented. The [Decisions](#decisions) section lists the choices Raj has
to make before the API is written down.

## Problem

Edge sites run three Kubernetes Nodes, one node-local pool, replication factor
3 and one zone. They have no spare machine. Operators regularly need to:

1. take one member's storage out of service on purpose (for example to wipe and
   repartition its disk), while the other two keep serving and the operator
   keeps managing keys and buckets;
2. bring that member back with empty storage and refill it until the same three
   machines hold full replicas;
3. reach the same end state after an unplanned disk loss;
4. know when the cluster is fully redundant again (#474, the `FullyReplicated`
   condition in `2026-10-06-full-redundancy-status-design.md`);
5. do all of this as a documented, repeatable operation that fits GitOps and
   needs no hand edits to operator-internal state or the Garage layout.

Reduced redundancy during the operation is acceptable. Losing quorum is not.
Keeping the old Garage identity is **not** required.

## Why the current paths cannot do it

| Path | Why it fails at members == RF |
| --- | --- |
| Unselect the Node (selector-driven retirement) | The normal drain path refuses with `ReplicationUnsafe` while a GarageNode exists. The process keeps running, so the disk can't be touched. If the GarageNode is already gone, #470 applies: retirement can never complete. #470 (fixed in #497, `ed43ea3`) lets reselection cancel it, which only returns to the old identity. |
| `acknowledge-lost-source` + `drain` (docs/node-local-pools.md, "Permanently lost Nodes") | Step 1 is "add replacement capacity". The administrator then runs `garage layout remove <old>`, but Garage refuses to compute a layout with fewer positive-capacity roles than the replication factor, so the removal can't be applied. |
| In-place metadata wipe (new identity on the same Node) | The operator keeps the old `status.nodeId` and fences the replacement process ("identity mismatch"). It then needs the lost-source path above, which is blocked by the same RF floor. |
| `cycle=true` | Add-before-remove. It explicitly excludes node-local members and needs spare capacity. |
| PVC lost-disk path (#349) | PVC-backed only. |

The operator already has the needed Garage primitive for gateways only. A
capacity-less identity replacement "stages one atomic Garage version that adds
the new capacity-less role and removes the old one", is persisted on the
canonical layout owner, and resumes after a restart (garagenode_controller.go,
`gatewayIdentityReplacement`). Garage documents the same move for storage:
`garage layout assign <new> --replace <old> -c <capacity> -z <zone> -t <tags>`,
a single staged change that keeps the role count at RF.

## Mechanism common to every option

Whatever API is chosen, the controller-side transaction is the same. Write it
once as a restartable state machine persisted in status. #482 applies: every
status-only transition requeues itself.

1. **Authorize.** An explicit request names the Kubernetes Node and the exact
   64-hex Garage identity to retire. The operator never infers that a disk may
   be discarded.
2. **Preconditions** (fail closed, re-checked under the canonical layout
   mutex):
   - the layout is settled (no draining versions, no staged changes);
   - every *other* positive-capacity role is up;
   - the surviving members hold write quorum for every partition;
   - no storage rollout, storage drain, or membership staging bridge is in
     flight;
   - only one replacement is active per layout owner.
3. **Take out of service (planned case only).** Fence the member's Pod: remove
   the activation label, or keep the scheduling gate closed. The claim and the
   old role stay committed. The cluster runs degraded with 2 of 3 replicas, and
   the operator keeps managing keys and buckets. With #472 (fixed in #496, `b7ec053`) the token proof
   no longer needs the stopped Pod.
4. **Wait for empty storage.** The administrator wipes or repartitions the disk
   and then lifts the hold. In the unplanned case the disk is already gone. The
   Pod starts and reports a **new** Garage ID. The existing identity-mismatch
   fence is the gate: the new ID must have no committed or staged role, the
   `.garage-volume-id` marker must be present, and the Pod's HostPath claim
   must be the same retained claim.
5. **Swap.** In one staged layout version, remove the old role and add the new
   one with the old zone, capacity and operator tags. Apply it once. Persist
   the transaction before staging so a restart resumes the same swap rather
   than staging a second one.
6. **Release the dead version.** The old layout version can't be acknowledged
   by the dead identity. The operator invokes Garage's `skip-dead-nodes` only
   when the old ID is the *only* down node in that version, and **never** with
   `allow-missing-data`. Otherwise it stops and reports.
7. **Refill and report.** Update the GarageNode (`status.nodeId`, recovery pin
   and claim `GarageNodeID`) to the new identity. Trigger a `tables` repair and
   then a `blocks` repair. Done means the #474 `FullyReplicated=True/Verified`
   condition, so a runbook or automation waits on that one signal before the
   next Node.

The invariants that keep holding:

- **One process per disk and identity.** The fence lifts only after the old
  process is gone, and the claim is never released.
- **One layout writer.** All steps run under the canonical layout mutex.
- **No silent data loss.** There is never an `allow-missing-data`, and nothing
  starts unless a quorum of survivors is up.

## Options for the user-facing API

### Option A: annotations on the generated GarageNode (operational, imperative)

```text
garage.rajsingh.info/replace-storage-in-place = <old 64-hex node ID>   # authorize + take out of service
garage.rajsingh.info/replace-storage-hold     = "true"                 # keep the Pod stopped; remove to refill
```

- **What it is:** progress is reported as a `StorageReplacement` condition on
  the GarageNode, with reasons such as `Fenced`, `WaitingForEmptyStorage`,
  `Swapping`, `Refilling`, `Completed` and `Blocked`. It follows the existing
  operational vocabulary: `drain`, `cycle`, `acknowledge-lost-source`,
  `recover-storage-rollout`.
- **Pros:** no CRD schema change. It is the smallest surface, close to
  `acknowledge-lost-source` (exact-ID and immutable-once-set webhook rules can
  be reused), and the fastest to ship.
- **Cons:** generated GarageNodes are operator-owned and aren't in Git, so it
  is **not GitOps-friendly** (requirement 5). Annotations are a weaker
  contract, with no OpenAPI or CEL and harder discovery. The new condition and
  reasons are still status API surface.

### Option B: declarative per-pool request in the GarageCluster spec (recommended)

```go
// NodeLocalPoolSpec gains:
// +optional
// +listType=map
// +listMapKey=kubernetesNodeName
// +kubebuilder:validation:MaxItems=1
StorageReplacements []NodeLocalPoolStorageReplacement `json:"storageReplacements,omitempty"`

type NodeLocalPoolStorageReplacement struct {
    // KubernetesNodeName is the pool member whose storage is replaced in place.
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=253
    KubernetesNodeName string `json:"kubernetesNodeName"`
    // ReplacesNodeID is the exact Garage identity being retired. The operator
    // acts only while this equals the member's committed role.
    // +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
    ReplacesNodeID string `json:"replacesNodeId"`
    // Hold keeps the member's Pod stopped (storage out of service) while true.
    // Set false (or omit) once the disk is ready to refill.
    // +optional
    Hold bool `json:"hold,omitempty"`
}
```

- **Status:** `status.nodeLocalPools[].storageReplacement`, which records
  `kubernetesNodeName`, `replacesNodeId`, `newNodeId`, `phase`,
  `transactionId`, the layout versions staged and applied, and timestamps.
  There is also one `NodeLocalStorageReplacement` condition. The #474
  `FullyReplicated` condition is the completion signal.
- **CEL / admission:**
  - At most one entry per pool, and one active replacement per GarageCluster
    (cross-pool CEL on `spec.storage`).
  - The entry can't be combined with other topology or runtime edits in the
    same update (same rule family as "Safe update sequencing").
  - `replacesNodeId` is immutable while the entry exists: delete it and re-add
    to retarget.
  - The webhook warns when the named Node isn't currently selected by the pool.
- **Defaults and upgrade:** the field is absent by default. v0.8.x objects
  have no entries and see no change in behavior, writes or Admin API calls. An
  old operator ignores the field: it is pruned only if the CRD isn't upgraded,
  and the chart ships CRD and operator together. Downgrade with an entry
  present is documented as unsupported mid-transaction; the persisted status
  transaction is inert to an older operator.
- **Pros:** fits GitOps, reviewable and auditable. The exact old ID in Git is
  an explicit per-identity authorization, consistent with the
  `acknowledge-lost-source` philosophy. Planned (`hold: true` first) and
  unplanned (`hold` omitted, disk already gone) cases are one API.
- **Cons:** a CRD change on `v1beta2`, more design and review work, and Git
  carries a node ID. The entry should be removed after `Completed`; if it is
  left in place it stays idempotent, because the old ID is no longer committed.

### Option C: pool policy that auto-accepts a wiped member (automatic)

```go
// NodeLocalPoolSpec gains:
// +kubebuilder:validation:Enum=Manual;InPlace
// +kubebuilder:default=Manual
IdentityReplacement NodeLocalPoolIdentityReplacement `json:"identityReplacement,omitempty"`
```

- **What it is:** with `InPlace`, a member whose Pod comes back with a new
  identity on the same Node and claim is swapped automatically once the
  preconditions hold. Taking storage out of service on purpose still needs a
  separate hold, for example the Option A hold annotation or a Node label.
- **Pros:** zero-touch across fleets. It is best for unplanned disk loss on
  many edge sites.
- **Cons:** it turns a disk that is "unexpectedly empty" into an automatic,
  irreversible layout change. An unmounted disk is mitigated by the
  `.garage-volume-id` marker, but this is still the opposite of the operator's
  explicit-acknowledgement stance for data-bearing identities. It also needs a
  second mechanism for the planned case.

## Recommendation

**Option B.** It is the only option that meets requirement 5 (GitOps,
repeatable, no internal-state edits). It keeps the per-identity acknowledgement
the operator already requires for discarding a storage identity, and it covers
the planned and unplanned cases with one entry. If something has to ship
sooner, Option A can be built on the same controller state machine and later
become an alias of Option B. Option C isn't recommended as the first step.

## Decisions

1. **API shape:** A (annotations), B (spec field), or C (policy).
   Recommended: B.
2. **Scope:** node-local pools only, or also Manual and Auto PVC-backed
   GarageNodes with the same swap. Recommended: node-local first; the state
   machine stays backend-neutral.
3. **`skip-dead-nodes` authority:** the operator invokes it automatically when
   the old ID is the only dead node and survivors hold quorum (never
   `allow-missing-data`), or it stops and asks for
   `garage.rajsingh.info/skip-dead-nodes=true`. Recommended: automatic under
   those exact checks. It is the step users currently do by hand, and gating it
   breaks requirement 5.
4. **Completion gate:** wait for #474 `FullyReplicated=True` before reporting
   `Completed`, or report `Completed` at the swap and let users watch
   `FullyReplicated`. Recommended: report `Swapped` and `Refilling`, then
   `Completed` only on `FullyReplicated=True` (depends on #486).
5. **Members > RF:** use the same in-place swap or keep add-before-remove.
   Recommended: allow in-place at any size, since it is the cheaper path, and
   document that add-before-remove keeps redundancy.

## Test plan (after the decision)

- **Unit and envtest** for every phase:
  - preconditions refused (quorum, unsettled layout, concurrent rollout or
    drain, second request);
  - the fence keeps the claim;
  - a new-ID gate where the new ID already has a role (refused);
  - the atomic swap staged exactly once across restarts;
  - `skip-dead-nodes` refused when another node is down.
- **#469 fault sweep** over the swap transaction: every Kubernetes write and
  every Admin API call (before and after commit) converges to one applied
  version and a quiet steady state.
- **e2e:** a 3-worker node-local lane with RF 3:
  1. write objects;
  2. request a replacement with `hold: true`;
  3. wipe the HostPath through a privileged debug Pod;
  4. release the hold;
  5. wait for `FullyReplicated=True`;
  6. read every object back with one of the other two Nodes stopped.
