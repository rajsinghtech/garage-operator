# VolumeAttributesClass for operator-managed PVCs

**Status:** Implemented — design for
[#445](https://github.com/rajsinghtech/garage-operator/issues/445), shipped in
[#454](https://github.com/rajsinghtech/garage-operator/pull/454). All ten
items in [Decisions](#decisions) were decided by Raj Singh on 2026-10-02 (every
recommended option was accepted). Differences between this record and the
shipped code are listed under
[Implementation notes / deviations](#implementation-notes-deviations).

## Problem

`spec.storage.{metadata,data}` lets a user pick a `StorageClass` for the PVCs
the operator generates, but not a Kubernetes `VolumeAttributesClass` (VAC).
`spec.storage.data.volumeAttributesClassName` is rejected at the API server
(`strict decoding error: unknown field`), and the only route to the PVC field,
`volumeClaimTemplateSpec`, is deliberately rejected for operator-managed
storage because an arbitrary claim template can clone a `node_key` onto the
wrong StatefulSet ordinal or bind two Garage identities to one disk (see
[volume-group data sources](2026-09-04-volume-group-data-source-design.md)).

A VAC carries mutable, driver-defined storage parameters (IOPS, throughput,
backing pool). The reporter uses one generic `StorageClass` and selects the
storage repository per volume through the VAC. Cloud users commonly want the
other half of VAC: changing IOPS/throughput **on a live volume** without
recreating the claim. Both uses are legitimate for a Garage cluster, and the
second one is incompatible with the operator's current "volume shape is
immutable while replicas are live" rule (`validateClusterVolumeUpdate`), so
the design has to decide mutability explicitly rather than copy
`storageClassName`.

## Verified Kubernetes facts

Checked against a real `kube-apiserver` v1.36.2 (the envtest version this repo
pins) with a throw-away test, and against the
[Kubernetes documentation](https://kubernetes.io/docs/concepts/storage/volume-attributes-classes/):

| Fact | Evidence |
| --- | --- |
| `VolumeAttributesClass` is GA in Kubernetes 1.34. In 1.31–1.33 it is beta and off by default. | k8s docs and the 1.34 release blog |
| A PVC may be **created** with `spec.volumeAttributesClassName` naming a class that does not exist; the API server does not check existence. | envtest: create succeeded |
| Updating `volumeAttributesClassName` on a **Pending** (unbound) PVC is rejected: `spec is immutable after creation except resources.requests and volumeAttributesClassName for bound claims`. | envtest |
| Changing it on a **Bound** PVC (A→B) is accepted and triggers CSI `ModifyVolume` through external-resizer. | envtest (API); k8s docs (behavior) |
| **Unsetting** it on a Bound PVC is accepted by the API server. | envtest. Whether the backend reverts is driver-defined; the VAC docs say omitted parameters fall back to driver defaults "depending on the CSI driver implementation". |
| Parameters of an existing VAC are immutable; to change parameters, point the PVC at another class. | k8s docs |
| `StatefulSet.spec.volumeClaimTemplates` is immutable. | existing operator behavior (`expandNodePVCs` comment) |
| The VAC `driverName` must match the StorageClass provisioner; a mismatch surfaces on the PVC (events and `status.modifyVolumeStatus`), not at admission. | Strimzi proposal discussion; k8s docs |
| On clusters where the feature is unavailable the field is dropped (create) or rejected (update, `Forbidden: update is forbidden when the VolumeAttributesClass feature gate is disabled`). | KEP-3751 |

## Prior art

| Operator | Shape | Live change? |
| --- | --- | --- |
| CloudNativePG | `spec.storage.pvcTemplate.volumeAttributesClassName` (the whole `pvcTemplate` is a PVC spec). | Yes. Fixed as a bug in [#7885](https://github.com/cloudnative-pg/cloudnative-pg/pull/7885): the operator reconciles the class onto existing PVCs, and a nil template value clears it. |
| Strimzi | Proposal [strimzi/proposals#149](https://github.com/strimzi/proposals/pull/149) and PR [#11210](https://github.com/strimzi/strimzi-kafka-operator/pull/11210) add `volumeAttributesClass` to the persistent-claim storage type. Work was deferred until the Kubernetes GA and is tracked in [#10462](https://github.com/strimzi/strimzi-kafka-operator/issues/10462). | Maintainers' stated expectation: PVCs are updated on the next reconcile. Unit test for "PVC changes on next reconciliation" requested. |
| Rook | Exposes whole `volumeClaimTemplate`s for mons/OSD device sets, so a VAC would be create-time passthrough. I did not find in-place VAC reconciliation (not exhaustively verified). | Unknown |

Take-aways: (1) CNPG and Strimzi both treat live reconciliation as part of the
feature; (2) neither validates class existence in the operator; the class/driver
mismatch is left to Kubernetes events. This design follows both.

## Decision

Add one optional string, `volumeAttributesClassName`, to every volume carrier
that already has `storageClassName` and generates a PVC. The operator copies it
onto the claim at creation and **reconciles it onto bound claims afterwards**.
The StatefulSet claim template carries the value only as a create-time hint;
the PVC is the source of truth. `volumeClaimTemplateSpec` stays rejected.

```yaml
spec:
  storage:
    replicas: 3
    metadata:
      size: 2Gi
      storageClassName: xenorchestra-shared
      volumeAttributesClassName: fast-pool-3
    data:
      size: 20Gi
      storageClassName: xenorchestra-shared
      volumeAttributesClassName: fast-pool-3
```

As with `dataSourceRef`, metadata, data, and each `data.paths[]` volume are
independent roles and each carries its own value; there is no cluster-level
shortcut that would silently apply one class to both `node_key`-bearing
metadata and block data.

## API

### Go types (v1beta2, hub)

Add the same field to `VolumeConfig` and `DataPathVolumeConfig`
(`api/v1beta2/garagecluster_types.go`). `VolumeConfig` is also the type of
`spec.gateway.metadata`, so the field appears there too (see
[Decisions](#decisions), D1).

```go
// VolumeAttributesClassName is the name of a cluster-scoped Kubernetes
// VolumeAttributesClass applied to every PVC generated for this volume role.
// The class's driver must match the StorageClass provisioner; the operator
// does not check that or whether the class exists. Valid only for
// PersistentVolumeClaim volumes. Unlike storageClassName it may be changed
// while replicas are live: the operator updates bound claims in place, which
// asks the CSI driver to modify the volume. Requires Kubernetes 1.34+ (or
// 1.31-1.33 with the VolumeAttributesClass feature enabled) and a driver that
// supports ModifyVolume. Removing a configured value from a live volume is
// rejected.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
// +optional
VolumeAttributesClassName *string `json:"volumeAttributesClassName,omitempty"`
```

Type-level CEL on both `VolumeConfig` and `DataPathVolumeConfig`:

```go
// +kubebuilder:validation:XValidation:rule="!has(self.volumeAttributesClassName) || !has(self.type) || self.type == 'PersistentVolumeClaim'",message="volumeAttributesClassName is only valid for PersistentVolumeClaim volumes"
```

Verified: the field, markers, and rule above were generated with
`controller-gen` v0.22.0 into the v1beta2 and v1beta1 CRDs and exercised on
kube-apiserver 1.36.2 (envtest). Accepted: `data` and `metadata` with a valid
class name (including a dotted DNS subdomain such as `a.b-c`) on both
versions. Rejected: `""` (MinLength), `Gold` (pattern), and
`type: EmptyDir` with a class (CEL).

`type` defaults to `PersistentVolumeClaim`, so the `!has(self.type)` branch
covers an object that has not yet been defaulted. The pattern is the
DNS-1123 subdomain Kubernetes applies to API object names. Constraints on a
**new** field cannot break an existing object, so the "no string constraints
on legacy fields" rule documented in `crd_schema_compatibility_test.go` does
not apply.

The field is a pointer so "unset" and "set" are distinguishable (a
non-pointer with `omitempty` would work too, but a pointer matches
`StorageClassName`, `DataSourceRef`, and `corev1.PersistentVolumeClaimSpec`).
There is **no CRD default**: an absent value must keep meaning "operator does
not manage this attribute", and a default would write the field into every
stored object.

### Go types (v1beta1)

`GarageCluster` v1beta1 mirrors the volume types and is converted by JSON
copy, so a field missing from v1beta1 would be dropped on every v1beta1 write
and silently remove it from the v1beta2 object. This is the same reason
`dataSourceRef` exists on the v1beta1 types. Add the identical field,
markers, and CEL rule to:

- `api/v1beta1.VolumeConfig` and `api/v1beta1.DataPathVolumeConfig`
  (`spec.storage.metadata/data/data.paths[].volume`, and
  `spec.storage.metadata` for `gateway: true`);
- `api/v1beta1.NodeVolumeConfig` (GarageNode `spec.storage.metadata`, `data`,
  and `dataPaths[]`; `GarageNode` is a single-version CRD, so no conversion
  applies to it).

`NodeVolumeConfig` needs two rules, because a node volume may also name an
existing claim, which the operator does not own:

```go
// +kubebuilder:validation:XValidation:rule="!has(self.volumeAttributesClassName) || !has(self.type) || self.type != 'EmptyDir'",message="volumeAttributesClassName is only valid for PersistentVolumeClaim volumes"
// +kubebuilder:validation:XValidation:rule="!has(self.volumeAttributesClassName) || !has(self.existingClaim) || size(self.existingClaim) == 0",message="volumeAttributesClassName cannot be combined with existingClaim: the referenced claim is user-managed"
```

`NodeVolumeConfig.type` is a two-value enum (`PersistentVolumeClaim`,
`EmptyDir`) with no CRD default, so "not `EmptyDir`" is equivalent to "PVC or
unset" and is the cheapest correct form. **These exact forms matter.** The
first draft of these rules (`self.type == '' || self.type == 'PersistentVolumeClaim'`
and `self.existingClaim == ''`) was rejected by the apiserver when the CRD was
installed: `GarageNode.spec.storage.dataPaths` has no `maxItems`, so the CEL cost
estimator multiplies the per-item rule cost by the largest possible array and
the string comparisons exceeded the budget by 1.15x. Adding `maxItems` to
`dataPaths` is not an option (a constraint on a legacy field could invalidate
existing objects), so the rules are written to be cost-minimal instead.
(`existingClaim: ""` is treated as not set.)

### Conversion

| Direction | Behavior |
| --- | --- |
| v1beta1 → v1beta2 | Automatic: volumes are JSON-copied (`copyJSON`), including the gateway-metadata path in the `Spec.Gateway` branch. |
| v1beta2 → v1beta1 | Automatic for the same reason. For a unified (storage+gateway) cluster the gateway tier travels in the existing `garage.rajsingh.info/v1beta2-gateway-tier` annotation, which already serialises the whole `GatewaySpec`; the field rides along unchanged. |
| `gatewayTierRequiresV1Beta2Payload` | Compares the projected and real `GatewaySpec` with semantic equality; because both sides now carry the field, no change is needed, but a test must prove it (a VAC-only difference must not be lost). |

No existing field changes meaning, so there are no breaking changes. An object
without the field serialises byte-identically.

### Immutability

| Carrier | Create | Update with live replicas | Update at zero replicas |
| --- | --- | --- | --- |
| `spec.storage.metadata/data/paths[].volume` | allowed | **set → set** (change): allowed. **unset → set**: allowed. **set → unset**: rejected. | any transition allowed (no claim exists to patch; same "separate update" rule as the other volume shape fields) |
| `spec.gateway.metadata` (unified, Auto) | allowed | same as above | same |
| `spec.gateway.metadata` (edge gateway) | allowed | same as above, and **must not** trigger the "metadata cannot change while edge gateway has live replicas" rule | any |
| Auto-generated child `GarageNode` | operator-written | operator may change; `GarageNodeValidator` must carve the field out of the "class … immutable" comparison | n/a |
| Manual `GarageNode` | allowed | same rules as the cluster | n/a |
| `existingClaim` volumes | rejected (CEL) | — | — |
| `EmptyDir` volumes | rejected (CEL) | — | — |
| `volumeClaimTemplateSpec` (legacy) | still rejected, including a `volumeAttributesClassName` inside it | — | — |

The three places that currently compare "volume shape" and would otherwise
reject or force a destructive recreate on a VAC edit must normalise the field
before comparing:

1. `validateClusterVolumeUpdate` (cluster) — nil the field on both shapes, for
   `VolumeConfig` and for each `paths[i].volume`; then apply the unset rule
   separately.
2. The edge-gateway rule in `validateDefaultPoolVolumeUpdate`
   (`spec.gateway.metadata cannot change while an edge gateway has live
   replicas`) — nil the field before `equality.Semantic.DeepEqual`.
3. `GarageNodeValidator` volume-immutability block ("volume source, path,
   class, access modes, and readOnly state are immutable on an existing
   GarageNode") — nil the field on both shapes.

On the controller side `gatewayVolumeClaimTemplatesChanged` must ignore the
VAC, otherwise a live class change would start the scale-to-zero,
orphan-delete, recreate sequence meant for real template changes.

### Webhook vs CEL split

| Rule | Where | Why |
| --- | --- | --- |
| name format, length, non-empty | CRD schema (`MinLength`, `MaxLength`, `Pattern`) | Must hold even when webhooks are disabled or `failurePolicy: Ignore`. |
| not with `EmptyDir`; not with `existingClaim` | CRD CEL | Local to the object. |
| unset-once-set on a live volume, change-while-live carve-outs | Admission webhook | Needs the old object and replica/placement context (`garageClusterHasManagedDefaultPool`). |
| warning when `selector` is set together with the field | Admission webhook (warning, not error) | A statically bound PV must itself carry a matching `spec.volumeAttributesClassName` or the claim will not bind. |
| class exists / driver matches StorageClass | **Not validated** (see D4) | Cluster-scoped read RBAC, racy with VAC creation order, and not validated by CNPG either. |

## Reconciliation

### Create path

Every place that builds a PVC template or PVC from a volume carrier sets
`Spec.VolumeAttributesClassName`:

- `buildNodeVolumeClaimTemplates` (GarageNode StatefulSet, via
  `buildBasePVC` callers, per metadata/data/`dataPaths[i]`);
- `buildGatewayVolumeClaimTemplates` (edge gateway);
- the PVC built from a template in `reserveManagedNodePVC` (it deep-copies the
  template, so it inherits the field with no extra code, but a test must pin
  that);
- Auto-mode child generation: the storage node builder
  (`garagecluster_automode.go`: metadata, data, and every `paths[i]`) and the
  unified-gateway node builder (`garagecluster_automode_gateway.go`), so the
  child `GarageNode` carries the value exactly as it carries `storageClassName`
  and `dataSourceRef`.

### Live path (new)

`applyAutoModeStorageNodeUpdate` and `autoModeStorageNodeNeedsUpdate` (and the
gateway counterpart) propagate the field from cluster to child in place,
beside `Size` and `StorageClassName`.

A new step in the GarageNode reconcile, **immediately after
`expandNodePVCs`** and before `reconcileStatefulSet`:

```text
reconcileNodePVCAttributes(ctx, node, cluster):
  for each managed claim (metadata, data | dataPaths[i]) with ExistingClaim == "",
      Type != EmptyDir, and a desired class:
    get PVC via the safety reader
    ensureManagedNodePVCProvenance(pvc, node, cluster)      # same gate as expandNodePVCs
    if pvc.Status.Phase != Bound:        record "waiting for bind"; continue   # API forbids update
    if pvc.Spec.VolumeAttributesClassName == desired:       continue
    patch pvc.Spec.VolumeAttributesClassName = desired      # MergeFrom patch, one field
```

Properties:

- **Patch, not Update.** A `client.MergeFrom` patch touches one field and does
  not conflict with a concurrent size expansion.
- **Idempotent and level-triggered, with a new watch.** Today the only PVC
  watch (`pvcMapper` in `garagecluster_controller.go`) enqueues the parent
  `GarageCluster`; `GarageNodeReconciler.SetupWithManager` has no PVC watch, and
  its primary watch is filtered by `GenerationChangedPredicate`. Completion or
  failure of the CSI call changes only PVC `status`, so the GarageNode
  controller gains `Watches(&corev1.PersistentVolumeClaim{}, …)` mapped through
  the `labelGarageNode` label that `buildNodeVolumeClaimTemplates`
  already stamps on every generated claim, with a
  predicate that fires only on `spec.volumeAttributesClassName`,
  `status.currentVolumeAttributesClassName`, `status.modifyVolumeStatus`, or
  `status.phase` changes. Without this watch the condition would lag by the
  periodic requeue.
- **No ordering coupling to the StatefulSet.** The claim template is
  immutable and keeps whatever value the StatefulSet was created with. It is
  only read when Kubernetes creates a claim that does not exist, and a missing
  managed claim is already refused by `validateConventionNamedNodePVCs`
  (recorded UID) — so a stale template cannot produce a wrongly-classed claim
  that is not subsequently corrected by this step.
- **Spec unset means hands off.** If the desired value is nil the operator does
  not touch `volumeAttributesClassName`, so a claim modified by an admin or by
  another tool is left alone (the webhook already forbids *removing* a value
  the operator previously applied, D3).
- **Spec set means the operator wins.** A different value found on a bound
  managed claim is overwritten, the same as CNPG.
- **Edge gateway.** A parallel `reconcileGatewayPVCAttributes` patches the
  claims of the cluster-owned gateway StatefulSet (names derive from the
  claim template and StatefulSet name, as `reconcileGatewayStatefulSet`
  already computes for its VCT checks).
- **Node-local pools** use HostPath and have no PVC; the field does not exist
  on `NodeLocalPoolSpec`.

### Failure handling

| Condition | Behavior |
| --- | --- |
| API server drops the field on create (feature off / pre-1.29) | After the claim exists, `pvc.Spec.VolumeAttributesClassName == nil` while a class is desired. Not retryable by the operator. Condition `VolumeAttributesClassApplied=False`, reason `Unsupported`; event on the GarageNode. Phase is **not** Failed and nothing is blocked. |
| API server rejects the patch (`Forbidden … feature gate is disabled`) | Same condition and reason; no requeue storm (back off to `RequeueAfterLong`). |
| Claim not bound yet | Reason `WaitingForBind`; the existing PVC watch retriggers on bind. |
| CSI reports `status.modifyVolumeStatus.status` = `InProgress` / `Pending` | Reason `ModifyInProgress`. |
| `Infeasible` (driver rejects the parameters) or class missing | Reason `Infeasible`, with the claim's `modifyVolumeStatus.targetVolumeAttributesClassName` in the message, plus a Warning event. **No automatic rollback**; Kubernetes 1.34 lets the user cancel by setting the previous class, which is a spec edit the operator then reconciles. |
| Everything matches (`status.currentVolumeAttributesClassName == desired`) | `True`, reason `Applied`. |

A VAC change **never** gates layout, scale-up/down, storage rollouts, drains,
or deletion. The value only affects backend volume performance/placement
attributes, and a driver that moves data (for example to another storage
repository) does so beneath the pod. Documentation must say that: "a
modification can briefly degrade I/O on that node; roll class changes across
nodes one at a time by editing one `GarageNode` at a time in Manual layout, or
accept that Auto changes all nodes together".

### Status and conditions

No new status fields. Conditions only:

| Resource | Type | Meaning |
| --- | --- | --- |
| `GarageNode` | `VolumeAttributesClassApplied` | `True` when every managed claim of this node with a desired class reports `status.currentVolumeAttributesClassName` equal to it. Absent when no class is desired. |
| `GarageCluster` | `StorageVolumeAttributesReady` | Aggregate over its generated `GarageNode`s (and edge gateway claims). `False` lists up to N failing node names. Informational; does **not** feed `Ready`/`Phase`. |

Condition type and reason constants go beside `ConditionGatewayTombstones` in
`api/v1beta1/condition_types.go`.

## Compatibility and upgrade

- **Existing clusters:** field absent, no behavior change, no stored-object
  change, no new RBAC (the operator already patches PVCs; the managed-PVC
  finalizer webhook only guards finalizer removal, so a class patch passes
  it).
- **CRD size:** +~1 KiB per carrier; negligible.
- **Operator rollback:** an older operator drops the unknown field when it
  reads through its older schema and ignores the claims' class. Claims already
  modified keep the class (Kubernetes owns it). Document this in the
  release notes.
- **Kubernetes support:** the existing floor (1.25+) is unchanged. The field
  is documented as requiring 1.34+, or 1.31–1.33 with the feature and the
  `storage.k8s.io/v1beta1` API enabled, and a CSI driver implementing
  ModifyVolume. The operator does not probe the server version; the
  `Unsupported` condition above is the runtime signal.
- **Adopting existing PVCs:** setting the field on a cluster whose claims
  already exist modifies those claims on the next reconcile. That is the
  intended behavior and the main reason it is a spec field rather than an
  annotation; document it prominently.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Allow `volumeClaimTemplateSpec` | Re-opens the identity-isolation hole closed by the existing webhook; also an immutable StatefulSet template cannot express live changes. |
| Create-time only (immutable) | Simple and consistent with `storageClassName`, but it removes the main value of VAC (live tuning) and forces drain-and-recreate to change IOPS. Offered as the conservative option in D2. |
| One cluster-level `spec.storage.volumeAttributesClassName` | Applies one class to `node_key` metadata and block data alike; contradicts the per-role model used for `dataSourceRef`. |
| Annotation on the cluster | Not discoverable, not schema-validated, and not carried by Auto-mode child generation. |

## Test plan

**Unit (`api/...`, `internal/controller/...`)**

- Webhook table (v1beta2 and v1beta1): accepted on metadata/data/paths/gateway
  metadata; rejected for EmptyDir, `existingClaim`, malformed names, and inside
  `volumeClaimTemplateSpec`; live change allowed; live unset rejected; zero
  replicas allows any transition; edge-gateway live change not blocked;
  `selector` produces a warning.
- `GarageNodeValidator`: VAC carved out of the immutability comparison; the
  neighboring fields (class, access modes, selector) still rejected.
- Builders: PVC template, reservation PVC, gateway template, Auto-mode
  cluster→child copy for metadata, data, paths, and unified gateway;
  `applyAutoModeStorageNodeUpdate`/`NeedsUpdate` propagate the change.
- `reconcileNodePVCAttributes` with a fake client: patches only bound,
  provenance-verified claims; skips Pending; leaves claims alone when the spec
  is unset; overwrites drift when set; surfaces each condition reason.
- `gatewayVolumeClaimTemplatesChanged` ignores the field.

**Conversion (`api/v1beta1/garagecluster_conversion_test.go`)** — round trips
in the style of `TestConvert_DataSourceRefRoundTrip`:

- v1beta1 → hub → v1beta1 for metadata, data, `paths[].volume`, and gateway
  (`gateway: true`) metadata;
- hub → v1beta1 → hub for a unified cluster whose **only** gateway difference
  is the VAC (proves the gateway payload annotation carries it);
- hub → v1beta1 → hub preserves absence (nil stays nil).

**CRD/CEL (envtest, Kubernetes 1.36.2)** — create objects asserting the
pattern, length, non-empty, EmptyDir and existingClaim rules reject at the API
server with webhooks absent. I ran this exact set against a prototype CRD
generated by `controller-gen v0.22.0` while preparing this record
(`vac + emptydir`, `vac bad name`, `vac empty` rejected; `vac ok` accepted).

**envtest (API semantics):** create PVC with a nonexistent class (accepted);
patch while Pending (forbidden); bind by setting `volumeName` and
`status.phase`, then patch (accepted). Documents the assumptions the
controller relies on.

**e2e** (`test/e2e`, label `volume-attributes-class`, skipped when the kind
API server is older than 1.34 or the CSI driver lacks ModifyVolume):
create → class applied on the claim; live change → claim and
`currentVolumeAttributesClassName` converge; unsupported driver →
`VolumeAttributesClassApplied=False`/`Infeasible` without blocking layout.

## Documentation

- `docs/reference/custom-resources.md`: field, constraints, mutability table.
- `docs/reference/compatibility.md`: Kubernetes/CSI requirements.
- `docs/how-to/configuration.md`: worked example including a
  `VolumeAttributesClass`, and the live-change warning.
- `docs/concepts/storage-and-layout.md`: one paragraph on why
  `volumeClaimTemplateSpec` remains unsupported and VAC is the safe route.
- Generated: `make manifests generate`, Helm CRD copies, `schemas/*.json`.
- Release note: rollback behavior, "adopting existing claims modifies them".

## Deferred

- Operator-side validation that the class exists and its `driverName` matches
  the StorageClass provisioner (read-only RBAC on `volumeattributesclasses`).
- Per-ordinal classes (silent wrong-disk assignment risk, same reasoning as
  `dataSourceRef`).
- Node-local pools (HostPath; no PVC).

## Decisions

Decided by Raj Singh on 2026-10-02. Each entry states the chosen option; the
options that were not chosen are kept as rationale.

**D1. Which volume carriers get the field?**
**Decision: (a).** every carrier that already has `storageClassName`:
cluster `metadata`, `data`, `data.paths[].volume`, `gateway.metadata`, and
GarageNode volumes. `VolumeConfig` is shared, so the CRD exposes it on
gateway metadata regardless; supporting it is cheaper than rejecting it and
keeps one rule. *Not chosen:* (b) Storage `metadata`/`data` and GarageNode only; reject on
gateway metadata and `paths[]` in the webhook (smaller first release, two
extra rejection rules and a follow-up). (c) `data` only.

**D2. May the class change while replicas are live?**
**Decision: (a).** yes; the operator patches bound claims in place (the point
of VAC; CNPG behavior). *Not chosen:* (b) No: create-time only, like `storageClassName`;
changing it requires draining the group to zero. Choosing (b) removes the live
path, the carve-outs, and most conditions, but also the main user benefit.

**D3. What happens when the field is removed from a live volume?**
**Decision: (a).** webhook rejects, with a message telling the user to set an
explicit "default" class. The API server accepts the unset (verified), but the
backend does not necessarily revert, so allowing it would leave the spec
saying "no class" while the volume keeps the old parameters. *Not chosen:* (b) Allow; the
operator then stops managing the field and the claim keeps the last class.
(c) Allow and patch the claim to nil.

**D4. Should the operator check that the class exists and matches the
StorageClass driver?**
**Decision: (a).** no; surface the failure from the claim's
`modifyVolumeStatus` and events. No new RBAC, no creation-order race.
*Not chosen:* (b) Read-only preflight producing a Warning condition (needs a ClusterRole rule
for `storage.k8s.io/volumeattributesclasses` get/list). (c) Hard admission
rejection when absent (couples GitOps apply order and fails closed on a
transient cache miss).

**D5. How is progress reported?**
**Decision: (a).** conditions on `GarageNode` and an aggregate on
`GarageCluster`, as above. *Not chosen:* (b) Events only. (c) A per-claim list in
`GarageNode.status` (more detail, new status schema, more churn).

**D6. Field name.**
**Decision: (a).** `volumeAttributesClassName`, identical to
`corev1.PersistentVolumeClaimSpec` and the name in the issue and in CNPG's
template. *Not chosen:* (b) `volumeAttributesClass`, the name in Strimzi's proposal (shorter
but diverges from the core field).

**D7. Is a v1beta1 mirror added?**
**Decision: (a).** yes; unavoidable with JSON-copy conversion unless a v1beta1
write is allowed to erase the field. *Not chosen:* (b) Carry it through a transport
annotation (the node-local-pool pattern); heavier and unnecessary for a
one-string field.

**D8. Behavior in Manual layout.**
**Decision: (a).** cluster-level volumes are ignored in Manual mode (existing
rule), and each `GarageNode` carries its own value, so users can roll a class
change one node at a time. *Not chosen:* (b) Also allow a cluster-level default that Manual
nodes inherit (contradicts the existing "Manual nodes do not inherit cluster
volume sources" rule).

**D9. Kubernetes version handling.**
**Decision: (a).** document the requirement and report runtime failure through
the `Unsupported` reason. *Not chosen:* (b) Discover the server version at startup and have
the webhook reject the field below 1.34 (fails closed, but wrong for 1.31–1.33
clusters that enabled the beta, and adds a discovery dependency).

**D10. Scope of the first implementation PR.**
**Decision: (a).** one PR containing types, CRDs, v1beta1 mirror, webhooks,
create path, live path, conditions, docs, and unit/envtest tests; the e2e
scenario in a second PR once a ModifyVolume-capable CSI driver is wired into
kind. *Not chosen:* (b) Split create-only first and the live path second (keeps each diff
small, but ships a field that behaves differently across releases).

## Implementation notes / deviations

Shipped in [#454](https://github.com/rajsinghtech/garage-operator/pull/454)
(merge commit `592082b`). The API (types, markers, CEL on `VolumeConfig` and
`DataPathVolumeConfig`), conversion, immutability rules, live in-place patching,
conditions and reasons (`Applied`, `WaitingForBind`, `ModifyInProgress`,
`Infeasible`, `Unsupported`) and the GarageNode PVC watch match this record.
Where the code differs from the text above, the code is authoritative:

1. **No Kubernetes Events.** The record mentions an event on the GarageNode and
   a Warning on `Infeasible`. The operator had no `EventRecorder` or `events`
   RBAC when this shipped, and the record says "no new RBAC", so conditions and
   log lines carry the signal. (An `EventRecorder` was added later by #453 for
   the layout-writer feature; wiring VAC events onto it is a follow-up.)
2. **Per-claim backoff on `Unsupported`.** An in-memory per-PVC-UID backoff
   (`RequeueAfterLong`, 5 minutes) means an API server that rejects the field is
   probed about every 5 minutes instead of on every reconcile.
3. **`data.paths[]` do not inherit the top-level `data` class** (same reasoning
   as `dataSourceRef`). A top-level class next to `paths` produces an admission
   **warning**; this warning is an addition to the record.
4. **Extra webhook checks.** The webhooks also reject `EmptyDir` and
   `existingClaim` combined with a class (defence in depth beyond the CEL rules).
5. **v1beta1 edge-gateway unset rule.** `validateV1Beta1ClusterVolumeUpdate` is
   not invoked for gateway clusters, so the "unsetting a configured class is
   rejected" rule is applied explicitly on that path.
6. **No e2e scenario.** As decided (D10), the e2e scenario waits for a
   ModifyVolume-capable CSI driver on kind. Coverage is unit tests, fake-client
   reconciles for every condition reason, and envtest on kube-apiserver 1.36.2
   (CRD pattern/length/CEL for v1beta2 `GarageCluster` and `GarageNode`, plus a
   v1beta1-only API server for the v1beta1 schema, which also proves the CEL cost
   budget).

Rollback and requirements are as designed: an older operator ignores the field
and already-modified claims keep their class; setting the field on a cluster
whose claims already exist modifies those claims on the next reconcile.
