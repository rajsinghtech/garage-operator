# Init containers, extra containers, and extra volumes on Garage pods

**Status:** Implemented — design for
[#441](https://github.com/rajsinghtech/garage-operator/issues/441), shipped in
[#452](https://github.com/rajsinghtech/garage-operator/pull/452). All eleven
items in [Decisions](#decisions) were decided by Raj Singh on 2026-10-02 (every
recommended option was accepted). Differences between this record and the
shipped code are listed under
[Implementation notes / deviations](#implementation-notes-deviations).

## Problem

`buildGaragePodSpec` (`internal/controller/helpers.go`) builds a pod with exactly
one container. Neither the `GarageCluster` pod template, `GarageNode`, nor a
node-local pool can add a companion process. The issue's examples share the
Garage pod's network namespace: a sidecar that configures a secondary
interface and a dynamic-DNS updater for the node's public address. Others
(log shippers, a config-fetching init step, a metrics exporter) have the same
shape. Today those deployments cannot use an operator-managed storage tier.

The risk is not privilege: `spec.image`, `env`, `serviceAccountName` and
`podTemplate.securityContext` already let the `GarageCluster` author run
an arbitrary image in the namespace. The risk is **data and identity safety**:

- the metadata volume holds `node_key`, the node's private identity;
- the operator-owned volumes and Secrets (config, metadata, data, RPC secret,
  admin and metrics tokens) are rendered, hashed, and rotated by the operator;
- the operator patches the pod's `initContainers` itself during
  replication-factor migration (`purge-cluster-layout`);
- pod-template changes roll storage pods through the OnDelete/StorageRollout
  sequencer, so a bad extra can stall a rollout.

## Evidence that shapes the design: CRD size

The `GarageCluster` CRD is already **1,034,098 bytes** (the committed file is
1,034,475). Kubernetes stores CRDs in etcd, whose default request limit is
1.5 MiB, and client-side `kubectl apply` already cannot work (the
`last-applied` annotation limit is 256 KiB), so installs rely on
server-side apply or create.

I measured the alternatives by running `controller-gen v0.22.0` on a scratch
copy of the types:

| Schema strategy for `initContainers` + `extraContainers` + `extraVolumes` | `garageclusters.yaml` |
| --- | --- |
| Baseline (current `main`) | 1,034,098 B |
| Fully typed `[]corev1.Container` / `[]corev1.Volume` in `PodTemplate` (storage, gateway) and the node-local pool template, v1beta2 only | **2,128,474 B** (+1.09 MB, over the etcd limit) |
| Fully typed, only `initContainers` + `extraVolumes`, `PodTemplate` only | 1,519,826 B (still dangerously close, and no room for v1beta1, pools, or GarageNode) |
| **Schema-light wrapper (this design)**, all three lists, all three locations | **1,055,206 B (+21 KB, +2.0%)** (includes the `volumeAttributesClassName` fields and every CEL rule from all three designs) |

A full `corev1.Container` schema is ~120 KB per occurrence and `corev1.Volume`
about as much, each repeated in every template location and in v1beta1.
`GarageNode` (191 KB today) would grow similarly. Fully typed passthrough, the
obvious choice (and what Prometheus Operator does, with a CRD it also ships
via server-side apply), is therefore not available here. That decision is
captured as D2.

## Prior art

| Operator | Shape | Notes |
| --- | --- | --- |
| Prometheus Operator | `spec.containers`, `spec.initContainers` (`[]corev1.Container`), `spec.volumes`, `spec.volumeMounts` (appended to the main container only). A container with an operator-reserved name is **strategic-merge-patched** onto the generated one (`MergePatchContainers`); documented as unsupported and "may break at any time". | Merge-by-name is deliberately avoided here: patching the Garage container would bypass reserved env, mounts, and the config-path invariant. |
| Zalando postgres-operator | `sidecars`, `initContainers` (full `v1.Container`), `additionalVolumes[]` with `targetContainers` and a `volumeSource`; operator-level `enable_sidecars` / `enable_init_containers` switches; a `validateContainers` check. | Source of the "global off switch" idea (D10) and per-volume target containers (not adopted: mounts stay on the container, which keeps the API standard Kubernetes). |
| Strimzi | `template.pod.volumes`/`additionalVolumes` plus per-container `volumeMounts` on named templates (`kafkaContainer`, `initContainer`), `template.pod.*` for scheduling. No free-form sidecars. | Closest to "volumes and mounts as separate lists". |
| CloudNativePG | No free-form sidecars in `Cluster`; extension points are the CNPG-I plugin interface (plugins can inject sidecars), `projectedVolumeTemplate`, `ephemeralVolumeSource`. | Shows the cost of staying closed: a whole plugin API. |
| Rook | No pod container passthrough on `CephCluster` daemons (placement, resources, annotations, labels, priority class only). | Same: closed API. |

(Comparisons are from each project's documentation as searched during this
design; I did not audit their source for undocumented fields.)

## Decision

Add three optional lists, named as in the issue, to every pod template the
operator renders from user input:

```yaml
spec:
  storage:
    initContainers:
      - name: wait-for-vip
        image: busybox:1.37
        command: ["sh", "-c", "until ip addr show net1; do sleep 1; done"]
    extraContainers:
      - name: ddns
        image: ghcr.io/example/ddns:1.2
        env: [{name: HOSTNAME, value: node.example.net}]
        volumeMounts: [{name: ddns-state, mountPath: /var/lib/ddns}]
    extraVolumes:
      - name: ddns-state
        emptyDir: {}
```

- `initContainers` run after the operator's own init containers, in listed
  order. An entry with `restartPolicy: Always` is a native sidecar.
- `extraContainers` are appended after the `garage` container; `garage` stays
  `containers[0]`.
- `extraVolumes` are added to `pod.spec.volumes`.
- The `garage` container, its environment, ports, probes, and every
  operator-owned volume and Secret stay exclusively operator-owned.
- A change rolls pods like any other pod-template change: it feeds
  `computePodSpecHash`, so the OnDelete StatefulSet/DaemonSet and the
  `StorageRollout` sequencer replace one identity at a time.

### Where the lists live

| Location | Fields | Applies to |
| --- | --- | --- |
| `spec.storage` (via embedded `PodTemplate`) | all three | the default StatefulSet/PVC group: every Auto-generated storage `GarageNode` |
| `spec.gateway` (via embedded `PodTemplate`) | all three | unified gateway `GarageNode`s and the edge gateway StatefulSet |
| `spec.storage.nodeLocalPools[].podTemplate` | all three | that pool's DaemonSet |
| `GarageNode.spec` | all three | that node's StatefulSet; overrides the tier value |

`PodTemplate` is embedded in both `StorageSpec` and `GatewaySpec`, so adding
the fields there covers both tiers with no duplicated type. The issue asked for
storage pods; the gateway tier is a consequence of the shared type and is
decision D1.

### Go types (v1beta2, hub)

Wrapper types (new file `api/v1beta2/pod_extras.go`):

```go
// PodExtraContainer is one user-supplied container. The CRD schema declares
// only name and preserves all other fields; the complete object is validated
// by the admission webhook and re-validated by the controller by strictly
// decoding it into a corev1.Container (Resolve). This keeps the CRD small:
// a fully typed corev1.Container would add ~120 KB per occurrence.
//
// +kubebuilder:pruning:PreserveUnknownFields
// +kubebuilder:object:generate=false
type PodExtraContainer struct {
	// Name of the container. It must be unique across initContainers and
	// extraContainers, a DNS-1123 label, and not an operator-reserved name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	Name string `json:"name"`

	Raw json.RawMessage `json:"-"` // the complete JSON object as submitted; never part of the schema (exported, see Implementation notes)
}

// PodExtraVolume is one user-supplied pod volume; same contract as
// PodExtraContainer, resolved as a corev1.Volume.
//
// +kubebuilder:pruning:PreserveUnknownFields
// +kubebuilder:object:generate=false
type PodExtraVolume struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	Name string `json:"name"`

	Raw json.RawMessage `json:"-"`
}
```

Hand-written (not generated) members, because `Name` and the raw payload must stay
in sync (the shipped code exports the payload as `Raw`; see Implementation notes):

```go
func NewPodExtraContainer(c corev1.Container) PodExtraContainer      // marshals c
func (c PodExtraContainer) MarshalJSON() ([]byte, error)             // returns raw
func (c *PodExtraContainer) UnmarshalJSON(b []byte) error            // LENIENT: keeps raw, sets Name
func (c PodExtraContainer) Resolve() (corev1.Container, error)       // STRICT: sigs.k8s.io/json UnmarshalStrict; unknown/duplicate fields (its []error result) are joined into the returned error
func (c *PodExtraContainer) DeepCopyInto(out *PodExtraContainer)     // copies raw
func (c *PodExtraContainer) DeepCopy() *PodExtraContainer
// the same five for PodExtraVolume / corev1.Volume
```

`UnmarshalJSON` is intentionally lenient. If it were strict, one object whose
fields do not parse (written while webhooks were off, or by a future version)
would fail the informer's decode and could stall list/watch for every
`GarageCluster`. Strictness is applied at `Resolve`, which happens in
admission and again in the controller before rendering.

`PodTemplate` and `NodeLocalPoolPodTemplate` gain (identical markers on both):

```go
// InitContainers run before the Garage container, after any operator-injected
// init containers. Entries with restartPolicy: Always are native sidecars
// (Kubernetes 1.29+ beta, GA in 1.33). Names garage, purge-cluster-layout and
// the prefix garage-operator- are reserved.
// +kubebuilder:validation:MaxItems=16
// +kubebuilder:validation:XValidation:rule="self.all(c, c.name != 'garage' && c.name != 'purge-cluster-layout' && !c.name.startsWith('garage-operator-'))",message="container name is operator-reserved"
// +listType=map
// +listMapKey=name
// +optional
InitContainers []PodExtraContainer `json:"initContainers,omitempty"`

// ExtraContainers run beside the Garage container in the same pod and network
// namespace. They cannot mount operator-owned volumes.
// +kubebuilder:validation:MaxItems=16
// +kubebuilder:validation:XValidation:rule="self.all(c, c.name != 'garage' && c.name != 'purge-cluster-layout' && !c.name.startsWith('garage-operator-'))",message="container name is operator-reserved"
// +listType=map
// +listMapKey=name
// +optional
ExtraContainers []PodExtraContainer `json:"extraContainers,omitempty"`

// ExtraVolumes are added to the pod. Operator-owned volume names are reserved
// (config, metadata, data, data-<N>, rpc-secret, admin-token, metrics-token).
// +kubebuilder:validation:MaxItems=32
// +kubebuilder:validation:XValidation:rule="self.all(v, !(v.name in ['config','metadata','data','rpc-secret','admin-token','metrics-token']) && !v.name.matches('^data-[0-9]+$'))",message="volume name is operator-reserved"
// +listType=map
// +listMapKey=name
// +optional
ExtraVolumes []PodExtraVolume `json:"extraVolumes,omitempty"`
```

and, on both `PodTemplate` and `NodeLocalPoolPodTemplate`:

```go
// +kubebuilder:validation:XValidation:rule="!has(self.initContainers) || !has(self.extraContainers) || !self.initContainers.exists(i, self.extraContainers.exists(e, e.name == i.name))",message="initContainers and extraContainers names must be unique across both lists"
```

The reserved lists in CEL are the **fast, webhook-independent** guard; the
authoritative collision check is computed from the pod the builder actually
produced (see [Reconciliation](#reconciliation)), so the static lists cannot
drift from the builder.

### Prototype evidence for the schema

The final Go types and markers in this record were built in a scratch copy of
the repository (`controller-gen` v0.22.0 generating both the deepcopy code and
the CRDs, `go build ./api/...`) and every row below was exercised against a real
`kube-apiserver` v1.36.2 (envtest), on the v1beta2 hub, the v1beta1 spec, and
`GarageNode`:

| Input | Result |
| --- | --- |
| all three lists on `spec.storage`, `spec.gateway`, v1beta1 `spec`, `GarageNode.spec` | accepted |
| container with an unknown field (`bogusField`) | **accepted** by the API server (preserved) — so content validation must be the webhook's and the controller's job |
| container named `garage`; or prefix `garage-operator-`; or `Bad_Name` | rejected (CEL / pattern), on every location |
| duplicate `name` within one list | rejected (`listType=map`: `Duplicate value`) |
| same `name` in `initContainers` and `extraContainers` | rejected (type-level CEL on `PodTemplate`, for storage **and** gateway; on v1beta1 `spec`; on `GarageNodeSpec`) |
| volume named `metadata`, `data-3` | rejected; `data-x` accepted |
| 17 containers | rejected (`MaxItems`) |
| CRD structurally valid; CEL cost within the apiserver budget | yes (the CRDs installed) |

Two implementation constraints this surfaced:

1. **Do not put `+kubebuilder:validation:Type=object` on the wrapper types.**
   With it, `controller-gen` emits `type: object` and drops `properties`, so
   `x-kubernetes-list-map-keys: [name]` is invalid and the apiserver rejects the
   whole CRD ("entries must all be names of item properties"). Without it the
   schema is `properties.name` (required, length and pattern) plus
   `x-kubernetes-preserve-unknown-fields: true`, which is what the markers
   below produce. The raw-payload field needs a `json:"-"` tag or
   `controller-gen` fails ("struct field without JSON tag"); as shipped it is the
   exported `Raw` (see Implementation notes).
2. `v1beta1` already imports `v1beta2` for conversion, so v1beta1
   `GarageClusterSpec` and `GarageNodeSpec` reuse the v1beta2 wrapper types
   directly; no duplicate type is needed.

A scratch unit test also confirmed the wrapper contract: an unknown field
survives `json.Unmarshal` → `json.Marshal` (lenient), `Resolve()` rejects it
(strict), `DeepCopy` does not alias the raw payload, and `NewPodExtraContainer` →
`Resolve()` round-trips.

A type-level `XValidation` on the **embedded** `PodTemplate` is emitted once
per embedding (storage and gateway), which is why one rule on `PodTemplate`
suffices; `NodeLocalPoolPodTemplate` is not built on it and needs its own.

### Go types (v1beta1)

`GarageCluster` v1beta1 has no pod template: scheduling fields are top-level
and map into the active tier's `PodTemplate` in `ConvertTo`/`ConvertFrom`.
A field missing on v1beta1 would be erased by any v1beta1 write (the hub is
rebuilt from the v1beta1 object), so the three lists need a v1beta1 home
(D4). With the schema-light wrapper a typed mirror costs ~2 KB:

```go
// v1beta1.GarageClusterSpec — beside PodAnnotations/PodLabels
InitContainers  []v1beta2.PodExtraContainer `json:"initContainers,omitempty"`
ExtraContainers []v1beta2.PodExtraContainer `json:"extraContainers,omitempty"`
ExtraVolumes    []v1beta2.PodExtraVolume    `json:"extraVolumes,omitempty"`
```

(same markers; the CEL rules above, which only reference those fields, are
copied to the v1beta1 `GarageClusterSpec`). `GarageNode` is single-version
(v1beta1) and gains the same three fields in its "Pod Configuration Overrides"
section with the same markers.

Conversion mapping, extending the existing `podTemplate` literal:

| v1beta1 | v1beta2 |
| --- | --- |
| `spec.{initContainers,extraContainers,extraVolumes}` with `gateway: false` | `spec.storage.{…}` |
| same with `gateway: true` (edge) | `spec.gateway.{…}` |
| unified (storage + gateway) hub → v1beta1 | storage lists go to the top-level fields; the gateway tier's lists ride in the existing `v1beta2-gateway-tier` annotation payload (already the whole `GatewaySpec`) |
| node-local pools | unchanged: pools are transported whole in `v1beta2-node-local-pools`; the new fields are part of `NodeLocalPoolPodTemplate` and serialise through the wrapper's `MarshalJSON` |

`gatewayTierRequiresV1Beta2Payload` builds a "projected" `GatewaySpec` from the
v1beta1 view to decide whether the annotation is needed; its `PodTemplate`
literal must carry the three new fields or an edge gateway that uses them would
be treated as representable and lose them.

### Immutability and defaulting

- No CRD defaults. Absent and empty both mean "none".
- All three lists are **mutable** at any time (they are pod-template inputs,
  like `env`). The effect is a rolling replacement, never an in-place edit of a
  running pod.
- Extras never influence identity: they do not appear in `ownerReferences`,
  PVC templates, StatefulSet selectors, labels, or the layout tags.

### Webhook validation (v1beta2 and v1beta1, on create and update)

Implemented in `api/v1beta2/garagecluster_webhook.go`,
`api/v1beta1/garagecluster_webhook.go`, and `api/v1beta1/garagenode_webhook.go`
(a shared validator in `api/v1beta2`). Run for `spec.storage`, `spec.gateway`, each `nodeLocalPools[].podTemplate`
(v1beta2), top-level fields (v1beta1), and `GarageNode.spec`. Errors name the
field path and the list index.

1. **Strict decode.** Every item must `Resolve()` with unknown fields rejected,
   so a typo such as `volumeMount:` is an error, not a silently dropped field
   (the API server preserves unknown fields, see above).
2. **Names.** Unique across `initContainers ∪ extraContainers`; DNS-1123
   label; none of `garage`, `purge-cluster-layout`, or the `garage-operator-`
   prefix. Volume names unique, DNS-1123 label, and not in the reserved set.
3. **Container shape.**
   - `image` non-empty.
   - `initContainers[].restartPolicy` is unset or `Always`; `extraContainers[]`
     must not set `restartPolicy` (Kubernetes rejects it on regular
     containers).
   - `volumeDevices` rejected (block devices are not in scope).
   - `ports[].containerPort` must not collide with Garage's configured
     S3/RPC/web/admin/K2V listen ports for this cluster (all containers share
     one network namespace; Kubernetes does not check this).
   - `ports[].hostPort` rejected in v1 (simplest; relax on request).
4. **Volume references.** Every `volumeMounts[].name` must name an entry in the
   same effective `extraVolumes` set (cluster list for tier/pool templates;
   cluster tier list overlaid by the node list for a `GarageNode`, validated
   best-effort in the node webhook through the API reader and authoritatively in
   the controller). A mount of a reserved volume name is rejected with a
   message that the metadata volume contains the node's private key.
5. **Volume sources.** Exactly one source (Kubernetes enforces it at pod
   admission; reject early). A `persistentVolumeClaim` source whose
   `claimName` is a claim managed by this operator is rejected by the
   controller (exact check against the managed-PVC labels/annotations), because
   a second writer on `metadata`/`data` is the failure this design exists to
   prevent. `hostPath` and every other source are allowed; Pod Security
   Admission in the namespace is the control for them (D8).
6. **Size.** Total serialised size of the three lists in one template ≤ 64 KiB
   (the CRD cannot bound the preserved objects, and the same JSON is copied
   into the v1beta1 transport annotation for pools and into the hub/gateway
   payloads).
7. **Where allowed.** Rejected on external `GarageNode`s (no pod) and on
   node-local-pool-backed `GarageNode`s (their pod comes from the pool's
   DaemonSet, so a per-node value would be silently unused). Use the pool's
   `podTemplate`.

Split summary:

| Check | CRD schema / CEL | Webhook | Controller (fail-closed) |
| --- | --- | --- | --- |
| item count, name format, list-key uniqueness | ✔ | | |
| reserved container / volume names (static) | ✔ | ✔ | ✔ (dynamic, from built pod) |
| cross-list name uniqueness | ✔ | ✔ | ✔ |
| unknown fields / full container schema | | ✔ | ✔ (`Resolve`) |
| restartPolicy, ports, mounts, volume sources | | ✔ | ✔ |
| mount of operator-owned volume | | ✔ | ✔ |
| managed-PVC claim reuse | | | ✔ |
| node-level merged-set validity | | best effort | ✔ |

The controller re-validates because webhooks can be disabled
(`webhooks.enabled=false`, or `failurePolicy: Ignore`), objects can predate a
future stricter rule, and the node webhook sees only a snapshot of the cluster.

## Reconciliation

### Builder

`PodSpecConfig` gains `InitContainers []corev1.Container`,
`ExtraContainers []corev1.Container`, `ExtraVolumes []corev1.Volume`. All three
callers of `buildGaragePodSpec` pass resolved values: the GarageNode
StatefulSet, the edge-gateway StatefulSet (`garagecluster_gateway.go`), and the
node-local-pool DaemonSet (`node_local_pool_daemonset.go`).

After the operator's pod spec is built, `buildGaragePodSpec` (or a new
`applyPodExtras`) does, in order:

1. Collect the names of operator volumes, containers, and init containers
   **from the built spec** (not from a constant list).
2. If any extra collides, or an extra mounts an operator volume, return an
   error. Callers surface it as `PodExtrasValid=False` (below) and **leave the
   existing workload untouched**.
3. Prepend nothing: operator init containers stay first; user init containers
   follow in listed order. Append extra containers after `garage`. Append extra
   volumes after operator volumes.

Order is deterministic; the pod-spec hash is computed over the **resolved**
`corev1.Container` values, so JSON key order or whitespace differences in the
submitted objects cannot cause a spurious rollout.

### Merge for `GarageNode`

Auto-generated nodes carry no copy of the tier lists: the node controller
already reads tier values from the cluster template at reconcile time
(`tierTemplate` in `reconcileStatefulSet`). The `GarageNode.spec.*` list, when
non-nil, **replaces** the tier list for that list (the rule `tolerations`,
`affinity` and `envFrom` already follow); a non-nil empty list opts a node out
of an inherited sidecar. The three lists are independent. Decision D5 records the
alternative by-name overlay.

### Interaction with operator-managed init containers

`patchSTSPurgeInitContainer` (replication-factor migration) prepends
`purge-cluster-layout` to a live StatefulSet and later removes it, filtering by
name. Because the name is reserved and user init containers are never
reordered by it, the two coexist. The existing
checks in `garagecluster_factor_migration.go` (`verifyFactorMigrationPurgePreparation`
and the per-node patch) already locate the purge container by name rather than
index, so no change is expected there. Required test: a factor migration against a cluster that defines user init containers
leaves them intact and in order, and removal restores exactly the user list.

### Rollout, readiness, and failure modes

| Failure | Behavior |
| --- | --- |
| Bad image / sidecar crash-loops during a rollout | The replaced pod does not become Ready (all containers must be). Garage on that identity is down; `StorageRollout` stops at that one pod. Replication tolerates one node; fix by reverting the spec. The sequencer never advances to a second node, so the blast radius is one identity. |
| A failing **init** container | Garage never starts on the replaced pod (same one-node impact). |
| A sidecar with a readiness probe on a **gateway** | Gateway Services use `publishNotReadyAddresses=false`; a NotReady sidecar withdraws that pod from S3 traffic. Document: extras are part of pod readiness. |
| Invalid extras at reconcile time | Condition `PodExtrasValid=False` on the `GarageCluster` (and `GarageNode` phase `Failed` with the message), event, **no workload update**, existing pods keep running with the previous spec. Not retried faster than `RequeueAfterLong`. |
| Extras added without `resources.requests` | The pod may leave `Guaranteed` QoS if Garage's resources are equal requests/limits. Document. |
| Secrets referenced by extras | Plain pod semantics; rotation does not restart pods (operator-owned Secrets are the only ones in the rollout hash). The static-credentials cleanup in `static_credentials.go` scans live pod specs (init, regular, and ephemeral containers) for referenced Secrets, so a Secret used only by an extra is retained without changes; a test pins this. |

Native sidecars (`restartPolicy: Always`) need Kubernetes 1.29+ (beta) / 1.33+
(GA). The operator does not probe the server; below that the API server rejects
or drops the field and the StatefulSet update fails visibly. Document in
`compatibility.md`.

## Status and conditions

- `GarageCluster` condition `PodExtrasValid` (`True`/`False`; reasons
  `Valid`, `InvalidContainer`, `ReservedName`, `UnknownVolume`,
  `OperatorVolumeMount`, `ManagedClaimReuse`, `DecodeError`). `False` does not
  change `Phase` by itself.
- No new status fields. The existing `annotationPodSpecHash` already shows the
  desired revision; `storageRollout` already shows the handoff.

## Compatibility and upgrade

- Existing objects: no behavior or stored-form change; fields absent.
- `kubectl apply -f` of the CRD: size grows ~2.0% (+21 KB); unchanged install
  guidance (server-side apply / create).
- Downgrade: an older operator ignores unknown fields it prunes via its older
  schema; the extras vanish from newly-written objects, and running pods keep
  them until the next template change. Document in release notes.
- No breaking change to any existing field. `PodTemplate`/`NodeLocalPoolPodTemplate`
  only gain optional members.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Fully typed `[]corev1.Container` / `[]corev1.Volume` | +1.09 MB; over the etcd limit (measured above). |
| A curated subset struct (our own `ExtraContainer`) | Needs every field maintained forever, still embeds `corev1.EnvVar`, `ResourceRequirements`, `SecurityContext`, probes (large), and would diverge from Kubernetes on every release. |
| ConfigMap/Secret reference holding YAML | Not declarative in the CR, not diffable in GitOps, new RBAC and watch, and the content is validated later than the CR. |
| Strategic-merge patch of the Garage container (Prometheus-style) | Allows silently rewriting reserved env, mounts, command; the operator's safety proofs depend on the rendered container. |
| Operator-level `PodSpec` patch (`spec.podSpecPatch`) | Same, plus unbounded surface (any pod field). |
| Mounting metadata/data read-only into sidecars (backup agents) | Valuable but exposes `node_key`; deferred behind an explicit opt-in (D6). |

## Test plan

**Unit**

- `PodExtraContainer`/`PodExtraVolume`: lenient `UnmarshalJSON`, strict
  `Resolve` (unknown field, wrong type), `MarshalJSON` round trip preserves
  bytes, `DeepCopy` independence, `NewPodExtraContainer`.
- Webhook table for every rule above in v1beta2, v1beta1, and `GarageNode`,
  including: reserved names, cross-list duplicate, bad `restartPolicy`,
  port collision, mount of `metadata`, unknown volume, `volumeDevices`,
  oversize, external node, node-local-pool-backed node.
- Builder: ordering (operator init first, then user; `garage` is container 0),
  collision detection from the built spec, deterministic hash independent of
  JSON key order, and identical output for the three callers.
- Merge: node list replaces tier list; non-nil empty list opts out; lists are
  independent.
- Factor migration with user init containers present.
- `gatewayTierRequiresV1Beta2Payload` with extras.

**Conversion** (`api/v1beta1/garagecluster_conversion*_test.go`)

- v1beta1 ⇄ hub round trip for storage, edge gateway (`gateway: true`),
  unified (extras on both tiers → top-level storage lists plus gateway payload),
  and node-local pools; assert deep equality of `Resolve()`d values, not raw
  bytes.
- A v1beta1 write that does not mention the fields must not clear hub values
  (the lossy-write test that motivates D4).

**CRD / CEL (envtest, Kubernetes 1.36.2)** — the table in *Prototype evidence*
becomes a permanent test against the generated CRD (`config/crd/bases`), with
webhooks absent.

**envtest controller**: create a GarageCluster with extras → StatefulSet pod
template contains them in the right order; edit an extra → pod-spec hash
changes and `StorageRollout` replaces exactly one pod; invalid extras → no
StatefulSet update and `PodExtrasValid=False`.

**e2e** (`test/e2e`, label `pod-extras`): storage cluster with an init
container writing to an `emptyDir` and a sidecar reading it; GarageNode
override; node-local pool; a rollout driven by an extras edit; a deliberately
bad image proving the rollout stops at one identity and recovers on revert.

## Documentation

- `docs/how-to/configuration.md`: the DDNS/secondary-interface examples.
- `docs/how-to/manual-nodes.md`: GarageNode override semantics.
- `docs/node-local-pools.md`: pool `podTemplate` additions.
- `docs/reference/custom-resources.md`, `compatibility.md` (native sidecars),
  `docs/concepts/storage-and-layout.md` (why metadata is not mountable).
- Generated: `make manifests generate`, Helm CRD copies, `schemas/*.json`.

## Deferred

- Read-only mounts of operator volumes for backup/export sidecars.
- `shareProcessNamespace`, `hostAliases`, `terminationGracePeriodSeconds`,
  `dnsConfig` as separate fields.
- Per-extra `readinessGate`/pod-readiness decoupling for gateways.
- An operator-level off switch.

## Decisions

Decided by Raj Singh on 2026-10-02. Each entry states the chosen option; the
options that were not chosen are kept as rationale.

**D1. Which tiers get the fields?**
**Decision: (a).** every `PodTemplate` consumer — default storage group,
gateway tier (unified and edge), node-local pools, and `GarageNode`. It is the
natural result of the shared embedded type and gateways need the same
companions (rpc address updaters). *Not chosen:* (b) Storage tier, pools, and `GarageNode`
only, as the issue is worded; requires splitting `PodTemplate` or rejecting the
fields on the gateway in the webhook.

**D2. CRD schema strategy.**
**Decision: (a).** schema-light wrapper (`name` declared, rest preserved),
strict validation in webhook and controller. +21 KB (2.0%). *Not chosen:* (b) Fully typed
`corev1.Container`/`Volume` — not viable: +1.09 MB measured, over the etcd
limit. (c) Curated subset struct — large and drifting; see Alternatives.
(d) ConfigMap reference — loses declarative GitOps.

**D3. Field names.**
**Decision: (a).** `initContainers`, `extraContainers`, `extraVolumes` (the
issue's names; "extra" avoids implying that `containers` replaces the Garage
container). *Not chosen:* (b) Prometheus-style `containers`/`volumes` (risks implying
replacement of the main container). (c) Zalando-style `sidecars`/`additionalVolumes`
("sidecar" is ambiguous with native-sidecar init containers).

**D4. v1beta1 representation.**
**Decision: (a).** typed mirror fields at the v1beta1 top level (beside
`podAnnotations`), mapped by tier in conversion; lossless, visible to `kubectl`,
~2 KB. *Not chosen:* (b) Transport annotation like node-local pools: smaller legacy API
surface, but adds another reserved-annotation payload that admission must
distinguish from forged input, and counts toward the 256 KiB annotation cap.
(c) v1beta2-only and reject v1beta1 writes that would drop them: surprising for
v1beta1 clients.

**D5. `GarageNode` override semantics.**
**Decision: (a).** per-list replace when set; non-nil empty list opts out
(matches `tolerations`, `affinity`, `envFrom`). *Not chosen:* (b) By-name overlay (node
entries replace same-name tier entries, others inherited; like `env`) — more
flexible, but no way to opt a node out of one inherited sidecar. (c) By-name
overlay plus a `disabled: true` tombstone — needs a field that is not part of
`corev1.Container`.

**D6. Can extras mount operator-owned volumes?**
**Decision: (a).** never in v1 — reject any mount of `metadata`, `data`,
`data-N`, config, or the Secret volumes (the metadata volume holds `node_key`).
*Not chosen:* (b) Allow `readOnly: true` mounts of `data`/`metadata` (backup shippers);
needs a rule that rejects `node_key` exposure, which is impossible at volume
granularity. (c) Per-container opt-in annotation acknowledging the identity
exposure.

**D7. Position of user init containers relative to operator init containers.**
**Decision: (a).** operator init containers first, user init containers after
in listed order (the operator's safety steps never depend on user steps).
*Not chosen:* (b) User first (lets a user step prepare a volume before the purge step);
makes the purge step conditional on user-step success.

**D8. Allowed `extraVolumes` sources.**
**Decision: (a).** all Kubernetes sources; rely on Pod Security Admission for
`hostPath`; reject only managed-PVC reuse. *Not chosen:* (b) Allow-list (`emptyDir`,
`configMap`, `secret`, `projected`, `downwardAPI`, `csi`, `ephemeral`,
non-managed `persistentVolumeClaim`) — tighter, but breaks `hostPath`-based
network helpers, which is the issue's own use case. (c) Allow-list plus a Helm
value to extend it.

**D9. Node-local pools in the first PR.**
**Decision: (a).** include. The DaemonSet shares `buildGaragePodSpec`, the
transport is already automatic, and omission would leave pools as the one
template without the feature. *Not chosen:* (b) Defer pools to a follow-up.

**D10. Operator-level off switch (Zalando `enable_sidecars` style).**
**Decision: (a).** none. The author can already run arbitrary images via
`spec.image`; a switch adds a Helm value and a failure mode. Namespace policy
(PSA, Kyverno) already governs containers. *Not chosen:* (b) Helm `podExtras.enabled`
(default true) that makes the webhook and controller reject non-empty lists —
useful for multi-tenant platforms.

**D11. Fail-closed behavior on invalid extras at reconcile time.**
**Decision: (a).** leave the running workload untouched, set
`PodExtrasValid=False`, retry slowly. *Not chosen:* (b) Also scale the affected node to zero
(never; destructive). (c) Drop the extras and continue (silently runs the pod
without a sidecar the user believes is there).

## Implementation notes / deviations

Shipped in [#452](https://github.com/rajsinghtech/garage-operator/pull/452)
(merge commit `3b08503`). Field names, markers, list-map keys, `MaxItems`
(16/16/32), the reserved-name and cross-list CEL rules, the v1beta1 mirror,
`GarageNode` replace-when-set semantics, the `PodExtrasValid` condition, and
rollout through the pod-spec hash match this record. CRD size when #452 merged:
`GarageCluster` 1,034,475 → 1,058,915 B (+24,440 B), under etcd's ~1.5 MiB limit
(the figure in the record, measured before implementation, was +21 KB). Where
the code differs from the text above, the code is authoritative:

1. **Exported `Raw` instead of unexported `raw`.** The wrapper types keep the
   raw JSON in an exported `Raw json.RawMessage` field (still `json:"-"`).
   `equality.Semantic.DeepEqual`, which the update webhooks use to compare whole
   specs, panics on unexported fields; the e2e run caught it (every update of
   an object that already had extras was denied). Regression tests added.
2. **A separate `applyPodExtras` step.** `buildGaragePodSpec` and `PodSpecConfig`
   are unchanged. Extras are applied right after `buildGaragePodSpec` for the
   gateway StatefulSet, the `GarageNode` StatefulSet and the node-local-pool
   DaemonSet; collisions are still computed from the built pod spec.
3. **Invalid extras block the whole reconcile pass.** `PodExtrasValid=False` on
   the cluster stops that cluster's reconcile pass (workloads untouched, `Phase`
   unchanged), with a retry no faster than `RequeueAfterLong` (5 minutes). Node
   level failures set the `GarageNode` phase `Failed` with the message. The
   record only promised that the running workload stays untouched.
4. **No Kubernetes Events.** The record mentions events on invalid extras; the
   operator had no `EventRecorder` or events RBAC when this shipped (decision D11
   is unaffected: the signal is the condition, a log line, and the `Failed`
   message).
5. **v1beta1 clients that omit the fields clear them.** A v1beta1 write without
   the new fields necessarily clears them on the hub (documented); the record's
   "lossy write" test covers a write that omits them. Downgrading the operator
   prunes them from newly written objects.
6. **Webhook vs controller split.** The node webhook's merged check is
   best-effort and the controller is authoritative. The managed-claim reuse
   check runs only in the controller (as the split table says), using a
   heuristic: managed-by label, UID annotation, or the claim-name pattern of a
   StatefulSet the operator renders.
7. **Bug fixed along the way: `purgeInitRunAsUser`.** It used the first
   container's `RunAsUser`; it now considers only the `garage` container so a
   sidecar cannot change the purge init container's user.
8. **Schema generator change.** `hack/openapi2jsonschema.py` now skips
   `additionalProperties: false` on objects marked
   `x-kubernetes-preserve-unknown-fields`; otherwise the generated JSON schemas
   (and `make validate-manifests`) rejected valid containers and volumes. Not in
   the record; required by the wrapper types.
9. **Rollout-freeze normalizers.** The three lists are treated as workload
   fields, so a bad sidecar can be reverted during an active storage rollout.
10. **e2e.** A new e2e spec (label `pod-extras`) covers an init container
    seeding an `emptyDir`, a sidecar reading it, webhook rejection of a
    malformed container and of a `metadata` mount, and a bad sidecar image
    stopping at one identity with recovery on revert. It does not cover a
    `GarageNode` override or a node-local pool (envtest does).
