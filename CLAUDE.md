# Garage Kubernetes Operator

> **Agent Notes**: Reference /Users/rajsingh/Documents/GitHub/garage for Garage source code. Update this file with important learnings.

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed S3-compatible object storage.
UPSTREAM CODEBASE ../garage
## Quick Reference

### CRDs

| CRD | Short | Description |
|-----|-------|-------------|
| `GarageCluster` | `gc` | Cluster deployment + multi-cluster federation |
| `GarageBucket` | `gb` | Buckets with quotas, website hosting |
| `GarageKey` | `gk` | S3 access keys with bucket permissions |
| `GarageNode` | `gn` | Node layout (zone, capacity, gateway) |
| `GarageAdminToken` | `gat` | Admin API tokens |
| `GarageReferenceGrant` | `grg` | Cross-namespace access grants (v1beta1+) |

### Development Commands

```bash
make dev-up        # Setup: kind + CRDs + operator
make dev-test      # Apply test resources
make dev-status    # View all garage resources
make dev-logs      # Stream operator logs
make dev-load      # Rebuild and reload operator
make dev-run       # Run operator locally (debugging)
make dev-down      # Tear down cluster
```

### Project Structure

```
api/v1beta1/           # CRD types + webhooks
internal/controller/    # Reconciliation logic
internal/garage/        # Admin API client (v2)
config/samples/         # Example CRs
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster A                         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Operator: Cluster | Bucket | Key | Node Controllers        │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │     Garage Cluster (Zone: us-east-1) - 3 Pods             │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────┘
                    Full Mesh RPC (port 3901)
┌──────────────────────────────┼──────────────────────────────────┐
│                     Kubernetes Cluster B                         │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │     Garage Cluster (Zone: eu-west-1) - 3 Pods             │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Multi-Cluster Federation

### Key Concepts

1. **Full Mesh Connectivity**: Every node must reach every other node on RPC port (3901)
2. **Shared RPC Secret**: Same 32-byte hex secret across ALL clusters
3. **Zones**: Labels for fault tolerance - Garage distributes replicas across zones
4. **No Single Leader**: Layout is a CRDT that converges across nodes

### Network Solutions

**LoadBalancer per Node** (recommended for federation — via `GarageNode` with `layoutPolicy: Manual`):
```yaml
# On each GarageNode:
publicEndpoint:
  type: LoadBalancer   # creates <node>-rpc service; rpc_public_addr auto-derived from LB ingress
```
Or set manually: `spec.network.rpcPublicAddr: "hostname:3901"`

**LoadBalancer shared** (single LB IP, all GarageCluster pods):
```yaml
publicEndpoint:
  type: LoadBalancer
  # operator auto-derives rpc_public_addr from the LB service ingress IP
```

**NodePort** (cheaper):
```yaml
publicEndpoint:
  type: NodePort
  nodePort:
    externalAddresses: ["node1.example.com", "node2.example.com"]
    basePort: 30901
```

### Federation Setup

1. Create shared RPC secret in ALL clusters:
   ```bash
   openssl rand -hex 32
   kubectl create secret generic garage-rpc-secret --from-literal=rpc-secret=<secret>
   ```

2. Deploy GarageCluster in each cluster with same `rpcSecretRef`, unique `zone`

3. Use `spec.remoteClusters` for automatic federation or `connect-nodes` annotation for manual

---

## API Versions

`GarageCluster` is served under two API versions to keep backward compatibility:

- **`garage.rajsingh.info/v1beta2`** (storage version) — the tier-based schema
  (`spec.storage`, `spec.gateway`). Use this for all new CRs. See "Cluster
  Tiers" below.
- **`garage.rajsingh.info/v1beta1`** (deprecated, still served) — the legacy
  flat schema (`spec.replicas`, `spec.gateway: bool`, `spec.storage` of type
  `StorageConfig`). Existing CRs continue to be accepted with no edit.

A conversion webhook (registered as part of the operator) handles both
directions. v1beta1 reads are converted up to v1beta2 before the controller
sees them — the controller code only operates on v1beta2 types.

Round-trip is **lossless** for every CR that v1beta1 can express. A v1beta2
CR that sets both `spec.storage` AND `spec.gateway` (a unified cluster) has
no v1beta1 form; the v1beta1 view renders only the storage tier and adds the
annotation `garage.rajsingh.info/v1beta2-only=gateway-tier-present` so
external tooling can detect that the gateway tier was elided. Tools that
manage unified clusters must read/write v1beta2 directly.

Other CRDs (`GarageBucket`, `GarageKey`, `GarageNode`, `GarageAdminToken`,
`GarageReferenceGrant`) remain on `v1beta1` exclusively.

---

## Cluster Tiers (storage + gateway)

A `GarageCluster` describes two optional tiers, both reconciled from the same CR:

- `spec.storage` — long-lived per-node **StatefulSet**s (one per replica), each
  with metadata + data PVCs. The cluster spec generates N × `GarageNode` CRs
  (one per pod ordinal), and the GarageNode controller owns each node's 1-replica
  STS. Pod node identity persists across restarts via the metadata PVC.
- `spec.gateway` — in a **unified cluster** (storage + gateway in the same CR),
  the gateway tier ALSO runs as N × per-node `GarageNode` CRs
  (`<cr>-gateway-N`, `gateway: true`) — symmetric with storage — each with a
  small metadata PVC (persistent identity) and EmptyDir data. The GarageNode
  controller assigns each gateway pod a `capacity: nil` layout role so
  `key_table`/`bucket_table` are full-replicated locally and S3 sig-auth resolves
  keys via `get_local()` without a per-request quorum RPC to the storage tier
  (issue #209). In an **edge gateway** (gateway-only CR + `connectTo`), the
  gateway tier stays a cluster-level **StatefulSet** (`<cr>-gateway`) because its
  layout lives on a remote storage cluster managed by the gateway-connection path.

A CR must set at least one of `storage`, `gateway`, or `connectTo`. The webhook
rejects empty specs and `gateway` without either `storage` (unified cluster) or
`connectTo` (edge gateway pattern). `connectTo` alongside `storage` (but no
gateway) is also rejected.

### Four valid shapes

1. **Unified cluster** — most common, both tiers in one CR:

   ```yaml
   spec:
     storage:
       replicas: 3
       metadata: { size: 10Gi }
       data:     { size: 100Gi }
     gateway:
       replicas: 2
   ```

2. **Storage-only** — headless backend, no S3/Admin traffic terminating locally.
3. **Edge gateway** — gateway pods in a different K8s cluster from the storage
   backend, connected via `connectTo.clusterRef` or `connectTo.adminApiEndpoint`.
4. **Management handle** — `connectTo` only, no tiers. See below.

### Management handle (connectTo-only, no tiers) — issue #269

A `GarageCluster` with **only** `spec.connectTo` set (no `storage`, no
`gateway`) is a pure connection handle to an **externally-managed** Garage
cluster (e.g. one deployed by the upstream Helm chart). The operator provisions
**no** workload for it — no RPC secret, ConfigMap, Service, StatefulSet, or
layout. It dials the external cluster's Admin API and manages Admin-API state
only: `GarageBucket` / `GarageKey` / `GarageAdminToken` CRs that reference the
handle. This lets you bring a Helm-deployed cluster under declarative control
incrementally, with zero risk to the running workload.

```yaml
spec:
  connectTo:
    adminApiEndpoint: "http://garage.garage.svc:3903"
    adminTokenSecretRef: { name: garage-admin, key: admin-token }
```

Implementation:
- `IsManagementHandle()` (`api/v1beta2/garagecluster_helpers.go`) = `connectTo != nil && storage == nil && gateway == nil`.
- The webhook requires an Admin-API path on a handle: `adminApiEndpoint` +
  `adminTokenSecretRef`, **or** `clusterRef`. `rpcSecretRef`/`bootstrapPeers`
  alone are rejected (they wire RPC, not the Admin API).
- `GetGarageClient` (`internal/controller/helpers.go`) routes through
  `resolveConnectToClient` on a handle — every controller (bucket/key/cluster)
  then talks to the external cluster transparently.
- `reconcileManagementHandle` (`garagecluster_controller.go`) probes the Admin
  API (`GetClusterStatus`) and sets `Status.Phase` Running/Pending plus the
  `ManagementHandleReady` condition. Buckets/keys gate on `Phase == Running`.
  Healthy handles requeue at 5m; unreachable at the fast unhealthy interval.
  `finalize` is a no-op for a handle (nothing owned).
- **Adoption:** `GarageBucket.spec.bucketId` / `GarageKey.spec.importKey` bind to
  pre-existing state. Creating a brand-new `GarageKey` without `importKey` needs
  deterministic key material, which derives from an RPC secret the handle does
  not auto-create — set `spec.network.rpcSecretRef` to the external cluster's RPC
  secret, or use `importKey`. The key controller surfaces this as an actionable
  error. A key's generated Secret derives its S3 endpoint from the
  `connectTo.adminApiEndpoint` host (not a nonexistent managed Service).
- **Stage 2 (not implemented):** having the operator adopt the external
  StatefulSet + PVCs in place and retire Helm. Blocked on PVC-name mismatch
  (operator `metadata`/`data` vs chart `meta-*`/`data-*`) and the per-node
  GarageNode architecture; needs a dedicated design.

### Workload differences

| Aspect | Storage tier | Gateway tier (unified) | Gateway tier (edge) |
|---|---|---|---|
| Workload | N × `StatefulSet`s (`replicas: 1`) | N × `StatefulSet`s (`replicas: 1`) | `StatefulSet` (`<cr>-gateway`) |
| GarageNode CRs | one per ordinal (`<cr>-storage-N`) | one per ordinal (`<cr>-gateway-N`, `gateway: true`) | none |
| metadata volume | PVC (per node) | PVC (per node, 1Gi default) | PVC (per replica) |
| data volume | PVC (per node) | EmptyDir | EmptyDir |
| Node identity | persists (PVC) | persists (PVC) | persists (PVC) |
| ConfigMap | per-node when overrides present, else shared | **always per-node** (so it never inherits the storage `rpc_public_addr`) | gateway-specific |
| Layout owner | per-`GarageNode` controller (local) | per-`GarageNode` controller (local) | gateway-connection path (remote) |
| Layout capacity | from PVC size | nil (gateway) | nil (gateway) |

In a unified cluster every tier is reconciled as per-pod `GarageNode`s; the
difference between tiers is `gateway: true` (capacity nil, EmptyDir data) and
between Auto/Manual is **ownership** of those GarageNodes (operator vs user),
not the workload shape. Edge gateways (a separate gateway-only CR connecting to
a remote storage cluster) keep the cluster-level StatefulSet because their layout
is owned remotely.

### Layout staging/apply concurrency

Every layout mutation goes through `Client.ApplyStagedLayoutChanges`
(`internal/garage/client.go`). Two upstream facts make a naive
`ApplyClusterLayout(version+1)` wrong (validated against Garage v2.3.0):
`ApplyClusterLayout`'s version-rejection is a generic error mapped to **HTTP 500,
not 409** (so `garage.IsConflict` never caught an apply race), and apply
**always** bumps the version (so an unconditional apply churns layout gossip).
The helper re-reads the layout, skips apply when nothing is staged, and on
failure re-reads to detect whether a concurrent writer already committed the
staged change (staging is a per-node `LwwMap` that merges, so this is safe).

### Gateway tombstone cleanup

On each reconcile the operator:

1. Picks the right admin client — local for unified clusters, remote for edge
   gateways (via `connectTo`).
2. Queries the cluster's layout and lists entries tagged with both
   `cluster:<name>/<namespace>` and `tier:gateway`.
3. Cross-references with the live gateway pods (`isUp`) AND the node IDs claimed
   by live operator-owned gateway `GarageNode` CRs (`status.nodeId`). A role
   claimed by an existing gateway GarageNode is **never** removed — this keeps
   the cluster-level cleanup from fighting the per-node controller during a brief
   pod restart (the per-node finalizer owns role removal on delete).
4. Stages removal of any remaining unclaimed `tier:gateway` entry.

When `spec.layoutManagement.autoApply: true` the removal is applied immediately
and `skip-dead-nodes` is called on the new layout version. Otherwise the
operator surfaces the pending removals on `status.pendingGatewayTombstones`
and sets the `GatewayTombstones` condition; an operator/admin can then
acknowledge with the `force-layout-apply` annotation or by toggling autoApply.

### External Gateway Connectivity

When `connectTo.adminApiEndpoint` is set (edge gateway in a different K8s
cluster from its storage backend), the operator calls `ConnectNode` in both
directions (gateway → external AND external → gateway). The reverse direction
requires the gateway to have an externally-routable address set via
`spec.gateway.rpcPublicAddr` (preferred), `spec.network.rpcPublicAddr`, or a
working `publicEndpoint`. Without it, Garage advertises the pod IP, which is
unreachable from outside K8s.

Reconciliation behavior:
- `ConditionGatewayConnected` is set True/False/PartiallyConnected based on results
- When True, the operator skips ConnectNode calls and only does a lightweight `isUp` check
- Healthy external gateway clusters requeue at 5m (not 1m) to avoid hammering the external admin API
- Garage marks peers `Abandoned` after 10 failed retries and never retries again — the operator's 5m drift check is the only recovery path at that point

### Auto → Manual ejection (one-way)

Flipping `spec.layoutPolicy` from `Auto` to `Manual` is a hand-off: the operator
**drops its controller-ownerReference** on each operator-owned child
`GarageNode` and strips the `app.kubernetes.io/managed-by=operator` label.
Implementation: `ejectAutoModeStorageNodes` in
`internal/controller/garagecluster_automode.go`, called from the cluster
Reconcile when `LayoutPolicy == Manual`.

After ejection:
- The child GarageNodes (named `<cluster>-storage-N`) keep running — their
  StatefulSets, PVCs, and Garage node identities are unaffected.
- The user owns the GarageNodes and may edit, rename, or delete them at will.
- The cluster-level reconcile no longer creates/updates/deletes them.

Pre-existing user-created GarageNodes (without the operator's controllerRef)
are unaffected at any time — the operator only touches CRs it owns.

**Manual → Auto is rejected by the validating webhook** (see
`api/v1beta2/garagecluster_webhook.go`). The operator cannot safely re-adopt
user-managed nodes that may carry settings the cluster spec can't express.

### Legacy storage-STS migration (#190)

Pre-#190 Auto clusters used a single cluster-level StatefulSet `<cluster>` with
N replicas. On first reconcile by a #190+ operator, that layout is auto-migrated
to per-node GarageNodes:

1. Operator detects the legacy STS by name (`<cluster>` in cluster namespace).
2. For each ordinal, creates an operator-owned `GarageNode` named
   `<cluster>-storage-<ord>` with
   `spec.storage.{metadata,data}.existingClaim` pointing at the legacy
   PVCs (`metadata-<cluster>-<ord>`, `data-<cluster>-<ord>`). The metadata
   PVC carries Garage's `node_key`, so node identity survives.
3. Orphan-deletes the legacy STS (`PropagationPolicy: Orphan`). The new
   per-node STSes take ownership of the RWO PVCs as the old pods terminate.

Status surfaced at `status.migration`:

```yaml
status:
  migration:
    phase: Completed   # NotStarted | InProgress | Completed | Failed | Skipped
    migratedOrdinals: [0, 1, 2]
    startedAt: 2026-05-24T16:00:00Z
    completedAt: 2026-05-24T16:00:12Z
    message: "migrated 3 ordinals from legacy StatefulSet to per-node GarageNodes"
```

**Multi-HDD clusters auto-migrate to per-node `GarageNode`s with
`spec.storage.dataPaths[]` populated** (one entry per legacy
`data-<idx>-<cluster>-<ord>` PVC, index-ordered). `buildAutoModeStorageNode`
emits `DataPaths` when the bucketed PVC list has more than one entry, and
`bucketLegacyDataPVCs` discovers the multi-HDD layout. End-state and
observability are identical to single-HDD migrations (`phase: Completed`).

Each migrated multi-HDD `DataPaths[i]` carries:

- `existingClaim` — binds to the legacy PVC (`data-<idx>-<cluster>-<ord>`).
- `size` — advertised to Garage as the per-disk capacity in
  `data_dir = [{path, capacity}]`. Without `capacity` upstream
  `make_data_dirs` (../garage `src/block/layout.rs`) rejects the config and
  the pod crashloops (#205). The `NodeVolumeConfig` webhook explicitly
  allows `existingClaim + size` together for this reason.
- `path` and `readOnly` — copied index-aligned from
  `cluster.spec.storage.data.paths[i]`. Garage's on-disk `DataLayout`
  (G09bmdl) is keyed by `path`, so preserving the user's original mount
  paths means Garage finds the same partitions at the same paths after
  upgrade. Without this, `DataLayout::update` sees the old path missing +
  the new path empty, reassigns partitions, and refetches blocks from
  peers even though the same on-disk data is still present (just at the
  hardcoded `/data/data-<i>` mount). `readOnly: true` emits `read_only =
  true` in the TOML entry and drops capacity (parity with upstream
  `DataDir.read_only`). The webhook accepts `readOnly: true` alone with
  no `size`/`existingClaim` on `dataPaths[]` entries.

`NodeVolumeConfig.Path` and `ReadOnly` apply only inside multi-HDD
`storage.dataPaths[]`. On `storage.{metadata,data}` they're harmless but
have no effect since those slots don't render TOML capacity/path fields.

As a defensive fallback, the per-node ConfigMap renderer
(`reconcileNodeConfigMap`) auto-heals multi-HDD nodes whose
`dataPaths[].size` is unset by looking up the bound PVC's requested storage
at render time, so any GarageNode migrated by a pre-#205 operator boots
cleanly on the next reconcile without a spec edit.

When the legacy STS has `replicas=0` AND legacy PVCs (metadata or data)
still exist, the operator **refuses to migrate** (`failMigration` with
`reason: Failed`, message containing `replicas=0`). Without this guard
the per-ordinal loop iterates zero times, the STS is orphan-deleted, the
condition is set to Completed, and the PVCs are stranded forever. The
user must scale the STS back up to its original replica count (so the
migration can adopt each metadata + data PVC by name) or delete the
leftover PVCs to abandon the data.

Implementation: `migrateLegacyStorageSTSIfNeeded` in
`internal/controller/garagecluster_automode.go`. Idempotent and resumable via
`status.migration.migratedOrdinals`.

---

## Configuration Reference

### GarageCluster Options

| Category | Options |
|----------|---------|
| **Tiers** | `spec.storage` (StatefulSet + PVCs) and/or `spec.gateway` (Deployment + EmptyDir) |
| **Replication** | `spec.replication.factor` (1-7), `consistencyMode` (consistent/degraded/dangerous) |
| **Storage tier** | `spec.storage.{replicas,metadata,data,resources,nodeSelector,tolerations,…}` |
| **Gateway tier** | `spec.gateway.{replicas,resources,nodeSelector,rpcPublicAddr,…}` |
| **Database** | Engine (lmdb/sqlite/fjall), LMDB map size, Fjall block cache |
| **Blocks** | Size, RAM buffer, compression, concurrent reads |
| **APIs** | S3 (3900), K2V (3904), Web (3902), Admin (3903) |
| **Network** | RPC port, public address, bootstrap peers |
| **Logging** | Level (RUST_LOG format), syslog, journald |
| **Maintenance** | `spec.maintenance.suspended` — pauses all reconciliation |
| **Workers** | `spec.workers.scrubTranquility`, `resyncWorkerCount`, `resyncTranquility` — continuously reconciled |

### Layout Policy

| Policy | Behavior |
|--------|----------|
| `Auto` (default) | Operator generates and owns one `GarageNode` per storage replica, named `<cluster>-storage-N`. Each child STS has 1 replica; the per-node GarageNode controller drives its lifecycle. Capacity derived from the cluster spec's PVC size. |
| `Manual` | User creates and owns `GarageNode` resources directly; the cluster-level Reconcile does not touch them. Use for per-node zone/capacity/tags/storage overrides, external nodes, or hand-tuned layouts. |

Transition rules:
- `Auto → Manual` is supported (one-way). The operator drops its controllerRef on each child `<cluster>-storage-N` GarageNode; the user inherits them. See "Auto → Manual ejection" above.
- `Manual → Auto` is **rejected by the validating webhook** (see `api/v1beta2/garagecluster_webhook.go`).

---

## GarageBucket Features

### Supported (via Admin API)

Quotas, Website hosting (index/error docs), Global/Local aliases, Key permissions

### Supported (via Admin API, operator-managed since v2.3.0)

Lifecycle rules. Since Garage v2.3.0, `UpdateBucket` accepts `lifecycleRules`
directly, so the operator uses `SetBucketLifecycle` on the Admin API client.
Garage accepts only a subset of the AWS S3 lifecycle spec: `Expiration` (days
or date, no `ExpiredObjectDeleteMarker`) and `AbortIncompleteMultipartUpload`,
with `Filter` carrying prefix and/or object size bounds. Tag filters and the
deprecated rule-level `Prefix` are not accepted. Rule evaluation is performed
by Garage's lifecycle worker, which runs daily at midnight UTC by default
(local TZ when `use_local_tz=true`).

### NOT Supported (use S3 API directly)

CORS rules, Website redirectAll/routingRules

---

## Operational Annotations

### GarageCluster (Implemented)

| Annotation | Description |
|------------|-------------|
| `garage.rajsingh.info/force-layout-apply` | Force apply staged layout (set to `"true"`) |
| `garage.rajsingh.info/connect-nodes` | Connect nodes: `"nodeId@addr:port,..."` (one-shot, removed after processing) |
| `garage.rajsingh.info/trigger-snapshot` | Trigger metadata snapshot on all nodes (set to `"true"`, one-shot) |
| `garage.rajsingh.info/trigger-repair` | Launch repair on all nodes — values: `Tables`, `Blocks`, `Versions`, `MultipartUploads`, `BlockRefs`, `BlockRc`, `Rebalance`, `Aliases`, `ClearResyncQueue` (one-shot) |
| `garage.rajsingh.info/scrub-command` | Control scrub worker on all nodes — values: `start`, `pause`, `resume`, `cancel` (one-shot) |
| `garage.rajsingh.info/revert-layout` | Discard staged layout changes (set to `"true"`). Does NOT revert an already-applied layout version. (one-shot) |
| `garage.rajsingh.info/retry-block-resync` | Clear resync backoff for blocks so they retry immediately. Set to `"true"` for all errored blocks, or comma-separated 64-hex-char hashes for specific blocks. (one-shot) |
| `garage.rajsingh.info/purge-blocks` | **DESTRUCTIVE** — permanently deletes all S3 objects referencing the given blocks. Set to comma-separated 64-hex-char block hashes. No undo. (one-shot) |
| `garage.rajsingh.info/retry-migration` | Clear `status.migration` and re-run the legacy-STS → per-GarageNode migration on the next reconcile. Use to recover from `Skipped`/`Failed` (e.g. false-positive multi-HDD detection) without hand-patching status. Set to `"true"`. (one-shot) |
| `garage.rajsingh.info/purge-cluster-layout` | **DESTRUCTIVE** — coordinated replication-factor migration (#208). Value `factor=N[,force]` (must match `spec.replication.factor`). Deletes the on-disk `cluster_layout` on every storage node and rebuilds the layout at factor N — the ONLY way to change the factor (validated upstream). Drives a resumable state machine on `status.factorMigration` (Validating→ScalingDown→Purging→Verifying→RebuildingLayout→Converging). Auto-mode only; **federation refused**; needs ≥ N storage nodes; **refused when any storage node carries per-node config overrides** (multi-HDD `dataPaths`, fsync, network, publicEndpoint, logging) — those use a `<node>-config` ConfigMap the suspended per-node controller can't refresh with the new factor, so the purged pod would boot at the OLD factor and wedge the cluster (remove the overrides or migrate the factor manually). Triggers full re-replication + brief unavailability. `,force` overrides the `dangerous`/pending-tombstone guards. A **failed or aborted** migration tears down cleanly (strips the purge init container, scales each storage STS back to 1, clears suspension) so the tier self-heals — it never leaves storage scaled-to-zero. The purge init container runs as the storage pod's effective UID (root by default), not a hardcoded UID. Abort with `garage.rajsingh.info/purge-cluster-layout-abort: "true"`. |
| `garage.rajsingh.info/pause-reconcile` | **Deprecated** — use `spec.maintenance.suspended: true` instead |

All one-shot annotations are removed after successful execution. On failure, the annotation is retained so the next reconcile retries. Results (success/error) are recorded in `status.lastOperation`.

### GarageBucket (Implemented)

| Annotation | Description |
|------------|-------------|
| `garage.rajsingh.info/cleanup-mpu` | Trigger cleanup of incomplete multipart uploads (set to `"true"`, one-shot) |
| `garage.rajsingh.info/cleanup-mpu-older-than` | Age threshold for MPU cleanup (e.g. `"24h"`, `"7d"`) — used with `cleanup-mpu` |

### Maintenance Mode

Prefer `spec.maintenance.suspended` over the deprecated annotation:

```yaml
spec:
  maintenance:
    suspended: true
```

The operator returns `RequeueAfter: 5m` while suspended and resumes immediately when the field is cleared.

**Per-node maintenance** — `GarageNode` exposes the same field
(`spec.maintenance.suspended: true`) for pausing reconciliation of a single
node's StatefulSet, ConfigMap, per-node Service, and layout entry. Use this
when you need to do PVC-level work (longhorn engine upgrade, manual `pvc-resize`
across storage classes, hardware swap) without the GarageNode controller
fighting the human. A `Suspended` status condition is set while paused. The
finalizer/delete path still runs so a suspended node can be deleted.
Implementation: `internal/controller/garagenode_controller.go` (Reconcile,
just after the finalizer block).

### Operation Status

Triggered operations (snapshot, repair, scrub) record their outcome in `status.lastOperation`:

```yaml
status:
  lastOperation:
    type: "Repair:Blocks"
    triggeredAt: "2026-05-02T10:00:00Z"
    succeeded: true
```

On failure, `succeeded: false` and `error` contains the message. The annotation is kept for retry.

### Cluster-health conditions (validated against Garage v2.3.0)

`updateStatusFromCluster` derives actionable conditions + a one-line
`status.layoutDiagnosis` (shown as the `Diagnosis` printcolumn) via
`setClusterHealthConditions` (`internal/controller/garagecluster_health.go`):

| Condition | True/False means | Lever |
|---|---|---|
| `QuorumAtRisk` | True when Garage reports `PartitionsQuorum < Partitions` — object writes to those partitions block | restore storage nodes, or `consistencyMode: dangerous` (NOT a layout edit) |
| `RemoteClustersHealthy` | False when a federated remote is unreachable > 1h (short blips ignored) | if a zone is permanently gone, reduce `replication.factor` |
| `FederationConfigured` | False when `spec.remoteClusters` is set but no `rpc_public_addr`/`publicEndpoint` (HelloMessage advertises the unroutable pod IP) | set `spec.network.rpcPublicAddr` or a `publicEndpoint` (also a webhook admission warning) |
| `PeerUnreachable` | True when a peer has been continuously down (`is_up:false`) beyond ~10m — surfaced in `status.unreachablePeers`. Detection is duration-based via `lastSeenSecsAgo` (the admin API can't read Garage's internal `Abandoned` state). | the operator's periodic `ConnectClusterNodes` nudge is the recovery path (esp. for single-link edge gateways) |

Validation notes: a roleless gateway is **not** a deterministic 403 — S3 auth
falls back to a quorum `get()` that succeeds in a healthy cluster; the
`capacity: nil` gateway role is a resilience/latency optimization (local-first
auth, decoupled from storage availability). `degraded` mode lowers only READ
quorum; it does **not** unblock stuck metadata (GarageKey/bucket) writes — those
need a reachable majority of roled nodes (`floor(N/2)+1`), and stale gateway
entries inflate N only in `consistent` mode (so tombstone cleanup matters for
admin-write availability).

---

## Admin API Client

Uses Admin API **v2** at `internal/garage/client.go`.

### Key Patterns

- Auth: `Authorization: Bearer <prefix>.<secret>` (prefix is 24 hex chars)
- Error helpers: `garage.IsNotFound(err)`, `garage.IsConflict(err)`, `garage.IsBadRequest(err)`
- bootstrap_peers format: `<64-char-hex-node-id>@<hostname>:<port>` (addresses without node IDs are ignored)

### Storage-tier reconnect after restart (#203)

`bootstrapCluster` is no longer gated off for storage-tier clusters
(previously it only ran for gateway-only clusters). It now runs every
reconcile as a runtime nudge: when the cluster's health probe shows any
local node disconnected, the operator hits each pod's Admin API and calls
`ConnectClusterNodes` against every sibling pod IP. This restores the
peers Garage's on-disk `peer_list` cache could not — when all storage
pods restart simultaneously, the cached IPs are stale and Garage cannot
find its siblings without an external nudge.

Layout assignment inside `bootstrapCluster` is short-circuited for
storage-tier clusters (`return nil` immediately after the reconnect half)
because the per-`GarageNode` reconciler owns storage layout entries.

For multi-cluster federation (`spec.remoteClusters` set), the
`healthStatus != healthy` reconnect branch is suppressed: federated
clusters permanently show `unavailable` until remote peers join, so the
local-only Admin nudge would just hammer ConnectClusterNodes on a
converged local quorum. The other two reconnect triggers (failed health
probe, `connectedNodes < len(nodes)`) still fire for federated clusters.

### SDK Evaluation (2026-04-12): Keep Hand-Crafted Client

**Decision: Keep hand-crafted client.**

Import test: `go get git.deuxfleurs.fr/garage-sdk/garage-admin-sdk-golang` succeeds (v0.0.0-20260106092213-694c0d66012a, hosted on `git.deuxfleurs.fr`). However, migrating adds risk with no meaningful benefit: our custom error helpers (`IsNotFound`, `IsConflict`, `IsBadRequest`) parse HTTP status codes directly and would need wrappers around SDK types, and the external forge is not a standard Go module proxy (no GOPROXY cache guarantee). The hand-crafted client covers all endpoints the operator actually uses.

**Spec endpoints NOT covered by our client** (not needed by operator today):

| Endpoint | OperationId | Notes |
|----------|-------------|-------|
| `GET /check` | CheckDomain | DNS check helper |
| `GET /metrics` | Metrics | Prometheus scrape endpoint |
| `GET /v2/GetAdminTokenInfo` | GetAdminTokenInfo | Token introspection |
| `GET /v2/GetCurrentAdminTokenInfo` | GetCurrentAdminTokenInfo | Self-info |
| `GET /v2/ListAdminTokens` | ListAdminTokens | |
| `POST /v2/CreateAdminToken` | CreateAdminToken | Used by GarageAdminToken CRD (TBD) |
| `POST /v2/DeleteAdminToken` | DeleteAdminToken | |
| `POST /v2/UpdateAdminToken` | UpdateAdminToken | |
| `POST /v2/GetBlockInfo` | GetBlockInfo | Block diagnostics |
| `GET /v2/ListBlockErrors` | ListBlockErrors | |
| `POST /v2/PurgeBlocks` | PurgeBlocks | |
| `POST /v2/RetryBlockResync` | RetryBlockResync | |
| `GET /v2/GetClusterStatistics` | GetClusterStatistics | Cluster-level stats |
| `GET /v2/GetNodeInfo` | GetNodeInfo | Per-node info |
| `GET /v2/GetNodeStatistics` | GetNodeStatistics | Per-node stats |
| `GET /v2/InspectObject` | InspectObject | Object block map |
| `POST /v2/PreviewClusterLayoutChanges` | PreviewClusterLayoutChanges | Dry-run layout |

---

## Known Limitations

| Feature | Notes |
|---------|-------|
| CORS/RoutingRules | Use S3 API directly (operator does not manage these) |
| Lifecycle scope | Garage subset only: Expiration (days/date) and AbortIncompleteMultipartUpload, with prefix and size filters |
| Permission Revocation | Removing from spec doesn't revoke - use `DenyBucketKey` API |
| TLS for APIs | External only - use service mesh or load balancer |
| Hot-reload config | NOT supported - config changes require pod restart |

---

## Implementation Notes

### Important Behaviors

1. **Config changes require pod restart** - Garage reads config once at startup, SIGHUP ignored
2. **Config hash annotation** - Changes trigger rolling restart via `garage.rajsingh.info/config-hash`
3. **Credential sync** - Key controller uses `ShowSecretKey: true` to detect/fix credential drift
4. **Layout conflicts** - Controller handles 409 Conflict with retry on next reconciliation
5. **Single-node clusters** - Supported for multi-cluster federation (1 replica per K8s cluster)
6. **Node identity in metadata_dir** - Garage stores `node_key` (Ed25519 private key) in `metadata_dir`. This file determines the node ID. Both storage and gateway clusters need persistent metadata to preserve node identity across restarts (see `garage/src/rpc/system.rs:gen_node_key`)
7. **No operator-internal S3 key** - Since v2.3.0, lifecycle rules are managed via the Admin API (`UpdateBucket`), so the operator no longer needs an internal S3 access key. The `--operator-namespace` flag is kept for backward-compat CLI parsing only and has no effect.

### Port Defaults

- RPC: 3901
- S3: 3900
- Admin: 3903
- K2V: 3904
- Web: 3902

---

## CI/CD

| Workflow | Description |
|----------|-------------|
| `test.yml` | Unit tests |
| `lint.yml` | golangci-lint |
| `test-e2e.yml` | E2E tests with Kind |
| `docker.yml` | Multi-arch images to `ghcr.io/rajsinghtech/garage-operator` |
| `helm.yml` | Helm chart lint, verify CRDs, verify version, push to OCI registry |
| `release.yml` | GitHub release with install.yaml |

```bash
# Install
kubectl apply -f https://github.com/rajsinghtech/garage-operator/releases/latest/download/install.yaml

# Release
make release VERSION=v0.6.18   # bump chart, commit, tag, push — all in one step
```

### Chart version management

The in-repo `charts/garage-operator/Chart.yaml` (version + appVersion) and
`charts/garage-operator/values.yaml` (image.tag) MUST match the latest release
tag. The `helm.yml` CI workflow has a `verify-version` job that fails the tag
push if these three values don't match the tag, and `release.yml` now runs
`make helm-verify-version` as its first step so a mismatch fails the Release
job loudly before any changelog/GitHub-release is created. Always cut a
release with `make release VERSION=vX.Y.Z` (bumps Chart.yaml/values.yaml,
verifies them, commits, tags, and pushes atomically) rather than the
individual `chart-bump`/`commit`/`tag` steps by hand — doing those manually
and skipping/misordering a step is exactly what produced the broken
v0.6.22/v0.6.23 releases on 2026-07-11 (see issue #278). The `appVersion`
field is what Helm uses as the default image tag when `values.yaml image.tag`
is empty; the previous practice of leaving them stale caused issue #260
(users installing from a local clone got a months-old operator image).

Note: `make release` pushes directly to `main`, which only works for an
actor with branch-protection bypass (repo admin); it must not be run from
CI with the default `GITHUB_TOKEN`, which is not an admin and would be
rejected by the 8 required status checks on `main`.

---

## TODOs

### E2E Test Gap: Credential Drift

Implemented in `test/e2e/e2e_test.go` (Gateway Cluster describe block):
- "should recreate key and update secret when key is deleted in Garage"
- "should successfully PUT and GET objects with credentials after drift recovery"

### Web API (s3_web) Support

Research Garage's Web API (port 3902) for static website hosting:
1. Understand how `[s3_web]` config section works (root_domain, index docs)
2. Determine if operator should expose web API configuration in GarageCluster spec
3. Consider adding HTTPRoute templates for web-hosted buckets
4. Investigate how website hosting interacts with GarageBucket's `website` field

### Per-node cycle annotation (deferred from #190)

Add a `garage.rajsingh.info/cycle: true` annotation on a single `GarageNode`
to perform a non-disruptive node swap:

1. Operator provisions a sibling GarageNode (new node ID, fresh PVCs, same
   zone/capacity/tags).
2. Waits for `sync_map_min` on the new node to reach the cluster's
   replication count (i.e. all partitions the new node owns are in sync).
3. Drains and removes the original node from layout, applies the new layout,
   deletes the old GarageNode + PVCs.

Use case: replace a node whose underlying disk is failing without taking the
cluster below quorum or losing the layout slot. A TODO marker is placed in
`internal/controller/garagenode_controller.go` near the top of `Reconcile`.

