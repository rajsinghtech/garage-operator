# Migration Guide

## Node-local pools (v0.7.0)

Node-local pools are an explicitly selected v1beta2 API under
`spec.storage.nodeLocalPools`. Released v0.6.29 does not contain the feature, so existing
v1beta1/v1beta2 clusters that do not declare node-local pools require no API migration.
Existing Manual SMB, Ceph, PVC, and external GarageNodes remain valid and can
coexist with pools in the same physical-site GarageCluster.

Pools follow the operator-wide Garage v2.0.0 minimum because the layout-history,
repair-worker, and block-error endpoints they use are present in Admin API v2;
Garage v2.4.0 is the tested default. Pools also require a cluster-scoped
operator installation and the validating and conversion webhooks. The shipped
webhook configurations use `failurePolicy: Fail`; disabling them is unsupported
because prepared storage deletion, immutable identity/path rules, topology-only
updates, and the v1beta1 preservation payload all depend on admission.

Development snapshots of PR #297 used unreleased names including
`spec.storage.workload: DaemonSet`, `spec.storage.pools`,
`spec.storage.nodePools`, `backing: StoragePool`, `backing: NodePool`,
`poolName`, `nodePoolName`, and their storage-pool/node-pool labels and
conversion annotations. There is deliberately no compatibility alias.
If a development cluster used those snapshots:

1. Stop the prototype operator and all affected identity-bearing workloads.
2. Record each Garage node ID, metadata path, pool membership, and retained
   data location, and verify no Pod still mounts those paths.
3. Update manifests to `spec.storage.nodeLocalPools`, `backing: NodeLocalPool`,
   `nodeLocalPoolName`, and `garage.rajsingh.info/node-local-pool`.
4. Install the final CRD, webhooks, and operator, then recreate or explicitly
   migrate the old generated children while every conflicting workload remains
   stopped.
5. Verify the same node IDs reconnect before resuming normal topology changes.

For disposable development clusters, recreation is safer. Never depend on CRD
field pruning to migrate storage state, and never run an old prototype workload
and a final pool workload against the same metadata directory.

Existing LocalPath PVC GarageNodes are not automatically adoptable because
their paths are PVC-specific and contain live `node_key` identities. Prefer
adding fresh HostPath pool identities, waiting for them to become healthy, and
then draining old GarageNodes one at a time. An identity-preserving LocalPath
cutover is an explicit offline, one-node-at-a-time procedure documented in
[the node-local-pool guide](docs/node-local-pools.md#migrating-existing-localpath-garagenodes).

In Manual mode, `spec.storage.replicas` and the default-group volume templates
remain ignored. Existing Manual manifests may normalize the
replica value to `0` and remove those unused templates; this does not request a
drain of user-owned GarageNodes.

PVC `selector` is now carried through every newly generated default storage
GarageNode (metadata, single data, and per-path data), Auto unified gateway,
edge gateway, and ordinary Manual GarageNode. Builds affected by the post-#190
or post-#209 projection regressions accepted cluster selectors but omitted them
from some generated per-node claims. Kubernetes cannot add a selector to or
reselect an existing PVC, so this upgrade deliberately does not rewrite old
StatefulSets, Bound claims, or Pending claims. New children, cycle replacements,
and newly created or recreated StatefulSets use the selector. An existing
StatefulSet keeps its historical claim template, so its controller may recreate
a missing claim without the selector. To repair a Pending claim,
drain/retire the exact Garage identity first, verify its Pod is gone, and then
replace the exact claim through the documented storage migration workflow.
Kubernetes does not dynamically provision a PV for a claim with a non-empty
selector. Pre-provision one distinct, access-mode/class-compatible PV per live
metadata/data/path claim, plus replacement headroom for add-before-remove
cycles. Classless static PVs usually require an explicit empty
`storageClassName`.

Here, an automatic cycle means only an established positive-capacity
StatefulSet-backed `GarageNode` whose metadata and data are repeatable dynamic
PVC templates or explicit `EmptyDir`. The operator repeats those templates and
their selectors into fresh sibling claims; it does not infer a destination from
a bound PV. `existingClaim`, gateway, external, and node-local-pool members are
rejected by cycle admission and by the runtime backstop. Replace those shapes
with an explicitly authored second `GarageNode` using distinct storage, then
drain the old identity. The operator never reuses or deletes source claims as
part of cycle automation.

PVC topology changes must not be combined with a `0 -> N` or `N -> 0` replica
transition. Scale to zero unchanged, wait for the serialized Garage drain and
workload removal, inspect retained claims, change the template while replicas
remain zero, then scale up separately. A retained PVC still has its old selector
and StorageClass: either intentionally reuse it to preserve identity or migrate
and remove it only after the role is safely retired. The operator never deletes
retained claims to make a template change take effect.

The historical `volumeClaimTemplateSpec` field was never applied by managed
workloads and arbitrary `dataSource`/`volumeName` settings can duplicate a
metadata `node_key` or bind identities to the wrong disk. New or changed values
are therefore rejected. An unchanged stored value is temporarily tolerated
with an admission warning so unrelated updates and removal remain possible.
Use the explicit size/class/access-mode/selector/metadata fields, or an ordinary
GarageNode `existingClaim` for a pre-provisioned PVC.

For any positive-capacity removal, first put every participating Garage process
in literal `consistent` mode and wait for `StorageRolloutReady=True` at the old
GarageCluster generation. Federated layouts additionally require the explicit
`AssumeConsistent` peer policy and exactly one topology-mutating writer across
the shared Garage layout at a time. Apply the later membership change as a
topology-only update.

After the final topology transaction and rollout have cleared at every site,
`degraded` and the default peer policy `Block` may be restored in a separate
configuration-only rollout if the deployment relies on that read-availability
tradeoff.

## Reserved Garage environment variables (v0.7.0)

Released operators let `spec.storage.env`, `spec.gateway.env`, and
`GarageNode.spec.env` override `GARAGE_CONFIG_FILE` and the RPC, Admin, and
metrics credential variables. This release reserves them: a silent override
removal changes the live mesh identity or the rendered consistency and timeout
settings a drain proof depends on. Objects carrying an override remain
readable, deletable, and repairable, but ordinary workload reconciliation fails
closed with `Ready=False` until the override is migrated. Clusters without one
are unaffected.

### `GARAGE_RPC_SECRET`

The operator never accepts an annotation as proof of credential equality. It
reads the active value from every Pod it can prove it owns through the exact
controller-owner chain, compares it with `spec.network.rpcSecretRef` and the
retained `<cluster>-rpc-secret` snapshot, and only then allows a roll.

1. Leave every override in place. Create a Secret holding the exact same 64-hex
   credential, then in one `v1beta2` update set `spec.network.rpcSecretRef` and
   the annotation `garage.rajsingh.info/migrate-legacy-rpc-secret: "true"`.
   Admission rejects this staging update if it also changes the image, replicas,
   topology, volumes, or any other environment entry.
2. If `<cluster>-rpc-secret` already exists it must be controlled by the exact
   GarageCluster and hold the same bytes. A mismatch is never overwritten or
   deleted; repair that retained mutable Secret to the active value while the
   old Pods still run.
3. Wait for the `Ready=False` message confirming that every managed RPC
   environment, the referenced Secret, and the snapshot agree. Then remove only
   the `GARAGE_RPC_SECRET` entries, keeping the typed reference and the
   annotation.
4. The cluster controller pins the matching snapshot immutable and consumes the
   annotation. GarageNode controllers stay frozen until that snapshot is
   immutable, so no node rolls onto an unproven credential.

### `GARAGE_CONFIG_FILE`

Remove the override from the API first. Old Pods stay frozen until you compare
the effective old TOML with the operator-rendered TOML and set
`garage.rajsingh.info/acknowledge-legacy-config-migration: "true"`. Byte
equality cannot prove configuration equivalence, so this step is an explicit
operator attestation. Keep it until the coordinated rollout completes, then
remove it.

### Overrides with no provable startup value

Broad `envFrom` sources, `GARAGE_RPC_SECRET_FILE`, and Admin/metrics credential
overrides have no recorded resolved value, so neither path above applies and a
config attestation cannot bypass them. Convert them to typed Secret references
under the previous operator before upgrading, or keep the workloads frozen and
migrate manually. The operator never guesses, deletes, or overwrites credential
bytes.

## Gateway tier (v0.5.x and later)

An edge gateway (`gateway` + `connectTo`) runs as one cluster-level
`StatefulSet <cr>-gateway`. In an Auto unified cluster (`storage` + `gateway`),
each generated gateway `GarageNode` owns a single-replica StatefulSet. Manual
unified clusters use ordinary user-owned gateway `GarageNode` resources. The
managed shapes use a small persistent metadata PVC (default 1Gi), unless
`metadata.type: EmptyDir` is explicitly selected with the resulting identity
churn. Persistent metadata holds the Ed25519 `node_key`, so a gateway process
keeps its Garage identity across Pod replacement. The data directory stays
`EmptyDir` because gateways store no object blocks.

Gateway pods participate in the cluster layout with `capacity: null` and a
`tier:gateway` tag (matching upstream `garage layout assign --gateway`). This
is required: Garage's S3 sig-auth path uses `get_local()` on `key_table`
(`src/api/common/signature/payload.rs:413`), which reads only the local DB.
FullReplication writes (`fullcopy.rs:113-118`) target `layout.all_nodes()`,
so a gateway outside the layout never receives those writes and every S3
request returns `403 Forbidden: No such key`.

> **If you were on v0.5.7 briefly:** it removed gateways from the layout.
> Don't stay there. Upgrade to v0.5.8+; the operator re-adds gateway pods on
> the next reconcile and S3 sig-auth recovers as soon as FullReplication
> catches up.

Unified per-GarageNode gateway StatefulSets leave the Kubernetes PVC-retention
policy unset, so metadata claims use the default `Retain`/`Retain`. Their
GarageNode finalizer retires the capacity-less role before deleting the child
workload. The cluster-level edge gateway StatefulSet instead explicitly uses
`Delete`/`Delete`: on scale-down Kubernetes removes the vacated Pod and claim,
then the operator discovers and tombstone-cleans the now-offline capacity-less
role. With `spec.layoutManagement.autoApply: true` the layout removal is applied
automatically; otherwise it surfaces via `status.pendingGatewayTombstones` and
the `GatewayTombstones` condition.

Set `spec.gateway.pvcRetentionPolicy` to override either managed gateway shape.
The field is independent from `spec.storage.pvcRetentionPolicy`; it does not
change positive-capacity member claims. A released v1beta1 edge gateway stores
the same setting at `spec.storage.pvcRetentionPolicy`; conversion now preserves
that value in the gateway field rather than dropping it. Existing edge
StatefulSets keep their observed policy when the v1beta2 field is omitted, and
an explicit policy is reconciled in place.

Override the metadata PVC size or StorageClass via `spec.gateway.metadata`:

```yaml
spec:
  gateway:
    replicas: 2
    metadata:
      size: 2Gi
      storageClassName: fast-ssd
```

This cluster-level field is used by Auto unified gateways and edge gateways;
Manual unified gateways configure metadata on each user-owned `GarageNode`.
`paths` and `volumeClaimTemplateSpec` are unsupported for gateways. A PVC
selector applies when a new claim is created in either unified or edge mode.
An edge StatefulSet cannot safely apply a live metadata
template change: scale `spec.gateway.replicas` to zero, wait for the
capacity-less roles to retire, make the change, and then scale it back up.

### Federated clusters: per-pod gateway endpoints (v0.5.9+)

Because gateways are in the layout, FullReplication tables (key_table,
bucket_table, …) need write/read quorum across `layout.all_nodes()` — which
includes gateway pods in every region. The storage-tier cross-region connect
loop alone is not enough: it uses one shared admin hostname for every remote
node, so a multi-pod gateway tier behind a single Tailscale/LB hostname only
ever lands one of N pods.

For each remote cluster in `spec.remoteClusters`, set
`connection.gatewayRpcEndpointTemplate` to a per-ordinal hostname pattern.
The operator iterates remote gateway nodes in the layout, parses each pod's
ordinal from its tag (e.g. `garage-gateway-0`), substitutes `{ordinal}` into
the template, and calls `ConnectClusterNodes` per pod.

```yaml
spec:
  remoteClusters:
    - name: ottawa
      zone: ottawa
      connection:
        adminApiEndpoint: "http://ottawa-garage.keiretsu.ts.net:3903"
        gatewayRpcEndpointTemplate: "ottawa-garage-gw-{ordinal}.keiretsu.ts.net:3901"
```

Provision the per-pod hostnames at the same time — typically one
`LoadBalancer` Service per gateway pod whose selector pins to
`statefulset.kubernetes.io/pod-name: <cr>-gateway-<ordinal>`. With the
Tailscale operator that looks like:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: garage-gateway-0-ts
  annotations:
    tailscale.com/hostname: ottawa-garage-gw-0
spec:
  loadBalancerClass: tailscale
  selector:
    statefulset.kubernetes.io/pod-name: garage-gateway-0
  ports:
    - name: rpc
      port: 3901
```

Without the template, federation works for storage but cross-region
FullReplication operations involving the gateway tier (e.g. cluster-wide
key creation, GetKeyInfo on `allBuckets: true` keys, DeleteKey) can hit
quorum timeouts.

## TL;DR for existing v1beta1 users

**You do not need to migrate anything.** Existing v1beta1 GarageCluster
manifests keep working without edits. The operator now serves two API
versions:

- **`garage.rajsingh.info/v1beta1`** — your existing manifests. Deprecated
  but still served in this release. A conversion webhook upgrades reads into
  v1beta2 before the controller sees them.
- **`garage.rajsingh.info/v1beta2`** — the new tier-based schema
  (`spec.storage`, `spec.gateway`). Use this for new manifests when you want
  to take advantage of the unified single-CR pattern (storage and gateway
  tiers managed together).

These v1beta1-native scenarios round-trip directly through the conversion
webhook:

1. v1beta1 storage cluster (`spec.gateway: false`, `spec.replicas`, `spec.storage`)
2. v1beta1 edge gateway (`spec.gateway: true`, `spec.connectTo`, `spec.replicas`)

The v1beta1 view cannot directly represent either a v1beta2 unified gateway
tier or `spec.storage.nodeLocalPools`. It projects the representable storage
fields and carries the v1beta2-only data in reserved conversion annotations:

- `garage.rajsingh.info/v1beta2-only` contains the relevant
  `gateway-tier-present` and/or `node-local-pools-present` components.
- `garage.rajsingh.info/v1beta2-gateway-tier` carries the unified gateway tier.
- `garage.rajsingh.info/v1beta2-node-local-pools` carries the node-local pool
  entries.

A complete v1beta1 read followed by a write therefore preserves the v1beta2-only
fields while still allowing edits to v1beta1-representable default-group
fields. The validating webhook rejects adding, removing, or mutating this
reserved transport through v1beta1. Use v1beta2 to modify a unified gateway or
node-local pools, and ensure clients preserve annotations on any v1beta1
read/modify/write.

## v1beta2 GarageCluster: unified storage + gateway tiers (issue #166)

In v1beta2 a single CR describes both a long-lived **storage** tier and a
**gateway** tier with persistent Garage identities by default. Gateway metadata
uses a PVC unless `gateway.metadata.type: EmptyDir` is explicitly selected;
gateway block data remains `EmptyDir`. v1beta1 kept the old `Gateway: bool`
plus top-level pod-template fields; v1beta2 collapses those into typed
sub-blocks.

### What changed

| Old field | New field |
|---|---|
| `spec.replicas` | `spec.storage.replicas` or `spec.gateway.replicas` |
| `spec.gateway: true` | omit `spec.storage`, set `spec.gateway: { ... }` (and `spec.connectTo` for edge clusters) |
| `spec.storage.metadata`, `spec.storage.data`, `spec.storage.metadataFsync`, etc. | unchanged path — now nested under the required `spec.storage` block |
| `spec.resources` | `spec.storage.resources` (or `spec.gateway.resources`) |
| `spec.nodeSelector` / `spec.tolerations` / `spec.affinity` / `spec.topologySpreadConstraints` | same fields under `spec.storage` / `spec.gateway` |
| `spec.podLabels` / `spec.podAnnotations` | same fields under `spec.storage` / `spec.gateway` |
| `spec.priorityClassName` | `spec.storage.priorityClassName` / `spec.gateway.priorityClassName` |
| `spec.securityContext` / `spec.containerSecurityContext` | same fields under each tier |
| `spec.podDisruptionBudget` | `spec.storage.podDisruptionBudget` |
| `spec.capacityReservePercent` | `spec.storage.capacityReservePercent` |

`spec.image`, `spec.imageRepository`, `spec.imagePullPolicy`, `spec.imagePullSecrets`,
`spec.serviceAccountName` remain at the top level (shared by both tiers).

### Current workload and identity shapes

| Member set | Workload and identity | Storage | Rollout/config |
|---|---|---|---|
| Default storage group (`layoutPolicy: Auto`) | One generated `GarageNode` per replica; each owns a single-replica StatefulSet | Metadata/data PVCs by default; explicit `EmptyDir` is supported | `OnDelete`; immutable per-node config revision |
| Manual/exceptional storage | One user-authored `GarageNode` per identity; managed nodes own a single-replica StatefulSet and external nodes own no workload | PVC, existing PVC (including SMB/Ceph CSI), `EmptyDir`, or external storage | Managed StatefulSets use `OnDelete` and immutable per-node config revisions |
| Node-local pool | One DaemonSet per `nodeLocalPools` entry; one generated identity on every selected Kubernetes Node | Metadata/data HostPaths | `OnDelete`; immutable pool-specific config revision |
| Unified gateway (`storage` + `gateway`) | Auto: one generated `GarageNode` and single-replica StatefulSet per replica. Manual: ordinary user-owned gateway `GarageNode` members | 1Gi metadata PVC by default (or explicit `EmptyDir`); data is `EmptyDir`; PVC policy defaults to Retain/Retain | Managed StatefulSets use `OnDelete`; immutable per-node config revision |
| Edge gateway (`gateway` + `connectTo`) | One cluster-level `<cr>-gateway` StatefulSet with the requested replica count | 1Gi metadata PVC per replica by default (or explicit `EmptyDir`); data is `EmptyDir`; PVC policy is Delete/Delete | `RollingUpdate`/`Parallel`; immutable shared config revision |

### Four valid CR shapes

1. **Unified cluster (most common)** — both tiers in one CR:

   ```yaml
   spec:
     storage:
       replicas: 3
       metadata: { size: 10Gi }
       data:     { size: 100Gi }
     gateway:
       replicas: 2
   ```

2. **Storage-only cluster** — headless backend, no app traffic terminating locally:

   ```yaml
   spec:
     storage:
       replicas: 3
       metadata: { size: 10Gi }
       data:     { size: 100Gi }
   ```

3. **Edge gateway** — gateway pods only, connecting to a remote storage cluster:

   ```yaml
   spec:
     gateway:
       replicas: 2
     connectTo:
       clusterRef:                    # same namespace
         name: garage-primary
       # OR
       adminApiEndpoint: "http://garage-primary.tailnet:3903"
       rpcSecretRef:                  # required for cross-namespace
         name: garage-rpc-secret
         key: rpc-secret
       adminTokenSecretRef:
         name: storage-admin-token
         key: admin-token
   ```

4. **Management handle** — no local workload; only a connection to an external
   Garage Admin API:

   ```yaml
   spec:
     connectTo:
       adminApiEndpoint: "https://garage-admin.example.com:3903"
       adminTokenSecretRef:
         name: storage-admin-token
         key: admin-token
   ```

The webhook rejects any CR that does not match one of these four shapes.

### Manual layout + GarageNode users (issue #173)

`GarageNode` stays on v1beta1; the conversion webhook handles your existing
v1beta1 parent transparently. No edits required.

If you do write the parent as v1beta2, apply the rename table above and add a
`spec.storage` block. Set `spec.storage.replicas: 0` explicitly and omit its
metadata/data templates when every member is an ordinary Manual `GarageNode`.
Omission defaults the field to three, but Manual storage policy does not create
or adopt a default operator-managed group: its replica count and cluster-level
metadata/data templates are ignored. Write `replicas: 0` and omit the templates
so the manifest states that ownership boundary unambiguously. Node-local pools
remain operator-managed even under this Manual default-group policy.

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata: { name: my-cluster }
spec:
  layoutPolicy: Manual
  replication: { factor: 3, consistencyMode: consistent }
  admin:
    adminTokenSecretRef: { name: my-cluster-admin-token, key: admin-token }
  storage:
    replicas: 0
    # podTemplate fields here become defaults for any GarageNode that
    # does not set its own (resources, securityContext, nodeSelector, ...).
---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata: { name: my-cluster-n1 }
spec:
  clusterRef: { name: my-cluster }
  zone: rack-1
  capacity: 5Ti
  storage:
    metadata: { size: 100Gi, storageClassName: fast-ssd }
    data:     { size: 5Ti,   storageClassName: bulk }
```

### Migration steps for existing two-CR deployments

If your current deployment has a separate `garage` (storage) CR and
`garage-gateway` edge CR (the pre-refactor pattern), do not create the unified
gateway tier beside it. The old edge CR owns different Garage node IDs, and its
primary Service normally occupies the `garage-gateway` name needed by the
unified tier's sibling Service. This is a serialized identity retirement and
replacement, not an in-place workload conversion.

First back up both CRs and record the exact old gateway node IDs from Garage's
live layout. Confirm they are capacity-less (`capacity: null`) gateway roles.
If the Garage layout is federated, externally serialize this operation with
every other site; the operator's in-memory coordinator is not a cross-cluster
lock.

Then retire the old edge identities while its controller and Admin connection
still exist:

```bash
NAMESPACE=garage-operator-system

# Use the v1beta2 endpoint even when the stored object originated as v1beta1.
# This preserves any v1beta2-only conversion payload while changing the exact
# field that controls the edge gateway workload.
kubectl -n "$NAMESPACE" patch \
  garageclusters.v1beta2.garage.rajsingh.info garage-gateway \
  --type=merge \
  -p '{"spec":{"gateway":{"replicas":0},"layoutManagement":{"autoApply":true}}}'
```

Wait until all recorded old gateway IDs are absent from the live Garage layout
and layout history is settled. An empty `status.pendingGatewayTombstones` alone
is not proof: it can be observed before stale-role discovery. If automatic
cleanup cannot complete, remove only the recorded capacity-less roles with the
Garage CLI and wait for the committed layout version to converge. Never use a
cluster-wide skip-dead-nodes operation as a substitute for identifying them.

Only after that proof, delete the old edge CR and wait for its workload and
Service to disappear:

```bash
kubectl -n "$NAMESPACE" delete garagecluster garage-gateway
kubectl -n "$NAMESPACE" wait --for=delete garagecluster/garage-gateway --timeout=10m
```

The edge StatefulSet's explicit `Delete`/`Delete` retention should remove its
metadata claims as it scales down, before the operator tombstone-cleans the
offline roles. Do not use a broad label deletion: gateway volumeClaimTemplates
are not guaranteed to carry an instance label. If a claim is orphaned, resolve
its exact name and owner after the old Pods and StatefulSet are gone, and delete
it explicitly only after its recorded node ID is absent from every
active/draining layout version.

Now apply the combined CR:

```bash
kubectl apply -f garage-combined.yaml
```

After the operator reconciles, you should see:

- `kubectl -n $NAMESPACE get garagenode -l garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage`
  — operator-generated default-group and node-local storage identities. Ordinary
  user-authored Manual GarageNodes are not automatically given these labels;
  list all GarageNodes and select the rows whose `spec.clusterRef.name` is
  `garage` (and whose `spec.gateway` is not true), or add your own query labels.
- `kubectl -n $NAMESPACE get garagenode -l garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=gateway`
  — one generated, capacity-less (`capacity: null`) gateway identity per replica.
- `kubectl -n $NAMESPACE get statefulset -l garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=gateway`
  — one single-replica StatefulSet per generated gateway identity. Each uses a
  small metadata PVC by default; gateway block data remains `EmptyDir`.
- `kubectl -n $NAMESPACE get garagecluster garage -o yaml` — the unified CR
  with both `spec.storage` and `spec.gateway` blocks.

Verify that the new gateway IDs are connected, hold `capacity: null` roles, and
are different from the retired edge IDs. The new parent cannot safely infer or
remove untagged roles owned by the deleted edge CR's different Kubernetes UID.

### Rollback

The current operator still serves v1beta1 through its conversion webhook and
accepts the two-CR topology. To return to it, reverse the same serialized
process: scale the unified gateway tier to zero, wait for its exact roles and
layout history to retire, remove `spec.gateway` from the storage CR, wait for
the sibling Service to disappear, and then recreate the edge gateway CR. Do not
run both gateway owners at once.

If you also downgrade the operator/CRDs, follow the target release's documented
API procedure after the topology is stable and remove any v1beta2-only fields
that release does not serve. Storage PVCs are not rewritten by this topology
change. Edge gateway metadata claims use `Delete` retention, while unified
per-GarageNode claims use Kubernetes' default `Retain` policy. Those workloads
have different owners, names, and Garage roles, so do not claim or rely on
gateway identity preservation across the two-parent conversion even when a
retained claim remains.

---

## v1alpha1 → v1beta1

v1beta1 is the first stable API version. All resources are `garage.rajsingh.info/v1beta1`.

### Will I lose data?

No. Migrating from v1alpha1 to v1beta1 does not delete or recreate your Garage cluster, buckets, or keys. Garage data lives in PersistentVolumes that the operator never touches during a migration — the operator only reconciles desired state against the Garage Admin API. Updating the `apiVersion` field or patching field formats in etcd is safe.

### Breaking Field Changes

These fields changed type and require updating existing manifests **before** or **after** upgrading, as the operator cannot deserialize objects with the old format.

#### GarageKey — `bucketPermissions[].bucketRef`

**Before (v1alpha1):** scalar string
```yaml
bucketPermissions:
  - bucketRef: my-bucket
    read: true
    write: true
```

**After (v1beta1):** object with `name` (and optional `namespace` for cross-namespace)
```yaml
bucketPermissions:
  - bucketRef:
      name: my-bucket
    read: true
    write: true
```

#### GarageBucket — `keyPermissions[].keyRef`

**Before (v1alpha1):** scalar string
```yaml
keyPermissions:
  - keyRef: my-key
    read: true
    write: true
```

**After (v1beta1):** object with `name` (and optional `namespace` for cross-namespace)
```yaml
keyPermissions:
  - keyRef:
      name: my-key
    read: true
    write: true
```

#### GarageCluster — `replication.zoneRedundancy`

**Before (v1alpha1):**
```yaml
replication:
  factor: 3
  zoneRedundancy: "AtLeast(2)"
```

**After (v1beta1):**
```yaml
replication:
  factor: 3
  zoneRedundancyMode: "AtLeast"
  zoneRedundancyMinZones: 2
```

#### GarageCluster — `admin.enabled` / `admin.bindPort` removed

**Before (v1alpha1):**
```yaml
admin:
  enabled: true
  bindPort: 3903
  adminTokenSecretRef:
    name: garage-admin-token
    key: admin-token
```

**After (v1beta1):** `enabled` and `bindPort` are removed. The admin API is always enabled on port 3903.
```yaml
admin:
  adminTokenSecretRef:
    name: garage-admin-token
    key: admin-token
```

### New: GarageReferenceGrant

Cross-namespace references (e.g. a `GarageKey` in `team-a` referencing a `GarageCluster` in `storage`) now require a `GarageReferenceGrant` in the target namespace. Without it, the webhook will reject the resource.

See the [README](README.md#namespace-isolation) for setup details.

---

### Upgrade Steps

The operator's HelmRelease uses `crds: CreateReplace` but Kubernetes blocks removing a version from a CRD's `spec.versions` while objects are still stored in etcd in that format. The upgrade handles this in two steps.

#### Known upgrade issue: GarageBucket CRD in v0.4.7/v0.4.8

v0.4.7 and v0.4.8 accidentally removed `v1alpha1` from the `GarageBucket` CRD's `spec.versions`. That is fine for fresh installs and for clusters whose CRD storage-version status has already been fully migrated, but it blocks upgrades from clusters that still record `GarageBucket` `v1alpha1` in CRD status.

Kubernetes rejects that CRD update when `garagebuckets.garage.rajsingh.info/status.storedVersions` still contains `v1alpha1`, even if `kubectl get garagebuckets.v1alpha1.garage.rajsingh.info` returns no objects. The apiserver validates the CRD status storage-version list, not just the currently visible objects.

The failure looks like:

```text
CustomResourceDefinition.apiextensions.k8s.io "garagebuckets.garage.rajsingh.info" is invalid:
status.storedVersions[0]: Invalid value: "v1alpha1": missing from spec.versions
```

If you hit this error while targeting v0.4.7 or v0.4.8, upgrade directly to the first release after v0.4.8 that restores the `GarageBucket` `v1alpha1` compatibility entry, or apply a CRD that includes both:

- `v1alpha1` with `storage: false`
- `v1beta1` with `storage: true`

After that CRD is accepted, continue the object migration below. Do not manually remove `v1alpha1` from `status.storedVersions` unless you have performed a proper Kubernetes storage migration and verified no data remains persisted in that version.

#### Flux

**Step 1 — Deploy v0.4.1** (adds `v1alpha1` as `served: false, storage: false`):

This allows the CRD upgrade to proceed. The operator starts up but cannot reconcile objects that still have the old field format — it logs deserialization errors until the objects are migrated.

**Step 2 — Migrate existing objects** (one-time, per cluster):

Run this script against each cluster to convert the stale etcd objects in-place using `kubectl replace`:

```bash
#!/usr/bin/env python3
import json, subprocess, sys

CONTEXT = sys.argv[1]  # e.g. my-cluster

for namespace in (sys.argv[2:] or ['default']):
    # Migrate GarageKey: bucketRef string → object
    result = subprocess.run(
        ['kubectl', '--context', CONTEXT, 'get', 'garagekey', '-n', namespace, '-o', 'json'],
        capture_output=True
    )
    data = json.loads(result.stdout)
    for item in data['items']:
        changed = False
        for bp in item.get('spec', {}).get('bucketPermissions', []):
            if isinstance(bp.get('bucketRef'), str):
                bp['bucketRef'] = {'name': bp['bucketRef']}
                changed = True
        if changed:
            item['metadata'].pop('managedFields', None)
            item['metadata'].pop('resourceVersion', None)
            subprocess.run(
                ['kubectl', '--context', CONTEXT, 'replace', '-n', namespace, '-f', '-'],
                input=json.dumps(item).encode()
            )
            print(f"Migrated GarageKey/{item['metadata']['name']}")

    # Migrate GarageBucket: keyRef string → object
    result = subprocess.run(
        ['kubectl', '--context', CONTEXT, 'get', 'garagebucket', '-n', namespace, '-o', 'json'],
        capture_output=True
    )
    data = json.loads(result.stdout)
    for item in data['items']:
        changed = False
        for kp in item.get('spec', {}).get('keyPermissions', []):
            if isinstance(kp.get('keyRef'), str):
                kp['keyRef'] = {'name': kp['keyRef']}
                changed = True
        if changed:
            item['metadata'].pop('managedFields', None)
            item['metadata'].pop('resourceVersion', None)
            subprocess.run(
                ['kubectl', '--context', CONTEXT, 'replace', '-n', namespace, '-f', '-'],
                input=json.dumps(item).encode()
            )
            print(f"Migrated GarageBucket/{item['metadata']['name']}")
```

Usage:
```bash
python3 migrate.py my-cluster-context garage
```

After migration, the operator recovers automatically (no restart needed — the reflector retries on backoff).

**Step 3 — Deploy v0.4.2+** (schema generator fix, no functional change):

Removes the v1alpha1 JSON schema file pollution from the `Generate & Validate Schemas` CI step.

#### ArgoCD

ArgoCD syncs CRDs and resources in separate waves, so the order of operations differs slightly:

**Step 1 — Bump the operator to v0.4.1 in your ArgoCD app** and let ArgoCD sync. The new CRDs are applied and v1alpha1 becomes `served: false`. The operator may log deserialization errors for objects with old field formats — this is expected and safe.

**Step 2 — Update your git manifests** to use `apiVersion: garage.rajsingh.info/v1beta1` and the new field formats listed above (both changes in the same commit). Applying the full corrected spec in one sync avoids ArgoCD getting stuck on the live-object decode mismatch.

**Step 3 — Let ArgoCD sync.** The updated resources are applied, etcd objects are updated to the new format, and the operator reconciles cleanly.

**Step 4 — Bump the operator to v0.4.2+** and let ArgoCD sync.

> If ArgoCD is already stuck (sync fails with `expected map, got &{...}`), run the migration script from the Flux section above to unblock it, then proceed from Step 3.

---

### Also update your manifests

Update all `GarageKey` and `GarageBucket` manifests in your GitOps repo to use the new field formats listed above before applying them, otherwise `kubectl apply` dry-runs will fail with SSA type-mismatch errors and Flux/ArgoCD will be unable to reconcile.
