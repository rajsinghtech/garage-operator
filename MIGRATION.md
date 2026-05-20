# Migration Guide

## v0.5.5 → v0.5.6: gateway tier becomes a StatefulSet with a persistent metadata PVC

### Why

Up through v0.5.5 the gateway tier ran as a Deployment with EmptyDir for both
`metadata_dir` and `data_dir`. Garage stores the Ed25519 `node_key` under
`metadata_dir`, so every gateway pod restart minted a brand-new node identity.
Each new identity that the operator added to the cluster layout produced a
fresh layout version, accumulating Draining versions over time and slowing
sync-map convergence on otherwise healthy clusters.

Switching the gateway to a small **persistent metadata PVC** preserves the
`node_key` across pod restarts. Gateways now re-join the layout with the same
UUID after a rolling update, so a routine rollout no longer generates new
layout versions. Garage's full-replica tables (key, bucket, alias, admin
token) still target every layout node, so the gateway's local FullCopy cache
keeps working — S3 reads do not need an extra hop to a storage node for key
or bucket lookups.

### What changes on upgrade

- The pre-v0.5.6 `Deployment <cr>-gateway` is deleted on first reconcile.
- A new `StatefulSet <cr>-gateway` is created in its place, provisioning a
  `<cr>-gateway-metadata-<ordinal>` PVC per replica (default size **1Gi**,
  cluster default StorageClass).
- The data directory stays `EmptyDir` — gateways do not store object blocks.
- PVC retention is `Delete`/`Delete`: when a replica is scaled away or the CR
  is deleted, the metadata PVC and node identity vanish with it. This
  preserves the existing "gateway data is cheap and ephemeral" mental model.
- Expect a brief gateway outage (<2 minutes) while the new StatefulSet rolls
  out. Storage-tier pods are untouched.

### How to customize

Override the default size or the StorageClass via `spec.gateway.metadata`:

```yaml
spec:
  gateway:
    replicas: 2
    metadata:
      size: 2Gi
      storageClassName: fast-ssd
```

All other `VolumeConfig` fields (`accessModes`, `selector`, `labels`,
`annotations`) are honored on the gateway metadata PVC.

### Tombstone cleanup

Superseded by the v0.5.6 → v0.5.7 migration below — gateway pods are removed
from the cluster layout entirely.

## v0.5.6 → v0.5.7 — gateway tier removed from cluster layout participation

The v0.5.6 gateway StatefulSet design preserved Ed25519 node identity across
restarts, eliminating per-restart layout churn. v0.5.7 extends that: gateway
pods no longer get added to the Garage cluster layout at all. Garage's
`nodes_of()` excludes gateway-tagged entries from `ring_assignment_data`
regardless (capacity is `None` for gateways, see
`src/rpc/layout/version.rs:118-134`), so layout participation was purely
cosmetic — and harmful at federation scale.

### Why

FullCopy tables (`key`, `bucket_v2`, `bucket_alias`, `admin_token`) replicate
to every node in `layout.all_nodes()` and require quorum on reads. When the
layout includes gateway pods from regions other than the requesting region,
those remote gateway pods are unreachable (the operator only calls
`ConnectClusterNodes` across regions for storage, not gateways). FullCopy
reads sit at the quorum boundary and produce 5-30 second timeouts on
`GetBucketInfo` / `GetKeyInfo` from regions other than the canonical one.

### One-time effect on first reconcile after upgrade

The operator runs a one-shot migration (`migrateGatewayOutOfLayout`) that
removes any `tier:gateway` role entries from the current layout (local for
unified clusters, remote for edge gateways via `spec.connectTo`). Subsequent
reconciles find nothing to remove and are no-ops.

Look for the log line `Migrated gateway tier out of layout` and a
`GatewayTombstones` condition on the GarageCluster status with the message
`Migrated gateway tier out of layout (removed N entries)`.

The deprecated `status.pendingGatewayTombstones` field is no longer written;
any leftover value from a previous operator version is cleared on the next
reconcile.

### Trade-off

Gateways no longer hold a local FullCopy cache. S3 GET / PUT against a
gateway pod adds 1-2 admin RPCs to a storage pod for key and bucket lookup.
Cross-region availability is the higher-value property here; the extra RPC
is small overhead for stable cross-region clusters. There is no opt-out for
this release.

### What changes for operators

- `garage status` (and `/v2/GetClusterLayout`) no longer lists gateway pods.
  Use `kubectl get pod -l garage.rajsingh.info/tier=gateway` to enumerate
  gateway pods, or `/v2/GetClusterStatus` (which still shows the gateway as
  a connected peer with no role assigned).
- The previously-staged "tombstone cleanup" reconciler has been removed.
- Edge-gateway clusters (gateway-only + `connectTo`) follow the same rule:
  the operator no longer registers gateway pod UUIDs in the remote storage
  cluster's layout. `ConnectClusterNodes` in both directions is unchanged.

### Rollback

Downgrade the operator image to v0.5.6. The gateway tier will start
re-registering its pods in the layout again on the next reconcile. Existing
storage-tier entries are untouched throughout — only gateway entries were
removed by the migration, and they're recreated by the older operator on
rollback.

## TL;DR for existing v1beta1 users

**You do not need to migrate anything.** Existing v1beta1 GarageCluster
manifests keep working without edits. The operator now serves two API
versions:

- **`garage.rajsingh.info/v1beta1`** — your existing manifests. Deprecated
  but served indefinitely. A conversion webhook upgrades reads into v1beta2
  before the controller sees them.
- **`garage.rajsingh.info/v1beta2`** — the new tier-based schema
  (`spec.storage`, `spec.gateway`). Use this for new manifests when you want
  to take advantage of the unified single-CR pattern (storage and gateway
  tiers managed together).

Two scenarios round-trip losslessly through the conversion webhook:

1. v1beta1 storage cluster (`spec.gateway: false`, `spec.replicas`, `spec.storage`)
2. v1beta1 edge gateway (`spec.gateway: true`, `spec.connectTo`, `spec.replicas`)

One scenario is **lossy when reading back as v1beta1**: a v1beta2 unified CR
that sets both `spec.storage` AND `spec.gateway`. v1beta1 has no
representation for "both tiers in one CR", so the v1beta1 view emits the
storage tier and tags the object with the annotation
`garage.rajsingh.info/v1beta2-only=gateway-tier-present`. Tools that
manage unified clusters must read/write v1beta2 directly.

## v1beta2 GarageCluster: unified storage + gateway tiers (issue #166)

In v1beta2 a single CR describes both a long-lived **storage** tier and an
ephemeral **gateway** tier. v1beta1 kept the old `Gateway: bool` plus
top-level pod-template fields; v1beta2 collapses those into typed sub-blocks.

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

### Workload differences

| | Storage tier | Gateway tier (v0.5.6+) |
|---|---|---|
| Workload | `StatefulSet` named `<cr>` | `StatefulSet` named `<cr>-gateway` |
| Metadata volume | PVC from `volumeClaimTemplates` | PVC from `volumeClaimTemplates` (default 1Gi) |
| Data volume | PVC from `volumeClaimTemplates` | `EmptyDir` |
| Update strategy | `RollingUpdate` (StatefulSet default) | `RollingUpdate` (StatefulSet default), `Parallel` pod management |
| Pod naming | ordinal (`<cr>-0`, `<cr>-1`, …) | ordinal (`<cr>-gateway-0`, …) |
| Node identity | persists across restarts (via metadata PVC) | persists across restarts (via metadata PVC) |
| PVC retention | `Retain`/`Retain` by default | `Delete`/`Delete` (gateway PVCs are cheap) |
| ConfigMap | per-pod when needed (Manual layout) | single shared ConfigMap |

Gateway-tier layout entries are still garbage-collected on every reconcile,
but with persistent identity (v0.5.6+) the only situation that generates
tombstones is a real scale-down (gateway PVC is deleted under the
`WhenScaled=Delete` retention policy, taking the node_key with it). When
`spec.layoutManagement.autoApply` is true the operator stages and applies
the removal; otherwise it surfaces stale entries via
`status.pendingGatewayTombstones` and the `GatewayTombstones` condition.

### Three valid CR shapes

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

The webhook rejects any CR that does not match one of these three shapes.

### Manual layout + GarageNode users (issue #173)

`GarageNode` stays on v1beta1; the conversion webhook handles your existing
v1beta1 parent transparently. No edits required.

If you do write the parent as v1beta2, apply the rename table above and add a
`spec.storage` block — Manual mode skips `validateStorageTier`, so cluster-level
metadata/data sizing is optional and `spec.storage.replicas` is ignored (set it
to `0` on v0.5.3+, or any value otherwise; the real count comes from the
`GarageNode` CRs).

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
`garage-gateway` CR (the pre-refactor pattern), the recommended migration is:

```bash
NAMESPACE=garage-operator-system

# 1. Delete the old gateway CR FIRST. Otherwise the new combined CR's gateway
#    tier and the old gateway StatefulSet will both try to manage the same
#    layout entries.
kubectl -n "$NAMESPACE" delete garagecluster garage-gateway

# 2. The old gateway StatefulSet's metadata PVCs become orphaned because they
#    were owned by the deleted GarageCluster. Delete them manually:
kubectl -n "$NAMESPACE" get pvc -l app.kubernetes.io/instance=garage-gateway
kubectl -n "$NAMESPACE" delete pvc -l app.kubernetes.io/instance=garage-gateway

# 3. Apply the new combined CR with both tiers:
kubectl apply -f garage-combined.yaml
```

After the operator reconciles, you should see:

- `kubectl -n $NAMESPACE get statefulset garage` — the storage tier (unchanged).
- `kubectl -n $NAMESPACE get deployment garage-gateway` — the new gateway tier
  (Deployment instead of StatefulSet, no PVCs).
- `kubectl -n $NAMESPACE get garagecluster garage -o yaml` — the unified CR
  with both `spec.storage` and `spec.gateway` blocks.

Stale gateway entries from the old StatefulSet pods will be detected by the
tombstone cleanup on the next reconcile. With
`spec.layoutManagement.autoApply: true` they are removed automatically.
Otherwise check the `GatewayTombstones` condition for guidance.

### Rollback

To revert to the previous operator release:

1. Re-apply your old two-CR manifest pair against the new (unified-schema)
   operator? **No — the new operator's webhook rejects the old schema.** You
   must downgrade the operator first.
2. Downgrade the operator image to the previous release.
3. Re-apply your old `garage` and `garage-gateway` CRs.

PVCs and Garage data on disk are untouched throughout — only the in-memory
layout entries change.

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
