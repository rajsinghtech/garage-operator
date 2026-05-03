# Migration Guide

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
