# API versions and compatibility

## Served versions

| Resource | Current | Compatibility |
| --- | --- | --- |
| `GarageCluster` | `garage.rajsingh.info/v1beta2` | `v1beta1` served through conversion; deprecated |
| `GarageBucket` | `garage.rajsingh.info/v1beta1` | `v1alpha1` deprecated (served with warning); stops being served in `v0.10.0` |
| `GarageKey` | `garage.rajsingh.info/v1beta1` | — |
| `GarageNode` | `garage.rajsingh.info/v1beta1` | — |
| `GarageAdminToken` | `garage.rajsingh.info/v1beta1` | — |
| `GarageReferenceGrant` | `garage.rajsingh.info/v1beta1` | — |

Write new `GarageCluster` manifests as `v1beta2`. Existing v1beta1 objects continue to be served through the conversion webhook. Tools that need unified storage + gateway tiers, node-local pools, or v1beta2-only fields must request the v1beta2 endpoint.

## Conversion caveats

The legacy v1beta1 shape has a flat `spec.replicas` and boolean `spec.gateway`. v1beta2 separates `spec.storage` and `spec.gateway` tiers. A v1beta2 object containing both tiers has no faithful v1beta1 representation; conversion returns the storage view and preserves v1beta2-only data in an internal reserved payload. A v1beta1 client cannot edit the hidden gateway or node-local-pool payload.

The scale subresource follows the requested API version:

```bash
# v1beta2: default Auto storage group
kubectl scale garagecluster garage --replicas=5

# Explicit v1beta1 endpoint for legacy edge-gateway scaling
kubectl scale garageclusters.v1beta1.garage.rajsingh.info edge --replicas=5
```

Manual storage and Manual gateways do not expose a controllable `/scale` group. Gateway replicas in v1beta2 are edited through `spec.gateway.replicas`.

## Webhook requirement

Conversion and validation require the webhook Service and its certificate. Install cert-manager before the chart, wait for the webhook endpoints, and do not disable webhooks when v1beta1 objects, node-local pools, PVC-backed storage, or prepared deletion are in use.

## Garage compatibility

The operator uses Garage's `/v2` Admin API and requires Garage `v2.0.0+`. Newer fields may be ignored by older Garage releases because Garage's TOML parser accepts unknown keys. The operator reports `LifecycleConfigured=False` when a lifecycle rule does not take effect and documents version-specific fields in the [compatibility matrix](../reference/compatibility.md).

## Planned Deprecations and Next-API-Version Cleanups

- **`GarageBucket` `v1alpha1` (`v0.10.0`):** Remains `served: true` with an API deprecation warning through `v0.9.x`, then transitions to `served: false` in `v0.10.0`. The non-served entry stays in CRD `spec.versions` until stored-version migration is complete.
- **Next API version (`v1beta2` / `v1`) cleanup bundle:**
  - Remove deprecated never-populated status fields (`GarageCluster.status.stagedLayoutVersion`, `stagedRoles`, `layoutPreview`; `GarageKey.status.effectivePermissions`; `GarageNode.status.storedData`, `repairInProgress`, `repairType`, `repairProgress`, `blockErrors`) and deprecated no-op `GarageCluster.spec.layoutManagement.minNodesHealthy`.
  - Add `+listType=map` / `+listMapKey` server-side-apply markers on slice-of-struct fields (such as `GarageCluster.spec.remoteClusters`, `GarageKey.spec.bucketPermissions`, and `GarageReferenceGrant.spec.from`/`to`).
  - Tighten `GarageReferenceGrant.spec.to` (`MinItems=1`) and related schema constraints.
  - Keep `GarageAdminToken` as-is unless scoped dynamic Admin API tokens are requested in a future release.
