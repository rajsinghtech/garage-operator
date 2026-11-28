# Upgrade and migration

Upgrade the operator chart and the Garage image as separate changes when possible. Read the release notes and compatibility matrix before changing a major behavior, API shape, storage template, or reserved environment.

## Chart upgrade

```bash
helm repo update  # if using a local repository mirror
helm upgrade garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.9.4 \
  --namespace garage-operator-system \
  --reuse-values
kubectl -n garage-operator-system rollout status \
  deployment/garage-operator-controller-manager --timeout=180s
```

For a new values file, render and inspect first:

```bash
helm template garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.9.4 --namespace garage-operator-system > rendered.yaml
```

CRDs are upgraded separately by Helm's CRD mechanism. Back up custom resources before a release that changes conversion or schema behavior.

### Ingress exposure is opt-in (chart `ingress.enabled`)

Releases before the `ingress.enabled` value always granted the operator
create/delete/patch/update/watch on `networking.k8s.io/ingresses` cluster-wide
and always watched Ingresses. Now this is controlled by the chart value
`ingress.enabled` (default `false`, like `gatewayAPI.enabled`), which renders
the `--enable-ingress` flag (`ENABLE_INGRESS`) and the Ingress RBAC rules, and
registers the Ingress watch only when set.

If any `GarageBucket` sets `spec.websiteExposure.ingress`, upgrade with
`--set ingress.enabled=true` (or add `ingress: {enabled: true}` to your values
file). Otherwise the bucket reports `WebsiteExposed=False` with reason
`IngressDisabled`; Ingresses created by the earlier release are left in place
(they keep serving and are still garbage-collected with their bucket) but are
no longer reconciled or cleaned up by the operator until you enable the value.
Installs that do not use Ingress exposure need no change and now run without
any Ingress RBAC. `--reuse-values` upgrades from a release without the value
render the new default (disabled), so pass `--set ingress.enabled=true`
explicitly if you need it.

Raw-manifest installs (`install.yaml` or the `config/default` kustomize base)
have no `ingress.enabled` value: they ship the Ingress RBAC rule but start the
manager without `--enable-ingress` (and without `--enable-gateway-api`), so
Ingress exposure stays off until you add the flag. See
[Raw manifests: website exposure flags](../getting-started/installation.md#raw-manifests-installyaml-kustomize-website-exposure-flags)
for a copy-paste `kubectl patch` and kustomize patch.

### SECURITY FIX (v0.9.1): cross-namespace cluster grants default to `bucketScope: Referenced`

This is a security fix for [#588](https://github.com/rajsinghtech/garage-operator/issues/588),
reported by [@kevinpark1217](https://github.com/kevinpark1217). Before v0.9.1, a
`GarageReferenceGrant` that let another namespace's `GarageKey` reference a
`GarageCluster` also let that key grant itself read, write, and owner on
**every** bucket in the cluster through `allBuckets`,
`bucketPermissions[].bucketId`, or `bucketPermissions[].globalAlias`. A
cross-namespace `GarageBucket` could also adopt any untracked bucket through
`spec.bucketId` and delete it with the default `deletionPolicy: Delete`.

From v0.9.1, `spec.to[].bucketScope` on a `GarageCluster` grant entry decides
this. Unset (and grants that omit `spec.to`) means `Referenced`: cross-namespace
keys only reach buckets backed by a `GarageBucket` they could reference by
`bucketRef`, and cross-namespace `GarageBuckets` cannot adopt existing buckets.
On upgrade the operator **revokes** permissions outside that scope from Garage
and reports `BucketScopeDenied` on the affected resources. Resources in the
cluster's own namespace are unaffected.

**To keep the previous cluster-wide behavior, add `bucketScope: Cluster` to
each `GarageCluster` grant target before upgrading:**

```yaml
spec:
  to:
    - kind: GarageCluster
      name: garage
      bucketScope: Cluster
```

The field is additive, so the v0.9.1 CRD must be installed before the grant can
carry it. Apply the new CRDs first (Helm installs them from the chart's
`crd-bases`), then patch the grants, then roll out the operator. To find
resources that rely on the old behavior before upgrading:

```bash
# Cross-namespace keys using allBuckets, bucketId, or globalAlias
kubectl get garagekeys -A -o json | jq -r '.items[]
  | select((.spec.clusterRef.namespace // "") != "" and .spec.clusterRef.namespace != .metadata.namespace)
  | select(.spec.allBuckets != null or ([.spec.bucketPermissions[]? | select(.bucketId or .globalAlias)] | length > 0))
  | "\(.metadata.namespace)/\(.metadata.name)"'
# Cross-namespace buckets adopted through spec.bucketId
kubectl get garagebuckets -A -o json | jq -r '.items[]
  | select((.spec.clusterRef.namespace // "") != "" and .spec.clusterRef.namespace != .metadata.namespace)
  | select((.spec.bucketId // "") != "")
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

A key that names another tenant's bucket by `bucketId` or `globalAlias` keeps
working under `Referenced` if that tenant grants the key's namespace access to
the backing `GarageBucket` (a `GarageBucket` target in a grant in the tenant's
namespace). After the upgrade, list what was denied with
`kubectl get garagekeys,garagebuckets -A -o json | jq -r '.items[] | select(any(.status.conditions[]?; .reason == "BucketScopeDenied")) | "\(.kind) \(.metadata.namespace)/\(.metadata.name)"'`.

Admission also rejects new out-of-scope `allBuckets` entries, `bucketId` or
`globalAlias` entries that match a `GarageBucket` the namespace may not
reference, and cross-namespace `spec.bucketId` adoptions. It also blocks removing
`spec.bucketId` from such an adoption, because that would leave the adopted
identity in status. One case can't be detected: a cross-namespace adoption
whose `spec.bucketId` was already removed before the upgrade looks like a
bucket the resource created. The `GarageBucket` audit above lists only
adoptions that still have `spec.bucketId`, so review older cross-namespace
`GarageBuckets` by hand if your tenants could have done this.

Downgrading to a release without `bucketScope` prunes the field and restores
cluster-wide reach for every cross-namespace grant (fail-open). Remove or narrow
the grants first if that's not acceptable.

## Garage image upgrade

Pin an image explicitly and let the operator coordinate identity-bearing rollouts:

```yaml
spec:
  image: dxflrs/garage:v2.6.0@sha256:4b5a318fc9fe2fbec5d3af590eeafe05d83492e6411266fa0b9e215c20264013
```

Do not change the image, volume topology, replica count, and replication factor in one unreviewed edit. Watch `StorageRolloutReady`, `StorageTopologyReady`, `NodeLocalPoolsReady`, and the Garage health conditions after each change.

## v1beta1 to v1beta2

Existing v1beta1 `GarageCluster` resources continue to work through conversion. New manifests should move from:

```yaml
spec:
  replicas: 3
  gateway: false
```

to:

```yaml
spec:
  storage:
    replicas: 3
```

For a unified cluster, declare both `storage` and `gateway` in v1beta2. Use the v1beta2 endpoint for tools that need gateway tiers, node-local pools, or conversion-preserved fields. See [API versions](../concepts/api-versions.md) and the repository's detailed [migration guide](https://github.com/rajsinghtech/garage-operator/blob/main/MIGRATION.md).

## Reserved environment migrations

Recent releases reserve Garage config and credential environment names so the operator can prove mesh identity and drain safety. Existing objects with these overrides reconcile only through a fail-closed migration.

### RPC secret override

1. Keep the old `GARAGE_RPC_SECRET` override in place.
2. Create a Secret with the exact same 64-hex value.
3. Set `spec.network.rpcSecretRef` and annotate `garage.rajsingh.info/migrate-legacy-rpc-secret=true` in a staging-only update.
4. Wait for the cluster status to confirm every managed Pod, Secret, and snapshot matches.
5. Remove only the old RPC environment entry; leave the typed reference and migration annotation until the operator consumes it.

The operator never overwrites a mismatched existing Secret or guesses the value.

### Config-file override

Remove `GARAGE_CONFIG_FILE` only after comparing the old effective TOML with the operator-rendered config, then add `garage.rajsingh.info/acknowledge-legacy-config-migration=true` until the coordinated rollout completes.

Broad `envFrom`, file-based credential overrides, and Admin/metrics credential overrides do not have an automatically provable startup value. Convert them before upgrading or use an explicit manual migration while workloads remain frozen.

## Node-local pools

Node-local pools are introduced in the v0.7 line and require Kubernetes `1.27+`, scheduling-gate support, enabled webhooks, and privileged workload namespaces. Existing LocalPath PVC `GarageNode`s are not automatically adoptable as node-local identities. Follow the [migration section in the node-local guide](../node-local-pools.md#migrating-existing-localpath-garagenodes).

## Rollback

Rollback the chart only when the CRD and controller contracts are compatible with the stored resources. Do not roll back an on-disk Garage layout or a completed identity drain by restoring a container image. If a rollout is stuck, use `garage.rajsingh.info/recover-storage-rollout` with a new nonce after correcting the workload-only failure; do not delete the identity's PVCs.
