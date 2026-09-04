# Upgrade and migration

Upgrade the operator chart and the Garage image as separate changes when possible. Read the release notes and compatibility matrix before changing a major behavior, API shape, storage template, or reserved environment.

## Chart upgrade

```bash
helm repo update  # if using a local repository mirror
helm upgrade garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.7.8 \
  --namespace garage-operator-system \
  --reuse-values
kubectl -n garage-operator-system rollout status \
  deployment/garage-operator-controller-manager --timeout=180s
```

For a new values file, render and inspect first:

```bash
helm template garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.7.8 --namespace garage-operator-system > rendered.yaml
```

CRDs are upgraded separately by Helm's CRD mechanism. Back up custom resources before a release that changes conversion or schema behavior.

## Garage image upgrade

Pin an image explicitly and let the operator coordinate identity-bearing rollouts:

```yaml
spec:
  image: dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690
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
