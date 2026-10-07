# Compatibility matrix

This matrix describes the current release line and the boundaries verified by the repository's tests and generated manifests.

## Operator, Kubernetes, and Garage

| Component | Supported / tested boundary | Notes |
| --- | --- | --- |
| Operator `v0.8.x` | Current release line (first release `v0.8.0`) | Chart and image version `v0.8.2` in this repository |
| Kubernetes | `1.25+` ordinary shapes | `nodeLocalPools` require `1.27+` scheduling gates |
| Garage | `v2.0.0+` minimum | `/v2` Admin API only; Garage `0.x` and `1.x` are unsupported |
| Garage CI images | `v2.4.1` (default; Ginkgo and topology suites), `v2.0.0` (floor lane) | Digest-pinned in the workflows and e2e scripts. v2.0.0 is the only v2.0.x release. A nightly canary also runs the core path on a build of Garage's `main-v2` branch and is informational, not a merge gate |
| `kubernetes_discovery` | `v2.4.1` (one e2e lane) | Runs with the namespaced RBAC and a pre-installed CRD described in the Kubernetes discovery how-to; `v2.3.0` and `v2.4.0` crash at start with any discovery configured |
| Helm | `3.8+` | OCI chart installation |
| cert-manager | Required by default | Admission/conversion webhook certificates |

## Garage version-specific fields

| Feature | Minimum Garage | Older behavior |
| --- | --- | --- |
| Core cluster, layout, bucket, key, repair APIs | `v2.0.0` | Admin calls are unavailable on older versions |
| `GarageBucket.spec.lifecycle` | `v2.3.0` | Rule writes may be accepted but the operator reports `LifecycleConfigured=False` when not reflected |
| `database.engine: fjall`, `fjallBlockCacheSize` | `v2.1.0` | Unknown config is ignored and Garage keeps its default |
| `blocks.maxConcurrentReads` | `v2.1.0` | Unknown config is ignored |
| `blocks.maxConcurrentWritesPerRequest` | `v2.2.0` | Unknown config is ignored |
| `spec.discovery.consul`, `spec.discovery.kubernetes` | `v2.4.1` recommended; `v2.0.0+` except `v2.3.0` and `v2.4.0` | `v2.3.0` and `v2.4.0` panic at start when discovery is configured (see below) |
| `discovery.consul.tokenSecretRef` with `api: catalog` | `v2.3.0` | Use `api: agent` with Garage `v2.0` to `v2.2`; the webhook warns |

The operator reports the running Garage build in `GarageCluster.status.buildInfo.version`:

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.buildInfo.version}{"\n"}'
```

## Known-bad Garage releases

| Garage release | Problem | Operator behavior |
| --- | --- | --- |
| `v2.3.0` | Panics at start when Consul discovery is configured (upstream [#1416](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1416), [#1526](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1526)): no rustls crypto provider is installed. Kubernetes discovery shares the dependency set and is treated as affected | The webhook warns when `spec.image` carries this tag and Consul or Kubernetes discovery is enabled; `DiscoveryCompatible=False` reports it from the version Garage reports |
| `v2.4.0` | Panics at start with Consul **or** Kubernetes discovery (upstream [#1532](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1532), [#1536](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1536)) | Same as above |
| `v2.4.1` | Fixes the panic (installs the `ring` provider) | The built-in default image |

Without discovery configured, `v2.3.0` and `v2.4.0` start normally and the
operator does not warn. The panic happens at pod start and does not damage data;
rolling the image forward to `v2.4.1` or back, or disabling `spec.discovery`,
recovers the pods. See [Garage discovery](../how-to/kubernetes-discovery.md).

## Kubernetes feature boundaries

Node-local pools require all of the following:

- Kubernetes `1.27+` with end-to-end Pod scheduling-gate behavior;
- cluster-scoped installation so the operator can inspect Nodes and coordinate selectors;
- enabled admission/conversion webhooks;
- leader election;
- a privileged or equivalent HostPath exception on each pool workload namespace;
- one durable marker file in each metadata/data HostPath before activation.

The operator performs discovery, dry-run, scheduler probe, selector, and identity checks. A schema-valid pool can still remain blocked until the live cluster proves these conditions.

`volumeAttributesClassName` is optional and does not raise the `1.25+` floor for clusters that leave it unset. Using it requires Kubernetes `1.34+` (VolumeAttributesClass is GA there), or `1.31`–`1.33` with the `VolumeAttributesClass` feature gate and `storage.k8s.io/v1beta1` API enabled, plus a CSI driver that implements `ModifyVolume`. The operator does not probe the server version; on a cluster without the feature the `VolumeAttributesClassApplied` condition reports `Unsupported` and nothing else is blocked.

Pod extras (`initContainers`, `extraContainers`, `extraVolumes`) are standard
Kubernetes container and volume objects. Native sidecars (an init container with
`restartPolicy: Always`) need Kubernetes `1.29+` (beta) or `1.33+` (GA). The
operator does not probe the API server: on an older cluster the API server
rejects or drops the field and the StatefulSet update fails visibly.

## API compatibility

`GarageCluster.v1beta1` remains served for conversion and legacy clients but is deprecated. New tier-based, node-local, and management-handle manifests should use `v1beta2`. Other operator CRDs are `v1beta1`.

## Feature notes

- COSI uses the `objectstorage.k8s.io/v1alpha2` API and supports only S3/Key authentication. `BucketAccess` requests using `ServiceAccount` authentication are rejected by the driver; Garage has no IAM authentication mode.
- CSI-S3 is a separate FUSE integration and has filesystem-semantic limitations.
- `security.tls` is retained for compatibility but rejected because current Garage removed `rpc_tls`.
- `publicEndpoint.externalIP`, `remoteClusters[].defaultCapacity`, arbitrary managed `volumeClaimTemplateSpec`, and remote Kubernetes kubeconfig references are not supported by the current operator contract.
