# Compatibility matrix

This matrix describes the current release line and the boundaries verified by the repository's tests and generated manifests.

## Operator, Kubernetes, and Garage

| Component | Supported / tested boundary | Notes |
| --- | --- | --- |
| Operator `v0.7.x` | Current release line | Chart and image version `v0.7.7` in this repository |
| Kubernetes | `1.25+` ordinary shapes | `nodeLocalPools` require `1.27+` scheduling gates |
| Garage | `v2.0.0+` minimum | `/v2` Admin API only; Garage `0.x` and `1.x` are unsupported |
| Garage CI images | `v2.3.0`, `v2.2.0` | The exact image digests are pinned in samples/workflows |
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

The operator reports the running Garage build in `GarageCluster.status.buildInfo.version`:

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.buildInfo.version}{"\n"}'
```

## Kubernetes feature boundaries

Node-local pools require all of the following:

- Kubernetes `1.27+` with end-to-end Pod scheduling-gate behavior;
- cluster-scoped installation so the operator can inspect Nodes and coordinate selectors;
- enabled admission/conversion webhooks;
- leader election;
- a privileged or equivalent HostPath exception on each pool workload namespace;
- one durable marker file in each metadata/data HostPath before activation.

The operator performs discovery, dry-run, scheduler probe, selector, and identity checks. A schema-valid pool can still remain blocked until the live cluster proves these conditions.

## API compatibility

`GarageCluster.v1beta1` remains served for conversion and legacy clients but is deprecated. New tier-based, node-local, and management-handle manifests should use `v1beta2`. Other operator CRDs are `v1beta1`.

## Feature notes

- COSI uses the `objectstorage.k8s.io/v1alpha2` API and supports only S3/Key authentication. `BucketAccess` requests using `ServiceAccount` authentication are rejected by the driver; Garage has no IAM authentication mode.
- CSI-S3 is a separate FUSE integration and has filesystem-semantic limitations.
- `security.tls` is retained for compatibility but rejected because current Garage removed `rpc_tls`.
- `publicEndpoint.externalIP`, `remoteClusters[].defaultCapacity`, arbitrary managed `volumeClaimTemplateSpec`, and remote Kubernetes kubeconfig references are not supported by the current operator contract.
