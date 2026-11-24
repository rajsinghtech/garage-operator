# Use CSI-S3 and COSI

The operator supports native S3 clients directly through `GarageKey` Secrets. CSI-S3 and COSI are optional integrations for workloads that need a Kubernetes storage/provisioning abstraction.

## CSI-S3

[k8s-csi-s3](https://github.com/yandex-cloud/k8s-csi-s3) mounts an S3 bucket through FUSE. It is useful for filesystem-oriented workloads, but it is not a block-storage replacement: expect higher latency, no true random writes, and no `fsync` semantics.

Create a bucket and key with the data keys expected by the CSI driver:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: csi-s3-key
  namespace: storage
spec:
  clusterRef:
    name: garage
  secretTemplate:
    name: csi-s3-secret
    accessKeyIdKey: accessKeyID
    secretAccessKeyKey: secretAccessKey
    additionalData:
      endpoint: http://garage.garage.svc:3900
      region: garage
  bucketPermissions:
    - bucketRef:
        name: csi-s3
      read: true
      write: true
```

Install CSI-S3 separately and configure its StorageClass to use the existing Secret. The CSI-S3 namespace needs a privileged Pod Security Admission exception because its node plugin uses FUSE.

One example using the upstream chart is:

```bash
kubectl create namespace csi-s3
kubectl label namespace csi-s3 pod-security.kubernetes.io/enforce=privileged
helm repo add csi-s3 https://yandex-cloud.github.io/k8s-csi-s3/charts
helm repo update
helm install csi-s3 csi-s3/csi-s3 \
  --namespace csi-s3 \
  --set storageClass.singleBucket=csi-s3 \
  --set 'storageClass.mountOptions=--memory-limit 1000 --dir-mode 0777 --file-mode 0666' \
  --set secret.create=false
```

The driver chart and its values can change independently of this operator.
Review the chart's current StorageClass/Secret wiring before production use;
the important contract here is that the `GarageKey` Secret has the access-key
and secret-key names selected by the driver, plus its S3 endpoint and region.

## COSI

COSI is a separate Kubernetes API and controller. The operator is a COSI driver implementation; it does not replace the cluster-wide COSI controller and does not use a per-driver sidecar.

Enable it in Helm:

```bash
helm upgrade --install garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --set cosi.enabled=true
```

Install the COSI CRDs and cluster-wide controller from the pinned revision
below, then create a `BucketClass` and `BucketAccessClass` with
`driverName: garage.rajsingh.info`.

The cluster-wide controller is a separate prerequisite. It reconciles
`BucketClaim` → `Bucket` and `BucketAccessClaim` → `BucketAccess` and populates the
`BucketClaimRef` and class parameters that this driver validates. The operator
does not run a per-driver sidecar.

```bash
COSI_REF=7b121df3e445b9f326d98ce7906205f0ce41c2e7
for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
  kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/${COSI_REF}/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
done
kubectl apply -k "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=${COSI_REF}"
# The kustomization at this revision references an older controller image
# (built before BucketAccessModes); run the controller built from 7b121df.
kubectl -n container-object-storage-system set image deployment/container-object-storage-controller \
  objectstorage-controller=gcr.io/k8s-staging-sig-storage/objectstorage-controller:v20260924-controllerv0.2.0-rc1-348-g7b121df@sha256:cc0c6da224328d355abd48cb76ae2cce19b86463f98650e2489206afd919b7d5
```

```yaml
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClass
metadata:
  name: garage-standard
spec:
  driverName: garage.rajsingh.info
  deletionPolicy: Delete
  parameters:
    clusterRef: garage
    clusterNamespace: storage
---
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketAccessClass
metadata:
  name: garage-readwrite
spec:
  driverName: garage.rajsingh.info
  authenticationType: Key
  parameters:
    clusterRef: garage
    clusterNamespace: storage
```

### Supported COSI revisions

COSI `v1alpha2` is unreleased upstream, so the driver is tested against one
pinned revision of the CRDs and controller:

| COSI revision | `BucketAccess` access field | Status |
|---|---|---|
| `7b121df` (2026-09-24) | `spec.bucketClaims[].accessModes` | Tested (CI pin) |
| `cc54469` (2026-08-06) and earlier `v1alpha2` | `spec.bucketClaims[].accessMode` | Supported for upgrades |

The driver maps `accessModes` onto a Garage key's bucket permission:
`objectData` and `objectMetadata` are unioned (read if either asks for read,
write if either asks for write), an unset category means "not required", and
`bucketMetadata` is not mapped (Garage's nearest permission, bucket ownership,
is broader). Requesting no category at all keeps `ReadWrite`.

On CRDs that still use the singular `accessMode`, the driver reads that field
instead, so upgrading the operator before COSI keeps `ReadOnly` and
`WriteOnly` grants as they are. Finalizer and annotation writes are
metadata-only patches, so neither CRD generation loses spec fields.

Only S3 and Key authentication are supported. `BucketAccess` requests using
`ServiceAccount` authentication are rejected by the driver with
`ServiceAccount auth not supported by Garage`; Garage has no IAM authentication
mode. `BucketClaim` creates a Garage bucket and `BucketAccess` creates a
key/credential Secret through operator-owned shadow `GarageBucket`/`GarageKey`
resources. `Delete` waits for the bucket to be empty; a non-empty bucket is not
silently destroyed. The driver records the failure in `Bucket.status.error`,
keeps the Garage cleanup finalizer, and retries with bounded backoff. Empty the
bucket and abort incomplete multipart uploads through S3, or change the
terminating Bucket to `deletionPolicy: Retain` when the remote data must stay.

The generated COSI access Secret contains the canonical keys
`COSI_PROTOCOL`, `COSI_S3_BUCKET_ID`, `COSI_S3_ENDPOINT`,
`COSI_S3_REGION`, `COSI_S3_ADDRESSING_STYLE`, `COSI_S3_ACCESS_KEY_ID`, and
`COSI_S3_ACCESS_SECRET_KEY`. The historical `S3_*` aliases are also retained:
`S3_BUCKET_ID`, `S3_ENDPOINT`, `S3_REGION`, `S3_ACCESS_KEY_ID`, and
`S3_ACCESS_SECRET_KEY`. The endpoint uses path-style addressing.

Bucket and access deletion is a two-controller handoff. The Garage protection
finalizer removes the remote bucket/key or revokes permissions, then releases
the upstream COSI protection finalizer. A retained bucket skips remote bucket
deletion; a `Delete` bucket must be emptied before cleanup can complete. When a
`Delete` Bucket is terminating, the driver temporarily keeps a matching
`BucketAccess`, its Garage key, and its generated Secret behind the driver's
cleanup finalizer. This gives a cleanup controller or administrator a way to
empty the bucket after a `BucketClaim` deletion has started. Once the bucket's
Garage cleanup finalizer is gone, access revocation resumes automatically. An
independently deleted access, or access to a `Retain` bucket, is revoked using
the normal path.

This is a cleanup handoff, not a purge policy: the operator never lists or
deletes bucket contents and does not add credentials to unrelated resources.
If access must be revoked immediately, retain the bucket first; setting
`deletionPolicy: Retain` lets the access cleanup proceed while preserving the
remote bucket.

If `cosi.namespace` differs from the target `GarageCluster` namespace, create a `GarageReferenceGrant` in that target namespace for the COSI shadow `GarageBucket` and `GarageKey` kinds.

The shadow resources live in the configured `cosi.namespace`, while COSI
`BucketClaim`, `BucketAccess`, and their Secrets remain in the requesting
namespace. The operator must watch both namespaces, and a cross-namespace
shadow reference is denied unless the destination namespace grants the shadow
namespace explicitly or through a matching `namespaceSelector`.
