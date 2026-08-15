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
COSI_REF=cc544691e2ef7ddc2fba972d796ed3188ea46315
for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
  kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/${COSI_REF}/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
done
kubectl apply -k "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=${COSI_REF}"
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

Only S3 and Key authentication are supported. `BucketAccess` requests using
`ServiceAccount` authentication are rejected by the driver with
`ServiceAccount auth not supported by Garage`; Garage has no IAM authentication
mode. `BucketClaim` creates a Garage bucket and `BucketAccess` creates a
key/credential Secret through operator-owned shadow `GarageBucket`/`GarageKey`
resources. `Delete` waits for the bucket to be empty; a non-empty bucket is not
silently destroyed.

The generated COSI access Secret contains the canonical keys
`COSI_PROTOCOL`, `COSI_S3_BUCKET_ID`, `COSI_S3_ENDPOINT`,
`COSI_S3_REGION`, `COSI_S3_ADDRESSING_STYLE`, `COSI_S3_ACCESS_KEY_ID`, and
`COSI_S3_ACCESS_SECRET_KEY`. The historical `S3_*` aliases are also retained:
`S3_BUCKET_ID`, `S3_ENDPOINT`, `S3_REGION`, `S3_ACCESS_KEY_ID`, and
`S3_ACCESS_SECRET_KEY`. The endpoint uses path-style addressing.

Bucket and access deletion is a two-controller handoff. The Garage protection
finalizer removes the remote bucket/key or revokes permissions, then releases
the upstream COSI protection finalizer. A retained bucket skips remote bucket
deletion; a `Delete` bucket must be emptied before cleanup can complete.

If `cosi.namespace` differs from the target `GarageCluster` namespace, create a `GarageReferenceGrant` in that target namespace for the COSI shadow `GarageBucket` and `GarageKey` kinds.

The shadow resources live in the configured `cosi.namespace`, while COSI
`BucketClaim`, `BucketAccess`, and their Secrets remain in the requesting
namespace. The operator must watch both namespaces, and a cross-namespace
shadow reference is denied unless the destination namespace grants the shadow
namespace explicitly or through a matching `namespaceSelector`.
