# Garage Kubernetes Operator

<p align="center">
  <img src="logo.svg" alt="Garage Kubernetes Operator" width="128" height="128">
</p>

<p align="center">
  <strong>S3-Compatible Object Storage on Kubernetes</strong>
</p>

<p align="center">
  <a href="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml"><img src="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/rajsinghtech/garage-operator"><img src="https://goreportcard.com/badge/github.com/rajsinghtech/garage-operator" alt="Go Report Card"></a>
  <a href="https://github.com/rajsinghtech/garage-operator/releases/latest"><img src="https://img.shields.io/github/v/release/rajsinghtech/garage-operator" alt="Latest Release"></a>
  <a href="https://deepwiki.com/rajsinghtech/garage-operator"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
</p>

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed, self-hosted object storage with multi-cluster federation.

- **Declarative cluster lifecycle** — StatefulSet, config, and layout managed via CRDs
- **Bucket & key management** — create buckets, quotas, and S3 credentials with kubectl
- **Multi-cluster federation** — span storage across Kubernetes clusters with automatic node discovery
- **Gateway clusters** — stateless S3 proxies that scale independently from storage
- **Scale subresource** — `kubectl scale` and VPA/HPA support for GarageCluster
- **COSI driver** — optional Kubernetes-native object storage provisioning

## Custom Resources

| CRD | Description |
|-----|-------------|
| `GarageCluster` | Deploys and manages a Garage cluster (storage or gateway) |
| `GarageBucket` | Creates buckets with quotas and website hosting |
| `GarageKey` | Provisions S3 access keys with per-bucket permissions |
| `GarageNode` | Fine-grained node layout control (zone, capacity, tags) |
| `GarageAdminToken` | Manages admin API tokens |

## Install

```bash
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace
```

## Quick Start

First, create an admin token secret for the operator to manage Garage resources:

```bash
kubectl create secret generic garage-admin-token \
  --from-literal=admin-token=$(openssl rand -hex 32)
```

Create a 3-node Garage cluster ([full example](config/samples/garage_v1alpha1_garagecluster.yaml)):

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage
spec:
  replicas: 3
  zone: us-east-1
  replication:
    factor: 3
  storage:
    data:
      size: 100Gi
  network:
    rpcBindPort: 3901
    service:
      type: ClusterIP
  admin:
    enabled: true
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

Wait for the cluster to be ready:

```bash
kubectl wait --for=condition=Ready garagecluster/garage --timeout=300s
```

Create a bucket:

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageBucket
metadata:
  name: my-bucket
spec:
  clusterRef:
    name: garage
  quotas:
    maxSize: 10Gi
```

Create access credentials:

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageKey
metadata:
  name: my-key
spec:
  clusterRef:
    name: garage
  bucketPermissions:
    - bucketRef: my-bucket
      read: true
      write: true
```

Or grant access to **all buckets** in the cluster — useful for admin tools, monitoring, or [mountpoint-s3](https://github.com/awslabs/mountpoint-s3) workloads that span multiple buckets:

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageKey
metadata:
  name: admin-key
spec:
  clusterRef:
    name: garage
  allBuckets:
    read: true
    write: true
    owner: true
```

Per-bucket overrides layer on top of `allBuckets`, so you can combine cluster-wide read with owner on a specific bucket:

```yaml
  allBuckets:
    read: true
  bucketPermissions:
    - bucketRef: metrics-bucket
      owner: true
```

Import existing credentials from an inline spec or a Kubernetes secret:

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageKey
metadata:
  name: imported-key
spec:
  clusterRef:
    name: garage
  importKey:
    accessKeyId: "GKxxxxxxxxxxxxxxxxxxxxxxxx"
    secretAccessKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Or reference an existing secret — use `accessKeyIdKey`/`secretAccessKeyKey` to specify which keys to read from the source secret (defaults to `access-key-id`/`secret-access-key`):

```yaml
  importKey:
    secretRef:
      name: my-existing-creds
    accessKeyIdKey: AWS_ACCESS_KEY_ID
    secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
```

### Secret Template

By default the generated secret includes `access-key-id`, `secret-access-key`, `endpoint`, `host`, `scheme`, and `region`. Use `secretTemplate` to customize what gets included and how keys are named:

```yaml
secretTemplate:
  accessKeyIdKey: AWS_ACCESS_KEY_ID
  secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
  endpointKey: AWS_ENDPOINT_URL_S3
  regionKey: AWS_REGION
  includeEndpoint: false   # omit endpoint/host/scheme
  includeRegion: false     # omit region
```

This is useful when mounting the secret directly as environment variables with `envFrom` — only the keys your app expects will be present.

Get S3 credentials:

```bash
kubectl get secret my-key -o jsonpath='{.data.access-key-id}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.secret-access-key}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.endpoint}' | base64 -d && echo
```

## Gateway Clusters

Gateway clusters handle S3 API requests without storing data. They connect to a storage cluster and scale independently, ideal for edge deployments or handling high request volumes. See [gateway examples](config/samples/garage_v1alpha1_garagecluster_gateway.yaml) for more configurations.

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-gateway
spec:
  replicas: 5
  gateway: true
  connectTo:
    clusterRef:
      name: garage  # Reference to storage cluster
  replication:
    factor: 3       # Must match storage cluster
  admin:
    enabled: true
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

Key differences from storage clusters:
- Uses a **StatefulSet with metadata PVC** for node identity persistence (no data PVC)
- Registers pods as **gateway nodes** in the layout (capacity=null)
- Requires `connectTo` to reference a storage cluster
- Lightweight and horizontally scalable

For cross-namespace or external storage clusters, use `rpcSecretRef` and `adminApiEndpoint`:

```yaml
connectTo:
  rpcSecretRef:
    name: garage-rpc-secret
    key: rpc-secret
  adminApiEndpoint: "http://garage.storage-namespace.svc.cluster.local:3903"
  adminTokenSecretRef:
    name: storage-admin-token
    key: admin-token
```

### External Storage (NAS, Bare Metal)

To connect a gateway to a Garage instance running outside Kubernetes (e.g., on a NAS or bare-metal server), use `bootstrapPeers` instead of `clusterRef`. Get the node ID from your external Garage with `garage node id`.

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-gateway
spec:
  replicas: 2
  gateway: true
  replication:
    factor: 3  # Must match the external cluster
  connectTo:
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
    bootstrapPeers:
      - "563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d@nas.local:3901"
  admin:
    enabled: true
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

The gateway pods will connect to the external nodes via the RPC port and register as gateway nodes in the existing cluster layout.

## Manual Node Layout (GarageNode)

By default, GarageCluster uses `layoutPolicy: Auto` — the operator assigns every pod to the Garage layout using the cluster's zone and PVC-derived capacity. For fine-grained control over individual nodes, set `layoutPolicy: Manual` and create GarageNode resources.

Each GarageNode creates a single-replica StatefulSet and manages that node's layout entry (zone, capacity, tags).

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: storage-node-a
spec:
  clusterRef:
    name: garage
  zone: zone-a
  capacity: 500Gi
  tags: ["ssd", "high-performance"]
  storage:
    metadata:
      size: 10Gi
    data:
      size: 500Gi
      storageClassName: fast-ssd
```

### Gateway Nodes

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: gateway-node
spec:
  clusterRef:
    name: garage
  zone: zone-a
  gateway: true
  storage:
    metadata:
      size: 1Gi
```

### External Nodes

For nodes running outside Kubernetes (bare-metal, NAS, other clusters):

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: external-node
spec:
  clusterRef:
    name: garage
  nodeId: "563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d"
  zone: dc-1
  capacity: 1Ti
  external:
    address: nas.local
    port: 3901
```

External nodes require `nodeId` (64-hex-char Ed25519 public key). No StatefulSet is created — the operator only manages the layout entry.

### Per-Node Overrides

GarageNode supports overriding cluster defaults: `image`, `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, and `priorityClassName`.

### Status

```bash
kubectl get garagenodes
# NAME              CLUSTER   ZONE    CAPACITY   GATEWAY   CONNECTED   INLAYOUT   AGE
# storage-node-a    garage    zone-a  500Gi      false     true        true       5m
```

The controller auto-discovers node IDs from pods, reconciles layout drift (zone/capacity/tags), and handles node removal with replication-safe finalization.

## Scaling

GarageCluster supports the Kubernetes [scale subresource](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#scale-subresource), enabling `kubectl scale` and compatibility with autoscalers like VPA and HPA.

```bash
kubectl scale garagecluster garage --replicas=5
```

The operator populates `status.replicas`, `status.readyReplicas`, and `status.selector` for the scale subresource to function correctly.

## PVC Retention Policy

By default, PVCs created by a GarageCluster's StatefulSet are **not deleted** when the cluster is deleted or scaled down. This is intentional: Garage stores your data in those volumes, and automatic deletion would be irreversible.

The behavior is controlled by `spec.storage.pvcRetentionPolicy`:

| Field | Value | Behavior |
|-------|-------|----------|
| `whenDeleted` | `Retain` (default) | PVCs survive GarageCluster deletion — manual cleanup required |
| `whenDeleted` | `Delete` | PVCs are deleted automatically when the GarageCluster is deleted |
| `whenScaled` | `Retain` (default) | PVCs for scaled-down pods are kept (allows scaling back up) |
| `whenScaled` | `Delete` | PVCs for removed replicas are deleted on scale-down |

For dev/test clusters where you want automatic cleanup:

```yaml
spec:
  storage:
    pvcRetentionPolicy:
      whenDeleted: Delete
      whenScaled: Delete
```

Requires Kubernetes 1.23+. For production clusters, leave this unset (defaults to `Retain`) or set `whenScaled: Delete` only if you're confident scaled-down nodes won't need their data again.

## Website Hosting

Website hosting is **enabled by default** on every GarageCluster. Buckets with website hosting enabled are served at `<bucket>.<root-domain>` on port 3902.

The default `rootDomain` is `.<cluster-name>.<namespace>.svc`, so a bucket named `my-site` on a cluster named `garage` in namespace `default` is accessible at `my-site.garage.default.svc:3902`.

To use a custom domain:

```yaml
spec:
  webApi:
    rootDomain: ".web.garage.example.com"
```

Then enable website hosting on a bucket:

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageBucket
metadata:
  name: my-site
spec:
  clusterRef:
    name: garage
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
```

The site is served at `my-site.web.garage.example.com:3902`. Point DNS (wildcard CNAME or per-bucket) at the Garage service, and optionally front it with an ingress or HTTPRoute.

Other options:

```yaml
spec:
  webApi:
    rootDomain: ".web.garage.example.com"
    bindPort: 8080           # default: 3902
    addHostToMetrics: true   # adds domain to Prometheus labels
```

To disable website hosting entirely:

```yaml
spec:
  webApi:
    disabled: true
```

## K2V API

The [K2V API](https://garagehq.deuxfleurs.fr/documentation/reference-manual/k2v/) provides a key-value store on top of Garage. Add `k2vApi` to enable it:

```yaml
spec:
  k2vApi:
    bindPort: 3904  # default
```

Omit `k2vApi` entirely to disable. The K2V endpoint is exposed on the same Service as the S3 API.

## Multi-Cluster Federation

Garage supports federating clusters across Kubernetes clusters for geo-distributed storage. All clusters share the same RPC secret and Garage distributes replicas across zones automatically.

1. Create the same RPC secret in every Kubernetes cluster:
   ```bash
   SECRET=$(openssl rand -hex 32)
   kubectl create secret generic garage-rpc-secret --from-literal=rpc-secret=$SECRET
   ```

2. Configure `remoteClusters` and `publicEndpoint` on each GarageCluster:
   ```yaml
   apiVersion: garage.rajsingh.info/v1alpha1
   kind: GarageCluster
   metadata:
     name: garage
   spec:
     replicas: 3
     zone: us-east-1
     replication:
       factor: 3
     network:
       rpcSecretRef:
         name: garage-rpc-secret
         key: rpc-secret
     publicEndpoint:
       type: LoadBalancer
       loadBalancer:
         perNode: true
     remoteClusters:
       - name: eu-west
         zone: eu-west-1
         connection:
           adminApiEndpoint: "http://garage-eu.example.com:3903"
           adminTokenSecretRef:
             name: garage-admin-token
             key: admin-token
     admin:
       enabled: true
       adminTokenSecretRef:
         name: garage-admin-token
         key: admin-token
   ```

The operator handles node discovery, layout coordination, and health monitoring across clusters. Each cluster needs a `publicEndpoint` so remote nodes can reach it on the RPC port. See the [Garage documentation](https://garagehq.deuxfleurs.fr/documentation/cookbook/real-world/) for networking requirements.

## CSI-S3: Mount Buckets as Persistent Volumes

You can use [k8s-csi-s3](https://github.com/yandex-cloud/k8s-csi-s3) to mount Garage buckets as PersistentVolumes via FUSE. This is useful for workloads that need filesystem-style access to S3 data (e.g., shared config, static assets, ML datasets).

1. Create a dedicated bucket and key:
   ```yaml
   apiVersion: garage.rajsingh.info/v1alpha1
   kind: GarageBucket
   metadata:
     name: csi-s3
   spec:
     clusterRef:
       name: garage
     globalAlias: csi-s3
     quotas:
       maxSize: 5Ti
       maxObjects: 10000000
     keyPermissions:
       - keyRef: csi-s3-key
         read: true
         write: true
   ---
   apiVersion: garage.rajsingh.info/v1alpha1
   kind: GarageKey
   metadata:
     name: csi-s3-key
   spec:
     clusterRef:
       name: garage
     name: "CSI-S3 Storage Key"
     secretTemplate:
       name: csi-s3-secret
       namespace: csi-s3
       accessKeyIdKey: accessKeyID
       secretAccessKeyKey: secretAccessKey
       additionalData:
         endpoint: "http://garage.garage.svc.cluster.local:3900"
         region: "garage"
     bucketPermissions:
       - bucketRef: csi-s3
         read: true
         write: true
   ```

   The `additionalData` fields on the secret template provide the S3 endpoint and region that the CSI driver expects in the secret.

2. Install the CSI driver via Helm:
   ```bash
   helm repo add csi-s3 https://yandex-cloud.github.io/k8s-csi-s3/charts
   helm install csi-s3 csi-s3/csi-s3 \
     --namespace csi-s3 --create-namespace \
     --set storageClass.singleBucket=csi-s3 \
     --set 'storageClass.mountOptions=--memory-limit 1000 --dir-mode 0777 --file-mode 0666' \
     --set secret.create=false
   ```

   Setting `secret.create=false` tells the chart to use the `csi-s3-secret` created by the GarageKey controller.

3. Create a PVC and use it:
   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: my-s3-pvc
   spec:
     accessModes:
       - ReadWriteMany
     storageClassName: csi-s3
     resources:
       requests:
         storage: 10Gi
   ---
   apiVersion: v1
   kind: Pod
   metadata:
     name: test-s3-mount
   spec:
     containers:
       - name: app
         image: busybox
         command: ["sleep", "infinity"]
         volumeMounts:
           - name: data
             mountPath: /data
     volumes:
       - name: data
         persistentVolumeClaim:
           claimName: my-s3-pvc
   ```

> **Note:** FUSE-backed S3 mounts have limitations — no true random writes, no `fsync`, and higher latency than block storage. The csi-s3 namespace requires the `pod-security.kubernetes.io/enforce: privileged` label. For native S3 API access, use GarageKey secrets directly.

## COSI Support (Optional)

The operator includes an optional COSI (Container Object Storage Interface) driver that provides Kubernetes-native object storage provisioning.

### Enabling COSI

1. Install the COSI CRDs:
   ```bash
   for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
     kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/main/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
   done
   ```

2. Deploy the COSI controller:
   ```bash
   kubectl apply -k "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=main"
   ```

3. Install the operator with COSI enabled:
   ```bash
   helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
     --namespace garage-operator-system \
     --create-namespace \
     --set cosi.enabled=true
   ```

### Using COSI

1. Create a BucketClass:
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
       clusterNamespace: garage-operator-system
   ```

2. Create a BucketAccessClass:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketAccessClass
   metadata:
     name: garage-readwrite
   spec:
     driverName: garage.rajsingh.info
     authenticationType: Key
     parameters:
       clusterRef: garage
       clusterNamespace: garage-operator-system
   ```

3. Request a bucket:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketClaim
   metadata:
     name: my-bucket
   spec:
     bucketClassName: garage-standard
     protocols:
     - S3
   ```

4. Request access credentials:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketAccess
   metadata:
     name: my-bucket-access
   spec:
     bucketAccessClassName: garage-readwrite
     protocol: S3
     bucketClaims:
       - bucketClaimName: my-bucket
         accessMode: ReadWrite
         accessSecretName: my-bucket-creds
   ```

5. Use the credentials in your application:
   ```yaml
   env:
   - name: S3_ENDPOINT
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ENDPOINT
   - name: AWS_ACCESS_KEY_ID
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ACCESS_KEY_ID
   - name: AWS_SECRET_ACCESS_KEY
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ACCESS_SECRET_KEY
   ```

### COSI Limitations

- Only S3 protocol is supported
- Only Key authentication is supported (no IAM)
- Bucket deletion requires the bucket to be empty first
- Upstream COSI controller does not yet implement deletion — `DriverDeleteBucket` and `DriverRevokeBucketAccess` are implemented but won't be called until upstream adds support

## Documentation

- [Helm Chart](charts/garage-operator/) - Installation and configuration
- [Garage Docs](https://garagehq.deuxfleurs.fr/) - Garage project documentation

## Development

```bash
make dev-up       # Start kind cluster with operator
make dev-test     # Apply test resources
make dev-status   # View cluster status
make dev-logs     # Stream operator logs
make dev-down     # Tear down
```
