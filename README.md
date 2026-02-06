# Garage Kubernetes Operator

<p align="center">
  <img src="logo.svg" alt="Garage Kubernetes Operator" width="128" height="128">
</p>

<p align="center">
  <strong>S3-Compatible Object Storage on Kubernetes</strong>
</p>

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed, self-hosted object storage with multi-cluster federation.

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

Create a 3-node Garage cluster:

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

Get S3 credentials:

```bash
kubectl get secret my-key -o jsonpath='{.data.access-key-id}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.secret-access-key}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.endpoint}' | base64 -d && echo
```

## Gateway Clusters

Gateway clusters handle S3 API requests without storing data. They connect to a storage cluster and scale independently, ideal for edge deployments or handling high request volumes.

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
- Creates a **Deployment** instead of StatefulSet (no PVCs needed)
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
   kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/main/deploy/controller/controller.yaml
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
     bucketClaimName: my-bucket
     credentialsSecretName: my-bucket-creds
     protocol: S3
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