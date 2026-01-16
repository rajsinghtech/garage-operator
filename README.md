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
    dataSize: 100Gi
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

Get S3 credentials:

```bash
kubectl get secret my-key -o jsonpath='{.data.access-key-id}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.secret-access-key}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.endpoint}' | base64 -d && echo
```

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