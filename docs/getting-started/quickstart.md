# Quickstart

This creates a small persistent Garage cluster, a bucket, and a scoped S3 key. The example uses `v1beta2` for `GarageCluster`; all other current CRDs are `v1beta1`.

## 1. Create the admin token

The operator needs a token for Garage's Admin API. Keep it in the same namespace as the `GarageCluster`.

```bash
kubectl create namespace garage
kubectl create secret generic garage-admin-token -n garage \
  --from-literal=admin-token="$(openssl rand -hex 32)"
```

## 2. Apply a cluster

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
  namespace: garage
spec:
  image: dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690
  zone: lab
  replication:
    factor: 3
    consistencyMode: consistent
  storage:
    replicas: 3
    metadata:
      size: 10Gi
    data:
      size: 100Gi
  network:
    rpcBindPort: 3901
    service:
      type: ClusterIP
  s3Api:
    bindPort: 3900
    region: garage
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

Save it as `garagecluster.yaml` and apply it:

```bash
kubectl apply -f garagecluster.yaml
kubectl wait --for=condition=Ready garagecluster/garage -n garage --timeout=10m
```

Three storage replicas and `factor: 3` are appropriate for a durable test or production topology only when the cluster has three independent failure domains and sufficient capacity. For a local single-node experiment, use `factor: 1` and `EmptyDir`, and treat the data as disposable.

## 3. Inspect the operator's view

```bash
kubectl get garagecluster,garagenode -n garage
kubectl get garagecluster garage -n garage \
  -o jsonpath='{.status.phase}{"\\n"}{.status.layoutDiagnosis}{"\\n"}'
kubectl get garagecluster garage -n garage \
  -o jsonpath='{.status.conditions}'
```

`Ready=True` means the requested shape is reconciled. It does not mean every object has been backed up or that an external federation peer is healthy; inspect the health conditions and the [operations guide](../operations/day-2.md).

## 4. Create a bucket and key

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: app-data
  namespace: garage
spec:
  clusterRef:
    name: garage
  quotas:
    maxSize: 10Gi
---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: app-key
  namespace: garage
spec:
  clusterRef:
    name: garage
  bucketPermissions:
    - bucketRef:
        name: app-data
      read: true
      write: true
```

```bash
kubectl apply -f bucket-and-key.yaml
kubectl wait --for=condition=Ready garagebucket/app-data -n garage --timeout=5m
kubectl wait --for=condition=Ready garagekey/app-key -n garage --timeout=5m
kubectl get secret app-key -n garage \
  -o jsonpath='{.data.endpoint}' | base64 --decode; echo
```

The generated Secret contains `access-key-id`, `secret-access-key`, `endpoint`, `host`, `scheme`, and `region` unless a `secretTemplate` changes those names or omits optional values. See [buckets and credentials](../how-to/buckets-and-credentials.md) for least-privilege and import patterns.

## 5. Test S3 access

Use an S3 client from a Pod that can reach the cluster Service. The default endpoint for this example is `http://garage.garage.svc:3900`.

```bash
kubectl -n garage get secret app-key \
  -o jsonpath='{.data.access-key-id}' | base64 -d; echo
kubectl -n garage get secret app-key \
  -o jsonpath='{.data.secret-access-key}' | base64 -d; echo
```

Do not expose the Admin API or RPC port to untrusted networks. Publish S3 through the Service, gateway, Ingress, or Gateway API path appropriate for your environment.

## Next steps

- [Choose a topology](topologies.md) before adding gateways or federation.
- [Manage buckets and credentials](../how-to/buckets-and-credentials.md).
- [Understand identity and layout](../concepts/storage-and-layout.md) before scaling, replacing, or deleting storage.
- [Enable monitoring](../how-to/monitoring.md).
