# Manage nodes manually

Manual `GarageNode` resources give you one declarative control surface per Garage identity. Use them for mixed disk profiles, SMB or pre-provisioned claims, per-node RPC addresses, external nodes, or a gateway identity that must be owned independently of a cluster's default Auto group.

## Create a managed storage node

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: garage-storage-a
  namespace: storage
spec:
  clusterRef:
    name: garage
  zone: rack-a
  capacity: 2Ti
  storage:
    metadata:
      size: 10Gi
      storageClassName: fast-ssd
    data:
      size: 2Ti
      storageClassName: bulk-hdd
  network:
    rpcPublicAddr: storage-a.example.net:3901
```

Unless `external` or `backing: NodeLocalPool` is set, the node owns a single-replica StatefulSet and its identity-bearing storage. `nodeId` is optional for managed nodes: the operator discovers the exact ID from the owned Pod and pins it before writing status or layout.

## Existing claims and multi-disk data

Use `storage.metadata.existingClaim` or `storage.data.existingClaim` only for a claim whose contents and ownership are already understood. The operator does not infer identity from a claim name and does not clone or rebind a live metadata claim.

For multiple disks, use `storage.dataPaths` instead of `storage.data`:

```yaml
storage:
  metadata:
    size: 10Gi
  dataPaths:
    - path: /data/data0
      volume:
        size: 1Ti
        storageClassName: fast-ssd
    - path: /data/data1
      volume:
        size: 4Ti
        storageClassName: bulk-hdd
```

Garage treats capacities as striping weights; the filesystem enforces actual size. `data` and `dataPaths` are mutually exclusive. Path topology and volume sources are immutable while a live actor exists: scale or drain to zero first, wait for the identity to settle, then make the storage change.

## Gateway nodes

```yaml
spec:
  zone: edge
  gateway: true
  storage:
    metadata:
      size: 1Gi
```

Gateway nodes do not need a data volume or positive capacity. They still need persistent metadata unless identity churn is intentional.

## Pod extras on one node

`spec.initContainers`, `spec.extraContainers`, and `spec.extraVolumes` follow the
same override rule as `tolerations` and `envFrom`: a list that is set replaces the
tier's list for this node, the three lists are independent, and an explicit `[]`
opts the node out of an inherited list.

```yaml
spec:
  extraContainers: []   # this node runs without the cluster's ddns sidecar
```

They are rejected on external nodes and on node-local-pool-backed nodes. See
[Init containers, sidecars, and extra volumes](configuration.md#init-containers-sidecars-and-extra-volumes).

## External nodes

An external node manages a Garage process outside Kubernetes:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: remote-storage-a
  namespace: storage
spec:
  clusterRef:
    name: garage
  nodeId: 563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d
  zone: remote-a
  capacity: 4Ti
  external:
    address: garage-a.example.net
    port: 3901
```

The node ID is authoritative because the operator cannot inspect an owned Pod. External nodes participate in the same Garage layout and drain safety rules, but automatic replacement and block scans may require an explicit cross-site policy.

## Per-node RPC exposure

Set `network.rpcPublicAddr` to a stable `host:port`, or use a `publicEndpoint` LoadBalancer. A node-specific endpoint must route to that exact Garage identity. A shared address behind a load balancer is not a valid steady-state identity endpoint for federation.

## Maintenance and replacement

Suspend one node with `spec.maintenance.suspended: true` only for a planned operation that does not require the operator to mutate the node. For a replacement, prefer the cycle annotation for a supported StatefulSet-backed node:

```bash
kubectl annotate garagenode garage-storage-a -n storage \
  garage.rajsingh.info/cycle=true
```

The automatic cycle creates a fresh sibling, waits for it to join and settle, then drains the old positive-capacity role. It rejects gateways, external nodes, node-local members, `existingClaim`, and unsupported custom storage profiles. For those cases, create a distinct replacement `GarageNode`, verify it, and use the [prepared drain workflow](../operations/maintenance-and-recovery.md).

## Layout policy is one-way

`layoutPolicy: Manual` is a handoff boundary. Manual → Auto is rejected because the operator cannot safely infer ownership or identity for existing roles. Plan an additive replacement and drain rather than editing the policy in place.
