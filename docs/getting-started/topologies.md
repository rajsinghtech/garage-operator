# Choose a topology

Start with the workload and identity shape you actually need. `GarageCluster` accepts four intentional shapes; combining fields from different shapes is rejected by admission.

| Shape | Fields | Operator-owned workload | Use it when |
| --- | --- | --- | --- |
| Storage | `storage` | One single-replica StatefulSet per managed StatefulSet-backed `GarageNode`; each `nodeLocalPools` entry adds a DaemonSet with one Garage member per selected Kubernetes Node | Durable object storage lives in this Kubernetes cluster |
| Unified | `storage` + `gateway` | Storage members plus one persistent-identity gateway `GarageNode` per gateway replica | Storage and S3 ingress should be managed together |
| Edge gateway | `gateway` + `connectTo` | One cluster-level gateway StatefulSet; storage is remote | S3 ingress belongs in another cluster or network |
| Management handle | `connectTo` only | No Garage workload | Manage buckets, keys, permissions, or layout for an existing Garage |

`storage` and `connectTo` are mutually exclusive. Federation of independently managed storage sites uses `remoteClusters`, not `connectTo`.

## Storage-only

Use this for the primary durable site when clients can reach its S3 Service directly or through a separate ingress.

```yaml
spec:
  zone: us-east-1
  replication:
    factor: 3
  storage:
    replicas: 3
    metadata: {size: 10Gi}
    data: {size: 1Ti}
```

Each Auto-mode replica becomes an operator-managed `GarageNode` with its own metadata identity volume and object-data volume. Scaling controls only this default Auto-managed group; manual nodes and node-local pools are independent.

## Unified storage and gateways

```yaml
spec:
  storage:
    replicas: 3
    metadata: {size: 10Gi}
    data: {size: 1Ti}
  gateway:
    replicas: 2
```

Unified gateways store no object blocks. Their metadata PVC preserves the capacity-less Garage identity and keeps authentication tables local. An explicit `gateway.metadata.type: EmptyDir` is supported but intentionally accepts identity churn and possible layout cleanup after restart.

In Auto mode, gateway replicas appear as gateway `GarageNode` resources and use single-replica StatefulSets. In Manual mode, create those gateway `GarageNode` resources yourself; ordinary `kubectl scale` is not available for a Manual tier.

## Edge gateways

An edge gateway has no local storage tier:

```yaml
spec:
  gateway:
    replicas: 1
    rpcPublicAddr: edge-gateway.example.net:3901
  connectTo:
    adminApiEndpoint: https://storage.example.net:3903
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
    adminTokenSecretRef:
      name: storage-admin-token
      key: admin-token
```

For bidirectional peering and remote visibility, the storage cluster must be able
to dial the gateway node back. Provide an externally routable address using
`gateway.rpcPublicAddr`, `network.rpcPublicAddr`, or a derived `publicEndpoint`.
Omitting all three is also supported for intentional forward-only operation: the
gateway can reach storage, but storage cannot dial it back or include the gateway
as a reachable remote identity. Admission warns about this choice, and a healthy
forward-only data-less gateway can still report `GatewayConnected=True`.
An edge gateway uses a single cluster-level config, so a shared address is safe only for one replica.
For multiple independently routed identities, use one one-replica edge
`GarageCluster` per route, or use a unified gateway tier with generated
`GarageNode`s and per-ordinal addresses. A shared L4 address cannot prove which
Garage identity answered.

Edge gateways use one cluster-level StatefulSet because their layout is owned by the remote storage cluster. Scale to zero and wait for capacity-less roles to retire before changing an edge metadata PVC source or claim template.

## Management handles

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: existing-garage
spec:
  connectTo:
    adminApiEndpoint: https://garage.example.net:3903
    adminTokenSecretRef:
      name: garage-admin
      key: admin-token
```

The operator creates no StatefulSet, PVC, Service, or Garage node for a management handle. It reports `ManagementHandleReady` when the Admin API is reachable; dependent bucket and key resources wait on that condition. Add `rpcSecretRef` only when the operator must derive new Garage key material through RPC. Imported keys and Admin-only operations do not require it.

## Manual storage layout

Use `layoutPolicy: Manual` when each storage identity has a distinct disk profile, external address, or ownership boundary. Create one `GarageNode` per identity. Manual mode is one-way: the operator does not convert a hand-managed layout back to Auto mode.

Manual nodes are still protected by the same identity and drain rules. See [manual nodes](../how-to/manual-nodes.md) and [storage identity and layout](../concepts/storage-and-layout.md).

## Node-local pools

Node-local pools add selector-driven HostPath identities to a cluster. They can coexist with Auto PVC storage, Manual `GarageNode` resources, and gateways, but require additional safety prerequisites. See the [node-local pool guide](../node-local-pools.md) before using them.
