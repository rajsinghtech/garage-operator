# Run gateways

Gateways serve S3 and Admin traffic but do not store object blocks. Choose a unified gateway when it belongs beside storage, or an edge gateway when its Pods are in a separate Kubernetes cluster or network.

## Unified gateways

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  storage:
    replicas: 3
    metadata: {size: 10Gi}
    data: {size: 1Ti}
  gateway:
    replicas: 2
    metadata:
      size: 1Gi
    resources:
      requests:
        cpu: 50m
        memory: 128Mi
```

In Auto mode the operator generates one gateway `GarageNode` and one single-replica StatefulSet per gateway identity. The metadata PVC holds `node_key`; block data is `EmptyDir`. Gateway roles are assigned `capacity: null` so Garage replicates authentication tables locally.

Use `kubectl get garagenodes` to inspect gateway roles:

```bash
kubectl get garagenodes -A \
  -l garage.rajsingh.info/tier=gateway \
  -o custom-columns=NAME:.metadata.name,ID:.status.nodeId,IN_LAYOUT:.status.inLayout,CONNECTED:.status.connected
```

If `GatewayLayoutDegraded=True`, inspect the named `GarageNode`s before forcing a layout action. A missing capacity-less role can cause signed requests to fail with `No such key`.

## Edge gateways

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage-edge
  namespace: edge
spec:
  gateway:
    # This edge shape has one shared config. Use one replica per independently
    # routed edge identity; use separate edge resources for multiple routes.
    replicas: 1
    rpcPublicAddr: edge-gateway.example.net:3901
  connectTo:
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
    adminApiEndpoint: https://garage-primary.example.net:3903
    adminTokenSecretRef:
      name: storage-admin-token
      key: admin-token
  admin:
    adminTokenSecretRef:
      name: edge-admin-token
      key: admin-token
```

`connectTo` requires either a same-namespace `clusterRef` or enough external endpoint/credential information to reach the storage cluster. The operator establishes connectivity in both directions when routing permits and periodically nudges reconnection when peers become sustained-unreachable.

For bidirectional peering and remote visibility, the storage cluster must be able
to dial the gateway identity at the address Garage advertises. Set
`gateway.rpcPublicAddr`, `network.rpcPublicAddr`, or a derived `publicEndpoint`.
If none is available, an edge gateway may intentionally operate forward-only:
the gateway can reach storage, but storage cannot dial it back or include it as a
reachable remote identity. The validating webhook warns about this configuration;
for a data-less gateway, a healthy forward connection can still produce
`GatewayConnected=True` with a forward-only reason. A single shared address is
safe only for one edge identity. An edge gateway uses one cluster-level StatefulSet and shared config, so
`{ordinal}` is not substituted in `gateway.rpcPublicAddr` for this shape and
`publicEndpoint.loadBalancer.perNode` does not by itself give each Pod a
different Garage advertisement. For several independently routable edge
identities, create one one-replica edge `GarageCluster` per route (or use a
unified gateway tier, whose generated `GarageNode`s support per-ordinal
addresses). On consuming federated sites, configure
`remoteClusters[].connection.gatewayRpcEndpointTemplate` only when the remote
gateway workload actually publishes matching per-ordinal routes.

## Public S3 endpoints

The primary API Service is named after the `GarageCluster`; gateway-only clusters use a gateway API Service. The status endpoint fields are the reliable way to discover rendered addresses:

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.endpoints}{"\n"}'
```

Configure `spec.network.service.type` for the S3/Admin API Service. Use `spec.publicEndpoint` for node-to-node RPC reachability, not for ordinary S3 ingress. The two concerns are deliberately separate.

## Gateway metadata and retention

Unified gateways default to retained metadata claims; edge gateways preserve the released delete-on-scale/delete-on-delete behavior unless you set `gateway.pvcRetentionPolicy`. Deleting gateway metadata creates a new identity and requires Garage layout cleanup.

To change an edge gateway's metadata source or PVC template:

1. Set `spec.gateway.replicas: 0`.
2. Wait until the old capacity-less roles have retired and the StatefulSet is gone or settled.
3. Change the metadata configuration.
4. Scale the gateway back up and verify `GatewayConnected` and `GatewayLayoutDegraded`.

An explicit `metadata.type: EmptyDir` is an ephemeral-identity choice. Use it only when identity churn and subsequent role cleanup are acceptable.

## Management handle instead

If you need no gateway workload and only want Kubernetes resources to manage an existing Garage, use a `connectTo`-only [management handle](../getting-started/topologies.md#management-handles).
