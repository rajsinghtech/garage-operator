# Federate clusters

Garage federation creates one distributed layout across physical sites. Treat the layout as shared state: every writer must use the same RPC secret, advertise identity-specific addresses, and serialize topology changes across Kubernetes clusters.

## Network contract

Every identity-bearing Garage process that participates in a federated layout
needs an externally routable RPC address. A shared L4 load balancer can send a
request to a different Pod and fail the Garage node-ID handshake. Edge gateways
that intentionally run forward-only behind an unroutable boundary are a
different topology: they can serve local clients through their forward link, but
the remote storage site cannot dial or expose that gateway identity. Use one of:

- `storage.rpcPublicAddr` or `gateway.rpcPublicAddr` with `{ordinal}`;
- per-node `GarageNode.spec.network.rpcPublicAddr`;
- `publicEndpoint.loadBalancer.perNode`;
- `publicEndpoint.type: NodePort` with one external address per node;
- a stable per-node Service/hostname for a node-local pool.

The Admin API endpoint is for control-plane calls. It does not replace per-node RPC routing.

## Shared credentials

Create the same RPC Secret value at every site. Admin tokens can be site-specific when each site has its own Admin endpoint.

```bash
RPC_SECRET="$(openssl rand -hex 32)"
kubectl create secret generic garage-rpc-secret -n storage \
  --from-literal=rpc-secret="$RPC_SECRET"
```

Copy the Secret value through your normal secret-management system; do not commit it to a manifest.

## Configure a site

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage-us
  namespace: storage
spec:
  zone: us-east-1
  replication:
    factor: 3
    consistencyMode: consistent
    zoneRedundancyMode: AtLeast
    zoneRedundancyMinZones: 2
  storage:
    replicas: 3
    rpcPublicAddr: garage-us-storage-{ordinal}.example.net:3901
    metadata: {size: 10Gi}
    data: {size: 1Ti}
  network:
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
  publicEndpoint:
    type: LoadBalancer
    loadBalancer:
      perNode: true
  remoteClusters:
    - name: garage-eu
      zone: eu-west-1
      connection:
        adminApiEndpoint: https://garage-eu-admin.example.net:3903
        adminTokenSecretRef:
          name: eu-admin-token
          key: admin-token
        storageRpcEndpointTemplate: garage-eu-storage-{ordinal}.example.net:3901
```

`remoteClusters[].name` and `.zone` identify the remote site's routing metadata. The source site's committed layout remains the authority for role capacity and identity. `defaultCapacity` is compatibility-only and is rejected by current admission.

## Bootstrap sequence

1. Deploy each site's `GarageCluster` and wait for local storage identities to be `Connected` and `InLayout`.
2. Verify the RPC Secret is byte-for-byte identical at every site.
3. Verify each storage identity has a distinct reachable address.
4. Configure `remoteClusters` and remote Admin credentials on every participating site.
5. Wait for `FederationConfigured=True`, `RemoteClustersHealthy=True`, and no sustained `PeerUnreachable` condition.
6. Confirm Garage's layout history is settled before creating or removing another role.

```bash
kubectl get garagecluster -A \
  -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,DIAGNOSIS:.status.layoutDiagnosis
kubectl get garagecluster garage-us -n storage \
  -o jsonpath='{.status.remoteClusters}{"\n"}{.status.conditions}'
```

## Federated gateways

Gateway identities participate in `layout.all_nodes()` to replicate authentication tables locally. If a remote site has multiple gateways, set `gatewayRpcEndpointTemplate` on the consuming site's `remoteClusters[].connection`:

```yaml
connection:
  adminApiEndpoint: https://garage-eu-admin.example.net:3903
  gatewayRpcEndpointTemplate: garage-eu-gateway-{ordinal}.example.net:3901
  storageRpcEndpointTemplate: garage-eu-storage-{ordinal}.example.net:3901
```

Without per-ordinal routing, remote gateway roles can remain `Not connected` and FullReplication calls such as key or bucket writes can fail.

## Failure and retirement rules

Federation reconciliation is additive. An absent or unreachable remote does not authorize this operator to delete that site's roles. Retire a source identity at the site that owns it, or use the explicit federated `deletionPolicy: Drain` workflow.

Before changing topology across sites:

- set literal `replication.consistencyMode: consistent` everywhere;
- choose one layout writer and serialize all other writers;
- set `layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent` only when every unverified process satisfies that assertion;
- wait for the prior layout version to leave `Draining`.

`AssumeConsistent` is an explicit maintenance attestation, not a health check. It does not prove remote processes or applications are quiescent.

## Diagnose connectivity

| Condition | Meaning | First check |
| --- | --- | --- |
| `FederationConfigured=False` | No usable advertised RPC address | `storage.rpcPublicAddr`, per-node `network.rpcPublicAddr`, or `publicEndpoint` |
| `RemoteClustersHealthy=False` | A remote has been stale beyond the sustained threshold | Admin endpoint, remote token, and remote status |
| `PeerUnreachable=True` | A peer has stayed down long enough to require intervention | Per-node RPC route and node identity |
| `GatewayConnected=False` / `PartiallyConnected` | A configured reverse path is incomplete, or no gateway direction is connected | For bidirectional peering, restore the reverse route from storage to every gateway; for intentional forward-only edge mode, omit the public RPC route and accept that the remote site cannot reach or expose the gateway identity |
| `GatewayLayoutDegraded=True` | A managed gateway lacks its capacity-less role | `GarageNode.status.inLayout` and layout history |

See [troubleshooting](../operations/troubleshooting.md) before using `skip-dead-nodes` or `allow-missing-data`.
