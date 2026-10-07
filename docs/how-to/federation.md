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

## Designate the layout writer

A federated Garage cluster has one shared layout. Two sites that commit layout changes at the same time can overwrite each other's staged changes, so exactly one site should be allowed to write. Set `layoutManagement.siteRole` on every site:

| `siteRole` | Behavior |
| --- | --- |
| absent, or `Writer` | The site stages, applies, reverts and removes layout roles. This is the behavior of every release before the field existed. |
| `Follower` | The site never writes the layout. It still runs its pods, connects to the other sites, reads the layout and reports status. |

`siteRole` has no CRD default, so existing objects are not rewritten when you upgrade. Leaving it unset on every site keeps today's behavior.

Writer site:

```yaml
spec:
  layoutManagement:
    siteRole: Writer
```

Follower site. A follower must list at least one `remoteClusters` entry and must not set `connectTo`; both rules are enforced by the CRD itself:

```yaml
spec:
  layoutManagement:
    siteRole: Follower
  remoteClusters:
    - name: garage-us
      zone: us-east-1
      connection:
        adminApiEndpoint: https://garage-us-admin.example.net:3903
        adminTokenSecretRef: {name: us-admin-token, key: admin-token}
```

### Declare follower nodes on the writer

A follower cannot assign roles to its own nodes. The writer site declares each follower node as an [external `GarageNode`](manual-nodes.md#external-nodes), using the node's Garage ID, its zone, its capacity and an address the writer can reach:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: garage-eu-storage-0
  namespace: storage
spec:
  clusterRef:
    name: garage-us        # the writer GarageCluster
  nodeId: 563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d
  zone: eu-west-1
  capacity: 1Ti
  external:
    address: garage-eu-storage-0.example.net
    port: 3901
```

Until the writer has done this, the follower's nodes run but hold no role. The follower reports `AwaitingLayoutWriter=True` with reason `NodesWithoutRole`.

### What a follower reports

`status.layoutWriter.role` shows the role the controller is acting under, and two conditions explain what a follower is waiting for. The status fields and conditions are only written when `siteRole` is set.

| Condition | Meaning |
| --- | --- |
| `LayoutWriter=True` / reason `WriterSite` | This site may write the layout. |
| `LayoutWriter=False` / reason `FollowerSite` | This site performs no layout writes. |
| `AwaitingLayoutWriter=True` | Follower only. Work is waiting for the writer; the reason is one of `PendingRoleRemoval`, `NodesWithoutRole`, `PendingTombstones` or `ReplicationChange`, and the message lists every pending item. |
| `AwaitingLayoutWriter=False` / reason `NothingPending` | Follower only. Nothing is waiting. |

`Ready` is not driven false by `AwaitingLayoutWriter`: a follower's pods and connectivity can be healthy while it waits. A refused write also increments `garage_operator_layout_write_blocked_total{cluster,operation}`, and `garage_operator_layout_site_role{cluster,role}` exports the configured role.

Each site runs the full-redundancy proof for its own storage nodes only:
the nodes of its own non-external `GarageNode`s. Layout tags do not decide
this, because the writer tags the follower roles it declares with its own
cluster UID. A follower runs the proof only when its own `verify-redundancy`
annotation gets a new value, never on a topology change; the writer runs it
on request, or on a topology change when
`spec.layoutManagement.redundancyVerification.onTopologyChange` is `true`.
A finished proof reports `FullyReplicated=True/VerifiedLocal` with the
coverage, for example `5/12 federated storage nodes verified (writer-local)`,
and `status.redundancy.scope=Local`. Read the condition on every site for the
full picture.

Sites take turns through Garage itself: before starting a storage node a site
looks at the cluster-wide worker list for a blocks repair on another site's
node and waits (`Unknown/WaitingForOtherSite`) until a hold-down after the
last one it saw: 15 minutes on the writer, 16 to 25 minutes on a follower
(a stable offset per cluster). No lock is held, so a crashed site leaves
nothing to clean up. A federated site (one with
`spec.remoteClusters`, or whose layout holds storage roles of another
cluster) that leaves `siteRole` unset runs no proof at all and reports
`FullyReplicated=Unknown/SiteRoleUnset`, so sites never repeat each other's
repairs. Set `siteRole` on every site to use the proof.

### Scale-down and deletion at a follower

When a follower removes a node, the node's role stays in the shared layout until the writer removes it. The follower keeps the pod and the finalizer, and reports `PendingRoleRemoval`. Delete or retire the matching external `GarageNode` on the writer; the follower then finishes by itself once Garage's layout history has settled. Deleting a whole follower `GarageCluster` waits the same way.

Stale gateway entries are recorded in `status.pendingGatewayTombstones` and left for the writer to remove (`PendingTombstones`).

### Operations a follower refuses

- The `revert-layout`, `skip-dead-nodes` (with `allow-missing-data`) and `purge-cluster-layout` annotations are not executed on a follower. The operator removes them, records the refusal in `status.lastOperation`, and emits a `LayoutWriteBlocked` Warning event, so a request is never left to fire after a later promotion. Run them on the writer.
- Changing `spec.replication` on a follower is admitted with a warning. The replication factor and zone redundancy are part of the shared layout, so the follower reports `AwaitingLayoutWriter` with reason `ReplicationChange` until the writer's layout matches.

### Promote or demote a site

- **Promotion (`Follower` to `Writer`)** is always allowed so that failover works when the old writer is gone. Admission warns you to demote or permanently retire the previous writer first. There is no acknowledgement step, and two writers can commit conflicting layout versions.
- **Demotion (`Writer` to `Follower`)** is rejected while a storage drain, a managed storage rollout or a replication-factor migration is in progress, because a follower could not finish them. Wait for the transaction to complete, then demote.

Detecting a second site that commits layout changes anyway is not part of this release.

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
- choose one layout writer, set `layoutManagement.siteRole: Follower` on every other site, and serialize any remaining writers;
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
