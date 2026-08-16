# Troubleshooting

Start with the exact resource status, conditions, Events, Pod logs, and Admin endpoint reachability. Avoid deleting Pods or PVCs as a first response: an identity-bearing workload may be in a durable handoff.

## Fast triage

```bash
kubectl describe garagecluster garage -n storage
kubectl get garagecluster garage -n storage -o yaml
kubectl get garagenode -n storage -o wide
kubectl get pods,pvc,events -n storage --sort-by=.metadata.creationTimestamp
kubectl logs -n garage-operator-system \
  deployment/garage-operator-controller-manager --tail=200
```

## Cluster is not Ready

Check the most specific condition:

| Condition / signal | Likely cause | Action |
| --- | --- | --- |
| `StorageTopologyReady=False` | Member joining, draining, or waiting for an older layout | Wait for the named member/layout version; do not start another topology edit |
| `StorageScaleDownBlocked=True` | Scale-down would violate `replication.factor` | Add capacity or lower factor through the documented migration, not a forced delete |
| `StorageRolloutReady=False` | One identity-bearing Pod is in an OnDelete handoff | Inspect `status.storageRollout` and exact Pod/PVC UIDs |
| `QuorumAtRisk=True` | One or more partitions lack write quorum | Restore reachable storage nodes or follow Garage recovery; do not edit layout casually |
| `PublicEndpointReady=False` | RPC endpoint cannot be derived or is invalid | Configure per-node routable endpoint or correct the Service |
| `ManagementHandleReady=False` | External Admin API is unreachable | Check URL, token Secret, NetworkPolicy, DNS, and TLS proxy |
| `GatewayConnected=False` | Edge/gateway RPC connection is not established | Check both directions and every gateway endpoint |

## Bucket or key is stuck

```bash
kubectl get garagebucket,garagekey -n storage -o yaml
kubectl describe garagebucket app-data -n storage
kubectl describe garagekey app-key -n storage
```

Confirm the referenced cluster is `Ready`, the Admin token works, and any cross-namespace `GarageReferenceGrant` exists in the destination namespace. A lifecycle rule on Garage `<2.3.0` can be accepted but remains `LifecycleConfigured=False` when the Admin API cannot persist it.

### Bucket/key/token stuck Pending with a `ClusterNotReady` condition mentioning DNS

The `GarageCluster` itself can be `Running` (its pods are reachable directly by
IP) while `GarageBucket`/`GarageKey`/`GarageAdminToken` resources stay
`Pending` forever, because those controllers reach the cluster through its
`<name>.<namespace>.svc.<cluster-domain>` Service DNS name, not a pod IP. On a
cluster with a non-default Kubernetes DNS domain (e.g. a Talos cluster with
`cluster.network.dnsDomain` set), the operator's internal admin-API calls use
the wrong suffix and every lookup fails with `no such host`.

```bash
kubectl get garagekey app-key -n storage \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}{"\n"}'
```

If the message contains `no such host` naming a `.svc.cluster.local` address
that doesn't match your cluster's real DNS domain, set the operator's cluster
domain to match:

- **Helm**: `--set clusterDomain=<your-domain>` (see the
  [Helm reference](../reference/helm.md)).
- **Raw manifest (`install.yaml`/kustomize)**: uncomment and set the
  `CLUSTER_DOMAIN` env var on the `manager` container in
  `config/manager/manager.yaml`, or patch the running Deployment directly.

The operator's admin-API flag/env var is `--cluster-domain` / `CLUSTER_DOMAIN`
(default `cluster.local`); a restart is required after changing it since it is
read once at startup.

## `403 No such key` from S3

This often means a gateway identity lost its capacity-less layout role, not that the S3 key Secret is wrong.

The `garage.rajsingh.info/tier` selector below targets an operator-managed
label emitted on generated workloads. Treat it as a read-only diagnostic
selector; do not edit the label to change gateway behavior.

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.gatewayNodesNotInLayout}{"\n"}'
kubectl get garagenode -n storage \
  -l garage.rajsingh.info/tier=gateway -o yaml
```

Resolve the named gateway role/layout condition first. Forcing arbitrary layout changes can make the problem worse.

## Federation is unhealthy

Check that:

- every site uses the same RPC Secret bytes;
- every storage and gateway identity has its own routable address;
- remote Admin endpoints resolve and accept the configured tokens;
- `storageRpcEndpointTemplate` and `gatewayRpcEndpointTemplate` match actual ordinals;
- no network policy or firewall blocks reverse RPC;
- only one layout writer is changing topology.

`RemoteClustersHealthy` ignores short blips; `PeerUnreachable` indicates sustained unreachability and needs direct endpoint testing.

## Node-local pool is blocked

Inspect the parent condition and generated nodes:

The `garage.rajsingh.info/cluster` selector below uses an operator-managed
label on generated resources. It is a read-only diagnostic selector, not a
supported way to assign a node to a cluster.

```bash
kubectl get garagecluster garage-mixed -n garage -o yaml
kubectl get garagenode -n garage \
  -l garage.rajsingh.info/cluster=garage-mixed -o wide
kubectl get daemonset,pods -n garage
```

Common reasons are an API server below `1.27`, scheduling-gate capability proof not yet complete, a namespace Pod Security policy that rejects HostPath, overlapping selectors, a HostPath marker missing, a Node selected by two pools, or the shared Garage 256-role limit. Correct the prerequisite and let the operator resume; do not manually activate the DaemonSet Pod.

## A rollout is stuck

Read the exact actor in `status.storageRollout`, including workload UID, prior Pod UID, PVC UIDs, and Garage node ID. Correct only workload conditions such as scheduling, image pull, or volume attachment. Then request a retry with a new nonce:

```bash
kubectl annotate garagecluster garage -n storage \
  garage.rajsingh.info/recover-storage-rollout="$(date +%s)"
```

If the identity or claim evidence is inconsistent, stop and preserve the resources. Manual Pod/PVC deletion can turn a recoverable rollout into an identity replacement.

## Use dangerous recovery annotations carefully

`skip-dead-nodes` and `allow-missing-data` can unblock a layout only when an identity is permanently gone and the data-loss consequences are understood. `purge-blocks` is irreversible. `purge-cluster-layout` is a disruptive factor migration. Read the [operations reference](../reference/operations.md) and record an incident decision before using them.
