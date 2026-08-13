# Annotations and conditions

Annotations are imperative requests layered onto declarative resources. Most are consumed after success; failures retain the annotation for retry. Read `status.lastOperation`, conditions, and Events after every request.

## `GarageCluster` annotations

| Annotation | Value | Effect / risk |
| --- | --- | --- |
| `trigger-snapshot` | `true` | Snapshot metadata on all nodes; keeps the two newest snapshots |
| `trigger-repair` | `Tables`, `Blocks`, `Versions`, `MultipartUploads`, `BlockRefs`, `BlockRc`, `Rebalance`, `Aliases` | Start the named Garage repair |
| `scrub-command` | `start`, `pause`, `resume`, `cancel` | Control the block scrub worker; not `trigger-repair: Scrub` |
| `revert-layout` | `true` | Discard staged layout changes; does not undo an applied version |
| `retry-block-resync` | `true` or comma-separated hashes | Clear resync backoff for all or selected blocks |
| `purge-blocks` | comma-separated hashes | **Irreversible:** delete objects referencing selected blocks |
| `force-layout-apply` | `true` | Narrow initial/bootstrap override below factor; not a tombstone approval |
| `connect-nodes` | `nodeID@address:port,...` | One-shot external node bootstrap |
| `skip-dead-nodes` | `true` | Mark unresponsive nodes synced to unblock a draining layout |
| `allow-missing-data` | `true` | With `skip-dead-nodes`, permits missing-data recovery with data-loss risk |
| `retry-migration` | `true` | Retry legacy StatefulSet → per-`GarageNode` migration |
| `purge-cluster-layout` | `factor=N[,force]` | **Destructive:** coordinated replication-factor migration |
| `purge-cluster-layout-abort` | `true` | Abort factor migration; cannot undo an on-disk purge |
| `force-delete-unrevoked-operator-tokens` | `true` | **Federated/edge teardown risk:** continue when internally generated Admin-token rows could not be revoked through a surviving Admin API. Deletes only local one-time Secrets; a copied bearer may remain valid remotely. |
| `migrate-legacy-rpc-secret` | `true` | Stage exact migration from released RPC env override |
| `acknowledge-legacy-config-migration` | `true` | Attest equivalent rendered config after removing old file override |
| `drain` | `true` | Prepare explicit federated cluster/site drain |
| `recover-storage-rollout` | new nonce | Retry the exact persisted workload handoff after a workload-only failure |

## `GarageNode` annotations

| Annotation | Value | Effect |
| --- | --- | --- |
| `drain` | `true` | Prepare exact identity removal; wait for `DrainPrepared=True` before DELETE |
| `acknowledge-lost-source` | exact 64-hex Garage ID | Pair with `drain` only when the source/data is permanently lost |
| `cycle` | `true` | Add-before-remove replacement for eligible StatefulSet-backed storage |
| `maintenance.suspended` | use spec instead | The old pause annotation is not supported; use `spec.maintenance.suspended` |

## `GarageBucket` annotations

| Annotation | Value | Effect |
| --- | --- | --- |
| `cleanup-mpu` | `true` | Delete old incomplete multipart uploads |
| `cleanup-mpu-older-than` | duration such as `48h` | Threshold used with `cleanup-mpu`; invalid values default to `24h` |

## Important conditions

The controllers currently write the conditions below. A condition may be absent
when its feature is not configured or no exceptional state has occurred. Older
condition constants such as `ClusterHealthy`, `LayoutApplied`, `LayoutStaged`,
`NodesConnected`, `FederationReady`, `StatefulSetReady`, `ServicesReady`,
`BucketCreated`, the quota/website/alias conditions, the key conditions, the
node discovery/layout conditions, and the token conditions remain in the API
package for compatibility but are not emitted as independent status conditions.

| Resource | Condition | Meaning |
| --- | --- | --- |
| `GarageCluster` | `Ready` | Requested topology and managed workload are reconciled |
| `GarageCluster` | `PublicEndpointReady` | Configured public RPC Services are reconciled; relevant when a public endpoint is requested |
| `GarageCluster` | `ManagementHandleReady` | A connectTo-only handle can reach the external Admin API |
| `GarageCluster` | `GatewayConnected` | Gateway RPC state; bidirectional or intentional forward-only connectivity can be True, while a configured-but-unreachable reverse path is False/partial |
| `GarageCluster` | `GatewayLayoutDegraded` | True means an operator-owned unified gateway lacks its capacity-less layout role |
| `GarageCluster` | `GatewayTombstones` | True means stale gateway roles await removal or normal layout convergence |
| `GarageCluster` | `QuorumAtRisk` | True means one or more Garage partitions lack write quorum |
| `GarageCluster` | `PeerUnreachable` | True means a peer has sustained unreachability |
| `GarageCluster` | `RemoteClustersHealthy` | True/False summarizes stale federated remote sites |
| `GarageCluster` | `FederationConfigured` | True means identity-specific RPC routing is configured for federation |
| `GarageCluster` | `StorageScaleDownBlocked` | True means a requested Auto storage scale-down would violate the replication factor |
| `GarageCluster` | `StorageTopologyReady` | Auto storage membership and layout history are settled |
| `GarageCluster` | `LegacySTSMigrated` | Legacy cluster-level StatefulSet migration is complete or still in progress |
| `GarageCluster` | `NodeLocalPoolsReady` | Node-local pool membership is activated and retired safely |
| `GarageCluster` | `StorageRolloutReady` | Identity-bearing workload templates are converged |
| `GarageCluster` | `StorageDrainReady` | No active drain, or exact terminal drain evidence is complete |
| `GarageBucket` | `Ready` | Bucket reconciliation is complete |
| `GarageBucket` | `LifecycleConfigured` | Requested lifecycle rules were applied; False reports an application failure |
| `GarageBucket` | `BucketLookupStuck` / `BucketMetadataDegraded` | True reports repeated Admin lookup timeouts or metadata decode failures |
| `GarageKey` | `Ready` | Key, permissions, and requested Secret state are reconciled |
| `GarageNode` | `Ready` | Node identity/workload and observed Garage state are reconciled |
| `GarageNode` | `DrainPrepared` | True means the exact drain transaction has made deletion safe |
| `GarageNode` | `Cycling` | A requested add-before-remove identity cycle is active or blocked |
| `GarageNode` | `Suspended` | Literal condition set while `spec.maintenance.suspended` pauses reconciliation |
| `GarageAdminToken` | `Ready` | Static Admin bootstrap material is ready and referenced by the cluster |
| `GarageReferenceGrant` | `Ready` / `InUse` | Grant validity and whether resources currently reference it |

Key expiry is represented by `GarageKey.status.phase: Expired`, not by a
`KeyExpired` condition. `GarageAdminToken` is static bootstrap material, so its
compatibility expiry fields do not create a live expiry condition.

## Condition query

```bash
kubectl get garagecluster garage -n storage -o jsonpath='{range .status.conditions[*]}{.type}={.status} ({.reason}): {.message}{"\n"}{end}'
```
