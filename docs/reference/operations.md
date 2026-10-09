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
| `connect-nodes` | `nodeID@address:port,...` | One-shot external node bootstrap; RPC-only repair remains reachable during safe layout/workload waits and is retained when a request fails |
| `skip-dead-nodes` | `true` | Mark unresponsive nodes synced to unblock a draining layout |
| `allow-missing-data` | `true` | With `skip-dead-nodes`, permits missing-data recovery with data-loss risk |
| `retry-migration` | `true` | Clear and re-drive the `LegacySTSMigrated` condition for legacy StatefulSet → per-`GarageNode` migration. The annotation is consumed once; inspect `Completed`, `InProgress`, or `Failed` and do not patch status manually. |
| `purge-cluster-layout` | `factor=N[,force]` | **Destructive:** coordinated replication-factor migration |
| `purge-cluster-layout-abort` | `true` | Abort factor migration; cannot undo an on-disk purge |
| `force-delete-unrevoked-operator-tokens` | `true` | **Federated/edge teardown risk:** continue when internally generated Admin-token rows could not be revoked through a surviving Admin API. Deletes only local one-time Secrets; a copied bearer may remain valid remotely. |
| `migrate-legacy-rpc-secret` | `true` | Stage exact migration from released RPC env override |
| `acknowledge-legacy-config-migration` | `true` | Attest equivalent rendered config after removing old file override |
| `drain` | `true` | Prepare explicit federated cluster/site drain |
| `recover-storage-rollout` | new nonce | Retry the exact persisted workload handoff after a workload-only failure |
| `verify-redundancy` | new token, for example a date | Run the full-redundancy proof: one tables repair and then one blocks repair per storage node that runs at this site (its non-external `GarageNode`s), one node at a time with a two-minute pause between nodes. This is the only way to run a proof unless `spec.layoutManagement.redundancyVerification.onTopologyChange` is `true`; the operator never starts one on upgrade. Works on writer and follower sites; in a federation each site waits until no other site ran a blocks repair within the hold-down (`WaitingForOtherSite`) and never repairs another site's nodes. Raise `spec.workers.resyncTranquility` above `0` first on busy disks: Garage tranquility is the only repair throttle. Not consumed: the operator records the token in `status.redundancy.verification.requestToken` and acts once per new value, so the annotation is safe to keep in Git. Ignored on a federated site without `siteRole`; waits while a drain or factor migration runs. Also retries nodes deferred with `RepairFailed` |
| `node-local-out-of-service` | `pool/kubernetes-node` | Stop one node-local Pod while retaining its Garage role and HostPath claim. Requires current `FullyReplicated=True/Verified`, live health, and every other selected member active. Single-site only. Incompatible with `node-local-replace-identity`. |
| `node-local-replace-identity` | `pool/kubernetes-node/old-64-hex-id` | Authorize one atomic layout version that assigns a new empty process and removes the named old role when nodes equal the replication factor. The old ID must still be the pinned identity. Single-site only. |

## `GarageNode` annotations

| Annotation | Value | Effect |
| --- | --- | --- |
| `drain` | `true` | Prepare exact identity removal; wait for `DrainPrepared=True` before DELETE |
| `acknowledge-lost-source` | exact 64-hex Garage ID | Pair with `drain` only when the source/data is permanently lost |
| `cycle` | `true` | Add-before-remove replacement for eligible StatefulSet-backed storage |

Maintenance suspension is not an annotation. Set
`spec.maintenance.suspended: true` on the `GarageNode`; the old
`garage.rajsingh.info/pause-reconcile` annotation is not supported.

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
| `GarageCluster` | `DiscoveryCompatible` | Written only while `spec.discovery.consul` or `spec.discovery.kubernetes` is enabled. `False` (reason `GarageVersionCrashesAtStart`) means a running node reports Garage v2.3.0 or v2.4.0, which panic at start with discovery configured; upgrade to v2.4.1+. `True` (reason `VersionSupported`) means no running node reports such a release. Informational: never changes `Ready` |
| `GarageCluster` | `FederationConfigured` | True means identity-specific RPC routing is configured for federation |
| `GarageCluster` | `StorageScaleDownBlocked` | True means a requested Auto storage scale-down would violate the replication factor |
| `GarageCluster` | `StorageTopologyReady` | Auto storage membership and layout history are settled |
| `GarageCluster` | `LegacySTSMigrated` | Legacy cluster-level StatefulSet migration. `True/Completed` means complete or no legacy StatefulSet; `False/InProgress` means it is being driven; `False/Failed` means inspect the message, correct the cause, and use `retry-migration`. |
| `GarageCluster` | `NodeLocalPoolsReady` | Node-local pool membership is activated and retired safely. `False/Stopping` means a requested service-hold Pod has not terminated; `False/OutOfService` means that Pod is gone and its role is retained until the hold annotation is removed |
| `GarageCluster` | `StorageRolloutReady` | Identity-bearing workload templates are converged |
| `GarageCluster` | `StorageDrainReady` | No active drain, or exact terminal drain evidence is complete |
| `GarageCluster` | `OperatorAdminTokenReady` | `True` (reason `Verified`) when the operator's dynamic Admin token is verified on every Ready managed Garage process; a missing, unscheduled, or stopped Pod does not block it. `False` with reason `ManagedPodsNotReady` names a Pod/GarageNode when no managed Pod is Ready, or when creating or replacing the token waits for every Pod; `NotVerified` and `Provisioning` cover the other waits; their underlying error is in the cluster's `OperatorAdminTokenNotReady` events. Once the token is authoritative, `False` blocks GarageKey and GarageBucket reconciliation. Written only when `spec.admin.adminTokenSecretRef` is set |
| `GarageCluster` | `FullyReplicated` | `True/Verified` only after a proof: settled layout, then per storage node of this site a clean full table sync and a clean blocks repair, then idle, error-free block resync through a quiet period. `True/VerifiedLocal` when other sites run storage nodes too: the message gives the coverage (`5/12 federated storage nodes verified (writer-local)`) and `status.redundancy.scope` is `Local`. `Unknown/NotVerified` after upgrade (baseline only), when a storage node was down after the last proof, or when the layout's storage nodes changed and `onTopologyChange` is off; set `verify-redundancy`. `Unknown/WaitingForOtherSite` while a requested proof waits for another site's blocks repair plus the hold-down. `False/Verifying` while the proof runs; `False/Partial` when the proof finished but nodes were deferred (listed in `status.redundancy.deferredNodes`); `False/Stalled` when no counter moved for 30 minutes, a repair or table sync reported errors, or block errors grew within 30 minutes; `False/BlockErrors` when blocks have persistent resync errors; `Unknown/PreconditionsNotMet` while layout changes are staged or the layout history is unsettled, a drain or factor migration runs, or no storage role of the layout runs at this site; `Unknown/SiteRoleUnset` on a federated site without `spec.layoutManagement.siteRole` (no proof runs); `Unknown/NotObserved` when Garage could not be read. Storage clusters without `connectTo` only. Informational: never changes `Ready` |
| `GarageCluster` | `PodExtrasValid` | `True` when `initContainers`, `extraContainers`, and `extraVolumes` pass strict validation; `False` (reason `DecodeError`, `InvalidContainer`, `ReservedName`, `UnknownVolume`, `OperatorVolumeMount`, or `ManagedClaimReuse`) leaves every workload untouched. Written only once a cluster uses pod extras |
| `GarageBucket` | `Ready` | Bucket reconciliation is complete |
| `GarageBucket` | `LifecycleConfigured` | Requested lifecycle rules were applied; False reports an application failure |
| `GarageBucket` | `BucketLookupStuck` / `BucketMetadataDegraded` | True reports repeated Admin lookup timeouts or metadata decode failures |
| `GarageBucket` | `DeletionBlocked` | True/`BucketNotEmpty` means Garage refused deletion because content remains; remove content or choose `deletionPolicy: Retain` |
| `GarageKey` | `Ready` | Key, permissions, and requested Secret state are reconciled. `False` with reason `ImportKeyRejected` means Garage answered 400 to the `importKey` credentials; the message carries Garage's own text and the cluster's Garage version (see [Import an existing key](../how-to/buckets-and-credentials.md#import-an-existing-key)) |
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
