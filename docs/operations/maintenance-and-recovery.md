# Maintenance and recovery

Storage removal is a data-safety operation, not a Kubernetes deletion. The operator keeps an identity-bearing process online while Garage removes its role and proves that blocks have been repaired or that the administrator has explicitly acknowledged a permanently lost source.

## Prepared storage-node deletion

For a positive-capacity `GarageNode`:

```bash
kubectl annotate garagenode garage-storage-a -n storage \
  garage.rajsingh.info/drain=true
kubectl get garagenode garage-storage-a -n storage \
  -o jsonpath='{.status.conditions}{"\n"}'
```

Wait for `DrainPrepared=True` with reason `PreparedForDeletion`. Then delete the exact object:

```bash
kubectl delete garagenode garage-storage-a -n storage
```

The annotation remains a cancellation request until the role enters its irreversible draining phase. Do not remove finalizers, delete the source Pod manually, or delete metadata/data PVCs while the proof is active.

## Wait for full redundancy

After a node returns, a disk is replaced, or the layout changes, Garage can
report a healthy cluster while some objects still have fewer copies than the
replication factor: partitions have quorum, but a node may hold no data yet.
The `FullyReplicated` condition on the `GarageCluster` turns `True` only after
the operator has proved that every storage node that runs at this site has
all its data again. The proof repairs one storage node at a time: a full table sync on
the node, then a blocks repair scan on it, then a two-minute pause before the
next node. Once every node is done, block resync must stay idle and error-free
through a quiet period (at least about 11 minutes, longer with a large
`network.rpcTimeout`). Progress is kept in `status.redundancy`, so an operator
restart resumes with the node it was on.

**Nothing starts on upgrade.** Upgrading the operator, or adopting an existing
cluster, only records a baseline and reports
`FullyReplicated=Unknown/NotVerified`. Garage pod restarts, node outages and
block errors start nothing either. A proof starts only when you set the
`garage.rajsingh.info/verify-redundancy` annotation to a new value (tables
and blocks on every storage node of this site).

A change in the storage nodes, zones or capacities of the layout voids the
last proof (`Unknown/NotVerified`, and a running proof stops) but starts
nothing by default. To have such a change start a proof on its own (blocks
scans only; Garage already syncs tables after a layout change), opt in on a
writer or single-site cluster:

```yaml
spec:
  layoutManagement:
    redundancyVerification:
      onTopologyChange: true
```

The flag is off by default and ignored on a federation `Follower` site.

**Throttle first.** Only Garage's tranquility settings slow the repairs down;
the operator has no rate setting of its own. A blocks repair queues every
block of the node for resync, and `spec.workers.resyncTranquility` is the
pause Garage takes between resync operations. On busy or shared disks, raise
it above `0` (for example `2` to `4`) before requesting a proof, and set it
back afterwards. The table sync and the blocks scan itself run at Garage's
own pace.

```bash
kubectl patch garagecluster garage -n storage --type merge \
  -p '{"spec":{"workers":{"resyncTranquility":2}}}'
kubectl annotate garagecluster garage -n storage --overwrite \
  garage.rajsingh.info/verify-redundancy="$(date +%Y%m%d%H%M)"
kubectl wait garagecluster garage -n storage \
  --for=condition=FullyReplicated --timeout=24h
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.redundancy.verification.phase}{" "}{.status.redundancy.verification.currentNodeId}{"\n"}'
```

In a federation each site proves only its own storage nodes: the nodes of
its own non-external `GarageNode`s. Request the proof on each site you want
covered, writer or follower; a site never repairs another site's nodes. When
other sites run storage nodes too, a finished proof reports
`True/VerifiedLocal` with a message such as `5/12 federated storage nodes
verified (writer-local)`, and `status.redundancy.scope` is `Local` with the
counts in `status.redundancy.storageNodes` (`total`, `local`, `remote`,
`verified`). A single-site cluster reports `True/Verified` and scope
`Cluster`.

Sites take turns. Before it starts a storage node, a site checks Garage's
cluster-wide worker list for a blocks repair on another site's storage
node. While one ran within the hold-down (15 minutes on the writer, 16 to 25
minutes on a follower), the site waits and reports
`Unknown/WaitingForOtherSite` with the node and the time it will start. A
writer checks only before its first node; a follower checks before each of
its nodes, so the writer goes first when both are requested. A site whose
operator crashed simply stops repairing; the others start once the
hold-down passes, so nothing is left holding a lock. A federated site
without `spec.layoutManagement.siteRole` runs nothing and reports
`Unknown/SiteRoleUnset`; see [Federation](../how-to/federation.md).

**Limits of the turn-taking.** Sites see each other only through Garage's
worker list, so the hold-down is a best effort, not a lock:

- Do not bump the `verify-redundancy` annotation on two sites at once. Two
  requests made at the same moment can overlap by one storage node's repair.
- Another site's table repairs cannot be seen; only blocks repairs count.
- A remote table stage that runs longer than about 12 minutes can let
  another site start in the gap.
- Blocks repairs you launch by hand (`garage repair blocks`) count as
  activity and delay proofs at the other sites.

Request one site at a time, in a quiet window, with
`spec.workers.resyncTranquility` at `2` to `4`, and wait for
`FullyReplicated` there before requesting the next site. Leave
`spec.layoutManagement.redundancyVerification.onTopologyChange` off on busy
fleets, so a topology change never starts repairs on its own.

Watch which node is behind:

```bash
kubectl get garagecluster garage -n storage -o jsonpath='{range .status.redundancy.nodes[*]}{.nodeId}{" queue="}{.resyncQueueLength}{" errors="}{.blockErrors}{" tables="}{.metadataSyncPartitions}{" repair="}{.blockRepairProgress}{"\n"}{end}'
```

**Unreachable nodes are deferred, not waited on.** A storage node that is
down or not answering when its turn comes is skipped and listed in
`status.redundancy.deferredNodes` with reason `Down` or `NotReporting` and a
`retryAfter` time. The proof goes on with the other nodes and ends at
`FullyReplicated=False/Partial`, naming the deferred nodes. A deferred node
gets its own turn once it is back and `retryAfter` (10 minutes) has passed;
when every node is done the proof settles and turns `Verified`. A node whose
table sync reported errors because a peer was down is rechecked with one
more table sync once every node is up.

Repairs are bounded: a node's turn launches at most three tables repairs and
three blocks repairs, retrying only after a Garage restart or a repair that
reported errors. A node that uses them up is deferred with reason
`RepairFailed` and is retried only when you set a new `verify-redundancy`
value. `Stalled` means no counter moved for 30 minutes, a repair or table sync
reported errors, or block errors grew. Read the condition message and
`status.blockErrorDetails`, then fix the node it names. Persistent block
errors keep the condition `False/BlockErrors` until `retry-block-resync` or
Garage clears them. If a storage node goes down after a proof, the condition
goes back to `Unknown/NotVerified`; request a new proof once the node is back.

For rate and ETA, use Garage's own metrics:

```promql
# blocks still queued for resync, cluster-wide
sum(block_resync_queue_length)
# resync throughput, blocks per second
sum(rate(block_resync_counter[15m]))
# rough ETA in seconds (meaningless until metadata has synced)
sum(block_resync_queue_length) / clamp_min(sum(rate(block_resync_counter[15m])), 0.001)
```

A queue near zero is not proof on its own: right after a node returns empty,
the queue stays small until its metadata has synced.

## Lost source identity

First determine whether the Garage identity survived.

If the metadata identity and `status.nodeId` are intact and only data blocks
need repair, keep the same `GarageNode` and its metadata/data claims in place.
After restoring the disk or path, run the targeted Garage repair from a healthy
Admin endpoint:

```bash
garage repair -a --yes blocks
```

If the metadata was lost or replaced and the process reports a new Garage ID,
do not disable the admission webhooks, remove the `GarageNode` finalizer, or
delete the old claims. The operator retains the old positive-capacity
`status.nodeId`, refuses to assign the replacement identity, and fences the
replacement until the old role has been handled. Pair the exact identity
acknowledgement with the drain request:

```bash
kubectl annotate garagenode garage-storage-a -n storage \
  garage.rajsingh.info/drain=true \
  garage.rajsingh.info/acknowledge-lost-source=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The operator verifies that Garage reports the exact identity down and that the
replacement has no committed or staged role. From a healthy Garage Admin
endpoint, remove and review the exact dead role, then apply that one staged
change:

```bash
garage layout remove 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
garage layout show
garage layout apply
```

If a dead identity still prevents the layout from settling, review the entire
layout before using the explicit cluster-wide recovery request:

```bash
kubectl annotate garagecluster garage -n storage \
  garage.rajsingh.info/skip-dead-nodes=true
```

Add `garage.rajsingh.info/allow-missing-data=true` only when the old data is
provably unrecoverable and the surviving replicas are sufficient. The
`skip-dead-nodes` operation is global rather than target-scoped, and
`allow-missing-data` can authorize data loss.

Wait for `DrainPrepared=True` with reason `PreparedForDeletion`, review the
parent `status.storageDrain`, and only then delete the exact `GarageNode`:

```bash
kubectl delete garagenode garage-storage-a -n storage
```

For an operator-owned Auto-mode storage slot, the finalizer records exact
retained PVC UIDs in the parent before releasing the old `GarageNode`. The
parent can then recreate the same slot and transfer only those exact claims;
leave retained metadata/data PVCs in place until that handoff completes. This
cannot restore blocks that existed only on the lost source.

## Federated site deletion

Use `deletionPolicy: Drain` when retiring one physical site from a surviving federated Garage layout. `Destroy` is the standalone whole-store teardown default; it is not a safe site-retirement workflow.

```yaml
spec:
  deletionPolicy: Drain
  layoutManagement:
    autoApply: true
    drain:
      unverifiedPeersPolicy: AssumeConsistent
```

Then request preparation:

```bash
kubectl annotate garagecluster garage-us -n storage \
  garage.rajsingh.info/drain=true
kubectl get garagecluster garage-us -n storage \
  -o jsonpath='{.status.storageDrain}{"\n"}{.status.conditions}{"\n"}'
```

Delete only after `StorageDrainReady=True` with reason `Completed`, and after reviewing the exact `roleRemovalNodeIds`, `removedStorageNodeIds`, verification IDs, and completion timestamp in `status.storageDrain`.

!!! warning "Serialize federation changes"
    Do not annotate multiple federated sites at once. Every site must use literal `consistencyMode: consistent`, and one writer must own the shared layout mutation at a time.

## Gateway tombstones

After a gateway scale-down or identity replacement, old capacity-less roles may remain in the Garage layout. With `layoutManagement.autoApply: false`, the operator reports them in `status.pendingGatewayTombstones` and sets `GatewayTombstones` without staging the removal.

Review the exact node IDs first:

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.pendingGatewayTombstones}{"\n"}'
```

Either remove those exact roles with a reviewed Garage layout operation, or enable `autoApply` and let the operator stage and apply them. `force-layout-apply` does not approve tombstones.

## Node-local pool changes

Node-local membership is selector-driven and drain-safe. To remove a Kubernetes Node, remove it from the selector and wait for the generated `GarageNode` and Pod to complete retirement before changing the HostPath or selecting it in another pool.

A Node cannot move directly between pools. Unselect it from the old pool, wait for `NodeLocalPoolsReady=True` and the old Pod to disappear, then select it in the new pool. This prevents two DaemonSets from mounting the same local disk.

See the [node-local-pool guide](../node-local-pools.md) for prepared deletion, identity markers, pool migration, and rollback details.

## Replacement cycles

For eligible StatefulSet-backed storage nodes, use:

```bash
kubectl annotate garagenode garage-storage-a -n storage \
  garage.rajsingh.info/cycle=true
```

The operator adds a fresh sibling before draining the source. It does not clone or reuse source claims, infer disk profiles, or cycle gateways, external nodes, or node-local members. Use explicit add-before-remove for those cases.

## GitOps volume restore (Auto group)

To populate new Auto PVCs from a VolumeGroupSnapshot-style populator (Kopiur,
Volsync, and similar), set `dataSourceRef` on each volume role of a **new**
`GarageCluster`. One same-namespace, non-core group source is copied onto every
generated PVC of that role. Replica mapping is the populator's job, not a
per-node operator API.

```yaml
spec:
  storage:
    replicas: 3
    metadata:
      size: 10Gi
      dataSourceRef:
        apiGroup: kopiur.example.io
        kind: Restore
        name: garage-metadata-restore
    data:
      size: 100Gi
      dataSourceRef:
        apiGroup: kopiur.example.io
        kind: Restore
        name: garage-data-restore
  gateway:
    replicas: 2
    metadata:
      size: 1Gi
      dataSourceRef:
        apiGroup: kopiur.example.io
        kind: Restore
        name: garage-gateway-metadata-restore
```

Setting the field is the opt-in. Do not use `volumeClaimTemplateSpec`. Admission
rejects core PVC/VolumeSnapshot clones, EmptyDir, selectors, `existingClaim`,
and cross-namespace references. Multi-disk layouts set the source on each
`storage.data.paths[].volume`.

| Sources set | Result |
| --- | --- |
| metadata + data (or per-path data) | Identity restore: old `node_key` and old object blocks on matching ordinals. Reuse the old cluster name so PVC names match snapshot members. |
| data only | New identities on old object blocks. Buckets, keys, and layout are not restored. |
| metadata only | Old identity, empty/new disks. Admission warns that layout/block-refs will not match. |
| gateway metadata | Restores gateway identities. Gateway data stays EmptyDir. |

The populator must map `metadata-<cluster>-storage-i-0` and
`data-<cluster>-storage-i-0` to the matching source-group members. The operator
does not inspect Restore contents. If the populator hangs, the PVC stays
Pending. If it finishes with the wrong member or a partial fill, Garage can
still start and then fail layout or block-ref checks. Set the field in the
create manifest; it is immutable afterwards because StatefulSet claim templates
and bound PVCs cannot be repopulated in place.

Manual nodes and node-local pools are out of scope here. Manual restore uses
`GarageNode.spec.storage.*.existingClaim` or a per-node `dataSourceRef` on a
new claim. Node-local pools are HostPath.

See [`storage.metadata.dataSourceRef` / `storage.data.dataSourceRef`](../reference/custom-resources.md) for the field contract.

## PVC retention and cleanup

Storage PVCs default to `Retain` on delete and scale-down. A removed node's StatefulSet is deleted as part of its identity handoff; its claims are governed by `whenDeleted`, not `whenScaled`.

```yaml
spec:
  storage:
    pvcRetentionPolicy:
      whenDeleted: Retain
      whenScaled: Retain
```

Only delete retained claims after the corresponding Garage role has been retired and you have confirmed the data is no longer required. A retained metadata claim can be part of a later exact handoff; deleting it destroys that recovery option.

## Cluster deletion

Before deleting a standalone cluster, choose whether to retain or delete its PVCs and whether the Garage store itself is still needed. Before deleting a federated site, use `deletionPolicy: Drain`. A namespace delete can bypass the normal user workflow; keep admission webhooks available and inspect finalizers and drain status rather than forcing deletion.
