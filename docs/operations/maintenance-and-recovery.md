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
