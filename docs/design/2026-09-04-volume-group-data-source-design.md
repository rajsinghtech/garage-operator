# Volume-group PVC data sources

**Status:** Implementation for
[#348](https://github.com/rajsinghtech/garage-operator/issues/348) /
[#381](https://github.com/rajsinghtech/garage-operator/pull/381).

## Problem

GitOps disaster recovery wants new Auto PVCs to be populated from a
VolumeGroupSnapshot-style source (Kopiur Restore, Volsync, and similar)
before Garage mounts them. The banned `volumeClaimTemplateSpec` could do
that, but it also lets an arbitrary claim clone a `node_key` onto the
wrong StatefulSet ordinal or bind two identities to one disk.

A single cluster-level `spec.storage.dataSourceRef` is the wrong scope:

- it can only populate the default single-disk **data** PVC;
- it cannot restore metadata (`node_key` + metadata DB), so it cannot
  bring a cluster back;
- it cannot restore multi-disk `data.paths[]` members;
- it cannot restore unified/edge gateway metadata;
- a per-replica map on `GarageNode` would let ordinal `i` be assigned
  the wrong disk.

Replica mapping is not an operator API problem. Auto mode creates N
identities with stable PVC names. A **group** populator maps each target
claim to the matching source-group member. The operator's job is to
stamp one group source onto every PVC of one volume **role**.

## Decision

Put `dataSourceRef` on the volume that owns the PVC, not on the cluster
and not per ordinal.

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
      # multi-disk: one group source per path, still shared across ordinals
      # paths:
      #   - path: /data/fast
      #     volume:
      #       size: 100Gi
      #       dataSourceRef: { apiGroup: kopiur.example.io, kind: Restore, name: garage-fast }
  gateway:
    replicas: 2
    metadata:
      size: 1Gi
      dataSourceRef:
        apiGroup: kopiur.example.io
        kind: Restore
        name: garage-gateway-metadata-restore
```

Setting the field is the opt-in. There is no acknowledgement boolean.

### Replica mapping

`replicas: 3` still uses **one** Restore per role. The operator copies
that ref onto every generated claim of that role:

| Role | Generated PVCs |
| --- | --- |
| `storage.metadata` | `metadata-<cluster>-storage-0-0` … `-N-0` |
| `storage.data` | `data-<cluster>-storage-0-0` … `-N-0` |
| `storage.data.paths[i]` | `data-<i>-<cluster>-storage-N-0` |
| Auto unified `gateway.metadata` | `metadata-<cluster>-gateway-N-0` |
| Edge `gateway.metadata` | `metadata-<cluster>-gateway-N` |

The populator must map target claim `i` to source-group member `i`,
typically by PVC name. Identity restore therefore requires the new
cluster to reuse the old `GarageCluster` name (and ordinal count) unless
the populator maps by some other stable key. The operator does not
inspect Restore contents.

A core `PersistentVolumeClaim` or single `VolumeSnapshot` is rejected:
Kubernetes would clone one volume into every replica.

### What each combination means

| Sources set | Result |
| --- | --- |
| data only | New `node_key`s, old object blocks. Not a full cluster restore. |
| metadata + data (same or paired group Restores) | Identity restore: old `node_key` + old blocks on the matching ordinals. |
| metadata only | Old identity, empty/new disks. Admission warning: layout/block-refs will not match. |
| path-level data sources | Each disk restored from its own group; ordinal mapping still belongs to the populator. |
| gateway metadata | Restores gateway identities. Gateway data stays EmptyDir. |

### Out of scope

| Shape | Why |
| --- | --- |
| Node-local pools | HostPath, not PVC populators. |
| Manual Auto inheritance | Manual GarageNodes do not inherit cluster volume sources. |
| Per-ordinal / per-node source maps | Silent wrong-disk assignment. |
| Re-populate after create | STS claim templates and bound PVCs cannot change in place. |
| `volumeClaimTemplateSpec` | Remains rejected. |

Manual restore remains `GarageNode.spec.storage.*.existingClaim` of a
pre-populated PVC, or `dataSourceRef` on that one node's newly created
claim (the populator then fills a single PVC, still from a non-core
group source so a later scale-up cannot clone it).

## API

Add optional `dataSourceRef *corev1.TypedObjectReference` to:

- `VolumeConfig` (cluster metadata/data, including gateway metadata)
- `DataPathVolumeConfig` (per-path PVC)
- `NodeVolumeConfig` (generated Auto children and Manual nodes)

Remove cluster-level `spec.storage.dataSourceRef`. v1beta1/v1beta2
conversion copies the volume-level field through the existing
`VolumeConfig` JSON copy.

Admission:

- non-core `apiGroup`, same-namespace, DNS name, no whitespace;
- rejected on EmptyDir, `existingClaim`, selectors, and Manual cluster
  inheritance of the Auto group;
- immutable after the `GarageCluster` / `GarageNode` is created;
- metadata-without-data produces a warning, not a reject.

## Reconciliation

Auto generation copies each volume's `dataSourceRef` onto the child
`GarageNode` the same way it already copies size, class, selector,
labels, and annotations. The GarageNode controller (and the edge
gateway StatefulSet builder) writes it onto the matching PVC template
and nowhere else. Metadata sources never land on data PVCs and data
sources never land on metadata PVCs.

## Test plan

- Webhook: group source accepted on metadata, data, paths, gateway
  metadata; core/single-volume, EmptyDir, selector, existingClaim,
  cross-namespace, and live mutation rejected.
- Conversion: volume-level refs round-trip v1beta1 ↔ v1beta2.
- Controller: Auto storage copies metadata/data/path refs only onto the
  matching PVC; unified gateway metadata can receive a gateway source
  and never a storage data source; Manual children do not inherit
  cluster refs; edge gateway STS templates receive `gateway.metadata.dataSourceRef`.
- Docs: GitOps identity restore vs data-only restore, replica mapping,
  name-stability requirement.
