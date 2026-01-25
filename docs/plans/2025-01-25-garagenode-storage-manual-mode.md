# GarageNode Storage & Manual Layout Mode

**Issue:** #17
**Date:** 2025-01-25
**Status:** Complete

## Problem

The `existingClaim` feature added to GarageCluster (PR #18) mounts the same PVC to all pods in the StatefulSet. This only works for `replicas: 1` and breaks for multi-replica deployments since:

1. RWO PVCs can't be mounted by multiple pods
2. Each Garage node needs its own unique `node_key` identity
3. Each node needs its own data directory

Additionally, users need heterogeneous storage support - different storage classes per node (e.g., NVMe for one node, Ceph for another).

## Solution

**Architecture Change:**
- **GarageCluster** = shared config (replication, RPC secret, services) - NO StatefulSet when `layoutPolicy: Manual`
- **GarageNode** = creates its OWN StatefulSet (replica 1) with independent storage configuration

This enables:
- Heterogeneous storage (different storage classes per node)
- Per-node resource configuration
- Fine-grained zone/capacity control
- Multiple nodes in the same K8s cluster with different backends

## Design

### Example Usage

```yaml
# Shared cluster config - no StatefulSet created
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage
spec:
  layoutPolicy: Manual
  replication:
    factor: 2
  # Default pod config (inherited by GarageNodes)
  image: dxflrs/garage:v2.2.0
  resources:
    requests:
      memory: 1Gi
---
# Node 1: Local NVMe storage - creates StatefulSet "garage-node-local"
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: garage-node-local
spec:
  clusterRef:
    name: garage
  zone: nvme-tier
  capacity: 100Gi
  storage:
    metadata:
      size: 10Gi
      storageClassName: local-path
    data:
      size: 100Gi
      storageClassName: local-path
  # Override - this node needs specific placement
  nodeSelector:
    node-type: nvme
  resources:
    requests:
      memory: 4Gi
---
# Node 2: Ceph storage - creates StatefulSet "garage-node-ceph"
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: garage-node-ceph
spec:
  clusterRef:
    name: garage
  zone: ceph-tier
  capacity: 500Gi
  storage:
    metadata:
      size: 10Gi
      storageClassName: ceph-rbd
    data:
      existingClaim: my-large-ceph-pvc  # Pre-existing PVC
```

### API Changes

#### GarageCluster

- Remove `existingClaim` from `VolumeConfig` and `DataStorageConfig`
- When `layoutPolicy: Manual`: skip StatefulSet creation, only create ConfigMap + Services
- `replicas` field ignored in Manual mode (GarageNodes define replicas)

#### GarageNode

New fields for pod configuration (inherit from GarageCluster, can override):

```go
type GarageNodeSpec struct {
    // Existing fields
    ClusterRef  ClusterReference
    Zone        string
    Capacity    *resource.Quantity
    Gateway     bool
    Tags        []string
    External    *ExternalNodeConfig  // For external nodes (no StatefulSet)
    Storage     *NodeStorageSpec     // Required for managed nodes

    // NEW: Pod config overrides (inherit from GarageCluster if not set)
    Image             string
    Resources         *corev1.ResourceRequirements
    NodeSelector      map[string]string
    Tolerations       []corev1.Toleration
    Affinity          *corev1.Affinity
    PodAnnotations    map[string]string  // Merged with cluster
    PodLabels         map[string]string  // Merged with cluster
    PriorityClassName string
}
```

Removed fields:
- `PodSelector` - no longer needed (each GarageNode creates its own StatefulSet)

### Controller Changes

#### GarageCluster Controller (Manual Mode)

```
Reconcile() when layoutPolicy: Manual
├─ Create/update ConfigMap (garage.toml)
├─ Create/update Services (S3, Admin, RPC)
├─ Create/update RPC Secret (if not externally provided)
├─ SKIP StatefulSet creation
├─ SKIP bootstrapCluster() - GarageNode handles layout
└─ Update status
```

#### GarageNode Controller

```
Reconcile() for managed nodes (not External)
├─ Get parent GarageCluster
├─ Build pod config (merge cluster defaults + node overrides)
├─ Create/update PVCs
│   ├─ If existingClaim: validate PVC exists
│   └─ If size: create PVC with storageClassName
├─ Create/update StatefulSet (replica 1)
│   ├─ Mount ConfigMap from GarageCluster
│   ├─ Mount PVCs for metadata/data
│   └─ Apply merged pod config
├─ Wait for pod running
├─ Discover nodeID from pod
├─ Update Garage layout (zone, capacity, tags)
└─ Update status

Reconcile() for External nodes
├─ Get parent GarageCluster
├─ Validate nodeID is specified
├─ Update Garage layout (zone, capacity, tags)
└─ Update status
```

### What Each Resource Manages

| Resource | Creates | Owns |
|----------|---------|------|
| GarageCluster (Auto) | StatefulSet, ConfigMap, Services, PDB | All pods |
| GarageCluster (Manual) | ConfigMap, Services | Config only |
| GarageNode (managed) | StatefulSet (replica 1), PVCs | Single pod |
| GarageNode (external) | Nothing | Layout entry only |

### Inheritance Model

GarageNode inherits pod config from GarageCluster unless overridden:

| Field | Inheritance |
|-------|-------------|
| image | Override (use node's if set, else cluster's) |
| resources | Override |
| nodeSelector | Override |
| tolerations | Override |
| affinity | Override |
| priorityClassName | Override |
| podAnnotations | Merge (node takes precedence) |
| podLabels | Merge (node takes precedence) |

### Validation Rules

**GarageCluster Webhook:**
- `layoutPolicy: Manual` - no replicas validation (replicas ignored)

**GarageNode Webhook:**
- `storage` required unless `external` is set
- `storage.data` required for non-gateway managed nodes
- `storage.*.existingClaim` and `storage.*.size` are mutually exclusive
- `external` nodes cannot have `storage`

### Migration Path

Existing `layoutPolicy: Auto` clusters continue to work unchanged.

For `Manual` mode:
1. Create GarageCluster with `layoutPolicy: Manual`
2. Create GarageNode for each desired node
3. GarageNodes create their own StatefulSets
4. Nodes automatically join the Garage cluster layout

## Implementation Tasks

1. [x] Remove `existingClaim` from GarageCluster types
2. [x] Add pod config fields to GarageNode types
3. [x] Remove `PodSelector` from GarageNode (no longer needed)
4. [x] Update GarageNode webhook validation
5. [x] Update GarageCluster controller - skip StatefulSet in Manual mode
6. [x] Rewrite GarageNode controller - create StatefulSet with inheritance
7. [x] Update GarageCluster webhook - allow any replicas in Manual mode
8. [x] Regenerate CRDs
9. [x] Update/fix tests
10. [x] E2E tests added for Manual mode with GarageNodes

## E2E Test Plan

### Single Cluster Tests (`hack/e2e-cluster.sh`)

Deploy GarageCluster with `layoutPolicy: Manual` and 2 GarageNodes:

```yaml
# GarageCluster (Manual mode - no StatefulSet)
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage
spec:
  layoutPolicy: Manual
  replication:
    factor: 2
  # ...shared config
---
# GarageNode 1
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: garage-node-1
spec:
  clusterRef:
    name: garage
  zone: zone-a
  capacity: 1Gi
  storage:
    data:
      size: 1Gi
    metadata:
      size: 100Mi
---
# GarageNode 2
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: garage-node-2
spec:
  clusterRef:
    name: garage
  zone: zone-b
  capacity: 1Gi
  storage:
    data:
      size: 1Gi
    metadata:
      size: 100Mi
```

**Tests:**
1. GarageCluster reaches Running phase (no StatefulSet)
2. Both GarageNodes create their own StatefulSets
3. Both pods are running
4. Both nodes are registered in Garage layout
5. Cluster health is healthy with 2 connected nodes
6. Bucket/key operations work through the cluster

### Multi-Cluster Tests (`hack/e2e-multicluster.sh`)

Deploy GarageCluster (Manual mode) in each cluster with 2 GarageNodes each (4 total):

**Cluster 1 (zone-a):**
- GarageCluster: `layoutPolicy: Manual`, zone-a
- GarageNode: garage-node-1a (zone-a)
- GarageNode: garage-node-2a (zone-a)

**Cluster 2 (zone-b):**
- GarageCluster: `layoutPolicy: Manual`, zone-b
- GarageNode: garage-node-1b (zone-b)
- GarageNode: garage-node-2b (zone-b)

**Tests:**
1. Each cluster creates 2 GarageNode-managed pods
2. Both clusters reach Running phase
3. Each cluster has 2 healthy nodes locally
4. Cross-cluster federation connects all 4 nodes
5. Bucket/key operations work across clusters
6. Layout contains nodes from both zones
