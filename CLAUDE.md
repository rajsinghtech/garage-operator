# Garage Kubernetes Operator

> **Agent Notes**: Reference /Users/rajsingh/Documents/GitHub/garage for Garage source code. Update this file with important learnings.

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed S3-compatible object storage.
UPSTREAM CODEBASE ../garage
## Quick Reference

### CRDs

| CRD | Short | Description |
|-----|-------|-------------|
| `GarageCluster` | `gc` | Cluster deployment + multi-cluster federation |
| `GarageBucket` | `gb` | Buckets with quotas, website hosting |
| `GarageKey` | `gk` | S3 access keys with bucket permissions |
| `GarageNode` | `gn` | Node layout (zone, capacity, gateway) |
| `GarageAdminToken` | `gat` | Admin API tokens |

### Development Commands

```bash
make dev-up        # Setup: kind + CRDs + operator
make dev-test      # Apply test resources
make dev-status    # View all garage resources
make dev-logs      # Stream operator logs
make dev-load      # Rebuild and reload operator
make dev-run       # Run operator locally (debugging)
make dev-down      # Tear down cluster
```

### Project Structure

```
api/v1alpha1/           # CRD types + webhooks
internal/controller/    # Reconciliation logic
internal/garage/        # Admin API client (v2)
config/samples/         # Example CRs
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster A                         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Operator: Cluster | Bucket | Key | Node Controllers        │ │
│  └─────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │     Garage Cluster (Zone: us-east-1) - 3 Pods             │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────┘
                    Full Mesh RPC (port 3901)
┌──────────────────────────────┼──────────────────────────────────┐
│                     Kubernetes Cluster B                         │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │     Garage Cluster (Zone: eu-west-1) - 3 Pods             │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Multi-Cluster Federation

### Key Concepts

1. **Full Mesh Connectivity**: Every node must reach every other node on RPC port (3901)
2. **Shared RPC Secret**: Same 32-byte hex secret across ALL clusters
3. **Zones**: Labels for fault tolerance - Garage distributes replicas across zones
4. **No Single Leader**: Layout is a CRDT that converges across nodes

### Network Solutions

**LoadBalancer per Node** (most reliable):
```yaml
publicEndpoint:
  type: LoadBalancer
  loadBalancer:
    perNode: true
```

**NodePort** (cheaper):
```yaml
publicEndpoint:
  type: NodePort
  nodePort:
    externalAddresses: ["node1.example.com", "node2.example.com"]
    basePort: 30901
```

### Federation Setup

1. Create shared RPC secret in ALL clusters:
   ```bash
   openssl rand -hex 32
   kubectl create secret generic garage-rpc-secret --from-literal=rpc-secret=<secret>
   ```

2. Deploy GarageCluster in each cluster with same `rpcSecretRef`, unique `zone`

3. Use `spec.remoteClusters` for automatic federation or `connect-nodes` annotation for manual

---

## Gateway Clusters

Gateway nodes handle S3 API requests without storing data.

```yaml
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-gateway
spec:
  replicas: 5
  gateway: true
  connectTo:
    clusterRef:
      name: garage-storage
```

| Aspect | Storage Cluster | Gateway Cluster |
|--------|-----------------|-----------------|
| Workload | StatefulSet | StatefulSet |
| Metadata PVC | 10Gi default | 1Gi default (node identity) |
| Data PVC | 100Gi default | EmptyDir (no blocks) |
| Layout capacity | From PVC size | null (gateway) |

### Node Identity Persistence

**Critical**: Garage nodes store their identity (Ed25519 keypair) in `metadata_dir/node_key`. This node ID is permanent and used for cluster membership. Gateway clusters use StatefulSet with a metadata PVC to preserve node identity across pod restarts. Without persistent metadata, each pod restart would generate a new node ID, causing stale nodes in the layout.

---

## Configuration Reference

### GarageCluster Options

| Category | Options |
|----------|---------|
| **Replication** | `factor` (1-7), `consistencyMode` (consistent/degraded/dangerous) |
| **Storage** | Metadata/data PVCs, fsync, auto-snapshots |
| **Database** | Engine (lmdb/sqlite/fjall), LMDB map size, Fjall block cache |
| **Blocks** | Size, RAM buffer, compression, concurrent reads |
| **APIs** | S3 (3900), K2V (3904), Web (3902), Admin (3903) |
| **Network** | RPC port, public address, bootstrap peers |
| **Logging** | Level (RUST_LOG format), syslog, journald |

### Layout Policy

| Policy | Behavior |
|--------|----------|
| `Auto` (default) | Auto-assign pods to layout using cluster zone. Capacity from PVC size. |
| `Manual` | Create GarageNode resources for fine-grained control. |

---

## GarageBucket Features

### Supported (via Admin API)

Quotas, Website hosting (index/error docs), Global/Local aliases, Key permissions

### NOT Supported (use S3 API directly)

CORS rules, Lifecycle rules, Website redirectAll/routingRules

---

## Operational Annotations

### GarageCluster (Implemented)

| Annotation | Description |
|------------|-------------|
| `garage.rajsingh.info/force-layout-apply` | Force apply staged layout (set to `"true"`) |
| `garage.rajsingh.info/connect-nodes` | Connect nodes: `"nodeId@addr:port,..."` (one-shot, removed after processing) |

### Defined but NOT Implemented

These annotations are defined as constants in `api/v1alpha1/condition_types.go` but have no controller logic:
- `trigger-snapshot`, `pause-reconcile`, `trigger-repair`, `scrub-command` (GarageCluster)
- `cleanup-mpu`, `cleanup-mpu-older-than` (GarageBucket)

---

## Admin API Client

Uses Admin API **v2** at `internal/garage/client.go`.

### Key Patterns

- Auth: `Authorization: Bearer <prefix>.<secret>` (prefix is 24 hex chars)
- Error helpers: `garage.IsNotFound(err)`, `garage.IsConflict(err)`, `garage.IsBadRequest(err)`
- bootstrap_peers format: `<64-char-hex-node-id>@<hostname>:<port>` (addresses without node IDs are ignored)

### SDK Evaluation (2026-04-12): Keep Hand-Crafted Client

**Decision: Keep hand-crafted client.**

Import test: `go get git.deuxfleurs.fr/garage-sdk/garage-admin-sdk-golang` succeeds (v0.0.0-20260106092213-694c0d66012a, hosted on `git.deuxfleurs.fr`). However, migrating adds risk with no meaningful benefit: our custom error helpers (`IsNotFound`, `IsConflict`, `IsBadRequest`) parse HTTP status codes directly and would need wrappers around SDK types, and the external forge is not a standard Go module proxy (no GOPROXY cache guarantee). The hand-crafted client covers all endpoints the operator actually uses.

**Spec endpoints NOT covered by our client** (not needed by operator today):

| Endpoint | OperationId | Notes |
|----------|-------------|-------|
| `GET /check` | CheckDomain | DNS check helper |
| `GET /metrics` | Metrics | Prometheus scrape endpoint |
| `GET /v2/GetAdminTokenInfo` | GetAdminTokenInfo | Token introspection |
| `GET /v2/GetCurrentAdminTokenInfo` | GetCurrentAdminTokenInfo | Self-info |
| `GET /v2/ListAdminTokens` | ListAdminTokens | |
| `POST /v2/CreateAdminToken` | CreateAdminToken | Used by GarageAdminToken CRD (TBD) |
| `POST /v2/DeleteAdminToken` | DeleteAdminToken | |
| `POST /v2/UpdateAdminToken` | UpdateAdminToken | |
| `POST /v2/GetBlockInfo` | GetBlockInfo | Block diagnostics |
| `GET /v2/ListBlockErrors` | ListBlockErrors | |
| `POST /v2/PurgeBlocks` | PurgeBlocks | |
| `POST /v2/RetryBlockResync` | RetryBlockResync | |
| `GET /v2/GetClusterStatistics` | GetClusterStatistics | Cluster-level stats |
| `GET /v2/GetNodeInfo` | GetNodeInfo | Per-node info |
| `GET /v2/GetNodeStatistics` | GetNodeStatistics | Per-node stats |
| `GET /v2/InspectObject` | InspectObject | Object block map |
| `POST /v2/PreviewClusterLayoutChanges` | PreviewClusterLayoutChanges | Dry-run layout |

---

## Known Limitations

| Feature | Notes |
|---------|-------|
| CORS/Lifecycle/RoutingRules | Use S3 API directly |
| Permission Revocation | Removing from spec doesn't revoke - use `DenyBucketKey` API |
| TLS for APIs | External only - use service mesh or load balancer |
| Hot-reload config | NOT supported - config changes require pod restart |

---

## Implementation Notes

### Important Behaviors

1. **Config changes require pod restart** - Garage reads config once at startup, SIGHUP ignored
2. **Config hash annotation** - Changes trigger rolling restart via `garage.rajsingh.info/config-hash`
3. **Credential sync** - Key controller uses `ShowSecretKey: true` to detect/fix credential drift
4. **Layout conflicts** - Controller handles 409 Conflict with retry on next reconciliation
5. **Single-node clusters** - Supported for multi-cluster federation (1 replica per K8s cluster)
6. **Node identity in metadata_dir** - Garage stores `node_key` (Ed25519 private key) in `metadata_dir`. This file determines the node ID. Both storage and gateway clusters need persistent metadata to preserve node identity across restarts (see `garage/src/rpc/system.rs:gen_node_key`)

### Port Defaults

- RPC: 3901
- S3: 3900
- Admin: 3903
- K2V: 3904
- Web: 3902

---

## CI/CD

| Workflow | Description |
|----------|-------------|
| `test.yml` | Unit tests |
| `lint.yml` | golangci-lint |
| `test-e2e.yml` | E2E tests with Kind |
| `docker.yml` | Multi-arch images to `ghcr.io/rajsinghtech/garage-operator` |
| `helm.yml` | Helm chart lint, verify CRDs, push to OCI registry |
| `release.yml` | GitHub release with install.yaml |

```bash
# Install
kubectl apply -f https://github.com/rajsinghtech/garage-operator/releases/latest/download/install.yaml

# Release
git tag v1.0.0 && git push origin v1.0.0
```

---

## TODOs

### Unimplemented Annotations

Several annotations are defined in `api/v1alpha1/condition_types.go` but have no controller logic:
- `trigger-snapshot`, `pause-reconcile`, `trigger-repair`, `scrub-command` (GarageCluster)
- `cleanup-mpu`, `cleanup-mpu-older-than` (GarageBucket)

### E2E Test Gap: Credential Drift

Implemented in `test/e2e/e2e_test.go` (Gateway Cluster describe block):
- "should recreate key and update secret when key is deleted in Garage"
- "should successfully PUT and GET objects with credentials after drift recovery"

### Web API (s3_web) Support

Research Garage's Web API (port 3902) for static website hosting:
1. Understand how `[s3_web]` config section works (root_domain, index docs)
2. Determine if operator should expose web API configuration in GarageCluster spec
3. Consider adding HTTPRoute templates for web-hosted buckets
4. Investigate how website hosting interacts with GarageBucket's `website` field
