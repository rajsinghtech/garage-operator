# Garage Kubernetes Operator

<p align="center">
  <img src="logo.svg" alt="Garage Kubernetes Operator" width="128" height="128">
</p>

<p align="center">
  <strong>S3-Compatible Object Storage on Kubernetes</strong>
</p>

<p align="center">
  <a href="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml"><img src="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/rajsinghtech/garage-operator"><img src="https://goreportcard.com/badge/github.com/rajsinghtech/garage-operator" alt="Go Report Card"></a>
  <a href="https://github.com/rajsinghtech/garage-operator/releases/latest"><img src="https://img.shields.io/github/v/release/rajsinghtech/garage-operator" alt="Latest Release"></a>
  <a href="https://deepwiki.com/rajsinghtech/garage-operator"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
</p>

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed, self-hosted object storage with multi-cluster federation.

- **Declarative cluster lifecycle** — StatefulSet, config, and layout managed via CRDs
- **Unified storage + gateway tiers in one CR** (v1beta2) — combine durable storage pods and ephemeral S3 proxies in a single `GarageCluster`
- **Bucket & key management** — create buckets, quotas, and S3 credentials with kubectl
- **Multi-cluster federation** — span storage across Kubernetes clusters with automatic node discovery
- **Persistent-identity gateway pods** — StatefulSet with a small metadata PVC; gateway pods keep the same Garage node identity across restarts and participate in the cluster layout with `capacity: null` (matching upstream `garage layout assign --gateway`)
- **Scale subresource** — `kubectl scale` and VPA/HPA support for GarageCluster
- **COSI driver** — optional Kubernetes-native object storage provisioning

## Custom Resources

| CRD | Description |
|-----|-------------|
| `GarageCluster` | Deploys and manages a Garage cluster (storage and/or gateway tiers) |
| `GarageBucket` | Creates buckets with quotas and website hosting |
| `GarageKey` | Provisions S3 access keys with per-bucket permissions |
| `GarageNode` | Fine-grained node layout control (zone, capacity, tags) |
| `GarageAdminToken` | Manages admin API tokens |
| `GarageReferenceGrant` | Grants cross-namespace access to clusters and buckets |

## Install

The Helm chart enables admission and conversion webhooks by default, so install cert-manager first. For local development or v1beta2-only installs, you can disable webhooks explicitly:

```bash
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace
```

```bash
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace \
  --set webhooks.enabled=false
```

## API Versions

`GarageCluster` is served under two API versions; all other CRDs are `v1beta1`.

| Version | Status | Schema |
|---|---|---|
| `garage.rajsingh.info/v1beta2` | **Current** (storage version, recommended) | Tier-based: `spec.storage` and/or `spec.gateway` |
| `garage.rajsingh.info/v1beta1` | Deprecated, still served | Legacy flat schema: `spec.replicas`, `spec.gateway: bool` |

A conversion webhook handles reads and writes in both directions, so existing v1beta1 manifests continue to work unchanged. The controller operates on v1beta2 internally. New clusters should be written as v1beta2.

`kubectl scale` is supported on both versions — the scale subresource targets `.spec.storage.replicas` on v1beta2 and `.spec.replicas` on v1beta1. A v1beta2 CR that declares **both** `storage` and `gateway` has no faithful v1beta1 form; the conversion webhook returns only the storage tier when read as v1beta1 and annotates the object with `garage.rajsingh.info/v1beta2-only=gateway-tier-present`. Tools that manage unified clusters must use v1beta2.

## Quick Start

First, create an admin token secret for the operator to manage Garage resources:

```bash
kubectl create secret generic garage-admin-token \
  --from-literal=admin-token=$(openssl rand -hex 32)
```

Create a unified 3-storage / 2-gateway Garage cluster ([full example](config/samples/garage_v1beta2_garagecluster.yaml)):

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  zone: us-east-1
  replication:
    factor: 3
  storage:
    replicas: 3
    metadata:
      size: 10Gi
    data:
      size: 100Gi
  gateway:
    replicas: 2
  network:
    rpcBindPort: 3901
    service:
      type: ClusterIP
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

`spec.gateway` is optional — omit it for a storage-only cluster. Existing `v1beta1` manifests (`spec.replicas`, `spec.gateway: bool`) are still accepted; the conversion webhook rewrites them to the tier-based shape on read.

Wait for the cluster to be ready:

```bash
kubectl wait --for=condition=Ready garagecluster/garage --timeout=300s
```

Create a bucket:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: my-bucket
spec:
  clusterRef:
    name: garage
  quotas:
    maxSize: 10Gi
```

Create access credentials:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: my-key
spec:
  clusterRef:
    name: garage
  bucketPermissions:
    - bucketRef:
        name: my-bucket
      read: true
      write: true
```

Or grant access to **all buckets** in the cluster — useful for admin tools, monitoring, or [mountpoint-s3](https://github.com/awslabs/mountpoint-s3) workloads that span multiple buckets:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: admin-key
spec:
  clusterRef:
    name: garage
  allBuckets:
    read: true
    write: true
    owner: true
```

Per-bucket overrides layer on top of `allBuckets`, so you can combine cluster-wide read with owner on a specific bucket:

```yaml
  allBuckets:
    read: true
  bucketPermissions:
    - bucketRef:
        name: metrics-bucket
      owner: true
```

Import existing credentials from an inline spec or a Kubernetes secret:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: imported-key
spec:
  clusterRef:
    name: garage
  importKey:
    accessKeyId: "GKxxxxxxxxxxxxxxxxxxxxxxxx"
    secretAccessKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Or reference an existing secret — use `accessKeyIdKey`/`secretAccessKeyKey` to specify which keys to read from the source secret (defaults to `access-key-id`/`secret-access-key`):

```yaml
  importKey:
    secretRef:
      name: my-existing-creds
    accessKeyIdKey: AWS_ACCESS_KEY_ID
    secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
```

### Secret Template

By default the generated secret includes `access-key-id`, `secret-access-key`, `endpoint`, `host`, `scheme`, and `region`. Use `secretTemplate` to customize what gets included and how keys are named:

```yaml
secretTemplate:
  accessKeyIdKey: AWS_ACCESS_KEY_ID
  secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
  endpointKey: AWS_ENDPOINT_URL_S3
  regionKey: AWS_REGION
  includeEndpoint: false   # omit endpoint/host/scheme
  includeRegion: false     # omit region
```

This is useful when mounting the secret directly as environment variables with `envFrom` — only the keys your app expects will be present.

Get S3 credentials:

```bash
kubectl get secret my-key -o jsonpath='{.data.access-key-id}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.secret-access-key}' | base64 -d && echo
kubectl get secret my-key -o jsonpath='{.data.endpoint}' | base64 -d && echo
```

## Gateway Tier

`spec.gateway` runs S3/Admin proxies as a `StatefulSet` (`<cluster>-gateway`) with a small **persistent metadata PVC** (default 1Gi, `Delete`/`Delete` retention) so each gateway pod keeps the same Ed25519 node identity across restarts. The data dir stays `EmptyDir` — gateways don't store object blocks.

Gateway pods participate in the cluster layout with `capacity: null` (matching upstream `garage layout assign --gateway`). This is required: Garage's S3 sig-auth path uses `key_table.get_local()` — only nodes in `layout.all_nodes()` receive FullReplication writes for `key_table` / `bucket_table` / `admin_token_table`, so a gateway outside the layout returns `403 Forbidden: No such key` on every request. Scale-downs are tombstone-cleaned by the operator on next reconcile.

A `GarageCluster` must set at least one of `storage`, `gateway`, or `connectTo`. The webhook also rejects `gateway` without either `storage` (unified pattern) or `connectTo` (edge pattern). See the [gateway examples](config/samples/garage_v1beta2_garagecluster_gateway.yaml) for more.

### Unified cluster (storage + local gateways)

Most common: one CR declares both tiers in the same namespace. Gateway pods talk to the storage tier over the in-cluster RPC service.

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  zone: us-east-1
  replication:
    factor: 3
  storage:
    replicas: 3
    metadata:
      size: 10Gi
    data:
      size: 100Gi
  gateway:
    replicas: 4
    resources:
      requests:
        cpu: 50m
        memory: 128Mi
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

### Edge gateway (gateway-only, connects to a remote storage cluster)

For gateways in a different K8s cluster, an external NAS, or a bare-metal Garage instance — omit `spec.storage` and use `connectTo`:

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage-edge
spec:
  replication:
    factor: 3        # must match the storage cluster
  gateway:
    replicas: 3
    # Tells the remote cluster how to dial back to this gateway.
    # Without it, Garage advertises the pod IP, which is unreachable from outside K8s.
    rpcPublicAddr: "edge-gateway.tailnet.example:3901"
  connectTo:
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
    adminApiEndpoint: "http://garage-primary.tailnet.example:3903"
    adminTokenSecretRef:
      name: storage-admin-token
      key: admin-token
  admin:
    adminTokenSecretRef:
      name: gateway-admin-token
      key: admin-token
  publicEndpoint:
    type: NodePort
    nodePort:
      basePort: 30901
      externalAddresses:
        - "edge-node1.example.com"
        - "edge-node2.example.com"
```

Or reference a storage `GarageCluster` in the same namespace via `connectTo.clusterRef.name`. The operator opens RPC in both directions (gateway -> external **and** external -> gateway) and re-establishes the link on drift; see the [gateway sample manifests](config/samples/garage_v1beta2_garagecluster_gateway.yaml) for complete examples.

### Workload differences

| Aspect | Storage tier | Gateway tier |
|---|---|---|
| Workload | `StatefulSet` (`<cluster>`) | `StatefulSet` (`<cluster>-gateway`) |
| Metadata volume | PVC via `volumeClaimTemplates` | PVC via `volumeClaimTemplates` (default 1Gi) |
| Data volume | PVC via `volumeClaimTemplates` | `EmptyDir` |
| Update strategy | StatefulSet default | StatefulSet default, `PodManagementPolicy: Parallel` |
| Pod naming | `<cluster>-0`, `<cluster>-1`, … | `<cluster>-gateway-0`, `<cluster>-gateway-1`, … |
| Node identity | persists across restarts | persists across restarts (metadata PVC) |
| PVC retention | `Retain` (default) | `Delete`/`Delete` (gateway data is cheap) |
| Layout capacity | from PVC size | `null` (gateway) |
| Stale-layout cleanup | finalizer-driven on CR deletion | operator tombstone-reaps on scale-down |

**`network.rpcPublicAddr` or `publicEndpoint` is required** for the external cluster to reach the gateway. Without an externally-routable RPC address, Garage advertises a pod IP, which is unreachable from outside Kubernetes. Set `network.rpcPublicAddr` to the externally-routable address of your gateway's RPC service, or configure `publicEndpoint` so the operator can derive the address from Kubernetes service status.

For a single shared RPC endpoint, use `publicEndpoint.type: LoadBalancer` without `loadBalancer.perNode`; the operator creates one `<cluster>-rpc` LoadBalancer service and derives one `rpc_public_addr` from it. This is the simplest setup when your infrastructure provides a global/shared load balancer address that can route RPC traffic to the gateway pods.

For per-pod LoadBalancer services, set `publicEndpoint.type: LoadBalancer` and `publicEndpoint.loadBalancer.perNode: true`; the operator creates `<cluster>-0-rpc`, `<cluster>-1-rpc`, etc. In auto-layout `GarageCluster` mode, the pods still share one Garage ConfigMap, so the operator does not write distinct per-pod `rpc_public_addr` values into Garage's config. The per-node service addresses are used by the operator when it asks the external Garage cluster to connect back to each gateway node. For true per-node advertised `rpc_public_addr` in Garage config, use `layoutPolicy: Manual` with `GarageNode` resources, or set explicit per-node addresses.

The operator establishes connectivity in both directions: gateway → external nodes and external cluster → gateway nodes. It also actively monitors the connection and re-establishes it if Garage marks a peer as unreachable.

> **Note:** `bootstrapPeers` is also accepted for one-shot bootstrapping when you know the node ID in advance, but `adminApiEndpoint` is preferred — it works without knowing node IDs upfront and keeps the connection stable across restarts.

## Manual Node Layout (GarageNode)

By default, GarageCluster uses `layoutPolicy: Auto` — the operator assigns every pod to the Garage layout using the cluster's zone and PVC-derived capacity. For fine-grained control over individual nodes, set `layoutPolicy: Manual` and create GarageNode resources.

Each GarageNode creates a single-replica StatefulSet and manages that node's layout entry (zone, capacity, tags).

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: storage-node-a
spec:
  clusterRef:
    name: garage
  zone: zone-a
  capacity: 500Gi
  tags: ["ssd", "high-performance"]
  storage:
    metadata:
      size: 10Gi
    data:
      size: 500Gi
      storageClassName: fast-ssd
```

### Gateway Nodes

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: gateway-node
spec:
  clusterRef:
    name: garage
  zone: zone-a
  gateway: true
  storage:
    metadata:
      size: 1Gi
```

### External Nodes

For nodes running outside Kubernetes (bare-metal, NAS, other clusters):

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: external-node
spec:
  clusterRef:
    name: garage
  nodeId: "563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d"
  zone: dc-1
  capacity: 1Ti
  external:
    address: nas.local
    port: 3901
```

External nodes require `nodeId` (64-hex-char Ed25519 public key). No StatefulSet is created — the operator only manages the layout entry.

### Per-Node Overrides

GarageNode supports overriding cluster defaults: `image`, `imageRepository`, `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `priorityClassName`, `imagePullPolicy`, `imagePullSecrets`, `serviceAccountName`, `securityContext`, `containerSecurityContext`, and `topologySpreadConstraints`.

### Status

```bash
kubectl get garagenodes
# NAME              CLUSTER   ZONE    CAPACITY   GATEWAY   CONNECTED   INLAYOUT   AGE
# storage-node-a    garage    zone-a  500Gi      false     true        true       5m
```

The controller auto-discovers node IDs from pods, reconciles layout drift (zone/capacity/tags), and handles node removal with replication-safe finalization.

## Scaling

GarageCluster supports the Kubernetes [scale subresource](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#scale-subresource), enabling `kubectl scale` and compatibility with autoscalers like VPA and HPA.

```bash
kubectl scale garagecluster garage --replicas=5
```

The scale subresource targets `.spec.storage.replicas` on v1beta2 and `.spec.replicas` on v1beta1. Gateway-tier replicas are not exposed via the scale subresource — adjust `spec.gateway.replicas` directly or via a separate HPA on the `<cluster>-gateway` Deployment. The operator populates `status.storageReplicas`, `status.gatewayReplicas`, `status.readyReplicas`, and `status.selector` for the scale subresource to function correctly.

## PVC Retention Policy

By default, PVCs created by a GarageCluster's StatefulSet are **not deleted** when the cluster is deleted or scaled down. This is intentional: Garage stores your data in those volumes, and automatic deletion would be irreversible.

The behavior is controlled by `spec.storage.pvcRetentionPolicy`:

| Field | Value | Behavior |
|-------|-------|----------|
| `whenDeleted` | `Retain` (default) | PVCs survive GarageCluster deletion — manual cleanup required |
| `whenDeleted` | `Delete` | PVCs are deleted automatically when the GarageCluster is deleted |
| `whenScaled` | `Retain` (default) | PVCs for scaled-down pods are kept (allows scaling back up) |
| `whenScaled` | `Delete` | PVCs for removed replicas are deleted on scale-down |

For dev/test clusters where you want automatic cleanup:

```yaml
spec:
  storage:
    pvcRetentionPolicy:
      whenDeleted: Delete
      whenScaled: Delete
```

Requires Kubernetes 1.23+. For production clusters, leave this unset (defaults to `Retain`) or set `whenScaled: Delete` only if you're confident scaled-down nodes won't need their data again.

## Multi-HDD Storage

Garage [supports](https://garagehq.deuxfleurs.fr/documentation/operations/multi-hdd/) striping a node's data across multiple disks. To use it, set `spec.storage.data.paths[]` instead of `spec.storage.data.size` — the operator emits one PVC + one volumeMount per path, and renders the matching `data_dir` TOML array.

```yaml
spec:
  storage:
    replicas: 3
    metadata:
      size: 10Gi
    data:
      paths:
        - path: /data/data0
          volume:
            size: 1Ti
            storageClassName: fast-ssd
        - path: /data/data1
          volume:
            size: 4Ti
            storageClassName: bulk-hdd
        - path: /mnt/archive
          readOnly: true   # legacy disk, read-only mount, no capacity
```

PVCs are named `data-<index>-<cluster>-<ord>` (e.g. `data-0-garage-0`). The Garage `data_dir` `capacity` value is taken from `path.capacity` if set, otherwise from `volume.size`. A `readOnly: true` path is mounted read-only and emits `read_only = true` in `data_dir` — capacity is not required.

> **Migration from a single-path cluster:** `StatefulSet.spec.volumeClaimTemplates` is immutable, so switching an existing cluster to `paths[]` requires `kubectl delete sts <cluster> --cascade=orphan -n <ns>` then deleting the orphan `data-<cluster>-*` PVC before re-applying. Node identity lives in the metadata PVC and is preserved.

## Custom Container Environment Variables

Both tiers expose `env` and `envFrom` for injecting arbitrary env vars into the Garage container. Built-in vars (`GARAGE_NODE_HOST`, log sinks) are set first; user entries are appended after, so a user-supplied `GARAGE_NODE_HOST` would shadow the built-in.

```yaml
spec:
  storage:
    env:
      - name: GARAGE_ALLOW_WORLD_READABLE_SECRETS
        value: "true"
    envFrom:
      - secretRef:
          name: garage-extra-config
  gateway:
    env:
      - name: RUST_BACKTRACE
        value: "full"
```

## Operational Annotations

One-shot operational commands are triggered by setting annotations on the resource. The operator processes the annotation, acts on it, removes it, and records the result in `status.lastOperation`. If the operation fails, the annotation is retained so the next reconcile retries.

### Maintenance Mode

To suspend reconciliation during planned maintenance, use `spec.maintenance.suspended`:

```yaml
spec:
  maintenance:
    suspended: true
```

The operator requeues every 5 minutes but makes no changes while suspended. Clear the field to resume.

> **Deprecated:** The `garage.rajsingh.info/pause-reconcile: "true"` annotation still works but `spec.maintenance.suspended` is preferred — it is version-controlled, visible in `kubectl get`, and works with GitOps tools.

### GarageCluster

| Annotation | Value | Action |
|---|---|---|
| `garage.rajsingh.info/trigger-snapshot` | `"true"` | Trigger a metadata database snapshot on all nodes. Keeps the 2 most recent snapshots. |
| `garage.rajsingh.info/trigger-repair` | repair type | Launch a repair operation on all nodes. Valid types: `Tables`, `Blocks`, `Versions`, `MultipartUploads`, `BlockRefs`, `BlockRc`, `Rebalance`, `Aliases`, `ClearResyncQueue`. |
| `garage.rajsingh.info/scrub-command` | command | Control the block integrity scrub worker on all nodes. Valid commands: `start`, `pause`, `resume`, `cancel`. |
| `garage.rajsingh.info/revert-layout` | `"true"` | Discard all staged layout changes. Does **not** undo an already-applied layout version — only clears the pending staging area. |
| `garage.rajsingh.info/retry-block-resync` | `"true"` or hashes | Clear the resync backoff for blocks so they are retried immediately. Use `"true"` to retry all errored blocks, or a comma-separated list of 64-hex-char block hashes to retry specific ones. |
| `garage.rajsingh.info/purge-blocks` | hashes | **Irreversible.** Permanently delete all S3 objects that reference the listed blocks. Value is a comma-separated list of 64-hex-char block hashes. Only use when you are certain the data is unrecoverable and must be removed from the cluster. |
| `garage.rajsingh.info/force-layout-apply` | `"true"` | Force-apply a staged layout version. |
| `garage.rajsingh.info/connect-nodes` | `nodeId@addr:port,...` | Connect to external nodes (one-shot federation bootstrap). |

**Example — trigger a Tables repair and check the result:**
```bash
kubectl annotate garagecluster garage garage.rajsingh.info/trigger-repair=Tables
kubectl get garagecluster garage -o jsonpath='{.status.lastOperation}'
# {"type":"Repair:Tables","triggeredAt":"2026-05-02T10:00:00Z","succeeded":true}
```

**Example — discard staged layout changes:**
```bash
kubectl annotate garagecluster garage garage.rajsingh.info/revert-layout=true
```

**Example — retry all block resync errors:**
```bash
kubectl annotate garagecluster garage garage.rajsingh.info/retry-block-resync=true
# Or retry specific blocks:
kubectl annotate garagecluster garage \
  'garage.rajsingh.info/retry-block-resync=abc123...,def456...'
```

**Example — purge a lost block (last resort):**
```bash
# First confirm the block is truly unrecoverable with: garage block list-errors
kubectl annotate garagecluster garage \
  'garage.rajsingh.info/purge-blocks=abc123def456...'
```

**Example — run and then pause a scrub:**
```bash
kubectl annotate garagecluster garage garage.rajsingh.info/scrub-command=start
# Later...
kubectl annotate garagecluster garage garage.rajsingh.info/scrub-command=pause
```

> **Note:** `trigger-repair: Scrub` is not supported — use `scrub-command: start` instead.

### Operation Status

All triggered operations record their outcome in `status.lastOperation`:

```yaml
status:
  lastOperation:
    type: "Repair:Blocks"
    triggeredAt: "2026-05-02T10:00:00Z"
    succeeded: true
```

On failure, `succeeded: false` and `error` contains the message. The annotation is kept so the next reconcile retries automatically.

### GarageBucket

| Annotation | Value | Action |
|---|---|---|
| `garage.rajsingh.info/cleanup-mpu` | `"true"` | Delete incomplete multipart uploads older than the threshold (default: 24h). |
| `garage.rajsingh.info/cleanup-mpu-older-than` | duration | Age threshold for MPU cleanup (e.g. `"12h"`, `"30m"`). Only used with `cleanup-mpu`. Defaults to `24h` if absent or invalid. |

**Example — clean up stale uploads older than 48 hours:**
```bash
kubectl annotate garagebucket my-bucket \
  garage.rajsingh.info/cleanup-mpu=true \
  garage.rajsingh.info/cleanup-mpu-older-than=48h
```

## Worker Tuning

Garage runs several background workers that can be tuned at runtime. Set `spec.workers` to configure them — the operator applies the values on every reconcile so they persist across pod restarts.

```yaml
spec:
  workers:
    scrubTranquility: 4      # default: 2, higher = slower scrub, less disk pressure
    resyncWorkerCount: 2     # default: 1, range: 1-8
    resyncTranquility: 4     # default: 2, higher = slower resync
```

| Field | Garage variable | Default | Notes |
|---|---|---|---|
| `scrubTranquility` | `scrub-tranquility` | 2 | Pauses between block integrity checks. Higher = less disk I/O. |
| `resyncWorkerCount` | `resync-worker-count` | 1 | Parallel block resync goroutines. Max 8. |
| `resyncTranquility` | `resync-tranquility` | 2 | Pauses between block resyncs. Higher = less disk I/O. |

Current values are visible in `status.workers.variables`. Unset fields leave the corresponding Garage default unchanged.

## Website Hosting

Website hosting is **enabled by default** on every GarageCluster. Buckets with website hosting enabled are served at `<bucket>.<root-domain>` on port 3902.

The default `rootDomain` is `.<cluster-name>.<namespace>.svc`, so a bucket named `my-site` on a cluster named `garage` in namespace `default` is accessible at `my-site.garage.default.svc:3902`.

To use a custom domain:

```yaml
spec:
  webApi:
    rootDomain: ".web.garage.example.com"
```

Then enable website hosting on a bucket:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: my-site
spec:
  clusterRef:
    name: garage
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
```

The site is served at `my-site.web.garage.example.com:3902`. Point DNS (wildcard CNAME or per-bucket) at the Garage service, and optionally front it with an ingress or HTTPRoute.

Once website hosting is enabled and the bucket has a global alias, the operator populates `status.websiteUrl`:

```bash
kubectl get garagebucket my-site -o jsonpath='{.status.websiteUrl}'
# http://my-site.web.garage.example.com
```

Other options:

```yaml
spec:
  webApi:
    rootDomain: ".web.garage.example.com"
    bindPort: 8080           # default: 3902
    addHostToMetrics: true   # adds domain to Prometheus labels
```

To disable website hosting entirely:

```yaml
spec:
  webApi:
    disabled: true
```

## Bucket Lifecycle Policies

Object expiration and incomplete multipart upload cleanup are configured via `spec.lifecycle` on a `GarageBucket`. The operator applies the rules using an internal S3 key it manages per cluster. Rules are evaluated by Garage's lifecycle worker, which runs daily at midnight UTC.

Garage supports a strict subset of the AWS S3 lifecycle spec: `Expiration` (by age or fixed date) and `AbortIncompleteMultipartUpload`, with optional prefix and object size filters. Tag filters are not supported.

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: my-bucket
spec:
  clusterRef:
    name: garage
  lifecycle:
    rules:
      - id: expire-logs
        status: Enabled
        filter:
          prefix: "logs/"
        expirationDays: 30

      - id: expire-old-uploads
        status: Enabled
        abortIncompleteMultipartUploadDays: 7

      - id: expire-on-date
        status: Enabled
        filter:
          prefix: "archive/"
          objectSizeGreaterThan: 1048576   # bytes
        expirationDate: "2027-01-01T00:00:00Z"
```

`expirationDays` and `expirationDate` are mutually exclusive within a rule. `expirationDate` must be midnight UTC.

Active rules are reflected in `status.lifecycleRules`:

```bash
kubectl get garagebucket my-bucket -o jsonpath='{.status.lifecycleRules}'
# [{"id":"expire-logs","status":"Enabled"},{"id":"expire-old-uploads","status":"Enabled"}]
```

To remove all lifecycle rules, set `spec.lifecycle.rules: []` (empty list). Omitting `spec.lifecycle` entirely leaves existing rules unchanged.

## K2V API

The [K2V API](https://garagehq.deuxfleurs.fr/documentation/reference-manual/k2v/) provides a key-value store on top of Garage. Add `k2vApi` to enable it:

```yaml
spec:
  k2vApi:
    bindPort: 3904  # default
```

Omit `k2vApi` entirely to disable. The K2V endpoint is exposed on the same Service as the S3 API.

## Namespace Isolation

By default, all cross-namespace references are **denied**. A `GarageKey` in namespace `team-b` cannot reference a `GarageCluster` or `GarageBucket` in namespace `storage-admin` unless the admin of `storage-admin` explicitly grants it.

### GarageReferenceGrant

`GarageReferenceGrant` (short: `grg`) lives in the **destination** namespace — the one that owns the `GarageCluster` or `GarageBucket`. Only admins of that namespace can create it, so tenants cannot self-grant access.

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReferenceGrant
metadata:
  name: allow-team-b
  namespace: storage-admin      # destination namespace
spec:
  from:
    - kind: GarageKey
      namespace: team-b         # who is allowed to reference
    - kind: GarageBucket
      namespace: team-b
  to:
    - kind: GarageCluster
      name: my-cluster          # specific cluster (omit name to allow all)
```

Once this grant exists, `team-b` can create a `GarageKey` that references the cluster cross-namespace:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: my-key
  namespace: team-b
spec:
  clusterRef:
    name: my-cluster
    namespace: storage-admin    # cross-namespace — requires the grant above
  bucketPermissions:
    - bucketRef:
        name: my-bucket
      read: true
      write: true
```

The same grant mechanism applies to:
- `GarageKey.spec.clusterRef` — which cluster the key belongs to
- `GarageKey.spec.bucketPermissions[].bucketRef.namespace` — cross-namespace bucket references
- `GarageBucket.spec.clusterRef` — cross-namespace cluster for a bucket
- `GarageAdminToken.spec.clusterRef` — cross-namespace cluster for an admin token

`GarageNode` does **not** support cross-namespace cluster references — node management is always same-namespace.

### Generated Secrets

Secrets generated by `GarageKey` and `GarageAdminToken` are always written to the same namespace as the resource. To make a secret available in another namespace, use a tool like [ExternalSecrets](https://external-secrets.io/) or [Reflector](https://github.com/emberstack/kubernetes-reflector).

### Multi-Tenant Setup Example

A typical setup: the platform team owns `storage-admin`, tenants live in their own namespaces.

```
storage-admin/
  GarageCluster: main-cluster
  GarageReferenceGrant: allow-team-a (→ team-a GarageKey + GarageBucket)
  GarageReferenceGrant: allow-team-b (→ team-b GarageKey)

team-a/
  GarageBucket: team-a-bucket   (clusterRef.namespace: storage-admin)
  GarageKey: team-a-key         (clusterRef.namespace: storage-admin)

team-b/
  GarageKey: team-b-key         (clusterRef.namespace: storage-admin)
```

Tenants can only access what the platform team grants them. Revoking access is as simple as deleting the `GarageReferenceGrant`.

## Multi-Cluster Federation

Garage supports federating clusters across Kubernetes clusters for geo-distributed storage. All clusters share the same RPC secret and Garage distributes replicas across zones automatically.

1. Create the same RPC secret in every Kubernetes cluster:
   ```bash
   SECRET=$(openssl rand -hex 32)
   kubectl create secret generic garage-rpc-secret --from-literal=rpc-secret=$SECRET
   ```

2. For **uniform clusters** (all nodes identical), use `GarageCluster` with a shared/global `publicEndpoint`:
   ```yaml
   apiVersion: garage.rajsingh.info/v1beta2
   kind: GarageCluster
   metadata:
     name: garage
   spec:
     zone: us-east-1
     replication:
       factor: 3
     storage:
       replicas: 3
       metadata:
         size: 10Gi
       data:
         size: 100Gi
     network:
       rpcSecretRef:
         name: garage-rpc-secret
         key: rpc-secret
     publicEndpoint:
       type: LoadBalancer   # single shared/global LB; all pods share one external RPC endpoint
     remoteClusters:
       - name: eu-west
         zone: eu-west-1
         connection:
           adminApiEndpoint: "http://garage-eu.example.com:3903"
           adminTokenSecretRef:
             name: garage-admin-token
             key: admin-token
     admin:
       adminTokenSecretRef:
         name: garage-admin-token
         key: admin-token
   ```

   Shared LoadBalancer mode is intentionally still supported. It is the smallest configuration when your load balancer provides one stable, externally-routable RPC endpoint for the cluster. If you need one externally-routable RPC endpoint per pod, add:
   ```yaml
   publicEndpoint:
     type: LoadBalancer
     loadBalancer:
       perNode: true
   ```
   In auto-layout `GarageCluster` mode, this creates one LoadBalancer service per StatefulSet pod and the operator uses those addresses for reverse `ConnectClusterNodes` calls. The Garage pods still share a single ConfigMap, so this mode does not write distinct per-pod `rpc_public_addr` values into Garage's own config.

3. For **per-node advertised RPC addresses** (recommended when every storage node needs its own stable public address in Garage config), use `layoutPolicy: Manual` with individual `GarageNode` resources — each node gets its own LoadBalancer service and `rpc_public_addr`:
   ```yaml
   # GarageCluster (no storage/gateway tier, no publicEndpoint — nodes are defined by GarageNode CRs below)
   apiVersion: garage.rajsingh.info/v1beta2
   kind: GarageCluster
   metadata:
     name: garage
   spec:
     layoutPolicy: Manual
     zone: us-east-1
     replication:
       factor: 3
     network:
       rpcSecretRef:
         name: garage-rpc-secret
         key: rpc-secret
     admin:
       adminTokenSecretRef:
         name: garage-admin-token
         key: admin-token
   ---
   # One GarageNode per storage node
   apiVersion: garage.rajsingh.info/v1beta1
   kind: GarageNode
   metadata:
     name: garage-node-0
   spec:
     clusterRef:
       name: garage
     zone: us-east-1
     capacity: 500Gi
     storage:
       metadata:
         size: 10Gi
       data:
         size: 500Gi
     publicEndpoint:
       type: LoadBalancer   # operator creates garage-node-0-rpc service
       # rpc_public_addr is auto-derived from the LB ingress IP
   ```
   Each `GarageNode` creates a separate StatefulSet and its own `<node>-rpc` LoadBalancer service. The operator writes the node-specific `rpc_public_addr` into the per-node ConfigMap automatically.

   To set `rpc_public_addr` manually (e.g. for a static hostname), use `spec.network.rpcPublicAddr` instead:
   ```yaml
   spec:
     network:
       rpcPublicAddr: "garage-node-0.example.com:3901"
   ```

The operator handles node discovery, layout coordination, and health monitoring across clusters. See the [Garage documentation](https://garagehq.deuxfleurs.fr/documentation/cookbook/real-world/) for networking requirements.

### Cross-region gateway peering

When remote clusters run multiple gateway pods (`gateway.replicas > 1`) behind a shared external hostname (e.g. one Tailscale LB per region), the load balancer routes each `ConnectClusterNodes` call to *one* of N pods — the rest stay listed in `layout.all_nodes()` as `Not connected` and break FullReplication quorum reads/writes (`GetKeyInfo`, `DeleteKey`, cross-region key/bucket writes).

Set `remoteClusters[].connection.gatewayRpcEndpointTemplate` to a per-ordinal hostname pattern and the operator dials each remote gateway pod individually. The literal `{ordinal}` is substituted with each pod's ordinal parsed from its layout role tag (`garage-gateway-0`, `garage-gateway-1`, …).

```yaml
spec:
  remoteClusters:
    - name: eu-west
      zone: eu-west-1
      connection:
        adminApiEndpoint: "http://garage-eu.example.com:3903"
        gatewayRpcEndpointTemplate: "garage-eu-gw-{ordinal}.example.com:3901"
        adminTokenSecretRef:
          name: garage-admin-token
          key: admin-token
```

Provision the per-ordinal hostnames separately — typically one `LoadBalancer` Service per gateway pod with a `statefulset.kubernetes.io/pod-name` selector. Leaving the template empty preserves the old single-hostname behavior.

## Monitoring

The operator integrates with Prometheus Operator for metrics scraping and alerting.

### ServiceMonitor

Enable `spec.monitoring` on a `GarageCluster` to create a `ServiceMonitor` targeting the admin API `/metrics` endpoint. Covers both Auto-mode pods and Manual-mode `GarageNode` pods via the `garage.rajsingh.info/cluster` label selector.

```yaml
spec:
  monitoring:
    enabled: true
    interval: 30s          # optional, defaults to Prometheus global interval
    additionalLabels:
      release: monitoring  # match your Prometheus serviceMonitorSelector
```

If the cluster uses `metricsTokenSecretRef`, the generated ServiceMonitor will include `Authorization: Bearer` from that secret. Ensure your Prometheus instance has RBAC to `get` secrets in the Garage namespace.

### PrometheusRules

The Helm chart includes alerting rules covering node availability, cluster health (quorum, partitions, disconnected nodes), RPC error rate, block resync errors, and low disk space:

```yaml
# values.yaml
prometheusRules:
  enabled: true
  labels:
    release: monitoring
```

### Grafana Dashboard

The Helm chart ships the official [Garage Prometheus dashboard](https://garagehq.deuxfleurs.fr/documentation/cookbook/monitoring/) as a ConfigMap:

```yaml
# values.yaml
grafanaDashboard:
  enabled: true
  labels:
    grafana_dashboard: "1"    # Grafana sidecar pattern
```

If you use the **Grafana Operator** (`grafana.integreatly.org`), create a `GrafanaDashboard` CR in the same namespace as your cluster pointing at the ConfigMap:

```yaml
apiVersion: grafana.integreatly.org/v1beta1
kind: GrafanaDashboard
metadata:
  name: garage
  namespace: garage           # same namespace as the ConfigMap
spec:
  allowCrossNamespaceImport: true
  instanceSelector:
    matchLabels:
      grafana.internal/instance: grafana
  folder: Garage
  configMapRef:
    name: <release-name>-garage-dashboard
    key: garage-prometheus.json
  datasources:
    - inputName: DS_PROMETHEUS
      datasourceName: Prometheus
```

> **Note**: `grafanaDashboard` in the Helm chart creates a single cluster-agnostic ConfigMap (`<release>-garage-dashboard`). The `GrafanaDashboard` CR pointing at it can live anywhere with `allowCrossNamespaceImport: true`.

## CSI-S3: Mount Buckets as Persistent Volumes

You can use [k8s-csi-s3](https://github.com/yandex-cloud/k8s-csi-s3) to mount Garage buckets as PersistentVolumes via FUSE. This is useful for workloads that need filesystem-style access to S3 data (e.g., shared config, static assets, ML datasets).

1. Create a dedicated bucket and key:
   ```yaml
   apiVersion: garage.rajsingh.info/v1beta1
   kind: GarageBucket
   metadata:
     name: csi-s3
   spec:
     clusterRef:
       name: garage
     globalAlias: csi-s3
     quotas:
       maxSize: 5Ti
       maxObjects: 10000000
     keyPermissions:
       - keyRef:
           name: csi-s3-key
         read: true
         write: true
   ---
   apiVersion: garage.rajsingh.info/v1beta1
   kind: GarageKey
   metadata:
     name: csi-s3-key
   spec:
     clusterRef:
       name: garage
     name: "CSI-S3 Storage Key"
     secretTemplate:
       name: csi-s3-secret
       accessKeyIdKey: accessKeyID
       secretAccessKeyKey: secretAccessKey
       additionalData:
         endpoint: "http://garage.garage.svc.cluster.local:3900"
         region: "garage"
     bucketPermissions:
       - bucketRef:
           name: csi-s3
         read: true
         write: true
   ```

   The `additionalData` fields on the secret template provide the S3 endpoint and region that the CSI driver expects in the secret.

2. Install the CSI driver via Helm:
   ```bash
   helm repo add csi-s3 https://yandex-cloud.github.io/k8s-csi-s3/charts
   helm install csi-s3 csi-s3/csi-s3 \
     --namespace csi-s3 --create-namespace \
     --set storageClass.singleBucket=csi-s3 \
     --set 'storageClass.mountOptions=--memory-limit 1000 --dir-mode 0777 --file-mode 0666' \
     --set secret.create=false
   ```

   Setting `secret.create=false` tells the chart to use the `csi-s3-secret` created by the GarageKey controller.

3. Create a PVC and use it:
   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: my-s3-pvc
   spec:
     accessModes:
       - ReadWriteMany
     storageClassName: csi-s3
     resources:
       requests:
         storage: 10Gi
   ---
   apiVersion: v1
   kind: Pod
   metadata:
     name: test-s3-mount
   spec:
     containers:
       - name: app
         image: busybox
         command: ["sleep", "infinity"]
         volumeMounts:
           - name: data
             mountPath: /data
     volumes:
       - name: data
         persistentVolumeClaim:
           claimName: my-s3-pvc
   ```

> **Note:** FUSE-backed S3 mounts have limitations — no true random writes, no `fsync`, and higher latency than block storage. The csi-s3 namespace requires the `pod-security.kubernetes.io/enforce: privileged` label. For native S3 API access, use GarageKey secrets directly.

## COSI Support (Optional)

The operator includes an optional COSI (Container Object Storage Interface) driver that provides Kubernetes-native object storage provisioning.

### Enabling COSI

> [!IMPORTANT]
> The COSI v1alpha2 API requires `spec.bucketClaimRef` on `Bucket` resources. This
> field is populated by the cluster-wide COSI **controller** — a separate deployment
> from `kubernetes-sigs/container-object-storage-interface`, installed once per
> cluster. Pin the install below to a ref that contains the `BucketClaimRef`-setting
> logic — older builds create `Bucket` objects without it and the operator rejects them.
>
> **Architecture:** The cluster-wide COSI controller reconciles `BucketClaim` →
> `Bucket` and `BucketAccessClaim` → `BucketAccess`. The garage-operator watches the
> resulting `Bucket` and `BucketAccess` objects directly (filtered by `driverName`)
> and translates them into Garage Admin API calls. There is no per-driver sidecar
> container — this was previously the upstream `objectstorage-sidecar`'s role.

1. Install the COSI CRDs (pinned to a known-good ref):
   ```bash
   COSI_REF=bf23a024f511482856f047525f732f26c61e2b85
   for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
     kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/${COSI_REF}/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
   done
   ```

2. Deploy the COSI controller (pinned — required for `bucketClaimRef` to be populated):
   ```bash
   kubectl apply -k "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=${COSI_REF}"
   ```

3. Install the operator with COSI enabled:
   ```bash
   helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
     --namespace garage-operator-system \
     --create-namespace \
     --set cosi.enabled=true
   ```

### Using COSI

1. Create a BucketClass:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketClass
   metadata:
     name: garage-standard
   spec:
     driverName: garage.rajsingh.info
     deletionPolicy: Delete
     parameters:
       clusterRef: garage
       clusterNamespace: garage-operator-system
   ```

2. Create a BucketAccessClass:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketAccessClass
   metadata:
     name: garage-readwrite
   spec:
     driverName: garage.rajsingh.info
     authenticationType: Key
     parameters:
       clusterRef: garage
       clusterNamespace: garage-operator-system
   ```

3. Request a bucket:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketClaim
   metadata:
     name: my-bucket
   spec:
     bucketClassName: garage-standard
     protocols:
     - S3
   ```

4. Request access credentials:
   ```yaml
   apiVersion: objectstorage.k8s.io/v1alpha2
   kind: BucketAccess
   metadata:
     name: my-bucket-access
   spec:
     bucketAccessClassName: garage-readwrite
     protocol: S3
     bucketClaims:
       - bucketClaimName: my-bucket
         accessMode: ReadWrite
         accessSecretName: my-bucket-creds
   ```

5. Use the credentials in your application:
   ```yaml
   env:
   - name: S3_ENDPOINT
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ENDPOINT
   - name: AWS_ACCESS_KEY_ID
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ACCESS_KEY_ID
   - name: AWS_SECRET_ACCESS_KEY
     valueFrom:
       secretKeyRef:
         name: my-bucket-creds
         key: COSI_S3_ACCESS_SECRET_KEY
   ```

### COSI Limitations

- Only S3 protocol is supported
- Only Key authentication is supported (no IAM)
- Bucket deletion requires the bucket to be empty first
- Upstream COSI controller does not yet implement deletion — `DriverDeleteBucket` and `DriverRevokeBucketAccess` are implemented but won't be called until upstream adds support

## Documentation

- [Helm Chart](charts/garage-operator/) - Installation and configuration
- [Garage Docs](https://garagehq.deuxfleurs.fr/) - Garage project documentation

## Development

```bash
make dev-up       # Start kind cluster with operator
make dev-test     # Apply test resources
make dev-status   # View cluster status
make dev-logs     # Stream operator logs
make dev-down     # Tear down
```
