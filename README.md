# Garage Kubernetes Operator

<p align="center">
  <img src="logo.svg" alt="Garage Kubernetes Operator" width="128" height="128">
</p>

<p align="center">
  <strong>S3-Compatible Object Storage on Kubernetes</strong>
</p>

<p align="center">
  <a href="https://rajsinghtech.github.io/garage-operator/">Read the operator documentation</a> ·
  <a href="https://github.com/rajsinghtech/garage-operator/releases">Releases</a> ·
  <a href="https://github.com/rajsinghtech/garage-operator/issues">Support</a>
</p>

<p align="center">
  <a href="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml"><img src="https://github.com/rajsinghtech/garage-operator/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/rajsinghtech/garage-operator"><img src="https://goreportcard.com/badge/github.com/rajsinghtech/garage-operator" alt="Go Report Card"></a>
  <a href="https://github.com/rajsinghtech/garage-operator/releases/latest"><img src="https://img.shields.io/github/v/release/rajsinghtech/garage-operator" alt="Latest Release"></a>
  <a href="https://deepwiki.com/rajsinghtech/garage-operator"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
</p>

A Kubernetes operator for [Garage](https://garagehq.deuxfleurs.fr/) - distributed, self-hosted object storage with multi-cluster federation.

- **Declarative cluster lifecycle** — StatefulSet, config, and layout managed via CRDs
- **Unified storage + gateway tiers in one CR** (v1beta2) — combine durable storage pods and persistent-identity S3 gateways in a single `GarageCluster`
- **Node-local pools** — bind Garage identities to selected Kubernetes Nodes and HostPath disks, including multi-disk layouts
- **Bucket & key management** — create buckets, quotas, and S3 credentials with kubectl
- **Multi-cluster federation** — span storage across Kubernetes clusters with automatic node discovery
- **Persistent-identity gateway pods** — StatefulSet with a small metadata PVC; gateway pods keep the same Garage node identity across restarts and participate in the cluster layout with `capacity: null` (matching upstream `garage layout assign --gateway`)
- **Scale subresource** — `kubectl scale` and autoscaler support for the Auto-managed default storage group (and v1beta1 edge gateways)
- **COSI driver** — optional Kubernetes-native object storage provisioning

## Custom Resources

| CRD | Description |
|-----|-------------|
| `GarageCluster` | Deploys and manages a Garage cluster (storage and/or gateway tiers) |
| `GarageBucket` | Creates buckets with quotas and website hosting |
| `GarageKey` | Provisions S3 access keys with per-bucket permissions |
| `GarageNode` | Fine-grained node layout control (zone, capacity, tags) |
| `GarageAdminToken` | Creates static Admin bootstrap material in a namespace-local Secret |
| `GarageReferenceGrant` | Grants selected cross-namespace access to clusters, buckets, and keys |

## Install

Requires Kubernetes 1.25+, or **1.27+ if you use
[node-local pools](#node-local-pools-daemonset-backed)**, which
depend on Pod scheduling gates for their activation fence.

The Helm chart enables admission and conversion webhooks by default, so install
cert-manager first. Disabling webhooks is limited to local development or
simple v1beta2-only installs that neither use `nodeLocalPools` nor rely on
admission-protected storage deletion. It removes those safety checks and all
v1beta1 conversion support; node-local pools and controller-managed persistent
claims do not support that mode. `EmptyDir` remains fully supported there;
explicit `existingClaim` volumes can be mounted, but their PVC-backed rollout
and recovery paths remain fenced until admission is enabled. The
webhooks also reserve managed PVC finalizer removal to the operator service
account, preventing namespace users with PVC update rights from reopening a
same-name claim replacement race before StatefulSet ownership is established.

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

### Verifying release artifacts

Released container images and Helm charts are signed with [cosign](https://docs.sigstore.dev/) keyless signing (the GitHub Actions OIDC identity — no long-lived keys), and carry SLSA build provenance. The image additionally carries an SPDX SBOM. All three are stored in GHCR as OCI referrers of the artifact digest.

```bash
IMAGE=ghcr.io/rajsinghtech/garage-operator:v0.7.4

# Signature
cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github.com/rajsinghtech/garage-operator/\.github/workflows/docker\.yml@refs/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Provenance and SBOM
gh attestation verify "oci://$IMAGE" --repo rajsinghtech/garage-operator
cosign download attestation "$IMAGE" --predicate-type https://spdx.dev/Document/v2.3
```

The Helm chart is signed the same way (`--certificate-identity-regexp` ending in `helm\.yml@refs/`), and `dist/install.yaml` attached to each GitHub release has a provenance attestation verifiable with `gh attestation verify install.yaml --repo rajsinghtech/garage-operator`.

Under a policy controller, pin by digest and require the signature — e.g. Kyverno `verifyImages` with `keyless.issuer: https://token.actions.githubusercontent.com` and the subject regexp above.

## Garage Version Compatibility

The Garage version is yours to choose — `GarageCluster.spec.image`, `GarageNode.spec.image`, or the chart-wide `defaultGarageImage`. The chart's `appVersion` tracks the *operator*, not Garage.

| Operator | Garage minimum | Garage tested in CI | Notes |
|---|---|---|---|
| 0.7.x | **v2.0.0** | v2.3.0, v2.2.0 | Admin API v2; node-local pools require Kubernetes 1.27+ |
| 0.6.x | **v2.0.0** | v2.3.0, v2.2.0 | Admin API v2 only |

`dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690` is the built-in default when `spec.image` is unset, so default deployments use the exact tested multi-platform image index. CI exercises two versions on purpose: the Ginkgo suite runs the pinned v2.3.0 index and the topology suites (multi-cluster, external gateway, IPv6, single-cluster) run the pinned v2.2.0 index, which is what backs the "v2.x range" claim rather than a single number.

**Garage 0.x and 1.x are not supported.** The operator drives buckets, keys, layout, and repair exclusively through the `/v2/...` admin API, which first shipped in Garage v2.0.0. Against an older node every admin call 404s and no cluster will reconcile.

Some fields need a newer Garage than the v2.0.0 floor:

| Field | Requires | Behavior on older Garage |
|---|---|---|
| `GarageBucket.spec.lifecycle` | v2.3.0 | Older nodes accept the write and drop the field. The operator reads the rules back and sets `LifecycleConfigured=False` naming this requirement, rather than reporting a success that never took effect. The bucket itself still reconciles. |
| `GarageCluster.spec.database.engine: fjall`, `spec.database.fjallBlockCacheSize` | v2.1.0 | Unknown config key, silently ignored; Garage falls back to the default engine |
| `GarageCluster.spec.blocks.maxConcurrentReads` | v2.1.0 | Silently ignored |
| `GarageCluster.spec.blocks.maxConcurrentWritesPerRequest` | v2.2.0 | Silently ignored |

Garage's TOML parser ignores unknown keys, so setting a too-new config field degrades to a no-op rather than a crashloop. The operator only emits these keys when you set the corresponding field.

The Garage version each cluster is actually running is reported back on the CR:

```bash
kubectl get garagecluster garage -o jsonpath='{.status.buildInfo.version}'
```

## API Versions

`GarageCluster` is served under two API versions; all other CRDs are `v1beta1`.

| Version | Status | Schema |
|---|---|---|
| `garage.rajsingh.info/v1beta2` | **Current** (storage version, recommended) | Tier-based: `spec.storage` and/or `spec.gateway` |
| `garage.rajsingh.info/v1beta1` | Deprecated, still served | Legacy flat schema: `spec.replicas`, `spec.gateway: bool` |

A conversion webhook handles reads and writes in both directions, so existing v1beta1 manifests continue to work unchanged. The controller operates on v1beta2 internally. New clusters should be written as v1beta2.

`kubectl scale` is supported for an Auto-managed default storage group on both
versions: the scale subresource targets `.spec.storage.replicas` on v1beta2 and
`.spec.replicas` on v1beta1. A gateway-only v1beta1 view retains its historical
gateway Scale behavior when clients explicitly target the v1beta1 resource;
the preferred v1beta2 endpoint and Manual shapes do not expose a controllable
scalable group. A v1beta2
CR that declares **both** `storage` and `gateway` has no faithful v1beta1 form;
the conversion webhook returns only the storage tier when read as v1beta1 and
marks the v1beta2-only gateway payload. `spec.storage.nodeLocalPools` is also
v1beta2-only. A reserved conversion payload preserves it through a v1beta1
read/write round trip, but v1beta1 clients cannot edit it. Tools that manage
either unified tiers or node-local pools must use v1beta2.

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

`spec.gateway` runs S3/Admin proxies that store no object blocks (data dir is `EmptyDir`). Its workload shape depends on the topology:

- **Unified cluster** (gateway alongside `spec.storage`): the gateway tier is reconciled as one per-pod `GarageNode` (`<cluster>-gateway-N`, `gateway: true`) — symmetric with the storage tier — each owning a single-replica `StatefulSet` with a small **persistent metadata PVC** (default 1Gi). Its StatefulSet leaves the Kubernetes PVC-retention policy unset, so the default is `Retain` on scale-down and deletion.
- **Edge gateway** (gateway-only CR + `connectTo`): the tier stays a single cluster-level `StatefulSet` (`<cluster>-gateway`) because its layout lives on a remote storage cluster. This StatefulSet explicitly uses `Delete`/`Delete` PVC retention.

`gateway.metadata.type: EmptyDir` is an explicit ephemeral-identity option for
either managed shape. In Manual unified mode, configure metadata on each
user-owned gateway `GarageNode`; the webhook rejects the unused cluster-level
field. Gateway metadata supports the ordinary size, class, access-mode,
selector, label, and annotation controls. The selector applies only when a new
claim is created in either managed shape and requires a compatible
pre-provisioned PV; `paths` and
`volumeClaimTemplateSpec` are rejected because arbitrary PVC sources can clone
or misbind the identity-bearing `node_key`. To change an edge gateway's
metadata source or PVC template, first scale
`spec.gateway.replicas` to zero and wait for its capacity-less roles to retire.
This prevents an accepted edit from silently leaving an immutable StatefulSet
claim template unchanged.

Gateway pods participate in the cluster layout with `capacity: null` (matching upstream `garage layout assign --gateway`). This is required: Garage's S3 sig-auth path uses `key_table.get_local()` — only nodes in `layout.all_nodes()` receive FullReplication writes for `key_table` / `bucket_table` / `admin_token_table`. A gateway outside the layout therefore lacks the local authentication record and returns `403 Forbidden: No such key`; Garage v2.3.0 does not fall back to a quorum read here. The `capacity: null` role keeps authentication local and available without an RPC to the storage tier. Scale-downs are tombstone-cleaned (see [Gateway tombstone cleanup](#gateway-tombstone-cleanup)).

A `GarageCluster` must set at least one of `storage`, `gateway`, or `connectTo`. The webhook also rejects `gateway` without either `storage` (unified pattern) or `connectTo` (edge pattern). See the [gateway examples](config/samples/garage_v1beta2_garagecluster_gateway.yaml) for more.

### Unified cluster (storage + local gateways)

Most common: one CR declares both tiers in the same namespace. Gateway pods talk to the storage tier over the in-cluster RPC service. In Auto mode the operator generates one gateway `GarageNode` per replica (`<cluster>-gateway-N`, `gateway: true`) alongside the storage tier's `<cluster>-storage-N` nodes — both show up in `kubectl get gn`. Each gateway node gets a `capacity: null` layout role so key/bucket auth resolves locally. They are operator-owned and are handed off to you on an Auto→Manual flip.

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
    # This edge shape has one shared config. Use one replica per independently
    # routed edge identity; use separate edge resources for multiple routes.
    replicas: 1
    # Tells the remote cluster how to dial back to this gateway for bidirectional
    # peering and remote visibility.
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

Or reference a storage `GarageCluster` in the same namespace via `connectTo.clusterRef.name`. The operator opens RPC in both directions (gateway -> external **and** external -> gateway) when a reverse route is configured; without one, an edge gateway may intentionally run forward-only and the remote site cannot dial or expose that gateway identity. The operator re-establishes configured links on drift; see the [gateway sample manifests](config/samples/garage_v1beta2_garagecluster_gateway.yaml) for complete examples.

### Management handle (no owned workload)

A `connectTo`-only `GarageCluster` manages buckets, keys, permissions, and
layout on an existing Garage deployment without adopting its pods or volumes:

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: existing-garage
spec:
  connectTo:
    adminApiEndpoint: http://garage.garage.svc:3903
    adminTokenSecretRef:
      name: garage-admin
      key: admin-token
    # Optional: required only to derive new GarageKey material deterministically.
    rpcSecretRef:
      name: garage-rpc
      key: rpc-secret
```

The operator creates no Garage workload for this shape. When `rpcSecretRef` is
present (or `connectTo.clusterRef` inherits one), it copies the exact value into
an immutable, handle-owned snapshot before reporting `ManagementHandleReady`.
An Admin-only handle needs no RPC secret; imported keys continue to work, and a
first RPC source may be attached later, but that source and value cannot then be
rotated in place.

### Workload differences

| Aspect | Storage tier | Gateway tier (unified) | Gateway tier (edge) |
|---|---|---|---|
| Workload | N × `StatefulSet`s (one per `GarageNode`, `replicas: 1`) | N × `StatefulSet`s (one per gateway `GarageNode`, `replicas: 1`) | `StatefulSet` (`<cluster>-gateway`) |
| Node CRs | one `GarageNode` per replica (Auto: operator-owned `<cluster>-storage-N`; Manual: user-owned) | one `GarageNode` per replica (`<cluster>-gateway-N`, `gateway: true`; operator-owned in Auto) | none |
| Metadata volume | PVC (per node) | PVC (per node, default 1Gi), or explicit `EmptyDir` | PVC (default 1Gi), or explicit `EmptyDir` |
| Data volume | PVC (per node) | `EmptyDir` | `EmptyDir` |
| Pod naming | `<garagenode>-0` | `<cluster>-gateway-N-0` | `<cluster>-gateway-0`, `<cluster>-gateway-1`, … |
| Node identity | persists (metadata PVC) | persists (metadata PVC) | persists (metadata PVC) |
| Layout owner | per-`GarageNode` controller (local) | per-`GarageNode` controller (local), capacity `null` | remote storage cluster (gateway-connection path) |
| Stale-layout cleanup | finalizer on CR deletion | per-node `GarageNode` finalizer; cluster reaper skips live-claimed roles | operator tombstone-reaps on scale-down |

An externally-routable RPC address is required for bidirectional edge peering and
for the remote storage cluster to include the gateway identity in its reachable
node view. If you intentionally need only forward connectivity (the gateway can
reach the remote cluster, but the remote cluster cannot dial the gateway), omit
the address. Garage then advertises the pod IP, the reverse `ConnectNode` cannot
succeed, and the validating webhook emits an admission warning. For a data-less
gateway this is a supported forward-only mode; `GatewayConnected=True` can still
mean healthy forward-only connectivity. Set an address when reverse dialing or
remote visibility is required. The operator checks three fields, in priority order:

1. `spec.gateway.rpcPublicAddr` — **preferred** for an edge gateway (it has no storage tier to inherit from).
2. `spec.network.rpcPublicAddr`.
3. `spec.publicEndpoint` — the operator derives the address from the Kubernetes service status.

The validating webhook emits an admission **warning** when an edge gateway sets `connectTo` but none of these.

For a single edge identity with bidirectional peering, use `publicEndpoint.type: LoadBalancer` without `loadBalancer.perNode`; the operator creates one `<cluster>-rpc` LoadBalancer service and derives one `rpc_public_addr` from it. This is the simplest setup when your infrastructure provides a global/shared load balancer address that routes RPC traffic to that one-replica edge gateway.

For per-pod LoadBalancer services, set `publicEndpoint.type: LoadBalancer` and `publicEndpoint.loadBalancer.perNode: true`; the operator creates `<cluster>-0-rpc`, `<cluster>-1-rpc`, etc. For an **edge** gateway (single cluster-level StatefulSet sharing one ConfigMap) the operator does not write distinct per-pod `rpc_public_addr` values into Garage's config; the per-node service addresses are used only when asking the external cluster to connect back to each gateway node. A shared edge config/address is therefore safe only for one independently routed identity. Use separate one-replica edge resources for multiple routes, or use unified gateway `GarageNode` resources when each identity needs its own advertised address.

The operator establishes connectivity in both directions: gateway → external nodes and external cluster → gateway nodes. It also actively monitors the connection and re-establishes it if Garage marks a peer as unreachable.

> **Note:** `bootstrapPeers` is also accepted for one-shot bootstrapping when you know the node ID in advance, but `adminApiEndpoint` is preferred — it works without knowing node IDs upfront and keeps the connection stable across restarts.

### Gateway tombstone cleanup

When a gateway scales down, its old `capacity: null` layout entries must be removed or they inflate the node count that `consistent`-mode metadata writes (GarageKey/bucket) need for quorum. On each reconcile the operator lists `tier:gateway` layout entries and cross-references them with the live gateway pods **and** the node IDs claimed by live operator-owned gateway `GarageNode`s — a role claimed by an existing `GarageNode` is never removed, so the cluster reaper never fights the per-node finalizer during a brief pod restart.

Removal is governed by `spec.layoutManagement.autoApply`:

- `autoApply: true` — stale entries are removed and the new layout is applied, then normal Garage history convergence is observed. The operator never runs the cluster-wide `skip-dead-nodes` recovery automatically.
- `autoApply: false` (**default**) — exact pending IDs are surfaced on `status.pendingGatewayTombstones` and the `GatewayTombstones` condition, but are not staged. Remove those exact roles with the Garage CLI or enable `autoApply`. `garage.rajsingh.info/force-layout-apply` does not approve tombstones.

## Node-local pools (DaemonSet-backed)

Add `spec.storage.nodeLocalPools` to run node-local, HostPath-backed storage
alongside the existing default operator-managed PVC group or hand-managed
SMB/PVC GarageNodes. This is the operator's equivalent of the upstream Helm
chart's DaemonSet deployment: each entry is realized as one operator-managed
**DaemonSet** running one Garage pod, one generated `GarageNode` identity, and
one Garage layout role per selected Kubernetes Node. The DaemonSet is the
current implementation of the node-local contract, not a selectable workload
kind, so the field is named for the storage it provides rather than the
workload it happens to use.
Each named pool has its own capacity, HostPaths, selector, Pod template, and
optional per-node RPC address template. Explicitly declaring
`spec.storage.nodeLocalPools` enables the node-local pool API. Node-local
pools require Kubernetes 1.27+ for the
Pod scheduling-gate safety fence; other cluster shapes retain the chart's
Kubernetes 1.25 minimum. The controller verifies the server version, performs a
server-side DaemonSet dry run, and requires a real gated probe Pod to receive
`PodScheduled=False` with reason `SchedulingGated` from kube-scheduler before
creating a pool workload or changing Node activation. Successful evidence is
namespace-scoped, cached for at most 30 seconds from kube-scheduler's condition
timestamp, and pinned only for the reconciliation that began from that proof.
The binary and every shipped install enable leader election;
silently disabling it is rejected because layout mutation is process-local.

Node-local pool Pods mount HostPaths. Kubernetes Pod Security Admission's
Baseline and Restricted policies prohibit HostPath volumes, so each workload
namespace that contains a pool needs `pod-security.kubernetes.io/enforce=privileged`
or an equivalent organization-specific exception. This is not required for the
operator namespace itself. Grant GarageCluster write access narrowly because a
pool Pod template controls access to paths on selected Nodes.

Across all node-local entries, selectors may choose at most 255 Nodes. Garage's
global layout limit is 256 positive-capacity roles across every storage backing
and federated site. At 255 live roles the controller admits a new node-local
identity only when it can prove a retiring generated member in its Kubernetes
control plane. That check does not reserve role 256 against independently
operated federated sites: another writer can consume the slot and make the
node-local assignment wait for a committed removal. Federated topology changes
must therefore be externally serialized.

Parent status keeps full per-member detail on label-addressable generated
`GarageNode` resources. Node-local, storage rollout/drain, and repeated-member
health condition messages are capped at 4096 bytes with five inventory examples;
diagnostic layout history is capped at 64 entries, and a crash-safe
rollout records at most 32 retired workload-controller UIDs. A 256-role,
eight-resync-worker drain projection measures 365085 bytes (about 357 KiB); a
conservative coexisting projection with all 26 GarageCluster conditions at
maximum message size measures 966767 bytes (about 944 KiB) and is
regression-capped at 1 MiB. These are explicit release-envelope projections,
not permission to increase Kubernetes object limits.

Pool membership is drain-safe. The operator translates the user selector into
private activation labels, serializes every same-cluster layout writer behind
one coordinator, waits for new identities to enter the
committed layout, drains retired GarageNodes one at a time while their pods
remain online, and removes activation only after finalization. A Kubernetes
Node cannot move directly between pools; unselect and fully drain it before
selecting the new pool.

Every pool Pod starts scheduler-gated. Only the exact current DaemonSet UID is
allowed through after live Node activation, HostPath claim, and competing-Pod
checks, so a late Pod from a retired DaemonSet cannot mount the same local disk.

Committed pool members also carry an internal, stable Garage-ID pin on their
Kubernetes Node. During a cold or same-name cluster recovery, all exact
already-committed roles may restart together, but each child must rediscover
that pinned identity from its own Pod and match the operator-tagged committed
role before any status or layout write. A wiped or swapped HostPath therefore
fails closed instead of enrolling a second identity.

Image, config, and pod-template changes use parent-controlled `OnDelete`
rollout: one pod across the whole GarageCluster is replaced, its identity is
rediscovered from the exact replacement pod, and cluster health/layout history
must settle before another pod is stopped.

Storage deletion is prepared before Kubernetes DELETE. The source process
stays online while Garage removes its role and exact source-plus-destination
repair/resync evidence reaches a terminal quiet window; admission then accepts
only that exact completed actor. Selector scale-down does this automatically.
Direct GarageNode deletion and federated-site retirement use the documented
`garage.rajsingh.info/drain=true` annotate, wait, then delete workflow.
Delete an individual `GarageNode` with default/background propagation; direct
foreground deletion is rejected because it could reap the identity-bearing pod
before finalizer convergence. A parent `GarageCluster` may foreground-cascade
its children only after its terminal Drain handoff, or as part of explicit
whole-store `Destroy` cleanup.

Pools use the operator-wide Garage v2.0.0+ Admin API v2 floor; v2.3.0 is the
tested default. They also require a cluster-scoped install, enabled validating
and conversion webhooks, and an Admin API token. One workload-owning
`GarageCluster` is one Garage store/site lifecycle and ownership boundary,
usually one physical site. Its members may share one static zone or derive
multiple actual failure-domain zones through `zoneFrom`. Express SMB, local
disks, and different local capacities as node-local pools or ordinary
GarageNodes inside it. Positive-capacity removals are a
separate topology-only generation after configuration rollout has converged.
See
[node-local storage guide](docs/node-local-pools.md), the
[mixed-storage sample](config/samples/garage_v1beta2_garagecluster_node_local_pools.yaml),
and the [design](docs/design/2026-07-30-node-local-pools-design.md).

## Failure Domains Inside One Cluster (`zoneFrom`)

`spec.zone` assigns one Garage zone to the whole cluster, which leaves `replication.zoneRedundancyMode` with nothing to act on: upstream computes `Maximum` as `min(distinct zones, replication factor)`, so a single-zone cluster has an effective redundancy of 1. `spec.zoneFrom` derives each storage node's zone from a label on the Kubernetes Node its pod is scheduled to, so one cluster can express racks, power circuits, or per-node domains without splitting into a federation.

```yaml
spec:
  zone: site-a                      # fallback, still required
  zoneFrom:
    nodeLabel: topology.kubernetes.io/zone
  replication:
    factor: 3
    zoneRedundancyMode: Maximum     # now meaningful — 3 copies in 3 domains
  storage:
    replicas: 6
```

Use `kubernetes.io/hostname` for per-node domains, or a custom label such as `example.com/rack` for physical racks.

The zone depends on where the pod landed, so it is resolved after scheduling and re-checked on every reconcile. `spec.zone` is the initial fallback before the Pod is scheduled and whenever the readable Kubernetes Node does not carry the configured label. Once a node has reported an effective `status.zone`, a transient Pod replacement gap retains that last proven value; this prevents an ordinary rollout from flipping the Garage layout to the fallback zone and back. Failure to read a required Kubernetes Node is different: the resource reports `Failed` and the operator does not silently mutate the layout using `spec.zone`. A successfully reconciled node therefore always has a proven zone. The effective value is reported as `status.zone` on each GarageNode and shown in the `ZONE` column:

```bash
kubectl get garagenodes
# NAME              CLUSTER   ZONE     CAPACITY   GATEWAY   CONNECTED   INLAYOUT   AGE
# garage-storage-0  garage    rack-a   500Gi      false     true        true       5m
# garage-storage-1  garage    rack-b   500Gi      false     true        true       5m
```

If a pod moves to a Kubernetes Node in a different domain, the layout is updated to match — Garage minimizes the resulting reassignment rather than reshuffling everything. Nodes whose PVCs pin them to a machine will not move at all.

Scope and caveats:

- **Operator-managed members.** Cluster-level `zoneFrom` applies to generated default-group GarageNodes and to `nodeLocalPools`, including when `storage.layoutPolicy: Manual` disables only the default group. Set `zoneFrom` directly on each user-owned Manual GarageNode.
- **Storage tier only.** It is deliberately not applied to gateway nodes: Garage counts gateway zones toward the `Maximum` redundancy target but satisfies that target from storage nodes only, so per-node gateway zones can make every layout apply fail.
- **`zoneRedundancyMode: AtLeast(n)`** requires the label to resolve to at least *n* distinct values across scheduled storage pods, otherwise layout apply is rejected upstream. The webhook warns about this combination.
- Requires the cluster-scoped install (the default). A namespace-scoped install cannot read Nodes, so affected GarageClusters and GarageNodes report `Failed` instead of silently falling back to `spec.zone`.

## Manual Node Layout (GarageNode)

By default, GarageCluster uses `layoutPolicy: Auto` — the operator generates one operator-owned `GarageNode` per storage replica (named `<cluster>-storage-N`), and each `GarageNode` controller drives its own single-replica StatefulSet. For fine-grained control over individual nodes (per-node zone, capacity, tags, storage class, RPC address, external nodes), set `layoutPolicy: Manual` and create `GarageNode` resources directly.

Each GarageNode creates a single-replica StatefulSet and manages that node's layout entry (zone, capacity, tags). Flipping a cluster from `Auto → Manual` is a one-way hand-off: the operator drops its controllerRef on each `<cluster>-storage-N` GarageNode and the user inherits them. The reverse (`Manual → Auto`) is rejected by the validating webhook.

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

GarageNode supports overriding cluster defaults: `image`, `imageRepository`, `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `priorityClassName`, `imagePullPolicy`, `imagePullSecrets`, `serviceAccountName`, `securityContext`, `containerSecurityContext`, `topologySpreadConstraints`, `env`, `envFrom`, and `logging`, plus per-node `network.rpcPublicAddr`, `publicEndpoint`, and `storage` (fsync, snapshots, `dataPaths`). A node with any of these gets its own `<node>-config` ConfigMap instead of the shared cluster config.

### Per-Node Maintenance

Set `spec.maintenance.suspended: true` on a single `GarageNode` to pause reconciliation of just that node's StatefulSet, ConfigMap, Service, and layout entry — useful for PVC-level work (StorageClass migration, longhorn engine upgrade, disk swap) without the controller fighting you. A `Suspended` status condition is set while paused, and the finalizer/delete path still runs so a suspended node can be deleted.

### Status

```bash
kubectl get garagenodes
# NAME              CLUSTER   ZONE    CAPACITY   GATEWAY   CONNECTED   INLAYOUT   AGE
# storage-node-a    garage    zone-a  500Gi      false     true        true       5m
```

The controller auto-discovers node IDs from pods, reconciles layout drift (zone/capacity/tags), and handles node removal with replication-safe finalization.

## Scaling

GarageCluster supports the Kubernetes [scale subresource](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#scale-subresource) for the Auto-managed default storage group, enabling `kubectl scale` and compatibility with autoscalers such as VPA and HPA for that workload.

```bash
kubectl scale garagecluster garage --replicas=5
```

The scale subresource targets `.spec.storage.replicas` on v1beta2 and `.spec.replicas` on v1beta1. It controls only the Auto-managed default StatefulSet/PVC group. Node-local pool cardinality follows each `storage.nodeLocalPools[].selector`; gateway-tier replicas are not exposed through v1beta2 `/scale`, so adjust `spec.gateway.replicas` directly. A gateway-only v1beta1 object retains its historical gateway Scale mapping. Dedicated `status.scaleReplicas`/`status.scaleSelector` report the actual non-terminating Pods and exact selector for the controllable workload; aggregate status remains separate. Manual storage has no scalable default group—its ordinary GarageNodes are individually owned resources—so HPA/VPA and `kubectl scale` are unsupported for that shape. A separate fail-closed admission handler runs the full GarageCluster topology validation for `/scale`, including active drain and prepared scale-down gates.

Because v1beta2 is the preferred discovery version, legacy edge-gateway scaling
must name the v1beta1 resource explicitly:

```bash
kubectl scale garageclusters.v1beta1.garage.rajsingh.info edge --replicas=5
```

## PVC Retention Policy

By default, PVCs created by a GarageCluster's StatefulSet are **not deleted** when the cluster is deleted or scaled down. This is intentional: Garage stores your data in those volumes, and automatic deletion would be irreversible.

Storage-member behavior is controlled by `spec.storage.pvcRetentionPolicy`:

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

Gateway metadata has a separate `spec.gateway.pvcRetentionPolicy`. An Auto
unified gateway member owns a single-replica StatefulSet and defaults to
Kubernetes `Retain`/`Retain`; an edge gateway keeps its released cluster-level
StatefulSet default of `Delete`/`Delete`. An explicit gateway policy applies to
both managed shapes and never changes storage-member claims. A v1beta1 edge
gateway's released `spec.storage.pvcRetentionPolicy` is losslessly projected to
this field by conversion.

```yaml
spec:
  gateway:
    pvcRetentionPolicy:
      whenDeleted: Retain
      whenScaled: Retain
```

Choose `Delete` only when losing that gateway's persisted `node_key` after its
capacity-less layout role is retired is intentional. Gateway claims contain no
object blocks, but deleting metadata still creates a different Garage identity
on the next start.

> **Note (Auto mode):** automatic storage and gateway topology changes wait until every earlier Garage layout version has left `Draining`. The initial storage bootstrap creates the required members together because no Admin API exists yet; every later scale-up or gateway addition admits one per-node `GarageNode` at a time. Scale-down likewise drains one member at a time and does not begin the next removal until the prior finalizer completes. `StorageTopologyReady=False` reports `AddingMembers`, `DrainingMember`, or `WaitingForLayoutSync`, and cluster `Ready=False`; `StorageScaleDownBlocked=True` is reserved for a scale-down that would violate `replication.factor`. A removed node's single-replica StatefulSet is deleted, so its PVCs are governed by `whenDeleted`, not `whenScaled`. To reclaim those volumes, set `whenDeleted: Delete`.

## GarageNode Replacement Cycles

`garage.rajsingh.info/cycle=true` is a narrow add-before-remove automation for
an established, positive-capacity, StatefulSet-backed `GarageNode`. Add the
annotation only after the source's exact Pod and 64-hex Garage node ID are
Ready, connected, committed to a settled layout, and observed at the current
generation:

```bash
kubectl -n garage-operator-system annotate garagenode garage-storage-a \
  garage.rajsingh.info/cycle=true
```

The operator creates one sibling with a fresh Garage identity and fresh claim
names from the same repeatable PVC templates (or the same explicit `EmptyDir`
profile), waits for that exact sibling Pod to become Ready and enter the settled
layout, then runs the ordinary cluster-wide drain and block-resync proof before
promoting it. A PVC selector is repeated on the new claim, so static-PV users
must provision distinct replacement PVs in advance.

Automatic cycle deliberately rejects `existingClaim`, gateways, external
processes, and node-local-pool members. It never infers replacement hardware or
a StorageClass from a bound claim, and it never reuses, clones, snapshots, or
deletes source claims. For SMB, Ceph, manually bound PVCs, exceptional members,
or a different disk profile, explicitly create a second `GarageNode` with
distinct metadata and data storage, wait for it to synchronize, then drain and
delete the old identity. Node-local membership changes use
`spec.storage.nodeLocalPools[].selector` and the pool retirement state machine
instead of this annotation.

Progress is durable in `status.cyclePhase` and the `Cycling` condition. Removing
the request before the source enters `Draining` is only a cancellation request:
an already-created sibling must first be explicitly drained and deleted. Once
the source has entered `Draining`, the annotation and transaction are one-way;
the controller fails closed unless the exact persisted sibling identity appears
in the terminal drain proof.

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

Each storage replica is its own single-replica StatefulSet `<cluster>-storage-<ord>`, so PVCs follow the `<template>-<sts>-<sts-ordinal>` convention: `data-<index>-<cluster>-storage-<ord>-0` (e.g. `data-0-garage-storage-0-0`). The Garage `data_dir` `capacity` value is taken from `volume.size` if set, otherwise from `path.capacity`, otherwise from the top-level `spec.storage.data.size`. A `readOnly: true` path is mounted read-only and emits `read_only = true` in `data_dir` — capacity is not required.

> **Note:** Garage uses `capacity` as a *striping weight* — blocks are assigned to paths proportionally to each path's capacity. The filesystem enforces the actual size limit, not Garage. In Auto layout mode the cluster spec projects the same `paths[]` onto every per-node `GarageNode`, so all storage replicas get identical paths and capacities. For asymmetric per-node disk layouts (e.g. one node with 2×4T, another with 1×8T+1×2T), switch to `layoutPolicy: Manual` and set `storage.dataPaths` per `GarageNode`.

> **Existing clusters:** volume source, selector, class/access mode, mount path,
> and single↔multi-path topology are immutable whenever a scale transition has
> live replicas on either side. The operator supports only in-place size growth
> on the same volume. Make topology changes as three separate steps: scale to
> zero without changing the template, wait for every exact GarageNode/Pod drain
> to finish, then change the template while it remains at zero, and finally
> scale up in another unchanged request. `Retain` PVCs keep their original
> selector and class and will be reused; a new selector applies only to a newly
> created claim. Intentionally reuse those claims to preserve identity, or,
> after the Garage role is fully retired, migrate/remove the exact retained
> claims before scaling up. Never delete live metadata/data PVCs: that can lose
> `node_key` or the only local block copies.

`selector` is supported on default storage metadata/data, each data path,
gateway metadata, and ordinary `GarageNode` volumes. Releases affected by the
post-#190 projection bug stored cluster selectors but omitted them from newly
generated per-node claims. A non-empty PVC selector matches pre-provisioned PVs;
Kubernetes does not dynamically provision for that claim. Provide one distinct,
access-mode/class-compatible PV for every live metadata/data/path claim, plus
replacement headroom for add-before-remove node cycles. Classless static PVs
usually require an explicit empty `storageClassName`. This release applies
selectors to new children, cycle replacements, and newly created or recreated
StatefulSets; it does not mutate an existing StatefulSet or reselect an existing
Bound or Pending PVC. Repair an affected Pending claim only through the drained
zero-replica/replacement procedure above. The legacy
`volumeClaimTemplateSpec` field was never rendered by managed workloads and is
now rejected for new or changed input; an unchanged legacy value is tolerated
with a warning only so it can be removed. Use the explicit PVC fields, or an
ordinary `GarageNode` with a pre-provisioned `existingClaim`.

## Custom Container Environment Variables

Both tiers expose `env` and `envFrom` for injecting arbitrary env vars into the Garage container, as does `GarageNode.spec.env`. Built-in vars (`GARAGE_NODE_HOST`, log sinks) are set first; user entries are appended after, so a user-supplied `GARAGE_NODE_HOST` would shadow the built-in.

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

### Reserved variables

These names are operator-reserved and rejected by admission:

| Variable | Also reserved |
|---|---|
| `GARAGE_CONFIG_FILE` | — |
| `GARAGE_RPC_SECRET` | `GARAGE_RPC_SECRET_FILE` |
| `GARAGE_ADMIN_TOKEN` | `GARAGE_ADMIN_TOKEN_FILE` |
| `GARAGE_METRICS_TOKEN` | `GARAGE_METRICS_TOKEN_FILE` |

Overriding them would change the live mesh identity, or the consistency and
timeout settings a storage-drain proof depends on, without the operator being
able to see it. `envFrom` prefixes that could expand into one of these names are
rejected for the same reason.

Earlier releases accepted these overrides. If you are upgrading with one set,
the object keeps reconciling only while the entry stays byte-for-byte unchanged,
and the operator asks you to remove it — see
[MIGRATION.md](MIGRATION.md#reserved-garage-environment-variables-v070) for the
two-step annotation flow.

## Operational Annotations

One-shot operational commands are triggered by setting annotations on the resource. For most commands (snapshot, repair, scrub, revert-layout, retry-block-resync, purge-blocks) the operator processes the annotation, acts on it, removes it, and records the result in `status.lastOperation`; if the operation fails the annotation is retained so the next reconcile retries. A few behave differently: `force-layout-apply` is a persistent, narrow legacy/bootstrap flag that permits the cluster-owned initial layout below the replication-factor node count (it is not a generic staged-layout or tombstone approval), and `connect-nodes` is removed after processing but does not write to `status.lastOperation`.

### Maintenance Mode

To suspend reconciliation during planned maintenance, use `spec.maintenance.suspended`:

```yaml
spec:
  maintenance:
    suspended: true
```

The operator requeues every 5 minutes but makes no changes while suspended. Clear the field to resume.

> **Note:** The old `garage.rajsingh.info/pause-reconcile` annotation is no longer honored — use `spec.maintenance.suspended: true` (above). It is version-controlled, visible in `kubectl get`, and works with GitOps tools.

### GarageCluster

| Annotation | Value | Action |
|---|---|---|
| `garage.rajsingh.info/trigger-snapshot` | `"true"` | Trigger a metadata database snapshot on all nodes. Keeps the 2 most recent snapshots. |
| `garage.rajsingh.info/trigger-repair` | repair type | Launch a repair operation on all nodes. Valid types: `Tables`, `Blocks`, `Versions`, `MultipartUploads`, `BlockRefs`, `BlockRc`, `Rebalance`, `Aliases`. Use `retry-block-resync` for resync queue retries; `ClearResyncQueue` is not available at the supported Garage v2.0 floor. |
| `garage.rajsingh.info/scrub-command` | command | Control the block integrity scrub worker on all nodes. Valid commands: `start`, `pause`, `resume`, `cancel`. |
| `garage.rajsingh.info/revert-layout` | `"true"` | Discard all staged layout changes. Does **not** undo an already-applied layout version — only clears the pending staging area. |
| `garage.rajsingh.info/retry-block-resync` | `"true"` or hashes | Clear the resync backoff for blocks so they are retried immediately. Use `"true"` to retry all errored blocks, or a comma-separated list of 64-hex-char block hashes to retry specific ones. |
| `garage.rajsingh.info/purge-blocks` | hashes | **Irreversible.** Permanently delete all S3 objects that reference the listed blocks. Value is a comma-separated list of 64-hex-char block hashes. Only use when you are certain the data is unrecoverable and must be removed from the cluster. |
| `garage.rajsingh.info/force-layout-apply` | `"true"` | Permit the legacy/cluster-owned bootstrap layout to apply below the replication-factor node count (persistent flag). It does not approve arbitrary staged changes or gateway tombstones. |
| `garage.rajsingh.info/connect-nodes` | `nodeId@addr:port,...` | Connect to external nodes (one-shot federation bootstrap). Node IDs must be 64-hex; malformed entries are skipped. |
| `garage.rajsingh.info/skip-dead-nodes` | `"true"` | Mark unresponsive nodes as synced to unblock a layout stuck `Draining`. Pair with `allow-missing-data` to also clear data-sync blockers. |
| `garage.rajsingh.info/allow-missing-data` | `"true"` | Used with `skip-dead-nodes`: force the sync even when quorum data is missing. **Risks data loss** — only when nodes are permanently gone. |
| `garage.rajsingh.info/retry-migration` | `"true"` | Clear the `LegacySTSMigrated` condition and re-run the legacy-StatefulSet → per-`GarageNode` migration. Inspect that condition for `Completed`, `InProgress`, or `Failed`; no status patch is needed. |
| `garage.rajsingh.info/migrate-legacy-rpc-secret` | `"true"` | Two-step, fail-closed migration for a released `GARAGE_RPC_SECRET` environment override. The operator compares the exact active bytes on every owner-proven Pod with `spec.network.rpcSecretRef` and the retained managed snapshot; it never treats this annotation as equality proof. |
| `garage.rajsingh.info/acknowledge-legacy-config-migration` | `"true"` | Attest that an old `GARAGE_CONFIG_FILE` override is semantically equivalent to the operator-rendered config after removing it from the API. This cannot authorize RPC, Admin, metrics, file-based credential, or broad `envFrom` replacement. |
| `garage.rajsingh.info/drain` | `"true"` | Prepare an explicit `deletionPolicy: Drain` federated-site deletion while every source process remains live. Wait for `StorageDrainReady=True` with reason `Completed`, inspect `status.storageDrain`, then issue DELETE. |
| `garage.rajsingh.info/force-delete-unrevoked-operator-tokens` | `"true"` | **Federated/edge teardown risk:** continue when internally generated Admin-token rows could not be revoked through a surviving Admin API. Deletes only local one-time Secrets; a copied bearer may remain valid remotely. |
| `garage.rajsingh.info/recover-storage-rollout` | a new nonce per retry | Retry the exact actor persisted in `status.storageRollout` after correcting a workload-only failure. Topology, identity, volume/capacity, federation, and routing fields remain frozen until that actor converges. |
| `garage.rajsingh.info/purge-cluster-layout` | `factor=N[,force]` | **Destructive.** Coordinated replication-factor change — see [Changing the replication factor](#changing-the-replication-factor) below. |
| `garage.rajsingh.info/purge-cluster-layout-abort` | `"true"` | Abort an in-progress factor migration (restores the tier; cannot roll back an already-applied on-disk purge). |

### GarageNode

These annotations apply to a positive-capacity storage `GarageNode`, not to the
parent `GarageCluster`:

| Annotation | Value | Action |
|---|---|---|
| `garage.rajsingh.info/drain` | `"true"` | Prepare the exact identity for deletion. Wait for `DrainPrepared=True` with reason `PreparedForDeletion` before issuing DELETE. |
| `garage.rajsingh.info/acknowledge-lost-source` | exact 64-hex Garage node ID | Pair atomically with `drain=true` only after the identity is permanently lost. The operator proves Garage reports it down, then waits for explicit dead-node role removal and destination-only repair/resync proof. This cannot recover blocks whose only copy was lost. |
| `garage.rajsingh.info/cycle` | `"true"` | Request an add-before-remove replacement for an eligible StatefulSet-backed storage node. See [GarageNode Replacement Cycles](#garagenode-replacement-cycles). |

### Upgrading released reserved Garage environments

Earlier releases allowed user environment variables to override Garage's
rendered config and credential sources. This release reserves
`GARAGE_CONFIG_FILE`, RPC, Admin, and metrics credential variables because a
silent override removal can change the live mesh identity or invalidate a drain
proof. Existing objects remain deletable and repairable, but ordinary workload
reconciliation fails closed until they are migrated.

For a direct `GARAGE_RPC_SECRET` override:

1. Keep every old override in place. Create a Secret containing the exact same
   64-hex credential and, using `v1beta2`, set `spec.network.rpcSecretRef` plus
   `garage.rajsingh.info/migrate-legacy-rpc-secret: "true"`. Do not combine this
   staging update with an image, topology, volume, replica, or environment
   change.
2. If `<cluster>-rpc-secret` already exists, it must be controlled by the exact
   GarageCluster and contain the same bytes. A mismatch is never overwritten or
   deleted automatically; while old Pods still use the environment override,
   repair that retained mutable Secret to the active value.
3. Wait until the `Ready=False` message says every exact managed RPC environment,
   the referenced Secret, and the retained snapshot match. Then remove only the
   released `GARAGE_RPC_SECRET` entries, leaving the typed reference and migration
   annotation in place.
4. The cluster controller pins the matching snapshot immutable and consumes the
   migration annotation before any GarageNode controller may roll. A late or
   label-drifted Pod is included through its exact controller-owner chain.

For a released `GARAGE_CONFIG_FILE`, first remove the desired override. Old Pods
remain frozen until you have compared the effective old TOML with the operator's
rendered TOML and explicitly set
`garage.rajsingh.info/acknowledge-legacy-config-migration: "true"`. Keep that
attestation until the coordinated rollout is complete, then remove it.

Broad `envFrom`, `GARAGE_RPC_SECRET_FILE`, and legacy Admin/metrics credential
overrides do not have an automatically provable startup value. A config
attestation cannot bypass them. Convert them to typed Secret references under
the previous operator before upgrading, or keep the workloads frozen and use an
explicit manual migration. The operator never guesses, deletes, or overwrites
credential bytes.

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

### Changing the replication factor

`spec.replication.factor` cannot be edited in place — Garage validates that the on-disk layout's factor never changes, so the **only** way to change it is to delete the `cluster_layout` on every storage node and rebuild it at the new factor. The operator automates this as a coordinated, resumable migration behind a destructive annotation:

```bash
# The factor and destructive request must enter admission atomically. This
# prevents a normal one-pod-at-a-time config rollout from starting first.
kubectl patch garagecluster garage --type=merge -p '{
  "metadata":{"annotations":{"garage.rajsingh.info/purge-cluster-layout":"factor=3"}},
  "spec":{"replication":{"factor":3}}
}'
```

The annotation's `factor=N` **must match** `spec.replication.factor` in that same API update; a factor-only edit is rejected. The migration drives a state machine on `status.factorMigration` (`Validating → ScalingDown → Purging → Verifying → RebuildingLayout → Converging → Completed`):

```bash
kubectl get garagecluster garage -o jsonpath='{.status.factorMigration}'
```

**This is destructive and disruptive:** it scales the storage tier to zero, deletes each node's `cluster_layout`, restarts at the new factor, rebuilds the layout, and triggers full re-replication — the cluster is briefly unavailable. Guards:

- **Auto mode only**, and **refused when `spec.remoteClusters` is set** (federated factor changes need a separate coordinated rollout).
- Requires **≥ N storage nodes**.
- **Refused when any storage node has per-node config overrides** (multi-HDD `dataPaths`, fsync, network, publicEndpoint, logging) — their `<node>-config` can't be refreshed with the new factor while the node is suspended, so it would boot at the old factor and wedge a mixed-factor cluster. Remove the overrides or change the factor manually.
- `consistencyMode: dangerous` and pending gateway tombstones each require appending `,force` (e.g. `factor=3,force`).

A **failed or aborted** migration tears down cleanly — it strips the purge init container, scales each storage StatefulSet back to 1, and clears the per-node suspension — so the tier self-heals rather than being stranded scaled-to-zero. Abort with:

```bash
kubectl annotate garagecluster garage garage.rajsingh.info/purge-cluster-layout-abort='true'
```

> Abort restores the workloads but **cannot roll back a purge already applied to disk** — if some nodes purged before you aborted, the layout must be rebuilt (re-run the migration) or repaired manually.

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
    scrubTranquility: 4      # default: 4, higher = slower scrub, less disk pressure
    resyncWorkerCount: 2     # default: 1, range: 1-8
    resyncTranquility: 4     # default: 2, higher = slower resync
```

| Field | Garage variable | Default | Notes |
|---|---|---|---|
| `scrubTranquility` | `scrub-tranquility` | 4 | Pauses between block integrity checks. Higher = less disk I/O. |
| `resyncWorkerCount` | `resync-worker-count` | 1 | Parallel block resync goroutines. Max 8. |
| `resyncTranquility` | `resync-tranquility` | 2 | Pauses between block resyncs. Higher = less disk I/O. |

The operator writes these to every node each reconcile but does not read them back, so they are not surfaced in status — confirm the live values with `garage worker get` on a pod. Unset fields leave the corresponding Garage default unchanged.

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

To disable website hosting entirely, set `spec.webApi.enabled: false` (it defaults to true):

```yaml
spec:
  webApi:
    enabled: false
```

## Bucket Lifecycle Policies

Object expiration and incomplete multipart upload cleanup are configured via `spec.lifecycle` on a `GarageBucket`. The operator applies the rules directly through the Garage Admin API (`SetBucketLifecycle`) — no S3 access key is involved. Rules are evaluated by Garage's lifecycle worker, which runs daily at midnight UTC.

Garage supports a strict subset of the AWS S3 lifecycle spec: `Expiration` (by age or fixed date) and `AbortIncompleteMultipartUpload`, with optional prefix and object size filters (which may be combined — e.g. a prefix *and* a size bound on one rule). Tag filters are not supported.

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

`GarageReferenceGrant` (short: `grg`) lives in the **destination** namespace — the one that owns the referenced `GarageCluster`, `GarageBucket`, or `GarageKey`. Only admins of that namespace can create it, so tenants cannot self-grant access.

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
      name: my-cluster          # specific cluster (omit name to allow all of that kind)
```

`from[].kind` accepts `GarageKey`, `GarageBucket`, or `GarageAdminToken`; `to[].kind` accepts `GarageCluster`, `GarageBucket`, or `GarageKey`. Within a `to` entry, omitting `name` matches every resource of that kind. Omitting the entire `to:` list preserves the original grant behavior and authorizes only `GarageCluster` and `GarageBucket` targets; add an explicit `to: { kind: GarageKey }` when a cross-namespace bucket grants access to a key. `GarageAdminToken` remains in the source-kind schema and grant status accounting for compatibility, but its static credential path is always namespace-local and a grant cannot make it cross-namespace. A cross-namespace **bucket** reference needs an explicit `to: { kind: GarageBucket }`.

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

The grant mechanism applies to:
- `GarageKey.spec.clusterRef` — which cluster the key belongs to
- `GarageKey.spec.bucketPermissions[].bucketRef.namespace` — cross-namespace bucket references
- `GarageBucket.spec.clusterRef` — cross-namespace cluster for a bucket

`GarageAdminToken.spec.clusterRef` is namespace-local; a grant cannot make it cross-namespace.

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

Tenants can only create or continue reconciling cross-namespace references while a matching grant exists. Deleting the `GarageReferenceGrant` makes those resources fail closed on their next reconcile, but it does not itself revoke credentials already issued by Garage or delete buckets. Remove the dependent `GarageKey`/`GarageBucket` permission relationship (or delete the dependent resource and let its finalizer complete) before deleting the grant when Garage-side revocation is required.

## Multi-Cluster Federation

Garage supports federating clusters across Kubernetes clusters for geo-distributed storage. All clusters share the same RPC secret and Garage distributes replicas across zones automatically.

Federation reconciliation is additive: a `remoteClusters` entry discovers,
connects, and imports roles, but it never treats an absent or down remote node
as permission to delete that role. Each physical site's GarageCluster and
GarageNode finalizers are the authority for retiring the exact identities they
own. Drain or replace a member at its source site, then let Garage replicate the
committed layout. `remoteClusters[].name` and `.zone` are routing/discovery
metadata, not immutable deletion authority; the API does not yet carry a
source-site UID that could safely transfer that authority.

> **Every Garage node in a federated cluster needs its own externally-routable RPC address.** Garage authenticates the expected node ID during its RPC handshake, so a shared L4 LoadBalancer cannot safely represent multiple nodes: if it selects a different pod, the identity check fails. Use per-node `spec.network.rpcPublicAddr`, `spec.publicEndpoint`, or ordinal address templates. Since v0.6.24 the operator publishes each effective node address in Garage's replicated layout and uses it for direct cross-cluster reconnection. Shared addresses remain bootstrap-only compatibility fallbacks.

1. Create the same RPC secret in every Kubernetes cluster:
   ```bash
   SECRET=$(openssl rand -hex 32)
   kubectl create secret generic garage-rpc-secret --from-literal=rpc-secret=$SECRET
   ```

2. For **uniform clusters** (all nodes identical), use Auto layout with a per-node RPC address template:
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
       rpcPublicAddr: "garage-us-storage-{ordinal}.example.com:3901"
       metadata:
         size: 10Gi
       data:
         size: 100Gi
     network:
       rpcSecretRef:
         name: garage-rpc-secret
         key: rpc-secret
     # Provision one external endpoint for each ordinal hostname above. As an
     # alternative, publicEndpoint.loadBalancer.perNode lets the operator create
     # one LoadBalancer and derive one effective RPC address per storage node.
     publicEndpoint:
       type: LoadBalancer
       loadBalancer:
         perNode: true
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

   A shared LoadBalancer is retained only for backwards-compatible bootstrap. Do not rely on it for steady-state federation with multiple identity-bearing RPC nodes. `loadBalancer.perNode` creates one Service per operator-managed node; alternatively, `storage.rpcPublicAddr` with `{ordinal}` writes a stable distinct address into every generated `GarageNode`.

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
   Each `GarageNode` creates a separate StatefulSet and its own `<node>-rpc` LoadBalancer service. The operator writes the node-specific `rpc_public_addr` into the per-node ConfigMap and publishes the same effective address as an operator-owned `rpc-address:` layout tag. Remote operators preserve that tag while importing roles and prefer it over shared regional endpoints. This works for storage nodes, gateways, external nodes, IPv4/IPv6 endpoints, and both Auto and Manual layout modes; it is independent of the operator container architecture.

   To set `rpc_public_addr` manually (e.g. for a static hostname), use `spec.network.rpcPublicAddr` instead:
   ```yaml
   spec:
     network:
       rpcPublicAddr: "garage-node-0.example.com:3901"
   ```

The operator handles node discovery, layout coordination, and health monitoring across clusters. See the [Garage documentation](https://garagehq.deuxfleurs.fr/documentation/cookbook/real-world/) for networking requirements.

### Cross-region gateway peering

When remote clusters run multiple gateway pods (`gateway.replicas > 1`) behind a shared external hostname (e.g. one Tailscale LB per region), the load balancer routes each `ConnectClusterNodes` call to *one* of N pods — the rest stay listed in `layout.all_nodes()` as `Not connected` and break FullReplication quorum reads/writes (`GetKeyInfo`, `DeleteKey`, cross-region key/bucket writes).

Set `remoteClusters[].connection.gatewayRpcEndpointTemplate` to a per-ordinal hostname pattern and the operator dials each remote gateway pod individually. The literal `{ordinal}` is substituted with each remote gateway pod's ordinal.

The operator derives the ordinal from the exact cluster-ownership and pod-name
layout tags. Arbitrary cluster names, including names containing hyphens, and
the operator-managed `<cluster>-gateway-<N>-0` pod tags are supported.

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

Enable `spec.monitoring` on a `GarageCluster` to create a `ServiceMonitor` targeting the admin API `/metrics` endpoint. Covers both Auto-mode pods and Manual-mode `GarageNode` pods via the operator-managed `garage.rajsingh.info/cluster` label selector. This is a diagnostic/workload-output label; do not edit it as a user configuration API.

```yaml
spec:
  monitoring:
    enabled: true
    interval: 30s          # optional, defaults to Prometheus global interval
    additionalLabels:
      release: monitoring  # match your Prometheus serviceMonitorSelector
```

If the cluster sets `spec.admin.metricsTokenSecretRef`, the generated ServiceMonitor includes `Authorization: Bearer` from that secret (default key `metrics-token`). Ensure your Prometheus instance has RBAC to `get` secrets in the Garage namespace.

> `spec.monitoring` scrapes each Garage node's admin `/metrics` (port `admin`, 3903). To scrape the **operator's own** controller-manager metrics instead, enable the Helm chart's `serviceMonitor.enabled` value (HTTPS on :8443, off by default) — that's a separate ServiceMonitor for the operator Deployment, not the Garage clusters.

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

## Cluster Health Conditions

Beyond `status.phase`, the operator derives actionable conditions and a one-line `status.layoutDiagnosis` (shown as the `Diagnosis` print column in `kubectl get gc`) so you can tell *why* a cluster is unhealthy and which lever to pull:

| Condition | True means | Lever |
|---|---|---|
| `QuorumAtRisk` | Garage reports `PartitionsQuorum < Partitions` — object writes to those partitions block | restore storage nodes, or set `replication.consistencyMode: dangerous` (not a layout edit) |
| `PeerUnreachable` | a peer has been continuously down beyond ~10m — listed in `status.unreachablePeers` | the operator's periodic `ConnectClusterNodes` nudge is the recovery path (esp. single-link edge gateways) |
| `RemoteClustersHealthy` | False when a federated remote has been unreachable > 1h (short blips ignored) | if a zone is permanently gone, reduce `replication.factor` |
| `FederationConfigured` | False when `spec.remoteClusters` is set but no routable `rpc_public_addr`/`publicEndpoint` | set `spec.network.rpcPublicAddr` or a `publicEndpoint` |
| `GatewayConnected` | gateway RPC state — bidirectional `True`, intentional forward-only `True`, or `False` with `PartiallyConnected`/offline reason when a configured link is incomplete | see [Gateway Tier](#gateway-tier) |
| `GatewayTombstones` | stale gateway layout entries pending removal — see `status.pendingGatewayTombstones` | remove the exact IDs with the Garage CLI, or enable `layoutManagement.autoApply` |

```bash
kubectl get gc                       # the Diagnosis column summarizes layout health at a glance
kubectl get gc garage -o jsonpath='{.status.conditions}'
```

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
> and Delete-policy BucketClaim cleanup logic — older builds create `Bucket` objects
> without the required reference or leave claim-driven deletion unfinished.
>
> **Architecture:** The cluster-wide COSI controller reconciles `BucketClaim` →
> `Bucket` and `BucketAccessClaim` → `BucketAccess`. The garage-operator watches the
> resulting `Bucket` and `BucketAccess` objects directly (filtered by `driverName`)
> and translates them into Garage Admin API calls. There is no per-driver sidecar
> container — this was previously the upstream `objectstorage-sidecar`'s role.

1. Install the COSI CRDs (pinned to a known-good ref):
   ```bash
   COSI_REF=cc544691e2ef7ddc2fba972d796ed3188ea46315
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

   By default, COSI shadow `GarageBucket` and `GarageKey` resources live in the
   Helm release namespace. If `cosi.namespace` is set to another namespace, each
   namespace containing a target `GarageCluster` must explicitly authorize that
   shadow namespace. For example:

   ```yaml
   apiVersion: garage.rajsingh.info/v1beta1
   kind: GarageReferenceGrant
   metadata:
     name: allow-cosi-shadows
     namespace: garage-operator-system # target GarageCluster namespace
   spec:
     from:
       - kind: GarageBucket
         namespace: cosi-shadows
       - kind: GarageKey
         namespace: cosi-shadows
     to:
       - kind: GarageCluster
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
   The secret also contains the canonical v1alpha2 fields `COSI_PROTOCOL`,
   `COSI_S3_BUCKET_ID`, `COSI_S3_REGION`, and
   `COSI_S3_ADDRESSING_STYLE`. Historical `S3_*` aliases remain available for
   compatibility with existing workloads.

### COSI Limitations

- Only S3 protocol is supported
- Only Key authentication is supported; `BucketAccess` requests using `ServiceAccount` authentication are rejected by the driver (`ServiceAccount auth not supported by Garage`), and Garage has no IAM authentication mode
- Bucket and credential deletion run via a protection finalizer when the BucketClaim/BucketAccess (and the resulting Bucket/BucketAccess) are deleted — the operator deletes the Garage bucket and revokes/deletes the key directly (no gRPC sidecar). A non-empty bucket is refused: the operator surfaces a `bucket not empty` error and retries until it is emptied.

## Documentation

The canonical documentation site is **[rajsinghtech.github.io/garage-operator](https://rajsinghtech.github.io/garage-operator/)**. It is built from `docs/` on every documentation change and includes installation, topology selection, API/Helm references, federation, node-local pools, day-2 operations, recovery, and troubleshooting.

- [Contributing](CONTRIBUTING.md) - Design, testing, and release workflow
- [Design Records](docs/design/) - Designs for substantial or high-risk changes
- [Helm Chart](charts/garage-operator/) - Installation and configuration
- [Garage Docs](https://garagehq.deuxfleurs.fr/) - Garage project documentation

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development and pull
request workflow.

```bash
make dev-up       # Start kind cluster with operator
make dev-test     # Apply test resources
make dev-status   # View cluster status
make dev-logs     # Stream operator logs
make dev-down     # Tear down
```
