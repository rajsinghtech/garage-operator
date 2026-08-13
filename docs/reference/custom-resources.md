# Custom resources

The generated CRDs under `config/crd/bases/` and JSON schemas under `schemas/`
are authoritative for validation. This page is an operator-oriented map of the
current API surface, including fields whose safety behavior is easy to miss.

## Resource map

| Kind | API version | Scope | Purpose |
| --- | --- | --- | --- |
| `GarageCluster` | `garage.rajsingh.info/v1beta2` (preferred), `v1beta1` (deprecated) | Namespaced | Garage topology, configuration, layout, federation, health, and operations |
| `GarageBucket` | `garage.rajsingh.info/v1beta1` | Namespaced | Bucket, aliases, quotas, website, lifecycle, and key grants |
| `GarageKey` | `garage.rajsingh.info/v1beta1` | Namespaced | S3 key import/generation and permissions |
| `GarageNode` | `garage.rajsingh.info/v1beta1` | Namespaced | One managed, gateway, external, or node-local Garage identity |
| `GarageAdminToken` | `garage.rajsingh.info/v1beta1` | Namespaced | Static Admin token Secret template |
| `GarageReferenceGrant` | `garage.rajsingh.info/v1beta1` | Namespaced | Allow listed namespaces/kinds to make cross-namespace references |

Short names include `gc`, `gb`, `gk`, `gn`, `gat`, and `grg` as published in
the CRDs. Confirm them on the target cluster with `kubectl api-resources`.

References to a `GarageCluster` use `name` and an optional `namespace`. For
`GarageBucket` and `GarageKey`, a cross-namespace reference is allowed only
when a `GarageReferenceGrant` in the destination namespace matches both the
source kind/namespace and the target kind/name. `GarageAdminToken` is
namespace-local: its `clusterRef.namespace` must be empty or match the token's
namespace, and a `GarageReferenceGrant` does not override that restriction.
`GarageNode` does not support cross-namespace cluster references.

## GarageCluster v1beta2

### Topology shapes

| Shape | Required fields | Operator-owned workload |
| --- | --- | --- |
| Storage | `storage` | One single-replica StatefulSet per managed storage `GarageNode` |
| Unified | `storage` + `gateway` | Storage members plus one persistent-identity gateway `GarageNode` per Auto gateway replica |
| Edge gateway | `gateway` + `connectTo` | One cluster-level gateway StatefulSet; storage is remote |
| Management handle | `connectTo` only | No Garage workload, PVC, Service, or node |

`storage` and `connectTo` are mutually exclusive. Federation of independently
managed storage sites uses `remoteClusters`, not `connectTo`. `gateway.replicas`
means Auto gateway identities in a unified cluster, but means replicas in the
single cluster-level StatefulSet for an edge cluster; it has no scaling effect
on user-owned Manual `GarageNode`s.

### Spec field matrix

| Group | Fields | Contract |
| --- | --- | --- |
| Image and identity | `image`, `imageRepository`, `imagePullPolicy`, `imagePullSecrets`, `serviceAccountName` | `image` wins over `imageRepository`; image and metadata changes are identity-bearing rollouts |
| Topology | `storage`, `gateway`, `connectTo`, `layoutPolicy`, `deletionPolicy` | Shapes are disjoint; `Auto` → `Manual` is a one-way handoff |
| Placement | `zone`, `zoneFrom`, `defaultNodeTags` | `zone` is the fallback; `zoneFrom` reads a Kubernetes Node label and requires cluster-scoped access |
| Replication | `replication.factor`, `consistencyMode`, `zoneRedundancyMode`, `zoneRedundancyMinZones` | Factor is 1–7; factor changes require the destructive migration workflow |
| RPC and Services | `network` | RPC bind/public address, shared secret, bootstrap peers, and API Service metadata/type |
| API listeners | `s3Api`, `k2vApi`, `webApi`, `admin` | S3 defaults to 3900, web 3902, Admin 3903, and K2V 3904 when enabled |
| Storage engine | `database`, `blocks` | Garage database and block-file tuning; some settings require newer Garage versions |
| Discovery/security | `discovery`, `security`, `logging` | Kubernetes/Consul discovery, supported security switches, and Rust logging |
| Federation | `publicEndpoint`, `remoteClusters` | RPC reachability and imported remote roles; these do not publish the S3 endpoint |
| Layout | `layoutManagement` | Automatic apply threshold and the fail-closed positive-capacity drain policy |
| Operations | `monitoring`, `maintenance`, `workers` | ServiceMonitor/relabeling, reconciliation suspension, and background worker tuning |

### Storage, gateway, and pod fields

| Field | Meaning and safety rule |
| --- | --- |
| `storage.replicas` | Only the default Auto PVC group. Set `0` when using only Manual nodes or node-local pools; omitted defaults to `3`. |
| `storage.metadata` | PVC or `EmptyDir` containing `node_key` and Garage metadata. Persistent metadata preserves identity. |
| `storage.data` | PVC or `EmptyDir` for object blocks. `data.paths` is the multi-disk form. |
| `storage.data.paths[]` | Each entry has `path`, `capacity`, `readOnly`, and an optional per-path `volume`; writable paths need capacity. |
| `storage.nodeLocalPools` | Additive selector-driven HostPath identities. Each selected Kubernetes Node gets one Garage role; the pool is not a replication group or failure domain. |
| `storage.layoutPolicy` | Overrides the cluster policy for the default PVC group only; node-local pools remain operator-owned. |
| `storage.pvcRetentionPolicy` | Controls claims on StatefulSet deletion and scale-down (`Retain` or `Delete`). |
| `storage.capacityReservePercent` | Reserves 0–50% of advertised capacity for overhead in Auto mode. |
| `storage.podDisruptionBudget` | One PDB for the storage tier, including node-local pools. |
| `gateway.replicas` | Auto unified identity count or edge StatefulSet replicas; gateway nodes have no object-block capacity. |
| `gateway.metadata` | Persistent by default for gateway identity; `EmptyDir` is an explicit identity-churn exception. |
| `gateway.rpcPublicAddr` | Address peers use for the gateway identity. One shared edge config/address is safe only for one independently routed edge identity. |
| `gateway.readinessProbe` | Overrides the default bind-only S3 TCP probe; a cluster-wide `/health` probe can withdraw all gateways during a quorum loss. |
| `storage`/`gateway` pod template | `resources`, `nodeSelector`, `tolerations`, `affinity`, topology spread, labels, annotations, priority, security contexts, `env`, and `envFrom`. |

### Volumes, selectors, and size growth

`VolumeConfig.selector` is a Kubernetes PV selector for a newly created claim.
It disables dynamic provisioning for that claim; provide a distinct compatible
PV and ensure its `storageClassName` matches. Selectors, storage classes, access
modes, claim labels, and claim annotations are claim-template inputs, not a way
to reselect an already-bound PVC.

The operator supports in-place size growth on the same volume. For a live
identity, the volume source, selector, class, access modes, mount paths, and
single-versus-multi-path topology are immutable safety boundaries. To change
one, scale the affected Auto group or edge gateway to zero, wait for its exact
Garage roles and workloads to settle, change the template, and scale up in a
separate update. Retained claims keep their original template values.

`volumeClaimTemplateSpec` remains in the schema only for compatibility and is
rejected for new or changed operator-managed workloads. Use the explicit volume
fields above, or `GarageNode.spec.storage.*.existingClaim` for a pre-provisioned
claim on a Manual node. `data.paths` is uniform across the default Auto group;
use `GarageNode.spec.storage.dataPaths` when disks differ per identity.

### Garage configuration matrix

| Field | Important subfields |
| --- | --- |
| `network` | `rpcBindPort`, `rpcBindAddress`, `rpcPublicAddr`, `rpcPublicAddrSubnet`, `rpcBindOutgoing`, `rpcSecretRef`, `rpcPingTimeout`, `rpcTimeout`, `bootstrapPeers`, `service` |
| `s3Api` | `bindPort`, `bindAddress`, `region`, `rootDomain` |
| `k2vApi` | `bindPort`, `bindAddress`; omitting the object disables K2V |
| `webApi` | `enabled`, `bindPort`, `bindAddress`, `rootDomain`, `addHostToMetrics` |
| `admin` | `bindPort`, wildcard `bindAddress`, `adminTokenSecretRef`, `metricsTokenSecretRef`, `metricsRequireToken`, `traceSink` |
| `database` | `engine` (`lmdb`, `sqlite`, `fjall`), `lmdbMapSize`, `fjallBlockCacheSize` |
| `blocks` | `size`, `ramBufferMax`, `maxConcurrentReads`, `maxConcurrentWritesPerRequest`, `compressionLevel`, `disableScrub`, `useLocalTZ` |
| `discovery` | Kubernetes discovery or Consul catalog/agent, TLS credentials, tags, metadata, and datacenters |
| `security` | `allowInsecureSecretPermissions`, `allowPunycode`; `security.tls` is retained but rejected because Garage removed `rpc_tls` |
| `logging` | `level`, `syslog`, `journald` |
| `workers` | `scrubTranquility`, `resyncWorkerCount` (1–8), `resyncTranquility` |
| `monitoring` | `enabled`, `interval`, `additionalLabels`, `metricRelabelings` for the generated ServiceMonitor |
| `maintenance` | `suspended: true` pauses reconciliation; it is not the old pause annotation |

K2V requires a Garage image built with the K2V feature; setting `k2vApi` only
renders the listener and Service port. Worker tranquility reduces I/O at the
cost of longer scrub/resync periods. See [Garage configuration](../how-to/configuration.md)
for examples and version caveats.

### Reserved environment variables

The following names are reserved in `env` and in prefixes that could inject
them through `envFrom`:

```text
GARAGE_CONFIG_FILE
GARAGE_RPC_SECRET
GARAGE_RPC_SECRET_FILE
GARAGE_ADMIN_TOKEN
GARAGE_ADMIN_TOKEN_FILE
GARAGE_METRICS_TOKEN
GARAGE_METRICS_TOKEN_FILE
```

They control the rendered configuration, mesh identity, or credential
provenance. Existing released objects that already contain an override enter a
fail-closed migration path; follow [migration details](../operations/migration.md)
before removing or changing it.

### GarageCluster status

| Status field | Use |
| --- | --- |
| `phase`, `replicas`, `readyReplicas`, `storageReplicas`, `storageReadyReplicas`, `gatewayReplicas`, `gatewayReadyReplicas` | Workload and identity counts; `scaleReplicas`/`scaleSelector` are the narrower Kubernetes Scale projection |
| `clusterId`, `buildInfo` | Garage cluster and build identity |
| `health`, `storageStats`, `nodes` | Connectivity, quorum, partitions, disk totals, and per-node observations |
| `layoutVersion`, `stagedLayoutVersion`, `stagedRoles`, `layoutPreview`, `layoutHistory` | Applied/staged layout and the bounded recent history |
| `activeRepairs`, `scrubStatus`, `lifecycleStatus`, `workers`, `blockErrors`, `blockErrorDetails`, `resyncQueueLength` | Background work and block-recovery evidence |
| `storageRollout` | Exact actor, workload/PVC UIDs, desired hashes, fencing state, and recovery pod evidence for one identity-bearing handoff |
| `autoModePvcHandoffs` | Exact retained PVC UID and replacement `GarageNode` authorization after an Auto slot recreation |
| `storageDrain` | Actor UID, transaction/target hash, removed roles, repair worker IDs, resync baselines, quiet period, and terminal proof |
| `factorMigration` | Phase and source/target factor for the destructive layout rebuild |
| `remoteClusters`, `totalNodes`, `drainingNodes` | Federation connectivity and layout-wide counts |
| `endpoints` | Rendered S3, K2V, web, Admin, metrics, and RPC URLs |
| `pendingGatewayTombstones`, `gatewayNodesNotInLayout`, `unreachablePeers`, `layoutDiagnosis` | Actionable gateway/layout degradation and peer reachability |
| `lastOperation`, `observedGeneration`, `conditions` | Last annotation result, reconciliation generation, and health gates |

The currently written cluster conditions include `Ready`,
`PublicEndpointReady`, `ManagementHandleReady`, `GatewayConnected`,
`GatewayLayoutDegraded`, `GatewayTombstones`, `QuorumAtRisk`,
`PeerUnreachable`, `RemoteClustersHealthy`, `FederationConfigured`,
`StorageScaleDownBlocked`, `StorageTopologyReady`, `LegacySTSMigrated`,
`NodeLocalPoolsReady`, `StorageRolloutReady`, and `StorageDrainReady`.
Older condition constants such as `ClusterHealthy`, `LayoutApplied`, and
`NodesConnected` remain for compatibility but are not emitted as independent
conditions by the current controllers.
The [annotations and conditions reference](operations.md) lists their meanings.

## GarageBucket

### Spec

`clusterRef` selects the cluster. `bucketId` pins an existing Garage bucket and
prevents replacement. `globalAlias` defaults from the object name when omitted;
`localAliases` create key-scoped aliases. `quotas` supports `maxSize` and
`maxObjects`. `website` manages `indexDocument` and `errorDocument`; routing
rules and redirect-all behavior must be configured through S3 APIs. `lifecycle`
supports Garage's subset of S3 expiration and incomplete-multipart rules and is
evaluated asynchronously by Garage's lifecycle worker. `keyPermissions` and
`GarageKey.spec.bucketPermissions` are equivalent declaration directions and
are merged when both describe the same grant.

Bucket and key references can name a namespace; cross-namespace grants must be
approved by a `GarageReferenceGrant` in the cluster's namespace.

### Status

`status.bucketId`, `phase`, `globalAlias`, and `createdAt` identify the remote
bucket. `size`, incomplete-upload counters, `quotaUsage`, `websiteEnabled`,
`websiteUrl`, and `websiteConfig` report observed state. `keys`,
`localAliases`, and `lifecycleRules` are read-back summaries. The
`managedGlobalAlias`, `pendingGlobalAlias`, `managedLocalAliases`, and
`managedKeyGrants` fields are controller ownership records used for crash-safe
replacement and revocation; do not edit them. Inspect the `Ready` and
`LifecycleConfigured` conditions, plus `BucketLookupStuck` or
`BucketMetadataDegraded` when a bucket is not ready. The older bucket condition
constants (`BucketCreated`, `QuotaConfigured`, `WebsiteConfigured`, and
`AliasesConfigured`) remain for compatibility and are not emitted independently.

## GarageKey

### Spec

`clusterRef` selects the cluster and `name` is a Garage-friendly display name.
Use `importKey` to adopt an existing key (prefer `secretRef` over inline
credentials), or omit it to generate a key. `secretTemplate` controls the
generated Secret's name, keys, endpoint/region/bucket fields, type, and extra
data. `bucketPermissions` grants per-bucket access; `allBuckets` intentionally
includes buckets created outside Kubernetes; `permissions.createBucket` grants
S3 bucket creation. `expiresAt` and `neverExpires` are mutually exclusive.
Expiry marks the resource and remote key but does not rotate credentials.

### Status

`keyId`, `accessKeyId`, `phase`, `createdAt`, `expiresAt`, and `secretRef`
identify the remote key and generated Secret. `clusterWide`, `permissions`, and
`buckets` report observed access. `managedBucketGrants` and `clusterWide` also
record controller ownership before and after remote mutations so a failed
reconcile can revoke only grants it owns. `effectivePermissions` is retained
for compatibility and is not currently populated; use `status.buckets`.
Inspect `Ready`. Expiry is represented by `status.phase: Expired`, not by a
`KeyExpired` condition; the older key condition constants remain for compatibility.

## GarageNode

### Spec

| Field | Meaning |
| --- | --- |
| `clusterRef`, `nodeId`, `zone`, `zoneFrom` | Parent and identity/placement. `nodeId` is authoritative for external nodes but an expected pin for managed nodes. |
| `capacity`, `gateway`, `tags` | Garage layout role. Gateway nodes omit capacity and store no blocks. |
| `external` | Address/port for an already-running process; no workload is created. |
| `backing` | `StatefulSet` (default) or controller-owned `NodeLocalPool`; the latter requires `kubernetesNodeName` and `nodeLocalPoolName`. |
| `storage` | Metadata/data or `dataPaths`, optional `existingClaim`, selectors, fsync, snapshots, and per-path capacity. |
| Pod overrides | Image, resources, scheduling, labels/annotations, service account, security contexts, topology spread, `env`, `envFrom`, and logging. |
| `network`, `publicEndpoint` | Per-node RPC advertisement and optional RPC Service exposure. |
| `maintenance` | `suspended: true` freezes this node's workload, Service, ConfigMap, and layout reconciliation. |

`gateway`, `external`, `backing`, and node-local ownership fields are identity
boundaries. Drain the old identity and create its replacement rather than
changing the role in place.

### Status

`nodeId`, `zone`, `phase`, `inLayout`, `layoutVersion`, `connected`, `lastSeen`,
`address`, `hostname`, `tags`, disk partitions, `version`, and `partitions`
describe the observed process. `managedPVCs` records exact PVC UID or pending
reservation evidence. `observedPodUid` prevents stale process evidence from
being reused. `cyclePhase`, `cycleSiblingName`, and `cycleSiblingNodeId` track
the narrow add-before-remove cycle workflow. `clusterAdminEndpoint` and
`clusterAdminTokenSecretRef` preserve delete-time access for an external/edge
parent. `parentDeletionRequestGeneration` is controller-owned handoff state.

`dbEngine`, `garageFeatures`, `storedData`, repair fields, and `blockErrors`
remain in the schema for compatibility but are not populated by the current
Garage Admin API. Inspect `Ready`, `DrainPrepared`, `Cycling`, and the literal
`Suspended` condition when `spec.maintenance.suspended` is active. The older
node discovery/layout condition constants are not emitted independently.

## GarageAdminToken

`GarageAdminToken` creates static bootstrap bearer material in a Secret. The
referenced cluster must select that Secret through
`spec.admin.adminTokenSecretRef`. `secretTemplate` controls the Secret name,
labels, annotations, token key, and optional endpoint key.

The resource and its referenced `GarageCluster` must be in the same namespace:
omit `clusterRef.namespace` or set it to the token's namespace. The generated
Secret is namespace-local, and `GarageCluster.spec.admin.adminTokenSecretRef`
cannot consume a Secret from another namespace. Although
`GarageReferenceGrant.spec.from` includes `GarageAdminToken` for schema and
status compatibility, a grant cannot make this static credential path
cross-namespace.

This is not a Garage dynamic-token row: `name`, `expiresAt`, and
`neverExpires` are compatibility fields and do not provide server-side scope,
expiry, or revocation. `status.tokenId` is a short display fingerprint and
`status.tokenDigest` is the full hash used to detect Secret mutation without
exposing the bearer. `status.phase`, `secretRef`, `observedGeneration`, and the
`Ready` condition report reconciliation. The older token condition constants
(`TokenCreated`, `TokenSecretCreated`, and `TokenExpired`) remain for
compatibility but are not emitted independently. Deleting the resource does
not revoke bytes already loaded by a running Garage process.

## GarageReferenceGrant

The grant lives in the destination namespace, where its administrator controls
the trust boundary. `spec.from` lists source kind and namespace; allowed source
kinds are `GarageBucket`, `GarageKey`, and `GarageAdminToken`. `spec.to` narrows
the destination kind and optional name; omitted names allow all resources of
that kind. Omitting `spec.to` preserves the original grant behavior and allows
only `GarageCluster` and `GarageBucket` targets; newer target kinds such as
`GarageKey` require an explicit entry. `GarageAdminToken` remains in the source
kind schema and status accounting for compatibility, but its static credential
path is namespace-local and a grant cannot make it cross-namespace.
`GarageNode` is never allowed cross-namespace.

`status.inUseBy` is rebuilt on every reconcile and lists the kind, name, and
namespace of current referencing resources. It is safe to remove a grant only
after this list is empty and dependent resources no longer need the reference.
Conditions report whether the grant is in use. Removing a grant makes future
reconciliation fail closed; it does not itself revoke already-issued Garage
permissions.

## Validation and compatibility-only fields

Some fields remain in schemas to support conversion or old manifests but are
rejected, warned, or ignored. Examples include `security.tls` (Garage removed
`rpc_tls`), `publicEndpoint.externalIP`, `remoteClusters[].defaultCapacity`,
arbitrary managed `volumeClaimTemplateSpec`, and
`connectTo.clusterRef.kubeConfigSecretRef`. Read admission warnings and errors
as the current contract.

For complete field-level descriptions, use the versioned generated schemas:

- [`garagecluster_v1beta2.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagecluster_v1beta2.json)
- [`garagecluster_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagecluster_v1beta1.json)
- [`garagebucket_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagebucket_v1beta1.json)
- [`garagebucket_v1alpha1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagebucket_v1alpha1.json)
- [`garagekey_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagekey_v1beta1.json)
- [`garagenode_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagenode_v1beta1.json)
- [`garageadmintoken_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garageadmintoken_v1beta1.json)
- [`garagereferencegrant_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagereferencegrant_v1beta1.json)
