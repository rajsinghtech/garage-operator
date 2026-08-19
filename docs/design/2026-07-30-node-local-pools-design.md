# Additive node-local pools

**Status:** v0.7.0 release design for
[#298](https://github.com/rajsinghtech/garage-operator/issues/298) and
[#297](https://github.com/rajsinghtech/garage-operator/pull/297).

## Decision

Node-local storage is an additive pool inside the existing storage tier:

```yaml
spec:
  storage:
    nodeLocalPools:
      - name: local-700
        capacity: 700Gi
        metadata:
          hostPath: /var/lib/garage/local-700/metadata
          hostPathType: Directory
        data:
          hostPath: /var/lib/garage/local-700/data
          hostPathType: Directory
        selector:
          matchLabels:
            storage.garage.example/pool: local-700
        network:
          rpcPublicAddrTemplate: "{nodeName}.storage.example.net:3901"
```

Node-local pools require Kubernetes 1.27+ because their workload-incarnation
boundary uses Pod scheduling gates. The operator's StatefulSet/PVC, Manual,
SMB, gateway, and management-handle configurations retain Kubernetes 1.25
compatibility. Pool reconciliation verifies the discovered version, an
API-server dry run that preserves the scheduling gate, and a real gated Pod on
which kube-scheduler reports `PodScheduled=False` with reason
`SchedulingGated`; inability to prove the end-to-end behavior blocks before
workload or Node activation mutation. Successful evidence is cached only per
namespace for at most 30 seconds from kube-scheduler's condition timestamp and
pinned for the duration of the reconciliation that began from that proof;
the next pass reproves expired evidence so a long-running manager detects an
API-server or scheduler downgrade/feature-gate change.

It is not a discriminator that turns the entire storage tier into one
DaemonSet. The existing `storage.replicas`, `metadata`, `data`, and
`podTemplate` fields remain the default StatefulSet/PVC group. Named
`nodeLocalPools` can coexist with:

- operator-owned default StatefulSet/PVC GarageNodes in Auto mode;
- user-owned PVC, SMB, or external GarageNodes in Manual mode;
- multiple local-disk classes with different capacity and scheduling;
- the existing gateway tier.

One workload-owning `GarageCluster` is one Garage store/site lifecycle and
ownership boundary, usually one physical site. Its members may share one static
zone or derive multiple actual failure-domain zones through `zoneFrom`. SMB and
local disks in that lifecycle are node-local pools or ordinary GarageNodes in
the same Garage cluster, not separate `GarageCluster` objects merely because
their backing differs. Separate objects create separate RPC secrets and stores
by default; reusing one secret between independently reconciled objects creates
competing ownership unless an explicit externally serialized federation design
assigns the ownership boundaries.

A `NodeLocalPool` is only an operator-side membership generator. Garage itself
has no pool entity, per-pool replication group, replication factor, or quorum;
its replication policy applies globally across every positive-capacity role
and the roles' actual zones. Pool capacity is the capacity of each generated
Garage role, not a total divided among selected Nodes. A pool is not a failure
domain, and its name never supplies a zone: static `zone` or per-member
`zoneFrom` remains independent.

Floating PVC, SMB, Ceph, external, and exceptional `GarageNode` resources
remain separate Garage identities backed by their own filesystems. They are
not shared filesystems merged with node-local HostPath data. One
`nodeLocalPools` entry is the normal single-DaemonSet deployment across all of
its selected Kubernetes Nodes; multiple entries create multiple DaemonSets for
disjoint local-disk profiles.

## Why the first API shape changed

The unreleased prototype used `spec.storage.workload: DaemonSet`. That made
PVC and HostPath storage a closed union and forced every storage node at a site
to use the same workload, volume type, capacity, and selector. It could not
model the target topology: a durable SMB node, several uniform local nodes, and
an exceptional smaller local node in one Garage zone.

A sibling top-level storage mode would have the same exclusivity problem or
would duplicate every storage-wide setting. A named list under `storage`
preserves the current API and makes the new capability additive.

## Upstream Garage invariants

The lifecycle is based on the adjacent upstream Garage checkout:

- Garage v2.0.0 is the minimum supported release for this contract; every
  participating process in one layout must meet that floor. The Admin API v2
  layout-history, repair-worker, and block-error endpoints used by the drain
  proof are present in upstream v2.0.0; v2.3.0 is the tested default.
- Garage creates or loads its Ed25519 identity from
  `metadata_dir/node_key` in `../garage/src/rpc/system.rs`. The metadata
  HostPath, not the Kubernetes Pod name, is the durable identity boundary.
- A layout role has one aggregate capacity. The Admin API rejects a positive
  capacity below 1024 bytes in `../garage/src/api/admin/layout.rs`.
- Multiple `data_dir` entries independently require either a non-zero
  `capacity` or `read_only = true`; at least one entry must remain writable
  (`../garage/src/block/layout.rs`).
- Garage persists a drive layout keyed by the in-container `data_dir` path and
  writes a marker into each directory. Repointing one path at another disk can
  fail marker validation; removing a writable path can discard the only known
  location for some block partitions.
- A read-only Garage data directory is still mounted read-write because Garage
  maintains its marker file and moves blocks out of it.
- Layout removal is staged, applied, and acknowledged over multiple layout
  versions. A Kubernetes pod must not be stopped merely because desired
  placement changed.
- Garage RPC authenticates the expected node identity. A shared L4 address may
  route to the wrong identity and fail the handshake.
- Garage does not hot-reload `garage.toml`; a config hash rolls the workload.

These make a DaemonSet rendering straightforward but a direct Kubernetes
selector unsafe. Membership needs an operator-owned handoff.

## API contract

Each `NodeLocalPoolSpec` contains:

| Field | Contract |
|---|---|
| `name` | Stable DNS-label identity for child names, labels, and layout tags |
| `capacity` | Uniform aggregate Garage layout capacity for each selected node, minimum 1Ki |
| `metadata` | HostPath containing `node_key` and metadata DB; path is immutable for the lifetime of the pool |
| `data` | One HostPath mounted at `/data/data` |
| `dataPaths` | Multi-disk alternative to `data`, with container path, HostPath, capacity/read-only state |
| `selector` | Non-empty Kubernetes `LabelSelector`; this is the durable desired-membership boundary |
| `network.rpcPublicAddrTemplate` | Optional identity-specific `host:port` containing `{nodeName}` |
| `podTemplate` | Resources, tolerations, preferred affinity, security context, environment, and pod metadata; it cannot redefine membership |

Exactly one of `data` and non-empty `dataPaths` is required. Paths must be
absolute, normalized, non-root, and non-overlapping. Multi-disk aggregate
capacity may be lower than the writable-path sum to reserve space but cannot
be higher. Pool capacity is a Garage layout weight, not a HostPath filesystem
quota or an automatic free-space measurement.

Selectors support normal `matchLabels` and `matchExpressions`. Admission
validates syntax and reserves the operator's activation-label keys. Actual
overlap is evaluated against live Kubernetes Nodes on every reconcile:

```yaml
selector:
  matchLabels:
    storage.garage.example/pool: local-700
```

If one Node matches two pools, neither conflicting identity is activated and
`NodeLocalPoolsReady=False/SelectorConflict` names the Node and pools. A dedicated
pool label is still the clearest operational convention.

Required node affinity is rejected. It would create a second durable
membership selector that the drain state machine could not observe reliably.
Preferred affinity, topology spread, and tolerations remain available.

HostPath type defaults to `Directory`. Directory existence by itself cannot
distinguish a mounted disk from an empty root-filesystem mountpoint, so each
production metadata/data directory must contain a pre-provisioned
`.garage-volume-id` regular file. The workload mounts that file separately as
a read-only HostPath of type `File`; an absent mount therefore fails pod volume
setup before Garage starts. The operator never creates the marker.
`DirectoryOrCreate` explicitly opts out of this marker guarantee for tests or
deliberate ephemeral provisioning.
The metadata path is immutable; changing only its HostPath type is allowed and
rolls the pool only when tightening `DirectoryOrCreate` to `Directory`.
Loosening a retained metadata or data path is rejected: a missing mount must
fail rather than create an empty identity or data directory. HostPaths must be
exclusive to one Garage workload across all namespaces and GarageClusters.
Reconciliation blocks parent/child path overlaps it can prove across desired
managed-pool specs, retained/retiring managed DaemonSets, and still-live
operator pool Pods, including foreign GarageClusters. Manual GarageNodes and
unrelated workloads do not carry enough pool ownership metadata to prove their
mounts; their exclusivity remains an administrator responsibility. The
operator never removes HostPath contents.

## Owned resources

For a cluster `garage` and pool `local-700`, the cluster controller owns:

- DaemonSet `garage-storage-local-700`;
- active ConfigMap revision `garage-storage-local-700-config-<config-hash>`
  (plus revisions still referenced during a rollout);
- one internal `GarageNode` per active Kubernetes Node;
- one UID-scoped deterministic activation label key on each active Kubernetes
  Node;
- one scheduler-enforced activation gate on every DaemonSet Pod, removed only
  for the exact current workload UID after live ownership checks; and
- one namespace/name/pool-scoped Garage identity annotation on each Node after
  that member has a committed role.

The internal GarageNode is controller-owned, has
`backing: NodeLocalPool`, and records both `nodeLocalPoolName` and
`kubernetesNodeName`. It owns only the Garage layout role. It does not create
a StatefulSet, PVC, ConfigMap, or Service.

Node-local pool-backed GarageNodes cannot be created as user-owned resources. The
admission webhook verifies the live GarageCluster owner UID and declared pool,
preventing a forged owner reference from assigning or removing a persisted
identity.

Pool resources use these stable labels:

```text
garage.rajsingh.info/node-local-pool=<pool name>
garage.rajsingh.info/kubernetes-node=<node name or stable hash>
```

The full Kubernetes Node name is also stored in the
`garage.rajsingh.info/kubernetes-node` annotation. Node names that are valid
label values and no longer than 63 characters are used directly; longer names
use a deterministic `sha256-...` label value.

## Membership state machine

The user selector expresses desired membership. It is not copied into the
DaemonSet. The operator translates it into a pool-specific activation label
that is the DaemonSet's actual selector. That label is also a durable
pool-ownership lock before the first Pod/GarageNode exists: a Node carrying one
pool's activation cannot be activated in another pool.

| State | Operator action | Safety property |
|---|---|---|
| Desired, inactive | Wait for every earlier layout version, then atomically add one activation label and HostPath claim | Pod remains scheduler-gated until the exact current DaemonSet UID passes final live checks |
| Current gated Pod has one proven Node target | Re-read the pool selector, activation token, HostPath claim, and all old pool Pods, then remove its scheduling gate | A late Pod from a retired DaemonSet keeps its immutable gate and cannot mount the disk |
| Pod scheduled | Patch stable node label, create GarageNode | No phantom Garage role for an unschedulable Node |
| GarageNode connected | Assign role and capacity | Identity comes from the persisted metadata directory |
| `status.connected=true` and `status.inLayout=true` | Member is ready | A live replacement is committed before old capacity moves |
| No longer desired | Add `garage.rajsingh.info/drain=true`; keep activation label, GarageNode, and pod | Preparation remains reversible before Kubernetes DELETE |
| `DrainPrepared=True/PreparedForDeletion` | Delete the GarageNode | Exact role removal and source/destination block proof completed while the source process remained live |
| GarageNode finalizer complete | Remove activation label | Pod stops only after the prepared deletion authorization is consumed |
| No roles remain in removed pool | Delete DaemonSet and ConfigMap revisions | Host data remains for recovery or explicit cleanup |

Cold recovery is a distinct transition, not a topology addition. A desired
member with a durable Node/GarageNode identity pin, or one exact positive-
capacity committed role tagged with the cluster name/namespace, pool, storage
tier, and Kubernetes Node, may be activated with that expected node ID. All
such committed members may start together so layout recovery cannot deadlock
on an offline peer. The child must discover the same ID from the exact Pod's
own Admin API and re-prove the tagged committed role before persisting status
or mutating layout. Missing, conflicting, or changed identity evidence blocks
recovery.

This mechanism adopts identities from one existing Garage store; it does not
merge an arbitrary retained subset into a new store. A same-name recovery must
restore the store's RPC secret and all surviving Manual/PVC/SMB and pool
metadata identities. Permanently missing roles use the explicit lost-source
workflow. Mixing fresh Manual identities with retained pool layout metadata is
fail-closed as an unresolved historical layout, not auto-pruned.

Only one stale GarageNode begins deletion at a time. For a non-federated
cluster, the controller also refuses a drain if fewer confirmed positive-
capacity roles than `replication.factor` would survive. In federation, remote
roles are not represented by local GarageNode objects, so Garage's own layout
constraint and the fail-closed GarageNode finalizer remain authoritative.

### Reversible live-node drain transaction

Role absence and settled layout history are necessary but are not sufficient
proof that object blocks left a source. Upstream Garage chooses normal block
replicas from the current layout, while a removed-but-live process can still
scan its on-disk blocks and offload unique data through a `Blocks` repair.
Consequently every positive-capacity removal uses one layout-wide transaction,
regardless of whether the actor is PVC-, SMB-, or node-local-pool-backed, an external
GarageNode, Auto scale-down, or whole-site retirement.

The protocol is:

1. Require literal `replication.consistencyMode: consistent`, a generation-
   current `StorageRolloutReady=True` (or `ManagementHandleReady=True` for a
   connection-only owner), settled layout history, and fully healthy live
   Garage status.
2. Persist `status.storageDrain` with the exact actor UID, transaction and
   target hashes, every role-removal ID, positive-capacity subset, and exact
   locally managed Pod UIDs before staging anything.
3. Re-read the GarageCluster, process incarnations, health, and exclusively
   owned global staging area immediately before Apply. A failed Apply is
   re-read: if every role remains, the operator reverts only its exact staging,
   verifies role-present/staging-empty, and clears the transaction. An
   ambiguous committed response keeps the transaction and every source live.
4. Keep the removed source process running after its role leaves the current
   layout. Wait for its old-layout tracker to disappear.
5. Read all current positive-capacity destinations plus every removed source
   from the Admin API. Every verification process must still be `isUp` and
   answer worker and block-error queries. Launch an exact `Blocks` repair on
   the source and every destination.
6. Require those repair workers to complete cleanly, exact block-resync workers
   to be idle and error-free, no persistent block errors, and—whenever any
   process is external or federated—a globally empty resync queue. Preserve a
   quiet window of at least Garage's block-GC delay before recording
   `completedAt`.
7. Publish `DrainPrepared=True/PreparedForDeletion`; only then may the parent or
   user issue DELETE. Validating admission rechecks the exact actor, target,
   annotation, and terminal timestamp.

`spec.layoutManagement.drain.unverifiedPeersPolicy` is intentionally attached
to the canonical layout owner, not `spec.storage`: a connection-only management
handle and a mixed or external topology need the same policy. `Block` is the
safe default. `AssumeConsistent` is required for a federated/external process
whose running configuration and Pod incarnation another control plane cannot
prove; it is an explicit operator assertion and also forces the terminal
empty-queue fallback.

All Admin API, discovery, worker, or Kubernetes observation errors retain the
source workload. The generic finalizer retry budget never discards a storage
role or bypasses an incomplete transaction.

One per-`GarageCluster` mutation coordinator is injected into both controllers
and wraps every same-Kubernetes-cluster layout writer: Manual and automatic
GarageNode reconcile/finalize, node-local pools, default-group bootstrap/finalize,
gateway assignment and tombstones, federation imports, and factor
migration. Each writer re-reads layout history after acquiring the coordinator
and may perform at most one successful Apply in that pass. A newer layout
version is never assumed to contain the caller's staged change; the next pass
re-reads the desired role.

The initial GarageNode batch is special only because no Admin API exists until
it boots and Garage may require several staged roles before the replication
factor permits one Apply. Those staging calls are still serialized. After the
first Apply, all changes wait for the active history to settle.

The binary and Helm chart enable controller-manager leader election by default,
so only one manager owns the in-process coordinator. Every shipped install path
enables it. Startup rejects a disabled value unless an explicit unsupported
single-replica override is supplied; custom HA deployments must retain leader
election.

The coordinator is local to one Kubernetes control plane. Separate Kubernetes
clusters in a Garage federation do not share a Kubernetes lock: although every
controller reads the shared Garage layout history, simultaneous changes at two
sites can both pass the settled-history check before either commits. Synthetic
ownership aliases derived from an external Admin endpoint coalesce writers only
inside one manager and are not a distributed lock. Operationally, exactly one
GarageCluster/operator may mutate topology in a shared federated or external
layout at a time. Wait for it to finish and for no `Draining` version before
changing the next physical site. This release does not claim a cross-cluster
transaction.

Positive-capacity membership removal is also an admission-enforced generation
boundary. A default-group replica decrease, node-local pool removal, or
retained node-local pool selector change may include pool additions, but every
retained pool's non-selector definition and all non-topology GarageCluster
fields must remain unchanged. Operators first apply image/config/template,
consistent-mode, federation-policy, volume, capacity, or service changes and
wait for `StorageRolloutReady=True` at that exact old generation plus fully
healthy Garage status. Only then is the topology-only generation accepted. This
keeps a departing process inside the rollout candidate set for every
configuration it must run during its drain.

### Parent-controlled workload rollout

Every pool DaemonSet and every GarageNode-owned StatefulSet uses `OnDelete`.
Updating an image, config revision, disk mapping, or `podTemplate` therefore
cannot make Kubernetes roll identity-bearing storage processes independently.
The parent selects one outdated PVC, SMB, unified-gateway, or node-local-pool pod
across the entire `GarageCluster` and deletes only that pod after proving:

- all current pool pods are Ready and none is terminating;
- every GarageNode has fresh NodeID/Connected/InLayout/observed-generation
  evidence;
- layout history is settled and no other layout writer owns the coordinator;
- Garage reports every storage node and partition healthy; and
- the candidate identity is live with a committed role.

After replacement, the GarageNode controller must rediscover the identity from
that exact replacement Pod and record its UID in `status.observedPodUid`.
Cached readiness from the previous Pod cannot unlock the next deletion. Surge
is forbidden because two Pods could mount the same `node_key` and HostPaths.
Gateway-only edge clusters retain the cluster-level StatefulSet's native
ordered, Ready-gated `RollingUpdate`; they have no per-ordinal GarageNode UID
handshake and are outside this transaction.

Recovery preserves every retired workload-controller UID that can still create
a late Pod. The status exclusion set is capped at 32 UIDs. At the boundary the
operator fails before publishing config or creating/adopting another workload;
it never evicts an older UID from the safety set. No generic status-patch bypass
is defined. Operator/developer-led recovery must preserve the transaction until
it can prove all Pods owned by every recorded UID absent from Kubernetes and
unable to mount the actor's PVCs or HostPaths. A reused controller name is
insufficient.

### Selector replacement

For a selector change inside one pool:

1. activate newly matching Nodes;
2. wait for their pods and GarageNodes;
3. wait for every replacement in that pool to report `Connected` and `InLayout`;
4. wait until `GetClusterLayoutHistory` reports no data migration still in
   progress and no other storage or gateway GarageNode is joining/finalizing;
5. drain old members one at a time;
6. remove their activation labels after finalization.

An activated but unschedulable pool blocks another automatic topology change:
its pod may schedule at any moment, so allowing a concurrent drain would break
the single-flight guarantee. Fix its scheduling or remove that desired member.
The previous pool Pod is itself an ownership fence for that Kubernetes Node,
even when its DaemonSet was deleted out of band and the replacement pool uses
disjoint HostPaths. The operator does not activate the replacement until the
old Pod is actually gone.
Replication safety still counts every confirmed storage role in the cluster.
A still-declared pool matching zero Nodes retains its old members and reports
`WaitingForReplacement`; removing the pool from spec is the explicit request
to drain it to zero.

### Moving one Kubernetes Node between pools

A Node must never run two pool pods at once: the two specs may point at the
same physical directories. A direct label value change from pool A to pool B
is therefore rejected at runtime before pool B receives an activation label.

The supported move is deliberately two-step:

1. remove the Node from every pool;
2. wait for its GarageNode to disappear, its old activation label to be
   removed, and its old pod to terminate;
3. change disk layout or contents if needed;
4. select it into the new pool.

`NodeLocalPoolsReady=False` reports `DirectNodeLocalPoolMoveBlocked` or
`WaitingForPreviousNodeLocalPoolPod` when this boundary is encountered.

### Node loss and identity replacement

The operator cannot keep a pod online after the physical Kubernetes Node
disappears. That is not a live-node drain: the missing source cannot perform
the required on-disk scan, so the operator retains the Garage role and blocks
automatic deletion. After adding replacement capacity and verifying
durability, an administrator must use Garage's explicit dead-node recovery;
`allowMissingData=true` is a separate acknowledgement that can authorize data
loss.

The administrator atomically adds `drain=true` and
`acknowledge-lost-source=<exact 64-hex Garage ID>` to the retained GarageNode.
Admission binds the one-way acknowledgement to that object's persisted ID. The
controller first proves Garage already reports the identity down—so the
annotation cannot manufacture its own outage—then fences any remaining managed
workload and waits for the administrator to remove/apply the exact dead role
through Garage. Destination-only `Blocks` repair/resync and quiet-window proof
must complete before `DrainPrepared=True`; it explicitly cannot prove data that
existed only on the lost source. If the identity was an active storage-rollout
actor, status ownership transfers atomically from rollout to storage drain
before PVC protection is released or the workload is fenced.

If a Kubernetes Node name returns with the same metadata directory, Garage
loads the same node ID. If the metadata disk was replaced, discovery sees a
new node ID. For positive-capacity storage the GarageNode controller retains
the old `status.nodeId`, invalidates the old Pod-UID/live-source observation,
leaves the replacement unassigned, and performs no layout mutation until the
administrator invokes the explicit lost-source workflow above. Before fencing,
the controller proves the current process has no committed or staged role; an
already-assigned replacement fails closed for an explicit dual-identity
recovery plan. Deletion/recreation can then enroll the new identity without two
storage roles ever being owned by one GarageNode. Capacity-less gateway
identity replacement remains automatic.

## Mixed default and manual storage

`storage.layoutPolicy` governs only the default StatefulSet/PVC group.
Node-local pools are always operator-managed.

The intended heterogeneous shape is:

```yaml
spec:
  layoutPolicy: Auto             # gateway can remain operator-managed
  storage:
    layoutPolicy: Manual         # SMB/PVC GarageNodes remain GitOps-owned
    replicas: 0
    nodeLocalPools:
      - name: local-700
        # ...
```

The default volume fields may be omitted when its replica count is zero; they
remain required when the default group has replicas. User-created GarageNodes
can continue to describe SMB, Ceph, LocalPath PVC, external, and
exceptional-capacity members. Their positive capacities count in the pool
drain safety check.

The current scalar default requires node-local-only and Manual-only manifests
to write `replicas: 0` explicitly; omission defaults the PVC group to three.
Across all node-local entries, at most 255 Nodes may be selected. Garage's
global hard limit is 256 positive-capacity roles across every backing and site.
At 255 live roles a new node-local activation is eligible only when this control
plane proves a retiring generated member. The in-process layout coordinator
serializes that decision with Manual/PVC/other writers in the same manager, but
it is not a durable reservation against an independently operated federated
site. If another writer consumes role 256, node-local role assignment fails
closed until a removal commits. Staged additions consume headroom, while staged
removals do not restore it until committed. Layouts at 256 remain drainable;
federated topology mutations must be externally serialized.

When `storage.podDisruptionBudget` is enabled, one PDB selects the whole storage
tier. With pools and no explicit threshold, it defaults to
`maxUnavailable: 1`. This protects voluntary eviction across mixed storage,
but Kubernetes PDBs alone do not serialize workload-controller rollouts. The
parent-controlled `OnDelete` protocol above handles operator-driven changes;
administrators must not bypass it by deleting several pool pods directly.

A permanently lost Kubernetes Node cannot acknowledge Garage's draining layout
history. The storage finalizer intentionally stays fail-closed. After adding
and verifying replacement capacity, an administrator may use the existing
`skip-dead-nodes` annotation; `allow-missing-data` remains an explicit,
data-loss-capable last resort.

## Pool-specific Garage configuration

Every pool gets its own immutable, content-addressed ConfigMap revisions:

- a single-disk pool renders `data_dir = "/data/data"`;
- a multi-disk pool renders only that pool's ordered path/capacity/read-only
  array;
- default-group multi-disk settings never leak into a node-local pool;
- cluster/default shared `rpc_public_addr` values are suppressed.

The DaemonSet mounts the pool's metadata and data HostPaths, RPC secret, Admin
token, and the revision whose name contains the config hash. A config change
therefore switches the Pod template to a different object instead of mutating
the config mounted by old pods. The operator retains old revisions until the
DaemonSet controller has observed a fully available rollout and no remaining
Pod object references them.

If a DaemonSet object disappears out of band, its background-garbage-collected
Pods may outlive it. The operator confirms live API state and refuses to create
the replacement controller until every Pod owned by the old DaemonSet is gone,
preventing two processes from mounting one identity during controller
recreation.

Garage has a valid staged multi-disk migration while every old path remains
mounted:

1. render old and new paths together;
2. mark the old path `readOnly`;
3. run active block repair/rebalance and verify the old path is empty;
4. keep the old path mounted read-only, or retire the entire pool.

Admission makes that ordering explicit. An existing container path cannot be
repointed or removed, including after it becomes read-only, because the
operator cannot prove that Garage evacuated that directory everywhere. A
single-disk pool may enter the sequence by switching to `dataPaths` while
retaining the original HostPath at `/data/data`, but completing physical disk
replacement requires retiring and fully draining the whole pool before
recreating it with the new layout. HostPath contents are never deleted.
Changing pool capacity updates every member's layout role and can trigger a
large rebalance.

Admission is not the only safety boundary. Each pool DaemonSet and every
ConfigMap revision carry an operator-owned, versioned disk-layout record
containing its metadata HostPath and HostPath type plus
container-path-to-HostPath/type/read-only mappings. Before changing the
ConfigMap revision or DaemonSet, the controller applies the same no-remap,
no-type-loosening, and read-only-removal transition rules against every
retained revision. It additionally verifies the DaemonSet record against the
actual pod-template mounts. ConfigMap copies preserve disk-identity evidence
if the DaemonSet is deleted out of band while GarageNodes still exist. A
DaemonSet created before the record existed is inspected directly and every
discovered path is conservatively treated as writable until a no-op rollout
records its state.

The metadata HostPath is immutable. To change it, remove and fully drain the
pool, wait for all old resources to disappear, and recreate it. Its HostPath
type may be tightened after provisioning. The DaemonSet/ConfigMap disk records
and content-addressed config references close the separate-update and pod
restart races: immediately re-adding a retired pool name with different disks
fails while any old resource remains, and an old pod always references its
matching old config. Removing and adding an overlapping/renamed pool in one API
update is rejected.

## RPC routing and federation

A shared Service cannot target a particular Garage identity. In a mixed
cluster, `spec.publicEndpoint` remains valid for the default PVC/Manual storage
group; its Service selects `garage.rajsingh.info/storage-group=default` and
never a node-local-pool pod. Node-local pools still require identity-specific routes.

An external controller may create one Service per Node using:

```yaml
selector:
  app.kubernetes.io/instance: garage
  garage.rajsingh.info/node-local-pool: local-700
  garage.rajsingh.info/kubernetes-node: worker-a
```

`nodeLocalPools[].network.rpcPublicAddrTemplate` resolves `{nodeName}` and is stored
on the generated GarageNode. The GarageNode controller publishes it as the
operator-owned layout tag `rpc-address:<host:port>`. Federation preserves and
prefers that tag when connecting to a remote identity.

Directly routed pod networks can omit the template and use
`network.rpcPublicAddrSubnet`; the operator chooses a Pod IP in that subnet.
Without either mechanism, local clustering may work through pod networking but
cross-cluster reconnect is not durable.

A federated `GarageCluster` with node-local pools currently uses one static
`spec.zone` for the source site. `zoneFrom` with `remoteClusters` is rejected because
`remoteClusters[].zone` identifies one remote site and cannot address several
node-derived zones behind the same source cluster.

Remote reconciliation is import-only. An Admin endpoint exposes Garage's
global replicated inventory rather than a source-site ownership set, and the
current `RemoteClusterConfig` carries no immutable site UID. Therefore missing,
down, friendly-name-tagged, or zone-matching roles are never removal proof. The
source site's exact GarageCluster/GarageNode finalizer transaction is solely
responsible for retirement.

## Status

`NodeLocalPoolsReady` is the pool lifecycle condition:

| Status/reason | Meaning |
|---|---|
| `True/Converged` | Every desired identity is in the committed layout, no layout version still requires data synchronization, and no retired role remains |
| `False/WaitingForMembers` | A selector matches no Nodes, or a desired pod, connected identity, or layout role is not ready |
| `False/WaitingForReplacement` | Same-pool replacements must commit before an old member drains |
| `False/WaitingForLayoutSync` | Garage is synchronizing a layout version, another storage/gateway member or pool activation is in flight, or the Admin API cannot prove convergence |
| `False/WaitingForDrainSafety` | Reversible consistency, rollout, health, or unverified-peer preflight has not authorized deletion |
| `False/Draining` | One old GarageNode is finalizing while its pod stays online |
| `False/ReplicationUnsafe` | The next drain would leave fewer confirmed roles than the factor |
| `False/DirectNodeLocalPoolMoveBlocked` | A Node was selected directly into another pool |
| `False/WaitingForPreviousNodeLocalPoolPod` | The old role is gone but its pod is still terminating |
| `False/IdentityCollision` | Multiple GarageNodes loaded the same durable `node_key`; they are one Garage identity, not separate replicas |
| `False/SelectorConflict` | One live Kubernetes Node matches more than one pool selector; no conflicting identity is activated |
| `False/HostPathConflict` | Another GarageCluster claims an overlapping HostPath on the same Kubernetes Node |
| `False/UnsupportedKubernetesVersion` | The API server is older than the Kubernetes 1.27 pool minimum |
| `False/SchedulingGatesUnavailable` | The API server or scheduler failed the required scheduling-gate behavior |
| `False/SchedulingGateCapabilityUnknown` | Discovery, transport, scheduler evidence, or probe cleanup was inconclusive, so activation remains blocked |
| `False/SchedulingGateProbePending` | The capability probe is waiting for positive `SchedulingGated` scheduler evidence |
| `False/MemberLimitExceeded` | Live selectors exceed the supported 255 node-local members per GarageCluster |
| `False/GarageRoleLimitExceeded` | The shared Garage layout has no safe headroom below its 256-role limit |

The cluster `Ready` condition is false while this condition is false.
Node-local pool-backed replicas count as ready only with a NodeID, fresh observed
generation, `Connected`, and `InLayout`. A rollout additionally requires that
evidence to name the current Pod UID and requires settled layout history;
Kubernetes Pod readiness alone is insufficient. The condition is removed
after the cluster no longer declares or owns any pool resources.

`StorageRolloutReady` is the cluster-wide workload replacement condition.
`False/RollingOut` identifies the one persisted actor and exact previous Pod
UID while the controller waits for the replacement's fresh UID, Garage
identity, health, and settled layout history. It applies to PVC, SMB, unified
gateway GarageNodes, and node-local-pool members; it is independent of whether a
cluster currently declares a node-local pool.

The default Auto StatefulSet/PVC group separately reports `StorageTopologyReady`.
`False/AddingMembers`, `False/DrainingMember`, and
`False/WaitingForLayoutSync` keep cluster `Ready=False`;
`StorageScaleDownBlocked=True` is reserved for the non-transient case where
the desired survivor count would violate `replication.factor`.

## API conversion

Pools are v1beta2-only. A v1beta1 view keeps the normal default StatefulSet/PVC group
editable and carries the pool list in a reserved conversion annotation:

```text
garage.rajsingh.info/v1beta2-node-local-pools
```

Converting back restores only the pool list. The payload and its
`v1beta2-only` marker are removed from hub state and regenerated whenever a
v1beta1 view is requested. The v1beta1 webhook rejects removal or mutation of
that payload when the original request used v1beta1, preventing an older client
from silently erasing pools without blocking legitimate v1beta2 edits routed
through an equivalent-version webhook. Admission also reserves the transport
annotations and rejects pool specs whose projected payload would exceed
Kubernetes' annotation-size limit. Projection includes user annotations,
combined gateway payload, and marker components; 262144 bytes is accepted and
262145 is rejected.

Routine node-local readiness status does not copy a full member inventory:
generated GarageNodes are selected by labels for detail. Node-local lifecycle,
storage rollout/drain, and repeated-member health condition messages are capped
at 4096 bytes; inventory summaries retain a count plus five sorted examples.
Informational layout history is capped at 64 entries while safety state machines
consume Garage's complete live response. The active drain proof still records
the exact role, process, repair-worker, and resync-worker evidence required to
resume safely after a crash. The release-envelope projection models 256 roles,
eight resync workers per role, 64 layout-history entries, 32 legacy top-error
details, the other role-derived diagnostic lists, and all 26 currently declared
GarageCluster conditions at maximum message size. The drain transaction
serializes to 365085 bytes (about 357 KiB) against a 512 KiB budget; the
coexisting status serializes to 966767 bytes (about 944 KiB) against a 1 MiB
budget. This is a conservative projection of the
operator's supported feature state, not a mathematical bound on arbitrary
legacy status writers or a justification for larger API limits.

New automation for a cluster with pools must use v1beta2.

## Migration from existing LocalPath PVC nodes

The operator does not automatically adopt LocalPath PVCs as HostPaths.
Provisioner directories are PVC-identity-specific, while a pool requires the
same declared HostPath on every selected Node. More importantly, the PVC
metadata contains the live `node_key`; mounting it concurrently from the old
StatefulSet and a new DaemonSet would run one Garage identity twice.

The preferred online migration creates new identities:

1. keep SMB and exceptional nodes as Manual GarageNodes;
2. provision and mount standard, empty metadata/data directories on candidate
   local Nodes, then create `.garage-volume-id` inside every mounted directory;
3. add a pool without deleting old LocalPath GarageNodes;
4. wait for `NodeLocalPoolsReady=True`, `StorageRolloutReady=True`, cluster health,
   and block resync;
5. delete old LocalPath GarageNodes one at a time and wait for each finalizer;
6. remove retained PVCs/directories only after Garage has drained them;
7. change per-node RPC Services to the stable pool Pod labels.

This needs temporary capacity. It is the only automated path that never starts
two processes against one `node_key`.

An identity-preserving conversion is possible only as an explicit offline,
one-node-at-a-time cutover. Record the node ID and the bound PV
`.spec.local.path` values, remove the old GarageNode and wait for its normal
layout drain plus StatefulSet/pod deletion, then create `.garage-volume-id`
inside each mounted retained path and add a single-node-local pool using those exact
metadata/data paths. The role is re-added with the same on-disk node key. Set
`storage.pvcRetentionPolicy.whenDeleted: Retain` before
removing the GarageNode and keep the LocalPath PVC/PV objects. If those objects
must ever be deleted, first change the PV's `persistentVolumeReclaimPolicy` to
`Retain`; deleting a dynamically provisioned volume may otherwise delete the
directory now mounted through HostPath.

PVC paths differ, so identity-preserving migrations normally use one pool per
Kubernetes Node. The pool and RPC Service selector change must be a later
GitOps step than removal of the old GarageNode. The operator deliberately does
not automate or guess this handoff.

### Rollback

Before old nodes are removed, rollback is simply pool removal; the operator
drains the new identities and leaves all HostPath data intact.

After old nodes are removed, restore retained old PVC-backed GarageNodes first,
wait for them to rejoin, then remove the pool. Never run the old StatefulSet
and pool pod against the same metadata directory.

After every old GarageNode, DaemonSet, ConfigMap revision, and activation label
is gone, recreating a removed pool with the same name and unchanged metadata
HostPath reuses the on-disk identities. They still need to be assigned to the
layout again because successful pool removal deliberately drained their roles.

## Upgrade, deletion, and permissions

- The operator must be installed cluster-wide. Node list/patch and Pod patch
  permissions are required for the activation and stable-label protocols.
- The validating and conversion webhooks are mandatory. Their shipped
  `failurePolicy: Fail` configuration fails closed when admission is
  unavailable; disabling the webhook configuration is unsupported for pools.
- Downgrading the operator to a namespace-scoped install while pools or their
  conditions remain is unsupported. Cluster finalization fails closed rather
  than leave hidden activation labels on Nodes.
- `spec.deletionPolicy: Destroy` is the default whole-store teardown. It skips
  Garage's impossible empty-storage-layout transition, removes Kubernetes
  workloads, activation labels, and Node identity records, and never deletes
  HostPath contents. Force deletion deliberately bypasses that cleanup; the
  stable identity record then fences any same-name recovery to the retained
  disk's previous Garage node ID.
- `spec.deletionPolicy: Drain` is a prepared federated-site retirement
  transaction. Set `garage.rajsingh.info/drain=true`, wait for
  `StorageDrainReady=True/Completed`, inspect the exact targets and terminal
  proof, and only then delete the GarageCluster. Admission rejects an
  unprepared DELETE.
- Activation-label keys include the immutable GarageCluster UID. A forced
  deletion may orphan labels, but a same-named replacement cannot reactivate
  them; an administrator may remove them after verifying the old workload is
  gone.
- HostPath-capable GarageCluster write access is equivalent to permission to
  mount selected host filesystem paths. Restrict it to trusted administrators
  and add admission policy for approved path prefixes where needed.
- Factor migration remains blocked while node-local pools exist; its all-storage-pods-
  stopped workflow does not yet coordinate activation labels.
- Released v0.6.29 has no node-local pool API, so ordinary clusters need no
  compatibility migration. Unreleased prototypes using
  `storage.workload: DaemonSet`, `storage.pools`, `storage.nodePools`,
  `backing: StoragePool`, `backing: NodePool`, `poolName`, `nodePoolName`, or
  their storage-pool/node-pool labels and conversion annotations must be stopped
  and recreated or explicitly migrated before the final CRD is installed. A
  live alias would risk two workload identities mounting one `node_key`, so none
  is provided.

## Verification boundary

Release coverage includes:

- pool API validation, live selector-conflict handling, path/capacity rules,
  identity immutability, routing warnings, and safe update warnings;
- v1beta1 round-trip preservation and reserved-payload protection;
- pool-specific single/multi-disk config with shared RPC suppression;
- HostPath DaemonSet rendering and stable labels;
- no GarageNode before Pod scheduling;
- initial readiness, add-before-remove selector handoff, one-at-a-time
  post-bootstrap addition and drain, all-writer serialization, direct
  pool-move refusal, activation cleanup, and replication guard;
- isolation from Auto/default GarageNode ownership;
- node-local-pool-backed node-ID discovery, stale identity replacement, and
  fail-closed finalization;
- source-plus-destination repair/resync proof, failed-Apply staging rollback,
  prepared GarageNode and GarageCluster DELETE admission, and management-handle
  layout-policy coverage;
- cluster-wide parent-controlled `OnDelete` rollout with replacement-pod UID
  observation;
- mixed topology status, PDB, per-identity federation route health, and generated
  CRD/RBAC/Helm artifacts.
