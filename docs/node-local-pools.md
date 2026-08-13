# Node-local pools (DaemonSet-backed)

Use `spec.storage.nodeLocalPools` for node-local disks. A pool runs one Garage
pod on each selected Kubernetes Node and keeps Garage identity and block data
in HostPath directories.

If you are coming from the upstream Garage Helm chart's DaemonSet deployment,
this is the equivalent feature. Each `nodeLocalPools` entry is realized as one
operator-managed **DaemonSet**. The field is named for the storage contract it
provides — one independently identified Garage process per selected Node,
backed by that Node's HostPaths — rather than for the workload kind, because
the DaemonSet is an implementation detail the operator coordinates, not a mode
you select. See [Garage semantics](#garage-semantics) for why that distinction
matters to the layout.

Pools are additive. Keep SMB, Ceph, PVC, external, and exceptional-capacity
nodes as ordinary `GarageNode` resources while uniform local nodes move into
one or more pools. See the
[mixed-storage sample](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_node_local_pools.yaml)
and the [complete design](design/2026-07-30-node-local-pools-design.md).

One workload-owning `GarageCluster` is one Garage store/site lifecycle and
ownership boundary, usually one physical site, not one object per storage
backend. Its SMB/PVC GarageNodes, optional default StatefulSet/PVC group, and
node-local pools share that object, Admin credential, rollout transaction, and
drain status. Members may share one static `spec.zone` or derive multiple actual
failure-domain zones through `zoneFrom`. Create another workload-owning
GarageCluster only for another site lifecycle or a genuinely independent
Garage object store. A connection-only
management handle is different: it owns no workload and can be used to manage
an external layout through `spec.connectTo`.

## Garage semantics

A `NodeLocalPool` is an operator-side membership generator, not a Garage
entity, replication group, quorum, or failure domain. Garage has durable node
identities and applies one cluster-wide replication policy across all
positive-capacity roles and their actual zones. A pool therefore has no
independent replication factor or quorum. Its `capacity` is assigned to each
generated Garage role, not divided across the pool or interpreted as a total.

The pool name identifies operator-owned membership; it never supplies a Garage
zone. `spec.zone` or `zoneFrom` remains an independent failure-domain decision.
Floating PVC, SMB, Ceph, external, and exceptional `GarageNode` members keep
their own Garage identities and filesystems; their storage is not a shared
filesystem merged with a pool's HostPath data. One `nodeLocalPools` entry—the
normal node-local deployment—produces one DaemonSet spanning all selected
Kubernetes Nodes. Multiple entries produce multiple DaemonSets for disjoint
local-disk profiles.

## Prerequisites

- Run Kubernetes 1.27 or newer. Pools use Pod scheduling gates as a hard
  workload-incarnation fence; the operator and every non-pool cluster shape
  retain the chart's Kubernetes 1.25 minimum. Before it creates a pool
  DaemonSet or changes Node activation, the controller checks discovery,
  server-side dry-runs a gated DaemonSet, and creates a harmless real gated Pod
  whose positive proof is `PodScheduled=False` with reason `SchedulingGated`.
  A server that is older than 1.27, an API server that rejects/drops the gate,
  or a scheduler that does not provide that evidence gets
  `NodeLocalPoolsReady=False`; no partial activation occurs. Successful evidence
  is scoped to the GarageCluster namespace and cached for at most 30 seconds
  from kube-scheduler's `PodScheduled` transition. It is pinned only for the
  reconciliation that began from that proof, so a running manager re-detects
  control-plane capability changes without expiring its safety premise halfway
  through one state transition.
  Deleting a desired-only pool that never produced any pool artifact remains
  possible on an unsupported server. Once a DaemonSet, generated GarageNode,
  rollout, activation label, or HostPath claim exists, cleanup stays fail-closed
  until the capability is available again. The short-lived probe Pod is
  normally controller-owned and explicitly removed after proof or feature
  removal. During foreground GarageCluster deletion the exact probe is
  temporarily ownerless so garbage collection cannot race the finalizer's
  proof; terminal finalization explicitly deletes it before releasing the
  parent finalizer.
- Run Garage v2.0.0 or newer on every process participating in the layout.
  The pool drain proof uses Admin API v2 layout-history, repair-worker, and
  block-error endpoints that are present in v2.0.0; v2.3.0 is the tested
  default.
- Install the operator cluster-wide. Pools require cluster-scoped Node
  list/patch and Pod patch permissions. `zoneFrom` also requires the
  cluster-scoped Node watch for every workload shape, including Manual/SMB
  GarageNodes; a namespace-scoped install reports those objects Failed instead
  of silently freezing a stale fallback zone.
- Permit HostPath workloads in every namespace that contains a node-local pool.
  Kubernetes Pod Security Admission's Baseline and Restricted policies prohibit
  HostPath volumes, so such a workload namespace normally needs
  `pod-security.kubernetes.io/enforce=privileged` or an equivalent organization-
  specific admission exception. This grants pool pods direct access to the
  configured Node paths; restrict who may edit the GarageCluster and its pool
  Pod template. The operator's own namespace can remain Restricted.
- Install both the validating and conversion webhooks. The shipped webhook
  configurations use `failurePolicy: Fail`; an unavailable webhook therefore
  fails closed. Disabling or omitting them removes the update, deletion, and
  v1beta1 conversion safety boundary and is unsupported for pools.
- Use the v1beta2 `GarageCluster` API.
- Declaring `spec.storage.nodeLocalPools` is the explicit opt-in. Earlier
  unreleased field names have no compatibility promise.
- Create the Secret referenced by `spec.admin.adminTokenSecretRef`.
- Give every pool a dedicated, non-empty Node label selector.
- Pre-create and mount metadata/data directories on every selected Node, then
  create a `.garage-volume-id` regular file inside every production
  `hostPathType: Directory` mount.
- Keep at least the replication factor healthy throughout enrollment.

For example:

```bash
kubectl label node worker-a worker-b worker-c \
  storage.garage.example/pool=local-700
```

This selects three Nodes and therefore generates three positive-capacity
Garage roles, matching the example's replication factor of `3`.

On each selected Node, after the real filesystems are mounted:

```bash
sudo install -d /var/lib/garage/local-700/metadata /var/lib/garage/local-700/data
sudo touch /var/lib/garage/local-700/metadata/.garage-volume-id
sudo touch /var/lib/garage/local-700/data/.garage-volume-id
```

The marker content is not interpreted; the important property is that the
file lives inside the mounted filesystem. The operator never creates it.

```yaml
spec:
  zone: site-a
  replication:
    factor: 3
    consistencyMode: consistent
  layoutManagement:
    autoApply: true
    drain:
      unverifiedPeersPolicy: Block
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  storage:
    layoutPolicy: Manual
    replicas: 0
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

`storage.layoutPolicy: Manual` affects only the default StatefulSet/PVC group.
`nodeLocalPools` remain operator-owned.
When the default StatefulSet/PVC group's `replicas` is `0`, its `metadata` and
`data` may be omitted; they remain required whenever that group has replicas.
Write `replicas: 0` explicitly for a node-local-only or Manual-GarageNode-only
cluster: the current CRD defaults an omitted value to `3`, so omission means
"create the default PVC group," not zero. No placeholder volume fields are
needed once the explicit zero is present.
Older Manual manifests may still carry a nonzero, historically ignored
`replicas` value and unused cluster-level volume templates. They may normalize
those fields to `replicas: 0` and omit the templates without draining or
changing any user-owned GarageNode.

Pool `capacity` is the uniform weight assigned to each member in Garage's
layout. It is not a HostPath filesystem quota and does not reserve or discover
disk space; provision and monitor the underlying filesystems separately.

## What the operator creates

For each pool, the cluster owns one DaemonSet, one active content-addressed
ConfigMap revision, and one internal GarageNode per active Kubernetes Node.
Old ConfigMap revisions remain temporarily while a DaemonSet rollout still has
pods using them. A GarageNode appears only after its pool pod has actually
scheduled; an unschedulable selected Node never becomes a phantom layout
member.

Every pool Pod is created with the
`garage.rajsingh.info/node-local-pool-activation` scheduling gate. The operator
removes that gate only from a Pod owned by the exact current DaemonSet UID,
after live checks of its one target Node, activation token, user selector,
durable HostPath claim, and every older pool Pod. A Pod created late by a
retired DaemonSet keeps its gate and therefore cannot race the replacement onto
the same disk, even if the scheduler still has an older Node-label snapshot.

If a pool DaemonSet is deleted out of band, the operator waits for every pod
owned by the old controller to disappear before recreating it. This prevents
old and replacement Garage processes from mounting the same `node_key`
concurrently.

The DaemonSet does not schedule directly from your selector. The operator adds
a private activation label to desired Nodes and schedules from that label. On
removal, it keeps the label and pod online until the GarageNode finalizer has
removed the role and Garage's active layout history no longer depends on that
identity, then removes the label.

After a role is committed, the operator also records its exact 64-hex Garage
node ID in an internal Kubernetes Node annotation. The scheduling label is
keyed by the immutable GarageCluster UID, but this disk-identity record is
keyed by namespace/name and pool. Consequently, a force-deleted and recreated
same-name GarageCluster cannot reuse an orphan scheduling authorization, while
retained HostPaths still carry the identity they are allowed to recover.

Watch convergence with:

The `garage.rajsingh.info/cluster` and `garage.rajsingh.info/node-local-pool`
selectors below target labels emitted by the operator on generated
`GarageNode`s. They are read-only diagnostic outputs; select pool membership by
editing the user-owned Node label selector in `spec.storage.nodeLocalPools`,
not by editing these generated labels.

```bash
kubectl get garagecluster garage \
  -o jsonpath='{range .status.conditions[?(@.type=="NodeLocalPoolsReady")]}{.status}{"  "}{.reason}{"  "}{.message}{"\n"}{end}'

kubectl get garagecluster garage \
  -o jsonpath='{range .status.conditions[?(@.type=="StorageRolloutReady")]}{.status}{"  "}{.reason}{"  "}{.message}{"\n"}{end}'

kubectl get garagenodes \
  -l garage.rajsingh.info/cluster=garage,garage.rajsingh.info/node-local-pool
```

The cluster is ready only after every desired pool identity is connected, in
the committed layout, and Garage reports no active `Draining` layout version.
A declared pool whose selector matches no Nodes reports `WaitingForMembers`
instead of silently appearing ready.

## Scaling and selector changes

Pool cardinality follows `selector`; `storage.replicas` controls only the
default operator-managed PVC group.

To replace nodes within one pool, label the replacements into the pool before
removing the old labels. The operator waits for same-pool replacements to be
both `Connected` and `InLayout`, then waits for Garage's prior layout version
to finish synchronizing before draining old members one at a time.

A direct move between pools is intentionally two-step: remove the Node from the
old pool, wait for its GarageNode and old Pod to disappear, then select it into
the new pool. A lingering old Pod remains a fence even if its DaemonSet was
deleted out of band and the new pool uses disjoint HostPaths.

### Safe update sequencing

A positive-capacity membership removal must be its own topology-only API
update. This includes decreasing the default group's `replicas`, removing a
node-local pool, or changing a retained pool's selector. The admission webhook
rejects combining that edit with an image, Garage configuration,
service/federation, volume, capacity, Pod-template, or other retained-pool
change. A newly added pool may carry its initial definition in the topology
update, and additions may be used to provide replacement capacity before
removals proceed.

Use two Git commits or GitOps sync waves:

1. Apply all runtime/configuration changes first. In particular, set
   `replication.consistencyMode: consistent`; for a federated layout also set
   `layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent`. Wait for
   `StorageRolloutReady=True` with `observedGeneration` equal to the current
   GarageCluster generation and for fully healthy Garage status.
2. Change only membership: default-group replica count, node-local pool
   additions/removals, or selectors. Keep every retained pool's non-selector
   fields and the rest of the GarageCluster spec unchanged until the drain
   finishes.

Check the generation boundary before the second step:

```bash
kubectl get garagecluster garage -o jsonpath='{.metadata.generation}{"  "}{range .status.conditions[?(@.type=="StorageRolloutReady")]}{.status}{"  "}{.observedGeneration}{"  "}{.reason}{"\n"}{end}'
```

The generation numbers must match and the condition must be `True`. To remove
an entire storage tier, first drain its replicas and pools to zero while keeping
the `storage` block; remove the empty block only in a later update if the
remaining cluster shape is valid.

Every same-Kubernetes-cluster layout writer uses one per-`GarageCluster`
mutation coordinator: Manual and automatic GarageNodes, node-local pools, the
default PVC group, gateways, federation imports, tombstone cleanup, finalizers,
and factor migration. Layout history is re-read after acquiring it. Additions
wait as well as removals: a member that joins while an older version is
draining can otherwise strand that version behind update trackers that did not
exist when it was created. An unavailable Admin API also fails closed.

The first GarageNode batch is the only bootstrap exception because no Admin
API exists before it boots and enough roles may need to be staged to satisfy
the replication factor. Staging still occurs inside the coordinator, and only
one successful layout apply is allowed per pass. After bootstrap, changes
proceed one committed, fully settled layout version at a time. Manual
GarageNode create, update, and deletion use this same path.

The binary and Helm chart enable controller-manager leader election by default,
and every shipped Helm/Kustomize/development/E2E installation keeps it enabled.
This makes the in-process coordinator authoritative for an HA operator
deployment. Disabling it is rejected at startup unless the single-replica
operator explicitly passes `--unsafe-allow-no-leader-election`; the Helm chart
likewise requires `leaderElection.unsafeAllowDisabled: true` and refuses more
than one replica. That override is unsupported and logs a prominent warning.

This coordinator is not a distributed lock between operators in separate
Kubernetes clusters. Every site observes the shared Garage layout history, yet
two sites changed at the same instant could both pass the settled-history check
before either commits. An endpoint-derived alias can serialize objects handled
by one controller manager, but it is only a best-effort local identity and not
a cross-cluster lock. Permit exactly one topology-mutating GarageCluster/operator
at a time for the shared federated or external Garage layout. Wait until it has
finished and the shared layout has no `Draining` version before changing the
next physical site.

For a federated or externally managed layout, configure every process with
literal `replication.consistencyMode: consistent`, finish its managed workload
rollout, and then set this on the canonical layout owner at each site:

```yaml
spec:
  layoutManagement:
    autoApply: true
    drain:
      unverifiedPeersPolicy: AssumeConsistent
```

`AssumeConsistent` is an explicit maintenance assertion. Garage's Admin API
does not expose the running consistency mode of another control plane and the
operator has no distributed cross-cluster lock. It therefore also requires
the stricter terminal empty-queue proof. Serialize topology changes through
one site at a time.

`consistent` is required for the prepared removal transaction, not forever.
After the last topology change has settled everywhere, no storage drain or
rollout remains active, and normal writes may resume, a deployment may restore
`degraded` and the default peer policy `Block` in a later configuration-only
rollout. Never combine that rollback with membership removal.

### Image, config, and pod-template updates

Every GarageNode-owned StatefulSet and every node-local-pool workload uses
`OnDelete`; Kubernetes never rolls these identity-bearing pods independently.
The parent replaces at most one PVC, SMB, unified-gateway, or node-local-pool pod
across the entire `GarageCluster`, then waits for all of the following before
it touches another:

1. the replacement Pod is Ready;
2. the GarageNode controller has rediscovered the identity from that exact Pod
   UID;
3. the identity is connected and has a committed role;
4. every storage node and partition is healthy; and
5. layout history has no draining version.

Surge is intentionally unsupported because two pods must never mount the same
metadata volume and `node_key`. `StorageRolloutReady=False/RollingOut` reports
the current replacement; `NodeLocalPoolsReady` remains the membership/drain
condition for pools. A manual `kubectl delete pod` bypasses this rollout
sequencer; delete only one managed identity-bearing pod at a time.

Crash recovery retains the exact UIDs of old workload controllers whose late
Pods must remain excluded. This list is capped at 32 entries. Reaching the cap
fails closed before another replacement workload or config is created; it does
not discard an old UID to make room. There is no automatic override or generic
status-patch procedure: preserve the transaction and stop for
operator/developer-led inspection. Before any purpose-built repair can clear
the exclusion, it must
verify that every Pod owned by every recorded UID is absent and that no such Pod
can mount the actor's PVCs or HostPaths. Pool-name reuse or a same-name DaemonSet
is not that proof.

The cluster-level StatefulSet used by a gateway-only edge cluster has no
per-ordinal GarageNode handshake. It keeps Kubernetes' ordered, Ready-gated
`RollingUpdate`; it is not part of `StorageRolloutReady`.

If a still-declared pool temporarily matches zero Nodes, the operator retains
its old members; this makes a selector or label typo non-destructive. Remove
the pool entry from `spec.storage.nodeLocalPools` to explicitly drain that pool
to zero.

A Node cannot move directly from pool A to pool B. First remove it from every
pool and wait for:

1. its old GarageNode to disappear;
2. its private activation label to disappear; and
3. its old pool pod to terminate.

Then select it into pool B. Direct moves report
`NodeLocalPoolsReady=False`, reason `DirectNodeLocalPoolMoveBlocked`, before a second
pod can mount that Node. The private activation label is treated as pool
ownership even before the first pod or GarageNode exists, closing the
pre-membership scheduling race.

If a drain would leave fewer confirmed positive-capacity roles than
`replication.factor`, the operator reports `ReplicationUnsafe` and keeps the
pod and GarageNode finalizer. Add replacement capacity and wait for it to enter
the committed layout. Do not strip the GarageNode finalizer: that would stop
the pod without proving its role left Garage.

Do not edit labels whose keys begin with
`garage.rajsingh.info/gc-`; they are operator-owned drain state.

### Permanently lost Nodes

If a Kubernetes Node and its local disks are permanently gone, the live-source
drain proof is impossible. The operator retains the exact GarageNode and role;
it never converts an unreachable process into proof that its blocks survived.

Use this explicit recovery order:

1. Add replacement capacity and wait for it to be `Connected`, `InLayout`, and
   healthy. Record the lost GarageNode's exact 64-hex `status.nodeId`; do not
   delete its GarageNode, PVCs, retained ConfigMaps, or HostPath evidence.
2. Verify through Garage that the exact identity is down and the loss is
   permanent. Atomically add both annotations to that GarageNode so ordinary
   reconciliation cannot re-add or replace the role while recovery runs:

   ```bash
   kubectl annotate garagenode NODE -n garage \
     garage.rajsingh.info/drain=true \
     garage.rajsingh.info/acknowledge-lost-source=FULL_64_HEX_NODE_ID
   ```

   The operator verifies that the annotation matches the persisted identity
   and refuses to fence a process that Garage still reports up.
3. From one Garage Admin endpoint, use Garage's explicit dead-node workflow for
   that exact ID: stage `garage layout remove`, review `garage layout show`,
   apply it once, and wait for layout history to settle. Do not let another
   operator or administrator mutate the shared layout concurrently.
4. If the dead identity prevents the applied layout from leaving `Draining`,
   inspect health and layout history before using:


   ```bash
   kubectl annotate garagecluster garage \
     garage.rajsingh.info/skip-dead-nodes=true
   ```

   Add `garage.rajsingh.info/allow-missing-data=true` only when the old data is
   provably unrecoverable and the surviving replicas are sufficient. It can
   authorize data loss.
5. Wait for the exact GarageNode to report
   `DrainPrepared=True/PreparedForDeletion`. This destination-only proof checks
   clean `Blocks` repair/resync state and a terminal quiet window on every
   surviving destination; it cannot recover a block whose only copy was lost.
   Delete the GarageNode only after reviewing the parent `status.storageDrain`.

The same two annotations are the only escape when the lost identity was the
persisted actor in an interrupted `status.storageRollout`: ownership is first
transferred atomically from rollout to storage drain, then the workload is
fenced and the same dead-role workflow applies. Never remove the GarageNode
finalizer merely to make the Kubernetes object disappear.

An in-place metadata wipe or disk replacement is treated as the same lost-source
event. If a managed storage process reports a new Garage ID while its
GarageNode still owns an old positive-capacity ID, the operator retains the old
`status.nodeId`, leaves the replacement identity unassigned, and performs no
layout write. Apply the two annotations above using the old ID. The operator
first proves the replacement has no committed or staged role, then fences that
process before destination-only recovery. An already-assigned replacement
fails closed and requires an explicit dual-identity recovery plan. After the
old GarageNode is safely deleted, its desired pool or Manual manifest may
create a fresh object that enrolls the replacement identity normally.
Capacity-less gateway identity replacement remains automatic because neither
role stores blocks. The operator first persists the exact old identity on the
canonical layout owner, then stages one atomic Garage version that adds the new
capacity-less role and removes the old one. It keeps status on the old ID until
normal layout history settles, never invokes global `skip-dead-nodes`, and can
resume the same transaction after a controller restart.

## Host paths and identity

Garage stores its Ed25519 `node_key` in `metadata_dir`. A pod replacement on
the same Node and metadata HostPath therefore returns as the same Garage
identity. Wiping that path creates a new identity and makes the old one a
layout member that must be drained.

Cold recovery fails closed around that fact. Before restarting an already
committed pool member, the parent binds its activation to the Node's retained
identity record or to the one unambiguous positive-capacity layout role carrying
all of these operator tags: `cluster:<name>/<namespace>`, `tier:storage`,
`node-local-pool:<pool>`, and `kubernetes-node:<node>`. The GarageNode controller
then discovers the identity from that exact Pod's own Admin API and requires
the same tagged role in the current committed layout before it persists status
or writes layout state. A wiped or swapped metadata disk therefore reports an
identity mismatch instead of being enrolled as a second role.

Already-committed recovery members may start together. They are existing
layout roles needed to make a cold layout converge, not new topology; forcing
them through the ordinary one-at-a-time addition gate can deadlock on a peer
that the gate itself kept offline. Members with no identity proof remain under
the normal serialized/bootstrap rules.

A same-name recovery is recovery of the existing Garage store, not permission
to combine old pool metadata with a freshly bootstrapped store. Restore the
same RPC secret and every surviving metadata identity first, including Manual
PVC/SMB GarageNodes that still own committed roles. If an old identity is truly
gone, complete the documented lost-source role removal and destination repair
proof. Starting fresh Manual identities while retained pool disks still carry
an older layout can make that older layout authoritative and leave its missing
roles draining; the operator deliberately will not discard or rewrite that
history. To create an unrelated empty store, complete clean finalization and
use empty paths (or a different namespace/name) instead of force-reusing this
recovery boundary.

Do not copy one metadata directory or mount it on multiple selected Nodes.
When two GarageNodes report the same node ID, the operator reports
`IdentityCollision` and stops pool membership changes: they are one
authenticated Garage identity, not two replicas. Stop the duplicate process,
give that Node a unique metadata directory, and only then re-enroll it. This
recovery is deliberately manual because removing either duplicate's shared
layout role automatically would also remove it for the healthy process.

`hostPathType: Directory` is the production default. Directory existence alone
cannot prove that a disk is mounted: an empty mountpoint can remain on the Node
root filesystem. For every such metadata or data path, the workload also
mounts `<hostPath>/.garage-volume-id` as a read-only HostPath of type `File`.
If the disk is absent, that file is absent and kubelet refuses to start the
pod before Garage can write to the wrong filesystem. The operator never
creates or repairs the marker.

`DirectoryOrCreate` must be selected explicitly. It omits the marker contract
and is intended for tests or deliberately ephemeral provisioning; kubelet may
create a root-owned directory on the Node filesystem instead of failing on a
missing disk.

HostPaths must be absolute, normalized, non-root, and non-overlapping. The
metadata path is immutable for the pool; its `hostPathType` may be tightened
from `DirectoryOrCreate` to `Directory` after the directory exists. That change
is one-way: loosening a metadata or retained data path back to
`DirectoryOrCreate` is rejected so a missing disk cannot silently become an
empty directory. Paths must also be exclusive to one Garage workload across
every namespace and `GarageCluster` on the Kubernetes cluster. At admission and
reconcile time, the operator rejects overlap it can prove among desired pool
specs, retained or retiring pool DaemonSets, and still-live operator pool Pods.
It cannot discover paths mounted by Manual GarageNodes or unrelated workloads.
The operator never deletes HostPath data.

Anyone who can edit a pool can cause pods to mount Node filesystem paths.
Restrict GarageCluster write RBAC to trusted administrators and use admission
policy if paths must stay under an approved prefix.

## Multiple local disks

Use `dataPaths` instead of `data`:

```yaml
nodeLocalPools:
  - name: local-array
    capacity: 700Gi
    metadata:
      hostPath: /var/lib/garage/local-array/metadata
      hostPathType: Directory
    dataPaths:
      - path: /data/fast
        hostPath: /mnt/fast/garage
        hostPathType: Directory
        capacity: 500Gi
      - path: /data/archive
        hostPath: /mnt/archive/garage
        hostPathType: Directory
        capacity: 200Gi
    selector:
      matchLabels:
        storage.garage.example/pool: local-array
```

Every writable path needs a positive capacity. A read-only migration path
omits capacity and sets `readOnly: true`. It is still mounted read-write at the
Kubernetes layer so Garage can maintain its marker and move blocks.

Paths may be added and an old path may be retained as read-only for Garage's
staged migration flow, but this release never detaches an existing path in
place—even after it becomes read-only. Garage exposes no authoritative
cluster-wide proof that a particular directory is empty on every selected
Node. Admission and the runtime disk-layout record therefore reject all path
removal and remapping.

To replace or remove a disk mapping, remove the entire pool from `nodeLocalPools`,
wait until every GarageNode role, activation label, pod, DaemonSet, and retained
ConfigMap revision for that pool is gone, then recreate the pool with the new
layout. This uses the normal one-member-at-a-time cluster drain to prove blocks
on the retiring identities reached other storage processes. It requires enough
capacity outside the pool to satisfy replication. The operator never deletes
HostPath contents; verify and clean the retired disks yourself.

The controller also records the rolled-out metadata/data mapping, HostPath
types, and Garage read-only state on both the pool DaemonSet and every ConfigMap
revision, then verifies the DaemonSet record against the actual HostPath mounts
before every update. Each config body gets an immutable, hash-named ConfigMap,
so an old pod can never restart with new `garage.toml` paths against its old
mounts. Old revisions are removed only after Kubernetes has observed a fully
available DaemonSet rollout and no remaining pod references them. A retained
revision also keeps identity evidence if the DaemonSet is deleted out of band
while GarageNodes still drain. These are second, fail-closed guards when
admission is bypassed. They also prevent removing and immediately re-adding
the same pool name with different disks while the retired DaemonSet, any
ConfigMap revision, or any GarageNode role still exists.

## Per-node RPC endpoints

Garage authenticates an expected node ID, so one L4 Service cannot safely
load-balance RPC across pool pods.

Use `nodeLocalPools[].network.rpcPublicAddrTemplate` for a directly routed hostname
per Kubernetes Node, or use directly routed Pod IPs with
`spec.network.rpcPublicAddrSubnet`.
The resolved address is published as an operator-owned `rpc-address:` layout
tag for federation reconnect.

Federation imports are deliberately non-destructive. A remote Admin endpoint
reports the global Garage inventory, not a Kubernetes-site-scoped ownership
set, so omission or prolonged downtime is not proof that this operator may
remove a role. The GarageCluster/GarageNode finalizers at the source site own
retirement; `remoteClusters[].name` and `.zone` are discovery metadata and the
current API has no immutable source-site UID delegation contract.

External per-node Services can select the stable Pod label:

The `garage.rajsingh.info/node-local-pool` and
`garage.rajsingh.info/kubernetes-node` labels in this Service are
operator-managed outputs. They are provided for exact diagnostics and Service
selection, but must not be edited on the generated Pod. Likewise,
`garage.rajsingh.info/storage-group` is an operator-managed selector for the
default storage group, not a user-facing membership control.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: garage-worker-a-rpc
spec:
  publishNotReadyAddresses: true
  selector:
    app.kubernetes.io/instance: garage
    garage.rajsingh.info/node-local-pool: local-700
    garage.rajsingh.info/kubernetes-node: worker-a
  ports:
    - name: rpc
      port: 3901
      targetPort: rpc
  type: LoadBalancer
```

For Node names longer than 63 characters, read the actual label from the Pod;
the full name remains in its annotation:

```bash
kubectl get pods -l garage.rajsingh.info/node-local-pool=local-700 \
  -L garage.rajsingh.info/kubernetes-node
```

`spec.publicEndpoint` remains valid in a mixed cluster, but its Service is
scoped to `garage.rajsingh.info/storage-group=default`; it cannot provide an
identity-specific route for node-local-pool pods. Give each node-local-pool
identity a direct address or exact-node Service.

The current federation API requires one static `spec.zone` when node-local
pools and `remoteClusters` are combined; it cannot address multiple
node-derived source-site zones. Outside that combination, `zoneFrom` remains
independent from the node-local pool name and may derive multiple actual
failure domains within one workload-owning cluster.

## Upgrading development snapshots of this feature

Node-local pools are new in v0.7.0; released v0.6.29 and the
upstream base do not contain a pool API. Ordinary v1beta1/v1beta2 clusters need
no compatibility migration.

Pre-release builds of PR #297 used prototype names such as
`spec.storage.workload: DaemonSet`, `spec.storage.pools`,
`spec.storage.nodePools`, `backing: StoragePool`, `backing: NodePool`,
`poolName`, `nodePoolName`, and their storage-pool/node-pool labels and
conversion annotations. Those names were never released and
have no live alias. Before installing the final CRD/operator, stop the prototype
operator and every affected identity-bearing workload, verify no old and new
pod can mount the same metadata path, update the parent manifests to
`nodeLocalPools`,
and recreate or explicitly migrate the prototype-generated children while all
affected workloads remain stopped. The safest option for a disposable
development cluster is to recreate it. Never rely on CRD pruning to perform
this storage migration.

## Migrating existing LocalPath GarageNodes

Existing LocalPath PVCs are not automatically adoptable. Their provisioner
paths are PVC-specific, and their metadata contains a live `node_key` that
must never be mounted by the old StatefulSet and new DaemonSet together.

The preferred online migration uses new identities:

1. leave SMB and exceptional nodes unchanged;
2. provision empty standard HostPaths;
3. add the pool alongside the existing LocalPath GarageNodes;
4. wait for `NodeLocalPoolsReady=True`, `StorageRolloutReady=True`, healthy layout,
   and completed resync;
5. for one old LocalPath GarageNode, set
   `garage.rajsingh.info/drain=true`, wait for `DrainPrepared` reason
   `PreparedForDeletion`, then remove/delete that exact object and wait for its
   finalizer and Pod; repeat only after the preceding deletion finishes;
6. remove retained PVCs only after the corresponding role has drained and the
   old Pod is gone;
7. switch per-node RPC Services from StatefulSet pod-name selectors to the
   stable pool labels.

This requires temporary disk capacity.

An identity-preserving cutover can reuse a LocalPath PV's exact directories,
but it is an offline, one-node-at-a-time handoff and is not automated:

1. record the GarageNode's node ID, its metadata/data PVCs, and each bound
   PV's `.spec.local.path`;
2. set the parent GarageCluster's
   `spec.storage.pvcRetentionPolicy.whenDeleted: Retain` (this policy applies to
   its GarageNode-owned StatefulSets), annotate the exact GarageNode with
   `garage.rajsingh.info/drain=true`, and wait
   until its `DrainPrepared` condition has reason `PreparedForDeletion` as shown
   in [Prepared deletion](#prepared-deletion); do not remove it from GitOps or
   issue DELETE before that proof;
3. remove only that prepared GarageNode from GitOps (or delete it directly),
   then wait for its finalizer, StatefulSet, and Pod to disappear;
4. keep the retained PVCs and PVs: deleting a dynamically provisioned LocalPath
   volume may delete the directory that the new HostPath workload will use; if
   those objects must ever be deleted, first change the PV's
   `persistentVolumeReclaimPolicy` to `Retain`;
5. after the retained filesystems are mounted, create `.garage-volume-id` in
   each exact old metadata/data PV path, then add one pool selected only by
   that Kubernetes Node with `hostPathType: Directory`;
6. change that node's RPC Service to the stable pool/node selectors, then
   verify the node-local-pool-backed GarageNode reports the recorded node ID,
   `Connected=True`, `InLayout=True`, `NodeLocalPoolsReady=True`, and
   `StorageRolloutReady=True`;
7. repeat for the next node only after Garage reports no `Draining` layout
   version.

Because LocalPath directories differ per PVC, existing nodes normally require
one pool entry per Kubernetes Node. A later fresh deployment can use one
multi-node-local pool only after every selected Node has the same directory layout.
Never put the exact-path pool in the same GitOps step that removes the old
GarageNode: the old pod must be observably gone before the activation label is
allowed to schedule the new process.

Do not create a second `GarageCluster` merely to separate local and SMB
storage. That creates another store/federation member instead of another
storage backing inside the same site lifecycle. The members in that lifecycle
may share a static zone or derive multiple actual failure-domain zones.

## Rollback and removal

Removing a pool drains one role at a time, deletes its DaemonSet and ConfigMap
revisions, and retains every HostPath directory.

Before deleting old nodes during migration, rollback by removing the new pool.
After old nodes have been removed, restore their retained PVC-backed
GarageNodes and wait for them to join before removing the pool.

Wait until the old GarageNodes, DaemonSet, ConfigMap revisions, and activation
labels are gone before recreating a removed pool. Re-adding the same pool name
with the same metadata HostPath then reuses its on-disk identities, but
successful prior removal means those identities must be assigned to the layout
again. A new metadata path creates new identities.

Never run a restored StatefulSet and a pool pod against the same metadata
directory.

### Prepared deletion

Positive-capacity deletion is a two-phase operation. Setting the drain
annotation asks the controller to remove the exact role while the source pod
is still live, launch a Garage `Blocks` repair on the removed source and every
current positive-capacity destination, and wait for exact repair/resync
workers, queues, errors, layout history, and a quiet window. Only the terminal
proof authorizes Kubernetes DELETE.

Selector-driven node-local-pool removal and Auto-mode scale-down perform the prepare
step automatically. For a directly managed storage GarageNode, use:

```bash
kubectl annotate garagenode NODE -n garage \
  garage.rajsingh.info/drain=true

kubectl wait garagenode/NODE -n garage \
  --for=jsonpath='{.status.conditions[?(@.type=="DrainPrepared")].reason}'=PreparedForDeletion \
  --timeout=45m

kubectl delete garagenode NODE -n garage
```

The validating webhook rejects an unprepared storage-node DELETE. Removing the
annotation before DELETE is a safe cancellation only while no drain transaction
is active; after Garage commits the role removal, keep the source running until
the proof completes.

Delete an individual GarageNode with Kubernetes' default/background
propagation. Direct `--cascade=foreground` is rejected because dependent
workloads could disappear before the finalizer proves the handoff. Parent
GarageCluster deletion is different: after a terminal Drain proof, or during
explicit whole-store Destroy, the parent finalizer owns a foreground cascade of
its children.

Whole-site retirement uses the same prepare boundary. It is supported only
for a federated storage site with an explicit `deletionPolicy: Drain`, declared
`remoteClusters`, literal consistent mode, and the explicit unverified-peer
assertion:

```yaml
spec:
  deletionPolicy: Drain
  replication:
    factor: 3
    consistencyMode: consistent
  layoutManagement:
    autoApply: true
    drain:
      unverifiedPeersPolicy: AssumeConsistent
```

```bash
kubectl annotate garagecluster SITE -n garage \
  garage.rajsingh.info/drain=true

kubectl wait garagecluster/SITE -n garage \
  --for=jsonpath='{.status.conditions[?(@.type=="StorageDrainReady")].reason}'=Completed \
  --timeout=45m

# Review status.storageDrain.actor, roleRemovalNodeIds,
# removedStorageNodeIds, verificationNodeIds, and completedAt first.
kubectl delete garagecluster SITE -n garage
```

Do not annotate every federated site concurrently. `Destroy` remains the
whole-store teardown policy and deliberately does not claim a data-preserving
layout drain.

`spec.deletionPolicy: Destroy` is the default for whole-store teardown. It
deliberately skips Garage's impossible empty-storage-layout transition, removes
the Kubernetes workloads, activation labels, and Node identity records, and
leaves HostPath contents.

Use the prepared `spec.deletionPolicy: Drain` workflow above to retire one site
from a surviving federated Garage cluster. Drain requires a readable Admin API
token, removes only exact GarageNode IDs or roles carrying this Kubernetes
object's `cluster-uid`, and keeps every storage workload online until the full
source/destination proof completes.

Force-deleting the cluster/finalizer can leave activation labels and retained-
disk identity annotations behind. Activation keys include the deleted cluster
UID, so a same-named replacement cannot reuse them. The identity annotations
are intentionally stable and let that replacement recover the same HostPaths
only as their previous Garage IDs. After verifying no old pool workload
remains, remove orphan activation labels manually. Remove an identity annotation
only when you are deliberately abandoning or wiping that exact disk and have
completed the corresponding Garage lost-source/role recovery.

## Current limitations

- Cluster-scoped operator installation is mandatory.
- Across every `nodeLocalPools` entry in one `GarageCluster`, selectors may
  choose at most 255 Kubernetes Nodes. Garage itself has a hard limit of 256
  positive-capacity roles across node-local, default PVC, Manual/SMB, external,
  and federated members. At 255 live roles, a new node-local identity is
  eligible only when this Kubernetes control plane proves a retiring generated
  member. This check does not reserve role 256 against an independently
  operated federated site; another writer may consume it and make the
  node-local assignment wait for a committed removal. Existing 256-role layouts
  remain readable and drainable, but must drain before adding. Staged additions
  consume headroom; a staged removal does not restore it until committed.
  Federated topology mutations must be externally serialized.
- Node-local lifecycle, storage rollout/drain, and repeated-member health
  condition messages are capped at 4096 bytes; inventory summaries contain a
  count plus at most five sorted examples. Use label-addressable generated `GarageNode`
  resources for complete per-member detail. Informational parent layout history
  is capped at 64 entries; safety decisions use Garage's complete live history.
  The release-envelope test projects 256 role entries, eight exact resync-worker
  counters per role, 64 layout-history entries, 32 legacy top-error details, 256
  entries in other role-derived diagnostic lists, and all 26 currently declared
  GarageCluster conditions at maximum message size. Its drain transaction is
  365085 bytes (about 357 KiB), below a 512 KiB feature budget; the coexisting
  `GarageCluster.status` is 966767 bytes (about 944 KiB), below a 1 MiB status
  budget and leaving at least 512 KiB of a
  1.5 MiB object envelope for spec and metadata. This is a conservative release
  projection, not a mathematical bound on arbitrary legacy status writers and
  not a reason to increase API limits. The v1beta1 conversion transport separately
  accounts for every existing annotation plus pool/gateway payload and rejects
  a projection above Kubernetes' 256 KiB annotation limit (the exact limit is
  accepted; one byte more is rejected).
- Rollout recovery retains at most 32 old workload-controller UIDs. The next
  exclusion fails closed before creating/adopting another controller; see the
  operator/developer-led recovery requirements under image/config updates
  above.
- Capacity is uniform within one pool; make another disjoint pool or retain a
  Manual GarageNode for different capacity.
- Replication-factor migration is blocked while pools exist.
- The storage PDB protects voluntary evictions. Parent-controlled `OnDelete`
  rollout serializes operator-driven image/config/template changes across PVC,
  SMB, unified gateway, and node-local-pool GarageNodes, but administrators can
  still bypass it by deleting several pods directly.
- The operator blocks HostPath parent/child overlaps it can prove among managed
  nodeLocalPools: desired pool specs, retained/retiring pool DaemonSets, and still-live
  operator pool Pods across GarageClusters and namespaces. It cannot discover
  HostPaths mounted by Manual GarageNodes or unrelated workloads; keeping those
  paths disjoint remains an administrator responsibility.
- HostPath provisioning, permissions, disk health, backup, and final cleanup
  remain administrator responsibilities.
