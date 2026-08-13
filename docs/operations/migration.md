# Migration details

Use this page for migrations where preserving the exact Garage identity or
credential value matters. The short [upgrade guide](upgrades.md) covers the
normal chart and image sequence; this page covers storage topology, reserved
environment variables, and the v1beta1/v1beta2 workload shapes.

## Before changing a live installation

Back up the custom resources, record each live Garage node ID, and confirm the
current metadata and data claims. Keep the old image and rendered configuration
available until the new Pods report the same identities and the layout history
is settled.

```bash
kubectl get garagecluster,garagenode,garagebucket,garagekey -A -o yaml \
  > garage-operator-backup.yaml
kubectl get pvc -A -l app.kubernetes.io/managed-by=garage-operator
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.nodes}{"\n"}{.status.layoutHistory}{"\n"}'
```

Do not combine a chart upgrade, Garage image change, PVC topology change,
replica change, and replication-factor migration in one unreviewed update.

## v1beta1 to v1beta2

Existing `GarageCluster` v1beta1 objects remain served through the conversion
webhook. New manifests should use the tier-based v1beta2 shape:

```yaml
# legacy v1beta1
spec:
  replicas: 3
  gateway: false
---
# v1beta2 storage-only equivalent
spec:
  storage:
    replicas: 3
```

For a unified site, add both `storage` and `gateway` in v1beta2. A v1beta2
object containing both tiers has no faithful v1beta1 representation: a
v1beta1 read exposes the storage view and preserves the gateway data in a
conversion payload. A v1beta1 client cannot edit that hidden gateway tier.
Node-local pools, management handles, and other v1beta2-only fields likewise
require v1beta2 clients.

Install cert-manager and keep conversion webhooks enabled while both versions
are served. Do not disable webhooks during this migration.

## Storage topology migration

The post-#190 workload shape is one single-replica StatefulSet per generated
`GarageNode` for Auto storage and unified Auto gateways. Older releases may
have used a cluster-level storage StatefulSet. The operator migrates ownership
only when the exact old Pod, StatefulSet, PVC, and Garage node identity can be
proved; it does not infer identity from a name or ordinal.

For PVC-backed storage:

- metadata contains `node_key` and the metadata database;
- data contains object blocks;
- `Retain` claims may be reused only with the operator's exact ownership and
  UID handoff;
- `selector`, StorageClass, access modes, mount paths, and single-versus-
  multi-path topology are not live edits;
- size growth on the same volume is the supported in-place volume change.

If a topology change is required, scale the affected group to zero, wait for
the exact role and workload evidence to settle, update the template, then
scale up separately. Existing retained claims keep their old selector and
class. A new selector applies only to a newly created claim.

Existing LocalPath PVC nodes are not automatically adoptable as
`storage.nodeLocalPools` members. A node-local pool has its own HostPath
identity contract and marker files; follow the [node-local pool migration
section](../node-local-pools.md#migrating-existing-localpath-garagenodes).

### Observe or retry the legacy StatefulSet migration

The migration has one status condition, `LegacySTSMigrated`; it does not use a
`status.migration` object. Query the condition directly:

```bash
kubectl get garagecluster garage -n storage -o jsonpath='{range .status.conditions[?(@.type=="LegacySTSMigrated")]}{.type}={.status} ({.reason}): {.message}{"\n"}{end}'
```

The normal terminal state is `status=True, reason=Completed`. This also means
that no legacy StatefulSet was present. During a migration the condition is
`status=False, reason=InProgress`; a blocked migration is
`status=False, reason=Failed`, with the remediation in its message. For
example, a legacy StatefulSet with `replicas=0` and leftover metadata or data
PVCs must be scaled back up before its claims can be adopted.

After correcting a failure, re-drive the operation with the one-shot
annotation:

```bash
kubectl annotate garagecluster garage -n storage \
  garage.rajsingh.info/retry-migration=true --overwrite
```

The operator removes the annotation and clears `LegacySTSMigrated` before
re-running the migration. Inspect the condition and Events afterward; no
manual status patch is required.

## Reserved Garage environment variables

The operator reserves these names because they can change mesh identity,
credential provenance, or the rendered configuration without being visible in
the typed API:

```text
GARAGE_CONFIG_FILE
GARAGE_RPC_SECRET
GARAGE_RPC_SECRET_FILE
GARAGE_ADMIN_TOKEN
GARAGE_ADMIN_TOKEN_FILE
GARAGE_METRICS_TOKEN
GARAGE_METRICS_TOKEN_FILE
```

New or changed overrides are rejected. A released object with an existing
override is handled in a staged, fail-closed migration.

### RPC secret override

1. Keep the existing `GARAGE_RPC_SECRET` entry unchanged.
2. Create a Secret containing the exact same 64-hex value and set
   `spec.network.rpcSecretRef` to it.
3. Add `garage.rajsingh.info/migrate-legacy-rpc-secret=true`.
4. Wait for the status message proving the exact active Pods, typed Secret,
   and managed snapshot agree.
5. Remove the old RPC environment entry, leaving the migration annotation until
   the operator consumes it.

The operator never overwrites a mismatched Secret and never treats the
annotation itself as proof that two values are equal.

### Config-file and credential overrides

Compare the effective old TOML with the operator-rendered configuration before
removing `GARAGE_CONFIG_FILE`. Then set
`garage.rajsingh.info/acknowledge-legacy-config-migration=true` while the exact
old Pods are still present. This annotation is an operator attestation; it
cannot authorize an RPC credential rotation or a file-based Admin/metrics
credential replacement.

Broad `envFrom` sources, `GARAGE_RPC_SECRET_FILE`, Admin/metrics credential
overrides, and other released reserved values do not have an automatically
provable startup value. Convert them to typed Secret references before the
rollout, or freeze the workload and perform an explicit manual migration.

## Gateway migrations

Unified gateways are capacity-less Garage roles with a metadata PVC by default.
Edge gateways use one cluster-level StatefulSet because the remote storage
cluster owns their layout roles. Edge metadata claims retain the historical
`Delete`/`Delete` behavior unless `spec.gateway.pvcRetentionPolicy` is set;
unified Auto gateway claims default to `Retain`/`Retain`.

To change an edge metadata volume source or claim template:

1. set `spec.gateway.replicas: 0`;
2. wait for the old Pods, claims, and capacity-less roles to retire;
3. change the metadata configuration;
4. scale up and verify `GatewayConnected` and `GatewayLayoutDegraded`.

An edge StatefulSet cannot safely apply a live claim-template edit. A gateway
metadata deletion creates a new Garage identity even though the Kubernetes
name is unchanged.

For federated gateway tiers, each identity needs a routable address. A shared
hostname behind an L4 balancer can only safely represent one identity. Use
per-ordinal gateway addresses and configure
`remoteClusters[].connection.gatewayRpcEndpointTemplate` on consuming sites.

## Older two-resource gateway deployments

If an older installation used a storage `GarageCluster` plus a separate edge
gateway `GarageCluster`, do not create a unified gateway tier beside the old
edge owner. The two owners have different Kubernetes UIDs and potentially
different Garage node IDs.

Retire the old edge identities first through its prepared drain/finalizer path,
wait until the old capacity-less roles are absent from the live layout, then
delete the old edge resource. Only after that should the unified gateway tier
be created. Back up both resources and record the old gateway IDs before
starting.

## Static and dynamic Admin credentials

`GarageAdminToken` creates static bootstrap material in a Secret; it is not a
revocable Garage token row. The operator also creates short-lived internal
dynamic credentials for operations that need replicated Admin-table access.
During federated or edge deletion, normal teardown must revoke those rows from
a surviving Admin endpoint. If that endpoint is unavailable, set
`garage.rajsingh.info/force-delete-unrevoked-operator-tokens=true` only after
accepting that copied bearer material may remain valid in the surviving Garage
cluster. The annotation deletes only local one-time Secrets and allows the
teardown to continue; it does not prove remote revocation.

## Rollback boundary

Rolling back the operator chart is possible only when the CRD, conversion, and
controller contracts are compatible with the stored objects. Restoring an
older image does not roll back an applied Garage layout, a completed identity
drain, a factor migration, or data written by a newer Garage version. For a
workload-only handoff failure, use a new
`garage.rajsingh.info/recover-storage-rollout` nonce after correcting the
referenced workload issue; never delete the identity PVC to unblock a rollout.
