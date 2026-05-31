# Gateway Path Unification + Fault-Tolerant Layout Management

**Status:** validated against upstream Garage v2.3.0 (`git describe` =
`v2.3.0-52-g2bde733e`; none of the 52 post-tag commits touch the load-bearing
layout/peering paths). Date: 2026-05-31.

This design is the output of an adversarial validation pass over every
upstream-grounded assumption. The validation **materially changed** several
motivations and corrected two latent bugs in the existing operator. Citations
below are to `../garage` source unless noted.

## Implementation status (this PR)

**Shipped + tested (unit/envtest + e2e + lint green):**

1. **Layout-apply correctness** — `Client.ApplyStagedLayoutChanges` replaces the
   broken `IsConflict`-based retry at all 8 apply sites (apply rejection is HTTP
   500, not 409). Re-reads version, skips no-op applies, resolves the
   concurrent-writer race.
2. **Per-node gateway unification for unified clusters (#209)** — gateway tier in
   a unified `storage + gateway` CR now runs as per-node `GarageNode`s
   (`gateway: true`, `capacity: nil` role, metadata PVC, EmptyDir data). Includes
   the v0.5.3-safe per-node gateway config (no storage `rpc_public_addr`
   inheritance) and tombstone cleanup that won't fight the per-node controller.
3. **Cluster-health surface** — `QuorumAtRisk`, `RemoteClustersHealthy`,
   `FederationConfigured` conditions + `status.layoutDiagnosis` printcolumn +
   federation `rpc_public_addr` webhook warning.

**Coordinated factor migration (#208)** — shipped in a **follow-up PR** (its own
focused change with dedicated e2e), implementing the validated safe sequence in
§4: the `purge-cluster-layout` annotation drives a resumable state machine
(Validating→ScalingDown→Purging→Verifying→RebuildingLayout→Converging) that
suspends the per-node controllers, scales all storage STSes to zero, deletes the
on-disk `cluster_layout` via a marker-guarded init container, restarts
simultaneously at the new factor, and rebuilds the entire layout. Federation is
refused; abort + stuck-timeout guards prevent hangs. Edge gateways unaffected.

**Scoped out (validation-driven):**

- **Edge gateways stay on the cluster-level StatefulSet path.** Their layout
  lives on a *remote* storage cluster; the existing gateway-connection path
  already assigns their `capacity: nil` role correctly (only unified clusters
  were broken). Migrating them to per-node would add a dual-admin-client code
  path in the node controller with no functional gain. The principled boundary:
  *within one GarageCluster CR every tier is per-pod; cross-cluster edge gateways
  keep the cluster-level connection logic.*

---

## 1. Problem statement

The operator treats its two tiers asymmetrically:

```
Storage tier (Auto):  spec.storage → N × GarageNode → N × 1-replica STS → per-node controller owns layout
Gateway tier (Auto):  spec.gateway → 1 × N-replica STS (cluster-owned)  → NO per-node controller; cluster code owns layout
```

That asymmetry is the root of three classes of problem:

1. **Gateway layout assignment is missing in unified clusters (#209).** In a
   unified `storage + gateway` Auto cluster, no code path ever assigns the
   gateway pods a layout role. `bootstrapCluster` short-circuits for
   storage-tier clusters (`garagecluster_controller.go:3286`) and
   `reconcileGatewayConnection` only runs when `connectTo != nil`
   (`:3474`). Gateways come up roleless.

   **Validation correction (A5/H1):** a roleless gateway does **not**
   deterministically 403. `verify_v4` does `key_table.get_local()` then an eager
   `Option::or(quorum get())` (`src/api/common/signature/payload.rs:423-428`);
   the quorum fallback succeeds in a healthy cluster. The roleless failure mode
   is a per-request synchronous quorum RPC and a **5xx (not 403)** when the
   layout is `LayoutNotReady`/storage quorum is unreachable. Assigning a
   `capacity:None` role makes `key_table` full-replicated locally so `get_local`
   hits — a **resilience + latency** win (decouples gateway auth from storage
   availability), and it keeps ephemeral gateway node IDs **out of partition
   assignment/quorum math** (`src/rpc/layout/version.rs:215-227`), which is the
   real correctness reason. We frame the feature accordingly — not as "fixes a
   403."

2. **Layout staging/apply concurrency is subtly wrong (NEW — G1/G2).** Each
   per-node controller independently stages and applies its own role. Staging is
   merge-safe — `staging.roles` is an `LwwMap<Uuid, NodeRoleV>` merged against
   live state every call (`src/api/admin/layout.rs:181-214`), so concurrent
   stagers converge. **But apply is not:** `ApplyClusterLayout`'s
   version-rejection is a generic `Error::Message("Invalid new layout version")`,
   **not HTTP 409** (`src/rpc/layout/history.rs:273-276`), so the operator's
   `garage.IsConflict()` misses it; and apply **always** bumps the version with
   no no-op short-circuit (`src/rpc/layout/version.rs:290-303`). This affects the
   **existing storage path** too.

3. **No operator-supported recovery when a zone dies permanently (#208).** The
   only way to change `replication_factor` is to delete the on-disk
   `cluster_layout` and restart all nodes simultaneously — there is no admin-API
   path (`src/rpc/layout/manager.rs:44-65`).

   **Validation correction (F2/F3):** factor reduction fixes **sharded-data**
   write quorum only; it does **not** lower the FullReplication admin-table
   threshold (`floor(N/2)+1` of all roled nodes — `src/table/replication/fullcopy.rs:64-89`).
   `degraded` mode does **not** unblock stuck metadata writes (it lowers READ
   quorum only; `src/rpc/replication_mode.rs:41-55`). **Stale gateway entries
   inflate N in `consistent` mode** (`src/rpc/layout/helper.rs:63-73`), so
   tombstone cleanup is itself load-bearing for admin-write availability.

---

## 2. Architecture: unify both tiers under per-pod `GarageNode`

`GarageNode.Spec.Gateway: bool` already exists (`api/v1beta1/garagenode_types.go:197`)
and the per-node controller already assigns `capacity:None` for it. The change is
to make the **gateway tier in Auto mode** generate per-pod GarageNodes exactly as
the storage tier does:

```
Both tiers (Auto):  spec.storage → N × GarageNode(gateway:false) → N × 1-replica STS
                    spec.gateway → N × GarageNode(gateway:true)  → N × 1-replica STS
                    per-node controller owns each node's layout role
```

### 2.1 New cluster-controller functions (mirror the storage tier)

- `reconcileAutoModeGatewayNodes` — sibling of `reconcileAutoModeStorageNodes`
  (`garagecluster_automode.go:127`). Generates `<cluster>-gateway-<ord>`
  GarageNodes with `Gateway: true`, `Storage.Metadata` = gateway metadata PVC
  (1Gi default, EmptyDir data), `Network.RPCPublicAddr` from
  `spec.gateway.rpcPublicAddr`, controllerRef to the cluster, labels
  `{labelCluster, labelTier=gateway, labelAppManagedBy=operator}`. Identical
  drift detection / scale-down / eject semantics.
- `migrateLegacyGatewaySTSIfNeeded` — sibling of `migrateLegacyStorageSTSIfNeeded`
  (`garagecluster_automode.go:630`). Detects the legacy `<cluster>-gateway` STS,
  adopts each `metadata-<cluster>-gateway-<ord>` PVC via `existingClaim`
  (identity preserved via `node_key`), orphan-deletes the legacy STS, deletes
  legacy pods so RWO PVCs release. **Strict pre-migration safety:** refuse unless
  all gateway pods are Ready + `IsUp` (so PVC→node-id mapping is unambiguous);
  refuse `replicas=0` with leftover PVCs (mirrors the storage `#205-#207` guard).
  Status on a new `gatewayMigration` field + `LegacyGatewaySTSMigrated` condition.
- `deleteAutoModeGatewayNodes` / `ejectAutoModeGatewayNodes` — tier-removal and
  Auto→Manual eject for gateways.

### 2.2 Per-node controller adaptations (`garagenode_controller.go`)

- **Pod template source:** branch on `node.Spec.Gateway` to pull
  `cluster.Spec.Gateway.PodTemplate` (and set `IsGateway: true` in
  `PodSpecConfig` — gives the gateway readiness probe + init-marker container).
- **Volumes:** gateway → metadata PVC + EmptyDir data (no data PVC); storage →
  unchanged. Webhook already forbids `data`/`dataPaths` on gateway nodes.
- **Admin-client routing:** extract a `layoutClientForNode(cluster, node)` helper
  (generalizing today's `gatewayLayoutClient`, `garagecluster_gateway.go:500`):
  edge-gateway GarageNode (`node.Spec.Gateway && cluster.Spec.ConnectTo != nil`)
  → remote storage admin (clusterRef or adminApiEndpoint); everything else →
  local cluster admin. The per-node controller already captures
  `status.clusterAdminEndpoint`/`clusterAdminTokenSecretRef` for the delete-time
  orphan finalize (`garagenode_types.go:444-458`) — that path already supports
  edge gateways.
- **Edge-gateway self-introduction:** after assigning its own `capacity:None`
  role, an edge-gateway GarageNode also calls `ConnectNode(myID, myPublicAddr)`
  on the remote storage admin (replacing `connectGatewayToExternalCluster`'s
  reverse-direction inference). The address comes declaratively from the node's
  own `spec.network.rpcPublicAddr`/`publicEndpoint`, not from heuristic
  pod-IP-vs-LB inference.

### 2.3 Correct layout staging/apply (NEW — fixes storage too)

Add one shared helper used by **both** storage and gateway per-node reconciles:

```go
// stageAndApplyRole stages this node's desired role and applies it, tolerating
// the concurrent-writer race correctly.
func stageAndApplyRole(ctx, client, change NodeRoleChange) error {
    layout := client.GetClusterLayout(ctx)
    if roleMatches(layout, change) { return nil }          // idempotent: no churn
    client.UpdateClusterLayout(ctx, []NodeRoleChange{change})
    layout = client.GetClusterLayout(ctx)                   // re-read after staging
    if err := client.ApplyClusterLayout(ctx, layout.Version+1); err != nil {
        // Apply rejection is NOT 409 — re-read and decide.
        fresh := client.GetClusterLayout(ctx)
        if roleMatches(fresh, change) { return nil }        // someone else applied ours
        return err                                          // requeue; retry current+1 next pass
    }
    return nil
}
```

Rules enforced (validated against `doc/book/operations/layout.md:66-91`):
- Gate apply on staged changes being non-empty (no unconditional version bump).
- Detect apply failure by **re-reading version**, never by `IsConflict()`.
- Funnel a node's stage+apply through a single admin client (the node's
  `layoutClientForNode`).

This is the minimal-correct fix that keeps the per-pod ownership model intact.
A future optimization (single cluster-scoped batched writer) is noted but **out
of scope** to avoid a risky refactor of the working storage path.

### 2.4 Code deleted (de-bloat)

- `reconcileGatewayStatefulSet` (`garagecluster_gateway.go:63-187`) — replaced by per-pod STSes.
- `reconcileGatewayTombstones` (`:390-494`) — per-node finalizer removes the layout role on delete.
- `gatewayLayoutClient` (`:500-524`) — folded into `layoutClientForNode`.
- `bootstrapCluster`'s gateway layout-assignment branch (`garagecluster_controller.go:3290-3352`).
- `deriveGatewayExternalAddrForNode` + reverse-direction inference in
  `connectGatewayToExternalCluster` (`:3736-3934`) — gateways declare their own address.
- The `<cluster>-gateway-config` ConfigMap split — per-node ConfigMaps via the
  existing `nodeHasConfigOverrides` path cover gateway `rpc_public_addr`.

### 2.5 LayoutPolicy — one knob gates both tiers

`spec.layoutPolicy` (Auto default / Manual) gates **both** tiers. Auto→Manual
ejects both atomically (drops controllerRefs, strips managed-by). Manual→Auto
stays webhook-rejected. Per-tier policy is deferred (YAGNI).

### 2.6 Migration cleanup (atomic, part of `migrateLegacyGatewaySTSIfNeeded`)

- Sweep the legacy `<cluster>-gateway-config` ConfigMap once all gateway nodes
  have per-node ConfigMaps.
- Repoint the `<cluster>-gateway` API Service selector to
  `{labelCluster, labelTier=gateway}` so it picks up old + new pods during the
  transition window.
- Recreate the gateway PDB against the new label selector.

---

## 3. Cluster-health surface (accurate, validated)

New `GarageClusterStatus.conditions` + fields, with **validated** semantics:

| Condition | Meaning | Validated basis |
|---|---|---|
| `LayoutConverged` | `False/ZoneUnreachable` when a remote cluster `lastSeen` exceeds a threshold; `False/FactorMismatch` when config factor ≠ live layout factor; else `True/Stable`. Message names the remediation. | `manager.rs:44-65` |
| `QuorumAtRisk` | `True` when **reachable roled-node count < floor(N/2)+1** (the actual admin-table write-availability lever). Surfaces `roledNodes`, `reachableNodes`, `writeQuorum`. | `fullcopy.rs:64-89`, `rpc_helper.rs:734-745` |
| `RemoteClustersHealthy` | aggregate of `status.remoteClusters[].lastSeen` ages (Degraded 5m–1h, False >1h). | operator-side |
| `PeerUnreachable` | `True` when any node reports a peer `is_up:false` for a sustained duration. **The admin API exposes only `is_up` + `lastSeenSecsAgo`, not Garage's internal `Abandoned` state** — detection is duration-based, not state-based. | `client.go` NodeInfo; validation D6 |
| `FederationConfigured` | `False/MissingRPCPublicAddr` when `spec.remoteClusters` set but no `network.rpcPublicAddr`/`publicEndpoint` (HelloMessage reachability, `netapp.rs:499-510`). | D5 |

New `status.layoutDiagnosis` string = one-line human summary from the
highest-severity condition. New printcolumns: `LAYOUT`, `QUORUM`, `DIAGNOSIS`.

`spec.recovery.autoRestartOnUnreachablePeer` (default **false**) + a 3-restarts/1h
circuit breaker. Lower urgency than originally thought — v2.3.0 reconnect is
bounded (~50s/peer/cycle) and `known_addrs` is self-limiting
([[garage-v2-3-0-peering-layout-corrections]]) — but the edge-gateway
single-link case (Garage marks a peer `Abandoned` after ~5.5h and never retries)
still needs the operator's periodic `ConnectClusterNodes` nudge as the sole
recovery path, which `reconcileGatewayConnection`'s drift check already provides.

---

## 4. Coordinated factor migration (#208) — validated safe sequence

Gated behind an explicit one-shot annotation (parallel to `purge-blocks`):

```yaml
metadata:
  annotations:
    garage.rajsingh.info/purge-cluster-layout: "factor=2"   # or "factor=2,force"
spec:
  replication: { factor: 2 }                                # must match the annotation
```

**Validated requirements (cluster C, H3):**
- Deleting on-disk `cluster_layout` is **unavoidable** (factor is absent from the
  admin API and staging; copied forward by `calculate_next_version`).
- **Simultaneous restart is mandatory.** Two hazards: a node hearing a peer with
  a strictly higher factor `std::process::exit(1)` (asymmetric — only the
  lower-factor node dies, so a factor **increase** is the dangerous direction,
  `system.rs:601-608`); and gossip-back re-adoption of the old layout from a
  surviving peer (`history.rs:232-238`).
- Purging `cluster_layout` **wipes ALL roles** → the operator must **rebuild the
  entire layout** (every storage capacity + every gateway `capacity:None`) after
  restart, funneled through one pod, validating `nongateway_nodes() ≥ new factor`
  (`version.rs:328-335`).

State machine on `status.lastOperation` (phases): `Validating → Suspending →
ScalingToZero → Purging → ScalingUp → Verifying → RebuildingLayout → Converging →
Done|Failed`. Idempotent/resumable via the phase field + an init-container marker
file (`/data/metadata/.purged-<uuid>`) so the post-purge rolling restart doesn't
re-nuke a freshly rebuilt layout.

- **Validating:** refuse if `spec.remoteClusters` non-empty (federation
  coordinator is a separate design); refuse if `nongateway storage nodes <
  newFactor` (would be unappliable); refuse `dangerous` consistency without
  `,force`; require all storage nodes currently reachable.
- **ScalingToZero:** suspend per-node controllers via an internal
  `operator-suspended` annotation (distinct from user `spec.maintenance.suspended`),
  scale all storage STSes to 0, **confirm zero old-factor pods remain** (Hazard 1).
- **Purging:** patch each storage STS with a guarded busybox init container
  (`rm -f /data/metadata/cluster_layout` under PSA-restricted SC, reusing the
  `helpers.go:655` pattern).
- **ScalingUp:** scale all back up together.
- **Verifying:** poll `GetNodeInfo` until all report the new factor + Ready, none CrashLooping.
- **RebuildingLayout:** re-stage **all** node roles (storage + gateway) and apply
  once via a single pod, version+1.
- **Converging:** wait for resync; do not reclaim PVCs until drained; optionally
  trigger `Tables` repair (gateways.md:35-39 metadata-lag caveat).

PDB handling: evict first, force-delete after a 30s grace (operation is
explicitly disruptive). Federation refused in v1.

> **Scope note:** this is genuinely destructive and (per validation) narrower in
> value than #208 framed — it addresses **sharded-data** write quorum after
> permanent zone loss, not stuck admin-table writes (those need restore-majority
> or `dangerous` + tombstone cleanup). It is built behind an explicit annotation
> with no automatic trigger, and is the last piece to land so the core
> (gateway unification + layout correctness + health surface) ships independently
> green.

---

## 5. Testing strategy

**Unit / envtest:**
- `reconcileAutoModeGatewayNodes`: create/drift/scale/eject (mirror storage tests).
- `migrateLegacyGatewaySTSIfNeeded`: idempotency, `replicas=0` guard, strict-readiness guard, PVC adoption, ConfigMap/Service/PDB cleanup.
- Per-node controller gateway branch: pod-template selection, volume builder, `layoutClientForNode` (4 shapes), `capacity:None` role.
- `stageAndApplyRole`: apply-rejection-not-409 retry, conditional apply (no version bump on no-op), concurrent-writer convergence.
- Status conditions: `LayoutConverged`, `QuorumAtRisk` (roled vs floor(N/2)+1), `PeerUnreachable` (duration-based), `FederationConfigured`.
- Factor migration: state-machine progression + per-phase failure injection + `nongateway ≥ factor` guard + federation refusal.

**Kind e2e (extends `test/e2e/e2e_test.go`):**
- **Unified-cluster gateway (the #209 gap — none exists today):** unified
  `storage+gateway` Auto cluster; assert gateway pods get `capacity:None` roles;
  S3 auth via the gateway Service succeeds; under storage degradation a **roled**
  gateway still authenticates locally (assert success, and that the failure mode
  for a roleless control is 5xx not 403 — validation test #9).
- Gateway legacy-STS → per-pod migration: upgrade path, no S3 disruption, identity preserved.
- Existing edge-gateway tests keep passing (now via per-pod gateway GarageNodes).
- Apply-version race (G1): two writers race, operator recovers via version re-read, no divergent same-version layouts.
- No-op reconcile does not bump layout version (G2).
- Gateway tombstone GC via finalizer, no `skip-dead-nodes`, no data movement (B5).
- Simultaneous storage restart reconnect (#203) with freshly-resolved IPs.
- Multi-HDD migration capacity/path/read_only correctness (#205/G3/G4).
- Factor-reduction happy path in Kind (decrease); increase-guard at unit level.

**CI:** `make test` (unit+envtest), `make lint`, `make test-e2e` green.

---

## 6. Rollout (single PR, core-first commits)

1. Shared `stageAndApplyRole` correctness fix (storage + gateway) + tests.
2. Per-node controller gateway branch + `layoutClientForNode` + tests.
3. `reconcileAutoModeGatewayNodes` + `migrateLegacyGatewaySTSIfNeeded` + cluster Reconcile wiring; delete legacy gateway STS/tombstone/bootstrap paths; webhook LayoutPolicy gating + tests.
4. Health surface: conditions + `layoutDiagnosis` + printcolumns + `FederationConfigured` webhook warning + tests.
5. Factor migration annotation + state machine + tests.
6. e2e additions; CRD/manifest regen; docs/CLAUDE.md update.

Each commit keeps `make test` + `make lint` green. The PR is complete and
shippable after step 4 (core); steps 5 lands the destructive recovery op.

---

## 7. Out of scope (deferred, documented)

- Single cluster-scoped batched layout writer (optimization over the corrected per-pod model).
- Per-tier `LayoutPolicy`.
- Multi-cluster federation coordinator for factor change.
- Upstream Garage patches (none needed — v2.3.0 already has bounded `known_addrs` + connect timeout).
- Storage-tier tombstone parity for force-deleted Manual GarageNodes.
