# connectTo-only management handle (Stage 1 of issue #269)

## Problem

A user runs Garage deployed by the upstream Helm chart and wants the operator
to manage cluster config declaratively — buckets, keys, permissions, layout —
without the operator owning the workload. Federation is operator-to-operator,
so it does not fit a cluster that has no operator on it yet.

Today there is no CR shape for "manage an external Garage's Admin-API state
only." Three blockers exist in the code:

1. `GetGarageClient` (`internal/controller/helpers.go`) always builds the admin
   endpoint from the managed Service (`svcFQDN(cluster.Name, …)`) and reads the
   token from `cluster.Spec.Admin`. `connectTo` is consulted only on the
   gateway-layout path (`gatewayLayoutClient` → `getExternalStorageClient`).
2. The validating webhook rejects the natural shape: `validateTiers` errors with
   *"spec.connectTo is only valid alongside spec.gateway"* whenever `connectTo`
   is set without a gateway tier.
3. `GarageBucket`/`GarageKey` gate on `cluster.Status.Phase == Running`, and the
   phase machinery derives Running only from storage/gateway pod readiness — a
   tier-less handle never reaches it.

## Chosen shape

A `GarageCluster` with **only** `spec.connectTo` set (no storage, no gateway) —
a pure management handle. Inferred, no new API field.

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
```

`GarageBucket`/`GarageKey` reference this cluster exactly as they would any
other. Helm keeps owning the pods; the operator touches only Admin-API state.

## Changes

### 1. `IsManagementHandle()` — `api/v1beta2/garagecluster_helpers.go`

```go
func (g *GarageCluster) IsManagementHandle() bool {
    return g != nil && g.Spec.Storage == nil && g.Spec.Gateway == nil && g.Spec.ConnectTo != nil
}
```

### 2. Webhook — `api/v1beta2/garagecluster_webhook.go`

- In `validateTiers`, replace the blanket `hasConnect && !hasGateway` rejection.
  Allow `connectTo` standalone (management handle). Keep the edge-gateway rule
  (`hasGateway && !hasStorage && !hasConnect` still errors).
- In `validateConnectTo`, when the CR is a management handle, require an
  admin-API path: `adminApiEndpoint` + `adminTokenSecretRef`, **or** `clusterRef`.
  `rpcSecretRef`/`bootstrapPeers` alone give no Admin API and are rejected as the
  only fields on a handle.

### 3. Client resolution — `internal/controller/helpers.go`

Extract the connectTo→client logic (currently duplicated in the reconciler's
`getExternalStorageClient`/`getStorageClusterClient`) into a shared free
function `resolveConnectToClient(ctx, c, cluster, clusterDomain)`:

- `adminApiEndpoint` + `adminTokenSecretRef` → build directly.
- `clusterRef` → resolve the referenced `GarageCluster`, use its managed
  endpoint + admin token.

`GetGarageClient` gains a leading branch: when `cluster.IsManagementHandle()`,
return `resolveConnectToClient(...)` instead of the `svcFQDN` path. Every
controller that already calls `GetGarageClient` (bucket, key, cluster) then
transparently talks to the external cluster.

### 4. Management-handle reconcile — `internal/controller/garagecluster_controller.go`

Early branch in `Reconcile`, after finalizer + maintenance, before
`ensureRPCSecret`:

```go
if cluster.IsManagementHandle() {
    return r.reconcileManagementHandle(ctx, cluster)
}
```

`reconcileManagementHandle`:
- Resolves the admin client and probes reachability (`GetClusterStatus`).
- Reachable → `Status.Phase = Running`, condition `ManagementHandleReady=True`,
  requeue `RequeueAfterLong` (5m, matching healthy edge gateways).
- Unreachable → `Status.Phase = Pending`, condition `False` with the error,
  requeue `RequeueAfterUnhealthy`.
- Creates/reconciles no workload: no RPC secret, ConfigMap, Services, PDB,
  layout, migration, or pod-derived health.

`finalize` short-circuits for a management handle (no owned Garage state or K8s
workload to tear down; bucket/key finalizers own their own remote cleanup).

### 5. Bucket/Key gating

No logic change — both already gate on `Status.Phase == Running`, satisfied by
the handle. Confirm `GarageKey` uses the same gate and nothing assumes a local
Service.

### 6. `GarageKey` RPC-secret consideration

`deriveKeyMaterial` needs `GetRPCSecret`, which falls back to
`<cluster>-rpc-secret` (absent on a handle). Adoption path is `importKey`
(supplied material) or operator-created keys via the Admin API. A `GarageKey`
on a handle without `importKey` and without a resolvable RPC secret must surface
a clear condition rather than an obscure error. Verify actual key-controller
behavior during implementation; handle explicitly if needed.

## Testing

- Webhook: handle accepted; `connectTo` with only rpcSecretRef/bootstrapPeers
  rejected; edge-gateway rule preserved; full cluster unaffected.
- `GetGarageClient`: handle → connectTo endpoint/token, not `svcFQDN`.
- Controller: handle reconcile sets `Running` on reachable admin API (mock),
  `Pending` when unreachable; asserts no STS/ConfigMap/Service created.

## Docs

- `CLAUDE.md`: document the management-handle shape under the cluster-shapes /
  connectTo sections.
- `config/samples/`: add a management-handle example CR.

## Out of scope (Stage 2)

In-place adoption of an existing StatefulSet + PVCs and retiring the Helm
release. Deferred — the modern operator manages per-node GarageNodes with
`metadata`/`data` PVC names that do not match the chart's `meta-*`/`data-*`,
so adoption needs a dedicated design.
