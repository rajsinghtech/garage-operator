# Federated rollout recovery and health projection

**Status:** proposed implementation for Forgejo issue #725

## Problem and evidence

The parent `GarageCluster` controller can enter a persisted storage-rollout
boundary while a `GarageNode` controller or another layout writer owns the
shared in-process coordinator. The rollout recovery path currently treats
`errLayoutMutationPending` as an ordinary reconciliation error. That writes
`Phase=Failed` and returns before the normal Admin API status projection runs.
Repeated retries can therefore leave a cluster reporting an old healthy health
snapshot while Garage is degraded, and make a transient coordination wait look
like a terminal failure.

The same failure window can hide federation repair. The automatic bootstrap
trigger compares Garage's global `ConnectedNodes` with only the Pods discovered
in the local Kubernetes cluster. For a storage-bearing federated cluster, a
17-of-18 global connection state can look complete when only three local Pods
are present. The operator then declines to call `ConnectClusterNodes` or the
federation reconnect path that could repair a stale RPC address.

## Decision

1. Treat `errLayoutMutationPending` as a retryable safety wait. Preserve the
   durable rollout actor and never clear it merely because
   `layoutHistory.minAck == currentVersion`; an unreachable peer can still make
   stopping or changing the exact workload unsafe.
2. Publish `StorageRolloutReady=False` with reason `Waiting`, refresh the live
   Garage health/status/layout-history projection, and retry on the bounded
   coordination cadence. Invalid or incomplete durable actor state remains a
   real reconciliation failure and is not hidden by this handling.
3. Clear the previous `Status.Health` observation before each new status pass.
   Health is live evidence, so an unavailable Admin API must not preserve a
   previously healthy value.
4. For storage-bearing clusters, use the larger of local discovery and Garage's
   global `KnownNodes` as the reconnect expectation. Gateway-only clusters keep
   local-Pod expectations because their remote storage membership is expected.
5. While a storage rollout boundary is active, permit only the federation RPC
   reconnect work and an explicitly requested `connect-nodes` operation. Do not
   import roles or stage/apply layout mutations until the rollout proof
   completes. Failed explicit requests remain annotated for the guard's bounded
   retry; successful requests are consumed.

The operator does not automatically clear a Garage layout guard, invoke
`skip-dead-nodes`, delete Pods, or infer that a disconnected node is safe to
remove. A sustained unreachable peer remains visible through the existing
health conditions and requires the separately supervised operational recovery
path. An explicit `connect-nodes` annotation is the narrow exception to the
layout wait: it only issues `ConnectClusterNodes` through a reachable current
Pod or the cluster Service and never stages, applies, drains, or retires a
layout role.

## Alternatives considered

- **Clear the guard after re-reading layout history:** rejected. A settled
  history snapshot does not prove that an unreachable process can safely be
  stopped or that an in-flight controller handoff is complete.
- **Keep returning `PhaseFailed`:** rejected. Coordinator contention is a
  normal transient overlap and prevents the live health projection from
  explaining a degraded-but-serving federation.
- **Allow the full federation reconcile during rollout:** rejected. Role import
  and layout stage/apply would bypass the cluster-wide workload handoff.
- **Use only the local Pod count:** rejected for storage-bearing federation; it
  suppresses repair of remote members precisely when global connectivity is
  degraded.

## Compatibility and safety

This is a controller-only behavior change; no CRD fields or migration are
required. Existing durable rollout records remain authoritative. A rollout
that is genuinely waiting on a dead or stale peer continues to wait and report
that evidence rather than risking a second workload outage or an unsafe layout
mutation. Gateway-only reconnect behavior is unchanged.

## Observability and tests

The waiting condition and refreshed health fields make the status projection
actionable without claiming that Kubernetes Pod readiness means Garage
membership is healthy. Regression coverage verifies global reconnect
expectations, RPC-only federation repair during a rollout wait, explicit
`connect-nodes` dispatch and failure retention during a rollout guard,
retryable rollout contention, and removal of stale healthy status after a
failed live observation.
