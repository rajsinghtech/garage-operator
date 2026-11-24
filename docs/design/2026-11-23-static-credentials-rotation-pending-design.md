# Defer static token rotation until the operator credential is ready

Status: Implemented in v0.9.1 (#600)

## Problem

Garage reads the static admin and metrics tokens only at startup. The operator
pins them in an immutable, content-addressed snapshot Secret and only moves the
pin once its table-backed operator token is verified on every running process,
so old and new processes keep accepting the operator. When the source Secret
changed before that bridge was ready (a scheduled rotation landing while a Pod
was Pending, down, or rolling), the operator returned an error and set the
GarageCluster to `Failed`. It stayed `Failed` until someone wrote the old value
back, although the pinned snapshot was still valid and still in use.

## Decision

The not-ready bridge is a wait, not a failure:

- `ensureStaticCredentialSnapshot` keeps returning the pinned snapshot, leaves
  the pin annotations untouched, and the reconcile continues. That lets the
  rest of the reconcile, including the operator token verification that makes
  the bridge ready, make progress.
- The wait is reported as a new GarageCluster condition,
  `StaticCredentialsRotationPending=True`, with reason
  `WaitingForOperatorAdminToken` or `WaitingForOperatorMetricsToken` and a
  message naming the pinned snapshot and the bridge error, if any. A Normal
  event is emitted when the condition appears or its reason changes.
- Once the bridge is ready, the existing path adopts the new revision and the
  condition is removed. Restoring the old source value also removes it.
- A bridge readiness error (for example a Pending Pod) is treated the same way:
  keeping the pin is always safe, because it is what every running process
  accepted.

Unchanged: a missing pinned snapshot plus a different source revision, and a
Consul credential change without its rotation-ready annotation, still fail,
because they need an operator action.

## API impact

No schema change. The condition is a new `type` value in the existing
`status.conditions` list of both served versions, so no conversion work is
needed. The cluster no longer goes `Failed` in this case; it keeps its normal phase
and shows the new condition instead.
