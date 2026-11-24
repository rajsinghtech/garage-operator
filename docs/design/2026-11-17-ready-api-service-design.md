# Ready-only API Service

**Status:** Proposed — design for [#594](https://github.com/rajsinghtech/garage-operator/issues/594).

## Problem

`reconcileAPIService` sets `PublishNotReadyAddresses: true` on the primary API
Service `<cr>`, and `spec.network.service` cannot change it. When a node dies,
its storage pod stays in the `<cr>` EndpointSlice with `ready: true`. Eviction
only marks the pod Terminating; a StatefulSet pod on an unreachable node is not
removed until the node returns, the pod is force-deleted, or the node gets the
`node.kubernetes.io/out-of-service` taint. Until then S3 clients of `<cr>` keep
reaching a dead endpoint. Reproduced on `main` (28f953a) with kind: the
endpoint was still `ready: true` 500 s after the node stopped, and 25–38% of
S3 requests through `<cr>` failed for the whole window.

Publishing not-ready addresses matters for RPC bootstrap (`<cr>-headless`,
public-endpoint RPC Services). The API ports on `<cr>` do
not depend on it. `<cr>-gateway` (#175) already routes only to Ready pods, but
exists only for unified clusters.

## Proposal

Reconcile `<cr>-ready` for every cluster shape:

- `ClusterIP`, selector `apiServiceSelector(cluster, primaryTier)` and ports
  `apiServicePorts(cluster)`, identical to `<cr>`;
- `PublishNotReadyAddresses: false`;
- IP-family fields from `spec.network.service`; type, labels, annotations and
  load-balancer settings stay with `<cr>`, as for `<cr>-gateway`;
- controller-owned by the GarageCluster and removed on finalization like the
  other API Services, leaving same-name Services it does not own alone.

`<cr>` is unchanged. Storage pods have no readiness probe, so a pod leaves
`<cr>-ready` when its Ready condition goes false: node NotReady (about 40–50 s
with the default node-monitor grace period) or pod termination. Gateway pods
also honour their readiness probe.

## Alternatives

- Opt-in `spec.network.service.publishNotReadyAddresses` on `<cr>`: changes the
  CRD and makes one Service behave differently per cluster.
- Flip `<cr>` to `false`: changes behaviour for existing users during
  bootstrap and rollouts.
- Users hand-write a Service: depends on internal pod labels such as
  `api-serving`, which can change between releases.

## Compatibility

One extra `ClusterIP` Service per GarageCluster. No CRD change, no migration.
Rollback: an older operator leaves `<cr>-ready` in place; deleting it is safe.
