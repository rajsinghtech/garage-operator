# Acknowledged service hold for a broken node-local member

Status: Implemented in v0.9.1 (#603). Extends
[the node-local service hold](2026-10-08-node-local-service-hold-design.md).

## Problem

`garage.rajsingh.info/node-local-out-of-service` stops one node-local Pod and
keeps its identity. It requires a current `FullyReplicated=True/Verified`
proof. A node whose own Garage metadata DB is corrupt makes the table-sync
stage of that proof fail, so the node that needs the hold for Garage's
documented repair (stop it, delete its DB, restart with the same identity,
`garage repair tables`) is the one that blocks it. The only route left was to
suspend reconciliation and edit operator-owned Node labels by hand, which
skips every check.

## Decision

A new GarageCluster annotation,
`garage.rajsingh.info/node-local-out-of-service-acknowledge-unverified`, whose
value is the exact 64-hex Garage node ID of the held node.

- Admission (both served versions): it requires `node-local-out-of-service`
  in the same object and must be a 64-hex ID (case-insensitive). The pair is
  set and removed together.
- Controller: when the value equals the held GarageNode's `status.nodeId`,
  only the `FullyReplicated` requirement is skipped. A value that names any
  other node stops the hold with a message. Everything else still applies:
  single site, matching HostPath claim, settled GarageNode, current DaemonSet
  activation, every other member active, consistent drain and rollout state,
  settled layout with a positive-capacity role, and live cluster health.
- The returning process keeps its identity, so no replace-identity step is
  needed. Docs tell the operator to request `verify-redundancy` afterwards.

Naming the exact node ID follows `acknowledge-lost-source`: an acknowledgement
cannot carry over to a different node or to a later identity on the same Node.

## API impact

Additive annotation only. No schema change and no conversion work;
annotations round-trip between v1beta1 and v1beta2 unchanged. Without the
annotation, behavior is exactly as before.
