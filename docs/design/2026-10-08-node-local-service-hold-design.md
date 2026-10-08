# Node-local service hold and identity refill at replication factor

**Status:** Implementation design for
[#475](https://github.com/rajsinghtech/garage-operator/issues/475).

## Problem

A three-node site with replication factor 3 cannot drain one node-local
member: Garage rejects a layout with fewer positive-capacity roles than the
factor, and the operator's ordinary retirement path needs spare capacity. The
site still needs a documented way to stop one node's storage, wipe or replace
the disk, and refill that machine as a new identity while the other two nodes
keep serving.

## Decision

Two explicit GarageCluster annotations, never both at once:

1. `garage.rajsingh.info/node-local-out-of-service=pool/kubernetes-node`
   removes only that Node's current DaemonSet activation label. The HostPath
   claim, recovery pin, GarageNode, and positive-capacity role stay assigned.
   The operator waits for a current `FullyReplicated=True/Verified` proof,
   live health, and every other selected member to remain active, then waits
   for the exact Pod to terminate before the disk is safe to service.
2. After the disk is empty (or failed),
   `garage.rajsingh.info/node-local-replace-identity=pool/kubernetes-node/old-64-hex-id`
   authorizes one atomic Garage layout version that assigns the new process
   and removes the old role. The old ID is part of the request so a stale
   GitOps annotation cannot replace a later identity. Pin repair then updates
   the GarageNode recovery annotation, `status.nodeId`, and the Kubernetes
   Node claim under the layout mutex.

The operator never infers a wipe from a missing disk. Reduced redundancy
during the hold is accepted; losing quorum on the remaining nodes is not.

## Safety boundaries

- Single-site layout writer only. Federated followers and `connectTo` handles
  are refused.
- One hold at a time: every other selected member must still carry the
  current DaemonSet activation.
- Ordinary activation restore skips the held pair while the hold annotation
  is present.
- Identity replacement requires `storageNodes == factor` and
  `storageNodesUp == factor-1`, the old identity down, and partition quorum.
- The GarageNode recovery pin stays immutable unless the live parent carries
  an exact matching replacement request for the previous ID.
- Same-identity restart remains the cold-recovery path: wiping metadata is
  what creates a new ID and requires the replacement annotation.

## Not in this change

- Changing the replication factor.
- Adding a spare Kubernetes Node.
- Keeping the same Garage node identity after a metadata wipe.
- Automatic start of a `FullyReplicated` proof; operators still set
  `verify-redundancy` after refill.
