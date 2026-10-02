# Storage identity and layout

Garage's node identity is the durable boundary. The operator never treats a Kubernetes name, StatefulSet ordinal, PVC name, or node-local pool name as sufficient proof that a new process is the old Garage process.

## What must persist

| Storage | Contains | If it is lost |
| --- | --- | --- |
| Metadata volume / HostPath | Garage `node_key` and metadata database | The process starts as a different Garage identity unless recovered from the exact original storage |
| Data volume / HostPath | Object blocks for the identity | Blocks may require repair or may be permanently lost |
| RPC secret | Shared authenticated mesh credential | Peers cannot authenticate; rotation is not an in-place operation |
| Garage Admin token | Operator authentication to the Admin API | Reconciliation cannot inspect or mutate Garage |

PVCs are `Retain` by default for storage members. Gateway metadata claims also retain by default in unified mode; edge gateways retain their released `Delete` behavior unless configured otherwise. A retained claim may be reused only when the operator's exact ownership and UID handoff permits it.

## Layout roles

Garage's layout contains positive-capacity storage roles and capacity-less gateway roles. Replication applies globally across positive-capacity roles, including Manual, Auto, node-local, external, and federated members.

Gateway roles participate in the layout because Garage's signed S3 request path reads authentication tables locally. A gateway outside `layout.all_nodes()` can return `403 Forbidden: No such key` even when the storage nodes are healthy. The operator therefore expects a capacity-less role for managed gateway identities and reports `GatewayLayoutDegraded` when it is absent.

## Auto versus Manual

Auto mode creates the default storage `GarageNode` slots and derives their layout capacity, zone, tags, and workload configuration from `GarageCluster`. The scale subresource controls only this group.

Manual mode makes each `GarageNode` an independent declarative identity. It is appropriate for mixed disk sizes, SMB or pre-provisioned PVCs, per-node networking, external processes, or deliberate lifecycle control. A Manual → Auto transition is rejected; migrate by adding and draining explicit identities according to the [maintenance procedure](../operations/maintenance-and-recovery.md).

## Safe changes

An ordinary image, config, or pod-template update uses a parent-controlled `OnDelete` handoff for identity-bearing workloads. The operator replaces at most one actor at a time, verifies the exact replacement Pod and Garage identity, waits for layout and health to settle, and then continues.

Backend volume attributes follow a different rule from claim shape. A claim's storage class, selector, and access modes are fixed for the life of the identity, and arbitrary `volumeClaimTemplateSpec` stays unsupported because a free-form claim spec could silently change any of them. `volumeAttributesClassName` is the supported route for tuning an existing volume: Kubernetes modifies the backend volume in place (IOPS, throughput) with no data movement by the operator, so the operator patches it on the bound claim without scaling, draining, or touching the layout. A modification can briefly degrade I/O on that node. Auto mode applies a change to every node together; in Manual layout, edit one `GarageNode` at a time to roll it across nodes.

Positive-capacity removal is a separate drain transaction. In `consistencyMode: consistent`, the operator proves layout convergence, runs exact block repair workers, observes delayed resync, and keeps the source process online until the terminal evidence is complete. External or federated peers require explicit `AssumeConsistent` policy and cross-site serialization.

!!! danger "Never delete a live metadata volume"
    Deleting a live metadata PVC or HostPath can discard `node_key` and create a second Garage identity under a familiar Kubernetes name. Stop the workload only through the operator's drain/replacement flow, and retain the exact source evidence until the role is retired.

## Replication and failure domains

`replication.factor` is a Garage layout invariant. A storage scale-down is refused when it would leave fewer positive-capacity roles than the factor. `zone` identifies the site or static failure domain; `zoneFrom` can derive per-node zones from Kubernetes Node labels for operator-managed workloads.

For a federated layout, each site must advertise individually routable RPC addresses. A shared load balancer may route to the wrong identity and pass the TCP check while failing Garage's node-ID handshake. Use per-node endpoints, `{ordinal}` templates, or per-node LoadBalancer services.

## Layout application

`layoutManagement.autoApply: true` lets the operator apply staged layout changes after its health and safety gates. With the default `false`, pending layout changes remain visible in status for an administrator to review and apply with an appropriate Garage workflow. `force-layout-apply` is a narrow initial bootstrap override; it does not approve arbitrary staged changes, gateway tombstones, or unsafe drains.
