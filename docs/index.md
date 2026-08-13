<div class="hero" markdown>

# Garage Kubernetes Operator

Run [Garage](https://garagehq.deuxfleurs.fr/)—distributed, self-hosted S3-compatible object storage—as a Kubernetes-native service. The operator owns cluster lifecycle, Garage layout, storage identity, gateways, buckets, credentials, and safe day-2 changes.

[Install the operator](getting-started/installation.md){ .md-button .md-button--primary }

</div>

<div class="feature-grid" markdown>

<div class="feature-card" markdown>

### Storage that survives change

PVC-backed members, manual `GarageNode` resources, and node-local HostPath pools retain the Garage identity and coordinate layout changes before workloads move.

</div>

<div class="feature-card" markdown>

### Gateways where clients are

Run persistent-identity gateways beside storage, at the edge, or as a management handle for an existing Garage deployment.

</div>

<div class="feature-card" markdown>

### Kubernetes-native access

Provision buckets, S3 keys, admin tokens, aliases, quotas, lifecycle rules, websites, and optional COSI resources declaratively.

</div>

<div class="feature-card" markdown>

### Operator-grade safety

Admission webhooks, leader election, layout coordination, drain barriers, identity pins, status conditions, and Prometheus integration make failure modes visible.

</div>

</div>

## Find the right page

| You need to… | Start here |
| --- | --- |
| Install a released chart | [Installation](getting-started/installation.md) |
| Decide between storage, unified, edge, manual, or management-handle shapes | [Choose a topology](getting-started/topologies.md) |
| Understand which resource owns a Garage identity | [Storage identity and layout](concepts/storage-and-layout.md) |
| Add buckets, keys, aliases, or tokens | [Buckets and credentials](how-to/buckets-and-credentials.md) |
| Operate node-local disks | [Node-local pools](node-local-pools.md) |
| Remove or replace storage safely | [Maintenance and recovery](operations/maintenance-and-recovery.md) |
| Look up a field, annotation, condition, or value | [Reference](reference/custom-resources.md) |

## Support boundary

The current release line is `v0.7.x`. The operator requires Garage `v2.0.0` or newer and uses Garage's `/v2` Admin API. The built-in Garage image is the digest-pinned, CI-tested `v2.3.0` image; see the [compatibility matrix](reference/compatibility.md) before selecting a different image.

Kubernetes `1.25+` is supported for ordinary cluster shapes. Node-local pools require Kubernetes `1.27+`, a cluster-scoped operator installation, enabled admission/conversion webhooks, leader election, and a workload namespace that permits the required HostPath policy.

!!! warning "The documentation describes the current API contract"
    Do not infer that every field accepted by an older CRD is active. Some fields are retained for conversion compatibility and are rejected or warned on by admission. The [custom-resource reference](reference/custom-resources.md) calls out supported and compatibility-only fields, while the generated schemas remain the validation source of truth.

## Project links

- [GitHub repository](https://github.com/rajsinghtech/garage-operator)
- [Releases and install manifests](https://github.com/rajsinghtech/garage-operator/releases)
- [Garage documentation](https://garagehq.deuxfleurs.fr/)
- [Contributing guide](https://github.com/rajsinghtech/garage-operator/blob/main/CONTRIBUTING.md)
