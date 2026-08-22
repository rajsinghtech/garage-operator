# Samples and generated schemas

Runnable examples live under [`config/samples/`](https://github.com/rajsinghtech/garage-operator/tree/main/config/samples). They are reviewed with the CRD schemas and are the best starting point for fields not covered in the conceptual guides. Most files contain multiple YAML documents; apply only the documents and namespaces appropriate for your installation.

## v1beta2 cluster topology samples

| Sample | Covers |
| --- | --- |
| [`garage_v1beta2_garagecluster.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster.yaml) | Persistent unified storage and gateway, API configuration, public RPC exposure, and multi-cluster federation |
| [`garage_v1beta2_garagecluster_auto_per_node.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_auto_per_node.yaml) | Default Auto mode: one generated `GarageNode` and one single-replica StatefulSet per storage identity |
| [`garage_v1beta2_garagecluster_ephemeral.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_ephemeral.yaml) | Disposable `EmptyDir` storage for local development and smoke tests; data and identity are lost on restart |
| [`garage_v1beta2_garagecluster_gateway.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_gateway.yaml) | Unified gateway notes plus same-namespace and remote edge gateways; the edge examples use one identity-safe replica per route |
| [`garage_v1beta2_garagecluster_management_handle.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_management_handle.yaml) | `connectTo`-only management handle for an existing Garage, including bucket adoption and imported key credentials |
| [`garage_v1beta2_garagecluster_node_local_pools.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_node_local_pools.yaml) | Selector-driven HostPath pools mixed with Manual/SMB storage, multi-path data, scheduling gates, and retirement notes |
| [`garage_v1beta2_garagecluster_zone_from.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_zone_from.yaml) | Failure-domain zones derived from Kubernetes Node labels |
| [`garage_v1beta2_garagecluster_eject_to_manual.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_eject_to_manual.yaml) | One-way Auto → Manual ownership handoff for generated `GarageNode`s |

## v1beta1 resource and compatibility samples

These examples remain useful for conversion tests and existing installations;
new `GarageCluster` manifests should use v1beta2.

| Sample | Covers |
| --- | --- |
| [`garage_v1beta1_garagecluster.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagecluster.yaml) | Legacy storage-only cluster shape and conversion |
| [`garage_v1beta1_garagecluster_ephemeral.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagecluster_ephemeral.yaml) | Legacy disposable `EmptyDir` clusters |
| [`garage_v1beta1_garagecluster_gateway.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagecluster_gateway.yaml) | Legacy gateway conversion to the v1beta2 edge shape |
| [`garage_v1beta1_garagebucket.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagebucket.yaml) | Quotas, website configuration, key grants, lifecycle rules, and the default `Delete` policy |
| [`garage_v1beta1_garagebucket_cross_namespace.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagebucket_cross_namespace.yaml) | Destination-namespace `GarageReferenceGrant` plus a cross-namespace bucket |
| [`garage_v1beta1_garagekey.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagekey.yaml) | Generated, imported, cluster-wide, and bucket-scoped S3 credentials |
| [`garage_v1beta1_garagenode.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagenode.yaml) | Manual storage, per-node PVC/RPC overrides, LoadBalancer RPC, gateway, and external nodes |
| [`garage_v1beta1_garagenode_cycle.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagenode_cycle.yaml) | Narrow add-before-remove storage identity cycle workflow |
| [`garage_v1beta1_garagenode_maintenance.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagenode_maintenance.yaml) | Per-node reconciliation suspension for hardware/PVC maintenance |
| [`garage_v1beta1_garageadmintoken.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garageadmintoken.yaml) | Static Admin bootstrap Secret material |
| [`garage_v1beta1_garagereferencegrant.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta1_garagereferencegrant.yaml) | Cross-namespace reference authorization |

## COSI samples

[`config/samples/cosi/`](https://github.com/rajsinghtech/garage-operator/tree/main/config/samples/cosi) contains the COSI `BucketClass`, `BucketAccessClass`,
`BucketClaim`, and `BucketAccess` examples, plus
[`garagecluster-e2e.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/cosi/garagecluster-e2e.yaml)
for a minimal test cluster. Apply the COSI class resources before claims and
access objects. The upstream cluster-wide COSI controller must be installed
separately; see [COSI installation](../how-to/object-storage-interfaces.md#cosi).

The repository's [`config/samples/kustomization.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/kustomization.yaml)
lists the ordinary sample set. It intentionally does not apply every example
at once because several samples reuse names or require different namespaces.

## Validate examples locally

```bash
make schemas
make validate-manifests
```

`make validate-manifests` requires `kubeconform`. It validates sample API
versions against `schemas/{{ .ResourceKind }}_{{ .ResourceAPIVersion }}.json`
using Kubernetes `1.25.0` as the baseline. Schema validation does not prove
node-local scheduling-gate support, HostPath marker setup, external network
routing, or that referenced Secrets and Garage peers exist.

## Generated schemas

The schemas are generated from the Go API types and CRDs. Do not hand-edit
them. Refresh them with `make manifests` or `make schemas`, then run the
relevant tests and inspect the diff. The generated CRDs under
[`config/crd/bases/`](https://github.com/rajsinghtech/garage-operator/tree/main/config/crd/bases)
are what Kubernetes applies.

Available schemas include:

- [`garagecluster_v1beta2.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagecluster_v1beta2.json)
- [`garagecluster_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagecluster_v1beta1.json)
- [`garagebucket_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagebucket_v1beta1.json)
- [`garagebucket_v1alpha1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagebucket_v1alpha1.json)
- [`garagekey_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagekey_v1beta1.json)
- [`garagenode_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagenode_v1beta1.json)
- [`garageadmintoken_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garageadmintoken_v1beta1.json)
- [`garagereferencegrant_v1beta1.json`](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/garagereferencegrant_v1beta1.json)

The [schema README](https://github.com/rajsinghtech/garage-operator/blob/main/schemas/README.md)
documents editor integration. The chart's [README](https://github.com/rajsinghtech/garage-operator/blob/main/charts/garage-operator/README.md)
is retained as a short package-level reference; this site is the canonical
cross-topic guide.
