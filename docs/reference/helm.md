# Helm values

The chart is `oci://ghcr.io/rajsinghtech/charts/garage-operator`. The complete, commented values file is [`charts/garage-operator/values.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/charts/garage-operator/values.yaml); this page highlights production decisions.

## Installation and security

| Value | Default | Notes |
| --- | --- | --- |
| `replicaCount` | `1` | Run multiple replicas with leader election enabled |
| `leaderElection.enabled` | `true` | Required for supported layout mutation |
| `leaderElection.unsafeAllowDisabled` | `false` | Explicit acknowledgement for unsupported single-manager mode |
| `webhooks.enabled` | `true` | Required for conversion, node-local pools, managed PVCs, and prepared deletion |
| `webhooks.certManager.enabled` | `true` | Use cert-manager for webhook certificates |
| `crds.install` | `true` | Install CRDs with Helm |
| `crds.keep` | `true` | Keep CRDs on uninstall |
| `rbac.create` | `true` | Set false only when supplying equivalent roles yourself |
| `securityContext` | restrictive | Read-only root filesystem, no privilege escalation, drop all capabilities |

## Images and resources

| Value | Default | Notes |
| --- | --- | --- |
| `image.repository` | `ghcr.io/rajsinghtech/garage-operator` | Operator image |
| `image.tag` | chart `appVersion` | Prefer a release tag or digest |
| `image.digest` | empty | `sha256:` digest takes precedence over tag |
| `defaultGarageImage` | empty | Default for Garage CRs omitting `spec.image` |
| `resources.requests.memory` | `128Mi` | `256Mi` is recommended for stable operation at larger resource counts |
| `clusterDomain` | `cluster.local` | Override for custom Kubernetes DNS domains. Renders as the operator's `--cluster-domain` flag (also settable as the `CLUSTER_DOMAIN` env var for non-Helm installs). See [troubleshooting](../operations/troubleshooting.md#bucketkeytoken-stuck-pending-with-a-clusternotready-condition-mentioning-dns) if bucket/key/token resources stay `Pending` with a DNS error. |

## Scope and COSI

| Value | Default | Notes |
| --- | --- | --- |
| `watchNamespaces` | `[]` | Empty watches all namespaces; populated values make the operator namespace-scoped |
| `watchAnyNamespace` | `false` | Force cluster-wide watching when a list is present |
| `cosi.enabled` | `false` | Enable the optional COSI driver |
| `cosi.driverName` | `garage.rajsingh.info` | Must match COSI classes |
| `cosi.namespace` | release namespace | Shadow `GarageBucket`/`GarageKey` resources |

## Operator metrics

| Value | Default | Notes |
| --- | --- | --- |
| `metrics.enabled` | `true` | Enable authenticated operator metrics |
| `metrics.service.enabled` | `true` | Create the metrics Service |
| `metrics.bindAddress` | `:8443` | Must be a wildcard address |
| `serviceMonitor.enabled` | `false` | Create Prometheus Operator ServiceMonitor |
| `prometheusRules.enabled` | `false` | Create operator/Garage alerting rules from chart templates |
| `grafanaDashboard.enabled` | `false` | Create the bundled Garage dashboard ConfigMap |
| `networkPolicy.enabled` | `false` | Restrict metrics ingress to labeled namespaces |

## Render before install

```bash
helm show values oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.7.4 > values.yaml
helm template garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.7.4 \
  --namespace garage-operator-system \
  --values values.yaml > rendered.yaml
helm lint charts/garage-operator
```

## Values that affect application behavior

`webhooks.failurePolicy` applies to ordinary webhooks; managed-PVC identity protection remains fail-closed. `extraObjects` renders additional templated Kubernetes objects and should be reviewed as part of the release. Pod security, tolerations, affinity, topology spread, and priority settings affect only the operator Pod; Garage workload scheduling belongs in `GarageCluster`/`GarageNode` specs.

See [installation](../getting-started/installation.md) for namespace scoping and [monitoring](../how-to/monitoring.md) for the chart's monitoring integrations.
