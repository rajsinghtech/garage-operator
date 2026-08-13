# Monitor Garage

There are two separate metrics surfaces:

1. Garage node metrics from each cluster's Admin API (`spec.monitoring`).
2. Operator controller-manager metrics from the Helm chart (`serviceMonitor.enabled`).

Do not confuse the two ServiceMonitors.

## Garage node metrics

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  monitoring:
    enabled: true
    interval: 30s
    additionalLabels:
      release: kube-prometheus-stack
    metricRelabelings:
      - sourceLabels: [__name__]
        regex: 'rpc_duration_seconds_bucket'
        action: drop
  admin:
    metricsRequireToken: true
    metricsTokenSecretRef:
      name: garage-metrics-token
      key: metrics-token
```

The operator creates a `ServiceMonitor` targeting each Garage node's Admin
`/metrics` endpoint. It selects both Auto and Manual node Services by the
cluster label and takes the Prometheus `job` label from each Service's
`app.kubernetes.io/name=garage` label, producing `job="garage"` for the bundled
dashboard.
`metricRelabelings` are copied to the endpoint and run after scraping, before
Prometheus stores samples; use them to control high-cardinality series such as
per-method RPC histograms. When `metricsRequireToken` is set, Prometheus must
be authorized to read the token Secret in the Garage namespace.

## Operator metrics

```bash
helm upgrade garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --set serviceMonitor.enabled=true \
  --set 'serviceMonitor.labels.release=kube-prometheus-stack'
```

The chart's operator metrics endpoint is HTTPS on port `8443` by default and is protected by Kubernetes authentication/authorization. The chart creates the required metrics Service and RBAC when metrics are enabled.

## Alerting and dashboard

The chart can create alerting rules and a Grafana dashboard ConfigMap:

```yaml
prometheusRules:
  enabled: true
  labels:
    release: kube-prometheus-stack
grafanaDashboard:
  enabled: true
  labels:
    grafana_dashboard: "1"
```

The bundled rules cover availability, cluster health, quorum, partitions, RPC failures, block resync errors, and low disk space. The dashboard ConfigMap uses the common Grafana sidecar label pattern.

The chart renders these alert names by default:

| Group | Alerts |
| --- | --- |
| Availability | `GarageNodeDown`, `GarageHighRPCErrorRate` |
| Storage | `GarageBlockResyncErrors`, `GarageHighBlockResyncQueue`, `GarageLowDiskSpace` |
| Cluster | `GarageClusterUnhealthy`, `GarageClusterUnavailable`, `GarageStorageNodeDown`, `GaragePartitionsDegraded`, `GarageNodeDisconnected` |

Set `prometheusRules.disabled.<AlertName>: true` to disable an individual
rule. `customRules.<AlertName>.severity` and `.for` override the rendered
severity or duration; `additionalRuleLabels`, `additionalRuleAnnotations`,
and per-group labels/annotations are applied to the generated rules.

The dashboard is a ConfigMap named `<release>-garage-dashboard` with key
`garage-prometheus.json`. With the Grafana sidecar, match
`grafanaDashboard.labels` to its discovery label. With Grafana Operator, use
a `GrafanaDashboard` resource that references that ConfigMap:

```yaml
apiVersion: grafana.integreatly.org/v1beta1
kind: GrafanaDashboard
metadata:
  name: garage
  namespace: garage-operator-system
spec:
  allowCrossNamespaceImport: true
  instanceSelector:
    matchLabels:
      grafana.internal/instance: grafana
  folder: Garage
  configMapRef:
    name: garage-operator-garage-dashboard
    key: garage-prometheus.json
  datasources:
    - inputName: DS_PROMETHEUS
      datasourceName: Prometheus
```

Use the actual Helm release name in `configMapRef.name`; `namespace` must be
the ConfigMap namespace when cross-namespace import is not enabled.

## Useful status queries

```bash
kubectl get garagecluster -A \
  -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,READY:.status.readyReplicas,DESIRED:.status.replicas,DIAGNOSIS:.status.layoutDiagnosis
kubectl get garagenode -A \
  -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,CONNECTED:.status.connected,IN_LAYOUT:.status.inLayout,VERSION:.status.version
kubectl get garagebucket,garagekey -A
```

Watch the actionable conditions rather than only `status.phase`: `QuorumAtRisk`, `PeerUnreachable`, `RemoteClustersHealthy`, `FederationConfigured`, `GatewayConnected`, `GatewayLayoutDegraded`, `GatewayTombstones`, `StorageTopologyReady`, `NodeLocalPoolsReady`, `StorageRolloutReady`, and `StorageDrainReady` explain why a resource is not ready.

## Metrics network policy

If `networkPolicy.enabled=true`, label the namespaces that are allowed to scrape the operator metrics Service with the configured selector (default `metrics: enabled`). Make sure Prometheus's namespace and any network path to the Service match this policy.
