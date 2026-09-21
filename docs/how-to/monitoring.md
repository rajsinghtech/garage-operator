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

### Bucket quota metrics

The operator exposes the following gauges on the same controller-manager
metrics endpoint for every `GarageBucket` with an observed bucket ID and quota
usage. Every series has the labels `namespace` and `bucket`; `bucket` is the
Kubernetes `GarageBucket` name, not the Garage global alias. If two resources
refer to one Garage bucket, they therefore produce two labelled series and
should not be summed across namespaces as if they were distinct Garage
buckets.

| Metric | Meaning | Units and unlimited behavior |
| --- | --- | --- |
| `garage_operator_bucket_size_bytes` | Current bucket size | Bytes |
| `garage_operator_bucket_size_limit_bytes` | Configured maximum bucket size | Bytes; `0` means unlimited |
| `garage_operator_bucket_quota_size_utilization_ratio` | Size divided by the configured size limit | Ratio from `0` to `1`; absent when the limit is `0` or less |
| `garage_operator_bucket_objects` | Current object count | Objects |
| `garage_operator_bucket_object_limit` | Configured maximum object count | Objects; `0` means unlimited |
| `garage_operator_bucket_quota_object_utilization_ratio` | Object count divided by the configured object limit | Ratio from `0` to `1`; absent when the limit is `0` or less |

The limit gauges remain present with value `0` for unlimited dimensions, while
the corresponding utilization series is absent. This lets `absent()`
distinguish an unlimited dimension from an empty bucket. The status fields
`status.quotaUsage.sizePercent` and `status.quotaUsage.objectPercent` are
integer, truncated status summaries; the Prometheus utilization gauges use the
raw Garage counts and limits to preserve a fractional ratio.

For example, this alert warns when either quota dimension reaches 90% for ten
minutes. Unlimited dimensions do not alert because their utilization series is
absent:

```yaml
groups:
- name: garage-bucket-quotas
  rules:
  - alert: GarageBucketQuotaNearlyFull
    expr: |
      garage_operator_bucket_quota_size_utilization_ratio > 0.9
      or
      garage_operator_bucket_quota_object_utilization_ratio > 0.9
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Garage bucket quota is nearly full"
      description: "{{ $labels.namespace }}/{{ $labels.bucket }} has reached more than 90% of a configured size or object quota."
```

Use either a `ServiceMonitor` or a `PodMonitor` for the operator endpoint. They
select the same operator metrics, so the chart deliberately fails to render if
both are enabled rather than silently double-scraping every replica. A
`PodMonitor` can be selected with:

```yaml
podMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
```

Both monitor values expose `namespaceSelector.matchNames`,
`selector.matchLabels`, `jobLabel`, `targetLabels`, `honorLabels`,
`relabelings`, and `metricRelabelings`. Empty selector overrides retain the
chart's existing release-namespace and chart-label defaults. The relabeling
lists are copied to the monitor endpoint, which is useful when forwarding
operator metrics through kube-prometheus-stack to Mimir.

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

The bundled rules cover availability, cluster health, quorum, partitions, RPC failures, block resync errors, low disk space, and bucket quotas. The dashboard ConfigMap uses the common Grafana sidecar label pattern and includes bucket size and object quota panels.

The chart renders these alert names by default:

| Group | Alerts |
| --- | --- |
| Availability | `GarageNodeDown`, `GarageHighRPCErrorRate` |
| Storage | `GarageBlockResyncErrors`, `GarageHighBlockResyncQueue`, `GarageLowDiskSpace` |
| Quota | `GarageBucketSizeQuotaNearLimit`, `GarageBucketObjectQuotaNearLimit` |
| Cluster | `GarageClusterUnhealthy`, `GarageClusterUnavailable`, `GarageStorageNodeDown`, `GaragePartitionsDegraded`, `GarageNodeDisconnected` |

Set `prometheusRules.disabled.<AlertName>: true` to disable an individual
rule. `customRules.<AlertName>.severity` and `.for` override the rendered
severity or duration; `additionalRuleLabels`, `additionalRuleAnnotations`,
and per-group labels/annotations are applied to the generated rules.

The quota rules use the post-rename bucket series listed above, a 90% threshold,
and a 15-minute `for` period. The utilization series are intentionally absent
when a bucket has no limit; the alert expressions also require a positive limit,
so unlimited buckets do not fire or produce an unknown quota state. Disable
either default alert with
`prometheusRules.disabled.GarageBucketSizeQuotaNearLimit: true` or
`prometheusRules.disabled.GarageBucketObjectQuotaNearLimit: true`.

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
