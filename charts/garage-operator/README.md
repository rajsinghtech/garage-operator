# Garage Operator Helm Chart

A Kubernetes operator for managing [Garage](https://garagehq.deuxfleurs.fr/) - a distributed S3-compatible object storage system.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- cert-manager for admission and conversion webhook certificates, unless `webhooks.enabled=false`
- (Optional) Prometheus Operator for ServiceMonitor and PrometheusRule resources

## Installation

### From OCI Registry (GHCR)

```bash
# Install the latest version
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace

# Install a specific version
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version <chart-version> \
  --namespace garage-operator-system \
  --create-namespace
```

### From Local Chart

```bash
# Clone the repository
git clone https://github.com/rajsinghtech/garage-operator.git
cd garage-operator

# Install from local chart
helm install garage-operator charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace
```

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters.

### Common Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Container image repository | `ghcr.io/rajsinghtech/garage-operator` |
| `image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `defaultGarageImage` | Default Garage image for GarageCluster/GarageNode resources that omit `spec.image` | `""` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `leaderElection.enabled` | Enable leader election for HA deployments | `true` |
| `logLevel` | Operator log level | `info` |
| `clusterDomain` | Kubernetes cluster domain used for service FQDNs | `cluster.local` |

### CRDs

| Parameter | Description | Default |
|-----------|-------------|---------|
| `crds.install` | Install CRDs with Helm | `true` |
| `crds.keep` | Keep CRDs on chart uninstall | `true` |

### Metrics & Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.service.enabled` | Create metrics service | `true` |
| `metrics.service.port` | Metrics service port | `8443` |
| `serviceMonitor.enabled` | Create ServiceMonitor for Prometheus | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `prometheusRules.enabled` | Create PrometheusRule alerting rules | `false` |
| `grafanaDashboard.enabled` | Create the Garage Grafana dashboard ConfigMap | `false` |
| `networkPolicy.enabled` | Create NetworkPolicy for metrics | `false` |

### Webhooks

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhooks.enabled` | Enable admission and conversion webhooks | `true` |
| `webhooks.failurePolicy` | Webhook failure policy | `Fail` |
| `webhooks.certManager.enabled` | Use cert-manager for certificates | `true` |

### Namespace Scoping & COSI

| Parameter | Description | Default |
|-----------|-------------|---------|
| `watchNamespaces` | Namespaces watched by the operator; empty means all namespaces | `[]` |
| `watchAnyNamespace` | Force cluster-wide watching when `watchNamespaces` is set | `false` |
| `cosi.enabled` | Enable the optional COSI driver | `false` |
| `cosi.driverName` | COSI driver name used by BucketClass/BucketAccessClass | `garage.rajsingh.info` |
| `extraObjects` | Extra templated Kubernetes objects to render with the chart | `[]` |

## Usage

After installation, create Garage resources:

### Create a Garage Cluster

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: my-garage
spec:
  zone: us-east-1
  replication:
    factor: 3
  storage:
    replicas: 3
    metadata:
      size: 10Gi
    data:
      size: 100Gi
  gateway:
    replicas: 2
```

### Create a Bucket

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: my-bucket
spec:
  clusterRef:
    name: my-garage
```

### Create an Access Key

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: my-key
spec:
  clusterRef:
    name: my-garage
  bucketPermissions:
    - bucketRef:
        name: my-bucket
      read: true
      write: true
```

## Upgrading

```bash
helm upgrade garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system
```

## Uninstalling

```bash
helm uninstall garage-operator --namespace garage-operator-system
```

**Note:** By default, CRDs are kept after uninstall. To remove CRDs:

```bash
kubectl delete crds garageclusters.garage.rajsingh.info \
  garagebuckets.garage.rajsingh.info \
  garagekeys.garage.rajsingh.info \
  garagenodes.garage.rajsingh.info \
  garageadmintokens.garage.rajsingh.info \
  garagereferencegrants.garage.rajsingh.info
```

## License

Apache 2.0 - See [LICENSE](../../LICENSE) for details.
