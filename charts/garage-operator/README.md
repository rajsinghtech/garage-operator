# Garage Operator Helm Chart

A Kubernetes operator for managing [Garage](https://garagehq.deuxfleurs.fr/) - a distributed S3-compatible object storage system.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- (Optional) cert-manager for webhook certificates
- (Optional) Prometheus Operator for ServiceMonitor

## Installation

### From OCI Registry (GHCR)

```bash
# Install the latest version
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace

# Install a specific version
helm install garage-operator oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.1.0 \
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
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |

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
| `networkPolicy.enabled` | Create NetworkPolicy for metrics | `false` |

### Webhooks

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhooks.enabled` | Enable admission webhooks | `false` |
| `webhooks.failurePolicy` | Webhook failure policy | `Fail` |
| `webhooks.certManager.enabled` | Use cert-manager for certificates | `true` |

## Usage

After installation, create Garage resources:

### Create a Garage Cluster

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: my-garage
spec:
  replicas: 3
  zone: us-east-1
  storage:
    data:
      size: 100Gi
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
    - bucketRef: my-bucket
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
  garageadmintokens.garage.rajsingh.info
```

## License

Apache 2.0 - See [LICENSE](../../LICENSE) for details.
