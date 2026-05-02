# JSON Schemas for Garage Operator CRDs

These JSON schemas enable editor validation and autocompletion for Garage Operator custom resources.

## Usage

### VS Code with YAML Extension

Add a schema comment at the top of your manifest:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagecluster_v1beta1.json
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: my-cluster
spec:
  # You'll get autocompletion and validation here
```

### Available Schemas

| CRD | Schema URL |
|-----|------------|
| GarageCluster | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagecluster_v1beta1.json` |
| GarageBucket | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagebucket_v1beta1.json` |
| GarageKey | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagekey_v1beta1.json` |
| GarageNode | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagenode_v1beta1.json` |
| GarageAdminToken | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garageadmintoken_v1beta1.json` |
| GarageReferenceGrant | `https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/garagereferencegrant_v1beta1.json` |

### kubeconform Validation

Validate manifests locally:

```bash
make validate-manifests
```

Or directly with [kubeconform](https://github.com/yannh/kubeconform):

```bash
kubeconform -strict -summary \
  -schema-location default \
  -schema-location 'schemas/{{.ResourceKind}}_v1beta1.json' \
  your-manifests.yaml
```

With remote schemas:

```bash
kubeconform -strict -summary \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/rajsinghtech/garage-operator/main/schemas/{{.ResourceKind}}_v1beta1.json' \
  your-manifests.yaml
```

## Regenerating Schemas

To regenerate schemas after CRD changes:

```bash
make schemas
```

Requires Python 3 with PyYAML (auto-installed if missing).
