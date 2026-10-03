# Garage Kubernetes and Consul discovery

`spec.discovery` renders Garage's own peer-discovery sections
(`[kubernetes_discovery]` and `[consul_discovery]`). Both are optional. The
operator already connects Garage peers and writes the layout through the Admin
API, including for [federated sites](federation.md), so a normal cluster needs
neither. Enable one when Garage processes outside the operator's control must
find each other, or when you want Garage to re-learn peer addresses by itself
after restarts.

## Use Garage v2.4.1 or newer

Garage **v2.3.0 and v2.4.0 panic at start** when any discovery section is
configured (a missing rustls crypto provider; upstream issues
[#1416](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1416),
[#1526](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1526),
[#1532](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1532) and
[#1536](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1536)).
v2.4.1 installs the provider and is the first v2.4 release that is safe.
Versions before v2.3.0 are not affected. A cluster pod that restarts on an
affected release crash-loops; data is not damaged, and rolling the image back
or disabling `spec.discovery` recovers it.

The operator guards this in two places:

- The admission webhook warns when `spec.image` carries a `v2.3.0` or `v2.4.0`
  tag while `spec.discovery.consul.enabled` or
  `spec.discovery.kubernetes.enabled` is true. Warnings never reject the
  object. A digest-only image has no tag to read, so the webhook cannot judge it.
- While discovery is enabled the controller sets the
  [`DiscoveryCompatible`](../reference/operations.md) condition from the version
  Garage itself reports (`status.buildInfo.version` and every node that is up).
  `False` with reason `GarageVersionCrashesAtStart` means a running node
  reports v2.3.0 or v2.4.0, and it also fires for digest-only images and
  per-node image overrides. It never changes `Ready`.

```bash
kubectl get garagecluster garage -n storage \
  -o jsonpath='{.status.conditions[?(@.type=="DiscoveryCompatible")]}{"\n"}'
```

`DiscoveryCompatible` only sees nodes that start. If the first pod of a rollout
crash-loops on an affected release, the nodes still running the old release
keep reporting a version, so use the webhook warning and the pod logs
(`kubectl logs garage-0 --previous`) together.

## Kubernetes discovery

`spec.discovery.kubernetes` makes every Garage node publish a
`garagenodes.deuxfleurs.fr` custom resource (named after its node ID, labelled
`garage.deuxfleurs.fr/service=<serviceName>`) and list the resources of its
peers. This is Garage's own custom resource; it is unrelated to the operator's
`GarageNode` kind in `garage.rajsingh.info`.

```yaml
spec:
  serviceAccountName: garage
  discovery:
    kubernetes:
      enabled: true
      namespace: storage        # default: the GarageCluster's namespace
      serviceName: garage       # default: the GarageCluster's name
      skipCRD: true             # recommended, see below
```

### RBAC the operator does not create

The operator renders the TOML only. It does not create a ServiceAccount, Role
or the CRD, and the Garage pods use `spec.serviceAccountName` (the namespace's
`default` ServiceAccount when unset). Without permissions Garage logs
`Could not retrieve node list from Kubernetes` and
`Error while publishing node to Kubernetes` and keeps running; nothing else is
blocked.

| Permission | Scope | Needed |
| --- | --- | --- |
| `get`, `list`, `create`, `update` on `garagenodes.deuxfleurs.fr` | the discovery `namespace` | always |
| `create`, `patch` on `customresourcedefinitions` (`garagenodes.deuxfleurs.fr`) | cluster | only when `skipCRD` is false |

With `skipCRD: false` (the default) Garage server-side-applies the CRD on
**every discovery pass**, so every Garage pod needs cluster-wide CRD write
access. Prefer `skipCRD: true`, apply the CRD once as a cluster administrator,
and give the pods only the namespaced Role. The ready-to-apply set is the CRD in
[`discovery/garagenodes.deuxfleurs.fr.crd.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/discovery/garagenodes.deuxfleurs.fr.crd.yaml)
(apply it first, as a cluster administrator) plus
[`garage_v1beta2_garagecluster_kubernetes_discovery.yaml`](https://github.com/rajsinghtech/garage-operator/blob/main/config/samples/garage_v1beta2_garagecluster_kubernetes_discovery.yaml)
(ServiceAccount, Role, RoleBinding and a `GarageCluster`).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: garage-discovery
  namespace: storage
rules:
  - apiGroups: ["deuxfleurs.fr"]
    resources: ["garagenodes"]
    verbs: ["get", "list", "create", "update"]
```

The admission webhook prints this requirement as a warning whenever Kubernetes
discovery is enabled.

### Behaviour to know

- A node only publishes itself when it has an `rpc_public_addr`, explicit or
  autodetected. Garage logs `Not advertising to Kubernetes because
  rpc_public_addr is not defined` otherwise.
- Discovery only helps nodes find addresses. Layout roles are still assigned by
  the operator, so discovery never makes a node a storage member by itself.
- The Garage image must be built with the `kubernetes-discovery` feature. The
  official `dxflrs/garage` images are; some distribution packages are not.

## Consul discovery

`spec.discovery.consul` registers each node in a Consul catalog or agent and
reads its peers back. The webhook validates the required fields and warns about
the version-dependent ones (catalog ACL tokens need Garage v2.3 or newer, which
is why `api: agent` is the choice that works across v2.0 to v2.2). Consul
discovery is subject to the same v2.3.0/v2.4.0 crash described above.

## Why there is no raw `garage.toml` escape hatch

New Garage configuration keys are added to the typed spec with the release that
introduces them, rather than through a free-form TOML field, so every key keeps
a schema, validation and a version note. If you need a key the spec does not
model yet, open an issue.
