# Use the Garage web admin UI

Garage `v2.6.0` and newer ship a browser UI for cluster administration. The
official `dxflrs/garage` images build it into the `garage` binary (Cargo feature
`webadmin`), and the operator's built-in default image includes it. There is no
separate container, binary, or Garage configuration key: the UI is always on in
these builds and cannot be switched off from `garage.toml`. Custom builds
compiled without the `webadmin` feature do not serve it.

## Where it is served

The UI shares the Admin API listener (`spec.admin.bindPort`, default `3903`):

| Path | Response |
| --- | --- |
| `/` | `302` redirect to `/ui/` |
| `/ui/`, `/ui/*` | The web app (unknown paths fall back to `index.html`) |
| `/favicon.ico`, `/favicon.svg` | Icons |
| `/v2/*` | The Admin API, which the UI calls from the browser |

The operator already publishes the admin port on the cluster's primary Service
(`<cluster>`, port name `admin`), so a GarageCluster running Garage `v2.6.0`
serves the UI in-cluster at (also published as
`status.endpoints.webUI.inCluster`):

```text
http://<cluster>.<namespace>.svc:3903/ui/
```

For a quick look from a workstation:

```bash
kubectl port-forward -n garage svc/garage 3903:3903
# then open http://localhost:3903/ui/
```

## Status the operator reports

Every GarageCluster with a Garage workload reports the UI in its status,
whether or not you expose it:

| Field | Meaning |
| --- | --- |
| `status.endpoints.webUI.inCluster` | Always set: `http://<cluster>.<namespace>.svc.<cluster-domain>:<adminPort>/ui/` |
| `status.endpoints.webUI.external` | Set only while `spec.admin.webUI` is exposed (`WebUIExposed=True`) |
| Condition `WebUIAvailable` | `True` (reason `FeaturePresent`) when every node that answers `GetNodeInfo` lists the `webadmin` feature; `False` (reason `FeatureNotPresent`) naming the nodes that do not, for example Garage before `v2.6.0` |
| Condition `WebUIExposed` | Only while `spec.admin.webUI` is set; see below |

`WebUIAvailable` is informational. The operator still creates the exposure
when it is `False`, so the route is ready the moment you upgrade Garage.

```bash
kubectl get garagecluster garage -n garage \
  -o jsonpath='{.status.endpoints.webUI}{"\n"}'
```

## Signing in

The static UI files load without a token. Every action the UI takes is an
Admin API call, and those still require a bearer token. Sign in with either:

- the static admin token from `spec.admin.adminTokenSecretRef` (full access), or
- a scoped, expiring token created through Garage's Admin API
  (`CreateAdminToken`) for people who should not have full access.

```bash
kubectl get secret garage-admin-token -n garage \
  -o jsonpath='{.data.admin-token}' | base64 -d
```

A scoped token lists the Admin API endpoints it may call. For example, a
read-only token that expires after a week (the UI shows an error for any
action outside the scope):

```bash
ADMIN_TOKEN=$(kubectl get secret garage-admin-token -n garage \
  -o jsonpath='{.data.admin-token}' | base64 -d)
kubectl port-forward -n garage svc/garage 3903:3903 &
curl -sS -X POST http://localhost:3903/v2/CreateAdminToken \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\": \"ui-readonly\", \"expiration\": \"$(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)\",
       \"scope\": [\"GetClusterStatus\", \"GetClusterHealth\", \"GetClusterStatistics\",
                 \"GetClusterLayout\", \"GetNodeInfo\", \"GetNodeStatistics\",
                 \"ListBuckets\", \"GetBucketInfo\", \"ListKeys\", \"GetKeyInfo\"]}"
```

The response's `secretToken` is shown once. Revoke it with `DeleteAdminToken`
when it is no longer needed.

The browser keeps the token in its local storage for that origin.

## Exposing it outside the cluster

Set `spec.admin.webUI` to have the operator create and own an Ingress or a
Gateway API HTTPRoute for the UI. It works like a bucket's
[`spec.websiteExposure`](buckets-and-credentials.md): one hostname, plus exactly
one of `ingress` or `gateway`, with the same `ingressClassName`,
`tlsSecretName`, `labels`, `annotations` and `parentRefs` fields. The route sends the **root of that host** (`/`)
to the existing `<cluster>` Service's `admin` port; no extra Service is
created. The bundled UI loads its assets from `/ui/` and calls the Admin API
at `/v2/` on its own origin, so it needs a dedicated host and cannot live
under a sub-path such as `/garage/`.

!!! danger "Exposing the UI exposes the whole Admin API"
    The UI and the Admin API share one listener, so the route also publishes
    every `/v2/*` Admin API endpoint and, unless
    `spec.admin.metricsRequireToken` is `true`, `/metrics`. Anyone who holds a
    token can administer the cluster from wherever the host is reachable.
    Terminate TLS (the token travels in every request), restrict who can reach
    the host (an internal ingress class, a VPN-only Gateway, source-range
    annotations, or an authenticating proxy), set `metricsRequireToken: true`,
    and hand out scoped tokens instead of the admin token.

`spec.admin.webUI` controls exposure only. Garage `v2.6.0` and newer always
serve the UI on the admin port, and the operator cannot turn it off: removing
`spec.admin.webUI` deletes the Ingress or HTTPRoute, but the UI stays
reachable in-cluster and through any `LoadBalancer` or `NodePort` Service.
Nothing is exposed by default.

### With an Ingress

Requires the operator to run with `--enable-ingress` (chart value
`ingress.enabled=true`).

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
  namespace: garage
spec:
  # ...
  admin:
    metricsRequireToken: true
    webUI:
      hostname: garage-ui.example.com
      ingress:
        ingressClassName: nginx-internal
        tlsSecretName: garage-ui-tls
        annotations:
          cert-manager.io/cluster-issuer: letsencrypt
```

### With a Gateway API HTTPRoute

Requires the Gateway API CRDs and the operator's `--enable-gateway-api` flag
(chart value `gatewayAPI.enabled=true`). A `parentRef` without a namespace
refers to the GarageCluster's namespace.

```yaml
spec:
  admin:
    webUI:
      hostname: garage-ui.example.com
      scheme: https   # the Gateway listener terminates TLS
      gateway:
        parentRefs:
          - name: internal
            namespace: gateway-system
            sectionName: https
```

### Fields

| Field | Description |
| --- | --- |
| `hostname` | Required. The DNS name routed to the UI (no scheme, port, path, or wildcard). |
| `scheme` | `http` or `https`, used only for `status.endpoints.webUI.external`. Defaults to `https` when `ingress.tlsSecretName` is set, otherwise `http`. |
| `ingress.ingressClassName` | IngressClass to use; the cluster default when empty. |
| `ingress.tlsSecretName` | TLS Secret for `hostname`. |
| `ingress.labels`, `ingress.annotations` | Extra metadata on the Ingress. Operator labels win on conflict. |
| `gateway.parentRefs` | Required, 1 to 32 Gateway API parent references. |
| `gateway.labels`, `gateway.annotations` | Extra metadata on the HTTPRoute. |

The generated object is named `<cluster>-webui`, lives in the cluster's
namespace, and is owned by the GarageCluster. The operator refuses to adopt an
existing object of that name that it does not own. Switching between
`ingress` and `gateway` deletes the old object.

`spec.admin.webUI` needs a Garage workload (`spec.storage` or
`spec.gateway`); the API server rejects it on a management handle, which runs
no Garage process. It is available on both `v1beta2` and the deprecated
`v1beta1` GarageCluster. Admission warns when `spec.image` names a Garage
release older than `v2.6.0`.

### `WebUIExposed`

| Status | Reason | Meaning |
| --- | --- | --- |
| `True` | `Exposed` | The Ingress is applied, or the HTTPRoute is accepted by its parents. `status.endpoints.webUI.external` is set. |
| `False` | `NotReady` | The HTTPRoute is not accepted (yet); the message carries the parent's reason. |
| `False` | `IngressDisabled` | `ingress` is set but the operator runs without `--enable-ingress`. |
| `False` | `GatewayAPIUnavailable` | `gateway` is set but `--enable-gateway-api` is off or the HTTPRoute CRD is missing. |
| `False` | `ReconcileFailed` | Creating, updating, or deleting the object failed; see the message. |

!!! warning "LoadBalancer and NodePort Services already expose it"
    When `spec.network.service.type` is `LoadBalancer` or `NodePort`, the
    `<cluster>` Service publishes every port on it, including `admin`. With
    Garage `v2.6.0` that means the web UI login page is reachable from wherever
    that Service is, alongside the token-protected Admin API, with or without
    `spec.admin.webUI`. This was already true of the Admin API before `v2.6.0`.
    Restrict it with `spec.network.service.loadBalancerSourceRanges`, a
    NetworkPolicy, or a firewall, keep the admin token secret, and set
    `metricsRequireToken: true`.
