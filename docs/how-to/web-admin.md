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
serves the UI in-cluster at:

```text
http://<cluster>.<namespace>.svc:3903/ui/
```

For a quick look from a workstation:

```bash
kubectl port-forward -n garage svc/garage 3903:3903
# then open http://localhost:3903/ui/
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

The browser keeps the token in its local storage for that origin.

## Exposing it outside the cluster

The operator does not yet create an Ingress or HTTPRoute for the UI. If you
create one yourself:

- Route the **root of a dedicated host** (`/`) to the `<cluster>` Service's
  `admin` port. The bundled UI loads its assets from `/ui/` and calls the Admin
  API at `/v2/` on its own origin, so a sub-path such as `/garage/` does not work.
- Terminate TLS in front of it. The admin token travels in every request.
- Routing the host to the admin port exposes the whole Admin API and, unless
  `spec.admin.metricsRequireToken` is set, `/metrics`, not only the UI.

!!! warning "LoadBalancer and NodePort Services already expose it"
    When `spec.network.service.type` is `LoadBalancer` or `NodePort`, the
    `<cluster>` Service publishes every port on it, including `admin`. With
    Garage `v2.6.0` that means the web UI login page is reachable from wherever
    that Service is, alongside the token-protected Admin API. This was already
    true of the Admin API before `v2.6.0`. Restrict it with
    `spec.network.service.loadBalancerSourceRanges`, a NetworkPolicy, or a
    firewall, keep the admin token secret, and set `metricsRequireToken: true`.
