# Website exposure for GarageBuckets (Ingress and Gateway API)

Issue: [#434](https://github.com/rajsinghtech/garage-operator/issues/434)

## Problem

A `GarageBucket` with `spec.website.enabled: true` is served by Garage's web
API (port 3902, `[s3_web]` section). Inside the cluster the existing API
Service already fronts it (the `web` ServicePort), but making the site
reachable externally today requires the user to hand-write an `Ingress` or
Gateway API `HTTPRoute` plus the knowledge of which Service and port to point
at, and which hostname Garage expects in the `Host` header (the bucket's
global alias followed by the cluster's `webApi.rootDomain`).

## Constraints

- The operator must not depend on a specific ingress controller or Gateway
  implementation: `ingressClassName` and Gateway `parentRefs` stay user
  configurable, TLS stays the ingress/Gateway controller's job (see
  "Open questions below").
- Garage resolves the bucket from the `Host` header
  (`host_to_bucket` in upstream `src/api/common/helpers.rs`): when the Host
  has the cluster's `webApi.rootDomain` as a suffix, the remainder is used as
  the alias, and **otherwise the full Host is used as the alias**
  (`host_to_bucket(host).unwrap_or(host)`). The canonical hostname is
  `<alias><rootDomain>` (e.g. `myalias.example.com` with
  `rootDomain: ".example.com"`); a bare alias also resolves. The generated
  routing resource must never be a catch-all.
- The web API Service is the cluster's in-cluster API Service, which already
  exposes the `web` port (port name `web` for Ingress backends, the effective
  web API port number for HTTPRoute backends). The exposure resource must
  reference that existing Service rather than introducing a new proxy:
  `<cluster>-gateway` for unified clusters (the gateway tier, where S3/Web
  traffic terminates), `<cluster>` otherwise.
- Buckets may live in a different namespace than their cluster (cross-
  namespace via `GarageReferenceGrant`). The exposure resource is created in
  the **bucket's** namespace and always carries a controller owner reference
  to the bucket (same namespace ⇒ garbage-collected with it, and no
  `<bucket>-website` name clash between namespaces). An Ingress backend
  cannot cross namespaces, so **Ingress exposure is only valid when the
  bucket and the cluster share a namespace**. An HTTPRoute backend reference
  crosses to the cluster's namespace and is gated by a Gateway API
  `ReferenceGrant` in that namespace (owned by the storage admin) — the
  intended Gateway API model, which also keeps a `GarageReferenceGrant` from
  quietly becoming permission to publish routes (with arbitrary annotations)
  from the storage namespace.
- The feature must be optional: an unset `spec.websiteExposure` changes
  nothing, and it requires `spec.website.enabled: true`.

## API

New optional field on `GarageBucket.spec` (v1beta1 is the only served bucket
version):

```yaml
spec:
  website:
    enabled: true
    indexDocument: index.html
  websiteExposure:
    hostnames: [www.example.com]   # optional; default <globalAlias><webApi.rootDomain>
    # backendRef:                   # optional backend override
    #   name: garage
    #   kind: ServiceImport
    #   group: multicluster.x-k8s.io
    #   namespace: garage-ns
    ingress:                        # exactly one of ingress / gateway
      ingressClassName: traefik
      tlsSecretName: my-tls         # optional, Ingress only (bucket's namespace)
      labels: {...}
      annotations: {...}
    # gateway:
    #   parentRefs:                 # embedded gatewayv1.ParentReference
    #     - name: public-gateway
    #       sectionName: http
    #   labels: {...}
    #   annotations: {...}
```

- At most one of `ingress` / `gateway` may be set (webhook-validated), and
  `websiteExposure` requires `spec.website.enabled: true`.
- `hostnames` are the external hostnames the exposure routes on. When empty
  the single canonical hostname `status.globalAlias + webApi.rootDomain`
  (effective cluster config) is used. Wildcards and duplicates are rejected.
  Because Garage falls back to the full Host as the alias, a hostname equal
  to the global alias also resolves. For an `HTTPRoute`, a hostname that is
  neither canonical nor the bare alias gets a `URLRewrite` filter rewriting
  the Host header to the canonical host. For an `Ingress` (no rewrite
  filter), only the canonical hostname and the bare alias are accepted; any
  other hostname is refused on the `WebsiteExposed` condition.
- `backendRef` overrides the backend Service (e.g. a cross-namespace
  `ServiceImport`). For an Ingress it must be a core/v1 Service in the
  bucket's namespace. The port is always the cluster's effective web API
  port.
- `ingress.tlsSecretName` maps to `Ingress.spec.tls`. TLS termination itself
  remains the ingress controller's concern; an HTTPRoute's TLS is on the
  parent `Gateway`.
- Labels/annotations on both resource kinds are merged the same way as other
  operator-managed metadata: operator keys win on conflict, foreign keys
  (external-dns, cert-manager, …) are preserved via
  `mergeOwnedMetadata`/`applyOwnedMetadata`.
- `parentRefs` are embedded upstream `gatewayv1.ParentReference` values,
  copied to `HTTPRoute.spec.parentRefs` with an omitted namespace defaulted
  to the bucket's (the route's) namespace.

### Naming

Generated resource name: `<bucket-name>-website` in the **bucket's**
namespace (see Constraints above: an Ingress backend cannot cross namespaces,
and a cross-namespace HTTPRoute backendRef is gated by a ReferenceGrant). A
name derived from the bucket name, in the bucket's own namespace, is unique
across clusters and cannot clash between namespaces.

## Reconciliation behavior

`GarageBucketReconciler.reconcileWebsiteExposure` runs after the bucket
reconcile in the normal (non-deleting) path:

- No `spec.websiteExposure` → ensure any previously generated resource is
  gone (delete the exact-owned one, leave foreign objects untouched).
- `ingress` requested:
  - The `networking.k8s.io` group is always available (core Kubernetes), so
    no CRD discovery is needed. Ingress creation and watching are still
    opt-in (v0.8.1, #460): the operator must be started with
    `--enable-ingress` (or `ENABLE_INGRESS`; chart value `ingress.enabled`),
    mirroring `--enable-gateway-api`. Without it the `Owns(Ingress)` watch is
    not registered, the cleanup path (`deleteWebsiteExposureIngress`) is a
    no-op, and a bucket that sets `ingress` reports condition
    `False/Reason=IngressDisabled`, no error, retried at the drift interval.
    This lets the operator run with no Ingress RBAC at all.
  - Cross-namespace is rejected (webhook + controller): the Ingress would
    have to target the cluster's web Service from another namespace.
  - Hostnames are `spec.websiteExposure.hostnames` or the derived canonical
    host. While the bucket has no recorded global alias yet, the canonical
    host cannot be derived and the hostname-vs-canonical check cannot run —
    the condition is set `False/Reason=WaitingForAlias` and the reconcile
    retries on the short interval (explicit hostnames included: an Ingress
    cannot rewrite the Host header, so every hostname must resolve to the
    bucket as-is (canonical form or bare alias); any other hostname is
    refused on the condition with no resource created).
  - The Ingress (one rule per hostname) routes path `/` (Prefix) to the
    cluster's web API Service in the bucket's namespace, port name `web`
    (`<cluster>-gateway` for unified clusters, `<cluster>` otherwise, or
    `backendRef` for an Ingress). `ingress.tlsSecretName` fills `spec.tls`
    with the hostnames.
- `gateway` requested:
  - HTTPRoute creation and watching are gated on the operator being started
    with `--enable-gateway-api` (or `ENABLE_GATEWAY_API`, like cert-manager)
    AND the Gateway API CRDs being installed (REST mapper probe, same
    pattern as `monitoringCRDExists`, so no informer starts without the
    CRDs). Missing either → condition `False/Reason=GatewayAPIUnavailable`,
    no error, retried at the drift interval.
  - An `HTTPRoute` is created with `spec.hostnames` = the resolved
    hostnames, the (copied) `parentRefs`, and one rule per hostname:
    HTTPRouteMatch `{path: {type: PathPrefix, value: "/"}}`, a `URLRewrite`
    hostname filter for non-canonical non-alias hostnames, and a backendRef
    to the cluster's web API Service (cluster namespace, effective web port)
    or `backendRef`. The cross-namespace backendRef needs the Gateway API
    `ReferenceGrant` in the cluster's namespace.
  - Readiness comes from the route's own `status.parents` (Accepted /
    ResolvedRefs / Ready per parent), not from the fact that the operator
    wrote the object: the controller owns and watches the
    Ingress/HTTPRoute back to the bucket, so a Gateway that rejects the
    route or a backend that does not resolve (missing ReferenceGrant,
    unknown Service) keeps the condition `False/Reason=NotReady` with the
    Gateway's message and a short requeue until it changes.
- A controller owner reference is always set (bucket's namespace), and
  switching the spec from `ingress` to `gateway` (or removing
  `websiteExposure`) deletes the other kind of generated resource.
- On any success/failure a `WebsiteExposed` status condition is maintained:
  - `True/Reason=Exposed` with the message naming the resource
    (`Ingress <ns>/<name>` or `HTTPRoute <ns>/<name>`).
  - `False/Reason=WaitingForAlias`, `False/Reason=GatewayAPIUnavailable`,
    `False/Reason=NotReady` (HTTPRoute parent status not yet ready),
    `False/Reason=ReconcileFailed` (message carries the error) otherwise.
  - The condition is removed entirely when `spec.websiteExposure` is unset.
  - `status.websiteExposure` mirrors the observed resource: `type`, `name`,
    `hostnames`, and for an HTTPRoute the per-parent
    `Accepted`/`ResolvedRefs`/`Ready` flags.
- `status.websiteUrl` is unchanged: it already publishes
  `scheme://alias.rootDomain` from the cluster's effective `webApi` config
  and remains the authoritative advertised URL.

The exposure resource is NOT a data-safety boundary: it is a plain routing
object with no finalizer of its own and no Garage-side state. A failed
reconcile (e.g. the Gateway does not exist yet) is a retryable condition,
not a `PhaseFailed` — the bucket itself is ready either way.

## Alternatives considered

- **Cluster-level exposure config on GarageCluster** — one resource per
  cluster hosting all buckets would need wildcard hosts and per-bucket path
  rewrites; Garage's host-based bucket resolution makes per-bucket hosts the
  natural unit.
- **Only HTTPRoute, no Ingress** — the issue explicitly asks for both;
  Ingress is more widely deployed than Gateway API and the shared build path
  (host + Service target) keeps the second type cheap.
- **Creating a dedicated Service per bucket** — unnecessary; the web port is
  already exposed on the cluster API Service and bucket selection happens at
  the HTTP layer via `Host`.

## Compatibility and migration

- New optional spec field on an existing CRD: old objects are unaffected,
  no conversion impact (GarageBucket has a single served version), no
  defaulting beyond what validation needs.
- Old operator + new field: the field is dropped by the old CRD schema only
  if the CRD is not upgraded; upgrading the CRD without the operator simply
  leaves the field inert. Rolling an operator up then down is safe: a
  removed `websiteExposure` on down-grade deletes the generated resource
  (controller owner ref), never data.
- Generated resources are controller-owned, so no manual cleanup is needed
  on feature removal or bucket deletion.

## Failure modes

- Alias not recorded yet (with or without explicit hostnames) →
  `False/WaitingForAlias` wait-and-retry condition, no partial resource.
- Gateway API disabled or CRDs absent → `False/GatewayAPIUnavailable`, no
  error, retried at the drift interval.
- Gateway does not accept the route, or the backend does not resolve
  (missing ReferenceGrant, unknown Service) → the route's `status.parents`
  keeps the condition `False/NotReady` with the Gateway's message; the
  owned-route watch re-reconciles when the status changes.
- Foreign object squatting on `<bucket>-website` → the operator refuses to
  mutate it (controller owner reference check, same pattern as
  `reconcileService`) and surfaces the error in the condition.
- Cluster Service missing (cluster still bootstrapping) → the bucket gates
  on `cluster.Status.Phase == Running` before the exposure reconcile runs,
  same as the rest of bucket reconciliation.

## Test plan

- Unit (envtest): Ingress create with derived canonical host, explicit
  hostnames (canonical + bare alias), `ingress.tlsSecretName`,
  labels/annotations merge; non-canonical hostname refused on the condition
  with no Ingress created; cross-namespace Ingress refused; delete on spec
  removal and on the ingress↔gateway switch; foreign object refusal.
- Unit (envtest with fake HTTPRoute): HTTPRoute create with parentRefs,
  hostnames, and the default backend; URLRewrite filter for non-canonical
  non-alias hostnames; `backendRef` override; readiness driven by simulated
  `status.parents` (Accepted/ResolvedRefs/Ready), including a not-accepted
  parent; missing-CRD and flag-disabled paths (condition only, no error);
  delete on spec removal.
- Webhook: exposure without `website.enabled` → rejected; both ingress and
  gateway set → rejected; neither → rejected; duplicate hostnames →
  rejected; cross-namespace Ingress → rejected; Ingress `backendRef` that is
  not a same-namespace core/v1 Service → rejected; gateway parentRef without
  name → rejected.
- RBAC chart sync test already pins `config/rbac/role.yaml` against the
  chart templates; the httproutes rule is gated on
  `.Values.gatewayAPI.enabled` and the ingresses rule on
  `.Values.ingress.enabled` in the chart, but both stay unconditional in the
  generated superset `config/rbac/role.yaml`.

## Documentation

- `docs/how-to/buckets-and-credentials.md` website section: new
  `websiteExposure` example (Ingress and Gateway API variants).
- `config/samples/garage_v1beta1_garagebucket.yaml`: website bucket gains an
  `ingress` exposure.
- README / CLAUDE.md GarageBucket feature table.

## Deferred

- TLS certificate provisioning (cert-manager etc.) — out of scope;
  `ingress.tlsSecretName` only names an existing Secret.
