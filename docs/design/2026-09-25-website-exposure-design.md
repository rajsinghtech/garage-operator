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
  (`host_to_bucket` in upstream `src/api/common/helpers.rs`): the host must
  be `<alias><rootDomain>`, e.g. `myalias.example.com` with
  `rootDomain: ".example.com"`. The generated routing resource must therefore
  carry that hostname and must not be a catch-all.
- The web API Service is the cluster-level in-cluster API Service
  (`<cluster>` in the cluster namespace — or `<cluster>-gateway` for
  gateway-only clusters), which already exposes the `web` port
  (`<cluster>-web` ServicePort is not used; the port is named `web`). The
  exposure resource must reference that existing Service rather than
  introducing a new proxy.
- Buckets may live in a different namespace than their cluster (cross-
  namespace via `GarageReferenceGrant`). An Ingress backend cannot cross
  namespaces, so the exposure resource is created in the **cluster's**
  namespace, next to the web API Service. Kubernetes also forbids
  cross-namespace owner references, so in that case the resource cannot be
  GC'd by the bucket: it instead carries a durable, collision-safe ownership
  label `garage.rajsingh.info/website-exposure-owner=<bucket UID>` (set only
  in the cross-namespace case), and the bucket controller removes it
  explicitly on deletion (finalize, Retain policy, COSI retain paths) —
  retaining the bucket finalizer until that cleanup succeeds.
- The feature must be optional: an unset `spec.websiteExposure` changes
  nothing.

## API

New optional field on `GarageBucket.spec` (v1beta1 is the only served bucket
version):

```yaml
spec:
  website:
    enabled: true
    indexDocument: index.html
  websiteExposure:
    host: www.example.com     # required for gateway; ingress may derive it
    tlsSecretName: my-tls     # optional, Ingress only
    ingress:
      ingressClassName: traefik
      labels: {...}
      annotations: {...}
    gateway:
      parentRefs:
        - name: public-gateway
          sectionName: http
```

- At most one of `ingress` / `gateway` may be set (webhook-validated).
- `host` is the external hostname. For `ingress`, when `host` is empty it is
  derived as `status.globalAlias + webApi.rootDomain` (effective cluster
  config), matching what Garage expects in `Host` and what
  `status.websiteUrl` already publishes. For `gateway`, an explicit `host` is
  required: an HTTPRoute with an empty `hostnames` entry is a wildcard route
  that would match any hostname the listener accepts, which is not a safe
  default for a bucket site.
- `tlsSecretName` maps to `Ingress.spec.tls`. TLS termination itself remains
  the ingress controller's concern.
- Labels/annotations on the Ingress are merged the same way as other
  operator-managed metadata: operator keys win on conflict, foreign keys are
  preserved via the existing `mergeOwnedMetadata`/`applyOwnedMetadata` path.
- `parentRefs` are passed through verbatim to `HTTPRoute.spec.parentRefs`.

### Naming

Generated resource name: `<bucket-name>-website` in the **cluster's**
namespace (see Constraints above: Ingress backends cannot cross namespaces,
and a cross-namespace HTTPRoute backendRef would need a ReferenceGrant). A
name derived from the bucket name (not the cluster name) keeps it unique
across clusters sharing a namespace.

## Reconciliation behavior

`GarageBucketReconciler.reconcileWebsiteExposure` runs after the bucket
reconcile in the normal (non-deleting) path:

- No `spec.websiteExposure` → ensure any previously generated resource is
  gone (delete the exact-owned one, leave foreign objects untouched).
- `ingress` requested:
  - `ingress` group is always available (core Kubernetes), so no CRD
    discovery is needed.
  - Host is `spec.websiteExposure.host` or the derived alias-based host.
    While the bucket has no recorded global alias yet, the host cannot be
    derived — the condition is set `False/Reason=WaitingForAlias` and the
    reconcile retries on the short interval; no resource is created with the
    wrong host. An explicit host is validated against the
    `<alias><rootDomain>` pattern **at reconcile time**, not admission: the
    alias lives in `status`, which the webhook does not read (and may not be
    recorded on CREATE). A mismatched host fails the exposure reconcile with
    `False/Reason=ReconcileFailed` and an explanatory message — only the
    *bare* `<alias><rootDomain>` host resolves in Garage, so a mismatched
    host would otherwise be a silent 404 site. The derived host (no explicit
    `host`) is consistent by construction.
  - The Ingress routes path `/` (Prefix) to the primary `<cluster>` Service
    in the cluster's namespace, port name `web`. `tlsSecretName` fills
    `spec.tls` with the resolved host.
  - Controller owner reference is set only when bucket and cluster share a
    namespace; otherwise the deletion paths (finalize, Retain, COSI retain)
    call `deleteWebsiteExposureResource` explicitly.
- `gateway` requested:
  - The Gateway API CRDs are optional. The reconciler probes the REST mapper
    for `gateway.networking.k8s.io/HTTPRoute` (same pattern as
    `monitoringCRDExists`). Missing CRDs → condition
    `False/Reason=GatewayAPIUnavailable`, no error, retried; this keeps
    installations without the Gateway API unaffected.
  - An `HTTPRoute` is created with `spec.hostnames: [host]`, one
    `parentRefs` entry each, and a single rule: HTTPRouteMatch `{path:
    {type: PathPrefix, value: "/"}}` → backendRef
    `<cluster>` Service (cluster namespace), port `web`. The backendRef
    points at the Service (not a Pod), so no cross-namespace ReferenceGrant
    is needed for the backend; the parentRef may cross namespaces per the
    user's `parentRefs`.
  - Owner reference set as above.
- On any success/failure a `WebsiteExposed` status condition is maintained:
  - `True/Reason=Exposed` with the message naming the resource
    (`Ingress <ns>/<name>` or `HTTPRoute <ns>/<name>`).
  - `False/Reason=WaitingForAlias`, `False/Reason=GatewayAPIUnavailable`,
    `False/Reason=ReconcileFailed` (message carries the error) otherwise.
  - The condition is removed entirely when `spec.websiteExposure` is unset.
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

- Host derivation before the alias is recorded → wait-and-retry condition,
  no partial resource.
- Explicit host that does not match `<alias><rootDomain>` → the exposure
  reconcile fails with `False/Reason=ReconcileFailed` (message explains
  Garage's host-based bucket resolution); the bucket itself stays ready.
- Gateway API absent → condition, no error, retried every reconcile cycle.
- Foreign object squatting on `<bucket>-website` → the operator refuses to
  mutate it (exact-UID ownership check, same pattern as `reconcileService`)
  and surfaces the error in the condition.
- Cluster Service missing (cluster still bootstrapping) → the bucket gates
  on `cluster.Status.Phase == Running` before the exposure reconcile runs,
  same as the rest of bucket reconciliation.

## Test plan

- Unit (envtest): Ingress create with derived host, explicit host,
  tlsSecretName, labels/annotations merge; delete on spec removal; foreign
  object refusal; no CRD impact for Ingress.
- Unit (envtest with fake HTTPRoute): HTTPRoute create with parentRefs and
  hostnames; missing-CRD path via a client whose mapper lacks the GVK
  (condition only, no error); delete on spec removal.
- Webhook: both ingress and gateway set → rejected; neither → rejected;
  gateway without host → rejected; gateway parentRef without name → rejected.
- Controller: explicit host not matching `<alias><rootDomain>` → condition
  `False/ReconcileFailed`, no resource written; cross-namespace placement →
  resource in the cluster namespace with no owner reference.
- RBAC chart sync test already pins `config/rbac/role.yaml` against the
  chart templates; the new ingress/httproutes rules must appear in both.

## Documentation

- `docs/how-to/buckets-and-credentials.md` website section: new
  `websiteExposure` example (Ingress and Gateway API variants).
- `config/samples/garage_v1beta1_garagebucket.yaml`: website bucket gains an
  `ingress` exposure.
- README / CLAUDE.md GarageBucket feature table.

## Deferred

- Per-`HTTPRoute` parentRef validation (the Gateway API itself reports
  attachment status; the operator does not read it back).
- TLS certificate provisioning (cert-manager etc.) — out of scope;
  `tlsSecretName` only names an existing Secret.
- `status` subresource back-population from the Gateway's `HTTPRouteStatus`
  (e.g. `ParentRefsAccepted` reasons) — the condition is sufficient for the
  first iteration.
