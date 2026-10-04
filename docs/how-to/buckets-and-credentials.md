# Manage buckets and credentials

The operator manages Garage resources through Kubernetes CRDs. Keep
`GarageBucket`, `GarageKey`, and `GarageAdminToken` in the namespace where you
want their generated Secrets to live. Cross-namespace `GarageBucket` and
`GarageKey` references require an explicit grant in the destination namespace;
`GarageAdminToken` references are always namespace-local.

## Create a bucket

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: app-data
  namespace: storage
spec:
  clusterRef:
    name: garage
  globalAlias: app-data
  quotas:
    maxSize: 500Gi
    maxObjects: 10000000
```

If `globalAlias` is omitted, the resource name is used as the bucket's global alias. Use `bucketId` to manage an existing Garage bucket by immutable ID; when set, the operator never creates a replacement bucket.

### Dropping `bucketId` after adoption

`spec.bucketId` is only needed to establish the mapping. After the first
reconciliation the operator records the resolved ID in `status.bucketId`, and
you can remove the field from your manifest without any bucket churn — the
operator keeps reconciling the same bucket from the recorded status:

```bash
kubectl get garagebucket app-data -n storage \
  -o jsonpath='{.status.bucketId}{"\n"}'
```

Wait until that prints the expected ID, then delete `spec.bucketId` from the
manifest. Three rules protect the mapping:

- Removing `spec.bucketId` is only accepted once `status.bucketId` is recorded.
- Setting `spec.bucketId` to a different bucket is always rejected — the
  mapping itself is immutable.
- A bucket ID can only be managed by one `GarageBucket` per GarageCluster;
  admission and the controller both reject duplicate claims, and a duplicate
  claimant's deletion can never remove a bucket another resource still manages.

If `status.bucketId` is somehow lost while the alias still resolves to the
adopted bucket, reconciliation fails with an actionable error instead of
creating a duplicate bucket.

## Choose bucket deletion behavior

`spec.deletionPolicy` controls what happens to the remote Garage bucket when
the `GarageBucket` resource is deleted:

- `Delete` is the default and preserves the existing behavior. The operator
  deletes the Garage bucket after Garage confirms it is empty. Garage does not
  recursively delete completed objects, so a non-empty bucket leaves the CR in
  `Deleting` until the objects are removed.
- `Retain` removes the Kubernetes resource without calling Garage's delete API.
  Objects, aliases, key permissions, quotas, website settings, and lifecycle
  rules remain in Garage. This works even when the referenced cluster or Admin
  API is unavailable.

`Delete` is safe with data: the operator never empties a bucket implicitly. If
Garage reports that the bucket is not empty, the finalizer remains and the
operator sets `DeletionBlocked=True` with reason `BucketNotEmpty` on the
`GarageBucket`. It retries with backoff, so the resource is visible as
`Deleting` rather than appearing healthy or being silently purged. Remove the
objects and incomplete multipart uploads through an S3 client, then allow the
next retry to delete the now-empty bucket. If the data should remain, change
the terminating resource to `deletionPolicy: Retain`; the operator then drops
its Kubernetes finalizer without contacting Garage.

Inspect the actionable condition and retry count with:

```bash
kubectl get garagebucket app-data -n storage -o jsonpath='{range .status.conditions[?(@.type=="DeletionBlocked")]}{.status} ({.reason}): {.message}{"\n"}{end}{.metadata.annotations.garage\.rajsingh\.info/finalization-retries}'
```

Do not remove the finalizer manually unless abandoning remote cleanup is
intentional; doing so can leave the remote bucket and its data unmanaged.

Use `Retain` for buckets containing backups or other data that must outlive the
Kubernetes resource:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: postgres-backups
  namespace: storage
spec:
  clusterRef:
    name: external-garage
  deletionPolicy: Retain
```

Before deleting a retained resource, record its immutable bucket ID:

```bash
kubectl get garagebucket postgres-backups -n storage \
  -o jsonpath='{.status.bucketId}{"\n"}'
```

To manage the retained bucket again, create a new `GarageBucket` with that ID
in `spec.bucketId`. Retaining the CR does not protect the underlying Garage
cluster, StatefulSets, or PVCs from being deleted.

Apply and inspect it:

```bash
kubectl apply -f bucket.yaml
kubectl get garagebucket app-data -n storage -o wide
kubectl get garagebucket app-data -n storage \
  -o jsonpath='{.status.bucketId}{"\n"}{.status.conditions}'
```

## Grant bucket access

Permissions can be expressed from either side. Choose one source of truth per relationship when possible; if both `GarageBucket.spec.keyPermissions` and `GarageKey.spec.bucketPermissions` describe a grant, the operator merges them.

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: app-key
  namespace: storage
spec:
  clusterRef:
    name: garage
  name: Application key
  bucketPermissions:
    - bucketRef:
        name: app-data
      read: true
      write: true
      owner: false
```

The `owner` permission controls bucket administration operations. `read` and `write` alone are not equivalent to owner access.

For a baseline permission on every bucket, use `allBuckets`. It applies to buckets created outside Kubernetes too, and the operator actively reconciles `false` values as revocations:

```yaml
spec:
  allBuckets:
    read: true
    write: false
    owner: false
  bucketPermissions:
    - bucketRef:
        name: app-data
      write: true
```

Use `bucketId`, `bucketRef`, or `globalAlias` exactly once in each permission entry. A cross-namespace bucket reference also needs a `GarageReferenceGrant`.

## Generate a Secret

By default a `GarageKey` creates a Secret named after the key. Customize the name, data keys, labels, annotations, and optional endpoint fields with `secretTemplate`:

```yaml
spec:
  secretTemplate:
    name: app-s3-credentials
    type: Opaque
    accessKeyIdKey: AWS_ACCESS_KEY_ID
    secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
    endpointKey: AWS_ENDPOINT_URL_S3
    regionKey: AWS_REGION
    includeEndpoint: true
    includeRegion: true
    includeBucketName: true
    websiteUrlKey: WEBSITE_URL
    includeWebsiteUrl: true
    includeCredentialsFile: true
    credentialsFileKey: credentials
    credentialsFileProfile: default
```

`includeCredentialsFile` adds a standard AWS shared credentials file under
`credentialsFileKey` (default `credentials`):

```ini
[default]
aws_access_key_id=GK...
aws_secret_access_key=...
```

The profile defaults to `default`; set `credentialsFileProfile` when a consumer
selects a named profile. Region and endpoint are intentionally not written to
this file; use `regionKey` and `endpointKey` for those values. The option is
disabled by default, so upgrading does not change existing generated Secrets.
Consumers that accept an AWS credentials file can select this single Secret
data key directly.

The source `GarageKey` and generated Secret remain in the same namespace. Use External Secrets, Reflector, or another controlled copy mechanism when a workload in another namespace needs the credentials.

Inspect readiness and Secret references without printing the Secret value into logs:

```bash
kubectl get garagekey app-key -n storage -o wide
kubectl get garagekey app-key -n storage \
  -o jsonpath='{.status.secretRef.name}{"\n"}{.status.conditions}'
kubectl get secret app-s3-credentials -n storage \
  -o jsonpath='{.data.endpoint}' | base64 -d; echo
```

## Import an existing key

Use `importKey` when Garage already contains the access key. The operator does not generate replacement material.

```yaml
spec:
  importKey:
    secretRef:
      name: existing-s3-credentials
    accessKeyIdKey: AWS_ACCESS_KEY_ID
    secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
```

The source Secret must contain the selected keys in the same namespace as the `GarageKey`. Inline `accessKeyId` and `secretAccessKey` are accepted for controlled bootstrap, but a Kubernetes Secret is preferable for GitOps and rotation workflows.

### Accepted credential formats

What Garage accepts depends on its version, and admission cannot see the running version:

| Garage | Access key ID | Secret access key |
| --- | --- | --- |
| `v2.0` to `v2.2` | `GK` followed by 24 hex characters (26 total) | 64 hex characters |
| `v2.3` or newer | At least 8 characters from ASCII letters, digits, `-`, `_` and `.` | At least 16 graphic ASCII characters (`U+0021` to `U+007E`: no spaces, control characters or non-ASCII text) |

Garage v2.3 relaxed the format so keys can be migrated from other S3 providers (AWS-style `AKIA...` IDs, MinIO keys). The admission webhook enforces the Garage v2.3 grammar on **inline** credentials and admits anything that matches it. If the credentials only satisfy the v2.3 grammar, the webhook adds a warning, because Garage v2.0 to v2.2 reject them. Credentials read from a `secretRef` are not inspected at admission; Garage checks them.

When Garage rejects an import with HTTP 400, the `GarageKey` stays `Failed` and the `Ready` condition explains why:

```bash
kubectl get garagekey app-key -n storage \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}: {.status.conditions[?(@.type=="Ready")].message}{"\n"}'
# ImportKeyRejected: Garage rejected the imported key (HTTP 400): The specified key ID is not a valid Garage key ID ...
```

The message carries Garage's own text, never the credential, and names the Garage version the cluster reports. Upgrade Garage to v2.3 or newer, or import a key in the Garage-generated shape. The operator keeps retrying, so the key recovers once Garage accepts it.

## Admin tokens

`GarageAdminToken` creates a Kubernetes Secret containing static bootstrap material. It does not create a revocable, Garage-assigned token row. The referenced token must be loaded by the Garage process and used by `GarageCluster.spec.admin.adminTokenSecretRef` or another Admin API client.

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageAdminToken
metadata:
  name: operator-admin
  namespace: storage
spec:
  clusterRef:
    name: garage
  secretTemplate:
    name: garage-admin-token
    tokenKey: admin-token
    includeEndpoint: true
```

`spec.name` and expiry fields are compatibility-only for this resource and are rejected or have no effect according to the current webhook contract. Use Garage's own token lifecycle when you need revocation semantics.

The Admin-token `secretTemplate` also accepts `labels`, `annotations`,
`includeEndpoint`, and `endpointKey`; the defaults are `includeEndpoint: true`
and `endpointKey: admin-endpoint`. See the [custom-resource reference](../reference/custom-resources.md#garageadmintoken)
for the complete field contract.

## Website hosting

Enable a bucket website with `website`. The cluster's `webApi` is enabled by default and serves bucket hostnames beneath its root domain.

```yaml
spec:
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
```

Set `spec.webApi.rootDomain` and publish the web API Service through the network path appropriate for your cluster. `status.websiteUrl` is populated once the bucket has an alias and the website configuration is applied. Advanced S3 website options such as routing rules must be configured through the S3 API.

When a `GarageKey` has exactly one `bucketRef`, set `secretTemplate.includeWebsiteUrl: true` to copy that bucket's observed `status.websiteUrl` into the generated Secret. The key defaults to `website-url` and can be changed with `websiteUrlKey`; the field is omitted until the bucket publishes a non-empty URL. Set `spec.webApi.scheme: https` when TLS is terminated by the proxy or load balancer in front of Garage.

### Exposing a website bucket through an Ingress or HTTPRoute

`spec.websiteExposure` lets the operator create an Ingress or Gateway API
`HTTPRoute` that routes a hostname to the cluster's web API Service, so a
website-enabled bucket is reachable at its alias hostname without exposing the
Service yourself.

```yaml
spec:
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
  websiteExposure:
    # hostnames: [site.example.com, www.example.com]   # default: <globalAlias><webApi.rootDomain>;
    #   for ingress only the canonical host or the global alias are accepted
    # Either ingress or gateway — not both.
    ingress:
      ingressClassName: traefik
      # tlsSecretName: site-tls   # Ingress TLS section only (bucket's namespace)
    # gateway:
    #   parentRefs:
    #     - name: garage-gateway
    #       namespace: gateway   # omit for the bucket's namespace
    #       kind: Gateway
    #       sectionName: web
    #   # labels: { external-dns.alpha.kubernetes.io/hostname: site.example.com }
    # # Optional backend override (e.g. a ServiceImport):
    # # backendRef:
    # #   name: garage
    # #   kind: ServiceImport
    # #   group: multicluster.x-k8s.io
    # #   namespace: garage-ns
```

The resource is named `<bucket>-website` and is created **in the bucket's
namespace**, controller-owned by the bucket (garbage-collected with it).
`websiteExposure` requires `spec.website.enabled: true`.

- **Ingress** is only valid when the bucket and its cluster share a
  namespace, because an Ingress backend cannot cross namespaces. Its backend
  is the cluster's web API Service in that namespace (`<cluster>-gateway`
  for unified clusters, `<cluster>` otherwise). Ingress exposure is opt-in:
  install the chart with `ingress.enabled: true` (the operator's
  `--enable-ingress` flag), which also grants the operator its
  `networking.k8s.io/ingresses` RBAC. Without it the `WebsiteExposed`
  condition reports `IngressDisabled` and no Ingress is created. (v0.8.0
  granted Ingress access unconditionally; see the
  [upgrade notes](../operations/upgrades.md#v080-to-v081-ingress-exposure-is-opt-in).)
- **HTTPRoute** works cross-namespace: the route is created in the bucket's
  namespace and its backendRef points at the cluster's web API Service in
  the cluster's namespace. That cross-namespace backend needs a Gateway API
  `ReferenceGrant` in the **cluster's** namespace (owned by the storage
  admin) allowing HTTPRoutes from the bucket's namespace. HTTPRoute
  exposure also requires the Gateway API CRDs and the operator started with
  `--enable-gateway-api` (or the chart's `gatewayAPI.enabled: true`);
  without them the `WebsiteExposed` condition reports
  `GatewayAPIUnavailable`.

The routed hostnames default to the single canonical
`<globalAlias><webApi.rootDomain>`; list `hostnames` to route more (no
wildcards, no duplicates). Garage resolves the bucket from the `Host`
header and falls back to the full Host as the alias, so a hostname equal to
the global alias also works. For an `HTTPRoute`, a hostname that is neither
canonical nor the bare alias gets a `URLRewrite` filter rewriting the Host
header to the canonical host. For an `Ingress`, which has no such rewrite,
only the canonical hostname and the global alias are accepted — any other
hostname is refused on the `WebsiteExposed` condition (use a `gateway`
exposure to route additional hostnames). `tlsSecretName` (under `ingress`)
fills the Ingress `spec.tls` section; for an `HTTPRoute` TLS is configured
on the parent `Gateway`.

The `WebsiteExposed` condition and `status.websiteExposure` surface the
resource (type, name, hostnames) and, for an `HTTPRoute`, the per-parent
`Accepted`/`ResolvedRefs`/`Ready` states the Gateway controller reports on
the route's `status.parents` — so readiness reflects the Gateway actually
accepting the route and resolving its backend, not just the object existing.

## Lifecycle rules

Garage evaluates lifecycle rules asynchronously, normally in its daily lifecycle worker. The operator supports expiration by age/date, prefix and object-size filters, and aborting incomplete multipart uploads; tag filters are not supported.

```yaml
spec:
  lifecycle:
    rules:
      - id: expire-logs
        status: Enabled
        filter:
          prefix: logs/
        expirationDays: 30
      - id: abort-stale-uploads
        status: Enabled
        abortIncompleteMultipartUploadDays: 7
```

Use `spec.lifecycle.rules: []` to remove all rules. Omitting `spec.lifecycle` leaves existing rules unchanged. Check `status.lifecycleRules` and the `LifecycleConfigured` condition; on Garage versions before `v2.3.0`, the rule may be accepted but not applied.

## Bucket operations

Trigger cleanup of old incomplete multipart uploads with annotations:

```bash
kubectl annotate garagebucket app-data -n storage \
  garage.rajsingh.info/cleanup-mpu=true \
  garage.rajsingh.info/cleanup-mpu-older-than=48h
```

The annotation is removed after success and retained for retry after failure. See the [operations reference](../reference/operations.md) for the complete annotation table.
