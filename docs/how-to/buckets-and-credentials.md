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
