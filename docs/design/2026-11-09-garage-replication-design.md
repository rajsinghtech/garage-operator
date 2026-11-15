# GarageReplication: cross-cluster object replication

Status: **implemented, behind `--enable-replication`.** The work lands in two
stacked changes, merged together:

1. **API**: the `GarageReplication` CRD, its schema validation, the admission
   webhook and the `GarageReferenceGrant` kind.
2. **Controller**: the rclone Job engine, the `--enable-replication` gate, CI
   coverage of the engine (a contract job running the Job script in the
   pinned rclone image, and a Kind e2e scenario) and the user guide.

"Review decisions" at the end records what changed after the first review of
the combined proposal (#580).

## Problem

Garage replicates data between the nodes of **one** cluster (the layout and
`replication.factor`). It has nothing that replicates between two
**independent** clusters: no bucket replication, no change feed, no bucket
notifications. Users want two things from the operator:

1. **Replication**: keep a warm copy of a production cluster's buckets on
   another cluster.
2. **Migration**: move objects to a new cluster with a short write freeze.

Today they write their own CronJobs around `rclone` or `aws s3 sync`. Each team
works out credentials, path-style addressing, regions, deletion safety and
monitoring again.

### Not a backup

rclone `copy`/`sync` is replication. There are no point-in-time snapshots and
no restore, and in `Mirror` mode an accidental deletion or overwrite on the
source reaches the destination on the next run. Bucket backups need a snapshot
tool (kopia, restic) and a separate design: the existing Kubernetes backup
operators (k8up, VolSync, Kopiur) only take PVCs as sources. The API and the
docs do not use backup wording, and there is no archive mode.

## Constraints and upstream semantics

- **S3 only.** The two clusters share no RPC secret, layout or metadata.
  Everything goes through the public S3 API. Garage's internal tables (keys,
  bucket IDs, aliases, permissions, quotas, website config, lifecycle,
  `node_key`) are **not** copied, and copying them between clusters is out of
  scope.
- **No change feed.** Garage has no event notifications or replication log.
  Every run lists both sides. A run is incremental in what it **transfers**,
  not in what it **lists**: listing a bucket costs O(objects) on each run.
- **No object versioning.** Garage does not implement S3 versioning or object
  lock.
- **Checksums.** For a single-part upload Garage's ETag is the hex MD5 of the
  body, so size + MD5 is a reliable comparison. A multipart ETag is not an MD5
  of the object (`md5-of-part-md5s-N`). For multipart objects that rclone did
  not upload itself, the comparison falls back to size only.
- **Signing.** SigV4 needs the cluster's `s3_api.s3_region` (default `garage`)
  and path-style addressing.
- **Not tied to the operator's cluster.** Either side may be a GarageCluster in
  this Kubernetes cluster, a Garage in another Kubernetes cluster, or a Garage
  outside Kubernetes (Helm, bare metal). The copy runs where the
  `GarageReplication` lives and only needs network reach to both S3 endpoints.
- **Repository conventions.** The new CRD is `v1beta1`, like every CRD except
  GarageCluster. Cross-namespace `clusterRef` goes through a
  `GarageReferenceGrant`. Optional features are off behind a flag. One-shot
  actions use annotations that are removed once handled, with the result in
  `status.lastOperation`.

## Replication engine

| Option | For | Against |
|---|---|---|
| **rclone in a Job** (selected) | Mature S3 → S3 `copy` / `sync` / `check`: size+MD5 comparison (`--checksum`), concurrency, bandwidth limit, retries, a deletion cap (`--max-delete`), metadata copy (`-M`), JSON logs with a final stats block. Configured through env vars, so credentials never appear in args. | A third-party image the operator does not build: pinned by digest, overridable for air-gapped installs. Stats come from parsing its output. |
| `aws s3 sync` / `mc mirror` | Common tools. | `aws s3 sync` compares size and mtime only and cannot cap deletes. `mc mirror` is AGPL with weaker deletion guards. |
| Native Go (aws-sdk-go-v2) | One image, typed stats. | Re-implements listing/diff, multipart streaming, retries and bandwidth limits: a lot of data-path code to own. |

**Decision: rclone, run as a Kubernetes Job**, upstream `rclone/rclone` image
pinned by digest (`--replication-image` to override). The CRD exposes no
rclone flags, so the engine can change later without an API change.

How the Job is configured:

- Remotes come from env vars (`RCLONE_CONFIG_SRC_*`, `RCLONE_CONFIG_DST_*`,
  provider `Other`, path style). The access key ID and secret use
  `valueFrom.secretKeyRef`; the operator never reads secret **values**.
- Base flags: `--checksum`, `-M`, `--s3-no-check-bucket` (never create
  buckets), JSON logs at NOTICE level.
- A small POSIX `sh` script (busybox in the rclone image) runs rclone and
  writes one bounded `key=value` line to `/dev/termination-log`: exit code,
  fixed failure reason, verification result and rclone counters. No object
  name or rclone error text reaches status.
- Failures are classified by rclone's exit code first, as measured against
  rclone 1.75.2 by the contract tests: 3 (directory not found, a missing source
  bucket) is `BucketNotFound`; 5 (retryable errors left after the retries:
  connection refused, timeouts, 5xx) is `EndpointUnreachable`; in `Mirror`, 7
  (fatal error, which only `--max-delete` and `--max-delete-size` raise with
  these flags) is `MaxDeletesExceeded`. Exit code 1 covers both an
  authentication failure and a missing destination bucket (a PUT answered
  404 `NoSuchBucket`), so the log decides those two; anything else is
  `TransferErrors`.
- API sizes (`bandwidthLimit`, `mirror.maxDeleteSize`) are bytes; a bare number
  gets a `B` suffix because rclone reads it as KiB.

## API

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReplication
metadata:
  name: production-to-dr
  namespace: storage
spec:
  source:
    # Exactly one of clusterRef | endpoint.
    clusterRef:                # operator-managed GarageCluster or management handle
      name: garage-prod
      namespace: storage       # cross-namespace needs a GarageReferenceGrant
    credentialsSecretRef:      # in the GarageReplication namespace; must opt in
      name: prod-replication-reader
      # accessKeyIdKey: access-key-id          (default; same as GarageKey Secrets)
      # secretAccessKeyKey: secret-access-key  (default)
  destination:
    endpoint:                  # any Garage, anywhere
      url: https://s3.dr.example.com   # scheme + host[:port] only
      region: garage           # default "garage"
      caBundleRef:             # optional: ConfigMap key with a PEM CA
        name: dr-ca
        key: ca.crt            # default
    credentialsSecretRef:
      name: dr-replication-writer

  buckets:                     # list-map keyed by destination; 1..50
    - source: medias
      destination: medias
    - source: pg-dumps
      destination: pg-dumps-dr

  schedule: "*/15 * * * *"     # optional; empty = runs only on trigger-sync
  suspend: false

  mode: Copy                   # Copy (default) | Mirror
  mirror:                      # required with mode Mirror, rejected otherwise
    maxDeletes: 1000           # per bucket per run; the run stops once reached
    maxDeleteSize: "10G"       # optional cap on deleted bytes per bucket per run

  verification: None           # None | Check (rclone check after the copy)

  transfer:
    concurrency: 4
    checkers: 8
    bandwidthLimit: "50M"      # bytes/s with K, M, G suffix; empty = unlimited
    maxConcurrentBuckets: 1

  retry:
    backoffLimit: 2
    activeDeadlineSeconds: 21600

  resources: {}
  podTemplate: {}              # labels, annotations, nodeSelector, tolerations,
                               # affinity, priorityClassName
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 3
```

API decisions:

- **`mode`, not `deletionPolicy`.** `GarageBucket.spec.deletionPolicy` already
  means "what happens to the Garage bucket when the CR is deleted". Deleting a
  `GarageReplication` never touches object data, in either mode.
- **Buckets are a list-map keyed by `destination`.** `destination` is required
  (a schema default cannot copy another field), so the API server itself
  rejects two entries writing the same bucket, and server-side apply merges
  entries by destination. The same source may feed several destinations.
  `status.buckets` uses the same key.
- **Credentials must opt in.** The Job sends the access key ID to the
  endpoint, which the creator of the `GarageReplication` chooses. If any Secret
  could be named, `create garagereplications` would amount to `get secrets`.
  The controller therefore only uses a Secret labelled
  `garage.rajsingh.info/replication-credentials: "true"`. Only someone who can
  write the Secret can add that label. Secrets generated for a `GarageKey` are
  not exempt: otherwise anyone allowed to create a `GarageReplication` could
  use another application's key in the namespace and copy its buckets to an
  endpoint of their choice. A `GarageKey` opts in through
  `spec.secretTemplate.labels`. The check runs in the controller, before
  any Job is created and on every run, not in admission: the Secret may not
  exist yet when the `GarageReplication` is applied, and the label can be
  removed later. A Secret that does not opt in sets `Ready=False` with reason
  `CredentialsNotAllowed`.
- **CA bundles come from ConfigMaps only.** A CA certificate is public, and a
  Secret reference would reopen the exfiltration path above.
- **`clusterRef` gets the endpoint and region** from the referenced
  GarageCluster through `ResolveS3Endpoint` and its `s3Api.region`, which
  covers managed clusters and management handles. `GarageReferenceGrant`'s
  `from.kind` enum gains `GarageReplication`.
- **Engine-neutral, no escape hatch.** No raw rclone flags and no `extraArgs`:
  they would allow destructive or credential-leaking behaviour (`--delete-*`,
  `--dump headers`) outside the validated model. No TLS skip-verify option.
- **Typed status.** `phase`, run reasons, results, verification results, holds
  and failure reasons are enums.

### Validation

The API is correct without the webhook. The CRD schema enforces:

- S3 bucket names (pattern, 3–63 characters) on both `source` and
  `destination`, and unique destinations (list-map key).
- Exactly one of `clusterRef` / `endpoint` per side, and no
  `clusterRef.kubeConfigSecretRef`.
- `endpoint.url`: `http(s)://host[:port]` with no path, query, fragment or
  credentials; `region` format.
- Secret and ConfigMap names (DNS-1123 subdomain) and data keys, and different
  `accessKeyIdKey` / `secretAccessKeyKey`.
- `mirror` set if and only if `mode: Mirror`; `maxDeletes ≥ 1`, so Mirror
  cannot be uncapped by omission.
- A bucket replicated onto itself between two identical endpoint URLs. The
  comparison is exact: Kubernetes 1.25 costs `lowerAscii()` as unbounded and
  rejects the CRD, so normalization is left to the webhook.
- Enums, bounds and `maxLength` on every string.

The webhook adds what needs context or cannot be written in CEL:

- the `GarageReferenceGrant` of a cross-namespace `clusterRef`;
- **destination exclusivity**: a destination bucket on a given destination
  cluster can be written by only one `GarageReplication`, whatever the
  namespace or mode (two Mirrors would delete each other's objects). The
  destination cluster is identified by its `clusterRef` (namespace defaulted)
  or by the normalized URL (lowercase, no trailing slash, no default port).
  The older object keeps the bucket. The check uses the informer cache, so it
  sees only the namespaces the operator watches. It is cluster-wide and first
  come, first served: a namespace can claim a destination bucket name before
  another one, and the error names the other object only when it is in the
  same namespace;
- the self-loop when a `clusterRef` namespace is implicit or URLs differ by
  case, a trailing slash or a default port (the CEL rule on unbounded `ClusterReference`
  strings exceeds the cost budget);
- the cron expression (`robfig/cron/v3`, the CronJob parser) and Pod label and
  annotation keys;
- warnings for `Mirror`, for same-cluster replication, and that the object is
  not reconciled while `--enable-replication` is off.

The controller re-runs the same checks before starting Jobs, including
destination exclusivity (two objects admitted concurrently, or created while
the webhook was unavailable), and also compares resolved URLs, so a
`clusterRef` and an `endpoint` that reach the same cluster are detected. The
loser gets `Ready=False` with reason `DestinationConflict` and runs nothing.

## Deletion semantics

| Mode | rclone | Source delete | Source overwrite | Destination-only objects |
|---|---|---|---|---|
| `Copy` (default) | `copy` | kept on destination | destination overwritten | kept |
| `Mirror` | `sync --max-delete N` | deleted on destination | destination overwritten | **deleted** |

- Nothing destructive is on by default. `Copy` still **overwrites** changed
  objects; the docs say this plainly.
- **First Mirror run waits for a person.** A Mirror bucket whose last Job did
  not run in Mirror mode (a new replication, or one switched from Copy) gets
  `hold: AwaitingTrigger`; switching back to Copy drops it. The first deletions happen only after a
  `trigger-sync` annotation, once someone has checked source and destination.
- **Empty-source guard.** Before `sync`, the script checks whether the source
  lists empty while the destination does not. If so it refuses (exit 64,
  reason `SourceEmpty`): a wrong bucket, a key with an empty view or a wiped
  source would otherwise empty the destination.
- **`maxDeletes`, `maxDeleteSize`.** rclone deletes up to N objects (and, when
  set, up to that many bytes), then aborts (exit 65, reason
  `MaxDeletesExceeded`).
- **Safety hold.** `podFailurePolicy` fails the Job on exit 64 and 65 without
  retrying, because a retry would delete another N objects. The bucket is then
  held (`status.buckets[].hold`) and scheduled runs skip it. **Only the
  `trigger-sync` annotation releases a hold.** Editing the spec does not: an
  unrelated edit (bandwidth, resources) must not re-arm deletions.
- Switching from `Mirror` to `Copy`, or removing a bucket from the spec,
  cancels a running Job of that bucket instead of letting it finish.

## Reconciliation

A standalone `GarageReplicationReconciler`. It only **reads** GarageClusters
(for endpoints) and `Owns()` the `batch/v1` Jobs it creates. It never calls
the Admin API.

Operator-created Jobs, not a CronJob: scheduled runs, `trigger-sync` runs,
per-bucket Jobs with a parallelism cap and the cancel-on-downgrade rule would
otherwise be split between the CronJob controller and the operator. One code
path that owns every Job keeps "at most one run per bucket" a single
invariant.

Loop:

1. Resolve references: endpoints, Secrets and their opt-in, CA ConfigMaps,
   reference grants, destination exclusivity. On failure set `Ready=False`
   with a fixed reason and create no Job.
2. Record finished Jobs into `status.buckets` from their termination message;
   a Job deleted by a person is recorded as `Cancelled`. Prune history.
3. Cancel Jobs per the downgrade rule.
4. Decide whether a run is due: `trigger-sync` (also while suspended, and the
   only way to release holds), or the cron time. Missed runs collapse into one.
5. Persist the run in `status.currentRun` **before** creating Jobs, then
   remove the trigger annotation. Job names
   `<name>-<runID>-<hash(source/destination)>` are deterministic, so a retried
   reconcile never creates a second Job.
6. Close the run once every participating bucket has a result.

Job shape: `restartPolicy: Never`, `backoffLimit`, `activeDeadlineSeconds`,
owner reference to the `GarageReplication`. Pod security: non-root,
read-only root filesystem, all capabilities dropped, RuntimeDefault seccomp,
no service account token. rclone stops on SIGTERM; single-part PUTs are
atomic, and an interrupted multipart upload is cleaned up by an
`abortIncompleteMultipartUpload` lifecycle rule.

No finalizer: owner references garbage-collect the Jobs, and object data on
either side is never touched.

**Feature gate.** `--enable-replication` (chart `replication.enabled`, default
`false`) controls the controller, the Job informer and the `batch/jobs` RBAC.
While it is off, the webhook warns that new objects will not be reconciled.

## Status and observability

```yaml
status:
  observedGeneration: 4
  phase: Syncing              # Pending | Idle | Syncing | Suspended | Failed
  lastScheduleTime: ...
  lastSyncTime: ...           # last run that finished, any result
  lastSuccessfulSyncTime: ... # last run where every bucket succeeded
  nextSyncTime: ...
  currentRun: { id: t5bz2c, reason: Scheduled, startTime: ..., buckets: [medias] }
  lastRun: { id: t5bz0g, reason: Scheduled, result: Succeeded, completionTime: ... }
  buckets:                    # list-map keyed by destination
    - destination: medias
      source: medias
      activeJob: production-to-dr-t5bz2c-1f2e3d4c
      lastResult: Succeeded   # Succeeded | Failed | Cancelled
      lastMode: Copy          # mode of the last Job; Mirror without a Mirror Job waits for a trigger
      lastStatistics: { transfers: 1250, bytes: 1073741824, checks: 98012, deletes: 0, errors: 0, elapsedSeconds: 41 }
      lastVerification: Passed
      hold: ""                # SourceEmpty | MaxDeletesExceeded | AwaitingTrigger
      lastError: ""           # fixed reason, never raw rclone output
  lastOperation: { type: TriggerSync, triggeredAt: ..., succeeded: true }
  conditions:
    - type: Ready             # e.g. CredentialsNotAllowed, DestinationConflict
    - type: Synced            # NeverSynced | SyncFailed | SafetyHold | ConfigChanged | Synced
    - type: Suspended
```

- Statistics are rclone's counters for the **last run** of each bucket. There
  is no replication lag (no change feed). A run whose termination message
  cannot be parsed gets `lastStatistics: null`, never zeros.
- `lastError` is a fixed reason: `AuthFailed`, `BucketNotFound`,
  `EndpointUnreachable`, `SourceEmpty`, `MaxDeletesExceeded`,
  `VerificationFailed`, `DeadlineExceeded`, `TransferErrors` or `Unknown`.
- Metrics (gauges derived from status): last success timestamp, last failed,
  last transferred bytes, held; labelled by namespace, replication, source and
  destination bucket.

## Migration workflow

| Step | Action |
|---|---|
| 1 | Recreate buckets and keys on the new cluster declaratively (see next section). |
| 2 | Create a `GarageReplication` (`mode: Copy`, a schedule). |
| 3 | Scheduled runs keep the destination close to the source while apps keep writing to the source. |
| 4 | Freeze writes: scale the writers down, or drop `write` from their GarageKey permissions on the source. |
| 5 | Final sync: set `mode: Mirror` (if source deletions must reach the destination) and `verification: Check`, then annotate `garage.rajsingh.info/trigger-sync`. |
| 6 | Wait until `lastSuccessfulSyncTime` is after the freeze and `Synced=True` with 0 differences. |
| 7 | Point apps at the destination. |
| 8 | `suspend: true`, or delete the `GarageReplication` (data is not touched). |

Limitations:

- **Not point-in-time.** A run lists while writes continue; only a write
  freeze makes the final sync complete.
- **Deletes in `Copy` mode are never propagated.** Anything written only to
  the destination before cutover is deleted by the final `Mirror` run
  (subject to `maxDeletes`).
- **No bidirectional or active-active replication.**
- **Metadata fidelity.** Content-Type and user metadata are copied.
  `Last-Modified` becomes the destination upload time. Multipart objects get
  different ETags. In-progress multipart uploads are not copied.
- **Listing cost.** Each run lists every object on both sides.

## Configuration and identity: what is *not* replicated

| Layer | Replicated? | How to carry it over |
|---|---|---|
| Objects and user metadata | **Yes** | this CRD |
| Buckets, aliases, quotas, website, lifecycle | No | `GarageBucket` CRs on the destination cluster |
| Access keys | No | `GarageKey` with `importKey.secretRef` reusing the same key ID and secret |
| Bucket ↔ key permissions | No | `GarageKey.bucketPermissions` / `GarageBucket.keyPermissions` |
| Cluster config, layout, node IDs, admin tokens | No, never | `GarageCluster` spec |

### Least privilege

- Source key: `read` on the listed buckets only.
- Destination key: `read` + `write` on the destination buckets (Garage's
  `write` includes delete). No `owner`, no bucket creation.

## Alternatives considered

- **Garage-level replication (shared RPC, federation).** That is
  `remoteClusters` and gives one cluster, not two independent ones.
- **A native Garage feature.** Garage has no bucket replication API, change
  feed or notifications. A change feed upstream would make runs incremental;
  the engine-neutral API leaves room for it.
- **Fields on `GarageBucket` (`spec.replicateTo`).** Ties replication to
  buckets the operator manages; external-to-external replication would be
  impossible.

## Compatibility and data safety

- Additive: a new CRD and a controller behind a disabled-by-default flag.
  While the flag is off, objects are accepted, not reconciled, and admission
  warns about it.
- Destructive behaviour needs an explicit `mode: Mirror`, a manual first
  trigger, and is capped by `maxDeletes` and the empty-source guard.

## Test plan

- **Schema (envtest):** valid objects and defaults; every schema
  rule above is rejected by the API server without the webhook
  (`internal/controller/garagereplication_schema_test.go`).
- **Webhook:** reference grants, destination exclusivity
  (ordering, URL normalization, implicit namespaces), self-loops, cron, Pod
  metadata keys, warnings.
- **Controller unit tests** (`garagereplication_controller_test.go`): Job
  rendering (no secret value in the Job), credential opt-in, CA from a
  ConfigMap, hold release only by `trigger-sync`, first Mirror run held (new
  or switched from Copy), destination conflicts through resolved URLs, run
  bookkeeping.
- **Contract tests in CI** (`test/contract/replication_contract_test.go`, the
  Garage Contract workflow): the Job's container run with Docker in the pinned
  image, as UID 65532 on a read-only root filesystem, against two Garage
  processes: Copy, Mirror, both delete caps and the empty-source guard with
  their exit codes, metadata, verification, failure reasons, SIGTERM. The
  workflow sets `REPLICATION_CONTRACT_REQUIRED=true` so the test fails instead
  of skipping without a container runtime.
- **Kind e2e** (`Label("replication")`, two GarageClusters): Copy, Mirror with
  the first trigger, both guards with hold and release, and the migration
  sequence.

## Review decisions

From the review of the combined proposal (#580):

1. Scope narrowed to replication and migration: the `Archive` mode and all
   backup wording are removed.
2. Credentials need an opt-in label on the Secret, GarageKey-generated
   Secrets included; CA bundles come from ConfigMaps only.
3. A hold is released only by `trigger-sync`, never by a spec edit; the first
   Mirror run waits for a trigger.
4. Destination buckets are exclusive across `GarageReplication`s (webhook and
   controller).
5. Validation moved into the schema; `buckets[]` and `status.buckets` are
   list-maps keyed by `destination`; status fields are typed enums.
6. The engine is tested in CI: the contract job runs the Job script in the
   pinned rclone image, and the Kind `replication` e2e runs two
   GarageClusters.

From the review of the API change:

7. The opt-in label is required on every credentials Secret, GarageKey
   Secrets included (a GarageKey sets it through `spec.secretTemplate.labels`).
8. Admission warns that objects are not reconciled while
   `--enable-replication` is off.
9. The destination conflict error does not name an object of another
   namespace; destination exclusivity is documented as cluster-wide, first
   come, first served.

Non-blocking items taken in the controller change: a size-based delete cap
(`mirror.maxDeleteSize`), classification by rclone exit code first, the first
Mirror run waiting for a trigger (also after a switch from Copy, tracked by
`status.buckets[].lastMode`), typed status enums with list-maps, and comparing
resolved URLs for same-cluster and destination-conflict detection.

## Deferred

`--max-age` top-up runs between full listings; per-bucket prefix filters;
server-side checksums once the supported floor is confirmed; bidirectional
sync (not planned); a bucket/key configuration export helper for migrations;
bucket backups with snapshots (separate design).
