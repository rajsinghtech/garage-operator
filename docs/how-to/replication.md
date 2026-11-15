# Replicate between clusters

`GarageReplication` copies objects between two **independent** Garage clusters
through their S3 APIs. Use it to:

- **Replicate**: keep a warm copy of production buckets on another cluster.
- **Migrate**: move buckets to a new cluster with a short write freeze.

It is **not a backup**. There are no point-in-time snapshots and no restore,
and in `Mirror` mode an accidental deletion or overwrite on the source reaches
the destination on the next run. Bucket backups need a snapshot tool.

It is also different from Garage's own replication (`replication.factor`),
which spreads data across the nodes of one cluster, and from
[federation](federation.md), which joins several Kubernetes clusters into one
Garage cluster. Two clusters linked by `GarageReplication` share nothing: no
RPC secret, no layout, no keys.

## How it works

Each run starts one Kubernetes Job per bucket, in the `GarageReplication`'s
namespace. The Job runs [rclone](https://rclone.org) (image
`docker.io/rclone/rclone`, pinned by digest) to compare the source and
destination buckets and copy what differs. The operator:

- schedules runs (cron), never runs two at once, and runs at most
  `transfer.maxConcurrentBuckets` buckets in parallel;
- passes credentials to rclone only through `secretKeyRef` environment
  variables. They never appear in the Job's arguments, in status or in the
  operator's logs, and the operator never reads their values;
- reads each Job's result from its termination message and records rclone's
  counters per bucket in `status.buckets`;
- deletes old Jobs (`successfulJobsHistoryLimit: 1`, `failedJobsHistoryLimit: 3`).

The Jobs need network access to **both** S3 endpoints. Nothing else talks to
Garage: the operator does not use either cluster's Admin API for replication.
The Pods run as a non-root user with a read-only root filesystem, no
capabilities and no service account token, so they pass the `restricted` Pod
Security Standard.

## Enable the controller

Replication is off by default. Enable it in the chart:

```yaml
replication:
  enabled: true
  # image: registry.example.com/mirror/rclone:1.75.2   # optional mirror
```

This adds `--enable-replication` to the operator and grants it
`create/delete/get/list/watch` on `batch/jobs` and write access to
`GarageReplication` status. Without it, `GarageReplication` objects are
validated but not reconciled, and `kubectl apply` prints a warning saying so.

## Credentials (least privilege)

Each side reads an S3 access key from a Secret **in the replication's
namespace**. The Job sends that key to the endpoint named in the spec, so the
Secret must **opt in** with the label
`garage.rajsingh.info/replication-credentials: "true"`. Without the label the
replication reports `Ready=False` with reason `CredentialsNotAllowed` and runs
nothing. Only someone who can write the Secret can add the label, so being
allowed to create a `GarageReplication` does not let anyone copy another
application's buckets with its key.

The default data keys, `access-key-id` and `secret-access-key`, are the ones a
`GarageKey` writes. Set the label through the key's Secret template:

```yaml
# Read-only key on the source cluster
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: replication-reader
  namespace: replication
spec:
  clusterRef:
    name: garage
    namespace: storage          # needs a GarageReferenceGrant for kind GarageKey
  secretTemplate:
    labels:
      garage.rajsingh.info/replication-credentials: "true"
  bucketPermissions:
    - globalAlias: medias
      read: true
```

| Side | Permissions |
|---|---|
| Source | `read` on every source bucket |
| Destination | `read` + `write` on every destination bucket (Garage's `write` includes deletes, which `Mirror` needs) |

No `owner` permission and no bucket creation are needed. Replication never
creates buckets: a missing bucket fails with `BucketNotFound`. Create
destination buckets beforehand, for example with `GarageBucket`.

For a destination outside the operator's reach, create and label the Secret
yourself:

```bash
kubectl -n replication create secret generic dr-replication-writer \
  --from-literal=access-key-id=GK... --from-literal=secret-access-key=...
kubectl -n replication label secret dr-replication-writer \
  garage.rajsingh.info/replication-credentials=true
```

A private CA for an `endpoint` comes from a **ConfigMap** (`caBundleRef`,
key `ca.crt` by default). A CA certificate is public; a Secret reference would
reopen the path the opt-in closes.

## Examples

### Replicate to another site

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReplication
metadata:
  name: production-to-dr
  namespace: replication
spec:
  source:
    clusterRef: {name: garage, namespace: storage}   # needs a GarageReferenceGrant
    credentialsSecretRef: {name: replication-reader}
  destination:
    endpoint:
      url: https://s3.dr.example.com
      region: garage
      caBundleRef: {name: dr-ca}      # only for a private CA
    credentialsSecretRef: {name: dr-replication-writer}
  buckets:
    - source: medias
      destination: medias
    - source: pg-dumps
      destination: pg-dumps-dr
  schedule: "*/15 * * * *"
```

`buckets` is keyed by `destination`: a destination bucket appears once, and the
same source may feed several destinations.

A cross-namespace `clusterRef` needs a grant in the cluster's namespace:

```yaml
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReferenceGrant
metadata:
  name: allow-replication
  namespace: storage
spec:
  from:
    - kind: GarageReplication
      namespace: replication
  to:
    - kind: GarageCluster
      name: garage
```

### One-shot copy

Without `schedule`, a `Copy` replication runs once when it is created, then
only when triggered:

```bash
kubectl -n replication annotate garagereplication production-to-dr \
  garage.rajsingh.info/trigger-sync="$(date +%s)" --overwrite
```

## Deletion semantics

Nothing destructive is enabled by default.

| `mode` | Source object deleted | Source object changed | Object only on the destination |
|---|---|---|---|
| `Copy` (default) | kept on the destination | **overwritten** on the destination | kept |
| `Mirror` | deleted on the destination | overwritten | **deleted** |

`Copy` does not make the destination immutable: changed objects are
overwritten.

Safety guards for `Mirror`:

- **First run on a trigger.** A bucket that has not run in `Mirror` mode yet
  (a new replication, or one switched from `Copy`) is held with
  `hold: AwaitingTrigger` and `Synced=False/AwaitingTrigger`. Check both sides,
  then set the `trigger-sync` annotation to start it. Later scheduled runs
  need no trigger.
- **Delete caps.** `mirror.maxDeletes` is required; `mirror.maxDeleteSize`
  (for example `10G`) optionally caps the deleted bytes too. A run that
  reaches either cap stops with `MaxDeletesExceeded`. Deletions made up to
  that point are kept.
- **Empty source.** If the source bucket is empty while the destination is
  not, the run refuses to start (`SourceEmpty`). This protects against a wrong
  bucket name, a key that sees nothing, or a wiped source.
- **Hold.** After a cap or the empty-source guard trips, the bucket is
  **held**: `status.buckets[].hold` is set, `Synced=False/SafetyHold`, scheduled
  runs skip it, and the Job is not retried, so the next run does not delete
  another batch. **Only the `trigger-sync` annotation releases a hold.**
  Editing the spec (for example raising `maxDeletes`) does not: investigate,
  adjust the spec if needed, then trigger.

Changing `mode` from `Mirror` to `Copy` cancels running `Mirror` Jobs and drops
`AwaitingTrigger` holds (`Copy` never deletes). Removing a bucket from
`spec.buckets`, or giving its destination another source, cancels its running
Job. Other changes apply from the next run; the running Job finishes with the
configuration it started with.

A destination bucket can be written by only one `GarageReplication`, across
all namespaces: two `Mirror`s on one bucket would delete each other's objects.
The first one keeps it; admission rejects the second, and if one slips through
(created while the webhook was down, or naming the same cluster through a
`clusterRef` and a URL) it reports `Ready=False/DestinationConflict` and runs
nothing. A conflicting object in another namespace is not named.

Deleting a `GarageReplication` deletes its Jobs (owner references) and never
touches objects on either side.

## Operate

| Action | How |
|---|---|
| Pause | `spec.suspend: true`. No scheduled run starts; a running run finishes. |
| Stop now | `kubectl delete job -l garage.rajsingh.info/replication-uid=<uid>`. The bucket is recorded as `Cancelled`. |
| Resume | `spec.suspend: false`. |
| Run now, release holds | `garage.rajsingh.info/trigger-sync=<unique value>`. Works while suspended. If a run is in progress, the triggered run starts right after it. The annotation is removed once the run starts, and `status.lastOperation` records it. |

```console
$ kubectl get garagereplications -n replication
NAME               MODE   SCHEDULE       PHASE     LAST SUCCESS   AGE
production-to-dr   Copy   */15 * * * *   Syncing   14m            3d
```

`status` reports:

- `phase`: `Pending` (configuration not usable, see `Ready`), `Idle`,
  `Syncing`, `Suspended` or `Failed` (the last run had a failed bucket);
- `currentRun` / `lastRun`: ID, reason (`Initial`, `Scheduled`,
  `Triggered`), start and completion time, result;
- `lastSyncTime`, `lastSuccessfulSyncTime`, `nextSyncTime`;
- `buckets[]`, keyed by `destination`: `activeJob`, `lastResult`, `lastMode`,
  `lastSuccessfulTime`, `hold`, `lastError`, `lastVerification`, and
  `lastStatistics` (`transfers`, `bytes`, `checks`, `deletes`, `errors`,
  `elapsedSeconds`, `differences`). The statistics are rclone's own counters
  for the last Job, and they are absent when the Job reported none (for
  example a Pod that was killed).

Conditions: `Ready` (endpoints, Secrets, opt-in, grants and destination
exclusivity resolve; reasons include `CredentialsNotAllowed`,
`DestinationConflict`, `SecretNotFound`, `ReferenceNotGranted`), `Synced`
(every bucket succeeded in the last run on the current configuration; reasons
`NeverSynced`, `SyncFailed`, `SafetyHold`, `AwaitingTrigger`, `ConfigChanged`),
`Suspended`. Events: `SyncStarted`, `SyncSucceeded`, `SyncFailed`,
`SyncCancelled`, `SyncSkipped`.

`lastError` is one of these fixed reasons, classified from rclone's exit code
first and from its log only where the exit code is ambiguous. rclone's own
output, which can name objects, stays in the Job's Pod logs.

| Reason | Meaning |
|---|---|
| `AuthFailed` | the S3 key was rejected (403) |
| `BucketNotFound` | a source or destination bucket does not exist |
| `EndpointUnreachable` | connection, timeout, server or TLS errors left after rclone's retries |
| `SourceEmpty` | empty-source guard (see above) |
| `MaxDeletesExceeded` | `maxDeletes` or `maxDeleteSize` reached (see above) |
| `VerificationFailed` | `verification: Check` found differences |
| `DeadlineExceeded` | the Job ran longer than `retry.activeDeadlineSeconds` |
| `TransferErrors` | other rclone errors; see the Pod log |
| `Unknown` | the Pod ended without a result (for example it was OOM-killed) |

Prometheus metrics (operator registry), with labels `namespace`,
`replication`, `source_bucket` and `destination_bucket`:

- `garage_operator_replication_last_success_timestamp_seconds`
- `garage_operator_replication_last_failed`
- `garage_operator_replication_last_transferred_bytes`
- `garage_operator_replication_held`

Example alert for a 15-minute schedule:

```yaml
- alert: GarageReplicationStale
  expr: time() - garage_operator_replication_last_success_timestamp_seconds > 3600
  for: 10m
```

### Tuning

| Field | Default | Effect |
|---|---|---|
| `transfer.concurrency` | 4 | objects copied in parallel per bucket (`rclone --transfers`) |
| `transfer.checkers` | 8 | objects compared in parallel per bucket (`--checkers`) |
| `transfer.bandwidthLimit` | unlimited | bytes/s per Job; `K`, `M`, `G` are KiB, MiB, GiB, e.g. `50M` (`--bwlimit`) |
| `transfer.maxConcurrentBuckets` | 1 | buckets replicated at the same time |
| `retry.backoffLimit` | 2 | Pod retries per bucket and run; already-copied objects are skipped |
| `retry.activeDeadlineSeconds` | 21600 | maximum duration of a bucket's Job |
| `verification` | `None` | `Check` re-compares source and destination after the copy |
| `resources`, `podTemplate` | | resources, node selector, tolerations, affinity, priority class, Pod labels/annotations |

Inside a run, rclone retries failed operations itself (3 attempts of the
whole bucket, 10 low-level retries). Kubernetes then retries the Pod
`backoffLimit` times, and the next scheduled run tries again.

Objects are compared by size and MD5. For objects uploaded in one part,
Garage's ETag is the MD5 of the content, so the comparison is exact. For
multipart objects that rclone did not upload itself there is no MD5, so the
comparison falls back to size only. A changed object of the same size, uploaded
in several parts by another client, is then not detected.

## Migrate to a new cluster

1. Recreate the configuration on the new cluster declaratively (see
   [What is not replicated](#what-is-not-replicated)): `GarageBucket`s, and
   `GarageKey`s with `importKey` reusing the **same** access key IDs and secrets,
   so applications only need a new endpoint.
2. Create a `GarageReplication` from the old cluster to the new one with
   `mode: Copy` and a schedule. The first run copies everything.
3. Let scheduled runs keep the new cluster close while applications write to
   the old one. Watch `lastStatistics.transfers` drop to the write rate.
4. Freeze writes: scale the writers down, or remove `write` from their keys on
   the old cluster.
5. Final sync: remove the schedule, set `mode: Mirror` (with
   `mirror.maxDeletes`) if deletions made since step 2 must reach the new
   cluster, and `verification: Check`. Then trigger a run; the trigger is also
   what lets the first `Mirror` run start:

   ```bash
   kubectl annotate garagereplication migrate garage.rajsingh.info/trigger-sync="final-$(date +%s)" --overwrite
   ```

6. Wait for `lastRun.reason: Triggered`, `lastRun.result: Succeeded`,
   `Synced=True`, and `lastVerification: Passed` with `differences: 0` on
   every bucket.
7. Point applications at the new cluster.
8. Set `suspend: true` or delete the `GarageReplication` (no data is deleted).

The Kind end-to-end test (`Label("replication")`) runs this sequence.

Limitations of this procedure:

- **A run is not a point-in-time snapshot.** It lists while writes continue;
  objects written after the listing are picked up by the next run. Only the
  write freeze in step 4 makes the final sync complete.
- **`Copy` never propagates deletions.** That is why step 5 switches to
  `Mirror`. Anything written directly to the new cluster before cutover is
  deleted by that run, up to `maxDeletes`.
- **No two-way replication.** Two `Mirror` replications in opposite directions
  delete each other's writes.
- **Object metadata.** `Content-Type`, `Cache-Control` and user metadata are
  copied. `Last-Modified` becomes the time of the copy (rclone keeps the
  original in `x-amz-meta-mtime`). Multipart objects get new ETags.
  In-progress multipart uploads are not copied.

## Switch to the replica after losing a site

1. Set `suspend: true` on the replication. If the source is unreachable, runs
   fail with `EndpointUnreachable` and change nothing on the destination.
2. Check `status.buckets[].lastSuccessfulTime`: objects written to the source
   after that time are not on the replica.
3. Recreate keys and permissions on the replica (see below) and point
   applications at it.
4. Once the original site is back, replicate in the other direction with
   `mode: Copy` first (never `Mirror` until you have checked which side holds
   which data), then cut back with the migration procedure.

## What is not replicated

Replication copies **objects and their metadata only**. Garage's internal
metadata is cluster-specific and must never be copied between clusters.

| Layer | Replicated? | How to carry it over |
|---|---|---|
| Objects and user metadata | yes | `GarageReplication` |
| Buckets, aliases, quotas, website, lifecycle rules | no | `GarageBucket` on the destination cluster (copy the manifests if the source is declarative) |
| Access keys | no | `GarageKey` with `importKey` (same ID and secret; IDs must be `GK` + 24 hex characters before Garage v2.3) |
| Bucket ↔ key permissions | no | `GarageKey.spec.bucketPermissions` / `GarageBucket.spec.keyPermissions` |
| CORS rules, website redirects and routing rules | no | S3 API |
| Cluster configuration, layout, node IDs, admin tokens | no, never | the destination's own `GarageCluster` |

## Known limitations

- Each run lists every object on both sides. Transfers are incremental, but
  the listing is not, because Garage has no change feed. For buckets with tens
  of millions of objects, use a schedule interval longer than one full listing.
- The copy runs in the operator's Kubernetes cluster. It streams through the
  Job Pod (no server-side copy between clusters), so plan network bandwidth
  and use `bandwidthLimit`.
- A `SIGTERM` (Job deleted, deadline, node drain) stops rclone cleanly. Objects
  are uploaded atomically, but an interrupted multipart upload leaves an
  incomplete upload on the destination. Add an
  `abortIncompleteMultipartUploadDays` lifecycle rule to destination buckets:

  ```yaml
  apiVersion: garage.rajsingh.info/v1beta1
  kind: GarageBucket
  metadata:
    name: medias
  spec:
    clusterRef: {name: garage-dr}
    lifecycle:
      rules:
        - id: abort-stale-uploads
          status: Enabled
          abortIncompleteMultipartUploadDays: 2
  ```
