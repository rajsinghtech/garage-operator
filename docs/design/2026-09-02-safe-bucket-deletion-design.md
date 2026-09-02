# Safe bucket deletion and COSI cleanup handoff

**Status:** implementation for [#359](https://github.com/rajsinghtech/garage-operator/issues/359)
and [#353](https://github.com/rajsinghtech/garage-operator/issues/353).

## Problem and evidence

Garage's `DeleteBucket` operation refuses to delete a bucket that still has
content. The native `GarageBucket` controller already kept its finalizer and
retried, but only exposed the reason in a log line. That left the Kubernetes
resource in `Deleting` with no durable, user-visible explanation.

The COSI `Bucket` path had the same remote constraint. In addition, deleting a
COSI `BucketAccess` immediately revoked its Garage key. When a
`BucketClaim`/namespace deletion caused the bucket and access to enter deletion
together, the controller responsible for cleanup could lose its only ordinary
bucket credential before it had emptied the bucket. #353 is the COSI form of
the same lifecycle problem; #360 is separate and is intentionally not part of
this change.

## Decision

Keep the existing `Delete` and `Retain` policies and do not add an implicit
purge. `Delete` continues to mean “ask Garage to delete the remote bucket,”
which succeeds only after Garage confirms it is empty. `Retain` remains the
explicit way to remove Kubernetes management while preserving remote data.

Automatic emptying is rejected because it would turn a normal Kubernetes
delete into irreversible data loss, require broad object-deletion credentials,
and provide no archive or recovery window. A new `Purge` API value is also not
introduced: native users already have `Retain`, while COSI's `Delete`/`Retain`
enum is owned by the external COSI API and cannot be extended by this driver.

When Garage returns its typed `BucketNotEmpty` conflict:

- Native `GarageBucket` keeps its finalizer, sets
  `DeletionBlocked=True`/`BucketNotEmpty` and `Ready=False` with an actionable
  message, and retries with a bounded exponential delay (30 seconds through a
  five-minute cap).
- COSI `Bucket` keeps the Garage cleanup finalizer, records the same action in
  `status.error`, marks `readyToUse=false`, and uses the same backoff. The
  COSI `Bucket` object therefore remains the durable status surface while the
  upstream COSI controller waits for deletion.
- A deleting COSI `BucketAccess` whose recorded status identifies the exact
  matching `Delete` bucket defers key revocation while that bucket's Garage
  cleanup finalizer remains. The generated Secret and Garage key remain usable
  for the explicit emptying action. Once bucket cleanup succeeds, the next
  access reconcile revokes the key and completes the normal COSI handoff. An
  access deleted independently, or an access for a `Retain` bucket, follows
  the existing immediate-revocation path.

The operator never lists, deletes, or purges bucket objects as part of this
workflow. The user or a cleanup controller must remove objects and incomplete
multipart uploads through S3 (and any other Garage-supported data API) before
the retry can succeed. If data must be kept, set `deletionPolicy: Retain` on
the terminating resource and let cleanup release Kubernetes management.

## Compatibility and API impact

Existing native users keep the historical default: omitted `deletionPolicy`
means `Delete`, empty buckets are deleted, and non-empty buckets are never
implicitly emptied. The change adds status and backoff observability without
changing the remote deletion result. Existing COSI users likewise retain
normal immediate access revocation except for the narrow, necessary handoff
where a dependent `Delete` bucket is concurrently waiting for cleanup.

No CRD schema or served API version changes are required. Native status already
uses generic `metav1.Condition`, so `DeletionBlocked` is an additional
condition value rather than a new field. COSI `Bucket.status.error` and the
existing `BucketAccess` status/finalizer fields provide the required surfaces.
No generated CRDs, conversion code, chart values, or release version fields
change. A rollback is data-safe, but an older operator will not preserve the
COSI access handoff and should not be used to finish a cleanup that depends on
that credential.

## Failure modes and safety

The remote delete is attempted before any cleanup finalizer is removed. A
non-empty response cannot remove a finalizer, and failures to write status or
the retry counter also leave the finalizer in place. Retry writes are conflict
aware and identify the object UID before retrying, so a deleted-and-recreated
object cannot inherit another object's cleanup count.

Changing to `Retain` is the recovery path when the data must survive. Manual
finalizer removal is intentionally not documented as a routine fix because it
can orphan the remote bucket or leave credentials and data outside Kubernetes
management.

## Test plan

Unit regressions cover:

- native `GarageBucket` finalization preserving the typed Garage error;
- native status condition, finalizer retention, retry counter, and backoff;
- COSI `Bucket` status/error, finalizer retention, retry counter, and backoff;
- COSI `BucketAccess` retaining access while the exact bucket is deleting and
  revoking it once that bucket cleanup finalizer is gone; and
- existing empty-bucket, retained-bucket, identity, and finalizer handoff
  behavior.

The change intentionally does not address unrelated cross-namespace
reconciliation failures in #360 or add an automatic object-deletion worker.
