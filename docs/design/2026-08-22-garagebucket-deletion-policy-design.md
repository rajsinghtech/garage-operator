# GarageBucket deletion policy

## Problem

Deleting a `GarageBucket` currently finalizes by calling Garage's
`DeleteBucket` API. That is useful for ordinary ephemeral buckets, but it is
unsafe for imported or backup buckets whose Kubernetes management object may be
removed independently of the data. Denying `DeleteBucket` permission only
leaves the Kubernetes finalizer stuck and is not a usable retention workflow.

## API

Add optional `GarageBucket.spec.deletionPolicy` with values `Delete` and
`Retain`. An omitted value is treated as `Delete` to preserve the existing
behavior for stored objects and upgrades. The field follows the vocabulary used
by COSI and other external-resource operators.

## Reconciliation

`Retain` is handled before cluster lookup, Admin API client construction, or
bucket identity resolution. The operator makes no Garage API calls, removes
only the Kubernetes finalizer, and leaves the remote bucket unchanged. This
allows retention even when the management handle, credentials, or external
endpoint is unavailable.

`Delete` keeps the existing identity-safe finalization path. Garage itself
rejects deletion of buckets containing completed objects; the operator retains
the finalizer and retries with an actionable status message. COSI's existing
UID-bound retention validation remains authoritative for COSI shadow resources
and cannot be bypassed by editing the native field.

## Compatibility and recovery

The CRD, served historical bucket schema, Helm CRD copy, JSON schemas, samples,
and documentation are updated together. Retained buckets can be re-adopted
using the existing immutable `spec.bucketId` field. Retaining a bucket does not
protect its underlying Garage workloads or PVCs.

## Test plan

- Validate the enum and effective default.
- Verify retained deletion succeeds without a referenced cluster.
- Preserve existing destructive finalization identity and retry tests.
- Verify generated CRDs and schemas remain synchronized.
