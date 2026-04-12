# Web API: Populate WebsiteURL Status

**Date:** 2026-04-12
**Status:** Approved

## Goal

Populate `GarageBucket.status.websiteUrl` when website hosting is enabled. The field is defined in the type but never set.

## Background

`GarageCluster.spec.webApi` is fully implemented: `[s3_web]` config is written, the port is exposed on the cluster Service, and `effectiveWebAPI()` computes the effective `rootDomain` (defaulting to `.<name>.<namespace>.svc`).

`GarageBucket.spec.website` is also fully implemented: `enabled`, `indexDocument`, `errorDocument` are reconciled via the Admin API, and `status.websiteEnabled` / `status.websiteConfig` are populated.

`status.websiteUrl` is the only gap — defined in the type, never assigned.

Garage's web hosting is purely host-header based. With `root_domain = ".web.example.com"`, a request with `Host: mybucket.web.example.com` serves from the `mybucket` bucket. The URL for a bucket is therefore `{globalAlias}{rootDomain}`.

HTTPRoute auto-provisioning is explicitly out of scope.

## Change

**File:** `internal/controller/garagebucket_controller.go`

In `syncStatus`, after setting `bucket.Status.GlobalAlias` (line ~651), set `WebsiteURL`:

```go
if garageBucket.WebsiteAccess {
    if w := effectiveWebAPI(cluster); w != nil {
        bucket.Status.WebsiteURL = "http://" + bucket.Status.GlobalAlias + w.RootDomain
    }
} else {
    bucket.Status.WebsiteURL = ""
}
```

`effectiveWebAPI` is in the same package — no import needed. `cluster` is already in scope (fetched at reconcile start). `GlobalAlias` must be set before this block runs (it is, at line ~651).

## Edge Cases

- **Website disabled:** `WebsiteURL` is cleared to `""`.
- **Web API disabled on cluster** (`webApi.disabled: true`): `effectiveWebAPI` returns nil, `WebsiteURL` stays empty.
- **Cluster fetch error:** The bucket controller gates on `clusterErr` before reaching reconciliation, so `cluster` is always valid when this code runs.
- **No global alias:** If `bucket.Status.GlobalAlias` is empty (bucket has no alias yet), the URL will be malformed. Guard: only set URL when `GlobalAlias != ""`.

## Updated Change

```go
if garageBucket.WebsiteAccess {
    if w := effectiveWebAPI(cluster); w != nil && bucket.Status.GlobalAlias != "" {
        bucket.Status.WebsiteURL = "http://" + bucket.Status.GlobalAlias + w.RootDomain
    }
} else {
    bucket.Status.WebsiteURL = ""
}
```

## Scope

Single file, ~5 lines added. No new types, no new dependencies, no API surface changes.
