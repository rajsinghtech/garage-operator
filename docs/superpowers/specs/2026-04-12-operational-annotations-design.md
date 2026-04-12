# Operational Annotation Handlers Design

**Date:** 2026-04-12  
**Status:** Approved

## Goal

Implement controller logic for six annotations that are already defined as constants but have no handler code. These are day-2 operational triggers: snapshot metadata, run repair/scrub, pause reconciliation, and clean up incomplete multipart uploads.

## Background

All six annotation constants exist in `api/v1alpha1/condition_types.go`. The corresponding Garage Admin API functions exist in `internal/garage/client.go`. Nothing wires them together.

The Garage admin API supports `node=*` as a wildcard that fans out to all nodes server-side, so the operator sends one request per operation — no node-ID looping needed.

## Scope

### GarageCluster (4 annotations)

Handled in `handleOperationalAnnotations` in `internal/controller/garagecluster_controller.go`.

#### `pause-reconcile: "true"`

- Checked **first** in `Reconcile`, before the cluster object is fetched from the API.
- Returns `ctrl.Result{RequeueAfter: RequeueAfterLong}` immediately — no Garage API calls, no status update.
- Stays until the annotation is manually removed by the user.
- Log line: `"Reconciliation paused via annotation"`.

#### `trigger-snapshot: "true"`

- Calls `garageClient.CreateMetadataSnapshot(ctx, "*")`.
- On success: remove annotation, update object. Log: `"Metadata snapshot triggered on all nodes"`.
- On API error: return error (controller retries; annotation stays for retry).
- Invalid value (anything other than `"true"`): log warning, remove annotation, skip.

#### `trigger-repair: <RepairType>`

Valid values (from `RepairType*` constants): `Tables`, `Blocks`, `Versions`, `MultipartUploads`, `BlockRefs`, `BlockRc`, `Rebalance`, `Aliases`, `ClearResyncQueue`.

- `"Scrub"` is **rejected** — use `scrub-command: start` instead. Log warning, remove annotation.
- Any other unrecognised value: log warning, remove annotation.
- On valid value: calls `garageClient.LaunchRepair(ctx, "*", value)`.
- On success: remove annotation. Log: `"Repair operation launched"` with `repairType` field.
- On API error: return error (retries).

#### `scrub-command: <command>`

Valid values (from `ScrubCommand*` constants): `start`, `pause`, `resume`, `cancel`.

- Calls `garageClient.LaunchScrubCommand(ctx, "*", value)` — a new client function (see below).
- On success: remove annotation. Log: `"Scrub command sent to all nodes"` with `command` field.
- On API error: return error.
- Invalid value: log warning, remove annotation.

`trigger-repair` and `scrub-command` are independent — both can be set simultaneously and are processed in order.

---

### GarageBucket (2 annotations)

New function `handleBucketAnnotations` called from the GarageBucket reconciler after the cluster is healthy and the Garage client is available.

#### `cleanup-mpu: "true"` + `cleanup-mpu-older-than: <duration>`

- `cleanup-mpu-older-than` is optional; defaults to `"24h"` if absent.
- Duration parsed with `time.ParseDuration`. Invalid duration: log warning, use default `24h`.
- Calls `garageClient.CleanupIncompleteUploads(ctx, bucket.Status.BucketID, olderThanSecs)`.
- On success: remove **both** annotations (`cleanup-mpu` and `cleanup-mpu-older-than`). Log result (aborted count if returned).
- On API error: return error (retries; both annotations stay).
- `cleanup-mpu-older-than` set without `cleanup-mpu`: ignored (no action, annotation stays).

---

## Client Change

Add to `internal/garage/client.go`:

```go
// LaunchScrubCommand sends a scrub control command (start/pause/resume/cancel) to nodes.
// The Garage API encodes this as {"repairType": {"scrub": "<command>"}}.
func (c *Client) LaunchScrubCommand(ctx context.Context, nodeID, command string) error {
    query := map[string]string{"node": nodeID}
    type scrubType struct {
        Scrub string `json:"scrub"`
    }
    type scrubRequest struct {
        RepairType scrubType `json:"repairType"`
    }
    req := scrubRequest{RepairType: scrubType{Scrub: command}}
    _, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/LaunchRepairOperation", query, req)
    return err
}
```

No changes to `LaunchRepair` — it remains for non-scrub repair types.

---

## File Changes

| File | Change |
|------|--------|
| `internal/garage/client.go` | Add `LaunchScrubCommand` |
| `internal/controller/garagecluster_controller.go` | Add `pause-reconcile` check in `Reconcile`, add 3 handlers in `handleOperationalAnnotations` |
| `internal/controller/garagebucket_controller.go` | Add `handleBucketAnnotations`, call it from reconcile loop |
| `internal/controller/garagekey_controller.go` | No changes |
| `internal/garage/client_test.go` | Unit tests for `LaunchScrubCommand` |
| `internal/controller/garagecluster_controller_test.go` | Tests for new annotation handlers |
| `internal/controller/garagebucket_controller_test.go` | Tests for MPU cleanup handler |

---

## Patterns to Follow

- **One-shot annotations**: processed then deleted with `r.Update(ctx, cluster)` — same pattern as `connect-nodes`.
- **Persistent annotations**: `pause-reconcile` stays until manually removed — checked before any work.
- **Error handling**: return error on API failure (annotation stays, controller retries). Log warning + remove annotation on invalid values (don't block reconciliation forever on user typos).
- **Placement**: `pause-reconcile` check goes before the cluster `r.Get` call. All others go inside `handleOperationalAnnotations` / `handleBucketAnnotations`, called after the Garage client is available.

---

## Out of Scope

- `AnnotationRetryBlockResync`, `AnnotationPurgeBlocks`, `AnnotationRevertLayout` — defined but not part of this implementation.
- Per-node targeting (all operations use `node=*`).
- Status conditions reflecting ongoing repair/scrub state (Garage doesn't expose scrub progress via the admin API in a way that maps cleanly to K8s conditions).
