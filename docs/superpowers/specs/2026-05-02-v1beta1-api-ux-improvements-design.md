# v1beta1 API UX Improvements

**Date:** 2026-05-02  
**Branch:** worktree-security (PR #128)  
**Scope:** Breaking field changes permitted — this is the beta promotion window.

---

## Motivation

PR #128 promotes the API to `v1beta1`. Before the version stabilizes, a set of UX issues
should be fixed: wrong field types, forced boilerplate, inverted booleans, near-duplicate
structs, and missing observability on `GarageReferenceGrant`. All changes are breaking at
the field level but non-breaking in behavior.

---

## Changes

### 1a. Expiration fields: `string` → `*metav1.Time`

**Affects:** `GarageKey`, `GarageAdminToken` (spec and status)

**Problem:** `expiration string` accepts any string with no validation. Users get a confusing
Garage error at runtime for malformed values.

**Change:**
- `spec.expiration` → `spec.expiresAt *metav1.Time` (rename + type change)
- `status.expiration string` → `status.expiresAt *metav1.Time`
- `spec.neverExpires bool` is unchanged

**Validation against upstream:** Garage Admin API uses `Option<DateTime<Utc>>` (RFC 3339)
for both key and admin token expiration. `*metav1.Time` serializes to the same format.
Controller passes the time directly to the Admin API — no conversion needed.

**Before:**
```yaml
spec:
  expiration: "2026-12-31T23:59:59Z"
```
**After:**
```yaml
spec:
  expiresAt: "2026-12-31T23:59:59Z"
```

---

### 1b. RPC timeout fields: `*int64` ms → `*metav1.Duration`

**Affects:** `GarageCluster.spec.network`

**Problem:** `rpcPingTimeoutMs` and `rpcTimeoutMs` use integer milliseconds while
`metadataAutoSnapshotInterval` uses a Go duration string. Users must remember different
conventions for different fields.

**Change:**
- `network.rpcPingTimeoutMs *int64` → `network.rpcPingTimeout *metav1.Duration`
- `network.rpcTimeoutMs *int64` → `network.rpcTimeout *metav1.Duration`

**Validation against upstream:** Garage TOML config uses `rpc_ping_timeout_msec: Option<u64>`
and `rpc_timeout_msec: Option<u64>`. Controller converts via `duration.Milliseconds()` when
writing TOML.

**Before:**
```yaml
network:
  rpcPingTimeoutMs: 10000
  rpcTimeoutMs: 30000
```
**After:**
```yaml
network:
  rpcPingTimeout: 10s
  rpcTimeout: 30s
```

---

### 1c. `ZoneRedundancy`: regex string → two fields

**Affects:** `GarageCluster.spec.replication`

**Problem:** `zoneRedundancy: "AtLeast(2)"` is a non-standard K8s pattern validated by regex.
Hard to discover, easy to mistype.

**Change:** Replace with two fields on `ReplicationConfig`:
```go
// +kubebuilder:validation:Enum=Maximum;AtLeast
// +optional
ZoneRedundancyMode string `json:"zoneRedundancyMode,omitempty"`

// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=7
// +optional
ZoneRedundancyMinZones *int `json:"zoneRedundancyMinZones,omitempty"`
```

CEL cross-field validation:
```go
// +kubebuilder:validation:XValidation:rule="self.zoneRedundancyMode != 'AtLeast' || has(self.zoneRedundancyMinZones)",message="zoneRedundancyMinZones is required when zoneRedundancyMode is AtLeast"
```

Default (omitted) maps to `ZoneRedundancy::Maximum` in the Garage Admin API.

**Validation against upstream:** Garage's internal enum is `ZoneRedundancy::Maximum` and
`ZoneRedundancy::AtLeast(usize)`. These map directly to the two field values.

**Before:**
```yaml
replication:
  zoneRedundancy: "AtLeast(2)"
```
**After:**
```yaml
replication:
  zoneRedundancyMode: AtLeast
  zoneRedundancyMinZones: 2
```

---

### 2a. `spec.replication` → optional pointer

**Affects:** `GarageCluster.spec`

**Problem:** `Replication ReplicationConfig` is `+required` even though all subfields have
defaults (`factor: 3`, `consistencyMode: consistent`). Every GarageCluster YAML must include
it even for a plain default cluster.

**Change:** `Replication ReplicationConfig` → `Replication *ReplicationConfig` with `+optional`.
Webhook defaulter populates `factor: 3` and `consistencyMode: consistent` when nil.

**Before:**
```yaml
spec:
  replication:
    factor: 3
    consistencyMode: consistent
```
**After:**
```yaml
spec:
  replicas: 3
  # replication can be omitted — defaults to factor: 3, consistencyMode: consistent
```

---

### 2b. `WebAPI.disabled bool` → `WebAPI.enabled *bool`

**Affects:** `GarageCluster.spec.webApi`

**Problem:** `disabled: true` reads backwards. Non-obvious that omitting the field means
enabled.

**Change:** `Disabled bool` → `Enabled *bool`. Webhook defaults to `true` when `webApi` is
present but `enabled` is nil. `nil` when `webApi` is absent means enabled (preserves current
behavior — web API on by default).

```go
// Enabled controls whether the web endpoint is active.
// Defaults to true. Set to false to disable.
// +optional
Enabled *bool `json:"enabled,omitempty"`
```

**Before:**
```yaml
webApi:
  disabled: true
```
**After:**
```yaml
webApi:
  enabled: false
```

---

### 2c. Remove `AdminConfig.enabled`

**Affects:** `GarageCluster.spec.admin`

**Problem:** If a user sets `admin.enabled: false`, the operator loses its Admin API
connection and breaks silently. The field should not exist.

**Change:** Remove `Enabled bool` from `AdminConfig`. Update the struct comment to note
that the admin port is always active; use NetworkPolicy for access restriction.

All other `AdminConfig` fields are unchanged.

---

### 3a. Unify `VolumeConfig` and `DataStorageConfig`

**Affects:** `GarageCluster.spec.storage`

**Problem:** Two near-identical structs with subtle field differences (`VolumeConfig` has
`AccessModes`, `Selector`, `VolumeClaimTemplateSpec`; `DataStorageConfig` has `Paths`).
Users must learn two almost-identical schemas.

**Change:** Remove `DataStorageConfig`. Merge `Paths []DataPath` into `VolumeConfig`.
`StorageConfig.Data` becomes `*VolumeConfig`.

Webhook validation rejects `spec.storage.metadata.paths` with: `"paths is only valid for
data volumes"`.

`DataPath` struct is unchanged.

**Before:**
```yaml
storage:
  data:
    type: PersistentVolumeClaim
    size: 100Gi
    paths:
      - path: /data1
        capacity: 50Gi
```
**After:** identical YAML — the user-facing field names are unchanged; only the Go struct
changes.

---

### 3b. `BucketPermission.bucketRef + bucketNamespace` → object reference

**Affects:** `GarageKey.spec.bucketPermissions`

**Problem:** Cross-namespace reference is split into two sibling string fields
(`bucketRef: "name"` + `bucketNamespace: "ns"`). Non-idiomatic and easy to miss the
namespace field.

**Change:** Introduce `BucketRef` struct, replace the two fields:

```go
type BucketRef struct {
    // +required
    Name string `json:"name"`
    // +optional
    Namespace string `json:"namespace,omitempty"`
}

type BucketPermission struct {
    // Mutually exclusive with BucketID and GlobalAlias.
    // +optional
    BucketRef *BucketRef `json:"bucketRef,omitempty"`

    // +optional
    BucketID string `json:"bucketId,omitempty"`

    // +optional
    GlobalAlias string `json:"globalAlias,omitempty"`

    Read  bool `json:"read,omitempty"`
    Write bool `json:"write,omitempty"`
    Owner bool `json:"owner,omitempty"`
}
```

CEL rule on `BucketPermission`:
```go
// +kubebuilder:validation:XValidation:rule="[has(self.bucketRef), has(self.bucketId), has(self.globalAlias)].filter(x, x).size() == 1",message="exactly one of bucketRef, bucketId, or globalAlias must be set"
```

**Before:**
```yaml
bucketPermissions:
  - bucketRef: my-bucket
    bucketNamespace: other-ns
    read: true
```
**After:**
```yaml
bucketPermissions:
  - bucketRef:
      name: my-bucket
      namespace: other-ns
    read: true
```

---

### 4. Add status to `GarageReferenceGrant`

**Affects:** `GarageReferenceGrant`

**Problem:** Only CRD with no status subresource. Users cannot observe whether a grant is
in use or safe to delete.

**Change:** Add `status` subresource with `InUseBy` and `Conditions`:

```go
type GarageReferenceGrantStatus struct {
    // InUseBy lists resources currently referencing through this grant.
    // Best-effort — populated by bucket/key/admintoken controllers on reconcile.
    // +optional
    InUseBy []ReferenceGrantUser `json:"inUseBy,omitempty"`

    // +listType=map
    // +listMapKey=type
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type ReferenceGrantUser struct {
    Kind      string `json:"kind,omitempty"`
    Name      string `json:"name,omitempty"`
    Namespace string `json:"namespace,omitempty"`
}
```

Two conditions:
- `Ready`: always `True` (grant is a policy object; valid if it exists)
- `InUse`: `True` when `InUseBy` is non-empty; `False` otherwise

New CRD marker:
```go
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="InUse",type="string",JSONPath=".status.conditions[?(@.type=='InUse')].status"
```

**Implementation:** Add a new `garagereferencegrant_controller.go`. The controller watches
`GarageKey`, `GarageBucket`, and `GarageAdminToken` resources (using `Watches` with
`EnqueueRequestsFromMapFunc` to map each resource's `clusterRef.namespace` to the relevant
grant). On reconcile it lists all resources that reference through this grant and rebuilds
`InUseBy` from scratch — this avoids stale entries and race conditions from multiple
controllers writing to the same status field. Having the three existing controllers each
patch the grant status would require broader RBAC and create update conflicts.

---

### 5a. Rename `allowWorldReadableSecrets`

**Affects:** `GarageCluster.spec.security`

**Problem:** The name sounds like a style preference. It is a security bypass that weakens
credential protection.

**Change:**
- `allowWorldReadableSecrets bool` → `allowInsecureSecretPermissions bool`
- Stronger comment making the risk explicit

Maps to Garage's `allow_world_readable_secrets` TOML key — rename is operator-level only.

---

## Implementation Notes

- All field renames require updating: Go types, controller reads/writes, webhook defaulters,
  webhook validators, deepcopy generated file, CRD YAML, Helm chart CRD bases, JSON schema.
- `replication *ReplicationConfig` nil-check must be added everywhere the controller reads
  replication fields — dereference after webhook defaulting is safe at reconcile time.
- A new `garagereferencegrant_controller.go` owns all writes to `GarageReferenceGrant` status.
  It watches GarageKey, GarageBucket, GarageAdminToken via `EnqueueRequestsFromMapFunc` and
  rebuilds `InUseBy` from scratch on each reconcile to avoid stale entries.
- `DataStorageConfig` removal: confirm no external consumers reference this type by name
  (it is an internal Go type, not exposed in JSON schema by name).

## Files Affected

- `api/v1beta1/garagecluster_types.go`
- `api/v1beta1/garagebucket_types.go` (BucketRef type lives here alongside KeyPermission)
- `api/v1beta1/garagekey_types.go`
- `api/v1beta1/garageadmintoken_types.go`
- `api/v1beta1/garagereferencegrant_types.go`
- `api/v1beta1/zz_generated.deepcopy.go`
- `api/v1beta1/*_webhook.go` (defaulters + validators)
- `internal/controller/garagekey_controller.go`
- `internal/controller/garagebucket_controller.go`
- `internal/controller/garageadmintoken_controller.go`
- `internal/controller/garagecluster_controller.go`
- `internal/controller/garagereferencegrant_controller.go` (new)
- `internal/controller/helpers.go`
- `config/crd/bases/*.yaml`
- `charts/garage-operator/crd-bases/*.yaml`
- `schemas/garagecluster_v1beta1.json`
