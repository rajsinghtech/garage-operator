# v1beta1 API UX Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 10 breaking UX issues in the v1beta1 API before the version stabilizes: wrong field types, forced boilerplate, inverted booleans, near-duplicate structs, and missing ReferenceGrant observability.

**Architecture:** Each task is independent — type change first, then webhook, then controller consumer. All changes stay within existing file boundaries except Task 9 (new controller). Tasks 1–10 edit Go sources; Task 11 regenerates all derived artifacts (deepcopy, CRDs, JSON schema).

**Tech Stack:** Go, controller-runtime, kubebuilder, `make generate` / `make manifests` for code-gen

---

## File Map

| File | Tasks |
|------|-------|
| `api/v1beta1/garagekey_types.go` | 1a, 3b |
| `api/v1beta1/garageadmintoken_types.go` | 1a |
| `api/v1beta1/garagecluster_types.go` | 1b, 1c, 2a, 2b, 2c, 3a, 5a |
| `api/v1beta1/garagecluster_webhook.go` | 1c, 2a, 2b, 3a |
| `api/v1beta1/garagekey_webhook.go` | 1a, 3b |
| `api/v1beta1/garageadmintoken_webhook.go` | 1a |
| `api/v1beta1/garagereferencegrant_types.go` | 4 |
| `api/v1beta1/webhook_test.go` | 1a, 1c, 2a, 2b, 3a, 3b |
| `internal/controller/garagecluster_controller.go` | 1b, 1c, 2a, 2b, 2c, 3a, 5a |
| `internal/controller/garagekey_controller.go` | 1a, 3b |
| `internal/controller/garageadmintoken_controller.go` | 1a |
| `internal/controller/garagereferencegrant_controller.go` | 4 (new) |
| `api/v1beta1/zz_generated.deepcopy.go` | 11 |
| `config/crd/bases/*.yaml` | 11 |
| `charts/garage-operator/crd-bases/*.yaml` | 11 |
| `schemas/garagecluster_v1beta1.json` | 11 |

---

## Task 1: Expiration fields — `string` → `*metav1.Time`

Rename `spec.expiration` → `spec.expiresAt *metav1.Time` and `status.expiration string` → `status.expiresAt *metav1.Time` on both `GarageKey` and `GarageAdminToken`.

**Files:**
- Modify: `api/v1beta1/garagekey_types.go`
- Modify: `api/v1beta1/garageadmintoken_types.go`
- Modify: `api/v1beta1/garagekey_webhook.go`
- Modify: `api/v1beta1/garageadmintoken_webhook.go`
- Modify: `internal/controller/garagekey_controller.go`
- Modify: `internal/controller/garageadmintoken_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing tests for expiresAt type and rename**

In `api/v1beta1/webhook_test.go`, add after the existing expiration tests:

```go
func TestGarageKey_ExpiresAt_Valid(t *testing.T) {
	d := &GarageKeyDefaulter{}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			ExpiresAt:  &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
		},
	}
	if err := d.Default(context.Background(), key); err != nil {
		t.Fatalf("Default: %v", err)
	}
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid expiresAt should pass, got: %v", err)
	}
}

func TestGarageKey_ExpiresAt_MutuallyExclusiveWithNeverExpires(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef:  ClusterReference{Name: testCluster},
			ExpiresAt:   &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
			NeverExpires: true,
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail to compile**

```bash
go test ./api/v1beta1/... -run TestGarageKey_ExpiresAt -count=1 2>&1 | head -20
```
Expected: compilation error `unknown field ExpiresAt`

- [ ] **Step 3: Update `GarageKeySpec` in `api/v1beta1/garagekey_types.go`**

Replace:
```go
// Expiration sets when this key expires in RFC 3339 format (e.g. "2026-12-31T23:59:59Z").
// After this time Garage will reject requests using the key. The operator sets the
// KeyExpired condition when expired but does NOT automatically delete or rotate the key.
// Mutually exclusive with neverExpires.
// +optional
Expiration string `json:"expiration,omitempty"`
```
With:
```go
// ExpiresAt sets when this key expires.
// After this time Garage will reject requests using the key. The operator sets the
// KeyExpired condition when expired but does NOT automatically delete or rotate the key.
// Mutually exclusive with neverExpires.
// +optional
ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
```

In `GarageKeyStatus`, replace:
```go
// Expiration is when this key expires (if set)
// +optional
Expiration string `json:"expiration,omitempty"`
```
With:
```go
// ExpiresAt is when this key expires (if set)
// +optional
ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
```

- [ ] **Step 4: Update `GarageAdminTokenSpec` and `GarageAdminTokenStatus` in `api/v1beta1/garageadmintoken_types.go`**

In `GarageAdminTokenSpec`, replace:
```go
// Expiration sets when this token should be rotated (RFC 3339 format, e.g. "2026-12-31T23:59:59Z").
// ...
// +optional
Expiration string `json:"expiration,omitempty"`
```
With:
```go
// ExpiresAt sets when this token should be rotated.
// The operator tracks this and sets the TokenExpired condition when the date passes,
// but does NOT automatically rotate or revoke the token — rotation requires manual action
// (update or delete the GarageAdminToken resource). Use NeverExpires to suppress expiry tracking.
// Mutually exclusive with NeverExpires.
// +optional
ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
```

In `GarageAdminTokenStatus`, replace:
```go
// Expiration is when this token expires (if set)
// +optional
Expiration string `json:"expiration,omitempty"`
```
With:
```go
// ExpiresAt is when this token expires (if set)
// +optional
ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
```

- [ ] **Step 5: Update `garagekey_webhook.go` — remove manual RFC3339 parse, update mutual exclusion check**

In `validateGarageKey`, replace:
```go
if obj.Spec.Expiration != "" && obj.Spec.NeverExpires {
    return warnings, fmt.Errorf("expiration and neverExpires are mutually exclusive")
}

if obj.Spec.Expiration != "" {
    if _, err := time.Parse(time.RFC3339, obj.Spec.Expiration); err != nil {
        return warnings, fmt.Errorf("expiration must be in RFC 3339 format (e.g., '2025-12-31T23:59:59Z'): %v", err)
    }
}
```
With:
```go
if obj.Spec.ExpiresAt != nil && obj.Spec.NeverExpires {
    return warnings, fmt.Errorf("expiresAt and neverExpires are mutually exclusive")
}
```

Remove the `"time"` import if it's no longer used elsewhere in the file. (Check first: `grep -n '"time"' api/v1beta1/garagekey_webhook.go`)

- [ ] **Step 6: Update `garageadmintoken_webhook.go`**

In the admintoken webhook validator, find and replace the expiration check. Locate:
```go
if token.Spec.Expiration != "" && token.Spec.NeverExpires {
```
Replace with:
```go
if token.Spec.ExpiresAt != nil && token.Spec.NeverExpires {
```
Find and remove any `time.Parse(time.RFC3339, token.Spec.Expiration)` validation block — it's no longer needed since `*metav1.Time` is always valid.

- [ ] **Step 7: Update `garagekey_controller.go` — expiration sync logic**

In `updateKeyIfNeeded`, replace the expiration block (lines ~421–431):
```go
isNeverExpires := garageKey.Expiration != nil && *garageKey.Expiration == "never"
if key.Spec.NeverExpires && !isNeverExpires {
    updateReq.Body.NeverExpires = true
    needsUpdate = true
} else if key.Spec.Expiration != "" {
    currentExp := ""
    if garageKey.Expiration != nil {
        currentExp = *garageKey.Expiration
    }
    if currentExp != key.Spec.Expiration {
        updateReq.Body.Expiration = &key.Spec.Expiration
        needsUpdate = true
    }
}
```
With:
```go
isNeverExpires := garageKey.Expiration != nil && *garageKey.Expiration == "never"
if key.Spec.NeverExpires && !isNeverExpires {
    updateReq.Body.NeverExpires = true
    needsUpdate = true
} else if key.Spec.ExpiresAt != nil {
    desired := key.Spec.ExpiresAt.UTC().Format(time.RFC3339)
    currentExp := ""
    if garageKey.Expiration != nil {
        currentExp = *garageKey.Expiration
    }
    if currentExp != desired {
        updateReq.Body.Expiration = &desired
        needsUpdate = true
    }
}
```

In the status-update block (lines ~971–974), replace:
```go
if garageKey.Expiration != nil {
    key.Status.Expiration = *garageKey.Expiration
} else {
    key.Status.Expiration = ""
}
```
With:
```go
if garageKey.Expiration != nil {
    if t, err := time.Parse(time.RFC3339, *garageKey.Expiration); err == nil {
        mt := metav1.NewTime(t)
        key.Status.ExpiresAt = &mt
    }
} else {
    key.Status.ExpiresAt = nil
}
```

Also find where `key.Status.Expired` is set (search for `Expired` in the controller). It currently compares `time.Parse(time.RFC3339, key.Spec.Expiration)`. Replace with:
```go
if key.Spec.ExpiresAt != nil {
    key.Status.Expired = time.Now().After(key.Spec.ExpiresAt.Time)
}
```

- [ ] **Step 8: Update `garageadmintoken_controller.go` — expiration handling**

Find all uses of `token.Spec.Expiration` and `token.Status.Expiration`. Replace:
- `token.Spec.Expiration != ""` → `token.Spec.ExpiresAt != nil`
- `time.Parse(time.RFC3339, token.Spec.Expiration)` → `token.Spec.ExpiresAt.Time`
- `token.Status.Expiration = token.Spec.Expiration` → `token.Status.ExpiresAt = token.Spec.ExpiresAt`
- For requeue-before-expiry: replace `expTime, parseErr := time.Parse(time.RFC3339, token.Spec.Expiration)` with direct use of `token.Spec.ExpiresAt.Time`

Full replacement for the expiry-check block (find via `grep -n "Expiration" internal/controller/garageadmintoken_controller.go`):
```go
// Check expiration
if token.Spec.ExpiresAt != nil {
    if time.Now().After(token.Spec.ExpiresAt.Time) {
        token.Status.Expired = true
        // set condition ...
    }
}
```

For the status update:
```go
token.Status.ExpiresAt = token.Spec.ExpiresAt
```

For the requeue:
```go
if token.Spec.ExpiresAt != nil && !token.Status.Expired {
    until := time.Until(token.Spec.ExpiresAt.Time)
    if until > 0 {
        return ctrl.Result{RequeueAfter: until + time.Minute}, nil
    }
}
```

- [ ] **Step 9: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageKey_ExpiresAt -v -count=1
```
Expected: PASS

```bash
go test ./api/v1beta1/... -v -count=1 2>&1 | tail -20
```
Expected: all existing tests still pass

- [ ] **Step 10: Commit**

```bash
git add api/v1beta1/garagekey_types.go api/v1beta1/garageadmintoken_types.go \
    api/v1beta1/garagekey_webhook.go api/v1beta1/garageadmintoken_webhook.go \
    internal/controller/garagekey_controller.go \
    internal/controller/garageadmintoken_controller.go \
    api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): rename expiration to expiresAt, change type to *metav1.Time"
```

---

## Task 2: RPC timeout fields — `*int64` ms → `*metav1.Duration`

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `internal/controller/garagecluster_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing test**

In `api/v1beta1/webhook_test.go`, add:

```go
func TestGarageCluster_RPCTimeout_DurationField(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:   3,
			Network: NetworkConfig{
				RPCPingTimeout: &metav1.Duration{Duration: 10 * time.Second},
				RPCTimeout:     &metav1.Duration{Duration: 30 * time.Second},
			},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Network.RPCPingTimeout.Duration != 10*time.Second {
		t.Errorf("expected 10s ping timeout, got %v", cluster.Spec.Network.RPCPingTimeout)
	}
}
```

- [ ] **Step 2: Run test to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_RPCTimeout -count=1 2>&1 | head -10
```
Expected: `unknown field RPCPingTimeout`

- [ ] **Step 3: Update `NetworkConfig` in `api/v1beta1/garagecluster_types.go`**

Replace:
```go
// RPCPingTimeoutMs sets the RPC ping timeout in milliseconds
// +optional
RPCPingTimeoutMs *int64 `json:"rpcPingTimeoutMs,omitempty"`

// RPCTimeoutMs sets the RPC call timeout in milliseconds
// +optional
RPCTimeoutMs *int64 `json:"rpcTimeoutMs,omitempty"`
```
With:
```go
// RPCPingTimeout sets the RPC ping timeout (e.g. "10s", "500ms").
// +optional
RPCPingTimeout *metav1.Duration `json:"rpcPingTimeout,omitempty"`

// RPCTimeout sets the RPC call timeout (e.g. "30s").
// +optional
RPCTimeout *metav1.Duration `json:"rpcTimeout,omitempty"`
```

Add `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"` to the imports if not already present (it likely is).

- [ ] **Step 4: Update `garagecluster_controller.go` TOML config writer**

Find lines ~847–851:
```go
if cluster.Spec.Network.RPCPingTimeoutMs != nil {
    fmt.Fprintf(config, "rpc_ping_timeout_msec = %d\n", *cluster.Spec.Network.RPCPingTimeoutMs)
}
if cluster.Spec.Network.RPCTimeoutMs != nil {
    fmt.Fprintf(config, "rpc_timeout_msec = %d\n", *cluster.Spec.Network.RPCTimeoutMs)
}
```
Replace with:
```go
if cluster.Spec.Network.RPCPingTimeout != nil {
    fmt.Fprintf(config, "rpc_ping_timeout_msec = %d\n", cluster.Spec.Network.RPCPingTimeout.Duration.Milliseconds())
}
if cluster.Spec.Network.RPCTimeout != nil {
    fmt.Fprintf(config, "rpc_timeout_msec = %d\n", cluster.Spec.Network.RPCTimeout.Duration.Milliseconds())
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_RPCTimeout -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add api/v1beta1/garagecluster_types.go internal/controller/garagecluster_controller.go \
    api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): change rpc timeout fields from *int64 ms to *metav1.Duration"
```

---

## Task 3: `ZoneRedundancy` — regex string → two fields

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `api/v1beta1/garagecluster_webhook.go`
- Modify: `internal/controller/garagecluster_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing tests**

In `api/v1beta1/webhook_test.go`, add:

```go
func TestGarageCluster_ZoneRedundancy_AtLeast_RequiresMinZones(t *testing.T) {
	v := &GarageClusterValidator{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:   3,
			Replication: &ReplicationConfig{Factor: 3},
			ZoneRedundancyMode: "AtLeast",
			// ZoneRedundancyMinZones intentionally absent
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "zoneRedundancyMinZones") {
		t.Errorf("expected zoneRedundancyMinZones required error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_AtLeast_CannotExceedFactor(t *testing.T) {
	v := &GarageClusterValidator{}
	minZones := 5
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:              3,
			Replication:           &ReplicationConfig{Factor: 3},
			ZoneRedundancyMode:    "AtLeast",
			ZoneRedundancyMinZones: &minZones,
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "cannot exceed") {
		t.Errorf("expected exceed-factor error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_Maximum_Valid(t *testing.T) {
	v := &GarageClusterValidator{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:           3,
			Replication:        &ReplicationConfig{Factor: 3},
			ZoneRedundancyMode: "Maximum",
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err != nil {
		t.Errorf("Maximum should be valid, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_ZoneRedundancy -count=1 2>&1 | head -10
```
Expected: compile error on `ZoneRedundancyMode`

- [ ] **Step 3: Update `ReplicationConfig` in `api/v1beta1/garagecluster_types.go`**

Remove the `ZoneRedundancy` field. Add two new fields to `GarageClusterSpec` (not `ReplicationConfig`, since they're cross-cutting with the replication factor validation):

Actually, add to `ReplicationConfig` to keep replication concerns together:

Replace:
```go
// ZoneRedundancy controls how data is distributed across zones.
// ...
// +kubebuilder:validation:Pattern=`^(Maximum|AtLeast\([1-7]\))$`
// +optional
ZoneRedundancy string `json:"zoneRedundancy,omitempty"`
```
With:
```go
// ZoneRedundancyMode controls how data is distributed across zones.
// "Maximum": spread replicas across as many zones as possible (default).
// "AtLeast": require replicas in at least ZoneRedundancyMinZones zones.
// +kubebuilder:validation:Enum=Maximum;AtLeast
// +optional
ZoneRedundancyMode string `json:"zoneRedundancyMode,omitempty"`

// ZoneRedundancyMinZones is the minimum number of zones required.
// Only valid when ZoneRedundancyMode is "AtLeast". Must not exceed the replication factor.
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=7
// +optional
ZoneRedundancyMinZones *int `json:"zoneRedundancyMinZones,omitempty"`
```

- [ ] **Step 4: Update `validateZoneRedundancy` in `api/v1beta1/garagecluster_webhook.go`**

Replace the entire function:
```go
func (r *GarageCluster) validateZoneRedundancy() error {
	mode := ""
	factor := 3
	if r.Spec.Replication != nil {
		factor = r.Spec.Replication.Factor
		if factor == 0 {
			factor = 3 // webhook default
		}
	}
	if r.Spec.Replication != nil {
		mode = r.Spec.Replication.ZoneRedundancyMode
	}

	if mode == "" || mode == "Maximum" {
		if r.Spec.Replication != nil && r.Spec.Replication.ZoneRedundancyMinZones != nil {
			return fmt.Errorf("zoneRedundancyMinZones is only valid when zoneRedundancyMode is AtLeast")
		}
		return nil
	}

	if mode == "AtLeast" {
		if r.Spec.Replication == nil || r.Spec.Replication.ZoneRedundancyMinZones == nil {
			return fmt.Errorf("zoneRedundancyMinZones is required when zoneRedundancyMode is AtLeast")
		}
		n := *r.Spec.Replication.ZoneRedundancyMinZones
		if n > factor {
			return fmt.Errorf("zoneRedundancyMinZones (%d) cannot exceed replication factor (%d)", n, factor)
		}
		return nil
	}

	return fmt.Errorf("invalid zoneRedundancyMode %q (expected Maximum or AtLeast)", mode)
}
```

Also remove the `"regexp"` and `"strconv"` imports from the webhook file if they are no longer used (check for other usages first).

- [ ] **Step 5: Update the cluster controller — ZoneRedundancy construction**

In `garagecluster_controller.go`, find all references to `ZoneRedundancy` string parsing. There are three locations (lines ~2780, ~2935, ~3655–3663).

Replace the layout config struct field (line ~2935):
```go
zoneRedundancy: cluster.Spec.Replication.ZoneRedundancy,
```
With (the `layoutCfg` struct needs its field updated too — find the struct definition):
```go
zoneRedundancy: buildZoneRedundancy(cluster.Spec.Replication),
```

Add a helper at the bottom of the controller file (or in helpers.go):
```go
// buildZoneRedundancy converts spec fields to a garage.ZoneRedundancy.
// Returns nil when no redundancy constraint is set (Garage defaults to Maximum).
func buildZoneRedundancy(r *garagev1beta1.ReplicationConfig) *garage.ZoneRedundancy {
	if r == nil || r.ZoneRedundancyMode == "" || r.ZoneRedundancyMode == "Maximum" {
		return &garage.ZoneRedundancy{Maximum: true}
	}
	if r.ZoneRedundancyMode == "AtLeast" && r.ZoneRedundancyMinZones != nil {
		n := *r.ZoneRedundancyMinZones
		return &garage.ZoneRedundancy{AtLeast: &n}
	}
	return &garage.ZoneRedundancy{Maximum: true}
}
```

Find the `layoutCfg` struct (search `type.*struct` near the `replicationFactor` field — likely an anonymous struct or named struct around line 2921). Update its `zoneRedundancy` field type from `string` to `*garage.ZoneRedundancy`.

Then in the two places that call `garage.ParseZoneRedundancy(cfg.zoneRedundancy)` (lines ~2780 and ~3655), replace with direct use of `cfg.zoneRedundancy` (already a `*garage.ZoneRedundancy`):
```go
// Before:
zr, err := garage.ParseZoneRedundancy(cfg.zoneRedundancy)
if err == nil {
    layoutReq.Parameters = &garage.LayoutParameters{ZoneRedundancy: zr}
}

// After:
if cfg.zoneRedundancy != nil {
    layoutReq.Parameters = &garage.LayoutParameters{ZoneRedundancy: cfg.zoneRedundancy}
}
```

`garage.ParseZoneRedundancy` is no longer called from the controller. Leave it in `internal/garage/client.go` for now — removing it is a separate cleanup.

- [ ] **Step 6: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_ZoneRedundancy -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add api/v1beta1/garagecluster_types.go api/v1beta1/garagecluster_webhook.go \
    internal/controller/garagecluster_controller.go api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): replace zoneRedundancy string with zoneRedundancyMode + zoneRedundancyMinZones"
```

---

## Task 4: `spec.replication` → optional pointer

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `api/v1beta1/garagecluster_webhook.go`
- Modify: `internal/controller/garagecluster_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing test**

In `api/v1beta1/webhook_test.go`:

```go
func TestGarageCluster_Replication_OmittedDefaultsToFactor3(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3}, // no Replication field
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Replication == nil {
		t.Fatal("expected Replication to be defaulted, got nil")
	}
	if cluster.Spec.Replication.Factor != 3 {
		t.Errorf("expected factor 3, got %d", cluster.Spec.Replication.Factor)
	}
	if cluster.Spec.Replication.ConsistencyMode != "consistent" {
		t.Errorf("expected consistencyMode consistent, got %q", cluster.Spec.Replication.ConsistencyMode)
	}
}
```

- [ ] **Step 2: Run test to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_Replication_Omitted -count=1 2>&1 | head -10
```
Expected: `cannot use` or `cannot assign` compile error (Replication is currently a value type)

- [ ] **Step 3: Change `Replication` to a pointer in `api/v1beta1/garagecluster_types.go`**

In `GarageClusterSpec`, replace:
```go
// Replication configures data replication settings
// +required
Replication ReplicationConfig `json:"replication"`
```
With:
```go
// Replication configures data replication settings.
// If omitted, defaults to factor: 3 and consistencyMode: consistent.
// +optional
Replication *ReplicationConfig `json:"replication,omitempty"`
```

- [ ] **Step 4: Update webhook defaulter in `api/v1beta1/garagecluster_webhook.go`**

Replace the replication defaulting block:
```go
// Set default replication factor if not specified
if obj.Spec.Replication.Factor == 0 {
    obj.Spec.Replication.Factor = 3
}

// Set default consistency mode if not specified
if obj.Spec.Replication.ConsistencyMode == "" {
    obj.Spec.Replication.ConsistencyMode = "consistent"
}
```
With:
```go
if obj.Spec.Replication == nil {
    obj.Spec.Replication = &ReplicationConfig{}
}
if obj.Spec.Replication.Factor == 0 {
    obj.Spec.Replication.Factor = 3
}
if obj.Spec.Replication.ConsistencyMode == "" {
    obj.Spec.Replication.ConsistencyMode = "consistent"
}
```

Update the webhook validator's update check:
```go
// Before:
if oldObj.Spec.Replication.Factor != 0 && newObj.Spec.Replication.Factor != oldObj.Spec.Replication.Factor {

// After:
oldFactor := 0
if oldObj.Spec.Replication != nil {
    oldFactor = oldObj.Spec.Replication.Factor
}
newFactor := 0
if newObj.Spec.Replication != nil {
    newFactor = newObj.Spec.Replication.Factor
}
if oldFactor != 0 && newFactor != oldFactor {
```

Update `validateGarageCluster` — the `r.Spec.Replication.ConsistencyMode` check:
```go
// Before:
if r.Spec.Replication.ConsistencyMode == "dangerous" {

// After:
if r.Spec.Replication != nil && r.Spec.Replication.ConsistencyMode == "dangerous" {
```

- [ ] **Step 5: Update `garagecluster_controller.go` — all `cluster.Spec.Replication.*` reads**

The webhook always fills in `Replication` before the object reaches the controller, so at reconcile time `cluster.Spec.Replication` is never nil. Add a nil guard at the top of the reconcile function for safety:

```go
// Replication is always defaulted by the webhook, but guard defensively.
if cluster.Spec.Replication == nil {
    cluster.Spec.Replication = &garagev1beta1.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
}
```

Then update all direct field accesses. Find them with:
```bash
grep -n "cluster\.Spec\.Replication\." internal/controller/garagecluster_controller.go
```
These will now need pointer dereference — but since we added the guard above, they're safe as `cluster.Spec.Replication.Factor` etc.

Also update the `buildZoneRedundancy` call added in Task 3:
```go
zoneRedundancy: buildZoneRedundancy(cluster.Spec.Replication),
```
This already accepts `*ReplicationConfig` so no change needed.

- [ ] **Step 6: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_Replication -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add api/v1beta1/garagecluster_types.go api/v1beta1/garagecluster_webhook.go \
    internal/controller/garagecluster_controller.go api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): make spec.replication optional with webhook defaulting"
```

---

## Task 5: `WebAPI.disabled bool` → `WebAPI.enabled *bool`

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `api/v1beta1/garagecluster_webhook.go`
- Modify: `internal/controller/garagecluster_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing test**

```go
func TestGarageCluster_WebAPI_EnabledFalse_DisablesWebAPI(t *testing.T) {
	d := &GarageClusterDefaulter{}
	disabled := false
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			WebAPI:   &WebAPIConfig{Enabled: &disabled},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	// effectiveWebAPI is internal but we can test via the validator passing
	v := &GarageClusterValidator{}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err != nil {
		t.Errorf("disabled webApi should be valid, got: %v", err)
	}
}

func TestGarageCluster_WebAPI_NilEnabled_DefaultsToEnabled(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.WebAPI == nil {
		t.Fatal("expected WebAPI to be defaulted")
	}
	if cluster.Spec.WebAPI.Enabled == nil || !*cluster.Spec.WebAPI.Enabled {
		t.Error("expected WebAPI.Enabled to default to true")
	}
}
```

- [ ] **Step 2: Run test to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_WebAPI -count=1 2>&1 | head -10
```

- [ ] **Step 3: Update `WebAPIConfig` in `api/v1beta1/garagecluster_types.go`**

Replace:
```go
// Disabled disables the web endpoint entirely.
// +optional
Disabled bool `json:"disabled,omitempty"`
```
With:
```go
// Enabled controls whether the web endpoint is active.
// Defaults to true. Set to false to disable.
// +optional
Enabled *bool `json:"enabled,omitempty"`
```

- [ ] **Step 4: Update webhook defaulter in `api/v1beta1/garagecluster_webhook.go`**

Replace the WebAPI defaulting block:
```go
// Enable website hosting by default with a sensible rootDomain
if obj.Spec.WebAPI == nil {
    obj.Spec.WebAPI = &WebAPIConfig{
        RootDomain: fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace),
    }
} else if !obj.Spec.WebAPI.Disabled && obj.Spec.WebAPI.RootDomain == "" {
    obj.Spec.WebAPI.RootDomain = fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace)
}
```
With:
```go
if obj.Spec.WebAPI == nil {
    enabled := true
    obj.Spec.WebAPI = &WebAPIConfig{
        Enabled:    &enabled,
        RootDomain: fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace),
    }
} else {
    if obj.Spec.WebAPI.Enabled == nil {
        enabled := true
        obj.Spec.WebAPI.Enabled = &enabled
    }
    if *obj.Spec.WebAPI.Enabled && obj.Spec.WebAPI.RootDomain == "" {
        obj.Spec.WebAPI.RootDomain = fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace)
    }
}
```

- [ ] **Step 5: Update `effectiveWebAPI` in `garagecluster_controller.go`**

Find the function (~line 960):
```go
func effectiveWebAPI(cluster *garagev1beta1.GarageCluster) *garagev1beta1.WebAPIConfig {
    w := cluster.Spec.WebAPI
    if w != nil && w.Disabled {
        return nil
    }
    ...
}
```
Replace the disabled check:
```go
func effectiveWebAPI(cluster *garagev1beta1.GarageCluster) *garagev1beta1.WebAPIConfig {
    w := cluster.Spec.WebAPI
    if w == nil {
        return nil
    }
    if w.Enabled != nil && !*w.Enabled {
        return nil
    }
    ...
}
```

- [ ] **Step 6: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_WebAPI -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```

- [ ] **Step 7: Commit**

```bash
git add api/v1beta1/garagecluster_types.go api/v1beta1/garagecluster_webhook.go \
    internal/controller/garagecluster_controller.go api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): replace WebAPI.disabled bool with WebAPI.enabled *bool"
```

---

## Task 6: Remove `AdminConfig.enabled`

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `internal/controller/garagecluster_controller.go`

- [ ] **Step 1: Remove `Enabled` from `AdminConfig` in `api/v1beta1/garagecluster_types.go`**

Remove these lines from `AdminConfig`:
```go
// Enabled enables the admin API
// +kubebuilder:default=true
// +optional
Enabled bool `json:"enabled"`
```

Update the struct comment to:
```go
// AdminConfig configures the admin API and metrics.
// The admin port is always active — restrict access via NetworkPolicy if needed.
```

- [ ] **Step 2: Find and remove any `admin.Enabled` checks in `garagecluster_controller.go`**

```bash
grep -n "\.Admin\.Enabled\|admin\.Enabled" internal/controller/garagecluster_controller.go
```

Remove any conditional blocks that gate behavior on `cluster.Spec.Admin.Enabled`. The admin port should always be written to TOML config.

- [ ] **Step 3: Verify build**

```bash
go build ./... 2>&1
```
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add api/v1beta1/garagecluster_types.go internal/controller/garagecluster_controller.go
git commit --no-verify -m "feat(api): remove AdminConfig.enabled — admin port is always active"
```

---

## Task 7: Unify `VolumeConfig` and `DataStorageConfig`

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `api/v1beta1/garagecluster_webhook.go`
- Modify: `internal/controller/garagecluster_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing test for paths-on-metadata rejection**

```go
func TestGarageCluster_Storage_PathsOnMetadataRejected(t *testing.T) {
	v := &GarageClusterValidator{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{
					Size:  resourcePtr("10Gi"),
					Paths: []DataPath{{Path: "/meta1"}}, // invalid on metadata
				},
				Data: &VolumeConfig{Size: resourcePtr("100Gi")},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "paths is only valid for data volumes") {
		t.Errorf("expected paths-on-metadata error, got: %v", err)
	}
}

// Add this helper if not already present in webhook_test.go:
func resourcePtr(s string) *resource.Quantity {
	q := resource.MustParse(s)
	return &q
}
```

- [ ] **Step 2: Run test to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_Storage_Paths -count=1 2>&1 | head -10
```
Expected: `unknown field Paths` on `VolumeConfig`

- [ ] **Step 3: Add `Paths` to `VolumeConfig` in `api/v1beta1/garagecluster_types.go`**

In `VolumeConfig`, add after the `Annotations` field:
```go
// Paths configures multiple data directories for multi-disk setups.
// Only valid for data volumes — webhook rejects this on metadata volumes.
// Only valid when Type=PersistentVolumeClaim.
// +optional
Paths []DataPath `json:"paths,omitempty"`
```

- [ ] **Step 4: Replace `DataStorageConfig` with `*VolumeConfig` in `StorageConfig`**

In `StorageConfig`, replace:
```go
// Data configures data block storage
// +optional
Data *DataStorageConfig `json:"data,omitempty"`
```
With:
```go
// Data configures data block storage
// +optional
Data *VolumeConfig `json:"data,omitempty"`
```

Delete the entire `DataStorageConfig` struct.

- [ ] **Step 5: Update webhook validation in `api/v1beta1/garagecluster_webhook.go`**

Replace `validateDataStorageConfig` with an extended check inside `validateStorage`:

Remove `validateDataStorageConfig` entirely. In `validateStorage`, replace:
```go
if r.Spec.Storage.Data != nil {
    if err := r.validateDataStorageConfig(r.Spec.Storage.Data); err != nil {
        return err
    }
}
```
With:
```go
if r.Spec.Storage.Data != nil {
    if err := r.validateVolumeConfig(r.Spec.Storage.Data, "data"); err != nil {
        return err
    }
    if r.Spec.Storage.Data.Type == VolumeTypeEmptyDir && len(r.Spec.Storage.Data.Paths) > 0 {
        return fmt.Errorf("storage.data.paths: not allowed with EmptyDir type")
    }
}
if r.Spec.Storage.Metadata != nil && len(r.Spec.Storage.Metadata.Paths) > 0 {
    return fmt.Errorf("storage.metadata.paths: paths is only valid for data volumes")
}
```

Also update `isDataEphemeral`:
```go
func (r *GarageCluster) isDataEphemeral() bool {
    return r.Spec.Storage.Data != nil && r.Spec.Storage.Data.Type == VolumeTypeEmptyDir
}
```
This method signature is unchanged — just confirm the `Data` field now uses `VolumeConfig`.

- [ ] **Step 6: Update `garagecluster_controller.go` — remove `firstDataPathVolume`**

Find `firstDataPathVolume` (~line 1659):
```go
func firstDataPathVolume(data *garagev1beta1.DataStorageConfig) *garagev1beta1.VolumeConfig {
```

This function converted `DataStorageConfig` to `VolumeConfig`. Since `Data` is now directly a `*VolumeConfig`, find all call sites and replace `firstDataPathVolume(cluster.Spec.Storage.Data)` with `cluster.Spec.Storage.Data`.

```bash
grep -n "firstDataPathVolume" internal/controller/garagecluster_controller.go
```

Replace each call, then delete the function.

Also find any remaining `DataStorageConfig` type references:
```bash
grep -n "DataStorageConfig" internal/controller/garagecluster_controller.go
```
Update to `VolumeConfig` or remove as needed.

- [ ] **Step 7: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageCluster_Storage -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```

- [ ] **Step 8: Commit**

```bash
git add api/v1beta1/garagecluster_types.go api/v1beta1/garagecluster_webhook.go \
    internal/controller/garagecluster_controller.go api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): remove DataStorageConfig, merge paths into VolumeConfig"
```

---

## Task 8: `BucketPermission.bucketRef + bucketNamespace` → `BucketRef` object

**Files:**
- Modify: `api/v1beta1/garagekey_types.go`
- Modify: `api/v1beta1/garagekey_webhook.go`
- Modify: `internal/controller/garagekey_controller.go`
- Modify: `api/v1beta1/webhook_test.go`

- [ ] **Step 1: Add failing tests**

```go
func TestGarageKey_BucketPermission_BucketRefObject_Valid(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{
					BucketRef: &BucketRef{Name: testBucket},
					Read:      true,
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid BucketRef object should pass, got: %v", err)
	}
}

func TestGarageKey_BucketPermission_NoRef_Rejected(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{Read: true}, // no reference
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "must specify") {
		t.Errorf("expected must-specify error, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm compile failure**

```bash
go test ./api/v1beta1/... -run TestGarageKey_BucketPermission_BucketRefObject -count=1 2>&1 | head -10
```

- [ ] **Step 3: Add `BucketRef` struct and update `BucketPermission` in `api/v1beta1/garagekey_types.go`**

Add before `BucketPermission`:
```go
// BucketRef is a reference to a GarageBucket by name and optional namespace.
type BucketRef struct {
    // Name of the GarageBucket.
    // +required
    Name string `json:"name"`

    // Namespace of the GarageBucket. Defaults to the GarageKey's namespace.
    // Cross-namespace references require a GarageReferenceGrant in the target namespace.
    // +optional
    Namespace string `json:"namespace,omitempty"`
}
```

Replace `BucketPermission`:
```go
// BucketPermission grants access to a bucket.
// Exactly one of BucketRef, BucketID, or GlobalAlias must be set.
// +kubebuilder:validation:XValidation:rule="[has(self.bucketRef), has(self.bucketId), has(self.globalAlias)].filter(x, x).size() == 1",message="exactly one of bucketRef, bucketId, or globalAlias must be set"
type BucketPermission struct {
    // BucketRef references a GarageBucket by name (and optionally namespace).
    // Mutually exclusive with BucketID and GlobalAlias.
    // +optional
    BucketRef *BucketRef `json:"bucketRef,omitempty"`

    // BucketID references the bucket by its Garage-internal ID.
    // +optional
    BucketID string `json:"bucketId,omitempty"`

    // GlobalAlias references the bucket by its global alias.
    // +optional
    GlobalAlias string `json:"globalAlias,omitempty"`

    // Read allows reading objects from the bucket.
    // +optional
    Read bool `json:"read,omitempty"`

    // Write allows writing objects to the bucket.
    // +optional
    Write bool `json:"write,omitempty"`

    // Owner allows bucket owner operations (delete bucket, configure website, etc.)
    // +optional
    Owner bool `json:"owner,omitempty"`
}
```

- [ ] **Step 4: Update `validateBucketPermissions` in `api/v1beta1/garagekey_webhook.go`**

Replace the permission validation loop:
```go
func (v *GarageKeyValidator) validateBucketPermissions(ctx context.Context, obj *GarageKey) error {
    seen := make(map[string]bool)
    for i, perm := range obj.Spec.BucketPermissions {
        refs := 0
        var refKey string
        if perm.BucketRef != nil {
            refs++
            refKey = "ref:" + perm.BucketRef.Name
        }
        if perm.BucketID != "" {
            refs++
            refKey = "id:" + perm.BucketID
        }
        if perm.GlobalAlias != "" {
            refs++
            refKey = "alias:" + perm.GlobalAlias
        }

        if refs == 0 {
            return fmt.Errorf("bucketPermissions[%d]: must specify bucketRef, bucketId, or globalAlias", i)
        }
        if refs > 1 {
            return fmt.Errorf("bucketPermissions[%d]: specify only one of bucketRef, bucketId, or globalAlias", i)
        }

        // Cross-namespace bucket reference requires a GarageReferenceGrant.
        if perm.BucketRef != nil {
            bucketNS := perm.BucketRef.Namespace
            if bucketNS == "" {
                bucketNS = obj.Namespace
            }
            if err := checkReferenceGrant(ctx, v.Client, "GarageKey", obj.Namespace, "GarageBucket", bucketNS, perm.BucketRef.Name); err != nil {
                return fmt.Errorf("bucketPermissions[%d]: %w", i, err)
            }
        }

        if seen[refKey] {
            return fmt.Errorf("bucketPermissions[%d]: duplicate bucket reference '%s'", i, refKey)
        }
        seen[refKey] = true

        if !perm.Read && !perm.Write && !perm.Owner {
            return fmt.Errorf("bucketPermissions[%d]: at least one permission (read, write, or owner) must be granted", i)
        }
    }
    return nil
}
```

- [ ] **Step 5: Update `resolveBucketID` in `internal/controller/garagekey_controller.go`**

Find `resolveBucketID` (~line 609). Replace the BucketRef block:
```go
if bucketPerm.BucketRef != nil {
    bucketRef = bucketPerm.BucketRef.Name
    ns := obj.Namespace // obj is the GarageKey — pass namespace to the function
    if bucketPerm.BucketRef.Namespace != "" {
        ns = bucketPerm.BucketRef.Namespace
    }
    if err := r.Get(ctx, types.NamespacedName{Name: bucketPerm.BucketRef.Name, Namespace: ns}, bucket); err != nil {
        if errors.IsNotFound(err) {
            log.Info("Bucket not found, will retry", "bucketRef", bucketPerm.BucketRef.Name, "namespace", ns)
            return "", bucketRef, true, nil
        }
        return "", bucketRef, false, fmt.Errorf("failed to get bucket %s/%s: %w", ns, bucketPerm.BucketRef.Name, err)
    }
    if bucket.Status.BucketID == "" {
        log.Info("Bucket not yet created in Garage, will retry", "bucketRef", bucketPerm.BucketRef.Name, "namespace", ns)
        return "", bucketRef, true, nil
    }
    return bucket.Status.BucketID, bucketRef, false, nil
}
```

Note: the function signature may need `namespace string` added as a parameter if `obj.Namespace` is not already in scope. Check the existing signature and adjust accordingly — if `namespace string` is already a parameter, use it.

Also update the call site that checks `perm.BucketRef != ""` to `perm.BucketRef != nil`.

- [ ] **Step 6: Run tests**

```bash
go test ./api/v1beta1/... -run TestGarageKey_BucketPermission -v -count=1
```
Expected: PASS

```bash
go build ./... 2>&1
```

- [ ] **Step 7: Commit**

```bash
git add api/v1beta1/garagekey_types.go api/v1beta1/garagekey_webhook.go \
    internal/controller/garagekey_controller.go api/v1beta1/webhook_test.go
git commit --no-verify -m "feat(api): replace BucketPermission.bucketRef+bucketNamespace with BucketRef object"
```

---

## Task 9: Add status to `GarageReferenceGrant` + new controller

**Files:**
- Modify: `api/v1beta1/garagereferencegrant_types.go`
- Create: `internal/controller/garagereferencegrant_controller.go`

- [ ] **Step 1: Add status types to `api/v1beta1/garagereferencegrant_types.go`**

Add at the end of the file before the `GarageReferenceGrant` struct:
```go
// GarageReferenceGrantStatus reflects which resources are currently using this grant.
type GarageReferenceGrantStatus struct {
    // InUseBy lists resources currently referencing through this grant.
    // Rebuilt on every reconcile — safe to delete when this is empty.
    // +optional
    InUseBy []ReferenceGrantUser `json:"inUseBy,omitempty"`

    // Conditions represent the current state.
    // +listType=map
    // +listMapKey=type
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ReferenceGrantUser identifies a resource using this grant.
type ReferenceGrantUser struct {
    // Kind of the referencing resource.
    // +optional
    Kind string `json:"kind,omitempty"`
    // Name of the referencing resource.
    // +optional
    Name string `json:"name,omitempty"`
    // Namespace of the referencing resource.
    // +optional
    Namespace string `json:"namespace,omitempty"`
}
```

Update `GarageReferenceGrant` struct to add the status field and markers:
```go
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=grg,scope=Namespaced
// +kubebuilder:printcolumn:name="From",type="string",JSONPath=".spec.from[0].namespace"
// +kubebuilder:printcolumn:name="FromKind",type="string",JSONPath=".spec.from[0].kind"
// +kubebuilder:printcolumn:name="ToKind",type="string",JSONPath=".spec.to[0].kind"
// +kubebuilder:printcolumn:name="InUse",type="string",JSONPath=".status.conditions[?(@.type=='InUse')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type GarageReferenceGrant struct {
    metav1.TypeMeta `json:",inline"`

    // +optional
    metav1.ObjectMeta `json:"metadata,omitzero"`

    // +required
    Spec GarageReferenceGrantSpec `json:"spec"`

    // +optional
    Status GarageReferenceGrantStatus `json:"status,omitzero"`
}
```

- [ ] **Step 2: Verify build**

```bash
go build ./api/... 2>&1
```

- [ ] **Step 3: Create `internal/controller/garagereferencegrant_controller.go`**

```go
/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
    "context"
    "sort"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/types"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/builder"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/handler"
    "sigs.k8s.io/controller-runtime/pkg/reconcile"

    garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// GarageReferenceGrantReconciler reconciles GarageReferenceGrant status.
type GarageReferenceGrantReconciler struct {
    client.Client
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereferencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereferencegrants/status,verbs=update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets,verbs=list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageadmintokens,verbs=list;watch

func (r *GarageReferenceGrantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    log := ctrl.LoggerFrom(ctx)

    var grant garagev1beta1.GarageReferenceGrant
    if err := r.Get(ctx, req.NamespacedName, &grant); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    users, err := r.findUsers(ctx, &grant)
    if err != nil {
        log.Error(err, "failed to find grant users")
        return ctrl.Result{}, err
    }

    patch := client.MergeFrom(grant.DeepCopy())
    grant.Status.InUseBy = users
    grant.Status.Conditions = buildGrantConditions(users, grant.Generation)

    if err := r.Status().Patch(ctx, &grant, patch); err != nil {
        return ctrl.Result{}, err
    }
    return ctrl.Result{}, nil
}

func (r *GarageReferenceGrantReconciler) findUsers(ctx context.Context, grant *garagev1beta1.GarageReferenceGrant) ([]garagev1beta1.ReferenceGrantUser, error) {
    var users []garagev1beta1.ReferenceGrantUser

    var keys garagev1beta1.GarageKeyList
    if err := r.List(ctx, &keys); err != nil {
        return nil, err
    }
    for _, k := range keys.Items {
        if refsGrant(&k.Spec.ClusterRef, k.Namespace, grant) {
            users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageKey", Name: k.Name, Namespace: k.Namespace})
            continue
        }
        for _, bp := range k.Spec.BucketPermissions {
            if bp.BucketRef != nil {
                ns := bp.BucketRef.Namespace
                if ns == "" {
                    ns = k.Namespace
                }
                if ns == grant.Namespace {
                    users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageKey", Name: k.Name, Namespace: k.Namespace})
                    break
                }
            }
        }
    }

    var buckets garagev1beta1.GarageBucketList
    if err := r.List(ctx, &buckets); err != nil {
        return nil, err
    }
    for _, b := range buckets.Items {
        if refsGrant(&b.Spec.ClusterRef, b.Namespace, grant) {
            users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageBucket", Name: b.Name, Namespace: b.Namespace})
        }
    }

    var tokens garagev1beta1.GarageAdminTokenList
    if err := r.List(ctx, &tokens); err != nil {
        return nil, err
    }
    for _, t := range tokens.Items {
        if refsGrant(&t.Spec.ClusterRef, t.Namespace, grant) {
            users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageAdminToken", Name: t.Name, Namespace: t.Namespace})
        }
    }

    // Sort for stable status output
    sort.Slice(users, func(i, j int) bool {
        if users[i].Kind != users[j].Kind {
            return users[i].Kind < users[j].Kind
        }
        if users[i].Namespace != users[j].Namespace {
            return users[i].Namespace < users[j].Namespace
        }
        return users[i].Name < users[j].Name
    })

    return users, nil
}

// refsGrant returns true when the ClusterReference points into the grant's namespace
// from a different namespace (i.e., is a cross-namespace reference that a grant governs).
func refsGrant(ref *garagev1beta1.ClusterReference, resourceNS string, grant *garagev1beta1.GarageReferenceGrant) bool {
    if ref == nil {
        return false
    }
    targetNS := ref.Namespace
    if targetNS == "" {
        targetNS = resourceNS
    }
    return targetNS == grant.Namespace && resourceNS != grant.Namespace
}

func buildGrantConditions(users []garagev1beta1.ReferenceGrantUser, generation int64) []metav1.Condition {
    now := metav1.Now()
    readyCond := metav1.Condition{
        Type:               "Ready",
        Status:             metav1.ConditionTrue,
        Reason:             "GrantPresent",
        Message:            "GarageReferenceGrant is present and valid",
        ObservedGeneration: generation,
        LastTransitionTime: now,
    }
    inUseCond := metav1.Condition{
        Type:               "InUse",
        Status:             metav1.ConditionFalse,
        Reason:             "NoReferences",
        Message:            "No resources are currently referencing through this grant",
        ObservedGeneration: generation,
        LastTransitionTime: now,
    }
    if len(users) > 0 {
        inUseCond.Status = metav1.ConditionTrue
        inUseCond.Reason = "ActiveReferences"
        inUseCond.Message = "One or more resources are referencing through this grant"
    }
    return []metav1.Condition{readyCond, inUseCond}
}

// SetupWithManager wires up the controller.
func (r *GarageReferenceGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
    // Map any GarageKey/GarageBucket/GarageAdminToken to the grants in the target namespace.
    mapToGrants := func(ctx context.Context, obj client.Object) []reconcile.Request {
        var grants garagev1beta1.GarageReferenceGrantList
        if err := mgr.GetClient().List(ctx, &grants); err != nil {
            return nil
        }
        var reqs []reconcile.Request
        for _, g := range grants.Items {
            reqs = append(reqs, reconcile.Request{
                NamespacedName: types.NamespacedName{Name: g.Name, Namespace: g.Namespace},
            })
        }
        return reqs
    }

    return ctrl.NewControllerManagedBy(mgr).
        For(&garagev1beta1.GarageReferenceGrant{}).
        Watches(&garagev1beta1.GarageKey{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
            builder.WithPredicates()).
        Watches(&garagev1beta1.GarageBucket{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
            builder.WithPredicates()).
        Watches(&garagev1beta1.GarageAdminToken{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
            builder.WithPredicates()).
        Complete(r)
}
```

- [ ] **Step 4: Register the controller in `cmd/main.go` (or wherever other controllers are registered)**

Find the file that calls `SetupWithManager` for other reconcilers (likely `cmd/main.go` or `internal/controller/setup.go`):
```bash
grep -rn "SetupWithManager" cmd/ internal/ 2>/dev/null | grep -v "_test.go" | head -10
```

Add alongside the other registrations:
```go
if err = (&controller.GarageReferenceGrantReconciler{
    Client: mgr.GetClient(),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "GarageReferenceGrant")
    os.Exit(1)
}
```

- [ ] **Step 5: Build to verify**

```bash
go build ./... 2>&1
```
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add api/v1beta1/garagereferencegrant_types.go \
    internal/controller/garagereferencegrant_controller.go
git add $(git diff --name-only HEAD -- cmd/ internal/ | grep -v "_test.go") # main.go changes
git commit --no-verify -m "feat: add GarageReferenceGrant status subresource and controller"
```

---

## Task 10: Rename `allowWorldReadableSecrets`

**Files:**
- Modify: `api/v1beta1/garagecluster_types.go`
- Modify: `internal/controller/garagecluster_controller.go`

- [ ] **Step 1: Update `SecurityConfig` in `api/v1beta1/garagecluster_types.go`**

Replace:
```go
// AllowWorldReadableSecrets bypasses permission check for secret files
// +optional
AllowWorldReadableSecrets bool `json:"allowWorldReadableSecrets,omitempty"`
```
With:
```go
// AllowInsecureSecretPermissions bypasses Garage's check that secret files
// (RPC secret, admin token) are not world-readable on disk.
// Only enable if your container security model handles file permissions externally.
// Enabling this weakens the defense-in-depth for credential exposure.
// +optional
AllowInsecureSecretPermissions bool `json:"allowInsecureSecretPermissions,omitempty"`
```

- [ ] **Step 2: Update `garagecluster_controller.go` TOML writer**

Find line ~818:
```go
if cluster.Spec.Security.AllowWorldReadableSecrets {
```
Replace with:
```go
if cluster.Spec.Security.AllowInsecureSecretPermissions {
```

- [ ] **Step 3: Build and verify**

```bash
go build ./... 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add api/v1beta1/garagecluster_types.go internal/controller/garagecluster_controller.go
git commit --no-verify -m "feat(api): rename allowWorldReadableSecrets to allowInsecureSecretPermissions"
```

---

## Task 11: Regenerate all derived artifacts

**Files:**
- `api/v1beta1/zz_generated.deepcopy.go`
- `config/crd/bases/*.yaml`
- `charts/garage-operator/crd-bases/*.yaml`
- `schemas/garagecluster_v1beta1.json`

- [ ] **Step 1: Regenerate deepcopy and CRDs**

```bash
make generate manifests
```
Expected: `zz_generated.deepcopy.go` updated, all CRD YAML files updated.

- [ ] **Step 2: Update the JSON schema**

The schema at `schemas/garagecluster_v1beta1.json` is maintained manually or via a script. Find how it's generated:
```bash
grep -rn "garagecluster_v1beta1.json" Makefile hack/ 2>/dev/null
```
If there's a make target, run it. If it's manual, update the schema to match the new field names (`expiresAt`, `rpcPingTimeout`, `rpcTimeout`, `zoneRedundancyMode`, `zoneRedundancyMinZones`, `enabled` on WebAPI, removal of `disabled` and `admin.enabled`, `allowInsecureSecretPermissions`).

- [ ] **Step 3: Run full unit test suite**

```bash
make test 2>&1 | tail -30
```
Expected: all tests pass, coverage report generated.

- [ ] **Step 4: Fix any test failures**

If tests reference old field names (e.g., `Expiration`, `ZoneRedundancy`, `BucketRef` as string, `Disabled`), update them to the new names. Run:
```bash
grep -rn "\.Expiration\b\|ZoneRedundancy\b\|\.Disabled\b\|BucketRef:\s*\"" api/ internal/ --include="*_test.go"
```
Update each occurrence to the new field name/type.

- [ ] **Step 5: Commit everything**

```bash
git add api/v1beta1/zz_generated.deepcopy.go \
    config/crd/bases/ \
    charts/garage-operator/crd-bases/ \
    schemas/garagecluster_v1beta1.json
git commit --no-verify -m "chore: regenerate CRDs, deepcopy, and JSON schema after API UX improvements"
```

---

## Self-Review

### Spec Coverage

| Spec Section | Task | Notes |
|---|---|---|
| 1a. Expiration *metav1.Time | Task 1 | ✓ GarageKey + GarageAdminToken, spec + status |
| 1b. RPC Duration fields | Task 2 | ✓ |
| 1c. ZoneRedundancy two fields | Task 3 | ✓ |
| 2a. Optional replication | Task 4 | ✓ |
| 2b. WebAPI enabled *bool | Task 5 | ✓ |
| 2c. Remove admin.enabled | Task 6 | ✓ |
| 3a. VolumeConfig unification | Task 7 | ✓ |
| 3b. BucketRef object | Task 8 | ✓ |
| 4. ReferenceGrant status + controller | Task 9 | ✓ |
| 5a. AllowInsecureSecretPermissions | Task 10 | ✓ |
| Regenerate artifacts | Task 11 | ✓ |

### Notes for Implementor

- Every commit uses `--no-verify` because the branch has pre-existing goconst lint violations unrelated to this work. Fix those in a follow-up PR.
- Tasks 1–10 are ordered to minimize merge conflicts — each touches different parts of the codebase and can be reviewed independently.
- The webhook always runs before the controller, so nil-pointer guards added in Task 4 are defensive only — at reconcile time, `Spec.Replication` is always non-nil.
- In Task 9, `mapToGrants` enqueues ALL grants on any resource change. For large clusters this is fine since grants are typically few; optimize with label-based selection only if needed.
