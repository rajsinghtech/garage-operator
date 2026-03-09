# WebAPI/K2VAPI Presence-Based Gating Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove `Enabled` field from `WebAPIConfig` and `K2VAPIConfig`, gate on struct presence instead, make `rootDomain` required for WebAPI.

**Architecture:** Match upstream Garage's `Option<WebConfig>` / `Option<K2VApiConfig>` semantics — nil pointer = disabled, non-nil = enabled. CRD validation enforces `rootDomain` when `webApi` is present.

**Tech Stack:** Go, Kubebuilder, controller-runtime webhooks

**Issue:** https://github.com/rajsinghtech/garage-operator/issues/63

---

### Task 1: Update Type Definitions

**Files:**
- Modify: `api/v1alpha1/garagecluster_types.go:533-584`

**Step 1: Remove `Enabled` from K2VAPIConfig and clean up**

Replace lines 533-550 with:

```go
// K2VAPIConfig configures the K2V (key-value) API.
// Presence of this field enables K2V — omit to disable.
type K2VAPIConfig struct {
	// BindPort is the port to bind for K2V API
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3904
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the K2V API.
	// Can be a TCP address or Unix socket path (e.g., "unix:///run/garage/k2v.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`
}
```

**Step 2: Remove `Enabled` from WebAPIConfig, make `rootDomain` required**

Replace lines 552-584 with:

```go
// WebAPIConfig configures static website hosting.
// Presence of this field enables the web endpoint — omit to disable.
type WebAPIConfig struct {
	// RootDomain is the root domain suffix for bucket website access.
	// Bucket websites are accessible via <bucket-name>.<root-domain>.
	//
	// Examples:
	// - ".web.garage.tld" -> Access bucket "site" website at "site.web.garage.tld"
	// - ".sites.example.com" -> Access bucket "blog" at "blog.sites.example.com"
	//
	// Note: Include the leading dot.
	// +kubebuilder:validation:MinLength=1
	RootDomain string `json:"rootDomain"`

	// BindPort is the port to bind for web serving
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3902
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the Web API.
	// Can be a TCP address or Unix socket path (e.g., "unix:///run/garage/web.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// AddHostToMetrics adds the domain name to metrics labels for per-domain tracking.
	// +optional
	AddHostToMetrics bool `json:"addHostToMetrics,omitempty"`
}
```

**Step 3: Update parent struct comments**

In `GarageClusterSpec` (lines 74-80), update comments:

```go
	// K2VAPI configures the K2V (key-value) API endpoint.
	// Omit to disable K2V.
	// +optional
	K2VAPI *K2VAPIConfig `json:"k2vApi,omitempty"`

	// WebAPI configures the static website hosting endpoint.
	// Omit to disable website hosting.
	// +optional
	WebAPI *WebAPIConfig `json:"webApi,omitempty"`
```

**Step 4: Verify it compiles**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && go build ./...`
Expected: PASS

**Step 5: Commit**

```
feat: remove Enabled from WebAPIConfig and K2VAPIConfig types

Presence of the struct now signals enablement, matching upstream
Garage's Option<T> semantics. rootDomain is now required for webApi.

Closes #63
```

---

### Task 2: Update Webhook Validation

**Files:**
- Modify: `api/v1alpha1/garagecluster_webhook.go:314-348`

**Step 1: Add rootDomain validation to validateAPIs()**

After the existing `webApi.bindAddress` check (line 338), add:

```go
	if r.Spec.WebAPI != nil && r.Spec.WebAPI.RootDomain == "" {
		return fmt.Errorf("webApi.rootDomain is required when webApi is configured")
	}
```

This is belt-and-suspenders with the CRD `MinLength=1` marker.

**Step 2: Verify it compiles**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && go build ./...`
Expected: PASS

**Step 3: Commit**

```
feat: add webhook validation for webApi.rootDomain
```

---

### Task 3: Update Controller Config Generation

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`

**Step 1: Simplify writeK2VAPIConfig (line 840-853)**

Change the guard from:
```go
if cluster.Spec.K2VAPI == nil || !cluster.Spec.K2VAPI.Enabled {
```
to:
```go
if cluster.Spec.K2VAPI == nil {
```

**Step 2: Simplify writeWebAPIConfig (line 856-874)**

Change the guard from:
```go
if cluster.Spec.WebAPI == nil || !cluster.Spec.WebAPI.Enabled || cluster.Spec.WebAPI.RootDomain == "" {
```
to:
```go
if cluster.Spec.WebAPI == nil {
```

**Step 3: Simplify reconcileAPIService K2V port block (line 1086)**

Change from:
```go
if cluster.Spec.K2VAPI != nil && cluster.Spec.K2VAPI.Enabled {
```
to:
```go
if cluster.Spec.K2VAPI != nil {
```

**Step 4: Simplify reconcileAPIService Web port block (line 1099-1100)**

Change from:
```go
if cluster.Spec.WebAPI != nil && cluster.Spec.WebAPI.Enabled && cluster.Spec.WebAPI.RootDomain != "" {
```
to:
```go
if cluster.Spec.WebAPI != nil {
```

**Step 5: Simplify buildContainerPorts K2V block (line 1226)**

Change from:
```go
if cluster.Spec.K2VAPI != nil && cluster.Spec.K2VAPI.Enabled {
```
to:
```go
if cluster.Spec.K2VAPI != nil {
```

**Step 6: Simplify buildContainerPorts Web block (line 1234-1235)**

Change from:
```go
// Web API port - only expose if RootDomain is set (required for [s3_web] config section)
if cluster.Spec.WebAPI != nil && cluster.Spec.WebAPI.Enabled && cluster.Spec.WebAPI.RootDomain != "" {
```
to:
```go
// Web API port
if cluster.Spec.WebAPI != nil {
```

**Step 7: Update the K2V comment on line 1225**

Change from:
```go
// K2V API port
if cluster.Spec.K2VAPI != nil && cluster.Spec.K2VAPI.Enabled {
```
Remove "K2V API port" comment is fine, just update the condition.

**Step 8: Update the Service port comments (lines 1083, 1099)**

Remove `- only expose if RootDomain is set (required for [s3_web] config section)` from the web comment.

**Step 9: Verify it compiles**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && go build ./...`
Expected: PASS

**Step 10: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && go test ./... 2>&1 | tail -20`
Expected: PASS (no tests reference WebAPI.Enabled or K2VAPI.Enabled)

**Step 11: Commit**

```
refactor: simplify K2V/Web API gating to presence-based checks
```

---

### Task 4: Regenerate CRD and Verify

**Files:**
- Regenerated: `config/crd/bases/garage.rajsingh.info_garageclusters.yaml`

**Step 1: Regenerate manifests**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && make manifests`

**Step 2: Verify CRD changes**

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && grep -A5 'rootDomain:' config/crd/bases/garage.rajsingh.info_garageclusters.yaml | head -20`

Expected: `rootDomain` should NOT have `type: string` under an `optional` context — it should be listed in `required:` for the webApi object.

Also verify `enabled` field is gone from both `webApi` and `k2vApi` sections:

Run: `cd /Users/rajsingh/Documents/GitHub/garage-operator && grep -B2 -A2 'enabled:' config/crd/bases/garage.rajsingh.info_garageclusters.yaml`

Expected: `enabled` should only appear under `admin` (which we kept), NOT under `webApi` or `k2vApi`.

**Step 3: Commit**

```
chore: regenerate CRD after removing Enabled fields
```

---

### Task 5: Update Kubernetes Manifests (GitOps repo)

**Files:**
- Modify: `/Users/rajsingh/Documents/GitHub/kubernetes-manifests/clusters/common/apps/garage/app/garagecluster.yaml`

**Step 1: Verify the gitops manifest already has the right shape**

The file was already updated earlier in this session with:
```yaml
webApi:
  enabled: true        # <-- remove this line
  bindPort: 3902
  rootDomain: ".web.garage.${CLUSTER_DOMAIN}"
```

Remove the `enabled: true` line since presence of `webApi` now implies enabled.

**Step 2: Commit in kubernetes-manifests repo**

```
update garage webApi config to match new presence-based gating
```
