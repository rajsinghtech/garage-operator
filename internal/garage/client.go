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

package garage

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Worker state constants
const (
	WorkerStateThrottled = "throttled"
	workerStateBusy      = "busy"
	workerStateIdle      = "idle"
	workerStateDone      = "done"
	workerStateNull      = "null"
	workerNodeKey        = "node"
	workerNodeSelf       = "self"
)

// APIError represents an error returned by the Garage Admin API
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found error
func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// IsConflict returns true if the error is a 409 Conflict error
func IsConflict(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusConflict
	}
	return false
}

// IsBadRequest returns true if the error is a 400 Bad Request error
func IsBadRequest(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusBadRequest
	}
	return false
}

// IsForbidden returns true when Garage rejected the supplied Admin bearer
// token or its dynamic-token scope.
func IsForbidden(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden
}

// IsServiceUnavailable returns true if the error is a 503 Service Unavailable error.
// Garage maps transient quorum/timeout/remote-node failures to HTTP 503
// (GarageError::{Timeout, RemoteError, Quorum} -> SERVICE_UNAVAILABLE; see upstream
// src/api/common/common_error.rs http_status_code). These are retryable: the same
// request typically succeeds once a quorum of nodes is reachable again.
func IsServiceUnavailable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusServiceUnavailable
	}
	return false
}

// IsBucketNotEmpty returns true if the error is a BucketNotEmpty error (409 Conflict with specific code)
func IsBucketNotEmpty(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		// Garage returns 409 Conflict for BucketNotEmpty
		// The error message JSON contains "BucketNotEmpty" code
		return apiErr.StatusCode == http.StatusConflict &&
			(strings.Contains(apiErr.Message, "BucketNotEmpty") || strings.Contains(apiErr.Message, "not empty"))
	}
	return false
}

// IsReplicationConstraint returns true if the error indicates that removing a node
// would violate the cluster's replication factor constraints. This happens when trying
// to remove a node that would leave fewer storage nodes than the replication factor.
//
// WARNING: VERSION-DEPENDENT ERROR MESSAGE DETECTION
// This detection relies on error message text patterns from Garage. If Garage
// changes its error messages, this function may break silently.
//
// Upstream references (verify these if upgrading Garage):
//   - src/rpc/layout/version.rs:335-341 - "positive capacity" / "replication factor"
//   - src/rpc/layout/version.rs:343-348 - "zone redundancy"
//   - src/api/admin/layout.rs:217-227 - zone redundancy validation
//
// Last verified: Garage v2.3.0
func IsReplicationConstraint(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	// Garage returns 400 (BadRequest) or 500 (InternalServerError) for layout constraint violations
	if apiErr.StatusCode != http.StatusInternalServerError && apiErr.StatusCode != http.StatusBadRequest {
		return false
	}

	msg := strings.ToLower(apiErr.Message)

	// Any message mentioning "replication factor" is likely a constraint violation
	// Pattern examples from Garage:
	// - "The number of nodes with positive capacity (N) is smaller than the replication factor (M)"
	// - "Cannot apply layout: replication factor requires more nodes"
	// - "REPLICATION FACTOR constraint violated"
	if strings.Contains(msg, "replication factor") {
		return true
	}

	// "positive capacity" typically appears in node count constraint messages
	if strings.Contains(msg, "positive capacity") {
		return true
	}

	// Zone redundancy constraint violations
	if strings.Contains(msg, "zone redundancy") {
		return true
	}

	return false
}

// IsMetadataDecodeError returns true if the error is a Garage internal error
// indicating table entry deserialization failure ("Unable to decode entry of key").
// This surfaces when key_table entries written by an older Garage version cannot
// be read by the running version. Recovery: trigger Repair:Tables on the cluster.
//
// Upstream reference: src/table/data.rs decode_entry() — TABLE_NAME="key"
// Last verified: Garage v2.3.0
func IsMetadataDecodeError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		return false
	}
	return strings.Contains(apiErr.Message, "Unable to decode entry of")
}

// Client is a client for the Garage Admin API v2
type Client struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
}

// NewClient creates a new Garage Admin API client
func NewClient(baseURL, adminToken string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		adminToken: adminToken,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

// BaseURL returns the Admin API endpoint the client dials. Useful for asserting
// which endpoint a client was built for (e.g. connectTo vs managed Service).
func (c *Client) BaseURL() string {
	return c.baseURL
}

// SetHTTPTimeout overrides the underlying http.Client.Timeout. Intended for
// tests that need a much shorter transport-level deadline than the 90s
// production default.
func (c *Client) SetHTTPTimeout(d time.Duration) {
	c.httpClient.Timeout = d
}

// doRequest performs an HTTP request to the Garage Admin API
func (c *Client) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	return c.doRequestWithQuery(ctx, method, path, nil, body)
}

// doRequestWithQuery performs an HTTP request with query parameters to the Garage Admin API
func (c *Client) doRequestWithQuery(ctx context.Context, method, path string, query map[string]string, body any) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	fullURL := c.baseURL + path
	if len(query) > 0 {
		params := url.Values{}
		for k, v := range query {
			params.Set(k, v)
		}
		fullURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Limit response size to prevent memory issues with large responses
	// 10MB should be more than enough for any admin API response
	const maxResponseSize = 10 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Truncate error message to prevent memory issues and potential info leakage
		errMsg := string(respBody)
		const maxErrorLen = 500
		if len(errMsg) > maxErrorLen {
			errMsg = errMsg[:maxErrorLen] + "... (truncated)"
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    errMsg,
		}
	}

	return respBody, nil
}

// ClusterStatus represents the Garage cluster status
// Matches Garage's GetClusterStatusResponse
type ClusterStatus struct {
	LayoutVersion uint64     `json:"layoutVersion"`
	Nodes         []NodeInfo `json:"nodes"`
}

// LocalNodeInfo is the identity-bearing subset of Garage's
// LocalGetNodeInfoResponse. The nodeId is read from garage.system.id by the
// daemon that serves the request; it is not inferred from cluster peer state.
type LocalNodeInfo struct {
	NodeID string `json:"nodeId"`
}

// AdminTokenInfo is Garage v2's metadata for a dynamic Admin API token. Static
// configured admin/metrics pseudo-entries returned by ListAdminTokens have a
// nil ID and cannot be updated or deleted through the table API.
type AdminTokenInfo struct {
	ID         *string    `json:"id"`
	Created    *time.Time `json:"created"`
	Name       string     `json:"name"`
	Expiration *time.Time `json:"expiration"`
	Expired    bool       `json:"expired"`
	Scope      []string   `json:"scope"`
}

// AdminTokenUpdate is accepted by CreateAdminToken and UpdateAdminToken.
type AdminTokenUpdate struct {
	Name         *string    `json:"name,omitempty"`
	Expiration   *time.Time `json:"expiration,omitempty"`
	NeverExpires bool       `json:"neverExpires,omitempty"`
	Scope        *[]string  `json:"scope,omitempty"`
}

// CreateAdminTokenResponse contains the one-time bearer secret plus flattened
// token metadata.
type CreateAdminTokenResponse struct {
	SecretToken string `json:"secretToken"`
	AdminTokenInfo
}

// ListAdminTokens returns dynamic table entries and Garage's static configured
// pseudo-entries (the latter have ID=nil).
func (c *Client) ListAdminTokens(ctx context.Context) ([]AdminTokenInfo, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/ListAdminTokens", nil)
	if err != nil {
		return nil, err
	}
	var tokens []AdminTokenInfo
	if err := json.Unmarshal(resp, &tokens); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admin token list: %w", err)
	}
	return tokens, nil
}

// GetAdminTokenInfo retrieves exactly one dynamic token by full ID or unique
// search string. Exactly one of id and search must be non-empty.
func (c *Client) GetAdminTokenInfo(ctx context.Context, id, search string) (*AdminTokenInfo, error) {
	if (id == "") == (search == "") {
		return nil, fmt.Errorf("exactly one of admin token id or search must be provided")
	}
	query := map[string]string{}
	if id != "" {
		query["id"] = id
	} else {
		query["search"] = search
	}
	resp, err := c.doRequestWithQuery(ctx, http.MethodGet, "/v2/GetAdminTokenInfo", query, nil)
	if err != nil {
		return nil, err
	}
	var info AdminTokenInfo
	if err := json.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admin token info: %w", err)
	}
	return &info, nil
}

// CreateAdminToken creates a table-backed token. SecretToken is returned by
// Garage only once and must be durably persisted by the caller.
func (c *Client) CreateAdminToken(ctx context.Context, update AdminTokenUpdate) (*CreateAdminTokenResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/CreateAdminToken", update)
	if err != nil {
		return nil, err
	}
	var created CreateAdminTokenResponse
	if err := json.Unmarshal(resp, &created); err != nil {
		return nil, fmt.Errorf("failed to unmarshal created admin token: %w", err)
	}
	if created.ID == nil || *created.ID == "" || created.SecretToken == "" {
		return nil, fmt.Errorf("garage returned an incomplete dynamic admin token")
	}
	return &created, nil
}

// UpdateAdminToken changes metadata, expiry, or scope for a dynamic token.
func (c *Client) UpdateAdminToken(ctx context.Context, id string, update AdminTokenUpdate) (*AdminTokenInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("admin token id must not be empty")
	}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/UpdateAdminToken", map[string]string{"id": id}, update)
	if err != nil {
		return nil, err
	}
	var info AdminTokenInfo
	if err := json.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal updated admin token: %w", err)
	}
	return &info, nil
}

// DeleteAdminToken tombstones a dynamic token. Garage uses POST rather than
// HTTP DELETE for this v2 endpoint.
func (c *Client) DeleteAdminToken(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("admin token id must not be empty")
	}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/DeleteAdminToken", map[string]string{"id": id}, nil)
	return err
}

// GetCurrentAdminTokenInfo verifies the client's own bearer against the
// endpoint and returns its effective dynamic/static metadata.
func (c *Client) GetCurrentAdminTokenInfo(ctx context.Context) (*AdminTokenInfo, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/GetCurrentAdminTokenInfo", nil)
	if err != nil {
		return nil, err
	}
	var info AdminTokenInfo
	if err := json.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal current admin token info: %w", err)
	}
	return &info, nil
}

// NodeInfo represents information about a Garage node
// Matches Garage's NodeResp
type NodeInfo struct {
	ID                string            `json:"id"`
	GarageVersion     *string           `json:"garageVersion,omitempty"`
	Address           *string           `json:"addr,omitempty"`
	Hostname          *string           `json:"hostname,omitempty"`
	IsUp              bool              `json:"isUp"`
	LastSeenSecsAgo   *uint64           `json:"lastSeenSecsAgo,omitempty"`
	Role              *NodeAssignedRole `json:"role,omitempty"`
	Draining          bool              `json:"draining"`
	DataPartition     *FreeSpaceResp    `json:"dataPartition,omitempty"`
	MetadataPartition *FreeSpaceResp    `json:"metadataPartition,omitempty"`
}

// NodeAssignedRole represents a node's assigned role in the layout
type NodeAssignedRole struct {
	Zone     string   `json:"zone"`
	Tags     []string `json:"tags"`
	Capacity *uint64  `json:"capacity,omitempty"`
}

// FreeSpaceResp represents disk space information
type FreeSpaceResp struct {
	Available uint64 `json:"available"`
	Total     uint64 `json:"total"`
}

// GetClusterStatus returns the current cluster status
func (c *Client) GetClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/GetClusterStatus", nil)
	if err != nil {
		return nil, err
	}

	var status ClusterStatus
	if err := json.Unmarshal(resp, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &status, nil
}

// GetSelfNodeInfo asks the daemon reached by this client for its own identity.
// Garage v2 returns local-node endpoints in a MultiResponse even for
// node=self, so a valid response has exactly one success, no dispatch errors,
// and a success-map key equal to the canonical nodeId in the response body.
func (c *Client) GetSelfNodeInfo(ctx context.Context) (*LocalNodeInfo, error) {
	resp, err := c.doRequestWithQuery(
		ctx,
		http.MethodGet,
		"/v2/GetNodeInfo",
		map[string]string{workerNodeKey: workerNodeSelf},
		nil,
	)
	if err != nil {
		return nil, err
	}
	var result multiNodeResponse[LocalNodeInfo]
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal self node-info response: %w", err)
	}
	if err := aggregateNodeErrors(result.Error); err != nil {
		return nil, fmt.Errorf("garage self node-info dispatch failed: %w", err)
	}
	if len(result.Success) != 1 {
		return nil, fmt.Errorf("garage self node-info returned %d successful nodes, expected exactly one", len(result.Success))
	}
	for responseKey, info := range result.Success {
		keyID, err := canonicalGarageNodeID(responseKey)
		if err != nil {
			return nil, fmt.Errorf("garage self node-info success key is invalid: %w", err)
		}
		bodyID, err := canonicalGarageNodeID(info.NodeID)
		if err != nil {
			return nil, fmt.Errorf("garage self node-info nodeId is invalid: %w", err)
		}
		if keyID != bodyID {
			return nil, fmt.Errorf("garage self node-info response key %s does not match body nodeId %s", keyID, bodyID)
		}
		info.NodeID = bodyID
		return &info, nil
	}
	return nil, fmt.Errorf("garage self node-info returned no successful node")
}

func canonicalGarageNodeID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) != 64 {
		return "", fmt.Errorf("node ID must contain exactly 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("node ID must contain exactly 64 hexadecimal characters")
	}
	return id, nil
}

// ClusterHealth represents the Garage cluster health
// Matches Garage's GetClusterHealthResponse
type ClusterHealth struct {
	Status           string `json:"status"`
	KnownNodes       int    `json:"knownNodes"`
	ConnectedNodes   int    `json:"connectedNodes"`
	StorageNodes     int    `json:"storageNodes"`
	StorageNodesUp   int    `json:"storageNodesUp"`
	Partitions       int    `json:"partitions"`
	PartitionsQuorum int    `json:"partitionsQuorum"`
	PartitionsAllOK  int    `json:"partitionsAllOk"`
}

// UnmarshalJSON accepts both Garage v2.0's storageNodesOk field and the
// storageNodesUp name introduced in v2.1. Presence-aware decoding prevents a
// dual-field response from silently selecting a contradictory value.
func (h *ClusterHealth) UnmarshalJSON(data []byte) error {
	type wireHealth struct {
		Status           string `json:"status"`
		KnownNodes       int    `json:"knownNodes"`
		ConnectedNodes   int    `json:"connectedNodes"`
		StorageNodes     int    `json:"storageNodes"`
		StorageNodesUp   *int   `json:"storageNodesUp"`
		StorageNodesOK   *int   `json:"storageNodesOk"`
		Partitions       int    `json:"partitions"`
		PartitionsQuorum int    `json:"partitionsQuorum"`
		PartitionsAllOK  int    `json:"partitionsAllOk"`
	}
	var wire wireHealth
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.StorageNodesUp != nil && wire.StorageNodesOK != nil && *wire.StorageNodesUp != *wire.StorageNodesOK {
		return fmt.Errorf("conflicting Garage health fields storageNodesUp=%d and storageNodesOk=%d", *wire.StorageNodesUp, *wire.StorageNodesOK)
	}
	storageNodesUp := 0
	if wire.StorageNodesUp != nil {
		storageNodesUp = *wire.StorageNodesUp
	} else if wire.StorageNodesOK != nil {
		storageNodesUp = *wire.StorageNodesOK
	}
	*h = ClusterHealth{
		Status: wire.Status, KnownNodes: wire.KnownNodes, ConnectedNodes: wire.ConnectedNodes,
		StorageNodes: wire.StorageNodes, StorageNodesUp: storageNodesUp,
		Partitions: wire.Partitions, PartitionsQuorum: wire.PartitionsQuorum, PartitionsAllOK: wire.PartitionsAllOK,
	}
	return nil
}

// GetClusterHealth returns the cluster health status
func (c *Client) GetClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/GetClusterHealth", nil)
	if err != nil {
		return nil, err
	}

	var health ClusterHealth
	if err := json.Unmarshal(resp, &health); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &health, nil
}

// CheckMetrics verifies that the configured bearer can scrape Garage's
// Prometheus endpoint. Dynamic tokens require the dedicated "Metrics" scope.
func (c *Client) CheckMetrics(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodGet, "/metrics", nil)
	return err
}

// ClusterLayout represents the Garage cluster layout
type ClusterLayout struct {
	Version           uint64            `json:"version"`
	Roles             []LayoutNodeRole  `json:"roles"`
	Parameters        *LayoutParameters `json:"parameters,omitempty"`
	PartitionSize     uint64            `json:"partitionSize"`
	StagedRoleChanges []NodeRoleChange  `json:"stagedRoleChanges"`
	StagedParameters  *LayoutParameters `json:"stagedParameters,omitempty"`
}

// LayoutNodeRole represents a node's role in the current layout
type LayoutNodeRole struct {
	ID               string   `json:"id"`
	Zone             string   `json:"zone"`
	Tags             []string `json:"tags"`
	Capacity         *uint64  `json:"capacity,omitempty"`
	StoredPartitions *uint64  `json:"storedPartitions,omitempty"`
	UsableCapacity   *uint64  `json:"usableCapacity,omitempty"`
}

// LayoutRole is an alias for backward compatibility with controllers
type LayoutRole = LayoutNodeRole

// GetClusterLayout returns the current cluster layout
func (c *Client) GetClusterLayout(ctx context.Context) (*ClusterLayout, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/GetClusterLayout", nil)
	if err != nil {
		return nil, err
	}

	var layout ClusterLayout
	if err := json.Unmarshal(resp, &layout); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &layout, nil
}

// NodeRoleChange represents a change to a node's role in the layout
// Uses untagged enum: either {id, remove: true} or {id, zone, tags, capacity}
// Note: Tags must NOT have omitempty because Garage's untagged enum requires
// the tags field to be present to match the "assign role" variant.
type NodeRoleChange struct {
	ID       string   `json:"id"`
	Zone     string   `json:"zone,omitempty"`
	Capacity *uint64  `json:"capacity,omitempty"`
	Tags     []string `json:"tags"` // No omitempty - Garage requires tags field for enum matching
	Remove   bool     `json:"remove,omitempty"`
}

// UpdateClusterLayoutRequest is the request body for UpdateClusterLayout
type UpdateClusterLayoutRequest struct {
	Roles      []NodeRoleChange  `json:"roles,omitempty"`
	Parameters *LayoutParameters `json:"parameters,omitempty"`
}

// LayoutParameters represents layout computation parameters
type LayoutParameters struct {
	ZoneRedundancy *ZoneRedundancy `json:"zoneRedundancy,omitempty"`
}

// ZoneRedundancy represents zone redundancy settings
// Serializes as either "Maximum" or {"atLeast": n}
type ZoneRedundancy struct {
	Maximum bool
	AtLeast *int
}

// MarshalJSON implements custom JSON marshaling for ZoneRedundancy
// Garage uses camelCase serialization, so Maximum becomes "maximum"
func (z ZoneRedundancy) MarshalJSON() ([]byte, error) {
	if z.Maximum {
		return json.Marshal("maximum")
	}
	if z.AtLeast != nil {
		return json.Marshal(map[string]int{"atLeast": *z.AtLeast})
	}
	return json.Marshal(nil)
}

// UnmarshalJSON implements custom JSON unmarshaling for ZoneRedundancy
// Garage uses lowercase "maximum" in JSON serialization (via serde rename_all = "camelCase")
func (z *ZoneRedundancy) UnmarshalJSON(data []byte) error {
	// Handle null value
	if string(data) == workerStateNull {
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// Garage only outputs lowercase "maximum" - be strict to match upstream exactly
		if s == "maximum" {
			z.Maximum = true
			return nil
		}
		return fmt.Errorf("invalid ZoneRedundancy string value: %q (expected 'maximum')", s)
	}
	var obj map[string]int
	if err := json.Unmarshal(data, &obj); err == nil {
		if v, ok := obj["atLeast"]; ok {
			// Basic sanity check - Garage API also validates atLeast <= replication_factor
			// (see src/api/admin/layout.rs:217-227)
			if v < 1 {
				return fmt.Errorf("invalid ZoneRedundancy atLeast value: %d (must be >= 1)", v)
			}
			z.AtLeast = &v
			return nil
		}
		return fmt.Errorf("invalid ZoneRedundancy object: missing 'atLeast' key")
	}
	return fmt.Errorf("invalid ZoneRedundancy format: expected string 'maximum' or object {\"atLeast\": n}")
}

// UpdateClusterLayout stages layout changes
func (c *Client) UpdateClusterLayout(ctx context.Context, roles []NodeRoleChange) error {
	if err := guardLayoutWrite(ctx, LayoutOpUpdate); err != nil {
		return err
	}
	req := UpdateClusterLayoutRequest{Roles: roles}
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/UpdateClusterLayout", req)
	return err
}

// UpdateClusterLayoutWithParams stages layout changes with parameters
func (c *Client) UpdateClusterLayoutWithParams(ctx context.Context, req UpdateClusterLayoutRequest) error {
	if err := guardLayoutWrite(ctx, LayoutOpUpdateParams); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/UpdateClusterLayout", req)
	return err
}

// ApplyLayoutRequest is the request to apply staged layout changes
type ApplyLayoutRequest struct {
	Version uint64 `json:"version"`
}

// ApplyClusterLayout applies staged layout changes
func (c *Client) ApplyClusterLayout(ctx context.Context, version uint64) error {
	if err := guardLayoutWrite(ctx, LayoutOpApply); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/ApplyClusterLayout", ApplyLayoutRequest{Version: version})
	return err
}

// ApplyStagedLayoutChanges commits whatever layout changes are currently staged.
// Callers must hold the per-GarageCluster layout mutation coordinator across
// staging and this apply.
//
// Two upstream facts make a naive `ApplyClusterLayout(version+1)` wrong (verified
// against Garage v2.3.0):
//
//  1. ApplyClusterLayout ALWAYS increments the version with no no-op
//     short-circuit (src/rpc/layout/version.rs:290-303). Applying when nothing
//     is staged churns the version + layout gossip pointlessly. So we read the
//     layout first and return early when nothing is staged.
//
// A version-mismatch rejection is a generic HTTP 500 rather than a conflict.
// We intentionally return it. Seeing a newer version is not proof that this
// caller's requested role mutation was included in that version; the caller
// must re-read roles on its next coordinated reconcile.
func (c *Client) ApplyStagedLayoutChanges(ctx context.Context) error {
	if err := guardLayoutWrite(ctx, LayoutOpApplyStaged); err != nil {
		return err
	}
	layout, err := c.GetClusterLayout(ctx)
	if err != nil {
		return err
	}
	if len(layout.StagedRoleChanges) == 0 && layout.StagedParameters == nil {
		// Nothing to apply — do not bump the version.
		return nil
	}
	target := layout.Version + 1
	return c.ApplyClusterLayout(ctx, target)
}

// RevertClusterLayout reverts staged layout changes
func (c *Client) RevertClusterLayout(ctx context.Context) error {
	if err := guardLayoutWrite(ctx, LayoutOpRevert); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/RevertClusterLayout", nil)
	return err
}

// SkipDeadNodesRequest is the request to skip dead nodes in draining layout versions
type SkipDeadNodesRequest struct {
	// Version is the layout version to assume is up-to-date (usually current version)
	Version uint64 `json:"version"`
	// AllowMissingData allows skipping even if quorum is missing (may cause data loss)
	AllowMissingData bool `json:"allowMissingData"`
}

// SkipDeadNodesResponse is the response from ClusterLayoutSkipDeadNodes
type SkipDeadNodesResponse struct {
	// AckUpdated contains node IDs whose ACK tracker was updated
	AckUpdated []string `json:"ackUpdated"`
	// SyncUpdated contains node IDs whose SYNC tracker was updated (only if AllowMissingData)
	SyncUpdated []string `json:"syncUpdated"`
}

// ClusterLayoutSkipDeadNodes marks dead/removed nodes as synced to unblock draining layout versions.
// This is useful when nodes are permanently removed and will never acknowledge syncing.
// AllowMissingData is global to the referenced layout version. Callers must
// reserve true for an explicit administrator acknowledgement; even when the
// intended target is a gateway it can force unrelated storage trackers synced.
func (c *Client) ClusterLayoutSkipDeadNodes(ctx context.Context, req SkipDeadNodesRequest) (*SkipDeadNodesResponse, error) {
	if err := guardLayoutWrite(ctx, LayoutOpSkipDeadNodes); err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/ClusterLayoutSkipDeadNodes", req)
	if err != nil {
		return nil, err
	}

	var result SkipDeadNodesResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

// LayoutVersionStatus represents the status of a layout version
type LayoutVersionStatus string

const (
	LayoutVersionStatusCurrent    LayoutVersionStatus = "Current"
	LayoutVersionStatusDraining   LayoutVersionStatus = "Draining"
	LayoutVersionStatusHistorical LayoutVersionStatus = "Historical"
)

// LayoutVersion represents a version in the layout history
type LayoutVersion struct {
	Version      uint64              `json:"version"`
	Status       LayoutVersionStatus `json:"status"`
	StorageNodes int                 `json:"storageNodes"`
	GatewayNodes int                 `json:"gatewayNodes"`
}

// NodeUpdateTrackers contains the update tracker values for a node
type NodeUpdateTrackers struct {
	Ack     uint64 `json:"ack"`
	Sync    uint64 `json:"sync"`
	SyncAck uint64 `json:"syncAck"`
}

// LayoutHistoryResponse is the response from GetClusterLayoutHistory
type LayoutHistoryResponse struct {
	CurrentVersion uint64                        `json:"currentVersion"`
	MinAck         uint64                        `json:"minAck"`
	Versions       []LayoutVersion               `json:"versions"`
	UpdateTrackers map[string]NodeUpdateTrackers `json:"updateTrackers,omitempty"`
}

// GetClusterLayoutHistory returns the layout version history including draining status
func (c *Client) GetClusterLayoutHistory(ctx context.Context) (*LayoutHistoryResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/GetClusterLayoutHistory", nil)
	if err != nil {
		return nil, err
	}

	var history LayoutHistoryResponse
	if err := json.Unmarshal(resp, &history); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &history, nil
}

// DataMigrationSettled reports whether every node Garage is tracking has
// completed a full table sync at the current layout version — i.e. the data
// movement a draining version exists to cover is finished, and only Garage's
// internal bookkeeping still trails.
//
// The distinction matters because "Draining" does not mean "still moving data".
// Upstream retires a version when sync_ack_map advances past it
// (LayoutHistory::cleanup_old_versions), and sync_ack_map is only ever written by
// LayoutHelper::update_update_trackers, which runs at startup and on merging a
// peer advertisement — nothing else. sync_table_until sets sync_map and
// broadcasts, but does not update sync_ack_map locally. A cluster with no peers
// therefore has no trigger: on a single-node cluster in `consistent` mode the
// previous version reports Draining until the process restarts, forever, even
// with an empty dataset. Multi-node clusters escape only because each peer's
// broadcast drives the others' merge path.
//
// sync_map is the honest progress signal: sync_table_until advances it to
// ack_map_min once every table's full sync completes (src/table/sync.rs), so
// Sync >= CurrentVersion means each tracked node holds what the current layout
// assigns it. A node that is gone never advances, so a genuinely dead peer still
// reports unsettled and still requires the explicit skip-dead-nodes recovery.
func (h *LayoutHistoryResponse) DataMigrationSettled() bool {
	// Garage attaches the trackers iff more than one version is live, and a
	// Draining entry is by definition a live non-current version, so any caller
	// that got here has them. Silence from an unexpected Garage proves nothing —
	// stay conservative rather than read it as done. Reading tracker absence as
	// a per-node verdict is what wedged the node cycle in #304.
	if len(h.UpdateTrackers) == 0 {
		return false
	}
	for _, t := range h.UpdateTrackers {
		if t.Sync < h.CurrentVersion {
			return false
		}
	}
	return true
}

// GetDrainingVersions returns all layout versions currently in Draining status
func (h *LayoutHistoryResponse) GetDrainingVersions() []LayoutVersion {
	var draining []LayoutVersion
	for _, v := range h.Versions {
		if v.Status == LayoutVersionStatusDraining {
			draining = append(draining, v)
		}
	}
	return draining
}

// AdminLifecycleRule is a lifecycle rule as returned/accepted by the Garage v2 Admin API.
// Field names use PascalCase to match the XML-derived serde serialization in Garage.
// Since v2.3.0, lifecycle can be managed via Admin API instead of S3 API.
type AdminLifecycleRule struct {
	ID                             *string                   `json:"ID,omitempty"`
	Status                         string                    `json:"Status"`
	Filter                         *AdminLifecycleFilter     `json:"Filter,omitempty"`
	Expiration                     *AdminLifecycleExpiration `json:"Expiration,omitempty"`
	AbortIncompleteMultipartUpload *AdminLifecycleAbort      `json:"AbortIncompleteMultipartUpload,omitempty"`
}

// AdminLifecycleFilter holds filter criteria for a lifecycle rule.
//
// Garage (src/api/common/xml/lifecycle.rs) requires that a filter with more
// than one condition wrap them in an <And> block: a flat multi-condition
// filter is rejected on write, and on read Garage nests any 2+-condition
// filter under And. The And field mirrors that so multi-condition filters
// round-trip; a single condition is emitted/read flat.
type AdminLifecycleFilter struct {
	And                   *AdminLifecycleFilter `json:"And,omitempty"`
	Prefix                *string               `json:"Prefix,omitempty"`
	ObjectSizeGreaterThan *int64                `json:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64                `json:"ObjectSizeLessThan,omitempty"`
}

// AdminLifecycleExpiration holds the expiration action for a lifecycle rule.
type AdminLifecycleExpiration struct {
	Days *int32  `json:"Days,omitempty"`
	Date *string `json:"Date,omitempty"` // RFC3339, midnight UTC
}

// AdminLifecycleAbort triggers cleanup of incomplete multipart uploads.
type AdminLifecycleAbort struct {
	DaysAfterInitiation int32 `json:"DaysAfterInitiation"`
}

// Bucket represents a Garage bucket
// Matches Garage's GetBucketInfoResponse
// Note: Local aliases are embedded in each BucketKeyInfo.BucketLocalAliases, not at the top level
type Bucket struct {
	ID                             string          `json:"id"`
	Created                        string          `json:"created"`
	GlobalAliases                  []string        `json:"globalAliases"`
	WebsiteAccess                  bool            `json:"websiteAccess"`
	WebsiteConfig                  *WebsiteConfig  `json:"websiteConfig,omitempty"`
	Keys                           []BucketKeyInfo `json:"keys"`
	Objects                        int64           `json:"objects"`
	Bytes                          int64           `json:"bytes"`
	UnfinishedUploads              int64           `json:"unfinishedUploads"`
	UnfinishedMultipartUploads     int64           `json:"unfinishedMultipartUploads"`
	UnfinishedMultipartUploadParts int64           `json:"unfinishedMultipartUploadParts"`
	UnfinishedMultipartUploadBytes int64           `json:"unfinishedMultipartUploadBytes"`
	Quotas                         *BucketQuotas   `json:"quotas"`
	// Added in v2.3.0: Admin API now exposes these directly (previously S3-API-only)
	LifecycleRules []AdminLifecycleRule `json:"lifecycleRules,omitempty"`
	CORSRules      []json.RawMessage    `json:"corsRules,omitempty"`
	RoutingRules   []json.RawMessage    `json:"routingRules,omitempty"`
}

// WebsiteConfig represents bucket website configuration returned by Admin API.
// NOTE: Garage Admin API only returns indexDocument and errorDocument.
// RedirectAll is S3-API-only and NOT returned here.
// RoutingRules are available via Admin API since v2.3.0 (in Bucket.RoutingRules).
type WebsiteConfig struct {
	IndexDocument string `json:"indexDocument"`
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// BucketKeyInfo represents key permissions on a bucket
type BucketKeyInfo struct {
	AccessKeyID        string         `json:"accessKeyId"`
	Name               string         `json:"name"`
	Permissions        BucketKeyPerms `json:"permissions"`
	BucketLocalAliases []string       `json:"bucketLocalAliases,omitempty"`
}

// BucketKeyPerms represents bucket key permissions
type BucketKeyPerms struct {
	Read  bool `json:"read"`
	Write bool `json:"write"`
	Owner bool `json:"owner"`
}

// BucketQuotas represents bucket quota settings
type BucketQuotas struct {
	MaxSize    *uint64 `json:"maxSize"`
	MaxObjects *uint64 `json:"maxObjects"`
}

// BucketListItem represents a bucket in the list response
// This is different from the full Bucket type returned by GetBucket
type BucketListItem struct {
	ID            string             `json:"id"`
	Created       string             `json:"created"`
	GlobalAliases []string           `json:"globalAliases"`
	LocalAliases  []BucketLocalAlias `json:"localAliases"`
}

// BucketLocalAlias represents a local alias with its owning key
type BucketLocalAlias struct {
	AccessKeyID string `json:"accessKeyId"`
	Alias       string `json:"alias"`
}

// ListBuckets returns all buckets (summary info only)
// Use GetBucket for full bucket details
func (c *Client) ListBuckets(ctx context.Context) ([]BucketListItem, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/ListBuckets", nil)
	if err != nil {
		return nil, err
	}

	var buckets []BucketListItem
	if err := json.Unmarshal(resp, &buckets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return buckets, nil
}

// GetBucketRequest identifies a bucket (uses query params, not JSON body)
type GetBucketRequest struct {
	ID          string // Exact bucket ID
	GlobalAlias string // Global alias
	Search      string // Partial ID or alias to search
}

// GetBucket returns information about a specific bucket
func (c *Client) GetBucket(ctx context.Context, req GetBucketRequest) (*Bucket, error) {
	query := make(map[string]string)
	if req.ID != "" {
		query["id"] = req.ID
	}
	if req.GlobalAlias != "" {
		query["globalAlias"] = req.GlobalAlias
	}
	if req.Search != "" {
		query["search"] = req.Search
	}

	resp, err := c.doRequestWithQuery(ctx, http.MethodGet, "/v2/GetBucketInfo", query, nil)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// CreateBucketLocalAlias specifies a local alias when creating a bucket
type CreateBucketLocalAlias struct {
	AccessKeyID string          `json:"accessKeyId"`
	Alias       string          `json:"alias"`
	Allow       *BucketKeyPerms `json:"allow,omitempty"` // Default permissions to grant (optional)
}

// CreateBucketRequest is the request to create a bucket
type CreateBucketRequest struct {
	GlobalAlias string                  `json:"globalAlias,omitempty"`
	LocalAlias  *CreateBucketLocalAlias `json:"localAlias,omitempty"`
}

// CreateBucket creates a new bucket
func (c *Client) CreateBucket(ctx context.Context, req CreateBucketRequest) (*Bucket, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/CreateBucket", req)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// DeleteBucket deletes a bucket (id passed as query param)
func (c *Client) DeleteBucket(ctx context.Context, id string) error {
	query := map[string]string{"id": id}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/DeleteBucket", query, nil)
	return err
}

// UpdateBucketWebsiteAccess represents website access settings for bucket update
// Note: routingRules can also be set here since v2.3.0, but we don't use that yet.
type UpdateBucketWebsiteAccess struct {
	Enabled       bool   `json:"enabled"`
	IndexDocument string `json:"indexDocument,omitempty"`
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// UpdateBucketRequestBody is the JSON body for updating bucket settings.
// Since v2.3.0, corsRules and lifecycleRules can also be set here (previously S3-API-only).
// The operator still uses the S3 API for lifecycle; that migration is tracked separately.
type UpdateBucketRequestBody struct {
	WebsiteAccess *UpdateBucketWebsiteAccess `json:"websiteAccess,omitempty"`
	Quotas        *BucketQuotas              `json:"quotas,omitempty"`
}

// UpdateBucketRequest is the full request to update bucket settings
type UpdateBucketRequest struct {
	ID   string // Bucket ID (passed as query param)
	Body UpdateBucketRequestBody
}

// UpdateBucket updates bucket settings (id passed as query param, body as JSON)
func (c *Client) UpdateBucket(ctx context.Context, req UpdateBucketRequest) (*Bucket, error) {
	query := map[string]string{"id": req.ID}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/UpdateBucket", query, req.Body)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// GetBucketLifecycle returns the lifecycle rules for a bucket, or nil if none are set.
func (c *Client) GetBucketLifecycle(ctx context.Context, bucketID string) ([]AdminLifecycleRule, error) {
	bucket, err := c.GetBucket(ctx, GetBucketRequest{ID: bucketID})
	if err != nil {
		return nil, err
	}
	return bucket.LifecycleRules, nil
}

// setBucketLifecycleBody is used exclusively for SetBucketLifecycle to avoid
// touching other bucket fields.
type setBucketLifecycleBody struct {
	LifecycleRules []AdminLifecycleRule `json:"lifecycleRules"`
}

// SetBucketLifecycle replaces the lifecycle rules on a bucket.
// Pass an empty (non-nil) slice to clear all rules.
func (c *Client) SetBucketLifecycle(ctx context.Context, bucketID string, rules []AdminLifecycleRule) error {
	query := map[string]string{"id": bucketID}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/UpdateBucket", query, setBucketLifecycleBody{LifecycleRules: rules})
	return err
}

// AddBucketAliasRequest adds an alias to a bucket
// Garage uses #[serde(flatten)] with an untagged enum, so the alias fields
// are at the top level, not nested. Either use globalAlias OR (localAlias + accessKeyId).
type AddBucketAliasRequest struct {
	BucketID    string `json:"bucketId"`
	GlobalAlias string `json:"globalAlias,omitempty"` // For global aliases
	LocalAlias  string `json:"localAlias,omitempty"`  // For local aliases (requires accessKeyId)
	AccessKeyID string `json:"accessKeyId,omitempty"` // Required when using localAlias
}

// AddBucketAlias adds an alias to a bucket
func (c *Client) AddBucketAlias(ctx context.Context, req AddBucketAliasRequest) (*Bucket, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/AddBucketAlias", req)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// RemoveBucketAliasRequest removes an alias from a bucket
// Garage uses #[serde(flatten)] with an untagged enum, so the alias fields
// are at the top level, not nested. Either use globalAlias OR (localAlias + accessKeyId).
type RemoveBucketAliasRequest struct {
	BucketID    string `json:"bucketId"`
	GlobalAlias string `json:"globalAlias,omitempty"` // For global aliases
	LocalAlias  string `json:"localAlias,omitempty"`  // For local aliases (requires accessKeyId)
	AccessKeyID string `json:"accessKeyId,omitempty"` // Required when using localAlias
}

// RemoveBucketAlias removes an alias from a bucket
func (c *Client) RemoveBucketAlias(ctx context.Context, req RemoveBucketAliasRequest) (*Bucket, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/RemoveBucketAlias", req)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// Key represents a Garage access key
type Key struct {
	AccessKeyID     string         `json:"accessKeyId"`
	Created         *string        `json:"created,omitempty"` // RFC3339 timestamp
	Name            string         `json:"name"`
	Expiration      *string        `json:"expiration,omitempty"` // RFC3339 timestamp
	Expired         bool           `json:"expired"`
	SecretAccessKey string         `json:"secretAccessKey,omitempty"` // Only returned if showSecretKey=true
	Permissions     KeyPermissions `json:"permissions"`
	Buckets         []KeyBucket    `json:"buckets"`
}

// KeyPermissions represents key-level permissions
type KeyPermissions struct {
	CreateBucket bool `json:"createBucket"`
}

// KeyBucket represents a bucket accessible by a key
type KeyBucket struct {
	ID            string         `json:"id"`
	GlobalAliases []string       `json:"globalAliases"`
	LocalAliases  []string       `json:"localAliases"`
	Permissions   BucketKeyPerms `json:"permissions"`
}

// KeyListItem represents summary info for a key in the list response
// Note: This is different from full Key - Garage uses "id" instead of "accessKeyId" in list responses
type KeyListItem struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Created    *string `json:"created,omitempty"`
	Expiration *string `json:"expiration,omitempty"`
	Expired    bool    `json:"expired"`
}

// ListKeys returns all access keys (summary info only)
// Use GetKey for full key details
func (c *Client) ListKeys(ctx context.Context) ([]KeyListItem, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/v2/ListKeys", nil)
	if err != nil {
		return nil, err
	}

	var keys []KeyListItem
	if err := json.Unmarshal(resp, &keys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return keys, nil
}

// GetKeyRequest identifies a key (uses query params, not JSON body)
type GetKeyRequest struct {
	ID            string // Access key ID
	Search        string // Partial key ID or name to search
	ShowSecretKey bool   // Whether to return the secret access key
}

// GetKey returns information about a specific key
func (c *Client) GetKey(ctx context.Context, req GetKeyRequest) (*Key, error) {
	query := make(map[string]string)
	if req.ID != "" {
		query["id"] = req.ID
	}
	if req.Search != "" {
		query["search"] = req.Search
	}
	if req.ShowSecretKey {
		query["showSecretKey"] = "true"
	}

	resp, err := c.doRequestWithQuery(ctx, http.MethodGet, "/v2/GetKeyInfo", query, nil)
	if err != nil {
		return nil, err
	}

	var key Key
	if err := json.Unmarshal(resp, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &key, nil
}

// CreateKeyRequest is the request to create a key.
// Garage's CreateKey API accepts the same fields as UpdateKey.
type CreateKeyRequest struct {
	Name         string          `json:"name,omitempty"`
	Expiration   *string         `json:"expiration,omitempty"` // RFC3339 timestamp
	NeverExpires bool            `json:"neverExpires,omitempty"`
	Allow        *KeyPermissions `json:"allow,omitempty"`
	Deny         *KeyPermissions `json:"deny,omitempty"`
}

// CreateKey creates a new access key
func (c *Client) CreateKey(ctx context.Context, name string) (*Key, error) {
	return c.CreateKeyWithOptions(ctx, CreateKeyRequest{Name: name})
}

// CreateKeyWithOptions creates a new access key with additional options like expiration and permissions
func (c *Client) CreateKeyWithOptions(ctx context.Context, req CreateKeyRequest) (*Key, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/CreateKey", req)
	if err != nil {
		return nil, err
	}

	var key Key
	if err := json.Unmarshal(resp, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &key, nil
}

// ImportKeyRequest is the request to import an existing key
type ImportKeyRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	Name            string `json:"name,omitempty"`
}

// ImportKey imports an existing access key
func (c *Client) ImportKey(ctx context.Context, req ImportKeyRequest) (*Key, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/ImportKey", req)
	if err != nil {
		return nil, err
	}

	var key Key
	if err := json.Unmarshal(resp, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &key, nil
}

// UpdateKeyRequestBody is the JSON body for updating a key
type UpdateKeyRequestBody struct {
	Name         string          `json:"name,omitempty"`
	Expiration   *string         `json:"expiration,omitempty"` // RFC3339 timestamp or null
	NeverExpires bool            `json:"neverExpires,omitempty"`
	Allow        *KeyPermissions `json:"allow,omitempty"`
	Deny         *KeyPermissions `json:"deny,omitempty"`
}

// UpdateKeyRequest is the full request to update a key
type UpdateKeyRequest struct {
	ID   string // Access key ID (passed as query param)
	Body UpdateKeyRequestBody
}

// UpdateKey updates a key's name or permissions (id passed as query param, body as JSON)
func (c *Client) UpdateKey(ctx context.Context, req UpdateKeyRequest) (*Key, error) {
	query := map[string]string{"id": req.ID}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/UpdateKey", query, req.Body)
	if err != nil {
		return nil, err
	}

	var key Key
	if err := json.Unmarshal(resp, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &key, nil
}

// DeleteKey deletes an access key (id passed as query param)
func (c *Client) DeleteKey(ctx context.Context, accessKeyID string) error {
	query := map[string]string{"id": accessKeyID}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/DeleteKey", query, nil)
	return err
}

// AllowBucketKeyRequest grants a key access to a bucket
type AllowBucketKeyRequest struct {
	BucketID    string         `json:"bucketId"`
	AccessKeyID string         `json:"accessKeyId"`
	Permissions BucketKeyPerms `json:"permissions"`
}

// AllowBucketKey grants a key access to a bucket
func (c *Client) AllowBucketKey(ctx context.Context, req AllowBucketKeyRequest) (*Bucket, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/AllowBucketKey", req)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// DenyBucketKeyRequest revokes a key's access to a bucket
// Note: Garage uses the same BucketKeyPermChangeRequest structure for both Allow and Deny.
// The Permissions field specifies WHICH permissions to deny (those set to true will be revoked).
type DenyBucketKeyRequest struct {
	BucketID    string         `json:"bucketId"`
	AccessKeyID string         `json:"accessKeyId"`
	Permissions BucketKeyPerms `json:"permissions"`
}

// DenyBucketKey revokes a key's access to a bucket
func (c *Client) DenyBucketKey(ctx context.Context, req DenyBucketKeyRequest) (*Bucket, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/DenyBucketKey", req)
	if err != nil {
		return nil, err
	}

	var bucket Bucket
	if err := json.Unmarshal(resp, &bucket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &bucket, nil
}

// ConnectNodeResult represents the result of a node connection attempt
type ConnectNodeResult struct {
	Success bool    `json:"success"`
	Error   *string `json:"error,omitempty"`
}

// ConnectNode attempts to connect to a new node
// nodeID is the full node ID (64 hex chars)
// address is the node's address in format "ip:port" or "hostname:port"
// Garage expects the format "nodeId@address"
// Returns the connection result with success status and any error message
func (c *Client) ConnectNode(ctx context.Context, nodeID, address string) (*ConnectNodeResult, error) {
	// Garage expects an array of connection strings in format "nodeId@address"
	connectionString := nodeID + "@" + address
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/ConnectClusterNodes", []string{connectionString})
	if err != nil {
		return nil, err
	}

	// Response is an array of results, one per connection string we sent
	var results []ConnectNodeResult
	if err := json.Unmarshal(resp, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("empty response from ConnectClusterNodes")
	}

	if !results[0].Success {
		if results[0].Error != nil && *results[0].Error != "" {
			return &results[0], fmt.Errorf("ConnectClusterNodes failed: %s", *results[0].Error)
		}
		return &results[0], fmt.Errorf("ConnectClusterNodes failed")
	}

	return &results[0], nil
}

// CleanupIncompleteUploadsRequest is the request to clean up incomplete multipart uploads
type CleanupIncompleteUploadsRequest struct {
	BucketID      string `json:"bucketId"`
	OlderThanSecs uint64 `json:"olderThanSecs"`
}

// CleanupIncompleteUploadsResponse is the response from cleanup
type CleanupIncompleteUploadsResponse struct {
	UploadsDeleted uint64 `json:"uploadsDeleted"`
}

// CleanupIncompleteUploads removes incomplete multipart uploads older than the specified duration
func (c *Client) CleanupIncompleteUploads(ctx context.Context, bucketID string, olderThanSecs uint64) (*CleanupIncompleteUploadsResponse, error) {
	req := CleanupIncompleteUploadsRequest{
		BucketID:      bucketID,
		OlderThanSecs: olderThanSecs,
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v2/CleanupIncompleteUploads", req)
	if err != nil {
		return nil, err
	}

	var result CleanupIncompleteUploadsResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

// WorkerState represents the state of a background worker
// Garage serializes this as an untagged enum: "busy", "idle", "done", or {"throttled": {"durationSecs": N}}
type WorkerState struct {
	State        string   // "busy", "idle", "done", "throttled"
	DurationSecs *float32 // Only set when State is "throttled"
}

// UnmarshalJSON implements custom JSON unmarshaling for WorkerState
func (w *WorkerState) UnmarshalJSON(data []byte) error {
	// Try string first (busy, idle, done)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		w.State = s
		w.DurationSecs = nil
		return nil
	}

	// Try object for throttled state: {"throttled": {"durationSecs": N}}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("invalid worker state: %s", string(data))
	}

	if throttledData, ok := obj[WorkerStateThrottled]; ok {
		w.State = WorkerStateThrottled
		var throttled struct {
			DurationSecs float32 `json:"durationSecs"`
		}
		if err := json.Unmarshal(throttledData, &throttled); err != nil {
			return fmt.Errorf("invalid throttled state: %w", err)
		}
		w.DurationSecs = &throttled.DurationSecs
		return nil
	}

	return fmt.Errorf("unknown worker state format: %s", string(data))
}

// MarshalJSON implements custom JSON marshaling for WorkerState
func (w WorkerState) MarshalJSON() ([]byte, error) {
	if w.State == WorkerStateThrottled && w.DurationSecs != nil {
		return json.Marshal(map[string]any{
			WorkerStateThrottled: map[string]float32{"durationSecs": *w.DurationSecs},
		})
	}
	return json.Marshal(w.State)
}

// IsBusy returns true if the worker is in busy state
func (w WorkerState) IsBusy() bool { return w.State == workerStateBusy }

// IsIdle returns true if the worker is in idle state
func (w WorkerState) IsIdle() bool { return w.State == workerStateIdle }

// IsDone returns true if the worker is in done state
func (w WorkerState) IsDone() bool { return w.State == workerStateDone }

// IsThrottled returns true if the worker is in throttled state
func (w WorkerState) IsThrottled() bool { return w.State == WorkerStateThrottled }

// WorkerLastError represents the last error from a worker
type WorkerLastError struct {
	Message string `json:"message"`
	SecsAgo uint64 `json:"secsAgo"`
}

// WorkerInfo represents information about a background worker
// Matches Garage's WorkerInfoResp from src/api/admin/api.rs
type WorkerInfo struct {
	ID                uint64           `json:"id"`
	Name              string           `json:"name"`
	State             WorkerState      `json:"state"`
	Errors            uint64           `json:"errors"`            // Total error count
	ConsecutiveErrors uint64           `json:"consecutiveErrors"` // Errors since last success
	LastError         *WorkerLastError `json:"lastError,omitempty"`
	Tranquility       *uint32          `json:"tranquility,omitempty"`
	Progress          *string          `json:"progress,omitempty"`
	QueueLength       *uint64          `json:"queueLength,omitempty"`
	PersistentErrors  *uint64          `json:"persistentErrors,omitempty"`
	Freeform          []string         `json:"freeform"`
}

// ListWorkersResponse preserves Garage's MultiResponse payload. The success
// map is keyed by node ID; the error map contains per-node dispatch failures.
type ListWorkersResponse struct {
	Success map[string][]WorkerInfo `json:"success"`
	Error   map[string]string       `json:"error"`
}

// BlockError is one persistent block-resync error reported by Garage.
type BlockError struct {
	BlockHash      string `json:"blockHash"`
	Refcount       uint64 `json:"refcount"`
	ErrorCount     uint64 `json:"errorCount"`
	LastTrySecsAgo uint64 `json:"lastTrySecsAgo"`
	NextTryInSecs  uint64 `json:"nextTryInSecs"`
}

// ListBlockErrorsResponse preserves Garage's per-node result so callers can
// fail closed when one verification process cannot read its error database.
type ListBlockErrorsResponse struct {
	Success map[string][]BlockError `json:"success"`
	Error   map[string]string       `json:"error"`
}

// ListWorkers returns structured background-worker state for one node, all
// nodes ("*"), or the responding node ("self"). Block resync workers have
// exposed queueLength and persistentErrors since Garage v2.0, making this the
// version-compatible data-drain signal.
func (c *Client) ListWorkers(ctx context.Context, nodeID string, busyOnly, errorOnly bool) (*ListWorkersResponse, error) {
	query := map[string]string{workerNodeKey: nodeID}
	body := struct {
		BusyOnly  bool `json:"busyOnly"`
		ErrorOnly bool `json:"errorOnly"`
	}{BusyOnly: busyOnly, ErrorOnly: errorOnly}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/ListWorkers", query, body)
	if err != nil {
		return nil, err
	}
	var workers ListWorkersResponse
	if err := json.Unmarshal(resp, &workers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if workers.Success == nil {
		workers.Success = make(map[string][]WorkerInfo)
	}
	if workers.Error == nil {
		workers.Error = make(map[string]string)
	}
	return &workers, nil
}

// ListBlockErrors returns persistent block-resync errors from one node, every
// node ("*"), or the responding node ("self").
func (c *Client) ListBlockErrors(ctx context.Context, nodeID string) (*ListBlockErrorsResponse, error) {
	resp, err := c.doRequestWithQuery(ctx, http.MethodGet, "/v2/ListBlockErrors", map[string]string{workerNodeKey: nodeID}, nil)
	if err != nil {
		return nil, err
	}
	var result ListBlockErrorsResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block-error response: %w", err)
	}
	if result.Success == nil {
		result.Success = make(map[string][]BlockError)
	}
	if result.Error == nil {
		result.Error = make(map[string]string)
	}
	return &result, nil
}

// SetWorkerVariableRequest sets a worker configuration variable
type SetWorkerVariableRequest struct {
	Variable string `json:"variable"`
	Value    string `json:"value"`
}

// SetWorkerVariable sets a worker configuration variable on a node
func (c *Client) SetWorkerVariable(ctx context.Context, nodeID, variable, value string) error {
	query := map[string]string{workerNodeKey: nodeID}
	req := SetWorkerVariableRequest{Variable: variable, Value: value}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/SetWorkerVariable", query, req)
	if err != nil {
		return err
	}
	return validateMultiNodeCommandResponse(resp, nodeID, "SetWorkerVariable")
}

// LaunchRepairRequest is the request to launch a repair operation
type LaunchRepairRequest struct {
	RepairType string `json:"repairType"` // Tables, Blocks, Versions, Rebalance, Scrub, etc.
}

// LaunchRepair starts a repair operation on a node.
// The annotation accepts PascalCase values (e.g. "Blocks") matching the operator
// constants, but the Garage v2 API expects camelCase (e.g. "blocks"). This function
// lowercases the first character before sending.
func (c *Client) LaunchRepair(ctx context.Context, nodeID, repairType string) error {
	query := map[string]string{workerNodeKey: nodeID}
	apiType := repairType
	if len(apiType) > 0 {
		apiType = strings.ToLower(apiType[:1]) + apiType[1:]
	}
	req := LaunchRepairRequest{RepairType: apiType}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/LaunchRepairOperation", query, req)
	if err != nil {
		return err
	}
	return validateMultiNodeCommandResponse(resp, nodeID, "LaunchRepairOperation")
}

// LaunchScrubCommand sends a scrub control command to nodes.
// The Garage API encodes scrub as {"repairType": {"scrub": "<command>"}} —
// a nested object, unlike other repair types which use a plain string.
// Valid commands: start, pause, resume, cancel.
func (c *Client) LaunchScrubCommand(ctx context.Context, nodeID, command string) error {
	type scrubType struct {
		Scrub string `json:"scrub"`
	}
	type scrubRequest struct {
		RepairType scrubType `json:"repairType"`
	}
	query := map[string]string{workerNodeKey: nodeID}
	req := scrubRequest{RepairType: scrubType{Scrub: command}}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/LaunchRepairOperation", query, req)
	if err != nil {
		return err
	}
	return validateMultiNodeCommandResponse(resp, nodeID, "LaunchRepairOperation")
}

// CreateMetadataSnapshot triggers a metadata snapshot on a node
func (c *Client) CreateMetadataSnapshot(ctx context.Context, nodeID string) error {
	query := map[string]string{workerNodeKey: nodeID}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/CreateMetadataSnapshot", query, nil)
	if err != nil {
		return err
	}
	return validateMultiNodeCommandResponse(resp, nodeID, "CreateMetadataSnapshot")
}

// multiNodeResponse mirrors Garage's MultiResponse<T> (src/api/admin/api.rs).
// Node-scoped ("local") admin endpoints dispatched with node="*" are fanned out
// to every node and ALWAYS return HTTP 200 — per-node outcomes are recorded in
// the success/error maps, NOT in the HTTP status. A flat decode of the bare
// local response therefore silently yields zero values and, worse, treats a
// run where every node failed as a success. Decode into this wrapper instead.
type multiNodeResponse[T any] struct {
	Success map[string]T      `json:"success"`
	Error   map[string]string `json:"error"`
}

// aggregateNodeErrors returns a deterministic aggregated error describing the
// per-node failures in a MultiResponse error map, or nil when there were none.
func aggregateNodeErrors(errs map[string]string) error {
	if len(errs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(errs))
	for node, msg := range errs {
		parts = append(parts, fmt.Sprintf("%s: %s", node, msg))
	}
	sort.Strings(parts)
	return fmt.Errorf("%d node(s) reported errors: %s", len(errs), strings.Join(parts, "; "))
}

// validateMultiNodeSuccess checks the dispatch envelope used by Garage's
// node-scoped Admin API. These endpoints return HTTP 200 even when every node
// failed, so callers must validate both maps before recording an operation as
// successful.
func validateMultiNodeSuccess[T any](result multiNodeResponse[T], nodeID, operation string) error {
	if err := aggregateNodeErrors(result.Error); err != nil {
		return fmt.Errorf("%s failed: %w", operation, err)
	}
	if len(result.Success) == 0 {
		return fmt.Errorf("%s returned no successful nodes", operation)
	}
	if nodeID != "*" && nodeID != workerNodeSelf {
		if _, ok := result.Success[nodeID]; !ok {
			return fmt.Errorf("%s returned no success result for node %s", operation, nodeID)
		}
	}
	return nil
}

func validateMultiNodeCommandResponse(resp []byte, nodeID, operation string) error {
	var result multiNodeResponse[json.RawMessage]
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("failed to unmarshal %s response: %w", operation, err)
	}
	return validateMultiNodeSuccess(result, nodeID, operation)
}

// RetryBlockResyncResult is the per-node response payload from RetryBlockResync.
type RetryBlockResyncResult struct {
	Count uint64 `json:"count"`
}

// RetryBlockResync clears the resync backoff for blocks, causing immediate retry.
// Pass all=true to retry all errored blocks, or provide specific block hashes.
// A wildcard retry of specific hashes is first partitioned by the nodes that
// currently report each error. Garage rejects a hash on every node where that
// hash is not errored, so sending the same hash list to node="*" cannot work in
// a healthy replicated cluster. Hashes that are no longer reported are treated
// as an idempotent no-op.
//
// Returns the count summed across all responding nodes; a per-node failure
// surfaces as a non-nil error (the HTTP status is always 200 for this endpoint).
func (c *Client) RetryBlockResync(ctx context.Context, nodeID string, all bool, hashes []string) (*RetryBlockResyncResult, error) {
	if nodeID == "*" && !all {
		return c.retryBlockResyncByErrorOwner(ctx, hashes)
	}

	query := map[string]string{"node": nodeID}
	var body any
	if all {
		body = map[string]bool{"all": true}
	} else {
		body = map[string][]string{"blockHashes": hashes}
	}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/RetryBlockResync", query, body)
	if err != nil {
		return nil, err
	}
	var multi multiNodeResponse[RetryBlockResyncResult]
	if err := json.Unmarshal(resp, &multi); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if err := validateMultiNodeSuccess(multi, nodeID, "RetryBlockResync"); err != nil {
		return nil, err
	}
	var agg RetryBlockResyncResult
	for _, r := range multi.Success {
		agg.Count += r.Count
	}
	return &agg, nil
}

func (c *Client) retryBlockResyncByErrorOwner(ctx context.Context, hashes []string) (*RetryBlockResyncResult, error) {
	requested := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		canonical := strings.ToLower(strings.TrimSpace(hash))
		decoded, err := hex.DecodeString(canonical)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("invalid block hash %q: expected 64 hexadecimal characters", hash)
		}
		requested[canonical] = struct{}{}
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf("at least one block hash is required")
	}

	blockErrors, err := c.ListBlockErrors(ctx, "*")
	if err != nil {
		return nil, fmt.Errorf("listing block errors before retry: %w", err)
	}
	if err := aggregateNodeErrors(blockErrors.Error); err != nil {
		return nil, fmt.Errorf("listing block errors before retry: %w", err)
	}
	if len(blockErrors.Success) == 0 {
		return nil, fmt.Errorf("listing block errors before retry returned no successful nodes")
	}

	hashesByNode := make(map[string][]string)
	for nodeID, nodeErrors := range blockErrors.Success {
		seen := make(map[string]struct{})
		for _, blockErr := range nodeErrors {
			canonical := strings.ToLower(strings.TrimSpace(blockErr.BlockHash))
			if _, wanted := requested[canonical]; !wanted {
				continue
			}
			if _, duplicate := seen[canonical]; duplicate {
				continue
			}
			seen[canonical] = struct{}{}
			hashesByNode[nodeID] = append(hashesByNode[nodeID], canonical)
		}
	}

	nodeIDs := make([]string, 0, len(hashesByNode))
	for nodeID := range hashesByNode {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)

	var aggregate RetryBlockResyncResult
	for _, nodeID := range nodeIDs {
		nodeHashes := hashesByNode[nodeID]
		sort.Strings(nodeHashes)
		result, err := c.RetryBlockResync(ctx, nodeID, false, nodeHashes)
		if err != nil {
			return nil, fmt.Errorf("retrying block resync on node %s: %w", nodeID, err)
		}
		aggregate.Count += result.Count
	}
	return &aggregate, nil
}

// PurgeBlocksResult is the per-node response payload from PurgeBlocks.
type PurgeBlocksResult struct {
	BlocksPurged    uint64 `json:"blocksPurged"`
	BlockRefsPurged uint64 `json:"blockRefsPurged"`
	VersionsDeleted uint64 `json:"versionsDeleted"`
	ObjectsDeleted  uint64 `json:"objectsDeleted"`
	UploadsDeleted  uint64 `json:"uploadsDeleted"`
}

// PurgeBlocks permanently removes all S3 objects referencing the given block hashes.
// WARNING: This is irreversible and will delete object data.
// Counts are summed across all responding nodes; because Garage returns HTTP 200
// even when every node rejected the purge (e.g. an invalid hash), any per-node
// failure is surfaced as a non-nil error so the caller does not record a
// destructive no-op as a success.
func (c *Client) PurgeBlocks(ctx context.Context, nodeID string, hashes []string) (*PurgeBlocksResult, error) {
	query := map[string]string{"node": nodeID}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/PurgeBlocks", query, hashes)
	if err != nil {
		return nil, err
	}
	var multi multiNodeResponse[PurgeBlocksResult]
	if err := json.Unmarshal(resp, &multi); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if err := validateMultiNodeSuccess(multi, nodeID, "PurgeBlocks"); err != nil {
		return nil, err
	}
	var agg PurgeBlocksResult
	for _, r := range multi.Success {
		agg.BlocksPurged += r.BlocksPurged
		agg.BlockRefsPurged += r.BlockRefsPurged
		agg.VersionsDeleted += r.VersionsDeleted
		agg.ObjectsDeleted += r.ObjectsDeleted
		agg.UploadsDeleted += r.UploadsDeleted
	}
	return &agg, nil
}
