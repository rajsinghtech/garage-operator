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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
func IsReplicationConstraint(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		// Garage returns 500 with a message about node count vs replication factor
		// Error looks like: "The number of nodes with positive capacity (2) is smaller than the replication factor (3)"
		msg := strings.ToLower(apiErr.Message)
		return (apiErr.StatusCode == http.StatusInternalServerError || apiErr.StatusCode == http.StatusBadRequest) &&
			(strings.Contains(msg, "replication factor") ||
				strings.Contains(msg, "smaller than") ||
				strings.Contains(msg, "positive capacity"))
	}
	return false
}

// GetStatusCode returns the HTTP status code from an API error, or 0 if not an API error
func GetStatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
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
		baseURL:    baseURL,
		adminToken: adminToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
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
	LayoutVersion int64      `json:"layoutVersion"`
	Nodes         []NodeInfo `json:"nodes"`
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

// ClusterLayout represents the Garage cluster layout
type ClusterLayout struct {
	Version           int64             `json:"version"`
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

// UpdateLayoutRequest is an alias for backward compatibility
type UpdateLayoutRequest = NodeRoleChange

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
// Garage uses camelCase serialization, so Maximum becomes "maximum"
func (z *ZoneRedundancy) UnmarshalJSON(data []byte) error {
	// Handle null value
	if string(data) == "null" {
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// Accept both "maximum" (Garage's format) and "Maximum" (legacy)
		if s == "maximum" || s == "Maximum" {
			z.Maximum = true
			return nil
		}
		return fmt.Errorf("invalid ZoneRedundancy string value: %q (expected 'maximum')", s)
	}
	var obj map[string]int
	if err := json.Unmarshal(data, &obj); err == nil {
		if v, ok := obj["atLeast"]; ok {
			if v < 1 || v > 7 {
				return fmt.Errorf("invalid ZoneRedundancy atLeast value: %d (must be 1-7)", v)
			}
			z.AtLeast = &v
			return nil
		}
		return fmt.Errorf("invalid ZoneRedundancy object: missing 'atLeast' key")
	}
	return fmt.Errorf("invalid ZoneRedundancy format: expected string 'maximum' or object {\"atLeast\": n}")
}

// ParseZoneRedundancy parses a zone redundancy string like "Maximum" or "AtLeast(2)"
// from the CRD spec format into the API struct format.
func ParseZoneRedundancy(s string) (*ZoneRedundancy, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Maximum") {
		return &ZoneRedundancy{Maximum: true}, nil
	}

	// Parse "AtLeast(N)" format
	if strings.HasPrefix(s, "AtLeast(") && strings.HasSuffix(s, ")") {
		numStr := s[8 : len(s)-1]
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, fmt.Errorf("invalid AtLeast value: %s", numStr)
		}
		if n < 1 || n > 7 {
			return nil, fmt.Errorf("AtLeast value must be between 1 and 7, got %d", n)
		}
		return &ZoneRedundancy{AtLeast: &n}, nil
	}

	return nil, fmt.Errorf("invalid zone redundancy format: %s (expected 'Maximum' or 'AtLeast(N)')", s)
}

// UpdateClusterLayout stages layout changes
func (c *Client) UpdateClusterLayout(ctx context.Context, roles []NodeRoleChange) error {
	req := UpdateClusterLayoutRequest{Roles: roles}
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/UpdateClusterLayout", req)
	return err
}

// UpdateClusterLayoutWithParams stages layout changes with parameters
func (c *Client) UpdateClusterLayoutWithParams(ctx context.Context, req UpdateClusterLayoutRequest) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/UpdateClusterLayout", req)
	return err
}

// ApplyLayoutRequest is the request to apply staged layout changes
type ApplyLayoutRequest struct {
	Version int64 `json:"version"`
}

// ApplyClusterLayout applies staged layout changes
func (c *Client) ApplyClusterLayout(ctx context.Context, version int64) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/ApplyClusterLayout", ApplyLayoutRequest{Version: version})
	return err
}

// RevertClusterLayout reverts staged layout changes
func (c *Client) RevertClusterLayout(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/v2/RevertClusterLayout", nil)
	return err
}

// SkipDeadNodesRequest is the request to skip dead nodes in draining layout versions
type SkipDeadNodesRequest struct {
	// Version is the layout version to assume is up-to-date (usually current version)
	Version int64 `json:"version"`
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
// Use allowMissingData=true for gateway nodes that never stored data.
func (c *Client) ClusterLayoutSkipDeadNodes(ctx context.Context, req SkipDeadNodesRequest) (*SkipDeadNodesResponse, error) {
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
	Version      int64               `json:"version"`
	Status       LayoutVersionStatus `json:"status"`
	StorageNodes int                 `json:"storageNodes"`
	GatewayNodes int                 `json:"gatewayNodes"`
}

// NodeUpdateTrackers contains the update tracker values for a node
type NodeUpdateTrackers struct {
	Ack     int64 `json:"ack"`
	Sync    int64 `json:"sync"`
	SyncAck int64 `json:"syncAck"`
}

// LayoutHistoryResponse is the response from GetClusterLayoutHistory
type LayoutHistoryResponse struct {
	CurrentVersion int64                         `json:"currentVersion"`
	MinAck         int64                         `json:"minAck"`
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

// HasDrainingVersions returns true if there are any layout versions in Draining status
func (h *LayoutHistoryResponse) HasDrainingVersions() bool {
	for _, v := range h.Versions {
		if v.Status == LayoutVersionStatusDraining {
			return true
		}
	}
	return false
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
}

// WebsiteConfig represents bucket website configuration returned by Admin API.
// NOTE: Garage Admin API only returns indexDocument and errorDocument.
// RoutingRules and RedirectAll are S3-API-only features and are NOT returned here.
type WebsiteConfig struct {
	IndexDocument string `json:"indexDocument"`
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// NOTE: WebsiteRedirectAll and WebsiteRoutingRule types are NOT included here
// because Garage Admin API does not support reading or writing these fields.
// These are S3-API-only features. If you need to configure routing rules or
// redirects, use the S3 PutBucketWebsite API directly.

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
type UpdateBucketWebsiteAccess struct {
	Enabled       bool   `json:"enabled"`
	IndexDocument string `json:"indexDocument,omitempty"`
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// UpdateBucketRequestBody is the JSON body for updating bucket settings
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

// WorkerInfo represents information about a background worker
type WorkerInfo struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	State             string  `json:"state"` // "Busy", "Idle", "Throttled", "Done", "Error"
	Progress          *string `json:"progress,omitempty"`
	ConsecutiveErrors int     `json:"consecutiveErrors"`
	LastError         *string `json:"lastError,omitempty"`
	LastErrorSecsAgo  *int64  `json:"lastErrorSecsAgo,omitempty"`
}

// ListWorkersRequest is the request body for listing workers
type ListWorkersRequest struct {
	BusyOnly  bool `json:"busyOnly,omitempty"`
	ErrorOnly bool `json:"errorOnly,omitempty"`
}

// ListWorkers returns information about background workers on a node
func (c *Client) ListWorkers(ctx context.Context, nodeID string, busyOnly, errorOnly bool) ([]WorkerInfo, error) {
	query := map[string]string{"node": nodeID}
	req := ListWorkersRequest{BusyOnly: busyOnly, ErrorOnly: errorOnly}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/ListWorkers", query, req)
	if err != nil {
		return nil, err
	}

	var workers []WorkerInfo
	if err := json.Unmarshal(resp, &workers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return workers, nil
}

// GetWorkerVariableRequest identifies which variable to get
type GetWorkerVariableRequest struct {
	Variable string `json:"variable"`
}

// GetWorkerVariableResponse contains the variable value
type GetWorkerVariableResponse struct {
	Variable string `json:"variable"`
	Value    string `json:"value"`
}

// GetWorkerVariable gets a worker configuration variable from a node
func (c *Client) GetWorkerVariable(ctx context.Context, nodeID, variable string) (*GetWorkerVariableResponse, error) {
	query := map[string]string{"node": nodeID}
	req := GetWorkerVariableRequest{Variable: variable}
	resp, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/GetWorkerVariable", query, req)
	if err != nil {
		return nil, err
	}

	var result GetWorkerVariableResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
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
	query := map[string]string{"node": nodeID}
	req := SetWorkerVariableRequest{Variable: variable, Value: value}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/SetWorkerVariable", query, req)
	return err
}

// LaunchRepairRequest is the request to launch a repair operation
type LaunchRepairRequest struct {
	RepairType string `json:"repairType"` // Tables, Blocks, Versions, Rebalance, Scrub, etc.
}

// LaunchRepair starts a repair operation on a node
func (c *Client) LaunchRepair(ctx context.Context, nodeID, repairType string) error {
	query := map[string]string{"node": nodeID}
	req := LaunchRepairRequest{RepairType: repairType}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/LaunchRepairOperation", query, req)
	return err
}

// CreateMetadataSnapshot triggers a metadata snapshot on a node
func (c *Client) CreateMetadataSnapshot(ctx context.Context, nodeID string) error {
	query := map[string]string{"node": nodeID}
	_, err := c.doRequestWithQuery(ctx, http.MethodPost, "/v2/CreateMetadataSnapshot", query, nil)
	return err
}
