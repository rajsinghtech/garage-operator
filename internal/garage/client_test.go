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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testAdminTokenID = "abc123"

func TestZoneRedundancy_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    ZoneRedundancy
		expected string
	}{
		{
			name:     "Maximum serializes to lowercase string",
			input:    ZoneRedundancy{Maximum: true},
			expected: `"maximum"`,
		},
		{
			name:     "AtLeast serializes to object",
			input:    ZoneRedundancy{AtLeast: intPtr(2)},
			expected: `{"atLeast":2}`,
		},
		{
			name:     "Empty serializes to null",
			input:    ZoneRedundancy{},
			expected: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(result))
			}
		})
	}
}

func TestZoneRedundancy_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    ZoneRedundancy
		expectError bool
		errorMsg    string
	}{
		{
			name:     "lowercase maximum",
			input:    `"maximum"`,
			expected: ZoneRedundancy{Maximum: true},
		},
		{
			name:        "uppercase Maximum rejected (matches upstream)",
			input:       `"Maximum"`,
			expectError: true,
			errorMsg:    "expected 'maximum'",
		},
		{
			name:     "atLeast object",
			input:    `{"atLeast":3}`,
			expected: ZoneRedundancy{AtLeast: intPtr(3)},
		},
		{
			name:     "null value",
			input:    `null`,
			expected: ZoneRedundancy{},
		},
		{
			name:        "invalid string value",
			input:       `"invalid"`,
			expectError: true,
			errorMsg:    "invalid ZoneRedundancy string value",
		},
		{
			name:        "atLeast value too low",
			input:       `{"atLeast":0}`,
			expectError: true,
			errorMsg:    "invalid ZoneRedundancy atLeast value: 0 (must be >= 1)",
		},
		{
			// High values are now allowed - Garage API validates atLeast <= replication_factor
			name:     "atLeast value high (API will validate against replication_factor)",
			input:    `{"atLeast":10}`,
			expected: ZoneRedundancy{AtLeast: intPtr(10)},
		},
		{
			name:        "object missing atLeast key",
			input:       `{"other":5}`,
			expectError: true,
			errorMsg:    "missing 'atLeast' key",
		},
		{
			name:        "invalid format - array",
			input:       `[1,2,3]`,
			expectError: true,
			errorMsg:    "invalid ZoneRedundancy format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result ZoneRedundancy
			err := json.Unmarshal([]byte(tt.input), &result)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Maximum != tt.expected.Maximum {
				t.Errorf("Maximum: expected %v, got %v", tt.expected.Maximum, result.Maximum)
			}
			if (result.AtLeast == nil) != (tt.expected.AtLeast == nil) {
				t.Errorf("AtLeast nil mismatch: expected %v, got %v", tt.expected.AtLeast, result.AtLeast)
			} else if result.AtLeast != nil && *result.AtLeast != *tt.expected.AtLeast {
				t.Errorf("AtLeast value: expected %v, got %v", *tt.expected.AtLeast, *result.AtLeast)
			}
		})
	}
}

func intPtr(v int) *int {
	return &v
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestIsReplicationConstraint(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Garage 500 error with replication factor message",
			err:      &APIError{StatusCode: 500, Message: "The number of nodes with positive capacity (2) is smaller than the replication factor (3)"},
			expected: true,
		},
		{
			name:     "Garage 400 error with replication constraint",
			err:      &APIError{StatusCode: 400, Message: "Cannot apply layout: replication factor requires more nodes"},
			expected: true,
		},
		{
			name:     "Case insensitive matching",
			err:      &APIError{StatusCode: 500, Message: "REPLICATION FACTOR constraint violated"},
			expected: true,
		},
		{
			name:     "Other 500 error",
			err:      &APIError{StatusCode: 500, Message: "Internal server error: database connection failed"},
			expected: false,
		},
		{
			name:     "404 error",
			err:      &APIError{StatusCode: 404, Message: "Not found"},
			expected: false,
		},
		{
			name:     "Non-API error",
			err:      fmt.Errorf("network timeout"),
			expected: false,
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsReplicationConstraint(tt.err)
			if result != tt.expected {
				t.Errorf("IsReplicationConstraint() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsServiceUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "503 quorum error",
			err:      &APIError{StatusCode: 503, Message: "Not enough nodes available to read quorum"},
			expected: true,
		},
		{
			name:     "503 timeout error",
			err:      &APIError{StatusCode: http.StatusServiceUnavailable, Message: "Timeout"},
			expected: true,
		},
		{
			name:     "500 internal error",
			err:      &APIError{StatusCode: 500, Message: "Internal server error"},
			expected: false,
		},
		{
			name:     "409 conflict",
			err:      &APIError{StatusCode: 409, Message: "Conflict"},
			expected: false,
		},
		{
			name:     "non-API error",
			err:      fmt.Errorf("network timeout"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsServiceUnavailable(tt.err); got != tt.expected {
				t.Errorf("IsServiceUnavailable() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestWorkerState_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedState    string
		expectedDuration *float32
		expectError      bool
	}{
		{
			name:          "busy state",
			input:         `"busy"`,
			expectedState: workerStateBusy,
		},
		{
			name:          "idle state",
			input:         `"idle"`,
			expectedState: workerStateIdle,
		},
		{
			name:          "done state",
			input:         `"done"`,
			expectedState: workerStateDone,
		},
		{
			name:             "throttled state with duration",
			input:            `{"throttled":{"durationSecs":1.5}}`,
			expectedState:    WorkerStateThrottled,
			expectedDuration: float32Ptr(1.5),
		},
		{
			name:             "throttled state with integer duration",
			input:            `{"throttled":{"durationSecs":5}}`,
			expectedState:    WorkerStateThrottled,
			expectedDuration: float32Ptr(5.0),
		},
		{
			name:        "invalid format",
			input:       `["invalid"]`,
			expectError: true,
		},
		{
			name:        "unknown object format",
			input:       `{"unknown":"value"}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state WorkerState
			err := json.Unmarshal([]byte(tt.input), &state)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if state.State != tt.expectedState {
				t.Errorf("State = %q, expected %q", state.State, tt.expectedState)
			}

			if tt.expectedDuration == nil {
				if state.DurationSecs != nil {
					t.Errorf("DurationSecs = %v, expected nil", *state.DurationSecs)
				}
			} else {
				if state.DurationSecs == nil {
					t.Errorf("DurationSecs = nil, expected %v", *tt.expectedDuration)
				} else if *state.DurationSecs != *tt.expectedDuration {
					t.Errorf("DurationSecs = %v, expected %v", *state.DurationSecs, *tt.expectedDuration)
				}
			}
		})
	}
}

func TestWorkerState_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    WorkerState
		expected string
	}{
		{
			name:     "busy state",
			input:    WorkerState{State: workerStateBusy},
			expected: `"busy"`,
		},
		{
			name:     "idle state",
			input:    WorkerState{State: workerStateIdle},
			expected: `"idle"`,
		},
		{
			name:     "done state",
			input:    WorkerState{State: workerStateDone},
			expected: `"done"`,
		},
		{
			name:     "throttled state with duration",
			input:    WorkerState{State: WorkerStateThrottled, DurationSecs: float32Ptr(2.5)},
			expected: `{"throttled":{"durationSecs":2.5}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(result) != tt.expected {
				t.Errorf("got %s, expected %s", string(result), tt.expected)
			}
		})
	}
}

func TestWorkerState_Helpers(t *testing.T) {
	tests := []struct {
		name        string
		state       WorkerState
		isBusy      bool
		isIdle      bool
		isDone      bool
		isThrottled bool
	}{
		{"busy", WorkerState{State: "busy"}, true, false, false, false},
		{"idle", WorkerState{State: "idle"}, false, true, false, false},
		{"done", WorkerState{State: "done"}, false, false, true, false},
		{"throttled", WorkerState{State: "throttled"}, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.state.IsBusy() != tt.isBusy {
				t.Errorf("IsBusy() = %v, expected %v", tt.state.IsBusy(), tt.isBusy)
			}
			if tt.state.IsIdle() != tt.isIdle {
				t.Errorf("IsIdle() = %v, expected %v", tt.state.IsIdle(), tt.isIdle)
			}
			if tt.state.IsDone() != tt.isDone {
				t.Errorf("IsDone() = %v, expected %v", tt.state.IsDone(), tt.isDone)
			}
			if tt.state.IsThrottled() != tt.isThrottled {
				t.Errorf("IsThrottled() = %v, expected %v", tt.state.IsThrottled(), tt.isThrottled)
			}
		})
	}
}

func TestWorkerInfo_UnmarshalJSON(t *testing.T) {
	// Test the full WorkerInfo struct unmarshaling matches Garage's response format
	input := `{
		"id": 42,
		"name": "block_manager",
		"state": "busy",
		"errors": 5,
		"consecutiveErrors": 2,
		"lastError": {"message": "connection timeout", "secsAgo": 120},
		"tranquility": 10,
		"progress": "50%",
		"queueLength": 100,
		"persistentErrors": 1,
		"freeform": ["extra", "info"]
	}`

	var worker WorkerInfo
	err := json.Unmarshal([]byte(input), &worker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if worker.ID != 42 {
		t.Errorf("ID = %d, expected 42", worker.ID)
	}
	if worker.Name != "block_manager" {
		t.Errorf("Name = %q, expected %q", worker.Name, "block_manager")
	}
	if !worker.State.IsBusy() {
		t.Errorf("State should be busy")
	}
	if worker.Errors != 5 {
		t.Errorf("Errors = %d, expected 5", worker.Errors)
	}
	if worker.ConsecutiveErrors != 2 {
		t.Errorf("ConsecutiveErrors = %d, expected 2", worker.ConsecutiveErrors)
	}
	if worker.LastError == nil {
		t.Error("LastError should not be nil")
	} else {
		if worker.LastError.Message != "connection timeout" {
			t.Errorf("LastError.Message = %q, expected %q", worker.LastError.Message, "connection timeout")
		}
		if worker.LastError.SecsAgo != 120 {
			t.Errorf("LastError.SecsAgo = %d, expected 120", worker.LastError.SecsAgo)
		}
	}
	if worker.Tranquility == nil || *worker.Tranquility != 10 {
		t.Errorf("Tranquility = %v, expected 10", worker.Tranquility)
	}
	if worker.Progress == nil || *worker.Progress != "50%" {
		t.Errorf("Progress = %v, expected %q", worker.Progress, "50%")
	}
	if worker.QueueLength == nil || *worker.QueueLength != 100 {
		t.Errorf("QueueLength = %v, expected 100", worker.QueueLength)
	}
	if worker.PersistentErrors == nil || *worker.PersistentErrors != 1 {
		t.Errorf("PersistentErrors = %v, expected 1", worker.PersistentErrors)
	}
	if len(worker.Freeform) != 2 || worker.Freeform[0] != "extra" || worker.Freeform[1] != "info" {
		t.Errorf("Freeform = %v, expected [extra, info]", worker.Freeform)
	}
}

func TestWorkerInfo_ThrottledState(t *testing.T) {
	// Test WorkerInfo with throttled state (the complex case)
	input := `{
		"id": 1,
		"name": "scrub_worker",
		"state": {"throttled": {"durationSecs": 3.5}},
		"errors": 0,
		"consecutiveErrors": 0,
		"freeform": []
	}`

	var worker WorkerInfo
	err := json.Unmarshal([]byte(input), &worker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !worker.State.IsThrottled() {
		t.Errorf("State should be throttled")
	}
	if worker.State.DurationSecs == nil || *worker.State.DurationSecs != 3.5 {
		t.Errorf("DurationSecs = %v, expected 3.5", worker.State.DurationSecs)
	}
}

func TestListWorkersPreservesStructuredPerNodeResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/ListWorkers" || r.URL.Query().Get("node") != "*" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var request struct {
			BusyOnly  bool `json:"busyOnly"`
			ErrorOnly bool `json:"errorOnly"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.BusyOnly || request.ErrorOnly {
			http.Error(w, "unexpected filters", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"success": {
				"storage-a": [{"id":7,"name":"Block resync worker #1","state":"idle","errors":0,"consecutiveErrors":0,"queueLength":3,"persistentErrors":1,"freeform":[]}]
			},
			"error": {"historical-node":"not connected"}
		}`)
	}))
	defer server.Close()

	workers, err := NewClient(server.URL, "token").ListWorkers(context.Background(), "*", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(workers.Success["storage-a"]) != 1 || workers.Success["storage-a"][0].QueueLength == nil ||
		*workers.Success["storage-a"][0].QueueLength != 3 || workers.Success["storage-a"][0].PersistentErrors == nil ||
		*workers.Success["storage-a"][0].PersistentErrors != 1 {
		t.Fatalf("unexpected block-resync worker response: %+v", workers.Success["storage-a"])
	}
	if workers.Error["historical-node"] != "not connected" {
		t.Fatalf("per-node error map was lost: %+v", workers.Error)
	}
}

func TestGetSelfNodeInfoRequiresExactConsistentMultiResponse(t *testing.T) {
	nodeID := strings.Repeat("a", 64)
	otherID := strings.Repeat("b", 64)
	tests := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "exact self response",
			payload: `{"success":{"` + nodeID + `":{"nodeId":"` + strings.ToUpper(nodeID) + `"}},"error":{}}`,
		},
		{
			name:    "embedded dispatch error",
			payload: `{"success":{"` + nodeID + `":{"nodeId":"` + nodeID + `"}},"error":{"` + nodeID + `":"unavailable"}}`,
			wantErr: "dispatch failed",
		},
		{
			name:    "missing success",
			payload: `{"success":{},"error":{}}`,
			wantErr: "exactly one",
		},
		{
			name: "multiple successes",
			payload: `{"success":{"` + nodeID + `":{"nodeId":"` + nodeID + `"},"` +
				otherID + `":{"nodeId":"` + otherID + `"}},"error":{}}`,
			wantErr: "exactly one",
		},
		{
			name:    "map key and body disagree",
			payload: `{"success":{"` + nodeID + `":{"nodeId":"` + otherID + `"}},"error":{}}`,
			wantErr: "does not match",
		},
		{
			name:    "malformed identity",
			payload: `{"success":{"short":{"nodeId":"short"}},"error":{}}`,
			wantErr: "64 hexadecimal",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v2/GetNodeInfo" || r.URL.Query().Get("node") != workerNodeSelf {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, test.payload)
			}))
			defer server.Close()

			info, err := NewClient(server.URL, "token").GetSelfNodeInfo(context.Background())
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info == nil || info.NodeID != nodeID {
				t.Fatalf("self node info = %+v, want canonical ID %s", info, nodeID)
			}
		})
	}
}

func TestLaunchRepairRequiresPerNodeSuccess(t *testing.T) {
	t.Run("exact node success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v2/LaunchRepairOperation" || r.URL.Query().Get("node") != "storage-a" {
				http.NotFound(w, r)
				return
			}
			var request LaunchRepairRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.RepairType != "blocks" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"success":{"storage-a":null},"error":{}}`)
		}))
		defer server.Close()
		if err := NewClient(server.URL, "token").LaunchRepair(context.Background(), "storage-a", "Blocks"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("embedded node failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":{},"error":{"storage-a":"not connected"}}`)
		}))
		defer server.Close()
		err := NewClient(server.URL, "token").LaunchRepair(context.Background(), "storage-a", "Blocks")
		if err == nil || !strings.Contains(err.Error(), "not connected") {
			t.Fatalf("embedded dispatch failure was accepted: %v", err)
		}
	})
}

func TestClientNormalizesTrailingSlashInBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/GetClusterStatus" {
			t.Fatalf("request path = %q, want one canonical slash before v2", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"layoutVersion":1,"nodes":[]}`)
	}))
	defer server.Close()

	client := NewClient("  "+server.URL+"/  ", "token")
	if client.BaseURL() != server.URL {
		t.Fatalf("base URL = %q, want %q", client.BaseURL(), server.URL)
	}
	if _, err := client.GetClusterStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func float32Ptr(v float32) *float32 {
	return &v
}

func TestLaunchScrubCommand_RequestBody(t *testing.T) {
	tests := []struct {
		command  string
		wantBody string
	}{
		{"start", `{"repairType":{"scrub":"start"}}`},
		{"pause", `{"repairType":{"scrub":"pause"}}`},
		{"resume", `{"repairType":{"scrub":"resume"}}`},
		{"cancel", `{"repairType":{"scrub":"cancel"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				if r.URL.Query().Get("node") != "*" {
					t.Errorf("expected node=*, got %q", r.URL.Query().Get("node"))
				}
				_, _ = io.WriteString(w, `{"success":{"node-a":null},"error":{}}`)
			}))
			defer srv.Close()

			c := NewClient(srv.URL, "test-token")
			if err := c.LaunchScrubCommand(context.Background(), "*", tt.command); err != nil {
				t.Fatal(err)
			}

			if string(gotBody) != tt.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tt.wantBody)
			}
		})
	}
}

func TestNodeScopedCommandsRejectEmbeddedFailures(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "worker variable",
			path: "/v2/SetWorkerVariable",
			call: func(c *Client) error {
				return c.SetWorkerVariable(context.Background(), "*", "scrub-tranquility", "10")
			},
		},
		{
			name: "scrub command",
			path: "/v2/LaunchRepairOperation",
			call: func(c *Client) error {
				return c.LaunchScrubCommand(context.Background(), "*", "start")
			},
		},
		{
			name: "metadata snapshot",
			path: "/v2/CreateMetadataSnapshot",
			call: func(c *Client) error {
				return c.CreateMetadataSnapshot(context.Background(), "*")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != test.path || r.URL.Query().Get("node") != "*" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
				}
				_, _ = io.WriteString(w, `{"success":{},"error":{"node-a":"not connected"}}`)
			}))
			defer server.Close()

			err := test.call(NewClient(server.URL, "token"))
			if err == nil || !strings.Contains(err.Error(), "node-a: not connected") {
				t.Fatalf("embedded dispatch failure was accepted: %v", err)
			}
		})
	}
}

func TestNodeScopedMutationsRequireAtLeastOneSuccess(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{
			name: "retry block resync",
			call: func(c *Client) error {
				_, err := c.RetryBlockResync(context.Background(), "*", true, nil)
				return err
			},
		},
		{
			name: "purge blocks",
			call: func(c *Client) error {
				_, err := c.PurgeBlocks(context.Background(), "*", []string{strings.Repeat("a", 64)})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"success":{},"error":{}}`)
			}))
			defer server.Close()

			err := test.call(NewClient(server.URL, "token"))
			if err == nil || !strings.Contains(err.Error(), "no successful nodes") {
				t.Fatalf("empty dispatch result was accepted: %v", err)
			}
		})
	}
}

func TestRetryBlockResyncPartitionsWildcardHashesByErrorOwner(t *testing.T) {
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	hashNoLongerErrored := strings.Repeat("c", 64)
	callOrder := make([]string, 0, 2)
	retriedByNode := make(map[string][]string)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/ListBlockErrors":
			if r.Method != http.MethodGet || r.URL.Query().Get("node") != "*" {
				t.Fatalf("unexpected ListBlockErrors request: %s %s", r.Method, r.URL.String())
			}
			_, _ = fmt.Fprintf(w, `{"success":{"node-b":[{"blockHash":%q}],"node-a":[{"blockHash":%q},{"blockHash":%q},{"blockHash":%q}]},"error":{}}`,
				hashA, hashB, hashA, hashA)
		case pathRetryBlockResync:
			nodeID := r.URL.Query().Get("node")
			if r.Method != http.MethodPost || nodeID == "" || nodeID == "*" {
				t.Fatalf("specific hashes must target one error-owning node, got: %s %s", r.Method, r.URL.String())
			}
			var body struct {
				BlockHashes []string `json:"blockHashes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode RetryBlockResync request: %v", err)
			}
			callOrder = append(callOrder, nodeID)
			retriedByNode[nodeID] = body.BlockHashes
			_, _ = fmt.Fprintf(w, `{"success":{%q:{"count":%d}},"error":{}}`, nodeID, len(body.BlockHashes))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	result, err := NewClient(srv.URL, "token").RetryBlockResync(context.Background(), "*", false,
		[]string{strings.ToUpper(hashA), hashB, hashA, hashNoLongerErrored})
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 3 {
		t.Fatalf("retry count = %d, want 3 node-local error records", result.Count)
	}
	if got := strings.Join(callOrder, ","); got != "node-a,node-b" {
		t.Fatalf("retry call order = %q, want deterministic node-a,node-b", got)
	}
	if got := strings.Join(retriedByNode["node-a"], ","); got != hashA+","+hashB {
		t.Fatalf("node-a hashes = %q, want only its unique requested errors", got)
	}
	if got := strings.Join(retriedByNode["node-b"], ","); got != hashA {
		t.Fatalf("node-b hashes = %q, want only its requested error", got)
	}
}

func TestRetryBlockResyncWildcardSpecificHashesFailsClosed(t *testing.T) {
	hash := strings.Repeat("d", 64)
	t.Run("invalid hash is rejected before an API request", func(t *testing.T) {
		requests := 0
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests++
		}))
		defer srv.Close()

		_, err := NewClient(srv.URL, "token").RetryBlockResync(context.Background(), "*", false, []string{"not-a-hash"})
		if err == nil || !strings.Contains(err.Error(), "64 hexadecimal") {
			t.Fatalf("invalid hash error = %v", err)
		}
		if requests != 0 {
			t.Fatalf("invalid input made %d API request(s), want 0", requests)
		}
	})

	t.Run("per-node listing failure prevents every retry", func(t *testing.T) {
		retryCalls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == pathRetryBlockResync {
				retryCalls++
			}
			_, _ = io.WriteString(w, `{"success":{"node-a":[]},"error":{"node-b":"not connected"}}`)
		}))
		defer srv.Close()

		_, err := NewClient(srv.URL, "token").RetryBlockResync(context.Background(), "*", false, []string{hash})
		if err == nil || !strings.Contains(err.Error(), "node-b: not connected") {
			t.Fatalf("listing failure error = %v", err)
		}
		if retryCalls != 0 {
			t.Fatalf("partial error inventory triggered %d retry call(s), want 0", retryCalls)
		}
	})

	t.Run("empty successful inventory is rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"success":{},"error":{}}`)
		}))
		defer srv.Close()

		_, err := NewClient(srv.URL, "token").RetryBlockResync(context.Background(), "*", false, []string{hash})
		if err == nil || !strings.Contains(err.Error(), "no successful nodes") {
			t.Fatalf("empty inventory error = %v", err)
		}
	})
}

func TestRetryBlockResyncAllStillUsesGarageWildcard(t *testing.T) {
	handled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		if r.Method != http.MethodPost || r.URL.Path != pathRetryBlockResync || r.URL.Query().Get("node") != "*" {
			t.Fatalf("unexpected wildcard retry request: %s %s", r.Method, r.URL.String())
		}
		var body map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body["all"] {
			t.Fatalf("wildcard retry body = %#v, err=%v", body, err)
		}
		_, _ = io.WriteString(w, `{"success":{"node-a":{"count":2},"node-b":{"count":1}},"error":{}}`)
	}))
	defer srv.Close()

	result, err := NewClient(srv.URL, "token").RetryBlockResync(context.Background(), "*", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || result.Count != 3 {
		t.Fatalf("wildcard retry handled=%v count=%d, want true/3", handled, result.Count)
	}
}

const (
	pathGetClusterLayout   = "/v2/GetClusterLayout"
	pathApplyClusterLayout = "/v2/ApplyClusterLayout"
	pathRetryBlockResync   = "/v2/RetryBlockResync"
)

// TestApplyStagedLayoutChanges exercises the coordinated apply path. Garage
// returns a generic 500 (not a 409) on a version race; that error must surface
// because a newer version alone does not prove our requested role landed.
func TestApplyStagedLayoutChanges(t *testing.T) {
	t.Run("no staged changes does not apply", func(t *testing.T) {
		applied := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case pathGetClusterLayout:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":7,"roles":[],"stagedRoleChanges":[]}`))
			case pathApplyClusterLayout:
				applied = true
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok")
		if err := c.ApplyStagedLayoutChanges(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if applied {
			t.Fatal("apply must not be called when nothing is staged (version churn)")
		}
	})

	t.Run("staged changes applied at version+1", func(t *testing.T) {
		var gotVersion uint64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case pathGetClusterLayout:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":7,"roles":[],"stagedRoleChanges":[{"id":"n1","zone":"z","tags":[]}]}`))
			case pathApplyClusterLayout:
				var req ApplyLayoutRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				gotVersion = req.Version
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok")
		if err := c.ApplyStagedLayoutChanges(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotVersion != 8 {
			t.Fatalf("applied version = %d, want 8", gotVersion)
		}
	})

	t.Run("version race surfaces for coordinated retry", func(t *testing.T) {
		getCalls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case pathGetClusterLayout:
				getCalls++
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":7,"roles":[],"stagedRoleChanges":[{"id":"n1","zone":"z","tags":[]}]}`))
			case pathApplyClusterLayout:
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"InternalError","message":"Invalid new layout version"}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok")
		if err := c.ApplyStagedLayoutChanges(context.Background()); err == nil {
			t.Fatal("expected version race to surface")
		}
		if getCalls != 1 {
			t.Fatalf("GetClusterLayout calls = %d, want 1; do not infer success from a later version", getCalls)
		}
	})

	t.Run("genuine apply failure surfaces error", func(t *testing.T) {
		// Apply rejected and the version did NOT advance — a real failure the
		// caller must requeue on.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case pathGetClusterLayout:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":7,"roles":[],"stagedRoleChanges":[{"id":"n1","zone":"z","tags":[]}]}`))
			case pathApplyClusterLayout:
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"InternalError","message":"some other failure"}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok")
		if err := c.ApplyStagedLayoutChanges(context.Background()); err == nil {
			t.Fatal("expected apply failure to surface as an error")
		}
	})
}

func TestConnectNode_ReturnsErrorWhenGarageReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/ConnectClusterNodes" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		var body []string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if len(body) != 1 || body[0] != "abc123@192.168.0.53:3901" {
			t.Fatalf("unexpected request body: %#v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"success":false,"error":"Error establishing RPC connection"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	result, err := c.ConnectNode(context.Background(), testAdminTokenID, "192.168.0.53:3901")

	if err == nil {
		t.Fatal("expected ConnectNode to return an error")
	}
	if result == nil {
		t.Fatal("expected ConnectNode to return the Garage response")
	}
	if result.Success {
		t.Fatal("expected result.Success to be false")
	}
	if got := err.Error(); got != "ConnectClusterNodes failed: Error establishing RPC connection" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestAdminTokenAPI(t *testing.T) {
	const bearer = "bootstrap-token"
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+bearer {
			t.Fatalf("Authorization = %q", got)
		}
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/ListAdminTokens":
			_, _ = w.Write([]byte(`[{"id":"abc123","created":"2026-07-31T12:00:00Z","name":"operator","expiration":null,"expired":false,"scope":["*"]},{"id":null,"created":null,"name":"admin_token (from daemon configuration)","expiration":null,"expired":false,"scope":["*"]}]`))
		case "/v2/GetAdminTokenInfo":
			if r.URL.Query().Get("id") != testAdminTokenID || r.URL.Query().Get("search") != "" {
				t.Fatalf("unexpected info query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"abc123","created":"2026-07-31T12:00:00Z","name":"operator","expiration":null,"expired":false,"scope":["*"]}`))
		case "/v2/CreateAdminToken":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "operator" || body["neverExpires"] != true {
				t.Fatalf("unexpected create body: %#v", body)
			}
			if scope, ok := body["scope"].([]any); !ok || len(scope) != 1 || scope[0] != "*" {
				t.Fatalf("unexpected create scope: %#v", body["scope"])
			}
			_, _ = w.Write([]byte(`{"secretToken":"abc123.secret","id":"abc123","created":"2026-07-31T12:00:00Z","name":"operator","expiration":null,"expired":false,"scope":["*"]}`))
		case "/v2/UpdateAdminToken":
			if r.URL.Query().Get("id") != testAdminTokenID {
				t.Fatalf("unexpected update query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"abc123","created":"2026-07-31T12:00:00Z","name":"renamed","expiration":null,"expired":false,"scope":["*"]}`))
		case "/v2/DeleteAdminToken":
			if r.Method != http.MethodPost || r.URL.Query().Get("id") != testAdminTokenID {
				t.Fatalf("unexpected delete request: %s %s", r.Method, r.URL.RequestURI())
			}
			_, _ = w.Write([]byte(`null`))
		case "/v2/GetCurrentAdminTokenInfo":
			_, _ = w.Write([]byte(`{"id":"abc123","created":"2026-07-31T12:00:00Z","name":"operator","expiration":null,"expired":false,"scope":["*"]}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, bearer)
	tokens, err := c.ListAdminTokens(context.Background())
	if err != nil || len(tokens) != 2 || tokens[0].ID == nil || *tokens[0].ID != testAdminTokenID || tokens[1].ID != nil {
		t.Fatalf("ListAdminTokens = %#v, %v", tokens, err)
	}
	if _, err := c.GetAdminTokenInfo(context.Background(), testAdminTokenID, ""); err != nil {
		t.Fatal(err)
	}
	name := "operator"
	scope := []string{"*"}
	created, err := c.CreateAdminToken(context.Background(), AdminTokenUpdate{
		Name: &name, NeverExpires: true, Scope: &scope,
	})
	if err != nil || created.SecretToken != "abc123.secret" || created.ID == nil || *created.ID != testAdminTokenID {
		t.Fatalf("CreateAdminToken = %#v, %v", created, err)
	}
	rename := "renamed"
	updated, err := c.UpdateAdminToken(context.Background(), testAdminTokenID, AdminTokenUpdate{Name: &rename})
	if err != nil || updated.Name != rename {
		t.Fatalf("UpdateAdminToken = %#v, %v", updated, err)
	}
	if err := c.DeleteAdminToken(context.Background(), testAdminTokenID); err != nil {
		t.Fatal(err)
	}
	current, err := c.GetCurrentAdminTokenInfo(context.Background())
	if err != nil || current.ID == nil || *current.ID != testAdminTokenID {
		t.Fatalf("GetCurrentAdminTokenInfo = %#v, %v", current, err)
	}
	if len(calls) != 6 {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestAdminTokenAPIRejectsInvalidInputsAndResponses(t *testing.T) {
	c := NewClient("http://unused", "token")
	if _, err := c.GetAdminTokenInfo(context.Background(), "", ""); err == nil {
		t.Fatal("empty id/search accepted")
	}
	if _, err := c.GetAdminTokenInfo(context.Background(), "id", "search"); err == nil {
		t.Fatal("both id and search accepted")
	}
	if err := c.DeleteAdminToken(context.Background(), ""); err == nil {
		t.Fatal("empty delete id accepted")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/CreateAdminToken":
			_, _ = w.Write([]byte(`{"id":"abc","name":"missing secret","expired":false,"scope":["*"]}`))
		case "/v2/ListAdminTokens":
			_, _ = w.Write([]byte(`not-json`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Invalid bearer token"}`))
		}
	}))
	defer srv.Close()
	c = NewClient(srv.URL, "token")
	if _, err := c.CreateAdminToken(context.Background(), AdminTokenUpdate{}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete create response accepted: %v", err)
	}
	if _, err := c.ListAdminTokens(context.Background()); err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("malformed list response accepted: %v", err)
	}
	if _, err := c.GetCurrentAdminTokenInfo(context.Background()); !IsForbidden(err) {
		t.Fatalf("403 not recognized as forbidden: %v", err)
	}
}

func TestClusterHealthAcceptsGarageV20AndV21StorageNodeFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{name: "Garage v2.0", body: `{"status":"healthy","storageNodes":3,"storageNodesOk":2}`, want: 2},
		{name: "Garage v2.1+", body: `{"status":"healthy","storageNodes":3,"storageNodesUp":2}`, want: 2},
		{name: "matching transition fields", body: `{"storageNodesOk":2,"storageNodesUp":2}`, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var health ClusterHealth
			if err := json.Unmarshal([]byte(tc.body), &health); err != nil {
				t.Fatal(err)
			}
			if health.StorageNodesUp != tc.want {
				t.Fatalf("StorageNodesUp = %d, want %d", health.StorageNodesUp, tc.want)
			}
		})
	}
	var health ClusterHealth
	if err := json.Unmarshal([]byte(`{"storageNodesOk":1,"storageNodesUp":2}`), &health); err == nil {
		t.Fatal("conflicting compatibility fields were accepted")
	}
}

func TestAPIErrorGarageMessage(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"json body": {`{"code":"InvalidRequest","message":"Key identifiers should be at least 8 characters long","path":"/v2/ImportKey"}`,
			"Key identifiers should be at least 8 characters long"},
		"padded message":     {`{"message":"  spaced  "}`, "spaced"},
		"json without text":  {`{"code":"X"}`, `{"code":"X"}`},
		"empty message":      {`{"message":"   "}`, `{"message":"   "}`},
		"plain text":         {"  upstream connect error  ", "upstream connect error"},
		"truncated json":     {`{"code":"InvalidRequest","message":"abc... (truncated)`, `{"code":"InvalidRequest","message":"abc... (truncated)`},
		"html from a proxy":  {"<html>Bad Gateway</html>", "<html>Bad Gateway</html>"},
		"empty body":         {"", ""},
		"non-object json":    {`"just a string"`, `"just a string"`},
		"nested message key": {`{"error":{"message":"inner"}}`, `{"error":{"message":"inner"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := (&APIError{StatusCode: http.StatusBadRequest, Message: tc.body}).GarageMessage(); got != tc.want {
				t.Fatalf("GarageMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}
