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
	"testing"
)

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
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			c := NewClient(srv.URL, "test-token")
			_ = c.LaunchScrubCommand(context.Background(), "*", tt.command)

			if string(gotBody) != tt.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tt.wantBody)
			}
		})
	}
}

const (
	pathGetClusterLayout   = "/v2/GetClusterLayout"
	pathApplyClusterLayout = "/v2/ApplyClusterLayout"
)

// TestApplyStagedLayoutChanges exercises the concurrent-writer-safe apply path.
// Garage returns a generic 500 ("Invalid new layout version") on a version
// race — NOT a 409 — so the helper must re-read the layout to decide whether a
// sibling writer already committed our staged change.
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

	t.Run("version race resolved when sibling already applied", func(t *testing.T) {
		// Apply is rejected with a generic 500; the subsequent GetClusterLayout
		// shows the version already advanced past our target, so the helper
		// treats it as success.
		getCalls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case pathGetClusterLayout:
				getCalls++
				w.Header().Set("Content-Type", "application/json")
				if getCalls == 1 {
					_, _ = w.Write([]byte(`{"version":7,"roles":[],"stagedRoleChanges":[{"id":"n1","zone":"z","tags":[]}]}`))
				} else {
					// Sibling committed; version advanced and staging cleared.
					_, _ = w.Write([]byte(`{"version":8,"roles":[{"id":"n1","zone":"z","tags":[]}],"stagedRoleChanges":[]}`))
				}
			case pathApplyClusterLayout:
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"InternalError","message":"Invalid new layout version"}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok")
		if err := c.ApplyStagedLayoutChanges(context.Background()); err != nil {
			t.Fatalf("expected race to resolve to success, got: %v", err)
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
	result, err := c.ConnectNode(context.Background(), "abc123", "192.168.0.53:3901")

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
