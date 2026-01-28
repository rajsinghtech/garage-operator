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
	"encoding/json"
	"fmt"
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

func TestParseZoneRedundancy(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *ZoneRedundancy
		expectError bool
		errorMsg    string
	}{
		{
			name:     "Empty string defaults to Maximum",
			input:    "",
			expected: &ZoneRedundancy{Maximum: true},
		},
		{
			name:     "Maximum",
			input:    "Maximum",
			expected: &ZoneRedundancy{Maximum: true},
		},
		{
			name:     "maximum lowercase",
			input:    "maximum",
			expected: &ZoneRedundancy{Maximum: true},
		},
		{
			name:     "MAXIMUM uppercase",
			input:    "MAXIMUM",
			expected: &ZoneRedundancy{Maximum: true},
		},
		{
			name:     "AtLeast(1)",
			input:    "AtLeast(1)",
			expected: &ZoneRedundancy{AtLeast: intPtr(1)},
		},
		{
			name:     "AtLeast(2)",
			input:    "AtLeast(2)",
			expected: &ZoneRedundancy{AtLeast: intPtr(2)},
		},
		{
			name:     "AtLeast(7)",
			input:    "AtLeast(7)",
			expected: &ZoneRedundancy{AtLeast: intPtr(7)},
		},
		{
			name:     "With whitespace",
			input:    "  Maximum  ",
			expected: &ZoneRedundancy{Maximum: true},
		},
		{
			name:        "AtLeast(0) too low",
			input:       "AtLeast(0)",
			expectError: true,
			errorMsg:    "must be >= 1",
		},
		{
			// High values are now allowed - Garage API validates atLeast <= replication_factor
			name:     "AtLeast(8) high value (API will validate against replication_factor)",
			input:    "AtLeast(8)",
			expected: &ZoneRedundancy{AtLeast: intPtr(8)},
		},
		{
			name:        "AtLeast(abc) invalid number",
			input:       "AtLeast(abc)",
			expectError: true,
			errorMsg:    "invalid AtLeast value",
		},
		{
			name:        "Invalid format",
			input:       "Something",
			expectError: true,
			errorMsg:    "invalid zone redundancy format",
		},
		{
			name:        "Malformed AtLeast",
			input:       "AtLeast(3",
			expectError: true,
			errorMsg:    "invalid zone redundancy format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseZoneRedundancy(tt.input)

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

			if result == nil {
				t.Fatal("expected non-nil result")
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
			expectedState: "busy",
		},
		{
			name:          "idle state",
			input:         `"idle"`,
			expectedState: "idle",
		},
		{
			name:          "done state",
			input:         `"done"`,
			expectedState: "done",
		},
		{
			name:             "throttled state with duration",
			input:            `{"throttled":{"durationSecs":1.5}}`,
			expectedState:    "throttled",
			expectedDuration: float32Ptr(1.5),
		},
		{
			name:             "throttled state with integer duration",
			input:            `{"throttled":{"durationSecs":5}}`,
			expectedState:    "throttled",
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
			input:    WorkerState{State: "busy"},
			expected: `"busy"`,
		},
		{
			name:     "idle state",
			input:    WorkerState{State: "idle"},
			expected: `"idle"`,
		},
		{
			name:     "done state",
			input:    WorkerState{State: "done"},
			expected: `"done"`,
		},
		{
			name:     "throttled state with duration",
			input:    WorkerState{State: "throttled", DurationSecs: float32Ptr(2.5)},
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
