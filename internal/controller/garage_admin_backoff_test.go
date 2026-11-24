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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

type adminTimeoutError struct{}

func (adminTimeoutError) Error() string   { return "i/o timeout" }
func (adminTimeoutError) Timeout() bool   { return true }
func (adminTimeoutError) Temporary() bool { return true }

func TestAdminCallBackoffDoublesUpToCapAndClearsOnSuccess(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	b := newAdminCallBackoff(func() time.Time { return now })
	const key = "http://garage|ListBlockErrors"

	if wait := b.wait(key); wait != 0 {
		t.Fatalf("fresh key waits %s", wait)
	}
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, pause := range want {
		b.observe(key, fmt.Errorf("request failed: %w", context.DeadlineExceeded), nil)
		if got := b.wait(key); got != pause {
			t.Fatalf("timeout %d: wait = %s, want %s", i+1, got, pause)
		}
	}
	for range 100 {
		b.observe(key, adminTimeoutError{}, nil)
	}
	if got := b.wait(key); got != adminCallBackoffMax {
		t.Fatalf("many timeouts: wait = %s, want the cap", got)
	}

	// A non-timeout error neither extends nor clears the pause.
	b.observe(key, errors.New("boom"), nil)
	if got := b.wait(key); got != adminCallBackoffMax {
		t.Fatalf("non-timeout error changed the pause to %s", got)
	}
	now = now.Add(adminCallBackoffMax)
	if got := b.wait(key); got != 0 {
		t.Fatalf("expired pause still waits %s", got)
	}
	b.observe(key, nil, nil)
	b.observe(key, adminTimeoutError{}, nil)
	if got := b.wait(key); got != adminCallBackoffBase {
		t.Fatalf("success did not reset the doubling: wait = %s", got)
	}
	if got := b.wait("other|ListBlockErrors"); got != 0 {
		t.Fatalf("another endpoint waits %s", got)
	}
}

func TestIsAdminCallTimeout(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err        error
		nodeErrors map[string]string
		want       bool
	}{
		"success":            {nil, nil, false},
		"deadline":           {fmt.Errorf("request failed: %w", context.DeadlineExceeded), nil, true},
		"net timeout":        {fmt.Errorf("request failed: %w", adminTimeoutError{}), nil, true},
		"gateway timeout":    {&garage.APIError{StatusCode: http.StatusGatewayTimeout}, nil, true},
		"garage rpc timeout": {&garage.APIError{StatusCode: http.StatusServiceUnavailable, Message: `{"code":"Timeout"}`}, nil, true},
		"quorum 503":         {&garage.APIError{StatusCode: http.StatusServiceUnavailable, Message: "Quorum"}, nil, false},
		"server error":       {&garage.APIError{StatusCode: http.StatusInternalServerError}, nil, false},
		"node timed out":     {nil, map[string]string{"storage-a": "Timeout"}, true},
		"node not connected": {nil, map[string]string{"storage-a": "not connected"}, false},
	} {
		if got := isAdminCallTimeout(tc.err, tc.nodeErrors); got != tc.want {
			t.Errorf("%s: isAdminCallTimeout = %v, want %v", name, got, tc.want)
		}
	}
}

// #604: Garage keeps building a timed-out ListBlockErrors response, so the
// next pass must not stack another one on top.
func TestObserveBlockResyncStatusBacksOffAfterListBlockErrorsTimeout(t *testing.T) {
	t.Parallel()
	workers := `{"success":{"storage-a":[` + resyncWorkerErrorsJSON(1, 0, 2) + `]},"error":{}}`
	var listed atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/ListWorkers":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, workers)
		case "/v2/ListBlockErrors":
			listed.Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { close(release); server.Close() })
	client := garage.NewClient(server.URL, "token")
	client.SetHTTPTimeout(100 * time.Millisecond)

	for pass := range 3 {
		status := &garagev1beta2.GarageClusterStatus{}
		_, resp := observeBlockResyncStatus(context.Background(), client, status, time.Now(), nil, true)
		if status.BlockErrors == nil || *status.BlockErrors != 2 || resp == nil || resp.Counts["storage-a"] != 2 {
			t.Fatalf("pass %d: a failed listing must fall back to counts, got errors=%v resp=%+v", pass, status.BlockErrors, resp)
		}
	}
	if got := listed.Load(); got != 1 {
		t.Fatalf("ListBlockErrors was issued %d times; want 1 then back off", got)
	}
	if wait := garageAdminBackoff.wait(adminCallBackoffKey(client, adminOperationListBlockErrors)); wait <= 0 {
		t.Fatal("no backoff recorded after the timeout")
	}
	if wait := garageAdminBackoff.wait(adminCallBackoffKey(client, adminOperationListWorkers)); wait != 0 {
		t.Fatalf("ListWorkers must not back off after a ListBlockErrors timeout, waits %s", wait)
	}
}

func TestObserveBlockResyncStatusBacksOffAfterListWorkersTimeout(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); server.Close() })
	client := garage.NewClient(server.URL, "token")
	client.SetHTTPTimeout(100 * time.Millisecond)

	for range 3 {
		status := &garagev1beta2.GarageClusterStatus{}
		workers, blockErrors := observeBlockResyncStatus(context.Background(), client, status, time.Now(), nil, true)
		if workers != nil || blockErrors != nil || status.ResyncQueueLength != nil || status.BlockErrors != nil {
			t.Fatalf("timed-out ListWorkers must leave every field unobserved: %+v", status)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Garage received %d requests; want one ListWorkers then back off", got)
	}
}
