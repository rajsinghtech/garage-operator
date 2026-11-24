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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	// adminCallBackoffBase is the first pause after a timed-out Admin call.
	// Garage keeps serving a request after the client gives up (#604), so
	// the next call must not start while the last one may still run.
	adminCallBackoffBase = 5 * time.Minute
	adminCallBackoffMax  = 30 * time.Minute

	adminOperationListWorkers     = "ListWorkers"
	adminOperationListBlockErrors = "ListBlockErrors"
)

// errAdminCallBackingOff is returned instead of issuing an Admin call that
// timed out recently.
var errAdminCallBackingOff = errors.New("garage admin call is backing off after a timeout")

// adminCallBackoff pauses an expensive Admin API call on one endpoint after
// it timed out, doubling the pause on each further timeout up to
// adminCallBackoffMax. A successful call clears it. State is in memory and
// keyed by Admin endpoint and operation, so one slow cluster never delays
// another, and an operator restart starts fresh.
type adminCallBackoff struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]adminCallBackoffEntry
}

type adminCallBackoffEntry struct {
	timeouts int
	until    time.Time
}

func newAdminCallBackoff(now func() time.Time) *adminCallBackoff {
	return &adminCallBackoff{now: now, entries: map[string]adminCallBackoffEntry{}}
}

// garageAdminBackoff is shared by every reconciler, so the status pass and a
// storage-drain proof reading the same endpoint back off together.
var garageAdminBackoff = newAdminCallBackoff(time.Now)

func adminCallBackoffKey(garageClient *garage.Client, operation string) string {
	return garageClient.BaseURL() + "|" + operation
}

// wait returns how long the call must still wait; zero means it may run.
func (b *adminCallBackoff) wait(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[key]
	if !ok {
		return 0
	}
	return max(entry.until.Sub(b.now()), 0)
}

// observe records a call's outcome: a timeout extends the pause, success
// clears it, and any other error leaves it unchanged.
func (b *adminCallBackoff) observe(key string, err error, nodeErrors map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case isAdminCallTimeout(err, nodeErrors):
		entry := b.entries[key]
		entry.timeouts++
		pause := adminCallBackoffMax
		if entry.timeouts <= 8 {
			pause = min(adminCallBackoffBase<<(entry.timeouts-1), adminCallBackoffMax)
		}
		entry.until = b.now().Add(pause)
		b.entries[key] = entry
	case err == nil:
		delete(b.entries, key)
	}
}

// isAdminCallTimeout reports a client-side timeout, a gateway or Garage
// timeout status, or a node that timed out answering the dispatching node.
func isAdminCallTimeout(err error, nodeErrors map[string]string) bool {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return true
		}
		var apiErr *garage.APIError
		if errors.As(err, &apiErr) {
			return apiErr.StatusCode == http.StatusGatewayTimeout ||
				(apiErr.StatusCode == http.StatusServiceUnavailable && strings.Contains(strings.ToLower(apiErr.Message), "timeout"))
		}
		return false
	}
	for _, message := range nodeErrors {
		if strings.Contains(strings.ToLower(message), "timeout") || strings.Contains(strings.ToLower(message), "timed out") {
			return true
		}
	}
	return false
}

// listWorkersWithBackoff is ListWorkers("*") behind garageAdminBackoff.
func listWorkersWithBackoff(ctx context.Context, garageClient *garage.Client) (*garage.ListWorkersResponse, error) {
	key := adminCallBackoffKey(garageClient, adminOperationListWorkers)
	if wait := garageAdminBackoff.wait(key); wait > 0 {
		return nil, fmt.Errorf("%w (ListWorkers, retry in %s)", errAdminCallBackingOff, wait.Round(time.Second))
	}
	workers, err := garageClient.ListWorkers(ctx, "*", false, false)
	var nodeErrors map[string]string
	if err == nil {
		nodeErrors = workers.Error
	}
	garageAdminBackoff.observe(key, err, nodeErrors)
	return workers, err
}

// listBlockErrorsWithBackoff is ListBlockErrors("*") behind
// garageAdminBackoff. Garage builds the whole list synchronously, so a large
// error set can run for minutes after the client gave up (#604).
func listBlockErrorsWithBackoff(ctx context.Context, garageClient *garage.Client) (*garage.ListBlockErrorsResponse, error) {
	key := adminCallBackoffKey(garageClient, adminOperationListBlockErrors)
	if wait := garageAdminBackoff.wait(key); wait > 0 {
		return nil, fmt.Errorf("%w (ListBlockErrors, retry in %s)", errAdminCallBackingOff, wait.Round(time.Second))
	}
	blockErrors, err := garageClient.ListBlockErrors(ctx, "*")
	var nodeErrors map[string]string
	if err == nil {
		nodeErrors = blockErrors.Error
	}
	garageAdminBackoff.observe(key, err, nodeErrors)
	return blockErrors, err
}
