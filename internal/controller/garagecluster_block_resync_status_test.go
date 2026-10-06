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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

var (
	resyncStatusHashA = strings.Repeat("a", 64)
	resyncStatusHashB = strings.Repeat("b", 64)
)

func newResyncStatusAdmin(t *testing.T, workers, blockErrors string) *garage.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node") != "*" {
			http.Error(w, "expected node=*", http.StatusBadRequest)
			return
		}
		var body string
		switch r.URL.Path {
		case "/v2/ListWorkers":
			body = workers
		case "/v2/ListBlockErrors":
			body = blockErrors
		}
		if body == "" {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return garage.NewClient(server.URL, "token")
}

func resyncWorkerJSON(index, queue int) string {
	return fmt.Sprintf(`{"id":%d,"name":"Block resync worker #%d","state":"idle","errors":0,"consecutiveErrors":0,"queueLength":%d,"persistentErrors":0,"freeform":[]}`,
		index, index, queue)
}

func TestObserveBlockResyncStatusAggregatesNodes(t *testing.T) {
	t.Parallel()
	// Every resync worker on a node reports the same node-wide queue, so
	// storage-a contributes 700, not 1400. storage-c's only resync worker is
	// disabled and reports no queue.
	workers := `{"success":{
		"storage-a":[` + resyncWorkerJSON(1, 700) + `,` + resyncWorkerJSON(2, 700) + `,
			{"id":9,"name":"Scrub worker","state":"idle","errors":0,"consecutiveErrors":0,"queueLength":99,"freeform":[]}],
		"storage-b":[` + resyncWorkerJSON(1, 650) + `],
		"storage-c":[{"id":1,"name":"Block resync worker #1","state":"idle","errors":0,"consecutiveErrors":0,"freeform":["This worker is currently disabled"]}]
	},"error":{}}`
	blockErrors := `{"success":{
		"storage-a":[
			{"blockHash":"` + resyncStatusHashA + `","refcount":1,"errorCount":3,"lastTrySecsAgo":30,"nextTryInSecs":60},
			{"blockHash":"` + resyncStatusHashB + `","refcount":1,"errorCount":1,"lastTrySecsAgo":10,"nextTryInSecs":120}],
		"storage-b":[
			{"blockHash":"` + resyncStatusHashA + `","refcount":1,"errorCount":5,"lastTrySecsAgo":20,"nextTryInSecs":300}],
		"storage-c":[]
	},"error":{}}`
	client := newResyncStatusAdmin(t, workers, blockErrors)
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)

	status := &garagev1beta2.GarageClusterStatus{}
	observeBlockResyncStatus(context.Background(), client, status, now, nil)

	if status.ResyncQueueLength == nil || *status.ResyncQueueLength != 1350 {
		t.Fatalf("ResyncQueueLength = %v, want 1350", status.ResyncQueueLength)
	}
	if status.BlockErrors == nil || *status.BlockErrors != 2 {
		t.Fatalf("BlockErrors = %v, want 2 distinct blocks", status.BlockErrors)
	}
	details := status.BlockErrorDetails
	if details == nil || details.Count != 2 || len(details.TopErrors) != 2 {
		t.Fatalf("unexpected BlockErrorDetails: %+v", details)
	}
	if !details.LastErrorAt.Time.Equal(now.Add(-10 * time.Second)) {
		t.Fatalf("LastErrorAt = %v, want most recent attempt", details.LastErrorAt)
	}
	top := details.TopErrors[0]
	if top.BlockHash != resyncStatusHashA || top.ErrorCount != 5 ||
		!top.LastAttempt.Time.Equal(now.Add(-20*time.Second)) || !top.NextRetry.Time.Equal(now.Add(300*time.Second)) {
		t.Fatalf("worst block should be the storage-b record for hash A, got %+v", top)
	}
	if details.TopErrors[1].BlockHash != resyncStatusHashB || details.TopErrors[1].ErrorCount != 1 {
		t.Fatalf("unexpected second entry: %+v", details.TopErrors[1])
	}

	// A second pass a second later, with Garage's relative times advanced by
	// one second, must not rewrite status.
	before := status.DeepCopy()
	later := strings.NewReplacer(`"lastTrySecsAgo":30`, `"lastTrySecsAgo":31`,
		`"lastTrySecsAgo":20`, `"lastTrySecsAgo":21`, `"lastTrySecsAgo":10`, `"lastTrySecsAgo":11`,
		`"nextTryInSecs":300`, `"nextTryInSecs":299`).Replace(blockErrors)
	observeBlockResyncStatus(context.Background(), newResyncStatusAdmin(t, workers, later), status, now.Add(time.Second), nil)
	if !equality.Semantic.DeepEqual(before, status) {
		t.Fatalf("steady block errors rewrote status:\nbefore %+v\nafter  %+v", before.BlockErrorDetails, status.BlockErrorDetails)
	}
}

func TestApplyBlockErrorStatusLastErrorAtUsesEveryRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	status := &garagev1beta2.GarageClusterStatus{}
	// The per-hash winner (errorCount 5) tried 20s ago, but node a retried the
	// same block 5s ago.
	applyBlockErrorStatus(status, &garage.ListBlockErrorsResponse{Success: map[string][]garage.BlockError{
		"storage-a": {{BlockHash: resyncStatusHashA, ErrorCount: 3, LastTrySecsAgo: 5}},
		"storage-b": {{BlockHash: resyncStatusHashA, ErrorCount: 5, LastTrySecsAgo: 20}},
	}}, now)

	if got := status.BlockErrorDetails.LastErrorAt.Time; !got.Equal(now.Add(-5 * time.Second)) {
		t.Fatalf("LastErrorAt = %v, want %v", got, now.Add(-5*time.Second))
	}
	if top := status.BlockErrorDetails.TopErrors[0]; top.ErrorCount != 5 {
		t.Fatalf("TopErrors[0] = %+v, want the errorCount=5 record", top)
	}
}

func TestApplyBlockErrorStatusKeepsOverdueNextRetry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	overdue := &garage.ListBlockErrorsResponse{Success: map[string][]garage.BlockError{
		"storage-a": {{BlockHash: resyncStatusHashA, ErrorCount: 1, NextTryInSecs: 0}},
	}}
	status := &garagev1beta2.GarageClusterStatus{}
	applyBlockErrorStatus(status, overdue, now)
	first := status.BlockErrorDetails.TopErrors[0].NextRetry.DeepCopy()

	applyBlockErrorStatus(status, overdue, now.Add(time.Minute))
	if got := status.BlockErrorDetails.TopErrors[0].NextRetry; !got.Equal(first) {
		t.Fatalf("overdue NextRetry moved from %v to %v", first, got)
	}
}

func TestObserveBlockResyncStatusClearsUnobservedFields(t *testing.T) {
	t.Parallel()
	lastErrorAt := metav1.NewTime(time.Date(2026, time.October, 6, 11, 0, 0, 0, time.UTC))
	previous := garagev1beta2.GarageClusterStatus{
		ResyncQueueLength: ptr.To[int64](42),
		BlockErrors:       ptr.To[int32](1),
		BlockErrorDetails: &garagev1beta2.BlockErrorsStatus{
			Count: 1, LastErrorAt: &lastErrorAt,
			TopErrors: []garagev1beta2.BlockErrorDetail{{BlockHash: resyncStatusHashA, ErrorCount: 2}},
		},
	}
	// storage-b may hold the backlog; a sum over storage-a alone would look
	// drained.
	partialWorkers := `{"success":{"storage-a":[` + resyncWorkerJSON(1, 0) + `]},"error":{"storage-b":"not connected"}}`
	partialErrors := `{"success":{"storage-a":[]},"error":{"storage-b":"not connected"}}`

	for name, client := range map[string]*garage.Client{
		"request fails":       newResyncStatusAdmin(t, "", ""),
		"one node unanswered": newResyncStatusAdmin(t, partialWorkers, partialErrors),
	} {
		status := previous.DeepCopy()
		observeBlockResyncStatus(context.Background(), client, status, time.Now(), nil)
		if status.ResyncQueueLength != nil || status.BlockErrors != nil || status.BlockErrorDetails != nil {
			t.Fatalf("%s: unobserved fields were not cleared: %+v", name, status)
		}
	}
}

func TestObserveBlockResyncStatusClearsResolvedErrors(t *testing.T) {
	t.Parallel()
	status := &garagev1beta2.GarageClusterStatus{
		ResyncQueueLength: ptr.To[int64](42),
		BlockErrors:       ptr.To[int32](1),
		BlockErrorDetails: &garagev1beta2.BlockErrorsStatus{Count: 1},
	}
	client := newResyncStatusAdmin(t,
		`{"success":{"storage-a":[`+resyncWorkerJSON(1, 0)+`]},"error":{}}`,
		`{"success":{"storage-a":[]},"error":{}}`)

	observeBlockResyncStatus(context.Background(), client, status, time.Now(), nil)

	if status.ResyncQueueLength == nil || *status.ResyncQueueLength != 0 ||
		status.BlockErrors == nil || *status.BlockErrors != 0 || status.BlockErrorDetails != nil {
		t.Fatalf("drained cluster must report observed zeros: %+v", status)
	}
}

func TestApplyBlockErrorStatusBoundsTopErrors(t *testing.T) {
	t.Parallel()
	nodeErrors := make([]garage.BlockError, 0, maximumReportedBlockErrors+8)
	for i := range maximumReportedBlockErrors + 8 {
		nodeErrors = append(nodeErrors, garage.BlockError{BlockHash: fmt.Sprintf("%064x", i), ErrorCount: uint64(i)})
	}
	status := &garagev1beta2.GarageClusterStatus{}
	applyBlockErrorStatus(status, &garage.ListBlockErrorsResponse{
		Success: map[string][]garage.BlockError{"storage-a": nodeErrors},
	}, time.Now())

	if *status.BlockErrors != maximumReportedBlockErrors+8 || len(status.BlockErrorDetails.TopErrors) != maximumReportedBlockErrors {
		t.Fatalf("count=%d topErrors=%d", *status.BlockErrors, len(status.BlockErrorDetails.TopErrors))
	}
	if status.BlockErrorDetails.TopErrors[0].ErrorCount != maximumReportedBlockErrors+7 {
		t.Fatalf("top errors not ordered worst-first: %+v", status.BlockErrorDetails.TopErrors[0])
	}
}

func TestObserveBlockResyncStatusToleratesSilentCapacitylessGateways(t *testing.T) {
	t.Parallel()
	// A federated or edge-gateway cluster often has an unreachable remote
	// gateway. It stores no blocks, so its silence must not blank the fields.
	workers := `{"success":{"storage-a":[` + resyncWorkerJSON(1, 7) + `]},"error":{"gateway-x":"not connected"}}`
	blockErrors := `{"success":{"storage-a":[]},"error":{"gateway-x":"not connected"}}`
	ignorable := capacitylessGatewayNodeIDs(&garage.ClusterStatus{Nodes: []garage.NodeInfo{
		{ID: "storage-a", IsUp: true, Role: &garage.NodeAssignedRole{Zone: "z", Capacity: ptr.To[uint64](1 << 30)}},
		{ID: "gateway-x", IsUp: false, Role: &garage.NodeAssignedRole{Zone: "z"}},
	}})

	status := &garagev1beta2.GarageClusterStatus{}
	observeBlockResyncStatus(context.Background(), newResyncStatusAdmin(t, workers, blockErrors), status, time.Now(), ignorable)
	if status.ResyncQueueLength == nil || *status.ResyncQueueLength != 7 {
		t.Fatalf("ResyncQueueLength = %v, want 7 despite the silent gateway", status.ResyncQueueLength)
	}
	if status.BlockErrors == nil || *status.BlockErrors != 0 {
		t.Fatalf("BlockErrors = %v, want observed 0 despite the silent gateway", status.BlockErrors)
	}

	// A silent storage node still makes the observation partial, even when
	// some gateway is ignorable.
	storageSilent := `{"success":{"gateway-x":[]},"error":{"storage-a":"not connected"}}`
	status = &garagev1beta2.GarageClusterStatus{}
	observeBlockResyncStatus(context.Background(), newResyncStatusAdmin(t, storageSilent, storageSilent), status, time.Now(), ignorable)
	if status.ResyncQueueLength != nil || status.BlockErrors != nil {
		t.Fatalf("silent storage node must leave fields unobserved, got queue=%v errors=%v", status.ResyncQueueLength, status.BlockErrors)
	}
}

func TestCapacitylessGatewayNodeIDs(t *testing.T) {
	t.Parallel()
	if got := capacitylessGatewayNodeIDs(nil); got != nil {
		t.Fatalf("nil cluster status must ignore nothing, got %v", got)
	}
	got := capacitylessGatewayNodeIDs(&garage.ClusterStatus{Nodes: []garage.NodeInfo{
		{ID: "storage", Role: &garage.NodeAssignedRole{Capacity: ptr.To[uint64](1)}},
		{ID: "gateway", Role: &garage.NodeAssignedRole{}},
		{ID: "zero-capacity", Role: &garage.NodeAssignedRole{Capacity: ptr.To[uint64](0)}},
		// Draining: part of an older layout version and may still be the
		// source of a block transfer.
		{ID: "draining-gateway", Draining: true, Role: &garage.NodeAssignedRole{}},
		// No current role: removed or never assigned; not provably blockless.
		{ID: "roleless"},
	}})
	want := map[string]struct{}{"gateway": {}, "zero-capacity": {}}
	if !equality.Semantic.DeepEqual(got, want) {
		t.Fatalf("capacitylessGatewayNodeIDs = %v, want %v", got, want)
	}
}
