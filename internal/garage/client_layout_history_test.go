/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package garage

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// layoutHistoryJSON mirrors GetClusterLayoutHistoryResponse (src/api/admin/api.rs,
// v2.0 through v2.6): updateTrackers is present only while more than one layout
// version is live (src/api/admin/layout.rs).
const layoutHistoryJSON = `{
  "currentVersion": 5,
  "minAck": 4,
  "versions": [
    {"version": 5, "status": "Current", "storageNodes": 3, "gatewayNodes": 1},
    {"version": 4, "status": "Draining", "storageNodes": 4, "gatewayNodes": 1},
    {"version": 3, "status": "Historical", "storageNodes": 4, "gatewayNodes": 0}
  ],
  "updateTrackers": {
    "aaaa": {"ack": 5, "sync": 5, "syncAck": 4},
    "bbbb": {"ack": 5, "sync": %s, "syncAck": 4}
  }
}`

func layoutHistoryServer(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/GetClusterLayoutHistory" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "token")
}

func TestLayoutHistoryDecodeAndDrainingVersions(t *testing.T) {
	c := layoutHistoryServer(t, sprintfHistory("5"))
	h, err := c.GetClusterLayoutHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if h.CurrentVersion != 5 || h.MinAck != 4 || len(h.Versions) != 3 || len(h.UpdateTrackers) != 2 {
		t.Fatalf("decoded history = %+v", h)
	}
	if got := h.UpdateTrackers["aaaa"]; got != (NodeUpdateTrackers{Ack: 5, Sync: 5, SyncAck: 4}) {
		t.Fatalf("trackers[aaaa] = %+v", got)
	}
	draining := h.GetDrainingVersions()
	if len(draining) != 1 || draining[0].Version != 4 || draining[0].StorageNodes != 4 {
		t.Fatalf("draining = %+v", draining)
	}
}

func TestDataMigrationSettled(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"every tracked node synced to current", sprintfHistory("5"), true},
		{"one node still behind", sprintfHistory("4"), false},
		{"no trackers proves nothing", `{"currentVersion":5,"minAck":5,"versions":[{"version":5,"status":"Current","storageNodes":3,"gatewayNodes":0}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h LayoutHistoryResponse
			if err := json.Unmarshal([]byte(tc.body), &h); err != nil {
				t.Fatal(err)
			}
			if got := h.DataMigrationSettled(); got != tc.want {
				t.Fatalf("DataMigrationSettled = %v, want %v", got, tc.want)
			}
		})
	}
}

func sprintfHistory(bSync string) string {
	return fmt.Sprintf(layoutHistoryJSON, bSync)
}
