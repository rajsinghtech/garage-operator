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
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ptrInt32(v int32) *int32 { return &v }

func newSampleConfig() *LifecycleConfiguration {
	prefix := "logs/"
	return &LifecycleConfiguration{
		Rules: []LifecycleXMLRule{
			{
				ID:     "expire-logs",
				Status: "Enabled",
				Filter: &LifecycleXMLFilter{Prefix: &prefix},
				Expiration: &LifecycleXMLExpiration{
					Days: ptrInt32(7),
				},
				AbortIncompleteMultipartUpload: &LifecycleXMLAbort{
					DaysAfterInitiation: 3,
				},
			},
		},
	}
}

func TestS3Lifecycle_RoundTrip(t *testing.T) {
	type captured struct {
		method string
		path   string
		query  string
		body   string
		auth   string
	}
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = captured{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			body:   string(body),
			auth:   r.Header.Get("Authorization"),
		}
		switch r.Method {
		case http.MethodPut, http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/xml")
			cfg := newSampleConfig()
			cfg.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
			out, _ := xml.Marshal(cfg)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(xml.Header))
			_, _ = w.Write(out)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	c := NewS3LifecycleClient(srv.URL, "garage", "AKEY", "SECRET")

	if err := c.PutLifecycle(context.Background(), "logs", newSampleConfig()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got.method != http.MethodPut || got.path != "/logs" || got.query != "lifecycle" {
		t.Fatalf("unexpected put request: %+v", got)
	}
	if !strings.Contains(got.body, "<ID>expire-logs</ID>") {
		t.Fatalf("body missing rule id: %s", got.body)
	}
	if !strings.HasPrefix(got.auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(got.auth, "Credential=AKEY/") {
		t.Fatalf("missing or malformed signature: %s", got.auth)
	}

	cfg, err := c.GetLifecycle(context.Background(), "logs")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg == nil || len(cfg.Rules) != 1 || cfg.Rules[0].ID != "expire-logs" {
		t.Fatalf("decoded wrong: %+v", cfg)
	}
	if got.method != http.MethodGet || got.query != "lifecycle" {
		t.Fatalf("unexpected get request: %+v", got)
	}

	if err := c.DeleteLifecycle(context.Background(), "logs"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got.method != http.MethodDelete {
		t.Fatalf("unexpected delete request: %+v", got)
	}
}

func TestS3Lifecycle_GetReturnsNilOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<Error><Code>NoSuchLifecycleConfiguration</Code></Error>`)
	}))
	defer srv.Close()

	c := NewS3LifecycleClient(srv.URL, "garage", "AKEY", "SECRET")
	cfg, err := c.GetLifecycle(context.Background(), "logs")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil cfg on 404, got %+v", cfg)
	}
}

func TestS3Lifecycle_PutSurfacesNon2xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Error><Code>MalformedXML</Code></Error>`)
	}))
	defer srv.Close()

	c := NewS3LifecycleClient(srv.URL, "garage", "AKEY", "SECRET")
	err := c.PutLifecycle(context.Background(), "logs", newSampleConfig())
	if err == nil {
		t.Fatal("expected error from 400")
	}
	s3err, ok := err.(*S3Error)
	if !ok || s3err.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected S3Error 400, got %v", err)
	}
}

func TestSigV4_DeterministicWithFixedClock(t *testing.T) {
	fixed := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	cli := NewS3LifecycleClient("http://x", "garage", "AKEY", "SECRET")
	cli.now = func() time.Time { return fixed }

	r1, err := cli.newRequest(context.Background(), http.MethodPut, "b", "lifecycle", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := cli.newRequest(context.Background(), http.MethodPut, "b", "lifecycle", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	a1 := r1.Header.Get("Authorization")
	a2 := r2.Header.Get("Authorization")
	if a1 != a2 {
		t.Fatalf("identical inputs should produce identical signatures:\n  %s\n  %s", a1, a2)
	}
	if !strings.Contains(a1, "Credential=AKEY/20260428/garage/s3/aws4_request") {
		t.Fatalf("credential scope wrong: %s", a1)
	}

	// Different time must produce a different signature.
	cli.now = func() time.Time { return fixed.Add(24 * time.Hour) }
	r3, err := cli.newRequest(context.Background(), http.MethodPut, "b", "lifecycle", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if r3.Header.Get("Authorization") == a1 {
		t.Fatal("signature should change when time changes")
	}
}
