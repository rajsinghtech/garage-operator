/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package garage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOversizedAdminResponseFailsExplicitly(t *testing.T) {
	big := strings.Repeat("x", maxAdminResponseSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "token").doRequest(t.Context(), http.MethodGet, "/v2/GetClusterStatus", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an explicit size error", err)
	}
}

func TestOversizedErrorResponseKeepsStatus(t *testing.T) {
	big := strings.Repeat("x", maxAdminResponseSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "token").doRequest(t.Context(), http.MethodGet, "/v2/GetKeyInfo", nil)
	if !IsNotFound(err) {
		t.Fatalf("err = %v, want a 404 APIError", err)
	}
}
