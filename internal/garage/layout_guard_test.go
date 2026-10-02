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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// layoutWriteCalls invokes each of the six layout-writing Client methods.
func layoutWriteCalls(c *Client) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		LayoutOpUpdate: func(ctx context.Context) error {
			return c.UpdateClusterLayout(ctx, []NodeRoleChange{{ID: "n", Remove: true}})
		},
		LayoutOpUpdateParams: func(ctx context.Context) error {
			return c.UpdateClusterLayoutWithParams(ctx, UpdateClusterLayoutRequest{})
		},
		LayoutOpApply: func(ctx context.Context) error { return c.ApplyClusterLayout(ctx, 2) },
		LayoutOpApplyStaged: func(ctx context.Context) error {
			return c.ApplyStagedLayoutChanges(ctx)
		},
		LayoutOpRevert: func(ctx context.Context) error { return c.RevertClusterLayout(ctx) },
		LayoutOpSkipDeadNodes: func(ctx context.Context) error {
			_, err := c.ClusterLayoutSkipDeadNodes(ctx, SkipDeadNodesRequest{Version: 1})
			return err
		},
	}
}

func TestLayoutWritesDisabledRefusesAllSixMethodsWithoutARequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	c := NewClient(server.URL, "token")

	var blocked []string
	ctx := WithLayoutWritesDisabled(context.Background(), LayoutWriteGuard{
		Cluster:   "ns/follower",
		Reason:    "layoutManagement.siteRole is Follower",
		OnBlocked: func(operation string) { blocked = append(blocked, operation) },
	})
	if !LayoutWritesDisabled(ctx) {
		t.Fatal("LayoutWritesDisabled must report the marker")
	}

	calls := layoutWriteCalls(c)
	if len(calls) != 6 {
		t.Fatalf("expected the six layout-writing methods, got %d", len(calls))
	}
	for operation, call := range calls {
		err := call(ctx)
		if !errors.Is(err, ErrLayoutWritesDisabled) {
			t.Errorf("%s: want ErrLayoutWritesDisabled, got %v", operation, err)
		}
		if !errors.Is(err, ErrLayoutPending) {
			t.Errorf("%s: a refused follower write must also read as a pending state, got %v", operation, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("a refused layout write must not reach Garage, saw %d request(s)", got)
	}
	if len(blocked) != len(calls) {
		t.Fatalf("OnBlocked must observe every refused operation, got %v", blocked)
	}
}

func TestLayoutWritesAreUnaffectedWithoutTheMarker(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/v2/GetClusterLayout":
			_, _ = w.Write([]byte(`{"version":1,"roles":[],"stagedRoleChanges":[{"id":"n","remove":true}]}`))
		case "/v2/ClusterLayoutSkipDeadNodes":
			_, _ = w.Write([]byte(`{"ackUpdated":[],"syncUpdated":[]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, "token")

	for operation, call := range layoutWriteCalls(c) {
		if err := call(context.Background()); err != nil {
			t.Errorf("%s without the marker must reach Garage: %v", operation, err)
		}
	}
	if requests.Load() == 0 {
		t.Fatal("expected requests to reach the server")
	}
	// A read-only method keeps working under the marker.
	ctx := WithLayoutWritesDisabled(context.Background(), LayoutWriteGuard{Cluster: "ns/follower"})
	before := requests.Load()
	if _, err := c.GetClusterLayout(ctx); err != nil {
		t.Fatalf("reads must not be guarded: %v", err)
	}
	if requests.Load() != before+1 {
		t.Fatal("GetClusterLayout under the marker must reach Garage")
	}
}

// TestLayoutWritingMethodsCallGuardFirst keeps a future edit from reordering or
// dropping the guard in any of the six methods.
func TestLayoutWritingMethodsCallGuardFirst(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "client.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	guarded := map[string]bool{}
	for _, decl := range parsed.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Recv == nil || len(function.Body.List) == 0 {
			continue
		}
		if _, isLayoutWrite := layoutWriteCalls(&Client{})[function.Name.Name]; !isLayoutWrite {
			continue
		}
		first, ok := function.Body.List[0].(*ast.IfStmt)
		if !ok {
			t.Errorf("%s: first statement must be the guardLayoutWrite check", function.Name.Name)
			continue
		}
		init, ok := first.Init.(*ast.AssignStmt)
		if !ok || len(init.Rhs) != 1 {
			t.Errorf("%s: first statement must be `if err := guardLayoutWrite(...)`", function.Name.Name)
			continue
		}
		call, ok := init.Rhs[0].(*ast.CallExpr)
		if ident, isIdent := call.Fun.(*ast.Ident); !ok || !isIdent || ident.Name != "guardLayoutWrite" {
			t.Errorf("%s: first statement must call guardLayoutWrite", function.Name.Name)
			continue
		}
		guarded[function.Name.Name] = true
	}
	for operation := range layoutWriteCalls(&Client{}) {
		if !guarded[operation] {
			t.Errorf("%s does not start with guardLayoutWrite", operation)
		}
	}
}
