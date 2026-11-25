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
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
)

// fakeBucketIDs returns n sorted, distinct 64-hex bucket IDs.
func fakeBucketIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	sort.Strings(ids)
	return ids
}

// garageListCap is the hard cap Garage applies to ListBuckets/ListKeys
// (src/api/admin/bucket.rs, key.rs).
const garageListCap = 10000

// pagedListServer mimics Garage's List* handlers. With paged=true it honours
// limit and an inclusive offset like v2.5+; otherwise it ignores both and
// returns at most garageListCap entries like v2.0-v2.4.
func pagedListServer(t *testing.T, ids []string, paged bool, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		start, limit := 0, garageListCap
		if paged {
			if l := r.URL.Query().Get("limit"); l != "" {
				limit, _ = strconv.Atoi(l)
			}
			if off := r.URL.Query().Get("offset"); off != "" {
				start = sort.SearchStrings(ids, off)
			}
		}
		end := min(start+limit, len(ids))
		out := make([]map[string]any, 0, end-start)
		for _, id := range ids[start:end] {
			out = append(out, map[string]any{"id": id, "name": id, "globalAliases": []string{}, "localAliases": []any{}})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func TestListBucketsPagesPastGarageCap(t *testing.T) {
	ids := fakeBucketIDs(2*adminListPageSize + 17)
	calls := 0
	srv := pagedListServer(t, ids, true, &calls)
	defer srv.Close()

	got, err := NewClient(srv.URL, "t").ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("expected %d buckets, got %d", len(ids), len(got))
	}
	for i := range ids {
		if got[i].ID != ids[i] {
			t.Fatalf("bucket %d: expected %s, got %s", i, ids[i], got[i].ID)
		}
	}
	if calls != 3 {
		t.Fatalf("expected 3 pages, got %d calls", calls)
	}
}

func TestListBucketsExactPageBoundary(t *testing.T) {
	ids := fakeBucketIDs(adminListPageSize)
	calls := 0
	srv := pagedListServer(t, ids, true, &calls)
	defer srv.Close()

	got, err := NewClient(srv.URL, "t").ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("expected %d buckets, got %d", len(ids), len(got))
	}
}

func TestListBucketsOlderGarageIgnoresPaging(t *testing.T) {
	for _, n := range []int{3, adminListPageSize, adminListPageSize + 5} {
		ids := fakeBucketIDs(n)
		calls := 0
		srv := pagedListServer(t, ids, false, &calls)
		got, err := NewClient(srv.URL, "t").ListBuckets(context.Background())
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != n {
			t.Fatalf("n=%d: expected %d buckets, got %d", n, n, len(got))
		}
		if calls > 2 {
			t.Fatalf("n=%d: an older Garage must not be polled repeatedly, got %d calls", n, calls)
		}
	}
}

func TestListKeysPages(t *testing.T) {
	ids := fakeBucketIDs(adminListPageSize + 1)
	calls := 0
	srv := pagedListServer(t, ids, true, &calls)
	defer srv.Close()

	got, err := NewClient(srv.URL, "t").ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("expected %d keys, got %d", len(ids), len(got))
	}
}
