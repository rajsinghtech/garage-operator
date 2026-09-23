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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestGetOrCreateBucket_SpecStatusDisagreementFailsClosed(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		t.Errorf("unexpected admin API request %s %s", req.Method, req.URL.String())
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "disagreeing", Namespace: testNamespace},
		Spec:       garagev1beta1.GarageBucketSpec{BucketID: "spec-id"},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: "status-id"},
	}
	_, err := (&GarageBucketReconciler{}).getOrCreateBucket(
		t.Context(), bucket, garage.NewClient(srv.URL, "token"), "disagreeing",
	)
	if err == nil || !strings.Contains(err.Error(), "disagrees with recorded status.bucketId") {
		t.Fatalf("err = %v, want spec/status disagreement failure", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("admin API requests = %d, want 0", requests.Load())
	}
}

func TestGetOrCreateBucket_TrackedIdentityWithoutSpecIDDoesNotChurn(t *testing.T) {
	const trackedID = "0123456789abcdef0123456789abcdef"
	var lookups, creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("id") == trackedID:
			lookups.Add(1)
			_, _ = w.Write([]byte(`{"id":"0123456789abcdef0123456789abcdef","globalAliases":[],"keys":[]}`))
		case req.URL.Path == "/v2/CreateBucket":
			creates.Add(1)
			t.Errorf("CreateBucket was called while the tracked identity resolved")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "tracked", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: trackedID},
	}
	got, err := (&GarageBucketReconciler{}).getOrCreateBucket(
		t.Context(), bucket, garage.NewClient(srv.URL, "token"), "tracked",
	)
	if err != nil || got.ID != trackedID {
		t.Fatalf("got=%+v err=%v, want the tracked bucket", got, err)
	}
	if bucket.Status.BucketID != trackedID {
		t.Fatalf("status.bucketId = %q, want %q", bucket.Status.BucketID, trackedID)
	}
	if lookups.Load() != 1 || creates.Load() != 0 {
		t.Fatalf("lookups=%d creates=%d, want exactly one lookup and no create", lookups.Load(), creates.Load())
	}
}

func TestGetOrCreateBucket_SpecBucketIDAdoptsExactRemoteWithoutCreate(t *testing.T) {
	const bucketID = "0123456789abcdef0123456789abcdef"
	var lookups, creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("id") == bucketID:
			lookups.Add(1)
			_, _ = w.Write([]byte(`{"id":"0123456789abcdef0123456789abcdef","globalAliases":["retained-alias"],"keys":[]}`))
		case req.URL.Path == "/v2/CreateBucket":
			creates.Add(1)
			t.Errorf("CreateBucket was called while spec.bucketId pinned the existing bucket")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "cluster"},
			BucketID:   bucketID,
		},
	}
	reconciler := &GarageBucketReconciler{}
	garageClient := garage.NewClient(srv.URL, "token")

	for reconcile := 0; reconcile < 2; reconcile++ {
		got, err := reconciler.getOrCreateBucket(t.Context(), bucket, garageClient, "adopted")
		if err != nil || got.ID != bucketID {
			t.Fatalf("reconcile %d: got=%+v err=%v, want exact bucket %q", reconcile+1, got, err, bucketID)
		}
		if bucket.Status.BucketID != bucketID {
			t.Fatalf("reconcile %d: status.bucketId = %q, want %q", reconcile+1, bucket.Status.BucketID, bucketID)
		}
	}
	if lookups.Load() != 2 || creates.Load() != 0 {
		t.Fatalf("lookups=%d creates=%d, want two exact-ID lookups and no create", lookups.Load(), creates.Load())
	}
}

func TestGetOrCreateBucket_ReleasesStaleClaimAndFailsClosedOnUntrackedAlias(t *testing.T) {
	const (
		staleID    = "0123456789abcdef0123456789abcdef"
		aliasName  = "stale-claim"
		aliasOwner = "other-bucket"
	)
	var creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("id") == staleID:
			w.WriteHeader(http.StatusNotFound)
		case req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("globalAlias") == aliasName:
			_, _ = fmt.Fprintf(w, `{"id":%q,"globalAliases":[%q],"keys":[]}`, aliasOwner, aliasName)
		case req.URL.Path == "/v2/CreateBucket":
			creates.Add(1)
			t.Errorf("CreateBucket was called while the alias is owned by an untracked bucket")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: aliasName, Namespace: testNamespace, UID: "stale-uid"},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: staleID},
	}
	_, err := (&GarageBucketReconciler{}).getOrCreateBucket(
		t.Context(), bucket, garage.NewClient(srv.URL, "token"), aliasName,
	)
	if err == nil || !strings.Contains(err.Error(), "untracked Garage bucket") {
		t.Fatalf("err = %v, want untracked alias ownership failure", err)
	}
	if bucket.Status.BucketID != "" {
		t.Fatalf("status.bucketId = %q, want released empty claim", bucket.Status.BucketID)
	}
	if creates.Load() != 0 {
		t.Fatalf("CreateBucket calls = %d, want 0", creates.Load())
	}
}

func TestGetOrCreateBucket_ReleasesStaleClaimAndCreatesReplacement(t *testing.T) {
	const (
		staleID    = "0123456789abcdef0123456789abcdef"
		createdID  = "fedcba9876543210fedcba9876543210"
		bucketName = "stale-claim-replacement"
	)
	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: bucketName, Namespace: testNamespace, UID: "replacement-uid"},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: staleID},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket).Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}

	var staleLookups, aliasLookups, creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("id") == staleID:
			staleLookups.Add(1)
			w.WriteHeader(http.StatusNotFound)
		case req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("globalAlias") == bucketName:
			aliasLookups.Add(1)
			w.WriteHeader(http.StatusNotFound)
		case req.URL.Path == "/v2/CreateBucket":
			creates.Add(1)
			var body garage.CreateBucketRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Errorf("decode CreateBucket: %v", err)
			}
			if !strings.HasPrefix(body.GlobalAlias, "garage-rsv-") {
				t.Errorf("created alias = %q, want the UID-bound reservation alias", body.GlobalAlias)
			}
			_, _ = fmt.Fprintf(w, `{"id":%q,"globalAliases":[],"keys":[]}`, createdID)
		default:
			t.Errorf("unexpected request %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	created, err := reconciler.getOrCreateBucket(t.Context(), bucket, garage.NewClient(srv.URL, "token"), bucketName)
	if err != nil || created.ID != createdID {
		t.Fatalf("created=%+v err=%v, want replacement bucket %q", created, err, createdID)
	}
	if bucket.Status.BucketID != createdID {
		t.Fatalf("status.bucketId = %q, want %q", bucket.Status.BucketID, createdID)
	}
	if staleLookups.Load() != 1 || aliasLookups.Load() != 1 || creates.Load() != 1 {
		t.Fatalf("staleLookups=%d aliasLookups=%d creates=%d, want 1 each",
			staleLookups.Load(), aliasLookups.Load(), creates.Load())
	}
}

func TestEnsureExclusiveBucketClaim(t *testing.T) {
	const claimedID = "0123456789abcdef0123456789abcdef"
	scheme := finalizationIdentityScheme(t)

	buildOther := func(name string, mutate func(*garagev1beta1.GarageBucket)) *garagev1beta1.GarageBucket {
		other := &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "cluster-a"}},
		}
		if mutate != nil {
			mutate(other)
		}
		return other
	}

	tests := []struct {
		name     string
		specID   string
		statusID string
		others   []*garagev1beta1.GarageBucket
		wantErr  string
	}{
		{
			name:   "spec adoption collides with another recorded claim",
			specID: claimedID,
			others: []*garagev1beta1.GarageBucket{buildOther("other", func(b *garagev1beta1.GarageBucket) {
				b.Status.BucketID = claimedID
			})},
			wantErr: "already managed by GarageBucket " + testNamespace + "/other",
		},
		{
			name:   "spec adoption collides with another spec claim",
			specID: claimedID,
			others: []*garagev1beta1.GarageBucket{buildOther("other", func(b *garagev1beta1.GarageBucket) {
				b.Spec.BucketID = claimedID
			})},
			wantErr: "already managed by GarageBucket " + testNamespace + "/other",
		},
		{
			name:     "recorded status collides with another recorded claim",
			statusID: claimedID,
			others: []*garagev1beta1.GarageBucket{buildOther("other", func(b *garagev1beta1.GarageBucket) {
				b.Status.BucketID = claimedID
			})},
			wantErr: "also recorded on GarageBucket " + testNamespace + "/other",
		},
		{
			name:     "recorded status beats a spec-only claimant",
			statusID: claimedID,
			others: []*garagev1beta1.GarageBucket{buildOther("other", func(b *garagev1beta1.GarageBucket) {
				b.Spec.BucketID = claimedID
			})},
		},
		{
			name:   "claims in a different GarageCluster do not collide",
			specID: claimedID,
			others: []*garagev1beta1.GarageBucket{buildOther("foreign", func(b *garagev1beta1.GarageBucket) {
				b.Spec.ClusterRef.Name = "cluster-b"
				b.Spec.BucketID = claimedID
			})},
		},
		{
			name:   "no duplicate claims",
			specID: claimedID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := make([]client.Object, 0, len(test.others))
			for _, other := range test.others {
				objects = append(objects, other)
			}
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Name: "self", Namespace: testNamespace},
				Spec: garagev1beta1.GarageBucketSpec{
					BucketID:   test.specID,
					ClusterRef: garagev1beta1.ClusterReference{Name: "cluster-a"},
				},
				Status: garagev1beta1.GarageBucketStatus{BucketID: test.statusID},
			}
			err := (&GarageBucketReconciler{Client: kubeClient}).ensureExclusiveBucketClaim(t.Context(), bucket)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ensureExclusiveBucketClaim: %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ensureExclusiveBucketClaim error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestGarageBucketFinalizationRefusesLiveDuplicateClaimant(t *testing.T) {
	const victimID = "victim-bucket-id"
	scheme := finalizationIdentityScheme(t)
	claimant := func(mutate func(*garagev1beta1.GarageBucket)) *garagev1beta1.GarageBucket {
		other := &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: "claimant", Namespace: testNamespace},
			Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "cluster-a"}},
		}
		mutate(other)
		return other
	}
	victim := func() *garagev1beta1.GarageBucket {
		return &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: testNamespace},
			Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "cluster-a"}},
			Status:     garagev1beta1.GarageBucketStatus{BucketID: victimID},
		}
	}

	t.Run("live claimant blocks deletion", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claimant(func(b *garagev1beta1.GarageBucket) {
			b.Status.BucketID = victimID
		})).Build()
		server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
		defer server.Close()

		err := (&GarageBucketReconciler{Client: kubeClient, Scheme: scheme}).
			finalize(t.Context(), victim(), garage.NewClient(server.URL, "token"))
		if err == nil || !strings.Contains(err.Error(), "refusing to delete bucket") ||
			!strings.Contains(err.Error(), testNamespace+"/claimant") {
			t.Fatalf("finalize error = %v, want duplicate-claimant refusal", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("DeleteBucket calls = %d, want 0", calls.Load())
		}
	})

	t.Run("terminating claimant is ignored", func(t *testing.T) {
		now := metav1.Now()
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claimant(func(b *garagev1beta1.GarageBucket) {
			b.Status.BucketID = victimID
			b.DeletionTimestamp = &now
			b.Finalizers = []string{garageBucketFinalizer}
		})).Build()
		server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
		defer server.Close()

		if err := (&GarageBucketReconciler{Client: kubeClient, Scheme: scheme}).
			finalize(t.Context(), victim(), garage.NewClient(server.URL, "token")); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("DeleteBucket calls = %d, want 1", calls.Load())
		}
	})

	t.Run("no claimant deletes once", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
		defer server.Close()

		if err := (&GarageBucketReconciler{Client: kubeClient, Scheme: scheme}).
			finalize(t.Context(), victim(), garage.NewClient(server.URL, "token")); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("DeleteBucket calls = %d, want 1", calls.Load())
		}
	})

	t.Run("claimant in a different cluster does not block", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claimant(func(b *garagev1beta1.GarageBucket) {
			b.Spec.ClusterRef.Name = "cluster-b"
			b.Status.BucketID = victimID
		})).Build()
		server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
		defer server.Close()

		if err := (&GarageBucketReconciler{Client: kubeClient, Scheme: scheme}).
			finalize(t.Context(), victim(), garage.NewClient(server.URL, "token")); err != nil {
			t.Fatalf("finalize: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("DeleteBucket calls = %d, want 1", calls.Load())
		}
	})

	t.Run("list failure fails closed", func(t *testing.T) {
		base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claimant(func(b *garagev1beta1.GarageBucket) {
			b.Status.BucketID = victimID
		})).Build()
		wrapped := interceptor.NewClient(base, interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*garagev1beta1.GarageBucketList); ok {
					return fmt.Errorf("injected list failure")
				}
				return c.List(ctx, list, opts...)
			},
		})
		server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
		defer server.Close()

		err := (&GarageBucketReconciler{Client: wrapped, Scheme: scheme}).
			finalize(t.Context(), victim(), garage.NewClient(server.URL, "token"))
		if err == nil || !strings.Contains(err.Error(), "failed to check duplicate bucket claims before deletion") {
			t.Fatalf("finalize error = %v, want fail-closed list error", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("DeleteBucket calls = %d, want 0", calls.Load())
		}
	})
}

func TestGarageBucketFinalizationWithoutClientSkipsClaimGuard(t *testing.T) {
	const victimID = "victim-bucket-id"
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", victimID)
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: victimID},
	}

	if err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token")); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("DeleteBucket calls = %d, want 1", calls.Load())
	}
}
