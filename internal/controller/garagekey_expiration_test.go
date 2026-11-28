package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Garage reports a key without an expiry as a null/omitted expiration. A
// neverExpires key that already has no expiry must not be rewritten on every
// reconcile.
func TestUpdateKeyIfNeeded_NeverExpiresIsIdempotent(t *testing.T) {
	expiry := "2030-01-02T03:04:05Z"
	cases := []struct {
		name       string
		expiration *string
		wantUpdate bool
	}{
		{name: "no expiry reported", expiration: nil, wantUpdate: false},
		{name: "expiry set in Garage", expiration: &expiry, wantUpdate: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var body garage.UpdateKeyRequestBody
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/v2/UpdateKey" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				calls.Add(1)
				_ = json.NewDecoder(req.Body).Decode(&body)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()

			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k"},
				Spec:       garagev1beta1.GarageKeySpec{NeverExpires: true},
			}
			existing := &garage.Key{AccessKeyID: "GKkey", Name: "k", Expiration: tc.expiration}
			r := &GarageKeyReconciler{}
			if err := r.updateKeyIfNeeded(context.Background(), key, garage.NewClient(srv.URL, "tok"), existing); err != nil {
				t.Fatal(err)
			}
			if got := calls.Load() > 0; got != tc.wantUpdate {
				t.Fatalf("UpdateKey called=%v, want %v", got, tc.wantUpdate)
			}
			if tc.wantUpdate && !body.NeverExpires {
				t.Fatalf("update body=%+v, want neverExpires=true", body)
			}
		})
	}
}

// An expiry set outside the GarageKey spec (CLI, Admin API, or an imported
// key) still makes Garage reject the key; status must not report Ready.
func TestUpdateStatusFromGarage_ReportsGarageObservedExpiry(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-key", Namespace: testNamespace, Generation: 1},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: "GKexpired"},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(key).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/GetKeyInfo" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"accessKeyId":"GKexpired","name":"expired-key","expiration":"` + past + `","expired":true,"permissions":{},"buckets":[]}`))
	}))
	defer srv.Close()

	r := &GarageKeyReconciler{Client: fc, Scheme: s}
	if _, err := r.updateStatusFromGarage(context.Background(), key, garage.NewClient(srv.URL, "tok")); err != nil {
		t.Fatal(err)
	}
	fresh := &garagev1beta1.GarageKey{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: key.Name, Namespace: key.Namespace}, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.Phase != PhaseExpired {
		t.Fatalf("status.phase=%q, want %q when Garage reports the key expired", fresh.Status.Phase, PhaseExpired)
	}
	if fresh.Status.ExpiresAt == nil {
		t.Fatal("status.expiresAt is empty, want the Garage expiration")
	}
}
