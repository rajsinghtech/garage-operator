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
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testAccessKeyID    = "GK-TEST-ID"
	testCachedKeyID    = "CACHED-ID"
	testCachedSecretAK = "CACHED-SECRET"
)

func newFakeKubeClient(initial ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(initial...).
		Build()
}

func clusterRef() ClusterRef {
	return ClusterRef{
		Name:       "demo",
		Namespace:  "default",
		UID:        types.UID("00000000-0000-0000-0000-000000000001"),
		APIVersion: "garage.rajsingh.info/v1alpha1",
		Kind:       "GarageCluster",
	}
}

// fakeAdmin returns a *Client backed by an httptest.Server that handles
// /v2/CreateKey by echoing the requested name and returning a synthetic key.
func fakeAdmin(t *testing.T, calls *int) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/CreateKey" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if calls != nil {
			*calls++
		}
		var req CreateKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Key{
			AccessKeyID:     testAccessKeyID,
			Name:            req.Name,
			SecretAccessKey: "secret-xyz",
		})
	}))
	c := NewClient(srv.URL, "00000000000000000000000000000000.token")
	return c, srv.Close
}

func TestInternalKeyManager_CreatesOnFirstUse(t *testing.T) {
	calls := 0
	admin, stop := fakeAdmin(t, &calls)
	defer stop()

	kc := newFakeKubeClient()
	mgr := NewInternalKeyManager(kc, "garage-operator-system")
	cluster := clusterRef()

	creds, err := mgr.EnsureKey(context.Background(), cluster, admin)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if creds.AccessKeyID != testAccessKeyID || creds.SecretAccessKey != "secret-xyz" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
	if calls != 1 {
		t.Fatalf("expected 1 CreateKey call, got %d", calls)
	}

	var sec corev1.Secret
	if err := kc.Get(context.Background(), types.NamespacedName{
		Namespace: "garage-operator-system",
		Name:      mgr.SecretName(cluster),
	}, &sec); err != nil {
		t.Fatalf("Secret should exist: %v", err)
	}
	if string(sec.Data[internalKeyAccessKeyIDField]) != testAccessKeyID {
		t.Fatalf("unexpected secret data: %s", sec.Data[internalKeyAccessKeyIDField])
	}
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].UID != cluster.UID {
		t.Fatalf("missing owner ref: %+v", sec.OwnerReferences)
	}
	if sec.Labels[internalKeyOwnerLabel] != internalKeyOwnerLabelValue {
		t.Fatalf("missing owner label")
	}
}

func TestInternalKeyManager_ReusesExistingSecret(t *testing.T) {
	calls := 0
	admin, stop := fakeAdmin(t, &calls)
	defer stop()

	cluster := clusterRef()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "garage-operator-system",
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			internalKeyAccessKeyIDField:     []byte(testCachedKeyID),
			internalKeySecretAccessKeyField: []byte(testCachedSecretAK),
		},
	}
	mgr := NewInternalKeyManager(newFakeKubeClient(existing), "garage-operator-system")

	creds, err := mgr.EnsureKey(context.Background(), cluster, admin)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if creds.AccessKeyID != testCachedKeyID || creds.SecretAccessKey != testCachedSecretAK {
		t.Fatalf("unexpected creds: %+v", creds)
	}
	if calls != 0 {
		t.Fatalf("expected zero CreateKey calls when Secret cached, got %d", calls)
	}
}

func TestInternalKeyManager_RecreatesMalformedSecret(t *testing.T) {
	calls := 0
	admin, stop := fakeAdmin(t, &calls)
	defer stop()

	cluster := clusterRef()
	malformed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "garage-operator-system",
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			// missing secretAccessKey
			internalKeyAccessKeyIDField: []byte(testCachedKeyID),
		},
	}
	mgr := NewInternalKeyManager(newFakeKubeClient(malformed), "garage-operator-system")

	creds, err := mgr.EnsureKey(context.Background(), cluster, admin)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if creds.AccessKeyID != testAccessKeyID {
		t.Fatalf("expected fresh creds, got %+v", creds)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 CreateKey call, got %d", calls)
	}
}

func TestInternalKeyManager_DeleteSecret(t *testing.T) {
	cluster := clusterRef()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "garage-operator-system",
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			internalKeyAccessKeyIDField:     []byte(testCachedKeyID),
			internalKeySecretAccessKeyField: []byte(testCachedSecretAK),
		},
	}
	kc := newFakeKubeClient(existing)
	mgr := NewInternalKeyManager(kc, "garage-operator-system")

	if err := mgr.DeleteSecret(context.Background(), cluster); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	var sec corev1.Secret
	err := kc.Get(context.Background(), types.NamespacedName{
		Namespace: "garage-operator-system",
		Name:      mgr.SecretName(cluster),
	}, &sec)
	if err == nil {
		t.Fatal("expected Secret to be gone")
	}

	// idempotent on a missing secret
	if err := mgr.DeleteSecret(context.Background(), cluster); err != nil {
		t.Fatalf("DeleteSecret on missing secret should be nil, got: %v", err)
	}
}

func TestInternalKeyManager_DeleteSecret_NoOpWithoutNamespace(t *testing.T) {
	mgr := NewInternalKeyManager(newFakeKubeClient(), "")
	if err := mgr.DeleteSecret(context.Background(), clusterRef()); err != nil {
		t.Fatalf("DeleteSecret without namespace should be nil, got: %v", err)
	}
}

func TestInternalKeyManager_RequiresOperatorNamespace(t *testing.T) {
	admin, stop := fakeAdmin(t, nil)
	defer stop()

	mgr := NewInternalKeyManager(newFakeKubeClient(), "")
	if _, err := mgr.EnsureKey(context.Background(), clusterRef(), admin); err == nil {
		t.Fatal("expected error for empty operator namespace")
	}
}

// fakeDeleteKeyAdmin returns a *Client whose /v2/DeleteKey handler is
// programmable via the status code argument. Captures the deleted access key
// id so tests can assert on it.
func fakeDeleteKeyAdmin(t *testing.T, status int, captured *string) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/DeleteKey" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if captured != nil {
			*captured = r.URL.Query().Get("id")
		}
		if status >= 400 {
			http.Error(w, "synthetic", status)
			return
		}
		w.WriteHeader(status)
	}))
	c := NewClient(srv.URL, "00000000000000000000000000000000.token")
	return c, srv.Close
}

func internalKeySecret(cluster ClusterRef, withFields bool) *corev1.Secret {
	data := map[string][]byte{
		internalKeyAccessKeyIDField: []byte(testCachedKeyID),
	}
	if withFields {
		data[internalKeySecretAccessKeyField] = []byte(testCachedSecretAK)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "garage-operator-system",
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: data,
	}
}

func TestInternalKeyManager_DeleteKey(t *testing.T) {
	const ns = "garage-operator-system"

	type fakeAdminFnFactory func(t *testing.T) (fn func() *Client, captured *string, builderCalls *int, stop func())

	adminWithStatus := func(status int) fakeAdminFnFactory {
		return func(t *testing.T) (func() *Client, *string, *int, func()) {
			captured := new(string)
			c, stop := fakeDeleteKeyAdmin(t, status, captured)
			calls := 0
			return func() *Client { calls++; return c }, captured, &calls, stop
		}
	}
	nilAdmin := func(t *testing.T) (func() *Client, *string, *int, func()) {
		captured := new(string)
		calls := 0
		return func() *Client { calls++; return nil }, captured, &calls, func() {}
	}

	cases := []struct {
		name             string
		seedSecret       bool
		secretWithSecret bool
		adminFactory     fakeAdminFnFactory
		wantBuilderCalls int
		wantCapturedID   string
		wantSecretGone   bool
	}{
		{
			name:             "no secret skips admin entirely",
			seedSecret:       false,
			adminFactory:     adminWithStatus(http.StatusOK),
			wantBuilderCalls: 0,
		},
		{
			name:             "happy path deletes key and secret",
			seedSecret:       true,
			secretWithSecret: true,
			adminFactory:     adminWithStatus(http.StatusOK),
			wantBuilderCalls: 1,
			wantCapturedID:   testCachedKeyID,
			wantSecretGone:   true,
		},
		{
			name:             "admin 404 still deletes secret",
			seedSecret:       true,
			secretWithSecret: true,
			adminFactory:     adminWithStatus(http.StatusNotFound),
			wantBuilderCalls: 1,
			wantCapturedID:   testCachedKeyID,
			wantSecretGone:   true,
		},
		{
			name:             "admin 500 still deletes secret",
			seedSecret:       true,
			secretWithSecret: true,
			adminFactory:     adminWithStatus(http.StatusInternalServerError),
			wantBuilderCalls: 1,
			wantCapturedID:   testCachedKeyID,
			wantSecretGone:   true,
		},
		{
			name:             "nil client skips admin call",
			seedSecret:       true,
			secretWithSecret: true,
			adminFactory:     nilAdmin,
			wantBuilderCalls: 1,
			wantSecretGone:   true,
		},
		{
			name:             "malformed secret skips admin builder",
			seedSecret:       true,
			secretWithSecret: false,
			adminFactory:     adminWithStatus(http.StatusOK),
			wantBuilderCalls: 0,
			wantSecretGone:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := clusterRef()
			var seeds []client.Object
			if tc.seedSecret {
				seeds = append(seeds, internalKeySecret(cluster, tc.secretWithSecret))
			}
			kc := newFakeKubeClient(seeds...)
			mgr := NewInternalKeyManager(kc, ns)

			fn, captured, calls, stop := tc.adminFactory(t)
			defer stop()

			if err := mgr.DeleteKey(context.Background(), cluster, fn); err != nil {
				t.Fatalf("DeleteKey: %v", err)
			}
			if *calls != tc.wantBuilderCalls {
				t.Fatalf("admin builder calls: want %d, got %d", tc.wantBuilderCalls, *calls)
			}
			if *captured != tc.wantCapturedID {
				t.Fatalf("captured id: want %q, got %q", tc.wantCapturedID, *captured)
			}
			if !tc.seedSecret {
				return
			}
			err := kc.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: mgr.SecretName(cluster)}, &corev1.Secret{})
			if tc.wantSecretGone && err == nil {
				t.Fatal("expected Secret to be deleted")
			}
			if !tc.wantSecretGone && err != nil {
				t.Fatalf("expected Secret to remain: %v", err)
			}
		})
	}
}
