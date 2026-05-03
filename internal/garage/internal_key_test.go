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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testAccessKeyID    = "GK-TEST-ID"
	testCachedKeyID    = "CACHED-ID"
	testCachedSecretAK = "CACHED-SECRET"

	pathCreateKey = "/v2/CreateKey"
	pathDeleteKey = "/v2/DeleteKey"
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
		APIVersion: "garage.rajsingh.info/v1beta1",
		Kind:       "GarageCluster",
	}
}

// fakeAdmin returns a *Client backed by an httptest.Server that handles
// /v2/CreateKey by echoing the requested name and returning a synthetic key.
// /v2/DeleteKey is also accepted; deletedID, when non-nil, captures the id
// that DeleteKey was invoked with. Optional deleteStatus overrides the
// DeleteKey response code (defaults to 200).
func fakeAdmin(t *testing.T, calls *int, deletedID *string, deleteStatus ...int) (*Client, func()) {
	t.Helper()
	status := http.StatusOK
	if len(deleteStatus) > 0 {
		status = deleteStatus[0]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pathCreateKey:
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
		case pathDeleteKey:
			if deletedID != nil {
				*deletedID = r.URL.Query().Get("id")
			}
			if status >= 400 {
				http.Error(w, "synthetic", status)
				return
			}
			w.WriteHeader(status)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	c := NewClient(srv.URL, "00000000000000000000000000000000.token")
	return c, srv.Close
}

func TestInternalKeyManager_CreatesOnFirstUse(t *testing.T) {
	calls := 0
	admin, stop := fakeAdmin(t, &calls, nil)
	defer stop()

	kc := newFakeKubeClient()
	mgr := NewInternalKeyManager(kc)
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
		Namespace: cluster.Namespace,
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
	admin, stop := fakeAdmin(t, &calls, nil)
	defer stop()

	cluster := clusterRef()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cluster.Namespace,
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			internalKeyAccessKeyIDField:     []byte(testCachedKeyID),
			internalKeySecretAccessKeyField: []byte(testCachedSecretAK),
		},
	}
	mgr := NewInternalKeyManager(newFakeKubeClient(existing))

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
	cases := []struct {
		name           string
		data           map[string][]byte
		wantDeletedID  string
		wantCreateCall int
	}{
		{
			name: "with stale access key id deletes old garage key",
			data: map[string][]byte{
				internalKeyAccessKeyIDField: []byte(testCachedKeyID),
			},
			wantDeletedID:  testCachedKeyID,
			wantCreateCall: 1,
		},
		{
			name: "without access key id skips garage delete",
			data: map[string][]byte{
				internalKeyGarageNameField: []byte("orphan"),
			},
			wantDeletedID:  "",
			wantCreateCall: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			deletedID := ""
			admin, stop := fakeAdmin(t, &calls, &deletedID)
			defer stop()

			cluster := clusterRef()
			malformed := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: cluster.Namespace,
					Name:      (&InternalKeyManager{}).SecretName(cluster),
				},
				Data: tc.data,
			}
			mgr := NewInternalKeyManager(newFakeKubeClient(malformed))

			creds, err := mgr.EnsureKey(context.Background(), cluster, admin)
			if err != nil {
				t.Fatalf("EnsureKey: %v", err)
			}
			if creds.AccessKeyID != testAccessKeyID {
				t.Fatalf("expected fresh creds, got %+v", creds)
			}
			if calls != tc.wantCreateCall {
				t.Fatalf("CreateKey calls: want %d, got %d", tc.wantCreateCall, calls)
			}
			if deletedID != tc.wantDeletedID {
				t.Fatalf("DeleteKey id: want %q, got %q", tc.wantDeletedID, deletedID)
			}
		})
	}
}

func TestInternalKeyManager_MalformedSecretPropagatesStaleKeyDeleteError(t *testing.T) {
	captured := new(string)
	admin, stop := fakeDeleteKeyAdmin(t, http.StatusInternalServerError, captured)
	defer stop()

	cluster := clusterRef()
	malformed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cluster.Namespace,
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			internalKeyAccessKeyIDField: []byte(testCachedKeyID),
		},
	}
	kc := newFakeKubeClient(malformed)
	mgr := NewInternalKeyManager(kc)

	if _, err := mgr.EnsureKey(context.Background(), cluster, admin); err == nil {
		t.Fatal("expected EnsureKey to fail when stale DeleteKey errors")
	}
	if *captured != testCachedKeyID {
		t.Fatalf("DeleteKey id: want %q, got %q", testCachedKeyID, *captured)
	}
	// secret must remain so the next reconcile can retry the cleanup
	if err := kc.Get(context.Background(), types.NamespacedName{Namespace: cluster.Namespace, Name: mgr.SecretName(cluster)}, &corev1.Secret{}); err != nil {
		t.Fatalf("malformed Secret should remain to allow retry: %v", err)
	}
}

func TestInternalKeyManager_DeleteSecret(t *testing.T) {
	cluster := clusterRef()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cluster.Namespace,
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: map[string][]byte{
			internalKeyAccessKeyIDField:     []byte(testCachedKeyID),
			internalKeySecretAccessKeyField: []byte(testCachedSecretAK),
		},
	}
	kc := newFakeKubeClient(existing)
	mgr := NewInternalKeyManager(kc)

	if err := mgr.DeleteSecret(context.Background(), cluster); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	var sec corev1.Secret
	err := kc.Get(context.Background(), types.NamespacedName{
		Namespace: cluster.Namespace,
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

// fakeDeleteKeyAdmin returns a *Client whose /v2/DeleteKey handler is
// programmable via the status code argument. Captures the deleted access key
// id so tests can assert on it.
func fakeDeleteKeyAdmin(t *testing.T, status int, captured *string) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathDeleteKey {
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
			Namespace: cluster.Namespace,
			Name:      (&InternalKeyManager{}).SecretName(cluster),
		},
		Data: data,
	}
}

func TestInternalKeyManager_DeleteKey(t *testing.T) {

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
			mgr := NewInternalKeyManager(kc)

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
			err := kc.Get(context.Background(), types.NamespacedName{Namespace: cluster.Namespace, Name: mgr.SecretName(cluster)}, &corev1.Secret{})
			if tc.wantSecretGone && err == nil {
				t.Fatal("expected Secret to be deleted")
			}
			if !tc.wantSecretGone && err != nil {
				t.Fatalf("expected Secret to remain: %v", err)
			}
		})
	}
}

// raceWinnerInterceptor returns an interceptor.Funcs that, on the first
// Secret Create, plants a winner Secret with winnerCreds and lets the
// original Create return AlreadyExists. Subsequent Creates pass through.
func raceWinnerInterceptor(winnerID, winnerSecret string) interceptor.Funcs {
	planted := false
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if !planted {
				if sec, ok := obj.(*corev1.Secret); ok {
					planted = true
					winner := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: sec.Namespace,
							Name:      sec.Name,
						},
						Data: map[string][]byte{
							internalKeyAccessKeyIDField:     []byte(winnerID),
							internalKeySecretAccessKeyField: []byte(winnerSecret),
						},
					}
					if err := c.Create(ctx, winner); err != nil {
						return err
					}
				}
			}
			return c.Create(ctx, obj, opts...)
		},
	}
}

func raceClient(winnerID, winnerSecret string) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(raceWinnerInterceptor(winnerID, winnerSecret)).
		Build()
}

func TestInternalKeyManager_RaceLoserDeletesOwnKey(t *testing.T) {
	const winnerID, winnerSecret = "WINNER-ID", "WINNER-SECRET"

	calls := 0
	deletedID := ""
	admin, stop := fakeAdmin(t, &calls, &deletedID)
	defer stop()

	kc := raceClient(winnerID, winnerSecret)
	mgr := NewInternalKeyManager(kc)
	cluster := clusterRef()

	creds, err := mgr.EnsureKey(context.Background(), cluster, admin)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if creds.AccessKeyID != winnerID || creds.SecretAccessKey != winnerSecret {
		t.Fatalf("expected winner creds, got %+v", creds)
	}
	if calls != 1 {
		t.Fatalf("expected 1 CreateKey call (loser only), got %d", calls)
	}
	if deletedID != testAccessKeyID {
		t.Fatalf("expected DeleteKey of loser %q, got %q", testAccessKeyID, deletedID)
	}

	var sec corev1.Secret
	if err := kc.Get(context.Background(), types.NamespacedName{
		Namespace: cluster.Namespace,
		Name:      mgr.SecretName(cluster),
	}, &sec); err != nil {
		t.Fatalf("winner Secret should exist: %v", err)
	}
	if string(sec.Data[internalKeyAccessKeyIDField]) != winnerID {
		t.Fatalf("expected stored Secret to be winner's, got %q", sec.Data[internalKeyAccessKeyIDField])
	}
}

func TestInternalKeyManager_RaceLoserSurvivesDeleteKeyError(t *testing.T) {
	const winnerID, winnerSecret = "WINNER-ID", "WINNER-SECRET"

	deletedID := ""
	admin, stop := fakeAdmin(t, nil, &deletedID, http.StatusInternalServerError)
	defer stop()

	kc := raceClient(winnerID, winnerSecret)
	mgr := NewInternalKeyManager(kc)

	creds, err := mgr.EnsureKey(context.Background(), clusterRef(), admin)
	if err != nil {
		t.Fatalf("EnsureKey must not fail when losing-key cleanup errors: %v", err)
	}
	if creds.AccessKeyID != winnerID {
		t.Fatalf("expected winner creds, got %+v", creds)
	}
	if deletedID != testAccessKeyID {
		t.Fatalf("expected DeleteKey attempt on loser %q, got %q", testAccessKeyID, deletedID)
	}
}
