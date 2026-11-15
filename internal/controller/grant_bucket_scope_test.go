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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Issue #588: a GarageReferenceGrant to a GarageCluster must not let a granted
// namespace's GarageKeys reach every bucket, and must not let its
// GarageBuckets adopt (and later delete) buckets they did not create, unless
// the grant opts into bucketScope: Cluster. These tests cover every bypass
// path under the unset default, explicit Referenced, and Cluster.

const (
	scopeClusterNS = "garage-system"
	scopeTenantNS  = "tenant-a"
	scopeOtherNS   = "tenant-b"
	scopeCluster   = "garage"
	scopeKeyID     = "GKscope588"

	idOwn       = "id-own"
	idForeign   = "id-foreign"
	idPlatform  = "id-platform"
	idUnmanaged = "id-unmanaged"
)

var scopeModes = []struct {
	name  string
	scope garagev1beta1.GrantBucketScope
	wide  bool
}{
	{name: "unset", scope: "", wide: false},
	{name: "Referenced", scope: garagev1beta1.GrantBucketScopeReferenced, wide: false},
	{name: "Cluster", scope: garagev1beta1.GrantBucketScopeCluster, wide: true},
}

func scopeClusterGrant(name, fromKind string, scope garagev1beta1.GrantBucketScope) *garagev1beta1.GarageReferenceGrant {
	return &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: scopeClusterNS},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: fromKind, Namespace: scopeTenantNS}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: scopeCluster, BucketScope: scope}},
		},
	}
}

func scopeGarageBucket(name, namespace, bucketID string) *garagev1beta1.GarageBucket {
	return &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: scopeCluster, Namespace: scopeClusterNS},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
}

// fakeScopeGarage records bucket permission and delete calls.
type fakeScopeGarage struct {
	mu      sync.Mutex
	allows  map[string]garage.BucketKeyPerms
	denies  map[string]garage.BucketKeyPerms
	deletes []string
	calls   int
}

func newFakeScopeGarage(t *testing.T) (*fakeScopeGarage, *garage.Client) {
	t.Helper()
	f := &fakeScopeGarage{allows: map[string]garage.BucketKeyPerms{}, denies: map[string]garage.BucketKeyPerms{}}
	aliases := map[string]string{"own": idOwn, "foreign": idForeign, "platform": idPlatform, "unmanaged": idUnmanaged}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		switch req.URL.Path {
		case "/v2/ListBuckets":
			_, _ = w.Write([]byte(`[{"id":"id-own"},{"id":"id-foreign"},{"id":"id-platform"},{"id":"id-unmanaged"}]`))
			return
		case "/v2/GetBucketInfo":
			id, ok := aliases[req.URL.Query().Get("globalAlias")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code":"NoSuchBucket"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
			return
		case testAllowBucketKeyPath:
			var body garage.AllowBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			f.allows[body.BucketID] = body.Permissions
		case testDenyBucketKeyPath:
			var body garage.DenyBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			f.denies[body.BucketID] = body.Permissions
		case "/v2/DeleteBucket":
			f.deletes = append(f.deletes, req.URL.Query().Get("id"))
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return f, garage.NewClient(srv.URL, "token")
}

type keyScopeEnv struct {
	key      *garagev1beta1.GarageKey
	r        *GarageKeyReconciler
	recorder *record.FakeRecorder
	garage   *fakeScopeGarage
	client   *garage.Client
}

func newKeyScopeEnv(t *testing.T, key *garagev1beta1.GarageKey, objects ...client.Object) *keyScopeEnv {
	t.Helper()
	scheme := runtimeGrantScheme(t)
	key.Status.AccessKeyID = scopeKeyID
	all := make([]client.Object, 0, 4+len(objects))
	all = append(all,
		key,
		scopeGarageBucket("own", scopeTenantNS, idOwn),
		scopeGarageBucket("foreign", scopeOtherNS, idForeign),
		scopeGarageBucket("platform", scopeClusterNS, idPlatform),
	)
	all = append(all, objects...)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(all...).
		WithStatusSubresource(&garagev1beta1.GarageKey{}, &garagev1beta1.GarageBucket{}).Build()
	recorder := record.NewFakeRecorder(20)
	f, gc := newFakeScopeGarage(t)
	return &keyScopeEnv{key: key, r: &GarageKeyReconciler{Client: c, Scheme: scheme, Recorder: recorder}, recorder: recorder, garage: f, client: gc}
}

func (e *keyScopeEnv) reconcile(t *testing.T, remote ...garage.KeyBucket) error {
	t.Helper()
	return e.r.reconcileManagedBucketPermissions(t.Context(), e.key, e.client, &garage.Key{AccessKeyID: scopeKeyID, Buckets: remote})
}

func tenantKey(perms []garagev1beta1.BucketPermission, all *garagev1beta1.AllBucketsPermission) *garagev1beta1.GarageKey {
	return &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: scopeTenantNS},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef:        garagev1beta1.ClusterReference{Name: scopeCluster, Namespace: scopeClusterNS},
			BucketPermissions: perms,
			AllBuckets:        all,
		},
	}
}

func assertScopeDenied(t *testing.T, e *keyScopeEnv, want bool) {
	t.Helper()
	cond := meta.FindStatusCondition(e.key.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	denied := cond != nil && cond.Status == metav1.ConditionFalse && cond.Reason == garagev1beta1.ReasonBucketScopeDenied
	if denied != want {
		t.Fatalf("PermissionsConfigured = %+v, want BucketScopeDenied=%v", cond, want)
	}
	if !want {
		return
	}
	select {
	case event := <-e.recorder.Events:
		if !strings.Contains(event, "Warning "+garagev1beta1.ReasonBucketScopeDenied) {
			t.Fatalf("event = %q, want BucketScopeDenied warning", event)
		}
	default:
		t.Fatal("no BucketScopeDenied event recorded")
	}
}

func TestGrantBucketScope_GarageKeyPaths(t *testing.T) {
	read := garage.BucketKeyPerms{Read: true}
	cases := []struct {
		name string
		key  func() *garagev1beta1.GarageKey
		// allowed lists the bucket IDs that receive Read when the scope is
		// narrow (unset/Referenced) and when it is Cluster.
		narrow, wide []string
	}{
		{
			name: "bucketRef to own GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{BucketRef: &garagev1beta1.BucketRef{Name: "own"}, Read: true}}, nil)
			},
			narrow: []string{idOwn}, wide: []string{idOwn},
		},
		{
			name: "allBuckets",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey(nil, &garagev1beta1.AllBucketsPermission{Read: true})
			},
			narrow: nil, wide: []string{idOwn, idForeign, idPlatform, idUnmanaged},
		},
		{
			name: "bucketId of own GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{BucketID: idOwn, Read: true}}, nil)
			},
			narrow: []string{idOwn}, wide: []string{idOwn},
		},
		{
			name: "bucketId of another tenant's GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{BucketID: idForeign, Read: true}}, nil)
			},
			narrow: nil, wide: []string{idForeign},
		},
		{
			name: "bucketId of the cluster namespace's GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{BucketID: idPlatform, Read: true}}, nil)
			},
			narrow: nil, wide: []string{idPlatform},
		},
		{
			name: "bucketId of an unmanaged bucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{BucketID: idUnmanaged, Read: true}}, nil)
			},
			narrow: nil, wide: []string{idUnmanaged},
		},
		{
			name: "globalAlias of own GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{GlobalAlias: "own", Read: true}}, nil)
			},
			narrow: []string{idOwn}, wide: []string{idOwn},
		},
		{
			name: "globalAlias of another tenant's GarageBucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{GlobalAlias: "foreign", Read: true}}, nil)
			},
			narrow: nil, wide: []string{idForeign},
		},
		{
			name: "globalAlias of an unmanaged bucket",
			key: func() *garagev1beta1.GarageKey {
				return tenantKey([]garagev1beta1.BucketPermission{{GlobalAlias: "unmanaged", Read: true}}, nil)
			},
			narrow: nil, wide: []string{idUnmanaged},
		},
	}
	for _, mode := range scopeModes {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				e := newKeyScopeEnv(t, tc.key(), scopeClusterGrant("keys", "GarageKey", mode.scope))
				if err := e.reconcile(t); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				want := tc.narrow
				if mode.wide {
					want = tc.wide
				}
				if len(e.garage.allows) != len(want) {
					t.Fatalf("allows = %v, want Read on %v", e.garage.allows, want)
				}
				for _, id := range want {
					if e.garage.allows[id] != read {
						t.Fatalf("allow on %s = %+v, want Read (allows=%v)", id, e.garage.allows[id], e.garage.allows)
					}
				}
				expectDenied := !mode.wide && len(tc.narrow) < len(tc.wide)
				assertScopeDenied(t, e, expectDenied)
				if tc.name == "allBuckets" && e.key.Status.ClusterWide != mode.wide {
					t.Fatalf("status.clusterWide = %v, want %v", e.key.Status.ClusterWide, mode.wide)
				}
			})
		}
	}
}

func TestGrantBucketScope_GrantedForeignBucketStaysReachable(t *testing.T) {
	share := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "share", Namespace: scopeOtherNS},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: "GarageKey", Namespace: scopeTenantNS}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageBucket", Name: "foreign"}},
		},
	}
	for _, perm := range []garagev1beta1.BucketPermission{
		{BucketRef: &garagev1beta1.BucketRef{Name: "foreign", Namespace: scopeOtherNS}, Read: true},
		{BucketID: idForeign, Read: true},
		{GlobalAlias: "foreign", Read: true},
	} {
		e := newKeyScopeEnv(t, tenantKey([]garagev1beta1.BucketPermission{perm}, nil), scopeClusterGrant("keys", "GarageKey", ""), share)
		if err := e.reconcile(t); err != nil {
			t.Fatalf("reconcile %+v: %v", perm, err)
		}
		if e.garage.allows[idForeign] != (garage.BucketKeyPerms{Read: true}) {
			t.Fatalf("%+v: allows = %v, want Read on the granted foreign bucket", perm, e.garage.allows)
		}
		assertScopeDenied(t, e, false)
	}
}

func TestGrantBucketScope_SameNamespaceUnaffected(t *testing.T) {
	key := tenantKey(nil, &garagev1beta1.AllBucketsPermission{Read: true})
	key.Namespace = scopeClusterNS
	e := newKeyScopeEnv(t, key)
	if err := e.reconcile(t); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(e.garage.allows) != 4 {
		t.Fatalf("allows = %v, want every bucket for a same-namespace allBuckets key", e.garage.allows)
	}
	assertScopeDenied(t, e, false)
}

// An upgrade from a release without bucketScope must actively revoke what a
// cross-namespace key was granted beyond the default scope.
func TestGrantBucketScope_RevokesAlreadyAppliedPermissions(t *testing.T) {
	rw := garage.BucketKeyPerms{Read: true, Write: true, Owner: true}
	remote := []garage.KeyBucket{
		{ID: idOwn, Permissions: rw},
		{ID: idForeign, Permissions: rw},
		{ID: idPlatform, Permissions: rw},
		{ID: idUnmanaged, Permissions: rw},
	}

	t.Run("allBuckets", func(t *testing.T) {
		for _, mode := range scopeModes {
			key := tenantKey([]garagev1beta1.BucketPermission{{BucketRef: &garagev1beta1.BucketRef{Name: "own"}, Read: true, Write: true, Owner: true}},
				&garagev1beta1.AllBucketsPermission{Read: true, Write: true, Owner: true})
			key.Status.ClusterWide = true
			e := newKeyScopeEnv(t, key, scopeClusterGrant("keys", "GarageKey", mode.scope))
			if err := e.reconcile(t, remote...); err != nil {
				t.Fatalf("%s: reconcile: %v", mode.name, err)
			}
			if mode.wide {
				if len(e.garage.denies) != 0 {
					t.Fatalf("Cluster scope revoked %v", e.garage.denies)
				}
				continue
			}
			for _, id := range []string{idForeign, idPlatform, idUnmanaged} {
				if e.garage.denies[id] != rw {
					t.Fatalf("%s: deny on %s = %+v, want full revoke (denies=%v)", mode.name, id, e.garage.denies[id], e.garage.denies)
				}
			}
			if _, revoked := e.garage.denies[idOwn]; revoked {
				t.Fatalf("%s: own bucket was revoked", mode.name)
			}
			if e.key.Status.ClusterWide {
				t.Fatalf("%s: status.clusterWide still true after revocation", mode.name)
			}
			assertScopeDenied(t, e, true)
		}
	})

	t.Run("bucketId and globalAlias", func(t *testing.T) {
		for _, mode := range scopeModes {
			key := tenantKey([]garagev1beta1.BucketPermission{
				{BucketID: idForeign, Read: true, Write: true, Owner: true},
				{GlobalAlias: "unmanaged", Read: true, Write: true, Owner: true},
				{BucketID: idPlatform, Read: true, Write: true, Owner: true},
			}, nil)
			key.Status.ManagedBucketGrants = []string{idForeign, idPlatform, idUnmanaged}
			e := newKeyScopeEnv(t, key, scopeClusterGrant("keys", "GarageKey", mode.scope))
			if err := e.reconcile(t, remote[1:]...); err != nil {
				t.Fatalf("%s: reconcile: %v", mode.name, err)
			}
			if mode.wide {
				if len(e.garage.denies) != 0 {
					t.Fatalf("Cluster scope revoked %v", e.garage.denies)
				}
				continue
			}
			for _, id := range []string{idForeign, idPlatform, idUnmanaged} {
				if e.garage.denies[id] != rw {
					t.Fatalf("%s: deny on %s = %+v, want full revoke", mode.name, id, e.garage.denies[id])
				}
			}
			if len(e.key.Status.ManagedBucketGrants) != 0 {
				t.Fatalf("%s: managed grants = %v, want none", mode.name, e.key.Status.ManagedBucketGrants)
			}
			assertScopeDenied(t, e, true)
		}
	})
}

// adoptedBucket models a cross-namespace GarageBucket that adopted an
// unmanaged bucket through spec.bucketId before the upgrade and granted the
// tenant key on it.
func adoptedBucket() *garagev1beta1.GarageBucket {
	b := scopeGarageBucket("adopted", scopeTenantNS, idUnmanaged)
	b.Spec.BucketID = idUnmanaged
	b.Spec.KeyPermissions = []garagev1beta1.KeyPermission{{KeyRef: garagev1beta1.KeyRef{Name: "key"}, Read: true, Write: true, Owner: true}}
	b.Status.ManagedKeyGrants = []string{scopeKeyID}
	return b
}

func TestGrantBucketScope_AdoptedBucketGrantsToKeys(t *testing.T) {
	rw := garage.BucketKeyPerms{Read: true, Write: true, Owner: true}
	for _, mode := range scopeModes {
		t.Run(mode.name, func(t *testing.T) {
			// The key's own grant is narrow, so the reference is only in scope
			// when the GarageBucket grant admits the adoption itself.
			key := tenantKey([]garagev1beta1.BucketPermission{{BucketRef: &garagev1beta1.BucketRef{Name: "adopted"}, Read: true}}, nil)
			e := newKeyScopeEnv(t, key, adoptedBucket(),
				scopeClusterGrant("keys", "GarageKey", ""),
				scopeClusterGrant("buckets", "GarageBucket", mode.scope))
			if err := e.reconcile(t, garage.KeyBucket{ID: idUnmanaged, Permissions: rw}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if mode.wide {
				if len(e.garage.denies) != 0 {
					t.Fatalf("in-scope adoption revoked %v", e.garage.denies)
				}
				assertScopeDenied(t, e, false)
				return
			}
			if e.garage.denies[idUnmanaged] != rw {
				t.Fatalf("deny on adopted bucket = %+v, want full revoke (denies=%v)", e.garage.denies[idUnmanaged], e.garage.denies)
			}
			if len(e.garage.allows) != 0 {
				t.Fatalf("allows = %v, want none on the adopted bucket", e.garage.allows)
			}
			assertScopeDenied(t, e, true)
		})
	}
}

func newBucketScopeReconciler(t *testing.T, objects ...client.Object) (*GarageBucketReconciler, client.Client, *record.FakeRecorder) {
	t.Helper()
	scheme := runtimeGrantScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	recorder := record.NewFakeRecorder(20)
	return &GarageBucketReconciler{Client: c, Scheme: scheme, Recorder: recorder}, c, recorder
}

func TestGrantBucketScope_GarageBucketAdoptionDenied(t *testing.T) {
	for _, mode := range scopeModes {
		t.Run(mode.name, func(t *testing.T) {
			bucket := adoptedBucket()
			bucket.Status = garagev1beta1.GarageBucketStatus{}
			r, c, recorder := newBucketScopeReconciler(t, bucket, scopeClusterGrant("buckets", "GarageBucket", mode.scope))
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(bucket)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			fresh := &garagev1beta1.GarageBucket{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
				t.Fatal(err)
			}
			ready := meta.FindStatusCondition(fresh.Status.Conditions, PhaseReady)
			denied := ready != nil && ready.Reason == garagev1beta1.ReasonBucketScopeDenied
			if denied == mode.wide {
				t.Fatalf("Ready = %+v, want BucketScopeDenied=%v", ready, !mode.wide)
			}
			if mode.wide {
				return
			}
			if fresh.Status.Phase != PhaseFailed || fresh.Status.BucketID != "" {
				t.Fatalf("phase=%q bucketID=%q, want Failed without a recorded identity", fresh.Status.Phase, fresh.Status.BucketID)
			}
			if controllerutil.ContainsFinalizer(fresh, garageBucketFinalizer) {
				t.Fatal("fenced adoption received a deletion finalizer")
			}
			select {
			case event := <-recorder.Events:
				if !strings.Contains(event, garagev1beta1.ReasonBucketScopeDenied) {
					t.Fatalf("event = %q", event)
				}
			default:
				t.Fatal("no BucketScopeDenied event")
			}
		})
	}
}

func TestGrantBucketScope_AdoptedBucketDeletion(t *testing.T) {
	cases := []struct {
		name       string
		bucket     func() *garagev1beta1.GarageBucket
		wantDelete map[string]bool // keyed by scope mode name
	}{
		{
			name:       "cross-namespace adoption",
			bucket:     adoptedBucket,
			wantDelete: map[string]bool{"unset": false, "Referenced": false, "Cluster": true},
		},
		{
			name: "cross-namespace bucket the resource created",
			bucket: func() *garagev1beta1.GarageBucket {
				return scopeGarageBucket("created", scopeTenantNS, idOwn)
			},
			wantDelete: map[string]bool{"unset": true, "Referenced": true, "Cluster": true},
		},
		{
			name: "same-namespace adoption",
			bucket: func() *garagev1beta1.GarageBucket {
				b := adoptedBucket()
				b.Namespace = scopeClusterNS
				return b
			},
			wantDelete: map[string]bool{"unset": true, "Referenced": true, "Cluster": true},
		},
	}
	for _, tc := range cases {
		for _, mode := range scopeModes {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				bucket := tc.bucket()
				now := metav1.Now()
				bucket.DeletionTimestamp = &now
				bucket.Finalizers = []string{garageBucketFinalizer}
				r, _, _ := newBucketScopeReconciler(t, bucket, scopeClusterGrant("buckets", "GarageBucket", mode.scope))
				f, gc := newFakeScopeGarage(t)
				if err := r.finalize(t.Context(), bucket, gc); err != nil {
					t.Fatalf("finalize: %v", err)
				}
				deleted := len(f.deletes) == 1 && f.deletes[0] == bucket.Status.BucketID
				if deleted != tc.wantDelete[mode.name] {
					t.Fatalf("deletes = %v, want delete=%v", f.deletes, tc.wantDelete[mode.name])
				}
			})
		}
	}
}
