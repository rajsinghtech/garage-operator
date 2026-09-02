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
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func runtimeGrantScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func runtimeClusterGrant(fromKind, fromNamespace, targetNamespace, clusterName string) *garagev1beta1.GarageReferenceGrant {
	return &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-grant", Namespace: targetNamespace},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: fromKind, Namespace: fromNamespace}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: clusterName}},
		},
	}
}

type errorReferenceGrantReader struct {
	client.Reader
	err error
}

func (r errorReferenceGrantReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*garagev1beta1.GarageReferenceGrantList); ok {
		return r.err
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestRuntimeSpecValidationFailsBeforeGarageMutation(t *testing.T) {
	scheme := runtimeGrantScheme(t)
	var garageCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		garageCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	keyCases := []struct {
		name       string
		permission garagev1beta1.BucketPermission
	}{
		{
			name:       "invalid bucket alias",
			permission: garagev1beta1.BucketPermission{GlobalAlias: "127.0.0.1", Read: true},
		},
		{
			name:       "invalid bucketRef name",
			permission: garagev1beta1.BucketPermission{BucketRef: &garagev1beta1.BucketRef{Name: "Bad_Bucket"}, Read: true},
		},
	}
	for _, test := range keyCases {
		t.Run("GarageKey "+test.name, func(t *testing.T) {
			garageCalls.Store(0)
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: "tenant"},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef:        garagev1beta1.ClusterReference{Name: "garage"},
					BucketPermissions: []garagev1beta1.BucketPermission{test.permission},
				},
			}
			cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key).
				WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
			reconciler := &GarageKeyReconciler{Client: cached, Scheme: scheme}
			if _, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			fresh := &garagev1beta1.GarageKey{}
			if err := cached.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
				t.Fatalf("get key: %v", err)
			}
			if fresh.Status.Phase != PhaseFailed {
				t.Fatalf("phase = %q, want %q", fresh.Status.Phase, PhaseFailed)
			}
			if controllerutil.ContainsFinalizer(fresh, garageKeyFinalizer) {
				t.Fatal("invalid key received a finalizer before validation failed")
			}
			if garageCalls.Load() != 0 {
				t.Fatalf("Garage calls = %d, want zero", garageCalls.Load())
			}
		})
	}

	bucketCases := []struct {
		name   string
		mutate func(*garagev1beta1.GarageBucket)
	}{
		{
			name: "invalid global alias",
			mutate: func(bucket *garagev1beta1.GarageBucket) {
				bucket.Spec.GlobalAlias = "127.0.0.1"
			},
		},
		{
			name: "invalid local alias keyRef",
			mutate: func(bucket *garagev1beta1.GarageBucket) {
				bucket.Spec.LocalAliases = []garagev1beta1.LocalAlias{{KeyRef: "Bad_Key", Alias: "valid-local-alias"}}
			},
		},
		{
			name: "invalid keyRef name",
			mutate: func(bucket *garagev1beta1.GarageBucket) {
				bucket.Spec.KeyPermissions = []garagev1beta1.KeyPermission{{KeyRef: garagev1beta1.KeyRef{Name: "Bad_Key"}, Read: true}}
			},
		},
		{
			name: "negative object quota",
			mutate: func(bucket *garagev1beta1.GarageBucket) {
				negative := int64(-1)
				bucket.Spec.Quotas = &garagev1beta1.BucketQuotas{MaxObjects: &negative}
			},
		},
	}
	for _, test := range bucketCases {
		t.Run("GarageBucket "+test.name, func(t *testing.T) {
			garageCalls.Store(0)
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: "tenant"},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef:  garagev1beta1.ClusterReference{Name: "garage"},
					GlobalAlias: "valid-bucket",
				},
			}
			test.mutate(bucket)
			cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket).
				WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
			reconciler := &GarageBucketReconciler{Client: cached, Scheme: scheme}
			if _, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(bucket)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			fresh := &garagev1beta1.GarageBucket{}
			if err := cached.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
				t.Fatalf("get bucket: %v", err)
			}
			if fresh.Status.Phase != PhaseFailed {
				t.Fatalf("phase = %q, want %q", fresh.Status.Phase, PhaseFailed)
			}
			if controllerutil.ContainsFinalizer(fresh, garageBucketFinalizer) {
				t.Fatal("invalid bucket received a finalizer before validation failed")
			}
			if garageCalls.Load() != 0 {
				t.Fatalf("Garage calls = %d, want zero", garageCalls.Load())
			}
		})
	}
}

func TestRuntimeAuthorizationIgnoresStaleCachedGrants(t *testing.T) {
	const (
		sourceNamespace = "tenant"
		targetNamespace = "storage"
		clusterName     = "garage"
	)
	scheme := runtimeGrantScheme(t)
	authoritative := fake.NewClientBuilder().WithScheme(scheme).Build()
	var garageCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		garageCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Run("GarageKey", func(t *testing.T) {
		garageCalls.Store(0)
		key := &garagev1beta1.GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: sourceNamespace},
			Spec: garagev1beta1.GarageKeySpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: targetNamespace},
				AllBuckets: &garagev1beta1.AllBucketsPermission{Read: true},
			},
		}
		cached := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(key, runtimeClusterGrant("GarageKey", sourceNamespace, targetNamespace, clusterName)).
			WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
		reconciler := &GarageKeyReconciler{Client: cached, AuthorizationReader: authoritative, Scheme: scheme}
		if _, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		fresh := &garagev1beta1.GarageKey{}
		if err := cached.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
			t.Fatalf("get key: %v", err)
		}
		if fresh.Status.Phase != PhaseFailed || !strings.Contains(fresh.Status.Conditions[0].Message, "GarageReferenceGrant") {
			t.Fatalf("stale cached grant was accepted: status=%+v", fresh.Status)
		}
		if garageCalls.Load() != 0 {
			t.Fatalf("Garage calls = %d, want zero", garageCalls.Load())
		}
	})

	t.Run("GarageBucket", func(t *testing.T) {
		garageCalls.Store(0)
		bucket := &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: sourceNamespace},
			Spec: garagev1beta1.GarageBucketSpec{
				ClusterRef:  garagev1beta1.ClusterReference{Name: clusterName, Namespace: targetNamespace},
				GlobalAlias: "valid-bucket",
			},
		}
		cached := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bucket, runtimeClusterGrant("GarageBucket", sourceNamespace, targetNamespace, clusterName)).
			WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
		reconciler := &GarageBucketReconciler{Client: cached, AuthorizationReader: authoritative, Scheme: scheme}
		if _, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(bucket)}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		fresh := &garagev1beta1.GarageBucket{}
		if err := cached.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
			t.Fatalf("get bucket: %v", err)
		}
		if fresh.Status.Phase != PhaseFailed || !strings.Contains(fresh.Status.Conditions[0].Message, "GarageReferenceGrant") {
			t.Fatalf("stale cached grant was accepted: status=%+v", fresh.Status)
		}
		if garageCalls.Load() != 0 {
			t.Fatalf("Garage calls = %d, want zero", garageCalls.Load())
		}
	})
}

func TestRuntimeAuthorizationAllowsNamespaceSelectorGrant(t *testing.T) {
	const (
		sourceNamespace = "tenant"
		targetNamespace = "storage"
		clusterName     = "garage"
	)
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: sourceNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: targetNamespace},
			AllBuckets: &garagev1beta1.AllBucketsPermission{Read: true},
		},
	}
	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-grant", Namespace: targetNamespace},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{
				Kind: "GarageKey",
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"garage.example.com/application": "app01",
				}},
			}},
			To: []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: clusterName}},
		},
	}
	source := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: sourceNamespace,
		Labels: map[string]string{
			"garage.example.com/application": "app01",
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, grant, source).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	r := &GarageKeyReconciler{Client: c, AuthorizationReader: c, Scheme: scheme}

	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	fresh := &garagev1beta1.GarageKey{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
		t.Fatalf("get key: %v", err)
	}
	if fresh.Status.Phase != PhasePending {
		t.Fatalf("phase = %q, want %q after selector authorization and missing cluster", fresh.Status.Phase, PhasePending)
	}
	if len(fresh.Status.Conditions) > 0 && strings.Contains(fresh.Status.Conditions[0].Message, "GarageReferenceGrant") {
		t.Fatalf("selector grant was not accepted: status=%+v", fresh.Status)
	}
}

func TestGarageBucketReconcileSkipsDeniedCrossNamespaceKey(t *testing.T) {
	const (
		bucketNamespace  = "bhaiya"
		foreignNamespace = "hermes"
		clusterName      = "garage"
		bucketID         = "bucket-id"
		allowedKeyID     = "GKallowed"
		deniedKeyID      = "GKdenied"
	)
	scheme := runtimeGrantScheme(t)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "workspace", Namespace: bucketNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
			KeyPermissions: []garagev1beta1.KeyPermission{{
				KeyRef: garagev1beta1.KeyRef{Name: "allowed"}, Read: true,
			}},
		},
	}
	allowed := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "allowed", Namespace: bucketNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: allowedKeyID},
	}
	foreign := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "hermes-s3-key", Namespace: foreignNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: bucketNamespace},
			AllBuckets: &garagev1beta1.AllBucketsPermission{Read: true},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: deniedKeyID, ClusterWide: true},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(bucket, allowed, foreign).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	var allows []garage.AllowBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/AllowBucketKey" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var allow garage.AllowBucketKeyRequest
		if err := json.NewDecoder(request.Body).Decode(&allow); err != nil {
			t.Errorf("decode AllowBucketKey request: %v", err)
		}
		allows = append(allows, allow)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	r := &GarageBucketReconciler{Client: c, Scheme: scheme}
	if err := r.reconcileKeyPermissions(t.Context(), bucket, garage.NewClient(server.URL, "token"), &garage.Bucket{ID: bucketID}); err != nil {
		t.Fatalf("reconcileKeyPermissions: %v", err)
	}
	if len(allows) != 1 || allows[0].AccessKeyID != allowedKeyID || allows[0].BucketID != bucketID || !allows[0].Permissions.Read {
		t.Fatalf("AllowBucketKey calls = %+v, want only the grantable key", allows)
	}

	fresh := &garagev1beta1.GarageBucket{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	condition := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	if condition == nil {
		t.Fatalf("missing permission condition: %+v", fresh.Status.Conditions)
	}
	if condition.Status != metav1.ConditionFalse || condition.Reason != garagev1beta1.ReasonReferenceGrantDenied {
		t.Fatalf("permission condition = %+v, want False/%s", condition, garagev1beta1.ReasonReferenceGrantDenied)
	}
	if !strings.Contains(condition.Message, foreignNamespace+"/hermes-s3-key") || !strings.Contains(condition.Message, "GarageReferenceGrant") {
		t.Fatalf("permission condition message = %q, want denied key and grant guidance", condition.Message)
	}
	if !stringSliceContains(fresh.Status.ManagedKeyGrants, allowedKeyID) {
		t.Fatalf("ManagedKeyGrants = %v, want grantable key %q", fresh.Status.ManagedKeyGrants, allowedKeyID)
	}
}

func TestGarageKeyReconcileSkipsDeniedCrossNamespaceBucket(t *testing.T) {
	const (
		keyNamespace     = "keys"
		bucketNamespace  = "buckets"
		clusterNamespace = "storage"
		clusterName      = "garage"
		ownBucketID      = "owned-bucket-id"
		foreignBucketID  = "foreign-bucket-id"
		keyID            = "GKowned"
	)
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: keyNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: clusterNamespace},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketID: ownBucketID, Read: true,
			}},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	foreign := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign-bucket", Namespace: bucketNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: clusterNamespace},
			KeyPermissions: []garagev1beta1.KeyPermission{{
				KeyRef: garagev1beta1.KeyRef{Name: key.Name, Namespace: key.Namespace},
				Write:  true,
			}},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: foreignBucketID},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, foreign).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	var allows []garage.AllowBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != testAllowBucketKeyPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var allow garage.AllowBucketKeyRequest
		if err := json.NewDecoder(request.Body).Decode(&allow); err != nil {
			t.Errorf("decode AllowBucketKey request: %v", err)
		}
		allows = append(allows, allow)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	r := &GarageKeyReconciler{Client: c, Scheme: scheme}
	if err := r.reconcileManagedBucketPermissions(t.Context(), key, garage.NewClient(server.URL, "token"),
		&garage.Key{AccessKeyID: keyID}); err != nil {
		t.Fatalf("reconcileManagedBucketPermissions: %v", err)
	}
	if len(allows) != 1 || allows[0].AccessKeyID != keyID || allows[0].BucketID != ownBucketID ||
		allows[0].Permissions != (garage.BucketKeyPerms{Read: true}) {
		t.Fatalf("AllowBucketKey calls = %+v, want only the key's own permission", allows)
	}

	fresh := &garagev1beta1.GarageKey{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
		t.Fatalf("get key: %v", err)
	}
	condition := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	if condition == nil {
		t.Fatalf("missing permission condition: %+v", fresh.Status.Conditions)
	}
	if condition.Status != metav1.ConditionFalse || condition.Reason != garagev1beta1.ReasonReferenceGrantDenied {
		t.Fatalf("permission condition = %+v, want False/%s", condition, garagev1beta1.ReasonReferenceGrantDenied)
	}
	if !strings.Contains(condition.Message, bucketNamespace+"/foreign-bucket") ||
		!strings.Contains(condition.Message, "GarageReferenceGrant") {
		t.Fatalf("permission condition message = %q, want denied bucket and grant guidance", condition.Message)
	}
	if len(fresh.Status.ManagedBucketGrants) != 1 || fresh.Status.ManagedBucketGrants[0] != ownBucketID {
		t.Fatalf("ManagedBucketGrants = %v, want key-owned bucket %q", fresh.Status.ManagedBucketGrants, ownBucketID)
	}
}

func TestGarageKeyReconcileKeepsExplicitBucketDenialFatal(t *testing.T) {
	const (
		keyNamespace    = "keys"
		bucketNamespace = "storage"
		clusterName     = "garage"
		bucketID        = "explicit-bucket-id"
		keyID           = "GKexplicit"
	)
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: keyNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: bucketNamespace},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketRef: &garagev1beta1.BucketRef{Name: "bucket", Namespace: bucketNamespace},
				Read:      true,
			}},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: bucketNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, bucket).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	var denies []garage.DenyBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != testDenyBucketKeyPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var deny garage.DenyBucketKeyRequest
		if err := json.NewDecoder(request.Body).Decode(&deny); err != nil {
			t.Errorf("decode DenyBucketKey request: %v", err)
		}
		denies = append(denies, deny)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	r := &GarageKeyReconciler{Client: c, Scheme: scheme}
	err := r.reconcileManagedBucketPermissions(t.Context(), key, garage.NewClient(server.URL, "token"),
		&garage.Key{AccessKeyID: keyID, Buckets: []garage.KeyBucket{{
			ID: bucketID, Permissions: garage.BucketKeyPerms{Read: true},
		}}})
	if err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
		t.Fatalf("error = %v, want explicit key-owned reference denial", err)
	}
	if len(denies) != 1 || denies[0].BucketID != bucketID || denies[0].AccessKeyID != keyID ||
		!denies[0].Permissions.Read {
		t.Fatalf("DenyBucketKey calls = %+v, want exact cleanup of the denied explicit target", denies)
	}
	condition := meta.FindStatusCondition(key.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	if condition == nil || condition.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("permission condition = %+v, want ReconcileFailed", condition)
	}
}

func TestGarageKeyReconcileKeepsReferenceGrantReadErrorsFatal(t *testing.T) {
	const (
		keyNamespace     = "keys"
		bucketNamespace  = "buckets"
		clusterNamespace = "storage"
		clusterName      = "garage"
		keyID            = "GKgrant-error"
	)
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: keyNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: clusterNamespace},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign-bucket", Namespace: bucketNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: clusterName, Namespace: clusterNamespace},
			KeyPermissions: []garagev1beta1.KeyPermission{{
				KeyRef: garagev1beta1.KeyRef{Name: key.Name, Namespace: key.Namespace},
				Read:   true,
			}},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "foreign-bucket-id"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, bucket).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	r := &GarageKeyReconciler{
		Client:              c,
		AuthorizationReader: errorReferenceGrantReader{Reader: c, err: stderrors.New("injected grant list failure")},
		Scheme:              scheme,
	}

	err := r.reconcileManagedBucketPermissions(t.Context(), key, garage.NewClient("http://127.0.0.1:1", "token"),
		&garage.Key{AccessKeyID: keyID})
	if err == nil || !strings.Contains(err.Error(), "failed to list GarageReferenceGrants") {
		t.Fatalf("error = %v, want fatal grant-evaluation error", err)
	}
	condition := meta.FindStatusCondition(key.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	if condition == nil || condition.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("permission condition = %+v, want ReconcileFailed", condition)
	}
}

func TestGrantRemovalRevokesPreviouslyManagedBucketPermission(t *testing.T) {
	const (
		bucketID = "bucket-id"
		keyID    = "GKwriter"
	)
	scheme := runtimeGrantScheme(t)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{KeyPermissions: []garagev1beta1.KeyPermission{{
			KeyRef: garagev1beta1.KeyRef{Name: "writer", Namespace: "keys"}, Read: true,
		}}},
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "keys"},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket, key).Build()
	var denied garage.DenyBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/DenyBucketKey" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(request.Body).Decode(&denied)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	existing := &garage.Bucket{ID: bucketID, Keys: []garage.BucketKeyInfo{{
		AccessKeyID: keyID, Permissions: garage.BucketKeyPerms{Read: true},
	}}}

	err := (&GarageBucketReconciler{Client: c}).reconcileKeyPermissions(t.Context(), bucket, garage.NewClient(server.URL, "token"), existing)
	if err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
		t.Fatalf("error=%v, want authorization failure after cleanup", err)
	}
	if denied.BucketID != bucketID || denied.AccessKeyID != keyID || !denied.Permissions.Read {
		t.Fatalf("deny request=%+v, want exact previously managed read grant revoked", denied)
	}
}

func TestGrantRemovalRevokesPreviouslyManagedKeyPermission(t *testing.T) {
	const (
		bucketID = "bucket-id"
		keyID    = "GKwriter"
	)
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "tenant"},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage", Namespace: "storage"},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketRef: &garagev1beta1.BucketRef{Name: "bucket", Namespace: "storage"}, Read: true,
			}},
		},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: "storage"},
		Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "garage"}},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, bucket).Build()
	var denied garage.DenyBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/DenyBucketKey" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(request.Body).Decode(&denied)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	garageKey := &garage.Key{AccessKeyID: keyID, Buckets: []garage.KeyBucket{{
		ID: bucketID, Permissions: garage.BucketKeyPerms{Read: true},
	}}}

	err := (&GarageKeyReconciler{Client: c}).reconcileManagedBucketPermissions(t.Context(), key, garage.NewClient(server.URL, "token"), garageKey)
	if err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
		t.Fatalf("error=%v, want authorization failure after cleanup", err)
	}
	if denied.BucketID != bucketID || denied.AccessKeyID != keyID || !denied.Permissions.Read {
		t.Fatalf("deny request=%+v, want exact previously managed read grant revoked", denied)
	}
}

func TestBucketPermissionReservationSurvivesAllowThenSpecRemoval(t *testing.T) {
	const (
		bucketID = "bucket-id"
		keyID    = "GKwriter"
	)
	scheme := runtimeGrantScheme(t)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{KeyPermissions: []garagev1beta1.KeyPermission{{
			KeyRef: garagev1beta1.KeyRef{Name: "writer"}, Read: true,
		}}},
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "tenant"},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket, key).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}, &garagev1beta1.GarageKey{}).Build()
	allowCalls, denyCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/AllowBucketKey":
			allowCalls++
			fresh := &garagev1beta1.GarageBucket{}
			if err := c.Get(request.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
				t.Errorf("read bucket reservation during allow: %v", err)
			} else if !stringSliceContains(fresh.Status.ManagedKeyGrants, keyID) {
				t.Errorf("remote allow preceded durable bucket ownership: %+v", fresh.Status)
			}
			_, _ = w.Write([]byte(`{}`))
		case "/v2/DenyBucketKey":
			denyCalls++
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	r := &GarageBucketReconciler{Client: c}
	if err := r.reconcileKeyPermissions(t.Context(), bucket, garage.NewClient(server.URL, "token"), &garage.Bucket{ID: bucketID}); err != nil {
		t.Fatal(err)
	}
	if allowCalls != 1 {
		t.Fatalf("allow calls = %d, want 1", allowCalls)
	}

	// Treat the allow as the last observable action of the old process. A user
	// now removes the declaration; the pre-allow reservation must drive denial.
	fresh := &garagev1beta1.GarageBucket{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Spec.KeyPermissions = nil
	if err := c.Update(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
	if err := r.reconcileKeyPermissions(t.Context(), fresh, garage.NewClient(server.URL, "token"), &garage.Bucket{
		ID: bucketID, Keys: []garage.BucketKeyInfo{{AccessKeyID: keyID, Permissions: garage.BucketKeyPerms{Read: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if denyCalls != 1 || len(fresh.Status.ManagedKeyGrants) != 0 {
		t.Fatalf("deny calls=%d managed=%v, want exact cleanup and ownership release", denyCalls, fresh.Status.ManagedKeyGrants)
	}
}

func TestKeyPermissionReservationsSurviveAllowThenSpecRemoval(t *testing.T) {
	for _, test := range []struct {
		name        string
		configure   func(*garagev1beta1.GarageKey)
		remove      func(*garagev1beta1.GarageKey)
		isReserved  func(*garagev1beta1.GarageKey) bool
		isReleased  func(*garagev1beta1.GarageKey) bool
		listBuckets bool
	}{
		{
			name: "explicit bucket",
			configure: func(key *garagev1beta1.GarageKey) {
				key.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{BucketID: "bucket-id", Read: true}}
			},
			remove: func(key *garagev1beta1.GarageKey) { key.Spec.BucketPermissions = nil },
			isReserved: func(key *garagev1beta1.GarageKey) bool {
				return stringSliceContains(key.Status.ManagedBucketGrants, "bucket-id")
			},
			isReleased: func(key *garagev1beta1.GarageKey) bool { return len(key.Status.ManagedBucketGrants) == 0 },
		},
		{
			name: "allBuckets",
			configure: func(key *garagev1beta1.GarageKey) {
				key.Spec.AllBuckets = &garagev1beta1.AllBucketsPermission{Read: true}
			},
			remove:      func(key *garagev1beta1.GarageKey) { key.Spec.AllBuckets = nil },
			isReserved:  func(key *garagev1beta1.GarageKey) bool { return key.Status.ClusterWide },
			isReleased:  func(key *garagev1beta1.GarageKey) bool { return !key.Status.ClusterWide },
			listBuckets: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const (
				bucketID = "bucket-id"
				keyID    = "GKwriter"
			)
			scheme := runtimeGrantScheme(t)
			key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "tenant"}}
			test.configure(key)
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key).
				WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
			allowCalls, denyCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v2/ListBuckets":
					if !test.listBuckets {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_, _ = w.Write([]byte(`[{"id":"bucket-id"}]`))
				case "/v2/AllowBucketKey":
					allowCalls++
					fresh := &garagev1beta1.GarageKey{}
					if err := c.Get(request.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
						t.Errorf("read key reservation during allow: %v", err)
					} else if !test.isReserved(fresh) {
						t.Errorf("remote allow preceded durable key ownership: %+v", fresh.Status)
					}
					_, _ = w.Write([]byte(`{}`))
				case "/v2/DenyBucketKey":
					denyCalls++
					_, _ = w.Write([]byte(`{}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			r := &GarageKeyReconciler{Client: c}
			garageKey := &garage.Key{AccessKeyID: keyID}
			if err := r.reconcileManagedBucketPermissions(t.Context(), key, garage.NewClient(server.URL, "token"), garageKey); err != nil {
				t.Fatal(err)
			}
			if allowCalls != 1 {
				t.Fatalf("allow calls = %d, want 1", allowCalls)
			}

			fresh := &garagev1beta1.GarageKey{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
				t.Fatal(err)
			}
			test.remove(fresh)
			if err := c.Update(t.Context(), fresh); err != nil {
				t.Fatal(err)
			}
			garageKey.Buckets = []garage.KeyBucket{{ID: bucketID, Permissions: garage.BucketKeyPerms{Read: true}}}
			if err := r.reconcileManagedBucketPermissions(t.Context(), fresh, garage.NewClient(server.URL, "token"), garageKey); err != nil {
				t.Fatal(err)
			}
			if denyCalls != 1 || !test.isReleased(fresh) {
				t.Fatalf("deny calls=%d status=%+v, want exact cleanup and ownership release", denyCalls, fresh.Status)
			}
		})
	}
}

func deleteRuntimeGrant(t *testing.T, c client.Client, grant *garagev1beta1.GarageReferenceGrant) {
	t.Helper()
	if err := c.Delete(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeGrantFailure(t *testing.T, phase string, conditions []metav1.Condition) {
	t.Helper()
	if phase != PhaseFailed {
		t.Fatalf("phase = %q, want %q", phase, PhaseFailed)
	}
	if len(conditions) == 0 || !strings.Contains(conditions[len(conditions)-1].Message, "GarageReferenceGrant") {
		t.Fatalf("conditions = %+v, want missing GarageReferenceGrant failure", conditions)
	}
}

func TestGarageKeyReconcileRejectsReferenceAfterGrantRemoval(t *testing.T) {
	const sourceNamespace = "tenant"
	const targetNamespace = "storage"
	scheme := runtimeGrantScheme(t)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: sourceNamespace},
		Spec: garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: "garage", Namespace: targetNamespace,
		}},
	}
	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-key", Namespace: targetNamespace},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: "GarageKey", Namespace: sourceNamespace}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: "garage"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, grant).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	deleteRuntimeGrant(t, c, grant)

	r := &GarageKeyReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{
		Name: key.Name, Namespace: key.Namespace,
	}}); err != nil {
		t.Fatal(err)
	}
	got := &garagev1beta1.GarageKey{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(key), got); err != nil {
		t.Fatal(err)
	}
	assertRuntimeGrantFailure(t, got.Status.Phase, got.Status.Conditions)
}

func TestGarageBucketReconcileRejectsReferenceAfterGrantRemoval(t *testing.T) {
	const sourceNamespace = "tenant"
	const targetNamespace = "storage"
	scheme := runtimeGrantScheme(t)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: sourceNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:  garagev1beta1.ClusterReference{Name: "garage", Namespace: targetNamespace},
			GlobalAlias: "bucket",
		},
	}
	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-bucket", Namespace: targetNamespace},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: "GarageBucket", Namespace: sourceNamespace}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: "garage"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket, grant).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	deleteRuntimeGrant(t, c, grant)

	r := &GarageBucketReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{
		Name: bucket.Name, Namespace: bucket.Namespace,
	}}); err != nil {
		t.Fatal(err)
	}
	got := &garagev1beta1.GarageBucket{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(bucket), got); err != nil {
		t.Fatal(err)
	}
	assertRuntimeGrantFailure(t, got.Status.Phase, got.Status.Conditions)
}

func TestGarageNodeReconcileRejectsUnsupportedRemoteClusterRef(t *testing.T) {
	scheme := runtimeGrantScheme(t)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "storage"},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage"},
			Zone:       "zone-a",
			Gateway:    true,
			External: &garagev1beta1.ExternalNodeConfig{
				Address:          "garage.example.test",
				Port:             3901,
				RemoteClusterRef: &garagev1beta1.ClusterReference{Name: "remote"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()

	r := &GarageNodeReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{
		Name: node.Name, Namespace: node.Namespace,
	}}); err != nil {
		t.Fatal(err)
	}
	got := &garagev1beta1.GarageNode{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(node), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != PhaseFailed {
		t.Fatalf("phase = %q, want %q", got.Status.Phase, PhaseFailed)
	}
	if len(got.Status.Conditions) == 0 || !strings.Contains(got.Status.Conditions[len(got.Status.Conditions)-1].Message, "spec.external.remoteClusterRef is not supported") {
		t.Fatalf("conditions = %+v, want unsupported remoteClusterRef failure", got.Status.Conditions)
	}
}

func TestGarageNodeReconcileRejectsUnsupportedExternalIPPublicEndpoint(t *testing.T) {
	scheme := runtimeGrantScheme(t)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "storage"},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage"},
			Zone:       "zone-a",
			Gateway:    true,
			PublicEndpoint: &garagev1beta1.PublicEndpointConfig{
				Type:       "ExternalIP",
				ExternalIP: &garagev1beta1.ExternalIPEndpointConfig{Addresses: map[string]string{"node": "192.0.2.10"}},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()

	r := &GarageNodeReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{
		Name: node.Name, Namespace: node.Namespace,
	}}); err != nil {
		t.Fatal(err)
	}
	got := &garagev1beta1.GarageNode{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(node), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != PhaseFailed || len(got.Status.Conditions) == 0 ||
		!strings.Contains(got.Status.Conditions[len(got.Status.Conditions)-1].Message, "spec.publicEndpoint.externalIP is not supported") {
		t.Fatalf("status = %+v, want unsupported ExternalIP failure", got.Status)
	}
}

func TestGarageClusterRuntimeConfigRejectsUnsupportedExternalIPPublicEndpoint(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
		PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
			Type:       "ExternalIP",
			ExternalIP: &garagev1beta2.ExternalIPEndpointConfig{AddressTemplate: "garage.example.test"},
		},
	}}
	if err := validateGarageClusterRuntimeConfig(cluster); err == nil || !strings.Contains(err.Error(), "spec.publicEndpoint.externalIP is not supported") {
		t.Fatalf("unsupported ExternalIP runtime config accepted: %v", err)
	}
}

func TestGarageClusterRuntimeConfigRejectsUnsupportedRemoteDefaultCapacity(t *testing.T) {
	capacity := resource.MustParse("100Gi")
	cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
		RemoteClusters: []garagev1beta2.RemoteClusterConfig{{DefaultCapacity: &capacity}},
	}}
	if err := validateGarageClusterRuntimeConfig(cluster); err == nil || !strings.Contains(err.Error(), "defaultCapacity is not supported") {
		t.Fatalf("unsupported remote defaultCapacity runtime config accepted: %v", err)
	}
}

func TestGarageClusterRuntimeConfigRejectsServiceFieldsForWrongType(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
		Network: garagev1beta2.NetworkConfig{Service: &garagev1beta2.ServiceConfig{
			Type: corev1.ServiceTypeClusterIP, LoadBalancerIP: "192.0.2.10",
		}},
	}}
	if err := validateGarageClusterRuntimeConfig(cluster); err == nil || !strings.Contains(err.Error(), "require type: LoadBalancer") {
		t.Fatalf("invalid persisted Service config accepted: %v", err)
	}
}
