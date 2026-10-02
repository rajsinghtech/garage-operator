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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

func exactDeleteServer(t *testing.T, path, id string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != path || request.URL.Query().Get("id") != id {
			t.Errorf("delete request = %s %s?id=%s, want POST %s?id=%s",
				request.Method, request.URL.Path, request.URL.Query().Get("id"), path, id)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	return server, &calls
}

func TestGarageBucketFinalizationUsesDurableIdentityWhenStatusIsEmpty(t *testing.T) {
	for _, test := range []struct {
		name   string
		id     string
		mutate func(*garagev1beta1.GarageBucket)
	}{
		{
			name: "explicit spec bucket ID",
			id:   "imported-bucket-exact",
			mutate: func(bucket *garagev1beta1.GarageBucket) {
				bucket.Spec.BucketID = "imported-bucket-exact"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: testNamespace}}
			test.mutate(bucket)
			server, calls := exactDeleteServer(t, "/v2/DeleteBucket", test.id)
			defer server.Close()

			if err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token")); err != nil {
				t.Fatalf("finalize: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("DeleteBucket calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestGarageBucketFinalizationDisagreementFailsClosed(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", "must-not-delete")
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "bucket",
			Namespace:   testNamespace,
			Annotations: map[string]string{garagev1beta1.AnnotationCOSIBucketID: "cosi-id"},
		},
		Spec:   garagev1beta1.GarageBucketSpec{BucketID: "spec-id"},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "status-id"},
	}

	err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("finalize error = %v, want identity disagreement", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("DeleteBucket calls = %d, want 0", calls.Load())
	}
}

func TestGarageBucketFinalizationPreservesBucketNotEmptyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`BucketNotEmpty`))
	}))
	defer server.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: "non-empty-id"},
	}
	err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token"))
	if err == nil || !garage.IsBucketNotEmpty(err) {
		t.Fatalf("finalize error = %v, want a typed BucketNotEmpty error", err)
	}
	if !strings.Contains(err.Error(), "delete all objects before removing") {
		t.Fatalf("finalize error = %v, want actionable deletion guidance", err)
	}
}

func TestGarageBucketNonEmptyDeletionSurfacesConditionAndBacksOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`BucketNotEmpty`))
	}))
	defer server.Close()
	handle, secret := finalizationRetryHandle(server.URL)
	now := metav1.Now()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bucket", Namespace: "tenant", Finalizers: []string{garageBucketFinalizer},
			DeletionTimestamp: &now,
			Annotations:       map[string]string{FinalizationRetryAnnotation: "1"},
		},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: handle.Name, Namespace: handle.Namespace,
		}},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "non-empty-id"},
	}
	wrapped, _ := finalizationRetryClient(t, []client.Object{handle, secret, bucket})
	reconciler := &GarageBucketReconciler{Client: wrapped, Scheme: wrapped.Scheme()}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	if err != nil {
		t.Fatalf("Reconcile error = %v, want status-driven retry", err)
	}
	if result.RequeueAfter != FinalizationRetryDelay(2) {
		t.Fatalf("RequeueAfter = %s, want %s", result.RequeueAfter, FinalizationRetryDelay(2))
	}

	fresh := &garagev1beta1.GarageBucket{}
	if err := wrapped.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if got := fresh.Annotations[FinalizationRetryAnnotation]; got != "2" {
		t.Fatalf("retry annotation = %q, want 2", got)
	}
	if fresh.Status.Phase != PhaseDeleting {
		t.Fatalf("phase = %q, want %q", fresh.Status.Phase, PhaseDeleting)
	}
	blocked := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionDeletionBlocked)
	if blocked == nil {
		t.Fatalf("conditions = %#v, want %s condition", fresh.Status.Conditions, garagev1beta1.ConditionDeletionBlocked)
	}
	if blocked.Status != metav1.ConditionTrue || blocked.Reason != garagev1beta1.ReasonBucketNotEmpty {
		t.Fatalf("deletion condition = %#v, want true/%s", blocked, garagev1beta1.ReasonBucketNotEmpty)
	}
	if !strings.Contains(blocked.Message, "remove all objects") || !strings.Contains(blocked.Message, "never empties") {
		t.Fatalf("deletion condition message = %q, want actionable safe-deletion guidance", blocked.Message)
	}
	ready := meta.FindStatusCondition(fresh.Status.Conditions, PhaseReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != garagev1beta1.ReasonBucketNotEmpty {
		t.Fatalf("ready condition = %#v, want false/%s", ready, garagev1beta1.ReasonBucketNotEmpty)
	}
	if !controllerutil.ContainsFinalizer(fresh, garageBucketFinalizer) {
		t.Fatal("bucket cleanup finalizer was removed while the bucket was non-empty")
	}
}

func TestFinalizationRetryDelayIsBounded(t *testing.T) {
	if got := FinalizationRetryDelay(0); got != RequeueAfterError {
		t.Fatalf("retry delay for zero retries = %s, want %s", got, RequeueAfterError)
	}
	if got := FinalizationRetryDelay(2); got != 2*RequeueAfterError {
		t.Fatalf("retry delay for two retries = %s, want %s", got, 2*RequeueAfterError)
	}
	if got := FinalizationRetryDelay(10); got != RequeueAfterLong {
		t.Fatalf("retry delay for ten retries = %s, want cap %s", got, RequeueAfterLong)
	}
	if got := FinalizationRetryDelay(-1); got != RequeueAfterError {
		t.Fatalf("retry delay for malformed negative count = %s, want %s", got, RequeueAfterError)
	}
}

func TestPendingCOSIBucketFinalizationRecoversReservationAlias(t *testing.T) {
	const bucketID = "reserved-bucket-exact"
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "pending-cosi", Namespace: testNamespace, UID: "pending-cosi-uid",
	}}
	alias, err := garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", bucket.Namespace, bucket.Name, bucket.UID)
	if err != nil {
		t.Fatal(err)
	}
	var lookupCalls atomic.Int32
	var deleteCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v2/GetBucketInfo":
			lookupCalls.Add(1)
			if request.URL.Query().Get("globalAlias") != alias {
				t.Errorf("lookup globalAlias = %q, want %q", request.URL.Query().Get("globalAlias"), alias)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"id":%q,"globalAliases":[%q]}`, bucketID, alias)
		case request.Method == http.MethodPost && request.URL.Path == "/v2/DeleteBucket":
			deleteCalls.Add(1)
			if request.URL.Query().Get("id") != bucketID {
				t.Errorf("delete bucket ID = %q, want %q", request.URL.Query().Get("id"), bucketID)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	bucket.Annotations = map[string]string{
		garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStatePending,
		garagev1beta1.AnnotationCOSIReservationAlias:  alias,
	}
	if err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token")); err != nil {
		t.Fatalf("finalize pending COSI reservation: %v", err)
	}
	if lookupCalls.Load() != 1 || deleteCalls.Load() != 1 {
		t.Fatalf("calls lookup=%d delete=%d, want 1 each", lookupCalls.Load(), deleteCalls.Load())
	}
}

func TestGarageBucketFinalizationRejectsReservationAliasNotBoundToUID(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", "victim-bucket")
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "bucket", Namespace: testNamespace, UID: "bucket-uid",
		Annotations: map[string]string{garagev1beta1.AnnotationBucketReservationAlias: "victim-alias"},
	}}

	err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound reservation finalization error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Garage calls = %d, want zero", calls.Load())
	}
}

func TestGarageBucketFinalizationRejectsCOSIAnnotationOnlyIdentity(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", "victim-bucket")
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "cosi-bucket", Namespace: testNamespace, UID: "cosi-bucket-uid",
		Annotations: map[string]string{garagev1beta1.AnnotationCOSIBucketID: "victim-bucket"},
	}}

	err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "no authoritative") {
		t.Fatalf("COSI annotation-only finalization error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Garage calls = %d, want zero", calls.Load())
	}
}

func TestGarageBucketFinalizationRejectsCOSIReservationCopiedAcrossUID(t *testing.T) {
	original := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "cosi-bucket", Namespace: testNamespace, UID: "original-cosi-uid",
	}}
	alias, err := garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", original.Namespace, original.Name, original.UID)
	if err != nil {
		t.Fatal(err)
	}
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", "victim-bucket")
	defer server.Close()
	recreated := original.DeepCopy()
	recreated.UID = "recreated-cosi-uid"
	recreated.Annotations = map[string]string{garagev1beta1.AnnotationCOSIReservationAlias: alias}

	err = (&GarageBucketReconciler{}).finalize(t.Context(), recreated, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("copied COSI reservation finalization error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Garage calls = %d, want zero", calls.Load())
	}
}

func TestGarageBucketFinalizationWithoutTrustedIdentityDoesNotDelete(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteBucket", "must-not-delete")
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "bucket", Namespace: testNamespace, UID: "bucket-uid",
	}}

	if err := (&GarageBucketReconciler{}).finalize(t.Context(), bucket, garage.NewClient(server.URL, "token")); err != nil {
		t.Fatalf("identity-free finalization: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Garage calls = %d, want zero without a trusted bucket identity", calls.Load())
	}
}

func TestValidatedCOSIRetainFailsClosedForUnverifiedBuckets(t *testing.T) {
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "cosi-shadow", Namespace: testNamespace, UID: "shadow-uid",
		Annotations: map[string]string{
			garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStateBound,
			garagev1beta1.AnnotationCOSIReservationOwner:  "claim",
			garagev1beta1.AnnotationCOSIBucketID:          "bucket-id",
		},
	}, Status: garagev1beta1.GarageBucketStatus{BucketID: "bucket-id"}}
	marker, err := garagev1beta1.UIDBoundReservationAlias("cosi-retain-", bucket.Namespace, bucket.Name, bucket.UID)
	if err != nil {
		t.Fatal(err)
	}
	bucket.Annotations[garagev1beta1.AnnotationCOSIRetain] = marker
	if retain, err := (&GarageBucketReconciler{}).validatedCOSIRetain(t.Context(), bucket); err == nil || retain {
		t.Fatalf("unmanaged bucket retain validation = (%v, %v), want rejection", retain, err)
	}
	bucket.Labels = map[string]string{garagev1beta1.LabelCOSIManaged: "true"}
	bucket.Annotations[garagev1beta1.AnnotationCOSIRetain] = "copied-marker"
	if retain, err := (&GarageBucketReconciler{}).validatedCOSIRetain(t.Context(), bucket); err == nil || retain {
		t.Fatalf("copied marker validation = (%v, %v), want rejection", retain, err)
	}
}

func TestValidatedCOSIRetainRejectsSelfConsistentForgeryWithoutParent(t *testing.T) {
	const (
		owner    = "forged-cosi-bucket"
		bucketID = "forged-bucket-id"
		driver   = "garage.example.test"
	)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      garageconfig.COSIShadowResourceName(owner),
			Namespace: testNamespace,
			UID:       "forged-shadow-uid",
			Labels:    map[string]string{garagev1beta1.LabelCOSIManaged: "true"},
			Annotations: map[string]string{
				garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStateBound,
				garagev1beta1.AnnotationCOSIReservationOwner:  owner,
				garagev1beta1.AnnotationCOSIBucketID:          bucketID,
			},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
	marker, err := garagev1beta1.UIDBoundReservationAlias("cosi-retain-", bucket.Namespace, bucket.Name, bucket.UID)
	if err != nil {
		t.Fatal(err)
	}
	bucket.Annotations[garagev1beta1.AnnotationCOSIRetain] = marker
	scheme := finalizationIdentityScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, COSIDriverName: driver}

	if retain, err := reconciler.validatedCOSIRetain(t.Context(), bucket); err == nil || retain {
		t.Fatalf("fully forged retain validation = (%v, %v), want rejection without an authoritative COSI parent", retain, err)
	}
}

func finalizationIdentityScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, garagev1beta1.AddToScheme, cosiv1alpha2.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	return scheme
}

func TestGarageKeyFinalizationUsesDurableIdentityWhenStatusIsEmpty(t *testing.T) {
	for _, test := range []struct {
		name   string
		id     string
		mutate func(*garagev1beta1.GarageKey) []runtime.Object
	}{
		{
			name: "inline imported key",
			id:   "GKinlineexact",
			mutate: func(key *garagev1beta1.GarageKey) []runtime.Object {
				key.Spec.ImportKey = &garagev1beta1.ImportKeyConfig{AccessKeyID: "GKinlineexact", SecretAccessKey: "secret"}
				return nil
			},
		},
		{
			name: "Secret import snapshot",
			id:   "GKsecretexact",
			mutate: func(key *garagev1beta1.GarageKey) []runtime.Object {
				key.Spec.ImportKey = &garagev1beta1.ImportKeyConfig{SecretRef: &corev1.SecretReference{Name: "imported-key"}}
				return []runtime.Object{&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: importKeySnapshotName(key), Namespace: key.Namespace,
						Labels: map[string]string{keyImportSnapshotLabel: "true"},
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: garagev1beta1.GroupVersion.String(), Kind: "GarageKey",
							Name: key.Name, UID: key.UID, Controller: ptr.To(true),
						}},
					},
					Immutable: ptr.To(true),
					Data: map[string][]byte{
						defaultAccessKeyIDKey: []byte("GKsecretexact"), defaultSecretAccessKeyKey: []byte("secret"),
					},
				}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace, UID: "key-uid"}}
			objects := test.mutate(key)
			scheme := finalizationIdentityScheme(t)
			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			reconciler := &GarageKeyReconciler{Client: client}
			server, calls := exactDeleteServer(t, "/v2/DeleteKey", test.id)
			defer server.Close()

			if err := reconciler.finalize(t.Context(), key, nil, garage.NewClient(server.URL, "token")); err != nil {
				t.Fatalf("finalize: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("DeleteKey calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestGarageKeyFinalizationResolvesExactLegacyDisplayNameIdentity(t *testing.T) {
	const (
		namespace  = "tenant"
		objectName = "backup-key"
		legacyName = "legacy display name"
	)
	rpcSecretHex := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rpcSecret, err := hex.DecodeString(string(rpcSecretHex))
	if err != nil {
		t.Fatal(err)
	}
	legacyID, legacySecret := deriveKeyMaterial(rpcSecret, namespace, legacyName)
	canonicalID, _ := deriveKeyMaterial(rpcSecret, namespace, objectName)

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: namespace}}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: objectName, Namespace: namespace},
		Spec: garagev1beta1.GarageKeySpec{
			Name: legacyName, ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
		},
	}
	rpcSecretObject := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: managedRPCSecretName(cluster), Namespace: namespace},
		Data:       map[string][]byte{RPCSecretKey: rpcSecretHex},
	}
	reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(rpcSecretObject).Build()}
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/GetKeyInfo":
			switch request.URL.Query().Get("id") {
			case legacyID:
				_ = json.NewEncoder(w).Encode(garage.Key{AccessKeyID: legacyID, SecretAccessKey: legacySecret})
			case canonicalID:
				w.WriteHeader(http.StatusNotFound)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		case "/v2/DeleteKey":
			deleted = append(deleted, request.URL.Query().Get("id"))
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := reconciler.finalize(t.Context(), key, cluster, garage.NewClient(server.URL, "token")); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != legacyID {
		t.Fatalf("deleted key IDs = %v, want exact legacy ID %q", deleted, legacyID)
	}
}

func TestGarageKeyStatuslessCanonicalFinalizationRequiresExactSecret(t *testing.T) {
	const namespace = "tenant"
	rpcSecretHex := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rpcSecret, err := hex.DecodeString(string(rpcSecretHex))
	if err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{Name: "canonical-key", Namespace: namespace}}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: namespace}}
	canonicalID, canonicalSecret := deriveKeyMaterial(rpcSecret, namespace, deterministicKeyName(key))

	for _, test := range []struct {
		name       string
		lookupCode int
		secret     string
		wantDelete bool
		wantError  bool
	}{
		{name: "exact material", lookupCode: http.StatusOK, secret: canonicalSecret, wantDelete: true},
		{name: "already absent", lookupCode: http.StatusNotFound},
		{name: "foreign same ID", lookupCode: http.StatusOK, secret: "foreign-secret", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			scheme := finalizationIdentityScheme(t)
			rpcSecretObject := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: managedRPCSecretName(cluster), Namespace: namespace},
				Data:       map[string][]byte{RPCSecretKey: rpcSecretHex},
			}
			reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(rpcSecretObject).Build()}
			var deleted []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v2/GetKeyInfo":
					if request.URL.Query().Get("id") != canonicalID {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if test.lookupCode == http.StatusNotFound {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_ = json.NewEncoder(w).Encode(garage.Key{AccessKeyID: canonicalID, SecretAccessKey: test.secret})
				case "/v2/DeleteKey":
					deleted = append(deleted, request.URL.Query().Get("id"))
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			err := reconciler.finalize(t.Context(), key.DeepCopy(), cluster, garage.NewClient(server.URL, "token"))
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "different secret material") {
					t.Fatalf("finalize error = %v, want secret-material refusal", err)
				}
			} else if err != nil {
				t.Fatalf("finalize: %v", err)
			}
			if test.wantDelete {
				if len(deleted) != 1 || deleted[0] != canonicalID {
					t.Fatalf("deleted IDs = %v, want %q", deleted, canonicalID)
				}
			} else if len(deleted) != 0 {
				t.Fatalf("deleted foreign or absent key IDs: %v", deleted)
			}
		})
	}
}

func TestGarageKeyFinalizationRejectsAnnotationOnlyIdentity(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteKey", "GKvictim")
	defer server.Close()
	key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{
		Name: "key", Namespace: testNamespace,
		Annotations: map[string]string{keyResolvedImportIDAnnotation: "GKvictim"},
	}}
	reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(finalizationIdentityScheme(t)).Build()}

	err := reconciler.finalize(t.Context(), key, nil, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "no authoritative") {
		t.Fatalf("annotation-only finalization error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("DeleteKey calls = %d, want zero", calls.Load())
	}
}

func TestGarageKeyFinalizationRejectsCOSIAnnotationOnlyIdentity(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteKey", "GKvictim")
	defer server.Close()
	key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{
		Name: "cosi-key", Namespace: testNamespace,
		Annotations: map[string]string{garagev1beta1.AnnotationCOSIAccountID: "GKvictim"},
	}}
	reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(finalizationIdentityScheme(t)).Build()}

	err := reconciler.finalize(t.Context(), key, nil, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "no controller-owned status") {
		t.Fatalf("COSI annotation-only finalization error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Garage calls = %d, want zero", calls.Load())
	}
}

func TestGarageKeyFinalizationRejectsMutableSourceAsSoleIdentity(t *testing.T) {
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			SecretRef: &corev1.SecretReference{Name: "mutable-source"},
		}},
	}
	reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(finalizationIdentityScheme(t)).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mutable-source", Namespace: testNamespace}, Data: map[string][]byte{
			defaultAccessKeyIDKey: []byte("GKvictim"),
		}},
	).Build()}

	_, err := reconciler.garageKeyFinalizationID(t.Context(), key, nil)
	if err == nil || !strings.Contains(err.Error(), "mutable source Secret") {
		t.Fatalf("mutable-source finalization error = %v", err)
	}
}

func TestGarageKeyFinalizationDisagreementFailsClosed(t *testing.T) {
	server, calls := exactDeleteServer(t, "/v2/DeleteKey", "must-not-delete")
	defer server.Close()
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "key",
			Namespace:   testNamespace,
			Annotations: map[string]string{garagev1beta1.AnnotationCOSIAccountID: "GKcosiid"},
		},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			AccessKeyID: "GKimportid", SecretAccessKey: "secret",
		}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: "GKstatusid"},
	}
	reconciler := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(finalizationIdentityScheme(t)).Build()}

	err := reconciler.finalize(context.Background(), key, nil, garage.NewClient(server.URL, "token"))
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("finalize error = %v, want identity disagreement", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("DeleteKey calls = %d, want 0", calls.Load())
	}
}

func finalizationRetryClient(
	t *testing.T,
	objects []client.Object,
) (client.Client, *atomic.Int32) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}, &garagev1beta1.GarageKey{})
	for _, object := range objects {
		builder = builder.WithObjects(object)
	}
	base := builder.Build()
	var statusUpdates atomic.Int32
	wrapped := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, object client.Object, opts ...client.SubResourceUpdateOption) error {
			if subResourceName == "status" && statusUpdates.Add(1) == 1 {
				return apierrors.NewConflict(schema.GroupResource{
					Group: garagev1beta1.GroupVersion.Group, Resource: "finalization-test",
				}, object.GetName(), fmt.Errorf("injected status conflict"))
			}
			return c.Status().Update(ctx, object, opts...)
		},
	})
	return wrapped, &statusUpdates
}

func failingFinalizationServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`finalization failed`))
	}))
}

func finalizationRetryHandle(endpoint string) (*garagev1beta2.GarageCluster, *corev1.Secret) {
	return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "handle", Namespace: "garage", UID: "handle-uid"},
			Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: endpoint,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token",
				},
			}},
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: "garage"},
			Data:       map[string][]byte{"token": []byte("prefix.secret")},
		}
}

func TestGarageBucketFinalizationRetryAnnotationSurvivesStatusConflict(t *testing.T) {
	server := failingFinalizationServer()
	defer server.Close()
	handle, secret := finalizationRetryHandle(server.URL)
	now := metav1.Now()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bucket", Namespace: "tenant", Finalizers: []string{garageBucketFinalizer}, DeletionTimestamp: &now,
			Annotations: map[string]string{FinalizationRetryAnnotation: "5"},
		},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: handle.Name, Namespace: handle.Namespace,
		}},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "bucket-id"},
	}
	wrapped, statusUpdates := finalizationRetryClient(t, []client.Object{handle, secret, bucket})
	reconciler := &GarageBucketReconciler{Client: wrapped, Scheme: wrapped.Scheme()}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	if err != nil || result.RequeueAfter != RequeueAfterError {
		t.Fatalf("Reconcile result=%+v err=%v, want finalization retry", result, err)
	}
	fresh := &garagev1beta1.GarageBucket{}
	if err := wrapped.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if got := fresh.Annotations[FinalizationRetryAnnotation]; got != "6" {
		t.Fatalf("retry annotation = %q, want 6", got)
	}
	if !controllerutil.ContainsFinalizer(fresh, garageBucketFinalizer) {
		t.Fatal("bucket cleanup finalizer was abandoned after repeated failures")
	}
	if statusUpdates.Load() != 2 {
		t.Fatalf("status updates = %d, want conflict plus retry", statusUpdates.Load())
	}
}

func TestGarageBucketRetainFinalizationDoesNotNeedCluster(t *testing.T) {
	now := metav1.Now()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "retained", Namespace: "tenant", UID: "retained-uid",
			Finalizers:        []string{garageBucketFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:     garagev1beta1.ClusterReference{Name: "missing-cluster"},
			DeletionPolicy: garagev1beta1.BucketDeletionPolicyRetain,
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "retained-bucket-id"},
	}
	scheme := finalizationIdentityScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket).Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	if err != nil || result != (reconcile.Result{}) {
		t.Fatalf("Reconcile result=%+v err=%v, want immediate retention", result, err)
	}
	fresh := &garagev1beta1.GarageBucket{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); !apierrors.IsNotFound(err) {
		t.Fatalf("retained bucket lookup error = %v, want object removed after finalizer release", err)
	}
}

func TestGarageKeyFinalizationRetryAnnotationSurvivesStatusConflict(t *testing.T) {
	server := failingFinalizationServer()
	defer server.Close()
	handle, secret := finalizationRetryHandle(server.URL)
	now := metav1.Now()
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "key", Namespace: "tenant", Finalizers: []string{garageKeyFinalizer}, DeletionTimestamp: &now,
			Annotations: map[string]string{FinalizationRetryAnnotation: "5"},
		},
		Spec: garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: handle.Name, Namespace: handle.Namespace,
		}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: "GKexact"},
	}
	wrapped, statusUpdates := finalizationRetryClient(t, []client.Object{handle, secret, key})
	reconciler := &GarageKeyReconciler{Client: wrapped, Scheme: wrapped.Scheme()}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: key.Name, Namespace: key.Namespace}})
	if err != nil || result.RequeueAfter != RequeueAfterError {
		t.Fatalf("Reconcile result=%+v err=%v, want finalization retry", result, err)
	}
	fresh := &garagev1beta1.GarageKey{}
	if err := wrapped.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
		t.Fatalf("get key: %v", err)
	}
	if got := fresh.Annotations[FinalizationRetryAnnotation]; got != "6" {
		t.Fatalf("retry annotation = %q, want 6", got)
	}
	if !controllerutil.ContainsFinalizer(fresh, garageKeyFinalizer) {
		t.Fatal("key cleanup finalizer was abandoned after repeated failures")
	}
	if statusUpdates.Load() != 2 {
		t.Fatalf("status updates = %d, want conflict plus retry", statusUpdates.Load())
	}
}
