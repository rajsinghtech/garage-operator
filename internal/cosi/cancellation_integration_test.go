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

package cosi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/cosi"
)

const (
	cancellationDriver    = "garage.example.com"
	cancellationNamespace = "garage-system"
	cancellationCluster   = "management-handle"
)

func cancellationScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, cosiv1alpha2.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("add scheme: %v", err)
		}
	}
	return scheme
}

func cancellationHandle(endpoint string) (*garagev1beta2.GarageCluster, *corev1.Secret) {
	return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: cancellationCluster, Namespace: cancellationNamespace, UID: "handle-uid"},
			Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint: endpoint,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token",
				},
			}},
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: cancellationNamespace},
			Data:       map[string][]byte{"token": []byte("prefix.secret")},
		}
}

func TestPendingCOSIParentCancellationWaitsForExactRemoteCleanup(t *testing.T) {
	const (
		bucketName = "pending-bucket"
		accessName = "pending-access"
		bucketID   = "bucket-created-before-bind"
		accountID  = "GKimportedbeforebind"
	)
	var alias string
	var bucketDeletes atomic.Int32
	var bucketLookups atomic.Int32
	var keyDeletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v2/GetBucketInfo":
			bucketLookups.Add(1)
			if request.URL.Query().Get("globalAlias") != alias {
				t.Errorf("bucket lookup alias = %q, want %q", request.URL.Query().Get("globalAlias"), alias)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"id":%q,"globalAliases":[%q]}`, bucketID, alias)
		case request.Method == http.MethodPost && request.URL.Path == "/v2/DeleteBucket":
			if request.URL.Query().Get("id") != bucketID {
				t.Errorf("bucket delete ID = %q, want %q", request.URL.Query().Get("id"), bucketID)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			bucketDeletes.Add(1)
			_, _ = w.Write([]byte(`{}`))
		case request.Method == http.MethodPost && request.URL.Path == "/v2/DeleteKey":
			if request.URL.Query().Get("id") != accountID {
				t.Errorf("key delete ID = %q, want %q", request.URL.Query().Get("id"), accountID)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			keyDeletes.Add(1)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected Garage request: %s %s", request.Method, request.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	now := metav1.Now()
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: bucketName, Finalizers: []string{cosi.GarageProtectionFinalizer}, DeletionTimestamp: &now,
		},
		Spec: cosiv1alpha2.BucketSpec{DriverName: cancellationDriver},
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: accessName, Namespace: "default", UID: "pending-access-uid",
			Finalizers:        []string{cosiv1alpha2.ProtectionFinalizer, cosi.GarageProtectionFinalizer},
			DeletionTimestamp: &now,
		},
		Status: cosiv1alpha2.BucketAccessStatus{DriverName: cancellationDriver},
	}
	handle, token := cancellationHandle(server.URL)
	k8sClient := newCOSIClientBuilder().WithScheme(cancellationScheme(t)).WithObjects(handle, token, bucket, access).Build()
	// Model the exact production race: the upstream controller finishes its
	// bookkeeping and removes the shared COSI finalizer before our reconciler
	// handles deletion. The Garage-owned finalizer must still retain the parent.
	upstreamReleased := &cosiv1alpha2.BucketAccess{}
	accessKey := types.NamespacedName{Name: accessName, Namespace: "default"}
	if err := k8sClient.Get(t.Context(), accessKey, upstreamReleased); err != nil {
		t.Fatalf("get access before upstream finalizer release: %v", err)
	}
	upstreamReleased.Finalizers = []string{cosi.GarageProtectionFinalizer}
	if err := k8sClient.Update(t.Context(), upstreamReleased); err != nil {
		t.Fatalf("simulate upstream finalizer release: %v", err)
	}
	shadowManager := cosi.NewShadowManager(k8sClient, cancellationNamespace)
	shadowBucket, _, err := shadowManager.ReserveShadowBucket(t.Context(), bucketName, cancellationCluster, cancellationNamespace, nil)
	if err != nil {
		t.Fatalf("reserve shadow bucket: %v", err)
	}
	alias, err = garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", shadowBucket.Namespace, shadowBucket.Name, shadowBucket.UID)
	if err != nil {
		t.Fatalf("derive shadow bucket alias: %v", err)
	}
	if err := shadowManager.AuthorizeShadowBucketCreate(t.Context(), shadowBucket, alias); err != nil {
		t.Fatalf("authorize shadow bucket: %v", err)
	}
	shadowKey, _, err := shadowManager.ReserveShadowKey(t.Context(), accessName, cancellationCluster, cancellationNamespace, nil, "")
	if err != nil {
		t.Fatalf("reserve shadow key: %v", err)
	}
	if err := shadowManager.SetShadowKeyReservationID(t.Context(), shadowKey, accountID); err != nil {
		t.Fatalf("set shadow key reservation ID: %v", err)
	}

	provisioner := cosi.NewProvisionerWithFactory(k8sClient, cancellationNamespace,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (cosi.GarageClient, error) {
			return nil, fmt.Errorf("Garage factory must not be called by name-based cancellation")
		})
	bucketReconciler := &cosi.BucketReconciler{
		Client: k8sClient, Scheme: k8sClient.Scheme(), DriverName: cancellationDriver,
		Namespace: cancellationNamespace, Provisioner: provisioner,
	}
	accessReconciler := &cosi.BucketAccessReconciler{
		Client: k8sClient, Scheme: k8sClient.Scheme(), DriverName: cancellationDriver,
		Namespace: cancellationNamespace, Provisioner: provisioner,
	}

	if _, err := bucketReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: bucketName}}); err != nil {
		t.Fatalf("request bucket cancellation: %v", err)
	}
	if _, err := accessReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: accessName, Namespace: "default"}}); err != nil {
		t.Fatalf("request access cancellation: %v", err)
	}
	assertParentFinalizer := func(key types.NamespacedName, object client.Object) {
		t.Helper()
		if err := k8sClient.Get(t.Context(), key, object); err != nil {
			t.Fatalf("parent disappeared before remote cleanup: %v", err)
		}
		for _, finalizer := range object.GetFinalizers() {
			if finalizer == cosi.GarageProtectionFinalizer {
				return
			}
		}
		t.Fatalf("parent %s released protection finalizer before remote cleanup", key)
	}
	assertParentFinalizer(types.NamespacedName{Name: bucketName}, &cosiv1alpha2.Bucket{})
	assertParentFinalizer(types.NamespacedName{Name: accessName, Namespace: "default"}, &cosiv1alpha2.BucketAccess{})
	if bucketDeletes.Load() != 0 || keyDeletes.Load() != 0 {
		t.Fatal("COSI parent cancellation must delegate remote deletion to shadow finalizers")
	}

	garageBucketReconciler := &controller.GarageBucketReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), ClusterDomain: "cluster.local"}
	garageKeyReconciler := &controller.GarageKeyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), ClusterDomain: "cluster.local"}
	shadowBucketRequest := reconcile.Request{NamespacedName: types.NamespacedName{
		Name: cosi.ShadowResourceName(bucketName), Namespace: cancellationNamespace,
	}}
	shadowKeyRequest := reconcile.Request{NamespacedName: types.NamespacedName{
		Name: cosi.ShadowResourceName(accessName), Namespace: cancellationNamespace,
	}}

	// If the management handle disappears during cancellation, the ordinary
	// shadow controllers must retain both remote identities and their finalizers.
	// The COSI parents remain protected until restoring the same cluster name lets
	// exact remote cleanup resume.
	persistedHandle := &garagev1beta2.GarageCluster{}
	if err := k8sClient.Get(t.Context(), client.ObjectKeyFromObject(handle), persistedHandle); err != nil {
		t.Fatalf("get management handle before disappearance: %v", err)
	}
	if err := k8sClient.Delete(t.Context(), persistedHandle); err != nil {
		t.Fatalf("remove management handle during cancellation: %v", err)
	}
	if _, err := garageBucketReconciler.Reconcile(t.Context(), shadowBucketRequest); err != nil {
		t.Fatalf("reconcile pending bucket shadow with missing cluster: %v", err)
	}
	if _, err := garageKeyReconciler.Reconcile(t.Context(), shadowKeyRequest); err != nil {
		t.Fatalf("reconcile pending key shadow with missing cluster: %v", err)
	}
	assertShadowRetained := func(key types.NamespacedName, object client.Object) {
		t.Helper()
		if err := k8sClient.Get(t.Context(), key, object); err != nil {
			t.Fatalf("pending shadow disappeared with missing cluster: %v", err)
		}
		if len(object.GetFinalizers()) == 0 {
			t.Fatalf("pending shadow %s lost its cleanup finalizer with missing cluster", key)
		}
	}
	assertShadowRetained(shadowBucketRequest.NamespacedName, &garagev1beta1.GarageBucket{})
	assertShadowRetained(shadowKeyRequest.NamespacedName, &garagev1beta1.GarageKey{})
	if _, err := bucketReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: bucketName}}); err != nil {
		t.Fatalf("recheck bucket cancellation with missing cluster: %v", err)
	}
	if _, err := accessReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: accessName, Namespace: "default"}}); err != nil {
		t.Fatalf("recheck access cancellation with missing cluster: %v", err)
	}
	assertParentFinalizer(types.NamespacedName{Name: bucketName}, &cosiv1alpha2.Bucket{})
	assertParentFinalizer(types.NamespacedName{Name: accessName, Namespace: "default"}, &cosiv1alpha2.BucketAccess{})
	if bucketDeletes.Load() != 0 || keyDeletes.Load() != 0 {
		t.Fatal("missing management handle must not discard or remotely mutate pending identities")
	}
	restoredHandle, _ := cancellationHandle(server.URL)
	restoredHandle.UID = "restored-handle-uid"
	if err := k8sClient.Create(t.Context(), restoredHandle); err != nil {
		t.Fatalf("restore management handle: %v", err)
	}

	// The ordinary controller may first persist a same-namespace cluster owner
	// reference and requeue before entering finalization.
	for i := 0; i < 3 && bucketDeletes.Load() == 0; i++ {
		if _, err := garageBucketReconciler.Reconcile(t.Context(), shadowBucketRequest); err != nil {
			t.Fatalf("finalize shadow bucket: %v", err)
		}
	}
	if _, err := garageKeyReconciler.Reconcile(t.Context(), shadowKeyRequest); err != nil {
		t.Fatalf("finalize shadow key: %v", err)
	}
	if bucketDeletes.Load() != 1 || keyDeletes.Load() != 1 {
		t.Fatalf("exact remote delete calls bucket=%d lookup=%d key=%d, want 1 each",
			bucketDeletes.Load(), bucketLookups.Load(), keyDeletes.Load())
	}

	if _, err := bucketReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: bucketName}}); err != nil {
		t.Fatalf("finish bucket cancellation: %v", err)
	}
	if _, err := accessReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: accessName, Namespace: "default"}}); err != nil {
		t.Fatalf("finish access cancellation: %v", err)
	}
	if err := k8sClient.Get(t.Context(), types.NamespacedName{Name: bucketName}, &cosiv1alpha2.Bucket{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Bucket remains after exact remote cleanup: %v", err)
	}
	if err := k8sClient.Get(t.Context(), types.NamespacedName{Name: accessName, Namespace: "default"}, &cosiv1alpha2.BucketAccess{}); !apierrors.IsNotFound(err) {
		t.Fatalf("BucketAccess remains after exact remote cleanup: %v", err)
	}
}

func TestCOSIBucketRetainForgetsShadowWithoutRemoteDeletion(t *testing.T) {
	for _, test := range []struct {
		name  string
		bound bool
	}{
		{name: "bound shadow", bound: true},
		{name: "remote-created pending shadow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const bucketName = "retained-bucket"
			now := metav1.Now()
			bucket := &cosiv1alpha2.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					Name: bucketName, Finalizers: []string{cosi.GarageProtectionFinalizer}, DeletionTimestamp: &now,
				},
				Spec: cosiv1alpha2.BucketSpec{
					DriverName: cancellationDriver, DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyRetain,
				},
			}
			if test.bound {
				bucket.Status.BucketID = "retained-exact-id"
			}
			k8sClient := newCOSIClientBuilder().WithScheme(cancellationScheme(t)).WithObjects(bucket).Build()
			shadowManager := cosi.NewShadowManager(k8sClient, cancellationNamespace)
			shadow, _, err := shadowManager.ReserveShadowBucket(t.Context(), bucketName, cancellationCluster, cancellationNamespace, nil)
			if err != nil {
				t.Fatalf("reserve shadow: %v", err)
			}
			if test.bound {
				if _, err := shadowManager.BindShadowBucket(t.Context(), shadow, "retained-exact-id", nil); err != nil {
					t.Fatalf("bind shadow: %v", err)
				}
			} else {
				alias, err := garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", shadow.Namespace, shadow.Name, shadow.UID)
				if err != nil {
					t.Fatalf("derive pending reservation: %v", err)
				}
				if err := shadowManager.AuthorizeShadowBucketCreate(t.Context(), shadow, alias); err != nil {
					t.Fatalf("authorize pending shadow: %v", err)
				}
			}

			factoryCalled := false
			provisioner := cosi.NewProvisionerWithFactory(k8sClient, cancellationNamespace,
				func(context.Context, client.Client, *garagev1beta2.GarageCluster) (cosi.GarageClient, error) {
					factoryCalled = true
					return nil, fmt.Errorf("Garage factory must not be called for Retain")
				})
			reconciler := &cosi.BucketReconciler{
				Client: k8sClient, Scheme: k8sClient.Scheme(), DriverName: cancellationDriver,
				Namespace: cancellationNamespace, Provisioner: provisioner,
			}
			if _, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: bucketName}}); err != nil {
				t.Fatalf("request retained shadow deletion: %v", err)
			}
			if factoryCalled {
				t.Fatal("Retain contacted Garage")
			}
			persistedShadow := &garagev1beta1.GarageBucket{}
			shadowKey := types.NamespacedName{Name: cosi.ShadowResourceName(bucketName), Namespace: cancellationNamespace}
			if err := k8sClient.Get(t.Context(), shadowKey, persistedShadow); err != nil {
				t.Fatalf("retained shadow disappeared before its marker was verified: %v", err)
			}
			if persistedShadow.DeletionTimestamp.IsZero() || len(persistedShadow.Finalizers) == 0 ||
				persistedShadow.Annotations[garagev1beta1.AnnotationCOSIRetain] == "" {
				t.Fatalf("retained shadow lacks durable deletion protocol: %+v", persistedShadow.ObjectMeta)
			}
			garageBucketReconciler := &controller.GarageBucketReconciler{
				Client: k8sClient, Scheme: k8sClient.Scheme(), ClusterDomain: "cluster.local",
				COSIDriverName: cancellationDriver,
			}
			if _, err := garageBucketReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: shadowKey}); err != nil {
				t.Fatalf("verify retained shadow marker: %v", err)
			}
			if _, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: bucketName}}); err != nil {
				t.Fatalf("finish retained Bucket deletion: %v", err)
			}
			if err := k8sClient.Get(t.Context(), types.NamespacedName{Name: bucketName}, &cosiv1alpha2.Bucket{}); !apierrors.IsNotFound(err) {
				t.Fatalf("retained COSI Bucket remains: %v", err)
			}
			if err := k8sClient.Get(t.Context(), shadowKey, &garagev1beta1.GarageBucket{}); !apierrors.IsNotFound(err) {
				t.Fatalf("retained internal shadow remains: %v", err)
			}
		})
	}
}
