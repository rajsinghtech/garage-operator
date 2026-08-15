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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testNamespace          = "default"
	testGarageKeyName      = "key"
	testAllowBucketKeyPath = "/v2/AllowBucketKey"
	testDenyBucketKeyPath  = "/v2/DenyBucketKey"
	testGetBucketInfoPath  = "/v2/GetBucketInfo"
	testRemoveAliasPath    = "/v2/RemoveBucketAlias"
	testOldGlobalAlias     = "old-global"
	testOldLocalAlias      = "old-local"
	testOldAlias           = "old"
)

// testBucketID is a throwaway bucket id used by the timeout tests where the
// upstream admin API call never returns or is mocked out before responding.
const testBucketID = "abc"

var _ = Describe("GarageBucket Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-bucket"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup the GarageBucket
			bucket := &garagev1beta1.GarageBucket{}
			err := k8sClient.Get(ctx, typeNamespacedName, bucket)
			if err == nil {
				bucket.Finalizers = nil
				_ = k8sClient.Update(ctx, bucket)
				_ = k8sClient.Delete(ctx, bucket)
			}
		})

		It("should set error status when cluster doesn't exist", func() {
			By("Creating a GarageBucket referencing non-existent cluster")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: "non-existent-cluster",
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Reconciling the GarageBucket")
			reconciler := &GarageBucketReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			// Controller returns requeue result, not error, when cluster not found
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Verifying status phase is Pending (cluster not found is transient)")
			updatedBucket := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedBucket)).To(Succeed())
			Expect(updatedBucket.Status.Phase).To(Equal(PhasePending))
		})

		It("should handle bucket creation spec with quotas", func() {
			By("Creating a GarageBucket with quotas")
			maxSize := resource.MustParse("10Gi")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Quotas: &garagev1beta1.BucketQuotas{
						MaxSize:    &maxSize,
						MaxObjects: int64Ptr(1000),
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket spec was stored correctly")
			createdBucket := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.Quotas).NotTo(BeNil())
			Expect(createdBucket.Spec.Quotas.MaxSize.String()).To(Equal("10Gi"))
			Expect(*createdBucket.Spec.Quotas.MaxObjects).To(Equal(int64(1000)))
		})

		It("should handle bucket with website config", func() {
			By("Creating a GarageBucket with website hosting")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Website: &garagev1beta1.WebsiteConfig{
						Enabled:       ptr.To(true),
						IndexDocument: "index.html",
						ErrorDocument: "error.html",
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket was created")
			createdBucket := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.Website).NotTo(BeNil())
			Expect(createdBucket.Spec.Website.IndexDocument).To(Equal("index.html"))
		})

		It("should store lifecycle rules on spec", func() {
			By("Creating a GarageBucket with a lifecycle rule")
			expDays := int32(7)
			abortDays := int32(3)
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Lifecycle: &garagev1beta1.BucketLifecycle{
						Rules: []garagev1beta1.LifecycleRule{
							{
								ID:                                 "expire-logs",
								Status:                             "Enabled",
								ExpirationDays:                     &expDays,
								AbortIncompleteMultipartUploadDays: &abortDays,
								Filter: &garagev1beta1.LifecycleFilter{
									Prefix: "logs/",
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying lifecycle was stored")
			created := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, created)).To(Succeed())
			Expect(created.Spec.Lifecycle).NotTo(BeNil())
			Expect(created.Spec.Lifecycle.Rules).To(HaveLen(1))
			Expect(created.Spec.Lifecycle.Rules[0].ID).To(Equal("expire-logs"))
			Expect(*created.Spec.Lifecycle.Rules[0].ExpirationDays).To(Equal(int32(7)))
			Expect(*created.Spec.Lifecycle.Rules[0].AbortIncompleteMultipartUploadDays).To(Equal(int32(3)))
			Expect(created.Spec.Lifecycle.Rules[0].Filter.Prefix).To(Equal("logs/"))
		})

		It("should bail out when the referenced cluster is being deleted", func() {
			By("Creating a GarageCluster with a finalizer, then marking it for deletion")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "deleting-cluster",
					Namespace:  testNamespace,
					Finalizers: []string{"test.garage.rajsingh.info/keep"},
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{},
						Data:     &garagev1beta2.VolumeConfig{},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() {
				fresh := &garagev1beta2.GarageCluster{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, fresh); err == nil {
					fresh.Finalizers = nil
					_ = k8sClient.Update(ctx, fresh)
					_ = k8sClient.Delete(ctx, fresh)
				}
			})
			Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())

			By("Creating a GarageBucket targeting the deleting cluster")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Reconciling")
			reconciler := &GarageBucketReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Verifying the reconciler bailed out with ClusterDeleting before calling Garage")
			updated := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(PhasePending))
			ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(ready).NotTo(BeNil())
			Expect(ready.Reason).To(Equal(garagev1beta1.ReasonClusterDeleting))
			Expect(ready.Message).To(ContainSubstring("being deleted"))
		})

		It("should handle bucket with key permissions", func() {
			By("Creating a GarageBucket with key permissions")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					KeyPermissions: []garagev1beta1.KeyPermission{
						{
							KeyRef: garagev1beta1.KeyRef{Name: "test-key"},
							Read:   true,
							Write:  true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket was created with permissions")
			createdBucket := &garagev1beta1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.KeyPermissions).To(HaveLen(1))
			Expect(createdBucket.Spec.KeyPermissions[0].KeyRef).To(Equal(garagev1beta1.KeyRef{Name: "test-key"}))
		})
	})

	Context("When reconciling a non-existent GarageBucket", func() {
		It("should return without error", func() {
			reconciler := &GarageBucketReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: testNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When deleting a GarageBucket", func() {
		const resourceName = "test-bucket-delete"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup
			bucket := &garagev1beta1.GarageBucket{}
			err := k8sClient.Get(ctx, typeNamespacedName, bucket)
			if err == nil {
				bucket.Finalizers = nil
				_ = k8sClient.Update(ctx, bucket)
				_ = k8sClient.Delete(ctx, bucket)
			}
		})

		It("should handle deletion request gracefully", func() {
			By("Creating the GarageBucket resource")
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Deleting the bucket")
			Expect(k8sClient.Delete(ctx, bucket)).To(Succeed())

			By("Reconciling after deletion request")
			reconciler := &GarageBucketReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			By("Verifying the bucket is deleted or has deletion timestamp")
			finalBucket := &garagev1beta1.GarageBucket{}
			err := k8sClient.Get(ctx, typeNamespacedName, finalBucket)
			if err == nil {
				// Bucket still exists - should have deletion timestamp if no finalizer was added
				Expect(finalBucket.DeletionTimestamp).NotTo(BeNil())
			} else {
				// Bucket was deleted
				Expect(errors.IsNotFound(err)).To(BeTrue())
			}
		})
	})
})

func int64Ptr(i int64) *int64 {
	return &i
}

// TestReconcileKeyPermissions_RevokesDroppedAndSkipsUnchanged drives
// reconcileKeyPermissions against a mock Garage admin server and asserts the
// churn short-circuit (no AllowBucketKey when current perms already match) and
// the dangling-grant revoke (DenyBucketKey only for IDs we previously granted
// that are dropped from the spec), without touching grants the operator never
// made.
func TestReconcileKeyPermissions_RevokesDroppedAndSkipsUnchanged(t *testing.T) {
	const (
		testKeyA = "key-a"
		keyAID   = "GKaaaaaaaaaaaaaaaaaaaaaa"
		keyBID   = "GKbbbbbbbbbbbbbbbbbbbbbb"
		keyCID   = "GKcccccccccccccccccccccc"
		bktID    = "0123456789abcdef0123456789abcdef"
	)

	// newKey builds a GarageKey CR with its AccessKeyID resolved in status.
	newKey := func(name, accessKeyID string) *garagev1beta1.GarageKey {
		return &garagev1beta1.GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName}},
			Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: accessKeyID},
		}
	}

	// newReconciler wires a fake client holding the keys + bucket and a mock
	// admin server recording Allow/Deny calls.
	newReconciler := func(t *testing.T, bucket *garagev1beta1.GarageBucket, keys ...*garagev1beta1.GarageKey) (*GarageBucketReconciler, *garage.Client, *[]garage.AllowBucketKeyRequest, *[]garage.DenyBucketKeyRequest, func()) {
		t.Helper()
		s := runtime.NewScheme()
		if err := garagev1beta1.AddToScheme(s); err != nil {
			t.Fatalf("AddToScheme v1beta1: %v", err)
		}
		if err := garagev1beta2.AddToScheme(s); err != nil {
			t.Fatalf("AddToScheme v1beta2: %v", err)
		}
		objs := make([]client.Object, 0, 1+len(keys))
		objs = append(objs, bucket)
		for _, k := range keys {
			objs = append(objs, k)
		}
		fc := fake.NewClientBuilder().
			WithScheme(s).
			WithObjects(objs...).
			WithStatusSubresource(&garagev1beta1.GarageBucket{}).
			Build()
		r := &GarageBucketReconciler{Client: fc, Scheme: s}

		var allowCalls []garage.AllowBucketKeyRequest
		var denyCalls []garage.DenyBucketKeyRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case testAllowBucketKeyPath:
				var body garage.AllowBucketKeyRequest
				_ = json.NewDecoder(req.Body).Decode(&body)
				allowCalls = append(allowCalls, body)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			case testDenyBucketKeyPath:
				var body garage.DenyBucketKeyRequest
				_ = json.NewDecoder(req.Body).Decode(&body)
				denyCalls = append(denyCalls, body)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		gc := garage.NewClient(srv.URL, "tok")
		return r, gc, &allowCalls, &denyCalls, srv.Close
	}

	bucketWithKeyPerms := func(name string, perms ...garagev1beta1.KeyPermission) *garagev1beta1.GarageBucket {
		return &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: garagev1beta1.GarageBucketSpec{
				ClusterRef:     garagev1beta1.ClusterReference{Name: testClusterName},
				KeyPermissions: perms,
			},
		}
	}

	t.Run("skips AllowBucketKey when current perms already match", func(t *testing.T) {
		ctx := context.Background()
		bucket := bucketWithKeyPerms("bkt-skip",
			garagev1beta1.KeyPermission{KeyRef: garagev1beta1.KeyRef{Name: testKeyA}, Read: true, Write: true})
		r, gc, allow, deny, stop := newReconciler(t, bucket, newKey(testKeyA, keyAID))
		defer stop()

		existing := &garage.Bucket{
			ID:   bktID,
			Keys: []garage.BucketKeyInfo{{AccessKeyID: keyAID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}}},
		}
		if err := r.reconcileKeyPermissions(ctx, bucket, gc, existing); err != nil {
			t.Fatalf("reconcileKeyPermissions: %v", err)
		}
		if len(*allow) != 0 {
			t.Errorf("expected 0 AllowBucketKey calls, got %d: %+v", len(*allow), *allow)
		}
		if len(*deny) != 0 {
			t.Errorf("expected 0 DenyBucketKey calls, got %d: %+v", len(*deny), *deny)
		}

		fresh := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: testNamespace}, fresh); err != nil {
			t.Fatalf("get bucket: %v", err)
		}
		if want := []string{keyAID}; !stringSlicesEqual(fresh.Status.ManagedKeyGrants, want) {
			t.Errorf("ManagedKeyGrants=%v, want %v", fresh.Status.ManagedKeyGrants, want)
		}
	})

	t.Run("issues AllowBucketKey when perms differ", func(t *testing.T) {
		ctx := context.Background()
		bucket := bucketWithKeyPerms("bkt-allow",
			garagev1beta1.KeyPermission{KeyRef: garagev1beta1.KeyRef{Name: testKeyA}, Read: true, Write: true})
		r, gc, allow, deny, stop := newReconciler(t, bucket, newKey(testKeyA, keyAID))
		defer stop()

		existing := &garage.Bucket{
			ID:   bktID,
			Keys: []garage.BucketKeyInfo{{AccessKeyID: keyAID, Permissions: garage.BucketKeyPerms{Read: true}}},
		}
		if err := r.reconcileKeyPermissions(ctx, bucket, gc, existing); err != nil {
			t.Fatalf("reconcileKeyPermissions: %v", err)
		}
		if len(*allow) != 1 {
			t.Fatalf("expected 1 AllowBucketKey call, got %d: %+v", len(*allow), *allow)
		}
		got := (*allow)[0]
		if got.AccessKeyID != keyAID || got.BucketID != bktID {
			t.Errorf("AllowBucketKey target=%+v, want bucket=%s key=%s", got, bktID, keyAID)
		}
		if want := (garage.BucketKeyPerms{Write: true}); got.Permissions != want {
			t.Errorf("AllowBucketKey perms=%+v, want %+v", got.Permissions, want)
		}
		if len(*deny) != 0 {
			t.Errorf("expected 0 DenyBucketKey calls, got %d", len(*deny))
		}

		fresh := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: testNamespace}, fresh); err != nil {
			t.Fatalf("get bucket: %v", err)
		}
		if want := []string{keyAID}; !stringSlicesEqual(fresh.Status.ManagedKeyGrants, want) {
			t.Errorf("ManagedKeyGrants=%v, want %v", fresh.Status.ManagedKeyGrants, want)
		}
	})

	t.Run("revokes a grant dropped from the spec", func(t *testing.T) {
		ctx := context.Background()
		bucket := bucketWithKeyPerms("bkt-revoke",
			garagev1beta1.KeyPermission{KeyRef: garagev1beta1.KeyRef{Name: testKeyA}, Read: true, Write: true})
		// keyA previously granted by us; keyB previously granted by us (now dropped);
		// keyC present on the bucket but never managed by this path (e.g. key-side).
		bucket.Status.ManagedKeyGrants = []string{keyAID, keyBID}
		r, gc, allow, deny, stop := newReconciler(t, bucket, newKey(testKeyA, keyAID))
		defer stop()

		existing := &garage.Bucket{
			ID: bktID,
			Keys: []garage.BucketKeyInfo{
				{AccessKeyID: keyAID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
				{AccessKeyID: keyBID, Permissions: garage.BucketKeyPerms{Read: true}},
				{AccessKeyID: keyCID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
			},
		}
		if err := r.reconcileKeyPermissions(ctx, bucket, gc, existing); err != nil {
			t.Fatalf("reconcileKeyPermissions: %v", err)
		}

		// keyA's perms already match — no Allow.
		if len(*allow) != 0 {
			t.Errorf("expected 0 AllowBucketKey calls, got %d: %+v", len(*allow), *allow)
		}
		// Exactly one Deny, for keyB, containing only the currently set bit.
		if len(*deny) != 1 {
			t.Fatalf("expected 1 DenyBucketKey call, got %d: %+v", len(*deny), *deny)
		}
		d := (*deny)[0]
		if d.AccessKeyID != keyBID {
			t.Errorf("DenyBucketKey AccessKeyID=%s, want %s (must not revoke keyA or keyC)", d.AccessKeyID, keyBID)
		}
		if want := (garage.BucketKeyPerms{Read: true}); d.Permissions != want {
			t.Errorf("DenyBucketKey perms=%+v, want %+v", d.Permissions, want)
		}

		fresh := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: testNamespace}, fresh); err != nil {
			t.Fatalf("get bucket: %v", err)
		}
		if want := []string{keyAID}; !stringSlicesEqual(fresh.Status.ManagedKeyGrants, want) {
			t.Errorf("ManagedKeyGrants=%v, want %v", fresh.Status.ManagedKeyGrants, want)
		}
	})

	t.Run("does not revoke a dropped grant still claimed by a GarageKey (no flap-war)", func(t *testing.T) {
		ctx := context.Background()
		bucket := bucketWithKeyPerms("bkt-flapwar",
			garagev1beta1.KeyPermission{KeyRef: garagev1beta1.KeyRef{Name: testKeyA}, Read: true, Write: true})
		// keyB was previously granted by the bucket (in ManagedKeyGrants) and is now
		// dropped from the bucket spec — but a GarageKey still declares keyB on this
		// bucket via spec.bucketPermissions, so we must NOT revoke it (#219 review).
		bucket.Status.ManagedKeyGrants = []string{keyAID, keyBID}

		keyBClaim := &garagev1beta1.GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: "key-b", Namespace: testNamespace},
			Spec: garagev1beta1.GarageKeySpec{
				ClusterRef:        garagev1beta1.ClusterReference{Name: testClusterName},
				BucketPermissions: []garagev1beta1.BucketPermission{{BucketRef: &garagev1beta1.BucketRef{Name: "bkt-flapwar"}, Read: true, Write: true}},
			},
			Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyBID, ManagedBucketGrants: []string{bktID}},
		}
		r, gc, _, deny, stop := newReconciler(t, bucket, newKey(testKeyA, keyAID), keyBClaim)
		defer stop()

		existing := &garage.Bucket{
			ID: bktID,
			Keys: []garage.BucketKeyInfo{
				{AccessKeyID: keyAID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
				{AccessKeyID: keyBID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
			},
		}
		if err := r.reconcileKeyPermissions(ctx, bucket, gc, existing); err != nil {
			t.Fatalf("reconcileKeyPermissions: %v", err)
		}
		if len(*deny) != 0 {
			t.Fatalf("expected 0 DenyBucketKey calls (keyB still claimed by a GarageKey), got %d: %+v", len(*deny), *deny)
		}
	})
}

func TestReconcileKeyPermissions_ExactUnionDowngrade(t *testing.T) {
	const (
		keyID    = "GKunion"
		bucketID = "bucket-union"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "union", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			KeyPermissions: []garagev1beta1.KeyPermission{{
				KeyRef: garagev1beta1.KeyRef{Name: testGarageKeyName}, Read: true,
			}},
		},
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testGarageKeyName, Namespace: testNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketID: bucketID, Write: true,
			}},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID, ManagedBucketGrants: []string{bucketID}},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket, key).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	var allows []garage.AllowBucketKeyRequest
	var denies []garage.DenyBucketKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case testAllowBucketKeyPath:
			var body garage.AllowBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			allows = append(allows, body)
		case testDenyBucketKeyPath:
			var body garage.DenyBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			denies = append(denies, body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	existing := &garage.Bucket{ID: bucketID, Keys: []garage.BucketKeyInfo{{
		AccessKeyID: keyID, Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
	}}}
	if err := r.reconcileKeyPermissions(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), existing); err != nil {
		t.Fatal(err)
	}
	if len(allows) != 0 {
		t.Fatalf("unexpected allow calls: %+v", allows)
	}
	if len(denies) != 1 || denies[0].Permissions != (garage.BucketKeyPerms{Owner: true}) {
		t.Fatalf("denies=%+v, want only Owner downgrade (Read from bucket + Write from key must remain)", denies)
	}
}

func TestReconcileAliases_RemovesOnlyPreviouslyManaged(t *testing.T) {
	const (
		bucketID = "bucket-alias"
		keyID    = "GKalias"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			GlobalAlias:  "new-global",
			LocalAliases: []garagev1beta1.LocalAlias{{KeyRef: testGarageKeyName, Alias: "new-local"}},
		},
		Status: garagev1beta1.GarageBucketStatus{
			ManagedGlobalAlias:  testOldGlobalAlias,
			ManagedLocalAliases: []garagev1beta1.LocalAliasStatus{{KeyID: keyID, Alias: testOldLocalAlias}},
		},
	}
	key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{Name: testGarageKeyName, Namespace: testNamespace}, Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID}}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket, key).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	var adds, removes []garage.RemoveBucketAliasRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body garage.RemoveBucketAliasRequest
		_ = json.NewDecoder(req.Body).Decode(&body)
		switch req.URL.Path {
		case "/v2/AddBucketAlias":
			adds = append(adds, body)
			if body.LocalAlias != "" {
				_, _ = fmt.Fprintf(w, `{"id":%q,"keys":[{"accessKeyId":%q,"name":"alias-key","bucketLocalAliases":[%q]}]}`,
					bucketID, keyID, body.LocalAlias)
				return
			}
		case testRemoveAliasPath:
			removes = append(removes, body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "tok")
	ctx := context.Background()
	if err := r.reconcileGlobalAlias(ctx, bucket, gc, bucketID, "new-global", []string{testOldGlobalAlias, "manual-global"}); err != nil {
		t.Fatal(err)
	}
	currentKeys := []garage.BucketKeyInfo{{AccessKeyID: keyID, BucketLocalAliases: []string{testOldLocalAlias, "manual-local"}}}
	aliasSnapshot, err := r.reconcileLocalAliases(ctx, bucket, gc, bucketID, currentKeys)
	if err != nil {
		t.Fatal(err)
	}
	if aliasSnapshot == nil || !bucketHasLocalAlias(aliasSnapshot.Keys, keyID, "new-local") {
		t.Fatalf("aliasSnapshot=%+v, want authoritative AddBucketAlias response", aliasSnapshot)
	}
	if len(adds) != 2 {
		t.Fatalf("adds=%+v, want new global and local aliases", adds)
	}
	if len(removes) != 2 {
		t.Fatalf("removes=%+v, want old managed global and local aliases", removes)
	}
	for _, call := range removes {
		if call.GlobalAlias == "manual-global" || call.LocalAlias == "manual-local" {
			t.Fatalf("removed unmanaged alias: %+v", call)
		}
	}
	if removes[0].GlobalAlias != testOldGlobalAlias || removes[1].LocalAlias != testOldLocalAlias {
		t.Fatalf("removes=%+v, want only prior managed aliases", removes)
	}
}

func TestUpdateStatusFromGarageUsesAuthoritativeMutationSnapshot(t *testing.T) {
	const (
		bucketID = "bucket-alias-snapshot"
		keyID    = "GKsnapshot"
		alias    = "local-snapshot"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "bucket-alias-snapshot",
			Namespace:  testNamespace,
			Generation: 2,
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}

	var getCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		getCalls.Add(1)
		_, _ = w.Write([]byte(`{"id":"stale","keys":[]}`))
	}))
	defer srv.Close()

	snapshot := &garage.Bucket{
		ID: bucketID,
		Keys: []garage.BucketKeyInfo{{
			AccessKeyID:        keyID,
			Name:               "snapshot-key",
			BucketLocalAliases: []string{alias},
		}},
	}
	if _, err := r.updateStatusFromGarage(
		context.Background(), bucket, garage.NewClient(srv.URL, "tok"),
		&garagev1beta2.GarageCluster{}, snapshot,
	); err != nil {
		t.Fatal(err)
	}
	if got := getCalls.Load(); got != 0 {
		t.Fatalf("GetBucketInfo calls=%d, want 0 when an authoritative mutation snapshot is available", got)
	}

	fresh := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Status.LocalAliases) != 1 ||
		fresh.Status.LocalAliases[0].KeyID != keyID ||
		fresh.Status.LocalAliases[0].KeyName != "snapshot-key" ||
		fresh.Status.LocalAliases[0].Alias != alias {
		t.Fatalf("localAliases=%+v, want exact authoritative alias status", fresh.Status.LocalAliases)
	}
}

// Adopting a bucket whose alias is already live must not write a reservation.
// The reservation records intent before an add; when no add happens there is
// nothing to record, and writing it costs an extra status round trip that the
// handoff below immediately undoes.
func TestReconcileGlobalAlias_AdoptionDoesNotReserve(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	const alias = "adopted-global"
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-adopt", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}

	var adminCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		adminCalls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	before := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, before); err != nil {
		t.Fatal(err)
	}

	if err := r.reconcileGlobalAlias(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "bucket-id", alias, []string{alias}); err != nil {
		t.Fatal(err)
	}

	if n := adminCalls.Load(); n != 0 {
		t.Fatalf("admin API calls=%d, want 0 when the alias is already live", n)
	}
	// Exactly one write: the ownership handoff. A reservation write here would
	// be dead weight, since the alias needed no add.
	after := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, after); err != nil {
		t.Fatal(err)
	}
	writes := mustAtoi(t, after.ResourceVersion) - mustAtoi(t, before.ResourceVersion)
	if writes != 1 {
		t.Fatalf("status writes=%d (rv %s -> %s), want 1 (the ownership handoff only)",
			writes, before.ResourceVersion, after.ResourceVersion)
	}
	if bucket.Status.ManagedGlobalAlias != alias {
		t.Fatalf("managedGlobalAlias=%q, want %q", bucket.Status.ManagedGlobalAlias, alias)
	}
	if bucket.Status.PendingGlobalAlias != "" {
		t.Fatalf("pendingGlobalAlias=%q, want empty", bucket.Status.PendingGlobalAlias)
	}
	if after.Status.ManagedGlobalAlias != alias {
		t.Fatalf("persisted managedGlobalAlias=%q, want %q", after.Status.ManagedGlobalAlias, alias)
	}
}

// mustAtoi parses a fake-client resourceVersion, which is a plain counter.
func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("resourceVersion %q is not an integer: %v", s, err)
	}
	return n
}

// A settled bucket must be a complete no-op: no status write, no admin call.
// The reserve/commit pair is self-cancelling (commit resets PendingGlobalAlias
// to "", which re-arms the reserve guard), so unless the reserve is gated on an
// add actually happening it writes status twice per reconcile, and each write
// wakes the watch that schedules the next reconcile — an unbounded loop that
// hammers the Garage admin API.
func TestReconcileGlobalAlias_SettledBucketIsNoOp(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	const alias = "settled-global"
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-settled", Namespace: testNamespace},
		Status: garagev1beta1.GarageBucketStatus{
			ManagedGlobalAlias: alias,
			GlobalAlias:        alias,
		},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}

	var adminCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		adminCalls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	before := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, before); err != nil {
		t.Fatal(err)
	}

	// Repeat: a loop only shows up once the first pass has cleared Pending.
	for i := range 3 {
		if err := r.reconcileGlobalAlias(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "bucket-id", alias, []string{alias, "user-managed"}); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}

	if n := adminCalls.Load(); n != 0 {
		t.Fatalf("admin API calls=%d, want 0 for a settled bucket", n)
	}
	if bucket.Status.PendingGlobalAlias != "" {
		t.Fatalf("pendingGlobalAlias=%q, want empty", bucket.Status.PendingGlobalAlias)
	}
	after := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, after); err != nil {
		t.Fatal(err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("resourceVersion %s -> %s, want no status write for a settled bucket",
			before.ResourceVersion, after.ResourceVersion)
	}
}

func TestReconcileGlobalAlias_DoesNotAdvanceOwnershipOnRemoveFailure(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-alias-failure", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{ManagedGlobalAlias: testOldAlias},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == testRemoveAliasPath {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`remove failed`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	err := r.reconcileGlobalAlias(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "bucket-id", "new", []string{testOldAlias})
	if err == nil {
		t.Fatal("rename unexpectedly succeeded")
	}
	fresh := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.ManagedGlobalAlias != testOldAlias {
		t.Fatalf("managedGlobalAlias=%q, want old after failed remove", fresh.Status.ManagedGlobalAlias)
	}
}

func TestReconcileGlobalAlias_DoesNotRemoveOldAliasOnConflictingAdd(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-alias-conflict", Namespace: testNamespace},
		Status:     garagev1beta1.GarageBucketStatus{ManagedGlobalAlias: testOldAlias},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	removeCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v2/AddBucketAlias":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`alias already exists`))
		case testGetBucketInfoPath:
			_, _ = w.Write([]byte(`{"id":"other-bucket"}`))
		case testRemoveAliasPath:
			removeCalls++
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	err := r.reconcileGlobalAlias(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "owned-bucket", "taken", []string{testOldAlias})
	if err == nil || !strings.Contains(err.Error(), "conflicts with another bucket") {
		t.Fatalf("err=%v, want conflicting alias failure", err)
	}
	if removeCalls != 0 {
		t.Fatalf("remove calls=%d, want zero", removeCalls)
	}
	if bucket.Status.ManagedGlobalAlias != testOldAlias {
		t.Fatalf("managedGlobalAlias=%q, want %q", bucket.Status.ManagedGlobalAlias, testOldAlias)
	}
}

func TestCleanupMPU_RetainsAnnotationsOnFailureAndRetries(t *testing.T) {
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup", Namespace: testNamespace, Annotations: map[string]string{
			garagev1beta1.AnnotationCleanupMPU:          "true",
			garagev1beta1.AnnotationCleanupMPUOlderThan: "2h",
		}},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "bucket-cleanup"},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(bucket).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/CleanupIncompleteUploads" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body garage.CleanupIncompleteUploadsRequest
		_ = json.NewDecoder(req.Body).Decode(&body)
		if body.OlderThanSecs != 7200 {
			t.Errorf("olderThanSecs=%d, want 7200", body.OlderThanSecs)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`failure`))
			return
		}
		_, _ = w.Write([]byte(`{"uploadsDeleted":1}`))
	}))
	defer srv.Close()
	gc := garage.NewClient(srv.URL, "tok")
	ctx := context.Background()
	if err := r.handleBucketAnnotations(ctx, bucket, gc); err == nil {
		t.Fatal("first cleanup unexpectedly succeeded")
	}
	fresh := &garagev1beta1.GarageBucket{}
	_ = fc.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh)
	if fresh.Annotations[garagev1beta1.AnnotationCleanupMPUOlderThan] != "2h" {
		t.Fatalf("cleanup annotations were not retained after failure: %v", fresh.Annotations)
	}
	if err := r.handleBucketAnnotations(ctx, fresh, gc); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	completed := &garagev1beta1.GarageBucket{}
	_ = fc.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, completed)
	if _, ok := completed.Annotations[garagev1beta1.AnnotationCleanupMPU]; ok {
		t.Fatalf("cleanup annotation remains after success: %v", completed.Annotations)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

func TestBuildQuotasUpdateRejectsNegativeValues(t *testing.T) {
	negativeObjects := int64(-1)
	negativeSize := resource.MustParse("-1Gi")
	for name, quotas := range map[string]*garagev1beta1.BucketQuotas{
		"objects": {MaxObjects: &negativeObjects},
		"size":    {MaxSize: &negativeSize},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildQuotasUpdate(quotas, nil); err == nil {
				t.Fatal("negative quota was converted to uint64")
			}
		})
	}
}

func TestGetOrCreateBucket_COSIAnnotationPinsExactID(t *testing.T) {
	const cosiID = "cosi-bucket-exact"
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "adopts exact annotated bucket", status: http.StatusOK},
		{name: "fails closed when annotated bucket is missing", status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests = append(requests, req.URL.Path+"?"+req.URL.RawQuery)
				if req.URL.Query().Get("id") != cosiID {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"id":"cosi-bucket-exact","globalAliases":[],"keys":[]}`))
				}
			}))
			defer srv.Close()
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{garagev1beta1.AnnotationCOSIBucketID: cosiID}},
				Spec:       garagev1beta1.GarageBucketSpec{GlobalAlias: "colliding-alias"},
				Status:     garagev1beta1.GarageBucketStatus{BucketID: cosiID},
			}
			r := &GarageBucketReconciler{}
			got, err := r.getOrCreateBucket(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "colliding-alias")
			if tc.status == http.StatusNotFound {
				if err == nil {
					t.Fatal("missing annotated bucket unexpectedly fell back to alias/create")
				}
			} else if err != nil || got.ID != cosiID || bucket.Status.BucketID != cosiID {
				t.Fatalf("got=%+v status=%q err=%v", got, bucket.Status.BucketID, err)
			}
			if len(requests) != 1 || !strings.Contains(requests[0], "id="+cosiID) {
				t.Fatalf("requests=%v, want one exact-ID lookup and no alias/create fallback", requests)
			}
		})
	}
}

func TestGetOrCreateBucket_DoesNotAdoptUntrackedAlias(t *testing.T) {
	var creates int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == testGetBucketInfoPath && req.URL.Query().Get("globalAlias") == "shared-alias" {
			_, _ = w.Write([]byte(`{"id":"unrelated-bucket","globalAliases":["shared-alias"],"keys":[]}`))
			return
		}
		if req.URL.Path == "/v2/CreateBucket" {
			creates++
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-alias", Namespace: testNamespace, UID: "bucket-uid"},
		Spec:       garagev1beta1.GarageBucketSpec{GlobalAlias: "shared-alias"},
	}
	r := &GarageBucketReconciler{}
	_, err := r.getOrCreateBucket(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), "shared-alias")
	if err == nil || !strings.Contains(err.Error(), "untracked Garage bucket") {
		t.Fatalf("err=%v, want untracked ownership failure", err)
	}
	if bucket.Status.BucketID != "" {
		t.Fatalf("adopted unrelated bucket ID %q", bucket.Status.BucketID)
	}
	if creates != 0 {
		t.Fatalf("CreateBucket calls=%d, want 0 while alias is occupied", creates)
	}
}

func TestGetOrCreateBucket_RecoversCommittedCreateBeforeStatusWrite(t *testing.T) {
	const (
		name     = "crash-safe-bucket"
		bucketID = "0123456789abcdef0123456789abcdef"
	)
	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, UID: "bucket-uid"}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bucket).Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}
	createdAlias := ""
	createCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/GetBucketInfo":
			alias := request.URL.Query().Get("globalAlias")
			if alias != "" && alias == createdAlias {
				_ = json.NewEncoder(w).Encode(garage.Bucket{ID: bucketID, GlobalAliases: []string{createdAlias}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case "/v2/CreateBucket":
			createCalls++
			var body garage.CreateBucketRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode CreateBucket: %v", err)
			}
			createdAlias = body.GlobalAlias
			if !strings.HasPrefix(createdAlias, "garage-rsv-") {
				t.Errorf("reservation alias = %q", createdAlias)
			}
			_ = json.NewEncoder(w).Encode(garage.Bucket{ID: bucketID, GlobalAliases: []string{createdAlias}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	garageClient := garage.NewClient(server.URL, "token")

	first := &garagev1beta1.GarageBucket{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), first); err != nil {
		t.Fatal(err)
	}
	created, err := reconciler.getOrCreateBucket(t.Context(), first, garageClient, name)
	if err != nil || created.ID != bucketID || createCalls != 1 {
		t.Fatalf("first create=%+v err=%v calls=%d", created, err, createCalls)
	}
	// Simulate process death before status.bucketID is persisted. Only the
	// metadata reservation patch survives in Kubernetes.
	fresh := &garagev1beta1.GarageBucket{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.BucketID != "" || fresh.Annotations[garagev1beta1.AnnotationBucketReservationAlias] != createdAlias {
		t.Fatalf("durable reservation state status=%q annotations=%v", fresh.Status.BucketID, fresh.Annotations)
	}
	recovered, err := reconciler.getOrCreateBucket(t.Context(), fresh, garageClient, name)
	if err != nil || recovered.ID != bucketID || fresh.Status.BucketID != bucketID {
		t.Fatalf("recovered=%+v status=%q err=%v", recovered, fresh.Status.BucketID, err)
	}
	if createCalls != 1 {
		t.Fatalf("CreateBucket calls=%d, want one across crash retry", createCalls)
	}
}

func TestGetOrCreateBucketRejectsReservationAliasNotBoundToUID(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	bucket := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "owned", Namespace: testNamespace, UID: "owned-uid",
		Annotations: map[string]string{garagev1beta1.AnnotationBucketReservationAlias: "victim-alias"},
	}}

	_, err := (&GarageBucketReconciler{}).getOrCreateBucket(
		t.Context(), bucket, garage.NewClient(server.URL, "token"), "owned",
	)
	if err == nil || !strings.Contains(err.Error(), "unbound bucket reservation alias") {
		t.Fatalf("unbound reservation error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("Garage requests = %d, want zero before ownership validation", requests.Load())
	}
}

func TestGarageBucketReservationAliasUsesUIDBound128BitDigest(t *testing.T) {
	original := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "owned", Namespace: testNamespace, UID: "original-uid",
	}}
	recreated := original.DeepCopy()
	recreated.UID = "recreated-uid"

	originalAlias, err := garageBucketReservationAlias(original)
	if err != nil {
		t.Fatalf("original reservation alias: %v", err)
	}
	recreatedAlias, err := garageBucketReservationAlias(recreated)
	if err != nil {
		t.Fatalf("recreated reservation alias: %v", err)
	}
	const prefix = "garage-rsv-"
	digest, err := hex.DecodeString(strings.TrimPrefix(originalAlias, prefix))
	if !strings.HasPrefix(originalAlias, prefix) || err != nil || len(digest) != 16 {
		t.Fatalf("reservation alias %q does not contain an exact 128-bit hexadecimal digest", originalAlias)
	}
	if recreatedAlias == originalAlias {
		t.Fatalf("reservation alias was reused across UID recreation: %q", originalAlias)
	}
}

func TestGetOrCreateBucketRejectsReservationAliasCopiedAcrossUIDRecreation(t *testing.T) {
	original := &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
		Name: "owned", Namespace: testNamespace, UID: "original-uid",
	}}
	copiedAlias, err := garageBucketReservationAlias(original)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	recreated := original.DeepCopy()
	recreated.UID = "recreated-uid"
	recreated.Annotations = map[string]string{garagev1beta1.AnnotationBucketReservationAlias: copiedAlias}

	_, err = (&GarageBucketReconciler{}).getOrCreateBucket(
		t.Context(), recreated, garage.NewClient(server.URL, "token"), "owned",
	)
	if err == nil || !strings.Contains(err.Error(), "unbound bucket reservation alias") {
		t.Fatalf("copied reservation error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("Garage requests = %d, want zero before UID ownership validation", requests.Load())
	}
}

// TestGetBucketWithTimeout_HangServer asserts that getBucketWithTimeout
// returns errBucketInfoTimeout (the sentinel) when the upstream admin API
// hangs past the per-call deadline — same shape as a wedged GetBucketInfo
// in production.
func TestGetBucketWithTimeout_HangServer(t *testing.T) {
	// Hang on every request — simulates a Garage admin API that's stuck on
	// a stale authorized_keys entry whose RPC lookup never returns.
	hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hangServer.Close()

	prev := getBucketInfoTimeout
	getBucketInfoTimeout = 100 * time.Millisecond
	defer func() { getBucketInfoTimeout = prev }()

	client := garage.NewClient(hangServer.URL, "test-token")
	start := time.Now()
	_, err := getBucketWithTimeout(context.Background(), client, garage.GetBucketRequest{ID: testBucketID})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isBucketLookupTimeout(err) {
		t.Errorf("expected isBucketLookupTimeout(err)=true; got err=%v", err)
	}
	// Should return ~100ms after deadline, not hang for the full client timeout.
	if elapsed > 2*time.Second {
		t.Errorf("getBucketWithTimeout took %s, expected <2s", elapsed)
	}
}

// TestGetBucketWithTimeout_ParentContextCancel ensures we DON'T mark a
// caller-cancelled context as a stuck-bucket signal. Only our own deadline
// firing should count.
func TestGetBucketWithTimeout_ParentContextCancel(t *testing.T) {
	hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hangServer.Close()

	prev := getBucketInfoTimeout
	getBucketInfoTimeout = 10 * time.Second
	defer func() { getBucketInfoTimeout = prev }()

	client := garage.NewClient(hangServer.URL, "test-token")
	parentCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := getBucketWithTimeout(parentCtx, client, garage.GetBucketRequest{ID: testBucketID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if isBucketLookupTimeout(err) {
		t.Errorf("parent-ctx cancel must not be reported as bucket lookup timeout; got %v", err)
	}
}

// newBucketReconcilerWithFakeClient builds a GarageBucketReconciler backed
// by a fake k8s client preloaded with the given bucket. Subresource status
// is enabled so r.Status().Update works.
func newBucketReconcilerWithFakeClient(t *testing.T, bucket *garagev1beta1.GarageBucket) (*GarageBucketReconciler, *garagev1beta1.GarageBucket) {
	t.Helper()
	s := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme v1beta1: %v", err)
	}
	if err := garagev1beta2.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme v1beta2: %v", err)
	}
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).
		Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}

	live := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, live); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	return r, live
}

// TestHandleBucketLookupTimeout_SetsConditionAtThreshold drives
// handleBucketLookupTimeout N consecutive times (no successes in between)
// and asserts: counter increments on each call; BucketLookupStuck condition
// is True with Reason=AdminAPITimeout once count reaches the threshold; and
// the result requeues on the unhealthy interval rather than surfacing an
// error.
func TestHandleBucketLookupTimeout_SetsConditionAtThreshold(t *testing.T) {
	ctx := context.Background()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "wedged-bucket", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:  garagev1beta1.ClusterReference{Name: testClusterName},
			GlobalAlias: "wedged-alias",
		},
	}
	r, live := newBucketReconcilerWithFakeClient(t, bucket)

	for i := 1; i <= BucketLookupStuckThreshold; i++ {
		res, err := r.handleBucketLookupTimeout(ctx, live)
		if err != nil {
			t.Fatalf("iter %d: unexpected error: %v", i, err)
		}
		if res.RequeueAfter != RequeueAfterUnhealthy {
			t.Errorf("iter %d: RequeueAfter=%s, want %s", i, res.RequeueAfter, RequeueAfterUnhealthy)
		}

		// Re-fetch to verify persisted annotation count.
		fresh := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
			t.Fatalf("iter %d: get bucket: %v", i, err)
		}
		gotCount := readTimeoutCounter(fresh)
		if gotCount != i {
			t.Errorf("iter %d: counter=%d, want %d", i, gotCount, i)
		}
		live = fresh

		cond := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck)
		if i < BucketLookupStuckThreshold {
			if cond != nil {
				t.Errorf("iter %d (below threshold): expected no BucketLookupStuck condition, got %+v", i, cond)
			}
		} else {
			if cond == nil {
				t.Fatalf("iter %d (threshold reached): expected BucketLookupStuck condition, got nil", i)
			}
			if cond.Status != metav1.ConditionTrue {
				t.Errorf("condition.Status=%v, want True", cond.Status)
			}
			if cond.Reason != garagev1beta1.ReasonBucketLookupStuck {
				t.Errorf("condition.Reason=%q, want %q", cond.Reason, garagev1beta1.ReasonBucketLookupStuck)
			}
			// Message should name the bucket alias and point at the manual fix.
			if !strings.Contains(cond.Message, "wedged-alias") {
				t.Errorf("condition.Message does not name the bucket alias: %q", cond.Message)
			}
			if !strings.Contains(cond.Message, garagev1beta1.RepairTypeAliases) {
				t.Errorf("condition.Message does not mention RepairType=Aliases: %q", cond.Message)
			}
		}
	}
}

// TestClearBucketLookupTimeouts_ResetsCounterAndCondition verifies that a
// successful GetBucketInfo (simulated by directly calling
// clearBucketLookupTimeouts) wipes both the counter annotation and the
// BucketLookupStuck condition.
func TestClearBucketLookupTimeouts_ResetsCounterAndCondition(t *testing.T) {
	ctx := context.Background()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "recovered-bucket",
			Namespace:   testNamespace,
			Annotations: map[string]string{garagev1beta1.AnnotationBucketLookupTimeouts: "3"},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
		},
		Status: garagev1beta1.GarageBucketStatus{
			Conditions: []metav1.Condition{
				{
					Type:               garagev1beta1.ConditionBucketLookupStuck,
					Status:             metav1.ConditionTrue,
					Reason:             garagev1beta1.ReasonBucketLookupStuck,
					Message:            "stuck",
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}
	r, live := newBucketReconcilerWithFakeClient(t, bucket)

	// Seed: pull current state so we have a non-zero count and live condition.
	if got := readTimeoutCounter(live); got != 3 {
		t.Fatalf("precondition: counter=%d, want 3", got)
	}

	if err := r.clearBucketLookupTimeouts(ctx, live); err != nil {
		t.Fatalf("clearBucketLookupTimeouts: %v", err)
	}

	fresh := &garagev1beta1.GarageBucket{}
	if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if got := readTimeoutCounter(fresh); got != 0 {
		t.Errorf("counter after clear=%d, want 0", got)
	}
	if _, ok := fresh.Annotations[garagev1beta1.AnnotationBucketLookupTimeouts]; ok {
		t.Errorf("annotation should be removed")
	}
	// Conditions on the live object are cleared in-memory by RemoveStatusCondition.
	// clearBucketLookupTimeouts does not flush status (callers do as part of
	// their own status update). We assert the in-memory clear here.
	if cond := meta.FindStatusCondition(live.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck); cond != nil {
		t.Errorf("BucketLookupStuck condition still set in-memory: %+v", cond)
	}
}

// TestHandleThenClear_FullCycle simulates the production sequence: three
// reconciles time out (condition gets set), then the next reconcile sees a
// success (clear is invoked) — final state has no counter and no condition.
func TestHandleThenClear_FullCycle(t *testing.T) {
	ctx := context.Background()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "cycle-bucket", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
		},
	}
	r, live := newBucketReconcilerWithFakeClient(t, bucket)

	for i := 0; i < BucketLookupStuckThreshold; i++ {
		if _, err := r.handleBucketLookupTimeout(ctx, live); err != nil {
			t.Fatalf("handleBucketLookupTimeout iter %d: %v", i, err)
		}
		if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, live); err != nil {
			t.Fatalf("get bucket iter %d: %v", i, err)
		}
	}
	if cond := meta.FindStatusCondition(live.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck); cond == nil {
		t.Fatal("expected BucketLookupStuck condition after threshold reached")
	}

	// First successful GetBucketInfo on the next reconcile.
	if err := r.clearBucketLookupTimeouts(ctx, live); err != nil {
		t.Fatalf("clearBucketLookupTimeouts: %v", err)
	}
	fresh := &garagev1beta1.GarageBucket{}
	if err := r.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if got := readTimeoutCounter(fresh); got != 0 {
		t.Errorf("counter after recovery=%d, want 0", got)
	}
	if cond := meta.FindStatusCondition(live.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck); cond != nil {
		t.Errorf("BucketLookupStuck condition should be cleared in-memory: %+v", cond)
	}
}

func TestParseMPUOlderThan(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"24h", 86400},
		{"1h", 3600},
		{"30m", 1800},
		{"", 86400},    // empty → default
		{"bad", 86400}, // invalid → default
		{"7d", 86400},  // "d" not supported by time.ParseDuration → default
		{"-1h", 86400}, // negative → default
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMPUOlderThan(tt.input)
			if got != tt.want {
				t.Errorf("parseMPUOlderThan(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestIsTimeoutErr_ClassifiesNetHTTPTimeouts verifies that isTimeoutErr
// classifies the timeout shapes net/http actually returns — not just
// context.DeadlineExceeded. http.Client.Timeout firing surfaces as a
// *url.Error wrapping a net.Error with Timeout()==true, and
// errors.Is(err, context.DeadlineExceeded) is FALSE for those.
//
// Regression for the case where getBucketWithTimeout previously only
// matched context.DeadlineExceeded; transport-level timeouts slipped
// through as generic errors and the stuck-bucket counter never moved.
func TestIsTimeoutErr_ClassifiesNetHTTPTimeouts(t *testing.T) {
	// A timeout-shaped *net.OpError, as returned by net/http when the
	// transport timeout fires.
	netTimeout := &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: timeoutError{},
	}
	// What http.Client.Do wraps the transport error in.
	urlTimeout := &url.Error{
		Op:  "Get",
		URL: "http://garage.example/v2/GetBucketInfo",
		Err: fmt.Errorf("net/http: timeout awaiting response headers"),
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context.DeadlineExceeded direct", context.DeadlineExceeded, true},
		{"wrapped context.DeadlineExceeded", fmt.Errorf("calling admin: %w", context.DeadlineExceeded), true},
		{"net.OpError with Timeout()==true", netTimeout, true},
		{"url.Error with timeout substring", urlTimeout, true},
		{"plain io timeout string", fmt.Errorf("read tcp: i/o timeout"), true},
		{"unrelated error", fmt.Errorf("HTTP 500 layout not ready"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTimeoutErr(tc.err)
			if got != tc.want {
				t.Errorf("isTimeoutErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// timeoutError is a minimal net.Error that reports Timeout()==true.
// Mirrors the shape of internal/poll.DeadlineExceededError.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestGetBucketWithTimeout_TransportTimeoutClassified verifies that a
// net/http transport-level timeout (http.Client.Timeout firing before our
// context's deadline) is reported as errBucketInfoTimeout — not as a
// generic error. Regression for the case where the per-call deadline was
// longer than the transport's own timeout (or vice-versa under load).
//
// Strategy: stand up a slow server, dial the *garage client* (which has its
// own 90s http.Client.Timeout — too long for unit tests) via a custom
// http.Client whose transport returns a *url.Error timeout to simulate the
// underlying behaviour without waiting on real socket timeouts.
//
// Simpler: build a Garage client whose http.Client.Timeout is the limiting
// factor, with the per-call ctx deadline well beyond it.
func TestGetBucketWithTimeout_TransportTimeoutClassified(t *testing.T) {
	// Server hangs — neither it nor the per-call ctx will respond before the
	// http.Client.Timeout fires.
	hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hangServer.Close()

	// Per-call ctx deadline well in excess of the transport timeout below
	// — so the *url.Error path is the one that wins.
	prev := getBucketInfoTimeout
	getBucketInfoTimeout = 5 * time.Second
	defer func() { getBucketInfoTimeout = prev }()

	// Build a garage client with a short transport-level Timeout so the
	// http.Client.Timeout fires first, producing a *url.Error{Timeout=true}.
	gc := garage.NewClient(hangServer.URL, "test-token")
	gc.SetHTTPTimeout(100 * time.Millisecond)

	start := time.Now()
	_, err := getBucketWithTimeout(context.Background(), gc, garage.GetBucketRequest{ID: testBucketID})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isBucketLookupTimeout(err) {
		t.Errorf("expected transport-level timeout to be classified as bucket lookup timeout; got err=%v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("call took %s, expected <2s (transport timeout should have fired first)", elapsed)
	}
}

// TestHandleBucketLookupTimeout_PreservesConditionOnConflict verifies that
// when r.Status().Update returns Conflict on the first attempt, the
// UpdateStatusWithRetry helper's re-fetch + retry path still preserves the
// BucketLookupStuck condition we set in-memory. The fix passes a mutate
// callback that re-applies the condition after the helper re-fetches the
// object from the fake client; without it, the freshly-fetched object's
// old (empty) Conditions slice would silently overwrite our change.
func TestHandleBucketLookupTimeout_PreservesConditionOnConflict(t *testing.T) {
	ctx := context.Background()
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "conflict-bucket",
			Namespace: testNamespace,
			// Pre-seed counter so a single handleBucketLookupTimeout call hits
			// the threshold and tries to set the condition.
			Annotations: map[string]string{
				garagev1beta1.AnnotationBucketLookupTimeouts: fmt.Sprintf("%d", BucketLookupStuckThreshold-1),
			},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:  garagev1beta1.ClusterReference{Name: testClusterName},
			GlobalAlias: "conflict-alias",
		},
	}

	s := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme v1beta1: %v", err)
	}
	if err := garagev1beta2.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme v1beta2: %v", err)
	}

	// Intercept SubResourceUpdate (used by Status().Update) and return
	// Conflict on the FIRST call only. The helper should then re-fetch and
	// retry — and the mutate callback must re-apply the condition so the
	// retry succeeds with the condition persisted.
	var statusUpdates int32
	base := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).
		Build()
	wrapped := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if subResourceName == "status" && atomic.AddInt32(&statusUpdates, 1) == 1 {
				gr := schema.GroupResource{Group: "garage.rajsingh.info", Resource: "garagebuckets"}
				return errors.NewConflict(gr, obj.GetName(), fmt.Errorf("simulated conflict"))
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	})
	r := &GarageBucketReconciler{Client: wrapped, Scheme: s}

	live := &garagev1beta1.GarageBucket{}
	if err := wrapped.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, live); err != nil {
		t.Fatalf("get bucket: %v", err)
	}

	res, err := r.handleBucketLookupTimeout(ctx, live)
	if err != nil {
		t.Fatalf("handleBucketLookupTimeout: %v", err)
	}
	if res.RequeueAfter != RequeueAfterUnhealthy {
		t.Errorf("RequeueAfter=%s, want %s", res.RequeueAfter, RequeueAfterUnhealthy)
	}
	if got := atomic.LoadInt32(&statusUpdates); got < 2 {
		t.Errorf("expected at least 2 status updates (conflict + retry), got %d", got)
	}

	// Re-fetch from the fake store: the condition MUST be persisted despite
	// the conflict on the first attempt.
	fresh := &garagev1beta1.GarageBucket{}
	if err := wrapped.Get(ctx, types.NamespacedName{Name: bucket.Name, Namespace: bucket.Namespace}, fresh); err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	cond := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck)
	if cond == nil {
		t.Fatal("BucketLookupStuck condition missing on retry: mutate fn likely not re-applied")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("cond.Status=%v, want True", cond.Status)
	}
	if cond.Reason != garagev1beta1.ReasonBucketLookupStuck {
		t.Errorf("cond.Reason=%q, want %q", cond.Reason, garagev1beta1.ReasonBucketLookupStuck)
	}
	if !strings.Contains(cond.Message, "conflict-alias") {
		t.Errorf("cond.Message does not name alias: %q", cond.Message)
	}
}
