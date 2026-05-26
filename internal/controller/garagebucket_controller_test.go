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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

const testNamespace = "default"

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
					Namespace:  "default",
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
