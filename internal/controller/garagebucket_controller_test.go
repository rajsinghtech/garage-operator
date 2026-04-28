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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

var _ = Describe("GarageBucket Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-bucket"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup the GarageBucket
			bucket := &garagev1alpha1.GarageBucket{}
			err := k8sClient.Get(ctx, typeNamespacedName, bucket)
			if err == nil {
				bucket.Finalizers = nil
				_ = k8sClient.Update(ctx, bucket)
				_ = k8sClient.Delete(ctx, bucket)
			}
		})

		It("should set error status when cluster doesn't exist", func() {
			By("Creating a GarageBucket referencing non-existent cluster")
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
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
			updatedBucket := &garagev1alpha1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedBucket)).To(Succeed())
			Expect(updatedBucket.Status.Phase).To(Equal(PhasePending))
		})

		It("should handle bucket creation spec with quotas", func() {
			By("Creating a GarageBucket with quotas")
			maxSize := resource.MustParse("10Gi")
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Quotas: &garagev1alpha1.BucketQuotas{
						MaxSize:    &maxSize,
						MaxObjects: int64Ptr(1000),
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket spec was stored correctly")
			createdBucket := &garagev1alpha1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.Quotas).NotTo(BeNil())
			Expect(createdBucket.Spec.Quotas.MaxSize.String()).To(Equal("10Gi"))
			Expect(*createdBucket.Spec.Quotas.MaxObjects).To(Equal(int64(1000)))
		})

		It("should handle bucket with website config", func() {
			By("Creating a GarageBucket with website hosting")
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Website: &garagev1alpha1.WebsiteConfig{
						Enabled:       true,
						IndexDocument: "index.html",
						ErrorDocument: "error.html",
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket was created")
			createdBucket := &garagev1alpha1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.Website).NotTo(BeNil())
			Expect(createdBucket.Spec.Website.IndexDocument).To(Equal("index.html"))
		})

		It("should store lifecycle rules on spec", func() {
			By("Creating a GarageBucket with a lifecycle rule")
			expDays := int32(7)
			abortDays := int32(3)
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Lifecycle: &garagev1alpha1.BucketLifecycle{
						Rules: []garagev1alpha1.LifecycleRule{
							{
								ID:                                 "expire-logs",
								Status:                             "Enabled",
								ExpirationDays:                     &expDays,
								AbortIncompleteMultipartUploadDays: &abortDays,
								Filter: &garagev1alpha1.LifecycleFilter{
									Prefix: "logs/",
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying lifecycle was stored")
			created := &garagev1alpha1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, created)).To(Succeed())
			Expect(created.Spec.Lifecycle).NotTo(BeNil())
			Expect(created.Spec.Lifecycle.Rules).To(HaveLen(1))
			Expect(created.Spec.Lifecycle.Rules[0].ID).To(Equal("expire-logs"))
			Expect(*created.Spec.Lifecycle.Rules[0].ExpirationDays).To(Equal(int32(7)))
			Expect(*created.Spec.Lifecycle.Rules[0].AbortIncompleteMultipartUploadDays).To(Equal(int32(3)))
			Expect(created.Spec.Lifecycle.Rules[0].Filter.Prefix).To(Equal("logs/"))
		})

		It("should handle bucket with key permissions", func() {
			By("Creating a GarageBucket with key permissions")
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					KeyPermissions: []garagev1alpha1.KeyPermission{
						{
							KeyRef: "test-key",
							Read:   true,
							Write:  true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			By("Verifying the bucket was created with permissions")
			createdBucket := &garagev1alpha1.GarageBucket{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdBucket)).To(Succeed())
			Expect(createdBucket.Spec.KeyPermissions).To(HaveLen(1))
			Expect(createdBucket.Spec.KeyPermissions[0].KeyRef).To(Equal("test-key"))
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
					Namespace: "default",
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
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup
			bucket := &garagev1alpha1.GarageBucket{}
			err := k8sClient.Get(ctx, typeNamespacedName, bucket)
			if err == nil {
				bucket.Finalizers = nil
				_ = k8sClient.Update(ctx, bucket)
				_ = k8sClient.Delete(ctx, bucket)
			}
		})

		It("should handle deletion request gracefully", func() {
			By("Creating the GarageBucket resource")
			bucket := &garagev1alpha1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageBucketSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
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
			finalBucket := &garagev1alpha1.GarageBucket{}
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
