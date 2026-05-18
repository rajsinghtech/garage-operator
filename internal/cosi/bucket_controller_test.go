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

package cosi

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func isAlreadyExists(err error) bool {
	return apierrors.IsAlreadyExists(err)
}

const (
	cosiTestNamespace = "default"
	cosiTestDriver    = "garage.example.com"
	cosiGarageNS      = "garage-system"
	cosiClusterName   = "test-cluster"
	cosiS3Endpoint    = "http://garage.test:3900"
)

var _ = Describe("BucketReconciler", func() {
	Context("happy path: create bucket", func() {
		const bucketName = "cosi-test-bucket"
		var nn types.NamespacedName

		BeforeEach(func() {
			nn = types.NamespacedName{Name: bucketName}

			// Create the garage-system namespace (not present by default in envtest).
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cosiGarageNS}}
			if err := k8sClient.Create(ctx, ns); err != nil && !isAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			// Create the GarageCluster in running state.
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      cosiClusterName,
					Namespace: cosiGarageNS,
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
			// Patch status to Running.
			cluster.Status = garagev1beta2.GarageClusterStatus{
				Phase: garagev1beta1.PhaseRunning,
				Endpoints: &garagev1beta2.ClusterEndpoints{
					S3: cosiS3Endpoint,
				},
			}
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())
		})

		AfterEach(func() {
			// Clean up Bucket
			b := &cosiv1alpha2.Bucket{}
			if err := k8sClient.Get(ctx, nn, b); err == nil {
				b.Finalizers = nil
				_ = k8sClient.Update(ctx, b)
				_ = k8sClient.Delete(ctx, b)
			}
			// Clean up GarageCluster
			gc := &garagev1beta2.GarageCluster{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: cosiClusterName, Namespace: cosiGarageNS}, gc); err == nil {
				_ = k8sClient.Delete(ctx, gc)
			}
			// Clean up shadow GarageBuckets
			gbList := &garagev1beta1.GarageBucketList{}
			if err := k8sClient.List(ctx, gbList, client.InNamespace(cosiGarageNS)); err == nil {
				for i := range gbList.Items {
					_ = k8sClient.Delete(ctx, &gbList.Items[i])
				}
			}
		})

		It("provisions bucket and sets ReadyToUse=true", func() {
			By("creating the COSI Bucket resource")
			bucket := &cosiv1alpha2.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					Name: bucketName,
				},
				Spec: cosiv1alpha2.BucketSpec{
					DriverName:     cosiTestDriver,
					DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
					Parameters: map[string]string{
						paramClusterRef:       cosiClusterName,
						paramClusterNamespace: cosiGarageNS,
					},
					BucketClaimRef: cosiv1alpha2.BucketClaimReference{
						Name:      "test-claim",
						Namespace: cosiTestNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			mockClient := newMockGarageClient()
			provisioner := NewProvisionerWithFactory(k8sClient, cosiGarageNS, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
				return mockClient, nil
			})

			reconciler := &BucketReconciler{
				Client:      k8sClient,
				Scheme:      k8sClient.Scheme(),
				DriverName:  cosiTestDriver,
				Namespace:   cosiGarageNS,
				Provisioner: provisioner,
			}

			By("first reconcile adds finalizer")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			withFinalizer := &cosiv1alpha2.Bucket{}
			Expect(k8sClient.Get(ctx, nn, withFinalizer)).To(Succeed())
			Expect(withFinalizer.Finalizers).To(ContainElement(cosiv1alpha2.ProtectionFinalizer))

			By("second reconcile provisions bucket")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			By("verifying bucket status")
			updated := &cosiv1alpha2.Bucket{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			Expect(updated.Status.ReadyToUse).NotTo(BeNil())
			Expect(*updated.Status.ReadyToUse).To(BeTrue())
			Expect(updated.Status.BucketID).NotTo(BeEmpty())

			By("verifying protection finalizer is present")
			Expect(updated.Finalizers).To(ContainElement(cosiv1alpha2.ProtectionFinalizer))

			By("verifying a shadow GarageBucket was created")
			gbList := &garagev1beta1.GarageBucketList{}
			Expect(k8sClient.List(ctx, gbList, client.InNamespace(cosiGarageNS),
				client.MatchingLabels{LabelCOSIManaged: paramTrue})).To(Succeed())
			Expect(gbList.Items).To(HaveLen(1))
		})
	})

	Context("driver name mismatch", func() {
		const bucketName = "cosi-wrong-driver-bucket"
		var nn types.NamespacedName

		AfterEach(func() {
			b := &cosiv1alpha2.Bucket{}
			if err := k8sClient.Get(ctx, nn, b); err == nil {
				b.Finalizers = nil
				_ = k8sClient.Update(ctx, b)
				_ = k8sClient.Delete(ctx, b)
			}
		})

		It("ignores buckets for other drivers", func() {
			nn = types.NamespacedName{Name: bucketName}
			bucket := &cosiv1alpha2.Bucket{
				ObjectMeta: metav1.ObjectMeta{Name: bucketName},
				Spec: cosiv1alpha2.BucketSpec{
					DriverName:     "other.driver",
					DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyRetain,
					Parameters: map[string]string{
						paramClusterRef:       cosiClusterName,
						paramClusterNamespace: cosiGarageNS,
					},
					BucketClaimRef: cosiv1alpha2.BucketClaimReference{
						Name:      "test-claim",
						Namespace: cosiTestNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, bucket)).To(Succeed())

			reconciler := &BucketReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				DriverName: cosiTestDriver,
				Namespace:  cosiGarageNS,
				Provisioner: NewProvisionerWithFactory(k8sClient, cosiGarageNS, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
					return newMockGarageClient(), nil
				}),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			// No finalizer should be added, status should be unchanged
			updated := &cosiv1alpha2.Bucket{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			Expect(updated.Finalizers).NotTo(ContainElement(cosiv1alpha2.ProtectionFinalizer))
		})
	})
})
