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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

var _ = Describe("BucketAccessReconciler", func() {
	Context("happy path: grant access", func() {
		const (
			accessName   = "cosi-test-access"
			claimName    = "cosi-test-claim"
			bucketName   = "cosi-test-bucket-for-access"
			secretName   = "test-creds"
			testBucketID = "garage-bucket-id-abc123"
		)
		var (
			accessNN types.NamespacedName
			bucketNN types.NamespacedName
			claimNN  types.NamespacedName
		)

		BeforeEach(func() {
			accessNN = types.NamespacedName{Name: accessName, Namespace: cosiTestNamespace}
			bucketNN = types.NamespacedName{Name: bucketName}
			claimNN = types.NamespacedName{Name: claimName, Namespace: cosiTestNamespace}

			// Create the garage-system namespace (not present by default in envtest).
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cosiGarageNS}}
			if err := k8sClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			// GarageCluster in Running state
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
			cluster.Status = garagev1beta2.GarageClusterStatus{
				Phase: garagev1beta1.PhaseRunning,
				Endpoints: &garagev1beta2.ClusterEndpoints{
					S3: cosiS3Endpoint,
				},
			}
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			// COSI Bucket with BucketID already provisioned
			cosiGarageBucket := &cosiv1alpha2.Bucket{
				ObjectMeta: metav1.ObjectMeta{Name: bucketName},
				Spec: cosiv1alpha2.BucketSpec{
					DriverName:     cosiTestDriver,
					DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
					Parameters: map[string]string{
						paramClusterRef:       cosiClusterName,
						paramClusterNamespace: cosiGarageNS,
					},
					BucketClaimRef: cosiv1alpha2.BucketClaimReference{
						Name:      claimName,
						Namespace: cosiTestNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cosiGarageBucket)).To(Succeed())
			// Set status with BucketID
			cosiGarageBucket.Status = cosiv1alpha2.BucketStatus{
				ReadyToUse: ptr.To(true),
				BucketID:   testBucketID,
			}
			Expect(k8sClient.Status().Update(ctx, cosiGarageBucket)).To(Succeed())

			// Shadow GarageBucket for alias lookup
			shadowBucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ShadowResourceName(bucketName),
					Namespace: cosiGarageNS,
					Labels: map[string]string{
						LabelCOSIManaged:  paramTrue,
						LabelCOSIBucketID: truncateLabelValue(testBucketID),
					},
					Annotations: map[string]string{
						AnnotationCOSIBucketID: testBucketID,
					},
				},
				Spec: garagev1beta1.GarageBucketSpec{
					GlobalAlias: bucketName,
					ClusterRef: garagev1beta1.ClusterReference{
						Name:      cosiClusterName,
						Namespace: cosiGarageNS,
					},
				},
			}
			Expect(k8sClient.Create(ctx, shadowBucket)).To(Succeed())

			// BucketClaim bound to the Bucket
			claim := &cosiv1alpha2.BucketClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      claimName,
					Namespace: cosiTestNamespace,
				},
				Spec: cosiv1alpha2.BucketClaimSpec{
					BucketClassName: "test-class",
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())
			claim.Status = cosiv1alpha2.BucketClaimStatus{
				BoundBucketName: bucketName,
				ReadyToUse:      ptr.To(true),
			}
			Expect(k8sClient.Status().Update(ctx, claim)).To(Succeed())
		})

		AfterEach(func() {
			// Clean up BucketAccess
			ba := &cosiv1alpha2.BucketAccess{}
			if err := k8sClient.Get(ctx, accessNN, ba); err == nil {
				ba.Finalizers = nil
				_ = k8sClient.Update(ctx, ba)
				_ = k8sClient.Delete(ctx, ba)
			}
			// Clean up BucketClaim
			bc := &cosiv1alpha2.BucketClaim{}
			if err := k8sClient.Get(ctx, claimNN, bc); err == nil {
				_ = k8sClient.Delete(ctx, bc)
			}
			// Clean up COSI Bucket
			b := &cosiv1alpha2.Bucket{}
			if err := k8sClient.Get(ctx, bucketNN, b); err == nil {
				b.Finalizers = nil
				_ = k8sClient.Update(ctx, b)
				_ = k8sClient.Delete(ctx, b)
			}
			// Clean up GarageCluster
			gc := &garagev1beta2.GarageCluster{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: cosiClusterName, Namespace: cosiGarageNS}, gc); err == nil {
				_ = k8sClient.Delete(ctx, gc)
			}
			// Clean up shadow resources
			gbList := &garagev1beta1.GarageBucketList{}
			if err := k8sClient.List(ctx, gbList, client.InNamespace(cosiGarageNS)); err == nil {
				for i := range gbList.Items {
					_ = k8sClient.Delete(ctx, &gbList.Items[i])
				}
			}
			gkList := &garagev1beta1.GarageKeyList{}
			if err := k8sClient.List(ctx, gkList, client.InNamespace(cosiGarageNS)); err == nil {
				for i := range gkList.Items {
					_ = k8sClient.Delete(ctx, &gkList.Items[i])
				}
			}
			// Clean up secrets
			sec := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cosiTestNamespace}, sec); err == nil {
				_ = k8sClient.Delete(ctx, sec)
			}
		})

		It("grants access, populates secret, sets ReadyToUse=true", func() {
			By("creating the BucketAccess resource")
			access := &cosiv1alpha2.BucketAccess{
				ObjectMeta: metav1.ObjectMeta{
					Name:      accessName,
					Namespace: cosiTestNamespace,
				},
				Spec: cosiv1alpha2.BucketAccessSpec{
					BucketAccessClassName: "test-access-class",
					Protocol:              cosiv1alpha2.ObjectProtocolS3,
					BucketClaims: []cosiv1alpha2.BucketClaimAccess{
						{
							BucketClaimName:  claimName,
							AccessMode:       cosiv1alpha2.BucketAccessModeReadWrite,
							AccessSecretName: secretName,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, access)).To(Succeed())

			// Simulate what the upstream COSI controller does: populate Status.DriverName + Parameters.
			// readyToUse must be set (required field in the CRD) — start as false, our reconciler sets it true.
			access.Status = cosiv1alpha2.BucketAccessStatus{
				ReadyToUse:         ptr.To(false),
				DriverName:         cosiTestDriver,
				AuthenticationType: cosiv1alpha2.BucketAccessAuthenticationTypeKey,
				Parameters: map[string]string{
					paramClusterRef:       cosiClusterName,
					paramClusterNamespace: cosiGarageNS,
				},
			}
			Expect(k8sClient.Status().Update(ctx, access)).To(Succeed())

			mockClient := newMockGarageClient()
			mockClient.buckets[testBucketID] = &garage.Bucket{
				ID:            testBucketID,
				GlobalAliases: []string{bucketName},
			}

			provisioner := NewProvisionerWithFactory(k8sClient, cosiGarageNS, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
				return mockClient, nil
			})

			reconciler := &BucketAccessReconciler{
				Client:      k8sClient,
				Scheme:      k8sClient.Scheme(),
				DriverName:  cosiTestDriver,
				Namespace:   cosiGarageNS,
				Provisioner: provisioner,
			}

			By("first reconcile adds finalizer")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: accessNN})
			Expect(err).NotTo(HaveOccurred())
			withFinalizer := &cosiv1alpha2.BucketAccess{}
			Expect(k8sClient.Get(ctx, accessNN, withFinalizer)).To(Succeed())
			Expect(withFinalizer.Finalizers).To(ContainElement(cosiv1alpha2.ProtectionFinalizer))

			By("second reconcile grants access")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: accessNN})
			Expect(err).NotTo(HaveOccurred())

			By("verifying BucketAccess status")
			updated := &cosiv1alpha2.BucketAccess{}
			Expect(k8sClient.Get(ctx, accessNN, updated)).To(Succeed())
			Expect(updated.Status.ReadyToUse).NotTo(BeNil())
			Expect(*updated.Status.ReadyToUse).To(BeTrue())
			Expect(updated.Status.AccountID).NotTo(BeEmpty())

			By("verifying the secret was populated with credentials")
			sec := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cosiTestNamespace}, sec)).To(Succeed())
			Expect(sec.Data).To(HaveKey("S3_ACCESS_KEY_ID"))
			Expect(sec.Data).To(HaveKey("S3_ACCESS_SECRET_KEY"))
			Expect(string(sec.Data["S3_ACCESS_KEY_ID"])).NotTo(BeEmpty())
			Expect(string(sec.Data["S3_ACCESS_SECRET_KEY"])).NotTo(BeEmpty())

			By("verifying the protection finalizer is present")
			Expect(updated.Finalizers).To(ContainElement(cosiv1alpha2.ProtectionFinalizer))
		})
	})

	Context("driver name not yet set", func() {
		const accessName = "cosi-unset-driver-access"
		var accessNN types.NamespacedName

		AfterEach(func() {
			ba := &cosiv1alpha2.BucketAccess{}
			if err := k8sClient.Get(ctx, accessNN, ba); err == nil {
				ba.Finalizers = nil
				_ = k8sClient.Update(ctx, ba)
				_ = k8sClient.Delete(ctx, ba)
			}
		})

		It("requeues when Status.DriverName is empty", func() {
			accessNN = types.NamespacedName{Name: accessName, Namespace: cosiTestNamespace}

			access := &cosiv1alpha2.BucketAccess{
				ObjectMeta: metav1.ObjectMeta{
					Name:      accessName,
					Namespace: cosiTestNamespace,
				},
				Spec: cosiv1alpha2.BucketAccessSpec{
					BucketAccessClassName: "test-access-class",
					Protocol:              cosiv1alpha2.ObjectProtocolS3,
					BucketClaims: []cosiv1alpha2.BucketClaimAccess{
						{
							BucketClaimName:  "some-claim",
							AccessMode:       cosiv1alpha2.BucketAccessModeReadWrite,
							AccessSecretName: "some-secret",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, access)).To(Succeed())

			reconciler := &BucketAccessReconciler{
				Client:     k8sClient,
				Scheme:     k8sClient.Scheme(),
				DriverName: cosiTestDriver,
				Namespace:  cosiGarageNS,
				Provisioner: NewProvisionerWithFactory(k8sClient, cosiGarageNS, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
					return newMockGarageClient(), nil
				}),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: accessNN})
			Expect(err).NotTo(HaveOccurred())
			// Should requeue after a delay waiting for the COSI controller to fill DriverName.
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		})
	})
})
