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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

var _ = Describe("GarageKey Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-key"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup the GarageKey
			key := &garagev1alpha1.GarageKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, key)
			if err == nil {
				key.Finalizers = nil
				_ = k8sClient.Update(ctx, key)
				_ = k8sClient.Delete(ctx, key)
			}
		})

		It("should set error status when cluster doesn't exist", func() {
			By("Creating a GarageKey referencing non-existent cluster")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "non-existent-cluster",
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Reconciling the GarageKey")
			reconciler := &GarageKeyReconciler{
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
			updatedKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedKey)).To(Succeed())
			Expect(updatedKey.Status.Phase).To(Equal(PhasePending))
		})

		It("should handle key creation spec with bucket permissions", func() {
			By("Creating a GarageKey with bucket permissions")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					BucketPermissions: []garagev1alpha1.BucketPermission{
						{
							BucketRef: "test-bucket",
							Read:      true,
							Write:     true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key spec was stored correctly")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.BucketPermissions).To(HaveLen(1))
			Expect(createdKey.Spec.BucketPermissions[0].BucketRef).To(Equal("test-bucket"))
			Expect(createdKey.Spec.BucketPermissions[0].Read).To(BeTrue())
		})

		It("should handle key with createBucket permission", func() {
			By("Creating a GarageKey with createBucket permission")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Permissions: &garagev1alpha1.KeyPermissions{
						CreateBucket: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.Permissions).NotTo(BeNil())
			Expect(createdKey.Spec.Permissions.CreateBucket).To(BeTrue())
		})

		It("should handle key with custom secret template", func() {
			By("Creating a GarageKey with secret template")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					SecretTemplate: &garagev1alpha1.SecretTemplate{
						Name: "custom-secret-name",
						Labels: map[string]string{
							"app": "test",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created with template")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.SecretTemplate).NotTo(BeNil())
			Expect(createdKey.Spec.SecretTemplate.Name).To(Equal("custom-secret-name"))
		})

		It("should handle key with allBuckets cluster-wide permissions", func() {
			By("Creating a GarageKey with allBuckets")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					AllBuckets: &garagev1alpha1.AllBucketsPermission{
						Read:  true,
						Write: true,
						Owner: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key spec was stored correctly")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.AllBuckets).NotTo(BeNil())
			Expect(createdKey.Spec.AllBuckets.Read).To(BeTrue())
			Expect(createdKey.Spec.AllBuckets.Write).To(BeTrue())
			Expect(createdKey.Spec.AllBuckets.Owner).To(BeTrue())
		})

		It("should handle key with allBuckets removed (revocation tracking)", func() {
			By("Creating a GarageKey with allBuckets set")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					AllBuckets: &garagev1alpha1.AllBucketsPermission{
						Read: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying allBuckets is stored")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.AllBuckets).NotTo(BeNil())

			By("Simulating status.clusterWide being set by reconciler")
			createdKey.Status.ClusterWide = true
			Expect(k8sClient.Status().Update(ctx, createdKey)).To(Succeed())

			By("Removing allBuckets from spec")
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			createdKey.Spec.AllBuckets = nil
			Expect(k8sClient.Update(ctx, createdKey)).To(Succeed())

			By("Verifying allBuckets is nil but clusterWide status remains for revocation")
			updatedKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedKey)).To(Succeed())
			Expect(updatedKey.Spec.AllBuckets).To(BeNil())
			Expect(updatedKey.Status.ClusterWide).To(BeTrue())
		})

		It("should handle key with allBuckets and bucketPermissions", func() {
			By("Creating a GarageKey with both allBuckets and bucketPermissions")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					AllBuckets: &garagev1alpha1.AllBucketsPermission{
						Read: true,
					},
					BucketPermissions: []garagev1alpha1.BucketPermission{
						{
							BucketRef: "special-bucket",
							Owner:     true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying both are stored")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.AllBuckets).NotTo(BeNil())
			Expect(createdKey.Spec.AllBuckets.Read).To(BeTrue())
			Expect(createdKey.Spec.BucketPermissions).To(HaveLen(1))
		})

		It("should handle key with expiration", func() {
			By("Creating a GarageKey with expiration")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Expiration: "2030-12-31T23:59:59Z",
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created with expiration")
			createdKey := &garagev1alpha1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.Expiration).To(Equal("2030-12-31T23:59:59Z"))
		})
	})

	Context("When reconciling a non-existent GarageKey", func() {
		It("should return without error", func() {
			reconciler := &GarageKeyReconciler{
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

	Context("When deleting a GarageKey", func() {
		const resourceName = "test-key-delete"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup
			key := &garagev1alpha1.GarageKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, key)
			if err == nil {
				key.Finalizers = nil
				_ = k8sClient.Update(ctx, key)
				_ = k8sClient.Delete(ctx, key)
			}
		})

		It("should handle deletion request gracefully", func() {
			By("Creating the GarageKey resource")
			key := &garagev1alpha1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageKeySpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Deleting the key")
			Expect(k8sClient.Delete(ctx, key)).To(Succeed())

			By("Reconciling after deletion request")
			reconciler := &GarageKeyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			By("Verifying the key is deleted or has deletion timestamp")
			finalKey := &garagev1alpha1.GarageKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, finalKey)
			if err == nil {
				// Key still exists - should have deletion timestamp
				Expect(finalKey.DeletionTimestamp).NotTo(BeNil())
			} else {
				// Key was deleted
				Expect(errors.IsNotFound(err)).To(BeTrue())
			}
		})
	})

	Describe("deriveKeyMaterial", func() {
		secret := []byte("deadbeefdeadbeefdeadbeefdeadbeef") // 32 bytes

		It("produces a GK-prefixed 26-char access key ID", func() {
			akID, _ := deriveKeyMaterial(secret, "default", "my-key")
			Expect(akID).To(HavePrefix("GK"))
			Expect(akID).To(HaveLen(26))
		})

		It("produces a 64-char hex secret key", func() {
			_, sk := deriveKeyMaterial(secret, "default", "my-key")
			Expect(sk).To(HaveLen(64))
			_, err := hex.DecodeString(sk)
			Expect(err).NotTo(HaveOccurred())
		})

		It("is deterministic for the same inputs", func() {
			ak1, sk1 := deriveKeyMaterial(secret, "default", "my-key")
			ak2, sk2 := deriveKeyMaterial(secret, "default", "my-key")
			Expect(ak1).To(Equal(ak2))
			Expect(sk1).To(Equal(sk2))
		})

		It("produces different material for different namespaces", func() {
			ak1, _ := deriveKeyMaterial(secret, "ns-a", "my-key")
			ak2, _ := deriveKeyMaterial(secret, "ns-b", "my-key")
			Expect(ak1).NotTo(Equal(ak2))
		})

		It("produces different material for different key names", func() {
			ak1, _ := deriveKeyMaterial(secret, "default", "key-a")
			ak2, _ := deriveKeyMaterial(secret, "default", "key-b")
			Expect(ak1).NotTo(Equal(ak2))
		})

		It("produces different material for different RPC secrets", func() {
			s1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
			s2 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2")
			ak1, _ := deriveKeyMaterial(s1, "default", "my-key")
			ak2, _ := deriveKeyMaterial(s2, "default", "my-key")
			Expect(ak1).NotTo(Equal(ak2))
		})

		It("access key ID and secret key are independent values", func() {
			akID, sk := deriveKeyMaterial(secret, "default", "my-key")
			Expect(akID[2:]).NotTo(Equal(sk[:24]))
		})
	})

	Describe("deterministic key creation path", func() {
		rpcSecret := []byte("aabbccddeeffaabbccddeeffaabbccdd") // 32 bytes

		It("derives the same key ID regardless of call order", func() {
			id1, sk1 := deriveKeyMaterial(rpcSecret, "media", "volsync-key")
			id2, sk2 := deriveKeyMaterial(rpcSecret, "media", "volsync-key")
			Expect(id1).To(Equal(id2))
			Expect(sk1).To(Equal(sk2))
		})

		It("two clusters with the same RPC secret produce the same key material", func() {
			// Simulates ottawa and robbinsdale operators both deriving for the same key
			ottawaID, ottawaSK := deriveKeyMaterial(rpcSecret, "media", "volsync-jellyseerr-config-key")
			robbinsID, robbinsSK := deriveKeyMaterial(rpcSecret, "media", "volsync-jellyseerr-config-key")
			Expect(ottawaID).To(Equal(robbinsID))
			Expect(ottawaSK).To(Equal(robbinsSK))
		})

		It("different key names in the same namespace produce different IDs", func() {
			id1, _ := deriveKeyMaterial(rpcSecret, "media", "key-a")
			id2, _ := deriveKeyMaterial(rpcSecret, "media", "key-b")
			Expect(id1).NotTo(Equal(id2))
		})

		It("produces a Garage-compatible access key ID", func() {
			akID, _ := deriveKeyMaterial(rpcSecret, "media", "my-key")
			Expect(akID).To(HavePrefix("GK"))
			Expect(akID).To(HaveLen(26))
			// All chars after GK prefix must be hex (0-9a-f)
			for _, c := range akID[2:] {
				Expect("0123456789abcdef").To(ContainSubstring(string(c)))
			}
		})
	})
})
