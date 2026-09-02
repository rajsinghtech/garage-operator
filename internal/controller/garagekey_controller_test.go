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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

var _ = Describe("GarageKey Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-key"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup the GarageKey
			key := &garagev1beta1.GarageKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, key)
			if err == nil {
				key.Finalizers = nil
				_ = k8sClient.Update(ctx, key)
				_ = k8sClient.Delete(ctx, key)
			}
		})

		It("should set error status when cluster doesn't exist", func() {
			By("Creating a GarageKey referencing non-existent cluster")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
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
			updatedKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedKey)).To(Succeed())
			Expect(updatedKey.Status.Phase).To(Equal(PhasePending))
		})

		It("should handle key creation spec with bucket permissions", func() {
			By("Creating a GarageKey with bucket permissions")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					BucketPermissions: []garagev1beta1.BucketPermission{
						{
							BucketRef: &garagev1beta1.BucketRef{Name: "test-bucket"},
							Read:      true,
							Write:     true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key spec was stored correctly")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.BucketPermissions).To(HaveLen(1))
			Expect(createdKey.Spec.BucketPermissions[0].BucketRef).To(Equal(&garagev1beta1.BucketRef{Name: "test-bucket"}))
			Expect(createdKey.Spec.BucketPermissions[0].Read).To(BeTrue())
		})

		It("should handle key with createBucket permission", func() {
			By("Creating a GarageKey with createBucket permission")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Permissions: &garagev1beta1.KeyPermissions{
						CreateBucket: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.Permissions).NotTo(BeNil())
			Expect(createdKey.Spec.Permissions.CreateBucket).To(BeTrue())
		})

		It("should handle key with custom secret template", func() {
			By("Creating a GarageKey with secret template")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					SecretTemplate: &garagev1beta1.SecretTemplate{
						Name: "custom-secret-name",
						Labels: map[string]string{
							"app": "test",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created with template")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.SecretTemplate).NotTo(BeNil())
			Expect(createdKey.Spec.SecretTemplate.Name).To(Equal("custom-secret-name"))
		})

		It("should handle key with allBuckets cluster-wide permissions", func() {
			By("Creating a GarageKey with allBuckets")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					AllBuckets: &garagev1beta1.AllBucketsPermission{
						Read:  true,
						Write: true,
						Owner: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key spec was stored correctly")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.AllBuckets).NotTo(BeNil())
			Expect(createdKey.Spec.AllBuckets.Read).To(BeTrue())
			Expect(createdKey.Spec.AllBuckets.Write).To(BeTrue())
			Expect(createdKey.Spec.AllBuckets.Owner).To(BeTrue())
		})

		It("should handle key with allBuckets removed (revocation tracking)", func() {
			By("Creating a GarageKey with allBuckets set")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					AllBuckets: &garagev1beta1.AllBucketsPermission{
						Read: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying allBuckets is stored")
			createdKey := &garagev1beta1.GarageKey{}
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
			updatedKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedKey)).To(Succeed())
			Expect(updatedKey.Spec.AllBuckets).To(BeNil())
			Expect(updatedKey.Status.ClusterWide).To(BeTrue())
		})

		It("should handle key with allBuckets and bucketPermissions", func() {
			By("Creating a GarageKey with both allBuckets and bucketPermissions")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					AllBuckets: &garagev1beta1.AllBucketsPermission{
						Read: true,
					},
					BucketPermissions: []garagev1beta1.BucketPermission{
						{
							BucketRef: &garagev1beta1.BucketRef{Name: "special-bucket"},
							Owner:     true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying both are stored")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.AllBuckets).NotTo(BeNil())
			Expect(createdKey.Spec.AllBuckets.Read).To(BeTrue())
			Expect(createdKey.Spec.BucketPermissions).To(HaveLen(1))
		})

		It("should handle key with expiration", func() {
			By("Creating a GarageKey with expiration")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					ExpiresAt: &metav1.Time{Time: time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)},
				},
			}
			Expect(k8sClient.Create(ctx, key)).To(Succeed())

			By("Verifying the key was created with expiration")
			createdKey := &garagev1beta1.GarageKey{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdKey)).To(Succeed())
			Expect(createdKey.Spec.ExpiresAt).NotTo(BeNil())
			Expect(createdKey.Spec.ExpiresAt.Time).To(BeTemporally("==", time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)))
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
					Namespace: testNamespace,
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
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup
			key := &garagev1beta1.GarageKey{}
			err := k8sClient.Get(ctx, typeNamespacedName, key)
			if err == nil {
				key.Finalizers = nil
				_ = k8sClient.Update(ctx, key)
				_ = k8sClient.Delete(ctx, key)
			}
		})

		It("should handle deletion request gracefully", func() {
			By("Creating the GarageKey resource")
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
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
			finalKey := &garagev1beta1.GarageKey{}
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

	Describe("finalize pre-revokes bucket grants before DeleteKey", func() {
		// Spins up a mock Garage admin server that lets each test override
		// per-bucket DenyBucketKey behavior (status code + optional sleep).
		type denyResp struct {
			delay  time.Duration
			status int
		}

		const (
			testAccessKeyID = "GKtestkey1234567890abcdef"
			bucketIDGood1   = "11111111111111111111111111111111"
			bucketIDStuck   = "22222222222222222222222222222222"
			bucketIDGood2   = "33333333333333333333333333333333"
		)

		buildKey := func() *garagev1beta1.GarageKey {
			return &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testNamespace},
				Status: garagev1beta1.GarageKeyStatus{
					AccessKeyID: testAccessKeyID,
					Buckets: []garagev1beta1.KeyBucketAccess{
						{BucketID: bucketIDGood1, Read: true},
						{BucketID: bucketIDStuck, Read: true, Write: true},
						{BucketID: bucketIDGood2, Owner: true},
					},
				},
			}
		}

		newServer := func(denyBehavior map[string]denyResp, deleteKeyStatus int, denyCalls *[]string, deleteCalls *int32) *httptest.Server {
			var mu sync.Mutex
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/DenyBucketKey"):
					var req garage.DenyBucketKeyRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					mu.Lock()
					*denyCalls = append(*denyCalls, req.BucketID)
					mu.Unlock()
					beh, ok := denyBehavior[req.BucketID]
					if !ok {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{}`))
						return
					}
					if beh.delay > 0 {
						select {
						case <-time.After(beh.delay):
						case <-r.Context().Done():
							return
						}
					}
					status := beh.status
					if status == 0 {
						status = http.StatusOK
					}
					w.WriteHeader(status)
					if status == http.StatusOK {
						_, _ = w.Write([]byte(`{}`))
					}
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/DeleteKey"):
					atomic.AddInt32(deleteCalls, 1)
					status := deleteKeyStatus
					if status == 0 {
						status = http.StatusOK
					}
					w.WriteHeader(status)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
		}

		It("revokes the surviving buckets and still calls DeleteKey when one DenyBucketKey errors", func() {
			var denyCalls []string
			var deleteCalls int32
			srv := newServer(map[string]denyResp{
				bucketIDStuck: {status: http.StatusInternalServerError},
			}, http.StatusOK, &denyCalls, &deleteCalls)
			defer srv.Close()

			r := &GarageKeyReconciler{}
			err := r.finalize(context.Background(), buildKey(), nil, garage.NewClient(srv.URL, "tok"))

			Expect(err).NotTo(HaveOccurred())
			Expect(denyCalls).To(ConsistOf(bucketIDGood1, bucketIDStuck, bucketIDGood2))
			Expect(atomic.LoadInt32(&deleteCalls)).To(Equal(int32(1)))
		})

		It("treats a NotFound from DeleteKey after pre-revoke as success", func() {
			var denyCalls []string
			var deleteCalls int32
			srv := newServer(nil, http.StatusNotFound, &denyCalls, &deleteCalls)
			defer srv.Close()

			r := &GarageKeyReconciler{}
			err := r.finalize(context.Background(), buildKey(), nil, garage.NewClient(srv.URL, "tok"))

			Expect(err).NotTo(HaveOccurred())
			Expect(denyCalls).To(HaveLen(3))
			Expect(atomic.LoadInt32(&deleteCalls)).To(Equal(int32(1)))
		})

		It("pre-revokes grants preserved only in managedBucketGrants", func() {
			var denyCalls []string
			var deleteCalls int32
			srv := newServer(nil, http.StatusOK, &denyCalls, &deleteCalls)
			defer srv.Close()

			key := buildKey()
			key.Status.Buckets = nil
			key.Status.ManagedBucketGrants = []string{bucketIDGood2}
			err := (&GarageKeyReconciler{}).finalize(context.Background(), key, nil, garage.NewClient(srv.URL, "tok"))

			Expect(err).NotTo(HaveOccurred())
			Expect(denyCalls).To(Equal([]string{bucketIDGood2}))
			Expect(atomic.LoadInt32(&deleteCalls)).To(Equal(int32(1)))
		})

		It("does not let a slow DenyBucketKey block subsequent buckets or DeleteKey", func() {
			var denyCalls []string
			var deleteCalls int32
			// Hang the stuck bucket past the per-call timeout but well under the
			// total test budget. The other two must still be called and DeleteKey
			// must still fire.
			srv := newServer(map[string]denyResp{
				bucketIDStuck: {delay: 20 * time.Second},
			}, http.StatusOK, &denyCalls, &deleteCalls)
			defer srv.Close()

			r := &GarageKeyReconciler{}

			done := make(chan error, 1)
			start := time.Now()
			go func() {
				done <- r.finalize(context.Background(), buildKey(), nil, garage.NewClient(srv.URL, "tok"))
			}()

			select {
			case err := <-done:
				elapsed := time.Since(start)
				Expect(err).NotTo(HaveOccurred())
				// Should finish at roughly one per-call timeout (15s) for the stuck
				// bucket plus negligible time for the others — well under 30s.
				Expect(elapsed).To(BeNumerically("<", 25*time.Second),
					"finalize should not be blocked by the full upstream delay")
				Expect(denyCalls).To(ConsistOf(bucketIDGood1, bucketIDStuck, bucketIDGood2))
				Expect(atomic.LoadInt32(&deleteCalls)).To(Equal(int32(1)))
			case <-time.After(45 * time.Second):
				Fail("finalize blocked past the per-call timeout budget")
			}
		})
	})
})

var _ = Describe("GarageKey server-side apply migration", func() {
	It("accepts an allBuckets grant reapplied as scoped permissions", func() {
		const (
			name       = "all-buckets-migration"
			fieldOwner = "garagekey-migration-test"
		)
		object := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: testNamespace,
		}}
		initial := []byte(`{
			"apiVersion":"garage.rajsingh.info/v1beta1",
			"kind":"GarageKey",
			"metadata":{"name":"all-buckets-migration","namespace":"default"},
			"spec":{"clusterRef":{"name":"test-cluster"},"allBuckets":{"read":true}}
		}`)
		// Apply the original cluster-wide declaration with the same field owner
		// used for the migration. This makes the second apply model the real
		// omission of allBuckets from a previously managed configuration.
		Expect(k8sClient.Patch(ctx, object, client.RawPatch(types.ApplyPatchType, initial),
			client.FieldOwner(fieldOwner), client.ForceOwnership)).To(Succeed())
		DeferCleanup(func() {
			stored := &garagev1beta1.GarageKey{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, stored); err == nil {
				stored.Finalizers = nil
				_ = k8sClient.Update(ctx, stored)
				_ = k8sClient.Delete(ctx, stored)
			}
		})

		stored := &garagev1beta1.GarageKey{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, stored)).To(Succeed())
		Expect(stored.Spec.AllBuckets).NotTo(BeNil())
		Expect(stored.Spec.AllBuckets.Read).To(BeTrue())

		migration := []byte(`{
			"apiVersion":"garage.rajsingh.info/v1beta1",
			"kind":"GarageKey",
			"metadata":{"name":"all-buckets-migration","namespace":"default"},
			"spec":{"clusterRef":{"name":"test-cluster"},"bucketPermissions":[{"bucketId":"scoped-bucket","read":true}]}
		}`)
		Expect(k8sClient.Patch(ctx, object, client.RawPatch(types.ApplyPatchType, migration),
			client.FieldOwner(fieldOwner), client.ForceOwnership)).To(Succeed())

		migrated := &garagev1beta1.GarageKey{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, migrated)).To(Succeed())
		Expect(migrated.Spec.BucketPermissions).To(HaveLen(1))
		// Depending on field ownership, the apiserver may remove the optional
		// parent or retain it as an all-false object after the omission. Both
		// representations mean that no cluster-wide permissions are desired.
		effective := migrated.DeepCopy()
		if effective.Spec.AllBuckets == nil {
			// The envtest apiserver removes the parent for this field-owner
			// sequence. Exercise the retained/defaulted representation too; that
			// is the shape produced by the production migration.
			effective.Spec.AllBuckets = &garagev1beta1.AllBucketsPermission{}
		}
		Expect(*effective.Spec.AllBuckets).To(Equal(garagev1beta1.AllBucketsPermission{}))
		Expect(garagev1beta1.ValidateGarageKeySpec(effective)).To(Succeed())
	})
})
