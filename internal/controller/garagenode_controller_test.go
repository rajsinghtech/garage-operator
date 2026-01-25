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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

var _ = Describe("GarageNode Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-node"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup the GarageNode
			node := &garagev1alpha1.GarageNode{}
			err := k8sClient.Get(ctx, typeNamespacedName, node)
			if err == nil {
				node.Finalizers = nil
				_ = k8sClient.Update(ctx, node)
				_ = k8sClient.Delete(ctx, node)
			}
		})

		It("should set error status when cluster doesn't exist", func() {
			By("Creating a GarageNode referencing non-existent cluster")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "non-existent-cluster",
					},
					Zone:     "dc1",
					Capacity: &capacity,
					Storage: &garagev1alpha1.NodeStorageSpec{
						Data: &garagev1alpha1.NodeVolumeSource{
							Size: &dataSize,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Reconciling the GarageNode")
			reconciler := &GarageNodeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			// Controller returns requeue result, not error, when cluster not found
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Verifying status phase is Error")
			updatedNode := &garagev1alpha1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedNode)).To(Succeed())
			Expect(updatedNode.Status.Phase).To(Equal(PhaseError))
		})

		It("should handle node creation spec with tags", func() {
			By("Creating a GarageNode with tags")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Zone:     "dc1",
					Capacity: &capacity,
					Tags:     []string{"ssd", "rack-a"},
					Storage: &garagev1alpha1.NodeStorageSpec{
						Data: &garagev1alpha1.NodeVolumeSource{
							Size: &dataSize,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the node spec was stored correctly")
			createdNode := &garagev1alpha1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Tags).To(ContainElements("ssd", "rack-a"))
		})

		It("should handle gateway node (no capacity)", func() {
			By("Creating a GarageNode as gateway")
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Zone:    "dc1",
					Gateway: true,
					Storage: &garagev1alpha1.NodeStorageSpec{
						// Gateway only needs metadata storage
						Metadata: &garagev1alpha1.NodeVolumeSource{
							Size: ptrQuantity(resource.MustParse("1Gi")),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the gateway node was created")
			createdNode := &garagev1alpha1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Gateway).To(BeTrue())
			Expect(createdNode.Spec.Capacity).To(BeNil())
		})

		It("should handle node with storage configuration", func() {
			By("Creating a GarageNode with storage config")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			metadataSize := resource.MustParse("10Gi")
			storageClass := "fast-ssd"
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Zone:     "dc1",
					Capacity: &capacity,
					Storage: &garagev1alpha1.NodeStorageSpec{
						Metadata: &garagev1alpha1.NodeVolumeSource{
							Size:             &metadataSize,
							StorageClassName: &storageClass,
						},
						Data: &garagev1alpha1.NodeVolumeSource{
							Size:             &dataSize,
							StorageClassName: &storageClass,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the node was created with storage config")
			createdNode := &garagev1alpha1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Storage).NotTo(BeNil())
			Expect(createdNode.Spec.Storage.Data).NotTo(BeNil())
			Expect(*createdNode.Spec.Storage.Data.StorageClassName).To(Equal("fast-ssd"))
		})

		It("should handle external node", func() {
			By("Creating a GarageNode with external address")
			capacity := resource.MustParse("100Gi")
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Zone:     "dc1",
					Capacity: &capacity,
					NodeID:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					External: &garagev1alpha1.ExternalNodeConfig{
						Address: "192.168.1.100",
						Port:    3901,
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the external node was created")
			createdNode := &garagev1alpha1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.External).NotTo(BeNil())
			Expect(createdNode.Spec.External.Address).To(Equal("192.168.1.100"))
		})
	})

	Context("When reconciling a non-existent GarageNode", func() {
		It("should return without error", func() {
			reconciler := &GarageNodeReconciler{
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

	Context("When deleting a GarageNode", func() {
		const resourceName = "test-node-delete"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup
			node := &garagev1alpha1.GarageNode{}
			err := k8sClient.Get(ctx, typeNamespacedName, node)
			if err == nil {
				node.Finalizers = nil
				_ = k8sClient.Update(ctx, node)
				_ = k8sClient.Delete(ctx, node)
			}
		})

		It("should handle deletion request gracefully", func() {
			By("Creating the GarageNode resource")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1alpha1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageNodeSpec{
					ClusterRef: garagev1alpha1.ClusterReference{
						Name: "test-cluster",
					},
					Zone:     "dc1",
					Capacity: &capacity,
					Storage: &garagev1alpha1.NodeStorageSpec{
						Data: &garagev1alpha1.NodeVolumeSource{
							Size: &dataSize,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Deleting the node")
			Expect(k8sClient.Delete(ctx, node)).To(Succeed())

			By("Reconciling after deletion request")
			reconciler := &GarageNodeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			By("Verifying the node is deleted or has deletion timestamp")
			finalNode := &garagev1alpha1.GarageNode{}
			err := k8sClient.Get(ctx, typeNamespacedName, finalNode)
			if err == nil {
				// Node still exists - should have deletion timestamp
				Expect(finalNode.DeletionTimestamp).NotTo(BeNil())
			} else {
				// Node was deleted
				Expect(errors.IsNotFound(err)).To(BeTrue())
			}
		})
	})
})
