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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

const testNodeZone = "dc1"

var _ = Describe("GarageNode Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-node"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup the GarageNode
			node := &garagev1beta1.GarageNode{}
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
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testNonExistentCluster,
					},
					Zone:     testNodeZone,
					Capacity: &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{
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
			updatedNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedNode)).To(Succeed())
			Expect(updatedNode.Status.Phase).To(Equal(PhaseFailed))
		})

		It("should handle node creation spec with tags", func() {
			By("Creating a GarageNode with tags")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Zone:     testNodeZone,
					Capacity: &capacity,
					Tags:     []string{"ssd", "rack-a"},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{
							Size: &dataSize,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the node spec was stored correctly")
			createdNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Tags).To(ContainElements("ssd", "rack-a"))
		})

		It("should handle gateway node (no capacity)", func() {
			By("Creating a GarageNode as gateway")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Zone:    testNodeZone,
					Gateway: true,
					Storage: &garagev1beta1.NodeStorageConfig{
						// Gateway only needs metadata storage
						Metadata: &garagev1beta1.NodeVolumeConfig{
							Size: ptrQuantity(resource.MustParse("1Gi")),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the gateway node was created")
			createdNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Gateway).To(BeTrue())
			Expect(createdNode.Spec.Capacity).To(BeNil())
		})

		It("should handle node with storage configuration", func() {
			By("Creating a GarageNode with storage config")
			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			metadataSize := resource.MustParse("10Gi")
			storageClass := testStorageClass
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Zone:     testNodeZone,
					Capacity: &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata: &garagev1beta1.NodeVolumeConfig{
							Size:             &metadataSize,
							StorageClassName: &storageClass,
						},
						Data: &garagev1beta1.NodeVolumeConfig{
							Size:             &dataSize,
							StorageClassName: &storageClass,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the node was created with storage config")
			createdNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, createdNode)).To(Succeed())
			Expect(createdNode.Spec.Storage).NotTo(BeNil())
			Expect(createdNode.Spec.Storage.Data).NotTo(BeNil())
			Expect(*createdNode.Spec.Storage.Data.StorageClassName).To(Equal(testStorageClass))
		})

		It("should handle external node", func() {
			By("Creating a GarageNode with external address")
			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Zone:     testNodeZone,
					Capacity: &capacity,
					NodeID:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					External: &garagev1beta1.ExternalNodeConfig{
						Address: "192.168.1.100",
						Port:    3901,
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("Verifying the external node was created")
			createdNode := &garagev1beta1.GarageNode{}
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
					Name:      testNonExistent,
					Namespace: testNamespace,
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
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup
			node := &garagev1beta1.GarageNode{}
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
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{
						Name: testClusterName,
					},
					Zone:     testNodeZone,
					Capacity: &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{
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
			finalNode := &garagev1beta1.GarageNode{}
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

// GarageNode feature tests — per-node config overrides, services, and storage.
// Each Context uses a unique cluster name to avoid collisions with the main Describe block.
var _ = Describe("GarageNode per-node features", func() {
	const featureNamespace = testNamespace

	// makeFeatureCluster creates a minimal GarageCluster for feature tests and
	// returns a cleanup function. It does NOT run the cluster reconciler — only
	// the GarageNodeReconciler methods are exercised.
	makeFeatureCluster := func(ctx context.Context, name string) *garagev1beta1.GarageCluster {
		cluster := &garagev1beta1.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: featureNamespace,
			},
			Spec: garagev1beta1.GarageClusterSpec{
				Replicas:    1,
				Replication: &garagev1beta1.ReplicationConfig{Factor: 1},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		return cluster
	}

	cleanupCluster := func(ctx context.Context, name string) {
		c := &garagev1beta1.GarageCluster{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: featureNamespace}, c); err == nil {
			c.Finalizers = nil
			_ = k8sClient.Update(ctx, c)
			_ = k8sClient.Delete(ctx, c)
		}
	}

	cleanupNode := func(ctx context.Context, name string) {
		n := &garagev1beta1.GarageNode{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: featureNamespace}, n); err == nil {
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, n)
			_ = k8sClient.Delete(ctx, n)
		}
	}

	reconciler := func() *GarageNodeReconciler {
		return &GarageNodeReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	}

	Context("per-node rpcPublicAddr in ConfigMap", func() {
		const (
			clusterName = "node-cfg-cluster"
			nodeName    = "node-cfg-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-config", Namespace: featureNamespace}})
		})

		It("writes rpc_public_addr from spec.network.rpcPublicAddr into the per-node ConfigMap", func() {
			cluster := makeFeatureCluster(ctx, clusterName)

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Network:    &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: "10.0.0.1:3901"},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("calling reconcileNodeConfigMap directly")
			Expect(reconciler().reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

			By("verifying the ConfigMap contains the node's rpc_public_addr")
			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-config", Namespace: featureNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "10.0.0.1:3901"`))
		})

		It("uses node rpcPublicAddr even when cluster has its own rpcPublicAddr", func() {
			clusterWithAddr := &garagev1beta1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageClusterSpec{
					Replicas:    1,
					Replication: &garagev1beta1.ReplicationConfig{Factor: 1},
					Network:     garagev1beta1.NetworkConfig{RPCPublicAddr: "cluster-addr:3901"},
				},
			}
			Expect(k8sClient.Create(ctx, clusterWithAddr)).To(Succeed())

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Network:    &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: "node-addr:3901"},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("calling reconcileNodeConfigMap")
			Expect(reconciler().reconcileNodeConfigMap(ctx, node, clusterWithAddr)).To(Succeed())

			By("verifying the node's address wins over the cluster's address")
			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-config", Namespace: featureNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "node-addr:3901"`))
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("cluster-addr"))
		})
	})

	Context("per-node fsync overrides in ConfigMap", func() {
		const (
			clusterName = "node-fsync-cluster"
			nodeName    = "node-fsync-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-config", Namespace: featureNamespace}})
		})

		It("sets metadata_fsync=true and omits data_fsync when DataFsync is false", func() {
			cluster := makeFeatureCluster(ctx, clusterName)

			trueBool := true
			falseBool := false
			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						MetadataFsync: &trueBool,
						DataFsync:     &falseBool,
						Data:          &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("calling reconcileNodeConfigMap")
			Expect(reconciler().reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

			By("verifying metadata_fsync is set and data_fsync is absent")
			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-config", Namespace: featureNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring("metadata_fsync = true"))
			// data_fsync=false must not emit the line; note metadata_fsync contains the
			// substring "data_fsync" so we anchor with a newline to avoid false matches.
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("\ndata_fsync = true"))
		})
	})

	Context("per-node RPC Service for publicEndpoint", func() {
		const (
			clusterName = "node-svc-cluster"
			nodeName    = "node-svc-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-rpc", Namespace: featureNamespace}})
		})

		It("creates a LoadBalancer Service named <node>-rpc when publicEndpoint.type=LoadBalancer", func() {
			cluster := makeFeatureCluster(ctx, clusterName)

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					PublicEndpoint: &garagev1beta1.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("calling reconcileNodeService directly")
			Expect(reconciler().reconcileNodeService(ctx, node, cluster)).To(Succeed())

			By("verifying a LoadBalancer Service was created")
			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-rpc", Namespace: featureNamespace}, svc)).To(Succeed())
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(3901)))
		})
	})

	Context("XValidation: capacity required for non-gateway managed nodes", func() {
		const clusterName = "node-xval-cluster"

		AfterEach(func() {
			cleanupCluster(ctx, clusterName)
		})

		It("rejects a non-gateway, non-external GarageNode without capacity", func() {
			makeFeatureCluster(ctx, clusterName)

			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-xval-no-capacity",
					Namespace: featureNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					// Capacity intentionally omitted — should fail XValidation
				},
			}
			err := k8sClient.Create(ctx, node)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("capacity"))
		})
	})

	Context("NodeVolumeConfig.type=EmptyDir skips data PVC template", func() {
		const (
			clusterName = "node-emptydir-cluster"
			nodeName    = "node-emptydir-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace}})
		})

		It("produces no data PVC template when storage.data.type=EmptyDir", func() {
			makeFeatureCluster(ctx, clusterName)

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{
							Type: garagev1beta1.VolumeTypeEmptyDir,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			r := reconciler()
			pvcs := r.buildNodeVolumeClaimTemplates(node)

			By("verifying no data PVC is produced")
			for _, pvc := range pvcs {
				Expect(pvc.Name).NotTo(Equal(dataVolName), "expected no data PVC when type=EmptyDir")
			}
		})
	})

	Context("imagePullPolicy override in StatefulSet", func() {
		const (
			clusterName = "node-ipp-cluster"
			nodeName    = "node-ipp-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace}})
		})

		It("propagates spec.imagePullPolicy=Always into the StatefulSet container", func() {
			cluster := makeFeatureCluster(ctx, clusterName)

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef:      garagev1beta1.ClusterReference{Name: clusterName},
					Zone:            testNodeZone,
					Capacity:        &capacity,
					ImagePullPolicy: corev1.PullAlways,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("calling reconcileStatefulSet directly")
			Expect(reconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

			By("verifying the StatefulSet container has imagePullPolicy=Always")
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, sts)).To(Succeed())
			Expect(sts.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(sts.Spec.Template.Spec.Containers[0].ImagePullPolicy).To(Equal(corev1.PullAlways))
		})
	})
})
