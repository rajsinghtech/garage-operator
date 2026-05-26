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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
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

		It("should reject GarageNode reconciliation unless the cluster is Manual", func() {
			clusterName := "auto-node-cluster"
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: "Auto",
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			defer func() {
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}()

			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: &dataSize},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			reconciler := &GarageNodeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedNode)).To(Succeed())
			Expect(updatedNode.Status.Phase).To(Equal(PhaseFailed))
			Expect(updatedNode.Status.Conditions).To(ContainElement(
				HaveField("Message", ContainSubstring("layoutPolicy: Manual")),
			))

			err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespace}, &appsv1.StatefulSet{})
			Expect(errors.IsNotFound(err)).To(BeTrue())
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
	makeFeatureCluster := func(ctx context.Context, name string) *garagev1beta2.GarageCluster {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: featureNamespace,
			},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		return cluster
	}

	cleanupCluster := func(ctx context.Context, name string) {
		c := &garagev1beta2.GarageCluster{}
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
					Network:    &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: testIPv4RPCAddr},
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
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "` + testIPv4RPCAddr + `"`))
		})

		It("uses node rpcPublicAddr even when cluster has its own rpcPublicAddr", func() {
			clusterWithAddr := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: featureNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
					Network:      garagev1beta2.NetworkConfig{RPCPublicAddr: "cluster-addr:3901"},
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
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
			cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: featureNamespace}}
			pvcs := r.buildNodeVolumeClaimTemplates(node, cluster)

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

	Context("maintenance.suspended pauses reconciliation", func() {
		const (
			clusterName = "node-maint-cluster"
			nodeName    = "node-maint-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace}})
		})

		// makeSuspendedNode creates a GarageNode with maintenance.suspended=true.
		makeSuspendedNode := func(suspended bool) *garagev1beta1.GarageNode {
			capacity := resource.MustParse("100Gi")
			return &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef:  garagev1beta1.ClusterReference{Name: clusterName},
					Zone:        testNodeZone,
					Capacity:    &capacity,
					Maintenance: &garagev1beta1.NodeMaintenanceSpec{Suspended: suspended},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
		}

		It("skips StatefulSet creation when suspended", func() {
			makeFeatureCluster(ctx, clusterName)
			node := makeSuspendedNode(true)
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			By("reconciling — first pass adds the finalizer")
			r := reconciler()
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("reconciling — second pass hits the suspension early-return")
			result, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(RequeueAfterLong))

			By("verifying no StatefulSet was created")
			sts := &appsv1.StatefulSet{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, sts)
			Expect(errors.IsNotFound(err)).To(BeTrue())

			By("verifying Suspended condition is True")
			updated := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Conditions).To(ContainElement(SatisfyAll(
				HaveField("Type", "Suspended"),
				HaveField("Status", metav1.ConditionTrue),
				HaveField("Reason", "MaintenanceSuspended"),
			)))
		})

		It("skips reconciliation even when a StatefulSet already exists", func() {
			cluster := makeFeatureCluster(ctx, clusterName)

			By("creating a node in non-suspended state and reconciling the StatefulSet directly")
			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			Expect(reconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

			By("flipping the node into maintenance mode")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, node)).To(Succeed())
			node.Spec.Maintenance = &garagev1beta1.NodeMaintenanceSpec{Suspended: true}
			// Add the finalizer manually so the reconciler skips the finalizer-add path
			// and hits the suspension check on the first pass.
			node.Finalizers = append(node.Finalizers, garageNodeFinalizer)
			Expect(k8sClient.Update(ctx, node)).To(Succeed())

			By("reconciling — must not call the garage admin API (no client configured)")
			r := reconciler()
			result, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred(), "must not attempt admin-API calls while suspended")
			Expect(result.RequeueAfter).To(Equal(RequeueAfterLong))

			By("verifying the existing StatefulSet was left alone")
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, sts)).To(Succeed())
		})

		It("clears the Suspended condition when unsuspended", func() {
			makeFeatureCluster(ctx, clusterName)
			node := makeSuspendedNode(true)
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			r := reconciler()
			By("reconciling while suspended to set the condition")
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Conditions).To(ContainElement(HaveField("Type", "Suspended")))

			By("flipping suspended to false and reconciling again")
			updated.Spec.Maintenance.Suspended = false
			Expect(k8sClient.Update(ctx, updated)).To(Succeed())

			// This reconcile will go past the suspension check and attempt full
			// reconciliation. It may fail later (no real pod for node discovery),
			// but the Suspended condition must be cleared regardless.
			_, _ = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})

			final := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, final)).To(Succeed())
			for _, c := range final.Status.Conditions {
				Expect(c.Type).NotTo(Equal("Suspended"), "Suspended condition should be removed when not suspended")
			}

			By("verifying a StatefulSet was created (reconciliation resumed)")
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, sts)).To(Succeed())
		})

		It("allows deletion of a suspended node (finalizer logic runs)", func() {
			makeFeatureCluster(ctx, clusterName)
			node := makeSuspendedNode(true)
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			r := reconciler()
			By("reconciling so the finalizer gets attached")
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("requesting deletion")
			Expect(k8sClient.Delete(ctx, node)).To(Succeed())

			By("reconciling — the deletion path runs even while suspended (admin API unavailable means finalizer remains but path is exercised)")
			_, err = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName, Namespace: featureNamespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the deletion path was taken — node has a DeletionTimestamp or is gone")
			final := &garagev1beta1.GarageNode{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, final)
			if err == nil {
				Expect(final.DeletionTimestamp).NotTo(BeNil(), "suspended node must enter terminating state on delete")
			} else {
				Expect(errors.IsNotFound(err)).To(BeTrue())
			}
		})
	})
})

var _ = Describe("GarageNode multi-HDD storage layout", func() {
	const (
		clusterName = "multihdd-cluster"
		nodeName    = "multihdd-node"
	)

	makeCluster := func(ctx context.Context) *garagev1beta2.GarageCluster {
		c := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
		return c
	}

	cleanup := func(ctx context.Context) {
		n := &garagev1beta1.GarageNode{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, n)
			_ = k8sClient.Delete(ctx, n)
		}
		c := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, c); err == nil {
			c.Finalizers = nil
			_ = k8sClient.Update(ctx, c)
			_ = k8sClient.Delete(ctx, c)
		}
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-config", Namespace: testNamespace}})
	}

	AfterEach(func() { cleanup(ctx) })

	It("emits one mount + one PVC template per dataPaths entry, named data-<i>", func() {
		_ = makeCluster(ctx)
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					DataPaths: []garagev1beta1.NodeVolumeConfig{
						{Size: ptrQuantity(resource.MustParse("50Gi"))},
						{Size: ptrQuantity(resource.MustParse("50Gi"))},
					},
				},
			},
		}
		// Don't Create — buildNodeVolumes... is pure and doesn't need a stored CR.

		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace}}
		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, mounts := r.buildNodeVolumesAndMounts(node, cluster)

		// Two data mounts at /data/data-0 and /data/data-1.
		mountByName := map[string]string{}
		for _, m := range mounts {
			mountByName[m.Name] = m.MountPath
		}
		for i := 0; i < 2; i++ {
			Expect(mountByName[fmt.Sprintf("data-%d", i)]).To(Equal(fmt.Sprintf("/data/data-%d", i)))
		}

		templates := r.buildNodeVolumeClaimTemplates(node, cluster)
		names := make([]string, 0, len(templates))
		for _, t := range templates {
			names = append(names, t.Name)
		}
		Expect(names).To(ContainElement("metadata"))
		for i := 0; i < 2; i++ {
			Expect(names).To(ContainElement(fmt.Sprintf("data-%d", i)))
		}
		Expect(names).NotTo(ContainElement("data"), "single-HDD PVC must not be emitted in multi-HDD mode")
	})

	It("writes a TOML data_dir array into the per-node ConfigMap", func() {
		cluster := makeCluster(ctx)
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					DataPaths: []garagev1beta1.NodeVolumeConfig{
						{Size: ptrQuantity(resource.MustParse("50Gi"))},
						{Size: ptrQuantity(resource.MustParse("70Gi"))},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-config", Namespace: testNamespace}, cm)).To(Succeed())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring("data_dir = ["))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-0", capacity = "50Gi" }`))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-1", capacity = "70Gi" }`))
	})
})

var _ = Describe("GarageNode per-node env/envFrom/logging/snapshots", func() {
	const (
		clusterName = "parity-cluster"
		nodeName    = "parity-node"
	)

	makeCluster := func(ctx context.Context, env []corev1.EnvVar, logging *garagev1beta2.LoggingConfig) *garagev1beta2.GarageCluster {
		c := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas:    1,
					Metadata:    &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:        &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					PodTemplate: garagev1beta2.PodTemplate{Env: env},
				},
				Logging: logging,
			},
		}
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
		return c
	}

	cleanup := func(ctx context.Context) {
		n := &garagev1beta1.GarageNode{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, n)
			_ = k8sClient.Delete(ctx, n)
		}
		c := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, c); err == nil {
			c.Finalizers = nil
			_ = k8sClient.Update(ctx, c)
			_ = k8sClient.Delete(ctx, c)
		}
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-config", Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace}})
	}

	AfterEach(func() { cleanup(ctx) })

	It("merges cluster + node env with node entries overriding by Name", func() {
		clusterEnv := []corev1.EnvVar{
			{Name: "FOO", Value: "cluster-foo"},
			{Name: "BAR", Value: "cluster-bar"},
		}
		cluster := makeCluster(ctx, clusterEnv, nil)
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				},
				Env: []corev1.EnvVar{
					{Name: "BAR", Value: "node-bar"},
					{Name: "BAZ", Value: "node-baz"},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

		sts := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, sts)).To(Succeed())

		envByName := map[string]string{}
		for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
			envByName[e.Name] = e.Value
		}
		Expect(envByName["FOO"]).To(Equal("cluster-foo"))
		Expect(envByName["BAR"]).To(Equal("node-bar"), "node env should override cluster env with the same Name")
		Expect(envByName["BAZ"]).To(Equal("node-baz"))
	})

	It("uses per-node logging override over cluster logging", func() {
		clusterLogging := &garagev1beta2.LoggingConfig{Level: "info"}
		cluster := makeCluster(ctx, nil, clusterLogging)
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				},
				Logging: &garagev1beta1.NodeLoggingConfig{Level: "debug"},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

		sts := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, sts)).To(Succeed())

		rustLog := ""
		for _, e := range sts.Spec.Template.Spec.Containers[0].Env {
			if e.Name == "RUST_LOG" {
				rustLog = e.Value
			}
		}
		Expect(rustLog).To(Equal("debug"))
	})

	It("writes per-node metadata snapshot overrides into the ConfigMap", func() {
		cluster := makeCluster(ctx, nil, nil)
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Data:                         &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					MetadataSnapshotsDir:         "/data/snaps",
					MetadataAutoSnapshotInterval: "12h",
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-config", Namespace: testNamespace}, cm)).To(Succeed())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring(`metadata_snapshots_dir = "/data/snaps"`))
		Expect(toml).To(ContainSubstring(`metadata_auto_snapshot_interval = "12h"`))
	})
})

var _ = Describe("GarageNode labelsForNode tier label", func() {
	// labelsForNode must include garage.rajsingh.info/tier so that the
	// cluster-level <cr> API Service (selector: {labelCluster, labelTier=storage})
	// matches per-node GarageNode pods. Without this label the Service has no
	// endpoints and admin/S3 traffic to <cr>.<ns>.svc fails.
	const (
		clusterName = "labelfornode-cluster"
		nsName      = "labelfornode-ns"
	)
	r := &GarageNodeReconciler{}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: nsName},
	}

	It("tags a storage GarageNode with tier=storage", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-storage-0", Namespace: nsName},
			Spec:       garagev1beta1.GarageNodeSpec{},
		}
		labels := r.labelsForNode(node, cluster)
		Expect(labels).To(HaveKeyWithValue(labelTier, tierStorage))
		Expect(labels).To(HaveKeyWithValue(labelCluster, clusterName))
	})

	It("tags a gateway GarageNode with tier=gateway", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-gateway-0", Namespace: nsName},
			Spec:       garagev1beta1.GarageNodeSpec{Gateway: true},
		}
		labels := r.labelsForNode(node, cluster)
		Expect(labels).To(HaveKeyWithValue(labelTier, tierGateway))
		Expect(labels).To(HaveKeyWithValue(labelCluster, clusterName))
	})

	// v0.6.1: storage pods carry the cluster-shared {app.kubernetes.io/name=garage,
	// app.kubernetes.io/instance=<cluster-name>} pair so user-defined Services
	// (Tailscale LBs, etc.) that select on the pre-#190 convention keep matching.
	// Regression guard for the v0.6.0 cross-cluster outage where storage pods
	// carried {name=garagenode, instance=<node-name>} and silently broke
	// externally-defined LoadBalancers.
	It("stamps storage pods with cluster-shared name+instance labels (legacy-compat)", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-storage-0", Namespace: nsName},
			Spec:       garagev1beta1.GarageNodeSpec{},
		}
		labels := r.labelsForNode(node, cluster)
		Expect(labels).To(HaveKeyWithValue(labelAppName, defaultAppName))
		Expect(labels).To(HaveKeyWithValue(labelAppInstance, clusterName))
		Expect(labels).To(HaveKeyWithValue(labelGarageNode, clusterName+"-storage-0"))
	})

	// The STS selector must be unique per GarageNode (so each per-node STS
	// owns exactly its own pod) AND must NOT contain labelAppName/Instance
	// (whose values are cluster-shared and would conflict with the immutable
	// per-STS selector contract).
	It("emits a per-node selector that omits cluster-shared app.kubernetes.io labels", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-storage-0", Namespace: nsName},
		}
		sel := r.selectorLabelsForNode(node)
		Expect(sel).To(HaveKeyWithValue(labelGarageNode, clusterName+"-storage-0"))
		Expect(sel).To(HaveKeyWithValue(labelAppManagedBy, operatorName))
		Expect(sel).NotTo(HaveKey(labelAppName))
		Expect(sel).NotTo(HaveKey(labelAppInstance))
	})
})

// Regression guard for #196 follow-ups: spec.storage.pvcRetentionPolicy was
// silently dropped after #192 on per-node STSes (the gateway STS still wired
// it in via garagecluster_gateway.go). Storage STSes now honor it too.
var _ = Describe("stsPVCRetentionPolicy", func() {
	mkNode := func(gateway bool) *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{Spec: garagev1beta1.GarageNodeSpec{Gateway: gateway}}
	}
	mkCluster := func(rp *garagev1beta2.PVCRetentionPolicy) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{PVCRetentionPolicy: rp},
		}}
	}

	It("returns nil for gateway nodes (gateway STS owns its own policy)", func() {
		got := stsPVCRetentionPolicy(mkCluster(&garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete}), mkNode(true))
		Expect(got).To(BeNil())
	})

	It("returns nil when cluster.storage.pvcRetentionPolicy is unset (k8s default of Retain stands)", func() {
		got := stsPVCRetentionPolicy(mkCluster(nil), mkNode(false))
		Expect(got).To(BeNil())
	})

	It("translates WhenDeleted=Delete and WhenScaled=Delete", func() {
		got := stsPVCRetentionPolicy(mkCluster(&garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete, WhenScaled: pvcRetentionDelete}), mkNode(false))
		Expect(got).NotTo(BeNil())
		Expect(got.WhenDeleted).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
		Expect(got.WhenScaled).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
	})

	It("defaults missing fields to Retain", func() {
		got := stsPVCRetentionPolicy(mkCluster(&garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete}), mkNode(false))
		Expect(got).NotTo(BeNil())
		Expect(got.WhenDeleted).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
		Expect(got.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
	})
})

// Regression guard for #196 follow-up: PVC expansion path was deleted with
// reconcilePVCExpansion in #192 and never reimplemented. Bumping
// spec.storage.metadata.size silently no-op'd. expandNodePVCs now patches
// bound PVCs in place when the desired size grows.
//
// envtest's API server enforces PVC spec immutability (no provisioner/CSI
// to service the resize), so the happy-path expansion is exercised via a
// fake client that doesn't apply that admission check. Real clusters with
// a CSI driver and allowVolumeExpansion=true accept the same Update.
var _ = Describe("expandNodePVCs", func() {
	const (
		ns       = "default"
		nodeName = "expand-node"
	)
	var (
		ctx     context.Context
		cluster *garagev1beta2.GarageCluster
		scheme  *runtime.Scheme
	)

	mkPVC := func(name, size string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)}},
			},
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		cluster = &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "expand-cluster", Namespace: ns}}
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
	})

	It("expands the metadata PVC when spec.storage.metadata.size grows", func() {
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkPVC("metadata-"+nodeName+"-0", "1Gi"),
			mkPVC("data-"+nodeName+"-0", "10Gi"),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		newMeta := resource.MustParse("5Gi")
		oldData := resource.MustParse("10Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &newMeta},
					Data:     &garagev1beta1.NodeVolumeConfig{Size: &oldData},
				},
			},
		}
		Expect(r.expandNodePVCs(ctx, node, cluster)).To(Succeed())

		got := &corev1.PersistentVolumeClaim{}
		Expect(fc.Get(ctx, types.NamespacedName{Name: "metadata-" + nodeName + "-0", Namespace: ns}, got)).To(Succeed())
		Expect(got.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(newMeta))
	})

	It("does not shrink a PVC when the spec is smaller (storage class would reject anyway)", func() {
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkPVC("metadata-"+nodeName+"-0", "5Gi"),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		smaller := resource.MustParse("1Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &smaller},
				},
			},
		}
		Expect(r.expandNodePVCs(ctx, node, cluster)).To(Succeed())

		got := &corev1.PersistentVolumeClaim{}
		Expect(fc.Get(ctx, types.NamespacedName{Name: "metadata-" + nodeName + "-0", Namespace: ns}, got)).To(Succeed())
		Expect(got.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(resource.MustParse("5Gi")))
	})

	It("skips PVCs bound via existingClaim (user-managed)", func() {
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkPVC("legacy-meta", "1Gi"),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		bigger := resource.MustParse("5Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{ExistingClaim: "legacy-meta", Size: &bigger},
				},
			},
		}
		Expect(r.expandNodePVCs(ctx, node, cluster)).To(Succeed())

		got := &corev1.PersistentVolumeClaim{}
		Expect(fc.Get(ctx, types.NamespacedName{Name: "legacy-meta", Namespace: ns}, got)).To(Succeed())
		Expect(got.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(resource.MustParse("1Gi")))
	})
})

// Bug #4 — orphaned-finalize path. When the parent GarageCluster CR is gone
// and the GarageNode is being deleted, the operator MUST attempt a best-effort
// layout removal against the captured external admin endpoint (so we don't
// leave a dead layout entry on the remote cluster) but MUST NOT block
// finalizer release indefinitely if the remote call fails.
const goneClusterName = "gone-cluster"

var _ = Describe("GarageNode orphaned-finalize against external admin endpoint", func() {
	const (
		ns         = "orphan-finalize-ns"
		nodeName   = "orphan-finalize-node"
		secretName = "ext-admin-token"
		nodeID     = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	)

	var (
		bctx   context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		bctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
	})

	// mockGarage builds a tiny admin-API mock that counts UpdateClusterLayout
	// and ApplyClusterLayout calls so the test can assert removal was attempted.
	mockGarage := func(extraNodeID string) (*httptest.Server, *int32, *int32) {
		var updates, applies int32
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/GetClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
			roles := []garage.LayoutRole{{ID: extraNodeID, Zone: "z"}}
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 1, Roles: roles})
		})
		mux.HandleFunc("/v2/UpdateClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&updates, 1)
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/v2/ApplyClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&applies, 1)
			w.WriteHeader(http.StatusOK)
		})
		return httptest.NewServer(mux), &updates, &applies
	}

	It("calls UpdateClusterLayout+ApplyClusterLayout against the captured admin endpoint when the parent cluster is NotFound", func() {
		srv, updates, applies := mockGarage(nodeID)
		defer srv.Close()

		// The admin token secret survives the cluster deletion (typical
		// when it's user-managed). Token value matches what the mock would
		// accept — the mock doesn't actually validate, but we still want
		// the request to be well-formed.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte("test-token")},
		}

		// GarageNode with the orphaned-finalize hints captured on Status,
		// a DeletionTimestamp, and the finalizer still set. Spec.ClusterRef
		// points at a cluster that has already been deleted.
		now := metav1.Now()
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:              nodeName,
				Namespace:         ns,
				Finalizers:        []string{garageNodeFinalizer},
				DeletionTimestamp: &now,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: goneClusterName},
				Zone:       "z",
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID:               nodeID,
				ClusterAdminEndpoint: srv.URL,
				ClusterAdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  DefaultAdminTokenKey,
				},
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(secret, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: nodeName, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(atomic.LoadInt32(updates)).To(Equal(int32(1)),
			"expected exactly one UpdateClusterLayout call against captured admin endpoint")
		Expect(atomic.LoadInt32(applies)).To(Equal(int32(1)),
			"expected exactly one ApplyClusterLayout call against captured admin endpoint")

		expectFinalizerReleased(bctx, fc, nodeName, ns)
	})

	It("releases the finalizer even when the captured admin endpoint is unreachable", func() {
		// Build a server, then close it immediately so the URL fails on
		// dial. The 5s timeout in attemptOrphanedFinalize keeps the test
		// fast.
		srv, _, _ := mockGarage(nodeID)
		srv.Close()

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte("test-token")},
		}
		now := metav1.Now()
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:              nodeName,
				Namespace:         ns,
				Finalizers:        []string{garageNodeFinalizer},
				DeletionTimestamp: &now,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: goneClusterName},
				Zone:       "z",
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID:               nodeID,
				ClusterAdminEndpoint: srv.URL,
				ClusterAdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  DefaultAdminTokenKey,
				},
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(secret, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: nodeName, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())

		expectFinalizerReleased(bctx, fc, nodeName, ns)
	})

	It("releases the finalizer immediately when no admin endpoint was captured (unified cluster path)", func() {
		now := metav1.Now()
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:              nodeName,
				Namespace:         ns,
				Finalizers:        []string{garageNodeFinalizer},
				DeletionTimestamp: &now,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: goneClusterName},
				Zone:       "z",
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: nodeName, Namespace: ns},
		})
		Expect(err).NotTo(HaveOccurred())

		expectFinalizerReleased(bctx, fc, nodeName, ns)
	})
})

// expectFinalizerReleased asserts that the named GarageNode either no longer
// exists (fake client GC'd it once the last finalizer was dropped) or still
// exists without the garageNodeFinalizer. Either outcome is correct — both
// mean the operator released the finalizer.
func expectFinalizerReleased(ctx context.Context, c client.Client, name, namespace string) {
	got := &garagev1beta1.GarageNode{}
	err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, got)
	if err == nil {
		Expect(controllerutil.ContainsFinalizer(got, garageNodeFinalizer)).To(BeFalse(),
			"GarageNode %s/%s still carries the finalizer after delete", namespace, name)
		return
	}
	Expect(errors.IsNotFound(err)).To(BeTrue(),
		"unexpected error fetching GarageNode %s/%s: %v", namespace, name, err)
}

// Bug #6 — nodesForClusterConfigMap mapper. The cluster controller owns the
// cluster-shared `<cluster>-config` ConfigMap. GarageNode's own
// Owns(ConfigMap) only catches the per-node override CM (absent on Auto-mode
// nodes without overrides), so a cluster CM rewrite would otherwise sit
// unrolled until the next periodic requeue. The mapper must enqueue every
// matching GarageNode and ignore unrelated CMs.
var _ = Describe("nodesForClusterConfigMap mapper", func() {
	const ns = "cm-mapper-ns"

	var (
		bctx   context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		bctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
	})

	mkNode := func(name, clusterName string) *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       "z",
			},
		}
	}

	It("enqueues every GarageNode whose ClusterRef matches the labelled cluster CM", func() {
		const clusterName = "stable-cluster"
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName + "-config",
				Namespace: ns,
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelAppManagedBy: operatorName,
				},
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkNode("n1", clusterName),
			mkNode("n2", clusterName),
			mkNode("n-other", "other-cluster"),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		reqs := r.nodesForClusterConfigMap(bctx, cm)
		names := make([]string, 0, len(reqs))
		for _, req := range reqs {
			names = append(names, req.Name)
		}
		Expect(names).To(ConsistOf("n1", "n2"))
	})

	It("ignores CMs without operator-stamped labels (defense against fan-out storms)", func() {
		const clusterName = "labelless-cluster"
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName + "-config",
				Namespace: ns,
				// No labels — must NOT fan out.
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkNode("n1", clusterName),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		Expect(r.nodesForClusterConfigMap(bctx, cm)).To(BeEmpty())
	})

	It("ignores the gateway-only CM (<cluster>-gateway-config) since no GarageNode consumes it", func() {
		const clusterName = "gw-cluster"
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName + "-gateway-config",
				Namespace: ns,
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelAppManagedBy: operatorName,
				},
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			mkNode("n1", clusterName),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		Expect(r.nodesForClusterConfigMap(bctx, cm)).To(BeEmpty())
	})
})
