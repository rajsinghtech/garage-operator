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
	"strings"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const testNodeZone = "dc1"

func deleteTestManagedNodePVCs(ctx context.Context, kubeClient client.Client, namespace, nodeName string) error {
	claims := &corev1.PersistentVolumeClaimList{}
	if err := kubeClient.List(ctx, claims, client.InNamespace(namespace), client.MatchingLabels{
		labelGarageNode: nodeName,
	}); err != nil {
		return err
	}
	for i := range claims.Items {
		if len(claims.Items[i].Finalizers) > 0 {
			claims.Items[i].Finalizers = nil
			if err := kubeClient.Update(ctx, &claims.Items[i]); err != nil {
				if errors.IsNotFound(err) {
					continue
				}
				return err
			}
		}
		if err := kubeClient.Delete(ctx, &claims.Items[i]); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

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

		It("should set Pending status (self-heal) when cluster doesn't exist", func() {
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
			// Controller returns requeue result, not error, when cluster not found.
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Verifying status phase is Pending (transient/self-heal, not Failed)")
			// A GarageNode whose referenced cluster is absent but is NOT being
			// deleted keeps its StatefulSet/pods/PVCs running; the operator surfaces
			// Pending and requeues so it self-heals when the cluster reappears,
			// rather than flapping to Failed (which would also let a cluster delete
			// look like a node failure).
			updatedNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedNode)).To(Succeed())
			Expect(updatedNode.Status.Phase).To(Equal(PhasePending))
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

		It("should accept a user storage node when spec.storage.layoutPolicy=Manual even if cluster is Auto", func() {
			// Per-tier policy: storage Manual + cluster (gateway) Auto. A user-owned
			// storage GarageNode must pass the policy gate (its StatefulSet gets
			// created), unlike the cluster-wide-Auto rejection case above.
			clusterName := "tier-manual-cluster"
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: "Auto",
					Storage: &garagev1beta2.StorageSpec{
						Replicas:     1,
						LayoutPolicy: "Manual",
						Metadata:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:         &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			Expect(publishTestClusterConfig(ctx, k8sClient, cluster)).To(Succeed())
			defer func() {
				_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}()

			capacity := resource.MustParse("100Gi")
			dataSize := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
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
			defer func() {
				fresh := &garagev1beta1.GarageNode{}
				if err := k8sClient.Get(ctx, typeNamespacedName, fresh); err == nil {
					fresh.Finalizers = nil
					_ = k8sClient.Update(ctx, fresh)
					_ = k8sClient.Delete(ctx, fresh)
				}
			}()

			reconciler := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			// Passed the policy gate: the StatefulSet gets created (the rejection
			// path returns before StatefulSet creation). The first reconcile adds
			// the finalizer; a later pass creates the STS — so reconcile until it
			// appears (later steps may error in envtest with no Garage admin API,
			// but the STS is created before that point).
			Eventually(func(g Gomega) {
				_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
				sts := &appsv1.StatefulSet{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: testNamespace}, sts)).To(Succeed())
			}).Should(Succeed())

			// And it was never rejected by the per-tier policy gate.
			updatedNode := &garagev1beta1.GarageNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedNode)).To(Succeed())
			for _, c := range updatedNode.Status.Conditions {
				Expect(c.Message).NotTo(ContainSubstring("requires its tier layoutPolicy: Manual"),
					"storage node with storage.layoutPolicy=Manual must not be rejected by the policy gate")
			}
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
		Expect(publishTestClusterConfig(ctx, k8sClient, cluster)).To(Succeed())
		return cluster
	}

	cleanupCluster := func(ctx context.Context, name string) {
		_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, name)
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
		_ = deleteTestManagedNodePVCs(ctx, k8sClient, featureNamespace, name)
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
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
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
			cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
			Expect(err).NotTo(HaveOccurred())
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
			cm, err := testNodeConfigMap(ctx, k8sClient, clusterWithAddr, node)
			Expect(err).NotTo(HaveOccurred())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "node-addr:3901"`))
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("cluster-addr"))
		})

		It("a gateway node does NOT inherit the storage tier's rpc_public_addr (v0.5.3 regression)", func() {
			// Unified cluster: storage tier advertises an rpc_public_addr; the
			// gateway tier has none of its own. A gateway pod inheriting the
			// storage LB hostname routes RPC peers to the wrong node ID and breaks
			// the handshake — the 2026-05-18 cross-cluster outage.
			clusterWithAddr := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: featureNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
					Network:      garagev1beta2.NetworkConfig{RPCPublicAddr: "storage-lb.example.com:3901"},
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
				},
			}
			Expect(k8sClient.Create(ctx, clusterWithAddr)).To(Succeed())

			gwNode := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Gateway:    true,
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gwNode)).To(Succeed())

			Expect(reconciler().reconcileNodeConfigMap(ctx, gwNode, clusterWithAddr)).To(Succeed())

			cm, err := testNodeConfigMap(ctx, k8sClient, clusterWithAddr, gwNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("storage-lb.example.com"),
				"gateway node must not inherit the storage tier rpc_public_addr")
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("rpc_public_addr ="),
				"gateway with no address of its own emits no rpc_public_addr at all")
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
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
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
			cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
			Expect(err).NotTo(HaveOccurred())
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

	Context("NodeVolumeConfig PVC metadata", func() {
		It("applies user labels and annotations while preserving operator labels", func() {
			const backupPolicyAnnotation = "dr.example.com/policy"
			size := resource.MustParse("10Gi")
			selector := &metav1.LabelSelector{MatchLabels: map[string]string{"disk.example.com/name": "manual-data"}}
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: "pvc-metadata-node", Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: "pvc-metadata-cluster"},
					Zone:       testNodeZone,
					Capacity:   &size,
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{
							Size:        &size,
							Selector:    selector,
							Labels:      map[string]string{"backup": "enabled", labelCluster: "overridden"},
							Annotations: map[string]string{backupPolicyAnnotation: "daily"},
						},
					},
				},
			}
			cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "pvc-metadata-cluster", Namespace: featureNamespace}}

			pvcs := reconciler().buildNodeVolumeClaimTemplates(node, cluster)
			var dataPVC *corev1.PersistentVolumeClaim
			for i := range pvcs {
				if pvcs[i].Name == dataVolName {
					dataPVC = &pvcs[i]
				}
			}

			Expect(dataPVC).NotTo(BeNil())
			Expect(dataPVC.Labels).To(HaveKeyWithValue("backup", "enabled"))
			Expect(dataPVC.Labels).To(HaveKeyWithValue(labelCluster, cluster.Name))
			Expect(dataPVC.Annotations).To(HaveKeyWithValue(backupPolicyAnnotation, "daily"))
			Expect(dataPVC.Spec.Selector).To(Equal(selector))
		})

		It("inherits selectors only for exact operator-owned replacement profiles", func() {
			size := resource.MustParse("10Gi")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "selector-upgrade", Namespace: featureNamespace, UID: types.UID("cluster-uid"),
				},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: &size, Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{testDiskTypeLabel: metadataVolName},
						}},
						Data: &garagev1beta2.VolumeConfig{Paths: []garagev1beta2.DataPath{
							{Path: testFastDataPath, Volume: &garagev1beta2.DataPathVolumeConfig{Size: &size, Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{testDiskTypeLabel: testFastValue},
							}}},
						}},
					},
				},
			}
			controller := true
			source := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: cluster.Name + "-storage-0", Namespace: featureNamespace,
					Labels: map[string]string{
						labelAppManagedBy: managedByOperatorValue,
						labelTier:         tierStorage,
						labelCluster:      cluster.Name,
					},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
						Name: cluster.Name, UID: cluster.UID, Controller: &controller,
					}},
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata:  &garagev1beta1.NodeVolumeConfig{Size: &size},
						DataPaths: []garagev1beta1.NodeVolumeConfig{{Size: &size, Path: testFastDataPath}},
					},
				},
			}

			replacement := source.Spec.DeepCopy()
			applyInheritedManagedPVCSelectors(replacement, source, cluster)
			Expect(replacement.Storage.Metadata.Selector).To(Equal(cluster.Spec.Storage.Metadata.Selector))
			Expect(replacement.Storage.DataPaths[0].Selector).To(Equal(cluster.Spec.Storage.Data.Paths[0].Volume.Selector))

			// Snapshotting must not alias the parent API object.
			replacement.Storage.Metadata.Selector.MatchLabels[testDiskTypeLabel] = "mutated"
			Expect(cluster.Spec.Storage.Metadata.Selector.MatchLabels).To(HaveKeyWithValue(testDiskTypeLabel, metadataVolName))

			forged := source.DeepCopy()
			forged.OwnerReferences = nil
			forgedSpec := forged.Spec.DeepCopy()
			applyInheritedManagedPVCSelectors(forgedSpec, forged, cluster)
			Expect(forgedSpec.Storage.Metadata.Selector).To(BeNil(),
				"managed labels without the exact parent controller UID must not inherit a profile")
		})
	})

	Context("restored PVC selector upgrade boundary", func() {
		const (
			clusterName = "selector-upgrade-sts"
			nodeName    = clusterName + "-storage-0"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName, Namespace: featureNamespace,
			}})
		})

		It("leaves an existing selector-less StatefulSet and its claims untouched", func() {
			oneGi := resource.MustParse("1Gi")
			tenGi := resource.MustParse("10Gi")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: featureNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: &oneGi},
						Data:     &garagev1beta2.VolumeConfig{Size: &tenGi},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			Expect(publishTestClusterConfig(ctx, k8sClient, cluster)).To(Succeed())

			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName, Namespace: featureNamespace,
					Labels: map[string]string{
						labelAppManagedBy: managedByOperatorValue,
						labelTier:         tierStorage,
						labelCluster:      clusterName,
					},
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata: &garagev1beta1.NodeVolumeConfig{Size: &oneGi},
						Data:     &garagev1beta1.NodeVolumeConfig{Size: &tenGi},
					},
				},
			}
			Expect(controllerutil.SetControllerReference(cluster, node, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, node)).To(Succeed())

			r := reconciler()
			Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			before := &appsv1.StatefulSet{}
			key := types.NamespacedName{Name: nodeName, Namespace: featureNamespace}
			Expect(k8sClient.Get(ctx, key, before)).To(Succeed())
			for i := range before.Spec.VolumeClaimTemplates {
				Expect(before.Spec.VolumeClaimTemplates[i].Spec.Selector).To(BeNil())
			}

			cluster.Spec.Storage.Metadata.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{testDiskTypeLabel: metadataVolName},
			}
			cluster.Spec.Storage.Data.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{testDiskTypeLabel: dataVolName},
			}
			Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

			after := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, key, after)).To(Succeed())
			Expect(after.UID).To(Equal(before.UID), "the StatefulSet must not be orphan-recreated")
			Expect(after.ResourceVersion).To(Equal(before.ResourceVersion), "selector-only parent drift must not update the StatefulSet")
			for i := range after.Spec.VolumeClaimTemplates {
				Expect(after.Spec.VolumeClaimTemplates[i].Spec.Selector).To(BeNil(),
					"existing immutable claim templates must retain their historical selector")
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

	Context("operator-owned pod labels", func() {
		const (
			clusterName = "node-label-cluster"
			nodeName    = "node-label-node"
		)

		AfterEach(func() {
			cleanupNode(ctx, nodeName)
			cleanupCluster(ctx, clusterName)
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace}})
			for _, name := range []string{"default-scale-pod", "node-local-scale-pod"} {
				_ = k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: featureNamespace}})
			}
		})

		It("makes canonical selector labels win and keeps Scale scoped to the default group", func() {
			cluster := makeFeatureCluster(ctx, clusterName)
			cluster.Spec.LayoutPolicy = LayoutPolicyAuto
			cluster.Spec.Storage.PodLabels = map[string]string{
				labelAppManagedBy: "hostile-cluster", labelCluster: "wrong-node-cluster",
				labelTier: tierGateway, labelStorageGroup: storageGroupNodeLocal,
				labelScaleTarget: scaleTargetDisabled, "example.com/cluster-label": "cluster-kept",
			}
			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: featureNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       testNodeZone, Capacity: &capacity,
					PodLabels: map[string]string{
						labelAppManagedBy: "hostile-node", labelGarageNode: "forged-node",
						labelCluster: "wrong-node-cluster", labelTier: tierGateway,
						labelStorageGroup: storageGroupNodeLocal, labelScaleTarget: scaleTargetDisabled,
						"example.com/node-label": "node-kept",
					},
					Storage: &garagev1beta1.NodeStorageConfig{
						Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
					},
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			Expect(reconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: featureNamespace}, sts)).To(Succeed())
			for key, value := range sts.Spec.Selector.MatchLabels {
				Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(key, value),
					"StatefulSet template must satisfy every immutable selector label")
			}
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelAppManagedBy, operatorName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelGarageNode, nodeName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelCluster, clusterName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelTier, tierStorage))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelStorageGroup, storageGroupDefault))
			Expect(sts.Spec.Template.Labels).NotTo(HaveKey(labelScaleTarget))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue("example.com/cluster-label", "cluster-kept"))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue("example.com/node-label", "node-kept"))

			defaultPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "default-scale-pod", Namespace: featureNamespace, Labels: map[string]string{},
			}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: fmGarageContainer, Image: hostileLabelTestImage}}}}
			for key, value := range sts.Spec.Template.Labels {
				defaultPod.Labels[key] = value
			}
			nodeLocalPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "node-local-scale-pod", Namespace: featureNamespace,
				Labels: map[string]string{
					labelCluster: clusterName, labelTier: tierStorage,
					labelStorageGroup: storageGroupNodeLocal,
				},
			}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: fmGarageContainer, Image: hostileLabelTestImage}}}}
			Expect(k8sClient.Create(ctx, defaultPod)).To(Succeed())
			Expect(k8sClient.Create(ctx, nodeLocalPod)).To(Succeed())
			observation, err := (&GarageClusterReconciler{Client: k8sClient}).observeGarageClusterScale(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(observation.replicas).To(Equal(int32(1)))
			Expect(observation.selector).To(Equal(
				"garage.rajsingh.info/cluster=" + clusterName +
					",garage.rajsingh.info/storage-group=default,garage.rajsingh.info/tier=storage",
			))
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
		Expect(publishTestClusterConfig(ctx, k8sClient, c)).To(Succeed())
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
		_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
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
		Expect(names).To(ContainElement(metadataVolName))
		for i := 0; i < 2; i++ {
			Expect(names).To(ContainElement(fmt.Sprintf("data-%d", i)))
		}
		Expect(names).NotTo(ContainElement(dataVolName), "single-HDD PVC must not be emitted in multi-HDD mode")
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
						{Size: ptrQuantity(resource.MustParse("500m"))},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

		cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(err).NotTo(HaveOccurred())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring("data_dir = ["))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-0", capacity = "53687091200" }`))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-1", capacity = "75161927680" }`))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-2", capacity = "1" }`))
	})

	// #205: pre-fix legacy-STS migrations created multi-HDD GarageNodes with
	// `dataPaths[].existingClaim` set but no Size, so the ConfigMap rendered
	// `data_dir = [{ path = "..." }]` without capacity — which Garage's
	// parser (../garage src/block/layout.rs `make_data_dirs`) rejects, killing
	// the storage pod. The renderer must heal these by reading the bound
	// PVC's requested storage at render time.
	It("falls back to the bound PVC capacity when dataPaths[].size is unset (#205 heal)", func() {
		cluster := makeCluster(ctx)
		nodeName := "heal-205-node"
		uniqueNS := nodeName
		// Use existing-claim PVCs in the test namespace; the migration shape.
		pvc0 := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueNS + "-data-0", Namespace: testNamespace},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("33Gi")},
				},
			},
		}
		pvc1 := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueNS + "-data-1", Namespace: testNamespace},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("44Gi")},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pvc0)).To(Succeed())
		Expect(k8sClient.Create(ctx, pvc1)).To(Succeed())
		defer func() {
			_ = k8sClient.Delete(ctx, pvc0)
			_ = k8sClient.Delete(ctx, pvc1)
		}()

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
						{ExistingClaim: pvc0.Name},
						{ExistingClaim: pvc1.Name},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		defer func() {
			n := &garagev1beta1.GarageNode{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
				n.Finalizers = nil
				_ = k8sClient.Update(ctx, n)
				_ = k8sClient.Delete(ctx, n)
			}
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
		}()

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())

		cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(err).NotTo(HaveOccurred())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-0", capacity = "35433480192" }`))
		Expect(toml).To(ContainSubstring(`{ path = "/data/data-1", capacity = "47244640256" }`))
	})

	// #219: a non-readOnly dataPaths[] entry with neither Size nor a bound
	// existingClaim resolves to no capacity. Upstream make_data_dirs rejects
	// such an entry (no capacity, not read_only), so emitting it crashloops the
	// pod. The renderer must fail the reconcile (PhaseFailed + requeue) instead.
	It("fails the reconcile when a non-readOnly dataPaths[] entry has no resolvable capacity (#219)", func() {
		cluster := makeCluster(ctx)
		nodeName := "no-capacity-node"
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata:  &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					DataPaths: []garagev1beta1.NodeVolumeConfig{{}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		defer func() {
			n := &garagev1beta1.GarageNode{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
				n.Finalizers = nil
				_ = k8sClient.Update(ctx, n)
				_ = k8sClient.Delete(ctx, n)
			}
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
		}()

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		err := r.reconcileNodeConfigMap(ctx, node, cluster)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("has no capacity"))

		// No invalid ConfigMap should have been written.
		_, getErr := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(getErr).To(MatchError(ContainSubstring("found 0 live ConfigMap revisions")))
	})

	// #219 positive control: a readOnly entry needs no capacity and still renders.
	It("renders a readOnly dataPaths[] entry with no capacity (#219)", func() {
		cluster := makeCluster(ctx)
		nodeName := "readonly-no-capacity-node"
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata:  &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					DataPaths: []garagev1beta1.NodeVolumeConfig{{ReadOnly: true}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		defer func() {
			n := &garagev1beta1.GarageNode{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
				n.Finalizers = nil
				_ = k8sClient.Update(ctx, n)
				_ = k8sClient.Delete(ctx, n)
			}
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
		}()

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())
		cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data["garage.toml"]).To(ContainSubstring(`{ path = "/data/data-0", read_only = true }`))
	})

	// #205 follow-up: dataPaths[].path honored in both K8s mount and TOML.
	It("uses dp.Path as the mount + TOML path; ReadOnly drops capacity", func() {
		cluster := makeCluster(ctx)
		nodeName := "path-readonly-node"
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
						{Path: "/mnt/ssd-fast", Size: ptrQuantity(resource.MustParse("50Gi"))},
						{Path: "/mnt/legacy-cold", ReadOnly: true},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		defer func() {
			n := &garagev1beta1.GarageNode{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, n); err == nil {
				n.Finalizers = nil
				_ = k8sClient.Update(ctx, n)
				_ = k8sClient.Delete(ctx, n)
			}
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
		}()

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())
		cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(err).NotTo(HaveOccurred())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring(`{ path = "/mnt/ssd-fast", capacity = "53687091200" }`))
		Expect(toml).To(ContainSubstring(`{ path = "/mnt/legacy-cold", read_only = true }`))

		_, mounts := r.buildNodeVolumesAndMounts(node, cluster)
		mountByName := map[string]string{}
		for _, m := range mounts {
			mountByName[m.Name] = m.MountPath
		}
		Expect(mountByName["data-0"]).To(Equal("/mnt/ssd-fast"))
		Expect(mountByName["data-1"]).To(Equal("/mnt/legacy-cold"))
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
		Expect(publishTestClusterConfig(ctx, k8sClient, c)).To(Succeed())
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
		_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-0", Namespace: testNamespace}})
		_ = deleteTestManagedNodePVCs(ctx, k8sClient, testNamespace, nodeName)
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
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())
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

	It("projects the released empty gateway marker for unified gateway nodes", func() {
		cluster := makeCluster(ctx, nil, nil)
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Gateway:    true,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())

		sts := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, sts)).To(Succeed())
		Expect(sts.Spec.Template.Annotations).To(HaveKeyWithValue(
			annotationGatewayDataMarker, gatewayDataMarkerLegacyContent,
		))
		var markerVolume *corev1.Volume
		for i := range sts.Spec.Template.Spec.Volumes {
			if sts.Spec.Template.Spec.Volumes[i].Name == gatewayDataMarkerVolumeName {
				markerVolume = &sts.Spec.Template.Spec.Volumes[i]
				break
			}
		}
		Expect(markerVolume).NotTo(BeNil())
		Expect(markerVolume.DownwardAPI).NotTo(BeNil())
		Expect(markerVolume.DownwardAPI.Items).To(HaveLen(1))
		Expect(markerVolume.DownwardAPI.Items[0].FieldRef.FieldPath).To(Equal(gatewayDataMarkerFieldPath))
	})

	It("repairs StatefulSet template metadata drift without replacing the OnDelete Pod", func() {
		cluster := makeCluster(ctx, nil, nil)
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Gateway:    true,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
		key := types.NamespacedName{Name: nodeName, Namespace: testNamespace}
		before := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, key, before)).To(Succeed())
		podSpecHash := before.Spec.Template.Annotations[annotationPodSpecHash]
		configHash := before.Spec.Template.Annotations[annotationConfigHash]

		podLabels := make(map[string]string, len(before.Spec.Template.Labels))
		for k, v := range before.Spec.Template.Labels {
			podLabels[k] = v
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName + "-0",
				Namespace: testNamespace,
				Labels:    podLabels,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
					before, appsv1.SchemeGroupVersion.WithKind("StatefulSet"),
				)},
			},
			Spec: *before.Spec.Template.Spec.DeepCopy(),
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "metadata", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		podUID := pod.UID

		delete(before.Spec.Template.Labels, labelCluster)
		delete(before.Spec.Template.Annotations, annotationGatewayDataMarker)
		before.Labels[labelAppManagedBy] = "drifted"
		Expect(k8sClient.Update(ctx, before)).To(Succeed())

		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
		after := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, key, after)).To(Succeed())
		Expect(after.UID).To(Equal(before.UID))
		Expect(after.Spec.Template.Labels).To(HaveKeyWithValue(labelCluster, clusterName))
		Expect(after.Spec.Template.Annotations).To(HaveKeyWithValue(annotationGatewayDataMarker, gatewayDataMarkerLegacyContent))
		Expect(after.Spec.Template.Annotations[annotationPodSpecHash]).To(Equal(podSpecHash))
		Expect(after.Spec.Template.Annotations[annotationConfigHash]).To(Equal(configHash))
		Expect(after.Labels).To(HaveKeyWithValue(labelAppManagedBy, operatorName))

		unchangedPod := &corev1.Pod{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, unchangedPod)).To(Succeed())
		Expect(unchangedPod.UID).To(Equal(podUID))
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
		Expect(r.reconcileNodeConfigMap(ctx, node, cluster)).To(Succeed())
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

	It("updates PVC retention policy on an existing StatefulSet", func() {
		cluster := makeCluster(ctx, nil, nil)
		cluster.Spec.Storage.PVCRetentionPolicy = &garagev1beta2.PVCRetentionPolicy{
			WhenDeleted: pvcRetentionDelete,
		}
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
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
		sts := &appsv1.StatefulSet{}
		key := types.NamespacedName{Name: nodeName, Namespace: testNamespace}
		Expect(k8sClient.Get(ctx, key, sts)).To(Succeed())
		Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted).
			To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))

		cluster.Spec.Storage.PVCRetentionPolicy = &garagev1beta2.PVCRetentionPolicy{
			WhenDeleted: testRetentionRetain,
		}
		Expect(r.reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, key, sts)).To(Succeed())
		Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted).
			To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
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

		cm, err := testNodeConfigMap(ctx, k8sClient, cluster, node)
		Expect(err).NotTo(HaveOccurred())
		toml := cm.Data["garage.toml"]
		Expect(toml).To(ContainSubstring(`metadata_snapshots_dir = "/data/snaps"`))
		Expect(toml).To(ContainSubstring(`metadata_auto_snapshot_interval = "12h"`))
	})
})

var _ = Describe("GarageNode capacity-less gateway cycle", func() {
	It("fails closed without promoting or deleting either gateway identity", func() {
		testScheme := runtime.NewScheme()
		Expect(garagev1beta1.AddToScheme(testScheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(testScheme)).To(Succeed())

		const (
			clusterName   = "gateway-cycle"
			originalName  = clusterName + "-gateway-0"
			siblingNodeID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		)
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace, UID: types.UID("gateway-cluster-uid")},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Storage:      &garagev1beta2.StorageSpec{Replicas: 1},
				Gateway:      &garagev1beta2.GatewaySpec{Replicas: 1},
			},
		}
		original := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: originalName, Namespace: testNamespace, UID: types.UID("gateway-node-uid"),
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelTier:         tierGateway,
					labelAppManagedBy: managedByOperatorValue,
				},
				Annotations: map[string]string{garagev1beta1.AnnotationCycle: annotationTrue},
				Finalizers:  []string{garageNodeFinalizer},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Gateway:    true,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				},
			},
			Status: garagev1beta1.GarageNodeStatus{
				CyclePhase:       garagev1beta1.CyclePhaseSyncing,
				CycleSiblingName: originalName + cycleSiblingSuffix,
			},
		}
		Expect(controllerutil.SetControllerReference(cluster, original, testScheme)).To(Succeed())

		siblingSpec := *original.Spec.DeepCopy()
		siblingSpec.NodeID = ""
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: originalName + cycleSiblingSuffix, Namespace: testNamespace,
				UID:    types.UID("gateway-sibling-uid"),
				Labels: cycleSiblingLabels(original),
			},
			Spec:   siblingSpec,
			Status: garagev1beta1.GarageNodeStatus{NodeID: siblingNodeID},
		}
		Expect(controllerutil.SetControllerReference(original, sibling, testScheme)).To(Succeed())

		fakeClient := fake.NewClientBuilder().WithScheme(testScheme).
			WithObjects(original, sibling).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fakeClient, Scheme: testScheme}

		_, err := r.reconcileCycle(context.Background(), original, cluster, cluster)
		Expect(err).NotTo(HaveOccurred())
		Expect(original.Annotations).NotTo(HaveKey(garagev1beta1.AnnotationDrain),
			"blocked gateway cycles must not enter the positive-capacity drain protocol")

		blockedSibling := &garagev1beta1.GarageNode{}
		Expect(fakeClient.Get(context.Background(), types.NamespacedName{
			Name: sibling.Name, Namespace: sibling.Namespace,
		}, blockedSibling)).To(Succeed())
		Expect(blockedSibling.Labels).To(HaveKeyWithValue(labelCycleSibling, annotationTrue))
		Expect(metav1.IsControlledBy(blockedSibling, original)).To(BeTrue())

		preserved := &garagev1beta1.GarageNode{}
		Expect(fakeClient.Get(context.Background(), types.NamespacedName{
			Name: original.Name, Namespace: original.Namespace,
		}, preserved)).To(Succeed())
		Expect(preserved.DeletionTimestamp.IsZero()).To(BeTrue())
		condition := meta.FindStatusCondition(preserved.Status.Conditions, garagev1beta1.ConditionCycling)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonCycleBlocked))
		Expect(condition.Message).To(ContainSubstring("gateway identities are not supported"))
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

	// The unset case resolves to an explicit Retain/Retain rather than nil. It is
	// the same effective policy the API server would default to, but stated so
	// the reconcile-time DeepEqual against the stored StatefulSet can match;
	// nil compared against the defaulted value rewrote the STS every pass.
	It("does not inherit the storage policy on gateway nodes (gateway STS owns its own)", func() {
		got := stsPVCRetentionPolicy(mkCluster(&garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete}), mkNode(true))
		Expect(got).NotTo(BeNil())
		Expect(got.WhenDeleted).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType),
			"storage WhenDeleted=Delete must not leak onto a gateway node")
		Expect(got.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
	})

	It("states the API server's Retain default when cluster.storage.pvcRetentionPolicy is unset", func() {
		got := stsPVCRetentionPolicy(mkCluster(nil), mkNode(false))
		Expect(got).NotTo(BeNil(), "nil can never equal the stored defaulted value; see stsPVCRetentionPolicy")
		Expect(got.WhenDeleted).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
		Expect(got.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
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
		nodeUID  = "expand-node-uid"
	)
	var (
		ctx     context.Context
		cluster *garagev1beta2.GarageCluster
		scheme  *runtime.Scheme
	)

	mkPVC := func(name, size string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: ns, UID: types.UID(name + "-uid"),
				Labels: map[string]string{
					labelAppManagedBy: operatorName, labelAppComponent: "node",
					labelGarageNode: nodeName, labelCluster: "expand-cluster",
				},
				Annotations: map[string]string{managedPVCNodeUIDAnnotation: nodeUID},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)}},
			},
		}
	}

	installLiveStatefulSetEvidence := func(
		fc client.Client,
		r *GarageNodeReconciler,
		node *garagev1beta1.GarageNode,
	) {
		statefulSet := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: node.Name, Namespace: ns, UID: types.UID(node.Name + "-statefulset-uid")},
			Spec: appsv1.StatefulSetSpec{
				VolumeClaimTemplates: r.buildNodeVolumeClaimTemplates(node, cluster),
			},
		}
		Expect(controllerutil.SetControllerReference(node, statefulSet, scheme)).To(Succeed())
		Expect(fc.Create(ctx, statefulSet)).To(Succeed())

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: node.Name + "-0", Namespace: ns, UID: types.UID(node.Name + "-pod-uid")},
		}
		for i := range statefulSet.Spec.VolumeClaimTemplates {
			claimName := fmt.Sprintf("%s-%s-0", statefulSet.Spec.VolumeClaimTemplates[i].Name, statefulSet.Name)
			node.Status.ManagedPVCs = append(node.Status.ManagedPVCs, garagev1beta1.ManagedNodePVCStatus{
				Name: claimName, UID: types.UID(claimName + "-uid"),
			})
			pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
				Name: statefulSet.Spec.VolumeClaimTemplates[i].Name,
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claimName,
				}},
			})
		}
		Expect(controllerutil.SetControllerReference(statefulSet, pod, scheme)).To(Succeed())
		Expect(fc.Create(ctx, pod)).To(Succeed())
	}

	BeforeEach(func() {
		ctx = context.Background()
		cluster = &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "expand-cluster", Namespace: ns}}
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
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
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: nodeUID},
			Spec: garagev1beta1.GarageNodeSpec{
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &newMeta},
					Data:     &garagev1beta1.NodeVolumeConfig{Size: &oldData},
				},
			},
		}
		installLiveStatefulSetEvidence(fc, r, node)
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
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: nodeUID},
			Spec: garagev1beta1.GarageNodeSpec{
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &smaller},
				},
			},
		}
		installLiveStatefulSetEvidence(fc, r, node)
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

	It("refuses to expand a foreign convention-named PVC", func() {
		foreign := mkPVC("metadata-"+nodeName+"-0", "1Gi")
		foreign.Annotations = nil
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(foreign).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}
		bigger := resource.MustParse("5Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: "node-uid"},
			Spec: garagev1beta1.GarageNodeSpec{Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: &bigger},
			}},
		}
		Expect(r.expandNodePVCs(ctx, node, cluster)).To(MatchError(ContainSubstring("labels alone are not ownership")))
		got := &corev1.PersistentVolumeClaim{}
		Expect(fc.Get(ctx, client.ObjectKeyFromObject(foreign), got)).To(Succeed())
		Expect(got.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(resource.MustParse("1Gi")))
	})

	It("refuses a convention-named PVC pinned to a previous GarageNode UID", func() {
		claim := mkPVC("metadata-"+nodeName+"-0", "1Gi")
		claim.Annotations = map[string]string{managedPVCNodeUIDAnnotation: "previous-node-uid"}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claim).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}
		bigger := resource.MustParse("5Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: "current-node-uid"},
			Spec: garagev1beta1.GarageNodeSpec{Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: &bigger},
			}},
		}
		Expect(r.expandNodePVCs(ctx, node, cluster)).To(MatchError(ContainSubstring("does not match")))
	})

	It("refuses a precreated PVC carrying the current public GarageNode UID", func() {
		claim := mkPVC("metadata-"+nodeName+"-0", "1Gi")
		claim.Annotations = map[string]string{managedPVCNodeUIDAnnotation: "current-node-uid"}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claim).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: "current-node-uid"},
			Spec: garagev1beta1.GarageNodeSpec{Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("5Gi"))},
			}},
		}
		templates := r.buildNodeVolumeClaimTemplates(node, cluster)

		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).
			To(MatchError(ContainSubstring("without an exact live GarageNode-controlled StatefulSet")))
	})

	It("pins the bounded legacy PVC UID and accepts only that identity after StatefulSet replacement", func() {
		legacy := mkPVC("metadata-"+nodeName+"-0", "1Gi")
		legacy.Annotations = nil
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(legacy).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}
		size := resource.MustParse("5Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: "current-node-uid"},
			Spec: garagev1beta1.GarageNodeSpec{Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: &size},
			}},
		}
		Expect(fc.Create(ctx, node)).To(Succeed())
		templates := r.buildNodeVolumeClaimTemplates(node, cluster)
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).To(MatchError(ContainSubstring("labels alone are not ownership")))
		statefulSet := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: "statefulset-uid"},
			Spec:       appsv1.StatefulSetSpec{VolumeClaimTemplates: templates},
		}
		Expect(controllerutil.SetControllerReference(node, statefulSet, scheme)).To(Succeed())
		Expect(fc.Create(ctx, statefulSet)).To(Succeed())
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).To(MatchError(ContainSubstring("exact StatefulSet Pod default/expand-node-0 is absent")))

		wrongPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName + "-0", Namespace: ns, UID: "wrong-pod-uid"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "garage", Image: "garage:test"}},
				Volumes: []corev1.Volume{{Name: "other", VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "other-claim"},
				}}},
			},
		}
		Expect(controllerutil.SetControllerReference(statefulSet, wrongPod, scheme)).To(Succeed())
		Expect(fc.Create(ctx, wrongPod)).To(Succeed())
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).To(MatchError(ContainSubstring("does not reference it")))
		Expect(fc.Delete(ctx, wrongPod)).To(Succeed())

		livePod := wrongPod.DeepCopy()
		livePod.ResourceVersion = ""
		livePod.UID = "live-pod-uid"
		livePod.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = legacy.Name
		Expect(controllerutil.SetControllerReference(statefulSet, livePod, scheme)).To(Succeed())
		Expect(fc.Create(ctx, livePod)).To(Succeed())
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).To(Succeed())
		pinned := &corev1.PersistentVolumeClaim{}
		Expect(fc.Get(ctx, client.ObjectKeyFromObject(legacy), pinned)).To(Succeed())
		Expect(pinned.Annotations).To(HaveKeyWithValue(managedPVCNodeUIDAnnotation, string(node.UID)))
		Expect(node.Status.ManagedPVCs).To(ContainElement(garagev1beta1.ManagedNodePVCStatus{Name: legacy.Name, UID: legacy.UID}))

		pinned.Annotations = nil
		Expect(fc.Update(ctx, pinned)).To(Succeed())
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).To(Succeed())

		replacement := pinned.DeepCopy()
		replacement.UID = "replacement-pvc-uid"
		controllerutil.RemoveFinalizer(pinned, managedPVCFinalizer)
		Expect(fc.Update(ctx, pinned)).To(Succeed())
		Expect(fc.Delete(ctx, pinned)).To(Succeed())
		replacement.ResourceVersion = ""
		Expect(fc.Create(ctx, replacement)).To(Succeed())
		Expect(r.validateConventionNamedNodePVCs(ctx, node, cluster, templates)).
			To(MatchError(ContainSubstring("GarageNode status records UID")))
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
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
	})

	// mockGarage builds a tiny admin-API mock that counts UpdateClusterLayout
	// and ApplyClusterLayout calls so the test can assert removal was attempted.
	mockGarage := func(extraNodeID string) (*httptest.Server, *int32, *int32) {
		var updates, applies int32
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/GetClusterLayoutHistory", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(settledLayoutHistoryResponse())
		})
		mux.HandleFunc("/v2/GetClusterLayout", func(w http.ResponseWriter, _ *http.Request) {
			roles := []garage.LayoutRole{{ID: extraNodeID, Zone: "z"}}
			layout := garage.ClusterLayout{Version: 1, Roles: roles}
			// Reflect a staged removal once UpdateClusterLayout has been called,
			// matching real Garage — ApplyStagedLayoutChanges re-reads the layout
			// and only applies when something is staged.
			if atomic.LoadInt32(&updates) > 0 {
				layout.StagedRoleChanges = []garage.NodeRoleChange{{ID: extraNodeID, Remove: true}}
			}
			_ = json.NewEncoder(w).Encode(layout)
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
				Gateway:    true,
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
				Gateway:    true,
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
				Gateway:    true,
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

	It("enqueues every GarageNode whose ClusterRef matches the exact owned cluster config revision", func() {
		const clusterName = "stable-cluster"
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: ns, UID: types.UID("stable-cluster-uid")},
		}
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      garageConfigRevisionName(clusterName+"-config", strings.Repeat("a", 64)),
				Namespace: ns,
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelAppManagedBy: operatorName,
				},
				Annotations: map[string]string{annotationGarageConfigBaseName: clusterName + "-config"},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster)),
				},
			},
		}

		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			cluster,
			mkNode("n1", clusterName),
			mkNode("n2", clusterName),
			mkNode("n-other", "other-cluster"),
		).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		reqs := r.nodesForClusterConfigResource(bctx, cm)
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

		Expect(r.nodesForClusterConfigResource(bctx, cm)).To(BeEmpty())
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

		Expect(r.nodesForClusterConfigResource(bctx, cm)).To(BeEmpty())
	})
})

var _ = Describe("nodeForManagedPod mapper", func() {
	const ns = "pod-mapper-ns"

	r := &GarageNodeReconciler{}
	requestNames := func(pod *corev1.Pod) []string {
		reqs := r.nodeForManagedPod(context.Background(), pod)
		names := make([]string, 0, len(reqs))
		for _, req := range reqs {
			names = append(names, req.Namespace+"/"+req.Name)
		}
		return names
	}

	It("maps an indirectly owned StatefulSet Pod to its labelled GarageNode", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testManualGarageNodeName + "-0",
				Namespace: ns,
				Labels: map[string]string{
					labelAppManagedBy: operatorName,
					labelGarageNode:   testManualGarageNodeName,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
					Name: testManualGarageNodeName, Controller: ptr.To(true),
				}},
			},
		}
		Expect(requestNames(pod)).To(Equal([]string{ns + "/" + testManualGarageNodeName}))
	})

	It("maps a scheduled node-local-pool DaemonSet Pod to its deterministic GarageNode", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "site-storage-fast-abcde",
				Namespace: ns,
				Labels: map[string]string{
					labelAppManagedBy:  operatorName,
					labelCluster:       testSiteName,
					labelTier:          tierStorage,
					labelStorageGroup:  storageGroupNodeLocal,
					labelNodeLocalPool: testFastValue,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "DaemonSet",
					Name: "site-storage-fast", Controller: ptr.To(true),
				}},
			},
			Spec: corev1.PodSpec{NodeName: testKubernetesWorkerA},
		}
		Expect(requestNames(pod)).To(Equal([]string{
			ns + "/" + nodeLocalPoolGarageNodeName(testSiteName, testFastValue, testKubernetesWorkerA),
		}))
	})

	It("ignores lookalike Pods that are not operator-managed or lack the expected owner", func() {
		unmanaged := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Labels: map[string]string{
				labelGarageNode: testManualGarageNodeName,
			},
		}}
		Expect(requestNames(unmanaged)).To(BeEmpty())

		wrongOwner := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Labels: map[string]string{
				labelAppManagedBy: operatorName,
				labelGarageNode:   testManualGarageNodeName,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Secret", Name: "lookalike", Controller: ptr.To(true),
			}},
		}}
		Expect(requestNames(wrongOwner)).To(BeEmpty())
	})
})

var _ = Describe("buildNodeVolumesAndMounts EmptyDir rendering (#283)", func() {
	r := &GarageNodeReconciler{}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "ephem", Namespace: testNamespace},
		Spec:       garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{Replicas: 1}},
	}

	volByName := func(vols []corev1.Volume, name string) *corev1.Volume {
		for i := range vols {
			if vols[i].Name == name {
				return &vols[i]
			}
		}
		return nil
	}

	It("renders EmptyDir volumes for a sizeless ephemeral node, and every mount resolves to a volume", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ephem-storage-0", Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Type: garagev1beta1.VolumeTypeEmptyDir},
					Data:     &garagev1beta1.NodeVolumeConfig{Type: garagev1beta1.VolumeTypeEmptyDir},
				},
			},
		}
		vols, mounts := r.buildNodeVolumesAndMounts(node, cluster)

		meta := volByName(vols, metadataVolName)
		Expect(meta).NotTo(BeNil())
		Expect(meta.EmptyDir).NotTo(BeNil(), "metadata must be an EmptyDir, not a PVC")
		Expect(meta.EmptyDir.SizeLimit).To(BeNil())

		data := volByName(vols, dataVolName)
		Expect(data).NotTo(BeNil())
		Expect(data.EmptyDir).NotTo(BeNil(), "data must be an EmptyDir, not a PVC")

		// The bug: a mount with no backing volume makes the STS invalid. Assert
		// every mount name resolves to a defined volume.
		for _, m := range mounts {
			Expect(volByName(vols, m.Name)).NotTo(BeNil(), "mount %q has no backing volume", m.Name)
		}

		// And no PVC templates are generated for an all-EmptyDir node.
		Expect(r.buildNodeVolumeClaimTemplates(node, cluster)).To(BeEmpty())
	})

	It("sets EmptyDir sizeLimit from the volume size (ephemeral-limited shape)", func() {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ephem-storage-0", Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Type: garagev1beta1.VolumeTypeEmptyDir, Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta1.NodeVolumeConfig{Type: garagev1beta1.VolumeTypeEmptyDir, Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
			},
		}
		vols, _ := r.buildNodeVolumesAndMounts(node, cluster)

		meta := volByName(vols, metadataVolName)
		Expect(meta.EmptyDir).NotTo(BeNil())
		Expect(meta.EmptyDir.SizeLimit).NotTo(BeNil())
		Expect(meta.EmptyDir.SizeLimit.Cmp(resource.MustParse("1Gi"))).To(Equal(0))

		data := volByName(vols, dataVolName)
		Expect(data.EmptyDir).NotTo(BeNil())
		Expect(data.EmptyDir.SizeLimit).NotTo(BeNil())
		Expect(data.EmptyDir.SizeLimit.Cmp(resource.MustParse("10Gi"))).To(Equal(0))

		// Still no PVC templates — a sized EmptyDir is a tmpfs sizeLimit, not a PVC.
		Expect(r.buildNodeVolumeClaimTemplates(node, cluster)).To(BeEmpty())
	})
})
