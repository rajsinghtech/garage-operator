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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func listOperatorOwnedGatewayNodes(clusterName string) *garagev1beta1.GarageNodeList {
	gnList := &garagev1beta1.GarageNodeList{}
	Expect(k8sClient.List(ctx, gnList,
		client.InNamespace(testNamespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      clusterName,
			labelTier:         tierGateway,
			labelAppManagedBy: managedByOperatorValue,
		}),
	)).To(Succeed())
	return gnList
}

var _ = Describe("GarageCluster unified-gateway Auto-mode (#209)", func() {
	var (
		reconciler *GarageClusterReconciler
		cluster    *garagev1beta2.GarageCluster
		clusterNN  types.NamespacedName
	)

	BeforeEach(func() {
		reconciler = &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		clusterNN = types.NamespacedName{Name: uniqueClusterName("uni-gw"), Namespace: testNamespace}
		cluster = &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Zone:         testZone,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 3,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Gateway:     &garagev1beta2.GatewaySpec{Replicas: 2},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
	})

	AfterEach(func() {
		fresh := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, clusterNN, fresh); err == nil {
			fresh.Finalizers = nil
			_ = k8sClient.Update(ctx, fresh)
			_ = k8sClient.Delete(ctx, fresh)
		}
		gnList := &garagev1beta1.GarageNodeList{}
		_ = k8sClient.List(ctx, gnList, client.InNamespace(testNamespace), client.MatchingLabels(map[string]string{labelCluster: clusterNN.Name}))
		for i := range gnList.Items {
			n := gnList.Items[i]
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, &n)
			_ = k8sClient.Delete(ctx, &n)
		}
	})

	It("creates one gateway GarageNode per gateway replica with capacity=nil", func() {
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		gnList := listOperatorOwnedGatewayNodes(clusterNN.Name)
		Expect(gnList.Items).To(HaveLen(2))

		names := map[string]bool{}
		for _, n := range gnList.Items {
			names[n.Name] = true
			Expect(metav1.IsControlledBy(&n, cluster)).To(BeTrue())
			Expect(n.Spec.Gateway).To(BeTrue(), "gateway nodes must carry Gateway:true")
			Expect(n.Spec.Capacity).To(BeNil(), "gateway nodes must have nil capacity")
			Expect(n.Spec.Zone).To(Equal(testZone))
			Expect(n.Labels).To(HaveKeyWithValue(labelTier, tierGateway))
			Expect(n.Spec.Storage).NotTo(BeNil())
			Expect(n.Spec.Storage.Metadata).NotTo(BeNil(), "gateway nodes need a metadata PVC for persistent identity")
			Expect(n.Spec.Storage.Data).To(BeNil(), "gateway nodes must not declare a data PVC")
			// Gateway tags must carry the tier:gateway + ownership tags the
			// tombstone-cleanup path filters on.
			Expect(n.Spec.Tags).To(ContainElement("tier:" + tierGateway))
		}
		Expect(names).To(HaveKey(clusterNN.Name + "-gateway-0"))
		Expect(names).To(HaveKey(clusterNN.Name + "-gateway-1"))
	})

	It("is a no-op for gateway-only (edge) clusters", func() {
		edge := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName("edge"), Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Zone:         testZone,
				Gateway:      &garagev1beta2.GatewaySpec{Replicas: 2},
				ConnectTo:    &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://storage:3903"},
			},
		}
		// No storage tier → reconcileAutoModeGatewayNodes must not create nodes
		// (edge gateways keep the cluster-level StatefulSet path).
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, edge)).To(Succeed())
		Expect(listOperatorOwnedGatewayNodes(edge.Name).Items).To(BeEmpty())
	})

	It("scales gateway GarageNodes down when replicas shrink", func() {
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		Expect(listOperatorOwnedGatewayNodes(clusterNN.Name).Items).To(HaveLen(2))

		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		cluster.Spec.Gateway.Replicas = 1
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		remaining := listOperatorOwnedGatewayNodes(clusterNN.Name)
		// The deleted node may linger on a finalizer in envtest; assert the
		// surviving desired node is present and the scaled-out one is being removed.
		got := map[string]bool{}
		for _, n := range remaining.Items {
			if n.DeletionTimestamp == nil {
				got[n.Name] = true
			}
		}
		Expect(got).To(HaveKey(clusterNN.Name + "-gateway-0"))
		Expect(got).NotTo(HaveKey(clusterNN.Name + "-gateway-1"))
	})

	It("propagates gateway rpcPublicAddr onto the node network override", func() {
		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		cluster.Spec.Gateway.RPCPublicAddr = "gw.example.com:3901"
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		for _, n := range listOperatorOwnedGatewayNodes(clusterNN.Name).Items {
			Expect(n.Spec.Network).NotTo(BeNil())
			Expect(n.Spec.Network.RPCPublicAddr).To(Equal("gw.example.com:3901"))
		}
	})

	It("ejects gateway GarageNodes on Auto→Manual (drops controllerRef + managed-by)", func() {
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		Expect(listOperatorOwnedGatewayNodes(clusterNN.Name).Items).To(HaveLen(2))

		Expect(reconciler.ejectAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		// After eject, the operator-owned list (filtered by managed-by) is empty.
		Expect(listOperatorOwnedGatewayNodes(clusterNN.Name).Items).To(BeEmpty())

		// The GarageNodes still exist, just no longer operator-owned.
		all := &garagev1beta1.GarageNodeList{}
		Expect(k8sClient.List(ctx, all, client.InNamespace(testNamespace),
			client.MatchingLabels(map[string]string{labelCluster: clusterNN.Name, labelTier: tierGateway}))).To(Succeed())
		Expect(all.Items).To(HaveLen(2))
		for _, n := range all.Items {
			Expect(metav1.IsControlledBy(&n, cluster)).To(BeFalse(), "controllerRef must be dropped on eject")
			Expect(n.Labels).NotTo(HaveKey(labelAppManagedBy))
		}
	})
})
