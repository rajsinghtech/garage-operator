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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
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
		cluster.Spec.Gateway.RPCPublicAddr = testGatewayRPCAddr
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

	It("adopts the legacy cluster-level gateway STS metadata PVC by existingClaim (identity-preserving) (#221)", func() {
		stsName := clusterNN.Name + "-gateway"

		legacySTS := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: stsName, Namespace: testNamespace},
			Spec: appsv1.StatefulSetSpec{
				Replicas:    ptr.To(int32(2)),
				ServiceName: clusterNN.Name + "-headless",
				Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{labelCluster: clusterNN.Name, labelTier: tierGateway}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{labelCluster: clusterNN.Name, labelTier: tierGateway}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "garage", Image: "garage:test"}}},
				},
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
					ObjectMeta: metav1.ObjectMeta{Name: metadataVolName},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
					},
				}},
				PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
					WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
					WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
				},
			},
		}
		Expect(k8sClient.Create(ctx, legacySTS)).To(Succeed())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: stsName, Namespace: testNamespace}, legacySTS)).To(Succeed())

		for ord := 0; ord < 2; ord++ {
			pvcName := fmt.Sprintf("%s-%s-%d", metadataVolName, stsName, ord)
			pvc := &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pvcName,
					Namespace: testNamespace,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "apps/v1",
						Kind:       "StatefulSet",
						Name:       stsName,
						UID:        legacySTS.UID,
						Controller: ptr.To(true),
					}},
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
				},
			}
			Expect(k8sClient.Create(ctx, pvc)).To(Succeed())
		}

		Expect(reconciler.migrateLegacyGatewaySTSIfNeeded(ctx, cluster)).To(Succeed())

		// (a)+(b) both metadata PVCs survive and no longer carry the STS ownerRef.
		for ord := 0; ord < 2; ord++ {
			pvcName := fmt.Sprintf("%s-%s-%d", metadataVolName, stsName, ord)
			pvc := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: pvcName, Namespace: testNamespace}, pvc)).To(Succeed())
			for _, ref := range pvc.OwnerReferences {
				Expect(ref.UID).NotTo(Equal(legacySTS.UID), "legacy STS ownerRef must be stripped so cascade delete cannot reap it")
			}
		}

		// (c) two adopted gateway nodes, each binding its metadata PVC by name with
		// no freshly-sized template.
		gnList := listOperatorOwnedGatewayNodes(clusterNN.Name)
		Expect(gnList.Items).To(HaveLen(2))
		for _, n := range gnList.Items {
			Expect(n.Spec.Storage).NotTo(BeNil())
			Expect(n.Spec.Storage.Metadata).NotTo(BeNil())
			Expect(n.Spec.Storage.Metadata.ExistingClaim).To(Equal(metadataVolName + "-" + n.Name))
			Expect(n.Spec.Storage.Metadata.Size).To(BeNil(), "adopted node must not declare a fresh size")
		}

		// (d) the legacy STS is gone or being deleted (envtest has no STS controller).
		fresh := &appsv1.StatefulSet{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: stsName, Namespace: testNamespace}, fresh)
		if err == nil {
			Expect(fresh.DeletionTimestamp).NotTo(BeNil())
		} else {
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}
	})

	It("per-node gateway STS does not delete the metadata PVC on STS update (Retain)", func() {
		gwNode, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		// Gateway node → nil retention policy == K8s default Retain.
		Expect(stsPVCRetentionPolicy(cluster, gwNode)).To(BeNil())

		// Positive control: a storage node without spec.storage.pvcRetentionPolicy
		// also yields nil (Retain).
		storageNode := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name + "-storage-0", Namespace: testNamespace},
			Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name}},
		}
		Expect(stsPVCRetentionPolicy(cluster, storageNode)).To(BeNil())
	})

	It("substitutes {ordinal} into gateway.rpcPublicAddr per pod (#cross-region per-pod reachability)", func() {
		c := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-ord", Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1},
				Gateway: &garagev1beta2.GatewaySpec{Replicas: 2, RPCPublicAddr: "gw-{ordinal}.example.ts.net:3901"},
			},
		}
		// Each pod ordinal advertises its own address, so remote regions can reach
		// every gateway pod (a single shared addr can route to only one).
		n0, err := reconciler.buildAutoModeGatewayNode(c, 0, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(n0.Spec.Network).NotTo(BeNil())
		Expect(n0.Spec.Network.RPCPublicAddr).To(Equal("gw-0.example.ts.net:3901"))

		n1, err := reconciler.buildAutoModeGatewayNode(c, 1, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(n1.Spec.Network.RPCPublicAddr).To(Equal("gw-1.example.ts.net:3901"))

		// An address without the placeholder is used verbatim (single-replica tiers).
		c.Spec.Gateway.RPCPublicAddr = "shared.example.ts.net:3901"
		n2, err := reconciler.buildAutoModeGatewayNode(c, 1, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(n2.Spec.Network.RPCPublicAddr).To(Equal("shared.example.ts.net:3901"))
	})
})
