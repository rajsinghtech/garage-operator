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
	"github.com/rajsinghtech/garage-operator/internal/garage"
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
		reconciler = &GarageClusterReconciler{
			Client:    k8sClient,
			APIReader: k8sClient,
			Scheme:    k8sClient.Scheme(),
			layoutHistoryGetter: func(_ context.Context, _ *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
				return &garage.LayoutHistoryResponse{
					CurrentVersion: 1,
					Versions: []garage.LayoutVersion{{
						Version:      1,
						Status:       garage.LayoutVersionStatusCurrent,
						StorageNodes: 3,
					}},
				}, nil
			},
		}
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

		// Unified gateway identities are not allowed to bootstrap an empty
		// Garage layout. Seed the already-settled storage member that would have
		// been created by reconcileAutoModeStorageNodes in a full cluster
		// reconciliation.
		storagePrerequisite := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterNN.Name + "-storage-prerequisite",
				Namespace: testNamespace,
				Labels: map[string]string{
					labelCluster: clusterNN.Name,
					labelTier:    tierStorage,
				},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name},
				Zone:       testZone,
				Capacity:   ptrQuantity(resource.MustParse("10Gi")),
			},
		}
		Expect(k8sClient.Create(ctx, storagePrerequisite)).To(Succeed())
		storagePrerequisite.Status.NodeID = "node-" + storagePrerequisite.Name
		storagePrerequisite.Status.Connected = true
		storagePrerequisite.Status.InLayout = true
		storagePrerequisite.Status.ObservedGeneration = storagePrerequisite.Generation
		Expect(k8sClient.Status().Update(ctx, storagePrerequisite)).To(Succeed())
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

	markGatewayNodesReady := func() {
		for _, item := range listOperatorOwnedGatewayNodes(clusterNN.Name).Items {
			node := item.DeepCopy()
			node.Status.NodeID = "node-" + node.Name
			node.Status.Connected = true
			node.Status.InLayout = true
			node.Status.ObservedGeneration = node.Generation
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())
		}
	}

	reconcileAllGatewayNodes := func() {
		for i := int32(0); i < cluster.GatewayReplicas(); i++ {
			Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
			markGatewayNodesReady()
		}
	}

	It("creates one gateway GarageNode per gateway replica with capacity=nil", func() {
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		Expect(listOperatorOwnedGatewayNodes(clusterNN.Name).Items).To(HaveLen(1),
			"gateway identities must be admitted one at a time")
		markGatewayNodesReady()
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

	It("projects the unified gateway metadata selector to newly generated GarageNodes", func() {
		selector := &metav1.LabelSelector{MatchLabels: map[string]string{"disk.example.com/name": "gateway-meta"}}
		cluster.Spec.Gateway.Metadata = &garagev1beta2.VolumeConfig{
			Size:     ptrQuantity(resource.MustParse("1Gi")),
			Selector: selector,
		}
		node, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.Storage).NotTo(BeNil())
		Expect(node.Spec.Storage.Metadata).NotTo(BeNil())
		Expect(node.Spec.Storage.Metadata.Selector).To(Equal(selector))
		Expect(node.Labels).To(HaveKeyWithValue(labelAutoNodeSlot, node.Name))
	})

	It("does not copy a storage data source onto unified Auto gateway metadata PVCs", func() {
		group := "kopiur.example.io"
		cluster.Spec.Storage.Data = &garagev1beta2.VolumeConfig{
			Size:          ptrQuantity(resource.MustParse("10Gi")),
			DataSourceRef: &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "storage-restore"},
		}
		cluster.Spec.Gateway.Metadata = &garagev1beta2.VolumeConfig{
			Size: ptrQuantity(resource.MustParse("1Gi")),
		}

		node, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		templates := (&GarageNodeReconciler{}).buildNodeVolumeClaimTemplates(node, cluster)
		Expect(templates).To(HaveLen(1))
		Expect(templates[0].Name).To(Equal(metadataVolName))
		Expect(templates[0].Spec.DataSourceRef).To(BeNil())
	})

	It("copies a gateway metadata data source onto unified Auto gateway metadata PVCs", func() {
		group := "kopiur.example.io"
		cluster.Spec.Gateway.Metadata = &garagev1beta2.VolumeConfig{
			Size:          ptrQuantity(resource.MustParse("1Gi")),
			DataSourceRef: &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "gateway-restore"},
		}

		node, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		templates := (&GarageNodeReconciler{}).buildNodeVolumeClaimTemplates(node, cluster)
		Expect(templates).To(HaveLen(1))
		Expect(templates[0].Name).To(Equal(metadataVolName))
		Expect(templates[0].Spec.DataSourceRef).NotTo(BeNil())
		Expect(templates[0].Spec.DataSourceRef.Name).To(Equal("gateway-restore"))
	})

	It("keeps a promoted cycle sibling as the durable gateway ordinal", func() {
		cluster.Spec.Gateway.Replicas = 1
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		markGatewayNodesReady()

		canonicalName := autoModeGatewayNodeName(cluster.Name, 0)
		canonical := &garagev1beta1.GarageNode{}
		canonicalKey := types.NamespacedName{Name: canonicalName, Namespace: testNamespace}
		Expect(k8sClient.Get(ctx, canonicalKey, canonical)).To(Succeed())

		promoted := canonical.DeepCopy()
		promoted.Name = canonicalName + cycleSiblingSuffix
		promoted.ResourceVersion = ""
		promoted.UID = ""
		promoted.Generation = 0
		promoted.CreationTimestamp = metav1.Time{}
		promoted.ManagedFields = nil
		promoted.Status = garagev1beta1.GarageNodeStatus{}
		promoted.Labels[labelAutoNodeSlot] = canonicalName
		delete(promoted.Labels, labelCycleSibling)
		Expect(k8sClient.Create(ctx, promoted)).To(Succeed())
		Expect(k8sClient.Delete(ctx, canonical)).To(Succeed())

		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		missingCanonical := &garagev1beta1.GarageNode{}
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, canonicalKey, missingCanonical))).To(BeTrue())
		kept := &garagev1beta1.GarageNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: promoted.Name, Namespace: testNamespace,
		}, kept)).To(Succeed())
		Expect(kept.DeletionTimestamp.IsZero()).To(BeTrue(),
			"the parent must not undo a completed gateway cycle")
	})

	It("is a no-op for gateway-only (edge) clusters", func() {
		edge := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName(testEdgeValue), Namespace: testNamespace},
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
		reconcileAllGatewayNodes()
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

	It("hands an exact retained gateway PVC incarnation to the recreated Auto slot", func() {
		reconcileAllGatewayNodes()
		slot := clusterNN.Name + "-gateway-1"
		oldNode := &garagev1beta1.GarageNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: slot, Namespace: testNamespace}, oldNode)).To(Succeed())

		claim := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:        metadataVolName + "-" + slot + "-0",
				Namespace:   testNamespace,
				Annotations: map[string]string{managedPVCNodeUIDAnnotation: string(oldNode.UID)},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("1Gi"),
				}},
			},
		}
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		oldNode.Status.ManagedPVCs = []garagev1beta1.ManagedNodePVCStatus{{Name: claim.Name, UID: claim.UID}}
		Expect(k8sClient.Status().Update(ctx, oldNode)).To(Succeed())

		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		cluster.Spec.Gateway.Replicas = 1
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: slot, Namespace: testNamespace}, &garagev1beta1.GarageNode{}))
		}).Should(BeTrue())

		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		Expect(cluster.Status.AutoModePVCHandoffs).To(ConsistOf(garagev1beta2.AutoModePVCHandoffStatus{
			SlotName: slot, PVCName: claim.Name, PVCUID: string(claim.UID), PreviousGarageNodeUID: string(oldNode.UID),
		}))

		cluster.Spec.Gateway.Replicas = 2
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())

		replacement := &garagev1beta1.GarageNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: slot, Namespace: testNamespace}, replacement)).To(Succeed())
		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		Expect(cluster.Status.AutoModePVCHandoffs).To(HaveLen(1))
		handoff := cluster.Status.AutoModePVCHandoffs[0]
		Expect(handoff.ReplacementGarageNodeUID).To(Equal(string(replacement.UID)))
		Expect(managedNodePVCNonceMatchesNode(replacement, handoff.ReplacementReservationHash)).To(BeTrue())

		forged := replacement.DeepCopy()
		forged.UID = types.UID("forged-replacement-uid")
		_, err := retainedAutoModePVCHandoff(cluster, forged, claim)
		Expect(err).To(MatchError(ContainSubstring("does not authorize GarageNode UID")))

		nodeReconciler := &GarageNodeReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(nodeReconciler.ensureManagedNodePVCProvenance(ctx, claim, replacement, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(replacement), replacement)).To(Succeed())
		Expect(replacement.Status.ManagedPVCs).To(ConsistOf(garagev1beta1.ManagedNodePVCStatus{Name: claim.Name, UID: claim.UID}))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(claim), claim)).To(Succeed())
		Expect(claim.Annotations).To(HaveKeyWithValue(managedPVCNodeUIDAnnotation, string(replacement.UID)))

		Expect(reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		Expect(cluster.Status.AutoModePVCHandoffs).To(BeEmpty())
	})

	It("propagates gateway rpcPublicAddr onto the node network override", func() {
		Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
		cluster.Spec.Gateway.RPCPublicAddr = testGatewayRPCAddr
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		reconcileAllGatewayNodes()

		for _, n := range listOperatorOwnedGatewayNodes(clusterNN.Name).Items {
			Expect(n.Spec.Network).NotTo(BeNil())
			Expect(n.Spec.Network.RPCPublicAddr).To(Equal("gw.example.com:3901"))
		}
	})

	It("ejects gateway GarageNodes on Auto→Manual (drops controllerRef + managed-by)", func() {
		reconcileAllGatewayNodes()
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
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: testGarageValue, Image: "garage:test"}}},
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
						Kind:       kindStatefulSet,
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
		expectRetain := func(policy *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy) {
			GinkgoHelper()
			// Stated explicitly rather than left nil: it is the same policy the API
			// server defaults to, but nil never DeepEquals the stored value, which
			// made every reconcile rewrite the StatefulSet.
			Expect(policy).NotTo(BeNil())
			Expect(policy.WhenDeleted).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
			Expect(policy.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
		}

		gwNode, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		expectRetain(stsPVCRetentionPolicy(cluster, gwNode))

		// Positive control: a storage node without spec.storage.pvcRetentionPolicy
		// also retains.
		storageNode := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name + "-storage-0", Namespace: testNamespace},
			Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name}},
		}
		expectRetain(stsPVCRetentionPolicy(cluster, storageNode))
	})

	It("applies an explicit gateway PVC retention policy only to unified gateway members", func() {
		cluster.Spec.Gateway.PVCRetentionPolicy = &garagev1beta2.PVCRetentionPolicy{
			WhenDeleted: pvcRetentionDelete, WhenScaled: testRetentionRetain,
		}
		gatewayNode, err := reconciler.buildAutoModeGatewayNode(cluster, 0, "")
		Expect(err).NotTo(HaveOccurred())
		policy := stsPVCRetentionPolicy(cluster, gatewayNode)
		Expect(policy).NotTo(BeNil())
		Expect(policy.WhenDeleted).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
		Expect(policy.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))

		storageNode := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name}},
		}
		storagePolicy := stsPVCRetentionPolicy(cluster, storageNode)
		Expect(storagePolicy).NotTo(BeNil())
		Expect(storagePolicy.WhenDeleted).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType),
			"gateway retention must not leak into positive-capacity storage claims")
		Expect(storagePolicy.WhenScaled).To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
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
