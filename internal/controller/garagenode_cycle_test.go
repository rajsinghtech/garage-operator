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
	"strings"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

type deleteOptionsRecordingClient struct {
	client.Client
	lastDeleteOptions *client.DeleteOptions
}

func (c *deleteOptionsRecordingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.lastDeleteOptions = (&client.DeleteOptions{}).ApplyOptions(opts)
	return c.Client.Delete(ctx, obj, opts...)
}

// Graceful node cycle (#231) — add-before-remove replacement state machine.
var _ = Describe("GarageNode graceful cycle", func() {
	const (
		ns           = "cycle-ns"
		clusterName  = "cyc"
		nodeName     = "cyc-storage-0"
		siblingName  = "cyc-storage-0-cycle"
		sourceID     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		siblingID    = "1111111111111111111111111111111111111111111111111111111111111111"
		sourcePodUID = "cycle-source-pod-uid"
	)

	var (
		bctx   context.Context
		scheme *runtime.Scheme
		cap    resource.Quantity
		dataSz resource.Quantity
	)

	BeforeEach(func() {
		bctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
		cap = resource.MustParse("100Gi")
		dataSz = resource.MustParse("100Gi")
	})

	// mkCluster returns an Auto cluster CR (no admin endpoint wired — tests that
	// need the layout-history call drive the predicate directly).
	mkCluster := func() *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: ns, UID: "cyc-uid", Generation: 1},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1, ConsistencyMode: consistencyModeConsistent},
			},
			Status: garagev1beta2.GarageClusterStatus{
				Conditions: []metav1.Condition{{
					Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
					Reason: garagev1beta1.ReasonStorageRolloutConverged, ObservedGeneration: 1,
				}},
				Health: &garagev1beta2.ClusterHealth{
					Status: healthStatusHealthy, Healthy: true, Available: true,
					StorageNodes: 1, StorageNodesOK: 1,
					Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				},
			},
		}
	}

	// mkNode returns an Auto-owned storage GarageNode carrying the cycle
	// annotation, with the finalizer already set so the reconcile skips the
	// add-finalizer requeue and reaches the cycle handler.
	mkNode := func(annotated bool) *garagev1beta1.GarageNode {
		ann := map[string]string{}
		if annotated {
			ann[garagev1beta1.AnnotationCycle] = annotationTrue
		}
		// Auto-owned: the cluster is the controller owner, which is what marks the
		// node operator-owned (metav1.IsControlledBy) and lets it bypass the
		// Manual-only policy gate.
		owner := mkCluster()
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:        nodeName,
				Namespace:   ns,
				UID:         types.UID("cycle-node-uid"),
				Generation:  1,
				Annotations: ann,
				Finalizers:  []string{garageNodeFinalizer},
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelTier:         tierStorage,
					labelAppManagedBy: managedByOperatorValue,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion:         garagev1beta2.GroupVersion.String(),
					Kind:               testGarageClusterKind,
					Name:               owner.Name,
					UID:                "cyc-uid",
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				}},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &cap,
				Tags:       []string{"role:hot"},
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
					Data:     &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
				},
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: sourceID, ObservedPodUID: sourcePodUID,
				ObservedGeneration: 1, Connected: true, InLayout: true,
			},
		}
	}

	mkSourceWorkload := func(node *garagev1beta1.GarageNode) (*appsv1.StatefulSet, *corev1.Pod) {
		sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
			Name: node.Name, Namespace: node.Namespace, UID: types.UID("sts-" + node.Name),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
			)},
		}}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: node.Name + "-0", Namespace: node.Namespace, UID: types.UID(node.Status.ObservedPodUID),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
					sts, appsv1.SchemeGroupVersion.WithKind(kindStatefulSet),
				)},
			},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}
		return sts, pod
	}

	It("creates a sibling and records the Provisioning phase when the cycle annotation is set", func() {
		node := mkNode(true)
		sts, pod := mkSourceWorkload(node)
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), node, sts, pod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		res, err := r.Reconcile(bctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName, Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))

		By("creating the sibling GarageNode with fresh identity + cloned layout spec")
		sib := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, sib)).To(Succeed())
		Expect(sib.Spec.Zone).To(Equal(testNodeZone))
		Expect(sib.Spec.Capacity.Cmp(cap)).To(Equal(0))
		Expect(sib.Spec.Tags).To(ConsistOf("role:hot"))
		Expect(sib.Spec.NodeID).To(BeEmpty(), "sibling must get a fresh node ID")
		Expect(isCycleSibling(sib)).To(BeTrue(), "sibling must be marked so the cluster loop ignores it")
		Expect(sib.Labels).NotTo(HaveKey(labelAppManagedBy), "sibling must not be Auto-managed until promoted")
		Expect(sib.Labels).To(HaveKeyWithValue(labelAutoNodeSlot, nodeName))

		By("recording cycle progress on the original's status")
		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, got)).To(Succeed())
		Expect(got.Status.CyclePhase).To(Equal(garagev1beta1.CyclePhaseProvisioning))
		Expect(got.Status.CycleSiblingName).To(Equal(siblingName))
		Expect(meta.IsStatusConditionTrue(got.Status.Conditions, garagev1beta1.ConditionCycling)).To(BeTrue())
	})

	It("requires the cycle source StatefulSet controller reference to match the exact GarageNode actor", func() {
		node := mkNode(true)
		sts, pod := mkSourceWorkload(node)
		sts.OwnerReferences[0].Name = "forged-same-uid-source"
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node, sts, pod).Build()
		r := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}

		ready, err := r.prepareCycleSourcePVCIdentityHandoff(bctx, node)
		Expect(ready).To(BeFalse())
		Expect(err).To(MatchError(ContainSubstring("not controlled by GarageNode UID")))
	})

	It("resumes an in-progress cycle without re-provisioning when the sibling already exists (idempotency)", func() {
		node := mkNode(true)
		node.Status.CyclePhase = garagev1beta1.CyclePhaseProvisioning
		node.Status.CycleSiblingName = siblingName
		sts, pod := mkSourceWorkload(node)

		// Sibling exists but has not yet discovered its node ID — still coming up.
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      siblingName,
				Namespace: ns,
				Labels: map[string]string{
					labelCycleSibling: annotationTrue,
					labelCluster:      clusterName,
					labelAutoNodeSlot: nodeName,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
					Name: node.Name, UID: node.UID, Controller: ptr.To(true),
				}},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &cap,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
					Data:     &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
				},
			},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), node, sibling, sts, pod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		res, err := r.Reconcile(bctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName, Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))

		By("the original node is NOT deleted while the sibling is unsynced")
		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, got)).To(Succeed())
		Expect(got.Status.CyclePhase).To(Equal(garagev1beta1.CyclePhaseProvisioning))

		By("no duplicate sibling is created")
		list := &garagev1beta1.GarageNodeList{}
		Expect(fc.List(bctx, list)).To(Succeed())
		count := 0
		for i := range list.Items {
			if list.Items[i].Name == siblingName {
				count++
			}
		}
		Expect(count).To(Equal(1))
	})

	It("requires one matching Current layout and no Draining version without consulting update trackers", func() {
		settled := &garage.LayoutHistoryResponse{
			CurrentVersion: 5,
			Versions:       []garage.LayoutVersion{{Version: 5, Status: garage.LayoutVersionStatusCurrent}},
		}
		Expect(requireCycleSettledLayoutHistory(settled)).To(Succeed())

		draining := *settled
		draining.Versions = append([]garage.LayoutVersion{{Version: 4, Status: garage.LayoutVersionStatusDraining}}, settled.Versions...)
		Expect(requireCycleSettledLayoutHistory(&draining)).To(MatchError(ContainSubstring("still draining")))

		missingCurrent := *settled
		missingCurrent.Versions = nil
		Expect(requireCycleSettledLayoutHistory(&missingCurrent)).To(MatchError(ContainSubstring("exactly one Current")))

		mismatched := *settled
		mismatched.Versions = []garage.LayoutVersion{{Version: 4, Status: garage.LayoutVersionStatusCurrent}}
		Expect(requireCycleSettledLayoutHistory(&mismatched)).To(MatchError(ContainSubstring("while currentVersion is 5")))
	})

	It("supports the cycle on a non-Auto (Manual) node — sibling is plain, not Auto-managed", func() {
		// Manual cluster + user-created node (no operator managed-by/tier labels).
		cluster := mkCluster()
		cluster.Spec.LayoutPolicy = LayoutPolicyManual
		cluster.Spec.Storage.LayoutPolicy = LayoutPolicyManual

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testManualGarageNodeName,
				Namespace:   ns,
				UID:         types.UID("manual-cycle-source-uid"),
				Generation:  1,
				Annotations: map[string]string{garagev1beta1.AnnotationCycle: annotationTrue},
				Finalizers:  []string{garageNodeFinalizer},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &cap,
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata: &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
					Data:     &garagev1beta1.NodeVolumeConfig{Size: &dataSz},
				},
			},
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: sourceID, ObservedPodUID: sourcePodUID,
				ObservedGeneration: 1, Connected: true, InLayout: true,
			},
		}
		sts, pod := mkSourceWorkload(node)
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(cluster, node, sts, pod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: testManualGarageNodeName, Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())

		sib := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: testManualGarageNodeName + cycleSiblingSuffix, Namespace: ns}, sib)).To(Succeed())
		Expect(isCycleSibling(sib)).To(BeTrue())
		Expect(sib.Spec.Zone).To(Equal(testNodeZone))
	})

	It("never starts a cycle on a sibling node, clearing a stray annotation", func() {
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:        siblingName,
				Namespace:   ns,
				Annotations: map[string]string{garagev1beta1.AnnotationCycle: annotationTrue},
				Finalizers:  []string{garageNodeFinalizer},
				Labels:      map[string]string{labelCycleSibling: annotationTrue, labelCluster: clusterName},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &cap,
			},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), sibling).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: siblingName, Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())

		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, got)).To(Succeed())
		Expect(got.Annotations).NotTo(HaveKey(garagev1beta1.AnnotationCycle))

		By("a sibling-of-a-sibling is never created")
		nested := &garagev1beta1.GarageNode{}
		err = fc.Get(bctx, types.NamespacedName{Name: siblingName + cycleSiblingSuffix, Namespace: ns}, nested)
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})

	// cloneCycleNodeSpec / promotion unit coverage (no client).
	It("cloneCycleNodeSpec rejects existingClaim instead of inferring replacement storage", func() {
		sz := resource.MustParse("50Gi")
		node := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID:   "abc",
				Zone:     "z1",
				Capacity: &sz,
				Tags:     []string{"a", "b"},
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata:  &garagev1beta1.NodeVolumeConfig{ExistingClaim: "meta-pvc", Size: &sz},
					DataPaths: []garagev1beta1.NodeVolumeConfig{{ExistingClaim: "d0", Size: &sz}, {ExistingClaim: "d1", Size: &sz}},
				},
			},
		}
		_, err := cloneCycleNodeSpec(node)
		Expect(err).To(MatchError(ContainSubstring("storage.metadata.existingClaim")))
		// Original is untouched.
		Expect(node.Spec.NodeID).To(Equal("abc"))
		Expect(node.Spec.Storage.Metadata.ExistingClaim).To(Equal("meta-pvc"))
	})

	It("cloneCycleNodeSpec preserves repeatable templates and clears only the identity", func() {
		sz := resource.MustParse("50Gi")
		node := &garagev1beta1.GarageNode{
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID:   "abc",
				Zone:     "z1",
				Capacity: &sz,
				Tags:     []string{"a", "b"},
				Storage: &garagev1beta1.NodeStorageConfig{
					Metadata:  &garagev1beta1.NodeVolumeConfig{Size: &sz},
					DataPaths: []garagev1beta1.NodeVolumeConfig{{Size: &sz}, {Type: garagev1beta1.VolumeTypeEmptyDir}},
				},
			},
		}
		got, err := cloneCycleNodeSpec(node)
		Expect(err).NotTo(HaveOccurred())
		Expect(got.NodeID).To(BeEmpty())
		Expect(got.Zone).To(Equal("z1"))
		Expect(got.Tags).To(ConsistOf("a", "b"))
		Expect(got.Storage.Metadata.ExistingClaim).To(BeEmpty())
		Expect(got.Storage.Metadata.Size.Cmp(sz)).To(Equal(0))
		Expect(got.Storage.DataPaths[0].Size.Cmp(sz)).To(Equal(0))
		Expect(got.Storage.DataPaths[1].Type).To(Equal(garagev1beta1.VolumeTypeEmptyDir))
		// Original is untouched (deep copy).
		Expect(node.Spec.NodeID).To(Equal("abc"))
	})

	It("fails closed before creating a sibling when admission is bypassed for existingClaim", func() {
		node := mkNode(true)
		node.Spec.Storage.Metadata = &garagev1beta1.NodeVolumeConfig{
			ExistingClaim: "shared-metadata", Size: &dataSz,
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.reconcileCycle(bctx, node, mkCluster(), mkCluster())
		Expect(err).NotTo(HaveOccurred())
		missing := &garagev1beta1.GarageNode{}
		Expect(errors.IsNotFound(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, missing))).To(BeTrue())
		preserved := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, preserved)).To(Succeed())
		Expect(preserved.DeletionTimestamp.IsZero()).To(BeTrue())
		condition := meta.FindStatusCondition(preserved.Status.Conditions, garagev1beta1.ConditionCycling)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Message).To(ContainSubstring("storage.metadata.existingClaim"))
	})

	It("fails closed before creating a sibling that would inherit one fixed RPC endpoint", func() {
		cluster := mkCluster()
		cluster.Spec.Network.RPCPublicAddr = "shared.storage.example.net:3901"
		node := mkNode(true)
		sts, pod := mkSourceWorkload(node)
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(cluster, node, sts, pod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}

		_, err := r.reconcileCycle(bctx, node, cluster, cluster)
		Expect(err).NotTo(HaveOccurred())
		missing := &garagev1beta1.GarageNode{}
		Expect(errors.IsNotFound(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, missing))).To(BeTrue())
		preserved := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, preserved)).To(Succeed())
		condition := meta.FindStatusCondition(preserved.Status.Conditions, garagev1beta1.ConditionCycling)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Message).To(ContainSubstring("share parent network.rpcPublicAddr"))
	})

	It("reasserts drain intent after a status-only Draining restart and promotes only for the exact sibling proof", func() {
		cluster := mkCluster()
		node := mkNode(true)
		node.Status.CyclePhase = garagev1beta1.CyclePhaseDraining
		node.Status.CycleSiblingName = siblingName
		node.Status.CycleSiblingNodeID = siblingID
		sourceSTS, sourcePod := mkSourceWorkload(node)
		sourceSTS.Generation = 1
		sourceSTS.Status.ObservedGeneration = 1
		sourceSTS.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: metadataVolName}},
			{ObjectMeta: metav1.ObjectMeta{Name: dataVolName}},
		}
		sourceSTS.Spec.PersistentVolumeClaimRetentionPolicy = &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
			WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
			WhenScaled:  appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
		}
		metadataPVC := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Name: metadataVolName + "-" + nodeName + "-0", Namespace: ns, UID: "source-metadata-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				sourceSTS, appsv1.SchemeGroupVersion.WithKind(kindStatefulSet),
			)},
		}}
		dataPVC := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
			Name: dataVolName + "-" + nodeName + "-0", Namespace: ns, UID: "source-data-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				sourcePod, corev1.SchemeGroupVersion.WithKind("Pod"),
			)},
		}}
		siblingSpec, err := cloneCycleNodeSpec(node)
		Expect(err).NotTo(HaveOccurred())
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: siblingName, Namespace: ns, UID: "cycle-sibling-uid",
				Labels: cycleSiblingLabels(node),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
					node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
				)},
			},
			Spec: siblingSpec,
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: siblingID, ObservedPodUID: "sibling-pod-uid",
				ObservedGeneration: 1, Connected: true, InLayout: true,
			},
		}
		siblingSTS, siblingPod := mkSourceWorkload(sibling)
		proof, err := storageDrainRemovalIntent(
			nil, storageDrainActorForNode(node), []string{sourceID}, []string{sourceID}, time.Now().Add(-time.Minute),
		)
		Expect(err).NotTo(HaveOccurred())
		proof.ManagedPodUIDs = map[string]string{sourceID: sourcePodUID}
		proof.VerificationNodeIDs = []string{sourceID} // deliberately omits sibling
		completedAt := metav1.Now()
		proof.CompletedAt = &completedAt
		cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)

		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(cluster, node, sourceSTS, sourcePod, metadataPVC, dataPVC, sibling, siblingSTS, siblingPod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
			Build()
		layoutCalls := 0
		firstManager := &GarageNodeReconciler{
			Client: fc, Scheme: scheme,
			cycleLayoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
				layoutCalls++
				return nil, nil
			},
		}
		res, err := firstManager.reconcileCycle(bctx, node, cluster, cluster)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(layoutCalls).To(BeZero(), "Draining restart must not recheck ephemeral layout trackers")
		recoveredSource := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, recoveredSource)).To(Succeed())
		Expect(recoveredSource.Annotations).To(HaveKeyWithValue(garagev1beta1.AnnotationDrain, annotationTrue),
			"persisted Draining status must reassert the ordinary drain request after restart")
		Expect(recoveredSource.DeletionTimestamp.IsZero()).To(BeTrue(),
			"the same reconcile that repairs drain intent must not consume a terminal proof")
		recoveredSibling := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, recoveredSibling)).To(Succeed())
		Expect(recoveredSibling.Labels).To(HaveKey(labelCycleSibling))

		// Simulate another manager restart after the annotation write. Only now may
		// the Draining phase consult the durable proof.
		freshSource := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, freshSource)).To(Succeed())
		freshCluster := &garagev1beta2.GarageCluster{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: clusterName, Namespace: ns}, freshCluster)).To(Succeed())
		restartedManager := &GarageNodeReconciler{Client: fc, Scheme: scheme}
		_, err = restartedManager.reconcileCycle(bctx, freshSource, freshCluster, freshCluster)
		Expect(err).NotTo(HaveOccurred())
		blockedSource := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, blockedSource)).To(Succeed())
		Expect(blockedSource.DeletionTimestamp.IsZero()).To(BeTrue())
		blockedSibling := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, blockedSibling)).To(Succeed())
		Expect(blockedSibling.Labels).To(HaveKey(labelCycleSibling))
		condition := meta.FindStatusCondition(blockedSource.Status.Conditions, garagev1beta1.ConditionCycling)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Message).To(ContainSubstring("does not include exact sibling destination"))

		Expect(fc.Get(bctx, types.NamespacedName{Name: clusterName, Namespace: ns}, freshCluster)).To(Succeed())
		freshProof := clusterStorageDrainProof(freshCluster.Status.StorageDrain)
		freshProof.VerificationNodeIDs = []string{sourceID, siblingID}
		freshCluster.Status.StorageDrain = v1beta2StorageDrainStatus(freshProof)
		Expect(fc.Status().Update(bctx, freshCluster)).To(Succeed())

		// Simulate a manager restart: use a new reconciler and freshly read actors.
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, freshSource)).To(Succeed())
		// Source labels are not the Auto-ownership authority. Strip every managed
		// label mid-cycle and prove exact GarageCluster ownership plus the persisted
		// sibling slot still restore one canonical member at promotion.
		freshSource.Labels = map[string]string{"example.test/retained": "true"}
		Expect(fc.Update(bctx, freshSource)).To(Succeed())
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, freshSource)).To(Succeed())
		freshSibling := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, freshSibling)).To(Succeed())
		Expect(fc.Get(bctx, types.NamespacedName{Name: clusterName, Namespace: ns}, freshCluster)).To(Succeed())
		secondManager := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}
		_, err = secondManager.reconcileCycle(bctx, freshSource, freshCluster, freshCluster)
		Expect(err).NotTo(HaveOccurred())
		retainedSTS := &appsv1.StatefulSet{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, retainedSTS)).To(Succeed())
		Expect(statefulSetRetentionIsRetain(retainedSTS)).To(BeTrue())
		stillSibling := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, stillSibling)).To(Succeed())
		Expect(stillSibling.Labels).To(HaveKey(labelCycleSibling),
			"persisting Retain/Retain must be a separate transition from promotion")

		// A later reconcile strips the exact old StatefulSet/Pod owner references,
		// then returns once more so API read-back is the promotion boundary.
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, freshSource)).To(Succeed())
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, freshSibling)).To(Succeed())
		Expect(fc.Get(bctx, types.NamespacedName{Name: clusterName, Namespace: ns}, freshCluster)).To(Succeed())
		thirdManager := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}
		_, err = thirdManager.reconcileCycle(bctx, freshSource, freshCluster, freshCluster)
		Expect(err).NotTo(HaveOccurred())
		for _, claimName := range []string{metadataPVC.Name, dataPVC.Name} {
			claim := &corev1.PersistentVolumeClaim{}
			Expect(fc.Get(bctx, types.NamespacedName{Name: claimName, Namespace: ns}, claim)).To(Succeed())
			Expect(claim.OwnerReferences).To(BeEmpty())
		}

		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, freshSource)).To(Succeed())
		Expect(fc.Get(bctx, types.NamespacedName{Name: clusterName, Namespace: ns}, freshCluster)).To(Succeed())
		deleteClient := &deleteOptionsRecordingClient{Client: fc}
		fourthManager := &GarageNodeReconciler{Client: deleteClient, APIReader: fc, Scheme: scheme}
		_, err = fourthManager.reconcileCycle(bctx, freshSource, freshCluster, freshCluster)
		Expect(err).NotTo(HaveOccurred())
		Expect(deleteClient.lastDeleteOptions).NotTo(BeNil())
		Expect(deleteClient.lastDeleteOptions.Preconditions).NotTo(BeNil())
		Expect(deleteClient.lastDeleteOptions.Preconditions.UID).NotTo(BeNil())
		Expect(*deleteClient.lastDeleteOptions.Preconditions.UID).To(Equal(types.UID("cycle-node-uid")))

		promoted := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, promoted)).To(Succeed())
		Expect(promoted.Labels).NotTo(HaveKey(labelCycleSibling))
		Expect(promoted.Labels).To(HaveKeyWithValue(labelAutoNodeSlot, nodeName))
		Expect(promoted.Labels).To(HaveKeyWithValue(labelCluster, clusterName))
		Expect(promoted.Labels).To(HaveKeyWithValue(labelTier, tierStorage))
		Expect(promoted.Labels).To(HaveKeyWithValue(labelAppManagedBy, managedByOperatorValue))
		Expect(metav1.IsControlledBy(promoted, freshCluster)).To(BeTrue())
		deleting := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, deleting)).To(Succeed())
		Expect(deleting.DeletionTimestamp.IsZero()).To(BeFalse())
		_, current, resolveErr := resolveAutoModeCycleSlot(map[string]*garagev1beta1.GarageNode{
			deleting.Name: deleting,
			promoted.Name: promoted,
		}, nodeName)
		Expect(resolveErr).NotTo(HaveOccurred())
		Expect(current).NotTo(BeNil())
		Expect(current.Name).To(Equal(promoted.Name),
			"the parent must resolve the promoted sibling as the sole canonical ordinal after source label drift")
	})

	It("refuses terminal promotion when the sibling StatefulSet Pod restarted after the proof", func() {
		cluster := mkCluster()
		node := mkNode(true)
		node.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
		node.Status.CyclePhase = garagev1beta1.CyclePhaseDraining
		node.Status.CycleSiblingName = siblingName
		node.Status.CycleSiblingNodeID = siblingID
		siblingSpec, err := cloneCycleNodeSpec(node)
		Expect(err).NotTo(HaveOccurred())
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: siblingName, Namespace: ns, UID: "cycle-sibling-restart-uid", Generation: 1,
				Labels: cycleSiblingLabels(node),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
					node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
				)},
			},
			Spec: siblingSpec,
			Status: garagev1beta1.GarageNodeStatus{
				NodeID: siblingID, ObservedPodUID: "proved-sibling-pod-uid",
				ObservedGeneration: 1, Connected: true, InLayout: true,
			},
		}
		siblingSTS, siblingPod := mkSourceWorkload(sibling)
		siblingPod.UID = "replacement-sibling-pod-uid"
		proof, err := storageDrainRemovalIntent(
			nil, storageDrainActorForNode(node), []string{sourceID}, []string{sourceID}, time.Now().Add(-time.Minute),
		)
		Expect(err).NotTo(HaveOccurred())
		proof.ManagedPodUIDs = map[string]string{sourceID: sourcePodUID}
		proof.VerificationNodeIDs = []string{sourceID, siblingID}
		completedAt := metav1.Now()
		proof.CompletedAt = &completedAt
		cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)

		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(cluster, node, sibling, siblingSTS, siblingPod).
			WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}
		_, err = r.reconcileCycle(bctx, node, cluster, cluster)
		Expect(err).NotTo(HaveOccurred())

		preservedSource := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, preservedSource)).To(Succeed())
		Expect(preservedSource.DeletionTimestamp.IsZero()).To(BeTrue())
		preservedSibling := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: siblingName, Namespace: ns}, preservedSibling)).To(Succeed())
		Expect(preservedSibling.Labels).To(HaveKey(labelCycleSibling))
		condition := meta.FindStatusCondition(preservedSource.Status.Conditions, garagev1beta1.ConditionCycling)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Message).To(ContainSubstring("exact current StatefulSet Pod"))
	})

	It("isCycleRequested only fires on the literal \"true\" value", func() {
		n := &garagev1beta1.GarageNode{}
		Expect(isCycleRequested(n)).To(BeFalse())
		n.Annotations = map[string]string{garagev1beta1.AnnotationCycle: "yes"}
		Expect(isCycleRequested(n)).To(BeFalse())
		n.Annotations[garagev1beta1.AnnotationCycle] = annotationTrue
		Expect(isCycleRequested(n)).To(BeTrue())
	})

	It("bounds replacement names while preserving a stable Auto slot", func() {
		longName := "this-is-a-valid-but-nearly-maximum-length-storage-node-name-0"
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: longName,
				Labels: map[string]string{
					labelCluster:      "this-is-a-valid-but-nearly-maximum-length",
					labelTier:         tierStorage,
					labelAppManagedBy: managedByOperatorValue,
					labelAutoNodeSlot: longName,
				},
			},
		}
		bounded := boundedGarageNodeName(node.Name + cycleSiblingSuffix)
		Expect(len(bounded)).To(BeNumerically("<=", 61))
		Expect(len(bounded + "-0")).To(BeNumerically("<=", 63))
		Expect(bounded).NotTo(Equal(node.Name + cycleSiblingSuffix))
		Expect(cycleSiblingLabels(node)).To(HaveKeyWithValue(labelAutoNodeSlot, longName))
	})

	It("provisions a repeated cycle from a hash-bounded promoted source's persisted Auto slot", func() {
		longClusterName := strings.Repeat("a", 50)
		canonical := autoModeGarageNodeName(longClusterName, 0)
		promotedName := boundedGarageNodeName(canonical + cycleSiblingSuffix)
		Expect(promotedName).NotTo(Equal(canonical + cycleSiblingSuffix))
		cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
			Name: longClusterName, Namespace: ns, UID: "long-cycle-cluster-uid",
		}}
		promoted := &garagev1beta1.GarageNode{ObjectMeta: metav1.ObjectMeta{
			Name: promotedName, Namespace: ns,
			Labels: map[string]string{labelAutoNodeSlot: canonical},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
			)},
		}}

		labels, err := cycleSiblingLabelsForCluster(promoted, cluster)
		Expect(err).NotTo(HaveOccurred())
		Expect(labels).To(HaveKeyWithValue(labelAutoNodeSlot, canonical))
		Expect(labels).To(HaveKeyWithValue(labelCluster, longClusterName))
	})

	It("resolves repeated replacements by stable slot and fails closed on ambiguity", func() {
		canonical := "garage-storage-0"
		deletingAt := metav1.Now()
		existing := map[string]*garagev1beta1.GarageNode{
			canonical: {
				ObjectMeta: metav1.ObjectMeta{
					Name: canonical, DeletionTimestamp: &deletingAt,
					Labels: map[string]string{labelAutoNodeSlot: canonical},
				},
			},
			"garage-storage-0-cycle": {
				ObjectMeta: metav1.ObjectMeta{
					Name: "garage-storage-0-cycle", DeletionTimestamp: &deletingAt,
					Labels: map[string]string{labelAutoNodeSlot: canonical},
				},
			},
			"bounded-hash-replacement": {
				ObjectMeta: metav1.ObjectMeta{
					Name:   "bounded-hash-replacement",
					Labels: map[string]string{labelAutoNodeSlot: canonical},
				},
			},
		}
		names, active, err := promotedCycleDescendantNames(existing, canonical)
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(ConsistOf("garage-storage-0-cycle", "bounded-hash-replacement"))
		Expect(active).NotTo(BeNil())
		Expect(active.Name).To(Equal("bounded-hash-replacement"))
		names, current, err := resolveAutoModeCycleSlot(existing, canonical)
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(ConsistOf("garage-storage-0-cycle", "bounded-hash-replacement"))
		Expect(current).NotTo(BeNil())
		Expect(current.Name).To(Equal("bounded-hash-replacement"),
			"a deleting canonical is an ancestor, while the promoted identity remains updateable")

		existing["second-live-replacement"] = &garagev1beta1.GarageNode{ObjectMeta: metav1.ObjectMeta{
			Name: "second-live-replacement", Labels: map[string]string{labelAutoNodeSlot: canonical},
		}}
		_, _, err = promotedCycleDescendantNames(existing, canonical)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ambiguous promoted cycle descendants"))

		delete(existing, "second-live-replacement")
		existing[canonical].DeletionTimestamp = nil
		_, _, err = resolveAutoModeCycleSlot(existing, canonical)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("both live"))
	})

	It("adopts only the bounded released legacy promoted shape", func() {
		cluster := mkCluster()
		legacy := mkNode(false)
		legacy.Name = nodeName + cycleSiblingSuffix
		legacy.OwnerReferences = nil
		legacy.Status.NodeID = siblingID
		legacy.Status.InLayout = true
		legacy.Labels = map[string]string{
			labelCluster: clusterName, labelTier: tierStorage, labelAppManagedBy: managedByOperatorValue,
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, legacy).Build()
		r := &GarageClusterReconciler{Client: fc, Scheme: scheme}
		adopted, err := r.ensureAutoModeCycleOwnership(
			bctx, cluster, map[string]*garagev1beta1.GarageNode{legacy.Name: legacy}, tierStorage,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(adopted).To(BeTrue())
		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: legacy.Name, Namespace: ns}, got)).To(Succeed())
		Expect(metav1.IsControlledBy(got, cluster)).To(BeTrue())
		Expect(got.Labels).To(HaveKeyWithValue(labelAutoNodeSlot, nodeName))

		spoof := legacy.DeepCopy()
		spoof.Name = nodeName + "-forged"
		spoof.ResourceVersion = ""
		spoof.UID = ""
		spoof.OwnerReferences = nil
		delete(spoof.Labels, labelAutoNodeSlot)
		spoof.Status = garagev1beta1.GarageNodeStatus{}
		adopted, err = r.ensureAutoModeCycleOwnership(
			bctx, cluster, map[string]*garagev1beta1.GarageNode{spoof.Name: spoof}, tierStorage,
		)
		Expect(adopted).To(BeFalse())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("refusing to trust or retire"))
	})

	It("preflights a legacy adoption before mutation and rejects another live slot occupant", func() {
		cluster := mkCluster()
		legacy := mkNode(false)
		legacy.Name = nodeName + cycleSiblingSuffix
		legacy.OwnerReferences = nil
		legacy.Status.NodeID = siblingID
		legacy.Status.InLayout = true
		legacy.Labels = map[string]string{
			labelCluster: clusterName, labelTier: tierStorage, labelAppManagedBy: managedByOperatorValue,
		}
		canonical := mkNode(false)
		canonical.Annotations = nil
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, legacy, canonical).Build()
		r := &GarageClusterReconciler{Client: fc, Scheme: scheme}
		adopted, err := r.ensureAutoModeCycleOwnership(
			bctx, cluster, map[string]*garagev1beta1.GarageNode{
				legacy.Name: legacy, canonical.Name: canonical,
			}, tierStorage,
		)
		Expect(adopted).To(BeFalse())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("also occupied by live GarageNode"))
		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: legacy.Name, Namespace: ns}, got)).To(Succeed())
		Expect(metav1.GetControllerOf(got)).To(BeNil(), "failed preflight must not partially adopt the legacy identity")
	})

	It("requires the complete resolved GarageCluster controller identity", func() {
		cluster := mkCluster()
		node := mkNode(false)
		sibling := &garagev1beta1.GarageNode{ObjectMeta: metav1.ObjectMeta{
			Name: siblingName,
			Labels: map[string]string{
				labelCycleSibling: annotationTrue,
				labelAutoNodeSlot: nodeName,
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
			)},
		}}
		for _, mutate := range []struct {
			name string
			fn   func(*metav1.OwnerReference)
		}{
			{name: "wrong API group", fn: func(owner *metav1.OwnerReference) { owner.APIVersion = garagev1beta1.GroupVersion.String() }},
			{name: "wrong kind", fn: func(owner *metav1.OwnerReference) { owner.Kind = kindGarageNode }},
			{name: "wrong name", fn: func(owner *metav1.OwnerReference) { owner.Name = "different-cluster" }},
			{name: "wrong UID", fn: func(owner *metav1.OwnerReference) { owner.UID = "different-uid" }},
		} {
			By(mutate.name)
			forged := node.DeepCopy()
			mutate.fn(&forged.OwnerReferences[0])
			Expect(validateCycleSiblingActor(forged, sibling, cluster)).To(MatchError(ContainSubstring("exact resolved GarageCluster")))
		}
		ownerless := node.DeepCopy()
		ownerless.OwnerReferences = nil
		Expect(validateCycleSiblingActor(ownerless, sibling, cluster)).To(MatchError(ContainSubstring("claims Auto membership")))
	})
})
