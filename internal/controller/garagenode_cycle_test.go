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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Graceful node cycle (#231) — add-before-remove replacement state machine.
var _ = Describe("GarageNode graceful cycle", func() {
	const (
		ns          = "cycle-ns"
		clusterName = "cyc"
		nodeName    = "cyc-storage-0"
		siblingName = "cyc-storage-0-cycle"
		siblingID   = "1111111111111111111111111111111111111111111111111111111111111111"
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
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: ns, UID: "cyc-uid"},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
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
				Annotations: ann,
				Finalizers:  []string{garageNodeFinalizer},
				Labels: map[string]string{
					labelCluster:      clusterName,
					labelTier:         tierStorage,
					labelAppManagedBy: managedByOperatorValue,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion:         garagev1beta2.GroupVersion.String(),
					Kind:               "GarageCluster",
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
			Status: garagev1beta1.GarageNodeStatus{NodeID: "deadbeef"},
		}
	}

	It("creates a sibling and records the Provisioning phase when the cycle annotation is set", func() {
		node := mkNode(true)
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), node).
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

		By("recording cycle progress on the original's status")
		got := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: nodeName, Namespace: ns}, got)).To(Succeed())
		Expect(got.Status.CyclePhase).To(Equal(garagev1beta1.CyclePhaseProvisioning))
		Expect(got.Status.CycleSiblingName).To(Equal(siblingName))
		Expect(meta.IsStatusConditionTrue(got.Status.Conditions, garagev1beta1.ConditionCycling)).To(BeTrue())
	})

	It("resumes an in-progress cycle without re-provisioning when the sibling already exists (idempotency)", func() {
		node := mkNode(true)
		node.Status.CyclePhase = garagev1beta1.CyclePhaseProvisioning
		node.Status.CycleSiblingName = siblingName

		// Sibling exists but has not yet discovered its node ID — still coming up.
		sibling := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      siblingName,
				Namespace: ns,
				Labels:    map[string]string{labelCycleSibling: annotationTrue, labelCluster: clusterName},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &cap,
			},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(mkCluster(), node, sibling).
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

	It("does not remove the original until the sibling reaches the replication-factor sync (predicate gate)", func() {
		// The drain+remove step is gated on LayoutHistoryResponse.NodeSyncedToCurrent.
		// Below the current layout version → not synced → original kept.
		hist := &garage.LayoutHistoryResponse{
			CurrentVersion: 5,
			UpdateTrackers: map[string]garage.NodeUpdateTrackers{
				siblingID: {Ack: 5, Sync: 4, SyncAck: 4},
			},
		}
		Expect(hist.NodeSyncedToCurrent(siblingID)).To(BeFalse(), "sync tracker behind current version")

		// A node with no tracker entry at all is never considered synced.
		Expect(hist.NodeSyncedToCurrent("nope")).To(BeFalse())

		// Caught up to the current version → safe to remove the original.
		hist.UpdateTrackers[siblingID] = garage.NodeUpdateTrackers{Ack: 5, Sync: 5, SyncAck: 5}
		Expect(hist.NodeSyncedToCurrent(siblingID)).To(BeTrue())
	})

	It("supports the cycle on a non-Auto (Manual) node — sibling is plain, not Auto-managed", func() {
		// Manual cluster + user-created node (no operator managed-by/tier labels).
		cluster := mkCluster()
		cluster.Spec.LayoutPolicy = LayoutPolicyManual
		cluster.Spec.Storage.LayoutPolicy = LayoutPolicyManual

		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "manual-node",
				Namespace:   ns,
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
			Status: garagev1beta1.GarageNodeStatus{NodeID: "cafe"},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(cluster, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).
			Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.Reconcile(bctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "manual-node", Namespace: ns}})
		Expect(err).NotTo(HaveOccurred())

		sib := &garagev1beta1.GarageNode{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: "manual-node" + cycleSiblingSuffix, Namespace: ns}, sib)).To(Succeed())
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
})

// cloneCycleNodeSpec / promotion unit coverage (no client).
var _ = Describe("cycle spec helpers", func() {
	It("cloneCycleNodeSpec strips identity + existingClaim but keeps layout fields", func() {
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
		got := cloneCycleNodeSpec(node)
		Expect(got.NodeID).To(BeEmpty())
		Expect(got.Zone).To(Equal("z1"))
		Expect(got.Tags).To(ConsistOf("a", "b"))
		Expect(got.Storage.Metadata.ExistingClaim).To(BeEmpty())
		Expect(got.Storage.Metadata.Size.Cmp(sz)).To(Equal(0))
		for _, dp := range got.Storage.DataPaths {
			Expect(dp.ExistingClaim).To(BeEmpty())
			Expect(dp.Size.Cmp(sz)).To(Equal(0))
		}
		// Original is untouched (deep copy).
		Expect(node.Spec.NodeID).To(Equal("abc"))
		Expect(node.Spec.Storage.Metadata.ExistingClaim).To(Equal("meta-pvc"))
	})

	It("isCycleRequested only fires on the literal \"true\" value", func() {
		n := &garagev1beta1.GarageNode{}
		Expect(isCycleRequested(n)).To(BeFalse())
		n.Annotations = map[string]string{garagev1beta1.AnnotationCycle: "yes"}
		Expect(isCycleRequested(n)).To(BeFalse())
		n.Annotations[garagev1beta1.AnnotationCycle] = annotationTrue
		Expect(isCycleRequested(n)).To(BeTrue())
	})
})
