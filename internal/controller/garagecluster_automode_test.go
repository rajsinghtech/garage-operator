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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// conflictInjectingClient wraps a client.Client and injects a Conflict error
// on the first Update of a target GarageCluster, then passes through. Used
// by the bug #3 regression test to exercise the retry-on-conflict path in
// migrateLegacyStorageSTSIfNeeded.
type conflictInjectingClient struct {
	client.Client
	targetName         string
	conflictsRemaining int
	updates            int
}

func (c *conflictInjectingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if c.conflictsRemaining > 0 {
		if gc, ok := obj.(*garagev1beta2.GarageCluster); ok && gc.Name == c.targetName {
			c.conflictsRemaining--
			gvr := schema.GroupResource{Group: garagev1beta2.GroupVersion.Group, Resource: "garageclusters"}
			return errors.NewConflict(gvr, gc.Name, fmt.Errorf("injected conflict"))
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

// uniqueClusterName returns a per-test cluster name based on the spec subject
// so each test gets its own resources in the shared testNamespace.
func uniqueClusterName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// testZone is the canonical zone name used across Auto-mode test fixtures.
const testZone = "us-east-1"

var _ = Describe("GarageCluster Auto-mode (#190)", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	var (
		reconciler *GarageClusterReconciler
		cluster    *garagev1beta2.GarageCluster
		clusterNN  types.NamespacedName
	)

	BeforeEach(func() {
		reconciler = &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	})

	// teardown removes the cluster and any operator-owned GarageNodes / STSes
	// it created. We rely on the cluster's finalizer to clean up downstream
	// objects via the controller; tests run in envtest with no real workload,
	// so we strip the finalizer to allow immediate deletion.
	teardown := func() {
		fresh := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, clusterNN, fresh); err == nil {
			fresh.Finalizers = nil
			_ = k8sClient.Update(ctx, fresh)
			_ = k8sClient.Delete(ctx, fresh)
		}
		// Best-effort cleanup of operator-owned GarageNodes.
		gnList := &garagev1beta1.GarageNodeList{}
		_ = k8sClient.List(ctx, gnList, client.InNamespace(testNamespace), client.MatchingLabels(map[string]string{labelCluster: clusterNN.Name}))
		for i := range gnList.Items {
			n := gnList.Items[i]
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, &n)
			_ = k8sClient.Delete(ctx, &n)
		}
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace}})
	}

	AfterEach(func() {
		teardown()
	})

	Context("Auto mode generates per-node GarageNodes", func() {
		BeforeEach(func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-create"), Namespace: testNamespace}
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
					Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		})

		It("creates one operator-owned GarageNode per storage replica", func() {
			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())

			gnList := listOperatorOwnedStorageNodes(clusterNN.Name)
			Expect(gnList.Items).To(HaveLen(3))

			names := map[string]bool{}
			for _, n := range gnList.Items {
				names[n.Name] = true
			}
			Expect(names).To(HaveKey(clusterNN.Name + "-storage-0"))
			Expect(names).To(HaveKey(clusterNN.Name + "-storage-1"))
			Expect(names).To(HaveKey(clusterNN.Name + "-storage-2"))

			// Verify ownership + spec.
			for _, n := range gnList.Items {
				Expect(metav1.IsControlledBy(&n, cluster)).To(BeTrue())
				Expect(n.Spec.ClusterRef.Name).To(Equal(clusterNN.Name))
				Expect(n.Spec.Zone).To(Equal(testZone))
				Expect(n.Spec.Capacity).NotTo(BeNil())
				Expect(n.Labels).To(HaveKeyWithValue(labelAppManagedBy, managedByOperatorValue))
				Expect(n.Labels).To(HaveKeyWithValue(labelCluster, clusterNN.Name))
				Expect(n.Labels).To(HaveKeyWithValue(labelTier, tierStorage))
				// Fresh creates must not have existingClaim set.
				Expect(n.Spec.Storage).NotTo(BeNil())
				Expect(n.Spec.Storage.Metadata.ExistingClaim).To(BeEmpty())
				Expect(n.Spec.Storage.Data.ExistingClaim).To(BeEmpty())
			}
		})

		It("scales up by creating new GarageNodes", func() {
			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())
			Expect(listOperatorOwnedStorageNodes(clusterNN.Name).Items).To(HaveLen(3))

			Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
			cluster.Spec.Storage.Replicas = 5
			Expect(k8sClient.Update(ctx, cluster)).To(Succeed())

			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())
			gnList := listOperatorOwnedStorageNodes(clusterNN.Name)
			Expect(gnList.Items).To(HaveLen(5))
		})

		It("scales down by deleting GarageNodes for ordinals >= replicas", func() {
			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())

			Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
			cluster.Spec.Storage.Replicas = 2
			Expect(k8sClient.Update(ctx, cluster)).To(Succeed())

			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())

			Eventually(func() []string {
				gnList := listOperatorOwnedStorageNodes(clusterNN.Name)
				names := []string{}
				for _, n := range gnList.Items {
					if n.DeletionTimestamp.IsZero() {
						names = append(names, n.Name)
					}
				}
				return names
			}, timeout, interval).Should(ConsistOf(clusterNN.Name+"-storage-0", clusterNN.Name+"-storage-1"))

			// In envtest, deletion may stall on finalizers; tolerate that by
			// scanning for at least the two remaining ordinals above. The
			// excess GarageNode either has a DeletionTimestamp or has been
			// removed — both are valid outcomes.
		})
	})

	Context("Auto→Manual ejection", func() {
		BeforeEach(func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-eject"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		})

		It("strips controllerOwnerRef and managed-by label", func() {
			// Create the operator-owned GarageNodes.
			Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())
			Expect(listOperatorOwnedStorageNodes(clusterNN.Name).Items).To(HaveLen(2))

			// Eject.
			Expect(reconciler.ejectAutoModeStorageNodes(ctx, cluster)).To(Succeed())

			// After ejection, listAutoModeStorageNodes must return zero (label stripped).
			Expect(listOperatorOwnedStorageNodes(clusterNN.Name).Items).To(BeEmpty())

			// But the GarageNode CRs themselves still exist with the cluster label.
			gnList := &garagev1beta1.GarageNodeList{}
			Expect(k8sClient.List(ctx, gnList,
				client.InNamespace(testNamespace),
				client.MatchingLabels(map[string]string{labelCluster: clusterNN.Name}),
			)).To(Succeed())
			Expect(gnList.Items).To(HaveLen(2))
			for _, n := range gnList.Items {
				Expect(metav1.IsControlledBy(&n, cluster)).To(BeFalse(), "ejected GarageNode must not have controllerOwnerRef to cluster")
				_, hasMB := n.Labels[labelAppManagedBy]
				Expect(hasMB).To(BeFalse(), "ejected GarageNode must not retain managed-by=operator label")
			}
		})
	})

	Context("Legacy STS migration", func() {
		It("sets LegacySTSMigrated condition to Completed on a fresh cluster with no legacy STS", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-fresh"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
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
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("Completed"))
		})

		It("migrates a multi-HDD legacy STS to per-node GarageNodes with DataPaths populated", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-multihdd"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data: &garagev1beta2.VolumeConfig{
							Size: ptrQuantity(resource.MustParse("10Gi")),
							// Cluster-level per-disk paths: the legacy STS mounted
							// data at /mnt/ssd-0 and /mnt/cold-1 (a frozen archive).
							// Migration must preserve these so Garage's DataLayout
							// finds blocks at the same paths after upgrade.
							Paths: []garagev1beta2.DataPath{
								{Path: "/mnt/ssd-0", Capacity: ptrQuantity(resource.MustParse("10Gi"))},
								{Path: "/mnt/cold-1", ReadOnly: true},
							},
						},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Seed a legacy STS plus multi-HDD PVCs (two disks per ordinal,
			// two ordinals → 4 data PVCs + 2 metadata PVCs).
			legacySTS := makeFakeLegacySTS(clusterNN.Name, 2)
			Expect(k8sClient.Create(ctx, legacySTS)).To(Succeed())
			for ord := 0; ord < 2; ord++ {
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("metadata-%s-%d", clusterNN.Name, ord)))).To(Succeed())
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-0-%s-%d", clusterNN.Name, ord)))).To(Succeed())
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-1-%s-%d", clusterNN.Name, ord)))).To(Succeed())
			}

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("Completed"))

			gnList := listOperatorOwnedStorageNodes(clusterNN.Name)
			Expect(gnList.Items).To(HaveLen(2))
			for _, n := range gnList.Items {
				Expect(n.Spec.Storage).NotTo(BeNil())
				Expect(n.Spec.Storage.Metadata.ExistingClaim).To(HavePrefix("metadata-" + clusterNN.Name))
				Expect(n.Spec.Storage.Data).To(BeNil(), "multi-HDD migration should populate DataPaths, not Data")
				Expect(n.Spec.Storage.DataPaths).To(HaveLen(2))
				Expect(n.Spec.Storage.DataPaths[0].ExistingClaim).To(HavePrefix("data-0-" + clusterNN.Name))
				Expect(n.Spec.Storage.DataPaths[1].ExistingClaim).To(HavePrefix("data-1-" + clusterNN.Name))
				// Migration must propagate the cluster's per-disk paths and
				// the read_only flag — DataLayout indexes by path on disk.
				Expect(n.Spec.Storage.DataPaths[0].Path).To(Equal("/mnt/ssd-0"))
				Expect(n.Spec.Storage.DataPaths[0].ReadOnly).To(BeFalse())
				Expect(n.Spec.Storage.DataPaths[1].Path).To(Equal("/mnt/cold-1"))
				Expect(n.Spec.Storage.DataPaths[1].ReadOnly).To(BeTrue())
			}
		})

		It("refuses to mark migration Completed when legacy STS has replicas=0 but PVCs exist", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-zero-replicas"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Legacy STS scaled to zero, but PVCs from the original 2-replica
			// run are still around — exactly the data-loss scenario the guard
			// closes (audit #6).
			legacySTS := makeFakeLegacySTS(clusterNN.Name, 0)
			Expect(k8sClient.Create(ctx, legacySTS)).To(Succeed())
			Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("metadata-%s-0", clusterNN.Name)))).To(Succeed())
			Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-%s-0", clusterNN.Name)))).To(Succeed())

			err := reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("replicas=0"))

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("Failed"))
			Expect(cond.Message).To(ContainSubstring("replicas=0"))

			// STS must NOT be orphan-deleted; PVCs must still exist.
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterNN.Name, Namespace: testNamespace}, sts)).To(Succeed())
			Expect(sts.DeletionTimestamp.IsZero()).To(BeTrue())
			pvc := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: fmt.Sprintf("metadata-%s-0", clusterNN.Name), Namespace: testNamespace}, pvc)).To(Succeed())
		})

		It("migrates a single-HDD legacy STS to per-node GarageNodes with existingClaim set", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-mig"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Seed a legacy STS named after the cluster + its PVCs.
			legacySTS := makeFakeLegacySTS(clusterNN.Name, 2)
			Expect(k8sClient.Create(ctx, legacySTS)).To(Succeed())
			for ord := 0; ord < 2; ord++ {
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("metadata-%s-%d", clusterNN.Name, ord)))).To(Succeed())
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-%s-%d", clusterNN.Name, ord)))).To(Succeed())
			}

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			// Condition reports Completed and 2 GarageNodes exist with existingClaim set.
			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("Completed"))

			gnList := listOperatorOwnedStorageNodes(clusterNN.Name)
			Expect(gnList.Items).To(HaveLen(2))
			for _, n := range gnList.Items {
				Expect(n.Spec.Storage).NotTo(BeNil())
				Expect(n.Spec.Storage.Metadata.ExistingClaim).To(HavePrefix("metadata-" + clusterNN.Name))
				Expect(n.Spec.Storage.Data.ExistingClaim).To(HavePrefix("data-" + clusterNN.Name))
			}

			// Legacy STS was orphan-deleted (envtest may take a moment).
			Eventually(func() bool {
				sts := &appsv1.StatefulSet{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: clusterNN.Name, Namespace: testNamespace}, sts)
				return errors.IsNotFound(err) || (err == nil && !sts.DeletionTimestamp.IsZero())
			}, timeout, interval).Should(BeTrue())
		})

		It("aggregates status from per-node GarageNodes (post-#190 storage tier)", func() {
			// Post-#190 fix: updateStatusFromCluster used to Get a single
			// cluster-named StatefulSet for storage readiness, which no longer
			// exists in Auto mode. Mirror the Manual-mode path and count
			// .status.connected on child GarageNodes instead.
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-status"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Zone:         testZone,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 2},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Seed two operator-owned GarageNodes with matching labels, both
			// reporting status.connected=true. Status is set after Create
			// because the API server strips status on Create.
			for i := 0; i < 2; i++ {
				nodeName := fmt.Sprintf("%s-storage-%d", clusterNN.Name, i)
				gn := &garagev1beta1.GarageNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:      nodeName,
						Namespace: testNamespace,
						Labels: map[string]string{
							labelCluster:      clusterNN.Name,
							labelTier:         tierStorage,
							labelAppManagedBy: managedByOperatorValue,
						},
					},
					Spec: garagev1beta1.GarageNodeSpec{
						ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name},
						Zone:       testZone,
						Capacity:   ptrQuantity(resource.MustParse("10Gi")),
					},
				}
				Expect(k8sClient.Create(ctx, gn)).To(Succeed())
				gn.Status.Connected = true
				Expect(k8sClient.Status().Update(ctx, gn)).To(Succeed())
			}

			_, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			Expect(updated.Status.StorageReplicas).To(Equal(int32(2)))
			Expect(updated.Status.StorageReadyReplicas).To(Equal(int32(2)))
			Expect(updated.Status.ReadyReplicas).To(Equal(int32(2)))
			Expect(updated.Status.Phase).To(Equal("Running"))
		})

		It("reports Degraded when some per-node GarageNodes are not connected", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-status-partial"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Zone:         testZone,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 2},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Two GarageNodes: only ordinal 0 reports Connected.
			for i := 0; i < 2; i++ {
				nodeName := fmt.Sprintf("%s-storage-%d", clusterNN.Name, i)
				gn := &garagev1beta1.GarageNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:      nodeName,
						Namespace: testNamespace,
						Labels: map[string]string{
							labelCluster:      clusterNN.Name,
							labelTier:         tierStorage,
							labelAppManagedBy: managedByOperatorValue,
						},
					},
					Spec: garagev1beta1.GarageNodeSpec{
						ClusterRef: garagev1beta1.ClusterReference{Name: clusterNN.Name},
						Zone:       testZone,
						Capacity:   ptrQuantity(resource.MustParse("10Gi")),
					},
				}
				Expect(k8sClient.Create(ctx, gn)).To(Succeed())
				if i == 0 {
					gn.Status.Connected = true
					Expect(k8sClient.Status().Update(ctx, gn)).To(Succeed())
				}
			}

			_, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			Expect(updated.Status.StorageReplicas).To(Equal(int32(2)))
			Expect(updated.Status.StorageReadyReplicas).To(Equal(int32(1)))
			Expect(updated.Status.Phase).To(Equal("Degraded"))
		})

		It("strips the retry-migration annotation through a Conflict on first Update", func() {
			// Regression for bug #3: when a competing reconcile bumps
			// ResourceVersion between the migration status write and the
			// annotation-strip Update, the bare r.Update returned Conflict
			// and the annotation persisted forever — looping the migration.
			// The fix wraps the strip in retry.RetryOnConflict.
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-retry-anno"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:        clusterNN.Name,
					Namespace:   testNamespace,
					Annotations: map[string]string{garagev1beta1.AnnotationRetryMigration: annotationTrue},
				},
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
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Wrap k8sClient so the first Update of *this* cluster returns
			// Conflict, then passes through. Status().Update() and Get() are
			// unaffected so UpdateStatusWithRetry still progresses; the
			// retry-on-conflict loop being exercised is the one around the
			// annotation strip.
			injector := &conflictInjectingClient{
				Client:             k8sClient,
				targetName:         clusterNN.Name,
				conflictsRemaining: 1,
			}
			testReconciler := &GarageClusterReconciler{Client: injector, Scheme: k8sClient.Scheme()}

			Expect(testReconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			// First Update was returned Conflict by the wrapper; the retry
			// loop must have re-fetched and succeeded on the second attempt.
			Expect(injector.conflictsRemaining).To(Equal(0), "wrapper should have consumed its conflict budget")
			Expect(injector.updates).To(BeNumerically(">=", 2), "retry loop should issue at least two Update calls (conflict + success)")

			// Annotation must be removed on the server.
			fresh := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, fresh)).To(Succeed())
			Expect(fresh.Annotations).NotTo(HaveKey(garagev1beta1.AnnotationRetryMigration))

			// Migration condition should still be set to Completed (no legacy
			// STS exists for this cluster).
			cond := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("Completed"))
		})

		It("is idempotent after Completed", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-idem"), Namespace: testNamespace}
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterNN.Name, Namespace: testNamespace},
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
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())
			// Force-refresh and call again — must be a no-op.
			Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
			before := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(before).NotTo(BeNil())
			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
			after := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
			Expect(after).NotTo(BeNil())
			Expect(after.Status).To(Equal(before.Status))
			Expect(after.Reason).To(Equal(before.Reason))
		})
	})
})

var _ = Describe("buildAutoModeStorageNode PublicEndpoint propagation (bug #7)", func() {
	// Regression for bug #7: per-node LoadBalancer Services were created by
	// the cluster controller at `<cluster>-<i>-rpc` but the per-node
	// GarageNodes never had spec.PublicEndpoint set, so the GarageNode
	// controller had no signal to derive rpc_public_addr from the LB. Pods
	// came up advertising the pod TCP source IP — the `known_addrs`
	// pollution failure mode.

	makeReconciler := func() *GarageClusterReconciler {
		return &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	}
	makeCluster := func(name string, ep *garagev1beta2.PublicEndpointConfig) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, UID: "test-uid"},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 2,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication:    &garagev1beta2.ReplicationConfig{Factor: 2},
				PublicEndpoint: ep,
			},
		}
	}

	It("propagates LoadBalancer+perNode=true onto each operator-owned GarageNode", func() {
		r := makeReconciler()
		cluster := makeCluster("ep-perNode", &garagev1beta2.PublicEndpointConfig{
			Type: publicEndpointTypeLoadBalancer,
			LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
				PerNode: true,
				ServiceMeta: garagev1beta2.ServiceMeta{
					Annotations: map[string]string{"example.com/key": "bar"},
				},
			},
		})

		for ord := int32(0); ord < 2; ord++ {
			node, err := r.buildAutoModeStorageNode(cluster, ord, "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(node.Spec.PublicEndpoint).NotTo(BeNil(),
				"buildAutoModeStorageNode must propagate PublicEndpoint to operator-owned GarageNode ord=%d", ord)
			Expect(node.Spec.PublicEndpoint.Type).To(Equal(publicEndpointTypeLoadBalancer))
			Expect(node.Spec.PublicEndpoint.LoadBalancer).NotTo(BeNil())
			Expect(node.Spec.PublicEndpoint.LoadBalancer.PerNode).To(BeTrue())
			Expect(node.Spec.PublicEndpoint.LoadBalancer.Annotations).To(HaveKeyWithValue("example.com/key", "bar"))

			// effectiveNodeRPCServiceName must point at the cluster-owned
			// per-node Service so the GarageNode controller derives
			// rpc_public_addr from the right LB.
			Expect(effectiveNodeRPCServiceName(node, cluster)).
				To(Equal(perNodeRPCServiceName(cluster.Name, ord)))

			// And clusterOwnsAutoModePerNodeService must report true so
			// reconcileNodeService skips creating a duplicate Service.
			Expect(clusterOwnsAutoModePerNodeService(node)).To(BeTrue())
		}
	})

	It("does NOT propagate a shared (non-perNode) LoadBalancer endpoint", func() {
		// A single shared LB Service doesn't give per-pod addressing, so
		// propagating it would just make the GarageNode controller try to
		// create a duplicate per-node Service for no benefit.
		r := makeReconciler()
		cluster := makeCluster("ep-shared", &garagev1beta2.PublicEndpointConfig{
			Type: publicEndpointTypeLoadBalancer,
			LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
				PerNode: false,
			},
		})
		node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.PublicEndpoint).To(BeNil())
		Expect(clusterOwnsAutoModePerNodeService(node)).To(BeFalse())
		Expect(effectiveNodeRPCServiceName(node, cluster)).To(Equal(node.Name + "-rpc"))
	})

	It("does NOT propagate when the cluster has no PublicEndpoint", func() {
		r := makeReconciler()
		cluster := makeCluster("ep-none", nil)
		node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.PublicEndpoint).To(BeNil())
	})

	It("treats PublicEndpoint changes as drift on existing operator-owned nodes", func() {
		// reconcileAutoModeStorageNodes must propagate PublicEndpoint
		// changes to existing GarageNodes; otherwise toggling perNode after
		// initial reconcile would leave the operator-owned nodes without
		// their LB hint.
		r := makeReconciler()

		// Start with no PublicEndpoint, then add one.
		clusterName := uniqueClusterName("ep-drift")
		cluster := makeCluster(clusterName, nil)
		cluster.UID = "" // let the API server assign
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		DeferCleanup(func() {
			fresh := &garagev1beta2.GarageCluster{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(ctx, fresh)
				_ = k8sClient.Delete(ctx, fresh)
			}
			gnList := &garagev1beta1.GarageNodeList{}
			_ = k8sClient.List(ctx, gnList, client.InNamespace(testNamespace), client.MatchingLabels(map[string]string{labelCluster: clusterName}))
			for i := range gnList.Items {
				n := gnList.Items[i]
				n.Finalizers = nil
				_ = k8sClient.Update(ctx, &n)
				_ = k8sClient.Delete(ctx, &n)
			}
		})

		Expect(r.reconcileAutoModeStorageNodes(ctx, cluster)).To(Succeed())
		gnList := listOperatorOwnedStorageNodes(clusterName)
		Expect(gnList.Items).To(HaveLen(2))
		for _, n := range gnList.Items {
			Expect(n.Spec.PublicEndpoint).To(BeNil())
		}

		// Add the PublicEndpoint and reconcile again — existing nodes
		// should pick up the new PublicEndpoint via the drift path.
		fresh := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, fresh)).To(Succeed())
		fresh.Spec.PublicEndpoint = &garagev1beta2.PublicEndpointConfig{
			Type: publicEndpointTypeLoadBalancer,
			LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
				PerNode: true,
			},
		}
		Expect(k8sClient.Update(ctx, fresh)).To(Succeed())

		Expect(r.reconcileAutoModeStorageNodes(ctx, fresh)).To(Succeed())

		gnList = listOperatorOwnedStorageNodes(clusterName)
		Expect(gnList.Items).To(HaveLen(2))
		for _, n := range gnList.Items {
			Expect(n.Spec.PublicEndpoint).NotTo(BeNil(), "drift detection must propagate PublicEndpoint to existing node %s", n.Name)
			Expect(n.Spec.PublicEndpoint.Type).To(Equal(publicEndpointTypeLoadBalancer))
			Expect(n.Spec.PublicEndpoint.LoadBalancer).NotTo(BeNil())
			Expect(n.Spec.PublicEndpoint.LoadBalancer.PerNode).To(BeTrue())
		}
	})
})

var _ = Describe("bucketLegacyDataPVCs", func() {
	makePVC := func(name, size string) corev1.PersistentVolumeClaim {
		return corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: corev1.PersistentVolumeClaimSpec{
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)},
				},
			},
		}
	}
	names := func(bucket []legacyDataPVC) []string {
		out := make([]string, len(bucket))
		for i, p := range bucket {
			out[i] = p.name
		}
		return out
	}

	It("buckets multi-HDD PVCs by ordinal in index order, carrying PVC sizes", func() {
		pvcs := []corev1.PersistentVolumeClaim{
			makePVC("data-1-my-cluster-0", "20Gi"),
			makePVC("data-0-my-cluster-0", "10Gi"),
			makePVC("data-2-my-cluster-1", "30Gi"),
			makePVC("data-0-my-cluster-1", "10Gi"),
			makePVC("data-1-my-cluster-1", "20Gi"),
		}
		got := bucketLegacyDataPVCs(pvcs, "my-cluster")
		Expect(got).To(HaveLen(2))
		Expect(names(got[0])).To(Equal([]string{"data-0-my-cluster-0", "data-1-my-cluster-0"}))
		Expect(names(got[1])).To(Equal([]string{"data-0-my-cluster-1", "data-1-my-cluster-1", "data-2-my-cluster-1"}))
		// Sizes propagate so the GarageNode controller emits TOML
		// `data_dir = [{ path = ..., capacity = ... }]` per #205.
		Expect(got[0][0].size.String()).To(Equal("10Gi"))
		Expect(got[0][1].size.String()).To(Equal("20Gi"))
		Expect(got[1][2].size.String()).To(Equal("30Gi"))
	})

	It("ignores single-HDD PVCs (caller resolves those by direct lookup)", func() {
		pvcs := []corev1.PersistentVolumeClaim{
			makePVC("data-my-cluster-0", "10Gi"),
			makePVC("metadata-my-cluster-0", "1Gi"),
		}
		got := bucketLegacyDataPVCs(pvcs, "my-cluster")
		Expect(got).To(BeEmpty())
	})

	It("ignores unrelated PVCs and name-collisions with non-numeric idx", func() {
		pvcs := []corev1.PersistentVolumeClaim{
			makePVC("data-abc-my-cluster-0", "10Gi"),
			makePVC("other-thing", "10Gi"),
			makePVC("data-0-other-cluster-0", "10Gi"),
		}
		got := bucketLegacyDataPVCs(pvcs, "my-cluster")
		Expect(got).To(BeEmpty())
	})
})

// listOperatorOwnedStorageNodes is a test helper that fetches all
// operator-owned GarageNodes for a cluster.
func listOperatorOwnedStorageNodes(clusterName string) *garagev1beta1.GarageNodeList {
	gnList := &garagev1beta1.GarageNodeList{}
	Expect(k8sClient.List(ctx, gnList,
		client.InNamespace(testNamespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      clusterName,
			labelTier:         tierStorage,
			labelAppManagedBy: managedByOperatorValue,
		}),
	)).To(Succeed())
	return gnList
}

// makeFakeLegacySTS returns a minimal pre-#190 storage StatefulSet for testing
// migration. The pod template is bare-bones because the test never actually
// schedules pods.
func makeFakeLegacySTS(clusterName string, replicas int32) *appsv1.StatefulSet {
	labels := map[string]string{labelCluster: clusterName, labelTier: tierStorage}
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace, Labels: labels},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: clusterName + "-headless",
			Replicas:    ptr.To(replicas),
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: defaultAppName, Image: defaultGarageImage}},
				},
			},
		},
	}
}

// makeFakePVC returns a minimal PVC for testing in testNamespace.
func makeFakePVC(name string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			},
		},
	}
}
