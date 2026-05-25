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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

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
		It("sets migration phase to Completed on a fresh cluster with no legacy STS", func() {
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
			Expect(updated.Status.Migration).NotTo(BeNil())
			Expect(updated.Status.Migration.Phase).To(Equal(garagev1beta2.MigrationPhaseCompleted))
		})

		It("skips migration with a clear message when multi-HDD PVCs are detected", func() {
			clusterNN = types.NamespacedName{Name: uniqueClusterName("auto-multihdd"), Namespace: testNamespace}
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

			// Seed a legacy STS plus a multi-HDD PVC name pattern.
			legacySTS := makeFakeLegacySTS(clusterNN.Name, 2)
			Expect(k8sClient.Create(ctx, legacySTS)).To(Succeed())
			Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-0-%s-0", clusterNN.Name), testNamespace))).To(Succeed())

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			Expect(updated.Status.Migration).NotTo(BeNil())
			Expect(updated.Status.Migration.Phase).To(Equal(garagev1beta2.MigrationPhaseSkipped))
			Expect(updated.Status.Migration.Message).To(ContainSubstring("multi-HDD"))
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
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("metadata-%s-%d", clusterNN.Name, ord), testNamespace))).To(Succeed())
				Expect(k8sClient.Create(ctx, makeFakePVC(fmt.Sprintf("data-%s-%d", clusterNN.Name, ord), testNamespace))).To(Succeed())
			}

			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			// Phase is Completed and 2 GarageNodes exist with existingClaim set.
			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterNN, updated)).To(Succeed())
			Expect(updated.Status.Migration).NotTo(BeNil())
			Expect(updated.Status.Migration.Phase).To(Equal(garagev1beta2.MigrationPhaseCompleted))
			Expect(updated.Status.Migration.MigratedOrdinals).To(ConsistOf(int32(0), int32(1)))

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
			before := cluster.Status.Migration.DeepCopy()
			Expect(reconciler.migrateLegacyStorageSTSIfNeeded(ctx, cluster)).To(Succeed())

			Expect(k8sClient.Get(ctx, clusterNN, cluster)).To(Succeed())
			Expect(cluster.Status.Migration.Phase).To(Equal(before.Phase))
		})
	})
})

var _ = Describe("isMultiHDDDataPVC", func() {
	DescribeTable("classifies PVC names",
		func(pvcName, clusterName string, want bool) {
			Expect(isMultiHDDDataPVC(pvcName, clusterName)).To(Equal(want))
		},
		Entry("single-HDD data PVC", "data-my-cluster-0", "my-cluster", false),
		Entry("multi-HDD data PVC", "data-0-my-cluster-0", "my-cluster", true),
		Entry("multi-HDD higher index", "data-12-my-cluster-3", "my-cluster", true),
		Entry("metadata PVC", "metadata-my-cluster-0", "my-cluster", false),
		Entry("unrelated PVC", "other-thing", "my-cluster", false),
		Entry("name collision with non-numeric prefix", "data-abc-my-cluster-0", "my-cluster", false),
	)
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

// makeFakePVC returns a minimal PVC for testing.
func makeFakePVC(name, namespace string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			},
		},
	}
}
