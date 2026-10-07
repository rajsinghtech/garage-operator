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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	daemonSetTestGarageImage              = "garage:test"
	daemonSetTestNodeLabel                = "garage.storage/pool"
	daemonSetTestNodeLocalPoolName        = "local-500"
	daemonSetTestArchiveNodeLocalPoolName = "archive"
	daemonSetTestFastDataPath             = "/data/fast"
	daemonSetTestDataHostPath             = "/var/lib/garage/data"
	daemonSetTestFastHostPath             = "/mnt/fast/garage"
	daemonSetTestPodIP                    = "10.0.0.8"
	daemonSetTestRPCAddress               = "{nodeName}.storage.example.net:3901"
	testGarageClusterKind                 = kindGarageCluster
)

var _ = Describe("GarageCluster additive node-local pools", func() {
	var (
		reconciler      *GarageClusterReconciler
		layoutHistory   *garage.LayoutHistoryResponse
		committedLayout *garage.ClusterLayout
	)

	BeforeEach(func() {
		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 1,
			Versions: []garage.LayoutVersion{{
				Version:      1,
				Status:       garage.LayoutVersionStatusCurrent,
				StorageNodes: 1,
			}},
		}
		committedLayout = &garage.ClusterLayout{}
		reconciler = &GarageClusterReconciler{
			Client:                     k8sClient,
			APIReader:                  k8sClient,
			Scheme:                     k8sClient.Scheme(),
			ClusterScoped:              true,
			NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
			layoutHistoryGetter: func(_ context.Context, _ *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
				return layoutHistory, nil
			},
			nodeLocalPoolLayoutGetter: func(_ context.Context, _ *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return committedLayout, nil
			},
		}
	})

	makePoolClusterWithPaths := func(prefix, metadataHostPath, dataHostPath string) *garagev1beta2.GarageCluster {
		capacity := resource.MustParse("500Gi")
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      uniqueClusterName(prefix),
				Namespace: testNamespace,
			},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Zone:         testZone,
				Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
				Admin: &garagev1beta2.AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "garage-admin-token"},
				}},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 3,
					Metadata: &garagev1beta2.VolumeConfig{},
					Data:     &garagev1beta2.VolumeConfig{Type: garagev1beta2.VolumeTypeEmptyDir},
					NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
						Name:     daemonSetTestNodeLocalPoolName,
						Selector: metav1.LabelSelector{MatchLabels: map[string]string{daemonSetTestNodeLabel: daemonSetTestNodeLocalPoolName}},
						Capacity: &capacity,
						Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: metadataHostPath},
						Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: dataHostPath},
						Network: &garagev1beta2.NodeLocalPoolNetworkSpec{
							RPCPublicAddrTemplate: daemonSetTestRPCAddress,
						},
					}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		DeferCleanup(func() {
			nodes := &garagev1beta1.GarageNodeList{}
			_ = k8sClient.List(ctx, nodes, client.InNamespace(testNamespace))
			for i := range nodes.Items {
				node := &nodes.Items[i]
				if node.Spec.ClusterRef.Name != cluster.Name {
					continue
				}
				node.Finalizers = nil
				_ = k8sClient.Update(ctx, node)
				_ = k8sClient.Delete(ctx, node)
			}
			fresh := &garagev1beta2.GarageCluster{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(ctx, fresh)
				_ = k8sClient.Delete(ctx, fresh)
			}
		})
		return cluster
	}
	makePoolCluster := func(prefix string) *garagev1beta2.GarageCluster {
		return makePoolClusterWithPaths(prefix, "/var/lib/garage/meta", daemonSetTestDataHostPath)
	}

	makeKubernetesNode := func(cluster *garagev1beta2.GarageCluster, suffix, poolValue string) *corev1.Node {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: uniqueClusterName(cluster.Name + "-" + suffix),
			Labels: map[string]string{
				daemonSetTestNodeLabel: poolValue,
			},
		}}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() {
			fresh := &corev1.Node{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(ctx, fresh)
				_ = k8sClient.Delete(ctx, fresh)
			}
		})
		return node
	}

	makePoolPod := func(cluster *garagev1beta2.GarageCluster, nodeName, suffix string) *corev1.Pod {
		nodeLocalPoolName := cluster.Spec.Storage.NodeLocalPools[0].Name
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		labels := make(map[string]string, len(daemonSet.Spec.Template.Labels))
		for key, value := range daemonSet.Spec.Template.Labels {
			labels[key] = value
		}
		annotations := make(map[string]string, len(daemonSet.Spec.Template.Annotations))
		for key, value := range daemonSet.Spec.Template.Annotations {
			annotations[key] = value
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        uniqueClusterName(cluster.Name + "-" + suffix),
				Namespace:   testNamespace,
				Labels:      labels,
				Annotations: annotations,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       daemonSetKind,
					Name:       storageDaemonSetName(cluster, nodeLocalPoolName),
					UID:        daemonSet.UID,
					Controller: ptr.To(true),
				}},
			},
			Spec: corev1.PodSpec{
				NodeName:   nodeName,
				Containers: []corev1.Container{{Name: fmGarageContainer, Image: "garage:test"}},
			},
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		pod.Status = corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		}
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
		return pod
	}

	reconcilePools := func(cluster *garagev1beta2.GarageCluster) error {
		hashes := map[string]string{}
		for i := range cluster.Spec.Storage.NodeLocalPools {
			hashes[cluster.Spec.Storage.NodeLocalPools[i].Name] = "test-config-hash"
		}
		return reconciler.reconcileNodeLocalPools(ctx, cluster, hashes)
	}
	nodeLocalPoolActivationValue := func(cluster *garagev1beta2.GarageCluster) string {
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		value := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
		Expect(nodeLocalPoolActivationValueIsActive(value)).To(BeTrue())
		return value
	}

	It("creates an independently selected, pool-labelled HostPath DaemonSet", func() {
		cluster := makePoolCluster("pool-ds")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		pool.PodTemplate = &garagev1beta2.NodeLocalPoolPodTemplate{PodLabels: map[string]string{
			labelAppName: "pool-hostile", labelCluster: "wrong-pool-cluster", labelTier: tierGateway,
			labelNodeLocalPool: "wrong-pool", labelStorageGroup: storageGroupDefault,
			labelScaleTarget: scaleTargetDisabled, "legacy invalid pool key": "pool-legacy",
			"example.com/media": "nvme",
		}}
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)

		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(ctx, cluster, pool, activationLabel, "hash")).To(Succeed())
		ds := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, ds)).To(Succeed())
		Expect(metav1.IsControlledBy(ds, cluster)).To(BeTrue())
		Expect(ds.Labels).To(HaveKeyWithValue(labelNodeLocalPool, pool.Name))
		Expect(ds.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelNodeLocalPool, pool.Name))
		for key, value := range ds.Spec.Selector.MatchLabels {
			Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue(labelCluster, cluster.Name))
		Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue(labelTier, tierStorage))
		Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue(labelStorageGroup, storageGroupNodeLocal))
		Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue(labelNodeLocalPool, pool.Name))
		Expect(ds.Spec.Template.Labels).NotTo(HaveKey(labelScaleTarget))
		Expect(ds.Spec.Template.Labels).NotTo(HaveKey("legacy invalid pool key"))
		Expect(ds.Spec.Template.Labels).To(HaveKeyWithValue("example.com/media", "nvme"))
		activationValue := nodeLocalPoolActivationValueForDaemonSet(ds)
		Expect(nodeLocalPoolActivationValueIsActive(activationValue)).To(BeTrue())
		Expect(ds.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{activationLabel: activationValue}))
		Expect(ds.Spec.Template.Spec.SchedulingGates).To(ContainElement(corev1.PodSchedulingGate{
			Name: nodeLocalPoolSchedulingGateName,
		}))
		Expect(activationValue).To(Equal(nodeLocalPoolActivationValueForWorkloadUID(ds.UID)))
		Expect(ds.Spec.Template.Spec.NodeSelector).NotTo(HaveKey(daemonSetTestNodeLabel),
			"the raw desired selector would bypass drain-safe membership")
		Expect(ds.Spec.UpdateStrategy.Type).To(Equal(appsv1.OnDeleteDaemonSetStrategyType))
		Expect(ds.Spec.Template.Annotations).To(HaveKeyWithValue(annotationConfigHash, "hash"))
		Expect(ds.Annotations).To(HaveKey(annotationStorageDiskLayout))
		configMapName := ""
		for i := range ds.Spec.Template.Spec.Volumes {
			volume := &ds.Spec.Template.Spec.Volumes[i]
			if volume.Name == configVolumeName && volume.ConfigMap != nil {
				configMapName = volume.ConfigMap.Name
			}
		}
		Expect(configMapName).To(Equal(storageDaemonSetConfigResourceName(cluster, pool, "hash")))
		recordedLayout, err := storageDiskLayoutFromDaemonSet(ds)
		Expect(err).NotTo(HaveOccurred())
		Expect(recordedLayout.MetadataHostPath).To(Equal("/var/lib/garage/meta"))
		Expect(recordedLayout.DataPaths).To(Equal([]nodeLocalPoolDiskPath{{
			Path:         dataPath,
			HostPath:     daemonSetTestDataHostPath,
			HostPathType: corev1.HostPathDirectory,
		}}))

		volumes := map[string]*corev1.HostPathVolumeSource{}
		for i := range ds.Spec.Template.Spec.Volumes {
			volume := &ds.Spec.Template.Spec.Volumes[i]
			volumes[volume.Name] = volume.HostPath
		}
		Expect(volumes[metadataVolName].Path).To(Equal("/var/lib/garage/meta"))
		Expect(volumes[dataVolName].Path).To(Equal(daemonSetTestDataHostPath))
		metadataMarker := volumes[storageVolumeMarkerNamePrefix+metadataVolName]
		dataMarker := volumes[storageVolumeMarkerNamePrefix+dataVolName]
		Expect(metadataMarker).NotTo(BeNil())
		Expect(metadataMarker.Path).To(Equal("/var/lib/garage/meta/" + storageVolumeMarkerFile))
		Expect(metadataMarker.Type).NotTo(BeNil())
		Expect(*metadataMarker.Type).To(Equal(corev1.HostPathFile))
		Expect(dataMarker).NotTo(BeNil())
		Expect(dataMarker.Path).To(Equal(daemonSetTestDataHostPath + "/" + storageVolumeMarkerFile))
		Expect(dataMarker.Type).NotTo(BeNil())
		Expect(*dataMarker.Type).To(Equal(corev1.HostPathFile))

		mounts := map[string]corev1.VolumeMount{}
		for i := range ds.Spec.Template.Spec.Containers[0].VolumeMounts {
			mount := ds.Spec.Template.Spec.Containers[0].VolumeMounts[i]
			mounts[mount.Name] = mount
		}
		Expect(mounts[storageVolumeMarkerNamePrefix+metadataVolName].ReadOnly).To(BeTrue())
		Expect(mounts[storageVolumeMarkerNamePrefix+dataVolName].ReadOnly).To(BeTrue())
	})

	It("checks every Directory marker, skips DirectoryOrCreate, and excludes markers from Garage's disk layout", func() {
		cluster := makePoolCluster("pool-marker-contract")
		pool := cluster.Spec.Storage.NodeLocalPools[0]
		pool.Metadata.HostPathType = corev1.HostPathDirectory
		pool.Data = nil
		pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{
				Path: daemonSetTestFastDataPath, HostPath: daemonSetTestFastHostPath,
				HostPathType: corev1.HostPathDirectory, Capacity: quantity("250Gi"),
			},
			{
				Path: "/data/archive", HostPath: "/mnt/archive/garage",
				HostPathType: corev1.HostPathDirectory, ReadOnly: true,
			},
			{
				Path: "/data/dev", HostPath: "/tmp/garage-dev",
				HostPathType: corev1.HostPathDirectoryOrCreate, Capacity: quantity("250Gi"),
			},
		}
		volumes, mounts := buildStorageDaemonSetVolumesAndMounts(cluster, &pool, "hash")
		byName := map[string]corev1.Volume{}
		for i := range volumes {
			byName[volumes[i].Name] = volumes[i]
		}
		// dataPaths are a map-list in the API, so runtime volume numbering follows
		// canonical path order: archive, dev, fast. Only the Directory entries get
		// marker mounts; DirectoryOrCreate remains the explicit escape hatch.
		for _, volumeName := range []string{metadataVolName, dataVolName + "-0", dataVolName + "-2"} {
			marker, found := byName[storageVolumeMarkerNamePrefix+volumeName]
			Expect(found).To(BeTrue(), "Directory volume %s must have a File marker", volumeName)
			Expect(marker.HostPath).NotTo(BeNil())
			Expect(marker.HostPath.Type).NotTo(BeNil())
			Expect(*marker.HostPath.Type).To(Equal(corev1.HostPathFile))
		}
		Expect(byName).NotTo(HaveKey(storageVolumeMarkerNamePrefix+dataVolName+"-1"),
			"DirectoryOrCreate is the explicit marker-free escape")

		podSpec := &corev1.PodSpec{
			Volumes:    volumes,
			Containers: []corev1.Container{{Name: defaultAppName, VolumeMounts: mounts}},
		}
		layout, err := extractStorageDiskLayoutFromPodSpec(podSpec)
		Expect(err).NotTo(HaveOccurred())
		Expect(layout.MetadataHostPath).To(Equal(pool.Metadata.HostPath))
		Expect(layout.DataPaths).To(HaveLen(3), "marker mounts must not become Garage data_dir entries")
	})

	It("waits for old pool pods before recreating an out-of-band deleted DaemonSet", func() {
		cluster := makePoolCluster("pool-ds-recreate")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)

		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "hash",
		)).To(Succeed())
		daemonSet := &appsv1.DaemonSet{}
		key := types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}
		Expect(k8sClient.Get(ctx, key, daemonSet)).To(Succeed())
		oldActivationValue := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		k8sNode.Labels[activationLabel] = oldActivationValue
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())
		oldPod := makePoolPod(cluster, k8sNode.Name, "old-controller-pod")
		Expect(k8sClient.Delete(ctx, daemonSet)).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, key, &appsv1.DaemonSet{}))
		}).Should(BeTrue())

		err := reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "hash",
		)
		Expect(err).To(MatchError(ContainSubstring("previous pool pod(s) still exist")))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(activationLabel, nodeLocalPoolActivationQuarantineValue),
			"the old workload token must be fenced before checking for a late Pod")
		Expect(errors.IsNotFound(k8sClient.Get(ctx, key, &appsv1.DaemonSet{}))).To(BeTrue(),
			"the replacement controller must not start while the old Garage process exists")

		Expect(k8sClient.Delete(ctx, oldPod, client.GracePeriodSeconds(0))).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldPod), &corev1.Pod{}))
		}).Should(BeTrue())
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "hash",
		)).To(Succeed())
		replacement := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, key, replacement)).To(Succeed())
		replacementActivationValue := nodeLocalPoolActivationValueForDaemonSet(replacement)
		Expect(nodeLocalPoolActivationValueIsActive(replacementActivationValue)).To(BeTrue())
		Expect(replacementActivationValue).NotTo(Equal(oldActivationValue))
		Expect(replacementActivationValue).To(Equal(nodeLocalPoolActivationValueForWorkloadUID(replacement.UID)))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(activationLabel, nodeLocalPoolActivationQuarantineValue),
			"ordinary membership reconciliation must explicitly authorize the replacement token")
	})

	It("fails closed on disk remaps and in-place path removal", func() {
		cluster := makePoolCluster("pool-disk-transition")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "hash-1",
		)).To(Succeed())

		By("refusing a metadata identity remap even when admission is bypassed")
		metadataRemap := cluster.DeepCopy().Spec.Storage.NodeLocalPools[0]
		metadataRemap.Metadata.HostPath = "/var/lib/garage/other-meta"
		err := reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &metadataRemap, activationLabel, "hash-2",
		)
		Expect(err).To(MatchError(ContainSubstring("must fully drain")))

		By("refusing an in-place data-directory remap")
		dataRemap := cluster.DeepCopy().Spec.Storage.NodeLocalPools[0]
		dataRemap.Data.HostPath = "/var/lib/garage/other-data"
		err = reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &dataRemap, activationLabel, "hash-2",
		)
		Expect(err).To(MatchError(ContainSubstring("cannot remap data path")))

		By("refusing to loosen a fail-closed HostPath type")
		directoryOnly := cluster.DeepCopy().Spec.Storage.NodeLocalPools[0]
		directoryOnly.Metadata.HostPathType = corev1.HostPathDirectory
		directoryOnly.Data.HostPathType = corev1.HostPathDirectory
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &directoryOnly, activationLabel, "hash-2",
		)).To(Succeed())
		loosened := directoryOnly
		loosened.Metadata = directoryOnly.Metadata.DeepCopy()
		loosened.Metadata.HostPathType = corev1.HostPathDirectoryOrCreate
		err = reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &loosened, activationLabel, "hash-3",
		)
		Expect(err).To(MatchError(ContainSubstring("cannot loosen metadata hostPathType")))
		dataLoosened := directoryOnly
		dataLoosened.Data = directoryOnly.Data.DeepCopy()
		dataLoosened.Data.HostPathType = corev1.HostPathDirectoryOrCreate
		err = reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &dataLoosened, activationLabel, "hash-3",
		)
		Expect(err).To(MatchError(ContainSubstring("cannot loosen data path")))

		By("refusing to remove the old writable path in one rollout")
		directRemoval := cluster.DeepCopy().Spec.Storage.NodeLocalPools[0]
		directRemoval.Metadata.HostPathType = corev1.HostPathDirectory
		directRemoval.Data.HostPathType = corev1.HostPathDirectory
		directRemoval.Data = nil
		directRemoval.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{{
			Path:         daemonSetTestFastDataPath,
			HostPath:     daemonSetTestFastHostPath,
			HostPathType: corev1.HostPathDirectory,
			Capacity:     quantity("500Gi"),
		}}
		err = reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &directRemoval, activationLabel, "hash-2",
		)
		Expect(err).To(MatchError(ContainSubstring("cannot remove data path")))

		By("retaining the old mapping as readOnly while a replacement is added")
		staged := cluster.DeepCopy().Spec.Storage.NodeLocalPools[0]
		staged.Metadata.HostPathType = corev1.HostPathDirectory
		staged.Data = nil
		staged.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{
				Path:         dataPath,
				HostPath:     daemonSetTestDataHostPath,
				HostPathType: corev1.HostPathDirectory,
				ReadOnly:     true,
			},
			{
				Path:         daemonSetTestFastDataPath,
				HostPath:     daemonSetTestFastHostPath,
				HostPathType: corev1.HostPathDirectory,
				Capacity:     quantity("500Gi"),
			},
		}
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &staged, activationLabel, "hash-2",
		)).To(Succeed())

		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		stagedLayout, err := storageDiskLayoutFromDaemonSet(daemonSet)
		Expect(err).NotTo(HaveOccurred())
		Expect(stagedLayout.DataPaths).To(ContainElement(nodeLocalPoolDiskPath{
			Path:         dataPath,
			HostPath:     daemonSetTestDataHostPath,
			HostPathType: corev1.HostPathDirectory,
			ReadOnly:     true,
		}))

		By("refusing to detach even a recorded readOnly path without filesystem proof")
		final := staged
		final.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{{
			Path:         daemonSetTestFastDataPath,
			HostPath:     daemonSetTestFastHostPath,
			HostPathType: corev1.HostPathDirectory,
			Capacity:     quantity("500Gi"),
		}}
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, &final, activationLabel, "hash-3",
		)).To(MatchError(ContainSubstring("do not prove the HostPath is empty")))
	})

	It("guards the live ConfigMap when a stale pool is rapidly re-added", func() {
		cluster := makePoolCluster("pool-config-guard")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "hash-1",
		)).To(Succeed())

		layout := storageDiskLayoutForPool(pool)
		record, err := marshalStorageDiskLayout(layout)
		Expect(err).NotTo(HaveOccurred())
		oldBody := "old garage config"
		configMapName := storageDaemonSetConfigResourceName(cluster, pool, garageConfigHash(oldBody))
		_, err = reconciler.writeConfigMapWithLabels(
			ctx,
			cluster,
			configMapName,
			oldBody,
			map[string]string{labelNodeLocalPool: pool.Name},
			map[string]string{annotationStorageDiskLayout: record},
		)
		Expect(err).NotTo(HaveOccurred())

		// Model an out-of-band DaemonSet deletion between pool removal and a
		// same-name re-add. The retained ConfigMap record must still prevent a
		// new metadata identity from receiving rewritten garage.toml.
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		Expect(k8sClient.Delete(ctx, daemonSet)).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), &appsv1.DaemonSet{}))
		}).Should(BeTrue())

		remapped := pool.DeepCopy()
		remapped.Metadata.HostPath = "/var/lib/garage/replacement-meta"
		err = reconciler.validateNodeLocalPoolDiskLayoutBeforeConfigUpdate(
			ctx,
			cluster,
			pool.Name,
			storageDiskLayoutForPool(remapped),
		)
		Expect(err).To(MatchError(ContainSubstring("must fully drain")))

		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: configMapName, Namespace: testNamespace,
		}, configMap)).To(Succeed())
		Expect(configMap.Data).To(HaveKeyWithValue(configFileName, "old garage config"))
		Expect(configMap.Annotations).To(HaveKeyWithValue(annotationStorageDiskLayout, record))
	})

	It("keeps content-addressed config revisions until a ready rollout releases old pods", func() {
		cluster := makePoolCluster("pool-config-revisions")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
		layoutRecord, err := marshalStorageDiskLayout(storageDiskLayoutForPool(pool))
		Expect(err).NotTo(HaveOccurred())

		writeRevision := func(body string) (string, string) {
			hash := garageConfigHash(body)
			name := storageDaemonSetConfigResourceName(cluster, pool, hash)
			writtenHash, writeErr := reconciler.writeConfigMapWithLabels(
				ctx,
				cluster,
				name,
				body,
				map[string]string{labelNodeLocalPool: pool.Name},
				map[string]string{annotationStorageDiskLayout: layoutRecord},
			)
			Expect(writeErr).NotTo(HaveOccurred())
			Expect(writtenHash).To(Equal(hash))
			return name, hash
		}

		oldName, oldHash := writeRevision("old garage config")
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx,
			cluster,
			pool,
			activationLabel,
			oldHash,
		)).To(Succeed())
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())

		podLabels := reconciler.labelsForTier(cluster, tierStorage)
		podLabels[labelNodeLocalPool] = pool.Name
		oldPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      uniqueClusterName(cluster.Name + "-old-config"),
				Namespace: testNamespace,
				Labels:    podLabels,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       daemonSetKind,
					Name:       daemonSet.Name,
					UID:        daemonSet.UID,
					Controller: ptr.To(true),
				}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: fmGarageContainer, Image: daemonSetTestGarageImage}},
				Volumes: []corev1.Volume{{
					Name: configVolumeName,
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: oldName},
					}},
				}},
			},
		}
		Expect(k8sClient.Create(ctx, oldPod)).To(Succeed())

		newName, newHash := writeRevision("new garage config")
		Expect(newName).NotTo(Equal(oldName))
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx,
			cluster,
			pool,
			activationLabel,
			newHash,
		)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), daemonSet)).To(Succeed())
		templateConfigMapName := ""
		for i := range daemonSet.Spec.Template.Spec.Volumes {
			volume := &daemonSet.Spec.Template.Spec.Volumes[i]
			if volume.Name == configVolumeName && volume.ConfigMap != nil {
				templateConfigMapName = volume.ConfigMap.Name
			}
		}
		Expect(templateConfigMapName).To(Equal(newName))
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: oldName, Namespace: testNamespace,
		}, &corev1.ConfigMap{})).To(Succeed())
		newConfigMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: newName, Namespace: testNamespace,
		}, newConfigMap)).To(Succeed())
		Expect(newConfigMap.Immutable).To(HaveValue(BeTrue()))

		daemonSet.Status = appsv1.DaemonSetStatus{
			CurrentNumberScheduled: 1,
			DesiredNumberScheduled: 1,
			NumberReady:            1,
			UpdatedNumberScheduled: 1,
			NumberAvailable:        1,
			ObservedGeneration:     daemonSet.Generation,
		}
		Expect(k8sClient.Status().Update(ctx, daemonSet)).To(Succeed())
		Expect(reconciler.cleanupObsoleteNodeLocalPoolConfigMaps(
			ctx,
			cluster,
			pool.Name,
			newName,
		)).To(Succeed())
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: oldName, Namespace: testNamespace,
		}, &corev1.ConfigMap{})).To(Succeed(), "a live old pod must retain its exact config revision")

		Expect(k8sClient.Delete(ctx, oldPod, client.GracePeriodSeconds(0))).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(
				ctx,
				client.ObjectKeyFromObject(oldPod),
				&corev1.Pod{},
			))
		}).Should(BeTrue())
		Expect(reconciler.cleanupObsoleteNodeLocalPoolConfigMaps(
			ctx,
			cluster,
			pool.Name,
			newName,
		)).To(Succeed())
		Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{
			Name: oldName, Namespace: testNamespace,
		}, &corev1.ConfigMap{}))).To(BeTrue())
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: newName, Namespace: testNamespace,
		}, &corev1.ConfigMap{})).To(Succeed())
	})

	It("never treats ConfigMap revision cleanup as proof that a data directory is empty", func() {
		cluster := makePoolCluster("pool-config-phase-cleanup")
		basePool := &cluster.Spec.Storage.NodeLocalPools[0]
		activationLabel := nodeLocalPoolActivationLabel(cluster, basePool.Name)

		writable := basePool.DeepCopy()
		writable.Data = nil
		writable.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{
				Path: daemonSetTestFastDataPath, HostPath: daemonSetTestFastHostPath,
				Capacity: quantity("250Gi"),
			},
			{
				Path: testLegacyDataPath, HostPath: daemonSetTestDataHostPath,
				Capacity: quantity("250Gi"),
			},
		}
		readOnly := writable.DeepCopy()
		readOnly.DataPaths[0].ReadOnly = true
		readOnly.DataPaths[0].Capacity = nil
		readOnly.DataPaths[1].Capacity = quantity("500Gi")
		final := readOnly.DeepCopy()
		final.DataPaths = append([]garagev1beta2.NodeLocalPoolDataPath(nil), readOnly.DataPaths[1])

		writeRevision := func(pool *garagev1beta2.NodeLocalPoolSpec, body string) (string, string) {
			record, recordErr := marshalStorageDiskLayout(storageDiskLayoutForPool(pool))
			Expect(recordErr).NotTo(HaveOccurred())
			hash := garageConfigHash(body)
			name := storageDaemonSetConfigResourceName(cluster, pool, hash)
			_, writeErr := reconciler.writeConfigMapWithLabels(
				ctx,
				cluster,
				name,
				body,
				map[string]string{labelNodeLocalPool: pool.Name},
				map[string]string{annotationStorageDiskLayout: record},
			)
			Expect(writeErr).NotTo(HaveOccurred())
			return name, hash
		}

		writableName, writableHash := writeRevision(writable, "writable garage config")
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx,
			cluster,
			writable,
			activationLabel,
			writableHash,
		)).To(Succeed())
		readOnlyName, readOnlyHash := writeRevision(readOnly, "read-only garage config")
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx,
			cluster,
			readOnly,
			activationLabel,
			readOnlyHash,
		)).To(Succeed())

		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, basePool.Name), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		daemonSet.Status.ObservedGeneration = daemonSet.Generation
		Expect(k8sClient.Status().Update(ctx, daemonSet)).To(Succeed())

		err := reconciler.validateNodeLocalPoolDiskLayoutBeforeConfigUpdate(
			ctx,
			cluster,
			basePool.Name,
			storageDiskLayoutForPool(final),
		)
		Expect(err).To(MatchError(ContainSubstring("cannot remove data path")))

		Expect(reconciler.cleanupObsoleteNodeLocalPoolConfigMapsForDeployedDaemonSet(
			ctx,
			cluster,
			basePool.Name,
		)).To(Succeed())
		Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{
			Name: writableName, Namespace: testNamespace,
		}, &corev1.ConfigMap{}))).To(BeTrue())
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: readOnlyName, Namespace: testNamespace,
		}, &corev1.ConfigMap{})).To(Succeed())
		Expect(reconciler.validateNodeLocalPoolDiskLayoutBeforeConfigUpdate(
			ctx,
			cluster,
			basePool.Name,
			storageDiskLayoutForPool(final),
		)).To(MatchError(ContainSubstring("do not prove the HostPath is empty")))
	})

	It("keys activation labels by UID while keeping retained-disk identity records stable", func() {
		first := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
			Name: "same", Namespace: testNamespace, UID: types.UID("first"),
		}}
		second := first.DeepCopy()
		second.UID = types.UID("second")
		Expect(nodeLocalPoolActivationLabel(first, daemonSetTestNodeLocalPoolName)).
			NotTo(Equal(nodeLocalPoolActivationLabel(second, daemonSetTestNodeLocalPoolName)))
		Expect(nodeLocalPoolRecoveryNodeIDAnnotation(first, daemonSetTestNodeLocalPoolName)).
			To(Equal(nodeLocalPoolRecoveryNodeIDAnnotation(second, daemonSetTestNodeLocalPoolName)))
	})

	It("removes both scheduling and retained-disk identity records after clean finalization", func() {
		cluster := makePoolCluster("pool-finalize-records")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		recoveryAnnotation := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, daemonSetTestNodeLocalPoolName)
		if k8sNode.Annotations == nil {
			k8sNode.Annotations = map[string]string{}
		}
		k8sNode.Annotations[recoveryAnnotation] = strings.Repeat("a", 64)
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())

		err := reconciler.deleteStorageDaemonSet(ctx, cluster)
		Expect(err).To(MatchError(ContainSubstring("activation-label fences")))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)))
		Expect(k8sNode.Annotations).To(HaveKey(recoveryAnnotation),
			"identity records must outlive the scheduling-label fence")

		err = reconciler.deleteStorageDaemonSet(ctx, cluster)
		Expect(err).To(MatchError(ContainSubstring("DaemonSets and their Pods")))
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{
				Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
			}, &appsv1.DaemonSet{}))
		}).Should(BeTrue())
		Eventually(func() error {
			return reconciler.deleteStorageDaemonSet(ctx, cluster)
		}).Should(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Annotations).NotTo(HaveKey(recoveryAnnotation))
	})

	It("renders every multi-disk pool HostPath and mount", func() {
		cluster := makePoolCluster("pool-multi")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		pool.Data = nil
		pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{Path: daemonSetTestFastDataPath, HostPath: daemonSetTestFastHostPath, Capacity: quantity("300Gi")},
			{Path: testLegacyDataPath, HostPath: "/mnt/legacy/garage", ReadOnly: true},
		}
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, nodeLocalPoolActivationLabel(cluster, pool.Name), "hash",
		)).To(Succeed())

		ds := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, ds)).To(Succeed())
		volumes := map[string]*corev1.HostPathVolumeSource{}
		mounts := map[string]corev1.VolumeMount{}
		for i := range ds.Spec.Template.Spec.Volumes {
			volume := &ds.Spec.Template.Spec.Volumes[i]
			volumes[volume.Name] = volume.HostPath
		}
		for _, mount := range ds.Spec.Template.Spec.Containers[0].VolumeMounts {
			mounts[mount.Name] = mount
		}
		Expect(volumes[nodeMultiHDDDataVolName(0)].Path).To(Equal(daemonSetTestFastHostPath))
		Expect(volumes[nodeMultiHDDDataVolName(1)].Path).To(Equal("/mnt/legacy/garage"))
		Expect(mounts[nodeMultiHDDDataVolName(0)].MountPath).To(Equal(daemonSetTestFastDataPath))
		Expect(mounts[nodeMultiHDDDataVolName(1)].MountPath).To(Equal(testLegacyDataPath))
		Expect(mounts[nodeMultiHDDDataVolName(1)].ReadOnly).To(BeFalse(),
			"Garage read_only controls placement; its marker file still needs a writable mount")
	})

	It("fails closed when no DaemonSet pod IP matches rpcPublicAddrSubnet", func() {
		cluster := makePoolCluster("pool-rpc-subnet")
		cluster.Spec.Network.RPCPublicAddrSubnet = "fd00:3901::/64"
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pool-pod", Namespace: testNamespace},
			Status: corev1.PodStatus{
				PodIP: daemonSetTestPodIP,
				PodIPs: []corev1.PodIP{
					{IP: daemonSetTestPodIP},
					{IP: "fd00:3901::8"},
				},
			},
		}

		address, err := daemonSetPodRPCIP(cluster, pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(address).To(Equal("fd00:3901::8"))

		pod.Status.PodIPs = []corev1.PodIP{{IP: daemonSetTestPodIP}}
		address, err = daemonSetPodRPCIP(cluster, pod)
		Expect(address).To(BeEmpty())
		Expect(err).To(MatchError(ContainSubstring("none match network.rpcPublicAddrSubnet")))
	})

	It("validates rpcPublicAddrTemplate after substituting the real Kubernetes Node name", func() {
		address, err := renderDaemonSetNodeRPCAddress(
			"{nodeName}.storage.example.net:3901",
			"worker-a",
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(address).To(Equal("worker-a.storage.example.net:3901"))

		longNodeName := strings.Join([]string{
			strings.Repeat("a", 63),
			strings.Repeat("b", 63),
			strings.Repeat("c", 63),
			strings.Repeat("d", 61),
		}, ".")
		Expect(longNodeName).To(HaveLen(253))
		_, err = renderDaemonSetNodeRPCAddress(
			"{nodeName}.storage.example.net:3901",
			longNodeName,
		)
		Expect(err).To(MatchError(ContainSubstring("renders invalid host")))
	})

	It("admits writable dataPaths when the optional readOnly field is omitted", func() {
		cluster := makePoolCluster("pool-cel-default")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		pool.Data = nil
		pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{Path: daemonSetTestFastDataPath, HostPath: daemonSetTestFastHostPath, Capacity: quantity("300Gi")},
			{Path: testLegacyDataPath, HostPath: "/mnt/legacy/garage", ReadOnly: true},
		}

		// This deliberately crosses the API server so the generated CRD's CEL
		// rule is evaluated. A direct self.readOnly reference used to reject
		// omitted (default-false) fields on newer Kubernetes API servers.
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
	})

	It("activates selected Nodes and materializes explicitly owned GarageNodes only after a pod schedules", func() {
		cluster := makePoolCluster("pool-node")
		cluster.Spec.DefaultNodeTags = []string{"rack:a"}
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		activationValue := nodeLocalPoolActivationValue(cluster)
		freshNode := &corev1.Node{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), freshNode)).To(Succeed())
		Expect(freshNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		garageNodes := &garagev1beta1.GarageNodeList{}
		Expect(k8sClient.List(ctx, garageNodes, client.InNamespace(testNamespace),
			client.MatchingLabels(map[string]string{labelCluster: cluster.Name}))).To(Succeed())
		Expect(garageNodes.Items).To(BeEmpty(), "an unscheduled node must not become a phantom Garage role")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		poolCondition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(poolCondition).NotTo(BeNil())
		Expect(poolCondition.Status).To(Equal(metav1.ConditionFalse))
		Expect(poolCondition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForMembers))

		pod := makePoolPod(cluster, k8sNode.Name, "pod")
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), pod)).To(Succeed())
		Expect(pod.Labels).To(HaveKeyWithValue(labelKubernetesNode, k8sNode.Name))
		Expect(pod.Annotations).To(HaveKeyWithValue(annotationKubernetesNode, k8sNode.Name))

		Expect(k8sClient.List(ctx, garageNodes, client.InNamespace(testNamespace),
			client.MatchingLabels(map[string]string{labelCluster: cluster.Name}))).To(Succeed())
		Expect(garageNodes.Items).To(HaveLen(1))
		garageNode := garageNodes.Items[0]
		Expect(garageNode.Spec.Backing).To(Equal(garagev1beta1.NodeBackingNodeLocalPool))
		Expect(garageNode.Spec.NodeLocalPoolName).To(Equal(daemonSetTestNodeLocalPoolName))
		Expect(garageNode.Spec.KubernetesNodeName).To(Equal(k8sNode.Name))
		Expect(garageNode.Labels).To(HaveKeyWithValue(labelNodeLocalPool, daemonSetTestNodeLocalPoolName))
		Expect(garageNode.Spec.Tags).To(Equal([]string{"rack:a"}),
			"generated specs must contain only user tags; ownership tags come from typed fields")
		Expect(garageNode.Spec.Network.RPCPublicAddr).To(Equal(k8sNode.Name + ".storage.example.net:3901"))
	})

	It("admits post-bootstrap DaemonSet identities one settled member at a time", func() {
		cluster := makePoolCluster("pool-serialized-add")
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		// A settled Manual/SMB-style member means this is an additive pool, not
		// the no-Admin-API bootstrap exception.
		manual := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name + "-manual",
				Namespace: testNamespace,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				Zone:       testZone,
				Capacity:   quantity("1Ti"),
			},
		}
		Expect(k8sClient.Create(ctx, manual)).To(Succeed())
		manual.Status.NodeID = strings.Repeat("d", 64)
		manual.Status.Connected = true
		manual.Status.InLayout = true
		manual.Status.ObservedGeneration = manual.Generation
		Expect(k8sClient.Status().Update(ctx, manual)).To(Succeed())

		first := makeKubernetesNode(cluster, "first", daemonSetTestNodeLocalPoolName)
		second := makeKubernetesNode(cluster, "second", daemonSetTestNodeLocalPoolName)
		Expect(reconcilePools(cluster)).To(Succeed())
		activationValue := nodeLocalPoolActivationValue(cluster)

		active, waiting := first, second
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(first), first)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(second), second)).To(Succeed())
		if first.Labels[activationLabel] != activationValue {
			active, waiting = second, first
		}
		Expect(active.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		Expect(waiting.Labels).NotTo(HaveKey(activationLabel),
			"a second identity must wait for the first one's Garage layout transition")

		makePoolPod(cluster, active.Name, "serialized-first")
		Expect(reconcilePools(cluster)).To(Succeed())
		poolGarageNodes := &garagev1beta1.GarageNodeList{}
		Expect(k8sClient.List(ctx, poolGarageNodes,
			client.InNamespace(testNamespace),
			client.MatchingLabels(map[string]string{
				labelCluster:       cluster.Name,
				labelNodeLocalPool: daemonSetTestNodeLocalPoolName,
			}),
		)).To(Succeed())
		Expect(poolGarageNodes.Items).To(HaveLen(1))
		firstGarageNode := poolGarageNodes.Items[0].DeepCopy()
		Expect(firstGarageNode.Spec.KubernetesNodeName).To(Equal(active.Name))
		firstGarageNode.Status.NodeID = strings.Repeat("e", 64)
		firstGarageNode.Status.Connected = true
		firstGarageNode.Status.InLayout = true
		firstGarageNode.Status.ObservedGeneration = firstGarageNode.Generation
		Expect(k8sClient.Status().Update(ctx, firstGarageNode)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(waiting), waiting)).To(Succeed())
		Expect(waiting.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
	})

	It("recovers all exact committed pool roles together after GarageCluster recreation", func() {
		cluster := makePoolCluster("pool-cold-recovery")
		first := makeKubernetesNode(cluster, "first", daemonSetTestNodeLocalPoolName)
		second := makeKubernetesNode(cluster, "second", daemonSetTestNodeLocalPoolName)
		firstNodeID := strings.Repeat("1", 64)
		secondNodeID := strings.Repeat("2", 64)
		capacity := uint64(500 * 1024 * 1024 * 1024)
		roleFor := func(k8sNode *corev1.Node, nodeID string) garage.LayoutNodeRole {
			return garage.LayoutNodeRole{
				ID:       nodeID,
				Zone:     testZone,
				Capacity: ptr.To(capacity),
				Tags: []string{
					fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace),
					"cluster-uid:previous-garagecluster-uid",
					"tier:" + tierStorage,
					nodeLocalPoolLayoutTagPrefix + daemonSetTestNodeLocalPoolName,
					"kubernetes-node:" + k8sNode.Name,
				},
			}
		}
		committedLayout = &garage.ClusterLayout{Roles: []garage.LayoutNodeRole{
			roleFor(first, firstNodeID),
			roleFor(second, secondNodeID),
		}}

		Expect(reconcilePools(cluster)).To(Succeed())
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)
		activationValue := nodeLocalPoolActivationValue(cluster)
		recoveryAnnotation := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, daemonSetTestNodeLocalPoolName)
		for k8sNode, nodeID := range map[*corev1.Node]string{first: firstNodeID, second: secondNodeID} {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
			Expect(k8sNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue),
				"all already-committed roles must start together on cold recovery")
			Expect(k8sNode.Annotations).To(HaveKeyWithValue(recoveryAnnotation, nodeID))
		}

		makePoolPod(cluster, first.Name, "cold-first")
		makePoolPod(cluster, second.Name, "cold-second")
		Expect(reconcilePools(cluster)).To(Succeed())
		for k8sNode, nodeID := range map[*corev1.Node]string{first: firstNodeID, second: secondNodeID} {
			garageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
			Expect(garageNode.Annotations).To(HaveKeyWithValue(
				garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID,
				nodeID,
			))
		}
	})

	It("fails closed when committed roles ambiguously claim one pool member", func() {
		cluster := makePoolCluster("pool-cold-ambiguous")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		capacity := uint64(1)
		tags := []string{
			fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace),
			"tier:" + tierStorage,
			nodeLocalPoolLayoutTagPrefix + daemonSetTestNodeLocalPoolName,
			"kubernetes-node:" + k8sNode.Name,
		}
		committedLayout = &garage.ClusterLayout{Roles: []garage.LayoutNodeRole{
			{ID: strings.Repeat("3", 64), Zone: testZone, Capacity: ptr.To(capacity), Tags: tags},
			{ID: strings.Repeat("4", 64), Zone: testZone, Capacity: ptr.To(capacity), Tags: tags},
		}}

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolIdentityCollision))
		Expect(condition.Message).To(ContainSubstring("both claim node-local pool"))
	})

	It("assembles a factor-three bootstrap from one joining Manual member and two node-local-pool members", func() {
		cluster := makePoolCluster("pool-mixed-bootstrap")
		cluster.Spec.Replication.Factor = 3
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 1,
			Versions: []garage.LayoutVersion{{
				Version:      1,
				Status:       garage.LayoutVersionStatusCurrent,
				StorageNodes: 0,
			}},
		}

		// This represents an SMB/PVC-backed Manual identity whose process exists
		// but whose role cannot be Applied alone at replication factor three.
		manual := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name + "-smb",
				Namespace: testNamespace,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				Zone:       testZone,
				Capacity:   quantity("1Ti"),
			},
		}
		Expect(k8sClient.Create(ctx, manual)).To(Succeed())

		first := makeKubernetesNode(cluster, "bootstrap-a", daemonSetTestNodeLocalPoolName)
		second := makeKubernetesNode(cluster, "bootstrap-b", daemonSetTestNodeLocalPoolName)
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		activationValue := nodeLocalPoolActivationValue(cluster)
		for _, kubernetesNode := range []*corev1.Node{first, second} {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(kubernetesNode), kubernetesNode)).To(Succeed())
			Expect(kubernetesNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue),
				"all identities required by the first valid Garage layout must be allowed to materialize")
		}

		makePoolPod(cluster, first.Name, "bootstrap-a")
		makePoolPod(cluster, second.Name, "bootstrap-b")
		Expect(reconcilePools(cluster)).To(Succeed())
		garageNodes := &garagev1beta1.GarageNodeList{}
		Expect(k8sClient.List(ctx, garageNodes, client.InNamespace(testNamespace))).To(Succeed())
		memberCount := 0
		for i := range garageNodes.Items {
			if garageNodes.Items[i].Spec.ClusterRef.Name == cluster.Name {
				memberCount++
			}
		}
		Expect(memberCount).To(Equal(3))
	})

	It("fails the pool condition when two members load the same durable Garage identity", func() {
		cluster := makePoolCluster("pool-duplicate-identity")
		firstNode := makeKubernetesNode(cluster, "worker-a", daemonSetTestNodeLocalPoolName)
		secondNode := makeKubernetesNode(cluster, "worker-b", daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		makePoolPod(cluster, firstNode.Name, "pod-a")
		makePoolPod(cluster, secondNode.Name, "pod-b")
		Expect(reconcilePools(cluster)).To(Succeed())

		duplicateID := strings.Repeat("d", 64)
		for _, k8sNode := range []*corev1.Node{firstNode, secondNode} {
			garageNode := garageNodeForKubernetesNode(
				cluster.Name,
				daemonSetTestNodeLocalPoolName,
				k8sNode.Name,
			)
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
			garageNode.Status.NodeID = duplicateID
			garageNode.Status.Connected = true
			garageNode.Status.InLayout = true
			garageNode.Status.ObservedGeneration = garageNode.Generation
			Expect(k8sClient.Status().Update(ctx, garageNode)).To(Succeed())
		}

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(
			cluster.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolIdentityCollision))
		Expect(condition.Message).To(ContainSubstring(firstNode.Name))
		Expect(condition.Message).To(ContainSubstring(secondNode.Name))
	})

	It("ignores a forged pool Pod whose DaemonSet owner UID does not match", func() {
		cluster := makePoolCluster("pool-forged-pod")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		Expect(reconcilePools(cluster)).To(Succeed())
		pod := makePoolPod(cluster, k8sNode.Name, "forged")
		pod.OwnerReferences[0].UID = types.UID("forged-daemonset-uid")
		Expect(k8sClient.Update(ctx, pod)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		garageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
		Expect(errors.IsNotFound(k8sClient.Get(
			ctx,
			client.ObjectKeyFromObject(garageNode),
			garageNode,
		))).To(BeTrue())
	})

	It("reports a declared pool whose selector matches no Kubernetes Nodes", func() {
		cluster := makePoolCluster("pool-empty")
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForMembers))
		Expect(condition.Message).To(ContainSubstring("match no Kubernetes Nodes"))
	})

	It("reports a deterministic conflict when live Node labels match two selectors", func() {
		cluster := makePoolCluster("pool-selector-conflict")
		capacity := resource.MustParse("1Ti")
		cluster.Spec.Storage.NodeLocalPools = append(cluster.Spec.Storage.NodeLocalPools, garagev1beta2.NodeLocalPoolSpec{
			Name: daemonSetTestArchiveNodeLocalPoolName,
			Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: daemonSetTestNodeLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{daemonSetTestNodeLocalPoolName},
			}}},
			Capacity: &capacity,
			Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveMetadataHostPath},
			Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveDataHostPath},
		})
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed(),
			"valid LabelSelectors are admitted; overlap is evaluated against live Nodes")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)))
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestArchiveNodeLocalPoolName)))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolSelectorConflict))
		Expect(condition.Message).To(ContainSubstring(k8sNode.Name))
		Expect(condition.Message).To(ContainSubstring(daemonSetTestNodeLocalPoolName))
		Expect(condition.Message).To(ContainSubstring(daemonSetTestArchiveNodeLocalPoolName))
	})

	It("allows independent GarageClusters on one Node only when their HostPaths are disjoint", func() {
		first := makePoolCluster("pool-multicluster-a")
		second := makePoolClusterWithPaths(
			"pool-multicluster-b",
			"/var/lib/garage/other-meta",
			"/var/lib/garage/other-data",
		)
		k8sNode := makeKubernetesNode(first, "worker", daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(first)).To(Succeed())
		Expect(reconcilePools(second)).To(Succeed())
		firstActivationValue := nodeLocalPoolActivationValue(first)
		secondActivationValue := nodeLocalPoolActivationValue(second)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(
			nodeLocalPoolActivationLabel(first, daemonSetTestNodeLocalPoolName),
			firstActivationValue,
		))
		Expect(k8sNode.Labels).To(HaveKeyWithValue(
			nodeLocalPoolActivationLabel(second, daemonSetTestNodeLocalPoolName),
			secondActivationValue,
		))

		conflicting := makePoolCluster("pool-multicluster-conflict")
		Expect(reconcilePools(conflicting)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(
			nodeLocalPoolActivationLabel(conflicting, daemonSetTestNodeLocalPoolName),
		))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(conflicting), conflicting)).To(Succeed())
		condition := meta.FindStatusCondition(
			conflicting.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolHostPathConflict))
		Expect(condition.Message).To(ContainSubstring(first.Namespace + "/" + first.Name))
		Expect(condition.Message).To(ContainSubstring(k8sNode.Name))
	})

	It("treats a lingering pod from a same-name old GarageCluster as a foreign HostPath owner", func() {
		cluster := makePoolCluster("pool-recreated-cluster")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)

		// Model a new GarageCluster incarnation and its current same-name
		// DaemonSet while a pod controlled by the deleted incarnation's
		// same-name DaemonSet still has the disk mounted.
		Expect(reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, activationLabel, "test-config-hash",
		)).To(Succeed())
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		oldPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        uniqueClusterName(cluster.Name + "-old-incarnation"),
				Namespace:   testNamespace,
				Labels:      daemonSet.Spec.Template.Labels,
				Annotations: daemonSet.Spec.Template.Annotations,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       daemonSetKind,
					Name:       daemonSet.Name,
					UID:        types.UID("deleted-daemonset-uid"),
					Controller: ptr.To(true),
				}},
			},
			Spec: *daemonSet.Spec.Template.Spec.DeepCopy(),
		}
		// This models an already-bound Pod from the retired workload. Pool Pods
		// created by the completed feature keep the gate until the operator
		// authorizes scheduling, but scheduling gates cannot remain after bind.
		oldPod.Spec.SchedulingGates = nil
		oldPod.Spec.NodeName = k8sNode.Name
		Expect(k8sClient.Create(ctx, oldPod)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, oldPod) })

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(activationLabel))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolHostPathConflict))
		Expect(condition.Message).To(ContainSubstring(oldPod.Name))
		Expect(condition.Message).To(ContainSubstring("mounted pod"))
	})

	It("retains old members when a still-declared pool temporarily matches no Kubernetes Nodes", func() {
		cluster := makePoolCluster("pool-selector-empty")
		k8sNode := makeKubernetesNode(cluster, "old", daemonSetTestNodeLocalPoolName)
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		activationValue := nodeLocalPoolActivationValue(cluster)
		makePoolPod(cluster, k8sNode.Name, testOldPodUID)
		Expect(reconcilePools(cluster)).To(Succeed())
		garageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		garageNode.Finalizers = []string{garageNodeFinalizer}
		Expect(k8sClient.Update(ctx, garageNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		garageNode.Status.NodeID = strings.Repeat("c", 64)
		garageNode.Status.InLayout = true
		garageNode.Status.Connected = true
		garageNode.Status.ObservedGeneration = garageNode.Generation
		Expect(k8sClient.Status().Update(ctx, garageNode)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		delete(k8sNode.Labels, daemonSetTestNodeLabel)
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		Expect(garageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement), condition.Message)
		Expect(condition.Message).To(ContainSubstring("still declared"))
		Expect(condition.Message).To(ContainSubstring("matches no Kubernetes Nodes"))
	})

	It("publishes a combined disk and capacity increase only after the new pool pod is observed", func() {
		cluster := makePoolCluster("pool-capacity-handoff")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		oldPod := makePoolPod(cluster, k8sNode.Name, "old-capacity")
		Expect(reconcilePools(cluster)).To(Succeed())
		garageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		garageNode.Status.NodeID = strings.Repeat("e", 64)
		garageNode.Status.InLayout = true
		garageNode.Status.Connected = true
		garageNode.Status.ObservedGeneration = garageNode.Generation
		garageNode.Status.ObservedPodUID = string(oldPod.UID)
		Expect(k8sClient.Status().Update(ctx, garageNode)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		oldCapacity := cluster.Spec.Storage.NodeLocalPools[0].Capacity.DeepCopy()
		newCapacity := resource.MustParse("750Gi")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		pool.Capacity = &newCapacity
		pool.Data = nil
		pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
			{Path: dataPath, HostPath: daemonSetTestDataHostPath, Capacity: quantity("500Gi")},
			{Path: daemonSetTestFastDataPath, HostPath: daemonSetTestFastHostPath, Capacity: quantity("250Gi")},
		}
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())

		By("updating the desired DaemonSet and durable claim without advertising its disks through the old pod")
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		Expect(garageNode.Spec.Capacity).NotTo(BeNil())
		Expect(garageNode.Spec.Capacity.Cmp(oldCapacity)).To(Equal(0))
		daemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
		}, daemonSet)).To(Succeed())
		Expect(oldPod.Annotations[annotationPodSpecHash]).NotTo(Equal(daemonSet.Spec.Template.Annotations[annotationPodSpecHash]))

		By("publishing the larger capacity after the exact replacement pod is Ready and observed")
		Expect(k8sClient.Delete(ctx, oldPod, client.GracePeriodSeconds(0))).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldPod), &corev1.Pod{}))
		}).Should(BeTrue())
		newPod := makePoolPod(cluster, k8sNode.Name, "new-capacity")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		garageNode.Status.NodeID = strings.Repeat("e", 64)
		garageNode.Status.InLayout = true
		garageNode.Status.Connected = true
		garageNode.Status.ObservedGeneration = garageNode.Generation
		garageNode.Status.ObservedPodUID = string(newPod.UID)
		Expect(k8sClient.Status().Update(ctx, garageNode)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(garageNode), garageNode)).To(Succeed())
		Expect(garageNode.Spec.Capacity).NotTo(BeNil())
		Expect(garageNode.Spec.Capacity.Cmp(newCapacity)).To(Equal(0))
	})

	It("adds and commits a replacement before draining the old node, then stops its pod", func() {
		cluster := makePoolCluster("pool-handoff")
		cluster.Spec.Replication.ConsistencyMode = consistencyModeConsistent
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		markGarageClusterDrainReady(cluster)
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())
		oldNode := makeKubernetesNode(cluster, "old", daemonSetTestNodeLocalPoolName)
		newNode := makeKubernetesNode(cluster, testNewValue, "not-selected")
		activationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		oldPod := makePoolPod(cluster, oldNode.Name, testOldPodUID)
		Expect(reconcilePools(cluster)).To(Succeed())
		oldGarageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, oldNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		oldGarageNode.Finalizers = []string{garageNodeFinalizer}
		Expect(k8sClient.Update(ctx, oldGarageNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		oldGarageNode.Status.NodeID = strings.Repeat("a", 64)
		oldGarageNode.Status.InLayout = true
		oldGarageNode.Status.Connected = true
		oldGarageNode.Status.ObservedGeneration = oldGarageNode.Generation
		oldGarageNode.Status.ObservedPodUID = string(oldPod.UID)
		Expect(k8sClient.Status().Update(ctx, oldGarageNode)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		delete(oldNode.Labels, daemonSetTestNodeLabel)
		Expect(k8sClient.Update(ctx, oldNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newNode), newNode)).To(Succeed())
		newNode.Labels[daemonSetTestNodeLabel] = daemonSetTestNodeLocalPoolName
		Expect(k8sClient.Update(ctx, newNode)).To(Succeed())

		By("not activating the replacement while an earlier gateway/layout transition is draining")
		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 2,
			Versions: []garage.LayoutVersion{
				{Version: 1, Status: garage.LayoutVersionStatusDraining, GatewayNodes: 1},
				{Version: 2, Status: garage.LayoutVersionStatusCurrent},
			},
		}
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newNode), newNode)).To(Succeed())
		Expect(newNode.Labels).NotTo(HaveKey(activationLabel))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync))
		Expect(condition.Message).To(ContainSubstring("version(s) 1"))

		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 2,
			Versions: []garage.LayoutVersion{{
				Version: 2,
				Status:  garage.LayoutVersionStatusCurrent,
			}},
		}
		By("keeping the old activation and role while the replacement has no pod")
		Expect(reconcilePools(cluster)).To(Succeed())
		activationValue := nodeLocalPoolActivationValue(cluster)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement), condition.Message)

		By("still keeping the old role until the replacement reaches InLayout")
		newPod := makePoolPod(cluster, newNode.Name, "new-pod")
		Expect(reconcilePools(cluster)).To(Succeed())
		newGarageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, newNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newGarageNode), newGarageNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())

		newGarageNode.Finalizers = []string{garageNodeFinalizer}
		Expect(k8sClient.Update(ctx, newGarageNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newGarageNode), newGarageNode)).To(Succeed())
		newGarageNode.Status.NodeID = strings.Repeat("b", 64)
		newGarageNode.Status.InLayout = true
		newGarageNode.Status.Connected = false
		newGarageNode.Status.ObservedGeneration = newGarageNode.Generation
		newGarageNode.Status.ObservedPodUID = string(newPod.UID)
		Expect(k8sClient.Status().Update(ctx, newGarageNode)).To(Succeed())

		By("keeping the old role while the replacement is in-layout but disconnected")
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForReplacement))

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newGarageNode), newGarageNode)).To(Succeed())
		newGarageNode.Status.Connected = true
		Expect(k8sClient.Status().Update(ctx, newGarageNode)).To(Succeed())

		By("keeping the old role while the replacement layout is still synchronizing")
		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 2,
			Versions: []garage.LayoutVersion{
				{Version: 1, Status: garage.LayoutVersionStatusDraining},
				{Version: 2, Status: garage.LayoutVersionStatusCurrent},
			},
		}
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync))
		Expect(condition.Message).To(ContainSubstring("version(s) 1"))

		By("starting one old-role drain only after Garage retires the prior layout")
		layoutHistory = &garage.LayoutHistoryResponse{
			CurrentVersion: 2,
			Versions: []garage.LayoutVersion{{
				Version: 2,
				Status:  garage.LayoutVersionStatusCurrent,
			}},
		}
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeTrue())
		Expect(oldGarageNode.Annotations).To(HaveKeyWithValue(garagev1beta1.AnnotationDrain, annotationTrue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).To(HaveKeyWithValue(
			activationLabel, nodeLocalPoolActivationValue(cluster),
		))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety))

		proof, err := storageDrainRemovalIntent(
			nil, storageDrainActorForNode(oldGarageNode),
			[]string{oldGarageNode.Status.NodeID}, []string{oldGarageNode.Status.NodeID}, time.Now(),
		)
		Expect(err).NotTo(HaveOccurred())
		proof.ManagedPodUIDs = map[string]string{oldGarageNode.Status.NodeID: string(oldPod.UID)}
		completedAt := metav1.Now()
		proof.CompletedAt = &completedAt
		cluster.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(oldGarageNode.DeletionTimestamp.IsZero()).To(BeFalse())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolDraining))

		By("rotating the workload fence before removing the activation after the GarageNode finalizer completes")
		oldGarageNode.Finalizers = nil
		Expect(k8sClient.Update(ctx, oldGarageNode)).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), &garagev1beta1.GarageNode{}))
		}).Should(BeTrue())
		// The test removes the child finalizer directly, so emulate its terminal
		// handoff cleanup before the parent continues ordinary pool work.
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		cluster.Status.StorageDrain = nil
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

		// envtest has no DaemonSet controller. The first pass must keep both
		// values eligible; narrowing immediately would delete every surviving
		// Pod before its Node carries the new token.
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		deployed := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
		}, deployed)).To(Succeed())
		stagedValue := nodeLocalPoolMembershipActivationValue(
			deployed, deployed.Annotations[annotationNodeLocalPoolMembershipStaging],
		)
		Expect(deployed.Spec.Template.Spec.NodeSelector).NotTo(HaveKey(activationLabel))
		terms := deployed.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		Expect(terms).To(HaveLen(1))
		Expect(terms[0].MatchExpressions).To(ContainElement(corev1.NodeSelectorRequirement{
			Key: activationLabel, Operator: corev1.NodeSelectorOpIn, Values: []string{activationValue, stagedValue},
		}))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newNode), newNode)).To(Succeed())
		Expect(newNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))

		// Once the bridge is observed, migrate the survivor while both tokens
		// remain eligible. Only then narrow the DaemonSet selector.
		deployed.Status.ObservedGeneration = deployed.Generation
		Expect(k8sClient.Status().Update(ctx, deployed)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(newNode), newNode)).To(Succeed())
		Expect(newNode.Labels).To(HaveKeyWithValue(activationLabel, stagedValue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue))
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(deployed), deployed)).To(Succeed())
		Expect(deployed.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue(activationLabel, stagedValue))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).To(HaveKeyWithValue(activationLabel, activationValue),
			"survivors move to the new token before the old token is released")
		Expect(reconcilePools(cluster)).To(Succeed(), "normalize the staged template")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(deployed), deployed)).To(Succeed())
		deployed.Status.ObservedGeneration = deployed.Generation
		Expect(k8sClient.Status().Update(ctx, deployed)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldNode), oldNode)).To(Succeed())
		Expect(oldNode.Labels).NotTo(HaveKey(activationLabel))

		By("retaining the durable claim until the old-token Pod is gone and Garage proves the role absent")
		Expect(k8sClient.Delete(ctx, oldPod, client.GracePeriodSeconds(0))).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldPod), &corev1.Pod{}))
		}).Should(BeTrue())
		committedLayout = &garage.ClusterLayout{
			Version: 2,
			Roles:   []garage.LayoutNodeRole{{ID: newGarageNode.Status.NodeID}},
		}
		Expect(reconcilePools(cluster)).To(Succeed(), "release the old claim by a settled-layout proof")
		Expect(reconcilePools(cluster)).To(Succeed(), "observe the released claim and converge")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolsConverged))
	})

	It("clears the pool condition after the final pool has no roles and is removed", func() {
		cluster := makePoolCluster("pool-remove-empty")
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		Expect(meta.FindStatusCondition(
			cluster.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)).NotTo(BeNil())

		cluster.Spec.Storage.NodeLocalPools = nil
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(
			cluster.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolDraining))

		// Deletion and immutable-revision cleanup are deliberately separate
		// reconciliation boundaries. envtest has no DaemonSet controller, but
		// the API server completes this child deletion before the next pass.
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{
				Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
			}, &appsv1.DaemonSet{}))
		}).Should(BeTrue())
		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		Expect(meta.FindStatusCondition(
			cluster.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)).To(BeNil())

		ds := &appsv1.DaemonSet{}
		Expect(errors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
		}, ds))).To(BeTrue())
	})

	It("blocks a direct Kubernetes Node move between pools before a second pod can mount it", func() {
		cluster := makePoolCluster("pool-direct-move")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		oldActivationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		oldActivationValue := nodeLocalPoolActivationValue(cluster)
		makePoolPod(cluster, k8sNode.Name, testOldPodUID)
		Expect(reconcilePools(cluster)).To(Succeed())
		oldGarageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		oldGarageNode.Finalizers = []string{garageNodeFinalizer}
		Expect(k8sClient.Update(ctx, oldGarageNode)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		oldGarageNode.Status.NodeID = strings.Repeat("c", 64)
		oldGarageNode.Status.InLayout = true
		oldGarageNode.Status.Connected = true
		oldGarageNode.Status.ObservedGeneration = oldGarageNode.Generation
		Expect(k8sClient.Status().Update(ctx, oldGarageNode)).To(Succeed())

		archiveCapacity := resource.MustParse("1Ti")
		cluster.Spec.Storage.NodeLocalPools = append(cluster.Spec.Storage.NodeLocalPools,
			garagev1beta2.NodeLocalPoolSpec{
				Name:     daemonSetTestArchiveNodeLocalPoolName,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{daemonSetTestNodeLabel: daemonSetTestArchiveNodeLocalPoolName}},
				Capacity: &archiveCapacity,
				Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveMetadataHostPath},
				Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveDataHostPath},
				Network: &garagev1beta2.NodeLocalPoolNetworkSpec{
					RPCPublicAddrTemplate: daemonSetTestRPCAddress,
				},
			},
		)
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		k8sNode.Labels[daemonSetTestNodeLabel] = daemonSetTestArchiveNodeLocalPoolName
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(oldActivationLabel, oldActivationValue))
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestArchiveNodeLocalPoolName)))

		archiveGarageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestArchiveNodeLocalPoolName, k8sNode.Name)
		Expect(errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(archiveGarageNode), archiveGarageNode))).To(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolMoveBlocked))
	})

	It("waits for an orphaned previous-pool pod after its DaemonSet disappears", func() {
		cluster := makePoolCluster("pool-orphaned-pod-move")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		oldActivationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		oldPod := makePoolPod(cluster, k8sNode.Name, "orphaned-old-pool")
		Expect(reconcilePools(cluster)).To(Succeed())

		oldGarageNode := garageNodeForKubernetesNode(cluster.Name, daemonSetTestNodeLocalPoolName, k8sNode.Name)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), oldGarageNode)).To(Succeed())
		Expect(k8sClient.Delete(ctx, oldGarageNode)).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldGarageNode), &garagev1beta1.GarageNode{}))
		}).Should(BeTrue())

		oldDaemonSet := &appsv1.DaemonSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
		}, oldDaemonSet)).To(Succeed())
		Expect(k8sClient.Delete(ctx, oldDaemonSet)).To(Succeed())
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldDaemonSet), &appsv1.DaemonSet{}))
		}).Should(BeTrue())

		archiveCapacity := resource.MustParse("1Ti")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		cluster.Spec.Storage.NodeLocalPools = []garagev1beta2.NodeLocalPoolSpec{{
			Name:     daemonSetTestArchiveNodeLocalPoolName,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{daemonSetTestNodeLabel: daemonSetTestArchiveNodeLocalPoolName}},
			Capacity: &archiveCapacity,
			Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveMetadataHostPath},
			Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveDataHostPath},
			Network: &garagev1beta2.NodeLocalPoolNetworkSpec{
				RPCPublicAddrTemplate: daemonSetTestRPCAddress,
			},
		}}
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		k8sNode.Labels[daemonSetTestNodeLabel] = daemonSetTestArchiveNodeLocalPoolName
		delete(k8sNode.Labels, oldActivationLabel)
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(oldPod), oldPod)).To(Succeed(),
			"the previous Garage process is deliberately still running")
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).NotTo(HaveKey(nodeLocalPoolActivationLabel(cluster, daemonSetTestArchiveNodeLocalPoolName)))

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolDraining))
		Expect(condition.Message).To(ContainSubstring("retired node-local-pool DaemonSets and Pods"))
	})

	It("treats activation as pool ownership before the first GarageNode exists", func() {
		cluster := makePoolCluster("pool-pre-membership-move")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		oldActivationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestNodeLocalPoolName)

		Expect(reconcilePools(cluster)).To(Succeed())
		oldActivationValue := nodeLocalPoolActivationValue(cluster)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		Expect(k8sNode.Labels).To(HaveKeyWithValue(oldActivationLabel, oldActivationValue))

		archiveCapacity := resource.MustParse("1Ti")
		cluster.Spec.Storage.NodeLocalPools = append(cluster.Spec.Storage.NodeLocalPools,
			garagev1beta2.NodeLocalPoolSpec{
				Name:     daemonSetTestArchiveNodeLocalPoolName,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{daemonSetTestNodeLabel: daemonSetTestArchiveNodeLocalPoolName}},
				Capacity: &archiveCapacity,
				Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveMetadataHostPath},
				Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: testArchiveDataHostPath},
				Network: &garagev1beta2.NodeLocalPoolNetworkSpec{
					RPCPublicAddrTemplate: daemonSetTestRPCAddress,
				},
			},
		)
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		k8sNode.Labels[daemonSetTestNodeLabel] = daemonSetTestArchiveNodeLocalPoolName
		Expect(k8sClient.Update(ctx, k8sNode)).To(Succeed())

		Expect(reconcilePools(cluster)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(k8sNode), k8sNode)).To(Succeed())
		newActivationLabel := nodeLocalPoolActivationLabel(cluster, daemonSetTestArchiveNodeLocalPoolName)
		Expect(k8sNode.Labels).To(HaveKeyWithValue(oldActivationLabel, oldActivationValue))
		Expect(k8sNode.Labels).NotTo(HaveKey(newActivationLabel))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
		condition := meta.FindStatusCondition(
			cluster.Status.Conditions,
			garagev1beta1.ConditionNodeLocalPoolsReady,
		)
		Expect(condition).NotTo(BeNil())
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolMoveBlocked))
	})

	It("refuses pools in a namespace-scoped install", func() {
		cluster := makePoolCluster("pool-ns")
		reconciler.ClusterScoped = false
		err := reconcilePools(cluster)
		Expect(err).To(MatchError(ContainSubstring("cluster-scoped operator")))
	})

	It("refuses to adopt colliding DaemonSet and ConfigMap names", func() {
		cluster := makePoolCluster("pool-collision")
		pool := &cluster.Spec.Storage.NodeLocalPools[0]
		selector := reconciler.selectorLabelsForTier(cluster, tierStorage)
		selector[labelNodeLocalPool] = pool.Name
		foreignDS := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      storageDaemonSetName(cluster, pool.Name),
				Namespace: testNamespace,
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: selector},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: selector},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: testForeignValue, Image: "foreign:test",
					}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, foreignDS)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, foreignDS) })
		err := reconciler.reconcileNodeLocalPoolDaemonSet(
			ctx,
			cluster,
			pool,
			nodeLocalPoolActivationLabel(cluster, pool.Name),
			"hash",
		)
		Expect(err).To(MatchError(ContainSubstring("refusing to adopt a colliding workload")))

		foreignCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name:      storageDaemonSetConfigMapName(cluster, pool.Name),
			Namespace: testNamespace,
		}}
		Expect(k8sClient.Create(ctx, foreignCM)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, foreignCM) })
		_, err = reconciler.writeConfigMapWithLabels(
			ctx,
			cluster,
			foreignCM.Name,
			"garage config",
			map[string]string{labelNodeLocalPool: pool.Name},
			nil,
		)
		Expect(err).To(MatchError(ContainSubstring("refusing to read, overwrite, or adopt the collision")))
	})

	It("keeps default-pool Auto/Manual ownership separate from pool nodes", func() {
		cluster := makePoolCluster("pool-separate")
		k8sNode := makeKubernetesNode(cluster, "worker", daemonSetTestNodeLocalPoolName)
		Expect(reconcilePools(cluster)).To(Succeed())
		makePoolPod(cluster, k8sNode.Name, "pod")
		Expect(reconcilePools(cluster)).To(Succeed())

		autoNodes, err := reconciler.listAutoModeStorageNodes(ctx, cluster)
		Expect(err).NotTo(HaveOccurred())
		Expect(autoNodes).To(BeEmpty(), "default-pool reconciliation must never adopt a node-local-pool GarageNode")
	})
})

func quantity(value string) *resource.Quantity {
	q := resource.MustParse(value)
	return &q
}

func garageNodeForKubernetesNode(clusterName, nodeLocalPoolName, nodeName string) *garagev1beta1.GarageNode {
	return &garagev1beta1.GarageNode{ObjectMeta: metav1.ObjectMeta{
		Name:      nodeLocalPoolGarageNodeName(clusterName, nodeLocalPoolName, nodeName),
		Namespace: testNamespace,
	}}
}
