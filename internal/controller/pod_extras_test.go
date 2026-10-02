/*
Copyright 2026.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	extrasTestImage   = "example.invalid/helper:1"
	extrasSidecarName = "ddns"
	extrasInitName    = "wait-for-vip"
	extrasVolumeName  = "ddns-state"
	extrasMountPath   = "/var/lib/ddns"
	extrasTypoJSON    = `{"name":"typo","image":"example.invalid/helper:1","volumeMount":[]}`
)

func extrasSidecar(name string, mounts ...string) corev1.Container {
	c := corev1.Container{Name: name, Image: extrasTestImage}
	for _, m := range mounts {
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: m, MountPath: extrasMountPath})
	}
	return c
}

func extrasEmptyDir(name string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
}

func extrasRaw(raw string) garagev1beta2.PodExtraContainer {
	var c garagev1beta2.PodExtraContainer
	ExpectWithOffset(1, json.Unmarshal([]byte(raw), &c)).To(Succeed())
	return c
}

func extrasContainerNames(list []corev1.Container) []string {
	names := make([]string, 0, len(list))
	for i := range list {
		names = append(names, list[i].Name)
	}
	return names
}

func extrasVolumeNames(list []corev1.Volume) []string {
	names := make([]string, 0, len(list))
	for i := range list {
		names = append(names, list[i].Name)
	}
	return names
}

func extrasTemplate() garagev1beta2.PodTemplate {
	return garagev1beta2.PodTemplate{
		InitContainers:  garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(extrasInitName)}),
		ExtraContainers: garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(extrasSidecarName, extrasVolumeName)}),
		ExtraVolumes:    garagev1beta2.NewPodExtraVolumes([]corev1.Volume{extrasEmptyDir(extrasVolumeName)}),
	}
}

func extrasForceDeleteCluster(name string) {
	_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, name)
	_ = deleteTestGarageNodesForCluster(ctx, k8sClient, testNamespace, name)
	c := &garagev1beta2.GarageCluster{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, c); err == nil {
		c.Finalizers = nil
		_ = k8sClient.Update(ctx, c)
		_ = k8sClient.Delete(ctx, c)
	}
}

// The unit tests below do not need an API server: they pin the pure functions
// that decide the shape of the rendered pod.
var _ = Describe("pod extras: applyPodExtras (#441)", func() {
	basePodSpec := func() corev1.PodSpec {
		return corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "operator-init"}},
			Containers:     []corev1.Container{{Name: defaultAppName}},
			Volumes:        []corev1.Volume{extrasEmptyDir(metadataVolName), extrasEmptyDir(dataVolName)},
		}
	}
	resolve := func(in garagev1beta2.PodExtrasInput) garagev1beta2.ResolvedPodExtras {
		resolved, err := resolvePodExtras(in)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return resolved
	}

	It("orders operator containers first, garage stays containers[0], extras follow", func() {
		tpl := extrasTemplate()
		spec := basePodSpec()
		Expect(applyPodExtras(&spec, resolve(garagev1beta2.PodExtrasInput{
			Field: "x", InitContainers: tpl.InitContainers, ExtraContainers: tpl.ExtraContainers, ExtraVolumes: tpl.ExtraVolumes,
		}))).To(Succeed())
		Expect(extrasContainerNames(spec.InitContainers)).To(Equal([]string{"operator-init", extrasInitName}))
		Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName, extrasSidecarName}))
		Expect(extrasVolumeNames(spec.Volumes)).To(Equal([]string{metadataVolName, dataVolName, extrasVolumeName}))
	})

	It("leaves the pod spec untouched when there are no extras", func() {
		spec := basePodSpec()
		before := spec.DeepCopy()
		Expect(applyPodExtras(&spec, garagev1beta2.ResolvedPodExtras{})).To(Succeed())
		Expect(spec).To(Equal(*before))
	})

	It("rejects a container that collides with one the builder rendered, computed from the built spec", func() {
		spec := basePodSpec()
		before := spec.DeepCopy()
		err := applyPodExtras(&spec, garagev1beta2.ResolvedPodExtras{
			ExtraContainers: []corev1.Container{extrasSidecar("operator-init")},
		})
		pe, ok := asPodExtrasError(err)
		Expect(ok).To(BeTrue())
		Expect(pe.Reason).To(Equal(garagev1beta2.PodExtrasReasonReservedName))
		Expect(spec).To(Equal(*before), "a failed apply must not mutate the pod spec")
	})

	It("rejects mounts of operator volumes and of undeclared volumes", func() {
		for name, tc := range map[string]struct{ mount, reason string }{
			"operator volume":   {metadataVolName, garagev1beta2.PodExtrasReasonOperatorVolumeMount},
			"undeclared volume": {"nope", garagev1beta2.PodExtrasReasonUnknownVolume},
		} {
			spec := basePodSpec()
			err := applyPodExtras(&spec, garagev1beta2.ResolvedPodExtras{
				ExtraContainers: []corev1.Container{extrasSidecar("x", tc.mount)},
			})
			pe, ok := asPodExtrasError(err)
			Expect(ok).To(BeTrue(), name)
			Expect(pe.Reason).To(Equal(tc.reason), name)
		}
	})

	It("rejects an extra volume named like an operator volume", func() {
		spec := basePodSpec()
		err := applyPodExtras(&spec, garagev1beta2.ResolvedPodExtras{ExtraVolumes: []corev1.Volume{extrasEmptyDir(dataVolName)}})
		pe, ok := asPodExtrasError(err)
		Expect(ok).To(BeTrue())
		Expect(pe.Reason).To(Equal(garagev1beta2.PodExtrasReasonReservedName))
	})

	It("does not alias the caller's slices", func() {
		tpl := extrasTemplate()
		spec := basePodSpec()
		resolved := resolve(garagev1beta2.PodExtrasInput{Field: "x", ExtraContainers: tpl.ExtraContainers, ExtraVolumes: tpl.ExtraVolumes})
		Expect(applyPodExtras(&spec, resolved)).To(Succeed())
		spec.Containers[1].Name = "mutated"
		Expect(resolved.ExtraContainers[0].Name).To(Equal(extrasSidecarName))
	})

	It("hashes resolved values, so JSON key order cannot cause a rollout", func() {
		a := extrasRaw(`{"name":"ddns","image":"example.invalid/helper:1","command":["a"]}`)
		b := extrasRaw(`{"command":["a"],"image":"example.invalid/helper:1","name":"ddns"}`)
		specFor := func(c garagev1beta2.PodExtraContainer) corev1.PodSpec {
			spec := basePodSpec()
			Expect(applyPodExtras(&spec, resolve(garagev1beta2.PodExtrasInput{
				Field: "x", ExtraContainers: []garagev1beta2.PodExtraContainer{c},
			}))).To(Succeed())
			return spec
		}
		Expect(computePodSpecHash(specFor(a), nil, nil)).To(Equal(computePodSpecHash(specFor(b), nil, nil)))
		c := extrasRaw(`{"name":"ddns","image":"example.invalid/helper:2","command":["a"]}`)
		Expect(computePodSpecHash(specFor(a), nil, nil)).NotTo(Equal(computePodSpecHash(specFor(c), nil, nil)))
	})

	It("purgeInitRunAsUser looks only at the garage container", func() {
		sts := &appsv1.StatefulSet{}
		sts.Spec.Template.Spec.Containers = []corev1.Container{
			{Name: defaultAppName, SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(int64(1000))}},
			{Name: extrasSidecarName, SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(int64(0))}},
		}
		Expect(purgeInitRunAsUser(sts)).To(Equal(ptr.To(int64(1000))))
		// A sidecar listed first must not decide either.
		sts.Spec.Template.Spec.Containers[0], sts.Spec.Template.Spec.Containers[1] =
			sts.Spec.Template.Spec.Containers[1], sts.Spec.Template.Spec.Containers[0]
		Expect(purgeInitRunAsUser(sts)).To(Equal(ptr.To(int64(1000))))
		sts.Spec.Template.Spec.Containers = sts.Spec.Template.Spec.Containers[:1]
		Expect(purgeInitRunAsUser(sts)).To(BeNil())
	})
})

var _ = Describe("pod extras: workloads (#441)", func() {
	reconciler := func() *GarageClusterReconciler {
		return &GarageClusterReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
	}
	newGatewayCluster := func(prefix string, tpl garagev1beta2.PodTemplate) *garagev1beta2.GarageCluster {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName(prefix), Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Gateway:     &garagev1beta2.GatewaySpec{Replicas: 1, PodTemplate: tpl},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				ConnectTo:   &garagev1beta2.ConnectToConfig{BootstrapPeers: []string{testBootstrapPeer}},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		DeferCleanup(func() { extrasForceDeleteCluster(cluster.Name) })
		return cluster
	}
	getGatewaySTS := func(cluster *garagev1beta2.GarageCluster) *appsv1.StatefulSet {
		sts := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cluster.Name + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())
		return sts
	}

	Context("edge gateway StatefulSet", func() {
		It("renders extras in order with garage as containers[0] and records them in the pod-spec hash", func() {
			cluster := newGatewayCluster("extras-gw", extrasTemplate())
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())

			sts := getGatewaySTS(cluster)
			spec := sts.Spec.Template.Spec
			Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName, extrasSidecarName}))
			Expect(extrasContainerNames(spec.InitContainers)).To(ContainElement(extrasInitName))
			Expect(extrasVolumeNames(spec.Volumes)).To(ContainElement(extrasVolumeName))
			hash := sts.Spec.Template.Annotations[annotationPodSpecHash]
			Expect(hash).NotTo(BeEmpty())

			By("an unchanged spec produces the same hash and no write")
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
			Expect(getGatewaySTS(cluster).ResourceVersion).To(Equal(sts.ResourceVersion))

			By("editing a sidecar changes the hash and the StatefulSet")
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
			edited := extrasSidecar(extrasSidecarName, extrasVolumeName)
			edited.Image = "example.invalid/helper:2"
			cluster.Spec.Gateway.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{edited})
			Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
			after := getGatewaySTS(cluster)
			Expect(after.Spec.Template.Annotations[annotationPodSpecHash]).NotTo(Equal(hash))
			Expect(after.Spec.Template.Spec.Containers[1].Image).To(Equal("example.invalid/helper:2"))

			By("removing every extra restores the original shape")
			cluster.Spec.Gateway.InitContainers = nil
			cluster.Spec.Gateway.ExtraContainers = nil
			cluster.Spec.Gateway.ExtraVolumes = nil
			Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
			cleared := getGatewaySTS(cluster)
			Expect(extrasContainerNames(cleared.Spec.Template.Spec.Containers)).To(Equal([]string{defaultAppName}))
			Expect(extrasContainerNames(cleared.Spec.Template.Spec.InitContainers)).NotTo(ContainElement(extrasInitName))
			Expect(cleared.Spec.Template.Annotations[annotationPodSpecHash]).NotTo(Equal(after.Spec.Template.Annotations[annotationPodSpecHash]))
		})

		It("refuses invalid extras without touching the existing StatefulSet", func() {
			cluster := newGatewayCluster("extras-gw-bad", extrasTemplate())
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
			before := getGatewaySTS(cluster)

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
			cluster.Spec.Gateway.ExtraContainers = []garagev1beta2.PodExtraContainer{extrasRaw(extrasTypoJSON)}
			Expect(k8sClient.Update(ctx, cluster)).To(Succeed(), "unknown fields must pass CRD validation: the strict check is ours")

			err := reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")
			pe, ok := asPodExtrasError(err)
			Expect(ok).To(BeTrue(), "got %v", err)
			Expect(pe.Reason).To(Equal(garagev1beta2.PodExtrasReasonDecodeError))
			Expect(pe.Error()).To(ContainSubstring("volumeMount"))
			Expect(getGatewaySTS(cluster).ResourceVersion).To(Equal(before.ResourceVersion))
		})

		It("rejects an extra volume that reuses a claim the operator manages", func() {
			claim := &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name: uniqueClusterName("managed-claim"), Namespace: testNamespace,
					Labels: map[string]string{labelAppManagedBy: managedByOperatorValue},
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("1Gi"),
					}},
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, claim) })

			tpl := extrasTemplate()
			tpl.ExtraVolumes = garagev1beta2.NewPodExtraVolumes([]corev1.Volume{{
				Name: extrasVolumeName,
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claim.Name,
				}},
			}})
			cluster := newGatewayCluster("extras-gw-claim", tpl)
			err := reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")
			pe, ok := asPodExtrasError(err)
			Expect(ok).To(BeTrue(), "got %v", err)
			Expect(pe.Reason).To(Equal(garagev1beta2.PodExtrasReasonManagedClaimReuse))
		})

		It("allows a claim the operator does not manage", func() {
			tpl := extrasTemplate()
			tpl.ExtraVolumes = garagev1beta2.NewPodExtraVolumes([]corev1.Volume{{
				Name: extrasVolumeName,
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: "my-own-scratch",
				}},
			}})
			cluster := newGatewayCluster("extras-gw-own-claim", tpl)
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
		})

		It("keeps a user init container next to the factor-migration purge init container and restores exactly the user list", func() {
			cluster := newGatewayCluster("extras-gw-purge", extrasTemplate())
			Expect(reconciler().reconcileGatewayStatefulSet(ctx, cluster, "cfg")).To(Succeed())
			name := cluster.Name + "-gateway"
			userInit := extrasContainerNames(getGatewaySTS(cluster).Spec.Template.Spec.InitContainers)

			Expect(reconciler().patchSTSPurgeInitContainer(ctx, cluster, name, "p-1", true)).To(Succeed())
			withPurge := extrasContainerNames(getGatewaySTS(cluster).Spec.Template.Spec.InitContainers)
			Expect(withPurge[0]).To(Equal(fmPurgeInitContainerName))
			Expect(withPurge[1:]).To(Equal(userInit), "user init containers keep their order behind the purge container")

			Expect(reconciler().patchSTSPurgeInitContainer(ctx, cluster, name, "p-1", false)).To(Succeed())
			Expect(extrasContainerNames(getGatewaySTS(cluster).Spec.Template.Spec.InitContainers)).To(Equal(userInit))
		})
	})

	Context("PodExtrasValid condition", func() {
		It("is False and blocks the pass on invalid extras, then recovers", func() {
			tpl := extrasTemplate()
			tpl.ExtraContainers = []garagev1beta2.PodExtraContainer{extrasRaw(extrasTypoJSON)}
			cluster := newGatewayCluster("extras-cond", tpl)

			blocked, err := reconciler().reconcilePodExtrasCondition(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(blocked).To(BeTrue())
			fresh := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), fresh)).To(Succeed())
			cond := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta2.ConditionPodExtrasValid)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(garagev1beta2.PodExtrasReasonDecodeError))
			Expect(cond.Message).To(ContainSubstring("volumeMount"))
			Expect(cond.ObservedGeneration).To(Equal(fresh.Generation))

			By("an unchanged invalid spec does not rewrite status")
			rv := fresh.ResourceVersion
			blocked, err = reconciler().reconcilePodExtrasCondition(ctx, fresh)
			Expect(err).NotTo(HaveOccurred())
			Expect(blocked).To(BeTrue())
			again := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), again)).To(Succeed())
			Expect(again.ResourceVersion).To(Equal(rv))

			By("fixing the spec flips the condition to True")
			again.Spec.Gateway.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(extrasSidecarName, extrasVolumeName)})
			Expect(k8sClient.Update(ctx, again)).To(Succeed())
			blocked, err = reconciler().reconcilePodExtrasCondition(ctx, again)
			Expect(err).NotTo(HaveOccurred())
			Expect(blocked).To(BeFalse())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), fresh)).To(Succeed())
			cond = meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta2.ConditionPodExtrasValid)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal(garagev1beta2.PodExtrasReasonValid))
		})

		It("is not published for a cluster that never used extras", func() {
			cluster := newGatewayCluster("extras-cond-none", garagev1beta2.PodTemplate{})
			blocked, err := reconciler().reconcilePodExtrasCondition(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(blocked).To(BeFalse())
			Expect(meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta2.ConditionPodExtrasValid)).To(BeNil())
		})
	})

	Context("GarageNode StatefulSet", func() {
		const nodeSuffix = "-storage-0"
		var cluster *garagev1beta2.GarageCluster

		newNode := func(mutate func(*garagev1beta1.GarageNodeSpec)) *garagev1beta1.GarageNode {
			capacity := resource.MustParse("100Gi")
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: cluster.Name + nodeSuffix, Namespace: testNamespace,
					Labels: map[string]string{
						labelAppManagedBy: managedByOperatorValue, labelTier: tierStorage, labelCluster: cluster.Name,
					},
				},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
					Zone:       testNodeZone,
					Capacity:   &capacity,
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
						Data:     &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("10Gi"))},
					},
				},
			}
			if mutate != nil {
				mutate(&node.Spec)
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			DeferCleanup(func() {
				n := &garagev1beta1.GarageNode{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(node), n); err == nil {
					n.Finalizers = nil
					_ = k8sClient.Update(ctx, n)
					_ = k8sClient.Delete(ctx, n)
				}
				_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: node.Name, Namespace: testNamespace}})
				_ = k8sClient.DeleteAllOf(ctx, &corev1.PersistentVolumeClaim{}, client.InNamespace(testNamespace), client.MatchingLabels{labelGarageNode: node.Name})
			})
			return node
		}
		nodeReconciler := func() *GarageNodeReconciler {
			return &GarageNodeReconciler{Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme()}
		}
		stsFor := func(node *garagev1beta1.GarageNode) *appsv1.StatefulSet {
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(node), sts)).To(Succeed())
			return sts
		}

		BeforeEach(func() {
			cluster = &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName("extras-node"), Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
					Storage: &garagev1beta2.StorageSpec{
						Replicas:    1,
						Metadata:    &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
						Data:        &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("10Gi"))},
						PodTemplate: extrasTemplate(),
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			Expect(publishTestClusterConfig(ctx, k8sClient, cluster)).To(Succeed())
			DeferCleanup(func() { extrasForceDeleteCluster(cluster.Name) })
		})

		It("inherits the tier's extras when the node sets none", func() {
			node := newNode(nil)
			Expect(nodeReconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			spec := stsFor(node).Spec.Template.Spec
			Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName, extrasSidecarName}))
			Expect(extrasContainerNames(spec.InitContainers)).To(ContainElement(extrasInitName))
			Expect(extrasVolumeNames(spec.Volumes)).To(ContainElement(extrasVolumeName))
		})

		It("replaces only the lists the node sets", func() {
			node := newNode(func(spec *garagev1beta1.GarageNodeSpec) {
				spec.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("node-only", extrasVolumeName)})
			})
			Expect(nodeReconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			spec := stsFor(node).Spec.Template.Spec
			Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName, "node-only"}),
				"the node's extraContainers replace the tier's")
			Expect(extrasContainerNames(spec.InitContainers)).To(ContainElement(extrasInitName),
				"initContainers stay inherited: the three lists are independent")
			Expect(extrasVolumeNames(spec.Volumes)).To(ContainElement(extrasVolumeName))
		})

		It("lets an explicit empty list opt the node out of that list", func() {
			node := newNode(nil)
			// A typed client drops empty slices under omitempty, so write the
			// explicit [] the way a manifest would.
			patch := []byte(`{"spec":{"extraContainers":[]}}`)
			Expect(k8sClient.Patch(ctx, node, client.RawPatch(types.MergePatchType, patch))).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(node), node)).To(Succeed())
			Expect(node.Spec.ExtraContainers).NotTo(BeNil())
			Expect(node.Spec.ExtraContainers).To(BeEmpty())

			Expect(nodeReconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			spec := stsFor(node).Spec.Template.Spec
			Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName}))
			Expect(extrasContainerNames(spec.InitContainers)).To(ContainElement(extrasInitName))
		})

		It("fails the node reconcile without touching the StatefulSet when the merged extras are invalid", func() {
			node := newNode(nil)
			Expect(nodeReconciler().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			before := stsFor(node)

			patch := []byte(`{"spec":{"extraContainers":[` + extrasTypoJSON + `]}}`)
			Expect(k8sClient.Patch(ctx, node, client.RawPatch(types.MergePatchType, patch))).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(node), node)).To(Succeed())

			err := nodeReconciler().reconcileStatefulSet(ctx, node, cluster)
			_, ok := asPodExtrasError(err)
			Expect(ok).To(BeTrue(), "got %v", err)
			Expect(stsFor(node).ResourceVersion).To(Equal(before.ResourceVersion))
		})
	})

	Context("node-local pool DaemonSet", func() {
		It("renders the pool's extras next to the garage container", func() {
			layoutHistory := &garage.LayoutHistoryResponse{
				CurrentVersion: 1,
				Versions:       []garage.LayoutVersion{{Version: 1, Status: garage.LayoutVersionStatusCurrent, StorageNodes: 1}},
			}
			r := &GarageClusterReconciler{
				Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme(), ClusterScoped: true,
				NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
				layoutHistoryGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
					return layoutHistory, nil
				},
				nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
					return &garage.ClusterLayout{}, nil
				},
			}
			capacity := resource.MustParse("500Gi")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName("extras-pool"), Namespace: testNamespace},
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
							Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/meta"},
							Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: daemonSetTestDataHostPath},
							Network:  &garagev1beta2.NodeLocalPoolNetworkSpec{RPCPublicAddrTemplate: daemonSetTestRPCAddress},
							PodTemplate: &garagev1beta2.NodeLocalPoolPodTemplate{
								InitContainers:  garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(extrasInitName)}),
								ExtraContainers: garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(extrasSidecarName, extrasVolumeName)}),
								ExtraVolumes:    garagev1beta2.NewPodExtraVolumes([]corev1.Volume{extrasEmptyDir(extrasVolumeName)}),
							},
						}},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster)).To(Succeed())
			DeferCleanup(func() { extrasForceDeleteCluster(cluster.Name) })

			k8sNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name:   uniqueClusterName(cluster.Name + "-worker"),
				Labels: map[string]string{daemonSetTestNodeLabel: daemonSetTestNodeLocalPoolName},
			}}
			Expect(k8sClient.Create(ctx, k8sNode)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, k8sNode) })

			Expect(r.reconcileNodeLocalPools(ctx, cluster, map[string]string{daemonSetTestNodeLocalPoolName: "cfg"})).To(Succeed())
			ds := &appsv1.DaemonSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: storageDaemonSetName(cluster, daemonSetTestNodeLocalPoolName), Namespace: testNamespace,
			}, ds)).To(Succeed())
			spec := ds.Spec.Template.Spec
			Expect(extrasContainerNames(spec.Containers)).To(Equal([]string{defaultAppName, extrasSidecarName}))
			Expect(extrasContainerNames(spec.InitContainers)).To(ContainElement(extrasInitName))
			Expect(extrasVolumeNames(spec.Volumes)).To(ContainElement(extrasVolumeName))
		})
	})
})

// These specs run against the real generated CRDs without webhooks: they pin the
// schema (wrapper marker, preserve-unknown-fields, list-map keys, CEL).
var _ = Describe("pod extras: CRD schema (#441)", func() {
	create := func(prefix string, mutate func(*garagev1beta2.GarageCluster)) error {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueClusterName(prefix), Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
				},
			},
		}
		mutate(cluster)
		err := k8sClient.Create(ctx, cluster)
		if err == nil {
			DeferCleanup(func() { extrasForceDeleteCluster(cluster.Name) })
		}
		return err
	}
	many := func(n int) []garagev1beta2.PodExtraContainer {
		out := make([]garagev1beta2.PodExtraContainer, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, garagev1beta2.NewPodExtraContainer(extrasSidecar(fmt.Sprintf("c%d", i))))
		}
		return out
	}

	It("accepts valid extras on the storage tier, an unknown field, and the same names across tiers", func() {
		Expect(create("crd-ok", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.PodTemplate = extrasTemplate()
		})).To(Succeed())
		Expect(create("crd-unknown", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = []garagev1beta2.PodExtraContainer{extrasRaw(extrasTypoJSON)}
		})).To(Succeed(), "unknown fields are preserved; the webhook and controller are strict")
	})

	DescribeTable("rejects at the schema",
		func(mutate func(*garagev1beta2.GarageCluster), want string) {
			err := create("crd-bad", mutate)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got %v", err)
			Expect(err.Error()).To(ContainSubstring(want))
		},
		Entry("reserved container name", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(defaultAppName)})
		}, "reserved"),
		Entry("operator-prefixed container name", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("garage-operator-x")})
		}, "reserved"),
		Entry("non-DNS-1123 container name", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("Bad_Name")})
		}, "should match"),
		Entry("duplicate container name in one list", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("dup"), extrasSidecar("dup")})
		}, "Duplicate"),
		Entry("same name in initContainers and extraContainers", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.InitContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("dup")})
			c.Spec.Storage.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("dup")})
		}, "unique"),
		Entry("volume named metadata", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraVolumes = garagev1beta2.NewPodExtraVolumes([]corev1.Volume{extrasEmptyDir(metadataVolName)})
		}, "reserved"),
		Entry("volume named data-3", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraVolumes = garagev1beta2.NewPodExtraVolumes([]corev1.Volume{extrasEmptyDir("data-3")})
		}, "reserved"),
		Entry("17 extra containers", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = many(17)
		}, "16"),
	)

	It("accepts a volume named like a data volume prefix but not an operator volume", func() {
		Expect(create("crd-data-x", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraVolumes = garagev1beta2.NewPodExtraVolumes([]corev1.Volume{extrasEmptyDir("data-x")})
		})).To(Succeed())
	})

	It("accepts 16 extra containers", func() {
		Expect(create("crd-16", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage.ExtraContainers = many(16)
		})).To(Succeed())
	})

	It("applies the same rules to gateway, node-local pool and GarageNode specs", func() {
		Expect(create("crd-gw", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage = nil
			c.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{BootstrapPeers: []string{testBootstrapPeer}}
			c.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1, PodTemplate: extrasTemplate()}
		})).To(Succeed())
		err := create("crd-gw-bad", func(c *garagev1beta2.GarageCluster) {
			c.Spec.Storage = nil
			c.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{BootstrapPeers: []string{testBootstrapPeer}}
			c.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1}
			c.Spec.Gateway.ExtraContainers = garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(defaultAppName)})
		})
		Expect(err).To(HaveOccurred())

		capacity := resource.MustParse("500Gi")
		pool := func(tpl *garagev1beta2.NodeLocalPoolPodTemplate) func(*garagev1beta2.GarageCluster) {
			return func(c *garagev1beta2.GarageCluster) {
				c.Spec.Storage.NodeLocalPools = []garagev1beta2.NodeLocalPoolSpec{{
					Name:        "p",
					Selector:    metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					Capacity:    &capacity,
					Metadata:    &garagev1beta2.HostPathVolumeConfig{HostPath: "/m"},
					Data:        &garagev1beta2.HostPathVolumeConfig{HostPath: "/d"},
					Network:     &garagev1beta2.NodeLocalPoolNetworkSpec{RPCPublicAddrTemplate: daemonSetTestRPCAddress},
					PodTemplate: tpl,
				}}
			}
		}
		Expect(create("crd-pool", pool(&garagev1beta2.NodeLocalPoolPodTemplate{
			ExtraContainers: garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("ok")}),
		}))).To(Succeed())
		Expect(create("crd-pool-bad", pool(&garagev1beta2.NodeLocalPoolPodTemplate{
			ExtraContainers: garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(defaultAppName)}),
		}))).NotTo(Succeed())

		node := func(name string, extra []garagev1beta2.PodExtraContainer) *garagev1beta1.GarageNode {
			cp := resource.MustParse("100Gi")
			return &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef:      garagev1beta1.ClusterReference{Name: "x"},
					Zone:            testNodeZone,
					Capacity:        &cp,
					ExtraContainers: extra,
				},
			}
		}
		good := node(uniqueClusterName("crd-node"), garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar("ok")}))
		Expect(k8sClient.Create(ctx, good)).To(Succeed())
		DeferCleanup(func() {
			good.Finalizers = nil
			_ = k8sClient.Delete(ctx, good)
		})
		bad := node(uniqueClusterName("crd-node-bad"), garagev1beta2.NewPodExtraContainers([]corev1.Container{extrasSidecar(defaultAppName)}))
		Expect(k8sClient.Create(ctx, bad)).NotTo(Succeed())
	})
})
