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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// An STS created by an older operator carries an immutable selector with a
// different label scheme; an in-place Update fails forever ("selector does not
// match template labels"). reconcileStatefulSet must heal it by orphan-recreate.
var _ = Describe("reconcileStatefulSet heals an immutable-selector mismatch (orphan-recreate)", func() {
	const (
		clusterName = "sel-heal-cluster"
		nodeName    = "sel-heal-node"
	)
	r := func() *GarageNodeReconciler {
		return &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	}

	AfterEach(func() {
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace}})
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
	})

	It("orphan-deletes the old-scheme STS and recreates it with the current selector", func() {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		capacity := resource.MustParse("10Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
				Zone:       testNodeZone,
				Capacity:   &capacity,
				Storage:    &garagev1beta1.NodeStorageConfig{Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))}},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		// Pre-create an STS with the OLD operator's selector scheme.
		oldSelector := map[string]string{
			labelAppName:     "garagenode",
			labelAppInstance: nodeName,
			labelGarageNode:  nodeName,
		}
		one := int32(1)
		oldSTS := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: clusterName + "-headless",
				Replicas:    &one,
				Selector:    &metav1.LabelSelector{MatchLabels: oldSelector},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: oldSelector},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "garage", Image: "dxflrs/garage:test"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, oldSTS)).To(Succeed())

		By("first reconcile detects the immutable-selector mismatch and orphan-deletes the STS")
		Expect(r().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
		// envtest has no garbage collector, so the Orphan delete leaves the STS
		// terminating with the apiserver's "orphan" finalizer (in a real cluster
		// the GC orphans the pod and removes it). Confirm the delete was issued,
		// then simulate the GC so the recreate path can run.
		sts := &appsv1.StatefulSet{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, sts)).To(Succeed())
			g.Expect(sts.DeletionTimestamp).NotTo(BeNil(), "orphan-delete should have been issued")
		}).Should(Succeed())
		sts.Finalizers = nil
		_ = k8sClient.Update(ctx, sts)
		Eventually(func() bool {
			err := k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, &appsv1.StatefulSet{})
			return apierrors.IsNotFound(err)
		}).Should(BeTrue(), "old-scheme STS should be gone after GC")

		By("subsequent reconcile recreates the STS with the CURRENT selector scheme")
		Eventually(func(g Gomega) {
			g.Expect(r().reconcileStatefulSet(ctx, node, cluster)).To(Succeed())
			sts := &appsv1.StatefulSet{}
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: testNamespace}, sts)).To(Succeed())
			g.Expect(sts.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelAppManagedBy, operatorName))
			g.Expect(sts.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelGarageNode, nodeName))
			// the old node-scoped instance/name keys are gone from the selector
			g.Expect(sts.Spec.Selector.MatchLabels).NotTo(HaveKey(labelAppName))
		}).Should(Succeed())
	})
})
