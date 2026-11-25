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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

var _ = Describe("GarageReferenceGrant & CRD Schema envtest", func() {
	It("populates status.inUseBy and InUse condition and clears them after deletion", func() {
		suffix := fmt.Sprintf("%d", time.Now().UnixNano())
		srcNS := "rg-envtest-src-" + suffix
		dstNS := "rg-envtest-dst-" + suffix

		for _, ns := range []string{srcNS, dstNS} {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: ns},
			})).To(Succeed())
			DeferCleanup(func(name string) {
				_ = k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
			}, ns)
		}

		grant := &garagev1beta1.GarageReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "grant-for-key", Namespace: dstNS},
			Spec: garagev1beta1.GarageReferenceGrantSpec{
				From: []garagev1beta1.ReferenceGrantFrom{{Kind: "GarageKey", Namespace: srcNS}},
				To:   []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster"}},
			},
		}
		Expect(k8sClient.Create(ctx, grant)).To(Succeed())

		key := &garagev1beta1.GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: "cross-ns-key", Namespace: srcNS},
			Spec: garagev1beta1.GarageKeySpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: "target-cluster", Namespace: dstNS},
			},
		}
		Expect(k8sClient.Create(ctx, key)).To(Succeed())

		r := &GarageReferenceGrantReconciler{Client: k8sClient}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: grant.Name, Namespace: dstNS}}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		var refreshed garagev1beta1.GarageReferenceGrant
		Expect(k8sClient.Get(ctx, req.NamespacedName, &refreshed)).To(Succeed())
		Expect(refreshed.Status.InUseBy).To(ContainElement(garagev1beta1.ReferenceGrantUser{
			Kind:      "GarageKey",
			Name:      "cross-ns-key",
			Namespace: srcNS,
		}))
		cond := apimeta.FindStatusCondition(refreshed.Status.Conditions, "InUse")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))

		Expect(k8sClient.Delete(ctx, key)).To(Succeed())
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, req.NamespacedName, &refreshed)).To(Succeed())
		Expect(refreshed.Status.InUseBy).To(BeEmpty())
		cond = apimeta.FindStatusCondition(refreshed.Status.Conditions, "InUse")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
	})

	It("rejects invalid GarageCluster layoutPolicy via CRD OpenAPI enum validation", func() {
		ns := fmt.Sprintf("crd-enum-envtest-%d", time.Now().UnixNano())
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		})).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
		})

		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   garagev1beta2.GroupVersion.Group,
			Version: garagev1beta2.GroupVersion.Version,
			Kind:    "GarageCluster",
		})
		u.SetName("invalid-cluster")
		u.SetNamespace(ns)
		u.Object["spec"] = map[string]any{
			"layoutPolicy": "InvalidPolicy",
			"replication":  map[string]any{"factor": int64(3)},
			"storage": map[string]any{
				"replicas": int64(1),
				"metadata": map[string]any{"size": "1Gi"},
				"data":     map[string]any{"size": "1Gi"},
			},
		}

		err := k8sClient.Create(ctx, u)
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("layoutpolicy"))
	})
})
