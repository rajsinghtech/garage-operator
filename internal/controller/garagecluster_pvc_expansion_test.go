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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestReconcileStoragePVCExpansionCondition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: "ns", UID: "cluster-uid", Generation: 3},
	}
	failing := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "garage-storage-0", Namespace: "ns",
			Labels: map[string]string{labelCluster: "garage"},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage"},
		},
		Status: garagev1beta1.GarageNodeStatus{
			Conditions: []metav1.Condition{{
				Type:    garagev1beta1.ConditionPVCExpansionFailed,
				Status:  metav1.ConditionTrue,
				Reason:  garagev1beta1.ReasonPVCExpansionRejected,
				Message: "data-garage-storage-0-0: expansion forbidden",
			}},
		},
	}
	ok := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "garage-storage-1", Namespace: "ns",
			Labels: map[string]string{labelCluster: "garage"},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage"},
		},
	}

	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).
		WithObjects(cluster, failing, ok).Build()
	r := &GarageClusterReconciler{Client: fc, Scheme: scheme}

	ctx := context.Background()
	if err := r.reconcileStoragePVCExpansionCondition(ctx, cluster); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	live := &garagev1beta2.GarageCluster{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), live); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(live.Status.Conditions, garagev1beta1.ConditionStoragePVCExpansionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse {
		t.Fatalf("want StoragePVCExpansionReady=False, got %#v", condition)
	}
	if condition.Reason != garagev1beta1.ReasonPVCExpansionRejected {
		t.Fatalf("reason = %q", condition.Reason)
	}
	if !strings.Contains(condition.Message, "garage-storage-0") || !strings.Contains(condition.Message, "expansion forbidden") {
		t.Fatalf("message = %q", condition.Message)
	}

	// Clear the node failure → aggregate condition is removed.
	liveNode := &garagev1beta1.GarageNode{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(failing), liveNode); err != nil {
		t.Fatal(err)
	}
	meta.RemoveStatusCondition(&liveNode.Status.Conditions, garagev1beta1.ConditionPVCExpansionFailed)
	if err := fc.Status().Update(ctx, liveNode); err != nil {
		t.Fatal(err)
	}
	if err := r.reconcileStoragePVCExpansionCondition(ctx, live); err != nil {
		t.Fatalf("clear aggregate: %v", err)
	}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), live); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(live.Status.Conditions, garagev1beta1.ConditionStoragePVCExpansionReady); got != nil {
		t.Fatalf("expected aggregate cleared, got %#v", got)
	}
}
