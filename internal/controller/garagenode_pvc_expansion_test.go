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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestExpandNodePVCsSetsPVCExpansionFailed(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	const ns, nodeName, nodeUID = "default", "expand-node", "expand-node-uid"
	mkPVC := func(name, size string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: ns, UID: types.UID(name + "-uid"),
				Labels: map[string]string{
					labelAppManagedBy: operatorName, labelAppComponent: "node",
					labelGarageNode: nodeName, labelCluster: "expand-cluster",
				},
				Annotations: map[string]string{managedPVCNodeUIDAnnotation: nodeUID},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)},
				},
			},
		}
	}

	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "expand-cluster", Namespace: ns}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		mkPVC("metadata-"+nodeName+"-0", "1Gi"),
		mkPVC("data-"+nodeName+"-0", "10Gi"),
	).WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()
	fc := interceptor.NewClient(base, interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if pvc, ok := obj.(*corev1.PersistentVolumeClaim); ok && pvc.Name == "data-"+nodeName+"-0" {
				want := resource.MustParse("50Gi")
				if cur, has := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; has && cur.Cmp(want) == 0 {
					return apierrors.NewForbidden(
						corev1.Resource("persistentvolumeclaims"), pvc.Name,
						fmt.Errorf("only dynamically provisioned pvc can be resized and the storageclass that provisions the pvc must support resize"),
					)
				}
			}
			return c.Update(ctx, obj, opts...)
		},
	})
	r := &GarageNodeReconciler{Client: fc, Scheme: scheme}
	ctx := context.Background()

	newData := resource.MustParse("50Gi")
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: ns, UID: nodeUID},
		Spec: garagev1beta1.GarageNodeSpec{
			Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
				Data:     &garagev1beta1.NodeVolumeConfig{Size: &newData},
			},
		},
	}
	if err := fc.Create(ctx, node); err != nil {
		t.Fatal(err)
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: node.Name, Namespace: ns, UID: types.UID(node.Name + "-sts")},
		Spec:       appsv1.StatefulSetSpec{VolumeClaimTemplates: r.buildNodeVolumeClaimTemplates(node, cluster)},
	}
	if err := controllerutil.SetControllerReference(node, sts, scheme); err != nil {
		t.Fatal(err)
	}
	if err := fc.Create(ctx, sts); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: node.Name + "-0", Namespace: ns, UID: "pod-uid"}}
	for i := range sts.Spec.VolumeClaimTemplates {
		claimName := fmt.Sprintf("%s-%s-0", sts.Spec.VolumeClaimTemplates[i].Name, sts.Name)
		node.Status.ManagedPVCs = append(node.Status.ManagedPVCs, garagev1beta1.ManagedNodePVCStatus{
			Name: claimName, UID: types.UID(claimName + "-uid"),
		})
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: sts.Spec.VolumeClaimTemplates[i].Name,
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: claimName,
			}},
		})
	}
	if err := controllerutil.SetControllerReference(sts, pod, scheme); err != nil {
		t.Fatal(err)
	}
	if err := fc.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}

	if err := r.expandNodePVCs(ctx, node, cluster); err != nil {
		t.Fatalf("expandNodePVCs: %v", err)
	}
	fresh := &garagev1beta1.GarageNode{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionPVCExpansionFailed)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("want PVCExpansionFailed=True, got %#v", condition)
	}
	if condition.Reason != garagev1beta1.ReasonPVCExpansionRejected {
		t.Fatalf("reason = %q", condition.Reason)
	}
	if !strings.Contains(condition.Message, "data-"+nodeName+"-0") || !strings.Contains(condition.Message, "support resize") {
		t.Fatalf("message = %q", condition.Message)
	}

	node.Spec.Storage.Data.Size = ptr.To(resource.MustParse("10Gi"))
	if err := r.expandNodePVCs(ctx, node, cluster); err != nil {
		t.Fatalf("clear expand: %v", err)
	}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
		t.Fatal(err)
	}
	if got := meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionPVCExpansionFailed); got != nil {
		t.Fatalf("expected condition cleared, got %#v", got)
	}
}
