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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestCycleFinalizationSkipsRetainedPVCHandoff(t *testing.T) {
	ctx := context.Background()
	scheme := managedPVCTestScheme(t)
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "default", UID: "cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
			},
		},
	}
	oldNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "store-storage-0", Namespace: "default", UID: "old-node-uid",
			Labels: map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierStorage,
				labelAppManagedBy: managedByOperatorValue,
				labelAutoNodeSlot: "store-storage-0",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(),
				Kind:       kindGarageCluster,
				Name:       cluster.Name,
				UID:        cluster.UID,
				Controller: &controller,
			}},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Capacity:   ptrQuantity(resource.MustParse("10Gi")),
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:           "old-garage-node-id",
			CyclePhase:       garagev1beta1.CyclePhaseDraining,
			CycleSiblingName: "store-storage-0-cycle",
			ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
				Name: "metadata-store-storage-0-0", UID: "metadata-pvc-uid",
			}},
		},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-store-storage-0-0", Namespace: "default", UID: "metadata-pvc-uid",
		Annotations: map[string]string{managedPVCNodeUIDAnnotation: string(oldNode.UID)},
	}}
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
		WithObjects(cluster, oldNode, claim).Build()

	nodeReconciler := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}
	if err := nodeReconciler.prepareAutoModePVCHandoffBeforeFinalization(ctx, oldNode, cluster); err != nil {
		t.Fatalf("cycle finalization handoff prepare: %v", err)
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		t.Fatal(err)
	}
	if len(freshCluster.Status.AutoModePVCHandoffs) != 0 {
		t.Fatalf("cycle finalization must not publish retained PVC handoffs (#541): got %#v", freshCluster.Status.AutoModePVCHandoffs)
	}
}

func TestReconcileClearsUnreservedCyclePVCHandoff(t *testing.T) {
	ctx := context.Background()
	scheme := managedPVCTestScheme(t)
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "default", UID: "cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
			},
		},
		Status: garagev1beta2.GarageClusterStatus{
			AutoModePVCHandoffs: []garagev1beta2.AutoModePVCHandoffStatus{{
				SlotName:              "store-storage-0",
				PVCName:               "metadata-store-storage-0-0",
				PVCUID:                "metadata-pvc-uid",
				PreviousGarageNodeUID: "old-node-uid",
				// No ReplacementReservationHash: the cycle sibling was promoted
				// without going through reserveAutoModeReplacement.
			}},
		},
	}
	sibling := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "store-storage-0", Namespace: "default", UID: "sibling-uid",
			Labels: map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierStorage,
				labelAppManagedBy: managedByOperatorValue,
				labelAutoNodeSlot: "store-storage-0",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(),
				Kind:       kindGarageCluster,
				Name:       cluster.Name,
				UID:        cluster.UID,
				Controller: &controller,
			}},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Capacity:   ptrQuantity(resource.MustParse("10Gi")),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
		WithObjects(cluster, sibling).Build()
	clusterReconciler := &GarageClusterReconciler{Client: fc, APIReader: fc, Scheme: scheme}
	changed, err := clusterReconciler.reconcileCurrentAutoModePVCHandoffs(ctx, cluster, sibling, "store-storage-0")
	if err != nil {
		t.Fatalf("clearing unreserved cycle handoff: %v", err)
	}
	if !changed {
		t.Fatal("expected handoff clear")
	}
	fresh := &garagev1beta2.GarageCluster{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Status.AutoModePVCHandoffs) != 0 {
		t.Fatalf("unreserved cycle handoff must clear (#541): got %#v", fresh.Status.AutoModePVCHandoffs)
	}
}
