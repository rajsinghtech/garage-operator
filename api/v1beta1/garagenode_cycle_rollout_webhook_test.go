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

package v1beta1

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestValidateUpdateAllowsCycleCancelDuringStorageRollout(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: testWebhookNS, UID: "cluster-uid"},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				GarageNodeName: "storage-0",
				GarageNodeUID:  "node-uid",
				PreviousPodUID: "old-pod",
			},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	v := &GarageNodeValidator{apiReader: fc}

	capacity := resource.MustParse("10Gi")
	metaSize := resource.MustParse("1Gi")
	dataSize := resource.MustParse("10Gi")
	oldNode := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage-0", Namespace: testWebhookNS, UID: "node-uid",
			Annotations: map[string]string{AnnotationCycle: stringTrue},
		},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: "garage"},
			Zone:       "a",
			Capacity:   &capacity,
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Size: &metaSize},
				Data:     &NodeVolumeConfig{Size: &dataSize},
			},
		},
		Status: GarageNodeStatus{CyclePhase: CyclePhaseProvisioning},
	}
	newNode := oldNode.DeepCopy()
	delete(newNode.Annotations, AnnotationCycle)

	if _, err := v.ValidateUpdate(context.Background(), oldNode, newNode); err != nil {
		t.Fatalf("cycle cancel during storageRollout must be allowed (#536): %v", err)
	}

	// Spec edits during an active storageRollout stay frozen even without a cycle.
	frozen := oldNode.DeepCopy()
	delete(frozen.Annotations, AnnotationCycle)
	frozen.Status.CyclePhase = ""
	edited := frozen.DeepCopy()
	edited.Spec.Zone = "elsewhere"
	if _, err := v.ValidateUpdate(context.Background(), frozen, edited); err == nil {
		t.Fatal("expected spec edit during storageRollout to be refused")
	} else if !strings.Contains(err.Error(), "status.storageRollout active") {
		t.Fatalf("unexpected error: %v", err)
	}
}
