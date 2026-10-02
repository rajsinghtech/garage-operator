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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func vacV1Beta1Cluster(replicas int32) *GarageCluster {
	return &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "vac", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: replicas, LayoutPolicy: layoutPolicyAuto,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: mustQty("1Gi"), VolumeAttributesClassName: ptr.To(testVACMetadata)},
				Data:     &VolumeConfig{Size: mustQty("10Gi"), VolumeAttributesClassName: ptr.To(testVACData)},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
}

func vacV1Beta1EdgeGateway(class *string) *GarageCluster {
	return &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Gateway: true, Replicas: 1,
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStoreCR}},
			Storage:     StorageConfig{Metadata: &VolumeConfig{Size: mustQty("1Gi"), VolumeAttributesClassName: class}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
}

func TestV1Beta1VolumeAttributesClass_ClusterCreate(t *testing.T) {
	validator := &GarageClusterValidator{}
	if _, err := validator.ValidateCreate(context.Background(), vacV1Beta1Cluster(1)); err != nil {
		t.Fatalf("metadata+data class rejected: %v", err)
	}
	withPaths := vacV1Beta1Cluster(1)
	withPaths.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{{
		Path: "/data/fast", Capacity: mustQty("10Gi"),
		Volume: &DataPathVolumeConfig{Size: mustQty("10Gi"), VolumeAttributesClassName: ptr.To(testVACPath)},
	}}}
	if _, err := validator.ValidateCreate(context.Background(), withPaths); err != nil {
		t.Fatalf("data path class rejected: %v", err)
	}
	if _, err := validator.ValidateCreate(context.Background(), vacV1Beta1EdgeGateway(ptr.To(testVACGateway))); err != nil {
		t.Fatalf("edge gateway metadata class rejected: %v", err)
	}

	emptyDir := vacV1Beta1Cluster(1)
	emptyDir.Spec.Storage.Metadata.Type = VolumeTypeEmptyDir
	emptyDir.Spec.Storage.Metadata.Size = nil
	if _, err := validator.ValidateCreate(context.Background(), emptyDir); err == nil ||
		!strings.Contains(err.Error(), "volumeAttributesClassName: not allowed with EmptyDir") {
		t.Fatalf("EmptyDir + class accepted: %v", err)
	}
	emptyPath := vacV1Beta1Cluster(1)
	emptyPath.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{{
		Path: "/data/fast", Capacity: mustQty("10Gi"),
		Volume: &DataPathVolumeConfig{Type: VolumeTypeEmptyDir, VolumeAttributesClassName: ptr.To(testVACPath)},
	}}}
	if _, err := validator.ValidateCreate(context.Background(), emptyPath); err == nil ||
		!strings.Contains(err.Error(), "volumeAttributesClassName: not allowed with EmptyDir") {
		t.Fatalf("EmptyDir path + class accepted: %v", err)
	}
	template := vacV1Beta1Cluster(1)
	template.Spec.Storage.Data.VolumeClaimTemplateSpec = &corev1.PersistentVolumeClaimSpec{VolumeAttributesClassName: ptr.To(testVACData)}
	if _, err := validator.ValidateCreate(context.Background(), template); err == nil ||
		!strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("claim template carrying a class accepted: %v", err)
	}

	withSelector := vacV1Beta1Cluster(1)
	withSelector.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}}
	warnings, err := validator.ValidateCreate(context.Background(), withSelector)
	if err != nil {
		t.Fatalf("selector + class must warn, not fail: %v", err)
	}
	found := false
	for _, w := range warnings {
		found = found || strings.Contains(w, "spec.storage.data sets both selector and volumeAttributesClassName")
	}
	if !found {
		t.Fatalf("missing selector warning: %v", warnings)
	}
}

func TestV1Beta1VolumeAttributesClass_ClusterLiveUpdate(t *testing.T) {
	update := func(old, newer *GarageCluster) error {
		_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer)
		return err
	}
	old := vacV1Beta1Cluster(1)
	changed := old.DeepCopy()
	changed.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("other-meta")
	changed.Spec.Storage.Data.VolumeAttributesClassName = ptr.To("other-data")
	if err := update(old, changed); err != nil {
		t.Fatalf("live class change rejected: %v", err)
	}

	adopt := old.DeepCopy()
	adopt.Spec.Storage.Data.VolumeAttributesClassName = nil
	if err := update(adopt, old); err != nil {
		t.Fatalf("adopting a class on a live volume rejected: %v", err)
	}

	unset := old.DeepCopy()
	unset.Spec.Storage.Data.VolumeAttributesClassName = nil
	if err := update(old, unset); err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName cannot be removed") {
		t.Fatalf("live unset accepted: %v", err)
	}

	smuggled := changed.DeepCopy()
	smuggled.Spec.Storage.Data.StorageClassName = ptr.To("other")
	if err := update(old, smuggled); err == nil || !strings.Contains(err.Error(), "immutable while replicas are live") {
		t.Fatalf("storageClassName change riding along a class change accepted: %v", err)
	}

	zero := vacV1Beta1Cluster(0)
	zeroUnset := zero.DeepCopy()
	zeroUnset.Spec.Storage.Metadata.VolumeAttributesClassName = nil
	zeroUnset.Spec.Storage.Data.VolumeAttributesClassName = nil
	if err := update(zero, zeroUnset); err != nil {
		t.Fatalf("zero-replica unset rejected: %v", err)
	}
	if err := update(zeroUnset, zero); err != nil {
		t.Fatalf("zero-replica set rejected: %v", err)
	}

	withPaths := func(class *string) *GarageCluster {
		c := vacV1Beta1Cluster(1)
		c.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{{
			Path: "/data/fast", Capacity: mustQty("10Gi"),
			Volume: &DataPathVolumeConfig{Size: mustQty("10Gi"), VolumeAttributesClassName: class},
		}}}
		return c
	}
	if err := update(withPaths(ptr.To(testVACPath)), withPaths(ptr.To("other"))); err != nil {
		t.Fatalf("live path class change rejected: %v", err)
	}
	if err := update(withPaths(ptr.To(testVACPath)), withPaths(nil)); err == nil ||
		!strings.Contains(err.Error(), "paths[0].volume.volumeAttributesClassName cannot be removed") {
		t.Fatalf("live path class removal accepted: %v", err)
	}
}

func TestV1Beta1VolumeAttributesClass_EdgeGatewayLiveUpdate(t *testing.T) {
	update := func(old, newer *GarageCluster) error {
		_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer)
		return err
	}
	if err := update(vacV1Beta1EdgeGateway(ptr.To(testVACGateway)), vacV1Beta1EdgeGateway(ptr.To("other"))); err != nil {
		t.Fatalf("live edge gateway class change blocked by the metadata-immutability rule: %v", err)
	}
	if err := update(vacV1Beta1EdgeGateway(nil), vacV1Beta1EdgeGateway(ptr.To(testVACGateway))); err != nil {
		t.Fatalf("live edge gateway class adoption rejected: %v", err)
	}
	if err := update(vacV1Beta1EdgeGateway(ptr.To(testVACGateway)), vacV1Beta1EdgeGateway(nil)); err == nil ||
		!strings.Contains(err.Error(), "cannot be removed") {
		t.Fatalf("live edge gateway class removal accepted: %v", err)
	}
	resized := vacV1Beta1EdgeGateway(ptr.To("other"))
	resized.Spec.Storage.Metadata.Size = mustQty("2Gi")
	if err := update(vacV1Beta1EdgeGateway(ptr.To(testVACGateway)), resized); err == nil ||
		!strings.Contains(err.Error(), "scale spec.replicas to 0") {
		t.Fatalf("size change riding along a class change not blocked: %v", err)
	}
}

func vacNode(class *string) *GarageNode {
	return &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testLocalZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Size: mustQty("1Gi"), VolumeAttributesClassName: class},
				Data:     &NodeVolumeConfig{Size: mustQty("100Gi"), VolumeAttributesClassName: class},
			},
		},
	}
}

func TestGarageNodeValidator_VolumeAttributesClassCreate(t *testing.T) {
	if _, err := vacNode(ptr.To(testVACData)).validateGarageNode(); err != nil {
		t.Fatalf("class on metadata/data rejected: %v", err)
	}
	paths := vacNode(nil)
	paths.Spec.Storage.Data = nil
	paths.Spec.Storage.DataPaths = []NodeVolumeConfig{{
		Path: "/data/a", Size: mustQty("100Gi"), VolumeAttributesClassName: ptr.To(testVACPath),
	}}
	if _, err := paths.validateGarageNode(); err != nil {
		t.Fatalf("class on dataPaths rejected: %v", err)
	}

	emptyDir := vacNode(nil)
	emptyDir.Spec.Storage.Data = &NodeVolumeConfig{Type: VolumeTypeEmptyDir, VolumeAttributesClassName: ptr.To(testVACData)}
	if _, err := emptyDir.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName cannot be used with type=EmptyDir") {
		t.Fatalf("EmptyDir + class accepted: %v", err)
	}
	existing := vacNode(nil)
	existing.Spec.Storage.Data = &NodeVolumeConfig{ExistingClaim: "pre-made", VolumeAttributesClassName: ptr.To(testVACData)}
	if _, err := existing.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName cannot be used with existingClaim") {
		t.Fatalf("existingClaim + class accepted: %v", err)
	}

	withSelector := vacNode(ptr.To(testVACData))
	withSelector.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}}
	warnings, err := withSelector.validateGarageNode()
	if err != nil {
		t.Fatalf("selector + class must warn, not fail: %v", err)
	}
	found := false
	for _, w := range warnings {
		found = found || strings.Contains(w, "spec.storage.data sets both selector and volumeAttributesClassName")
	}
	if !found {
		t.Fatalf("missing selector warning: %v", warnings)
	}
}

func TestGarageNodeValidator_VolumeAttributesClassIsCarvedOutOfImmutability(t *testing.T) {
	old := vacNode(ptr.To(testVACData))

	changed := old.DeepCopy()
	changed.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("other")
	changed.Spec.Storage.Data.VolumeAttributesClassName = ptr.To("other")
	if err := validateGarageNodeStorageUpdate(old, changed); err != nil {
		t.Fatalf("live class change rejected: %v", err)
	}

	adopt := vacNode(nil)
	if err := validateGarageNodeStorageUpdate(adopt, old); err != nil {
		t.Fatalf("adopting a class on a live node rejected: %v", err)
	}

	unset := old.DeepCopy()
	unset.Spec.Storage.Data.VolumeAttributesClassName = nil
	if err := validateGarageNodeStorageUpdate(old, unset); err == nil ||
		!strings.Contains(err.Error(), "storage.data.volumeAttributesClassName cannot be removed") {
		t.Fatalf("live class removal accepted: %v", err)
	}

	paths := func(class *string) *GarageNode {
		n := vacNode(nil)
		n.Spec.Storage.Data = nil
		n.Spec.Storage.DataPaths = []NodeVolumeConfig{{Path: "/data/a", Size: mustQty("100Gi"), VolumeAttributesClassName: class}}
		return n
	}
	if err := validateGarageNodeStorageUpdate(paths(ptr.To(testVACPath)), paths(ptr.To("other"))); err != nil {
		t.Fatalf("live dataPaths class change rejected: %v", err)
	}
	if err := validateGarageNodeStorageUpdate(paths(ptr.To(testVACPath)), paths(nil)); err == nil ||
		!strings.Contains(err.Error(), "storage.dataPaths[0].volumeAttributesClassName cannot be removed") {
		t.Fatalf("live dataPaths class removal accepted: %v", err)
	}

	// The neighbouring identity-bearing fields stay immutable even when the
	// class changes in the same update.
	for name, mutate := range map[string]func(*NodeVolumeConfig){
		"storageClassName": func(v *NodeVolumeConfig) { v.StorageClassName = ptr.To("other") },
		"selector": func(v *NodeVolumeConfig) {
			v.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: "b"}}
		},
		"accessModes": func(v *NodeVolumeConfig) {
			v.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := changed.DeepCopy()
			mutate(n.Spec.Storage.Data)
			if err := validateGarageNodeStorageUpdate(old, n); err == nil || !strings.Contains(err.Error(), "immutable") {
				t.Fatalf("%s change next to a class change accepted: %v", name, err)
			}
		})
	}
}

func TestV1Beta1VolumeAttributesClass_TopLevelDataClassIsIgnoredWithPaths(t *testing.T) {
	c := vacV1Beta1Cluster(1)
	c.Spec.Storage.Data = &VolumeConfig{
		VolumeAttributesClassName: ptr.To(testVACData),
		Paths: []DataPath{{
			Path: "/data/fast", Capacity: mustQty("10Gi"),
			Volume: &DataPathVolumeConfig{Size: mustQty("10Gi"), VolumeAttributesClassName: ptr.To(testVACPath)},
		}},
	}
	warnings, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), c)
	if err != nil {
		t.Fatalf("top-level class next to paths must warn, not fail: %v", err)
	}
	found := false
	for _, w := range warnings {
		found = found || strings.Contains(w, "spec.storage.data.volumeAttributesClassName is ignored")
	}
	if !found {
		t.Fatalf("missing ignored-with-paths warning: %v", warnings)
	}
}
