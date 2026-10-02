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

package v1beta2

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	vacFast = "fast-pool-3"
	vacSlow = "slow-pool-1"
)

func vacCluster(replicas int32) *GarageCluster {
	q := func(v string) *resource.Quantity { r := resource.MustParse(v); return &r }
	return &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "vac", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: replicas,
				Metadata: &VolumeConfig{Size: q("1Gi"), VolumeAttributesClassName: ptr.To(vacFast)},
				Data:     &VolumeConfig{Size: q("10Gi"), VolumeAttributesClassName: ptr.To(vacFast), Paths: nil},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
}

func vacClusterWithPaths() *GarageCluster {
	q := func(v string) *resource.Quantity { r := resource.MustParse(v); return &r }
	c := vacCluster(1)
	c.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{{
		Path:     "/data/fast",
		Capacity: q("10Gi"),
		Volume:   &DataPathVolumeConfig{Size: q("10Gi"), VolumeAttributesClassName: ptr.To(vacFast)},
	}}}
	return c
}

func TestVolumeAttributesClass_CreateAcceptedOnEveryCarrier(t *testing.T) {
	q := resource.MustParse("1Gi")
	cases := map[string]*GarageCluster{
		"metadata and data": vacCluster(1),
		"data paths":        vacClusterWithPaths(),
		"gateway metadata": func() *GarageCluster {
			c := vacCluster(1)
			c.Spec.Gateway = &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &q, VolumeAttributesClassName: ptr.To(vacFast)}}
			return c
		}(),
		"edge gateway metadata": {
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Gateway:     &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &q, VolumeAttributesClassName: ptr.To(vacFast)}},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		},
	}
	for name, cluster := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), cluster); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestVolumeAttributesClass_CreateRejections(t *testing.T) {
	t.Run("EmptyDir metadata", func(t *testing.T) {
		c := vacCluster(1)
		c.Spec.Storage.Metadata.Type = VolumeTypeEmptyDir
		c.Spec.Storage.Metadata.Size = nil
		if _, err := c.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName: not allowed with EmptyDir") {
			t.Fatalf("EmptyDir + class accepted: %v", err)
		}
	})
	t.Run("EmptyDir data path", func(t *testing.T) {
		c := vacClusterWithPaths()
		c.Spec.Storage.Data.Paths[0].Volume.Type = VolumeTypeEmptyDir
		c.Spec.Storage.Data.Paths[0].Volume.Size = nil
		if _, err := c.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName: not allowed with EmptyDir") {
			t.Fatalf("EmptyDir path + class accepted: %v", err)
		}
	})
	t.Run("claim template stays rejected even with a class inside it", func(t *testing.T) {
		c := vacCluster(1)
		c.Spec.Storage.Data.VolumeClaimTemplateSpec = &corev1.PersistentVolumeClaimSpec{VolumeAttributesClassName: ptr.To(vacFast)}
		if _, err := c.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
			t.Fatalf("claim template carrying a class accepted: %v", err)
		}
	})
}

func TestVolumeAttributesClass_SelectorProducesWarning(t *testing.T) {
	c := vacCluster(1)
	c.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testOldValue}}
	warnings, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), c)
	if err != nil {
		t.Fatalf("selector + class must be a warning, not an error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "spec.storage.data sets both selector and volumeAttributesClassName") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing selector warning in %v", warnings)
	}
	if got := volumeAttributesClassWarnings(vacCluster(1)); len(got) != 0 {
		t.Fatalf("unexpected warnings without a selector: %v", got)
	}
}

func TestVolumeAttributesClass_LiveUpdateRules(t *testing.T) {
	updateErr := func(old, newer *GarageCluster) error {
		_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer)
		return err
	}
	t.Run("change while live is allowed", func(t *testing.T) {
		old := vacCluster(1)
		newer := old.DeepCopy()
		newer.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To(vacSlow)
		newer.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(vacSlow)
		if err := updateErr(old, newer); err != nil {
			t.Fatalf("live class change rejected: %v", err)
		}
	})
	t.Run("unset to set while live is allowed", func(t *testing.T) {
		old := vacCluster(1)
		old.Spec.Storage.Data.VolumeAttributesClassName = nil
		newer := old.DeepCopy()
		newer.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(vacFast)
		if err := updateErr(old, newer); err != nil {
			t.Fatalf("adopting a class on a live volume rejected: %v", err)
		}
	})
	t.Run("set to unset while live is rejected", func(t *testing.T) {
		for _, field := range []string{"metadata", "data"} {
			old := vacCluster(1)
			newer := old.DeepCopy()
			if field == "metadata" {
				newer.Spec.Storage.Metadata.VolumeAttributesClassName = nil
			} else {
				newer.Spec.Storage.Data.VolumeAttributesClassName = nil
			}
			err := updateErr(old, newer)
			if err == nil || !strings.Contains(err.Error(), "volumeAttributesClassName cannot be removed") ||
				!strings.Contains(err.Error(), "spec.storage."+field) {
				t.Fatalf("%s: live unset not rejected with the explanatory message: %v", field, err)
			}
		}
	})
	t.Run("data path change allowed and unset rejected", func(t *testing.T) {
		old := vacClusterWithPaths()
		changed := old.DeepCopy()
		changed.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName = ptr.To(vacSlow)
		if err := updateErr(old, changed); err != nil {
			t.Fatalf("live path class change rejected: %v", err)
		}
		unset := old.DeepCopy()
		unset.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName = nil
		if err := updateErr(old, unset); err == nil || !strings.Contains(err.Error(), "paths[0].volume.volumeAttributesClassName cannot be removed") {
			t.Fatalf("live path unset accepted: %v", err)
		}
	})
	t.Run("neighbouring fields stay immutable alongside a class change", func(t *testing.T) {
		old := vacCluster(1)
		newer := old.DeepCopy()
		newer.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(vacSlow)
		newer.Spec.Storage.Data.StorageClassName = ptr.To("other")
		if err := updateErr(old, newer); err == nil || !strings.Contains(err.Error(), "immutable while replicas are live") {
			t.Fatalf("storageClassName change smuggled in with a class change: %v", err)
		}
	})
	t.Run("zero replicas allows any transition", func(t *testing.T) {
		old := vacCluster(0)
		unset := old.DeepCopy()
		unset.Spec.Storage.Metadata.VolumeAttributesClassName = nil
		unset.Spec.Storage.Data.VolumeAttributesClassName = nil
		if err := updateErr(old, unset); err != nil {
			t.Fatalf("zero-replica unset rejected: %v", err)
		}
		if err := updateErr(unset, old); err != nil {
			t.Fatalf("zero-replica set rejected: %v", err)
		}
	})
	t.Run("N to zero cannot combine with removal", func(t *testing.T) {
		old := vacCluster(1)
		newer := old.DeepCopy()
		newer.Spec.Storage.Replicas = 0
		newer.Spec.Storage.Data.VolumeAttributesClassName = nil
		if err := validateDefaultPoolVolumeUpdate(old, newer); err == nil {
			t.Fatalf("combined scale-to-zero and class removal accepted")
		}
	})
	t.Run("manual layout ignores cluster-level volumes", func(t *testing.T) {
		old := vacCluster(1)
		old.Spec.LayoutPolicy = layoutPolicyManual
		newer := old.DeepCopy()
		newer.Spec.Storage.Data.VolumeAttributesClassName = nil
		if err := validateDefaultPoolVolumeUpdate(old, newer); err != nil {
			t.Fatalf("manual-layout cluster volumes are ignored, yet unset rejected: %v", err)
		}
	})
}

func TestVolumeAttributesClass_GatewayLiveUpdateRules(t *testing.T) {
	q := resource.MustParse("1Gi")
	edge := func(class *string) *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Gateway:     &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &q, VolumeAttributesClassName: class}},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	update := func(old, newer *GarageCluster) error {
		_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer)
		return err
	}
	// The edge-gateway "metadata cannot change while live" rule must not fire
	// for a class change.
	if err := update(edge(ptr.To(vacFast)), edge(ptr.To(vacSlow))); err != nil {
		t.Fatalf("live edge gateway class change blocked: %v", err)
	}
	if err := update(edge(nil), edge(ptr.To(vacFast))); err != nil {
		t.Fatalf("live edge gateway class adoption blocked: %v", err)
	}
	if err := update(edge(ptr.To(vacFast)), edge(nil)); err == nil || !strings.Contains(err.Error(), "cannot be removed") {
		t.Fatalf("live edge gateway class removal accepted: %v", err)
	}
	// A real metadata change next to the class change is still blocked.
	twoGi := resource.MustParse("2Gi")
	changed := edge(ptr.To(vacSlow))
	changed.Spec.Gateway.Metadata.Size = &twoGi
	if err := update(edge(ptr.To(vacFast)), changed); err == nil || !strings.Contains(err.Error(), "scale spec.gateway.replicas to 0") {
		t.Fatalf("size change riding along a class change not blocked: %v", err)
	}

	// Unified gateway.
	unified := func(class *string) *GarageCluster {
		c := vacCluster(1)
		c.Spec.Gateway = &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &q, VolumeAttributesClassName: class}}
		return c
	}
	if err := update(unified(ptr.To(vacFast)), unified(ptr.To(vacSlow))); err != nil {
		t.Fatalf("live unified gateway class change blocked: %v", err)
	}
	if err := update(unified(ptr.To(vacFast)), unified(nil)); err == nil || !strings.Contains(err.Error(), "spec.gateway.metadata.volumeAttributesClassName cannot be removed") {
		t.Fatalf("live unified gateway class removal accepted: %v", err)
	}
}

func TestVolumeAttributesClass_TopLevelDataClassIsIgnoredWithPaths(t *testing.T) {
	c := vacClusterWithPaths()
	c.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(vacFast)
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
