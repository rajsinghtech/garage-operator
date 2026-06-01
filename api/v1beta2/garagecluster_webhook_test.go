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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testNamespace = "default"

func TestGarageClusterDefaulter_PreservesExplicitZeroReplicas(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "zero-replicas", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
			},
			Gateway: &GatewaySpec{
				Replicas: 0,
			},
		},
	}

	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}

	if cluster.Spec.Storage.Replicas != 0 {
		t.Fatalf("storage replicas defaulted to %d, want explicit 0 preserved", cluster.Spec.Storage.Replicas)
	}
	if cluster.Spec.Gateway.Replicas != 0 {
		t.Fatalf("gateway replicas defaulted to %d, want explicit 0 preserved", cluster.Spec.Gateway.Replicas)
	}
}

func TestGarageClusterValidator_AllowsZeroReplicas(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "zero-replicas", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Gateway: &GatewaySpec{
				Replicas: 0,
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("validateGarageCluster rejected zero replicas: %v", err)
	}
}

func TestGarageClusterValidator_RejectsManualToAutoTransition(t *testing.T) {
	v := &GarageClusterValidator{}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tx", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			LayoutPolicy: "Manual",
			Storage: &StorageSpec{
				Replicas: 1,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	newer := old.DeepCopy()
	newer.Spec.LayoutPolicy = "Auto"

	if _, err := v.ValidateUpdate(context.Background(), old, newer); err == nil {
		t.Fatalf("ValidateUpdate accepted Manual→Auto transition, want error")
	}

	// Manual→Manual (or Manual with empty new) is fine.
	sameManual := old.DeepCopy()
	if _, err := v.ValidateUpdate(context.Background(), old, sameManual); err != nil {
		t.Fatalf("ValidateUpdate rejected Manual→Manual: %v", err)
	}
}

func TestGarageClusterValidator_AllowsAutoToManualTransition(t *testing.T) {
	v := &GarageClusterValidator{}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tx", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			LayoutPolicy: "Auto",
			Storage: &StorageSpec{
				Replicas: 1,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	newer := old.DeepCopy()
	newer.Spec.LayoutPolicy = "Manual"

	if _, err := v.ValidateUpdate(context.Background(), old, newer); err != nil {
		t.Fatalf("ValidateUpdate rejected Auto→Manual: %v", err)
	}
}

func TestGarageClusterValidator_RejectsMinNodesHealthyWhenAllReplicasPaused(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "paused", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication:      &ReplicationConfig{Factor: 1},
			LayoutManagement: &LayoutManagementConfig{MinNodesHealthy: 1},
		},
	}

	if err := cluster.validateLayoutManagement(); err == nil {
		t.Fatalf("validateLayoutManagement accepted minNodesHealthy with zero replicas")
	}
}

// TestGarageClusterValidator_RejectsGatewayMetadataEmptyDirMisconfig verifies
// the gateway-tier metadata VolumeConfig is now validated the same way storage
// is — an EmptyDir volume carrying PVC-only fields is rejected (issue #219).
func TestGarageClusterValidator_RejectsGatewayMetadataEmptyDirMisconfig(t *testing.T) {
	sc := "fast"
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{
				Replicas: 2,
				Metadata: &VolumeConfig{
					Type:             VolumeTypeEmptyDir,
					StorageClassName: &sc,
				},
			},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: "store"}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	if _, err := cluster.validateGarageCluster(); err == nil {
		t.Fatalf("validateGarageCluster accepted EmptyDir gateway metadata with storageClassName, want error")
	}
}

// TestGarageClusterValidator_WarnsGatewayMetadataEmptyDir verifies the
// node-identity warning is emitted for an EmptyDir gateway metadata volume,
// matching the storage-tier behavior (issue #219).
func TestGarageClusterValidator_WarnsGatewayMetadataEmptyDir(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{
				Replicas: 2,
				Metadata: &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: "store"}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatalf("validateGarageCluster: unexpected error %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "gateway.metadata.type=EmptyDir") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected gateway.metadata EmptyDir identity warning, got %v", warnings)
	}
}
