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
