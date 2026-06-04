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

// TestGarageClusterValidator_WarnsSharedStorageRPCAddr guards the multi-replica
// storage tier sharing one rpc_public_addr (reachable cross-region at one pod).
func TestGarageClusterValidator_WarnsSharedStorageRPCAddr(t *testing.T) {
	base := func(addr string) *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "stg", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas:      3,
					RPCPublicAddr: addr,
					Metadata:      &VolumeConfig{Type: VolumeTypeEmptyDir},
					Data:          &VolumeConfig{Type: VolumeTypeEmptyDir},
				},
				Replication: &ReplicationConfig{Factor: 2},
			},
		}
	}
	hasWarn := func(c *GarageCluster) bool {
		warnings, err := c.validateGarageCluster()
		if err != nil {
			t.Fatalf("validateGarageCluster: unexpected error %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "spec.storage.rpcPublicAddr is a single address") {
				return true
			}
		}
		return false
	}
	if !hasWarn(base("storage.example.ts.net:3901")) {
		t.Fatal("expected shared-storage-rpcaddr warning for multi-replica storage without {ordinal}")
	}
	if hasWarn(base("storage-{ordinal}.example.ts.net:3901")) {
		t.Fatal("must NOT warn when {ordinal} placeholder is present")
	}
	if hasWarn(base("")) {
		t.Fatal("must NOT warn when rpcPublicAddr is unset")
	}
}

func TestGarageClusterValidator_WarnsSharedGatewayRPCAddr(t *testing.T) {
	mk := func(addr string) *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage:     &StorageSpec{Replicas: 1, Metadata: &VolumeConfig{}, Data: &VolumeConfig{Type: VolumeTypeEmptyDir}},
				Gateway:     &GatewaySpec{Replicas: 2, RPCPublicAddr: addr},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	hasSharedWarning := func(t *testing.T, c *GarageCluster) bool {
		t.Helper()
		warnings, err := c.validateGarageCluster()
		if err != nil {
			t.Fatalf("validateGarageCluster: unexpected error %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "shared by all gateway pods") {
				return true
			}
		}
		return false
	}

	// Multi-pod gateway with a single shared addr (no {ordinal}) → warn.
	if !hasSharedWarning(t, mk("shared.example.ts.net:3901")) {
		t.Fatal("expected shared-gateway-rpcPublicAddr warning for a 2-replica gateway with no {ordinal}")
	}
	// Per-ordinal template → no warning.
	if hasSharedWarning(t, mk("gw-{ordinal}.example.ts.net:3901")) {
		t.Fatal("did not expect the warning when rpcPublicAddr uses an {ordinal} placeholder")
	}
}
