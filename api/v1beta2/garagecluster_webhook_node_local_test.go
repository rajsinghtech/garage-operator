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
)

const testDaemonSetClusterName = "mixed-storage"
const testNodeLocalPoolSelectorLabel = "storage.example.com/garage-pool"

func validNodeLocalPool(name, selectorValue string) NodeLocalPoolSpec {
	capacity := resource.MustParse("500Gi")
	return NodeLocalPoolSpec{
		Name:     name,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{testNodeLocalPoolSelectorLabel: selectorValue}},
		Capacity: &capacity,
		Metadata: &HostPathVolumeConfig{HostPath: "/var/lib/garage/" + name + "/meta"},
		Data:     &HostPathVolumeConfig{HostPath: "/var/lib/garage/" + name + "/data"},
	}
}

// validDaemonSetCluster deliberately uses Manual for the default pool: this is
// the production coexistence shape (user-managed SMB/PVC GarageNodes plus an
// operator-managed local-disk pool).
func validDaemonSetCluster() *GarageCluster {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testDaemonSetClusterName, Namespace: testNamespace, Generation: 1},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyManual,
			Storage: &StorageSpec{
				Replicas:       3,
				Metadata:       &VolumeConfig{},
				Data:           &VolumeConfig{Type: VolumeTypeEmptyDir},
				NodeLocalPools: []NodeLocalPoolSpec{validNodeLocalPool("local-500", "local-500")},
			},
			Replication: &ReplicationConfig{Factor: 1},
			Admin: &AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "garage-admin-token"},
			}},
		},
	}
	markGarageClusterDrainReady(cluster)
	return cluster
}

func markGarageClusterDrainReady(cluster *GarageCluster) {
	cluster.Status.Conditions = []metav1.Condition{{
		Type: storageRolloutReadyCondition, Status: metav1.ConditionTrue,
		Reason: "Converged", ObservedGeneration: cluster.Generation,
	}}
	cluster.Status.Health = &ClusterHealth{
		Status: healthStatusHealthy, Healthy: true, Available: true,
		StorageNodes: 3, StorageNodesOK: 3,
		Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
	}
}

func TestGarageClusterValidator_AcceptsMixedManualAndNodeLocalPools(t *testing.T) {
	cluster := validDaemonSetCluster()
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid mixed storage cluster rejected: %v", err)
	}
}

func TestGarageClusterValidator_NodeLocalServiceHoldAnnotations(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Annotations = map[string]string{
		nodeLocalOutOfServiceAnnotation: cluster.Spec.Storage.NodeLocalPools[0].Name + "/worker-a",
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid service hold rejected: %v", err)
	}
	cluster.Annotations[nodeLocalOutOfServiceAnnotation] = "missing-pool/worker-a"
	if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("unknown pool hold accepted: %v", err)
	}
	replaceID := strings.Repeat("a", 64)
	cluster.Annotations = map[string]string{
		nodeLocalReplaceIdentityAnnotation: cluster.Spec.Storage.NodeLocalPools[0].Name + "/worker-a/" + replaceID,
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid identity replacement rejected: %v", err)
	}
	cluster.Annotations[nodeLocalOutOfServiceAnnotation] = cluster.Spec.Storage.NodeLocalPools[0].Name + "/worker-a"
	if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "cannot be set together") {
		t.Fatalf("simultaneous hold and replacement accepted: %v", err)
	}
	cluster.Annotations = map[string]string{nodeLocalReplaceIdentityAnnotation: "local-500/worker-a/not-an-id"}
	if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "old-64-hex") {
		t.Fatalf("malformed replacement identity accepted: %v", err)
	}
}

func TestGarageClusterValidator_RejectsReservedDefaultNodeTags(t *testing.T) {
	for _, tag := range []string{
		"cluster:other/ns",
		"cluster-uid:forged",
		"tier:gateway",
		"rpc-address:other.example:3901",
		"node-local-pool:other",
		"kubernetes-node:worker-9",
	} {
		t.Run(tag, func(t *testing.T) {
			cluster := validDaemonSetCluster()
			cluster.Spec.DefaultNodeTags = []string{"rack:a", tag}
			if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "operator-managed prefix") {
				t.Fatalf("reserved defaultNodeTags value %q was accepted: %v", tag, err)
			}
		})
	}
	cluster := validDaemonSetCluster()
	cluster.Spec.DefaultNodeTags = []string{"rack:a", "media:nvme"}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("ordinary defaultNodeTags rejected: %v", err)
	}
}

func TestGarageClusterValidator_AcceptsDefaultPoolPublicEndpointWithNodeLocalPools(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.PublicEndpoint = &PublicEndpointConfig{Type: "LoadBalancer"}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("default-pool public endpoint rejected by unrelated node-local pool: %v", err)
	}
}

func TestGarageClusterValidator_DefaultPoolVolumesAreConditional(t *testing.T) {
	poolOnly := validDaemonSetCluster()
	poolOnly.Spec.LayoutPolicy = layoutPolicyAuto
	poolOnly.Spec.Storage.LayoutPolicy = ""
	poolOnly.Spec.Storage.Replicas = 0
	poolOnly.Spec.Storage.Metadata = nil
	poolOnly.Spec.Storage.Data = nil
	if _, err := poolOnly.validateGarageCluster(); err != nil {
		t.Fatalf("pool-only cluster with zero default replicas rejected: %v", err)
	}

	withDefaultReplicas := poolOnly.DeepCopy()
	withDefaultReplicas.Spec.Storage.Replicas = 1
	if _, err := withDefaultReplicas.validateGarageCluster(); err == nil ||
		!strings.Contains(err.Error(), testMetadataValue) {
		t.Fatalf("expected default-pool metadata/data requirement, got %v", err)
	}
}

func TestGarageClusterValidator_AcceptsMultipleProvablyDisjointPools(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.Storage.NodeLocalPools = append(cluster.Spec.Storage.NodeLocalPools,
		validNodeLocalPool("archive", "archive"))
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid disjoint pools rejected: %v", err)
	}
}

func TestGarageClusterValidator_AcceptsSelectorsWhoseLiveOverlapIsCheckedByController(t *testing.T) {
	cluster := validDaemonSetCluster()
	second := validNodeLocalPool("archive", "local-500")
	second.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"disk.example.net/class": "archive"}}
	cluster.Spec.Storage.NodeLocalPools = append(cluster.Spec.Storage.NodeLocalPools, second)

	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid selectors rejected before live Node overlap can be evaluated: %v", err)
	}
}

func TestGarageClusterValidator_NodeLocalPoolRequirements(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*GarageCluster)
		wantErr string
	}{
		{
			name: "admin token",
			mutate: func(c *GarageCluster) {
				c.Spec.Admin = nil
			},
			wantErr: "adminTokenSecretRef",
		},
		{
			name: "capacity",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Capacity = nil
			},
			wantErr: "capacity",
		},
		{
			name: selectorJSONField,
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Selector = metav1.LabelSelector{}
			},
			wantErr: selectorJSONField,
		},
		{
			name: testMetadataValue,
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Metadata = nil
			},
			wantErr: testMetadataValue,
		},
		{
			name: "data union neither",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Data = nil
			},
			wantErr: "exactly one",
		},
		{
			name: "data union both",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].DataPaths = []NodeLocalPoolDataPath{{
					Path: "/data/disk-0", HostPath: "/mnt/disk-0", Capacity: quantityPtr("500Gi"),
				}}
			},
			wantErr: "exactly one",
		},
		{
			name: "absolute host path",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Metadata.HostPath = "var/lib/garage/meta"
			},
			wantErr: "absolute",
		},
		{
			name: "host root",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Data.HostPath = "/"
			},
			wantErr: "host root",
		},
		{
			name: "overlapping host paths",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].Data.HostPath =
					c.Spec.Storage.NodeLocalPools[0].Metadata.HostPath + "/data"
			},
			wantErr: "non-overlapping",
		},
		{
			name: "required node affinity",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{},
					},
				}}
			},
			wantErr: "durable membership boundary",
		},
		{
			name: "reserved pod label",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{PodLabels: map[string]string{nodeLocalPoolKubernetesNodeLabel: "fake"}}
			},
			wantErr: "operator-managed",
		},
		{
			name: "invalid pod label",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{PodLabels: map[string]string{"not a label": "value"}}
			},
			wantErr: "invalid key",
		},
		{
			name: "reserved pod annotation",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{PodAnnotations: map[string]string{"garage.rajsingh.info/config-hash": "fake"}}
			},
			wantErr: "operator-managed",
		},
		{
			name: "duplicate pool name",
			mutate: func(c *GarageCluster) {
				c.Spec.Storage.NodeLocalPools = append(
					c.Spec.Storage.NodeLocalPools,
					validNodeLocalPool("local-500", "archive"),
				)
			},
			wantErr: "duplicate pool name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := validDaemonSetCluster()
			tt.mutate(cluster)
			_, err := cluster.validateGarageCluster()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("wanted error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestGarageClusterValidator_NodeLocalPoolMultiDisk(t *testing.T) {
	cluster := validDaemonSetCluster()
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	pool.Data = nil
	pool.Capacity = quantityPtr("700Gi")
	pool.DataPaths = []NodeLocalPoolDataPath{
		{Path: "/data/fast", HostPath: "/mnt/fast/garage", Capacity: quantityPtr("500Gi")},
		{Path: "/data/archive", HostPath: "/mnt/archive/garage", Capacity: quantityPtr("200Gi")},
		{Path: "/data/legacy", HostPath: "/mnt/legacy/garage", ReadOnly: true},
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid multi-disk pool rejected: %v", err)
	}

	t.Run("layout capacity cannot exceed writable paths", func(t *testing.T) {
		bad := cluster.DeepCopy()
		bad.Spec.Storage.NodeLocalPools[0].Capacity = quantityPtr("701Gi")
		_, err := bad.validateGarageCluster()
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected summed-capacity rejection, got %v", err)
		}
	})

	t.Run("read-only path cannot declare capacity", func(t *testing.T) {
		bad := cluster.DeepCopy()
		bad.Spec.Storage.NodeLocalPools[0].DataPaths[2].Capacity = quantityPtr("1Gi")
		_, err := bad.validateGarageCluster()
		if err == nil || !strings.Contains(err.Error(), "omitted") {
			t.Fatalf("expected read-only capacity rejection, got %v", err)
		}
	})

	t.Run("mount paths cannot conflict with metadata", func(t *testing.T) {
		bad := cluster.DeepCopy()
		bad.Spec.Storage.NodeLocalPools[0].DataPaths[0].Path = "/data/metadata/nested"
		_, err := bad.validateGarageCluster()
		if err == nil || !strings.Contains(err.Error(), "operator-managed") {
			t.Fatalf("expected reserved mount rejection, got %v", err)
		}
	})

	for _, reserved := range []string{
		"/secrets/metrics",
		"/secrets/consul/client-key/nested",
		"/var/run/garage-volume-markers/data-0",
	} {
		t.Run("mount path cannot conflict with "+strings.ReplaceAll(reserved, "/", "-"), func(t *testing.T) {
			bad := cluster.DeepCopy()
			bad.Spec.Storage.NodeLocalPools[0].DataPaths[0].Path = reserved
			_, err := bad.validateGarageCluster()
			if err == nil || !strings.Contains(err.Error(), "operator-managed") {
				t.Fatalf("expected reserved mount rejection for %q, got %v", reserved, err)
			}
		})
	}
}

func TestGarageClusterValidator_NodeLocalPoolRPCAddress(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.Storage.NodeLocalPools[0].Network = &NodeLocalPoolNetworkSpec{
		RPCPublicAddrTemplate: "{nodeName}.storage.example.net:3901",
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid address template rejected: %v", err)
	}

	for name, value := range map[string]string{
		"missing node placeholder": "shared.storage.example.net:3901",
		"scheme":                   "http://{nodeName}:3901",
		"bad port":                 "{nodeName}.example.net:70000",
	} {
		t.Run(name, func(t *testing.T) {
			bad := validDaemonSetCluster()
			bad.Spec.Storage.NodeLocalPools[0].Network = &NodeLocalPoolNetworkSpec{RPCPublicAddrTemplate: value}
			if _, err := bad.validateGarageCluster(); err == nil {
				t.Fatalf("invalid address template %q accepted", value)
			}
		})
	}
}

func TestGarageClusterValidator_RejectsNodeLocalPoolZoneFromWithFederation(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.ZoneFrom = &ZoneSource{NodeLabel: corev1.LabelTopologyZone}
	cluster.Spec.RemoteClusters = []RemoteClusterConfig{{
		Name: "remote",
		Zone: "remote-zone",
		Connection: RemoteClusterConnection{
			AdminAPIEndpoint: "http://remote.example.test:3903",
		},
	}}
	_, err := cluster.validateGarageCluster()
	if err == nil || !strings.Contains(err.Error(), "physical site") {
		t.Fatalf("expected federated zoneFrom rejection, got %v", err)
	}
}

func TestGarageClusterDefaulter_DefaultsPoolHostPathTypes(t *testing.T) {
	cluster := validDaemonSetCluster()
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	pool.Data = nil
	pool.DataPaths = []NodeLocalPoolDataPath{{
		Path: "/data/disk-0", HostPath: "/mnt/disk-0", Capacity: quantityPtr("500Gi"),
	}}
	if err := (&GarageClusterDefaulter{}).Default(context.Background(), cluster); err != nil {
		t.Fatalf("default: %v", err)
	}
	if pool.Metadata.HostPathType != corev1.HostPathDirectory ||
		pool.DataPaths[0].HostPathType != corev1.HostPathDirectory {
		t.Fatalf("pool hostPath types were not defaulted: %+v", pool)
	}
}

func TestGarageClusterValidator_NodeLocalPoolUpdates(t *testing.T) {
	validator := &GarageClusterValidator{}

	t.Run("metadata identity is immutable", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Metadata.HostPath = "/var/lib/garage/new-meta"
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "metadata is immutable") {
			t.Fatalf("expected metadata immutability rejection, got %v", err)
		}
	})

	t.Run("selector change advertises safe handoff", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Selector = metav1.LabelSelector{
			MatchLabels: map[string]string{testNodeLocalPoolSelectorLabel: "replacement"},
		}
		warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err != nil {
			t.Fatalf("selector update rejected: %v", err)
		}
		if !warningContains(warnings, "add-before-remove") {
			t.Fatalf("safe handoff warning missing: %v", warnings)
		}
	})

	t.Run("direct data path remap is rejected", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Data.HostPath = "/var/lib/garage/new-data"
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "cannot remap") {
			t.Fatalf("expected direct data remap rejection, got %v", err)
		}
	})

	t.Run("single disk can enter a staged multi-disk migration", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		pool := &newer.Spec.Storage.NodeLocalPools[0]
		oldHostPath := pool.Data.HostPath
		pool.Data = nil
		pool.DataPaths = []NodeLocalPoolDataPath{
			{Path: nodeLocalPoolDataDir, HostPath: oldHostPath, Capacity: quantityPtr("250Gi")},
			{Path: "/data/replacement", HostPath: "/var/lib/garage/new-data", Capacity: quantityPtr("250Gi")},
		}
		warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err != nil {
			t.Fatalf("safe staged data migration rejected: %v", err)
		}
		if !warningContains(warnings, "data HostPath") {
			t.Fatalf("data migration warning missing: %v", warnings)
		}
	})

	t.Run("writable data path must become read-only before removal", func(t *testing.T) {
		old := validDaemonSetCluster()
		oldPool := &old.Spec.Storage.NodeLocalPools[0]
		oldPool.Data = nil
		oldPool.DataPaths = []NodeLocalPoolDataPath{
			{Path: "/data/old", HostPath: "/var/lib/garage/old-data", Capacity: quantityPtr("250Gi")},
			{Path: "/data/current", HostPath: "/var/lib/garage/current-data", Capacity: quantityPtr("500Gi")},
		}
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].DataPaths =
			newer.Spec.Storage.NodeLocalPools[0].DataPaths[1:]
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "cannot remove data path") {
			t.Fatalf("expected writable path removal rejection, got %v", err)
		}
	})

	t.Run("read-only data path still cannot be detached without filesystem proof", func(t *testing.T) {
		old := validDaemonSetCluster()
		oldPool := &old.Spec.Storage.NodeLocalPools[0]
		oldPool.Data = nil
		oldPool.DataPaths = []NodeLocalPoolDataPath{
			{Path: "/data/old", HostPath: "/var/lib/garage/old-data", ReadOnly: true},
			{Path: "/data/current", HostPath: "/var/lib/garage/current-data", Capacity: quantityPtr("500Gi")},
		}
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].DataPaths =
			newer.Spec.Storage.NodeLocalPools[0].DataPaths[1:]
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "do not prove the HostPath is empty") {
			t.Fatalf("expected read-only path removal rejection, got %v", err)
		}
	})

	t.Run("metadata hostPath type can be tightened", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Metadata.HostPathType = corev1.HostPathDirectory
		warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err != nil {
			t.Fatalf("metadata hostPathType update rejected: %v", err)
		}
		if !warningContains(warnings, "metadata.hostPathType") {
			t.Fatalf("metadata hostPathType rollout warning missing: %v", warnings)
		}
	})

	t.Run("metadata hostPath type cannot be loosened", func(t *testing.T) {
		old := validDaemonSetCluster()
		old.Spec.Storage.NodeLocalPools[0].Metadata.HostPathType = corev1.HostPathDirectory
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Metadata.HostPathType = corev1.HostPathDirectoryOrCreate
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "cannot be loosened") {
			t.Fatalf("expected metadata hostPathType loosening rejection, got %v", err)
		}
	})

	t.Run("data hostPath type cannot be loosened", func(t *testing.T) {
		old := validDaemonSetCluster()
		old.Spec.Storage.NodeLocalPools[0].Data.HostPathType = corev1.HostPathDirectory
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Data.HostPathType = corev1.HostPathDirectoryOrCreate
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "cannot be loosened") {
			t.Fatalf("expected data hostPathType loosening rejection, got %v", err)
		}
	})

	t.Run("pool removal warns about drain", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools = nil
		warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err != nil {
			t.Fatalf("pool removal rejected: %v", err)
		}
		if !warningContains(warnings, "one-node-at-a-time") {
			t.Fatalf("pool removal warning missing: %v", warnings)
		}
	})

	t.Run("pool removal cannot skip a simultaneous image rollout", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools = nil
		newer.Spec.Image = "dxflrs/garage:v2.4.0"
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "topology-only update") {
			t.Fatalf("expected combined membership and image update rejection, got %v", err)
		}
	})

	t.Run("selector handoff cannot change the retained pool template", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools[0].Selector = metav1.LabelSelector{
			MatchLabels: map[string]string{testNodeLocalPoolSelectorLabel: "replacement"},
		}
		newer.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{
			PriorityClassName: "storage-critical",
		}
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "topology-only update") {
			t.Fatalf("expected combined selector and template update rejection, got %v", err)
		}
	})

	t.Run("replica removal cannot skip a simultaneous Garage config rollout", func(t *testing.T) {
		old := validDaemonSetCluster()
		old.Spec.LayoutPolicy = layoutPolicyAuto
		old.Spec.Storage.Metadata = &VolumeConfig{Type: VolumeTypeEmptyDir}
		newer := old.DeepCopy()
		newer.Spec.Storage.Replicas--
		newer.Spec.Storage.MetadataFsync = !old.Spec.Storage.MetadataFsync
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "topology-only update") {
			t.Fatalf("expected combined replica and config update rejection, got %v", err)
		}
	})

	t.Run("default managed pool N to zero cannot bypass prepared drain gates", func(t *testing.T) {
		old := validDaemonSetCluster()
		old.Spec.LayoutPolicy = layoutPolicyAuto
		newer := old.DeepCopy()
		newer.Spec.Storage.Replicas = 0
		newer.Spec.Storage.MetadataFsync = !old.Spec.Storage.MetadataFsync
		if !garageClusterPositiveStorageRemoval(old, newer) {
			t.Fatal("managed default-pool N -> 0 was not classified as positive-capacity removal")
		}
		_, err := validator.ValidateUpdate(context.Background(), old, newer)
		if err == nil || !strings.Contains(err.Error(), "topology-only update") {
			t.Fatalf("managed default-pool N -> 0 bypassed the prepared drain boundary: %v", err)
		}
	})

	t.Run("Manual default-pool placeholders do not impersonate live storage", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.Replicas = 0
		newer.Spec.Storage.Metadata = nil
		newer.Spec.Storage.Data = nil
		newer.Spec.Storage.MetadataFsync = !old.Spec.Storage.MetadataFsync

		if garageClusterPositiveStorageRemoval(old, newer) {
			t.Fatal("ignored Manual replicas were classified as positive-capacity removal")
		}
		if _, err := validator.ValidateUpdate(context.Background(), old, newer); err != nil {
			t.Fatalf("cleaning ignored Manual default-pool fields was rejected: %v", err)
		}
	})

	t.Run("pool rename is admitted and live activation ownership enforces two-step handoff", func(t *testing.T) {
		old := validDaemonSetCluster()
		newer := old.DeepCopy()
		newer.Spec.Storage.NodeLocalPools = []NodeLocalPoolSpec{
			validNodeLocalPool("renamed", "local-500"),
		}
		if _, err := validator.ValidateUpdate(context.Background(), old, newer); err != nil {
			t.Fatalf("rename rejected before controller could evaluate live activation ownership: %v", err)
		}
	})
}

func TestGarageClusterValidator_NodeLocalPoolPDBDefaultsToOneUnavailable(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.Storage.PodDisruptionBudget = &PodDisruptionBudgetConfig{Enabled: true}
	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatalf("valid PDB rejected: %v", err)
	}
	if !warningContains(warnings, "maxUnavailable=1") {
		t.Fatalf("mixed-tier PDB default warning missing: %v", warnings)
	}
}

func TestGarageClusterValidator_NodeLocalPoolConversionTransport(t *testing.T) {
	t.Run("reserved payload annotation", func(t *testing.T) {
		cluster := validDaemonSetCluster()
		cluster.Annotations = map[string]string{
			v1beta1PoolConversionPayloadAnnotation: "forged",
		}
		_, err := cluster.validateGarageCluster()
		if err == nil || !strings.Contains(err.Error(), "reserved for v1beta1 API conversion") {
			t.Fatalf("expected reserved conversion annotation rejection, got %v", err)
		}
	})

	t.Run("v1beta1 round-trip annotation budget", func(t *testing.T) {
		cluster := validDaemonSetCluster()
		cluster.Spec.Storage.NodeLocalPools[0].PodTemplate = &NodeLocalPoolPodTemplate{PodAnnotations: map[string]string{
			"example.com/large": strings.Repeat("x", kubernetesTotalAnnotationSizeLimit),
		}}
		_, err := cluster.validateGarageCluster()
		if err == nil || !strings.Contains(err.Error(), "too large to round-trip") {
			t.Fatalf("expected conversion annotation budget rejection, got %v", err)
		}
	})

	t.Run("exact aggregate annotation boundary", func(t *testing.T) {
		cluster := validDaemonSetCluster()
		baseline, err := cluster.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		key := "example.com/existing-budget"
		remaining := kubernetesTotalAnnotationSizeLimit - baseline - len(key)
		if remaining <= 0 {
			t.Fatalf("unexpected baseline conversion size %d", baseline)
		}
		cluster.Annotations = map[string]string{key: strings.Repeat("x", remaining)}
		projected, err := cluster.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if projected != kubernetesTotalAnnotationSizeLimit {
			t.Fatalf("projected exact boundary is %d, want %d", projected, kubernetesTotalAnnotationSizeLimit)
		}
		if err := cluster.validateNodeLocalPoolConversionTransport(); err != nil {
			t.Fatalf("exact Kubernetes annotation boundary rejected: %v", err)
		}
		cluster.Annotations[key] += "x"
		if err := cluster.validateNodeLocalPoolConversionTransport(); err == nil ||
			!strings.Contains(err.Error(), "exceeds Kubernetes limit") {
			t.Fatalf("boundary +1 byte was accepted: %v", err)
		}
	})

	t.Run("combined pool gateway and existing marker components consume one budget", func(t *testing.T) {
		poolOnly := validDaemonSetCluster()
		poolSize, err := poolOnly.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		combined := validDaemonSetCluster()
		combined.Spec.Gateway = &GatewaySpec{Replicas: 1}
		combined.Annotations = map[string]string{
			v1beta2OnlyAnnotation: "unrelated-component",
			"example.com/user":    "existing-value",
		}
		combinedSize, err := combined.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if combinedSize <= poolSize || combinedSize <= len("example.com/user")+len("existing-value") {
			t.Fatalf("combined conversion projection omitted a component: pool=%d combined=%d", poolSize, combinedSize)
		}
		if err := combined.validateNodeLocalPoolConversionTransport(); err != nil {
			t.Fatalf("valid combined conversion projection rejected: %v", err)
		}
	})

	t.Run("gateway-only v1beta2 payload consumes conversion budget", func(t *testing.T) {
		edge := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "edge-budget", Namespace: testNamespace},
			Spec: GarageClusterSpec{Gateway: &GatewaySpec{
				Replicas: 1,
				PodTemplate: PodTemplate{Env: []corev1.EnvVar{{
					Name: testEdgePayloadEnv, Value: strings.Repeat("x", kubernetesTotalAnnotationSizeLimit),
				}}},
			}},
		}
		projected, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if projected <= kubernetesTotalAnnotationSizeLimit {
			t.Fatalf("gateway-only v1beta2 payload was omitted from projection: %d", projected)
		}
		if err := edge.validateNodeLocalPoolConversionTransport(); err == nil ||
			!strings.Contains(err.Error(), "too large to round-trip") {
			t.Fatalf("oversized gateway-only conversion payload was accepted: %v", err)
		}
	})

	t.Run("gateway-only exact aggregate annotation boundary", func(t *testing.T) {
		edge := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "edge-exact-budget", Namespace: testNamespace},
			Spec: GarageClusterSpec{Gateway: &GatewaySpec{
				Replicas:    1,
				PodTemplate: PodTemplate{Env: []corev1.EnvVar{{Name: testEdgePayloadEnv, Value: "v2-only"}}},
			}},
		}
		baseline, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if baseline == 0 {
			t.Fatal("gateway-only conversion projection is empty")
		}
		key := "example.com/edge-existing-budget"
		remaining := kubernetesTotalAnnotationSizeLimit - baseline - len(key)
		if remaining <= 0 {
			t.Fatalf("unexpected gateway-only conversion baseline %d", baseline)
		}
		edge.Annotations = map[string]string{key: strings.Repeat("x", remaining)}
		projected, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if projected != kubernetesTotalAnnotationSizeLimit {
			t.Fatalf("gateway-only exact boundary is %d, want %d", projected, kubernetesTotalAnnotationSizeLimit)
		}
		if err := edge.validateNodeLocalPoolConversionTransport(); err != nil {
			t.Fatalf("gateway-only exact boundary rejected: %v", err)
		}
		edge.Annotations[key] += "x"
		if err := edge.validateNodeLocalPoolConversionTransport(); err == nil {
			t.Fatal("gateway-only boundary +1 byte was accepted")
		}
	})

	t.Run("released gateway projection can only stay unchanged or shrink", func(t *testing.T) {
		edge := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-edge-budget", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Gateway: &GatewaySpec{
					Replicas: 1,
					PodTemplate: PodTemplate{Env: []corev1.EnvVar{{
						Name: testEdgePayloadEnv, Value: strings.Repeat("x", kubernetesTotalAnnotationSizeLimit),
					}}},
				},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
		oldSize, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if oldSize <= kubernetesTotalAnnotationSizeLimit {
			t.Fatalf("legacy edge projection is not over budget: %d", oldSize)
		}

		metadataUpdate := edge.DeepCopy()
		metadataUpdate.Finalizers = []string{testCleanupFinalizer}
		warnings, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), edge, metadataUpdate)
		if err != nil {
			t.Fatalf("metadata update on unchanged released edge projection was rejected: %v", err)
		}
		if !warningContains(warnings, "non-expanding update") {
			t.Fatalf("over-budget edge projection lacked a migration warning: %v", warnings)
		}

		grown := edge.DeepCopy()
		grown.Spec.Gateway.Env[0].Value += "x"
		if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), edge, grown); err == nil ||
			!strings.Contains(err.Error(), "may not grow") {
			t.Fatalf("growth of released over-budget edge projection was accepted: %v", err)
		}

		shrunk := edge.DeepCopy()
		shrunk.Spec.Gateway.Env[0].Value = "small"
		if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), edge, shrunk); err != nil {
			t.Fatalf("repair below the conversion annotation budget was rejected: %v", err)
		}
	})

	t.Run("released marker cleanup cannot inflate the legacy growth baseline", func(t *testing.T) {
		edge := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "legacy-marker-budget",
				Namespace: testNamespace,
				Annotations: map[string]string{
					v1beta2OnlyAnnotation: v1beta1GatewayConversionMarker,
				},
			},
			Spec: GarageClusterSpec{
				Gateway: &GatewaySpec{
					Replicas: 1,
					PodTemplate: PodTemplate{Env: []corev1.EnvVar{{
						Name: testEdgePayloadEnv, Value: "legacy",
					}}},
				},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
		withMarker, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		withoutMarker := edge.DeepCopy()
		withoutMarker.Annotations = nil
		generatedMarker, err := withoutMarker.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if withMarker != generatedMarker {
			t.Fatalf("existing generated marker changed exact projection: with=%d generated=%d", withMarker, generatedMarker)
		}

		// Put the released object just over the annotation limit. Removing the
		// legacy marker does not free space because conversion writes the same
		// marker; any payload growth must therefore be rejected.
		growBy := kubernetesTotalAnnotationSizeLimit + 10 - withMarker
		if growBy <= 0 {
			t.Fatalf("unexpected marker projection baseline %d", withMarker)
		}
		edge.Spec.Gateway.Env[0].Value += strings.Repeat("x", growBy)
		oldSize, err := edge.projectedV1beta1ConversionAnnotationSize()
		if err != nil {
			t.Fatal(err)
		}
		if oldSize != kubernetesTotalAnnotationSizeLimit+10 {
			t.Fatalf("legacy exact projection = %d, want %d", oldSize, kubernetesTotalAnnotationSizeLimit+10)
		}

		grown := edge.DeepCopy()
		grown.Annotations = nil
		grown.Spec.Gateway.Env[0].Value += "x"
		if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), edge, grown); err == nil ||
			!strings.Contains(err.Error(), "may not grow") {
			t.Fatalf("marker cleanup inflated the old projection and admitted payload growth: %v", err)
		}
	})
}

func quantityPtr(value string) *resource.Quantity {
	quantity := resource.MustParse(value)
	return &quantity
}

func warningContains(warnings []string, substring string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, substring) {
			return true
		}
	}
	return false
}
