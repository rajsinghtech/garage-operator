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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

const (
	metadataVolumeName = "metadata"
	dataVolumeName     = "data"
	testClusterName    = "test-cluster"
)

func TestResolveSecretConfig(t *testing.T) {
	tests := []struct {
		name     string
		key      *garagev1alpha1.GarageKey
		expected secretConfig
	}{
		{
			name: "default config when no template specified",
			key: &garagev1alpha1.GarageKey{
				Spec: garagev1alpha1.GarageKeySpec{},
			},
			expected: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				endpointKey:        "endpoint",
				regionKey:          "region",
				includeEndpoint:    true,
				includeRegion:      true,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "custom key names",
			key: &garagev1alpha1.GarageKey{
				Spec: garagev1alpha1.GarageKeySpec{
					SecretTemplate: &garagev1alpha1.SecretTemplate{
						AccessKeyIDKey:     "AWS_ACCESS_KEY_ID",
						SecretAccessKeyKey: "AWS_SECRET_ACCESS_KEY",
						EndpointKey:        "AWS_ENDPOINT",
						RegionKey:          "AWS_REGION",
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     "AWS_ACCESS_KEY_ID",
				secretAccessKeyKey: "AWS_SECRET_ACCESS_KEY",
				endpointKey:        "AWS_ENDPOINT",
				regionKey:          "AWS_REGION",
				includeEndpoint:    true,
				includeRegion:      true,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "disable endpoint and region",
			key: &garagev1alpha1.GarageKey{
				Spec: garagev1alpha1.GarageKeySpec{
					SecretTemplate: &garagev1alpha1.SecretTemplate{
						IncludeEndpoint: boolPtr(false),
						IncludeRegion:   boolPtr(false),
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				endpointKey:        "endpoint",
				regionKey:          "region",
				includeEndpoint:    false,
				includeRegion:      false,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "custom secret type",
			key: &garagev1alpha1.GarageKey{
				Spec: garagev1alpha1.GarageKeySpec{
					SecretTemplate: &garagev1alpha1.SecretTemplate{
						Type: corev1.SecretTypeDockerConfigJson,
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				endpointKey:        "endpoint",
				regionKey:          "region",
				includeEndpoint:    true,
				includeRegion:      true,
				secretType:         corev1.SecretTypeDockerConfigJson,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveSecretConfig(tt.key)

			if result.accessKeyIDKey != tt.expected.accessKeyIDKey {
				t.Errorf("accessKeyIDKey = %q, want %q", result.accessKeyIDKey, tt.expected.accessKeyIDKey)
			}
			if result.secretAccessKeyKey != tt.expected.secretAccessKeyKey {
				t.Errorf("secretAccessKeyKey = %q, want %q", result.secretAccessKeyKey, tt.expected.secretAccessKeyKey)
			}
			if result.endpointKey != tt.expected.endpointKey {
				t.Errorf("endpointKey = %q, want %q", result.endpointKey, tt.expected.endpointKey)
			}
			if result.regionKey != tt.expected.regionKey {
				t.Errorf("regionKey = %q, want %q", result.regionKey, tt.expected.regionKey)
			}
			if result.includeEndpoint != tt.expected.includeEndpoint {
				t.Errorf("includeEndpoint = %v, want %v", result.includeEndpoint, tt.expected.includeEndpoint)
			}
			if result.includeRegion != tt.expected.includeRegion {
				t.Errorf("includeRegion = %v, want %v", result.includeRegion, tt.expected.includeRegion)
			}
			if result.secretType != tt.expected.secretType {
				t.Errorf("secretType = %v, want %v", result.secretType, tt.expected.secretType)
			}
		})
	}
}

func TestBuildSecretData(t *testing.T) {
	tests := []struct {
		name            string
		cfg             secretConfig
		key             *garagev1alpha1.GarageKey
		cluster         *garagev1alpha1.GarageCluster
		secretAccessKey string
		wantKeys        []string
		wantValues      map[string]string
	}{
		{
			name: "basic secret with all fields",
			cfg: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				endpointKey:        "endpoint",
				regionKey:          "region",
				includeEndpoint:    true,
				includeRegion:      true,
			},
			key: &garagev1alpha1.GarageKey{
				Status: garagev1alpha1.GarageKeyStatus{
					AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				},
			},
			cluster: &garagev1alpha1.GarageCluster{
				Spec: garagev1alpha1.GarageClusterSpec{
					S3API: &garagev1alpha1.S3APIConfig{
						Region: "us-west-2",
					},
				},
			},
			secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantKeys:        []string{"access-key-id", "secret-access-key", "endpoint", "region"},
			wantValues: map[string]string{
				"access-key-id":     "AKIAIOSFODNN7EXAMPLE",
				"secret-access-key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-west-2",
			},
		},
		{
			name: "without endpoint and region",
			cfg: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				endpointKey:        "endpoint",
				regionKey:          "region",
				includeEndpoint:    false,
				includeRegion:      false,
			},
			key: &garagev1alpha1.GarageKey{
				Status: garagev1alpha1.GarageKeyStatus{
					AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				},
			},
			cluster:         &garagev1alpha1.GarageCluster{},
			secretAccessKey: "secret123",
			wantKeys:        []string{"access-key-id", "secret-access-key"},
		},
		{
			name: "default region when not specified",
			cfg: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				regionKey:          "region",
				includeEndpoint:    false,
				includeRegion:      true,
			},
			key: &garagev1alpha1.GarageKey{
				Status: garagev1alpha1.GarageKeyStatus{
					AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				},
			},
			cluster:         &garagev1alpha1.GarageCluster{},
			secretAccessKey: "secret123",
			wantValues: map[string]string{
				"region": "garage",
			},
		},
		{
			name: "with additional data",
			cfg: secretConfig{
				accessKeyIDKey:     "access-key-id",
				secretAccessKeyKey: "secret-access-key",
				includeEndpoint:    false,
				includeRegion:      false,
				additionalData: map[string]string{
					"custom-key": "custom-value",
				},
			},
			key: &garagev1alpha1.GarageKey{
				Status: garagev1alpha1.GarageKeyStatus{
					AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				},
			},
			cluster:         &garagev1alpha1.GarageCluster{},
			secretAccessKey: "secret123",
			wantKeys:        []string{"access-key-id", "secret-access-key", "custom-key"},
			wantValues: map[string]string{
				"custom-key": "custom-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSecretData(tt.cfg, tt.key, tt.cluster, tt.secretAccessKey)

			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("missing key %q in result", key)
				}
			}

			for key, want := range tt.wantValues {
				if got := string(result[key]); got != want {
					t.Errorf("result[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestBuildContainerPorts(t *testing.T) {
	tests := []struct {
		name        string
		cluster     *garagev1alpha1.GarageCluster
		wantMinPort int
		wantPorts   []string
	}{
		{
			name: "default ports",
			cluster: &garagev1alpha1.GarageCluster{
				Spec: garagev1alpha1.GarageClusterSpec{},
			},
			wantMinPort: 3, // RPC, Admin, S3
			wantPorts:   []string{"rpc", "s3", "admin"},
		},
		{
			name: "with S3 API disabled",
			cluster: &garagev1alpha1.GarageCluster{
				Spec: garagev1alpha1.GarageClusterSpec{
					S3API: &garagev1alpha1.S3APIConfig{
						Enabled: false,
					},
				},
			},
			wantMinPort: 2, // RPC, Admin only
			wantPorts:   []string{"rpc", "admin"},
		},
		{
			name: "with Admin API disabled",
			cluster: &garagev1alpha1.GarageCluster{
				Spec: garagev1alpha1.GarageClusterSpec{
					Admin: &garagev1alpha1.AdminConfig{
						Enabled: false,
					},
				},
			},
			wantMinPort: 2, // RPC, S3 only
			wantPorts:   []string{"rpc", "s3"},
		},
		{
			name: "custom RPC port",
			cluster: &garagev1alpha1.GarageCluster{
				Spec: garagev1alpha1.GarageClusterSpec{
					Network: garagev1alpha1.NetworkConfig{
						RPCBindPort: 4901,
					},
				},
			},
			wantMinPort: 3,
			wantPorts:   []string{"rpc", "s3", "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := buildContainerPorts(tt.cluster)
			if len(ports) < tt.wantMinPort {
				t.Errorf("got %d ports, want at least %d", len(ports), tt.wantMinPort)
			}

			portNames := make(map[string]bool)
			for _, p := range ports {
				portNames[p.Name] = true
			}

			for _, want := range tt.wantPorts {
				if !portNames[want] {
					t.Errorf("missing expected port %q", want)
				}
			}
		})
	}
}

func TestBuildVolumeClaimTemplates(t *testing.T) {
	storageClass := "fast-ssd"
	dataSize := resource.MustParse("10Gi")

	t.Run("storage cluster - default sizes", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{},
					Data:     &garagev1alpha1.DataStorageConfig{},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 2 {
			t.Errorf("got %d PVCs, want 2", len(pvcs))
			return
		}
		if pvcs[0].Name != metadataVolumeName {
			t.Errorf("PVC[0] name = %q, want %q", pvcs[0].Name, metadataVolumeName)
		}
		gotMetadataSize := pvcs[0].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotMetadataSize.String() != "10Gi" {
			t.Errorf("Metadata size = %q, want %q", gotMetadataSize.String(), "10Gi")
		}
		if pvcs[1].Name != dataVolumeName {
			t.Errorf("PVC[1] name = %q, want %q", pvcs[1].Name, dataVolumeName)
		}
		gotDataSize := pvcs[1].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotDataSize.String() != "100Gi" {
			t.Errorf("Data size = %q, want %q", gotDataSize.String(), "100Gi")
		}
	})

	t.Run("storage cluster - custom sizes and storage class", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						Size: resource.MustParse("1Gi"),
					},
					Data: &garagev1alpha1.DataStorageConfig{
						Size:             &dataSize,
						StorageClassName: &storageClass,
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 2 {
			t.Errorf("got %d PVCs, want 2", len(pvcs))
			return
		}
		gotMetadataSize := pvcs[0].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotMetadataSize.String() != "1Gi" {
			t.Errorf("Metadata size = %q, want %q", gotMetadataSize.String(), "1Gi")
		}
		gotDataSize := pvcs[1].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotDataSize.String() != "10Gi" {
			t.Errorf("Data size = %q, want %q", gotDataSize.String(), "10Gi")
		}
		if pvcs[1].Spec.StorageClassName == nil || *pvcs[1].Spec.StorageClassName != storageClass {
			t.Errorf("Data StorageClassName = %v, want %q", pvcs[1].Spec.StorageClassName, storageClass)
		}
	})

	t.Run("gateway cluster - only metadata PVC (1Gi default)", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Gateway: true,
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 1 {
			t.Errorf("gateway cluster: got %d PVCs, want 1 (metadata only)", len(pvcs))
			return
		}
		if pvcs[0].Name != metadataVolumeName {
			t.Errorf("PVC[0] name = %q, want %q", pvcs[0].Name, metadataVolumeName)
		}
		gotMetadataSize := pvcs[0].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotMetadataSize.String() != "1Gi" {
			t.Errorf("Gateway metadata size = %q, want %q (default for gateway)", gotMetadataSize.String(), "1Gi")
		}
	})

	t.Run("gateway cluster - custom metadata size", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Gateway: true,
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						Size:             resource.MustParse("2Gi"),
						StorageClassName: &storageClass,
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 1 {
			t.Errorf("gateway cluster: got %d PVCs, want 1", len(pvcs))
			return
		}
		gotMetadataSize := pvcs[0].Spec.Resources.Requests[corev1.ResourceStorage]
		if gotMetadataSize.String() != "2Gi" {
			t.Errorf("Gateway metadata size = %q, want %q", gotMetadataSize.String(), "2Gi")
		}
		if pvcs[0].Spec.StorageClassName == nil || *pvcs[0].Spec.StorageClassName != storageClass {
			t.Errorf("Gateway metadata StorageClassName = %v, want %q", pvcs[0].Spec.StorageClassName, storageClass)
		}
	})
}

func boolPtr(b bool) *bool {
	return &b
}

func TestBuildVolumeClaimTemplates_ExistingClaim(t *testing.T) {
	t.Run("storage cluster - data existingClaim skips data PVC", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						Size: resource.MustParse("10Gi"),
					},
					Data: &garagev1alpha1.DataStorageConfig{
						ExistingClaim: "my-existing-data-pvc",
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 1 {
			t.Errorf("got %d PVCs, want 1 (metadata only)", len(pvcs))
			return
		}
		if pvcs[0].Name != metadataVolumeName {
			t.Errorf("PVC[0] name = %q, want %q", pvcs[0].Name, metadataVolumeName)
		}
	})

	t.Run("storage cluster - metadata existingClaim skips metadata PVC", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						ExistingClaim: "my-existing-metadata-pvc",
					},
					Data: &garagev1alpha1.DataStorageConfig{
						Size: ptrQuantity(resource.MustParse("100Gi")),
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 1 {
			t.Errorf("got %d PVCs, want 1 (data only)", len(pvcs))
			return
		}
		if pvcs[0].Name != dataVolumeName {
			t.Errorf("PVC[0] name = %q, want %q", pvcs[0].Name, dataVolumeName)
		}
	})

	t.Run("storage cluster - both existingClaims skips all PVCs", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						ExistingClaim: "my-existing-metadata-pvc",
					},
					Data: &garagev1alpha1.DataStorageConfig{
						ExistingClaim: "my-existing-data-pvc",
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 0 {
			t.Errorf("got %d PVCs, want 0 (both use existingClaim)", len(pvcs))
		}
	})

	t.Run("gateway cluster - metadata existingClaim skips PVC", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Gateway: true,
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						ExistingClaim: "my-existing-metadata-pvc",
					},
				},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 0 {
			t.Errorf("gateway cluster with existingClaim: got %d PVCs, want 0", len(pvcs))
		}
	})
}

func TestBuildVolumesAndMounts_ExistingClaim(t *testing.T) {
	t.Run("storage cluster - data existingClaim creates PVC volume", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Data: &garagev1alpha1.DataStorageConfig{
						ExistingClaim: "my-existing-data-pvc",
					},
				},
			},
		}
		cluster.Name = testClusterName
		volumes, mounts := buildVolumesAndMounts(cluster)

		// Check that data volume exists with PVC source
		var dataVolume *corev1.Volume
		for i := range volumes {
			if volumes[i].Name == dataVolumeName {
				dataVolume = &volumes[i]
				break
			}
		}
		if dataVolume == nil {
			t.Error("data volume not found")
			return
		}
		if dataVolume.PersistentVolumeClaim == nil {
			t.Error("data volume should use PersistentVolumeClaim source")
			return
		}
		if dataVolume.PersistentVolumeClaim.ClaimName != "my-existing-data-pvc" {
			t.Errorf("data PVC claim name = %q, want %q", dataVolume.PersistentVolumeClaim.ClaimName, "my-existing-data-pvc")
		}

		// Verify mount still exists
		var hasDataMount bool
		for _, m := range mounts {
			if m.Name == dataVolumeName {
				hasDataMount = true
				break
			}
		}
		if !hasDataMount {
			t.Error("data mount not found")
		}
	})

	t.Run("storage cluster - metadata existingClaim creates PVC volume", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{
					Metadata: &garagev1alpha1.VolumeConfig{
						ExistingClaim: "my-existing-metadata-pvc",
					},
				},
			},
		}
		cluster.Name = testClusterName
		volumes, mounts := buildVolumesAndMounts(cluster)

		// Check that metadata volume exists with PVC source
		var metadataVolume *corev1.Volume
		for i := range volumes {
			if volumes[i].Name == metadataVolumeName {
				metadataVolume = &volumes[i]
				break
			}
		}
		if metadataVolume == nil {
			t.Error("metadata volume not found")
			return
		}
		if metadataVolume.PersistentVolumeClaim == nil {
			t.Error("metadata volume should use PersistentVolumeClaim source")
			return
		}
		if metadataVolume.PersistentVolumeClaim.ClaimName != "my-existing-metadata-pvc" {
			t.Errorf("metadata PVC claim name = %q, want %q", metadataVolume.PersistentVolumeClaim.ClaimName, "my-existing-metadata-pvc")
		}

		// Verify mount still exists
		var hasMetadataMount bool
		for _, m := range mounts {
			if m.Name == metadataVolumeName {
				hasMetadataMount = true
				break
			}
		}
		if !hasMetadataMount {
			t.Error("metadata mount not found")
		}
	})

	t.Run("storage cluster - no existingClaim does not add PVC volumes", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Storage: garagev1alpha1.StorageConfig{},
			},
		}
		cluster.Name = testClusterName
		volumes, _ := buildVolumesAndMounts(cluster)

		// Without existingClaim, metadata and data volumes come from VolumeClaimTemplates
		// so buildVolumesAndMounts should NOT add them
		for _, v := range volumes {
			if v.Name == metadataVolumeName && v.PersistentVolumeClaim != nil {
				t.Error("metadata volume should not have PVC source when no existingClaim")
			}
			if v.Name == dataVolumeName && v.PersistentVolumeClaim != nil {
				t.Error("data volume should not have PVC source when no existingClaim")
			}
		}
	})

	t.Run("gateway cluster - uses EmptyDir for data regardless of existingClaim", func(t *testing.T) {
		cluster := &garagev1alpha1.GarageCluster{
			Spec: garagev1alpha1.GarageClusterSpec{
				Gateway: true,
				Storage: garagev1alpha1.StorageConfig{
					Data: &garagev1alpha1.DataStorageConfig{
						ExistingClaim: "should-be-ignored",
					},
				},
			},
		}
		cluster.Name = "test-gateway"
		volumes, _ := buildVolumesAndMounts(cluster)

		var dataVolume *corev1.Volume
		for i := range volumes {
			if volumes[i].Name == dataVolumeName {
				dataVolume = &volumes[i]
				break
			}
		}
		if dataVolume == nil {
			t.Error("data volume not found for gateway cluster")
			return
		}
		if dataVolume.EmptyDir == nil {
			t.Error("gateway data volume should use EmptyDir, not PVC")
		}
	})
}

func ptrQuantity(q resource.Quantity) *resource.Quantity {
	return &q
}
