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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	metadataVolumeName     = "metadata"
	dataVolumeName         = "data"
	testClusterName        = "test-cluster"
	testNonExistentCluster = "non-existent-cluster"
	testNonExistent        = "non-existent"
	testExternalRPCSecret  = "external-rpc-secret"
	testStorageClass       = "fast-ssd"
	testIPv4Addr           = "10.0.0.1"
	testEndpointKey        = "endpoint"
	testHostKey            = "host"
	testAccessKeyID        = "AKIAIOSFODNN7EXAMPLE"
	testCustomKey          = "custom-key"
	testImageFull          = "custom/garage:v1.0.0"
	testImageRepo          = "my-mirror/garage"
	testImageFull2         = "custom/garage:v3.0.0"
	testNodeImageRepo      = "node-mirror/garage"
	testAccessKeyIDKey     = "access-key-id"
	testSecretAccessKey    = "secret-access-key"
	testSchemeKey          = "scheme"
	testRegionKey          = "region"
	testSecretValue        = "secret123"
	testOperatorImage      = "registry.example.com/garage:v2.0.0"
	testPortNameRPC        = "rpc"
)

func TestResolveSecretConfig(t *testing.T) {
	tests := []struct {
		name     string
		key      *garagev1beta1.GarageKey
		expected secretConfig
	}{
		{
			name: "default config when no template specified",
			key: &garagev1beta1.GarageKey{
				Spec: garagev1beta1.GarageKeySpec{},
			},
			expected: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				endpointKey:        testEndpointKey,
				hostKey:            testHostKey,
				schemeKey:          testSchemeKey,
				regionKey:          testRegionKey,
				includeEndpoint:    true,
				includeRegion:      true,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "custom key names",
			key: &garagev1beta1.GarageKey{
				Spec: garagev1beta1.GarageKeySpec{
					SecretTemplate: &garagev1beta1.SecretTemplate{
						AccessKeyIDKey:     "AWS_ACCESS_KEY_ID",
						SecretAccessKeyKey: "AWS_SECRET_ACCESS_KEY",
						EndpointKey:        "AWS_ENDPOINT",
						HostKey:            "AWS_HOST",
						SchemeKey:          "AWS_SCHEME",
						RegionKey:          "AWS_REGION",
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     "AWS_ACCESS_KEY_ID",
				secretAccessKeyKey: "AWS_SECRET_ACCESS_KEY",
				endpointKey:        "AWS_ENDPOINT",
				hostKey:            "AWS_HOST",
				schemeKey:          "AWS_SCHEME",
				regionKey:          "AWS_REGION",
				includeEndpoint:    true,
				includeRegion:      true,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "disable endpoint and region",
			key: &garagev1beta1.GarageKey{
				Spec: garagev1beta1.GarageKeySpec{
					SecretTemplate: &garagev1beta1.SecretTemplate{
						IncludeEndpoint: boolPtr(false),
						IncludeRegion:   boolPtr(false),
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				endpointKey:        testEndpointKey,
				hostKey:            testHostKey,
				schemeKey:          testSchemeKey,
				regionKey:          testRegionKey,
				includeEndpoint:    false,
				includeRegion:      false,
				secretType:         corev1.SecretTypeOpaque,
			},
		},
		{
			name: "custom secret type",
			key: &garagev1beta1.GarageKey{
				Spec: garagev1beta1.GarageKeySpec{
					SecretTemplate: &garagev1beta1.SecretTemplate{
						Type: corev1.SecretTypeDockerConfigJson,
					},
				},
			},
			expected: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				endpointKey:        testEndpointKey,
				hostKey:            testHostKey,
				schemeKey:          testSchemeKey,
				regionKey:          testRegionKey,
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
			if result.hostKey != tt.expected.hostKey {
				t.Errorf("hostKey = %q, want %q", result.hostKey, tt.expected.hostKey)
			}
			if result.schemeKey != tt.expected.schemeKey {
				t.Errorf("schemeKey = %q, want %q", result.schemeKey, tt.expected.schemeKey)
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
		key             *garagev1beta1.GarageKey
		cluster         *garagev1beta1.GarageCluster
		secretAccessKey string
		wantKeys        []string
		wantValues      map[string]string
	}{
		{
			name: "basic secret with all fields",
			cfg: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				endpointKey:        testEndpointKey,
				hostKey:            testHostKey,
				schemeKey:          testSchemeKey,
				regionKey:          testRegionKey,
				includeEndpoint:    true,
				includeRegion:      true,
			},
			key: &garagev1beta1.GarageKey{
				Status: garagev1beta1.GarageKeyStatus{
					AccessKeyID: testAccessKeyID,
				},
			},
			cluster: &garagev1beta1.GarageCluster{
				Spec: garagev1beta1.GarageClusterSpec{
					S3API: &garagev1beta1.S3APIConfig{
						Region: "us-west-2",
					},
				},
			},
			secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantKeys:        []string{testAccessKeyIDKey, testSecretAccessKey, testEndpointKey, testHostKey, testSchemeKey, testRegionKey},
			wantValues: map[string]string{
				testAccessKeyIDKey:  testAccessKeyID,
				testSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				testRegionKey:       "us-west-2",
				testSchemeKey:       "http",
			},
		},
		{
			name: "without endpoint and region",
			cfg: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				endpointKey:        testEndpointKey,
				hostKey:            testHostKey,
				schemeKey:          testSchemeKey,
				regionKey:          testRegionKey,
				includeEndpoint:    false,
				includeRegion:      false,
			},
			key: &garagev1beta1.GarageKey{
				Status: garagev1beta1.GarageKeyStatus{
					AccessKeyID: testAccessKeyID,
				},
			},
			cluster:         &garagev1beta1.GarageCluster{},
			secretAccessKey: testSecretValue,
			wantKeys:        []string{"access-key-id", "secret-access-key"},
		},
		{
			name: "default region when not specified",
			cfg: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				regionKey:          testRegionKey,
				includeEndpoint:    false,
				includeRegion:      true,
			},
			key: &garagev1beta1.GarageKey{
				Status: garagev1beta1.GarageKeyStatus{
					AccessKeyID: testAccessKeyID,
				},
			},
			cluster:         &garagev1beta1.GarageCluster{},
			secretAccessKey: testSecretValue,
			wantValues: map[string]string{
				testRegionKey: defaultS3Region,
			},
		},
		{
			name: "with additional data",
			cfg: secretConfig{
				accessKeyIDKey:     testAccessKeyIDKey,
				secretAccessKeyKey: testSecretAccessKey,
				includeEndpoint:    false,
				includeRegion:      false,
				additionalData: map[string]string{
					testCustomKey: "custom-value",
				},
			},
			key: &garagev1beta1.GarageKey{
				Status: garagev1beta1.GarageKeyStatus{
					AccessKeyID: testAccessKeyID,
				},
			},
			cluster:         &garagev1beta1.GarageCluster{},
			secretAccessKey: testSecretValue,
			wantKeys:        []string{"access-key-id", "secret-access-key", "custom-key"},
			wantValues: map[string]string{
				testCustomKey: "custom-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSecretData(tt.cfg, tt.key, tt.cluster, tt.secretAccessKey, "cluster.local")

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

func TestResolveGarageImage(t *testing.T) {
	tests := []struct {
		name            string
		image           string
		imageRepository string
		operatorDefault string
		expected        string
	}{
		{
			name:     "defaults when all empty",
			expected: defaultGarageImage,
		},
		{
			name:     "image takes precedence",
			image:    testImageFull,
			expected: "custom/garage:v1.0.0",
		},
		{
			name:            "imageRepository uses default tag",
			imageRepository: testImageRepo,
			expected:        "my-mirror/garage:" + defaultGarageTag,
		},
		{
			name:            "image overrides imageRepository",
			image:           "full/override:latest",
			imageRepository: testImageRepo,
			expected:        "full/override:latest",
		},
		{
			name:            "operator default used when CR fields empty",
			operatorDefault: testOperatorImage,
			expected:        testOperatorImage,
		},
		{
			name:            "CR image overrides operator default",
			image:           testImageFull,
			operatorDefault: testOperatorImage,
			expected:        "custom/garage:v1.0.0",
		},
		{
			name:            "CR imageRepository overrides operator default",
			imageRepository: testImageRepo,
			operatorDefault: testOperatorImage,
			expected:        "my-mirror/garage:" + defaultGarageTag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveGarageImage(tt.image, tt.imageRepository, tt.operatorDefault)
			if got != tt.expected {
				t.Errorf("resolveGarageImage(%q, %q, %q) = %q, want %q", tt.image, tt.imageRepository, tt.operatorDefault, got, tt.expected)
			}
		})
	}
}

func TestMergeNodeImage(t *testing.T) {
	tests := []struct {
		name            string
		clusterImage    string
		clusterRepo     string
		nodeImage       string
		nodeRepo        string
		operatorDefault string
		expected        string
	}{
		{
			name:     "all empty uses default",
			expected: defaultGarageImage,
		},
		{
			name:         "cluster image only",
			clusterImage: testImageFull2,
			expected:     testImageFull2,
		},
		{
			name:        "cluster imageRepository only",
			clusterRepo: testImageRepo,
			expected:    "my-mirror/garage:" + defaultGarageTag,
		},
		{
			name:         "node image overrides cluster image",
			clusterImage: "cluster/garage:v1.0.0",
			nodeImage:    "node/garage:v2.0.0",
			expected:     "node/garage:v2.0.0",
		},
		{
			name:         "node imageRepository overrides cluster image",
			clusterImage: "cluster/garage:v3.0.0",
			nodeRepo:     testNodeImageRepo,
			expected:     "node-mirror/garage:" + defaultGarageTag,
		},
		{
			name:        "node imageRepository overrides cluster imageRepository",
			clusterRepo: "cluster-mirror/garage",
			nodeRepo:    testNodeImageRepo,
			expected:    "node-mirror/garage:" + defaultGarageTag,
		},
		{
			name:         "node image wins over everything",
			clusterImage: "cluster/garage:v1.0.0",
			clusterRepo:  "cluster-mirror/garage",
			nodeImage:    "node/garage:latest",
			nodeRepo:     testNodeImageRepo,
			expected:     "node/garage:latest",
		},
		{
			name:            "operator default used when all empty",
			operatorDefault: testOperatorImage,
			expected:        testOperatorImage,
		},
		{
			name:            "cluster image overrides operator default",
			clusterImage:    testImageFull2,
			operatorDefault: testOperatorImage,
			expected:        testImageFull2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeNodeImage(tt.clusterImage, tt.clusterRepo, tt.nodeImage, tt.nodeRepo, tt.operatorDefault)
			if got != tt.expected {
				t.Errorf("mergeNodeImage(%q, %q, %q, %q, %q) = %q, want %q",
					tt.clusterImage, tt.clusterRepo, tt.nodeImage, tt.nodeRepo, tt.operatorDefault, got, tt.expected)
			}
		})
	}
}

func TestBuildContainerPorts(t *testing.T) {
	tests := []struct {
		name        string
		cluster     *garagev1beta1.GarageCluster
		wantMinPort int
		wantPorts   []string
	}{
		{
			name: "default ports",
			cluster: &garagev1beta1.GarageCluster{
				Spec: garagev1beta1.GarageClusterSpec{},
			},
			wantMinPort: 3, // RPC, Admin, S3
			wantPorts:   []string{testPortNameRPC, "s3", adminPortName},
		},
		// S3 API is always enabled - Garage requires the [s3_api] section
		{
			name: "with Admin API disabled",
			cluster: &garagev1beta1.GarageCluster{
				Spec: garagev1beta1.GarageClusterSpec{
					Admin: &garagev1beta1.AdminConfig{
						Enabled: false,
					},
				},
			},
			wantMinPort: 2, // RPC, S3 only
			wantPorts:   []string{testPortNameRPC, "s3"},
		},
		{
			name: "custom RPC port",
			cluster: &garagev1beta1.GarageCluster{
				Spec: garagev1beta1.GarageClusterSpec{
					Network: garagev1beta1.NetworkConfig{
						RPCBindPort: 4901,
					},
				},
			},
			wantMinPort: 3,
			wantPorts:   []string{testPortNameRPC, "s3", adminPortName},
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
	storageClass := testStorageClass
	dataSize := resource.MustParse("10Gi")

	t.Run("storage cluster - default sizes", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Metadata: &garagev1beta1.VolumeConfig{},
					Data:     &garagev1beta1.DataStorageConfig{},
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
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Metadata: &garagev1beta1.VolumeConfig{
						Size: ptrQuantity(resource.MustParse("1Gi")),
					},
					Data: &garagev1beta1.DataStorageConfig{
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
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
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
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Gateway: true,
				Storage: garagev1beta1.StorageConfig{
					Metadata: &garagev1beta1.VolumeConfig{
						Size:             ptrQuantity(resource.MustParse("2Gi")),
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

func TestBuildDataPVC_PathVolumeConfig(t *testing.T) {
	encryptedSC := "rook-ceph-block-encrypted"
	fastSC := testStorageClass

	t.Run("storageClassName from paths[].volume when top-level is unset", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						Paths: []garagev1beta1.DataPath{
							{
								Path:     dataPath,
								Capacity: ptrQuantity(resource.MustParse("100Gi")),
								Volume: &garagev1beta1.VolumeConfig{
									Size:             ptrQuantity(resource.MustParse("100Gi")),
									StorageClassName: &encryptedSC,
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != encryptedSC {
			t.Errorf("StorageClassName = %v, want %q", pvc.Spec.StorageClassName, encryptedSC)
		}
	})

	t.Run("top-level storageClassName takes precedence over paths", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						StorageClassName: &fastSC,
						Paths: []garagev1beta1.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta1.VolumeConfig{
									StorageClassName: &encryptedSC,
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != fastSC {
			t.Errorf("StorageClassName = %v, want %q (top-level should win)", pvc.Spec.StorageClassName, fastSC)
		}
	})

	t.Run("accessModes from paths[].volume", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						Paths: []garagev1beta1.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta1.VolumeConfig{
									AccessModes: []corev1.PersistentVolumeAccessMode{
										corev1.ReadWriteMany,
									},
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteMany {
			t.Errorf("AccessModes = %v, want [ReadWriteMany]", pvc.Spec.AccessModes)
		}
	})

	t.Run("selector from paths[].volume", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						Paths: []garagev1beta1.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta1.VolumeConfig{
									Selector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"tier": "fast"},
									},
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.Selector == nil {
			t.Fatal("Selector is nil, want non-nil")
		}
		if pvc.Spec.Selector.MatchLabels["tier"] != "fast" {
			t.Errorf("Selector.MatchLabels = %v, want tier=fast", pvc.Spec.Selector.MatchLabels)
		}
	})

	t.Run("no paths - defaults unchanged", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName != nil {
			t.Errorf("StorageClassName = %v, want nil (cluster default)", pvc.Spec.StorageClassName)
		}
		if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce {
			t.Errorf("AccessModes = %v, want [ReadWriteOnce]", pvc.Spec.AccessModes)
		}
		if pvc.Spec.Selector != nil {
			t.Errorf("Selector = %v, want nil", pvc.Spec.Selector)
		}
	})

	t.Run("paths with no volume config - defaults unchanged", func(t *testing.T) {
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						Paths: []garagev1beta1.DataPath{
							{Path: dataPath, Capacity: ptrQuantity(resource.MustParse("50Gi"))},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName != nil {
			t.Errorf("StorageClassName = %v, want nil", pvc.Spec.StorageClassName)
		}
		if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce {
			t.Errorf("AccessModes = %v, want [ReadWriteOnce]", pvc.Spec.AccessModes)
		}
	})

	t.Run("first path with volume wins over later paths", func(t *testing.T) {
		secondSC := "slow-hdd"
		cluster := &garagev1beta1.GarageCluster{
			Spec: garagev1beta1.GarageClusterSpec{
				Storage: garagev1beta1.StorageConfig{
					Data: &garagev1beta1.DataStorageConfig{
						Paths: []garagev1beta1.DataPath{
							{Path: "/data/a", Volume: &garagev1beta1.VolumeConfig{StorageClassName: &encryptedSC}},
							{Path: "/data/b", Volume: &garagev1beta1.VolumeConfig{StorageClassName: &secondSC}},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != encryptedSC {
			t.Errorf("StorageClassName = %v, want %q (first path should win)", pvc.Spec.StorageClassName, encryptedSC)
		}
	})
}

func TestFindNodeByIPs(t *testing.T) {
	addr := func(s string) *string { return &s }
	var u64 uint64 = 5

	tests := []struct {
		name   string
		nodes  []garage.NodeInfo
		podIPs []string
		wantID string
		wantOK bool
	}{
		{
			name: "ipv4 match on primary",
			nodes: []garage.NodeInfo{
				{ID: "aaa", Address: addr("10.0.0.1:3901"), IsUp: true, LastSeenSecsAgo: &u64},
			},
			podIPs: []string{testIPv4Addr},
			wantID: "aaa", wantOK: true,
		},
		{
			name: "ipv6 match on secondary pod IP",
			nodes: []garage.NodeInfo{
				{ID: "bbb", Address: addr("[2a14::1]:3901"), IsUp: true, LastSeenSecsAgo: &u64},
			},
			podIPs: []string{"192.168.1.5", "2a14::1"},
			wantID: "bbb", wantOK: true,
		},
		{
			name: "no match when node has nil address",
			nodes: []garage.NodeInfo{
				{ID: "ccc", Address: nil, IsUp: true, LastSeenSecsAgo: nil},
			},
			podIPs: []string{testIPv4Addr},
			wantOK: false,
		},
		{
			name:   "no match in empty list",
			nodes:  []garage.NodeInfo{},
			podIPs: []string{testIPv4Addr},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := findNodeByIPs(tt.nodes, tt.podIPs)
			if gotOK != tt.wantOK {
				t.Errorf("findNodeByIPs() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotOK && gotID != tt.wantID {
				t.Errorf("findNodeByIPs() id = %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestFindSelfNode(t *testing.T) {
	addr := func(s string) *string { return &s }
	var u64 uint64 = 3

	tests := []struct {
		name   string
		nodes  []garage.NodeInfo
		wantID string
		wantOK bool
	}{
		{
			name: "self is isUp with nil lastSeenSecsAgo",
			nodes: []garage.NodeInfo{
				{ID: "peer1", Address: addr("10.0.0.2:3901"), IsUp: true, LastSeenSecsAgo: &u64},
				{ID: "self1", Address: nil, IsUp: true, LastSeenSecsAgo: nil},
			},
			wantID: "self1", wantOK: true,
		},
		{
			name: "self with rpc_public_addr set still has nil lastSeenSecsAgo",
			nodes: []garage.NodeInfo{
				{ID: "peer1", Address: addr("10.0.0.2:3901"), IsUp: true, LastSeenSecsAgo: &u64},
				{ID: "self2", Address: addr("203.0.113.1:3901"), IsUp: true, LastSeenSecsAgo: nil},
			},
			wantID: "self2", wantOK: true,
		},
		{
			name: "no self when all nodes have lastSeenSecsAgo",
			nodes: []garage.NodeInfo{
				{ID: "n1", Address: addr("10.0.0.1:3901"), IsUp: true, LastSeenSecsAgo: &u64},
				{ID: "n2", Address: addr("10.0.0.2:3901"), IsUp: true, LastSeenSecsAgo: &u64},
			},
			wantOK: false,
		},
		{
			name:   "empty list",
			nodes:  []garage.NodeInfo{},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := findSelfNode(tt.nodes)
			if gotOK != tt.wantOK {
				t.Errorf("findSelfNode() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotOK && gotID != tt.wantID {
				t.Errorf("findSelfNode() id = %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestAdminEndpoint(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int32
		want string
	}{
		{"ipv4", "192.168.1.1", 3903, "http://192.168.1.1:3903"},
		{"ipv6", "2a14:abcd::5d92", 3903, "http://[2a14:abcd::5d92]:3903"},
		{"ipv6 loopback", "::1", 3903, "http://[::1]:3903"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := adminEndpoint(tt.ip, tt.port)
			if got != tt.want {
				t.Errorf("adminEndpoint(%q, %d) = %q, want %q", tt.ip, tt.port, got, tt.want)
			}
		})
	}
}

func TestRPCAddr(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int32
		want string
	}{
		{"ipv4", "10.0.0.1", 3901, "10.0.0.1:3901"},
		{"ipv6", "2a14:abcd::5d92", 3901, "[2a14:abcd::5d92]:3901"},
		{"ipv6 loopback", "::1", 3901, "[::1]:3901"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rpcAddr(tt.ip, tt.port)
			if got != tt.want {
				t.Errorf("rpcAddr(%q, %d) = %q, want %q", tt.ip, tt.port, got, tt.want)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestEffectiveWebAPI(t *testing.T) {
	tests := []struct {
		name               string
		cluster            *garagev1beta1.GarageCluster
		expectNonNil       bool
		expectedRootDomain string
		wantURL            string
	}{
		{
			name: "default rootDomain when WebAPI spec is nil",
			cluster: &garagev1beta1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec:       garagev1beta1.GarageClusterSpec{},
			},
			expectNonNil:       true,
			expectedRootDomain: ".garage.default.svc",
			wantURL:            "http://mybucket.garage.default.svc",
		},
		{
			name: "returns nil when web API disabled",
			cluster: &garagev1beta1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec: garagev1beta1.GarageClusterSpec{
					WebAPI: &garagev1beta1.WebAPIConfig{Disabled: true},
				},
			},
			expectNonNil: false,
		},
		{
			name: "uses custom rootDomain when set",
			cluster: &garagev1beta1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec: garagev1beta1.GarageClusterSpec{
					WebAPI: &garagev1beta1.WebAPIConfig{RootDomain: ".web.example.com"},
				},
			},
			expectNonNil:       true,
			expectedRootDomain: ".web.example.com",
			wantURL:            "http://mybucket.web.example.com",
		},
		{
			name: "explicit Disabled: false with custom domain",
			cluster: &garagev1beta1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "mygarage", Namespace: "myns"},
				Spec: garagev1beta1.GarageClusterSpec{
					WebAPI: &garagev1beta1.WebAPIConfig{
						Disabled:   false,
						RootDomain: ".custom.local",
					},
				},
			},
			expectNonNil:       true,
			expectedRootDomain: ".custom.local",
			wantURL:            "http://mybucket.custom.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := effectiveWebAPI(tt.cluster)

			if tt.expectNonNil {
				if result == nil {
					t.Errorf("effectiveWebAPI() = nil, want non-nil")
					return
				}
				if result.RootDomain != tt.expectedRootDomain {
					t.Errorf("RootDomain = %q, want %q", result.RootDomain, tt.expectedRootDomain)
				}
				if tt.wantURL != "" {
					gotURL := "http://mybucket" + result.RootDomain
					if gotURL != tt.wantURL {
						t.Errorf("composed URL = %q, want %q", gotURL, tt.wantURL)
					}
				}
			} else {
				if result != nil {
					t.Errorf("effectiveWebAPI() = %v, want nil", result)
				}
			}
		})
	}
}

func ptrQuantity(q resource.Quantity) *resource.Quantity {
	return &q
}
