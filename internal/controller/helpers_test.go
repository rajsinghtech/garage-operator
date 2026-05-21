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
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
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
	teamLabelKey           = "team"
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
		cluster         *garagev1beta2.GarageCluster
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
			cluster: &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{
					S3API: &garagev1beta2.S3APIConfig{
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
			cluster:         &garagev1beta2.GarageCluster{},
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
			cluster:         &garagev1beta2.GarageCluster{},
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
			cluster:         &garagev1beta2.GarageCluster{},
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
		cluster     *garagev1beta2.GarageCluster
		wantMinPort int
		wantPorts   []string
	}{
		{
			name: "default ports",
			cluster: &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{},
			},
			wantMinPort: 3, // RPC, Admin, S3
			wantPorts:   []string{testPortNameRPC, "s3", adminPortName},
		},
		// S3 API is always enabled - Garage requires the [s3_api] section
		{
			name: "with Admin API disabled",
			cluster: &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{},
			},
			wantMinPort: 2, // RPC, S3 only
			wantPorts:   []string{testPortNameRPC, "s3"},
		},
		{
			name: "custom RPC port",
			cluster: &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{
					Network: garagev1beta2.NetworkConfig{
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
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{},
					Data:     &garagev1beta2.VolumeConfig{},
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
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{
						Size: ptrQuantity(resource.MustParse("1Gi")),
					},
					Data: &garagev1beta2.VolumeConfig{
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

	t.Run("gateway-only cluster - no PVCs (EmptyDir for both)", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Gateway:   &garagev1beta2.GatewaySpec{Replicas: 1},
				ConnectTo: &garagev1beta2.ConnectToConfig{ClusterRef: &garagev1beta2.ClusterReference{Name: "storage"}},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 0 {
			t.Errorf("gateway-only cluster: got %d PVCs, want 0 (gateway tier uses EmptyDir)", len(pvcs))
		}
	})

	t.Run("unified cluster (storage + gateway) - only storage PVCs", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("2Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("50Gi"))},
				},
				Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			},
		}
		pvcs := buildVolumeClaimTemplates(cluster)
		if len(pvcs) != 2 {
			t.Errorf("unified cluster: got %d PVCs, want 2 (gateway never gets PVCs)", len(pvcs))
		}
	})
}

func TestBuildDataPVC_PathVolumeConfig(t *testing.T) {
	const fastTier = "fast"
	encryptedSC := "rook-ceph-block-encrypted"
	fastSC := testStorageClass

	t.Run("storageClassName set on data volume directly", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Size:             ptrQuantity(resource.MustParse("100Gi")),
						StorageClassName: &encryptedSC,
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
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						StorageClassName: &fastSC,
						Paths: []garagev1beta2.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta2.DataPathVolumeConfig{
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

	t.Run("accessModes set on data volume directly", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						AccessModes: []corev1.PersistentVolumeAccessMode{
							corev1.ReadWriteMany,
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

	t.Run("selector set on data volume directly", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"tier": fastTier},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.Selector == nil {
			t.Fatal("Selector is nil, want non-nil")
		}
		if pvc.Spec.Selector.MatchLabels["tier"] != fastTier {
			t.Errorf("Selector.MatchLabels = %v, want tier=fast", pvc.Spec.Selector.MatchLabels)
		}
	})

	t.Run("no paths - defaults unchanged", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{},
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
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
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

	t.Run("top-level storageClassName used when paths present but no volume-level override", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						StorageClassName: &encryptedSC,
						Paths: []garagev1beta2.DataPath{
							{Path: "/data/a", Capacity: ptrQuantity(resource.MustParse("50Gi"))},
							{Path: "/data/b", Capacity: ptrQuantity(resource.MustParse("50Gi"))},
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

	t.Run("paths[].volume.storageClassName applied when top-level unset (issue #162)", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
							{
								Path:     dataPath,
								Capacity: ptrQuantity(resource.MustParse("50Gi")),
								Volume: &garagev1beta2.DataPathVolumeConfig{
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
			t.Errorf("StorageClassName = %v, want %q (path-level fallback)", pvc.Spec.StorageClassName, encryptedSC)
		}
	})

	t.Run("paths[].volume.accessModes applied when top-level unset", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta2.DataPathVolumeConfig{
									AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteMany {
			t.Errorf("AccessModes = %v, want [ReadWriteMany] (path-level fallback)", pvc.Spec.AccessModes)
		}
	})

	t.Run("paths[].volume.selector applied when top-level unset", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta2.DataPathVolumeConfig{
									Selector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"tier": fastTier},
									},
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.Selector == nil || pvc.Spec.Selector.MatchLabels["tier"] != fastTier {
			t.Errorf("Selector = %v, want tier=fast (path-level fallback)", pvc.Spec.Selector)
		}
	})

	t.Run("paths[].volume.size applied when top-level size unset", func(t *testing.T) {
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
							{
								Path: dataPath,
								Volume: &garagev1beta2.DataPathVolumeConfig{
									Size: ptrQuantity(resource.MustParse("250Gi")),
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		got := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
		if got.String() != "250Gi" {
			t.Errorf("size = %q, want %q (path-level fallback)", got.String(), "250Gi")
		}
	})

	t.Run("first path with volume wins when multiple paths present", func(t *testing.T) {
		other := "other-sc"
		cluster := &garagev1beta2.GarageCluster{
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{Replicas: 1,
					Data: &garagev1beta2.VolumeConfig{
						Paths: []garagev1beta2.DataPath{
							{Path: "/data/a", Capacity: ptrQuantity(resource.MustParse("50Gi"))},
							{
								Path: "/data/b",
								Volume: &garagev1beta2.DataPathVolumeConfig{
									StorageClassName: &encryptedSC,
								},
							},
							{
								Path: "/data/c",
								Volume: &garagev1beta2.DataPathVolumeConfig{
									StorageClassName: &other,
								},
							},
						},
					},
				},
			},
		}
		pvc := buildDataPVC(cluster)
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != encryptedSC {
			t.Errorf("StorageClassName = %v, want %q (first path with volume wins)", pvc.Spec.StorageClassName, encryptedSC)
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
		cluster            *garagev1beta2.GarageCluster
		expectNonNil       bool
		expectedRootDomain string
		wantURL            string
	}{
		{
			name: "returns_config_when_WebAPI_enabled_is_true",
			cluster: &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					WebAPI: &garagev1beta2.WebAPIConfig{Enabled: boolPtr(true), RootDomain: ".test.svc"},
				},
			},
			expectNonNil:       true,
			expectedRootDomain: ".test.svc",
			wantURL:            "http://mybucket.test.svc",
		},
		{
			name: "returns nil when web API disabled",
			cluster: &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					WebAPI: &garagev1beta2.WebAPIConfig{Enabled: boolPtr(false)},
				},
			},
			expectNonNil: false,
		},
		{
			name: "uses custom rootDomain when set",
			cluster: &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: defaultS3Region, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					WebAPI: &garagev1beta2.WebAPIConfig{RootDomain: ".web.example.com"},
				},
			},
			expectNonNil:       true,
			expectedRootDomain: ".web.example.com",
			wantURL:            "http://mybucket.web.example.com",
		},
		{
			name: "explicit Disabled: false with custom domain",
			cluster: &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "mygarage", Namespace: "myns"},
				Spec: garagev1beta2.GarageClusterSpec{
					WebAPI: &garagev1beta2.WebAPIConfig{
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

func TestMergeLabels(t *testing.T) {
	const (
		keyApp       = labelAppName
		keyManagedBy = labelAppManagedBy
		keyPool      = "example.io/pool"
	)
	tests := []struct {
		name string
		base map[string]string
		user map[string]string
		want map[string]string
	}{
		{
			name: "user labels merged",
			base: map[string]string{keyApp: defaultAppName, keyManagedBy: "operator"},
			user: map[string]string{keyPool: "rpc"},
			want: map[string]string{keyApp: defaultAppName, keyManagedBy: "operator", keyPool: "rpc"},
		},
		{
			name: "base wins on conflict",
			base: map[string]string{keyApp: defaultAppName},
			user: map[string]string{keyApp: "override"},
			want: map[string]string{keyApp: defaultAppName},
		},
		{
			name: "nil user returns base",
			base: map[string]string{keyApp: defaultAppName},
			user: nil,
			want: map[string]string{keyApp: defaultAppName},
		},
		{
			name: "empty user returns base",
			base: map[string]string{keyApp: defaultAppName},
			user: map[string]string{},
			want: map[string]string{keyApp: defaultAppName},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeLabels(tt.base, tt.user)
			if len(got) != len(tt.want) {
				t.Fatalf("mergeLabels len = %d, want %d: got %v", len(got), len(tt.want), got)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("mergeLabels[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestBuildNodeTags_TierTag verifies the tier:<tier> tag is emitted when a
// non-empty tier is provided. Tier tags let federation and admin tooling
// distinguish storage from gateway entries in the layout.
func TestBuildNodeTags_TierTag(t *testing.T) {
	tests := []struct {
		name      string
		tier      string
		wantTier  bool
		wantValue string
	}{
		{name: "gateway tier emits tier:gateway", tier: tierGateway, wantTier: true, wantValue: "tier:" + tierGateway},
		{name: "storage tier emits tier:storage", tier: tierStorage, wantTier: true, wantValue: "tier:" + tierStorage},
		{name: "empty tier omits tier tag", tier: "", wantTier: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := buildNodeTags("my-cluster", "my-ns", tt.tier, nil, "pod-0")
			gotTier := false
			for _, tag := range tags {
				if tag == tt.wantValue {
					gotTier = true
				}
				if len(tag) > 5 && tag[:5] == "tier:" {
					if !tt.wantTier {
						t.Errorf("unexpected tier tag %q in %v", tag, tags)
					}
				}
			}
			if tt.wantTier && !gotTier {
				t.Errorf("missing tier tag %q in %v", tt.wantValue, tags)
			}
			// Always expect the ownership tag.
			ownership := "cluster:my-cluster/my-ns"
			gotOwnership := false
			for _, tag := range tags {
				if tag == ownership {
					gotOwnership = true
				}
			}
			if !gotOwnership {
				t.Errorf("missing ownership tag %q in %v", ownership, tags)
			}
		})
	}
}

func TestCountTotalNodesAfterApply(t *testing.T) {
	role := func(id string) garage.LayoutNodeRole { return garage.LayoutNodeRole{ID: id, Zone: "z"} }
	add := func(id string) garage.NodeRoleChange { return garage.NodeRoleChange{ID: id, Zone: "z"} }
	remove := func(id string) garage.NodeRoleChange { return garage.NodeRoleChange{ID: id, Remove: true} }

	tests := []struct {
		name   string
		layout garage.ClusterLayout
		want   int
	}{
		{
			name: "three real roles, three stale removes (issue #171)",
			layout: garage.ClusterLayout{
				Roles:             []garage.LayoutNodeRole{role("a"), role("b"), role("c")},
				StagedRoleChanges: []garage.NodeRoleChange{remove("stale1"), remove("stale2"), remove("stale3")},
			},
			want: 3,
		},
		{
			name: "three real roles, one real remove",
			layout: garage.ClusterLayout{
				Roles:             []garage.LayoutNodeRole{role("a"), role("b"), role("c")},
				StagedRoleChanges: []garage.NodeRoleChange{remove("a")},
			},
			want: 2,
		},
		{
			name: "zero roles, three adds",
			layout: garage.ClusterLayout{
				Roles:             nil,
				StagedRoleChanges: []garage.NodeRoleChange{add("a"), add("b"), add("c")},
			},
			want: 3,
		},
		{
			name: "three roles, one add matching existing (drift fix)",
			layout: garage.ClusterLayout{
				Roles:             []garage.LayoutNodeRole{role("a"), role("b"), role("c")},
				StagedRoleChanges: []garage.NodeRoleChange{add("a")},
			},
			want: 3,
		},
		{
			name: "mixed: 2 real roles, 1 real remove, 1 stale remove, 1 new add",
			layout: garage.ClusterLayout{
				Roles:             []garage.LayoutNodeRole{role("a"), role("b")},
				StagedRoleChanges: []garage.NodeRoleChange{remove("a"), remove("ghost"), add("c")},
			},
			want: 2, // 2 - 1 (real) + 1 (new) = 2
		},
		{
			name:   "empty layout",
			layout: garage.ClusterLayout{},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countTotalNodesAfterApply(&tt.layout); got != tt.want {
				t.Errorf("countTotalNodesAfterApply() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestComputePodSpecHash(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{{Name: "garage", Image: "dxflrs/garage:v2.3.0"}},
	}

	baseHash := computePodSpecHash(spec, nil, nil)

	t.Run("same input is deterministic across calls", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			if got := computePodSpecHash(spec, nil, nil); got != baseHash {
				t.Errorf("non-deterministic hash: iter %d got %q, want %q", i, got, baseHash)
			}
		}
	})

	t.Run("different podAnnotations produce different hash", func(t *testing.T) {
		h := computePodSpecHash(spec, map[string]string{teamLabelKey: "platform"}, nil)
		if h == baseHash {
			t.Errorf("expected different hash when annotations added, got same %q", h)
		}
	})

	t.Run("different podLabels produce different hash", func(t *testing.T) {
		h := computePodSpecHash(spec, nil, map[string]string{"role": "hot"})
		if h == baseHash {
			t.Errorf("expected different hash when labels added, got same %q", h)
		}
	})

	t.Run("same annotations produce same hash (map ordering)", func(t *testing.T) {
		a := map[string]string{"a": "1", "b": "2", "c": "3"}
		b := map[string]string{"c": "3", "a": "1", "b": "2"}
		if computePodSpecHash(spec, a, nil) != computePodSpecHash(spec, b, nil) {
			t.Errorf("expected same hash for equivalent annotation maps")
		}
	})

	t.Run("annotation value change produces different hash", func(t *testing.T) {
		a := computePodSpecHash(spec, map[string]string{teamLabelKey: "platform"}, nil)
		b := computePodSpecHash(spec, map[string]string{teamLabelKey: "infra"}, nil)
		if a == b {
			t.Errorf("expected different hashes for different annotation values")
		}
	})

	t.Run("hash is 16 hex chars", func(t *testing.T) {
		if len(baseHash) != 16 {
			t.Errorf("hash length = %d, want 16", len(baseHash))
		}
	})
}

func TestBuildGaragePodSpec_UserEnv(t *testing.T) {
	userEnv := []corev1.EnvVar{
		{Name: "GARAGE_ALLOW_WORLD_READABLE_SECRETS", Value: "true"},
		{Name: "MY_EXTRA", Value: "foo"},
		// Intentional override: user re-declares GARAGE_NODE_HOST. Since user env
		// is appended AFTER the built-in, this entry must appear after the
		// built-in in the resulting container.Env slice.
		{Name: envGarageNodeHost, Value: "overridden.example"},
	}
	userEnvFrom := []corev1.EnvFromSource{
		{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"}}},
	}

	spec := buildGaragePodSpec(PodSpecConfig{
		Image:   defaultGarageImage,
		Env:     userEnv,
		EnvFrom: userEnvFrom,
	}, nil, nil, nil)
	if len(spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(spec.Containers))
	}
	c := spec.Containers[0]

	// EnvFrom passes through verbatim.
	if len(c.EnvFrom) != 1 || c.EnvFrom[0].SecretRef == nil || c.EnvFrom[0].SecretRef.Name != "my-secret" {
		t.Errorf("envFrom not propagated: %+v", c.EnvFrom)
	}

	// Custom env var must be present.
	got := map[string][]string{}
	for _, e := range c.Env {
		got[e.Name] = append(got[e.Name], e.Value)
	}
	if vs, ok := got["GARAGE_ALLOW_WORLD_READABLE_SECRETS"]; !ok || vs[0] != "true" {
		t.Errorf("expected GARAGE_ALLOW_WORLD_READABLE_SECRETS=true, got %v", vs)
	}
	if vs, ok := got["MY_EXTRA"]; !ok || vs[0] != "foo" {
		t.Errorf("expected MY_EXTRA=foo, got %v", vs)
	}

	// Built-in must still be present, and the user override must appear AFTER
	// the built-in so the runtime resolves to the user value.
	var builtInIdx, overrideIdx = -1, -1
	for i, e := range c.Env {
		if e.Name == envGarageNodeHost {
			if e.ValueFrom != nil && builtInIdx == -1 {
				builtInIdx = i
			} else if e.Value == "overridden.example" {
				overrideIdx = i
			}
		}
	}
	if builtInIdx == -1 {
		t.Errorf("built-in GARAGE_NODE_HOST (fieldRef) missing")
	}
	if overrideIdx == -1 {
		t.Errorf("user override GARAGE_NODE_HOST missing")
	}
	if builtInIdx != -1 && overrideIdx != -1 && overrideIdx <= builtInIdx {
		t.Errorf("user override at index %d must appear AFTER built-in at index %d", overrideIdx, builtInIdx)
	}
}

const (
	multiPathDataPath0 = "/data/data0"
	multiPathDataPath1 = "/data/data1"
	dataPathPVC0       = "data-0"
)

// TestBuildVolumeClaimTemplates_MultiPath asserts that issue #188 is fixed:
// when storage.data.paths[] declares multiple data directories, the operator
// must emit one PVC per path so each disk gets a separate volume — not a
// single PVC with a multi-mount overlap.
func TestBuildVolumeClaimTemplates_MultiPath(t *testing.T) {
	fastSC := "fast-ssd"
	slowSC := "bulk-hdd"
	size1 := resource.MustParse("500Gi")
	size2 := resource.MustParse("2Ti")

	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("5Gi"))},
				Data: &garagev1beta2.VolumeConfig{
					// top-level storageClass acts as fallback for paths
					// that don't override it
					StorageClassName: &slowSC,
					Paths: []garagev1beta2.DataPath{
						{
							Path:     multiPathDataPath0,
							Capacity: &size1,
							Volume: &garagev1beta2.DataPathVolumeConfig{
								Size:             &size1,
								StorageClassName: &fastSC,
							},
						},
						{
							Path:     multiPathDataPath1,
							Capacity: &size2,
							// no per-path volume — inherits top-level slowSC,
							// size falls back to Capacity
						},
					},
				},
			},
		},
	}

	pvcs := buildVolumeClaimTemplates(cluster)
	if len(pvcs) != 3 {
		t.Fatalf("got %d PVCs, want 3 (metadata + 2 data paths)", len(pvcs))
	}

	if pvcs[0].Name != metadataVolumeName {
		t.Errorf("PVC[0] name = %q, want %q", pvcs[0].Name, metadataVolumeName)
	}
	if pvcs[1].Name != dataPathPVC0 {
		t.Errorf("PVC[1] name = %q, want %q", pvcs[1].Name, dataPathPVC0)
	}
	if pvcs[2].Name != "data-1" {
		t.Errorf("PVC[2] name = %q, want %q", pvcs[2].Name, "data-1")
	}

	// Per-path volume config wins (fastSC, size1).
	if got := pvcs[1].Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(size1) != 0 {
		t.Errorf("data-0 size = %s, want %s", got.String(), size1.String())
	}
	if pvcs[1].Spec.StorageClassName == nil || *pvcs[1].Spec.StorageClassName != fastSC {
		t.Errorf("data-0 storageClass = %v, want %q", pvcs[1].Spec.StorageClassName, fastSC)
	}

	// Path with no per-path volume — falls back to top-level storageClass,
	// size derived from the path's Capacity.
	if got := pvcs[2].Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(size2) != 0 {
		t.Errorf("data-1 size = %s, want %s (from Capacity)", got.String(), size2.String())
	}
	if pvcs[2].Spec.StorageClassName == nil || *pvcs[2].Spec.StorageClassName != slowSC {
		t.Errorf("data-1 storageClass = %v, want %q (top-level fallback)", pvcs[2].Spec.StorageClassName, slowSC)
	}
}

// TestBuildVolumeClaimTemplates_SinglePathBackwardCompat ensures that the
// legacy (no-paths) layout still produces a single `data` PVC. Existing
// clusters must not see a PVC rename.
func TestBuildVolumeClaimTemplates_SinglePathBackwardCompat(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("5Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
		},
	}
	pvcs := buildVolumeClaimTemplates(cluster)
	if len(pvcs) != 2 {
		t.Fatalf("got %d PVCs, want 2", len(pvcs))
	}
	if pvcs[1].Name != dataVolumeName {
		t.Errorf("data PVC name = %q, want %q (legacy backward-compat)", pvcs[1].Name, dataVolumeName)
	}
}

// TestBuildVolumesAndMounts_MultiPath verifies one volumeMount per data path
// is emitted at the user-supplied path, and that read-only flags propagate.
func TestBuildVolumesAndMounts_MultiPath(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("5Gi"))},
				Data: &garagev1beta2.VolumeConfig{
					Paths: []garagev1beta2.DataPath{
						{Path: multiPathDataPath0, Capacity: ptrQuantity(resource.MustParse("1Ti"))},
						{Path: multiPathDataPath1, Capacity: ptrQuantity(resource.MustParse("1Ti"))},
						{Path: "/data/legacy", ReadOnly: true},
					},
				},
			},
		},
	}
	_, mounts := buildVolumesAndMounts(cluster)

	want := map[string]struct {
		path     string
		readOnly bool
	}{
		dataPathPVC0: {path: multiPathDataPath0, readOnly: false},
		"data-1":     {path: multiPathDataPath1, readOnly: false},
		"data-2":     {path: "/data/legacy", readOnly: true},
	}
	got := map[string]corev1.VolumeMount{}
	for _, m := range mounts {
		got[m.Name] = m
	}
	for name, expect := range want {
		m, ok := got[name]
		if !ok {
			t.Errorf("missing volumeMount %q", name)
			continue
		}
		if m.MountPath != expect.path {
			t.Errorf("%s mountPath = %q, want %q", name, m.MountPath, expect.path)
		}
		if m.ReadOnly != expect.readOnly {
			t.Errorf("%s readOnly = %v, want %v", name, m.ReadOnly, expect.readOnly)
		}
	}
	// The legacy single `data` mount must NOT appear in multi-path mode.
	if _, ok := got[dataVolumeName]; ok {
		t.Errorf("legacy %q mount must not appear when paths[] is set", dataVolumeName)
	}
}

// TestBuildVolumesAndMounts_SinglePathBackwardCompat ensures the legacy
// single-mount layout at /data/data is preserved when paths[] is not set.
func TestBuildVolumesAndMounts_SinglePathBackwardCompat(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("5Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
		},
	}
	_, mounts := buildVolumesAndMounts(cluster)

	var found bool
	for _, m := range mounts {
		if m.Name == dataVolumeName {
			found = true
			if m.MountPath != "/data/data" {
				t.Errorf("data mountPath = %q, want %q", m.MountPath, "/data/data")
			}
			if m.ReadOnly {
				t.Errorf("data mount unexpectedly readOnly")
			}
		}
		if m.Name == dataPathPVC0 {
			t.Errorf("unexpected %q mount in single-path mode", dataPathPVC0)
		}
	}
	if !found {
		t.Errorf("missing legacy %q volumeMount", dataVolumeName)
	}
}
