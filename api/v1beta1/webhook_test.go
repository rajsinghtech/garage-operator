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
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testSourceNS  = "ns-a"
	testTargetNS  = "ns-b"
	testCluster   = "cluster"
	testBucket    = "my-bucket"
	testKey       = "my-key"
	testWebhookNS = "ns"
	testField     = "s3Api"
	kindGarageKey = "GarageKey"
)

var testKeyRef = KeyRef{Name: "key1"}

// fakeScheme builds a minimal scheme with v1beta1 types registered.
func fakeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// grant builds a GarageReferenceGrant in namespace testTargetNS for test use.
func grant(fromKind, fromNS, toKind, toName string) *GarageReferenceGrant {
	g := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grant",
			Namespace: testTargetNS,
		},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: fromKind, Namespace: fromNS}},
		},
	}
	if toKind != "" {
		g.Spec.To = []ReferenceGrantTo{{Kind: toKind, Name: toName}}
	}
	return g
}

// ── ReferenceGrant check ──────────────────────────────────────────────────────

func TestCheckReferenceGrant_SameNamespace(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testSourceNS, "my-cluster")
	if err != nil {
		t.Errorf("same-namespace reference should always be allowed, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "my-cluster")
	if err == nil {
		t.Error("cross-namespace reference without a grant should be denied")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WithMatchingGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageCluster", "my-cluster")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "my-cluster")
	if err != nil {
		t.Errorf("should be allowed with matching grant, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_WildcardTo(t *testing.T) {
	// Grant with no To entries permits all resources in the namespace.
	g := grant(kindGarageKey, testSourceNS, "", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "any-cluster")
	if err != nil {
		t.Errorf("wildcard To should allow any resource, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongFromKind(t *testing.T) {
	g := grant("GarageBucket", testSourceNS, "GarageCluster", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for GarageBucket should not satisfy GarageKey reference")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongFromNamespace(t *testing.T) {
	g := grant(kindGarageKey, "ns-c", "GarageCluster", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for ns-c should not satisfy reference from ns-a")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongToName(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageCluster", "other-cluster")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for 'other-cluster' should not satisfy reference to 'my-cluster'")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WildcardToName(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageCluster", "") // Name="" means all clusters
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageCluster", testTargetNS, "any-cluster")
	if err != nil {
		t.Errorf("wildcard name in To should allow any cluster, got: %v", err)
	}
}

func TestCheckReferenceGrant_BucketRef(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageBucket", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageBucket", testTargetNS, "my-bucket")
	if err != nil {
		t.Errorf("should be allowed for bucket cross-ns ref with grant, got: %v", err)
	}
}

// ── GarageKeyValidator ────────────────────────────────────────────────────────

func TestGarageKeyValidator_SameNamespaceClusterRef(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("same-namespace clusterRef should be allowed: %v", err)
	}
}

func TestGarageKeyValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageKeyValidator_CrossNamespaceClusterRef_WithGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageCluster", testCluster)
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("cross-namespace clusterRef with grant should be allowed: %v", err)
	}
}

func TestGarageKeyValidator_CrossNamespaceBucketRef_NoGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageCluster", "") // only cluster grant, no bucket grant
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: "my-bucket", Namespace: testTargetNS}, Read: true},
			},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err == nil {
		t.Error("cross-namespace bucketRef without bucket grant should be denied")
	}
	if err != nil && !strings.Contains(err.Error(), "bucketPermissions[0]") {
		t.Errorf("error should mention bucketPermissions[0], got: %v", err)
	}
}

func TestGarageKeyValidator_CrossNamespaceBucketRef_WithGrant(t *testing.T) {
	clusterGrant := grant(kindGarageKey, testSourceNS, "GarageCluster", "")
	bucketGrant := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-grant", Namespace: testTargetNS},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
			To:   []ReferenceGrantTo{{Kind: "GarageBucket"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(clusterGrant, bucketGrant).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: "my-bucket", Namespace: testTargetNS}, Read: true},
			},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("cross-namespace bucketRef with grant should be allowed: %v", err)
	}
}

func TestGarageKey_BucketPermission_BucketRefObject_Valid(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{
					BucketRef: &BucketRef{Name: testBucket},
					Read:      true,
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid BucketRef object should pass, got: %v", err)
	}
}

func TestGarageKey_BucketPermission_NoRef_Rejected(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{Read: true},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "must specify") {
		t.Errorf("expected must-specify error, got: %v", err)
	}
}

// ── GarageBucketValidator ─────────────────────────────────────────────────────

func TestGarageBucketValidator_SameNamespaceClusterRef(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err != nil {
		t.Errorf("same-namespace clusterRef should be allowed: %v", err)
	}
}

func TestGarageBucketValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageBucketValidator_CrossNamespaceClusterRef_WithGrant(t *testing.T) {
	g := grant("GarageBucket", testSourceNS, "GarageCluster", testCluster)
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err != nil {
		t.Errorf("cross-namespace clusterRef with grant should be allowed: %v", err)
	}
}

// ── GarageAdminTokenValidator ─────────────────────────────────────────────────

func TestGarageAdminTokenValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageAdminTokenValidator{Client: c}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec:       GarageAdminTokenSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageAdminToken(context.Background(), token)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageAdminTokenValidator_CrossNamespaceClusterRef_WithGrant(t *testing.T) {
	g := grant("GarageAdminToken", testSourceNS, "GarageCluster", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageAdminTokenValidator{Client: c}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec:       GarageAdminTokenSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageAdminToken(context.Background(), token)
	if err != nil {
		t.Errorf("cross-namespace clusterRef with grant should be allowed: %v", err)
	}
}

// ── GarageNodeValidator: cross-namespace always blocked ───────────────────────

func TestGarageNodeValidator_CrossNamespaceBlocked(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			Zone:       "us-east-1",
			Capacity:   func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }(),
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
			},
		},
	}
	_, err := node.validateGarageNode()
	if err == nil {
		t.Error("cross-namespace clusterRef on GarageNode should always be blocked")
	}
	if err != nil && !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGarageNodeValidator_SameNamespaceExplicit(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS}, // explicit but same NS
			Zone:       "us-east-1",
			Capacity:   func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }(),
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
			},
		},
	}
	_, err := node.validateGarageNode()
	if err != nil {
		t.Errorf("same-namespace explicit clusterRef on GarageNode should be allowed: %v", err)
	}
}

// ── Ported tests from v1alpha1 ────────────────────────────────────────────────

func TestValidateBindAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		field   string
		wantErr bool
	}{
		{"valid port only", ":3900", testField, false},
		{"valid host:port", "0.0.0.0:3900", testField, false},
		{"valid IPv6", "[::]:3900", testField, false},
		{"valid unix socket", "unix:///run/garage/s3.sock", testField, false},
		{"invalid - no port", "localhost", testField, true},
		{"invalid - empty", "", testField, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindAddress(tt.addr, tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBindAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageCluster_ValidateZoneRedundancy(t *testing.T) {
	ptr := func(n int) *int { return &n }
	tests := []struct {
		name        string
		mode        string
		minZones    *int
		replication int
		wantErr     bool
	}{
		{"empty mode is valid", "", nil, 3, false},
		{"Maximum is valid", zoneRedundancyMaximum, nil, 3, false},
		{"AtLeast(1) with RF3", zoneRedundancyAtLeast, ptr(1), 3, false},
		{"AtLeast(3) with RF3", zoneRedundancyAtLeast, ptr(3), 3, false},
		{"AtLeast(4) exceeds RF3", zoneRedundancyAtLeast, ptr(4), 3, true},
		{"AtLeast without minZones is invalid", zoneRedundancyAtLeast, nil, 3, true},
		{"Maximum with minZones is invalid", zoneRedundancyMaximum, ptr(2), 3, true},
		{"invalid mode", "Invalid", nil, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{
				Spec: GarageClusterSpec{
					Replication: &ReplicationConfig{
						Factor:                 tt.replication,
						ZoneRedundancyMode:     tt.mode,
						ZoneRedundancyMinZones: tt.minZones,
					},
				},
			}
			err := cluster.validateZoneRedundancy()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateZoneRedundancy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageCluster_ValidateStorage(t *testing.T) {
	size := resource.MustParse("100Gi")
	tests := []struct {
		name    string
		storage StorageConfig
		wantErr bool
	}{
		{"valid size config", StorageConfig{Data: &VolumeConfig{Size: &size}}, false},
		{"invalid - paths not supported", StorageConfig{Data: &VolumeConfig{Paths: []DataPath{{Path: "/data"}}}}, true},
		{"invalid - no size", StorageConfig{Data: &VolumeConfig{}}, true},
		{"invalid - no data config", StorageConfig{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{Spec: GarageClusterSpec{Storage: tt.storage}}
			err := cluster.validateStorage()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStorage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageCluster_ValidateGateway(t *testing.T) {
	size := resource.MustParse("100Gi")
	tests := []struct {
		name    string
		cluster GarageCluster
		wantErr bool
		errMsg  string
	}{
		{
			name:    "reject gateway without connectTo",
			cluster: GarageCluster{Spec: GarageClusterSpec{Gateway: true}},
			wantErr: true, errMsg: "connectTo is required",
		},
		{
			name: "reject connectTo without gateway",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Storage:   StorageConfig{Data: &VolumeConfig{Size: &size}},
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "other"}},
			}},
			wantErr: true, errMsg: "connectTo can only be specified",
		},
		{
			name: "reject gateway with data storage",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "storage-cluster"}},
				Storage:   StorageConfig{Data: &VolumeConfig{Size: &size}},
			}},
			wantErr: true, errMsg: "storage.data cannot be PersistentVolumeClaim",
		},
		{
			name: "reject empty connectTo",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{},
			}},
			wantErr: true, errMsg: "must specify clusterRef",
		},
		{
			name: "accept gateway with clusterRef",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "storage-cluster"}},
			}},
			wantErr: false,
		},
		{
			name: "accept gateway with rpcSecretRef",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway: true,
				ConnectTo: &ConnectToConfig{RPCSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "rpc-secret"},
					Key:                  "rpc-secret",
				}},
			}},
			wantErr: false,
		},
		{
			name: "accept gateway with bootstrapPeers",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{BootstrapPeers: []string{"abc123@192.168.1.1:3901"}},
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cluster.validateGateway()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGateway() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateGateway() error = %v, want containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestValidateAllBuckets(t *testing.T) {
	tests := []struct {
		name       string
		allBuckets *AllBucketsPermission
		wantErr    bool
	}{
		{"nil is valid", nil, false},
		{"read only", &AllBucketsPermission{Read: true}, false},
		{"write only", &AllBucketsPermission{Write: true}, false},
		{"owner only", &AllBucketsPermission{Owner: true}, false},
		{"all permissions", &AllBucketsPermission{Read: true, Write: true, Owner: true}, false},
		{"no permissions", &AllBucketsPermission{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllBuckets(tt.allBuckets)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAllBuckets() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageKeyValidator_NoBucketPermissionsWarning(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}

	// allBuckets set — no warning expected
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	warnings, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings when allBuckets is set, got: %v", warnings)
	}

	// no permissions at all — warning expected
	key2 := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey + "2", Namespace: testWebhookNS},
		Spec:       GarageKeySpec{ClusterRef: ClusterReference{Name: testCluster}},
	}
	warnings2, err := v.validateGarageKey(context.Background(), key2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warnings2) == 0 {
		t.Error("expected warning when no bucket permissions defined")
	}
}

func TestGarageKeyValidator_AllBucketsAndBucketPermissionsBothSet_Warning(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: testBucket}, Write: true},
			},
		},
	}
	warnings, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("both set is not an error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected a warning when both allBuckets and bucketPermissions are set")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "allBuckets") && strings.Contains(w, "bucketPermissions") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning mentioning allBuckets and bucketPermissions, got: %v", warnings)
	}
}

func TestValidateKeyPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []KeyPermission
		wantErr     bool
	}{
		{"nil", nil, false},
		{"empty", []KeyPermission{}, false},
		{"valid read", []KeyPermission{{KeyRef: testKeyRef, Read: true}}, false},
		{"valid write", []KeyPermission{{KeyRef: testKeyRef, Write: true}}, false},
		{"valid owner", []KeyPermission{{KeyRef: testKeyRef, Owner: true}}, false},
		{"missing keyRef", []KeyPermission{{Read: true}}, true},
		{"no permissions granted", []KeyPermission{{KeyRef: testKeyRef}}, true},
		{"duplicate keyRef", []KeyPermission{{KeyRef: KeyRef{Name: "k"}, Read: true}, {KeyRef: KeyRef{Name: "k"}, Write: true}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyPermissions(tt.permissions)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeyPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageKey_ExpiresAt_Valid(t *testing.T) {
	d := &GarageKeyDefaulter{}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			ExpiresAt:  &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
		},
	}
	if err := d.Default(context.Background(), key); err != nil {
		t.Fatalf("Default: %v", err)
	}
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid expiresAt should pass, got: %v", err)
	}
}

func TestGarageKey_ExpiresAt_MutuallyExclusiveWithNeverExpires(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef:   ClusterReference{Name: testCluster},
			ExpiresAt:    &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
			NeverExpires: true,
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}

func TestValidateReferenceGrant(t *testing.T) {
	tests := []struct {
		name     string
		grant    *GarageReferenceGrant
		wantErr  bool
		wantWarn bool
	}{
		{
			name: "valid cross-namespace grant",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty from is invalid",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec:       GarageReferenceGrantSpec{},
			},
			wantErr: true,
		},
		{
			name: "same-namespace from produces warning",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
		{
			name: "missing from namespace is invalid",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty namespace after same-namespace entry is still caught",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{
						{Kind: kindGarageKey, Namespace: testSourceNS},
						{Kind: kindGarageKey},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "multiple same-namespace entries all produce warnings",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{
						{Kind: kindGarageKey, Namespace: testSourceNS},
						{Kind: "GarageBucket", Namespace: testSourceNS},
					},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := validateReferenceGrant(tt.grant)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateReferenceGrant() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantWarn && len(warnings) == 0 {
				t.Error("expected a warning but got none")
			}
		})
	}
}

func TestGarageCluster_RPCTimeout_DurationField(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Network: NetworkConfig{
				RPCPingTimeout: &metav1.Duration{Duration: 10 * time.Second},
				RPCTimeout:     &metav1.Duration{Duration: 30 * time.Second},
			},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Network.RPCPingTimeout.Duration != 10*time.Second {
		t.Errorf("expected 10s ping timeout, got %v", cluster.Spec.Network.RPCPingTimeout)
	}
	if cluster.Spec.Network.RPCTimeout.Duration != 30*time.Second {
		t.Errorf("expected 30s rpc timeout, got %v", cluster.Spec.Network.RPCTimeout)
	}
}

func TestGarageCluster_ZoneRedundancy_AtLeast_RequiresMinZones(t *testing.T) {
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{Factor: 3, ZoneRedundancyMode: "AtLeast"},
			// ZoneRedundancyMinZones intentionally absent
		},
	}
	err := cluster.validateZoneRedundancy()
	if err == nil || !strings.Contains(err.Error(), "zoneRedundancyMinZones") {
		t.Errorf("expected zoneRedundancyMinZones required error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_AtLeast_CannotExceedFactor(t *testing.T) {
	minZones := 5
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{
				Factor:                 3,
				ZoneRedundancyMode:     "AtLeast",
				ZoneRedundancyMinZones: &minZones,
			},
		},
	}
	err := cluster.validateZoneRedundancy()
	if err == nil || !strings.Contains(err.Error(), "cannot exceed") {
		t.Errorf("expected exceed-factor error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_Maximum_Valid(t *testing.T) {
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{
				Factor:             3,
				ZoneRedundancyMode: "Maximum",
			},
		},
	}
	if err := cluster.validateZoneRedundancy(); err != nil {
		t.Errorf("Maximum should be valid, got: %v", err)
	}
}

func TestGarageCluster_Replication_OmittedDefaultsToFactor3(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3}, // no Replication field
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Replication == nil {
		t.Fatal("expected Replication to be defaulted, got nil")
	}
	if cluster.Spec.Replication.Factor != 3 {
		t.Errorf("expected factor 3, got %d", cluster.Spec.Replication.Factor)
	}
	if cluster.Spec.Replication.ConsistencyMode != "consistent" {
		t.Errorf("expected consistencyMode consistent, got %q", cluster.Spec.Replication.ConsistencyMode)
	}
}

func TestGarageCluster_WebAPI_EnabledFalse_DisablesWebAPI(t *testing.T) {
	d := &GarageClusterDefaulter{}
	disabled := false
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			WebAPI:   &WebAPIConfig{Enabled: &disabled},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.WebAPI.Enabled == nil || *cluster.Spec.WebAPI.Enabled != false {
		t.Error("expected WebAPI.Enabled to remain false")
	}
}

func TestGarageCluster_WebAPI_NilEnabled_DefaultsToTrue(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.WebAPI == nil {
		t.Fatal("expected WebAPI to be defaulted")
	}
	if cluster.Spec.WebAPI.Enabled == nil || !*cluster.Spec.WebAPI.Enabled {
		t.Error("expected WebAPI.Enabled to default to true")
	}
}

func TestBucketRef_UnmarshalJSON_StringForm(t *testing.T) {
	// v1alpha1 stored bucketRef as a plain string. The informer crashes on LIST
	// if the Go type can't handle it, so we accept the string and map it to Name.
	var ref BucketRef
	if err := json.Unmarshal([]byte(`"`+testBucket+`"`), &ref); err != nil {
		t.Fatalf("unexpected error unmarshaling string bucketRef: %v", err)
	}
	if ref.Name != testBucket {
		t.Errorf("expected Name=my-bucket, got %q", ref.Name)
	}
	if ref.Namespace != "" {
		t.Errorf("expected empty Namespace, got %q", ref.Namespace)
	}
}

func TestBucketRef_UnmarshalJSON_ObjectForm(t *testing.T) {
	var ref BucketRef
	if err := json.Unmarshal([]byte(`{"name":"`+testBucket+`","namespace":"ns"}`), &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Name != testBucket || ref.Namespace != "ns" {
		t.Errorf("unexpected value: %+v", ref)
	}
}

func TestBucketRef_UnmarshalJSON_InGarageKeyList(t *testing.T) {
	// Simulate what the informer sees when a legacy resource is in etcd.
	raw := `{
		"apiVersion": "garage.rajsingh.info/v1beta1",
		"kind": "GarageKey",
		"metadata": {"name": "test", "namespace": "default"},
		"spec": {
			"clusterRef": {"name": "garage"},
			"bucketPermissions": [{"bucketRef": "` + testBucket + `", "read": true}]
		}
	}`
	var key GarageKey
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		t.Fatalf("expected no error for legacy string bucketRef, got: %v", err)
	}
	if len(key.Spec.BucketPermissions) != 1 {
		t.Fatal("expected 1 bucket permission")
	}
	ref := key.Spec.BucketPermissions[0].BucketRef
	if ref == nil || ref.Name != testBucket {
		t.Errorf("expected BucketRef.Name=%s, got %+v", testBucket, ref)
	}
}

func TestGarageCluster_ValidateLayoutManagement(t *testing.T) {
	tests := []struct {
		name     string
		replicas int32
		lm       *LayoutManagementConfig
		wantErr  bool
		errMsg   string
	}{
		{"nil layoutManagement is valid", 3, nil, false, ""},
		{"minNodesHealthy=0 is valid", 3, &LayoutManagementConfig{MinNodesHealthy: 0}, false, ""},
		{"minNodesHealthy equals replicas is valid", 3, &LayoutManagementConfig{MinNodesHealthy: 3}, false, ""},
		{"minNodesHealthy less than replicas is valid", 5, &LayoutManagementConfig{MinNodesHealthy: 3}, false, ""},
		{"minNodesHealthy exceeds replicas is rejected", 3, &LayoutManagementConfig{MinNodesHealthy: 4}, true, "cannot exceed replicas"},
		{"minNodesHealthy=1 with default replicas(0→3) is valid", 0, &LayoutManagementConfig{MinNodesHealthy: 1}, false, ""},
		{"minNodesHealthy=4 with default replicas(0→3) is rejected", 0, &LayoutManagementConfig{MinNodesHealthy: 4}, true, "cannot exceed replicas"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{
				Spec: GarageClusterSpec{
					Replicas:         tt.replicas,
					LayoutManagement: tt.lm,
				},
			}
			err := cluster.validateLayoutManagement()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLayoutManagement() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateLayoutManagement() error = %v, want containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestGarageCluster_Storage_PathsOnMetadataRejected(t *testing.T) {
	v := &GarageClusterValidator{}
	size := resource.MustParse("10Gi")
	dataSize := resource.MustParse("100Gi")
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{
					Size:  &size,
					Paths: []DataPath{{Path: "/meta1"}},
				},
				Data: &VolumeConfig{Size: &dataSize},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "paths is only valid for data volumes") {
		t.Errorf("expected paths-on-metadata error, got: %v", err)
	}
}
