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
	testKeyRef    = "key1"
	testWebhookNS = "ns"
	testField     = "s3Api"
	kindGarageKey = "GarageKey"
)

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
				{BucketRef: "my-bucket", BucketNamespace: testTargetNS, Read: true},
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
				{BucketRef: "my-bucket", BucketNamespace: testTargetNS, Read: true},
			},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("cross-namespace bucketRef with grant should be allowed: %v", err)
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
			Storage: &NodeStorageSpec{
				Data: &NodeVolumeSource{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
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
			Storage: &NodeStorageSpec{
				Data: &NodeVolumeSource{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
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
	tests := []struct {
		name           string
		zoneRedundancy string
		replication    int
		wantErr        bool
	}{
		{"empty is valid", "", 3, false},
		{"Maximum is valid", "Maximum", 3, false},
		{"AtLeast(1) with RF3", "AtLeast(1)", 3, false},
		{"AtLeast(3) with RF3", "AtLeast(3)", 3, false},
		{"AtLeast(4) exceeds RF3", "AtLeast(4)", 3, true},
		{"AtLeast(0) is invalid", "AtLeast(0)", 3, true},
		{"invalid format", "Invalid", 3, true},
		{"invalid AtLeast(abc)", "AtLeast(abc)", 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{
				Spec: GarageClusterSpec{
					Replication: ReplicationConfig{Factor: tt.replication, ZoneRedundancy: tt.zoneRedundancy},
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
		{"valid size config", StorageConfig{Data: &DataStorageConfig{Size: &size}}, false},
		{"invalid - paths not supported", StorageConfig{Data: &DataStorageConfig{Paths: []DataPath{{Path: "/data"}}}}, true},
		{"invalid - no size", StorageConfig{Data: &DataStorageConfig{}}, true},
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
				Storage:   StorageConfig{Data: &DataStorageConfig{Size: &size}},
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "other"}},
			}},
			wantErr: true, errMsg: "connectTo can only be specified",
		},
		{
			name: "reject gateway with data storage",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "storage-cluster"}},
				Storage:   StorageConfig{Data: &DataStorageConfig{Size: &size}},
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
		{"duplicate keyRef", []KeyPermission{{KeyRef: "k", Read: true}, {KeyRef: "k", Write: true}}, true},
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
