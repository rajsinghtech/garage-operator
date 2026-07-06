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

package cosi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testGarageAccessKeyID = "GKtest-access"
	testGarageSystem      = "garage-system"
	testClusterRef        = paramClusterRef
	testClusterNamespace  = paramClusterNamespace
	testBucketNotFound    = "bucket not found"
	testNotFound          = "not found"
	testConflictMsg       = "conflict"
	testGKTestKey         = "GKtest-key"
	testExistingSecret    = "existing-secret"
	testBucket1           = "bucket-1"
	testMyCluster         = "my-cluster"
	testBucketName        = "test-bucket"
	testAccountName       = "test-access"
	testBucketID          = "test-bucket-id"
	testMyBucket          = "my-bucket"
)

// mockGarageClient implements GarageClient for testing
type mockGarageClient struct {
	buckets map[string]*garage.Bucket
	keys    map[string]*garage.Key

	// For tracking calls
	createBucketCalls   []garage.CreateBucketRequest
	deleteBucketCalls   []string
	createKeyCalls      []string
	deleteKeyCalls      []string
	allowBucketKeyCalls []garage.AllowBucketKeyRequest
	denyBucketKeyCalls  []garage.DenyBucketKeyRequest

	// For simulating errors
	createBucketErr error
	updateBucketErr error
	deleteBucketErr error
	createKeyErr    error
	getKeyErr       error
	deleteKeyErr    error
	allowKeyErr     error
	denyKeyErr      error
}

func newMockGarageClient() *mockGarageClient {
	return &mockGarageClient{
		buckets: make(map[string]*garage.Bucket),
		keys:    make(map[string]*garage.Key),
	}
}

func (m *mockGarageClient) CreateBucket(ctx context.Context, req garage.CreateBucketRequest) (*garage.Bucket, error) {
	m.createBucketCalls = append(m.createBucketCalls, req)
	if m.createBucketErr != nil {
		return nil, m.createBucketErr
	}
	bucket := &garage.Bucket{
		ID:            "bucket-" + req.GlobalAlias,
		GlobalAliases: []string{req.GlobalAlias},
	}
	m.buckets[bucket.ID] = bucket
	return bucket, nil
}

func (m *mockGarageClient) GetBucket(ctx context.Context, req garage.GetBucketRequest) (*garage.Bucket, error) {
	for _, b := range m.buckets {
		if req.ID != "" && b.ID == req.ID {
			return b, nil
		}
		if req.GlobalAlias != "" {
			for _, alias := range b.GlobalAliases {
				if alias == req.GlobalAlias {
					return b, nil
				}
			}
		}
	}
	return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
}

func (m *mockGarageClient) UpdateBucket(ctx context.Context, req garage.UpdateBucketRequest) (*garage.Bucket, error) {
	if m.updateBucketErr != nil {
		return nil, m.updateBucketErr
	}
	bucket, ok := m.buckets[req.ID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
	}
	if req.Body.Quotas != nil {
		bucket.Quotas = req.Body.Quotas
	}
	return bucket, nil
}

func (m *mockGarageClient) DeleteBucket(ctx context.Context, bucketID string) error {
	m.deleteBucketCalls = append(m.deleteBucketCalls, bucketID)
	if m.deleteBucketErr != nil {
		return m.deleteBucketErr
	}
	delete(m.buckets, bucketID)
	return nil
}

func (m *mockGarageClient) CreateKey(ctx context.Context, name string) (*garage.Key, error) {
	m.createKeyCalls = append(m.createKeyCalls, name)
	if m.createKeyErr != nil {
		return nil, m.createKeyErr
	}
	key := &garage.Key{
		AccessKeyID:     "GK" + name,
		SecretAccessKey: "secret-" + name,
		Name:            name,
	}
	m.keys[key.AccessKeyID] = key
	return key, nil
}

func (m *mockGarageClient) GetKey(ctx context.Context, req garage.GetKeyRequest) (*garage.Key, error) {
	if m.getKeyErr != nil {
		return nil, m.getKeyErr
	}
	if req.ID != "" {
		if key, ok := m.keys[req.ID]; ok {
			return key, nil
		}
	}
	if req.Search != "" {
		for _, k := range m.keys {
			if k.Name == req.Search {
				return k, nil
			}
		}
	}
	return nil, &garage.APIError{StatusCode: 404, Message: "key not found"}
}

func (m *mockGarageClient) DeleteKey(ctx context.Context, accessKeyID string) error {
	m.deleteKeyCalls = append(m.deleteKeyCalls, accessKeyID)
	if m.deleteKeyErr != nil {
		return m.deleteKeyErr
	}
	delete(m.keys, accessKeyID)
	return nil
}

func (m *mockGarageClient) AllowBucketKey(ctx context.Context, req garage.AllowBucketKeyRequest) (*garage.Bucket, error) {
	m.allowBucketKeyCalls = append(m.allowBucketKeyCalls, req)
	if m.allowKeyErr != nil {
		return nil, m.allowKeyErr
	}
	bucket, ok := m.buckets[req.BucketID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
	}
	if key, ok := m.keys[req.AccessKeyID]; ok {
		key.Buckets = append(key.Buckets, garage.KeyBucket{
			ID:          req.BucketID,
			Permissions: req.Permissions,
		})
	}
	return bucket, nil
}

func (m *mockGarageClient) DenyBucketKey(ctx context.Context, req garage.DenyBucketKeyRequest) (*garage.Bucket, error) {
	m.denyBucketKeyCalls = append(m.denyBucketKeyCalls, req)
	if m.denyKeyErr != nil {
		return nil, m.denyKeyErr
	}
	bucket, ok := m.buckets[req.BucketID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
	}
	return bucket, nil
}

// createShadowBucket creates a shadow GarageBucket resource for use in tests that call
// GetShadowBucketGlobalAliasByID (buildBucketResult, buildPerBucketResults).
func createShadowBucket(bucketID, globalAlias string) *garagev1beta1.GarageBucket {
	return &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shadow-" + bucketID,
			Namespace: testGarageSystem,
			Labels: map[string]string{
				LabelCOSIManaged:  paramTrue,
				LabelCOSIBucketID: truncateLabelValue(bucketID),
			},
			Annotations: map[string]string{
				AnnotationCOSIBucketID: bucketID,
			},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			GlobalAlias: globalAlias,
		},
	}
}

// Helper to create a ready cluster
func createReadyCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testMyCluster,
			Namespace: testGarageSystem,
		},
		Spec: garagev1beta2.GarageClusterSpec{},
		Status: garagev1beta2.GarageClusterStatus{
			Phase: garagev1beta1.PhaseRunning,
			Endpoints: &garagev1beta2.ClusterEndpoints{
				S3: cosiS3Endpoint,
			},
		},
	}
}

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(scheme)
	_ = garagev1beta2.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// defaultParams builds a BucketClassParameters for tests.
func defaultBucketParams() *BucketClassParameters {
	p, _ := ParseBucketClassParameters(map[string]string{
		testClusterRef:       testMyCluster,
		testClusterNamespace: testGarageSystem,
	}, testGarageSystem)
	return p
}

func defaultAccessParams() *BucketAccessClassParameters {
	p, _ := ParseBucketAccessClassParameters(map[string]string{
		testClusterRef:       testMyCluster,
		testClusterNamespace: testGarageSystem,
	}, testGarageSystem)
	return p
}

// === Error Path Tests ===

func TestProvisioner_EnsureBucket_MissingClusterRef(t *testing.T) {
	_, err := ParseBucketClassParameters(map[string]string{}, testGarageSystem)
	require.Error(t, err) // clusterRef is required
}

func TestProvisioner_EnsureBucket_ClusterNotFound(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	params, _ := ParseBucketClassParameters(map[string]string{
		testClusterRef:       "nonexistent",
		testClusterNamespace: testGarageSystem,
	}, testGarageSystem)

	_, err := p.EnsureBucket(context.Background(), testBucketName, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProvisioner_EnsureBucket_ClusterNotReady(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testMyCluster, Namespace: testGarageSystem},
		Status:     garagev1beta2.GarageClusterStatus{Phase: "Pending"},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not ready")
}

func TestProvisioner_EnsureBucket_EmptyName(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.EnsureBucket(context.Background(), "", defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket name is required")
}

func TestProvisioner_GrantAccess_EmptyAccountName(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.GrantAccess(context.Background(), "", "", []BucketAccessSlot{{BucketID: testBucketID}}, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accountName is required")
}

func TestProvisioner_GrantAccess_NoBuckets(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.GrantAccess(context.Background(), testAccountName, "", []BucketAccessSlot{}, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one bucket")
}

func TestProvisioner_DeleteBucket_EmptyBucketId(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	err := p.DeleteBucket(context.Background(), "", defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucketID is required")
}

func TestProvisioner_RevokeAccess_EmptyAccountId(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	err := p.RevokeAccess(context.Background(), "", []string{testBucketID}, defaultAccessParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accountID is required")
}

// === Happy Path Tests ===

func TestProvisioner_EnsureBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", result.BucketID)
	assert.Equal(t, testBucketName, result.GlobalAlias)
	assert.NotEmpty(t, result.Endpoint)

	require.Len(t, mockClient.createBucketCalls, 1)
	assert.Equal(t, testBucketName, mockClient.createBucketCalls[0].GlobalAlias)
}

func TestProvisioner_DeleteBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err := p.DeleteBucket(context.Background(), testBucketID, defaultBucketParams())

	require.NoError(t, err)
	require.Len(t, mockClient.deleteBucketCalls, 1)
	assert.Equal(t, testBucketID, mockClient.deleteBucketCalls[0])
}

func TestProvisioner_GrantAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	result, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Contains(t, result.AccountID, "GK")
	assert.NotEmpty(t, result.AccessKeyID)
	assert.NotEmpty(t, result.SecretAccessKey)
	require.Len(t, result.PerBucket, 1)
	assert.Equal(t, testBucketName, result.PerBucket[0].GlobalAlias)

	require.Len(t, mockClient.createKeyCalls, 1)
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, testBucketID, mockClient.allowBucketKeyCalls[0].BucketID)
}

func TestProvisioner_RevokeAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys[testGKTestKey] = &garage.Key{AccessKeyID: testGKTestKey}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err := p.RevokeAccess(context.Background(), testGKTestKey, []string{testBucketID}, defaultAccessParams())

	require.NoError(t, err)
	require.Len(t, mockClient.denyBucketKeyCalls, 1)
	assert.Equal(t, testBucketID, mockClient.denyBucketKeyCalls[0].BucketID)
	assert.Equal(t, testGKTestKey, mockClient.denyBucketKeyCalls[0].AccessKeyID)
	require.Len(t, mockClient.deleteKeyCalls, 1)
	assert.Equal(t, testGKTestKey, mockClient.deleteKeyCalls[0])
}

// === Idempotency Tests ===

func TestProvisioner_GrantAccess_Idempotent(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	// Pre-existing key with the same name
	mockClient.keys[testGarageAccessKeyID] = &garage.Key{
		AccessKeyID:     testGarageAccessKeyID,
		SecretAccessKey: testExistingSecret,
		Name:            testAccountName,
		Buckets: []garage.KeyBucket{
			{ID: testBucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
		},
	}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	result, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, testGarageAccessKeyID, result.AccountID)
	assert.Equal(t, testExistingSecret, result.SecretAccessKey)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)
}

func TestProvisioner_DeleteBucket_NotFound(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 404, Message: testNotFound}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	// Should succeed even if bucket doesn't exist (idempotent delete)
	err := p.DeleteBucket(context.Background(), "nonexistent-bucket", defaultBucketParams())
	require.NoError(t, err)
}

func TestEnsureBucket_QuotaUpdateFailure_RollsBackBucket(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.updateBucketErr = fmt.Errorf("quota update failed")

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	params, _ := ParseBucketClassParameters(map[string]string{
		testClusterRef:       testMyCluster,
		testClusterNamespace: testGarageSystem,
		paramMaxSize:         "1073741824", // 1Gi in bytes
	}, testGarageSystem)

	_, err := p.EnsureBucket(context.Background(), testBucketName, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota update failed")

	// The bucket created by CreateBucket should have been rolled back.
	require.Len(t, mockClient.createBucketCalls, 1)
	createdID := "bucket-" + mockClient.createBucketCalls[0].GlobalAlias
	require.Len(t, mockClient.deleteBucketCalls, 1)
	assert.Equal(t, createdID, mockClient.deleteBucketCalls[0])

	// No shadow GarageBucket should have been created.
	gbList := &garagev1beta1.GarageBucketList{}
	require.NoError(t, fakeClient.List(context.Background(), gbList, client.InNamespace(testGarageSystem)))
	assert.Empty(t, gbList.Items)
}

// === Bug Fix Tests ===

func TestProvisioner_GrantAccess_MultiBucket(t *testing.T) {
	cluster := createReadyCluster()
	shadow1 := createShadowBucket("bucket-1", "alias-bucket-1")
	shadow2 := createShadowBucket("bucket-2", "alias-bucket-2")
	shadow3 := createShadowBucket("bucket-3", "alias-bucket-3")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow1, shadow2, shadow3).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-1"] = &garage.Bucket{ID: "bucket-1"}
	mockClient.buckets["bucket-2"] = &garage.Bucket{ID: "bucket-2"}
	mockClient.buckets["bucket-3"] = &garage.Bucket{ID: "bucket-3"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{
		{BucketID: "bucket-1"},
		{BucketID: "bucket-2"},
		{BucketID: "bucket-3"},
	}
	result, err := p.GrantAccess(context.Background(), "multi-bucket-access", "", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	require.Len(t, result.PerBucket, 3)

	aliases := make(map[string]bool)
	for _, br := range result.PerBucket {
		aliases[br.GlobalAlias] = true
		assert.NotEmpty(t, br.Endpoint)
	}
	assert.True(t, aliases["alias-bucket-1"])
	assert.True(t, aliases["alias-bucket-2"])
	assert.True(t, aliases["alias-bucket-3"])

	require.Len(t, mockClient.allowBucketKeyCalls, 3)
}

func TestProvisioner_GrantAccess_AccessModes(t *testing.T) {
	cluster := createReadyCluster()
	shadowRW := createShadowBucket("bucket-rw", "alias-bucket-rw")
	shadowRO := createShadowBucket("bucket-ro", "alias-bucket-ro")
	shadowWO := createShadowBucket("bucket-wo", "alias-bucket-wo")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowRW, shadowRO, shadowWO).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-rw"] = &garage.Bucket{ID: "bucket-rw"}
	mockClient.buckets["bucket-ro"] = &garage.Bucket{ID: "bucket-ro"}
	mockClient.buckets["bucket-wo"] = &garage.Bucket{ID: "bucket-wo"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{
		{BucketID: "bucket-rw", AccessMode: AccessModeReadWrite},
		{BucketID: "bucket-ro", AccessMode: AccessModeReadOnly},
		{BucketID: "bucket-wo", AccessMode: AccessModeWriteOnly},
	}
	result, err := p.GrantAccess(context.Background(), "access-modes-test", "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	require.Len(t, result.PerBucket, 3)

	require.Len(t, mockClient.allowBucketKeyCalls, 3)
	permsByBucket := make(map[string]garage.BucketKeyPerms)
	for _, call := range mockClient.allowBucketKeyCalls {
		permsByBucket[call.BucketID] = call.Permissions
	}

	assert.True(t, permsByBucket["bucket-rw"].Read)
	assert.True(t, permsByBucket["bucket-rw"].Write)
	assert.True(t, permsByBucket["bucket-ro"].Read)
	assert.False(t, permsByBucket["bucket-ro"].Write)
	assert.False(t, permsByBucket["bucket-wo"].Read)
	assert.True(t, permsByBucket["bucket-wo"].Write)
}

func TestProvisioner_EnsureBucket_IdempotentMismatch(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	existingSize := uint64(1000)
	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{testBucketName},
		Quotas:        &garage.BucketQuotas{MaxSize: &existingSize},
	}
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: testConflictMsg}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	params, _ := ParseBucketClassParameters(map[string]string{
		testClusterRef:       testMyCluster,
		testClusterNamespace: testGarageSystem,
		"maxSize":            "5000",
	}, testGarageSystem)

	_, err := p.EnsureBucket(context.Background(), testBucketName, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "different configuration")
}

func TestProvisioner_EnsureBucket_IdempotentMatch(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("bucket-test-bucket", testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	existingSize := uint64(5000)
	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{testBucketName},
		Quotas:        &garage.BucketQuotas{MaxSize: &existingSize},
	}
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: testConflictMsg}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	params, _ := ParseBucketClassParameters(map[string]string{
		testClusterRef:       testMyCluster,
		testClusterNamespace: testGarageSystem,
		"maxSize":            "5000",
	}, testGarageSystem)

	result, err := p.EnsureBucket(context.Background(), testBucketName, params)

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", result.BucketID)
}

func TestSanitizeBucketName_Short(t *testing.T) {
	name := "my-bucket"
	assert.Equal(t, "my-bucket", sanitizeBucketName(name))
}

func TestSanitizeBucketName_ExactlyMax(t *testing.T) {
	name := strings.Repeat("a", 63)
	assert.Equal(t, name, sanitizeBucketName(name))
}

func TestSanitizeBucketName_Long(t *testing.T) {
	name := strings.Repeat("a", 100)
	result := sanitizeBucketName(name)

	assert.LessOrEqual(t, len(result), 63)
	assert.True(t, strings.HasPrefix(result, strings.Repeat("a", 50)))
	assert.Contains(t, result, "-")
}

func TestSanitizeBucketName_DifferentLongNamesProduceDifferentResults(t *testing.T) {
	name1 := strings.Repeat("a", 70) + "xxx"
	name2 := strings.Repeat("a", 70) + "yyy"

	result1 := sanitizeBucketName(name1)
	result2 := sanitizeBucketName(name2)

	assert.NotEqual(t, result1, result2)
	assert.LessOrEqual(t, len(result1), 63)
	assert.LessOrEqual(t, len(result2), 63)
}

func TestSanitizeKeyName_Short(t *testing.T) {
	name := "my-key"
	assert.Equal(t, "my-key", sanitizeKeyName(name))
}

func TestSanitizeKeyName_Long(t *testing.T) {
	name := strings.Repeat("k", 200)
	result := sanitizeKeyName(name)

	assert.LessOrEqual(t, len(result), 128)
	assert.True(t, strings.HasPrefix(result, strings.Repeat("k", 115)))
}

func TestSanitizeKeyName_DifferentLongNamesProduceDifferentResults(t *testing.T) {
	name1 := strings.Repeat("k", 130) + "xxx"
	name2 := strings.Repeat("k", 130) + "yyy"

	result1 := sanitizeKeyName(name1)
	result2 := sanitizeKeyName(name2)

	assert.NotEqual(t, result1, result2)
	assert.LessOrEqual(t, len(result1), 128)
	assert.LessOrEqual(t, len(result2), 128)
}

func TestMapAccessModeForGarage(t *testing.T) {
	tests := []struct {
		name      string
		mode      AccessMode
		wantRead  bool
		wantWrite bool
	}{
		{
			name:      "ReadWrite",
			mode:      AccessModeReadWrite,
			wantRead:  true,
			wantWrite: true,
		},
		{
			name:      "ReadOnly",
			mode:      AccessModeReadOnly,
			wantRead:  true,
			wantWrite: false,
		},
		{
			name:      "WriteOnly",
			mode:      AccessModeWriteOnly,
			wantRead:  false,
			wantWrite: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := mapAccessModeForGarage(tt.mode)
			assert.Equal(t, tt.wantRead, perms.Read)
			assert.Equal(t, tt.wantWrite, perms.Write)
		})
	}
}

func TestProvisioner_GrantAccess_IdempotentUpdatesPermissions(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	// Pre-existing key with READ_WRITE permissions
	mockClient.keys[testGarageAccessKeyID] = &garage.Key{
		AccessKeyID:     testGarageAccessKeyID,
		SecretAccessKey: testExistingSecret,
		Name:            testAccountName,
		Buckets: []garage.KeyBucket{
			{ID: testBucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
		},
	}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	// Request READ_ONLY -- should update even though key already has access
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}
	result, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, testGarageAccessKeyID, result.AccountID)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)

	// Should have called AllowBucketKey to update permissions
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, testBucketID, mockClient.allowBucketKeyCalls[0].BucketID)
	assert.True(t, mockClient.allowBucketKeyCalls[0].Permissions.Read)
	assert.False(t, mockClient.allowBucketKeyCalls[0].Permissions.Write, "should have updated to READ_ONLY")
}

func TestProvisioner_GrantAccess_IdempotentSkipsMatchingPermissions(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	// Pre-existing key with READ_ONLY permissions - matches what we'll request
	mockClient.keys[testGarageAccessKeyID] = &garage.Key{
		AccessKeyID:     testGarageAccessKeyID,
		SecretAccessKey: testExistingSecret,
		Name:            testAccountName,
		Buckets: []garage.KeyBucket{
			{ID: testBucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: false}},
		},
	}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}
	result, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, testGarageAccessKeyID, result.AccountID)

	// Should NOT call AllowBucketKey since permissions already match
	assert.Len(t, mockClient.allowBucketKeyCalls, 0)
}

func TestProvisioner_GetS3Endpoint_NilEndpoints(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testMyCluster, Namespace: testGarageSystem},
		Status: garagev1beta2.GarageClusterStatus{
			Phase:     garagev1beta1.PhaseRunning,
			Endpoints: nil,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return newMockGarageClient(), nil
	})

	endpoint := p.getS3Endpoint(cluster)
	assert.Contains(t, endpoint, "my-cluster.garage-system.svc.cluster.local")
}

func TestProvisioner_GrantAccess_StoresServiceAccountName(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID}}
	_, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "my-sa")
	require.NoError(t, err)

	keyList := &garagev1beta1.GarageKeyList{}
	require.NoError(t, fakeClient.List(context.Background(), keyList, client.InNamespace(testGarageSystem)))
	require.Len(t, keyList.Items, 1)
	assert.Equal(t, "my-sa", keyList.Items[0].Annotations[AnnotationCOSIServiceAccountName])
}

func TestDeleteBucket_NotEmpty_PreservesTypedError(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 409, Message: "BucketNotEmpty"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err := p.DeleteBucket(context.Background(), testBucketID, defaultBucketParams())
	require.Error(t, err)
	assert.True(t, garage.IsBucketNotEmpty(err), "wrapped error must still satisfy IsBucketNotEmpty")
}

func TestGrantAccess_ShadowKeyFailure_RollsBackGarageKey(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	// Use a scheme that intentionally does NOT register GarageKey so Create returns an error.
	badScheme := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(badScheme)
	_ = garagev1beta2.AddToScheme(badScheme)
	_ = corev1.AddToScheme(badScheme)

	// Build a fake client but intercept GarageKey creates by using a scheme where
	// GarageKey IS registered (so the fake client works), then inject a sub-client
	// that always fails on GarageKey creates via a wrapper.
	goodClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	// Wrap the fake client so Create on GarageKey always fails.
	failingClient := &failCreateGarageKeyClient{Client: goodClient}

	mockGC := newMockGarageClient()
	mockGC.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}

	p := &Provisioner{
		client:        failingClient,
		namespace:     testGarageSystem,
		clusterDomain: "cluster.local",
		shadowManager: NewShadowManager(failingClient, testGarageSystem),
		garageClientFactory: func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockGC, nil
		},
	}

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	_, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create shadow key")

	// The Garage key that was created should have been rolled back.
	require.Len(t, mockGC.deleteKeyCalls, 1, "DeleteKey must be called to roll back the orphaned Garage key")
	// DenyBucketKey should be called for each slot.
	require.Len(t, mockGC.denyBucketKeyCalls, len(slots), "DenyBucketKey must be called for each slot during rollback")
}

// failCreateGarageKeyClient wraps a fake client and returns an error whenever
// Create is called with a GarageKey object.
type failCreateGarageKeyClient struct {
	client.Client
}

func (f *failCreateGarageKeyClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*garagev1beta1.GarageKey); ok {
		return fmt.Errorf("injected: GarageKey create failure")
	}
	return f.Client.Create(ctx, obj, opts...)
}

func TestProvisioner_RevokeAccess_NoParameters_UsesClusterRefFromShadow(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys[testGKTestKey] = &garage.Key{AccessKeyID: testGKTestKey}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	// Simulate what grant would do: create the shadow key first
	_, err := p.shadowManager.CreateShadowKeyWithID(
		context.Background(), testAccountName, testGKTestKey,
		testMyCluster, testGarageSystem,
		[]BucketPermission{{BucketID: testBucketID, Read: true, Write: true}},
		"",
	)
	require.NoError(t, err)

	// Revoke with nil params (no clusterRef)
	err = p.RevokeAccess(context.Background(), testGKTestKey, []string{testBucketID}, nil)

	require.NoError(t, err)
	require.Len(t, mockClient.deleteKeyCalls, 1)
	assert.Equal(t, testGKTestKey, mockClient.deleteKeyCalls[0])
}

// Regression: a transient (non-404) key-lookup failure must surface as an
// error, NOT fall through to CreateKey — otherwise every failed reconcile
// mints a duplicate Garage key (key leak), and once two keys share a name the
// name search stays ambiguous forever.
func TestGrantAccess_TransientLookupErrorDoesNotCreateKey(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.getKeyErr = &garage.APIError{StatusCode: 500, Message: "temporarily unavailable"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	_, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "lookup key")
	assert.Empty(t, mockClient.createKeyCalls, "a lookup failure must never mint a new key")
}

// Regression: when the BucketAccess already records an AccountID, the lookup
// must be by that exact ID — key names are not unique in Garage, so a name
// search can match the wrong key (or turn ambiguous) once duplicates exist.
func TestGrantAccess_KnownAccountIDReusesExactKey(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	// Two keys with the SAME name (the duplicate scenario); only GKoriginal is
	// the recorded account.
	mockClient.keys["GKoriginal"] = &garage.Key{AccessKeyID: "GKoriginal", SecretAccessKey: "secret-original", Name: testAccountName}
	mockClient.keys["GKduplicate"] = &garage.Key{AccessKeyID: "GKduplicate", SecretAccessKey: "secret-duplicate", Name: testAccountName}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	result, err := p.GrantAccess(context.Background(), testAccountName, "GKoriginal", slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, "GKoriginal", result.AccountID)
	assert.Equal(t, "secret-original", result.SecretAccessKey)
	assert.Empty(t, mockClient.createKeyCalls, "an already-provisioned access must reuse its recorded key")
}
