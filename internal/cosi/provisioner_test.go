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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
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
	deleteBucketErr error
	createKeyErr    error
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
	return nil, &garage.APIError{StatusCode: 404, Message: "bucket not found"}
}

func (m *mockGarageClient) UpdateBucket(ctx context.Context, req garage.UpdateBucketRequest) (*garage.Bucket, error) {
	bucket, ok := m.buckets[req.ID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: "bucket not found"}
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
		return nil, &garage.APIError{StatusCode: 404, Message: "bucket not found"}
	}
	// Add key to bucket's key list
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
		return nil, &garage.APIError{StatusCode: 404, Message: "bucket not found"}
	}
	return bucket, nil
}

// Helper to create a ready cluster
func createReadyCluster() *garagev1alpha1.GarageCluster {
	return &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "garage-system",
		},
		Spec: garagev1alpha1.GarageClusterSpec{},
		Status: garagev1alpha1.GarageClusterStatus{
			Phase: garagev1alpha1.PhaseRunning,
			Endpoints: &garagev1alpha1.ClusterEndpoints{
				S3: "http://garage.test:3900",
			},
		},
	}
}

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// === Error Path Tests ===

func TestProvisionerServer_DriverCreateBucket_MissingClusterRef(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{}, // Missing clusterRef
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotFound(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "nonexistent",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotReady(t *testing.T) {
	cluster := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "garage-system",
		},
		Spec: garagev1alpha1.GarageClusterSpec{},
		Status: garagev1alpha1.GarageClusterStatus{
			Phase: "Pending", // Not ready
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_ServiceAccountRejected(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_SERVICE_ACCOUNT,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_MissingClusterRef(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{}, // Missing clusterRef
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_NoBuckets(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets:     []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{}, // Empty
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// === Happy Path Tests ===

func TestProvisionerServer_DriverCreateBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverCreateBucket(context.Background(), req)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.BucketId)
	assert.Equal(t, "bucket-test-bucket", resp.BucketId)
	assert.NotNil(t, resp.Protocols)
	assert.NotNil(t, resp.Protocols.S3)

	// Verify Garage client was called
	require.Len(t, mockClient.createBucketCalls, 1)
	assert.Equal(t, "test-bucket", mockClient.createBucketCalls[0].GlobalAlias)
}

func TestProvisionerServer_DriverDeleteBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverDeleteBucketRequest{
		BucketId: "test-bucket-id",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverDeleteBucket(context.Background(), req)

	require.NoError(t, err)

	// Verify Garage client was called
	require.Len(t, mockClient.deleteBucketCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.deleteBucketCalls[0])
}

func TestProvisionerServer_DriverGrantBucketAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccountId)
	assert.Contains(t, resp.AccountId, "GK")

	// Verify credentials are returned
	require.NotNil(t, resp.Credentials)
	require.NotNil(t, resp.Credentials.S3)
	assert.NotEmpty(t, resp.Credentials.S3.AccessKeyId)
	assert.NotEmpty(t, resp.Credentials.S3.AccessSecretKey)

	// Verify bucket info
	require.Len(t, resp.Buckets, 1)
	assert.Equal(t, "test-bucket-id", resp.Buckets[0].BucketId)
	assert.NotNil(t, resp.Buckets[0].BucketInfo)
	assert.NotNil(t, resp.Buckets[0].BucketInfo.S3)

	// Verify Garage client was called
	require.Len(t, mockClient.createKeyCalls, 1)
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.allowBucketKeyCalls[0].BucketID)
}

func TestProvisionerServer_DriverRevokeBucketAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	mockClient.keys["GKtest-key"] = &garage.Key{AccessKeyID: "GKtest-key"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverRevokeBucketAccessRequest{
		AccountId: "GKtest-key",
		Buckets: []*cosiproto.DriverRevokeBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverRevokeBucketAccess(context.Background(), req)

	require.NoError(t, err)

	// Verify Garage client was called
	require.Len(t, mockClient.denyBucketKeyCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.denyBucketKeyCalls[0].BucketID)
	assert.Equal(t, "GKtest-key", mockClient.denyBucketKeyCalls[0].AccessKeyID)

	require.Len(t, mockClient.deleteKeyCalls, 1)
	assert.Equal(t, "GKtest-key", mockClient.deleteKeyCalls[0])
}

// === Idempotency Tests ===

func TestProvisionerServer_DriverGrantBucketAccess_Idempotent(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	// Pre-existing key with the same name
	mockClient.keys["GKtest-access"] = &garage.Key{
		AccessKeyID:     "GKtest-access",
		SecretAccessKey: "existing-secret",
		Name:            "test-access",
		Buckets: []garage.KeyBucket{
			{ID: "test-bucket-id", Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
		},
	}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "GKtest-access", resp.AccountId)
	assert.Equal(t, "existing-secret", resp.Credentials.S3.AccessSecretKey)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)
}

func TestProvisionerServer_DriverDeleteBucket_NotFound(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 404, Message: "not found"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverDeleteBucketRequest{
		BucketId: "nonexistent-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	// Should succeed even if bucket doesn't exist (idempotent delete)
	_, err := server.DriverDeleteBucket(context.Background(), req)
	require.NoError(t, err)
}

// === Bug Fix Tests ===

func TestProvisionerServer_DriverGrantBucketAccess_MultiBucket(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-1"] = &garage.Bucket{ID: "bucket-1"}
	mockClient.buckets["bucket-2"] = &garage.Bucket{ID: "bucket-2"}
	mockClient.buckets["bucket-3"] = &garage.Bucket{ID: "bucket-3"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "multi-bucket-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "bucket-1"},
			{BucketId: "bucket-2"},
			{BucketId: "bucket-3"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)

	// All 3 buckets must have BucketInfo entries
	require.Len(t, resp.Buckets, 3)
	bucketIDs := make(map[string]bool)
	for _, b := range resp.Buckets {
		bucketIDs[b.BucketId] = true
		require.NotNil(t, b.BucketInfo)
		require.NotNil(t, b.BucketInfo.S3)
	}
	assert.True(t, bucketIDs["bucket-1"])
	assert.True(t, bucketIDs["bucket-2"])
	assert.True(t, bucketIDs["bucket-3"])

	// All 3 AllowBucketKey calls should have been made
	require.Len(t, mockClient.allowBucketKeyCalls, 3)
}

func TestProvisionerServer_DriverGrantBucketAccess_AccessModes(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-rw"] = &garage.Bucket{ID: "bucket-rw"}
	mockClient.buckets["bucket-ro"] = &garage.Bucket{ID: "bucket-ro"}
	mockClient.buckets["bucket-wo"] = &garage.Bucket{ID: "bucket-wo"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "access-modes-test",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "bucket-rw", AccessMode: &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_WRITE}},
			{BucketId: "bucket-ro", AccessMode: &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_ONLY}},
			{BucketId: "bucket-wo", AccessMode: &cosiproto.AccessMode{Mode: cosiproto.AccessMode_WRITE_ONLY}},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Buckets, 3)

	// Verify permissions passed to Garage
	require.Len(t, mockClient.allowBucketKeyCalls, 3)

	permsByBucket := make(map[string]garage.BucketKeyPerms)
	for _, call := range mockClient.allowBucketKeyCalls {
		permsByBucket[call.BucketID] = call.Permissions
	}

	// READ_WRITE
	assert.True(t, permsByBucket["bucket-rw"].Read)
	assert.True(t, permsByBucket["bucket-rw"].Write)

	// READ_ONLY
	assert.True(t, permsByBucket["bucket-ro"].Read)
	assert.False(t, permsByBucket["bucket-ro"].Write)

	// WRITE_ONLY
	assert.False(t, permsByBucket["bucket-wo"].Read)
	assert.True(t, permsByBucket["bucket-wo"].Write)
}

func TestProvisionerServer_DriverGrantBucketAccess_UnsupportedProtocol(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Protocol: &cosiproto.ObjectProtocol{
			Type: cosiproto.ObjectProtocol_AZURE,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_S3ProtocolAllowed(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Protocol: &cosiproto.ObjectProtocol{
			Type: cosiproto.ObjectProtocol_S3,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccountId)
}

func TestProvisionerServer_DriverGetExistingBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["existing-bucket-id"] = &garage.Bucket{
		ID:            "existing-bucket-id",
		GlobalAliases: []string{"my-bucket"},
	}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGetExistingBucketRequest{
		ExistingBucketId: "existing-bucket-id",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGetExistingBucket(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "existing-bucket-id", resp.BucketId)
	require.NotNil(t, resp.Protocols)
	require.NotNil(t, resp.Protocols.S3)
	assert.Equal(t, "existing-bucket-id", resp.Protocols.S3.BucketId)
	assert.Equal(t, "http://garage.test:3900", resp.Protocols.S3.Endpoint)
}

func TestProvisionerServer_DriverGetExistingBucket_NotFound(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGetExistingBucketRequest{
		ExistingBucketId: "nonexistent-id",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverGetExistingBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestProvisionerServer_DriverGetExistingBucket_MissingID(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGetExistingBucketRequest{
		ExistingBucketId: "",
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGetExistingBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_IdempotentMismatch(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	existingSize := uint64(1000)
	mockClient := newMockGarageClient()
	// Pre-populate a bucket with specific quotas
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{"test-bucket"},
		Quotas: &garage.BucketQuotas{
			MaxSize: &existingSize,
		},
	}
	// CreateBucket will return conflict since the bucket exists
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: "conflict"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	differentSize := resource.MustParse("2000")
	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
			"maxSize":          "5000",
		},
	}
	_ = differentSize // just to validate it parses

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_IdempotentMatch(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	existingSize := uint64(5000)
	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{"test-bucket"},
		Quotas: &garage.BucketQuotas{
			MaxSize: &existingSize,
		},
	}
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: "conflict"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
			"maxSize":          "5000",
		},
	}

	resp, err := server.DriverCreateBucket(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", resp.BucketId)
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

	// Must be <= 63 chars
	assert.LessOrEqual(t, len(result), 63)
	// Must start with the prefix
	assert.True(t, strings.HasPrefix(result, strings.Repeat("a", 50)))
	// Must contain a hash separator
	assert.Contains(t, result, "-")
}

func TestSanitizeBucketName_DifferentLongNamesProduceDifferentResults(t *testing.T) {
	// Two names with the same 63-char prefix but different suffixes
	name1 := strings.Repeat("a", 70) + "xxx"
	name2 := strings.Repeat("a", 70) + "yyy"

	result1 := sanitizeBucketName(name1)
	result2 := sanitizeBucketName(name2)

	// Old behavior would truncate both to the same string - new behavior must differ
	assert.NotEqual(t, result1, result2)
	assert.LessOrEqual(t, len(result1), 63)
	assert.LessOrEqual(t, len(result2), 63)
}

// === Round 2 Bug Fix Tests ===

func TestProvisionerServer_DriverCreateBucket_EmptyName(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "",
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_EmptyAccountName(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_GetS3Endpoint_NilEndpoints(t *testing.T) {
	cluster := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "garage-system",
		},
		Spec: garagev1alpha1.GarageClusterSpec{},
		Status: garagev1alpha1.GarageClusterStatus{
			Phase:     garagev1alpha1.PhaseRunning,
			Endpoints: nil, // nil Endpoints pointer
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	// This should NOT panic even with nil Endpoints
	req := &cosiproto.DriverGetExistingBucketRequest{
		ExistingBucketId: "test-bucket-id",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGetExistingBucket(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "test-bucket-id", resp.BucketId)
	// Should fall back to constructing endpoint from service
	assert.Contains(t, resp.Protocols.S3.Endpoint, "my-cluster.garage-system.svc.cluster.local")
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

func TestProvisionerServer_DriverGrantBucketAccess_IdempotentUpdatesPermissions(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	// Pre-existing key with READ_WRITE permissions
	mockClient.keys["GKtest-access"] = &garage.Key{
		AccessKeyID:     "GKtest-access",
		SecretAccessKey: "existing-secret",
		Name:            "test-access",
		Buckets: []garage.KeyBucket{
			{ID: "test-bucket-id", Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
		},
	}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	// Request READ_ONLY -- should update even though key already has access
	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id", AccessMode: &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_ONLY}},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "GKtest-access", resp.AccountId)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)

	// Should have called AllowBucketKey to update permissions
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.allowBucketKeyCalls[0].BucketID)
	assert.True(t, mockClient.allowBucketKeyCalls[0].Permissions.Read)
	assert.False(t, mockClient.allowBucketKeyCalls[0].Permissions.Write, "should have updated to READ_ONLY")
}

func TestProvisionerServer_DriverGrantBucketAccess_IdempotentSkipsMatchingPermissions(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	// Pre-existing key with READ_ONLY permissions - matches what we'll request
	mockClient.keys["GKtest-access"] = &garage.Key{
		AccessKeyID:     "GKtest-access",
		SecretAccessKey: "existing-secret",
		Name:            "test-access",
		Buckets: []garage.KeyBucket{
			{ID: "test-bucket-id", Permissions: garage.BucketKeyPerms{Read: true, Write: false}},
		},
	}

	factory := func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", factory)

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id", AccessMode: &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_ONLY}},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "GKtest-access", resp.AccountId)

	// Should NOT call AllowBucketKey since permissions already match
	assert.Len(t, mockClient.allowBucketKeyCalls, 0)
}

func TestProvisionerServer_DriverDeleteBucket_EmptyBucketId(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverDeleteBucketRequest{
		BucketId: "",
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverDeleteBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverRevokeBucketAccess_EmptyAccountId(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverRevokeBucketAccessRequest{
		AccountId: "",
		Buckets: []*cosiproto.DriverRevokeBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverRevokeBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestMapAccessMode(t *testing.T) {
	tests := []struct {
		name      string
		mode      *cosiproto.AccessMode
		wantRead  bool
		wantWrite bool
	}{
		{
			name:      "nil defaults to read-write",
			mode:      nil,
			wantRead:  true,
			wantWrite: true,
		},
		{
			name:      "READ_WRITE",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_WRITE},
			wantRead:  true,
			wantWrite: true,
		},
		{
			name:      "READ_ONLY",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_ONLY},
			wantRead:  true,
			wantWrite: false,
		},
		{
			name:      "WRITE_ONLY",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_WRITE_ONLY},
			wantRead:  false,
			wantWrite: true,
		},
		{
			name:      "UNKNOWN defaults to read-write",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_UNKNOWN},
			wantRead:  true,
			wantWrite: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := mapAccessMode(tt.mode)
			assert.Equal(t, tt.wantRead, perms.Read)
			assert.Equal(t, tt.wantWrite, perms.Write)
		})
	}
}
