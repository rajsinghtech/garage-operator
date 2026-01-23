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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
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
			Phase: "Running",
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

func TestProvisionerServer_DriverGrantBucketAccess_IAMRejected(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_IAM,
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
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{}, // Missing clusterRef
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_NoBucketId(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "", // Empty
		AuthenticationType: cosiproto.AuthenticationType_Key,
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
	assert.NotNil(t, resp.BucketInfo)
	assert.NotNil(t, resp.BucketInfo.GetS3())

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
		DeleteContext: map[string]string{
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
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
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
	s3Creds, ok := resp.Credentials["s3"]
	require.True(t, ok, "s3 credentials should be present")
	assert.NotEmpty(t, s3Creds.Secrets["accessKeyID"])
	assert.NotEmpty(t, s3Creds.Secrets["accessSecretKey"])
	assert.NotEmpty(t, s3Creds.Secrets["endpoint"])

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
		BucketId:  "test-bucket-id",
		AccountId: "GKtest-key",
		RevokeAccessContext: map[string]string{
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
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	resp, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "GKtest-access", resp.AccountId)
	assert.Equal(t, "existing-secret", resp.Credentials["s3"].Secrets["accessSecretKey"])

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
		DeleteContext: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	// Should succeed even if bucket doesn't exist (idempotent delete)
	_, err := server.DriverDeleteBucket(context.Background(), req)
	require.NoError(t, err)
}
