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

	createBucketCalls   []garage.CreateBucketRequest
	deleteBucketCalls   []string
	createKeyCalls      []string
	deleteKeyCalls      []string
	allowBucketKeyCalls []garage.AllowBucketKeyRequest
	denyBucketKeyCalls  []garage.DenyBucketKeyRequest

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
	if key, ok := m.keys[req.AccessKeyID]; ok {
		key.Buckets = append(key.Buckets, garage.KeyBucket{ID: req.BucketID, Permissions: req.Permissions})
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

func createShadowBucket(bucketID, globalAlias string) *garagev1alpha1.GarageBucket {
	return &garagev1alpha1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shadow-" + bucketID,
			Namespace: "garage-system",
			Labels: map[string]string{
				LabelCOSIManaged:  "true",
				LabelCOSIBucketID: truncateLabelValue(bucketID),
			},
			Annotations: map[string]string{
				AnnotationCOSIBucketID: bucketID,
			},
		},
		Spec: garagev1alpha1.GarageBucketSpec{
			GlobalAlias: globalAlias,
		},
	}
}

func createReadyCluster() *garagev1alpha1.GarageCluster {
	return &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "garage-system"},
		Spec:       garagev1alpha1.GarageClusterSpec{},
		Status: garagev1alpha1.GarageClusterStatus{
			Phase:     garagev1alpha1.PhaseRunning,
			Endpoints: &garagev1alpha1.ClusterEndpoints{S3: "http://garage.test:3900"},
		},
	}
}

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

// === DriverCreateBucket ===

func TestProvisionerServer_DriverCreateBucket_MissingClusterRef(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotFound(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{"clusterRef": "nonexistent", "clusterNamespace": "garage-system"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotReady(t *testing.T) {
	cluster := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "garage-system"},
		Status:     garagev1alpha1.GarageClusterStatus{Phase: "Pending"},
	}
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build(), "garage-system", "cluster.local")
	_, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestProvisionerServer_DriverCreateBucket_EmptyName(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "",
		Parameters: map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverCreateBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("bucket-test-bucket", "test-bucket")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resp, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", resp.BucketId)
	assert.NotNil(t, resp.BucketInfo)
	assert.NotNil(t, resp.BucketInfo.GetS3())
	require.Len(t, mockClient.createBucketCalls, 1)
	assert.Equal(t, "test-bucket", mockClient.createBucketCalls[0].GlobalAlias)
}

func TestProvisionerServer_DriverCreateBucket_IdempotentMatch(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("bucket-test-bucket", "existing-alias")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	existingSize := uint64(5000)
	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{"test-bucket"},
		Quotas:        &garage.BucketQuotas{MaxSize: &existingSize},
	}
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: "conflict"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resp, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system", "maxSize": "5000"},
	})

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", resp.BucketId)
}

func TestProvisionerServer_DriverCreateBucket_IdempotentMismatch(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	existingSize := uint64(1000)
	mockClient := newMockGarageClient()
	mockClient.buckets["bucket-test-bucket"] = &garage.Bucket{
		ID:            "bucket-test-bucket",
		GlobalAliases: []string{"test-bucket"},
		Quotas:        &garage.BucketQuotas{MaxSize: &existingSize},
	}
	mockClient.createBucketErr = &garage.APIError{StatusCode: 409, Message: "conflict"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	_ = resource.MustParse("5000") // just validates parsing

	_, err := server.DriverCreateBucket(context.Background(), &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system", "maxSize": "5000"},
	})

	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

// === DriverDeleteBucket ===

func TestProvisionerServer_DriverDeleteBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := server.DriverDeleteBucket(context.Background(), &cosiproto.DriverDeleteBucketRequest{
		BucketId:      "test-bucket-id",
		DeleteContext: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})

	require.NoError(t, err)
	require.Len(t, mockClient.deleteBucketCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.deleteBucketCalls[0])
}

func TestProvisionerServer_DriverDeleteBucket_NotFound(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 404, Message: "not found"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := server.DriverDeleteBucket(context.Background(), &cosiproto.DriverDeleteBucketRequest{
		BucketId:      "nonexistent-bucket",
		DeleteContext: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})
	require.NoError(t, err) // idempotent delete
}

func TestProvisionerServer_DriverDeleteBucket_EmptyBucketId(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverDeleteBucket(context.Background(), &cosiproto.DriverDeleteBucketRequest{
		BucketId:      "",
		DeleteContext: map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// === DriverGrantBucketAccess ===

func TestProvisionerServer_DriverGrantBucketAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("test-bucket-id", "test-bucket")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resp, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccountId)
	assert.Contains(t, resp.AccountId, "GK")

	// Verify credentials map structure
	require.NotNil(t, resp.Credentials)
	s3creds, ok := resp.Credentials["s3"]
	require.True(t, ok, "expected 's3' key in credentials")
	assert.NotEmpty(t, s3creds.Secrets["accessKeyId"])
	assert.NotEmpty(t, s3creds.Secrets["accessSecretKey"])
	assert.NotEmpty(t, s3creds.Secrets["endpoint"])
	assert.Equal(t, "test-bucket", s3creds.Secrets["bucketName"])

	require.Len(t, mockClient.createKeyCalls, 1)
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.allowBucketKeyCalls[0].BucketID)
}

func TestProvisionerServer_DriverGrantBucketAccess_IAMRejected(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_IAM,
		Parameters:         map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverGrantBucketAccess_EmptyAccountName(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverGrantBucketAccess_EmptyBucketId(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverGrantBucketAccess_MissingClusterRef(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestProvisionerServer_DriverGrantBucketAccess_Idempotent(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("test-bucket-id", "test-bucket")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	mockClient.keys["GKtest-access"] = &garage.Key{
		AccessKeyID:     "GKtest-access",
		SecretAccessKey: "existing-secret",
		Name:            "test-access",
		Buckets:         []garage.KeyBucket{{ID: "test-bucket-id", Permissions: garage.BucketKeyPerms{Read: true, Write: true}}},
	}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resp, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})

	require.NoError(t, err)
	assert.Equal(t, "GKtest-access", resp.AccountId)
	assert.Equal(t, "existing-secret", resp.Credentials["s3"].Secrets["accessSecretKey"])
	assert.Len(t, mockClient.createKeyCalls, 0) // should NOT create new key
}

// === DriverRevokeBucketAccess ===

func TestProvisionerServer_DriverRevokeBucketAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}
	mockClient.keys["GKtest-key"] = &garage.Key{AccessKeyID: "GKtest-key"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := server.DriverRevokeBucketAccess(context.Background(), &cosiproto.DriverRevokeBucketAccessRequest{
		AccountId:           "GKtest-key",
		BucketId:            "test-bucket-id",
		RevokeAccessContext: map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})

	require.NoError(t, err)
	require.Len(t, mockClient.denyBucketKeyCalls, 1)
	assert.Equal(t, "test-bucket-id", mockClient.denyBucketKeyCalls[0].BucketID)
	assert.Equal(t, "GKtest-key", mockClient.denyBucketKeyCalls[0].AccessKeyID)
	require.Len(t, mockClient.deleteKeyCalls, 1)
	assert.Equal(t, "GKtest-key", mockClient.deleteKeyCalls[0])
}

func TestProvisionerServer_DriverRevokeBucketAccess_EmptyAccountId(t *testing.T) {
	server := NewProvisionerServer(fake.NewClientBuilder().WithScheme(newTestScheme()).Build(), "garage-system", "cluster.local")
	_, err := server.DriverRevokeBucketAccess(context.Background(), &cosiproto.DriverRevokeBucketAccessRequest{
		AccountId:           "",
		BucketId:            "test-bucket-id",
		RevokeAccessContext: map[string]string{"clusterRef": "my-cluster"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// === Sanitize helpers ===

func TestSanitizeBucketName_Short(t *testing.T) {
	assert.Equal(t, "my-bucket", sanitizeBucketName("my-bucket"))
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
	r1 := sanitizeBucketName(strings.Repeat("a", 70) + "xxx")
	r2 := sanitizeBucketName(strings.Repeat("a", 70) + "yyy")
	assert.NotEqual(t, r1, r2)
	assert.LessOrEqual(t, len(r1), 63)
	assert.LessOrEqual(t, len(r2), 63)
}

func TestSanitizeKeyName_Short(t *testing.T) {
	assert.Equal(t, "my-key", sanitizeKeyName("my-key"))
}

func TestSanitizeKeyName_Long(t *testing.T) {
	name := strings.Repeat("k", 200)
	result := sanitizeKeyName(name)
	assert.LessOrEqual(t, len(result), 128)
	assert.True(t, strings.HasPrefix(result, strings.Repeat("k", 115)))
}

func TestSanitizeKeyName_DifferentLongNamesProduceDifferentResults(t *testing.T) {
	r1 := sanitizeKeyName(strings.Repeat("k", 130) + "xxx")
	r2 := sanitizeKeyName(strings.Repeat("k", 130) + "yyy")
	assert.NotEqual(t, r1, r2)
	assert.LessOrEqual(t, len(r1), 128)
	assert.LessOrEqual(t, len(r2), 128)
}

// === GetS3Endpoint fallback ===

func TestProvisionerServer_GetS3Endpoint_NilEndpoints(t *testing.T) {
	cluster := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "garage-system"},
		Spec:       garagev1alpha1.GarageClusterSpec{},
		Status:     garagev1alpha1.GarageClusterStatus{Phase: garagev1alpha1.PhaseRunning, Endpoints: nil},
	}
	shadowBucket := createShadowBucket("test-bucket-id", "test-bucket")
	fakeClient := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets["test-bucket-id"] = &garage.Bucket{ID: "test-bucket-id"}

	server := NewProvisionerServerWithFactory(fakeClient, "garage-system", func(_ context.Context, _ client.Client, _ *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resp, err := server.DriverGrantBucketAccess(context.Background(), &cosiproto.DriverGrantBucketAccessRequest{
		Name:               "test-access",
		BucketId:           "test-bucket-id",
		AuthenticationType: cosiproto.AuthenticationType_Key,
		Parameters:         map[string]string{"clusterRef": "my-cluster", "clusterNamespace": "garage-system"},
	})
	require.NoError(t, err)
	// Fallback endpoint should be constructed from service name
	assert.Contains(t, resp.Credentials["s3"].Secrets["endpoint"], "my-cluster.garage-system.svc.cluster.local")
}
