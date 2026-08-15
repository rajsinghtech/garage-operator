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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
	addBucketAliasCalls []garage.AddBucketAliasRequest
	removeAliasCalls    []garage.RemoveBucketAliasRequest
	deleteBucketCalls   []string
	createKeyCalls      []string
	importKeyCalls      []garage.ImportKeyRequest
	deleteKeyCalls      []string
	allowBucketKeyCalls []garage.AllowBucketKeyRequest
	denyBucketKeyCalls  []garage.DenyBucketKeyRequest

	// For simulating errors
	createBucketErr  error
	addAliasErr      error
	updateBucketErr  error
	deleteBucketErr  error
	createKeyErr     error
	importKeyErrOnce error
	getKeyErr        error
	deleteKeyErr     error
	allowKeyErr      error
	denyKeyErr       error
}

type failCOSIShadowBindOnceClient struct {
	client.Client
	failBucket bool
	failKey    bool
}

func (c *failCOSIShadowBindOnceClient) Update(ctx context.Context, object client.Object, opts ...client.UpdateOption) error {
	switch typed := object.(type) {
	case *garagev1beta1.GarageBucket:
		if c.failBucket && typed.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStateBound {
			c.failBucket = false
			return fmt.Errorf("injected bucket bind failure")
		}
	case *garagev1beta1.GarageKey:
		if c.failKey && typed.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStateBound {
			c.failKey = false
			return fmt.Errorf("injected key bind failure")
		}
	}
	return c.Client.Update(ctx, object, opts...)
}

type deletingOnClusterRecheckClient struct {
	client.Client
	clusterGets int
}

type failReservationAliasClearOnceClient struct {
	client.Client
	fail bool
}

type failKeyStatusUpdateClient struct {
	client.Client
	updates int
	failAt  int
}

type replaceReservationSecretOnDeleteClient struct {
	client.Client
	target      types.NamespacedName
	replacement *corev1.Secret
	replaced    bool
}

type failFirstShadowListClient struct {
	client.Client
	failBucket bool
	failKey    bool
}

func (c *failFirstShadowListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	switch list.(type) {
	case *garagev1beta1.GarageBucketList:
		if c.failBucket {
			c.failBucket = false
			return fmt.Errorf("injected transient GarageBucket list failure")
		}
	case *garagev1beta1.GarageKeyList:
		if c.failKey {
			c.failKey = false
			return fmt.Errorf("injected transient GarageKey list failure")
		}
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *replaceReservationSecretOnDeleteClient) Delete(ctx context.Context, object client.Object, opts ...client.DeleteOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok || c.replaced || client.ObjectKeyFromObject(secret) != c.target {
		return c.Client.Delete(ctx, object, opts...)
	}
	c.replaced = true
	current := &corev1.Secret{}
	if err := c.Get(ctx, c.target, current); err != nil {
		return err
	}
	if err := c.Client.Delete(ctx, current); err != nil {
		return err
	}
	returnErr := c.Create(ctx, c.replacement.DeepCopy())
	if returnErr != nil {
		return returnErr
	}
	deleteOptions := (&client.DeleteOptions{}).ApplyOptions(opts)
	if deleteOptions.Preconditions != nil && deleteOptions.Preconditions.UID != nil &&
		*deleteOptions.Preconditions.UID != c.replacement.UID {
		return fmt.Errorf("UID precondition rejected replacement Secret")
	}
	return c.Client.Delete(ctx, object, opts...)
}

func (c *failKeyStatusUpdateClient) Status() client.SubResourceWriter {
	return &failKeyStatusWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type failKeyStatusWriter struct {
	client.SubResourceWriter
	parent *failKeyStatusUpdateClient
}

func (w *failKeyStatusWriter) Update(ctx context.Context, object client.Object, opts ...client.SubResourceUpdateOption) error {
	if _, ok := object.(*garagev1beta1.GarageKey); ok {
		w.parent.updates++
		if w.parent.updates == w.parent.failAt {
			return fmt.Errorf("injected replacement status failure")
		}
	}
	return w.SubResourceWriter.Update(ctx, object, opts...)
}

func (c *failReservationAliasClearOnceClient) Patch(ctx context.Context, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if bucket, ok := object.(*garagev1beta1.GarageBucket); ok && c.fail &&
		bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStateBound &&
		bucket.Annotations[garagev1beta1.AnnotationCOSIReservationAlias] == "" {
		c.fail = false
		return fmt.Errorf("injected reservation annotation clear failure")
	}
	return c.Client.Patch(ctx, object, patch, opts...)
}

func (c *deletingOnClusterRecheckClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, object, opts...); err != nil {
		return err
	}
	if cluster, ok := object.(*garagev1beta2.GarageCluster); ok {
		c.clusterGets++
		if c.clusterGets == 2 {
			now := metav1.Now()
			cluster.DeletionTimestamp = &now
		}
	}
	return nil
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
		ID: "bucket-" + req.GlobalAlias,
	}
	if req.GlobalAlias == "" {
		bucket.ID = fmt.Sprintf("generated-bucket-%d", len(m.buckets)+1)
	} else {
		bucket.GlobalAliases = []string{req.GlobalAlias}
	}
	m.buckets[bucket.ID] = bucket
	return bucket, nil
}

func (m *mockGarageClient) AddBucketAlias(_ context.Context, req garage.AddBucketAliasRequest) (*garage.Bucket, error) {
	m.addBucketAliasCalls = append(m.addBucketAliasCalls, req)
	if m.addAliasErr != nil {
		return nil, m.addAliasErr
	}
	bucket, ok := m.buckets[req.BucketID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
	}
	bucket.GlobalAliases = append(bucket.GlobalAliases, req.GlobalAlias)
	return bucket, nil
}

func (m *mockGarageClient) RemoveBucketAlias(_ context.Context, req garage.RemoveBucketAliasRequest) (*garage.Bucket, error) {
	m.removeAliasCalls = append(m.removeAliasCalls, req)
	bucket, ok := m.buckets[req.BucketID]
	if !ok {
		return nil, &garage.APIError{StatusCode: 404, Message: testBucketNotFound}
	}
	for i, alias := range bucket.GlobalAliases {
		if alias == req.GlobalAlias {
			bucket.GlobalAliases = append(bucket.GlobalAliases[:i], bucket.GlobalAliases[i+1:]...)
			break
		}
	}
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
	if req.Body.WebsiteAccess != nil {
		bucket.WebsiteAccess = req.Body.WebsiteAccess.Enabled
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

func (m *mockGarageClient) ImportKey(_ context.Context, req garage.ImportKeyRequest) (*garage.Key, error) {
	m.importKeyCalls = append(m.importKeyCalls, req)
	if m.importKeyErrOnce != nil {
		err := m.importKeyErrOnce
		m.importKeyErrOnce = nil
		return nil, err
	}
	if _, exists := m.keys[req.AccessKeyID]; exists {
		return nil, &garage.APIError{StatusCode: 409, Message: testConflictMsg}
	}
	key := &garage.Key{AccessKeyID: req.AccessKeyID, SecretAccessKey: req.SecretAccessKey, Name: req.Name}
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
		updated := false
		for i := range key.Buckets {
			if key.Buckets[i].ID != req.BucketID {
				continue
			}
			key.Buckets[i].Permissions.Read = key.Buckets[i].Permissions.Read || req.Permissions.Read
			key.Buckets[i].Permissions.Write = key.Buckets[i].Permissions.Write || req.Permissions.Write
			key.Buckets[i].Permissions.Owner = key.Buckets[i].Permissions.Owner || req.Permissions.Owner
			updated = true
			break
		}
		if !updated {
			key.Buckets = append(key.Buckets, garage.KeyBucket{
				ID: req.BucketID, Permissions: req.Permissions,
			})
		}
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
	if key, ok := m.keys[req.AccessKeyID]; ok {
		for i := 0; i < len(key.Buckets); i++ {
			if key.Buckets[i].ID != req.BucketID {
				continue
			}
			if req.Permissions.Read {
				key.Buckets[i].Permissions.Read = false
			}
			if req.Permissions.Write {
				key.Buckets[i].Permissions.Write = false
			}
			if req.Permissions.Owner {
				key.Buckets[i].Permissions.Owner = false
			}
			if key.Buckets[i].Permissions == (garage.BucketKeyPerms{}) {
				key.Buckets = append(key.Buckets[:i], key.Buckets[i+1:]...)
			}
			break
		}
	}
	return bucket, nil
}

// createShadowBucket creates a shadow GarageBucket resource for use in tests that call
// GetShadowBucketGlobalAliasByID (buildBucketResult, buildPerBucketResults).
func createShadowBucket(bucketID, globalAlias string) *garagev1beta1.GarageBucket {
	return &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ShadowResourceName(globalAlias),
			Namespace: testGarageSystem,
			Labels: map[string]string{
				LabelCOSIManaged:     paramTrue,
				LabelCOSIBucketClaim: truncateLabelValue(globalAlias),
				LabelCOSIBucketID:    truncateLabelValue(bucketID),
			},
			Annotations: map[string]string{
				AnnotationCOSIBucketID:         bucketID,
				annotationCOSIReservationOwner: globalAlias,
			},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:  garagev1beta1.ClusterReference{Name: testMyCluster, Namespace: testGarageSystem},
			GlobalAlias: globalAlias,
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID},
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
	_ = cosiv1alpha2.AddToScheme(scheme)
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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
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

	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not ready")
}

func TestProvisioner_EnsureBucket_EmptyName(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.EnsureBucket(context.Background(), "", defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket name is required")
}

func TestProvisioner_EnsureBucket_RejectsNegativeQuotasBeforeGarageCall(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	negative := int64(-1)
	params := defaultBucketParams()
	params.MaxObjects = &negative
	_, err := p.EnsureBucket(context.Background(), testBucketName, params)
	require.ErrorContains(t, err, "must not be negative")
	assert.Empty(t, mockClient.createBucketCalls)
}

func TestProvisioner_GrantAccess_EmptyAccountName(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.GrantAccess(context.Background(), "", "", []BucketAccessSlot{{BucketID: testBucketID}}, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accountName is required")
}

func TestProvisioner_GrantAccess_RejectsInvalidSlotsBeforeGarageCall(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	for name, slots := range map[string][]BucketAccessSlot{
		"empty bucket ID": {{AccessMode: AccessModeReadOnly}},
		"unknown mode":    {{BucketID: testBucketID, AccessMode: AccessMode(99)}},
		"duplicate bucket": {
			{BucketID: testBucketID, AccessMode: AccessModeReadOnly},
			{BucketID: testBucketID, AccessMode: AccessModeReadWrite},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")
			require.Error(t, err)
			assert.Empty(t, mockClient.createKeyCalls)
		})
	}
}

func TestProvisioner_GrantAccess_NoBuckets(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	_, err := p.GrantAccess(context.Background(), testAccountName, "", []BucketAccessSlot{}, defaultAccessParams(), "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one bucket")
}

func TestProvisioner_DeleteBucket_EmptyBucketId(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	err := p.DeleteBucket(context.Background(), "", defaultBucketParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucketID is required")
}

func TestProvisioner_RevokeAccess_EmptyAccountId(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	p := NewProvisioner(fakeClient, testGarageSystem, "cluster.local")

	err := p.RevokeAccess(context.Background(), "", []string{testBucketID}, defaultAccessParams())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accountID is required")
}

// === Happy Path Tests ===

func TestProvisioner_EnsureBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())

	require.NoError(t, err)
	assert.Equal(t, testBucketName, result.GlobalAlias)
	assert.NotEmpty(t, result.Endpoint)

	require.Len(t, mockClient.createBucketCalls, 1)
	recoveryAlias := mockClient.createBucketCalls[0].GlobalAlias
	assert.True(t, strings.HasPrefix(recoveryAlias, "cosi-rsv-"))
	assert.Len(t, recoveryAlias, len("cosi-rsv-")+32)
	assert.Equal(t, "bucket-"+recoveryAlias, result.BucketID)
	require.Len(t, mockClient.addBucketAliasCalls, 1)
	assert.Equal(t, testBucketName, mockClient.addBucketAliasCalls[0].GlobalAlias)
	require.Len(t, mockClient.removeAliasCalls, 1)
}

func TestEnsureBucketAppliesWebsiteBeforeReportingReady(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	params := defaultBucketParams()
	params.WebsiteEnabled = true

	result, err := p.EnsureBucket(t.Context(), testBucketName, params)
	require.NoError(t, err)
	assert.True(t, mockClient.buckets[result.BucketID].WebsiteAccess)
}

func TestEnsureBucketRejectsPrecreatedShadowAnnotationWithoutStatusProof(t *testing.T) {
	cluster := createReadyCluster()
	shadow := createShadowBucket("victim-bucket", testBucketName)
	shadow.Status = garagev1beta1.GarageBucketStatus{}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets["victim-bucket"] = &garage.Bucket{ID: "victim-bucket"}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(t.Context(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "without matching controller-owned status reservation")
	assert.Empty(t, mockClient.createBucketCalls)
	assert.Contains(t, mockClient.buckets, "victim-bucket")
}

func TestGrantAccessRejectsPrecreatedShadowAnnotationWithoutStatusProof(t *testing.T) {
	cluster := createReadyCluster()
	bucket := createShadowBucket(testBucketID, testBucketName)
	shadow := shadowKey(testAccountName, testMyCluster, testGarageSystem,
		[]BucketPermission{{BucketID: testBucketID, Read: true, Write: true}}, "")
	shadow.Namespace = testGarageSystem
	shadow.Annotations[AnnotationCOSIAccountID] = "GKvictim"
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, bucket, shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys["GKvictim"] = &garage.Key{AccessKeyID: "GKvictim", SecretAccessKey: "victim-secret"}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.GrantAccess(t.Context(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.ErrorContains(t, err, "without matching controller-owned status or BucketAccess identity")
	assert.Empty(t, mockClient.importKeyCalls)
	assert.Equal(t, "victim-secret", mockClient.keys["GKvictim"].SecretAccessKey)
}

func TestGrantAccessPrecreatedReservationSecretCannotReserveVictimID(t *testing.T) {
	cluster := createReadyCluster()
	bucket := createShadowBucket(testBucketID, testBucketName)
	shadow := shadowKey(testAccountName, testMyCluster, testGarageSystem,
		[]BucketPermission{{BucketID: testBucketID, Read: true, Write: true}}, "")
	shadow.Namespace = testGarageSystem
	shadow.UID = "shadow-key-uid"
	controller, block, immutable := true, true, true
	precreated := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: keyReservationSecretName(testAccountName), Namespace: testGarageSystem,
			Labels:      ShadowKeyLabels(testAccountName),
			Annotations: map[string]string{annotationCOSIReservationOwner: testAccountName},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: "GarageKey", Name: shadow.Name, UID: shadow.UID,
				Controller: &controller, BlockOwnerDeletion: &block,
			}},
		},
		Immutable: &immutable,
		Data: map[string][]byte{
			reservationAccessKeyIDKey: []byte("GKvictim"), reservationSecretKeyKey: []byte("wrong-secret"),
		},
	}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, bucket, shadow, precreated).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys["GKvictim"] = &garage.Key{AccessKeyID: "GKvictim", SecretAccessKey: "victim-secret"}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.GrantAccess(t.Context(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.ErrorContains(t, err, "does not match controller-owned status ID")
	persisted := &garagev1beta1.GarageKey{}
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), persisted))
	assert.NotEmpty(t, persisted.Status.AccessKeyID)
	assert.NotEqual(t, "GKvictim", persisted.Status.AccessKeyID)
	assert.Equal(t, "victim-secret", mockClient.keys["GKvictim"].SecretAccessKey)
	assert.Empty(t, mockClient.importKeyCalls)
}

func TestProvisioner_DeleteBucket_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

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

func TestProvisioner_DeleteBucket_PropagatesShadowDeleteFailure(t *testing.T) {
	cluster := createReadyCluster()
	shadow := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow).Build()
	failingClient := &failDeleteShadowClient{Client: baseClient}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err := p.DeleteBucket(context.Background(), testBucketID, defaultBucketParams())
	require.ErrorContains(t, err, "delete shadow bucket")
	assert.NotNil(t, failingClient.bucketDelete)
	assert.Len(t, mockClient.deleteBucketCalls, 1)
}

func TestProvisioner_GrantAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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

	require.Len(t, mockClient.importKeyCalls, 1)
	assert.Empty(t, mockClient.createKeyCalls)
	require.Len(t, mockClient.allowBucketKeyCalls, 1)
	assert.Equal(t, testBucketID, mockClient.allowBucketKeyCalls[0].BucketID)
}

func TestBucketAccessesWithSameNameInDifferentNamespacesGetDistinctKeys(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	a := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "team-a", UID: "uid-a"}}
	b := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "team-b", UID: "uid-b"}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket, a, b).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	resolvedA, err := p.ResolveBucketAccessIdentity(t.Context(), a.Namespace, a.Name, string(a.UID), "", cosiTestDriver)
	require.NoError(t, err)
	require.False(t, resolvedA.OwnsLegacyAccount)
	require.False(t, resolvedA.SharedLegacyAccount)
	resolvedB, err := p.ResolveBucketAccessIdentity(t.Context(), b.Namespace, b.Name, string(b.UID), "", cosiTestDriver)
	require.NoError(t, err)
	require.False(t, resolvedB.OwnsLegacyAccount)
	require.False(t, resolvedB.SharedLegacyAccount)
	identityA, identityB := resolvedA.Identity, resolvedB.Identity
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	resultA, err := p.GrantAccess(t.Context(), identityA, "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	resultB, err := p.GrantAccess(t.Context(), identityB, "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	assert.NotEqual(t, resultA.AccountID, resultB.AccountID)
	assert.NotEqual(t, resultA.SecretAccessKey, resultB.SecretAccessKey)
	assert.NotEqual(t, ShadowResourceName(identityA), ShadowResourceName(identityB))
}

func TestProvisioner_RevokeAccess_Success(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

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

func TestProvisioner_RevokeAccess_PropagatesShadowDeleteFailure(t *testing.T) {
	cluster := createReadyCluster()
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mgr := NewShadowManager(baseClient, testGarageSystem)
	_, err := mgr.CreateShadowKeyWithID(context.Background(), testAccountName, testGKTestKey,
		testMyCluster, testGarageSystem, []BucketPermission{{BucketID: testBucketID, Read: true}}, "")
	require.NoError(t, err)
	failingClient := &failDeleteShadowClient{Client: baseClient}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys[testGKTestKey] = &garage.Key{AccessKeyID: testGKTestKey}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err = p.RevokeAccess(context.Background(), testGKTestKey, []string{testBucketID}, defaultAccessParams())
	require.ErrorContains(t, err, "delete shadow key")
	assert.NotNil(t, failingClient.keyDelete)
	assert.Len(t, mockClient.deleteKeyCalls, 1)
}

// === Idempotency Tests ===

func TestProvisioner_GrantAccess_Idempotent(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	result, err := p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID, slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, testGarageAccessKeyID, result.AccountID)
	assert.Equal(t, testExistingSecret, result.SecretAccessKey)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)
}

func TestProvisioner_DeleteBucket_NotFound(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 404, Message: testNotFound}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	// Should succeed even if bucket doesn't exist (idempotent delete)
	err := p.DeleteBucket(context.Background(), "nonexistent-bucket", defaultBucketParams())
	require.NoError(t, err)
}

func TestEnsureBucket_QuotaUpdateFailureResumesShadowTrackedBucket(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

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

	// The exact bucket and shadow must survive so a retry cannot create a
	// duplicate if a compensating Garage delete were to fail.
	require.Len(t, mockClient.createBucketCalls, 1)
	createdID := "bucket-" + mockClient.createBucketCalls[0].GlobalAlias
	assert.Empty(t, mockClient.deleteBucketCalls)
	shadowID, shadowErr := p.shadowManager.GetShadowBucketID(context.Background(), testBucketName)
	require.NoError(t, shadowErr)
	assert.Equal(t, createdID, shadowID)

	mockClient.updateBucketErr = nil
	result, err := p.EnsureBucket(context.Background(), testBucketName, params)
	require.NoError(t, err)
	assert.Equal(t, createdID, result.BucketID)
	assert.Len(t, mockClient.createBucketCalls, 1, "retry must reuse the shadow-tracked Garage bucket")
}

func TestEnsureBucket_AliasFailureResumesShadowTrackedBucket(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.addAliasErr = fmt.Errorf("alias table unavailable")
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "alias table unavailable")
	require.Len(t, mockClient.createBucketCalls, 1)

	shadowID, err := p.shadowManager.GetShadowBucketID(context.Background(), testBucketName)
	require.NoError(t, err)
	assert.Equal(t, "bucket-"+mockClient.createBucketCalls[0].GlobalAlias, shadowID)

	mockClient.addAliasErr = nil
	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.NoError(t, err)
	assert.Equal(t, shadowID, result.BucketID)
	assert.Len(t, mockClient.createBucketCalls, 1, "retry must not create a second Garage bucket")
	require.Len(t, mockClient.addBucketAliasCalls, 2)
}

func TestEnsureBucket_RetryRecoversRemoteCreateBeforeShadowBind(t *testing.T) {
	cluster := createReadyCluster()
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	failingClient := &failCOSIShadowBindOnceClient{Client: baseClient, failBucket: true}
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "injected bucket bind failure")
	require.Len(t, mockClient.createBucketCalls, 1)

	reservation := &garagev1beta1.GarageBucket{}
	require.NoError(t, baseClient.Get(context.Background(), types.NamespacedName{
		Name: ShadowResourceName(testBucketName), Namespace: testGarageSystem,
	}, reservation))
	assert.Equal(t, garagev1beta1.COSIProvisioningStatePending,
		reservation.Annotations[garagev1beta1.AnnotationCOSIProvisioningState])
	assert.Empty(t, reservation.Annotations[AnnotationCOSIBucketID])

	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.NoError(t, err)
	assert.Len(t, mockClient.createBucketCalls, 1, "retry must recover by the reservation alias")
	assert.Equal(t, "bucket-"+mockClient.createBucketCalls[0].GlobalAlias, result.BucketID)
	require.NoError(t, baseClient.Get(context.Background(), client.ObjectKeyFromObject(reservation), reservation))
	assert.Equal(t, garagev1beta1.COSIProvisioningStateBound,
		reservation.Annotations[garagev1beta1.AnnotationCOSIProvisioningState])
	assert.Equal(t, result.BucketID, reservation.Annotations[AnnotationCOSIBucketID])
	assert.Empty(t, reservation.Annotations[garagev1beta1.AnnotationCOSIReservationAlias])
}

func TestEnsureBucketPendingStatusIdentityWinsWhenReservationAliasIsMissing(t *testing.T) {
	cluster := createReadyCluster()
	reservation := shadowBucket(testBucketName, testMyCluster, testGarageSystem, defaultBucketParams())
	reservation.Namespace = testGarageSystem
	reservation.UID = "shadow-bucket-uid"
	reservation.Status.BucketID = testBucketID
	alias, err := cosiBucketReservationAlias(reservation)
	require.NoError(t, err)
	reservation.Annotations[garagev1beta1.AnnotationCOSIReservationAlias] = alias
	reservation.Annotations[annotationCOSIReservationReady] = paramTrue
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, reservation).Build()
	mockClient := newMockGarageClient()
	// The exact bucket remains, but its private recovery alias was removed after
	// status persisted and before the metadata handoff completed.
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(baseClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	result, err := p.EnsureBucket(t.Context(), testBucketName, defaultBucketParams())
	require.NoError(t, err)
	assert.Equal(t, testBucketID, result.BucketID)
	assert.Empty(t, mockClient.createBucketCalls, "status-owned bucket must be fetched by exact ID")
}

func TestEnsureBucketRejectsExistingShadowForDifferentClusterBeforeRemoteMutation(t *testing.T) {
	cluster := createReadyCluster()
	reservation := shadowBucket(testBucketName, "other-cluster", testGarageSystem, defaultBucketParams())
	reservation.Namespace = testGarageSystem
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, reservation).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(t.Context(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "not requested cluster")
	assert.Empty(t, mockClient.createBucketCalls)
}

func TestEnsureBucket_RetryAfterReservationAliasRemovedBeforeAnnotationClear(t *testing.T) {
	cluster := createReadyCluster()
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	failingClient := &failReservationAliasClearOnceClient{Client: baseClient, fail: true}
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "injected reservation annotation clear failure")
	require.Len(t, mockClient.removeAliasCalls, 1)

	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.NoError(t, err)
	assert.Equal(t, "bucket-"+mockClient.createBucketCalls[0].GlobalAlias, result.BucketID)
	assert.Len(t, mockClient.createBucketCalls, 1)
	assert.Len(t, mockClient.removeAliasCalls, 1, "retry must not remove an alias already absent upstream")
}

func TestGrantAccess_RetryRecoversRemoteImportBeforeShadowBind(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	failingClient := &failCOSIShadowBindOnceClient{Client: baseClient, failKey: true}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}

	_, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")
	require.ErrorContains(t, err, "injected key bind failure")
	require.Len(t, mockClient.importKeyCalls, 1)
	firstID := mockClient.importKeyCalls[0].AccessKeyID

	result, err := p.GrantAccess(context.Background(), testAccountName, "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	assert.Equal(t, firstID, result.AccountID)
	assert.Len(t, mockClient.importKeyCalls, 1, "retry must fetch the exact reserved import ID")
	reservationSecret := &corev1.Secret{}
	err = baseClient.Get(context.Background(), types.NamespacedName{
		Name: keyReservationSecretName(testAccountName), Namespace: testGarageSystem,
	}, reservationSecret)
	assert.True(t, apierrors.IsNotFound(err), "bound reservation material should be removed")
}

func TestGrantAccessReservationDeleteUsesUIDPrecondition(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	secretKey := types.NamespacedName{
		Name: keyReservationSecretName(testAccountName), Namespace: testGarageSystem,
	}
	replacement := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: secretKey.Name, Namespace: secretKey.Namespace, UID: "foreign-replacement-uid",
	}, Data: map[string][]byte{"foreign": []byte("must-survive")}}
	racingClient := &replaceReservationSecretOnDeleteClient{
		Client: baseClient, target: secretKey, replacement: replacement,
	}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(racingClient, testGarageSystem,
		func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	_, err := p.GrantAccess(t.Context(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.ErrorContains(t, err, "delete bound key reservation Secret")
	require.True(t, racingClient.replaced)
	persisted := &corev1.Secret{}
	require.NoError(t, baseClient.Get(t.Context(), secretKey, persisted))
	require.Equal(t, replacement.UID, persisted.UID)
	require.Equal(t, replacement.Data, persisted.Data)
}

func TestDuplicateCleanupReservationDeleteUsesUIDPrecondition(t *testing.T) {
	identity := "ba-duplicate"
	accountID := "GKduplicate"
	cluster := createReadyCluster()
	shadow := shadowKey(identity, testMyCluster, testGarageSystem, nil, "")
	shadow.Namespace = testGarageSystem
	shadow.UID = "duplicate-shadow-uid"
	shadow.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	shadow.Annotations[AnnotationCOSIAccountID] = accountID
	shadow.Labels[LabelCOSIAccountID] = truncateLabelValue(accountID)
	shadow.Status.AccessKeyID, shadow.Status.KeyID = accountID, accountID
	immutable := true
	secretKey := types.NamespacedName{Name: keyReservationSecretName(identity), Namespace: testGarageSystem}
	controller, block := true, true
	reservation := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: secretKey.Name, Namespace: secretKey.Namespace, UID: "reservation-uid",
		Labels:      ShadowKeyLabels(identity),
		Annotations: map[string]string{annotationCOSIReservationOwner: identity},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: "GarageKey", Name: shadow.Name, UID: shadow.UID,
			Controller: &controller, BlockOwnerDeletion: &block,
		}},
	}, Data: map[string][]byte{
		reservationAccessKeyIDKey: []byte(accountID), reservationSecretKeyKey: []byte("reserved-secret"),
	}, Immutable: &immutable}
	replacement := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: secretKey.Name, Namespace: secretKey.Namespace, UID: "foreign-replacement-uid",
	}, Data: map[string][]byte{"foreign": []byte("must-survive")}}
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow, reservation).Build()
	racingClient := &replaceReservationSecretOnDeleteClient{
		Client: baseClient, target: secretKey, replacement: replacement,
	}
	mockClient := newMockGarageClient()
	mockClient.keys[accountID] = &garage.Key{AccessKeyID: accountID}
	p := NewProvisionerWithFactory(racingClient, testGarageSystem,
		func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	done, err := p.CleanupDuplicateAccessIdentity(t.Context(), identity)
	require.False(t, done)
	require.ErrorContains(t, err, "delete duplicate key reservation Secret")
	require.True(t, racingClient.replaced)
	persisted := &corev1.Secret{}
	require.NoError(t, baseClient.Get(t.Context(), secretKey, persisted))
	require.Equal(t, replacement.UID, persisted.UID)
	require.Equal(t, replacement.Data, persisted.Data)
}

func TestDuplicateCleanupWithoutShadowPreservesSameNameSecret(t *testing.T) {
	identity := "ba-absent"
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: keyReservationSecretName(identity), Namespace: testGarageSystem, UID: "foreign-secret-uid",
	}}
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(secret).Build()
	p := NewProvisionerWithFactory(baseClient, testGarageSystem, nil)

	done, err := p.CleanupDuplicateAccessIdentity(t.Context(), identity)
	require.NoError(t, err)
	require.True(t, done)
	require.NoError(t, baseClient.Get(t.Context(), client.ObjectKeyFromObject(secret), &corev1.Secret{}))
}

func TestGrantAccessRotatesGarageTombstonedReservation(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.importKeyErrOnce = &garage.APIError{StatusCode: 409, Message: "KeyAlreadyExists"}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}

	_, err := p.GrantAccess(t.Context(), testAccountName, "", slots, defaultAccessParams(), "")
	require.ErrorContains(t, err, "import or recover reserved Garage key")
	require.Len(t, mockClient.importKeyCalls, 1)
	tombstonedID := mockClient.importKeyCalls[0].AccessKeyID

	result, err := p.GrantAccess(t.Context(), testAccountName, "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	require.NotEqual(t, tombstonedID, result.AccountID)
	require.Len(t, mockClient.importKeyCalls, 2)
	require.Equal(t, result.AccountID, mockClient.importKeyCalls[1].AccessKeyID)
}

func TestGrantAccessReservationRotationRecoversAfterStatusFailure(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	failingClient := &failKeyStatusUpdateClient{Client: baseClient, failAt: 2}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.importKeyErrOnce = &garage.APIError{StatusCode: 409, Message: "KeyAlreadyExists"}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}

	_, err := p.GrantAccess(t.Context(), testAccountName, "", slots, defaultAccessParams(), "")
	require.Error(t, err)
	oldID := mockClient.importKeyCalls[0].AccessKeyID
	_, err = p.GrantAccess(t.Context(), testAccountName, "", slots, defaultAccessParams(), "")
	require.ErrorContains(t, err, "injected replacement status failure")
	reservationSecret := &corev1.Secret{}
	err = baseClient.Get(t.Context(), types.NamespacedName{Name: keyReservationSecretName(testAccountName), Namespace: testGarageSystem}, reservationSecret)
	require.True(t, apierrors.IsNotFound(err), "old reservation material must be gone before status advances")
	reservation := &garagev1beta1.GarageKey{}
	require.NoError(t, baseClient.Get(t.Context(), types.NamespacedName{Name: ShadowResourceName(testAccountName), Namespace: testGarageSystem}, reservation))
	require.Equal(t, oldID, reservation.Status.AccessKeyID)

	result, err := p.GrantAccess(t.Context(), testAccountName, "", slots, defaultAccessParams(), "")
	require.NoError(t, err)
	require.NotEqual(t, oldID, result.AccountID)
}

func TestGrantAccessReservationRotationRecoversStatusFirstCrash(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	reservation, _, err := p.shadowManager.ReserveShadowKey(t.Context(), testAccountName,
		testMyCluster, testGarageSystem, []BucketPermission{{BucketID: testBucketID, Read: true, Write: true}}, "")
	require.NoError(t, err)
	require.NoError(t, p.shadowManager.SetShadowKeyReservationID(t.Context(), reservation, "GKtombstoned"))
	require.NoError(t, p.shadowManager.persistShadowKeyStatusID(t.Context(), reservation, "GKtombstoned", "GKreplacement"))

	result, err := p.GrantAccess(t.Context(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.NoError(t, err)
	require.Equal(t, "GKreplacement", result.AccountID)
	require.Len(t, mockClient.importKeyCalls, 1)
	require.Equal(t, "GKreplacement", mockClient.importKeyCalls[0].AccessKeyID)
}

func TestPendingBucketReservationFencesDeletionAfterRemoteCreate(t *testing.T) {
	cluster := createReadyCluster()
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	failingClient := &failCOSIShadowBindOnceClient{Client: baseClient, failBucket: true}
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "injected bucket bind failure")
	require.Len(t, mockClient.createBucketCalls, 1)

	reservation := &garagev1beta1.GarageBucket{}
	objectKey := types.NamespacedName{Name: ShadowResourceName(testBucketName), Namespace: testGarageSystem}
	require.NoError(t, baseClient.Get(context.Background(), objectKey, reservation))
	assert.Contains(t, reservation.Finalizers, garagev1beta1.GarageBucketFinalizer)
	require.NoError(t, baseClient.Delete(context.Background(), reservation))
	require.NoError(t, baseClient.Get(context.Background(), objectKey, reservation))
	assert.False(t, reservation.DeletionTimestamp.IsZero(), "pending reservation must survive until its controller deletes the remote bucket")
}

func TestPendingKeyReservationFencesDeletionAfterRemoteImport(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	failingClient := &failCOSIShadowBindOnceClient{Client: baseClient, failKey: true}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.GrantAccess(context.Background(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.ErrorContains(t, err, "injected key bind failure")
	require.Len(t, mockClient.importKeyCalls, 1)

	reservation := &garagev1beta1.GarageKey{}
	objectKey := types.NamespacedName{Name: ShadowResourceName(testAccountName), Namespace: testGarageSystem}
	require.NoError(t, baseClient.Get(context.Background(), objectKey, reservation))
	assert.Contains(t, reservation.Finalizers, garagev1beta1.GarageKeyFinalizer)
	require.NoError(t, baseClient.Delete(context.Background(), reservation))
	require.NoError(t, baseClient.Get(context.Background(), objectKey, reservation))
	assert.False(t, reservation.DeletionTimestamp.IsZero(), "pending reservation must survive until its controller deletes the remote key")
}

func TestGrantAccess_ReplacesPendingKnownAccountIDOnlyAfterExactNotFound(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	reservation, _, err := p.shadowManager.ReserveShadowKey(context.Background(), testAccountName,
		testMyCluster, testGarageSystem, []BucketPermission{{BucketID: testBucketID, Read: true}}, "")
	require.NoError(t, err)
	require.NoError(t, p.shadowManager.SetShadowKeyReservationID(context.Background(), reservation, "GKdeleted"))

	result, err := p.GrantAccess(context.Background(), testAccountName, "GKdeleted",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}, defaultAccessParams(), "")
	require.NoError(t, err)
	assert.NotEqual(t, "GKdeleted", result.AccountID)
	require.Len(t, mockClient.importKeyCalls, 1)
	assert.Equal(t, result.AccountID, mockClient.importKeyCalls[0].AccessKeyID)
}

func TestProvisioningRechecksClusterDeletionBeforeRemoteCreate(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Provisioner) error
	}{
		{
			name: "bucket",
			run: func(p *Provisioner) error {
				_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
				return err
			},
		},
		{
			name: "key",
			run: func(p *Provisioner) error {
				_, err := p.GrantAccess(context.Background(), testAccountName, "",
					[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := createReadyCluster()
			baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
			fencedClient := &deletingOnClusterRecheckClient{Client: baseClient}
			mockClient := newMockGarageClient()
			mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
			p := NewProvisionerWithFactory(fencedClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
				return mockClient, nil
			})

			err := tc.run(p)
			require.ErrorContains(t, err, "deleting")
			assert.Empty(t, mockClient.createBucketCalls)
			assert.Empty(t, mockClient.importKeyCalls)
			assert.Empty(t, mockClient.createKeyCalls)
		})
	}
}

func TestProvisioningRequiresRuntimeCrossNamespaceClusterGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Provisioner) error
	}{
		{
			name: "bucket",
			run: func(p *Provisioner) error {
				_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
				return err
			},
		},
		{
			name: "key",
			run: func(p *Provisioner) error {
				_, err := p.GrantAccess(context.Background(), testAccountName, "",
					[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := createReadyCluster()
			fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
			mockClient := newMockGarageClient()
			factoryCalled := false
			p := NewProvisionerWithFactory(fakeClient, "cosi-system", func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
				factoryCalled = true
				return mockClient, nil
			})

			err := tc.run(p)
			require.ErrorContains(t, err, "not permitted")
			assert.False(t, factoryCalled)
			assert.Empty(t, mockClient.createBucketCalls)
			assert.Empty(t, mockClient.importKeyCalls)
		})
	}
}

func TestProvisioningAllowsNamespaceSelectorClusterGrant(t *testing.T) {
	const shadowNamespace = "cosi-system"
	cluster := createReadyCluster()
	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-cosi-selector", Namespace: testGarageSystem},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{
				Kind: "GarageBucket",
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"garage.example.com/application": "cosi",
				}},
			}},
			To: []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: testMyCluster}},
		},
	}
	sourceNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: shadowNamespace,
		Labels: map[string]string{
			"garage.example.com/application": "cosi",
		},
	}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, grant, sourceNamespace).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, shadowNamespace, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	if _, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams()); err != nil {
		t.Fatalf("COSI bucket provisioning with matching namespace selector: %v", err)
	}
	if len(mockClient.createBucketCalls) != 1 {
		t.Fatalf("Garage CreateBucket calls = %d, want 1", len(mockClient.createBucketCalls))
	}
}

func TestEnsureBucket_DoesNotAdoptUntrackedExistingAlias(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID, GlobalAliases: []string{testBucketName}}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "untracked Garage bucket")
	assert.Empty(t, mockClient.createBucketCalls)
	assert.Empty(t, mockClient.deleteBucketCalls)
	assert.Contains(t, mockClient.buckets, testBucketID)
	_, err = p.shadowManager.GetShadowBucketID(context.Background(), testBucketName)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestEnsureBucket_ResumeConvergesQuotasAfterCrash(t *testing.T) {
	cluster := createReadyCluster()
	params := defaultBucketParams()
	maxObjects := int64(42)
	params.MaxObjects = &maxObjects
	shadow := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	result, err := p.EnsureBucket(context.Background(), testBucketName, params)
	require.NoError(t, err)
	assert.Equal(t, testBucketID, result.BucketID)
	require.NotNil(t, mockClient.buckets[testBucketID].Quotas)
	require.NotNil(t, mockClient.buckets[testBucketID].Quotas.MaxObjects)
	assert.Equal(t, uint64(42), *mockClient.buckets[testBucketID].Quotas.MaxObjects)
	assert.Empty(t, mockClient.createBucketCalls, "resume must not create another Garage bucket")
}

func TestEnsureBucket_ReplacesStaleShadowOnlyAfterExactBucketIsGone(t *testing.T) {
	cluster := createReadyCluster()
	staleShadow := createShadowBucket("deleted-bucket", testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, staleShadow).Build()
	mockClient := newMockGarageClient()
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.ErrorContains(t, err, "stale shadow deletion started")
	assert.Empty(t, mockClient.createBucketCalls, "must not create while the stale ownership record still exists")

	result, err := p.EnsureBucket(context.Background(), testBucketName, defaultBucketParams())
	require.NoError(t, err)
	assert.NotEqual(t, "deleted-bucket", result.BucketID)
	assert.Len(t, mockClient.createBucketCalls, 1)
}

// === Bug Fix Tests ===

func TestProvisioner_GrantAccess_MultiBucket(t *testing.T) {
	cluster := createReadyCluster()
	shadow1 := createShadowBucket("bucket-1", "alias-bucket-1")
	shadow2 := createShadowBucket("bucket-2", "alias-bucket-2")
	shadow3 := createShadowBucket("bucket-3", "alias-bucket-3")
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow1, shadow2, shadow3).Build()

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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowRW, shadowRO, shadowWO).Build()

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

func TestProvisioner_EnsureBucket_IdempotentMismatchConverges(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("bucket-test-bucket", testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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

	result, err := p.EnsureBucket(context.Background(), testBucketName, params)

	require.NoError(t, err)
	assert.Equal(t, "bucket-test-bucket", result.BucketID)
	require.NotNil(t, mockClient.buckets["bucket-test-bucket"].Quotas.MaxSize)
	assert.Equal(t, uint64(5000), *mockClient.buckets["bucket-test-bucket"].Quotas.MaxSize)
}

func TestProvisioner_EnsureBucket_IdempotentMatch(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket("bucket-test-bucket", testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	result, err := p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID, slots, defaultAccessParams(), "")

	require.NoError(t, err)
	assert.Equal(t, testGarageAccessKeyID, result.AccountID)

	// Should NOT create a new key (idempotent)
	assert.Len(t, mockClient.createKeyCalls, 0)

	// Garage's Allow endpoint is additive. A downgrade must explicitly deny the
	// stale write bit instead of sending Allow(read=true, write=false), which
	// leaves write access untouched upstream.
	assert.Empty(t, mockClient.allowBucketKeyCalls)
	require.Len(t, mockClient.denyBucketKeyCalls, 1)
	assert.Equal(t, testBucketID, mockClient.denyBucketKeyCalls[0].BucketID)
	assert.False(t, mockClient.denyBucketKeyCalls[0].Permissions.Read)
	assert.True(t, mockClient.denyBucketKeyCalls[0].Permissions.Write)
}

func TestProvisioner_GrantAccess_RemovesBucketsNoLongerRequested(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.buckets["stale-bucket"] = &garage.Bucket{ID: "stale-bucket"}
	mockClient.keys[testGarageAccessKeyID] = &garage.Key{
		AccessKeyID: testGarageAccessKeyID, SecretAccessKey: testExistingSecret, Name: testAccountName,
		Buckets: []garage.KeyBucket{
			{ID: testBucketID, Permissions: garage.BucketKeyPerms{Read: true}},
			{ID: "stale-bucket", Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true}},
		},
	}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	_, err := p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID,
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}, defaultAccessParams(), "")
	require.NoError(t, err)
	require.Len(t, mockClient.denyBucketKeyCalls, 1)
	assert.Equal(t, "stale-bucket", mockClient.denyBucketKeyCalls[0].BucketID)
	assert.Equal(t, garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
		mockClient.denyBucketKeyCalls[0].Permissions)

	shadow := &garagev1beta1.GarageKey{}
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{
		Name: ShadowResourceName(testAccountName), Namespace: testGarageSystem,
	}, shadow))
	require.Len(t, shadow.Spec.BucketPermissions, 1)
	assert.Equal(t, testBucketID, shadow.Spec.BucketPermissions[0].BucketID)

	beforeDeny, beforeAllow := len(mockClient.denyBucketKeyCalls), len(mockClient.allowBucketKeyCalls)
	_, err = p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID,
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}, defaultAccessParams(), "")
	require.NoError(t, err)
	assert.Len(t, mockClient.denyBucketKeyCalls, beforeDeny)
	assert.Len(t, mockClient.allowBucketKeyCalls, beforeAllow)
}

func TestProvisioner_GrantAccess_IdempotentSkipsMatchingPermissions(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	result, err := p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID, slots, defaultAccessParams(), "")

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

	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return newMockGarageClient(), nil
	})

	endpoint, err := p.getS3Endpoint(cluster)
	require.NoError(t, err)
	assert.Contains(t, endpoint, "my-cluster.garage-system.svc.cluster.local")
	assert.True(t, strings.HasPrefix(endpoint, "http://"))
}

func TestProvisioner_GetS3Endpoint_ManagementHandleRequiresObservedEndpoint(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testMyCluster, Namespace: testGarageSystem},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			AdminAPIEndpoint: "https://admin.garage.example",
		}},
		Status: garagev1beta2.GarageClusterStatus{Phase: garagev1beta1.PhaseRunning},
	}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()
	factoryCalled := false
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		factoryCalled = true
		return newMockGarageClient(), nil
	})

	_, err := p.getS3Endpoint(cluster)
	require.ErrorContains(t, err, "management-handle GarageCluster")
	require.ErrorContains(t, err, "no observed S3 endpoint")

	_, err = p.GrantAccess(t.Context(), "access", "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.ErrorContains(t, err, "no observed S3 endpoint")
	require.False(t, factoryCalled, "endpoint validation must happen before constructing a Garage client or mutating a key")
}

func TestProvisioner_GrantAccess_StoresServiceAccountName(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 409, Message: "BucketNotEmpty"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	err := p.DeleteBucket(context.Background(), testBucketID, defaultBucketParams())
	require.Error(t, err)
	assert.True(t, garage.IsBucketNotEmpty(err), "wrapped error must still satisfy IsBucketNotEmpty")
}

func TestDeleteBucket_TransientShadowLookupFailureRetainsRemoteAndShadow(t *testing.T) {
	shadow := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(shadow).Build()
	failingClient := &failFirstShadowListClient{Client: baseClient, failBucket: true}
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	err := p.DeleteBucket(t.Context(), testBucketID, nil)
	require.ErrorContains(t, err, "injected transient GarageBucket list failure")
	require.Empty(t, mockClient.deleteBucketCalls)
	require.Contains(t, mockClient.buckets, testBucketID)
	require.NoError(t, baseClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageBucket{}))
}

func TestRevokeAccess_TransientShadowLookupFailureRetainsRemoteAndShadow(t *testing.T) {
	shadow := shadowKey(testAccountName, testMyCluster, testGarageSystem, nil, "")
	shadow.Namespace = testGarageSystem
	shadow.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	shadow.Annotations[AnnotationCOSIAccountID] = testGKTestKey
	shadow.Labels[LabelCOSIAccountID] = truncateLabelValue(testGKTestKey)
	shadow.Status.AccessKeyID, shadow.Status.KeyID = testGKTestKey, testGKTestKey
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(shadow).Build()
	failingClient := &failFirstShadowListClient{Client: baseClient, failKey: true}
	mockClient := newMockGarageClient()
	mockClient.keys[testGKTestKey] = &garage.Key{AccessKeyID: testGKTestKey}
	p := NewProvisionerWithFactory(failingClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	err := p.RevokeAccess(t.Context(), testGKTestKey, nil, nil)
	require.ErrorContains(t, err, "injected transient GarageKey list failure")
	require.Empty(t, mockClient.deleteKeyCalls)
	require.Contains(t, mockClient.keys, testGKTestKey)
	require.NoError(t, baseClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageKey{}))
}

func TestDeleteBucket_MissingClusterRetainsRemoteAndShadow(t *testing.T) {
	shadow := createShadowBucket(testBucketID, testBucketName)
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(baseClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	err := p.DeleteBucket(t.Context(), testBucketID, defaultBucketParams())
	require.ErrorContains(t, err, "for bucket cleanup")
	require.Empty(t, mockClient.deleteBucketCalls)
	require.Contains(t, mockClient.buckets, testBucketID)
	require.NoError(t, baseClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageBucket{}))
}

func TestRevokeAccess_MissingClusterRetainsRemoteAndShadow(t *testing.T) {
	shadow := shadowKey(testAccountName, testMyCluster, testGarageSystem, nil, "")
	shadow.Namespace = testGarageSystem
	shadow.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	shadow.Annotations[AnnotationCOSIAccountID] = testGKTestKey
	shadow.Labels[LabelCOSIAccountID] = truncateLabelValue(testGKTestKey)
	shadow.Status.AccessKeyID, shadow.Status.KeyID = testGKTestKey, testGKTestKey
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[testGKTestKey] = &garage.Key{AccessKeyID: testGKTestKey}
	p := NewProvisionerWithFactory(baseClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	err := p.RevokeAccess(t.Context(), testGKTestKey, nil, defaultAccessParams())
	require.ErrorContains(t, err, "for access cleanup")
	require.Empty(t, mockClient.deleteKeyCalls)
	require.Contains(t, mockClient.keys, testGKTestKey)
	require.NoError(t, baseClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageKey{}))
}

func TestDuplicateCleanupConvergesAcrossReservationRotationStatusCrash(t *testing.T) {
	const (
		identity = "ba-rotated-duplicate"
		oldID    = "GKduplicate-old"
		newID    = "GKduplicate-new"
	)
	cluster := createReadyCluster()
	shadow := shadowKey(identity, testMyCluster, testGarageSystem, nil, "")
	shadow.Namespace = testGarageSystem
	shadow.UID = "rotated-shadow-uid"
	shadow.Annotations[AnnotationCOSIAccountID] = oldID
	shadow.Labels[LabelCOSIAccountID] = truncateLabelValue(oldID)
	shadow.Status.AccessKeyID, shadow.Status.KeyID = newID, newID
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow).Build()
	mockClient := newMockGarageClient()
	// ReplaceShadowKeyReservationID proves the old remote ID absent before its
	// status-first rotation. The stale annotation must not become deletion
	// authority if the process crashes before patching it to the new ID.
	mockClient.keys[newID] = &garage.Key{AccessKeyID: newID}
	p := NewProvisionerWithFactory(baseClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	done, err := p.CleanupDuplicateAccessIdentity(t.Context(), identity)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, []string{newID}, mockClient.deleteKeyCalls)
	require.NotContains(t, mockClient.keys, newID)
	require.True(t, apierrors.IsNotFound(
		baseClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageKey{}),
	))
}

func TestDuplicateCleanupNeverDeletesAnnotationOnlyAccountID(t *testing.T) {
	const (
		identity = "ba-forged-duplicate"
		victimID = "GKvictim"
	)
	cluster := createReadyCluster()
	shadow := shadowKey(identity, testMyCluster, testGarageSystem, nil, "")
	shadow.Namespace = testGarageSystem
	shadow.UID = "forged-shadow-uid"
	shadow.Annotations[AnnotationCOSIAccountID] = victimID
	shadow.Labels[LabelCOSIAccountID] = truncateLabelValue(victimID)
	shadow.Status.AccessKeyID, shadow.Status.KeyID = "", ""
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadow).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[victimID] = &garage.Key{AccessKeyID: victimID}
	p := NewProvisionerWithFactory(baseClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})

	done, err := p.CleanupDuplicateAccessIdentity(t.Context(), identity)
	require.NoError(t, err)
	require.False(t, done, "shadow finalization must verify the annotation instead of treating it as deletion authority")
	require.Empty(t, mockClient.deleteKeyCalls)
	require.Contains(t, mockClient.keys, victimID)
}

func TestGrantAccess_ShadowReservationFailureDoesNotCreateGarageKey(t *testing.T) {
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
	goodClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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
	assert.Contains(t, err.Error(), "reserve shadow key")
	assert.Empty(t, mockGC.importKeyCalls, "remote creation must not precede its durable reservation")
	assert.Empty(t, mockGC.createKeyCalls)
	assert.Empty(t, mockGC.deleteKeyCalls)
	assert.Empty(t, mockGC.denyBucketKeyCalls)
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

type failDeleteShadowClient struct {
	client.Client
	bucketDelete *garagev1beta1.GarageBucket
	keyDelete    *garagev1beta1.GarageKey
}

func (f *failDeleteShadowClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	switch typed := obj.(type) {
	case *garagev1beta1.GarageBucket:
		f.bucketDelete = typed.DeepCopy()
		return fmt.Errorf("injected: GarageBucket delete failure")
	case *garagev1beta1.GarageKey:
		f.keyDelete = typed.DeepCopy()
		return fmt.Errorf("injected: GarageKey delete failure")
	default:
		return f.Client.Delete(ctx, obj, opts...)
	}
}

func TestProvisioner_RevokeAccess_NoParameters_UsesClusterRefFromShadow(t *testing.T) {
	cluster := createReadyCluster()
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster).Build()

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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.getKeyErr = &garage.APIError{StatusCode: 500, Message: "temporarily unavailable"}

	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}
	_, err := p.GrantAccess(context.Background(), testAccountName, testGarageAccessKeyID, slots, defaultAccessParams(), "")

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
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

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

// Regression: a first-time BucketAccess must not adopt a Garage key merely
// because it has the same display name. Garage permits duplicate key names;
// adopting by name would disclose that unrelated key's secret and later let
// COSI revoke or delete a key it does not own.
func TestGrantAccess_FirstUseDoesNotAdoptSameNameKey(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()

	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	mockClient.keys["GKunrelated"] = &garage.Key{
		AccessKeyID: "GKunrelated", SecretAccessKey: "must-not-leak", Name: testAccountName,
	}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})

	result, err := p.GrantAccess(context.Background(), testAccountName, "",
		[]BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadWrite}}, defaultAccessParams(), "")
	require.NoError(t, err)
	assert.NotEqual(t, "GKunrelated", result.AccountID)
	assert.NotEqual(t, "must-not-leak", result.SecretAccessKey)
	require.Len(t, mockClient.importKeyCalls, 1)
	assert.Equal(t, testAccountName, mockClient.importKeyCalls[0].Name)
	assert.Empty(t, mockClient.createKeyCalls)
	assert.Contains(t, mockClient.keys, "GKunrelated")
	assert.Empty(t, mockClient.keys["GKunrelated"].Buckets)
	assert.NotContains(t, mockClient.deleteKeyCalls, "GKunrelated")
}

func TestGrantAccessRefusesReplacementForImmutableMissingStatusKey(t *testing.T) {
	cluster := createReadyCluster()
	shadowBucket := createShadowBucket(testBucketID, testBucketName)
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(cluster, shadowBucket).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	p := NewProvisionerWithFactory(fakeClient, testGarageSystem, func(_ context.Context, _ client.Client, _ *garagev1beta2.GarageCluster) (GarageClient, error) {
		return mockClient, nil
	})
	_, err := p.shadowManager.CreateShadowKeyWithID(context.Background(), testAccountName, "GKdeleted",
		testMyCluster, testGarageSystem, []BucketPermission{{BucketID: testBucketID, Read: true}}, "")
	require.NoError(t, err)
	slots := []BucketAccessSlot{{BucketID: testBucketID, AccessMode: AccessModeReadOnly}}

	_, err = p.GrantAccess(context.Background(), testAccountName, "GKdeleted", slots, defaultAccessParams(), "")
	require.ErrorContains(t, err, "stale shadow deletion started")
	assert.Empty(t, mockClient.createKeyCalls, "must not create while the stale ownership record still exists")

	_, err = p.GrantAccess(context.Background(), testAccountName, "GKdeleted", slots, defaultAccessParams(), "")
	require.ErrorContains(t, err, "refusing immutable account replacement")
	assert.Empty(t, mockClient.importKeyCalls)
}
