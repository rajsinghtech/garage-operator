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
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

var log = ctrl.Log.WithName("cosi-provisioner")

// GarageClient defines the interface for Garage API operations used by COSI
type GarageClient interface {
	CreateBucket(ctx context.Context, req garage.CreateBucketRequest) (*garage.Bucket, error)
	GetBucket(ctx context.Context, req garage.GetBucketRequest) (*garage.Bucket, error)
	UpdateBucket(ctx context.Context, req garage.UpdateBucketRequest) (*garage.Bucket, error)
	DeleteBucket(ctx context.Context, bucketID string) error
	CreateKey(ctx context.Context, name string) (*garage.Key, error)
	GetKey(ctx context.Context, req garage.GetKeyRequest) (*garage.Key, error)
	DeleteKey(ctx context.Context, accessKeyID string) error
	AllowBucketKey(ctx context.Context, req garage.AllowBucketKeyRequest) (*garage.Bucket, error)
	DenyBucketKey(ctx context.Context, req garage.DenyBucketKeyRequest) (*garage.Bucket, error)
}

// GarageClientFactory creates a GarageClient for a given cluster
type GarageClientFactory func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error)

func makeDefaultGarageClientFactory(clusterDomain string) GarageClientFactory {
	return func(ctx context.Context, c client.Client, cluster *garagev1alpha1.GarageCluster) (GarageClient, error) {
		return controller.GetGarageClient(ctx, c, cluster, clusterDomain)
	}
}

// ProvisionerServer implements the COSI Provisioner service
type ProvisionerServer struct {
	cosiproto.UnimplementedProvisionerServer
	client              client.Client
	namespace           string
	clusterDomain       string
	shadowManager       *ShadowManager
	garageClientFactory GarageClientFactory
}

// NewProvisionerServer creates a new ProvisionerServer
func NewProvisionerServer(c client.Client, namespace, clusterDomain string) *ProvisionerServer {
	return &ProvisionerServer{
		client:              c,
		namespace:           namespace,
		clusterDomain:       clusterDomain,
		shadowManager:       NewShadowManager(c, namespace),
		garageClientFactory: makeDefaultGarageClientFactory(clusterDomain),
	}
}

// NewProvisionerServerWithFactory creates a ProvisionerServer with a custom GarageClient factory (for testing)
func NewProvisionerServerWithFactory(c client.Client, namespace string, factory GarageClientFactory) *ProvisionerServer {
	return &ProvisionerServer{
		client:              c,
		namespace:           namespace,
		clusterDomain:       "cluster.local",
		shadowManager:       NewShadowManager(c, namespace),
		garageClientFactory: factory,
	}
}

// DriverCreateBucket creates a new bucket
func (s *ProvisionerServer) DriverCreateBucket(ctx context.Context, req *cosiproto.DriverCreateBucketRequest) (*cosiproto.DriverCreateBucketResponse, error) {
	log.Info("DriverCreateBucket called", "name", req.Name)

	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bucket name is required")
	}

	params, err := ParseBucketClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, ErrClusterNotFound(params.ClusterRef, params.ClusterNamespace)
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	if cluster.Status.Phase != garagev1alpha1.PhaseRunning {
		return nil, ErrClusterNotReady(params.ClusterRef, params.ClusterNamespace)
	}

	garageClient, err := s.garageClientFactory(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	bucketAlias := sanitizeBucketName(req.Name)
	garageBucket, err := garageClient.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: bucketAlias})
	if err != nil {
		if garage.IsConflict(err) {
			existing, getErr := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: bucketAlias})
			if getErr == nil {
				if !bucketQuotasMatch(existing.Quotas, params) {
					return nil, status.Errorf(codes.AlreadyExists, "bucket %q already exists with different configuration", bucketAlias)
				}
				log.Info("Bucket already exists with matching config, returning existing", "bucketId", existing.ID)
				return s.buildCreateBucketResponse(ctx, existing.ID)
			}
		}
		return nil, MapGarageErrorToCOSI(err)
	}

	if params.MaxSize != nil || params.MaxObjects != nil {
		updateReq := garage.UpdateBucketRequest{ID: garageBucket.ID}
		updateReq.Body.Quotas = &garage.BucketQuotas{}
		if params.MaxSize != nil {
			size := uint64(params.MaxSize.Value())
			updateReq.Body.Quotas.MaxSize = &size
		}
		if params.MaxObjects != nil {
			maxObj := uint64(*params.MaxObjects)
			updateReq.Body.Quotas.MaxObjects = &maxObj
		}
		if _, err := garageClient.UpdateBucket(ctx, updateReq); err != nil {
			log.Error(err, "Failed to apply quotas to bucket, deleting bucket", "bucketId", garageBucket.ID)
			_ = garageClient.DeleteBucket(ctx, garageBucket.ID)
			return nil, status.Errorf(codes.Internal, "failed to apply quotas to bucket: %v", err)
		}
	}

	_, err = s.shadowManager.CreateShadowBucketWithID(ctx, req.Name, garageBucket.ID, params.ClusterRef, params.ClusterNamespace, params)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		log.Error(err, "Failed to create shadow GarageBucket, rolling back Garage bucket", "name", req.Name, "bucketId", garageBucket.ID)
		if deleteErr := garageClient.DeleteBucket(ctx, garageBucket.ID); deleteErr != nil {
			log.Error(deleteErr, "Failed to rollback Garage bucket after shadow resource failure", "bucketId", garageBucket.ID)
		}
		return nil, status.Errorf(codes.Internal, "failed to create shadow resource: %v", err)
	}

	log.Info("Bucket created successfully", "bucketId", garageBucket.ID, "name", bucketAlias)
	return s.buildCreateBucketResponse(ctx, garageBucket.ID)
}

// DriverDeleteBucket deletes a bucket
func (s *ProvisionerServer) DriverDeleteBucket(ctx context.Context, req *cosiproto.DriverDeleteBucketRequest) (*cosiproto.DriverDeleteBucketResponse, error) {
	log.Info("DriverDeleteBucket called", "bucketId", req.BucketId)

	if req.BucketId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bucket_id is required")
	}

	params, err := ParseBucketClassParameters(req.DeleteContext, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.Info("Cluster not found, cleaning up shadow resources only", "cluster", params.ClusterRef)
			if cleanupErr := s.shadowManager.DeleteShadowBucketByID(ctx, req.BucketId); cleanupErr != nil {
				log.Error(cleanupErr, "Failed to delete shadow bucket by ID", "bucketId", req.BucketId)
			}
			return &cosiproto.DriverDeleteBucketResponse{}, nil
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	garageClient, err := s.garageClientFactory(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	if err := garageClient.DeleteBucket(ctx, req.BucketId); err != nil {
		if garage.IsNotFound(err) {
			log.Info("Bucket already deleted from Garage", "bucketId", req.BucketId)
		} else if garage.IsBucketNotEmpty(err) {
			return nil, status.Errorf(codes.FailedPrecondition, "bucket is not empty, delete all objects first")
		} else {
			return nil, MapGarageErrorToCOSI(err)
		}
	}

	if err := s.shadowManager.DeleteShadowBucketByID(ctx, req.BucketId); err != nil {
		log.Error(err, "Failed to delete shadow GarageBucket", "bucketId", req.BucketId)
	}

	log.Info("Bucket deleted successfully", "bucketId", req.BucketId)
	return &cosiproto.DriverDeleteBucketResponse{}, nil
}

// DriverGrantBucketAccess grants access to a single bucket (COSI v0.2.2: one bucket per request)
func (s *ProvisionerServer) DriverGrantBucketAccess(ctx context.Context, req *cosiproto.DriverGrantBucketAccessRequest) (*cosiproto.DriverGrantBucketAccessResponse, error) {
	log.Info("DriverGrantBucketAccess called", "name", req.Name, "bucketId", req.BucketId)

	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "account name is required")
	}
	if req.BucketId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bucket_id is required")
	}

	// Only KEY authentication is supported; IAM is not available in Garage
	if req.AuthenticationType == cosiproto.AuthenticationType_IAM {
		return nil, ErrUnsupportedAuthType
	}

	params, err := ParseBucketAccessClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, ErrClusterNotFound(params.ClusterRef, params.ClusterNamespace)
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	if cluster.Status.Phase != garagev1alpha1.PhaseRunning {
		return nil, ErrClusterNotReady(params.ClusterRef, params.ClusterNamespace)
	}

	garageClient, err := s.garageClientFactory(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	keyName := sanitizeKeyName(req.Name)
	perms := garage.BucketKeyPerms{Read: true, Write: true}

	// Idempotency: reuse existing key if present
	existingKey, err := garageClient.GetKey(ctx, garage.GetKeyRequest{Search: keyName, ShowSecretKey: true})
	if err == nil && existingKey != nil {
		log.Info("Key already exists, ensuring bucket permission", "keyId", existingKey.AccessKeyID)
		if _, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    req.BucketId,
			AccessKeyID: existingKey.AccessKeyID,
			Permissions: perms,
		}); err != nil {
			return nil, MapGarageErrorToCOSI(err)
		}
		if existingKey.SecretAccessKey == "" {
			return nil, status.Errorf(codes.Internal, "existing key secret is not available")
		}
		return s.buildGrantAccessResponse(ctx, existingKey, req.BucketId, cluster)
	}

	key, err := garageClient.CreateKey(ctx, keyName)
	if err != nil {
		return nil, MapGarageErrorToCOSI(err)
	}

	if _, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
		BucketID:    req.BucketId,
		AccessKeyID: key.AccessKeyID,
		Permissions: perms,
	}); err != nil {
		log.Error(err, "Failed to grant access to bucket", "bucketId", req.BucketId, "keyId", key.AccessKeyID)
		_ = garageClient.DeleteKey(ctx, key.AccessKeyID)
		return nil, MapGarageErrorToCOSI(err)
	}

	bucketRef := req.BucketId
	if shadowName, err := s.shadowManager.GetShadowBucketNameByID(ctx, req.BucketId); err == nil {
		bucketRef = shadowName
	}

	_, err = s.shadowManager.CreateShadowKeyWithID(ctx, req.Name, key.AccessKeyID, params.ClusterRef, params.ClusterNamespace, []BucketPermission{
		{BucketID: bucketRef, Read: true, Write: true},
	})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		log.Error(err, "Failed to create shadow GarageKey", "name", req.Name)
	}

	log.Info("Bucket access granted successfully", "accountId", key.AccessKeyID, "bucketId", req.BucketId)
	return s.buildGrantAccessResponse(ctx, key, req.BucketId, cluster)
}

// buildGrantAccessResponse builds the v0.2.2 grant access response.
// Credentials are returned as a map[string]*CredentialDetails; the sidecar
// mounts them as a Secret for the workload.
func (s *ProvisionerServer) buildGrantAccessResponse(ctx context.Context, key *garage.Key, bucketID string, cluster *garagev1alpha1.GarageCluster) (*cosiproto.DriverGrantBucketAccessResponse, error) {
	if key.SecretAccessKey == "" {
		return nil, status.Errorf(codes.Internal, "key secret is not available (was showSecretKey=true used?)")
	}

	globalAlias, err := s.shadowManager.GetShadowBucketGlobalAliasByID(ctx, bucketID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "global alias for bucket %s not found", bucketID)
	}

	return &cosiproto.DriverGrantBucketAccessResponse{
		AccountId: key.AccessKeyID,
		Credentials: map[string]*cosiproto.CredentialDetails{
			"s3": {
				Secrets: map[string]string{
					"endpoint":        s.getS3Endpoint(cluster),
					"region":          s.getS3Region(cluster),
					"bucketName":      globalAlias,
					"accessKeyId":     key.AccessKeyID,
					"accessSecretKey": key.SecretAccessKey,
				},
			},
		},
	}, nil
}

// DriverRevokeBucketAccess revokes access for a single bucket (COSI v0.2.2: one bucket per request)
func (s *ProvisionerServer) DriverRevokeBucketAccess(ctx context.Context, req *cosiproto.DriverRevokeBucketAccessRequest) (*cosiproto.DriverRevokeBucketAccessResponse, error) {
	log.Info("DriverRevokeBucketAccess called", "accountId", req.AccountId, "bucketId", req.BucketId)

	if req.AccountId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "account_id is required")
	}

	params, err := ParseBucketAccessClassParameters(req.RevokeAccessContext, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.Info("Cluster not found, cleaning up shadow resources only", "cluster", params.ClusterRef)
			if cleanupErr := s.shadowManager.DeleteShadowKeyByID(ctx, req.AccountId); cleanupErr != nil {
				log.Error(cleanupErr, "Failed to delete shadow key by ID", "accountId", req.AccountId)
			}
			return &cosiproto.DriverRevokeBucketAccessResponse{}, nil
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	garageClient, err := s.garageClientFactory(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	if req.BucketId != "" {
		if _, err := garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
			BucketID:    req.BucketId,
			AccessKeyID: req.AccountId,
		}); err != nil && !garage.IsNotFound(err) {
			return nil, MapGarageErrorToCOSI(err)
		}
	}

	if err := garageClient.DeleteKey(ctx, req.AccountId); err != nil && !garage.IsNotFound(err) {
		return nil, MapGarageErrorToCOSI(err)
	}

	if err := s.shadowManager.DeleteShadowKeyByID(ctx, req.AccountId); err != nil {
		log.Error(err, "Failed to delete shadow GarageKey", "accountId", req.AccountId)
	}

	log.Info("Bucket access revoked successfully", "accountId", req.AccountId, "bucketId", req.BucketId)
	return &cosiproto.DriverRevokeBucketAccessResponse{}, nil
}

func (s *ProvisionerServer) buildCreateBucketResponse(ctx context.Context, bucketID string) (*cosiproto.DriverCreateBucketResponse, error) {
	globalAlias, err := s.shadowManager.GetShadowBucketGlobalAliasByID(ctx, bucketID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "global alias for bucket %s not found", bucketID)
	}

	return &cosiproto.DriverCreateBucketResponse{
		BucketId: bucketID,
		BucketInfo: &cosiproto.Protocol{
			Type: &cosiproto.Protocol_S3{
				S3: &cosiproto.S3{
					Region:           globalAlias,
					SignatureVersion: cosiproto.S3SignatureVersion_S3V4,
				},
			},
		},
	}, nil
}

func (s *ProvisionerServer) getS3Endpoint(cluster *garagev1alpha1.GarageCluster) string {
	if cluster.Status.Endpoints != nil && cluster.Status.Endpoints.S3 != "" {
		return cluster.Status.Endpoints.S3
	}
	port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort > 0 {
		port = cluster.Spec.S3API.BindPort
	}
	return fmt.Sprintf("%s.%s.svc.%s:%d", cluster.Name, cluster.Namespace, s.clusterDomain, port)
}

func (s *ProvisionerServer) getS3Region(cluster *garagev1alpha1.GarageCluster) string {
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		return cluster.Spec.S3API.Region
	}
	return "garage"
}

func sanitizeBucketName(name string) string {
	if len(name) <= 63 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:6])
	return name[:50] + "-" + suffix
}

func sanitizeKeyName(name string) string {
	if len(name) <= 128 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:6])
	return name[:115] + "-" + suffix
}

func bucketQuotasMatch(existing *garage.BucketQuotas, params *BucketClassParameters) bool {
	wantMaxSize := uint64(0)
	wantMaxObjects := uint64(0)
	hasWantSize := false
	hasWantObjects := false

	if params.MaxSize != nil {
		wantMaxSize = uint64(params.MaxSize.Value())
		hasWantSize = true
	}
	if params.MaxObjects != nil {
		wantMaxObjects = uint64(*params.MaxObjects)
		hasWantObjects = true
	}

	if existing == nil {
		return !hasWantSize && !hasWantObjects
	}

	if hasWantSize {
		if existing.MaxSize == nil || *existing.MaxSize != wantMaxSize {
			return false
		}
	} else if existing.MaxSize != nil && *existing.MaxSize != 0 {
		return false
	}

	if hasWantObjects {
		if existing.MaxObjects == nil || *existing.MaxObjects != wantMaxObjects {
			return false
		}
	} else if existing.MaxObjects != nil && *existing.MaxObjects != 0 {
		return false
	}

	return true
}
