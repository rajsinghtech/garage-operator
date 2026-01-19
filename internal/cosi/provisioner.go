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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

var log = ctrl.Log.WithName("cosi-provisioner")

// ProvisionerServer implements the COSI Provisioner service
type ProvisionerServer struct {
	cosiproto.UnimplementedProvisionerServer
	client        client.Client
	namespace     string // Namespace for shadow resources
	shadowManager *ShadowManager
}

// NewProvisionerServer creates a new ProvisionerServer
func NewProvisionerServer(c client.Client, namespace string) *ProvisionerServer {
	return &ProvisionerServer{
		client:        c,
		namespace:     namespace,
		shadowManager: NewShadowManager(c, namespace),
	}
}

// DriverCreateBucket creates a new bucket
func (s *ProvisionerServer) DriverCreateBucket(ctx context.Context, req *cosiproto.DriverCreateBucketRequest) (*cosiproto.DriverCreateBucketResponse, error) {
	log.Info("DriverCreateBucket called", "name", req.Name)

	// Parse parameters
	params, err := ParseBucketClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	// Get the GarageCluster
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

	// Check cluster is ready
	if cluster.Status.Phase != "Running" {
		return nil, ErrClusterNotReady(params.ClusterRef, params.ClusterNamespace)
	}

	// Get Garage client
	garageClient, err := controller.GetGarageClient(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	// Use the COSI-provided name directly for bucket creation
	// COSI names are DNS-safe and unique
	bucketAlias := sanitizeBucketName(req.Name)
	createReq := garage.CreateBucketRequest{
		GlobalAlias: bucketAlias,
	}

	garageBucket, err := garageClient.CreateBucket(ctx, createReq)
	if err != nil {
		if garage.IsConflict(err) {
			// Bucket exists - check if it's ours (idempotent)
			existing, getErr := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: bucketAlias})
			if getErr == nil {
				log.Info("Bucket already exists, returning existing", "bucketId", existing.ID)
				return s.buildCreateBucketResponse(existing.ID, cluster)
			}
		}
		return nil, MapGarageErrorToCOSI(err)
	}

	// Apply quotas if specified - return error on failure
	if params.MaxSize != nil || params.MaxObjects != nil {
		updateReq := garage.UpdateBucketRequest{
			ID: garageBucket.ID,
		}
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
			// Clean up the bucket since we couldn't apply required quotas
			_ = garageClient.DeleteBucket(ctx, garageBucket.ID)
			return nil, status.Errorf(codes.Internal, "failed to apply quotas to bucket: %v", err)
		}
	}

	// Create shadow GarageBucket resource with bucketId annotation for later lookup
	_, err = s.shadowManager.CreateShadowBucketWithID(ctx, req.Name, garageBucket.ID, params.ClusterRef, params.ClusterNamespace, params)
	if err != nil && !isAlreadyExists(err) {
		log.Error(err, "Failed to create shadow GarageBucket, rolling back Garage bucket", "name", req.Name, "bucketId", garageBucket.ID)
		// Rollback: delete the Garage bucket since we can't track it without the shadow resource
		if deleteErr := garageClient.DeleteBucket(ctx, garageBucket.ID); deleteErr != nil {
			log.Error(deleteErr, "Failed to rollback Garage bucket after shadow resource failure", "bucketId", garageBucket.ID)
		}
		return nil, status.Errorf(codes.Internal, "failed to create shadow resource: %v", err)
	}

	log.Info("Bucket created successfully", "bucketId", garageBucket.ID, "name", bucketAlias)
	return s.buildCreateBucketResponse(garageBucket.ID, cluster)
}

// DriverDeleteBucket deletes a bucket
func (s *ProvisionerServer) DriverDeleteBucket(ctx context.Context, req *cosiproto.DriverDeleteBucketRequest) (*cosiproto.DriverDeleteBucketResponse, error) {
	log.Info("DriverDeleteBucket called", "bucketId", req.BucketId)

	// Parse parameters
	params, err := ParseBucketClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	// Get the GarageCluster
	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Cluster doesn't exist, still try to cleanup shadow resources
			log.Info("Cluster not found, cleaning up shadow resources only", "cluster", params.ClusterRef)
			if cleanupErr := s.shadowManager.DeleteShadowBucketByID(ctx, req.BucketId); cleanupErr != nil {
				log.Error(cleanupErr, "Failed to delete shadow bucket by ID", "bucketId", req.BucketId)
			}
			return &cosiproto.DriverDeleteBucketResponse{}, nil
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	// Get Garage client
	garageClient, err := controller.GetGarageClient(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	// Delete bucket from Garage
	if err := garageClient.DeleteBucket(ctx, req.BucketId); err != nil {
		if garage.IsNotFound(err) {
			log.Info("Bucket already deleted from Garage", "bucketId", req.BucketId)
		} else if garage.IsBucketNotEmpty(err) {
			return nil, status.Errorf(codes.FailedPrecondition, "bucket is not empty, delete all objects first")
		} else {
			return nil, MapGarageErrorToCOSI(err)
		}
	}

	// Delete shadow GarageBucket resource by bucketId
	if err := s.shadowManager.DeleteShadowBucketByID(ctx, req.BucketId); err != nil {
		log.Error(err, "Failed to delete shadow GarageBucket", "bucketId", req.BucketId)
	}

	log.Info("Bucket deleted successfully", "bucketId", req.BucketId)
	return &cosiproto.DriverDeleteBucketResponse{}, nil
}

// DriverGrantBucketAccess grants access to a bucket
func (s *ProvisionerServer) DriverGrantBucketAccess(ctx context.Context, req *cosiproto.DriverGrantBucketAccessRequest) (*cosiproto.DriverGrantBucketAccessResponse, error) {
	log.Info("DriverGrantBucketAccess called", "accountName", req.AccountName, "bucketCount", len(req.Buckets))

	// Reject SERVICE_ACCOUNT authentication (Garage only supports KEY authentication)
	if req.AuthenticationType != nil && req.AuthenticationType.GetType() == cosiproto.AuthenticationType_SERVICE_ACCOUNT {
		return nil, ErrUnsupportedAuthType
	}

	// Validate we have at least one bucket
	if len(req.Buckets) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "at least one bucket is required")
	}

	// Parse parameters
	params, err := ParseBucketAccessClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	// Get the GarageCluster
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

	// Check cluster is ready
	if cluster.Status.Phase != "Running" {
		return nil, ErrClusterNotReady(params.ClusterRef, params.ClusterNamespace)
	}

	// Get Garage client
	garageClient, err := controller.GetGarageClient(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	// Use COSI-provided account name for key name
	keyName := sanitizeKeyName(req.AccountName)

	// Check for idempotency - see if key already exists
	existingKey, err := garageClient.GetKey(ctx, garage.GetKeyRequest{Search: keyName, ShowSecretKey: true})
	if err == nil && existingKey != nil {
		log.Info("Key already exists, verifying bucket permissions", "keyId", existingKey.AccessKeyID)

		// Verify key has access to all requested buckets with correct permissions
		// If not, grant the missing permissions
		missingPerms := s.findMissingBucketPermissions(existingKey, req.Buckets)
		if len(missingPerms) > 0 {
			log.Info("Granting missing permissions for existing key", "keyId", existingKey.AccessKeyID, "missingBuckets", len(missingPerms))
			for _, perm := range missingPerms {
				allowReq := garage.AllowBucketKeyRequest{
					BucketID:    perm.BucketID,
					AccessKeyID: existingKey.AccessKeyID,
					Permissions: garage.BucketKeyPerms{
						Read:  perm.Read,
						Write: perm.Write,
						Owner: perm.Owner,
					},
				}
				if _, err := garageClient.AllowBucketKey(ctx, allowReq); err != nil {
					log.Error(err, "Failed to grant missing access to bucket for existing key", "bucketId", perm.BucketID, "keyId", existingKey.AccessKeyID)
					return nil, MapGarageErrorToCOSI(err)
				}
			}
		}

		// Verify secret key is available
		if existingKey.SecretAccessKey == "" {
			return nil, status.Errorf(codes.Internal, "existing key secret is not available")
		}

		return s.buildGrantAccessResponse(ctx, existingKey, req.Buckets, cluster)
	}

	// Create key in Garage
	key, err := garageClient.CreateKey(ctx, keyName)
	if err != nil {
		return nil, MapGarageErrorToCOSI(err)
	}

	// Grant access to each bucket, track which ones succeed for cleanup
	grantedBuckets := make([]string, 0, len(req.Buckets))
	for _, bucket := range req.Buckets {
		// Parse permissions from access mode
		read, write, owner := parseAccessMode(bucket.AccessMode)

		// Grant access to the bucket
		allowReq := garage.AllowBucketKeyRequest{
			BucketID:    bucket.BucketId,
			AccessKeyID: key.AccessKeyID,
			Permissions: garage.BucketKeyPerms{
				Read:  read,
				Write: write,
				Owner: owner,
			},
		}
		if _, err := garageClient.AllowBucketKey(ctx, allowReq); err != nil {
			log.Error(err, "Failed to grant access to bucket", "bucketId", bucket.BucketId, "keyId", key.AccessKeyID)
			// Clean up: revoke already granted permissions and delete key
			for _, grantedBucketId := range grantedBuckets {
				_, _ = garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
					BucketID:    grantedBucketId,
					AccessKeyID: key.AccessKeyID,
				})
			}
			_ = garageClient.DeleteKey(ctx, key.AccessKeyID)
			return nil, MapGarageErrorToCOSI(err)
		}
		grantedBuckets = append(grantedBuckets, bucket.BucketId)
	}

	// Validate that all requested buckets were granted access by re-fetching the key
	updatedKey, err := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: key.AccessKeyID, ShowSecretKey: true})
	if err != nil {
		log.Error(err, "Failed to verify granted access", "keyId", key.AccessKeyID)
		// Clean up: revoke granted permissions and delete key
		for _, grantedBucketId := range grantedBuckets {
			_, _ = garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
				BucketID:    grantedBucketId,
				AccessKeyID: key.AccessKeyID,
			})
		}
		_ = garageClient.DeleteKey(ctx, key.AccessKeyID)
		return nil, status.Errorf(codes.Internal, "failed to verify granted access: %v", err)
	}

	// Verify all requested buckets have the correct permissions
	if err := s.validateGrantedAccess(updatedKey, req.Buckets); err != nil {
		log.Error(err, "Access validation failed", "keyId", key.AccessKeyID)
		// Clean up: revoke granted permissions and delete key
		for _, grantedBucketId := range grantedBuckets {
			_, _ = garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
				BucketID:    grantedBucketId,
				AccessKeyID: key.AccessKeyID,
			})
		}
		_ = garageClient.DeleteKey(ctx, key.AccessKeyID)
		return nil, status.Errorf(codes.Internal, "access validation failed: %v", err)
	}

	// Build bucket info response
	bucketInfos := make([]*cosiproto.DriverGrantBucketAccessResponse_BucketInfo, 0, len(req.Buckets))
	for _, bucket := range req.Buckets {
		// Add bucket info to response
		bucketInfos = append(bucketInfos, &cosiproto.DriverGrantBucketAccessResponse_BucketInfo{
			BucketId: bucket.BucketId,
			BucketInfo: &cosiproto.ObjectProtocolAndBucketInfo{
				S3: &cosiproto.S3BucketInfo{
					BucketId: bucket.BucketId,
					Endpoint: s.getS3Endpoint(cluster),
					Region:   s.getS3Region(cluster),
					AddressingStyle: &cosiproto.S3AddressingStyle{
						Style: cosiproto.S3AddressingStyle_PATH,
					},
				},
			},
		})
	}

	// Create shadow GarageKey resource with all bucket permissions
	bucketPerms := make([]BucketPermission, 0, len(req.Buckets))
	for _, bucket := range req.Buckets {
		read, write, owner := parseAccessMode(bucket.AccessMode)
		bucketPerms = append(bucketPerms, BucketPermission{
			BucketID: bucket.BucketId,
			Read:     read,
			Write:    write,
			Owner:    owner,
		})
	}
	_, err = s.shadowManager.CreateShadowKeyWithID(ctx, req.AccountName, key.AccessKeyID, params.ClusterRef, params.ClusterNamespace, bucketPerms)
	if err != nil && !isAlreadyExists(err) {
		log.Error(err, "Failed to create shadow GarageKey", "name", req.AccountName)
	}

	log.Info("Bucket access granted successfully", "accountId", key.AccessKeyID, "bucketCount", len(req.Buckets))
	return &cosiproto.DriverGrantBucketAccessResponse{
		AccountId: key.AccessKeyID,
		Buckets:   bucketInfos,
		Credentials: &cosiproto.CredentialInfo{
			S3: &cosiproto.S3CredentialInfo{
				AccessKeyId:     key.AccessKeyID,
				AccessSecretKey: key.SecretAccessKey,
			},
		},
	}, nil
}

// buildGrantAccessResponse builds response for existing key (idempotency case)
func (s *ProvisionerServer) buildGrantAccessResponse(_ context.Context, key *garage.Key, buckets []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket, cluster *garagev1alpha1.GarageCluster) (*cosiproto.DriverGrantBucketAccessResponse, error) {
	// Validate that secret key is available
	if key.SecretAccessKey == "" {
		return nil, status.Errorf(codes.Internal, "key secret is not available (was showSecretKey=true used?)")
	}

	bucketInfos := make([]*cosiproto.DriverGrantBucketAccessResponse_BucketInfo, 0, len(buckets))
	for _, bucket := range buckets {
		bucketInfos = append(bucketInfos, &cosiproto.DriverGrantBucketAccessResponse_BucketInfo{
			BucketId: bucket.BucketId,
			BucketInfo: &cosiproto.ObjectProtocolAndBucketInfo{
				S3: &cosiproto.S3BucketInfo{
					BucketId: bucket.BucketId,
					Endpoint: s.getS3Endpoint(cluster),
					Region:   s.getS3Region(cluster),
					AddressingStyle: &cosiproto.S3AddressingStyle{
						Style: cosiproto.S3AddressingStyle_PATH,
					},
				},
			},
		})
	}

	return &cosiproto.DriverGrantBucketAccessResponse{
		AccountId: key.AccessKeyID,
		Buckets:   bucketInfos,
		Credentials: &cosiproto.CredentialInfo{
			S3: &cosiproto.S3CredentialInfo{
				AccessKeyId:     key.AccessKeyID,
				AccessSecretKey: key.SecretAccessKey,
			},
		},
	}, nil
}

// DriverRevokeBucketAccess revokes access to a bucket
func (s *ProvisionerServer) DriverRevokeBucketAccess(ctx context.Context, req *cosiproto.DriverRevokeBucketAccessRequest) (*cosiproto.DriverRevokeBucketAccessResponse, error) {
	log.Info("DriverRevokeBucketAccess called", "accountId", req.AccountId, "bucketCount", len(req.Buckets))

	// Parse parameters
	params, err := ParseBucketAccessClassParameters(req.Parameters, s.namespace)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parameters: %v", err)
	}

	// Get the GarageCluster
	cluster := &garagev1alpha1.GarageCluster{}
	if err := s.client.Get(ctx, types.NamespacedName{
		Name:      params.ClusterRef,
		Namespace: params.ClusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Cluster doesn't exist, still try to cleanup shadow resources
			log.Info("Cluster not found, cleaning up shadow resources only", "cluster", params.ClusterRef)
			if cleanupErr := s.shadowManager.DeleteShadowKeyByID(ctx, req.AccountId); cleanupErr != nil {
				log.Error(cleanupErr, "Failed to delete shadow key by ID", "accountId", req.AccountId)
			}
			return &cosiproto.DriverRevokeBucketAccessResponse{}, nil
		}
		return nil, status.Errorf(codes.Unavailable, "failed to get cluster: %v", err)
	}

	// Get Garage client
	garageClient, err := controller.GetGarageClient(ctx, s.client, cluster)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create garage client: %v", err)
	}

	// Revoke access from each bucket
	for _, bucket := range req.Buckets {
		denyReq := garage.DenyBucketKeyRequest{
			BucketID:    bucket.BucketId,
			AccessKeyID: req.AccountId,
		}
		if _, err := garageClient.DenyBucketKey(ctx, denyReq); err != nil {
			if !garage.IsNotFound(err) {
				return nil, MapGarageErrorToCOSI(err)
			}
		}
	}

	// Delete the key from Garage
	if err := garageClient.DeleteKey(ctx, req.AccountId); err != nil {
		if !garage.IsNotFound(err) {
			return nil, MapGarageErrorToCOSI(err)
		}
	}

	// Delete shadow GarageKey resource by accountId
	if err := s.shadowManager.DeleteShadowKeyByID(ctx, req.AccountId); err != nil {
		log.Error(err, "Failed to delete shadow GarageKey", "accountId", req.AccountId)
	}

	log.Info("Bucket access revoked successfully", "accountId", req.AccountId, "bucketCount", len(req.Buckets))
	return &cosiproto.DriverRevokeBucketAccessResponse{}, nil
}

// parseAccessMode converts COSI AccessMode to read/write/owner permissions
// nolint:unparam // owner is always false since COSI doesn't have an owner mode, but we need it for Garage API
func parseAccessMode(accessMode *cosiproto.AccessMode) (read, write, owner bool) {
	if accessMode == nil {
		return true, true, false // Default to read/write
	}
	switch accessMode.GetMode() {
	case cosiproto.AccessMode_READ_WRITE:
		return true, true, false
	case cosiproto.AccessMode_READ_ONLY:
		return true, false, false
	case cosiproto.AccessMode_WRITE_ONLY:
		return false, true, false
	default:
		return true, true, false
	}
}

// bucketPermReq represents a required bucket permission
type bucketPermReq struct {
	BucketID string
	Read     bool
	Write    bool
	Owner    bool
}

// findMissingBucketPermissions compares requested bucket access against existing key permissions
// and returns any missing permissions that need to be granted
func (s *ProvisionerServer) findMissingBucketPermissions(key *garage.Key, requestedBuckets []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket) []bucketPermReq {
	// Build map of existing bucket permissions
	existingPerms := make(map[string]garage.BucketKeyPerms)
	for _, bucket := range key.Buckets {
		existingPerms[bucket.ID] = bucket.Permissions
	}

	var missing []bucketPermReq
	for _, reqBucket := range requestedBuckets {
		reqRead, reqWrite, reqOwner := parseAccessMode(reqBucket.AccessMode)

		existing, found := existingPerms[reqBucket.BucketId]
		if !found {
			// Bucket not in key's access list at all
			missing = append(missing, bucketPermReq{
				BucketID: reqBucket.BucketId,
				Read:     reqRead,
				Write:    reqWrite,
				Owner:    reqOwner,
			})
			continue
		}

		// Check if existing permissions are sufficient
		needsUpdate := false
		if reqRead && !existing.Read {
			needsUpdate = true
		}
		if reqWrite && !existing.Write {
			needsUpdate = true
		}
		if reqOwner && !existing.Owner {
			needsUpdate = true
		}

		if needsUpdate {
			// Merge permissions - keep existing, add new
			missing = append(missing, bucketPermReq{
				BucketID: reqBucket.BucketId,
				Read:     reqRead || existing.Read,
				Write:    reqWrite || existing.Write,
				Owner:    reqOwner || existing.Owner,
			})
		}
	}

	return missing
}

// validateGrantedAccess verifies that the key has all the requested bucket permissions
func (s *ProvisionerServer) validateGrantedAccess(key *garage.Key, requestedBuckets []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket) error {
	// Build map of granted bucket permissions
	grantedPerms := make(map[string]garage.BucketKeyPerms)
	for _, bucket := range key.Buckets {
		grantedPerms[bucket.ID] = bucket.Permissions
	}

	for _, reqBucket := range requestedBuckets {
		reqRead, reqWrite, reqOwner := parseAccessMode(reqBucket.AccessMode)

		granted, found := grantedPerms[reqBucket.BucketId]
		if !found {
			return fmt.Errorf("bucket %s not found in key's access list", reqBucket.BucketId)
		}

		// Verify permissions match or exceed requirements
		if reqRead && !granted.Read {
			return fmt.Errorf("bucket %s missing read permission", reqBucket.BucketId)
		}
		if reqWrite && !granted.Write {
			return fmt.Errorf("bucket %s missing write permission", reqBucket.BucketId)
		}
		if reqOwner && !granted.Owner {
			return fmt.Errorf("bucket %s missing owner permission", reqBucket.BucketId)
		}
	}

	return nil
}

func (s *ProvisionerServer) buildCreateBucketResponse(bucketID string, cluster *garagev1alpha1.GarageCluster) (*cosiproto.DriverCreateBucketResponse, error) {
	return &cosiproto.DriverCreateBucketResponse{
		BucketId: bucketID,
		Protocols: &cosiproto.ObjectProtocolAndBucketInfo{
			S3: &cosiproto.S3BucketInfo{
				BucketId: bucketID,
				Endpoint: s.getS3Endpoint(cluster),
				Region:   s.getS3Region(cluster),
				AddressingStyle: &cosiproto.S3AddressingStyle{
					Style: cosiproto.S3AddressingStyle_PATH,
				},
			},
		},
	}, nil
}

func (s *ProvisionerServer) getS3Endpoint(cluster *garagev1alpha1.GarageCluster) string {
	if cluster.Status.Endpoints.S3 != "" {
		return cluster.Status.Endpoints.S3
	}
	// Fallback to constructing from service
	port := 3900
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort > 0 {
		port = int(cluster.Spec.S3API.BindPort)
	}
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, port)
}

func (s *ProvisionerServer) getS3Region(cluster *garagev1alpha1.GarageCluster) string {
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		return cluster.Spec.S3API.Region
	}
	return "garage"
}

// sanitizeBucketName ensures the bucket name is valid for Garage
func sanitizeBucketName(name string) string {
	// COSI names are already DNS-safe, just ensure length limit
	if len(name) > 63 {
		return name[:63]
	}
	return name
}

// sanitizeKeyName ensures the key name is valid for Garage
func sanitizeKeyName(name string) string {
	// COSI names are already DNS-safe, just ensure length limit
	if len(name) > 128 {
		return name[:128]
	}
	return name
}

func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
