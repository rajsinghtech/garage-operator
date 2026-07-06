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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
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
type GarageClientFactory func(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster) (GarageClient, error)

// makeDefaultGarageClientFactory returns a GarageClientFactory backed by the real controller helper.
func makeDefaultGarageClientFactory(clusterDomain string) GarageClientFactory {
	return func(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster) (GarageClient, error) {
		return controller.GetGarageClient(ctx, c, cluster, clusterDomain)
	}
}

// BucketResult is returned from EnsureBucket.
type BucketResult struct {
	BucketID    string
	GlobalAlias string
	Endpoint    string
	Region      string
}

// AccessResult is returned from GrantAccess.
type AccessResult struct {
	AccountID       string
	AccessKeyID     string
	SecretAccessKey string
	PerBucket       []BucketResult // one entry per slot
}

// BucketAccessSlot pairs a Garage bucket ID with the access mode requested for
// that specific bucket. v1alpha2 allows mixed read/write modes per claim
// within a single BucketAccess.
type BucketAccessSlot struct {
	BucketID   string
	AccessMode AccessMode
}

// AccessMode is the Read/Write capability requested for a BucketAccess.
type AccessMode int

const (
	AccessModeReadWrite AccessMode = iota
	AccessModeReadOnly
	AccessModeWriteOnly
)

func mapAccessModeForGarage(m AccessMode) garage.BucketKeyPerms {
	switch m {
	case AccessModeReadOnly:
		return garage.BucketKeyPerms{Read: true}
	case AccessModeWriteOnly:
		return garage.BucketKeyPerms{Write: true}
	default:
		return garage.BucketKeyPerms{Read: true, Write: true}
	}
}

// Provisioner performs Garage-side bucket/key operations on behalf of COSI
// reconcilers. Pure Go API — no gRPC types in method signatures.
type Provisioner struct {
	client              client.Client
	namespace           string
	clusterDomain       string
	shadowManager       *ShadowManager
	garageClientFactory GarageClientFactory
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(c client.Client, namespace, clusterDomain string) *Provisioner {
	return &Provisioner{
		client:              c,
		namespace:           namespace,
		clusterDomain:       clusterDomain,
		shadowManager:       NewShadowManager(c, namespace),
		garageClientFactory: makeDefaultGarageClientFactory(clusterDomain),
	}
}

// NewProvisionerWithFactory creates a Provisioner with a custom GarageClient factory (for testing).
func NewProvisionerWithFactory(c client.Client, namespace string, factory GarageClientFactory) *Provisioner {
	return &Provisioner{
		client:              c,
		namespace:           namespace,
		clusterDomain:       "cluster.local",
		shadowManager:       NewShadowManager(c, namespace),
		garageClientFactory: factory,
	}
}

// EnsureBucket creates or idempotently returns an existing Garage bucket.
func (p *Provisioner) EnsureBucket(ctx context.Context, name string, params *BucketClassParameters) (*BucketResult, error) {
	if name == "" {
		return nil, fmt.Errorf("bucket name is required")
	}

	cluster, err := p.getCluster(ctx, params.ClusterRef, params.ClusterNamespace)
	if err != nil {
		return nil, err
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return nil, fmt.Errorf("garage client: %w", err)
	}

	bucketAlias := sanitizeBucketName(name)
	gb, err := gc.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: bucketAlias})
	if err != nil {
		if garage.IsConflict(err) {
			existing, getErr := gc.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: bucketAlias})
			if getErr == nil {
				if !bucketQuotasMatch(existing.Quotas, params) {
					return nil, fmt.Errorf("bucket %q exists with different configuration", bucketAlias)
				}
				log.Info("bucket already exists with matching config", "bucketId", existing.ID)
				return p.buildBucketResult(ctx, existing.ID, cluster)
			}
		}
		return nil, err
	}

	if params.MaxSize != nil || params.MaxObjects != nil {
		upd := garage.UpdateBucketRequest{ID: gb.ID}
		upd.Body.Quotas = &garage.BucketQuotas{}
		if params.MaxSize != nil {
			size := uint64(params.MaxSize.Value())
			upd.Body.Quotas.MaxSize = &size
		}
		if params.MaxObjects != nil {
			m := uint64(*params.MaxObjects)
			upd.Body.Quotas.MaxObjects = &m
		}
		if _, err := gc.UpdateBucket(ctx, upd); err != nil {
			log.Error(err, "failed to apply quotas, rolling back bucket", "bucketId", gb.ID)
			_ = gc.DeleteBucket(ctx, gb.ID)
			return nil, fmt.Errorf("apply quotas: %w", err)
		}
	}

	if _, err := p.shadowManager.CreateShadowBucketWithID(ctx, name, gb.ID, params.ClusterRef, params.ClusterNamespace, params); err != nil && !apierrors.IsAlreadyExists(err) {
		log.Error(err, "failed to create shadow bucket, rolling back", "name", name, "bucketId", gb.ID)
		if deleteErr := gc.DeleteBucket(ctx, gb.ID); deleteErr != nil {
			log.Error(deleteErr, "failed to rollback Garage bucket", "bucketId", gb.ID)
		}
		return nil, fmt.Errorf("create shadow: %w", err)
	}

	log.Info("bucket created", "bucketId", gb.ID, "alias", bucketAlias)
	return p.buildBucketResult(ctx, gb.ID, cluster)
}

// DeleteBucket removes a Garage bucket and its shadow resource.
func (p *Provisioner) DeleteBucket(ctx context.Context, bucketID string, params *BucketClassParameters) error {
	if bucketID == "" {
		return fmt.Errorf("bucketID is required")
	}

	cluster := &garagev1beta2.GarageCluster{}
	err := p.client.Get(ctx, types.NamespacedName{Name: params.ClusterRef, Namespace: params.ClusterNamespace}, cluster)
	if err != nil && client.IgnoreNotFound(err) == nil {
		log.Info("cluster not found, cleaning up shadow only", "cluster", params.ClusterRef)
		_ = p.shadowManager.DeleteShadowBucketByID(ctx, bucketID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get cluster: %w", err)
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return fmt.Errorf("garage client: %w", err)
	}

	if err := gc.DeleteBucket(ctx, bucketID); err != nil {
		if garage.IsNotFound(err) {
			log.Info("bucket already deleted from Garage", "bucketId", bucketID)
		} else if garage.IsBucketNotEmpty(err) {
			return fmt.Errorf("bucket not empty: %w", err)
		} else {
			return err
		}
	}

	_ = p.shadowManager.DeleteShadowBucketByID(ctx, bucketID)
	log.Info("bucket deleted", "bucketId", bucketID)
	return nil
}

// GrantAccess creates or idempotently returns a Garage key with access to the given bucket slots.
// Each slot specifies its own AccessMode so a single BucketAccess can grant
// mixed RW/RO permissions across buckets, as v1alpha2 requires.
// knownAccountID, when non-empty (the BucketAccess already has Status.AccountID),
// pins the lookup to that exact key — Garage key NAMES are not unique, so a
// name search can turn ambiguous and must never be the source of truth for an
// already-provisioned access.
// The returned AccessResult.PerBucket is in the same order as the input slots —
// callers may index it positionally against their slot slice.
func (p *Provisioner) GrantAccess(ctx context.Context, accountName, knownAccountID string, slots []BucketAccessSlot, params *BucketAccessClassParameters, serviceAccountName string) (*AccessResult, error) {
	if accountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("at least one bucket is required")
	}

	cluster, err := p.getCluster(ctx, params.ClusterRef, params.ClusterNamespace)
	if err != nil {
		return nil, err
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return nil, fmt.Errorf("garage client: %w", err)
	}

	keyName := sanitizeKeyName(accountName)

	// Idempotency: reuse the existing key, re-applying permissions as needed.
	// Look up by the recorded account ID when we have one (exact, unique);
	// fall back to a name search only for first-time adoption. Only a genuine
	// NotFound may fall through to CreateKey — treating ANY lookup failure as
	// "absent" mints a duplicate key per reconcile (key leak) and, once two
	// keys share a name, the search stays ambiguous forever.
	var existing *garage.Key
	var err2 error
	if knownAccountID != "" {
		existing, err2 = gc.GetKey(ctx, garage.GetKeyRequest{ID: knownAccountID, ShowSecretKey: true})
	} else {
		existing, err2 = gc.GetKey(ctx, garage.GetKeyRequest{Search: keyName, ShowSecretKey: true})
	}
	if err2 != nil && !garage.IsNotFound(err2) {
		return nil, fmt.Errorf("lookup key: %w", err2)
	}
	var key *garage.Key
	if err2 == nil && existing != nil {
		log.Info("key already exists, verifying bucket permissions", "keyId", existing.AccessKeyID)
		for _, slot := range slots {
			perms := mapAccessModeForGarage(slot.AccessMode)
			needsUpdate := true
			for _, kb := range existing.Buckets {
				if kb.ID == slot.BucketID {
					if kb.Permissions.Read == perms.Read && kb.Permissions.Write == perms.Write {
						needsUpdate = false
					}
					break
				}
			}
			if needsUpdate {
				if _, err := gc.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
					BucketID:    slot.BucketID,
					AccessKeyID: existing.AccessKeyID,
					Permissions: perms,
				}); err != nil {
					return nil, err
				}
			}
		}
		if existing.SecretAccessKey == "" {
			return nil, fmt.Errorf("existing key %s has no secret available", existing.AccessKeyID)
		}
		results, err := p.buildPerBucketResults(ctx, slots, cluster)
		if err != nil {
			return nil, err
		}
		return &AccessResult{
			AccountID:       existing.AccessKeyID,
			AccessKeyID:     existing.AccessKeyID,
			SecretAccessKey: existing.SecretAccessKey,
			PerBucket:       results,
		}, nil
	}

	createdKey := false
	key, err = gc.CreateKey(ctx, keyName)
	if err != nil {
		return nil, err
	}
	createdKey = true

	bucketPerms := make([]BucketPermission, 0, len(slots))
	for _, slot := range slots {
		perms := mapAccessModeForGarage(slot.AccessMode)
		if _, err := gc.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    slot.BucketID,
			AccessKeyID: key.AccessKeyID,
			Permissions: perms,
		}); err != nil {
			log.Error(err, "failed to grant access, rolling back key", "bucketId", slot.BucketID, "keyId", key.AccessKeyID)
			_ = gc.DeleteKey(ctx, key.AccessKeyID)
			return nil, err
		}
		bucketPerms = append(bucketPerms, BucketPermission{
			BucketID: slot.BucketID,
			Read:     perms.Read,
			Write:    perms.Write,
		})
	}

	if _, err := p.shadowManager.CreateShadowKeyWithID(ctx, accountName, key.AccessKeyID, params.ClusterRef, params.ClusterNamespace, bucketPerms, serviceAccountName); err != nil && !apierrors.IsAlreadyExists(err) {
		if createdKey {
			for _, slot := range slots {
				_, _ = gc.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
					BucketID:    slot.BucketID,
					AccessKeyID: key.AccessKeyID,
				})
			}
			_ = gc.DeleteKey(ctx, key.AccessKeyID)
		}
		return nil, fmt.Errorf("create shadow key: %w", err)
	}

	if key.SecretAccessKey == "" {
		return nil, fmt.Errorf("garage key %s has no secret available", key.AccessKeyID)
	}

	results, err := p.buildPerBucketResults(ctx, slots, cluster)
	if err != nil {
		return nil, err
	}

	log.Info("access granted", "accountId", key.AccessKeyID, "buckets", len(slots))
	return &AccessResult{
		AccountID:       key.AccessKeyID,
		AccessKeyID:     key.AccessKeyID,
		SecretAccessKey: key.SecretAccessKey,
		PerBucket:       results,
	}, nil
}

// RevokeAccess removes bucket permissions and deletes the Garage key.
func (p *Provisioner) RevokeAccess(ctx context.Context, accountID string, bucketIDs []string, params *BucketAccessClassParameters) error {
	if accountID == "" {
		return fmt.Errorf("accountID is required")
	}

	clusterRef, clusterNS := "", p.namespace
	if params != nil {
		clusterRef, clusterNS = params.ClusterRef, params.ClusterNamespace
	}
	if clusterRef == "" {
		var lookupErr error
		clusterRef, clusterNS, lookupErr = p.shadowManager.GetShadowKeyClusterRef(ctx, accountID)
		if lookupErr != nil {
			log.Info("cluster ref not found in params or shadow; cleaning up shadow only", "accountId", accountID)
			_ = p.shadowManager.DeleteShadowKeyByID(ctx, accountID)
			return nil
		}
	}

	cluster := &garagev1beta2.GarageCluster{}
	if err := p.client.Get(ctx, types.NamespacedName{Name: clusterRef, Namespace: clusterNS}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.Info("cluster not found, cleaning up shadow only", "cluster", clusterRef)
			_ = p.shadowManager.DeleteShadowKeyByID(ctx, accountID)
			return nil
		}
		return fmt.Errorf("get cluster: %w", err)
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return fmt.Errorf("garage client: %w", err)
	}

	for _, bid := range bucketIDs {
		if _, err := gc.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: bid, AccessKeyID: accountID}); err != nil {
			if !garage.IsNotFound(err) {
				return err
			}
		}
	}

	if err := gc.DeleteKey(ctx, accountID); err != nil && !garage.IsNotFound(err) {
		return err
	}

	_ = p.shadowManager.DeleteShadowKeyByID(ctx, accountID)
	log.Info("access revoked", "accountId", accountID)
	return nil
}

func (p *Provisioner) getCluster(ctx context.Context, name, namespace string) (*garagev1beta2.GarageCluster, error) {
	cluster := &garagev1beta2.GarageCluster{}
	if err := p.client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, fmt.Errorf("cluster %s/%s not found", namespace, name)
		}
		return nil, fmt.Errorf("get cluster: %w", err)
	}
	if cluster.Status.Phase != garagev1beta1.PhaseRunning {
		return nil, fmt.Errorf("cluster %s/%s not ready (phase=%s)", namespace, name, cluster.Status.Phase)
	}
	return cluster, nil
}

func (p *Provisioner) buildBucketResult(ctx context.Context, bucketID string, cluster *garagev1beta2.GarageCluster) (*BucketResult, error) {
	alias, err := p.shadowManager.GetShadowBucketGlobalAliasByID(ctx, bucketID)
	if err != nil {
		return nil, fmt.Errorf("global alias for %s not found: %w", bucketID, err)
	}
	return &BucketResult{
		BucketID:    bucketID,
		GlobalAlias: alias,
		Endpoint:    p.getS3Endpoint(cluster),
		Region:      p.getS3Region(cluster),
	}, nil
}

func (p *Provisioner) buildPerBucketResults(ctx context.Context, slots []BucketAccessSlot, cluster *garagev1beta2.GarageCluster) ([]BucketResult, error) {
	results := make([]BucketResult, 0, len(slots))
	for _, slot := range slots {
		br, err := p.buildBucketResult(ctx, slot.BucketID, cluster)
		if err != nil {
			return nil, err
		}
		results = append(results, *br)
	}
	return results, nil
}

func (p *Provisioner) getS3Endpoint(cluster *garagev1beta2.GarageCluster) string {
	if cluster.Status.Endpoints != nil && cluster.Status.Endpoints.S3 != "" {
		return cluster.Status.Endpoints.S3
	}
	port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort > 0 {
		port = cluster.Spec.S3API.BindPort
	}
	return fmt.Sprintf("%s.%s.svc.%s:%d", cluster.Name, cluster.Namespace, p.clusterDomain, port)
}

func (p *Provisioner) getS3Region(cluster *garagev1beta2.GarageCluster) string {
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		return cluster.Spec.S3API.Region
	}
	return "garage"
}

// sanitizeBucketName ensures the bucket name is valid for Garage (max 63 chars).
// For long names, uses a hash suffix to avoid collisions from truncation.
func sanitizeBucketName(name string) string {
	if len(name) <= 63 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:6]) // 12 hex chars
	return name[:50] + "-" + suffix
}

// sanitizeKeyName ensures the key name is valid for Garage (max 128 chars).
// For long names, uses a hash suffix to avoid collisions from truncation.
func sanitizeKeyName(name string) string {
	if len(name) <= 128 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:6]) // 12 hex chars
	return name[:115] + "-" + suffix
}

// bucketQuotasMatch checks if existing bucket quotas match the requested params
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
