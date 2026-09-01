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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	AddBucketAlias(ctx context.Context, req garage.AddBucketAliasRequest) (*garage.Bucket, error)
	RemoveBucketAlias(ctx context.Context, req garage.RemoveBucketAliasRequest) (*garage.Bucket, error)
	CreateKey(ctx context.Context, name string) (*garage.Key, error)
	ImportKey(ctx context.Context, req garage.ImportKeyRequest) (*garage.Key, error)
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

	reservationAccessKeyIDKey = "access-key-id"
	reservationSecretKeyKey   = "secret-access-key"
	garageBucketKind          = "GarageBucket"
	garageClusterKind         = "GarageCluster"
	garageKeyKind             = "GarageKey"
)

func mapAccessModeForGarage(m AccessMode) garage.BucketKeyPerms {
	switch m {
	case AccessModeReadWrite:
		return garage.BucketKeyPerms{Read: true, Write: true}
	case AccessModeReadOnly:
		return garage.BucketKeyPerms{Read: true}
	case AccessModeWriteOnly:
		return garage.BucketKeyPerms{Write: true}
	default:
		return garage.BucketKeyPerms{}
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

func cosiBucketReservationAlias(bucket *garagev1beta1.GarageBucket) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("COSI GarageBucket is required before reserving a remote identity")
	}
	return garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", bucket.Namespace, bucket.Name, bucket.UID)
}

func keyReservationSecretName(cosiName string) string {
	return ShadowResourceName(cosiName) + "-reservation"
}

func randomHex(byteCount int) (string, error) {
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (p *Provisioner) ensureKeyReservationSecret(ctx context.Context, cosiName string, shadow *garagev1beta1.GarageKey) (*corev1.Secret, error) {
	reservedID := shadow.Status.AccessKeyID
	if reservedID == "" {
		idSuffix, err := randomHex(12)
		if err != nil {
			return nil, fmt.Errorf("generate reservation access key ID: %w", err)
		}
		reservedID = "GK" + idSuffix
		// Reserve the unpredictable ID through the protected status subresource
		// before inspecting any same-name Secret. A precreated Secret can cause a
		// collision/DoS, but cannot select a victim ID that finalization will trust.
		if err := p.shadowManager.persistShadowKeyStatusID(ctx, shadow, "", reservedID); err != nil {
			return nil, err
		}
	}
	objectKey := types.NamespacedName{Name: keyReservationSecretName(cosiName), Namespace: p.namespace}
	existing := &corev1.Secret{}
	if err := p.client.Get(ctx, objectKey, existing); err == nil {
		if err := validateKeyReservationSecret(existing, shadow, cosiName, reservedID); err != nil {
			return nil, err
		}
		return existing, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	secretKey, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate reservation secret key: %w", err)
	}
	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      objectKey.Name,
			Namespace: objectKey.Namespace,
			Labels:    ShadowKeyLabels(cosiName),
			Annotations: map[string]string{
				annotationCOSIReservationOwner: cosiName,
			},
		},
		Data: map[string][]byte{
			reservationAccessKeyIDKey: []byte(reservedID),
			reservationSecretKeyKey:   []byte(secretKey),
		},
		Immutable: &immutable,
	}
	if shadow.UID != "" {
		controller, block := true, true
		secret.OwnerReferences = []metav1.OwnerReference{{
			APIVersion:         garagev1beta1.GroupVersion.String(),
			Kind:               garageKeyKind,
			Name:               shadow.Name,
			UID:                shadow.UID,
			Controller:         &controller,
			BlockOwnerDeletion: &block,
		}}
	}
	if err := p.client.Create(ctx, secret); err == nil {
		return secret, nil
	} else if !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	if err := p.client.Get(ctx, objectKey, existing); err != nil {
		return nil, err
	}
	if err := validateKeyReservationSecret(existing, shadow, cosiName, reservedID); err != nil {
		return nil, err
	}
	return existing, nil
}

func validateKeyReservationSecret(secret *corev1.Secret, shadow *garagev1beta1.GarageKey, cosiName, reservedID string) error {
	objectKey := client.ObjectKeyFromObject(secret)
	if secret.Annotations[annotationCOSIReservationOwner] != cosiName ||
		secret.Labels[LabelCOSIManaged] != paramTrue || !metav1.IsControlledBy(secret, shadow) {
		return fmt.Errorf("refusing to use non-matching key reservation Secret %s", objectKey)
	}
	if secret.Immutable == nil || !*secret.Immutable {
		return fmt.Errorf("refusing mutable key reservation Secret %s", objectKey)
	}
	if string(secret.Data[reservationAccessKeyIDKey]) != reservedID || len(secret.Data[reservationSecretKeyKey]) == 0 {
		return fmt.Errorf("key reservation Secret %s does not match controller-owned status ID %q", objectKey, reservedID)
	}
	return nil
}

func (p *Provisioner) deleteKeyReservationSecret(
	ctx context.Context, cosiName string, shadow *garagev1beta1.GarageKey, reservedID string,
) error {
	secret := &corev1.Secret{}
	objectKey := types.NamespacedName{Name: keyReservationSecretName(cosiName), Namespace: p.namespace}
	if err := p.client.Get(ctx, objectKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if shadow == nil || shadow.UID == "" {
		return fmt.Errorf("authoritative GarageKey shadow UID is required before deleting reservation material")
	}
	if err := validateKeyReservationSecret(secret, shadow, cosiName, reservedID); err != nil {
		return err
	}
	uid := secret.UID
	if err := p.client.Delete(ctx, secret, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// EnsureBucket creates or idempotently returns an existing Garage bucket.
func (p *Provisioner) EnsureBucket(ctx context.Context, name string, params *BucketClassParameters) (*BucketResult, error) {
	if name == "" {
		return nil, fmt.Errorf("bucket name is required")
	}
	if err := validateBucketClassQuotas(params); err != nil {
		return nil, err
	}

	cluster, err := p.getCluster(ctx, params.ClusterRef, params.ClusterNamespace)
	if err != nil {
		return nil, err
	}
	if err := garagev1beta1.CheckReferenceGrant(ctx, p.client, garageBucketKind, p.namespace,
		garageClusterKind, params.ClusterNamespace, params.ClusterRef); err != nil {
		return nil, fmt.Errorf("authorize COSI bucket cluster reference: %w", err)
	}
	if _, err := p.getS3Endpoint(cluster); err != nil {
		return nil, err
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return nil, fmt.Errorf("garage client: %w", err)
	}

	bucketAlias := sanitizeBucketName(name)
	reservation, _, err := p.shadowManager.ReserveShadowBucket(ctx, name, params.ClusterRef, params.ClusterNamespace, params)
	if err != nil {
		return nil, fmt.Errorf("reserve shadow bucket: %w", err)
	}

	var gb *garage.Bucket
	if shadowID := reservation.Annotations[AnnotationCOSIBucketID]; shadowID != "" {
		if reservation.Status.BucketID != shadowID {
			return nil, fmt.Errorf("refusing shadow bucket annotation %q without matching controller-owned status reservation", shadowID)
		}
		gb, err = gc.GetBucket(ctx, garage.GetBucketRequest{ID: shadowID})
		if err != nil {
			if garage.IsNotFound(err) {
				if deleteErr := p.shadowManager.DeleteShadowBucketByID(ctx, shadowID); deleteErr != nil {
					return nil, fmt.Errorf("delete stale shadow bucket %s: %w", shadowID, deleteErr)
				}
				return nil, fmt.Errorf("shadow-tracked Garage bucket %s no longer exists; stale shadow deletion started, retry provisioning", shadowID)
			}
			return nil, fmt.Errorf("get shadow-tracked bucket %s: %w", shadowID, err)
		}
		if _, err := p.shadowManager.BindShadowBucket(ctx, reservation, shadowID, params); err != nil {
			return nil, fmt.Errorf("refresh bound shadow bucket %s: %w", shadowID, err)
		}
	} else if statusID := reservation.Status.BucketID; statusID != "" {
		// BindShadowBucket writes status before its metadata handoff. Honor that
		// protected identity directly; falling back to the private alias can create
		// a second bucket if the alias disappeared after the status write.
		gb, err = gc.GetBucket(ctx, garage.GetBucketRequest{ID: statusID})
		if err != nil {
			if garage.IsNotFound(err) {
				if _, deleteErr := p.shadowManager.RequestDeleteShadowBucketByName(ctx, name); deleteErr != nil {
					return nil, fmt.Errorf("delete stale status-owned shadow bucket %s: %w", statusID, deleteErr)
				}
				return nil, fmt.Errorf("status-tracked Garage bucket %s no longer exists; stale shadow deletion started, retry provisioning", statusID)
			}
			return nil, fmt.Errorf("get status-tracked bucket %s: %w", statusID, err)
		}
		if _, err := p.shadowManager.BindShadowBucket(ctx, reservation, statusID, params); err != nil {
			return nil, fmt.Errorf("finish shadow bucket metadata handoff %s: %w", statusID, err)
		}
	} else {
		recoveryAlias := reservation.Annotations[garagev1beta1.AnnotationCOSIReservationAlias]
		expectedRecoveryAlias, aliasErr := cosiBucketReservationAlias(reservation)
		if aliasErr != nil {
			return nil, fmt.Errorf("derive private bucket reservation alias: %w", aliasErr)
		}
		if recoveryAlias != "" && recoveryAlias != expectedRecoveryAlias {
			return nil, fmt.Errorf("bucket reservation alias %q is not bound to shadow UID %s", recoveryAlias, reservation.UID)
		}
		if reservation.Annotations[annotationCOSIReservationReady] != paramTrue {
			if recoveryAlias != "" {
				return nil, fmt.Errorf("bucket reservation has alias %q without create authorization", recoveryAlias)
			}
			recoveryAlias = expectedRecoveryAlias
			for _, alias := range []string{bucketAlias, recoveryAlias} {
				if existing, getErr := gc.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: alias}); getErr == nil {
					if deleteErr := p.shadowManager.DeleteShadowBucketReservation(ctx, reservation); deleteErr != nil {
						return nil, fmt.Errorf("delete rejected bucket reservation: %w", deleteErr)
					}
					return nil, fmt.Errorf("bucket alias %q is already used by an untracked Garage bucket %s", alias, existing.ID)
				} else if !garage.IsNotFound(getErr) {
					return nil, fmt.Errorf("lookup bucket alias %q: %w", alias, getErr)
				}
			}
			if err := p.shadowManager.AuthorizeShadowBucketCreate(ctx, reservation, recoveryAlias); err != nil {
				return nil, fmt.Errorf("authorize bucket reservation: %w", err)
			}
		} else if recoveryAlias == "" {
			return nil, fmt.Errorf("authorized bucket reservation has no recovery alias")
		}

		if err := p.assertClusterProvisionable(ctx, cluster); err != nil {
			return nil, err
		}
		gb, err = gc.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: recoveryAlias})
		if garage.IsNotFound(err) {
			gb, err = gc.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: recoveryAlias})
			if err != nil {
				// The request may have committed before its response failed. Resolve the
				// reservation alias before reporting failure so the exact bucket survives.
				if recovered, getErr := gc.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: recoveryAlias}); getErr == nil {
					gb, err = recovered, nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("create or recover reserved Garage bucket: %w", err)
		}
		if _, err := p.shadowManager.BindShadowBucket(ctx, reservation, gb.ID, params); err != nil {
			return nil, fmt.Errorf("bind shadow bucket %s: %w", gb.ID, err)
		}
	}

	if err := ensureCOSIBucketQuotas(ctx, gc, gb, params); err != nil {
		// Keep the shadow and exact Garage ID. A compensating delete can fail
		// after the shadow is gone, leaving an untrackable bare bucket and causing
		// the next retry to create a duplicate. Retrying converges this bucket.
		log.Error(err, "failed to apply quotas; retaining shadow-tracked bucket for retry", "bucketId", gb.ID)
		return nil, err
	}
	if err := ensureCOSIBucketWebsite(ctx, gc, gb, params); err != nil {
		return nil, err
	}
	if err := ensureCOSIGlobalAlias(ctx, gc, gb, bucketAlias); err != nil {
		// Keep the shadow+ID so the next reconcile resumes this exact bucket.
		return nil, err
	}
	if recoveryAlias := reservation.Annotations[garagev1beta1.AnnotationCOSIReservationAlias]; recoveryAlias != "" && recoveryAlias != bucketAlias {
		if bucketHasGlobalAlias(gb, recoveryAlias) {
			if _, err := gc.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: gb.ID, GlobalAlias: recoveryAlias}); err != nil && !garage.IsNotFound(err) {
				return nil, fmt.Errorf("remove COSI bucket reservation alias %q: %w", recoveryAlias, err)
			}
		}
		if err := p.shadowManager.ClearShadowBucketReservationAlias(ctx, reservation); err != nil {
			return nil, fmt.Errorf("clear bound bucket reservation alias: %w", err)
		}
	}

	log.Info("bucket ready", "bucketId", gb.ID, "alias", bucketAlias)
	return p.buildBucketResult(ctx, gb.ID, cluster)
}

func bucketHasGlobalAlias(bucket *garage.Bucket, alias string) bool {
	for _, current := range bucket.GlobalAliases {
		if current == alias {
			return true
		}
	}
	return false
}

func ensureCOSIGlobalAlias(ctx context.Context, gc GarageClient, bucket *garage.Bucket, alias string) error {
	if bucketHasGlobalAlias(bucket, alias) {
		return nil
	}
	if _, err := gc.AddBucketAlias(ctx, garage.AddBucketAliasRequest{
		BucketID: bucket.ID, GlobalAlias: alias,
	}); err != nil {
		return fmt.Errorf("add global alias %q to bucket %s: %w", alias, bucket.ID, err)
	}
	return nil
}

func ensureCOSIBucketQuotas(ctx context.Context, gc GarageClient, bucket *garage.Bucket, params *BucketClassParameters) error {
	if bucketQuotasMatch(bucket.Quotas, params) {
		return nil
	}

	quotas := &garage.BucketQuotas{}
	if params.MaxSize != nil {
		size := uint64(params.MaxSize.Value())
		quotas.MaxSize = &size
	}
	if params.MaxObjects != nil {
		objects := uint64(*params.MaxObjects)
		quotas.MaxObjects = &objects
	}
	if _, err := gc.UpdateBucket(ctx, garage.UpdateBucketRequest{
		ID: bucket.ID, Body: garage.UpdateBucketRequestBody{Quotas: quotas},
	}); err != nil {
		return fmt.Errorf("apply quotas to bucket %s: %w", bucket.ID, err)
	}
	bucket.Quotas = quotas
	return nil
}

func ensureCOSIBucketWebsite(ctx context.Context, gc GarageClient, bucket *garage.Bucket, params *BucketClassParameters) error {
	if bucket.WebsiteAccess == params.WebsiteEnabled {
		return nil
	}
	website := &garage.UpdateBucketWebsiteAccess{Enabled: params.WebsiteEnabled}
	if params.WebsiteEnabled {
		website.IndexDocument = "index.html"
	}
	if _, err := gc.UpdateBucket(ctx, garage.UpdateBucketRequest{
		ID: bucket.ID, Body: garage.UpdateBucketRequestBody{WebsiteAccess: website},
	}); err != nil {
		return fmt.Errorf("apply website setting to bucket %s: %w", bucket.ID, err)
	}
	bucket.WebsiteAccess = params.WebsiteEnabled
	return nil
}

// DeleteBucket removes a Garage bucket and its shadow resource.
func (p *Provisioner) DeleteBucket(ctx context.Context, bucketID string, params *BucketClassParameters) error {
	if bucketID == "" {
		return fmt.Errorf("bucketID is required")
	}

	clusterRef, clusterNamespace := "", p.namespace
	if params != nil {
		clusterRef, clusterNamespace = params.ClusterRef, params.ClusterNamespace
	}
	if clusterRef == "" {
		var err error
		clusterRef, clusterNamespace, err = p.shadowManager.GetShadowBucketClusterRef(ctx, bucketID)
		if err != nil {
			return fmt.Errorf("recover cluster reference from shadow bucket %s: %w", bucketID, err)
		}
	}

	cluster := &garagev1beta2.GarageCluster{}
	err := p.client.Get(ctx, types.NamespacedName{Name: clusterRef, Namespace: clusterNamespace}, cluster)
	if err != nil && client.IgnoreNotFound(err) == nil {
		return fmt.Errorf("get cluster %s/%s for bucket cleanup: %w", clusterNamespace, clusterRef, err)
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

	if err := p.shadowManager.DeleteShadowBucketByID(ctx, bucketID); err != nil {
		return fmt.Errorf("delete shadow bucket %s: %w", bucketID, err)
	}
	log.Info("bucket deleted", "bucketId", bucketID)
	return nil
}

// CancelBucketProvisioning requests deletion of the name-addressed shadow and
// waits for its generic cleanup finalizer when COSI status never received an ID.
func (p *Provisioner) CancelBucketProvisioning(ctx context.Context, cosiName string) (bool, error) {
	return p.shadowManager.RequestDeleteShadowBucketByName(ctx, cosiName)
}

// RetainBucketProvisioning forgets the operator-internal shadow while leaving
// the Garage bucket untouched, as required by COSI Retain policy.
func (p *Provisioner) RetainBucketProvisioning(ctx context.Context, cosiName, bucketID string) (bool, error) {
	return p.shadowManager.ForgetShadowBucketByName(ctx, cosiName, bucketID)
}

// OwnsBucketCleanup proves that an out-of-scope, deleting cluster-scoped
// Bucket belongs to this provisioner's private shadow namespace.
func (p *Provisioner) OwnsBucketCleanup(ctx context.Context, cosiName, bucketID string) (bool, error) {
	return p.shadowManager.OwnsShadowBucket(ctx, cosiName, bucketID)
}

// GrantAccess creates or idempotently returns a Garage key with access to the given bucket slots.
// Each slot specifies its own AccessMode so a single BucketAccess can grant
// mixed RW/RO permissions across buckets, as v1alpha2 requires.
// knownAccountID, when non-empty (the BucketAccess already has Status.AccountID),
// pins the lookup to that exact key. When it is absent, a durable COSI shadow
// may provide the ID. Garage key names are not unique and are never used for
// adoption, so an unrelated same-name key cannot be exposed or deleted.
// The returned AccessResult.PerBucket is in the same order as the input slots —
// callers may index it positionally against their slot slice.
func (p *Provisioner) GrantAccess(ctx context.Context, accountName, knownAccountID string, slots []BucketAccessSlot, params *BucketAccessClassParameters, serviceAccountName string) (*AccessResult, error) {
	if accountName == "" {
		return nil, fmt.Errorf("accountName is required")
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("at least one bucket is required")
	}
	if err := validateBucketAccessSlots(slots); err != nil {
		return nil, err
	}

	cluster, err := p.getCluster(ctx, params.ClusterRef, params.ClusterNamespace)
	if err != nil {
		return nil, err
	}
	if err := garagev1beta1.CheckReferenceGrant(ctx, p.client, garageKeyKind, p.namespace,
		garageClusterKind, params.ClusterNamespace, params.ClusterRef); err != nil {
		return nil, fmt.Errorf("authorize COSI key cluster reference: %w", err)
	}
	if _, err := p.getS3Endpoint(cluster); err != nil {
		return nil, err
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return nil, fmt.Errorf("garage client: %w", err)
	}

	keyName := sanitizeKeyName(accountName)
	bucketPerms := bucketPermissionsForSlots(slots)
	reservation, _, err := p.shadowManager.ReserveShadowKey(
		ctx, accountName, params.ClusterRef, params.ClusterNamespace, bucketPerms, serviceAccountName,
	)
	if err != nil {
		return nil, fmt.Errorf("reserve shadow key: %w", err)
	}
	state := reservation.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	shadowID := reservation.Annotations[AnnotationCOSIAccountID]
	if knownAccountID != "" && shadowID != "" && knownAccountID != shadowID {
		return nil, fmt.Errorf("BucketAccess status account ID %s disagrees with COSI shadow account ID %s", knownAccountID, shadowID)
	}
	if shadowID != "" && reservation.Status.AccessKeyID != shadowID && knownAccountID != shadowID {
		if state != garagev1beta1.COSIProvisioningStatePending || reservation.Status.AccessKeyID == "" {
			return nil, fmt.Errorf("refusing shadow key annotation %q without matching controller-owned status or BucketAccess identity", shadowID)
		}
	}

	var key *garage.Key
	secretAccessKey := ""
	statusReservedReplacement := state == garagev1beta1.COSIProvisioningStatePending && shadowID != "" &&
		reservation.Status.AccessKeyID != "" && reservation.Status.AccessKeyID != shadowID
	pendingShadowIDProvenAbsent := statusReservedReplacement
	if state != garagev1beta1.COSIProvisioningStatePending && shadowID != "" {
		key, err = gc.GetKey(ctx, garage.GetKeyRequest{ID: shadowID, ShowSecretKey: true})
		if err != nil {
			if garage.IsNotFound(err) {
				if deleteErr := p.shadowManager.DeleteShadowKeyByID(ctx, shadowID); deleteErr != nil {
					return nil, fmt.Errorf("delete stale shadow key %s: %w", shadowID, deleteErr)
				}
				return nil, fmt.Errorf("shadow-tracked Garage key %s no longer exists; stale shadow deletion started, retry provisioning", shadowID)
			}
			return nil, fmt.Errorf("lookup shadow-tracked key: %w", err)
		}
		secretAccessKey = key.SecretAccessKey
	} else if shadowID != "" && !statusReservedReplacement {
		key, err = gc.GetKey(ctx, garage.GetKeyRequest{ID: shadowID, ShowSecretKey: true})
		if err != nil && !garage.IsNotFound(err) {
			return nil, fmt.Errorf("lookup pending shadow key %s: %w", shadowID, err)
		}
		if err == nil {
			secretAccessKey = key.SecretAccessKey
		} else {
			pendingShadowIDProvenAbsent = true
		}
	} else if knownAccountID != "" {
		key, err = gc.GetKey(ctx, garage.GetKeyRequest{ID: knownAccountID, ShowSecretKey: true})
		if err != nil && !garage.IsNotFound(err) {
			return nil, fmt.Errorf("lookup key from BucketAccess status %s: %w", knownAccountID, err)
		}
		if err == nil {
			if err := p.shadowManager.SetShadowKeyReservationID(ctx, reservation, knownAccountID); err != nil {
				return nil, err
			}
			secretAccessKey = key.SecretAccessKey
		} else {
			if _, deleteErr := p.shadowManager.RequestDeleteShadowKeyByName(ctx, accountName); deleteErr != nil {
				return nil, fmt.Errorf("delete reservation for missing BucketAccess status key %s: %w", knownAccountID, deleteErr)
			}
			return nil, fmt.Errorf("BucketAccess status-tracked Garage key %s no longer exists; refusing immutable account replacement", knownAccountID)
		}
	}
	if key == nil {
		if pendingShadowIDProvenAbsent && reservation.Status.AccessKeyID == shadowID {
			// Garage permanently tombstones imported IDs. Remove the old exact-owned
			// material before advancing status; a crash at either boundary retries
			// from the absent old key or the status-first replacement state.
			if err := p.deleteKeyReservationSecret(ctx, accountName, reservation, shadowID); err != nil {
				return nil, fmt.Errorf("delete replaced key reservation Secret: %w", err)
			}
			idSuffix, generateErr := randomHex(12)
			if generateErr != nil {
				return nil, fmt.Errorf("generate replacement reservation access key ID: %w", generateErr)
			}
			if err := p.shadowManager.persistShadowKeyStatusID(ctx, reservation, shadowID, "GK"+idSuffix); err != nil {
				return nil, err
			}
		}
		material, err := p.ensureKeyReservationSecret(ctx, accountName, reservation)
		if err != nil {
			return nil, fmt.Errorf("persist exact key reservation material: %w", err)
		}
		accessKeyID := string(material.Data[reservationAccessKeyIDKey])
		secretAccessKey = string(material.Data[reservationSecretKeyKey])
		if shadowID != "" && shadowID != accessKeyID {
			if !pendingShadowIDProvenAbsent {
				return nil, fmt.Errorf("pending shadow key account ID %s disagrees with reservation Secret ID %s", shadowID, accessKeyID)
			}
			if err := p.shadowManager.ReplaceShadowKeyReservationID(ctx, reservation, shadowID, accessKeyID); err != nil {
				return nil, fmt.Errorf("replace missing key reservation ID: %w", err)
			}
		} else if err := p.shadowManager.SetShadowKeyReservationID(ctx, reservation, accessKeyID); err != nil {
			return nil, fmt.Errorf("persist key reservation ID: %w", err)
		}
		if err := p.assertClusterProvisionable(ctx, cluster); err != nil {
			return nil, err
		}
		key, err = gc.GetKey(ctx, garage.GetKeyRequest{ID: accessKeyID, ShowSecretKey: true})
		if garage.IsNotFound(err) {
			key, err = gc.ImportKey(ctx, garage.ImportKeyRequest{
				AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, Name: keyName,
			})
			if garage.IsConflict(err) {
				key, err = gc.GetKey(ctx, garage.GetKeyRequest{ID: accessKeyID, ShowSecretKey: true})
			}
		}
		if err != nil {
			return nil, fmt.Errorf("import or recover reserved Garage key %s: %w", accessKeyID, err)
		}
		if key.SecretAccessKey != "" && key.SecretAccessKey != secretAccessKey {
			return nil, fmt.Errorf("garage key %s exists with different secret material", accessKeyID)
		}
	}
	if _, err := p.shadowManager.BindShadowKey(ctx, reservation, key.AccessKeyID, bucketPerms, serviceAccountName); err != nil {
		return nil, fmt.Errorf("bind shadow key %s: %w", key.AccessKeyID, err)
	}
	if secretAccessKey == "" {
		secretAccessKey = key.SecretAccessKey
	}
	if secretAccessKey == "" {
		return nil, fmt.Errorf("existing key %s has no secret available", key.AccessKeyID)
	}
	if err := reconcileCOSIKeyPermissions(ctx, gc, key, slots); err != nil {
		return nil, err
	}

	results, err := p.buildPerBucketResults(ctx, slots, cluster)
	if err != nil {
		return nil, err
	}

	if err := p.deleteKeyReservationSecret(ctx, accountName, reservation, key.AccessKeyID); err != nil {
		return nil, fmt.Errorf("delete bound key reservation Secret: %w", err)
	}
	log.Info("access granted", "accountId", key.AccessKeyID, "buckets", len(slots))
	return &AccessResult{
		AccountID:       key.AccessKeyID,
		AccessKeyID:     key.AccessKeyID,
		SecretAccessKey: secretAccessKey,
		PerBucket:       results,
	}, nil
}

// ValidateBucketAccessCluster proves every bound Garage bucket belongs to the
// exact GarageCluster selected by the BucketAccessClass before any key is
// created or permissions are mutated.
func (p *Provisioner) ValidateBucketAccessCluster(ctx context.Context, slots []BucketAccessSlot, params *BucketAccessClassParameters) error {
	if params == nil {
		return fmt.Errorf("BucketAccessClass parameters are required")
	}
	for _, slot := range slots {
		clusterRef, clusterNamespace, err := p.shadowManager.GetShadowBucketClusterRef(ctx, slot.BucketID)
		if err != nil {
			return fmt.Errorf("verify cluster for bucket %s: %w", slot.BucketID, err)
		}
		if clusterRef != params.ClusterRef || clusterNamespace != params.ClusterNamespace {
			return fmt.Errorf("bucket %s belongs to GarageCluster %s/%s, not BucketAccessClass cluster %s/%s",
				slot.BucketID, clusterNamespace, clusterRef, params.ClusterNamespace, params.ClusterRef)
		}
	}
	return nil
}

func validateBucketAccessSlots(slots []BucketAccessSlot) error {
	seen := make(map[string]int, len(slots))
	for i, slot := range slots {
		if slot.BucketID == "" {
			return fmt.Errorf("bucket slot %d has an empty bucket ID", i)
		}
		switch slot.AccessMode {
		case AccessModeReadWrite, AccessModeReadOnly, AccessModeWriteOnly:
		default:
			return fmt.Errorf("bucket slot %d has unsupported access mode %d", i, slot.AccessMode)
		}
		if previous, duplicate := seen[slot.BucketID]; duplicate {
			return fmt.Errorf("bucket slot %d duplicates bucket slot %d for bucket %s", i, previous, slot.BucketID)
		}
		seen[slot.BucketID] = i
	}
	return nil
}

func bucketPermissionsForSlots(slots []BucketAccessSlot) []BucketPermission {
	permissions := make([]BucketPermission, 0, len(slots))
	for _, slot := range slots {
		perms := mapAccessModeForGarage(slot.AccessMode)
		permissions = append(permissions, BucketPermission{
			BucketID: slot.BucketID,
			Read:     perms.Read,
			Write:    perms.Write,
			Owner:    perms.Owner,
		})
	}
	return permissions
}

func reconcileCOSIKeyPermissions(ctx context.Context, gc GarageClient, key *garage.Key, slots []BucketAccessSlot) error {
	desired := make(map[string]garage.BucketKeyPerms, len(slots))
	for _, slot := range slots {
		desired[slot.BucketID] = mapAccessModeForGarage(slot.AccessMode)
	}
	current := make(map[string]garage.BucketKeyPerms, len(key.Buckets))
	for _, bucket := range key.Buckets {
		current[bucket.ID] = bucket.Permissions
	}

	for bucketID, have := range current {
		want := desired[bucketID]
		deny := garage.BucketKeyPerms{
			Read:  have.Read && !want.Read,
			Write: have.Write && !want.Write,
			Owner: have.Owner && !want.Owner,
		}
		if !deny.Read && !deny.Write && !deny.Owner {
			continue
		}
		if _, err := gc.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
			BucketID: bucketID, AccessKeyID: key.AccessKeyID, Permissions: deny,
		}); err != nil {
			return fmt.Errorf("deny stale bucket permissions for %s: %w", bucketID, err)
		}
	}

	for bucketID, want := range desired {
		have := current[bucketID]
		allow := garage.BucketKeyPerms{
			Read:  want.Read && !have.Read,
			Write: want.Write && !have.Write,
			Owner: want.Owner && !have.Owner,
		}
		if !allow.Read && !allow.Write && !allow.Owner {
			continue
		}
		if _, err := gc.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID: bucketID, AccessKeyID: key.AccessKeyID, Permissions: allow,
		}); err != nil {
			return fmt.Errorf("allow desired bucket permissions for %s: %w", bucketID, err)
		}
	}
	return nil
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
		var err error
		clusterRef, clusterNS, err = p.shadowManager.GetShadowKeyClusterRef(ctx, accountID)
		if err != nil {
			return fmt.Errorf("recover cluster reference from shadow key %s: %w", accountID, err)
		}
	}

	cluster := &garagev1beta2.GarageCluster{}
	if err := p.client.Get(ctx, types.NamespacedName{Name: clusterRef, Namespace: clusterNS}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return fmt.Errorf("get cluster %s/%s for access cleanup: %w", clusterNS, clusterRef, err)
		}
		return fmt.Errorf("get cluster: %w", err)
	}

	gc, err := p.garageClientFactory(ctx, p.client, cluster)
	if err != nil {
		return fmt.Errorf("garage client: %w", err)
	}

	for _, bid := range bucketIDs {
		if _, err := gc.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
			BucketID: bid, AccessKeyID: accountID,
			Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
		}); err != nil {
			if !garage.IsNotFound(err) {
				return err
			}
		}
	}

	if err := gc.DeleteKey(ctx, accountID); err != nil && !garage.IsNotFound(err) {
		return err
	}

	if err := p.shadowManager.DeleteShadowKeyByID(ctx, accountID); err != nil {
		return fmt.Errorf("delete shadow key %s: %w", accountID, err)
	}
	log.Info("access revoked", "accountId", accountID)
	return nil
}

// CancelAccessProvisioning requests deletion of a name-addressed GarageKey
// shadow and reports completion only after its cleanup finalizer is gone.
func (p *Provisioner) CancelAccessProvisioning(ctx context.Context, cosiName string) (bool, error) {
	return p.shadowManager.RequestDeleteShadowKeyByName(ctx, cosiName)
}

// ResolveBucketAccessIdentity chooses the UID-scoped identity for new access
// grants and safely recognizes a bound name-scoped shadow from older releases.
func (p *Provisioner) ResolveBucketAccessIdentity(
	ctx context.Context, accessNamespace, accessName, accessUID, knownAccountID, driverName string,
) (BucketAccessIdentityResolution, error) {
	return p.shadowManager.ResolveBucketAccessIdentity(ctx, accessNamespace, accessName, accessUID, knownAccountID, driverName)
}

// CleanupDuplicateAccessIdentity removes every exact Garage account tracked by
// a duplicate UID-scoped shadow, its reservation Secret, and the shadow itself.
func (p *Provisioner) CleanupDuplicateAccessIdentity(ctx context.Context, identity string) (bool, error) {
	key := &garagev1beta1.GarageKey{}
	objectKey := types.NamespacedName{Name: ShadowResourceName(identity), Namespace: p.namespace}
	if err := p.client.Get(ctx, objectKey, key); err != nil {
		if apierrors.IsNotFound(err) {
			// Without the authoritative shadow UID, a same-name Secret may be an
			// unrelated replacement. A legitimate reservation is controller-owned
			// and is removed by GarageKey garbage collection.
			return true, nil
		}
		return false, err
	}
	if key.Labels[LabelCOSIManaged] != paramTrue || key.Annotations[annotationCOSIReservationOwner] != identity {
		return false, fmt.Errorf("refusing to clean non-matching duplicate GarageKey shadow %s", objectKey)
	}
	// Only status is controller-owned authority for a remote key identity.
	// Labels and annotations are useful indexes/correlation hints, but a
	// namespace actor can forge them and must not turn duplicate cleanup into an
	// arbitrary Garage DeleteKey call.
	ids := shadowKeyStatusAccountIDs(key)
	if len(ids) == 0 {
		done, err := p.shadowManager.RequestDeleteShadowKeyByName(ctx, identity)
		if err != nil || !done {
			return done, err
		}
	} else {
		ordered := make([]string, 0, len(ids))
		for id := range ids {
			ordered = append(ordered, id)
		}
		sort.Strings(ordered)
		params := &BucketAccessClassParameters{
			ClusterRef:       key.Spec.ClusterRef.Name,
			ClusterNamespace: key.Spec.ClusterRef.Namespace,
		}
		if params.ClusterNamespace == "" {
			params.ClusterNamespace = p.namespace
		}
		cluster := &garagev1beta2.GarageCluster{}
		clusterKey := types.NamespacedName{Name: params.ClusterRef, Namespace: params.ClusterNamespace}
		if err := p.client.Get(ctx, clusterKey, cluster); err != nil {
			return false, fmt.Errorf("get cluster %s for duplicate access cleanup: %w", clusterKey, err)
		}
		gc, err := p.garageClientFactory(ctx, p.client, cluster)
		if err != nil {
			return false, fmt.Errorf("garage client for duplicate access cleanup: %w", err)
		}
		for _, id := range ordered {
			if err := gc.DeleteKey(ctx, id); err != nil && !garage.IsNotFound(err) {
				return false, fmt.Errorf("delete duplicate Garage account %s: %w", id, err)
			}
		}
	}
	reservedID := key.Status.AccessKeyID
	if reservedID == "" {
		reservedID = key.Status.KeyID
	}
	if reservedID != "" {
		if err := p.deleteKeyReservationSecret(ctx, identity, key, reservedID); err != nil {
			return false, fmt.Errorf("delete duplicate key reservation Secret: %w", err)
		}
	}
	if len(ids) > 0 {
		if err := p.shadowManager.deleteShadow(ctx, key, garagev1beta1.GarageKeyFinalizer); err != nil {
			return false, fmt.Errorf("delete duplicate GarageKey shadow %s: %w", objectKey, err)
		}
	}
	return true, nil
}

func (p *Provisioner) getCluster(ctx context.Context, name, namespace string) (*garagev1beta2.GarageCluster, error) {
	cluster := &garagev1beta2.GarageCluster{}
	if err := p.client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, fmt.Errorf("cluster %s/%s not found", namespace, name)
		}
		return nil, fmt.Errorf("get cluster: %w", err)
	}
	if !cluster.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("cluster %s/%s is deleting; refusing COSI provisioning", namespace, name)
	}
	if cluster.Status.Phase != garagev1beta1.PhaseRunning {
		return nil, fmt.Errorf("cluster %s/%s not ready (phase=%s)", namespace, name, cluster.Status.Phase)
	}
	return cluster, nil
}

func (p *Provisioner) assertClusterProvisionable(ctx context.Context, original *garagev1beta2.GarageCluster) error {
	current := &garagev1beta2.GarageCluster{}
	key := types.NamespacedName{Name: original.Name, Namespace: original.Namespace}
	if err := p.client.Get(ctx, key, current); err != nil {
		return fmt.Errorf("recheck cluster %s before remote create: %w", key, err)
	}
	if original.UID != "" && current.UID != original.UID {
		return fmt.Errorf("cluster %s was recreated during COSI provisioning", key)
	}
	if !current.DeletionTimestamp.IsZero() {
		return fmt.Errorf("cluster %s is deleting; refusing remote COSI creation", key)
	}
	if current.Status.Phase != garagev1beta1.PhaseRunning {
		return fmt.Errorf("cluster %s is no longer ready (phase=%s)", key, current.Status.Phase)
	}
	return nil
}

func (p *Provisioner) buildBucketResult(ctx context.Context, bucketID string, cluster *garagev1beta2.GarageCluster) (*BucketResult, error) {
	alias, err := p.shadowManager.GetShadowBucketGlobalAliasByID(ctx, bucketID)
	if err != nil {
		return nil, fmt.Errorf("global alias for %s not found: %w", bucketID, err)
	}
	endpoint, err := p.getS3Endpoint(cluster)
	if err != nil {
		return nil, err
	}
	return &BucketResult{
		BucketID:    bucketID,
		GlobalAlias: alias,
		Endpoint:    endpoint,
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

func (p *Provisioner) getS3Endpoint(cluster *garagev1beta2.GarageCluster) (string, error) {
	parsed, err := controller.ResolveS3Endpoint(cluster, p.clusterDomain)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
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

func validateBucketClassQuotas(params *BucketClassParameters) error {
	if params == nil {
		return fmt.Errorf("bucket class parameters are required")
	}
	if params.MaxSize != nil && params.MaxSize.Sign() < 0 {
		return fmt.Errorf("maxSize must not be negative")
	}
	if params.MaxObjects != nil && *params.MaxObjects < 0 {
		return fmt.Errorf("maxObjects must not be negative")
	}
	return nil
}
