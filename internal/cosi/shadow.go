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
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

const (
	// LabelCOSIManaged indicates this resource was created by COSI
	LabelCOSIManaged = garagev1beta1.LabelCOSIManaged
	// LabelCOSIBucketClaim references the BucketClaim that created this bucket
	LabelCOSIBucketClaim = "garage.rajsingh.info/cosi-bucket-claim"
	// LabelCOSIBucketAccess references the BucketAccess that created this key
	LabelCOSIBucketAccess = "garage.rajsingh.info/cosi-bucket-access"
	// LabelCOSIBucketID stores the Garage bucket ID as a label for efficient lookup
	LabelCOSIBucketID = "garage.rajsingh.info/cosi-bucket-id"
	// LabelCOSIAccountID stores the Garage key/account ID as a label for efficient lookup
	LabelCOSIAccountID = "garage.rajsingh.info/cosi-account-id"
	// AnnotationCOSIBucketID stores the Garage bucket ID for lookup during delete (kept for backwards compat)
	AnnotationCOSIBucketID = garagev1beta1.AnnotationCOSIBucketID
	// AnnotationCOSIAccountID stores the Garage key/account ID for lookup during delete (kept for backwards compat)
	AnnotationCOSIAccountID = garagev1beta1.AnnotationCOSIAccountID
	// AnnotationCOSIServiceAccountName stores the Kubernetes ServiceAccount name linked to this access grant
	AnnotationCOSIServiceAccountName = "garage.rajsingh.info/cosi-service-account-name"
	annotationCOSIReservationOwner   = garagev1beta1.AnnotationCOSIReservationOwner
	annotationCOSIReservationReady   = garagev1beta1.AnnotationCOSIReservationReady
	// annotationCOSILegacyAccessUID permanently attributes an adopted
	// name-scoped pre-UID BucketAccess reservation to the first uniquely
	// identifiable BucketAccess. Once set, a later same-name object cannot
	// steal the in-flight reservation merely because its UID sorts earlier.
	annotationCOSILegacyAccessUID = "garage.rajsingh.info/cosi-legacy-bucket-access-uid"
)

// BucketPermission represents permissions for a single bucket
type BucketPermission struct {
	BucketID string
	Read     bool
	Write    bool
	Owner    bool
}

// ShadowResourceName generates a deterministic name for a shadow resource from COSI name
func ShadowResourceName(cosiName string) string {
	return garageconfig.COSIShadowResourceName(cosiName)
}

// truncateLabelValue ensures a value is valid for use as a Kubernetes label value
// Label values must be 63 characters or less and contain only alphanumeric, '-', '_', or '.'
func truncateLabelValue(value string) string {
	if len(value) <= 63 {
		return value
	}
	// Truncating a DNS name can leave '-' or '.' at the end, which is not a
	// valid label value. A digest is also collision-resistant across long COSI
	// names while keeping selectors compact.
	sum := sha256.Sum256([]byte(value))
	return "sha256-" + hex.EncodeToString(sum[:16])
}

// ShadowBucketLabels returns labels for a shadow GarageBucket
func ShadowBucketLabels(cosiName string) map[string]string {
	return map[string]string{
		LabelCOSIManaged:     paramTrue,
		LabelCOSIBucketClaim: truncateLabelValue(cosiName),
	}
}

// ShadowKeyLabels returns labels for a shadow GarageKey
func ShadowKeyLabels(cosiName string) map[string]string {
	return map[string]string{
		LabelCOSIManaged:      paramTrue,
		LabelCOSIBucketAccess: truncateLabelValue(cosiName),
	}
}

// ShadowManager handles creation and deletion of shadow resources
type ShadowManager struct {
	client    client.Client
	namespace string // Namespace where shadow resources are created
}

// NewShadowManager creates a new ShadowManager
func NewShadowManager(c client.Client, namespace string) *ShadowManager {
	return &ShadowManager{
		client:    c,
		namespace: namespace,
	}
}

func shadowBucket(cosiName, clusterRef, clusterNamespace string, params *BucketClassParameters) *garagev1beta1.GarageBucket {
	name := ShadowResourceName(cosiName)
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Labels:     ShadowBucketLabels(cosiName),
			Finalizers: []string{garagev1beta1.GarageBucketFinalizer},
			Annotations: map[string]string{
				annotationCOSIReservationOwner:                cosiName,
				garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStatePending,
			},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{
				Name:      clusterRef,
				Namespace: clusterNamespace,
			},
			GlobalAlias: sanitizeBucketName(cosiName),
		},
	}

	if params != nil {
		if params.MaxSize != nil || params.MaxObjects != nil {
			bucket.Spec.Quotas = &garagev1beta1.BucketQuotas{}
			if params.MaxSize != nil {
				bucket.Spec.Quotas.MaxSize = params.MaxSize
			}
			if params.MaxObjects != nil {
				bucket.Spec.Quotas.MaxObjects = params.MaxObjects
			}
		}
		if params.WebsiteEnabled {
			bucket.Spec.Website = &garagev1beta1.WebsiteConfig{
				Enabled: ptr.To(true),
			}
		}
	}
	return bucket
}

// ReserveShadowBucket persists the Kubernetes side of a two-phase COSI create
// before Garage is mutated. The bool reports whether this call created it.
func (m *ShadowManager) ReserveShadowBucket(ctx context.Context, cosiName, clusterRef, clusterNamespace string, params *BucketClassParameters) (*garagev1beta1.GarageBucket, bool, error) {
	bucket := shadowBucket(cosiName, clusterRef, clusterNamespace, params)
	bucket.Namespace = m.namespace
	if err := m.client.Create(ctx, bucket); err == nil {
		return bucket, true, nil
	} else if !apierrors.IsAlreadyExists(err) {
		return nil, false, err
	}

	existing := &garagev1beta1.GarageBucket{}
	if err := m.client.Get(ctx, client.ObjectKeyFromObject(bucket), existing); err != nil {
		return nil, false, err
	}
	owner := existing.Annotations[annotationCOSIReservationOwner]
	if existing.Labels[LabelCOSIManaged] != paramTrue {
		return nil, false, fmt.Errorf("refusing to overwrite non-COSI GarageBucket %s/%s", existing.Namespace, existing.Name)
	}
	if owner != cosiName && (owner != "" || existing.Labels[LabelCOSIBucketClaim] != truncateLabelValue(cosiName)) {
		return nil, false, fmt.Errorf("refusing to overwrite non-matching GarageBucket reservation %s/%s", existing.Namespace, existing.Name)
	}
	if !existing.DeletionTimestamp.IsZero() {
		return nil, false, fmt.Errorf("GarageBucket reservation %s/%s is deleting", existing.Namespace, existing.Name)
	}
	if existing.Spec.ClusterRef.Name != clusterRef || existing.Spec.ClusterRef.Namespace != clusterNamespace {
		return nil, false, fmt.Errorf("GarageBucket reservation %s/%s targets cluster %s/%s, not requested cluster %s/%s",
			existing.Namespace, existing.Name, existing.Spec.ClusterRef.Namespace, existing.Spec.ClusterRef.Name,
			clusterNamespace, clusterRef)
	}
	state := existing.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	if state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound {
		return nil, false, fmt.Errorf("GarageBucket reservation %s/%s has unknown provisioning state %q", existing.Namespace, existing.Name, state)
	}
	needsFinalizer := !containsString(existing.Finalizers, garagev1beta1.GarageBucketFinalizer)
	needsCorrelationLabel := existing.Labels[LabelCOSIBucketClaim] != truncateLabelValue(cosiName)
	if owner == "" || needsFinalizer || needsCorrelationLabel {
		patch := client.MergeFrom(existing.DeepCopy())
		if existing.Annotations == nil {
			existing.Annotations = map[string]string{}
		}
		if owner == "" {
			existing.Annotations[annotationCOSIReservationOwner] = cosiName
		}
		if needsFinalizer {
			existing.Finalizers = append(existing.Finalizers, garagev1beta1.GarageBucketFinalizer)
		}
		if needsCorrelationLabel {
			if existing.Labels == nil {
				existing.Labels = map[string]string{}
			}
			existing.Labels[LabelCOSIBucketClaim] = truncateLabelValue(cosiName)
		}
		if err := m.client.Patch(ctx, existing, patch); err != nil {
			return nil, false, err
		}
	}
	return existing, false, nil
}

// AuthorizeShadowBucketCreate records that both the requested and recovery
// aliases were absent before the first Garage create attempt.
func (m *ShadowManager) AuthorizeShadowBucketCreate(ctx context.Context, bucket *garagev1beta1.GarageBucket, recoveryAlias string) error {
	expected, err := cosiBucketReservationAlias(bucket)
	if err != nil {
		return err
	}
	if recoveryAlias != expected {
		return fmt.Errorf("COSI reservation alias %q is not bound to shadow UID %s", recoveryAlias, bucket.UID)
	}
	patch := client.MergeFrom(bucket.DeepCopy())
	if bucket.Annotations == nil {
		bucket.Annotations = map[string]string{}
	}
	bucket.Annotations[annotationCOSIReservationReady] = paramTrue
	bucket.Annotations[garagev1beta1.AnnotationCOSIReservationAlias] = recoveryAlias
	return m.client.Patch(ctx, bucket, patch)
}

func (m *ShadowManager) ClearShadowBucketReservationAlias(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	if bucket.Annotations[garagev1beta1.AnnotationCOSIReservationAlias] == "" {
		return nil
	}
	patch := client.MergeFrom(bucket.DeepCopy())
	delete(bucket.Annotations, garagev1beta1.AnnotationCOSIReservationAlias)
	delete(bucket.Annotations, annotationCOSIReservationReady)
	return m.client.Patch(ctx, bucket, patch)
}

// BindShadowBucket completes the durable handoff from the reservation to one
// exact Garage bucket ID.
func (m *ShadowManager) BindShadowBucket(ctx context.Context, bucket *garagev1beta1.GarageBucket, bucketID string, params *BucketClassParameters) (*garagev1beta1.GarageBucket, error) {
	if bucketID == "" {
		return nil, fmt.Errorf("cannot bind an empty Garage bucket ID")
	}
	if bucket.Labels[LabelCOSIManaged] != paramTrue {
		return nil, fmt.Errorf("refusing to bind non-COSI GarageBucket %s/%s", bucket.Namespace, bucket.Name)
	}
	owner := bucket.Annotations[annotationCOSIReservationOwner]
	if owner == "" {
		return nil, fmt.Errorf("refusing to bind GarageBucket %s/%s without a COSI reservation owner", bucket.Namespace, bucket.Name)
	}
	trackedID := bucket.Annotations[AnnotationCOSIBucketID]
	state := bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	if trackedID != "" && trackedID != bucketID {
		return nil, fmt.Errorf("shadow bucket %s/%s belongs to bucket %q, not %q", bucket.Namespace, bucket.Name, trackedID, bucketID)
	}
	if state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound {
		return nil, fmt.Errorf("shadow bucket %s/%s has unknown provisioning state %q", bucket.Namespace, bucket.Name, state)
	}
	if bucket.Status.BucketID != "" && bucket.Status.BucketID != bucketID {
		return nil, fmt.Errorf("shadow bucket %s/%s status belongs to bucket %q, not %q", bucket.Namespace, bucket.Name, bucket.Status.BucketID, bucketID)
	}
	if bucket.Status.BucketID == "" {
		bucket.Status.BucketID = bucketID
		if err := m.client.Status().Update(ctx, bucket); err != nil {
			return nil, fmt.Errorf("persist COSI bucket ownership status before handoff: %w", err)
		}
	}
	desired := shadowBucket(owner, bucket.Spec.ClusterRef.Name, bucket.Spec.ClusterRef.Namespace, params)
	bucket.Spec = desired.Spec
	if bucket.Labels == nil {
		bucket.Labels = map[string]string{}
	}
	bucket.Labels[LabelCOSIBucketClaim] = truncateLabelValue(owner)
	bucket.Labels[LabelCOSIBucketID] = truncateLabelValue(bucketID)
	if bucket.Annotations == nil {
		bucket.Annotations = map[string]string{}
	}
	bucket.Annotations[AnnotationCOSIBucketID] = bucketID
	bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	if err := m.client.Update(ctx, bucket); err != nil {
		return nil, err
	}
	return bucket, nil
}

// CreateShadowBucketWithID creates or binds a shadow GarageBucket. New remote
// provisioning should call ReserveShadowBucket before the Garage API write.
func (m *ShadowManager) CreateShadowBucketWithID(ctx context.Context, cosiName, bucketID, clusterRef, clusterNamespace string, params *BucketClassParameters) (*garagev1beta1.GarageBucket, error) {
	bucket, _, err := m.ReserveShadowBucket(ctx, cosiName, clusterRef, clusterNamespace, params)
	if err != nil {
		return nil, err
	}
	return m.BindShadowBucket(ctx, bucket, bucketID, params)
}

// GetShadowBucketID returns the durable Garage bucket ID recorded for a COSI
// bucket name. It lets retries resume between bare bucket creation and alias
// assignment without creating another upstream bucket.
func (m *ShadowManager) GetShadowBucketID(ctx context.Context, cosiName string) (string, error) {
	bucket := &garagev1beta1.GarageBucket{}
	key := client.ObjectKey{Name: ShadowResourceName(cosiName), Namespace: m.namespace}
	if err := m.client.Get(ctx, key, bucket); err != nil {
		return "", err
	}
	if bucket.Labels[LabelCOSIManaged] != paramTrue {
		return "", fmt.Errorf("resource %s/%s is not a COSI-managed shadow bucket", key.Namespace, key.Name)
	}
	if bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStatePending {
		return "", fmt.Errorf("shadow bucket %s/%s is still a pending reservation", key.Namespace, key.Name)
	}
	id := bucket.Annotations[AnnotationCOSIBucketID]
	if id == "" {
		return "", fmt.Errorf("shadow bucket %s/%s has no Garage bucket ID", key.Namespace, key.Name)
	}
	return id, nil
}

// RequestDeleteShadowBucketByName starts cancellation of a COSI reservation.
// It reports done only after Kubernetes no longer contains the shadow, which
// means its GarageBucket cleanup finalizer has completed remote deletion.
func (m *ShadowManager) RequestDeleteShadowBucketByName(ctx context.Context, cosiName string) (bool, error) {
	bucket := &garagev1beta1.GarageBucket{}
	key := client.ObjectKey{Name: ShadowResourceName(cosiName), Namespace: m.namespace}
	if err := m.client.Get(ctx, key, bucket); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	owner := bucket.Annotations[annotationCOSIReservationOwner]
	if bucket.Labels[LabelCOSIManaged] != paramTrue ||
		(owner != cosiName && (owner != "" || bucket.Labels[LabelCOSIBucketClaim] != truncateLabelValue(cosiName))) {
		return false, fmt.Errorf("refusing to delete non-matching GarageBucket reservation %s/%s", bucket.Namespace, bucket.Name)
	}
	if bucket.DeletionTimestamp.IsZero() {
		if err := m.client.Delete(ctx, bucket); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	return false, nil
}

// ForgetShadowBucketByName requests Kubernetes-only deletion of a COSI shadow.
// The ordinary GarageBucket controller verifies the durable UID-bound marker,
// removes its cleanup finalizer without contacting Garage, and deletes the
// shadow. The caller must retain its own finalizer until done is true.
func (m *ShadowManager) ForgetShadowBucketByName(ctx context.Context, cosiName, knownBucketID string) (bool, error) {
	bucket := &garagev1beta1.GarageBucket{}
	key := client.ObjectKey{Name: ShadowResourceName(cosiName), Namespace: m.namespace}
	if err := m.client.Get(ctx, key, bucket); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	owner := bucket.Annotations[annotationCOSIReservationOwner]
	if bucket.Labels[LabelCOSIManaged] != paramTrue ||
		(owner != cosiName && (owner != "" || bucket.Labels[LabelCOSIBucketClaim] != truncateLabelValue(cosiName))) {
		return false, fmt.Errorf("refusing to forget non-matching GarageBucket reservation %s/%s", bucket.Namespace, bucket.Name)
	}
	if knownBucketID != "" {
		if annotated := bucket.Annotations[AnnotationCOSIBucketID]; annotated != "" && annotated != knownBucketID {
			return false, fmt.Errorf("COSI Bucket status ID %q disagrees with shadow bucket ID %q", knownBucketID, annotated)
		}
		if bucket.Status.BucketID != "" && bucket.Status.BucketID != knownBucketID {
			return false, fmt.Errorf("COSI Bucket status ID %q disagrees with shadow status bucket ID %q", knownBucketID, bucket.Status.BucketID)
		}
		if bucket.Status.BucketID == "" {
			bucket.Status.BucketID = knownBucketID
			if err := m.client.Status().Update(ctx, bucket); err != nil {
				return false, fmt.Errorf("persist retained COSI bucket identity: %w", err)
			}
		}
	}
	marker, err := garagev1beta1.UIDBoundReservationAlias("cosi-retain-", bucket.Namespace, bucket.Name, bucket.UID)
	if err != nil {
		return false, err
	}
	if existing := bucket.Annotations[garagev1beta1.AnnotationCOSIRetain]; existing != "" && existing != marker {
		return false, fmt.Errorf("refusing mismatched COSI retain marker %q on GarageBucket %s/%s", existing, bucket.Namespace, bucket.Name)
	}
	state := bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	if state == "" && knownBucketID == "" {
		return false, fmt.Errorf("legacy COSI shadow %s/%s has no exact retained bucket identity", bucket.Namespace, bucket.Name)
	}
	if state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound {
		return false, fmt.Errorf("COSI shadow %s/%s has unknown provisioning state %q", bucket.Namespace, bucket.Name, state)
	}
	if bucket.Annotations[garagev1beta1.AnnotationCOSIRetain] == "" || owner == "" || state == "" {
		patch := client.MergeFrom(bucket.DeepCopy())
		if bucket.Annotations == nil {
			bucket.Annotations = make(map[string]string)
		}
		if owner == "" {
			bucket.Annotations[annotationCOSIReservationOwner] = cosiName
		}
		if state == "" {
			bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
			bucket.Annotations[AnnotationCOSIBucketID] = knownBucketID
		}
		bucket.Annotations[garagev1beta1.AnnotationCOSIRetain] = marker
		if err := m.client.Patch(ctx, bucket, patch); err != nil {
			return false, err
		}
	}
	if bucket.DeletionTimestamp.IsZero() {
		if err := m.client.Delete(ctx, bucket); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	return false, nil
}

// GetShadowBucketNameByID looks up the shadow GarageBucket resource name by Garage bucket ID
func (m *ShadowManager) GetShadowBucketNameByID(ctx context.Context, bucketID string) (string, error) {
	bucket, found, err := m.authoritativeShadowBucketByID(ctx, bucketID)
	if err != nil {
		return "", err
	}
	if found {
		return bucket.Name, nil
	}
	return "", fmt.Errorf("shadow bucket not found for Garage bucket ID %s", bucketID)
}

// GetShadowBucketGlobalAliasByID looks up the shadow GarageBucket resource globalAlias by Garage bucket ID
func (m *ShadowManager) GetShadowBucketGlobalAliasByID(ctx context.Context, bucketID string) (string, error) {
	bucket, found, err := m.authoritativeShadowBucketByID(ctx, bucketID)
	if err != nil {
		return "", err
	}
	if found && bucket.Spec.GlobalAlias != "" {
		return bucket.Spec.GlobalAlias, nil
	}
	if found {
		return "", fmt.Errorf("global alias not set for Garage bucket ID %s", bucketID)
	}
	return "", fmt.Errorf("shadow bucket not found for Garage bucket ID %s", bucketID)
}

// GetShadowBucketClusterRef recovers the authoritative cluster identity from a
// bound shadow. This keeps previously provisioned Buckets deletable when their
// historical BucketClass parameters no longer pass current provisioning rules.
func (m *ShadowManager) GetShadowBucketClusterRef(ctx context.Context, bucketID string) (name, namespace string, err error) {
	bucket, found, err := m.authoritativeShadowBucketByID(ctx, bucketID)
	if err != nil {
		return "", "", err
	}
	if found {
		return bucket.Spec.ClusterRef.Name, bucket.Spec.ClusterRef.Namespace, nil
	}
	return "", "", fmt.Errorf("shadow bucket not found for bucket ID %s", bucketID)
}

// OwnsShadowBucket reports whether this manager's shadow namespace contains
// the exact authoritative shadow for a COSI Bucket. It is used only to resume
// cleanup after a namespace-scope change; the shared driver name and finalizer
// on the cluster-scoped Bucket are not sufficient ownership proof.
func (m *ShadowManager) OwnsShadowBucket(ctx context.Context, cosiName, bucketID string) (bool, error) {
	if cosiName == "" || bucketID == "" {
		return false, nil
	}
	bucket, found, err := m.authoritativeShadowBucketByID(ctx, bucketID)
	if err != nil || !found {
		return false, err
	}
	owner := bucket.Annotations[annotationCOSIReservationOwner]
	return bucket.Name == ShadowResourceName(cosiName) &&
		bucket.Labels[LabelCOSIBucketClaim] == truncateLabelValue(cosiName) &&
		(owner == cosiName || owner == ""), nil
}

func (m *ShadowManager) authoritativeShadowBucketByID(
	ctx context.Context, bucketID string,
) (*garagev1beta1.GarageBucket, bool, error) {
	bucketList := &garagev1beta1.GarageBucketList{}
	if err := m.client.List(ctx, bucketList,
		client.InNamespace(m.namespace),
		client.MatchingLabels{
			LabelCOSIManaged:  paramTrue,
			LabelCOSIBucketID: truncateLabelValue(bucketID),
		},
	); err != nil {
		return nil, false, err
	}
	var authoritative *garagev1beta1.GarageBucket
	claimed := false
	for i := range bucketList.Items {
		bucket := &bucketList.Items[i]
		if bucket.Annotations[AnnotationCOSIBucketID] != bucketID {
			continue
		}
		claimed = true
		state := bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
		if bucket.Status.BucketID != bucketID ||
			(state != "" && bucket.Annotations[annotationCOSIReservationOwner] == "") ||
			(state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound) {
			continue
		}
		if authoritative != nil {
			return nil, false, fmt.Errorf("multiple authoritative COSI shadows claim Garage bucket ID %s", bucketID)
		}
		authoritative = bucket
	}
	if authoritative != nil {
		return authoritative, true, nil
	}
	if claimed {
		return nil, false, fmt.Errorf("refusing COSI bucket ID %s without matching controller-owned shadow status", bucketID)
	}
	return nil, false, nil
}

// DeleteShadowBucketByID deletes a shadow GarageBucket resource by bucket ID
func (m *ShadowManager) DeleteShadowBucketByID(ctx context.Context, bucketID string) error {
	bucket, found, err := m.authoritativeShadowBucketByID(ctx, bucketID)
	if err != nil {
		return err
	}
	if found {
		return m.deleteShadow(ctx, bucket, garagev1beta1.GarageBucketFinalizer)
	}
	return nil
}

// DeleteShadowBucketReservation removes a pending reservation only after its
// caller has proved no Garage bucket was created for it.
func (m *ShadowManager) DeleteShadowBucketReservation(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	return m.deleteShadow(ctx, bucket, garagev1beta1.GarageBucketFinalizer)
}

func shadowKey(cosiName, clusterRef, clusterNamespace string, permissions []BucketPermission, serviceAccountName string) *garagev1beta1.GarageKey {
	name := ShadowResourceName(cosiName)

	// Convert BucketPermission to GarageBucketPermission
	bucketPerms := make([]garagev1beta1.BucketPermission, 0, len(permissions))
	for _, perm := range permissions {
		bucketPerms = append(bucketPerms, garagev1beta1.BucketPermission{
			BucketID: perm.BucketID,
			Read:     perm.Read,
			Write:    perm.Write,
			Owner:    perm.Owner,
		})
	}

	annotations := map[string]string{
		annotationCOSIReservationOwner:                cosiName,
		garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStatePending,
	}
	if serviceAccountName != "" {
		annotations[AnnotationCOSIServiceAccountName] = serviceAccountName
	}

	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      ShadowKeyLabels(cosiName),
			Annotations: annotations,
			Finalizers:  []string{garagev1beta1.GarageKeyFinalizer},
		},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{
				Name:      clusterRef,
				Namespace: clusterNamespace,
			},
			Name:              sanitizeKeyName(cosiName),
			BucketPermissions: bucketPerms,
		},
	}
	return key
}

// ReserveShadowKey persists the desired COSI key relationship before any
// Garage key is imported. The bool reports whether this call created it.
func (m *ShadowManager) ReserveShadowKey(ctx context.Context, cosiName, clusterRef, clusterNamespace string, permissions []BucketPermission, serviceAccountName string) (*garagev1beta1.GarageKey, bool, error) {
	key := shadowKey(cosiName, clusterRef, clusterNamespace, permissions, serviceAccountName)
	key.Namespace = m.namespace
	if err := m.client.Create(ctx, key); err == nil {
		return key, true, nil
	} else if !apierrors.IsAlreadyExists(err) {
		return nil, false, err
	}

	existing := &garagev1beta1.GarageKey{}
	if err := m.client.Get(ctx, client.ObjectKeyFromObject(key), existing); err != nil {
		return nil, false, err
	}
	owner := existing.Annotations[annotationCOSIReservationOwner]
	if existing.Labels[LabelCOSIManaged] != paramTrue {
		return nil, false, fmt.Errorf("refusing to overwrite non-COSI GarageKey %s/%s", existing.Namespace, existing.Name)
	}
	if owner != cosiName && (owner != "" || existing.Labels[LabelCOSIBucketAccess] != truncateLabelValue(cosiName)) {
		return nil, false, fmt.Errorf("refusing to overwrite non-matching GarageKey reservation %s/%s", existing.Namespace, existing.Name)
	}
	if !existing.DeletionTimestamp.IsZero() {
		return nil, false, fmt.Errorf("GarageKey reservation %s/%s is deleting", existing.Namespace, existing.Name)
	}
	if existing.Spec.ClusterRef.Name != clusterRef || existing.Spec.ClusterRef.Namespace != clusterNamespace {
		return nil, false, fmt.Errorf("GarageKey reservation %s/%s targets cluster %s/%s, not requested cluster %s/%s",
			existing.Namespace, existing.Name, existing.Spec.ClusterRef.Namespace, existing.Spec.ClusterRef.Name,
			clusterNamespace, clusterRef)
	}
	state := existing.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	if state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound {
		return nil, false, fmt.Errorf("GarageKey reservation %s/%s has unknown provisioning state %q", existing.Namespace, existing.Name, state)
	}
	needsFinalizer := !containsString(existing.Finalizers, garagev1beta1.GarageKeyFinalizer)
	needsCorrelationLabel := existing.Labels[LabelCOSIBucketAccess] != truncateLabelValue(cosiName)
	if owner == "" || needsFinalizer || needsCorrelationLabel {
		patch := client.MergeFrom(existing.DeepCopy())
		if existing.Annotations == nil {
			existing.Annotations = map[string]string{}
		}
		if owner == "" {
			existing.Annotations[annotationCOSIReservationOwner] = cosiName
		}
		if needsFinalizer {
			existing.Finalizers = append(existing.Finalizers, garagev1beta1.GarageKeyFinalizer)
		}
		if needsCorrelationLabel {
			if existing.Labels == nil {
				existing.Labels = map[string]string{}
			}
			existing.Labels[LabelCOSIBucketAccess] = truncateLabelValue(cosiName)
		}
		if err := m.client.Patch(ctx, existing, patch); err != nil {
			return nil, false, err
		}
	}
	return existing, false, nil
}

// BucketAccessIdentityResolution describes both the authoritative shadow and
// any UID-scoped duplicate that must be removed before reconciliation proceeds.
type BucketAccessIdentityResolution struct {
	Identity                   string
	OwnsLegacyAccount          bool
	SharedLegacyAccount        bool
	DuplicateCanonicalIdentity string
}

// ResolveBucketAccessIdentity returns the UID-scoped identity used for all new
// BucketAccess shadows. A bound pre-v0.7.4 name-scoped shadow is adopted only
// when controller-owned status and the BucketAccess status both prove the same
// exact Garage key; otherwise sharing a legacy name across namespaces fails
// closed instead of exposing credentials.
func (m *ShadowManager) ResolveBucketAccessIdentity(
	ctx context.Context, accessNamespace, accessName, accessUID, knownAccountID, driverName string,
) (BucketAccessIdentityResolution, error) {
	resolved := func(identity string, ownsLegacyAccount, sharedLegacyAccount bool, duplicateCanonical string) (BucketAccessIdentityResolution, error) {
		return BucketAccessIdentityResolution{
			Identity:                   identity,
			OwnsLegacyAccount:          ownsLegacyAccount,
			SharedLegacyAccount:        sharedLegacyAccount,
			DuplicateCanonicalIdentity: duplicateCanonical,
		}, nil
	}
	if accessUID == "" {
		return BucketAccessIdentityResolution{}, fmt.Errorf("BucketAccess UID is required for COSI key identity")
	}
	if driverName == "" {
		return BucketAccessIdentityResolution{}, fmt.Errorf("BucketAccess driver name is required for COSI key identity")
	}
	canonical := "ba-" + accessUID
	duplicateCanonical := ""
	canonicalKey := client.ObjectKey{Name: ShadowResourceName(canonical), Namespace: m.namespace}
	canonicalShadow := &garagev1beta1.GarageKey{}
	if err := m.client.Get(ctx, canonicalKey, canonicalShadow); err == nil {
		if canonicalShadow.Labels[LabelCOSIManaged] != paramTrue ||
			canonicalShadow.Annotations[annotationCOSIReservationOwner] != canonical {
			return BucketAccessIdentityResolution{}, fmt.Errorf("refusing non-matching canonical BucketAccess shadow %s", canonicalKey)
		}
		canonicalIDs := shadowKeyAccountIDs(canonicalShadow)
		if knownAccountID == "" || (len(canonicalIDs) == 1 && canonicalIDs[knownAccountID]) {
			return resolved(canonical, false, false, "")
		}
		duplicateCanonical = canonical
	} else if !apierrors.IsNotFound(err) {
		return BucketAccessIdentityResolution{}, err
	}

	legacyKey := client.ObjectKey{Name: ShadowResourceName(accessName), Namespace: m.namespace}
	legacy := &garagev1beta1.GarageKey{}
	if err := m.client.Get(ctx, legacyKey, legacy); err != nil {
		if apierrors.IsNotFound(err) {
			return resolved(canonical, false, false, duplicateCanonical)
		}
		return BucketAccessIdentityResolution{}, err
	}
	legacyOwner := legacy.Annotations[annotationCOSIReservationOwner]
	if legacy.Labels[LabelCOSIManaged] != paramTrue ||
		(legacyOwner != accessName && (legacyOwner != "" || legacy.Labels[LabelCOSIBucketAccess] != truncateLabelValue(accessName))) {
		return resolved(canonical, false, false, duplicateCanonical)
	}
	legacyID := legacy.Status.AccessKeyID
	if legacyID == "" {
		legacyID = legacy.Status.KeyID
	}
	accesses := &cosiv1alpha2.BucketAccessList{}
	if err := m.client.List(ctx, accesses); err != nil {
		return BucketAccessIdentityResolution{}, fmt.Errorf("list BucketAccesses for legacy identity attribution: %w", err)
	}
	candidates := make([]*cosiv1alpha2.BucketAccess, 0)
	for i := range accesses.Items {
		candidate := &accesses.Items[i]
		if candidate.Name != accessName || candidate.Status.DriverName != driverName {
			continue
		}
		if knownAccountID != "" {
			if candidate.Status.AccountID != knownAccountID {
				continue
			}
		} else if candidate.Status.AccountID != "" {
			continue
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool { return string(candidates[i].UID) < string(candidates[j].UID) })
	isCurrent := func(candidate *cosiv1alpha2.BucketAccess) bool {
		return candidate.Namespace == accessNamespace && string(candidate.UID) == accessUID
	}
	currentIndex := -1
	for i, candidate := range candidates {
		if isCurrent(candidate) {
			currentIndex = i
			break
		}
	}

	if knownAccountID != "" && legacyID == knownAccountID && legacy.Annotations[AnnotationCOSIAccountID] == knownAccountID {
		if currentIndex < 0 {
			return BucketAccessIdentityResolution{}, fmt.Errorf("BucketAccess %s/%s UID %s was not present while attributing legacy account %s", accessNamespace, accessName, accessUID, knownAccountID)
		}

		live := make([]*cosiv1alpha2.BucketAccess, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.DeletionTimestamp.IsZero() {
				live = append(live, candidate)
			}
		}
		current := candidates[currentIndex]
		if !current.DeletionTimestamp.IsZero() {
			if len(live) > 0 {
				return resolved(canonical, false, true, duplicateCanonical)
			}
			cleanupCandidates := make([]*cosiv1alpha2.BucketAccess, 0, len(candidates))
			for _, candidate := range candidates {
				if _, handedOff := candidate.Annotations[cosiv1alpha2.SidecarCleanupFinishedAnnotation]; !handedOff {
					cleanupCandidates = append(cleanupCandidates, candidate)
				}
			}
			if len(cleanupCandidates) > 0 && isCurrent(cleanupCandidates[0]) {
				return resolved(accessName, true, false, duplicateCanonical)
			}
			return resolved(canonical, false, true, duplicateCanonical)
		}

		ownerUID := legacy.Annotations[annotationCOSILegacyAccessUID]
		ownerIndex := 0
		if ownerUID != "" {
			for i, candidate := range live {
				if string(candidate.UID) == ownerUID {
					ownerIndex = i
					break
				}
			}
		}
		shared := len(live) > 1
		if isCurrent(live[ownerIndex]) {
			return resolved(accessName, true, shared, duplicateCanonical)
		}
		return resolved(canonical, false, shared, duplicateCanonical)
	}

	if knownAccountID == "" && legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStatePending {
		if ownerUID := legacy.Annotations[annotationCOSILegacyAccessUID]; ownerUID != "" {
			if ownerUID == accessUID {
				return resolved(accessName, true, false, duplicateCanonical)
			}
			return resolved(canonical, false, false, duplicateCanonical)
		}
		if currentIndex < 0 {
			return BucketAccessIdentityResolution{}, fmt.Errorf("BucketAccess %s/%s UID %s was not present while attributing pending legacy reservation", accessNamespace, accessName, accessUID)
		}
		if len(candidates) > 0 {
			winnerUID := string(candidates[0].UID)
			legacy.Annotations[annotationCOSILegacyAccessUID] = winnerUID
			if err := m.client.Update(ctx, legacy); err != nil {
				return BucketAccessIdentityResolution{}, fmt.Errorf("persist legacy BucketAccess reservation owner UID: %w", err)
			}
			if winnerUID == accessUID {
				return resolved(accessName, true, false, duplicateCanonical)
			}
			return resolved(canonical, false, false, duplicateCanonical)
		}
	}
	return resolved(canonical, false, false, duplicateCanonical)
}

func shadowKeyAccountIDs(key *garagev1beta1.GarageKey) map[string]bool {
	ids := make(map[string]bool, 3)
	for _, id := range []string{key.Annotations[AnnotationCOSIAccountID], key.Status.AccessKeyID, key.Status.KeyID} {
		if id != "" {
			ids[id] = true
		}
	}
	return ids
}

func shadowKeyStatusAccountIDs(key *garagev1beta1.GarageKey) map[string]bool {
	ids := make(map[string]bool, 2)
	for _, id := range []string{key.Status.AccessKeyID, key.Status.KeyID} {
		if id != "" {
			ids[id] = true
		}
	}
	return ids
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// SetShadowKeyReservationID records exact, replayable key material identity
// before ImportKey is called.
func (m *ShadowManager) SetShadowKeyReservationID(ctx context.Context, key *garagev1beta1.GarageKey, accountID string) error {
	if accountID == "" {
		return fmt.Errorf("cannot reserve an empty Garage account ID")
	}
	if tracked := key.Annotations[AnnotationCOSIAccountID]; tracked != "" && tracked != accountID {
		return fmt.Errorf("shadow key %s/%s reserves account %q, not %q", key.Namespace, key.Name, tracked, accountID)
	}
	if err := m.persistShadowKeyStatusID(ctx, key, "", accountID); err != nil {
		return err
	}
	patch := client.MergeFrom(key.DeepCopy())
	if key.Annotations == nil {
		key.Annotations = map[string]string{}
	}
	key.Annotations[AnnotationCOSIAccountID] = accountID
	return m.client.Patch(ctx, key, patch)
}

// ReplaceShadowKeyReservationID rotates a still-pending reservation only after
// the caller has proved the previously recorded Garage key does not exist.
// Bound ownership is immutable and must never use this recovery path.
func (m *ShadowManager) ReplaceShadowKeyReservationID(ctx context.Context, key *garagev1beta1.GarageKey, previousID, accountID string) error {
	if previousID == "" || accountID == "" {
		return fmt.Errorf("both previous and replacement Garage account IDs are required")
	}
	if key.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] != garagev1beta1.COSIProvisioningStatePending {
		return fmt.Errorf("cannot replace account ID on non-pending shadow key %s/%s", key.Namespace, key.Name)
	}
	if tracked := key.Annotations[AnnotationCOSIAccountID]; tracked != previousID {
		return fmt.Errorf("shadow key %s/%s reserves account %q, not expected previous account %q", key.Namespace, key.Name, tracked, previousID)
	}
	if err := m.persistShadowKeyStatusID(ctx, key, previousID, accountID); err != nil {
		return err
	}
	patch := client.MergeFrom(key.DeepCopy())
	key.Annotations[AnnotationCOSIAccountID] = accountID
	return m.client.Patch(ctx, key, patch)
}

// BindShadowKey completes the durable handoff to one exact Garage key ID.
func (m *ShadowManager) BindShadowKey(ctx context.Context, key *garagev1beta1.GarageKey, accountID string, permissions []BucketPermission, serviceAccountName string) (*garagev1beta1.GarageKey, error) {
	if accountID == "" {
		return nil, fmt.Errorf("cannot bind an empty Garage account ID")
	}
	if key.Labels[LabelCOSIManaged] != paramTrue {
		return nil, fmt.Errorf("refusing to bind non-COSI GarageKey %s/%s", key.Namespace, key.Name)
	}
	owner := key.Annotations[annotationCOSIReservationOwner]
	if owner == "" {
		return nil, fmt.Errorf("refusing to bind GarageKey %s/%s without a COSI reservation owner", key.Namespace, key.Name)
	}
	if tracked := key.Annotations[AnnotationCOSIAccountID]; tracked != "" && tracked != accountID {
		return nil, fmt.Errorf("shadow key %s/%s belongs to account %q, not %q", key.Namespace, key.Name, tracked, accountID)
	}
	if err := m.persistShadowKeyStatusID(ctx, key, "", accountID); err != nil {
		return nil, err
	}
	desired := shadowKey(owner, key.Spec.ClusterRef.Name, key.Spec.ClusterRef.Namespace, permissions, serviceAccountName)
	key.Spec = desired.Spec
	if key.Labels == nil {
		key.Labels = map[string]string{}
	}
	key.Labels[LabelCOSIBucketAccess] = truncateLabelValue(owner)
	key.Labels[LabelCOSIAccountID] = truncateLabelValue(accountID)
	if key.Annotations == nil {
		key.Annotations = map[string]string{}
	}
	key.Annotations[AnnotationCOSIAccountID] = accountID
	key.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	if serviceAccountName != "" {
		key.Annotations[AnnotationCOSIServiceAccountName] = serviceAccountName
	}
	if err := m.client.Update(ctx, key); err != nil {
		return nil, err
	}
	return key, nil
}

// persistShadowKeyStatusID reserves deletion authority through the status
// subresource before COSI can perform ImportKey. User-settable annotations may
// corroborate this identity but cannot replace it.
func (m *ShadowManager) persistShadowKeyStatusID(ctx context.Context, key *garagev1beta1.GarageKey, replaceFrom, accountID string) error {
	for field, current := range map[string]string{
		"status.accessKeyId": key.Status.AccessKeyID,
		"status.keyId":       key.Status.KeyID,
	} {
		if current != "" && current != accountID && current != replaceFrom {
			return fmt.Errorf("shadow key %s/%s %s belongs to account %q, not %q", key.Namespace, key.Name, field, current, accountID)
		}
	}
	if key.Status.AccessKeyID == accountID && key.Status.KeyID == accountID {
		return nil
	}
	key.Status.AccessKeyID = accountID
	key.Status.KeyID = accountID
	if err := m.client.Status().Update(ctx, key); err != nil {
		return fmt.Errorf("persist COSI key ownership status before remote write: %w", err)
	}
	return nil
}

// CreateShadowKeyWithID creates or binds a GarageKey shadow. New provisioning
// should reserve and persist its exact import identity before touching Garage.
func (m *ShadowManager) CreateShadowKeyWithID(ctx context.Context, cosiName, accountID, clusterRef, clusterNamespace string, permissions []BucketPermission, serviceAccountName string) (*garagev1beta1.GarageKey, error) {
	key, _, err := m.ReserveShadowKey(ctx, cosiName, clusterRef, clusterNamespace, permissions, serviceAccountName)
	if err != nil {
		return nil, err
	}
	if err := m.SetShadowKeyReservationID(ctx, key, accountID); err != nil {
		return nil, err
	}
	return m.BindShadowKey(ctx, key, accountID, permissions, serviceAccountName)
}

// DeleteShadowKeyByID deletes a shadow GarageKey resource by account ID
func (m *ShadowManager) DeleteShadowKeyByID(ctx context.Context, accountID string) error {
	key, found, err := m.authoritativeShadowKeyByID(ctx, accountID)
	if err != nil {
		return err
	}
	if found {
		return m.deleteShadow(ctx, key, garagev1beta1.GarageKeyFinalizer)
	}
	return nil
}

func (m *ShadowManager) deleteShadow(ctx context.Context, object client.Object, finalizer string) error {
	if containsString(object.GetFinalizers(), finalizer) {
		patch := client.MergeFrom(object.DeepCopyObject().(client.Object))
		finalizers := object.GetFinalizers()
		kept := make([]string, 0, len(finalizers)-1)
		for _, existing := range finalizers {
			if existing != finalizer {
				kept = append(kept, existing)
			}
		}
		object.SetFinalizers(kept)
		if err := m.client.Patch(ctx, object, patch); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	uid := object.GetUID()
	if err := m.client.Delete(ctx, object, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// GetShadowKeyAccountID returns the durable Garage key ID recorded for a COSI
// BucketAccess name.
func (m *ShadowManager) GetShadowKeyAccountID(ctx context.Context, cosiName string) (string, error) {
	key := &garagev1beta1.GarageKey{}
	objectKey := client.ObjectKey{Name: ShadowResourceName(cosiName), Namespace: m.namespace}
	if err := m.client.Get(ctx, objectKey, key); err != nil {
		return "", err
	}
	if key.Labels[LabelCOSIManaged] != paramTrue {
		return "", fmt.Errorf("resource %s/%s is not a COSI-managed shadow key", objectKey.Namespace, objectKey.Name)
	}
	if key.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStatePending {
		return "", fmt.Errorf("shadow key %s/%s is still a pending reservation", objectKey.Namespace, objectKey.Name)
	}
	id := key.Annotations[AnnotationCOSIAccountID]
	if id == "" {
		return "", fmt.Errorf("shadow key %s/%s has no Garage account ID", objectKey.Namespace, objectKey.Name)
	}
	return id, nil
}

// RequestDeleteShadowKeyByName starts cancellation of a COSI key reservation.
// The caller must retain its own finalizer until done is true.
func (m *ShadowManager) RequestDeleteShadowKeyByName(ctx context.Context, cosiName string) (bool, error) {
	key := &garagev1beta1.GarageKey{}
	objectKey := client.ObjectKey{Name: ShadowResourceName(cosiName), Namespace: m.namespace}
	if err := m.client.Get(ctx, objectKey, key); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	owner := key.Annotations[annotationCOSIReservationOwner]
	if key.Labels[LabelCOSIManaged] != paramTrue ||
		(owner != cosiName && (owner != "" || key.Labels[LabelCOSIBucketAccess] != truncateLabelValue(cosiName))) {
		return false, fmt.Errorf("refusing to delete non-matching GarageKey reservation %s/%s", key.Namespace, key.Name)
	}
	if key.DeletionTimestamp.IsZero() {
		if err := m.client.Delete(ctx, key); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	return false, nil
}

// GetShadowKeyClusterRef looks up the cluster reference stored on the shadow key.
// Used by DriverRevokeBucketAccess when the sidecar omits Parameters from the request.
func (m *ShadowManager) GetShadowKeyClusterRef(ctx context.Context, accountID string) (name, namespace string, err error) {
	key, found, err := m.authoritativeShadowKeyByID(ctx, accountID)
	if err != nil {
		return "", "", err
	}
	if found {
		return key.Spec.ClusterRef.Name, key.Spec.ClusterRef.Namespace, nil
	}
	return "", "", fmt.Errorf("shadow key not found for account ID %s", accountID)
}

func (m *ShadowManager) authoritativeShadowKeyByID(
	ctx context.Context, accountID string,
) (*garagev1beta1.GarageKey, bool, error) {
	keyList := &garagev1beta1.GarageKeyList{}
	if err := m.client.List(ctx, keyList,
		client.InNamespace(m.namespace),
		client.MatchingLabels{
			LabelCOSIManaged:   paramTrue,
			LabelCOSIAccountID: truncateLabelValue(accountID),
		},
	); err != nil {
		return nil, false, err
	}
	var authoritative *garagev1beta1.GarageKey
	claimed := false
	for i := range keyList.Items {
		key := &keyList.Items[i]
		if key.Annotations[AnnotationCOSIAccountID] != accountID {
			continue
		}
		claimed = true
		state := key.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
		accessID, keyID := key.Status.AccessKeyID, key.Status.KeyID
		statusMatches := (accessID == accountID || keyID == accountID) &&
			(accessID == "" || accessID == accountID) && (keyID == "" || keyID == accountID)
		if !statusMatches ||
			(state != "" && key.Annotations[annotationCOSIReservationOwner] == "") ||
			(state != "" && state != garagev1beta1.COSIProvisioningStatePending && state != garagev1beta1.COSIProvisioningStateBound) {
			continue
		}
		if authoritative != nil {
			return nil, false, fmt.Errorf("multiple authoritative COSI shadows claim Garage account ID %s", accountID)
		}
		authoritative = key
	}
	if authoritative != nil {
		return authoritative, true, nil
	}
	if claimed {
		return nil, false, fmt.Errorf("refusing COSI account ID %s without matching controller-owned shadow status", accountID)
	}
	return nil, false, nil
}
