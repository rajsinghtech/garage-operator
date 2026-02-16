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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

const (
	// LabelCOSIManaged indicates this resource was created by COSI
	LabelCOSIManaged = "garage.rajsingh.info/cosi-managed"
	// LabelCOSIBucketClaim references the BucketClaim that created this bucket
	LabelCOSIBucketClaim = "garage.rajsingh.info/cosi-bucket-claim"
	// LabelCOSIBucketAccess references the BucketAccess that created this key
	LabelCOSIBucketAccess = "garage.rajsingh.info/cosi-bucket-access"
	// LabelCOSIBucketID stores the Garage bucket ID as a label for efficient lookup
	LabelCOSIBucketID = "garage.rajsingh.info/cosi-bucket-id"
	// LabelCOSIAccountID stores the Garage key/account ID as a label for efficient lookup
	LabelCOSIAccountID = "garage.rajsingh.info/cosi-account-id"
	// AnnotationCOSIBucketID stores the Garage bucket ID for lookup during delete (kept for backwards compat)
	AnnotationCOSIBucketID = "garage.rajsingh.info/cosi-bucket-id"
	// AnnotationCOSIAccountID stores the Garage key/account ID for lookup during delete (kept for backwards compat)
	AnnotationCOSIAccountID = "garage.rajsingh.info/cosi-account-id"
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
	// Use hash to ensure name is valid K8s resource name and unique
	hash := sha256.Sum256([]byte(cosiName))
	shortHash := hex.EncodeToString(hash[:8])
	// Prefix with "cosi-" and use hash to keep under 63 chars
	name := fmt.Sprintf("cosi-%s", shortHash)
	if len(name) > 63 {
		return name[:63]
	}
	return name
}

// truncateLabelValue ensures a value is valid for use as a Kubernetes label value
// Label values must be 63 characters or less and contain only alphanumeric, '-', '_', or '.'
func truncateLabelValue(value string) string {
	if len(value) > 63 {
		return value[:63]
	}
	return value
}

// ShadowBucketLabels returns labels for a shadow GarageBucket
func ShadowBucketLabels(cosiName string) map[string]string {
	return map[string]string{
		LabelCOSIManaged:     "true",
		LabelCOSIBucketClaim: truncateLabelValue(cosiName),
	}
}

// ShadowKeyLabels returns labels for a shadow GarageKey
func ShadowKeyLabels(cosiName string) map[string]string {
	return map[string]string{
		LabelCOSIManaged:      "true",
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

// CreateShadowBucketWithID creates a shadow GarageBucket resource with bucket ID annotation
func (m *ShadowManager) CreateShadowBucketWithID(ctx context.Context, cosiName, bucketID, clusterRef, clusterNamespace string, params *BucketClassParameters) (*garagev1alpha1.GarageBucket, error) {
	name := ShadowResourceName(cosiName)

	labels := ShadowBucketLabels(cosiName)
	// Add bucket ID as label for efficient lookup (truncate if needed for label validity)
	if bucketID != "" {
		labels[LabelCOSIBucketID] = truncateLabelValue(bucketID)
	}

	bucket := &garagev1alpha1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.namespace,
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationCOSIBucketID: bucketID, // Keep full ID in annotation
			},
		},
		Spec: garagev1alpha1.GarageBucketSpec{
			ClusterRef: garagev1alpha1.ClusterReference{
				Name:      clusterRef,
				Namespace: clusterNamespace,
			},
			GlobalAlias: sanitizeBucketName(cosiName),
		},
	}

	if params != nil {
		if params.MaxSize != nil || params.MaxObjects != nil {
			bucket.Spec.Quotas = &garagev1alpha1.BucketQuotas{}
			if params.MaxSize != nil {
				bucket.Spec.Quotas.MaxSize = params.MaxSize
			}
			if params.MaxObjects != nil {
				bucket.Spec.Quotas.MaxObjects = params.MaxObjects
			}
		}
		if params.WebsiteEnabled {
			bucket.Spec.Website = &garagev1alpha1.WebsiteConfig{
				Enabled: true,
			}
		}
	}

	if err := m.client.Create(ctx, bucket); err != nil {
		return nil, err
	}
	return bucket, nil
}

// GetShadowBucketNameByID looks up the shadow GarageBucket resource name by Garage bucket ID
func (m *ShadowManager) GetShadowBucketNameByID(ctx context.Context, bucketID string) (string, error) {
	bucketList := &garagev1alpha1.GarageBucketList{}
	labelSelector := client.MatchingLabels{
		LabelCOSIManaged:  "true",
		LabelCOSIBucketID: truncateLabelValue(bucketID),
	}
	if err := m.client.List(ctx, bucketList,
		client.InNamespace(m.namespace),
		labelSelector,
	); err != nil {
		return "", err
	}
	for _, bucket := range bucketList.Items {
		if bucket.Annotations[AnnotationCOSIBucketID] == bucketID {
			return bucket.Name, nil
		}
	}
	return "", fmt.Errorf("shadow bucket not found for Garage bucket ID %s", bucketID)
}

// DeleteShadowBucketByID deletes a shadow GarageBucket resource by bucket ID
func (m *ShadowManager) DeleteShadowBucketByID(ctx context.Context, bucketID string) error {
	// Use label selector for efficient lookup
	bucketList := &garagev1alpha1.GarageBucketList{}
	labelSelector := client.MatchingLabels{
		LabelCOSIManaged:  "true",
		LabelCOSIBucketID: truncateLabelValue(bucketID),
	}
	if err := m.client.List(ctx, bucketList,
		client.InNamespace(m.namespace),
		labelSelector,
	); err != nil {
		return err
	}

	// Verify annotation matches (in case of label truncation collision)
	for _, bucket := range bucketList.Items {
		if bucket.Annotations[AnnotationCOSIBucketID] == bucketID {
			return m.client.Delete(ctx, &bucket)
		}
	}

	// Bucket not found - this is ok, might already be deleted
	return nil
}

// CreateShadowKeyWithID creates a shadow GarageKey resource with account ID annotation and all bucket permissions
func (m *ShadowManager) CreateShadowKeyWithID(ctx context.Context, cosiName, accountID, clusterRef, clusterNamespace string, permissions []BucketPermission) (*garagev1alpha1.GarageKey, error) {
	name := ShadowResourceName(cosiName)

	// Convert BucketPermission to GarageBucketPermission
	bucketPerms := make([]garagev1alpha1.BucketPermission, 0, len(permissions))
	for _, perm := range permissions {
		bucketPerms = append(bucketPerms, garagev1alpha1.BucketPermission{
			BucketRef: perm.BucketID,
			Read:      perm.Read,
			Write:     perm.Write,
			Owner:     perm.Owner,
		})
	}

	labels := ShadowKeyLabels(cosiName)
	// Add account ID as label for efficient lookup (truncate if needed for label validity)
	if accountID != "" {
		labels[LabelCOSIAccountID] = truncateLabelValue(accountID)
	}

	key := &garagev1alpha1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.namespace,
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationCOSIAccountID: accountID, // Keep full ID in annotation
			},
		},
		Spec: garagev1alpha1.GarageKeySpec{
			ClusterRef: garagev1alpha1.ClusterReference{
				Name:      clusterRef,
				Namespace: clusterNamespace,
			},
			Name:              sanitizeKeyName(cosiName),
			BucketPermissions: bucketPerms,
		},
	}

	if err := m.client.Create(ctx, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeleteShadowKeyByID deletes a shadow GarageKey resource by account ID
func (m *ShadowManager) DeleteShadowKeyByID(ctx context.Context, accountID string) error {
	// Use label selector for efficient lookup
	keyList := &garagev1alpha1.GarageKeyList{}
	labelSelector := client.MatchingLabels{
		LabelCOSIManaged:   "true",
		LabelCOSIAccountID: truncateLabelValue(accountID),
	}
	if err := m.client.List(ctx, keyList,
		client.InNamespace(m.namespace),
		labelSelector,
	); err != nil {
		return err
	}

	// Verify annotation matches (in case of label truncation collision)
	for _, key := range keyList.Items {
		if key.Annotations[AnnotationCOSIAccountID] == accountID {
			return m.client.Delete(ctx, &key)
		}
	}

	// Key not found - this is ok, might already be deleted
	return nil
}

