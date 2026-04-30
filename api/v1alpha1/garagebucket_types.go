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

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageBucketSpec defines the desired state of GarageBucket
type GarageBucketSpec struct {
	// ClusterRef references the GarageCluster this bucket belongs to
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// GlobalAlias is the global alias for this bucket (optional)
	// If not set, the bucket name from metadata.name is used
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// LocalAliases are per-key local aliases for this bucket
	// +optional
	LocalAliases []LocalAlias `json:"localAliases,omitempty"`

	// Quotas configures bucket quotas
	// +optional
	Quotas *BucketQuotas `json:"quotas,omitempty"`

	// Website configures static website hosting for this bucket.
	// Note: Only indexDocument and errorDocument are supported via the Admin API.
	// For advanced features (routing rules, redirectAll), use S3 PutBucketWebsite API directly.
	// +optional
	Website *WebsiteConfig `json:"website,omitempty"`

	// KeyPermissions grants access to specific GarageKeys.
	//
	// Note: Permissions can be granted from either direction:
	// - Here (GarageBucket.keyPermissions): Grant keys access to this bucket
	// - On GarageKey (GarageKey.bucketPermissions): Grant the key access to buckets
	//
	// Both approaches are equivalent and result in the same Garage API calls.
	// Use whichever is more convenient for your workflow:
	// - Bucket-centric: Define all key access on the bucket
	// - Key-centric: Define all bucket access on the key
	//
	// If the same permission is defined in both places, they are merged (not conflicting).
	// +optional
	KeyPermissions []KeyPermission `json:"keyPermissions,omitempty"`

	// Lifecycle configures bucket lifecycle policies (object expiration,
	// abort of incomplete multipart uploads).
	//
	// Garage exposes lifecycle only via the S3 API, not the admin API. The
	// operator applies rules using an internal access key it manages per
	// GarageCluster. Garage supports a strict subset of the AWS S3 lifecycle
	// spec: only Expiration (days or date, no ExpiredObjectDeleteMarker) and
	// AbortIncompleteMultipartUpload. Filters support prefix and object size
	// bounds; tag filters and the deprecated rule-level Prefix are not
	// accepted.
	//
	// Garage's lifecycle worker runs daily at midnight (UTC by default), so
	// rule evaluation is asynchronous from reconciliation.
	// +optional
	Lifecycle *BucketLifecycle `json:"lifecycle,omitempty"`
}

// LocalAlias represents a per-key local alias for a bucket
type LocalAlias struct {
	// KeyRef references the GarageKey
	// +required
	KeyRef string `json:"keyRef"`

	// Alias is the local alias name
	// +required
	Alias string `json:"alias"`
}

// BucketQuotas configures bucket quotas
type BucketQuotas struct {
	// MaxSize is the maximum bucket size in bytes
	// +optional
	MaxSize *resource.Quantity `json:"maxSize,omitempty"`

	// MaxObjects is the maximum number of objects
	// +optional
	MaxObjects *int64 `json:"maxObjects,omitempty"`
}

// WebsiteConfig configures static website hosting.
// Only indexDocument and errorDocument are supported via the Garage Admin API.
// For routing rules and redirectAll, use the S3 PutBucketWebsite API directly.
type WebsiteConfig struct {
	// Enabled enables static website hosting
	// +optional
	Enabled bool `json:"enabled"`

	// IndexDocument is the default index document (default: index.html)
	// +kubebuilder:default="index.html"
	// +optional
	IndexDocument string `json:"indexDocument,omitempty"`

	// ErrorDocument is the error document to serve for 404s
	// +optional
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// BucketLifecycle is a set of lifecycle rules applied to a bucket.
type BucketLifecycle struct {
	// Rules to apply. The operator replaces the bucket's lifecycle
	// configuration with this exact set on each reconcile.
	// +optional
	Rules []LifecycleRule `json:"rules,omitempty"`
}

// LifecycleRule is a single lifecycle rule. At least one action
// (ExpirationDays, ExpirationDate, AbortIncompleteMultipartUploadDays)
// must be set. ExpirationDays and ExpirationDate are mutually exclusive.
type LifecycleRule struct {
	// ID is the rule identifier. Must be unique within the bucket.
	// +required
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`

	// Status enables or disables this rule. Disabled rules are sent to
	// Garage but skipped by the lifecycle worker.
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +kubebuilder:default=Enabled
	// +optional
	Status string `json:"status,omitempty"`

	// Filter narrows the rule to a subset of objects. If unset, the rule
	// applies to every object in the bucket.
	// +optional
	Filter *LifecycleFilter `json:"filter,omitempty"`

	// ExpirationDays expires current objects this many days after creation.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ExpirationDays *int32 `json:"expirationDays,omitempty"`

	// ExpirationDate expires current objects on or after this UTC date.
	// +optional
	ExpirationDate *metav1.Time `json:"expirationDate,omitempty"`

	// AbortIncompleteMultipartUploadDays aborts multipart uploads that have
	// been pending for at least this many days.
	// +kubebuilder:validation:Minimum=1
	// +optional
	AbortIncompleteMultipartUploadDays *int32 `json:"abortIncompleteMultipartUploadDays,omitempty"`
}

// LifecycleFilter narrows a lifecycle rule to a subset of objects.
type LifecycleFilter struct {
	// Prefix matches object keys starting with this string.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// ObjectSizeGreaterThan matches objects strictly larger than this many
	// bytes.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ObjectSizeGreaterThan *int64 `json:"objectSizeGreaterThan,omitempty"`

	// ObjectSizeLessThan matches objects strictly smaller than this many
	// bytes.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ObjectSizeLessThan *int64 `json:"objectSizeLessThan,omitempty"`
}

// KeyPermission grants access to a key
type KeyPermission struct {
	// KeyRef references the GarageKey by name
	// +required
	KeyRef string `json:"keyRef"`

	// Read allows reading objects
	// +optional
	Read bool `json:"read"`

	// Write allows writing objects
	// +optional
	Write bool `json:"write"`

	// Owner allows bucket owner operations
	// +optional
	Owner bool `json:"owner"`
}

// GarageBucketStatus defines the observed state of GarageBucket
type GarageBucketStatus struct {
	// BucketID is the internal Garage bucket ID
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// Phase represents the current phase
	// +optional
	Phase string `json:"phase,omitempty"`

	// GlobalAlias is the assigned global alias
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// CreatedAt is when the bucket was created in Garage
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	// Size is the current bucket size
	// +optional
	Size string `json:"size,omitempty"`

	// ObjectCount is the current object count
	// +optional
	ObjectCount int64 `json:"objectCount,omitempty"`

	// IncompleteUploads is the count of incomplete multipart uploads
	// +optional
	IncompleteUploads int64 `json:"incompleteUploads,omitempty"`

	// IncompleteUploadParts is the count of parts in incomplete multipart uploads
	// +optional
	IncompleteUploadParts int64 `json:"incompleteUploadParts,omitempty"`

	// IncompleteUploadBytes is the total bytes in incomplete multipart uploads
	// +optional
	IncompleteUploadBytes int64 `json:"incompleteUploadBytes,omitempty"`

	// WebsiteEnabled indicates if website hosting is currently enabled
	// +optional
	WebsiteEnabled bool `json:"websiteEnabled"`

	// WebsiteURL is the computed website URL (if website hosting is enabled)
	// +optional
	WebsiteURL string `json:"websiteUrl,omitempty"`

	// WebsiteConfig shows the current website configuration details
	// +optional
	WebsiteConfig *WebsiteConfigStatus `json:"websiteConfig,omitempty"`

	// QuotaUsage shows current quota consumption
	// +optional
	QuotaUsage *QuotaUsageStatus `json:"quotaUsage,omitempty"`

	// Keys contains keys with access to this bucket
	// +optional
	Keys []BucketKeyStatus `json:"keys,omitempty"`

	// LocalAliases tracks per-key local aliases for this bucket
	// +optional
	LocalAliases []LocalAliasStatus `json:"localAliases,omitempty"`

	// LifecycleRules summarises lifecycle rules currently applied to the
	// bucket in Garage. Spec is the source of truth for rule contents; this
	// list reports id and enabled state only.
	// +optional
	LifecycleRules []LifecycleRuleStatus `json:"lifecycleRules,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// QuotaUsageStatus shows quota consumption for a bucket
type QuotaUsageStatus struct {
	// SizeBytes is the current size in bytes
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// SizeLimit is the configured size limit in bytes (0 = unlimited)
	// +optional
	SizeLimit int64 `json:"sizeLimit,omitempty"`

	// SizePercent is the percentage of size quota used
	// +optional
	SizePercent int32 `json:"sizePercent,omitempty"`

	// ObjectCount is the current object count
	// +optional
	ObjectCount int64 `json:"objectCount,omitempty"`

	// ObjectLimit is the configured object limit (0 = unlimited)
	// +optional
	ObjectLimit int64 `json:"objectLimit,omitempty"`

	// ObjectPercent is the percentage of object quota used
	// +optional
	ObjectPercent int32 `json:"objectPercent,omitempty"`
}

// BucketKeyStatus shows key access status
type BucketKeyStatus struct {
	// KeyID is the access key ID
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// Name is the key name
	// +optional
	Name string `json:"name,omitempty"`

	// Permissions granted to this key
	// +optional
	Permissions BucketKeyPermissions `json:"permissions,omitempty"`
}

// BucketKeyPermissions shows key permissions
type BucketKeyPermissions struct {
	// Read permission
	// +optional
	Read bool `json:"read"`

	// Write permission
	// +optional
	Write bool `json:"write"`

	// Owner permission
	// +optional
	Owner bool `json:"owner"`
}

// LocalAliasStatus shows the status of a local alias for this bucket
type LocalAliasStatus struct {
	// KeyID is the access key ID that owns this alias
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// KeyName is the friendly name of the key
	// +optional
	KeyName string `json:"keyName,omitempty"`

	// Alias is the local alias name
	// +optional
	Alias string `json:"alias,omitempty"`
}

// LifecycleRuleStatus reports the id and enabled state of a lifecycle rule
// currently applied to the bucket.
type LifecycleRuleStatus struct {
	// ID of the rule.
	ID string `json:"id"`

	// Status is Enabled or Disabled.
	Status string `json:"status"`
}

// WebsiteConfigStatus shows the current website configuration from Garage
// Note: Only indexDocument and errorDocument are returned by the Admin API.
// Routing rules and redirectAll are S3-API-only features and not visible here.
type WebsiteConfigStatus struct {
	// IndexDocument is the configured index document
	// +optional
	IndexDocument string `json:"indexDocument,omitempty"`

	// ErrorDocument is the configured error document
	// +optional
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gb
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Alias",type="string",JSONPath=".status.globalAlias"
// +kubebuilder:printcolumn:name="Size",type="string",JSONPath=".status.size"
// +kubebuilder:printcolumn:name="Objects",type="integer",JSONPath=".status.objectCount"
// +kubebuilder:printcolumn:name="Website",type="boolean",JSONPath=".status.websiteEnabled"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageBucket is the Schema for the garagebuckets API
type GarageBucket struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageBucketSpec `json:"spec"`

	// +optional
	Status GarageBucketStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageBucketList contains a list of GarageBucket
type GarageBucketList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageBucket `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageBucket{}, &GarageBucketList{})
}
