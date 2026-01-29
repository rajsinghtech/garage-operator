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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageKeySpec defines the desired state of GarageKey
type GarageKeySpec struct {
	// ClusterRef references the GarageCluster this key belongs to
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// Name is a friendly name for this access key
	// If not set, metadata.name is used
	// +optional
	Name string `json:"name,omitempty"`

	// ImportKey imports an existing key instead of generating new credentials
	// +optional
	ImportKey *ImportKeyConfig `json:"importKey,omitempty"`

	// SecretTemplate configures how the secret is generated
	// +optional
	SecretTemplate *SecretTemplate `json:"secretTemplate,omitempty"`

	// BucketPermissions grants this key access to buckets.
	//
	// Note: Permissions can be granted from either direction:
	// - Here (GarageKey.bucketPermissions): Grant this key access to buckets
	// - On GarageBucket (GarageBucket.keyPermissions): Grant keys access to the bucket
	//
	// Both approaches are equivalent and result in the same Garage API calls.
	// Use whichever is more convenient for your workflow:
	// - Key-centric: Define all bucket access on the key
	// - Bucket-centric: Define all key access on the bucket
	//
	// If the same permission is defined in both places, they are merged (not conflicting).
	// +optional
	BucketPermissions []BucketPermission `json:"bucketPermissions,omitempty"`

	// Permissions configures key-level permissions
	// Note: For admin API access, use admin tokens configured in GarageCluster
	// +optional
	Permissions *KeyPermissions `json:"permissions,omitempty"`

	// Expiration sets when this key expires (RFC 3339 format)
	// Example: "2025-12-31T23:59:59Z"
	// Mutually exclusive with NeverExpires
	// +optional
	Expiration string `json:"expiration,omitempty"`

	// NeverExpires sets the key to never expire
	// Mutually exclusive with Expiration
	// +optional
	NeverExpires bool `json:"neverExpires,omitempty"`
}

// ImportKeyConfig allows importing existing credentials
type ImportKeyConfig struct {
	// AccessKeyID is the existing access key ID
	// +optional
	AccessKeyID string `json:"accessKeyId,omitempty"`

	// SecretAccessKey is the existing secret access key
	// +optional
	SecretAccessKey string `json:"secretAccessKey,omitempty"`

	// SecretRef references a secret containing the credentials
	// Secret should have keys: access-key-id, secret-access-key
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`
}

// SecretTemplate configures the generated secret
type SecretTemplate struct {
	// Name is the name of the secret to create
	// Defaults to the GarageKey name
	// +optional
	Name string `json:"name,omitempty"`

	// Namespace is the namespace for the secret
	// Defaults to the GarageKey namespace
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Labels to add to the secret
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the secret
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Type is the secret type
	// +kubebuilder:default="Opaque"
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`

	// AccessKeyIDKey is the key name for the access key ID
	// +kubebuilder:default="access-key-id"
	// +optional
	AccessKeyIDKey string `json:"accessKeyIdKey,omitempty"`

	// SecretAccessKeyKey is the key name for the secret access key
	// +kubebuilder:default="secret-access-key"
	// +optional
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`

	// EndpointKey is the key name for the S3 endpoint (includes http:// scheme)
	// +kubebuilder:default="endpoint"
	// +optional
	EndpointKey string `json:"endpointKey,omitempty"`

	// HostKey is the key name for the S3 host (without scheme, e.g., "host:port")
	// +kubebuilder:default="host"
	// +optional
	HostKey string `json:"hostKey,omitempty"`

	// SchemeKey is the key name for the endpoint scheme (http or https)
	// +kubebuilder:default="scheme"
	// +optional
	SchemeKey string `json:"schemeKey,omitempty"`

	// RegionKey is the key name for the S3 region
	// +kubebuilder:default="region"
	// +optional
	RegionKey string `json:"regionKey,omitempty"`

	// IncludeEndpoint includes the S3 endpoint in the secret
	// Defaults to true if not specified
	// +optional
	IncludeEndpoint *bool `json:"includeEndpoint,omitempty"`

	// IncludeRegion includes the S3 region in the secret
	// Defaults to true if not specified
	// +optional
	IncludeRegion *bool `json:"includeRegion,omitempty"`

	// AdditionalData includes additional key-value pairs in the secret
	// +optional
	AdditionalData map[string]string `json:"additionalData,omitempty"`
}

// BucketPermission grants access to a bucket
type BucketPermission struct {
	// BucketRef references the GarageBucket by name
	// +optional
	BucketRef string `json:"bucketRef,omitempty"`

	// BucketID references the bucket by its Garage ID
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// GlobalAlias references the bucket by global alias
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// Read allows reading objects from the bucket
	// +optional
	Read bool `json:"read,omitempty"`

	// Write allows writing objects to the bucket
	// +optional
	Write bool `json:"write,omitempty"`

	// Owner allows bucket owner operations (delete bucket, configure website, etc.)
	// +optional
	Owner bool `json:"owner,omitempty"`
}

// KeyPermissions configures key-level permissions in Garage
// Note: Garage's Admin API uses separate admin tokens (configured in GarageCluster),
// not S3 keys. This only controls S3-level permissions for the key.
type KeyPermissions struct {
	// CreateBucket allows this key to create new buckets via the S3 CreateBucket API
	// +optional
	CreateBucket bool `json:"createBucket,omitempty"`
}

// GarageKeyStatus defines the observed state of GarageKey
type GarageKeyStatus struct {
	// KeyID is the Garage-assigned key ID
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// AccessKeyID is the S3 access key ID
	// +optional
	AccessKeyID string `json:"accessKeyId,omitempty"`

	// Phase represents the current phase
	// +optional
	Phase string `json:"phase,omitempty"`

	// CreatedAt is when the key was created in Garage
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	// Expiration is when this key expires (if set)
	// +optional
	Expiration string `json:"expiration,omitempty"`

	// Expired indicates if this key has expired
	// +optional
	Expired bool `json:"expired,omitempty"`

	// SecretRef references the created secret
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`

	// Permissions shows the current permissions for this key
	// +optional
	Permissions *KeyPermissions `json:"permissions,omitempty"`

	// Buckets lists buckets this key has access to
	// +optional
	Buckets []KeyBucketAccess `json:"buckets,omitempty"`

	// EffectivePermissions shows merged permissions from both bucket and key definitions
	// +optional
	EffectivePermissions []EffectivePermission `json:"effectivePermissions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EffectivePermission shows the resolved permission for a bucket
type EffectivePermission struct {
	// BucketID is the bucket ID
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// BucketAlias is the bucket's global alias (if set)
	// +optional
	BucketAlias string `json:"bucketAlias,omitempty"`

	// Read permission
	// +optional
	Read bool `json:"read,omitempty"`

	// Write permission
	// +optional
	Write bool `json:"write,omitempty"`

	// Owner permission
	// +optional
	Owner bool `json:"owner,omitempty"`

	// Source indicates where this permission was defined ("bucket", "key", or "both")
	// +optional
	Source string `json:"source,omitempty"`
}

// KeyBucketAccess shows bucket access for this key
type KeyBucketAccess struct {
	// BucketID is the bucket ID
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// GlobalAlias is the bucket's global alias
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// LocalAlias is this key's local alias for the bucket
	// +optional
	LocalAlias string `json:"localAlias,omitempty"`

	// Read permission
	// +optional
	Read bool `json:"read,omitempty"`

	// Write permission
	// +optional
	Write bool `json:"write,omitempty"`

	// Owner permission
	// +optional
	Owner bool `json:"owner,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gk
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="KeyID",type="string",JSONPath=".status.keyId"
// +kubebuilder:printcolumn:name="AccessKeyID",type="string",JSONPath=".status.accessKeyId"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageKey is the Schema for the garagekeys API
type GarageKey struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageKeySpec `json:"spec"`

	// +optional
	Status GarageKeyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageKeyList contains a list of GarageKey
type GarageKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageKey{}, &GarageKeyList{})
}
