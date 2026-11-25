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

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageAdminTokenSpec defines the desired state of GarageAdminToken.
//
// GarageAdminToken provisions a static bootstrap Secret for the Garage Admin
// HTTP API. The referenced GarageCluster must explicitly select this Secret in
// spec.admin.adminTokenSecretRef. This resource does not create a row in
// Garage's dynamic Admin-token table, and deletion does not revoke bytes that a
// running Garage process already loaded at startup.
// Admin tokens authenticate differently from S3 keys (GarageKey) — they use
// Bearer token auth against the admin port (default 3903) instead of HMAC-SHA256.
//
// Static configured tokens always have full admin access and no server-side
// name, scope, or expiry metadata. Use Garage's Admin API directly for a
// user-managed scoped/dynamic token.
// +kubebuilder:validation:XValidation:rule="self.clusterRef == oldSelf.clusterRef",message="clusterRef is immutable after creation"
// +kubebuilder:validation:XValidation:rule="has(self.secretTemplate) == has(oldSelf.secretTemplate)",message="secretTemplate cannot be added or removed after creation"
// +kubebuilder:validation:XValidation:rule="!has(self.secretTemplate) || (((!has(self.secretTemplate.name) || size(self.secretTemplate.name) == 0) ? (!has(oldSelf.secretTemplate.name) || size(oldSelf.secretTemplate.name) == 0) : (has(oldSelf.secretTemplate.name) && self.secretTemplate.name == oldSelf.secretTemplate.name)) && (has(self.secretTemplate.tokenKey) ? self.secretTemplate.tokenKey : 'admin-token') == (has(oldSelf.secretTemplate.tokenKey) ? oldSelf.secretTemplate.tokenKey : 'admin-token') && (has(self.secretTemplate.endpointKey) ? self.secretTemplate.endpointKey : 'admin-endpoint') == (has(oldSelf.secretTemplate.endpointKey) ? oldSelf.secretTemplate.endpointKey : 'admin-endpoint') && has(self.secretTemplate.includeEndpoint) == has(oldSelf.secretTemplate.includeEndpoint) && (!has(self.secretTemplate.includeEndpoint) || self.secretTemplate.includeEndpoint == oldSelf.secretTemplate.includeEndpoint))",message="secretTemplate identity fields (name, tokenKey, endpointKey, includeEndpoint) are immutable after creation"
type GarageAdminTokenSpec struct {
	// ClusterRef references the GarageCluster this token belongs to
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// Name is retained for compatibility but rejected because static bootstrap
	// material has no Garage-side friendly name.
	// +optional
	Name string `json:"name,omitempty"`

	// ExpiresAt is retained for compatibility but rejected because static
	// configured tokens have no Garage-side expiry or revocation record.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// NeverExpires is retained for compatibility. Static configured tokens are
	// always non-expiring, so this field is deprecated and has no effect.
	// +optional
	NeverExpires bool `json:"neverExpires"`

	// SecretTemplate configures how the secret containing the token is generated
	// +optional
	SecretTemplate *AdminTokenSecretTemplate `json:"secretTemplate,omitempty"`
}

// AdminTokenSecretTemplate configures the generated secret
type AdminTokenSecretTemplate struct {
	// Name is the name of the secret to create
	// Defaults to the GarageAdminToken name
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Name string `json:"name,omitempty"`

	// Labels to add to the secret
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the secret
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// TokenKey is the key name for the admin token in the secret
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="admin-token"
	// +optional
	TokenKey string `json:"tokenKey,omitempty"`

	// IncludeEndpoint includes the admin API endpoint in the secret
	// Defaults to true if not specified
	// +optional
	IncludeEndpoint *bool `json:"includeEndpoint,omitempty"`

	// EndpointKey is the key name for the admin endpoint
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="admin-endpoint"
	// +optional
	EndpointKey string `json:"endpointKey,omitempty"`
}

// GarageAdminTokenStatus defines the observed state of GarageAdminToken
type GarageAdminTokenStatus struct {
	// TokenID is a short display fingerprint of the generated static token. It is
	// not a Garage-assigned dynamic token ID.
	// +optional
	TokenID string `json:"tokenId,omitempty"`

	// TokenDigest is the full SHA-256 digest of the static bearer. The controller
	// uses it to detect mutation of an existing generated Secret without exposing
	// any bearer bytes.
	// +optional
	TokenDigest string `json:"tokenDigest,omitempty"`

	// Phase represents the current phase
	// +kubebuilder:validation:Enum=Pending;Creating;Ready;Deleting;Failed;Expired;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// ExpiresAt is deprecated and always cleared because static configured
	// tokens have no Garage-side expiry record.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// SecretRef references the created secret
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gat,categories=garage
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="TokenID",type="string",JSONPath=".status.tokenId"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageAdminToken is the Schema for the garageadmintokens API
// It manages static Admin API bootstrap material for Garage clusters.
type GarageAdminToken struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageAdminTokenSpec `json:"spec"`

	// +optional
	Status GarageAdminTokenStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageAdminTokenList contains a list of GarageAdminToken
type GarageAdminTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageAdminToken `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageAdminToken{}, &GarageAdminTokenList{})
}
