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
// GarageAdminToken provisions secrets for accessing the Garage Admin HTTP API.
// Admin tokens authenticate differently from S3 keys (GarageKey) — they use
// Bearer token auth against the admin port (default 3903) instead of HMAC-SHA256.
//
// The operator writes the token as an admin_token_file in Garage's TOML config.
// File-based tokens always have full admin access; there is no scope restriction.
// To create scoped tokens, use Garage's Admin API (CreateAdminToken) directly —
// this resource is for provisioning the full-access operator/tooling token.
type GarageAdminTokenSpec struct {
	// ClusterRef references the GarageCluster this token belongs to
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// Name is a friendly name for this admin token
	// If not set, metadata.name is used
	// +optional
	Name string `json:"name,omitempty"`

	// ExpiresAt sets when this token should be rotated.
	// The operator tracks this and sets the TokenExpired condition when the date passes,
	// but does NOT automatically rotate or revoke the token — rotation requires manual action
	// (update or delete the GarageAdminToken resource). Use NeverExpires to suppress expiry tracking.
	// Mutually exclusive with NeverExpires.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// NeverExpires sets the token to never expire.
	// Mutually exclusive with ExpiresAt.
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
	// +optional
	Name string `json:"name,omitempty"`

	// Labels to add to the secret
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the secret
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// TokenKey is the key name for the admin token in the secret
	// +kubebuilder:default="admin-token"
	// +optional
	TokenKey string `json:"tokenKey,omitempty"`

	// IncludeEndpoint includes the admin API endpoint in the secret
	// Defaults to true if not specified
	// +optional
	IncludeEndpoint *bool `json:"includeEndpoint,omitempty"`

	// EndpointKey is the key name for the admin endpoint
	// +kubebuilder:default="admin-endpoint"
	// +optional
	EndpointKey string `json:"endpointKey,omitempty"`
}

// GarageAdminTokenStatus defines the observed state of GarageAdminToken
type GarageAdminTokenStatus struct {
	// TokenID is the Garage-assigned token ID (first 8 chars)
	// +optional
	TokenID string `json:"tokenId,omitempty"`

	// Phase represents the current phase
	// +kubebuilder:validation:Enum=Pending;Creating;Ready;Deleting;Failed;Expired;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// ExpiresAt is when this token expires (if set)
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// Expired indicates if this token has expired
	// +optional
	Expired bool `json:"expired"`

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
// +kubebuilder:resource:shortName=gat
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="TokenID",type="string",JSONPath=".status.tokenId"
// +kubebuilder:printcolumn:name="Expired",type="boolean",JSONPath=".status.expired"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageAdminToken is the Schema for the garageadmintokens API
// It manages admin API tokens for Garage clusters
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
