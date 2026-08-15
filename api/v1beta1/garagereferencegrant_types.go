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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageReferenceGrantSpec defines which namespaces and resource kinds are
// permitted to make cross-namespace references to resources in this namespace.
type GarageReferenceGrantSpec struct {
	// From lists the permitted sources of cross-namespace references.
	// +kubebuilder:validation:MinItems=1
	// +required
	From []ReferenceGrantFrom `json:"from"`

	// To lists the target resource kinds (and optionally specific names) that
	// may be referenced. If omitted, all GarageCluster and GarageBucket resources
	// in this namespace are accessible. This preserves the original grant
	// behavior; newer target kinds such as GarageKey require an explicit entry.
	// +optional
	To []ReferenceGrantTo `json:"to,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.namespace) != has(self.namespaceSelector)",message="exactly one of namespace or namespaceSelector must be set"
//
// ReferenceGrantFrom specifies a permitted source namespace (by exact name or
// labels) and resource kind.
type ReferenceGrantFrom struct {
	// Kind is the resource kind allowed to make cross-namespace references.
	// GarageAdminToken remains in the schema for compatibility, but the static
	// credential path is namespace-local and does not accept cross-namespace grants.
	// +kubebuilder:validation:Enum=GarageKey;GarageBucket;GarageAdminToken
	// +required
	Kind string `json:"kind"`

	// Namespace is the exact namespace from which cross-namespace references are
	// allowed. Exactly one of Namespace or NamespaceSelector must be set.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// NamespaceSelector selects source namespaces by their Kubernetes labels.
	// Exactly one of Namespace or NamespaceSelector must be set. An empty
	// selector matches every namespace.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// ReferenceGrantTo specifies a target resource kind and optionally a specific name.
type ReferenceGrantTo struct {
	// Kind is the target resource kind.
	// +kubebuilder:validation:Enum=GarageCluster;GarageBucket;GarageKey
	// +required
	Kind string `json:"kind"`

	// Name restricts access to a specific resource. If omitted, all resources of
	// the given kind in this namespace are accessible.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Name string `json:"name,omitempty"`
}

// GarageReferenceGrantStatus reflects which resources are currently using this grant.
type GarageReferenceGrantStatus struct {
	// InUseBy lists resources currently referencing through this grant.
	// Rebuilt on every reconcile — safe to delete when this is empty.
	// +optional
	InUseBy []ReferenceGrantUser `json:"inUseBy,omitempty"`

	// Conditions represent the current state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ReferenceGrantUser identifies a resource using this grant.
type ReferenceGrantUser struct {
	// Kind of the referencing resource.
	// +optional
	Kind string `json:"kind,omitempty"`
	// Name of the referencing resource.
	// +optional
	Name string `json:"name,omitempty"`
	// Namespace of the referencing resource.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=grg,scope=Namespaced
// +kubebuilder:printcolumn:name="InUse",type="string",JSONPath=".status.conditions[?(@.type=='InUse')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageReferenceGrant grants permission for resources in other namespaces to
// reference GarageCluster, GarageBucket, or GarageKey resources in this namespace.
// GarageAdminToken remains a listed source kind for schema/status compatibility,
// but its static credential path is namespace-local and does not accept a grant.
//
// This resource must be created in the destination namespace (where the
// referenced GarageCluster, GarageBucket, or GarageKey lives). Only admins of that namespace can
// create it, so tenants cannot self-grant cross-namespace access.
//
// Example: allow GarageKey objects in namespace "team-b" to reference
// GarageCluster "my-cluster" in namespace "storage-admin":
//
//	apiVersion: garage.rajsingh.info/v1beta1
//	kind: GarageReferenceGrant
//	metadata:
//	  namespace: storage-admin
//	spec:
//	  from:
//	    - kind: GarageKey
//	      namespace: team-b
//	  to:
//	    - kind: GarageCluster
//	      name: my-cluster
//
// Namespace selectors provide the same authorization using labels. Namespace
// labels are part of this authorization decision: namespaces that gain a
// matching label gain access, and namespaces that lose it no longer match.
type GarageReferenceGrant struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageReferenceGrantSpec `json:"spec"`

	// +optional
	Status GarageReferenceGrantStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageReferenceGrantList contains a list of GarageReferenceGrant
type GarageReferenceGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageReferenceGrant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageReferenceGrant{}, &GarageReferenceGrantList{})
}
