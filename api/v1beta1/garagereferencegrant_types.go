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
	// in this namespace are accessible.
	// +optional
	To []ReferenceGrantTo `json:"to,omitempty"`
}

// ReferenceGrantFrom specifies a permitted source namespace and resource kind.
type ReferenceGrantFrom struct {
	// Kind is the resource kind allowed to make cross-namespace references.
	// +kubebuilder:validation:Enum=GarageKey;GarageBucket;GarageAdminToken
	// +required
	Kind string `json:"kind"`

	// Namespace is the namespace from which cross-namespace references are allowed.
	// +kubebuilder:validation:MinLength=1
	// +required
	Namespace string `json:"namespace"`
}

// ReferenceGrantTo specifies a target resource kind and optionally a specific name.
type ReferenceGrantTo struct {
	// Kind is the target resource kind.
	// +kubebuilder:validation:Enum=GarageCluster;GarageBucket
	// +required
	Kind string `json:"kind"`

	// Name restricts access to a specific resource. If omitted, all resources of
	// the given kind in this namespace are accessible.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Name string `json:"name,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=grg,scope=Namespaced
// +kubebuilder:printcolumn:name="From",type="string",JSONPath=".spec.from[0].namespace"
// +kubebuilder:printcolumn:name="FromKind",type="string",JSONPath=".spec.from[0].kind"
// +kubebuilder:printcolumn:name="ToKind",type="string",JSONPath=".spec.to[0].kind"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageReferenceGrant grants permission for resources in other namespaces to
// reference GarageCluster or GarageBucket resources in this namespace.
//
// This resource must be created in the destination namespace (where the
// GarageCluster or GarageBucket lives). Only admins of that namespace can
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
type GarageReferenceGrant struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageReferenceGrantSpec `json:"spec"`
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
