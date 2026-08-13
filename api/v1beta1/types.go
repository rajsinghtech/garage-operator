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
)

// This file contains shared types used across multiple CRDs.

// ClusterReference identifies a GarageCluster resource.
// Used by GarageBucket, GarageKey, GarageNode, and GarageAdminToken.
//
// GarageBucket and GarageKey support cross-namespace references when a
// GarageReferenceGrant in the target namespace (where the GarageCluster lives)
// authorizes them. GarageNode and GarageAdminToken are namespace-local and reject
// cross-namespace references.
type ClusterReference struct {
	// Name of the GarageCluster resource.
	// +required
	Name string `json:"name"`

	// Namespace of the GarageCluster. Defaults to the referencing resource's namespace.
	// Cross-namespace references require a GarageReferenceGrant where supported by
	// the owning resource. GarageNode and GarageAdminToken reject them.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// KubeConfigSecretRef is reserved for a future remote Kubernetes client integration.
	// It is currently rejected by admission because the operator does not use it.
	// +optional
	KubeConfigSecretRef *corev1.SecretKeySelector `json:"kubeConfigSecretRef,omitempty"`
}

// SecretReference is a simple reference to a Kubernetes secret in the same namespace.
type SecretReference struct {
	// Name of the secret
	// +required
	Name string `json:"name"`
}

// ZoneSource derives a Garage layout zone from Kubernetes topology instead of a
// static string. See the v1beta2 GarageCluster docs for the full semantics.
type ZoneSource struct {
	// NodeLabel is the label key on the Kubernetes Node whose value becomes the
	// Garage layout zone.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=316
	// +required
	NodeLabel string `json:"nodeLabel"`
}
