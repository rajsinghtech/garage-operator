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
// Cross-namespace references require a GarageReferenceGrant in the target namespace
// (the namespace where the GarageCluster lives). Without it, the webhook will reject
// the resource. GarageNode does not support cross-namespace references at all.
type ClusterReference struct {
	// Name of the GarageCluster resource.
	// +required
	Name string `json:"name"`

	// Namespace of the GarageCluster. Defaults to the referencing resource's namespace.
	// Cross-namespace references require a GarageReferenceGrant in the target namespace.
	// Not supported on GarageNode.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// KubeConfigSecretRef references a secret containing a kubeconfig for a remote Kubernetes cluster.
	// Only needed for multi-cluster federation where the GarageCluster lives in a different
	// Kubernetes cluster entirely (not just a different namespace).
	// +optional
	KubeConfigSecretRef *corev1.SecretKeySelector `json:"kubeConfigSecretRef,omitempty"`
}

// SecretReference is a simple reference to a Kubernetes secret in the same namespace.
type SecretReference struct {
	// Name of the secret
	// +required
	Name string `json:"name"`
}
