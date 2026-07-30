/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	corev1 "k8s.io/api/core/v1"
)

// This file contains shared types referenced from v1beta2 GarageCluster.

// ClusterReference identifies a GarageCluster resource.
//
// Cross-namespace references require a GarageReferenceGrant in the target namespace
// (the namespace where the GarageCluster lives).
type ClusterReference struct {
	// Name of the GarageCluster resource.
	// +required
	Name string `json:"name"`

	// Namespace of the GarageCluster. Defaults to the referencing resource's namespace.
	// Cross-namespace references require a GarageReferenceGrant in the target namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// KubeConfigSecretRef references a secret containing a kubeconfig for a remote Kubernetes cluster.
	// Only needed for multi-cluster federation where the GarageCluster lives in a different
	// Kubernetes cluster entirely (not just a different namespace).
	// +optional
	KubeConfigSecretRef *corev1.SecretKeySelector `json:"kubeConfigSecretRef,omitempty"`
}

// ZoneSource derives a Garage layout zone from Kubernetes topology instead of a
// static string.
//
// Resolution happens after the pod is scheduled, since the answer depends on
// which Kubernetes Node it landed on. Until then — and whenever the label is
// absent or unreadable — the static zone is used, so a node is never left
// without one.
type ZoneSource struct {
	// NodeLabel is the label key on the Kubernetes Node whose value becomes the
	// Garage layout zone.
	//
	// Examples: "topology.kubernetes.io/zone" for cloud AZs,
	// "kubernetes.io/hostname" for per-node failure domains, or a custom label
	// such as "example.com/rack" for physical racks or power circuits.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=316
	// +required
	NodeLabel string `json:"nodeLabel"`
}
