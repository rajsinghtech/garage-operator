/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package v1alpha1 keeps the historical GarageCluster v1alpha1 GroupVersion
// registered with the scheme so the conversion webhook can dispatch instead
// of erroring with "no kind GarageCluster is registered for version
// v1alpha1" on every API server storedVersions migration sweep.
//
// The CRD still declares v1alpha1 (served=false, storage=false) until the
// API server has finished sweeping the entry out of status.storedVersions.
// Removing the CRD entry without first clearing storedVersions fails the
// CRD update with "must appear in spec.versions because it appears in
// status.storedVersions". The scheme-registered Spoke here unblocks the
// sweep so a future release can drop the v1alpha1 CRD entry safely.
//
// Conversion is a no-op in both directions because the v1alpha1 schema is
// not preserved in this package (no objects of this version actually
// exist; the CRD has stored objects only at v1beta1+).
//
// +kubebuilder:object:generate=false
// +groupName=garage.rajsingh.info
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the historical group version for GarageCluster v1alpha1.
	GroupVersion = schema.GroupVersion{Group: "garage.rajsingh.info", Version: "v1alpha1"}

	// SchemeBuilder is used to add legacy types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion} //nolint:staticcheck

	// AddToScheme adds the legacy types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
