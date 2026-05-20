/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// LegacyGarageCluster is the historical v1alpha1 placeholder. The struct
// name intentionally differs from "GarageCluster" so controller-gen does
// NOT emit a CRD for it — we register it under the canonical
// "GarageCluster" GVK manually in init() to satisfy controller-runtime's
// runtime.Scheme expectation while keeping the existing CRD's v1alpha1
// entry (served=false, storage=false) untouched.
//
// No objects exist at this version, so the struct carries only TypeMeta +
// ObjectMeta. The CRD's v1alpha1 schema is
// `x-kubernetes-preserve-unknown-fields: true`; any payload hitting the
// conversion webhook discards down to metadata before reaching the v1beta2
// hub.
type LegacyGarageCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

// DeepCopyObject implements runtime.Object.
func (in *LegacyGarageCluster) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := &LegacyGarageCluster{}
	out.TypeMeta = in.TypeMeta
	in.DeepCopyInto(&out.ObjectMeta)
	return out
}

// LegacyGarageClusterList is the matching list type.
type LegacyGarageClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LegacyGarageCluster `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *LegacyGarageClusterList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := &LegacyGarageClusterList{}
	out.TypeMeta = in.TypeMeta
	in.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]LegacyGarageCluster, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopyObject().(*LegacyGarageCluster)
		}
	}
	return out
}

func init() {
	SchemeBuilder.SchemeBuilder.Register(func(s *runtime.Scheme) error {
		gvk := GroupVersion.WithKind("GarageCluster")
		listGVK := GroupVersion.WithKind("GarageClusterList")
		s.AddKnownTypeWithName(gvk, &LegacyGarageCluster{})
		s.AddKnownTypeWithName(listGVK, &LegacyGarageClusterList{})
		return nil
	})
}
