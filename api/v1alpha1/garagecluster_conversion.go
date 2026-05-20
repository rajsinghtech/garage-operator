/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1alpha1

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// ConvertTo converts this v1alpha1 placeholder into the v1beta2 hub. No real
// v1alpha1 objects exist (the CRD is served=false, storage=false); we just
// copy metadata so the implementation satisfies the conversion.Convertible
// contract that controller-runtime's webhook builder checks on startup.
func (src *LegacyGarageCluster) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*v1beta2.GarageCluster)
	if !ok {
		return fmt.Errorf("ConvertTo: unexpected hub type %T", dstRaw)
	}
	src.ObjectMeta.DeepCopyInto(&dst.ObjectMeta) //nolint:staticcheck // explicit field for clarity
	dst.Kind = "GarageCluster"
	dst.APIVersion = v1beta2.GroupVersion.String()
	return nil
}

// ConvertFrom converts a v1beta2 GarageCluster into this v1alpha1 placeholder.
func (dst *LegacyGarageCluster) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*v1beta2.GarageCluster)
	if !ok {
		return fmt.Errorf("ConvertFrom: unexpected hub type %T", srcRaw)
	}
	src.ObjectMeta.DeepCopyInto(&dst.ObjectMeta) //nolint:staticcheck // explicit field for clarity
	dst.Kind = "GarageCluster"
	dst.APIVersion = GroupVersion.String()
	return nil
}
