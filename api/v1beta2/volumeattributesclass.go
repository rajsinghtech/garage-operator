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

package v1beta2

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// rejectVolumeAttributesClassUnset enforces the "set -> unset is rejected on a
// live volume" rule for volumeAttributesClassName (design #445, D3). The API
// server accepts unsetting the field on a bound PersistentVolumeClaim, but a
// CSI driver is not required to revert the volume's parameters when it is
// omitted, so allowing it would leave the spec saying "no class" while the
// volume keeps the old attributes. Changing the value, or setting it for the
// first time, is allowed.
func rejectVolumeAttributesClassUnset(field string, oldClass, newClass *string) error {
	if oldClass == nil || newClass != nil {
		return nil
	}
	return fmt.Errorf(
		"%s.volumeAttributesClassName cannot be removed while replicas are live: Kubernetes accepts unsetting it on a bound claim but the CSI driver is not required to revert the volume, so the spec would claim no class while the volume keeps the old parameters; set an explicit default VolumeAttributesClass instead, or scale the group to zero first",
		field)
}

const volumeAttributesClassIgnoredWithPathsMessage = "spec.storage.data.volumeAttributesClassName is ignored when spec.storage.data.paths is set: each path is an independent volume role, so set it on every spec.storage.data.paths[].volume"

const volumeAttributesClassSelectorMessage = "%s sets both selector and volumeAttributesClassName: a statically bound PersistentVolume must itself carry a matching spec.volumeAttributesClassName or the claim will not bind"

// volumeAttributesClassWarnings returns the non-fatal advice for
// volumeAttributesClassName:
//   - a volume that pairs a PV selector with a class: a statically bound PV has
//     to name the same class or Kubernetes will not bind the claim; not an error
//     because the PV may be correctly configured;
//   - a class on storage.data next to storage.data.paths: each path is an
//     independent volume role and never inherits the top-level value, so the
//     top-level class would be silently ignored.
func volumeAttributesClassWarnings(cluster *GarageCluster) admission.Warnings {
	if cluster == nil {
		return nil
	}
	var warnings admission.Warnings
	check := func(field string, selectorSet, classSet bool) {
		if selectorSet && classSet {
			warnings = append(warnings, fmt.Sprintf(volumeAttributesClassSelectorMessage, field))
		}
	}
	volume := func(field string, vc *VolumeConfig) {
		if vc != nil {
			check(field, vc.Selector != nil, vc.VolumeAttributesClassName != nil)
		}
	}
	if storage := cluster.Spec.Storage; storage != nil {
		volume("spec.storage.metadata", storage.Metadata)
		volume("spec.storage.data", storage.Data)
		if storage.Data != nil {
			if storage.Data.VolumeAttributesClassName != nil && len(storage.Data.Paths) > 0 {
				warnings = append(warnings, volumeAttributesClassIgnoredWithPathsMessage)
			}
			for i := range storage.Data.Paths {
				if v := storage.Data.Paths[i].Volume; v != nil {
					check(fmt.Sprintf("spec.storage.data.paths[%d].volume", i), v.Selector != nil, v.VolumeAttributesClassName != nil)
				}
			}
		}
	}
	if gateway := cluster.Spec.Gateway; gateway != nil {
		volume("spec.gateway.metadata", gateway.Metadata)
	}
	return warnings
}
