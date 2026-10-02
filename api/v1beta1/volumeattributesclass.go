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

const volumeAttributesClassSelectorWarning = "%s sets both selector and volumeAttributesClassName: a statically bound PersistentVolume must itself carry a matching spec.volumeAttributesClassName or the claim will not bind"

func volumeAttributesClassSelectorMessage(field string) string {
	return fmt.Sprintf(volumeAttributesClassSelectorWarning, field)
}

// v1beta1VolumeAttributesClassWarnings returns the non-fatal advice for
// volumeAttributesClassName: a PV selector paired with a class (a statically
// bound PV has to name the same class or the claim will not bind) and a
// top-level storage.data class next to storage.data.paths (each path is an
// independent volume role and never inherits it, so it would be ignored).
func v1beta1VolumeAttributesClassWarnings(cluster *GarageCluster) admission.Warnings {
	if cluster == nil {
		return nil
	}
	var warnings admission.Warnings
	volume := func(field string, vc *VolumeConfig) {
		if vc != nil && vc.Selector != nil && vc.VolumeAttributesClassName != nil {
			warnings = append(warnings, volumeAttributesClassSelectorMessage(field))
		}
	}
	volume("spec.storage.metadata", cluster.Spec.Storage.Metadata)
	if cluster.Spec.Gateway {
		return warnings
	}
	volume("spec.storage.data", cluster.Spec.Storage.Data)
	if data := cluster.Spec.Storage.Data; data != nil {
		if data.VolumeAttributesClassName != nil && len(data.Paths) > 0 {
			warnings = append(warnings, "spec.storage.data.volumeAttributesClassName is ignored when spec.storage.data.paths is set: each path is an independent volume role, so set it on every spec.storage.data.paths[].volume")
		}
		for i := range data.Paths {
			if v := data.Paths[i].Volume; v != nil && v.Selector != nil && v.VolumeAttributesClassName != nil {
				warnings = append(warnings, volumeAttributesClassSelectorMessage(fmt.Sprintf("spec.storage.data.paths[%d].volume", i)))
			}
		}
	}
	return warnings
}

// nodeVolumeAttributesClassSelectorWarnings is the GarageNode counterpart of
// v1beta1VolumeAttributesClassWarnings.
func nodeVolumeAttributesClassSelectorWarnings(node *GarageNode) admission.Warnings {
	if node == nil || node.Spec.Storage == nil {
		return nil
	}
	var warnings admission.Warnings
	check := func(field string, vs *NodeVolumeConfig) {
		if vs != nil && vs.Selector != nil && vs.VolumeAttributesClassName != nil {
			warnings = append(warnings, volumeAttributesClassSelectorMessage(field))
		}
	}
	storage := node.Spec.Storage
	check("spec.storage.metadata", storage.Metadata)
	check("spec.storage.data", storage.Data)
	for i := range storage.DataPaths {
		check(fmt.Sprintf("spec.storage.dataPaths[%d]", i), &storage.DataPaths[i])
	}
	return warnings
}
