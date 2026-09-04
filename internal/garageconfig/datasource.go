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

package garageconfig

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// ValidateGroupVolumeDataSource checks a PVC dataSourceRef that the operator
// will copy onto every generated claim of one volume role. The source must be a
// same-namespace, non-core group-aware populator so each target ordinal maps to
// a distinct source-group member. A core PVC or VolumeSnapshot would clone one
// volume into every replica.
func ValidateGroupVolumeDataSource(ref *corev1.TypedObjectReference, clusterNamespace, field string) error {
	if ref == nil {
		return nil
	}
	if strings.TrimSpace(ref.Name) == "" || strings.TrimSpace(ref.Kind) == "" {
		return fmt.Errorf("%s: kind and name are required", field)
	}
	if strings.TrimSpace(ref.Kind) != ref.Kind {
		return fmt.Errorf("%s.kind must not have leading or trailing whitespace", field)
	}
	if ref.APIGroup == nil || strings.TrimSpace(*ref.APIGroup) == "" {
		return fmt.Errorf("%s.apiGroup: a non-core group-aware populator source is required; a core PVC or single-volume source cannot safely initialize every target claim", field)
	}
	if strings.TrimSpace(*ref.APIGroup) != *ref.APIGroup {
		return fmt.Errorf("%s.apiGroup must not have leading or trailing whitespace", field)
	}
	if ref.Namespace != nil {
		if strings.TrimSpace(*ref.Namespace) == "" || *ref.Namespace == clusterNamespace {
			return fmt.Errorf("%s.namespace: omit the namespace for a same-namespace source; explicit namespace requires a disabled cross-namespace feature gate", field)
		}
		return fmt.Errorf("%s.namespace: cross-namespace references are not supported", field)
	}
	return ValidateNamespacedObjectReference(ref.Name, "", field)
}
