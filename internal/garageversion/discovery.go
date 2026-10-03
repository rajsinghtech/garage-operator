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

package garageversion

import "fmt"

// DiscoverySpec is the part of a GarageCluster spec that decides which
// discovery admission warnings apply. Both served API versions fill it from
// their own types so the warnings cannot drift apart.
type DiscoverySpec struct {
	// Namespace is the GarageCluster's own namespace.
	Namespace string
	// Image is spec.image ("" when unset: the operator default is a fixed,
	// discovery-safe release).
	Image string

	ConsulEnabled bool

	KubernetesEnabled bool
	// KubernetesNamespace is spec.discovery.kubernetes.namespace ("" means
	// the cluster's namespace).
	KubernetesNamespace string
	KubernetesSkipCRD   bool
	// ServiceAccountName is spec.serviceAccountName ("" means the namespace's
	// default ServiceAccount).
	ServiceAccountName string
}

// DiscoveryWarnings returns the admission warnings for the discovery section:
// the crashing-release guard and, for Garage-native Kubernetes discovery, the
// RBAC the Garage pods need.
func DiscoveryWarnings(in DiscoverySpec) []string {
	var warnings []string
	if w := DiscoveryImageWarning(in.Image, in.ConsulEnabled, in.KubernetesEnabled); w != "" {
		warnings = append(warnings, w)
	}
	if in.KubernetesEnabled {
		namespace := in.KubernetesNamespace
		if namespace == "" {
			namespace = in.Namespace
		}
		account := in.ServiceAccountName
		if account == "" {
			account = "default"
		}
		crd := "and create/patch on the cluster-scoped garagenodes.deuxfleurs.fr CustomResourceDefinition"
		if in.KubernetesSkipCRD {
			crd = "(no CustomResourceDefinition permission is needed because skipCRD is true, but you must install the CRD yourself)"
		}
		warnings = append(warnings, fmt.Sprintf(
			"spec.discovery.kubernetes enables Garage's own Kubernetes discovery, and the operator does not provision its RBAC: "+
				"ServiceAccount %q needs get/list/create/update on garagenodes.deuxfleurs.fr in namespace %q %s; "+
				"the operator already connects Garage peers itself, so this is optional "+
				"(see docs/how-to/kubernetes-discovery.md)",
			account, namespace, crd))
	}
	return warnings
}
