/*
Copyright 2026.

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

import "fmt"

// PodExtrasInputs returns one input per pod template of the cluster that can
// carry extras: the storage tier, the gateway tier and each node-local pool.
// Webhook and controller validate exactly these inputs.
func (r *GarageCluster) PodExtrasInputs() []PodExtrasInput {
	ports := r.GarageListenerPorts()
	var out []PodExtrasInput
	if r.Spec.Storage != nil {
		out = append(out, PodExtrasInput{
			Field:           "spec.storage",
			InitContainers:  r.Spec.Storage.InitContainers,
			ExtraContainers: r.Spec.Storage.ExtraContainers,
			ExtraVolumes:    r.Spec.Storage.ExtraVolumes,
			ListenerPorts:   ports,
		})
		for i := range r.Spec.Storage.NodeLocalPools {
			pool := &r.Spec.Storage.NodeLocalPools[i]
			if pool.PodTemplate == nil {
				continue
			}
			out = append(out, PodExtrasInput{
				Field:           fmt.Sprintf("spec.storage.nodeLocalPools[%q].podTemplate", pool.Name),
				InitContainers:  pool.PodTemplate.InitContainers,
				ExtraContainers: pool.PodTemplate.ExtraContainers,
				ExtraVolumes:    pool.PodTemplate.ExtraVolumes,
				ListenerPorts:   ports,
			})
		}
	}
	if r.Spec.Gateway != nil {
		out = append(out, PodExtrasInput{
			Field:           "spec.gateway",
			InitContainers:  r.Spec.Gateway.InitContainers,
			ExtraContainers: r.Spec.Gateway.ExtraContainers,
			ExtraVolumes:    r.Spec.Gateway.ExtraVolumes,
			ListenerPorts:   ports,
		})
	}
	return out
}

// validatePodExtras strictly validates initContainers, extraContainers and
// extraVolumes on every pod template of the cluster.
func (r *GarageCluster) validatePodExtras() error {
	var issues []PodExtrasIssue
	for _, in := range r.PodExtrasInputs() {
		_, found := ResolvePodExtras(in)
		issues = append(issues, found...)
	}
	return PodExtrasIssuesError(issues)
}
