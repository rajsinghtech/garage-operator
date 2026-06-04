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

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// TestGenerateGarageConfigDeterministic guards against config-hash thrash: the
// rendered garage.toml must be byte-identical across calls for a fixed spec.
// Before the fix, the [consul_discovery.meta] block iterated a Go map directly,
// so field order varied per call, the config hash changed every reconcile, and
// the per-node StatefulSets rolled in an endless loop. A multi-key Meta map
// makes the old non-determinism overwhelmingly likely to surface across N runs.
func TestGenerateGarageConfigDeterministic(t *testing.T) {
	enabled := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "det-cluster", Namespace: "det-ns"},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{Replicas: 3},
			Discovery: &garagev1beta2.DiscoveryConfig{
				Consul: &garagev1beta2.ConsulDiscoveryConfig{
					Enabled:  &enabled,
					HTTPAddr: "http://consul.service.consul:8500",
					Meta: map[string]string{
						"zone":    "us-east-1",
						"rack":    "r1",
						"tier":    "storage",
						"datacen": "dc1",
						"env":     "prod",
						"role":    "garagesvc",
						"owner":   "platform-team",
					},
				},
			},
		},
	}

	first := generateGarageConfig(cluster, &configContext{})
	for i := 0; i < 100; i++ {
		got := generateGarageConfig(cluster, &configContext{})
		if got != first {
			t.Fatalf("generateGarageConfig is non-deterministic at iteration %d\n--- first ---\n%s\n--- got ---\n%s", i, first, got)
		}
	}
}
