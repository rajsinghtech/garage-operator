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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func discoveryTestCluster(image string, discovery *DiscoveryConfig) *GarageCluster {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "disc", Namespace: "garage"},
		Spec:       GarageClusterSpec{Replicas: 1, Replication: &ReplicationConfig{Factor: 1}, Storage: StorageConfig{Data: &VolumeConfig{Type: VolumeTypeEmptyDir}}},
	}
	cluster.Spec.Image = image
	cluster.Spec.Discovery = discovery
	return cluster
}

func warningsContaining(warnings []string, needle string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			n++
		}
	}
	return n
}

func TestDiscoveryAdmissionWarnings(t *testing.T) {
	consul := &DiscoveryConfig{Consul: &ConsulDiscoveryConfig{
		Enabled: ptr.To(true), HTTPAddr: "http://consul:8500", ServiceName: "garage",
	}}
	kubernetes := &DiscoveryConfig{Kubernetes: &KubernetesDiscoveryConfig{Enabled: ptr.To(true)}}
	both := &DiscoveryConfig{Consul: consul.Consul, Kubernetes: kubernetes.Kubernetes}
	disabled := &DiscoveryConfig{
		Consul:     &ConsulDiscoveryConfig{Enabled: ptr.To(false), HTTPAddr: "http://consul:8500", ServiceName: "garage"},
		Kubernetes: &KubernetesDiscoveryConfig{Enabled: ptr.To(false)},
	}
	const crashing = "panics at start when peer discovery is enabled"

	for _, tc := range []struct {
		name         string
		image        string
		discovery    *DiscoveryConfig
		wantCrash    int
		wantRBAC     int
		crashContain string
	}{
		{"no discovery on a crashing release", "dxflrs/garage:v2.4.0", nil, 0, 0, ""},
		{"disabled discovery on a crashing release", "dxflrs/garage:v2.4.0", disabled, 0, 0, ""},
		{"consul on v2.3.0", "dxflrs/garage:v2.3.0", consul, 1, 0, "spec.discovery.consul is enabled"},
		{"consul on v2.4.0 with digest", "dxflrs/garage:v2.4.0@sha256:715d176efc35384bf72cf6052fd61b74b3e27a1e31a9dfedabe646bd1e92f137", consul, 1, 0, "v2.4.0"},
		{"kubernetes on v2.4.0", "dxflrs/garage:v2.4.0", kubernetes, 1, 1, "spec.discovery.kubernetes is enabled"},
		{"both on v2.4.0", "dxflrs/garage:v2.4.0", both, 1, 1, "spec.discovery.consul and spec.discovery.kubernetes are enabled"},
		{"consul on fixed v2.4.1", "dxflrs/garage:v2.4.1", consul, 0, 0, ""},
		{"kubernetes on fixed v2.4.1", "dxflrs/garage:v2.4.1", kubernetes, 0, 1, ""},
		{"consul on unaffected v2.2.0", "dxflrs/garage:v2.2.0", consul, 0, 0, ""},
		{"digest-only image is left to the runtime condition", "dxflrs/garage@sha256:715d176efc35384bf72cf6052fd61b74b3e27a1e31a9dfedabe646bd1e92f137", both, 0, 1, ""},
		{"unset image uses the operator default", "", both, 0, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := discoveryTestCluster(tc.image, tc.discovery)
			warnings, err := cluster.validateGarageCluster()
			if err != nil {
				t.Fatalf("discovery warnings must never reject the object: %v", err)
			}
			if got := warningsContaining(warnings, crashing); got != tc.wantCrash {
				t.Errorf("crash warnings = %d, want %d: %v", got, tc.wantCrash, warnings)
			}
			if got := warningsContaining(warnings, "garagenodes.deuxfleurs.fr"); got != tc.wantRBAC {
				t.Errorf("RBAC warnings = %d, want %d: %v", got, tc.wantRBAC, warnings)
			}
			if tc.crashContain != "" && warningsContaining(warnings, tc.crashContain) == 0 {
				t.Errorf("no warning contains %q: %v", tc.crashContain, warnings)
			}
		})
	}
}

func TestDiscoveryAdmissionWarningsKubernetesDetails(t *testing.T) {
	cluster := discoveryTestCluster("dxflrs/garage:v2.4.1", &DiscoveryConfig{Kubernetes: &KubernetesDiscoveryConfig{
		Enabled: ptr.To(true), Namespace: "peers", SkipCRD: true,
	}})
	cluster.Spec.ServiceAccountName = "garage-sa"
	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ServiceAccount "garage-sa"`, `namespace "peers"`, "skipCRD is true"} {
		if warningsContaining(warnings, want) != 1 {
			t.Errorf("warnings missing %q: %v", want, warnings)
		}
	}
}
