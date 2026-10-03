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

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Version
		ok   bool
	}{
		{"v2.4.1", Version{2, 4, 1}, true},
		{"2.4.1", Version{2, 4, 1}, true},
		{" v2.0.10 ", Version{2, 0, 10}, true},
		{"v2.4", Version{}, false},
		{"v2.4.1-rc1", Version{}, false},
		{"v2.4.0-5-gabcdef", Version{}, false},
		{"v02.4.1", Version{}, false},
		{"v2.+4.1", Version{}, false},
		{"v2.-4.1", Version{}, false},
		{"latest", Version{}, false},
		{"", Version{}, false},
		{"v2..1", Version{}, false},
	} {
		got, ok := Parse(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Parse(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFromImage(t *testing.T) {
	const digest = "@sha256:715d176efc35384bf72cf6052fd61b74b3e27a1e31a9dfedabe646bd1e92f137"
	for _, tc := range []struct {
		image string
		want  Version
		ok    bool
	}{
		{"dxflrs/garage:v2.4.0", Version{2, 4, 0}, true},
		{"dxflrs/garage:v2.4.0" + digest, Version{2, 4, 0}, true},
		{"registry.example.com:5000/dxflrs/garage:v2.3.0", Version{2, 3, 0}, true},
		{"registry.example.com:5000/dxflrs/garage", Version{}, false},
		{"dxflrs/garage" + digest, Version{}, false},
		{"dxflrs/garage:latest", Version{}, false},
		{"dxflrs/garage:v2.4.0-arm64", Version{}, false},
		{"", Version{}, false},
	} {
		got, ok := FromImage(tc.image)
		if got != tc.want || ok != tc.ok {
			t.Errorf("FromImage(%q) = %v, %v; want %v, %v", tc.image, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDiscoveryPanicsAtStart(t *testing.T) {
	for v, want := range map[Version]bool{
		{2, 0, 0}: false, {2, 2, 0}: false, {2, 3, 0}: true, {2, 3, 1}: false,
		{2, 4, 0}: true, {2, 4, 1}: false, {2, 5, 0}: false, {3, 3, 0}: false,
	} {
		if got := v.DiscoveryPanicsAtStart(); got != want {
			t.Errorf("%v.DiscoveryPanicsAtStart() = %v, want %v", v, got, want)
		}
	}
}

func TestDiscoveryImageWarning(t *testing.T) {
	if got := DiscoveryImageWarning("dxflrs/garage:v2.4.0", false, false); got != "" {
		t.Errorf("no discovery enabled must not warn, got %q", got)
	}
	if got := DiscoveryImageWarning("dxflrs/garage:v2.4.1", true, true); got != "" {
		t.Errorf("fixed release must not warn, got %q", got)
	}
	if got := DiscoveryImageWarning("dxflrs/garage@sha256:abc", true, true); got != "" {
		t.Errorf("digest-only image is unknown at admission, got %q", got)
	}
	for _, tc := range []struct {
		image      string
		consul, k8 bool
		contains   []string
	}{
		{"dxflrs/garage:v2.3.0", true, false, []string{"v2.3.0", "spec.discovery.consul is enabled", "v2.4.1"}},
		{"dxflrs/garage:v2.4.0@sha256:abc", false, true, []string{"v2.4.0", "spec.discovery.kubernetes is enabled"}},
		{"dxflrs/garage:v2.4.0", true, true, []string{"spec.discovery.consul and spec.discovery.kubernetes are enabled"}},
	} {
		got := DiscoveryImageWarning(tc.image, tc.consul, tc.k8)
		for _, want := range tc.contains {
			if !strings.Contains(got, want) {
				t.Errorf("DiscoveryImageWarning(%q) = %q, missing %q", tc.image, got, want)
			}
		}
	}
}

func TestDiscoveryRuntimeMessage(t *testing.T) {
	got := DiscoveryRuntimeMessage([]Version{{2, 3, 0}, {2, 4, 0}})
	for _, want := range []string{"v2.3.0, v2.4.0", "v2.4.1", "crash-loop"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q missing %q", got, want)
		}
	}
}

func TestDiscoveryWarnings(t *testing.T) {
	if got := DiscoveryWarnings(DiscoverySpec{Namespace: "ns", Image: "dxflrs/garage:v2.4.0"}); len(got) != 0 {
		t.Fatalf("discovery disabled must not warn, got %v", got)
	}
	got := DiscoveryWarnings(DiscoverySpec{
		Namespace: "ns", Image: "dxflrs/garage:v2.4.0", KubernetesEnabled: true,
	})
	if len(got) != 2 {
		t.Fatalf("want crash and RBAC warnings, got %v", got)
	}
	for _, want := range []string{`ServiceAccount "default"`, `namespace "ns"`, "create/patch on the cluster-scoped", "docs/how-to/kubernetes-discovery.md"} {
		if !strings.Contains(got[1], want) {
			t.Errorf("RBAC warning %q missing %q", got[1], want)
		}
	}
	got = DiscoveryWarnings(DiscoverySpec{
		Namespace: "ns", Image: "dxflrs/garage:v2.4.1", KubernetesEnabled: true,
		KubernetesNamespace: "disc", KubernetesSkipCRD: true, ServiceAccountName: "garage",
	})
	if len(got) != 1 {
		t.Fatalf("fixed release must only carry the RBAC warning, got %v", got)
	}
	for _, want := range []string{`ServiceAccount "garage"`, `namespace "disc"`, "skipCRD is true"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("RBAC warning %q missing %q", got[0], want)
		}
	}
	if got := DiscoveryWarnings(DiscoverySpec{ConsulEnabled: true, Image: "dxflrs/garage:v2.3.0"}); len(got) != 1 {
		t.Errorf("consul on v2.3.0 must warn once, got %v", got)
	}
}
