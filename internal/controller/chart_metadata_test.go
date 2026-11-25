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
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// Artifact Hub renders the chart's CRD list from the artifacthub.io/crds
// annotation, which is hand-maintained. Keep it in step with crd-bases: one
// entry per CRD, at its storage version.
func TestChartArtifactHubAnnotationListsEveryCRD(t *testing.T) {
	chart := filepath.Join(repositoryRoot(t), "charts", "garage-operator")

	raw, err := os.ReadFile(filepath.Join(chart, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := yaml.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	var listed []struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
		Name    string `json:"name"`
	}
	if err := yaml.Unmarshal([]byte(meta.Annotations["artifacthub.io/crds"]), &listed); err != nil {
		t.Fatalf("parsing artifacthub.io/crds: %v", err)
	}
	byName := map[string]string{}
	for _, c := range listed {
		if _, dup := byName[c.Name]; dup {
			t.Errorf("artifacthub.io/crds lists %s twice", c.Name)
		}
		byName[c.Name] = c.Kind + "@" + c.Version
	}

	bases, err := filepath.Glob(filepath.Join(chart, "crd-bases", "*.yaml"))
	if err != nil || len(bases) == 0 {
		t.Fatalf("no CRDs in crd-bases: %v", err)
	}
	for _, path := range bases {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var crd struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Names struct {
					Kind string `json:"kind"`
				} `json:"names"`
				Versions []struct {
					Name    string `json:"name"`
					Storage bool   `json:"storage"`
				} `json:"versions"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		storage := ""
		for _, v := range crd.Spec.Versions {
			if v.Storage {
				storage = v.Name
			}
		}
		want := crd.Spec.Names.Kind + "@" + storage
		got, ok := byName[crd.Metadata.Name]
		if !ok {
			t.Errorf("artifacthub.io/crds does not list %s (%s)", crd.Metadata.Name, want)
			continue
		}
		if got != want {
			t.Errorf("artifacthub.io/crds lists %s as %s, want %s", crd.Metadata.Name, got, want)
		}
		delete(byName, crd.Metadata.Name)
	}
	for name := range byName {
		t.Errorf("artifacthub.io/crds lists %s, which is not in crd-bases", name)
	}
}
