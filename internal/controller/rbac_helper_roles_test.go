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
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// The kustomize admin/editor/viewer ClusterRoles ship in install.yaml for
// cluster admins to delegate access to the custom resources. They are not
// generated, so a wrong API group grants nothing and nothing else notices.
// Every role must name the real group and a served CRD, and every CRD must
// have all three roles.
func TestKustomizeHelperRolesTargetServedCRDs(t *testing.T) {
	root := repositoryRoot(t)
	group := garagev1beta1.GroupVersion.Group

	plurals := map[string]bool{}
	crds, err := filepath.Glob(filepath.Join(root, "config", "crd", "bases", group+"_*.yaml"))
	if err != nil || len(crds) == 0 {
		t.Fatalf("no CRDs found under config/crd/bases: %v", err)
	}
	for _, path := range crds {
		plural := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), group+"_"), ".yaml")
		plurals[plural] = true
	}

	raw, err := os.ReadFile(filepath.Join(root, "config", "rbac", "kustomization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	if err := yaml.Unmarshal(raw, &kustomization); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, resource := range kustomization.Resources {
		listed[resource] = true
	}

	for plural := range plurals {
		kind := strings.TrimSuffix(plural, "s")
		for _, role := range []string{"admin", "editor", "viewer"} {
			name := kind + "_" + role + "_role.yaml"
			if !listed[name] {
				t.Errorf("config/rbac/kustomization.yaml does not list %s", name)
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, "config", "rbac", name))
			if err != nil {
				t.Errorf("read %s: %v", name, err)
				continue
			}
			var doc rbacDocument
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				t.Errorf("parse %s: %v", name, err)
				continue
			}
			if len(doc.Rules) == 0 {
				t.Errorf("%s has no rules", name)
			}
			for _, rule := range doc.Rules {
				for _, g := range rule.APIGroups {
					if g != group {
						t.Errorf("%s grants API group %q, want %q", name, g, group)
					}
				}
				for _, resource := range rule.Resources {
					base := strings.TrimSuffix(resource, "/status")
					if base != plural {
						t.Errorf("%s grants resource %q, want %s or %s/status", name, resource, plural, plural)
					}
				}
			}
		}
	}
}
