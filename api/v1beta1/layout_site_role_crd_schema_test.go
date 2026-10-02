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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

const (
	siteRoleFollowerRule = "!has(self.layoutManagement) || !has(self.layoutManagement.siteRole) || self.layoutManagement.siteRole != 'Follower' || (has(self.remoteClusters) && size(self.remoteClusters) > 0)"
	siteRoleConnectRule  = "!has(self.layoutManagement) || !has(self.layoutManagement.siteRole) || self.layoutManagement.siteRole != 'Follower' || !has(self.connectTo)"
)

func clusterCRDVersion(t *testing.T, path, versionName string) extensionsv1.CustomResourceDefinitionVersion {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	crd := &extensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, crd); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	for _, version := range crd.Spec.Versions {
		if version.Name == versionName {
			return version
		}
	}
	t.Fatalf("%s has no version %s", path, versionName)
	return extensionsv1.CustomResourceDefinitionVersion{}
}

// TestGarageClusterCRDLayoutSiteRoleSchema pins the exact CRD contract of
// layoutManagement.siteRole (#442) in both served versions and in the Helm copy
// of the CRD: the enum, no default, the two spec-level CEL rules, and the
// status.layoutWriter shape.
func TestGarageClusterCRDLayoutSiteRoleSchema(t *testing.T) {
	for _, root := range []string{
		filepath.Join("..", "..", "config", "crd", "bases"),
		filepath.Join("..", "..", "charts", "garage-operator", "crd-bases"),
	} {
		for _, versionName := range []string{"v1beta1", "v1beta2"} {
			t.Run(filepath.Base(filepath.Dir(root))+"/"+filepath.Base(root)+"/"+versionName, func(t *testing.T) {
				version := clusterCRDVersion(t, filepath.Join(root, "garage.rajsingh.info_garageclusters.yaml"), versionName)
				root := version.Schema.OpenAPIV3Schema
				spec := root.Properties["spec"]

				siteRole := spec.Properties["layoutManagement"].Properties["siteRole"]
				if siteRole.Type != "string" {
					t.Fatalf("siteRole type = %q", siteRole.Type)
				}
				if siteRole.Default != nil {
					t.Fatalf("siteRole must have no CRD default, got %s", string(siteRole.Default.Raw))
				}
				var enum []string
				for _, value := range siteRole.Enum {
					enum = append(enum, string(value.Raw))
				}
				if want := []string{`"Writer"`, `"Follower"`}; !reflect.DeepEqual(enum, want) {
					t.Fatalf("siteRole enum = %v, want %v", enum, want)
				}
				for _, required := range spec.Properties["layoutManagement"].Required {
					if required == "siteRole" {
						t.Fatal("siteRole must be optional")
					}
				}

				rules := map[string]string{}
				for _, rule := range spec.XValidations {
					rules[rule.Rule] = rule.Message
				}
				for rule, wantMessage := range map[string]string{
					siteRoleFollowerRule: "layoutManagement.siteRole: Follower requires at least one remoteClusters entry (a Follower with nothing to follow is a cluster nobody can assign roles to)",
					siteRoleConnectRule:  "layoutManagement.siteRole: Follower is not supported with connectTo; edge gateways and management handles act on their layout owner",
				} {
					if got, ok := rules[rule]; !ok || got != wantMessage {
						t.Fatalf("missing or changed spec CEL rule %q (message %q, want %q)", rule, got, wantMessage)
					}
				}

				layoutWriter := root.Properties["status"].Properties["layoutWriter"]
				if layoutWriter.Type != "object" {
					t.Fatalf("status.layoutWriter type = %q", layoutWriter.Type)
				}
				role := layoutWriter.Properties["role"]
				if role.Default != nil || len(role.Enum) != 2 {
					t.Fatalf("status.layoutWriter.role = %+v, want a two-value enum without default", role)
				}
			})
		}
	}
}
