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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The Helm chart's ClusterRole and namespace-scoped Role are hand-maintained
// mirrors of the controller-gen output in config/rbac/role.yaml. envtest runs
// with admin credentials and never enforces RBAC, so a permission the
// controllers actually need can be missing from every shipped install while the
// whole unit suite stays green -- the failure only appears as a Forbidden list
// against a real API server, which fails closed and wedges reconciliation.
//
// These tests pin the mirrors to the generated source of truth.

type rbacRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type rbacDocument struct {
	Kind  string     `json:"kind"`
	Rules []rbacRule `json:"rules"`
}

type rbacPermission struct {
	group    string
	resource string
	verb     string
}

func (p rbacPermission) String() string {
	group := p.group
	if group == "" {
		group = "core"
	}
	return fmt.Sprintf("%s/%s:%s", group, p.resource, p.verb)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repository root: %v", err)
	}
	return root
}

// readHelmRBACRules strips Helm control actions and template expressions so the
// static rule list can be parsed as plain YAML. Every RBAC rule in these
// templates is literal; only the surrounding metadata is templated.
func readHelmRBACRules(t *testing.T, path string) map[rbacPermission]struct{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{{") || strings.Contains(line, "{{") {
			continue
		}
		kept = append(kept, line)
	}
	permissions := make(map[rbacPermission]struct{})
	for _, document := range strings.Split(strings.Join(kept, "\n"), "\n---") {
		if strings.TrimSpace(document) == "" {
			continue
		}
		var parsed rbacDocument
		if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
			// A document whose only content was templated metadata is not an
			// RBAC rule source; the generated-role comparison still covers it.
			continue
		}
		collectRBACPermissions(parsed.Rules, permissions)
	}
	if len(permissions) == 0 {
		t.Fatalf("parsed no RBAC rules from %s; the template shape changed and this guard is no longer checking anything", path)
	}
	return permissions
}

func collectRBACPermissions(rules []rbacRule, into map[rbacPermission]struct{}) {
	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					into[rbacPermission{group: group, resource: resource, verb: verb}] = struct{}{}
				}
			}
		}
	}
}

func generatedManagerRBAC(t *testing.T) map[rbacPermission]struct{} {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), "config", "rbac", "role.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	permissions := make(map[rbacPermission]struct{})
	for _, document := range strings.Split(string(raw), "\n---") {
		if strings.TrimSpace(document) == "" {
			continue
		}
		var parsed rbacDocument
		if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		if parsed.Kind != "ClusterRole" {
			continue
		}
		collectRBACPermissions(parsed.Rules, permissions)
	}
	if len(permissions) == 0 {
		t.Fatalf("parsed no rules from generated %s", path)
	}
	return permissions
}

func assertRBACSuperset(t *testing.T, required, actual map[rbacPermission]struct{}, chartPath string) {
	t.Helper()
	var missing []string
	for permission := range required {
		if _, found := actual[permission]; !found {
			missing = append(missing, permission.String())
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	t.Fatalf("%s is missing %d permission(s) the controllers declare in config/rbac/role.yaml:\n  %s\n\n"+
		"envtest does not enforce RBAC, so this gap would only surface as a Forbidden request that fails "+
		"reconciliation closed in a real cluster. Mirror the generated rule into the chart template.",
		chartPath, len(missing), strings.Join(missing, "\n  "))
}

// The chart splits the manager's permissions across templates: the scope-gated
// role (cluster- or namespace-scoped) plus the always-rendered COSI and metrics
// roles. Compare against their union.
func chartRBACUnion(t *testing.T, scopedTemplate string) map[rbacPermission]struct{} {
	t.Helper()
	root := repositoryRoot(t)
	union := make(map[rbacPermission]struct{})
	templates := []string{scopedTemplate, "cosi-rbac.yaml", "metrics-rbac.yaml"}
	if scopedTemplate == "namespace-rbac.yaml" {
		// Namespace is cluster-scoped, so the namespace-scoped install grants
		// its narrowly required label-read access through a separate ClusterRole.
		templates = append(templates, "namespace-selector-rbac.yaml")
	}
	for _, name := range templates {
		for permission := range readHelmRBACRules(t, filepath.Join(root, "charts", "garage-operator", "templates", name)) {
			union[permission] = struct{}{}
		}
	}
	return union
}

func TestHelmClusterRoleCoversEveryGeneratedManagerPermission(t *testing.T) {
	assertRBACSuperset(t, generatedManagerRBAC(t), chartRBACUnion(t, "clusterrole.yaml"),
		"charts/garage-operator/templates/clusterrole.yaml")
}

func TestHelmNamespaceRoleCoversEveryNamespacedManagerPermission(t *testing.T) {
	required := generatedManagerRBAC(t)
	// A Role cannot grant cluster-scoped resources. Both are documented as
	// degraded-but-supported in a namespace-scoped install: effectiveNodeZone
	// falls back to spec.zone when nodes are unreadable, and StorageClass lookups
	// are advisory. Exclude them rather than requiring an impossible rule.
	for permission := range required {
		if (permission.group == "" && permission.resource == "nodes") ||
			(permission.group == "storage.k8s.io" && permission.resource == "storageclasses") {
			delete(required, permission)
		}
	}
	assertRBACSuperset(t, required, chartRBACUnion(t, "namespace-rbac.yaml"),
		"charts/garage-operator/templates/namespace-rbac.yaml")
}
