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
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// layoutWriteMethods are the six garage.Client methods that change the shared
// Garage layout. Each starts with guardLayoutWrite, which refuses the call on a
// layout Follower (#442).
var layoutWriteMethods = map[string]bool{
	"UpdateClusterLayout":           true,
	"UpdateClusterLayoutWithParams": true,
	"ApplyClusterLayout":            true,
	"ApplyStagedLayoutChanges":      true,
	"RevertClusterLayout":           true,
	"ClusterLayoutSkipDeadNodes":    true,
}

// layoutWriteCallAllowList is the complete set of production functions that may
// call a layout-writing method, with how each behaves on a Follower. The
// context guard in garage.Client is the backstop for all of them; the
// explicit pre-check named here makes the common path clean instead of noisy.
//
// A new call site fails TestLayoutWriteCallSiteInventory until it is added
// here AND given a Follower scenario: add the entry only after deciding what
// the function does when ctx forbids layout writes.
var layoutWriteCallAllowList = map[string]string{
	"internal/garage/client.go:ApplyStagedLayoutChanges->ApplyClusterLayout":                                             "client-internal: both methods call guardLayoutWrite first",
	"internal/controller/layout_mutation_coordinator.go:stageAndApplyExclusiveLayoutWithCheck->ApplyStagedLayoutChanges": "generic apply after a stage; the guard refuses it",
	"internal/controller/layout_mutation_coordinator.go:verifyCommittedLayout->UpdateClusterLayoutWithParams":            "re-stage only after this call's own Apply succeeded, which the guard refuses on a Follower",
	"internal/controller/layout_mutation_coordinator.go:verifyCommittedLayout->ApplyStagedLayoutChanges":                 "re-apply only after this call's own Apply succeeded, which the guard refuses on a Follower",
	"internal/controller/garagecluster_controller.go:assignNewNodesToLayout->UpdateClusterLayoutWithParams":              "bootstrapCluster skips layout assignment on a Follower",
	"internal/controller/garagecluster_controller.go:addRemoteNodesToLayoutLocked->UpdateClusterLayoutWithParams":        "connectToRemoteClusterWithLayout skips the remote role import on a Follower",
	"internal/controller/garagecluster_controller.go:removeNodesFromLayoutLocked->UpdateClusterLayout":                   "returns AwaitingLayoutWriter/PendingRoleRemoval; finalizer held",
	"internal/controller/garagecluster_controller.go:handleOperationalAnnotations->RevertClusterLayout":                  "revert-layout is consumed with a LayoutWriteBlocked event before this runs",
	"internal/controller/garagecluster_controller.go:handleSkipDeadNodes->ClusterLayoutSkipDeadNodes":                    "skip-dead-nodes is consumed with a LayoutWriteBlocked event before this runs",
	"internal/controller/garagecluster_factor_migration.go:fmRebuildLayout->UpdateClusterLayout":                         "Reconcile does not advance a factor migration on a Follower",
	"internal/controller/garagecluster_gateway.go:reconcileGatewayTombstones->UpdateClusterLayout":                       "autoApply is treated as off; tombstones are only recorded",
	"internal/controller/garagenode_controller.go:reconcileNode->UpdateClusterLayout":                                    "returns AwaitingLayoutWriter/NodesWithoutRole",
	"internal/controller/garagenode_controller.go:finalize->UpdateClusterLayout":                                         "returns AwaitingLayoutWriter/PendingRoleRemoval; finalizer held",
	"internal/controller/garagenode_controller.go:removeStaleNodeRole->UpdateClusterLayout":                              "returns AwaitingLayoutWriter/PendingRoleRemoval",
	"internal/controller/garagenode_controller.go:removeNodeFromExternalLayout->UpdateClusterLayout":                     "orphaned-finalize path: runs only after the parent cluster is gone, which a Follower cannot be before the writer removed its roles",
	"internal/controller/block_resync_barrier.go:recoverClusterDrainApplyFailure->RevertClusterLayout":                   "reachable only after a staged removal, which the guard refuses",
	"internal/controller/block_resync_barrier.go:recoverNodeDrainApplyFailure->RevertClusterLayout":                      "reachable only after a staged removal, which the guard refuses",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestLayoutWriteCallSiteInventory fails when a call to any layout-writing
// garage.Client method appears in production code outside the allow-list, so a
// new feature cannot silently bypass the Follower design.
func TestLayoutWriteCallSiteInventory(t *testing.T) {
	root := repoRoot(t)
	found := map[string]bool{}
	for _, dir := range []string{"internal", "cmd", "api"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			for _, decl := range parsed.Decls {
				function, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(function, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok && layoutWriteMethods[selector.Sel.Name] {
						found[relative+":"+function.Name.Name+"->"+selector.Sel.Name] = true
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scanning %s: %v", dir, err)
		}
	}

	var unlisted, stale []string
	for site := range found {
		if _, allowed := layoutWriteCallAllowList[site]; !allowed {
			unlisted = append(unlisted, site)
		}
	}
	for site := range layoutWriteCallAllowList {
		if !found[site] {
			stale = append(stale, site)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(stale)
	if len(unlisted) > 0 {
		t.Errorf("new Garage layout-writing call site(s) outside the Follower allow-list; decide how each behaves on a layoutManagement.siteRole: Follower site, add a pre-check and a scenario test, then list it in layoutWriteCallAllowList:\n  %s",
			strings.Join(unlisted, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("layoutWriteCallAllowList names call site(s) that no longer exist; remove them:\n  %s", strings.Join(stale, "\n  "))
	}
}
