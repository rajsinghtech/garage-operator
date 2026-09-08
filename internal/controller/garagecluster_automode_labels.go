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
	"context"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// expectedAutoModeNodeLabels returns the labels the GarageCluster controller
// owns on a generated Auto-mode GarageNode. The slot is the canonical ordinal,
// not the name of a promoted cycle descendant.
func expectedAutoModeNodeLabels(cluster *garagev1beta2.GarageCluster, tier, slot string) map[string]string {
	return map[string]string{
		labelCluster:      cluster.Name,
		labelTier:         tier,
		labelAppManagedBy: managedByOperatorValue,
		labelAutoNodeSlot: slot,
	}
}

// repairAutoModeNodeLabels restores only the generated Auto-mode labels after
// the caller has proved exact ownership and an unambiguous slot. It deliberately
// does not use Update: a MergeFrom patch cannot overwrite the node's spec,
// annotations, finalizers, or owner references. The optimistic-lock option
// makes a concurrent owner change fail instead of applying labels to a new
// identity at the old resourceVersion.
func (r *GarageClusterReconciler) repairAutoModeNodeLabels(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	expected map[string]string,
) (bool, error) {
	if !hasExactGarageClusterControllerReference(node, cluster) {
		return false, fmt.Errorf("refusing to repair Auto-mode GarageNode %s/%s labels without exact GarageCluster ownership", node.Namespace, node.Name)
	}
	if node.Spec.External != nil || isNodeLocalPoolBacked(node) {
		return false, fmt.Errorf("refusing to repair non-Auto GarageNode %s/%s labels", node.Namespace, node.Name)
	}

	before := node.DeepCopy()
	if node.Labels == nil {
		node.Labels = make(map[string]string, len(expected))
	}
	changed := false
	for key, value := range expected {
		if node.Labels[key] == value {
			continue
		}
		node.Labels[key] = value
		changed = true
	}
	if !changed {
		return false, nil
	}

	if err := r.Patch(ctx, node, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return false, err
	}
	return true, nil
}

func autoModeNodeTier(node *garagev1beta1.GarageNode) string {
	if node != nil && node.Spec.Gateway {
		return tierGateway
	}
	return tierStorage
}

func autoModeTierMatchesNode(node *garagev1beta1.GarageNode, tier string) bool {
	return autoModeNodeTier(node) == tier
}

func autoModeCanonicalSlotForName(name, clusterName, tier string) string {
	if ancestor := cycleCanonicalAncestorName(name); ancestor != "" {
		name = ancestor
	}
	if tier == tierGateway {
		if _, ok := parseAutoModeGatewayOrdinal(name, clusterName); ok {
			return name
		}
		return ""
	}
	if _, ok := parseAutoModeOrdinal(name, clusterName); ok {
		return name
	}
	return ""
}

// autoModeNodeSlotForCluster resolves the stable membership slot for an exact
// Auto-owned node. Canonical and parseable -cycle names are stronger than their
// mutable slot label, so a wrong slot label on those objects is repairable. A
// hash-bounded promoted name has no reversible name-based decoding; its valid
// persisted slot label is therefore mandatory.
func autoModeNodeSlotForCluster(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	tier string,
) (string, error) {
	if node == nil || cluster == nil || !hasExactGarageClusterControllerReference(node, cluster) {
		return "", fmt.Errorf("cannot resolve Auto-mode slot without exact GarageCluster ownership")
	}
	refNamespace := node.Spec.ClusterRef.Namespace
	if refNamespace == "" {
		refNamespace = node.Namespace
	}
	if node.Spec.ClusterRef.Name != cluster.Name || refNamespace != cluster.Namespace {
		return "", fmt.Errorf("auto-mode GarageNode %s/%s has clusterRef %s/%s, expected %s/%s", node.Namespace, node.Name, refNamespace, node.Spec.ClusterRef.Name, cluster.Namespace, cluster.Name)
	}
	if !autoModeTierMatchesNode(node, tier) {
		return "", fmt.Errorf("auto-mode GarageNode %s/%s is %s, not %s", node.Namespace, node.Name, autoModeNodeTier(node), tier)
	}

	if nameSlot := autoModeCanonicalSlotForName(node.Name, cluster.Name, tier); nameSlot != "" {
		return nameSlot, nil
	}
	persisted := node.Labels[labelAutoNodeSlot]
	if autoModeCanonicalSlotForName(persisted, cluster.Name, tier) == persisted && persisted != "" {
		return persisted, nil
	}
	if persisted == "" {
		return "", fmt.Errorf("auto-mode GarageNode %s/%s has no canonical name or persisted Auto slot; refusing to guess a bounded cycle identity", node.Namespace, node.Name)
	}
	return "", fmt.Errorf("auto-mode GarageNode %s/%s has invalid persisted Auto slot %q", node.Namespace, node.Name, persisted)
}

func hasAutoModeManagedLabels(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster, tier string) bool {
	return node != nil && node.Labels[labelCluster] == cluster.Name &&
		node.Labels[labelTier] == tier &&
		node.Labels[labelAppManagedBy] == managedByOperatorValue
}

// listAutoModeNodes discovers both normally labelled nodes and exact-owned
// nodes whose generated labels have drifted. The authoritative scan is small
// (GarageNodes in one namespace) and is required because a label-filtered List
// cannot discover the object whose selector label was removed.
//
// Non-owned objects carrying the managed label set remain in the result so
// ensureAutoModeCycleOwnership can apply its existing fail-closed foreign-owner
// and legacy-adoption checks. Exact-owned objects must have a provable slot;
// otherwise they are rejected before the parent can place them in a delete set.
func (r *GarageClusterReconciler) listAutoModeNodes(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	tier string,
	canonicalNames []string,
) (map[string]*garagev1beta1.GarageNode, error) {
	nodeList := &garagev1beta1.GarageNodeList{}
	if err := r.safetyReader().List(ctx, nodeList, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, err
	}

	byName := make(map[string]*garagev1beta1.GarageNode, len(nodeList.Items))
	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		byName[node.Name] = node
	}

	out := make(map[string]*garagev1beta1.GarageNode, len(nodeList.Items))
	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		// Named node-local pools have an independent identity/lifecycle path.
		if isNodeLocalPoolBacked(node) {
			continue
		}
		if hasExactGarageClusterControllerReference(node, cluster) {
			// External GarageNodes are not Auto-mode generated identities. A
			// canonical-name collision is checked below; otherwise leave them out.
			if node.Spec.External != nil || !autoModeTierMatchesNode(node, tier) {
				continue
			}
			if _, err := autoModeNodeSlotForCluster(node, cluster, tier); err != nil {
				return nil, err
			}
			out[node.Name] = node
			continue
		}
		if hasAutoModeManagedLabels(node, cluster, tier) {
			out[node.Name] = node
		}
	}

	// A desired canonical name must never be silently occupied by an object
	// whose ownership proof is absent or foreign. This closes the old
	// Create/AlreadyExists loop even when that object has no labels at all.
	for _, name := range canonicalNames {
		node, found := byName[name]
		if !found {
			continue
		}
		if !hasExactGarageClusterControllerReference(node, cluster) {
			return nil, fmt.Errorf("canonical Auto-mode %s GarageNode %s/%s is occupied without the exact GarageCluster controller UID; refusing to adopt or overwrite it", tier, node.Namespace, node.Name)
		}
		if node.Spec.External != nil || isNodeLocalPoolBacked(node) || !autoModeTierMatchesNode(node, tier) {
			return nil, fmt.Errorf("canonical Auto-mode %s GarageNode %s/%s has an incompatible identity; refusing to create or overwrite it", tier, node.Namespace, node.Name)
		}
		if _, err := autoModeNodeSlotForCluster(node, cluster, tier); err != nil {
			return nil, err
		}
		out[node.Name] = node
	}

	return out, nil
}

// resolveAutoModeCycleSlotForCluster is the cluster-aware counterpart to the
// legacy resolver. It treats a canonical/parseable cycle name as the stable
// identity even when its slot label is wrong, while requiring a valid slot for
// hash-bounded promoted names. The caller has already run
// ensureAutoModeCycleOwnership, so an unowned candidate is still an error here
// rather than a candidate to adopt.
func resolveAutoModeCycleSlotForCluster(
	existing map[string]*garagev1beta1.GarageNode,
	canonicalName string,
	cluster *garagev1beta2.GarageCluster,
	tier string,
) ([]string, *garagev1beta1.GarageNode, error) {
	var (
		descendants []string
		active      []*garagev1beta1.GarageNode
	)
	for name, node := range existing {
		if name == canonicalName || node == nil || isCycleSibling(node) {
			continue
		}
		slot, err := autoModeNodeSlotForCluster(node, cluster, tier)
		if err != nil {
			return descendants, nil, err
		}
		if slot != canonicalName {
			continue
		}
		descendants = append(descendants, name)
		if node.DeletionTimestamp.IsZero() {
			active = append(active, node)
		}
	}
	sort.Strings(descendants)
	sort.Slice(active, func(i, j int) bool { return active[i].Name < active[j].Name })
	if len(active) > 1 {
		activeNames := make([]string, 0, len(active))
		for _, node := range active {
			activeNames = append(activeNames, node.Name)
		}
		return descendants, nil, fmt.Errorf("canonical Auto-mode GarageNode %s has ambiguous promoted cycle descendants: %s", canonicalName, strings.Join(activeNames, ", "))
	}

	canonical := existing[canonicalName]
	if len(active) == 1 {
		if canonical != nil && canonical.DeletionTimestamp.IsZero() {
			return descendants, nil, fmt.Errorf("canonical GarageNode %s and promoted cycle descendant %s are both live", canonicalName, active[0].Name)
		}
		return descendants, active[0], nil
	}
	return descendants, canonical, nil
}
