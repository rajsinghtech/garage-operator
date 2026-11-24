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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// maxPVCExpansionFailingNodes bounds how many failing GarageNode names the
// aggregate StoragePVCExpansionReady message lists.
const maxPVCExpansionFailingNodes = 5

// reconcileStoragePVCExpansionCondition publishes the cluster-level
// StoragePVCExpansionReady aggregate from every GarageNode's
// ConditionPVCExpansionFailed. It is informational only and never feeds Ready
// or Phase. Absent when no node currently reports a rejected expansion (#537).
func (r *GarageClusterReconciler) reconcileStoragePVCExpansionCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(cluster.Namespace), client.MatchingLabels{
		labelCluster: cluster.Name,
	}); err != nil {
		return fmt.Errorf("listing GarageNodes for PVC expansion aggregation: %w", err)
	}
	failing := make([]string, 0)
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !garageNodeReferencesCluster(node, cluster) {
			continue
		}
		condition := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionPVCExpansionFailed)
		if condition == nil || condition.Status != metav1.ConditionTrue {
			continue
		}
		detail := condition.Reason
		if condition.Message != "" {
			detail = condition.Message
		}
		failing = append(failing, fmt.Sprintf("%s (%s)", node.Name, detail))
	}

	var desired *metav1.Condition
	if len(failing) == 0 {
		desired = nil
	} else {
		sort.Strings(failing)
		shown := failing
		if len(shown) > maxPVCExpansionFailingNodes {
			shown = shown[:maxPVCExpansionFailingNodes]
		}
		message := fmt.Sprintf("PVC expansion rejected on %d GarageNode(s): %s",
			len(failing), strings.Join(shown, ", "))
		if len(failing) > len(shown) {
			message += fmt.Sprintf(", and %d more", len(failing)-len(shown))
		}
		desired = &metav1.Condition{
			Status:  metav1.ConditionFalse,
			Reason:  garagev1beta1.ReasonPVCExpansionRejected,
			Message: limitStatusConditionMessage(message),
		}
	}
	return r.setStoragePVCExpansionCondition(ctx, cluster, desired)
}

func (r *GarageClusterReconciler) setStoragePVCExpansionCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	desired *metav1.Condition,
) error {
	existing := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStoragePVCExpansionReady)
	if desired == nil {
		if existing == nil {
			return nil
		}
		apply := func() {
			meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionStoragePVCExpansionReady)
		}
		apply()
		return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
	}
	desired.Type = garagev1beta1.ConditionStoragePVCExpansionReady
	desired.ObservedGeneration = cluster.Generation
	if existing != nil &&
		existing.Status == desired.Status &&
		existing.Reason == desired.Reason &&
		existing.Message == desired.Message &&
		existing.ObservedGeneration == desired.ObservedGeneration {
		return nil
	}
	condition := *desired
	apply := func() { meta.SetStatusCondition(&cluster.Status.Conditions, condition) }
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}
