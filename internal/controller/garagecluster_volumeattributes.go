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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// maxVolumeAttributesFailingNodes bounds how many failing GarageNode names the
// aggregate StorageVolumeAttributesReady message lists.
const maxVolumeAttributesFailingNodes = 5

// gatewayVolumeAttributesClaim returns the metadata claim of ordinal i of the
// cluster-owned edge gateway StatefulSet (template "meta", 1 claim per pod).
func gatewayVolumeAttributesClaim(cluster *garagev1beta2.GarageCluster, ordinal int32) string {
	return fmt.Sprintf("%s-%s-%d", metadataVolName, gatewayWorkloadName(cluster), ordinal)
}

// edgeGatewayVolumeAttributesClass returns the class requested for the edge
// gateway's metadata claims, or "" when none is desired or the gateway metadata
// is not a PVC. Only the edge gateway (a gateway tier without a storage tier)
// uses cluster-owned claims; a unified cluster's gateway claims belong to its
// per-node GarageNodes.
func edgeGatewayVolumeAttributesClass(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil || cluster.HasStorageTier() || !cluster.HasGatewayTier() ||
		cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		return ""
	}
	md := cluster.Spec.Gateway.Metadata
	if md == nil || md.Type == garagev1beta2.VolumeTypeEmptyDir ||
		md.VolumeAttributesClassName == nil || *md.VolumeAttributesClassName == "" {
		return ""
	}
	return *md.VolumeAttributesClassName
}

// reconcileGatewayPVCAttributes is the edge-gateway counterpart of
// reconcileNodePVCAttributes. The gateway StatefulSet's claim template is
// immutable, so a class change is applied by patching the bound claims of the
// cluster-owned gateway StatefulSet. Claim names derive from the template and
// StatefulSet name exactly as reconcileGatewayStatefulSet computes them. It
// returns the observed per-claim state for the aggregate condition and never
// fails the cluster for an unsupported or infeasible class.
func (r *GarageClusterReconciler) reconcileGatewayPVCAttributes(ctx context.Context, cluster *garagev1beta2.GarageCluster) ([]vacClaimState, error) {
	class := edgeGatewayVolumeAttributesClass(cluster)
	if class == "" {
		return nil, nil
	}
	log := logf.FromContext(ctx)
	reader := r.safetyReader()

	statefulSet := &appsv1.StatefulSet{}
	if err := reader.Get(ctx, types.NamespacedName{Name: gatewayWorkloadName(cluster), Namespace: cluster.Namespace}, statefulSet); err != nil {
		if errors.IsNotFound(err) {
			return []vacClaimState{{
				claim:   gatewayVolumeAttributesClaim(cluster, 0),
				reason:  garagev1beta1.ReasonVolumeAttributesClassWaitingForBind,
				message: fmt.Sprintf("gateway StatefulSet %s does not exist yet", gatewayWorkloadName(cluster)),
			}}, nil
		}
		return nil, fmt.Errorf("get gateway StatefulSet before VolumeAttributesClass reconcile: %w", err)
	}
	if !metav1.IsControlledBy(statefulSet, cluster) {
		return nil, fmt.Errorf("refusing VolumeAttributesClass reconcile because gateway StatefulSet %s/%s is not controlled by GarageCluster UID %s",
			statefulSet.Namespace, statefulSet.Name, cluster.UID)
	}

	replicas := cluster.GatewayReplicas()
	selector := r.selectorLabelsForTier(cluster, tierGateway)
	var states []vacClaimState
	for ordinal := int32(0); ordinal < replicas; ordinal++ {
		name := gatewayVolumeAttributesClaim(cluster, ordinal)
		pvc := &corev1.PersistentVolumeClaim{}
		if err := reader.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				states = append(states, vacClaimState{claim: name, reason: garagev1beta1.ReasonVolumeAttributesClassWaitingForBind,
					message: fmt.Sprintf("claim %s does not exist yet", name)})
				continue
			}
			return nil, fmt.Errorf("get PVC %s: %w", name, err)
		}
		// Provenance: the StatefulSet controller stamps its selector labels on
		// every claim it creates. A same-named claim without them was not made
		// by this workload and is left strictly alone.
		if !pvc.DeletionTimestamp.IsZero() {
			continue
		}
		owned := true
		for key, value := range selector {
			if pvc.Labels[key] != value {
				owned = false
			}
		}
		if !owned {
			return nil, fmt.Errorf("refusing to modify PVC %s/%s: it does not carry the gateway StatefulSet's selector labels", pvc.Namespace, pvc.Name)
		}

		needsPatch, reason, message := evaluateClaimVolumeAttributes(pvc, class)
		if needsPatch {
			now := time.Now()
			if r.vacBackoff.active(pvc.UID, now) {
				states = append(states, vacClaimState{claim: name, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported, message: unsupportedVACMessage(name)})
				continue
			}
			log.Info("Applying VolumeAttributesClass to gateway PVC", "pvc", name, "class", class)
			if err := patchClaimVolumeAttributesClass(ctx, r.Client, pvc, class); err != nil {
				if isVolumeAttributesClassUnsupported(err) {
					r.vacBackoff.arm(pvc.UID, now)
					states = append(states, vacClaimState{claim: name, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported, message: unsupportedVACMessage(name)})
					continue
				}
				log.Error(err, "gateway VolumeAttributesClass patch failed; will retry", "pvc", name)
				states = append(states, vacClaimState{claim: name, reason: garagev1beta1.ReasonVolumeAttributesClassModifyInProgress,
					message: fmt.Sprintf("claim %s: patching VolumeAttributesClass %q failed (will retry): %v", name, class, err)})
				continue
			}
			r.vacBackoff.clear(pvc.UID)
			if pvc.Spec.VolumeAttributesClassName == nil {
				r.vacBackoff.arm(pvc.UID, now)
				states = append(states, vacClaimState{claim: name, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported, message: unsupportedVACMessage(name)})
				continue
			}
		}
		states = append(states, vacClaimState{claim: name, reason: reason, message: message})
	}
	return states, nil
}

// reconcileStorageVolumeAttributesCondition publishes the cluster-level
// aggregate StorageVolumeAttributesReady condition: one input per generated
// Auto-mode GarageNode that requests a class (read from that node's own
// VolumeAttributesClassApplied condition) plus the edge gateway's claims. It is
// informational only and never feeds Ready or Phase. Absent when no generated
// workload requests a class.
func (r *GarageClusterReconciler) reconcileStorageVolumeAttributesCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	gatewayStates []vacClaimState,
) error {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(cluster.Namespace), client.MatchingLabels{
		labelCluster:      cluster.Name,
		labelAppManagedBy: managedByOperatorValue,
	}); err != nil {
		return fmt.Errorf("listing generated GarageNodes for VolumeAttributesClass aggregation: %w", err)
	}
	var (
		requesting int
		failing    []string
		worst      string
	)
	note := func(reason string) {
		if vacReasonPriority[reason] >= vacReasonPriority[worst] {
			worst = reason
		}
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !metav1.IsControlledBy(node, cluster) || len(nodeVolumeAttributesClaims(node)) == 0 {
			continue
		}
		requesting++
		condition := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionVolumeAttributesClassApplied)
		switch {
		case condition == nil:
			failing = append(failing, node.Name+" (pending)")
			note(garagev1beta1.ReasonVolumeAttributesClassWaitingForBind)
		case condition.Status != metav1.ConditionTrue:
			failing = append(failing, fmt.Sprintf("%s (%s)", node.Name, condition.Reason))
			note(condition.Reason)
		}
	}
	for _, state := range gatewayStates {
		requesting++
		if state.reason != garagev1beta1.ReasonVolumeAttributesClassApplied {
			failing = append(failing, fmt.Sprintf("%s (%s)", state.claim, state.reason))
			note(state.reason)
		}
	}

	var desired *metav1.Condition
	switch {
	case requesting == 0:
		desired = nil
	case len(failing) == 0:
		desired = &metav1.Condition{
			Status:  metav1.ConditionTrue,
			Reason:  garagev1beta1.ReasonVolumeAttributesClassApplied,
			Message: fmt.Sprintf("VolumeAttributesClass applied on %d workload(s)", requesting),
		}
	default:
		sort.Strings(failing)
		shown := failing
		if len(shown) > maxVolumeAttributesFailingNodes {
			shown = shown[:maxVolumeAttributesFailingNodes]
		}
		message := fmt.Sprintf("VolumeAttributesClass not yet applied on %d of %d workload(s): %s",
			len(failing), requesting, strings.Join(shown, ", "))
		if len(failing) > len(shown) {
			message += fmt.Sprintf(", and %d more", len(failing)-len(shown))
		}
		desired = &metav1.Condition{Status: metav1.ConditionFalse, Reason: worst, Message: message}
	}
	return r.setStorageVolumeAttributesCondition(ctx, cluster, desired)
}

func (r *GarageClusterReconciler) setStorageVolumeAttributesCondition(ctx context.Context, cluster *garagev1beta2.GarageCluster, desired *metav1.Condition) error {
	existing := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageVolumeAttributesReady)
	if desired == nil {
		if existing == nil {
			return nil
		}
		apply := func() {
			meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionStorageVolumeAttributesReady)
		}
		apply()
		return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
	}
	desired.Type = garagev1beta1.ConditionStorageVolumeAttributesReady
	desired.ObservedGeneration = cluster.Generation
	desired.Message = limitStatusConditionMessage(desired.Message)
	if !vacConditionChanged(existing, desired, cluster.Generation) {
		return nil
	}
	condition := *desired
	apply := func() { meta.SetStatusCondition(&cluster.Status.Conditions, condition) }
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}
