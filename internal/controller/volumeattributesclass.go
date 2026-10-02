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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// VolumeAttributesClass reconciliation (design #445).
//
// volumeClaimTemplates are immutable, so the StatefulSet only carries the class
// as a create-time hint. The claim itself is the source of truth: for every
// operator-generated claim with a desired class the controller patches
// spec.volumeAttributesClassName on the BOUND claim (Kubernetes forbids the
// change while a claim is Pending) and reports progress through conditions. A
// class change only modifies backend volume attributes and never gates layout,
// scaling, rollouts, drains, or deletion.

// vacClaimState is the observed VolumeAttributesClass state of one claim.
type vacClaimState struct {
	claim   string
	reason  string
	message string
}

// vacDesiredClaim names one operator-generated claim and the class it must carry.
type vacDesiredClaim struct {
	claim string
	class string
}

// vacReasonPriority orders reasons from most to least severe so the aggregate
// condition reports the state a user most needs to act on.
var vacReasonPriority = map[string]int{
	garagev1beta1.ReasonVolumeAttributesClassUnsupported:      4,
	garagev1beta1.ReasonVolumeAttributesClassInfeasible:       3,
	garagev1beta1.ReasonVolumeAttributesClassModifyInProgress: 2,
	garagev1beta1.ReasonVolumeAttributesClassWaitingForBind:   1,
	garagev1beta1.ReasonVolumeAttributesClassApplied:          0,
}

// nodeVolumeAttributesClaims lists the claims of node that the operator
// generates and that have a desired class. Claims backed by existingClaim or
// EmptyDir are user-managed or ephemeral and never carry a class (the webhook
// and CRD reject the combination); node-local-pool members have no PVC at all.
// The claim names follow the StatefulSet convention <template>-<sts>-0 for the
// 1-replica per-node StatefulSet, as expandNodePVCs relies on.
func nodeVolumeAttributesClaims(node *garagev1beta1.GarageNode) []vacDesiredClaim {
	if node == nil || node.Spec.Storage == nil {
		return nil
	}
	var out []vacDesiredClaim
	add := func(template string, volume *garagev1beta1.NodeVolumeConfig) {
		if volume == nil || volume.ExistingClaim != "" || volume.Type == garagev1beta1.VolumeTypeEmptyDir ||
			volume.Size == nil || volume.VolumeAttributesClassName == nil || *volume.VolumeAttributesClassName == "" {
			return
		}
		out = append(out, vacDesiredClaim{
			claim: fmt.Sprintf("%s-%s-0", template, node.Name),
			class: *volume.VolumeAttributesClassName,
		})
	}
	add(metadataVolName, node.Spec.Storage.Metadata)
	if node.Spec.Gateway {
		return out
	}
	if nodeHasMultiHDD(node) {
		for i := range node.Spec.Storage.DataPaths {
			add(nodeMultiHDDDataVolName(i), &node.Spec.Storage.DataPaths[i])
		}
		return out
	}
	add(dataVolName, node.Spec.Storage.Data)
	return out
}

// evaluateClaimVolumeAttributes inspects a claim against the class it must
// carry. needsPatch reports that spec.volumeAttributesClassName must be
// written; the returned reason/message describe the claim as observed (or, when
// needsPatch is true, as it will be right after the patch).
func evaluateClaimVolumeAttributes(pvc *corev1.PersistentVolumeClaim, desired string) (needsPatch bool, reason, message string) {
	if pvc.Status.Phase != corev1.ClaimBound {
		return false, garagev1beta1.ReasonVolumeAttributesClassWaitingForBind,
			fmt.Sprintf("claim %s is %s; Kubernetes forbids changing its VolumeAttributesClass until it binds", pvc.Name, phaseOrPending(pvc))
	}
	current := pvc.Spec.VolumeAttributesClassName
	if current == nil || *current != desired {
		return true, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress,
			fmt.Sprintf("claim %s: requested VolumeAttributesClass %q", pvc.Name, desired)
	}
	if status := pvc.Status.ModifyVolumeStatus; status != nil {
		target := status.TargetVolumeAttributesClassName
		switch status.Status {
		case corev1.PersistentVolumeClaimModifyVolumeInfeasible:
			return false, garagev1beta1.ReasonVolumeAttributesClassInfeasible,
				fmt.Sprintf("claim %s: the driver rejected VolumeAttributesClass %q (or it does not exist); restore the previous class in the spec to cancel", pvc.Name, target)
		case corev1.PersistentVolumeClaimModifyVolumePending, corev1.PersistentVolumeClaimModifyVolumeInProgress:
			return false, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress,
				fmt.Sprintf("claim %s: ModifyVolume to %q is %s", pvc.Name, target, status.Status)
		}
	}
	if applied := pvc.Status.CurrentVolumeAttributesClassName; applied != nil && *applied == desired {
		return false, garagev1beta1.ReasonVolumeAttributesClassApplied,
			fmt.Sprintf("claim %s: VolumeAttributesClass %q applied", pvc.Name, desired)
	}
	return false, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress,
		fmt.Sprintf("claim %s: waiting for the CSI driver to report VolumeAttributesClass %q as current", pvc.Name, desired)
}

func phaseOrPending(pvc *corev1.PersistentVolumeClaim) string {
	if pvc.Status.Phase == "" {
		return string(corev1.ClaimPending)
	}
	return string(pvc.Status.Phase)
}

// aggregateVolumeAttributesStates collapses per-claim states into one
// condition. The most severe reason wins; Applied only when every claim is.
func aggregateVolumeAttributesStates(states []vacClaimState) *metav1.Condition {
	if len(states) == 0 {
		return nil
	}
	sorted := append([]vacClaimState(nil), states...)
	sort.Slice(sorted, func(i, j int) bool {
		if vacReasonPriority[sorted[i].reason] != vacReasonPriority[sorted[j].reason] {
			return vacReasonPriority[sorted[i].reason] > vacReasonPriority[sorted[j].reason]
		}
		return sorted[i].claim < sorted[j].claim
	})
	worst := sorted[0].reason
	if worst == garagev1beta1.ReasonVolumeAttributesClassApplied {
		return &metav1.Condition{
			Status:  metav1.ConditionTrue,
			Reason:  garagev1beta1.ReasonVolumeAttributesClassApplied,
			Message: fmt.Sprintf("VolumeAttributesClass applied on %d claim(s)", len(states)),
		}
	}
	messages := make([]string, 0, len(sorted))
	for _, state := range sorted {
		if state.reason != garagev1beta1.ReasonVolumeAttributesClassApplied {
			messages = append(messages, state.message)
		}
	}
	return &metav1.Condition{
		Status:  metav1.ConditionFalse,
		Reason:  worst,
		Message: strings.Join(messages, "; "),
	}
}

// vacCondition reports whether condition differs from existing in a way worth a
// status write. LastTransitionTime is managed by SetStatusCondition.
func vacConditionChanged(existing *metav1.Condition, desired *metav1.Condition, generation int64) bool {
	if existing == nil {
		return true
	}
	return existing.Status != desired.Status || existing.Reason != desired.Reason ||
		existing.Message != desired.Message || existing.ObservedGeneration != generation
}

// vacUnsupportedBackoff remembers claims whose class update the API server
// rejected so an unsupported cluster is probed once per RequeueAfterLong
// instead of on every reconcile.
type vacUnsupportedBackoff struct {
	until sync.Map // types.UID -> time.Time
}

func (b *vacUnsupportedBackoff) active(uid types.UID, now time.Time) bool {
	if uid == "" {
		return false
	}
	value, ok := b.until.Load(uid)
	if !ok {
		return false
	}
	return now.Before(value.(time.Time))
}

func (b *vacUnsupportedBackoff) arm(uid types.UID, now time.Time) {
	if uid != "" {
		b.until.Store(uid, now.Add(RequeueAfterLong))
	}
}

func (b *vacUnsupportedBackoff) clear(uid types.UID) {
	if uid != "" {
		b.until.Delete(uid)
	}
}

// isVolumeAttributesClassUnsupported recognises the API server's refusal to
// change spec.volumeAttributesClassName ("update is forbidden when the
// VolumeAttributesClass feature gate is disabled", KEP-3751).
func isVolumeAttributesClassUnsupported(err error) bool {
	return errors.IsForbidden(err) || errors.IsInvalid(err)
}

// patchClaimVolumeAttributesClass writes spec.volumeAttributesClassName with a
// one-field merge patch. A patch (not Update) neither conflicts with a
// concurrent size expansion nor rewrites any other field of the claim.
func patchClaimVolumeAttributesClass(ctx context.Context, c client.Client, pvc *corev1.PersistentVolumeClaim, class string) error {
	patch := client.MergeFrom(pvc.DeepCopy())
	pvc.Spec.VolumeAttributesClassName = cloneStringPtr(&class)
	return c.Patch(ctx, pvc, patch)
}

// reconcileNodePVCAttributes applies spec.storage.*.volumeAttributesClassName
// to the node's bound, provenance-verified claims and records the result in
// the VolumeAttributesClassApplied condition.
//
//   - Spec unset means hands off: a claim modified by an admin or another tool
//     is left alone (the webhook already rejects removing a configured value).
//   - Spec set means the operator wins: a different value on a bound managed
//     claim is overwritten.
//   - Failures to change the class are reported on the condition; they never
//     fail the node or block the rest of the reconcile.
func (r *GarageNodeReconciler) reconcileNodePVCAttributes(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	wants := nodeVolumeAttributesClaims(node)
	if len(wants) == 0 {
		return r.setVolumeAttributesClassCondition(ctx, node, nil)
	}

	reader := r.nodeLocalPoolReader()
	states := make([]vacClaimState, 0, len(wants))
	for _, want := range wants {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := reader.Get(ctx, types.NamespacedName{Name: want.claim, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				states = append(states, vacClaimState{
					claim:   want.claim,
					reason:  garagev1beta1.ReasonVolumeAttributesClassWaitingForBind,
					message: fmt.Sprintf("claim %s does not exist yet", want.claim),
				})
				continue
			}
			return fmt.Errorf("get PVC %s: %w", want.claim, err)
		}
		// Same identity gate as expandNodePVCs: never touch a claim whose
		// provenance cannot be proven to belong to this exact GarageNode.
		if err := r.ensureManagedNodePVCProvenance(ctx, pvc, node, cluster); err != nil {
			return err
		}

		needsPatch, reason, message := evaluateClaimVolumeAttributes(pvc, want.class)
		if needsPatch {
			now := time.Now()
			if r.vacBackoff.active(pvc.UID, now) {
				states = append(states, vacClaimState{claim: want.claim, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported,
					message: unsupportedVACMessage(want.claim)})
				continue
			}
			log.Info("Applying VolumeAttributesClass to PVC", "pvc", want.claim, "class", want.class)
			if err := patchClaimVolumeAttributesClass(ctx, r.Client, pvc, want.class); err != nil {
				if isVolumeAttributesClassUnsupported(err) {
					r.vacBackoff.arm(pvc.UID, now)
					log.Info("API server rejected the VolumeAttributesClass update", "pvc", want.claim, "error", err.Error())
					states = append(states, vacClaimState{claim: want.claim, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported,
						message: unsupportedVACMessage(want.claim)})
					continue
				}
				log.Error(err, "VolumeAttributesClass patch failed; will retry", "pvc", want.claim)
				states = append(states, vacClaimState{claim: want.claim, reason: garagev1beta1.ReasonVolumeAttributesClassModifyInProgress,
					message: fmt.Sprintf("claim %s: patching VolumeAttributesClass %q failed (will retry): %v", want.claim, want.class, err)})
				continue
			}
			r.vacBackoff.clear(pvc.UID)
			if pvc.Spec.VolumeAttributesClassName == nil {
				// The server accepted the patch but dropped the field: the
				// feature is not available. Not retryable by the operator.
				r.vacBackoff.arm(pvc.UID, now)
				states = append(states, vacClaimState{claim: want.claim, reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported,
					message: unsupportedVACMessage(want.claim)})
				continue
			}
		}
		states = append(states, vacClaimState{claim: want.claim, reason: reason, message: message})
	}
	return r.setVolumeAttributesClassCondition(ctx, node, aggregateVolumeAttributesStates(states))
}

func unsupportedVACMessage(claim string) string {
	return fmt.Sprintf("claim %s: the API server did not accept spec.volumeAttributesClassName (the VolumeAttributesClass feature is unavailable or disabled); requires Kubernetes 1.34+ or 1.31-1.33 with the feature enabled; retrying every %s", claim, RequeueAfterLong)
}

// setVolumeAttributesClassCondition records (or, for nil, removes) the node's
// VolumeAttributesClassApplied condition, writing status only on a change.
func (r *GarageNodeReconciler) setVolumeAttributesClassCondition(ctx context.Context, node *garagev1beta1.GarageNode, desired *metav1.Condition) error {
	existing := meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionVolumeAttributesClassApplied)
	if desired == nil {
		if existing == nil {
			return nil
		}
		apply := func() {
			meta.RemoveStatusCondition(&node.Status.Conditions, garagev1beta1.ConditionVolumeAttributesClassApplied)
		}
		apply()
		return UpdateStatusWithRetry(ctx, r.Client, node, apply)
	}
	desired.Type = garagev1beta1.ConditionVolumeAttributesClassApplied
	desired.ObservedGeneration = node.Generation
	if !vacConditionChanged(existing, desired, node.Generation) {
		return nil
	}
	condition := *desired
	apply := func() { meta.SetStatusCondition(&node.Status.Conditions, condition) }
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, node, apply)
}

// pvcVolumeAttributesPredicate wakes the GarageNode controller only for the PVC
// changes that move the VolumeAttributesClass condition: the requested class,
// the CSI-reported current class, the modify status, and the bind phase. Every
// other PVC event (including the controller's own metadata patches) is ignored.
func pvcVolumeAttributesPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return pvcRequestsOrReportsClass(e.Object) },
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPVC, oldOK := e.ObjectOld.(*corev1.PersistentVolumeClaim)
			newPVC, newOK := e.ObjectNew.(*corev1.PersistentVolumeClaim)
			if !oldOK || !newOK {
				return false
			}
			return !equality.Semantic.DeepEqual(oldPVC.Spec.VolumeAttributesClassName, newPVC.Spec.VolumeAttributesClassName) ||
				!equality.Semantic.DeepEqual(oldPVC.Status.CurrentVolumeAttributesClassName, newPVC.Status.CurrentVolumeAttributesClassName) ||
				!equality.Semantic.DeepEqual(oldPVC.Status.ModifyVolumeStatus, newPVC.Status.ModifyVolumeStatus) ||
				oldPVC.Status.Phase != newPVC.Status.Phase
		},
	}
}

func pvcRequestsOrReportsClass(obj client.Object) bool {
	pvc, ok := obj.(*corev1.PersistentVolumeClaim)
	if !ok {
		return false
	}
	return pvc.Spec.VolumeAttributesClassName != nil || pvc.Status.CurrentVolumeAttributesClassName != nil ||
		pvc.Status.ModifyVolumeStatus != nil
}

// nodeForManagedPVC maps an operator-generated claim back to its GarageNode
// through the labelGarageNode label that buildNodeVolumeClaimTemplates stamps on
// every generated claim (operator labels always win over user labels). The map
// only enqueues; reconcileNodePVCAttributes still proves provenance.
func (r *GarageNodeReconciler) nodeForManagedPVC(_ context.Context, obj client.Object) []reconcile.Request {
	pvc, ok := obj.(*corev1.PersistentVolumeClaim)
	if !ok {
		return nil
	}
	labels := pvc.GetLabels()
	if labels[labelAppManagedBy] != operatorName || labels[labelGarageNode] == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: labels[labelGarageNode], Namespace: pvc.Namespace}}}
}
