/*
Copyright 2026.

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
	stderrors "errors"
	"fmt"
	"regexp"
	"slices"

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

// podExtrasError reports user-supplied initContainers, extraContainers or
// extraVolumes that fail strict validation at reconcile time. Callers fail
// closed: the existing workload is left untouched.
type podExtrasError struct {
	// Reason is one of the garagev1beta2.PodExtrasReason* constants.
	Reason string
	Err    error
}

func (e *podExtrasError) Error() string { return "invalid pod extras: " + e.Err.Error() }

func (e *podExtrasError) Unwrap() error { return e.Err }

// asPodExtrasError returns the podExtrasError in err's chain, if any.
func asPodExtrasError(err error) (*podExtrasError, bool) {
	var target *podExtrasError
	if stderrors.As(err, &target) {
		return target, true
	}
	return nil, false
}

func newPodExtrasError(issues []garagev1beta2.PodExtrasIssue) error {
	if len(issues) == 0 {
		return nil
	}
	return &podExtrasError{Reason: issues[0].Reason, Err: garagev1beta2.PodExtrasIssuesError(issues)}
}

// resolvePodExtras strictly decodes and validates one template's extras with the
// same validator the admission webhooks use, so the two cannot drift.
func resolvePodExtras(in garagev1beta2.PodExtrasInput) (garagev1beta2.ResolvedPodExtras, error) {
	resolved, issues := garagev1beta2.ResolvePodExtras(in)
	if err := newPodExtrasError(issues); err != nil {
		return garagev1beta2.ResolvedPodExtras{}, err
	}
	return resolved, nil
}

// applyPodExtras appends the resolved extras to a pod spec the builder
// produced. Collisions are computed from that spec, not from a constant list, so
// they cannot drift from the builder. Order is deterministic: operator init
// containers first, then user init containers; the garage container stays
// containers[0] with extras after it; extra volumes follow operator volumes.
// On error the pod spec is unchanged.
func applyPodExtras(podSpec *corev1.PodSpec, extras garagev1beta2.ResolvedPodExtras) error {
	if podSpec == nil || extras.IsEmpty() {
		return nil
	}
	operatorContainers := map[string]struct{}{}
	for i := range podSpec.InitContainers {
		operatorContainers[podSpec.InitContainers[i].Name] = struct{}{}
	}
	for i := range podSpec.Containers {
		operatorContainers[podSpec.Containers[i].Name] = struct{}{}
	}
	operatorVolumes := map[string]struct{}{}
	for i := range podSpec.Volumes {
		operatorVolumes[podSpec.Volumes[i].Name] = struct{}{}
	}
	extraVolumes := map[string]struct{}{}
	for i := range extras.ExtraVolumes {
		extraVolumes[extras.ExtraVolumes[i].Name] = struct{}{}
	}

	var issues []garagev1beta2.PodExtrasIssue
	add := func(reason, path, format string, args ...any) {
		issues = append(issues, garagev1beta2.PodExtrasIssue{Reason: reason, Path: path, Detail: fmt.Sprintf(format, args...)})
	}
	check := func(path string, list []corev1.Container) {
		for i := range list {
			item := fmt.Sprintf("%s[%d]", path, i)
			if _, clash := operatorContainers[list[i].Name]; clash {
				add(garagev1beta2.PodExtrasReasonReservedName, item+".name",
					"container name %q collides with a container the operator renders", list[i].Name)
			}
			for j := range list[i].VolumeMounts {
				name := list[i].VolumeMounts[j].Name
				if _, ok := extraVolumes[name]; ok {
					continue
				}
				if _, owned := operatorVolumes[name]; owned {
					add(garagev1beta2.PodExtrasReasonOperatorVolumeMount, fmt.Sprintf("%s.volumeMounts[%d].name", item, j),
						"volume %q is operator-owned and cannot be mounted by extras", name)
				} else {
					add(garagev1beta2.PodExtrasReasonUnknownVolume, fmt.Sprintf("%s.volumeMounts[%d].name", item, j),
						"volume %q is not declared in extraVolumes", name)
				}
			}
		}
	}
	check("initContainers", extras.InitContainers)
	check("extraContainers", extras.ExtraContainers)
	for i := range extras.ExtraVolumes {
		if _, clash := operatorVolumes[extras.ExtraVolumes[i].Name]; clash {
			add(garagev1beta2.PodExtrasReasonReservedName, fmt.Sprintf("extraVolumes[%d].name", i),
				"volume name %q collides with a volume the operator renders", extras.ExtraVolumes[i].Name)
		}
	}
	if err := newPodExtrasError(issues); err != nil {
		return err
	}

	podSpec.InitContainers = append(slices.Clone(podSpec.InitContainers), extras.InitContainers...)
	podSpec.Containers = append(slices.Clone(podSpec.Containers), extras.ExtraContainers...)
	podSpec.Volumes = append(slices.Clone(podSpec.Volumes), extras.ExtraVolumes...)
	return nil
}

// managedClaimNamePattern matches the claim names of StatefulSet volume claim
// templates the operator renders: <template>-<statefulset>-<ordinal>.
var managedClaimNamePattern = regexp.MustCompile(`^(?:metadata|data|data-[0-9]+)-(.+)-[0-9]+$`)

// checkPodExtrasManagedClaims rejects an extraVolume whose persistentVolumeClaim
// is a claim managed by this operator. A second writer on metadata or data is
// the failure the design exists to prevent. A claim is managed when it carries
// the operator's managed-by label or UID reservation annotation, or when its name
// is the claim name of a StatefulSet the operator renders in this namespace (a
// GarageNode or a cluster's edge gateway), even before the claim exists.
func checkPodExtrasManagedClaims(
	ctx context.Context, reader client.Reader, namespace, field string, volumes []corev1.Volume,
) ([]garagev1beta2.PodExtrasIssue, error) {
	var issues []garagev1beta2.PodExtrasIssue
	var workloadNames map[string]struct{}
	for i := range volumes {
		pvcSource := volumes[i].PersistentVolumeClaim
		if pvcSource == nil || pvcSource.ClaimName == "" {
			continue
		}
		claim := pvcSource.ClaimName
		managed := false
		pvc := &corev1.PersistentVolumeClaim{}
		err := reader.Get(ctx, types.NamespacedName{Name: claim, Namespace: namespace}, pvc)
		switch {
		case err == nil:
			managed = pvc.Labels[labelAppManagedBy] == managedByOperatorValue ||
				pvc.Annotations[managedPVCNodeUIDAnnotation] != ""
		case !errors.IsNotFound(err):
			return nil, fmt.Errorf("checking extraVolume claim %s/%s: %w", namespace, claim, err)
		}
		if !managed {
			if m := managedClaimNamePattern.FindStringSubmatch(claim); m != nil {
				if workloadNames == nil {
					names, err := operatorStatefulSetNames(ctx, reader, namespace)
					if err != nil {
						return nil, err
					}
					workloadNames = names
				}
				_, managed = workloadNames[m[1]]
			}
		}
		if managed {
			issues = append(issues, garagev1beta2.PodExtrasIssue{
				Reason: garagev1beta2.PodExtrasReasonManagedClaimReuse,
				Path:   fmt.Sprintf("%s.extraVolumes[%d].persistentVolumeClaim.claimName", field, i),
				Detail: fmt.Sprintf("claim %q is managed by the operator; mounting it would add a second writer to Garage's metadata or data", claim),
			})
		}
	}
	return issues, nil
}

func operatorStatefulSetNames(ctx context.Context, reader client.Reader, namespace string) (map[string]struct{}, error) {
	names := map[string]struct{}{}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := reader.List(ctx, nodes, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing GarageNodes to check extraVolume claims: %w", err)
	}
	for i := range nodes.Items {
		names[nodes.Items[i].Name] = struct{}{}
	}
	clusters := &garagev1beta2.GarageClusterList{}
	if err := reader.List(ctx, clusters, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing GarageClusters to check extraVolume claims: %w", err)
	}
	for i := range clusters.Items {
		names[gatewayWorkloadName(&clusters.Items[i])] = struct{}{}
	}
	return names, nil
}

// validateClusterPodExtras strictly re-validates the extras of every pod
// template of the cluster. Admission can be disabled or bypassed, so this is
// the fail-closed copy of the webhook check plus the managed-claim check, which
// needs the API.
func validateClusterPodExtras(ctx context.Context, reader client.Reader, cluster *garagev1beta2.GarageCluster) error {
	var issues []garagev1beta2.PodExtrasIssue
	for _, in := range cluster.PodExtrasInputs() {
		resolved, found := garagev1beta2.ResolvePodExtras(in)
		if len(found) > 0 {
			issues = append(issues, found...)
			continue
		}
		claimIssues, err := checkPodExtrasManagedClaims(ctx, reader, cluster.Namespace, in.Field, resolved.ExtraVolumes)
		if err != nil {
			return err
		}
		issues = append(issues, claimIssues...)
	}
	return newPodExtrasError(issues)
}

// podExtrasConfigured reports whether any template of the cluster sets extras.
func podExtrasConfigured(cluster *garagev1beta2.GarageCluster) bool {
	for _, in := range cluster.PodExtrasInputs() {
		if len(in.InitContainers) > 0 || len(in.ExtraContainers) > 0 || len(in.ExtraVolumes) > 0 {
			return true
		}
	}
	return false
}

// reconcilePodExtrasCondition publishes PodExtrasValid. It returns blocked=true
// when the extras are invalid: the caller must not touch any workload, so the
// running pods keep their previous spec (D11), and retries no faster than
// RequeueAfterLong. Phase is deliberately left alone.
func (r *GarageClusterReconciler) reconcilePodExtrasCondition(
	ctx context.Context, cluster *garagev1beta2.GarageCluster,
) (blocked bool, err error) {
	existing := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta2.ConditionPodExtrasValid)
	if existing == nil && !podExtrasConfigured(cluster) {
		return false, nil
	}
	cond := metav1.Condition{
		Type:               garagev1beta2.ConditionPodExtrasValid,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta2.PodExtrasReasonValid,
		Message:            "initContainers, extraContainers and extraVolumes are valid",
		ObservedGeneration: cluster.Generation,
	}
	if !podExtrasConfigured(cluster) {
		cond.Message = "no initContainers, extraContainers or extraVolumes are configured"
	}
	validateErr := validateClusterPodExtras(ctx, r.safetyReader(), cluster)
	if validateErr != nil {
		pe, ok := asPodExtrasError(validateErr)
		if !ok {
			return false, validateErr
		}
		cond.Status = metav1.ConditionFalse
		cond.Reason = pe.Reason
		cond.Message = pe.Err.Error()
		blocked = true
		logf.FromContext(ctx).Info("Refusing to update workloads: invalid pod extras", "reason", pe.Reason, "error", pe.Err.Error())
	}
	apply := func() {
		meta.SetStatusCondition(&cluster.Status.Conditions, cond)
	}
	before := meta.FindStatusCondition(cluster.Status.Conditions, cond.Type)
	if before != nil && before.Status == cond.Status && before.Reason == cond.Reason &&
		before.Message == cond.Message && before.ObservedGeneration == cond.ObservedGeneration {
		return blocked, nil
	}
	apply()
	if statusErr := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); statusErr != nil {
		return blocked, statusErr
	}
	return blocked, nil
}

// buildAndApplyPodExtras resolves, validates and applies one template's extras
// to a pod spec the builder produced. Any error is a *podExtrasError (or an API
// read error) and leaves the pod spec unchanged.
func buildAndApplyPodExtras(
	ctx context.Context,
	reader client.Reader,
	namespace string,
	in garagev1beta2.PodExtrasInput,
	podSpec *corev1.PodSpec,
) error {
	resolved, err := resolvePodExtras(in)
	if err != nil {
		return err
	}
	if resolved.IsEmpty() {
		return nil
	}
	claimIssues, err := checkPodExtrasManagedClaims(ctx, reader, namespace, in.Field, resolved.ExtraVolumes)
	if err != nil {
		return err
	}
	if err := newPodExtrasError(claimIssues); err != nil {
		return err
	}
	return applyPodExtras(podSpec, resolved)
}
