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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	managedPVCFinalizerValidationPath = "/validate-core-v1-managed-pvc-finalizer"
	persistentVolumeClaimResource     = "persistentvolumeclaims"
)

var storageRolloutPVCFinalizerPattern = regexp.MustCompile(
	"^" + regexp.QuoteMeta(nodeLocalPoolActivationLabelDomain+storageRolloutPVCFinalizerPrefix) + "[0-9a-f]{16}$",
)

// SetupManagedPVCFinalizerWebhook protects the replacement and storage-rollout
// barriers used to retain exact PVC UIDs across workload creation and recovery.
// Only this controller's authenticated service account may remove them; a
// namespace user with ordinary PVC update rights therefore cannot reopen a
// same-name replacement race.
func SetupManagedPVCFinalizerWebhook(server webhook.Server, controllerUsername string) error {
	if server == nil {
		return errors.New("cannot register managed PVC finalizer webhook without a webhook server")
	}
	if controllerUsername == "" {
		return errors.New("cannot register managed PVC finalizer webhook without the controller service-account username")
	}
	server.Register(managedPVCFinalizerValidationPath, &admission.Webhook{Handler: &managedPVCFinalizerValidator{
		controllerUsername: controllerUsername,
	}})
	return nil
}

// +kubebuilder:webhook:path=/validate-core-v1-managed-pvc-finalizer,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=persistentvolumeclaims,verbs=update,versions=v1,name=vmanagedpvcfinalizer.kb.io,admissionReviewVersions=v1,patch=`{"objectSelector":{"matchLabels":{"app.kubernetes.io/managed-by":"garage-operator"}}}`

type managedPVCFinalizerValidator struct {
	controllerUsername string
}

var _ admission.Handler = &managedPVCFinalizerValidator{}

func (v *managedPVCFinalizerValidator) Handle(_ context.Context, request admission.Request) admission.Response {
	if request.Operation != admissionv1.Update || request.SubResource != "" ||
		request.Resource != (metav1.GroupVersionResource{Group: "", Version: "v1", Resource: persistentVolumeClaimResource}) {
		return admission.Denied("managed PVC finalizer webhook accepts only core/v1 PersistentVolumeClaim UPDATE requests")
	}
	oldClaim := &corev1.PersistentVolumeClaim{}
	if err := json.Unmarshal(request.OldObject.Raw, oldClaim); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode old PersistentVolumeClaim: %w", err))
	}
	newClaim := &corev1.PersistentVolumeClaim{}
	if err := json.Unmarshal(request.Object.Raw, newClaim); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode new PersistentVolumeClaim: %w", err))
	}
	removedFinalizer := removedProtectedPVCFinalizer(oldClaim, newClaim)
	if removedFinalizer == "" {
		return admission.Allowed("managed PVC replacement barrier was not removed")
	}
	if request.UserInfo.Username != v.controllerUsername {
		return admission.Denied(fmt.Sprintf(
			"operator PVC identity finalizer %q may be removed only by controller service account %q",
			removedFinalizer, v.controllerUsername,
		))
	}
	return admission.Allowed("controller service account removed managed PVC replacement barrier")
}

func removedProtectedPVCFinalizer(oldClaim, newClaim *corev1.PersistentVolumeClaim) string {
	for _, finalizer := range oldClaim.Finalizers {
		if (finalizer == managedPVCFinalizer || storageRolloutPVCFinalizerPattern.MatchString(finalizer)) &&
			!controllerutil.ContainsFinalizer(newClaim, finalizer) {
			return finalizer
		}
	}
	return ""
}
