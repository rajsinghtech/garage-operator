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
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garagereferencegrantlog = logf.Log.WithName("garagereferencegrant-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageReferenceGrant) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&GarageReferenceGrantValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagereferencegrant,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagereferencegrants,verbs=create;update,versions=v1beta1,name=vgaragereferencegrant.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageReferenceGrant] = &GarageReferenceGrantValidator{}

// GarageReferenceGrantValidator handles validation for GarageReferenceGrant.
type GarageReferenceGrantValidator struct{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReferenceGrantValidator) ValidateCreate(ctx context.Context, obj *GarageReferenceGrant) (admission.Warnings, error) {
	garagereferencegrantlog.Info("validate create", "name", obj.Name)
	return validateReferenceGrant(obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReferenceGrantValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageReferenceGrant) (admission.Warnings, error) {
	garagereferencegrantlog.Info("validate update", "name", newObj.Name)
	return validateReferenceGrant(newObj)
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReferenceGrantValidator) ValidateDelete(ctx context.Context, obj *GarageReferenceGrant) (admission.Warnings, error) {
	garagereferencegrantlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func validateReferenceGrant(obj *GarageReferenceGrant) (admission.Warnings, error) {
	if len(obj.Spec.From) == 0 {
		return nil, fmt.Errorf("spec.from must have at least one entry")
	}

	var warnings admission.Warnings
	for i, f := range obj.Spec.From {
		if f.Namespace == "" {
			return nil, fmt.Errorf("spec.from[%d].namespace is required", i)
		}
		// Granting access from the same namespace is a no-op but not an error.
		if f.Namespace == obj.Namespace {
			warnings = append(warnings,
				fmt.Sprintf("spec.from[%d]: namespace %q is the same as this resource's namespace; same-namespace references are always permitted without a grant", i, f.Namespace))
		}
	}

	return warnings, nil
}
