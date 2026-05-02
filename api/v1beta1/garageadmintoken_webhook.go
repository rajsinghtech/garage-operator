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
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garageadmintokenlog = logf.Log.WithName("garageadmintoken-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageAdminToken) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&GarageAdminTokenValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garageadmintoken,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageadmintokens,verbs=create;update,versions=v1beta1,name=vgarageadmintoken.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageAdminToken] = &GarageAdminTokenValidator{}

// +kubebuilder:object:generate=false

// GarageAdminTokenValidator handles validation for GarageAdminToken.
// It carries a client to check GarageReferenceGrants for cross-namespace references.
type GarageAdminTokenValidator struct {
	Client client.Client
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageAdminTokenValidator) ValidateCreate(ctx context.Context, obj *GarageAdminToken) (admission.Warnings, error) {
	garageadmintokenlog.Info("validate create", "name", obj.Name)
	return v.validateGarageAdminToken(ctx, obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageAdminTokenValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageAdminToken) (admission.Warnings, error) {
	garageadmintokenlog.Info("validate update", "name", newObj.Name)
	return v.validateGarageAdminToken(ctx, newObj)
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageAdminTokenValidator) ValidateDelete(ctx context.Context, obj *GarageAdminToken) (admission.Warnings, error) {
	garageadmintokenlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageAdminTokenValidator) validateGarageAdminToken(ctx context.Context, obj *GarageAdminToken) (admission.Warnings, error) {
	var warnings admission.Warnings

	if obj.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
	}

	// Cross-namespace cluster reference requires a GarageReferenceGrant.
	targetNS := obj.Spec.ClusterRef.Namespace
	if targetNS == "" {
		targetNS = obj.Namespace
	}
	if err := checkReferenceGrant(ctx, v.Client, "GarageAdminToken", obj.Namespace, "GarageCluster", targetNS, obj.Spec.ClusterRef.Name); err != nil {
		return warnings, err
	}

	if obj.Spec.Expiration != "" && obj.Spec.NeverExpires {
		return warnings, fmt.Errorf("expiration and neverExpires are mutually exclusive")
	}

	return warnings, nil
}
