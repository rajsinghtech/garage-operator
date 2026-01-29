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

package v1alpha1

import (
	"context"
	"fmt"
	"regexp"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garagekeylog = logf.Log.WithName("garagekey-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageKey) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageKeyDefaulter{}).
		WithValidator(&GarageKeyValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1alpha1-garagekey,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagekeys,verbs=create;update,versions=v1alpha1,name=mgaragekey.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageKey] = &GarageKeyDefaulter{}

// GarageKeyDefaulter handles defaulting for GarageKey.
type GarageKeyDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageKeyDefaulter) Default(ctx context.Context, obj *GarageKey) error {
	garagekeylog.Info("default", "name", obj.Name)

	// Set default name to metadata.name if not specified
	if obj.Spec.Name == "" {
		obj.Spec.Name = obj.Name
	}

	// Set default secret template settings
	if obj.Spec.SecretTemplate != nil {
		if obj.Spec.SecretTemplate.Name == "" {
			obj.Spec.SecretTemplate.Name = obj.Name
		}
		if obj.Spec.SecretTemplate.Type == "" {
			obj.Spec.SecretTemplate.Type = "Opaque"
		}
		if obj.Spec.SecretTemplate.AccessKeyIDKey == "" {
			obj.Spec.SecretTemplate.AccessKeyIDKey = "access-key-id"
		}
		if obj.Spec.SecretTemplate.SecretAccessKeyKey == "" {
			obj.Spec.SecretTemplate.SecretAccessKeyKey = "secret-access-key"
		}
		if obj.Spec.SecretTemplate.EndpointKey == "" {
			obj.Spec.SecretTemplate.EndpointKey = "endpoint"
		}
		if obj.Spec.SecretTemplate.HostKey == "" {
			obj.Spec.SecretTemplate.HostKey = "host"
		}
		if obj.Spec.SecretTemplate.SchemeKey == "" {
			obj.Spec.SecretTemplate.SchemeKey = "scheme"
		}
		if obj.Spec.SecretTemplate.RegionKey == "" {
			obj.Spec.SecretTemplate.RegionKey = "region"
		}
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1alpha1-garagekey,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagekeys,verbs=create;update,versions=v1alpha1,name=vgaragekey.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageKey] = &GarageKeyValidator{}

// GarageKeyValidator handles validation for GarageKey.
type GarageKeyValidator struct{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateCreate(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate create", "name", obj.Name)
	return obj.validateGarageKey()
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate update", "name", newObj.Name)
	return newObj.validateGarageKey()
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateDelete(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

// validateGarageKey validates the GarageKey spec.
func (r *GarageKey) validateGarageKey() (admission.Warnings, error) {
	var warnings admission.Warnings

	// Validate cluster reference
	if r.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
	}

	// Validate expiration and neverExpires are mutually exclusive
	if r.Spec.Expiration != "" && r.Spec.NeverExpires {
		return warnings, fmt.Errorf("expiration and neverExpires are mutually exclusive")
	}

	// Validate expiration format (RFC 3339)
	if r.Spec.Expiration != "" {
		if _, err := time.Parse(time.RFC3339, r.Spec.Expiration); err != nil {
			return warnings, fmt.Errorf("expiration must be in RFC 3339 format (e.g., '2025-12-31T23:59:59Z'): %v", err)
		}
	}

	// Validate import key configuration
	if err := r.validateImportKey(); err != nil {
		return warnings, err
	}

	// Validate bucket permissions
	if err := r.validateBucketPermissions(); err != nil {
		return warnings, err
	}

	// Warn if no bucket permissions defined
	if len(r.Spec.BucketPermissions) == 0 {
		warnings = append(warnings,
			"No bucket permissions defined. The key will not have access to any buckets. "+
				"You can grant access via GarageKey.bucketPermissions or GarageBucket.keyPermissions.")
	}

	return warnings, nil
}

// validateImportKey validates the import key configuration.
func (r *GarageKey) validateImportKey() error {
	if r.Spec.ImportKey == nil {
		return nil
	}

	ik := r.Spec.ImportKey

	// If using secretRef, don't require inline credentials
	if ik.SecretRef != nil {
		if ik.AccessKeyID != "" || ik.SecretAccessKey != "" {
			return fmt.Errorf("importKey: specify either secretRef or inline credentials (accessKeyId/secretAccessKey), not both")
		}
		return nil
	}

	// If not using secretRef, both accessKeyId and secretAccessKey are required
	if ik.AccessKeyID != "" || ik.SecretAccessKey != "" {
		if ik.AccessKeyID == "" {
			return fmt.Errorf("importKey: accessKeyId is required when specifying inline credentials")
		}
		if ik.SecretAccessKey == "" {
			return fmt.Errorf("importKey: secretAccessKey is required when specifying inline credentials")
		}

		// Validate access key ID format (Garage uses GK followed by alphanumeric)
		accessKeyPattern := regexp.MustCompile(`^GK[a-zA-Z0-9]+$`)
		if !accessKeyPattern.MatchString(ik.AccessKeyID) {
			return fmt.Errorf("importKey: accessKeyId should start with 'GK' followed by alphanumeric characters")
		}
	}

	return nil
}

// validateBucketPermissions validates the bucket permissions configuration.
func (r *GarageKey) validateBucketPermissions() error {
	seen := make(map[string]bool)
	for i, perm := range r.Spec.BucketPermissions {
		// Must have at least one bucket reference
		refs := 0
		var refKey string
		if perm.BucketRef != "" {
			refs++
			refKey = "ref:" + perm.BucketRef
		}
		if perm.BucketID != "" {
			refs++
			refKey = "id:" + perm.BucketID
		}
		if perm.GlobalAlias != "" {
			refs++
			refKey = "alias:" + perm.GlobalAlias
		}

		if refs == 0 {
			return fmt.Errorf("bucketPermissions[%d]: must specify bucketRef, bucketId, or globalAlias", i)
		}
		if refs > 1 {
			return fmt.Errorf("bucketPermissions[%d]: specify only one of bucketRef, bucketId, or globalAlias", i)
		}

		// Check for duplicates
		if seen[refKey] {
			return fmt.Errorf("bucketPermissions[%d]: duplicate bucket reference '%s'", i, refKey)
		}
		seen[refKey] = true

		// At least one permission should be granted
		if !perm.Read && !perm.Write && !perm.Owner {
			return fmt.Errorf("bucketPermissions[%d]: at least one permission (read, write, or owner) must be granted", i)
		}
	}

	return nil
}
