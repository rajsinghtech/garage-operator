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
	"regexp"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garagekeylog = logf.Log.WithName("garagekey-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageKey) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageKeyDefaulter{}).
		WithValidator(&GarageKeyValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta1-garagekey,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagekeys,verbs=create;update,versions=v1beta1,name=mgaragekey.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageKey] = &GarageKeyDefaulter{}

// GarageKeyDefaulter handles defaulting for GarageKey.
type GarageKeyDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageKeyDefaulter) Default(ctx context.Context, obj *GarageKey) error {
	garagekeylog.Info("default", "name", obj.Name)

	if obj.Spec.Name == "" {
		obj.Spec.Name = obj.Name
	}

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

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagekey,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagekeys,verbs=create;update,versions=v1beta1,name=vgaragekey.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageKey] = &GarageKeyValidator{}

// +kubebuilder:object:generate=false

// GarageKeyValidator handles validation for GarageKey.
// It carries a client to check GarageReferenceGrants for cross-namespace references.
type GarageKeyValidator struct {
	Client client.Client
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateCreate(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate create", "name", obj.Name)
	return v.validateGarageKey(ctx, obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate update", "name", newObj.Name)
	return v.validateGarageKey(ctx, newObj)
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateDelete(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageKeyValidator) validateGarageKey(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	var warnings admission.Warnings

	if obj.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
	}

	// Cross-namespace cluster reference requires a GarageReferenceGrant.
	clusterNS := obj.Spec.ClusterRef.Namespace
	if clusterNS == "" {
		clusterNS = obj.Namespace
	}
	if err := checkReferenceGrant(ctx, v.Client, "GarageKey", obj.Namespace, "GarageCluster", clusterNS, obj.Spec.ClusterRef.Name); err != nil {
		return warnings, err
	}

	if obj.Spec.ExpiresAt != nil && obj.Spec.NeverExpires {
		return warnings, fmt.Errorf("expiresAt and neverExpires are mutually exclusive")
	}

	if err := validateImportKey(obj.Spec.ImportKey); err != nil {
		return warnings, err
	}

	if err := v.validateBucketPermissions(ctx, obj); err != nil {
		return warnings, err
	}

	if err := validateAllBuckets(obj.Spec.AllBuckets); err != nil {
		return warnings, err
	}

	if len(obj.Spec.BucketPermissions) == 0 && obj.Spec.AllBuckets == nil {
		warnings = append(warnings,
			"No bucket permissions defined. The key will not have access to any buckets. "+
				"You can grant access via GarageKey.bucketPermissions, GarageKey.allBuckets, or GarageBucket.keyPermissions.")
	}

	return warnings, nil
}

func validateImportKey(ik *ImportKeyConfig) error {
	if ik == nil {
		return nil
	}

	if ik.SecretRef != nil {
		if ik.AccessKeyID != "" || ik.SecretAccessKey != "" {
			return fmt.Errorf("importKey: specify either secretRef or inline credentials (accessKeyId/secretAccessKey), not both")
		}
		return nil
	}

	if ik.AccessKeyIDKey != "" || ik.SecretAccessKeyKey != "" {
		return fmt.Errorf("importKey: accessKeyIdKey/secretAccessKeyKey can only be used with secretRef")
	}

	if ik.AccessKeyID != "" || ik.SecretAccessKey != "" {
		if ik.AccessKeyID == "" {
			return fmt.Errorf("importKey: accessKeyId is required when specifying inline credentials")
		}
		if ik.SecretAccessKey == "" {
			return fmt.Errorf("importKey: secretAccessKey is required when specifying inline credentials")
		}

		accessKeyPattern := regexp.MustCompile(`^GK[a-zA-Z0-9]+$`)
		if !accessKeyPattern.MatchString(ik.AccessKeyID) {
			return fmt.Errorf("importKey: accessKeyId should start with 'GK' followed by alphanumeric characters")
		}
	}

	return nil
}

func validateAllBuckets(ab *AllBucketsPermission) error {
	if ab == nil {
		return nil
	}
	if !ab.Read && !ab.Write && !ab.Owner {
		return fmt.Errorf("allBuckets: at least one permission (read, write, or owner) must be granted")
	}
	return nil
}

// validateBucketPermissions validates bucket permissions, including cross-namespace bucket references.
func (v *GarageKeyValidator) validateBucketPermissions(ctx context.Context, obj *GarageKey) error {
	seen := make(map[string]bool)
	for i, perm := range obj.Spec.BucketPermissions {
		refs := 0
		var refKey string
		if perm.BucketRef != nil {
			refs++
			refKey = "ref:" + perm.BucketRef.Name
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

		// Cross-namespace bucket reference requires a GarageReferenceGrant.
		if perm.BucketRef != nil {
			bucketNS := perm.BucketRef.Namespace
			if bucketNS == "" {
				bucketNS = obj.Namespace
			}
			if err := checkReferenceGrant(ctx, v.Client, "GarageKey", obj.Namespace, "GarageBucket", bucketNS, perm.BucketRef.Name); err != nil {
				return fmt.Errorf("bucketPermissions[%d]: %w", i, err)
			}
		}

		if seen[refKey] {
			return fmt.Errorf("bucketPermissions[%d]: duplicate bucket reference '%s'", i, refKey)
		}
		seen[refKey] = true

		if !perm.Read && !perm.Write && !perm.Owner {
			return fmt.Errorf("bucketPermissions[%d]: at least one permission (read, write, or owner) must be granted", i)
		}
	}

	return nil
}
