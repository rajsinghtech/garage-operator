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
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garagebucketlog = logf.Log.WithName("garagebucket-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageBucket) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageBucketDefaulter{}).
		WithValidator(&GarageBucketValidator{Client: mgr.GetClient(), AuthorizationReader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta1-garagebucket,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagebuckets,verbs=create;update,versions=v1beta1,name=mgaragebucket.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageBucket] = &GarageBucketDefaulter{}

// GarageBucketDefaulter handles defaulting for GarageBucket.
type GarageBucketDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageBucketDefaulter) Default(ctx context.Context, obj *GarageBucket) error {
	garagebucketlog.Info("default", "name", obj.Name)

	if obj.Spec.GlobalAlias == "" {
		obj.Spec.GlobalAlias = obj.Name
	}

	if obj.Spec.Website != nil && obj.Spec.Website.Enabled != nil && *obj.Spec.Website.Enabled && obj.Spec.Website.IndexDocument == "" {
		obj.Spec.Website.IndexDocument = "index.html"
	}

	// default rule status to Enabled when omitted
	if obj.Spec.Lifecycle != nil {
		for i := range obj.Spec.Lifecycle.Rules {
			if obj.Spec.Lifecycle.Rules[i].Status == "" {
				obj.Spec.Lifecycle.Rules[i].Status = "Enabled"
			}
		}
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagebucket,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagebuckets,verbs=create;update,versions=v1beta1,name=vgaragebucket.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageBucket] = &GarageBucketValidator{}

// +kubebuilder:object:generate=false

// GarageBucketValidator handles validation for GarageBucket.
// It carries a client to check GarageReferenceGrants for cross-namespace references.
type GarageBucketValidator struct {
	Client              client.Client
	AuthorizationReader client.Reader
}

func (v *GarageBucketValidator) authorizationReader() client.Reader {
	if v.AuthorizationReader != nil {
		return v.AuthorizationReader
	}
	return v.Client
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageBucketValidator) ValidateCreate(ctx context.Context, obj *GarageBucket) (admission.Warnings, error) {
	garagebucketlog.Info("validate create", "name", obj.Name)
	return v.validateGarageBucket(ctx, obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageBucketValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageBucket) (admission.Warnings, error) {
	garagebucketlog.Info("validate update", "name", newObj.Name)
	if clusterReferenceChanged(oldObj.Spec.ClusterRef, newObj.Spec.ClusterRef, newObj.Namespace) {
		return nil, fmt.Errorf("clusterRef is immutable after creation; create a new GarageBucket to manage a bucket in another GarageCluster")
	}
	if oldObj.Status.BucketID != "" && oldObj.Spec.BucketID != newObj.Spec.BucketID {
		return nil, fmt.Errorf("bucketId is immutable after the Garage bucket identity has been established")
	}
	oldDefaulted := oldObj.DeepCopy()
	_ = (&GarageBucketDefaulter{}).Default(ctx, oldDefaulted)
	return v.validateGarageBucketWithOptions(ctx, newObj, equality.Semantic.DeepEqual(oldDefaulted.Spec, newObj.Spec))
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageBucketValidator) ValidateDelete(ctx context.Context, obj *GarageBucket) (admission.Warnings, error) {
	garagebucketlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageBucketValidator) validateGarageBucket(ctx context.Context, obj *GarageBucket) (admission.Warnings, error) {
	return v.validateGarageBucketWithOptions(ctx, obj, false)
}

func (v *GarageBucketValidator) validateGarageBucketWithOptions(ctx context.Context, obj *GarageBucket, allowUnchangedLegacy bool) (admission.Warnings, error) {
	var warnings admission.Warnings
	if err := validateGarageBucketSpecWithOptions(obj, allowUnchangedLegacy); err != nil {
		return warnings, err
	}

	// Cross-namespace cluster reference requires a GarageReferenceGrant.
	targetNS := obj.Spec.ClusterRef.Namespace
	if targetNS == "" {
		targetNS = obj.Namespace
	}
	if !allowUnchangedLegacy {
		if err := checkReferenceGrant(ctx, v.authorizationReader(), garageBucketKind, obj.Namespace, garageClusterKind, targetNS, obj.Spec.ClusterRef.Name); err != nil {
			return warnings, err
		}
		for i, permission := range obj.Spec.KeyPermissions {
			keyNamespace := permission.KeyRef.Namespace
			if keyNamespace == "" {
				keyNamespace = obj.Namespace
			}
			if err := checkReferenceGrant(ctx, v.authorizationReader(), garageBucketKind, obj.Namespace, garageKeyKind, keyNamespace, permission.KeyRef.Name); err != nil {
				return warnings, fmt.Errorf("keyPermissions[%d]: %w", i, err)
			}
		}
	}
	return warnings, nil
}

// ValidateGarageBucketSpec validates GarageBucket fields without performing
// ReferenceGrant reads. Controllers call it before any remote mutation.
func ValidateGarageBucketSpec(obj *GarageBucket) error {
	return validateGarageBucketSpecWithOptions(obj, false)
}

func validateGarageBucketSpecWithOptions(obj *GarageBucket, allowUnchangedLegacy bool) error {
	if obj.Spec.DeletionPolicy != "" &&
		obj.Spec.DeletionPolicy != BucketDeletionPolicyDelete &&
		obj.Spec.DeletionPolicy != BucketDeletionPolicyRetain {
		return fmt.Errorf("deletionPolicy must be Delete or Retain")
	}
	if obj.Spec.ClusterRef.Name == "" {
		return fmt.Errorf("clusterRef.name is required")
	}
	if !allowUnchangedLegacy {
		if err := ValidateClusterReference(obj.Spec.ClusterRef, "clusterRef"); err != nil {
			return err
		}
		alias := obj.Spec.GlobalAlias
		if alias == "" {
			alias = obj.Name
		}
		if err := validateGarageBucketAlias(alias, "globalAlias"); err != nil {
			return err
		}
		if err := validateLocalAliases(obj.Spec.LocalAliases); err != nil {
			return err
		}
	}
	if err := validateKeyPermissions(obj.Namespace, obj.Spec.KeyPermissions, allowUnchangedLegacy); err != nil {
		return err
	}
	if !allowUnchangedLegacy && obj.Spec.Quotas != nil {
		if obj.Spec.Quotas.MaxSize != nil && obj.Spec.Quotas.MaxSize.Sign() < 0 {
			return fmt.Errorf("quotas.maxSize must be >= 0")
		}
		if obj.Spec.Quotas.MaxObjects != nil && *obj.Spec.Quotas.MaxObjects < 0 {
			return fmt.Errorf("quotas.maxObjects must be >= 0")
		}
	}
	return validateLifecycle(obj.Spec.Lifecycle)
}

func validateGarageBucketAlias(alias, field string) error {
	if len(alias) < 3 || len(alias) > 63 {
		return fmt.Errorf("%s must contain between 3 and 63 characters", field)
	}
	for _, char := range alias {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '.' && char != '-' {
			return fmt.Errorf("%s %q must contain only lowercase letters, digits, dots, and hyphens", field, alias)
		}
	}
	if strings.HasPrefix(alias, ".") || strings.HasPrefix(alias, "-") ||
		strings.HasSuffix(alias, ".") || strings.HasSuffix(alias, "-") {
		return fmt.Errorf("%s %q must start and end with a letter or digit", field, alias)
	}
	if net.ParseIP(alias) != nil {
		return fmt.Errorf("%s %q must not be formatted as an IP address", field, alias)
	}
	if strings.HasPrefix(alias, "xn--") || strings.Contains(alias, ".xn--") {
		return fmt.Errorf("%s %q must not contain a punycode label", field, alias)
	}
	if strings.HasSuffix(alias, "-s3alias") {
		return fmt.Errorf("%s %q uses the reserved -s3alias suffix", field, alias)
	}
	return nil
}

func validateLocalAliases(aliases []LocalAlias) error {
	seen := make(map[string]int, len(aliases))
	for i, alias := range aliases {
		if problems := utilvalidation.IsDNS1123Subdomain(alias.KeyRef); len(problems) > 0 {
			return fmt.Errorf("localAliases[%d].keyRef %q is invalid: %s", i, alias.KeyRef, strings.Join(problems, "; "))
		}
		if err := validateGarageBucketAlias(alias.Alias, fmt.Sprintf("localAliases[%d].alias", i)); err != nil {
			return err
		}
		key := alias.KeyRef + "\x00" + alias.Alias
		if previous, duplicate := seen[key]; duplicate {
			return fmt.Errorf("localAliases[%d] duplicates localAliases[%d] for key %q and alias %q", i, previous, alias.KeyRef, alias.Alias)
		}
		seen[key] = i
	}
	return nil
}

// validateLifecycle validates lifecycle rules against the subset Garage accepts.
// Garage rejects unsupported fields with opaque 400s, so we catch problems here
// and surface them as admission errors.
func validateLifecycle(lifecycle *BucketLifecycle) error {
	if lifecycle == nil {
		return nil
	}
	seen := make(map[string]bool)
	for i, rule := range lifecycle.Rules {
		if rule.ID == "" {
			return fmt.Errorf("lifecycle.rules[%d]: id is required", i)
		}
		if seen[rule.ID] {
			return fmt.Errorf("lifecycle.rules[%d]: duplicate id '%s'", i, rule.ID)
		}
		seen[rule.ID] = true

		switch rule.Status {
		case "", "Enabled", "Disabled":
		default:
			return fmt.Errorf("lifecycle.rules[%d]: status must be Enabled or Disabled", i)
		}

		hasExpDays := rule.ExpirationDays != nil
		hasExpDate := rule.ExpirationDate != nil
		hasAbort := rule.AbortIncompleteMultipartUploadDays != nil
		if !hasExpDays && !hasExpDate && !hasAbort {
			return fmt.Errorf("lifecycle.rules[%d]: at least one of expirationDays, expirationDate, abortIncompleteMultipartUploadDays must be set", i)
		}
		if hasExpDays && hasExpDate {
			return fmt.Errorf("lifecycle.rules[%d]: expirationDays and expirationDate are mutually exclusive", i)
		}
		if hasExpDays && *rule.ExpirationDays < 1 {
			return fmt.Errorf("lifecycle.rules[%d]: expirationDays must be >= 1", i)
		}
		if hasExpDate {
			u := rule.ExpirationDate.UTC()
			if u.Hour() != 0 || u.Minute() != 0 || u.Second() != 0 || u.Nanosecond() != 0 {
				return fmt.Errorf("lifecycle.rules[%d]: expirationDate must be midnight UTC (00:00:00Z)", i)
			}
		}
		if hasAbort && *rule.AbortIncompleteMultipartUploadDays < 1 {
			return fmt.Errorf("lifecycle.rules[%d]: abortIncompleteMultipartUploadDays must be >= 1", i)
		}
		if rule.Filter != nil {
			gt := rule.Filter.ObjectSizeGreaterThan
			lt := rule.Filter.ObjectSizeLessThan
			if gt != nil && *gt < 0 {
				return fmt.Errorf("lifecycle.rules[%d]: filter.objectSizeGreaterThan must be >= 0", i)
			}
			if lt != nil && *lt < 1 {
				return fmt.Errorf("lifecycle.rules[%d]: filter.objectSizeLessThan must be >= 1", i)
			}
			if gt != nil && lt != nil && *gt >= *lt {
				return fmt.Errorf("lifecycle.rules[%d]: filter.objectSizeGreaterThan must be less than objectSizeLessThan", i)
			}
		}
	}
	return nil
}

func validateKeyPermissions(objectNamespace string, perms []KeyPermission, allowUnchangedLegacy bool) error {
	seen := make(map[string]bool)
	for i, perm := range perms {
		if perm.KeyRef.Name == "" {
			return fmt.Errorf("keyPermissions[%d]: keyRef.name is required", i)
		}
		if !allowUnchangedLegacy {
			if err := validateNamespacedObjectReference(perm.KeyRef.Name, perm.KeyRef.Namespace, fmt.Sprintf("keyPermissions[%d].keyRef", i)); err != nil {
				return err
			}
		}
		keyNamespace := perm.KeyRef.Namespace
		if keyNamespace == "" && !allowUnchangedLegacy {
			keyNamespace = objectNamespace
		}
		key := keyNamespace + "/" + perm.KeyRef.Name
		if seen[key] {
			return fmt.Errorf("keyPermissions[%d]: duplicate keyRef '%s'", i, perm.KeyRef.Name)
		}
		seen[key] = true

		if !perm.Read && !perm.Write && !perm.Owner {
			return fmt.Errorf("keyPermissions[%d]: at least one permission (read, write, or owner) must be granted", i)
		}
	}
	return nil
}
