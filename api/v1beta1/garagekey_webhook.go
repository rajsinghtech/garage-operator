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
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

var garagekeylog = logf.Log.WithName("garagekey-resource")

const (
	defaultAccessKeyIDSecretDataKey     = "access-key-id"
	defaultSecretAccessKeySecretDataKey = "secret-access-key"
	defaultBucketSecretDataKey          = "bucket"
	defaultCredentialsFileSecretDataKey = "credentials"
	defaultCredentialsFileProfile       = "default"
)

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageKey) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageKeyDefaulter{}).
		WithValidator(&GarageKeyValidator{Client: mgr.GetClient(), AuthorizationReader: mgr.GetAPIReader()}).
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
			obj.Spec.SecretTemplate.AccessKeyIDKey = defaultAccessKeyIDSecretDataKey
		}
		if obj.Spec.SecretTemplate.SecretAccessKeyKey == "" {
			obj.Spec.SecretTemplate.SecretAccessKeyKey = defaultSecretAccessKeySecretDataKey
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
		if obj.Spec.SecretTemplate.BucketNameKey == "" {
			obj.Spec.SecretTemplate.BucketNameKey = defaultBucketSecretDataKey
		}
		if obj.Spec.SecretTemplate.CredentialsFileKey == "" {
			obj.Spec.SecretTemplate.CredentialsFileKey = defaultCredentialsFileSecretDataKey
		}
		if obj.Spec.SecretTemplate.CredentialsFileProfile == "" {
			obj.Spec.SecretTemplate.CredentialsFileProfile = defaultCredentialsFileProfile
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
	Client              client.Client
	AuthorizationReader client.Reader
}

func (v *GarageKeyValidator) authorizationReader() client.Reader {
	if v.AuthorizationReader != nil {
		return v.AuthorizationReader
	}
	return v.Client
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateCreate(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate create", "name", obj.Name)
	return v.validateGarageKey(ctx, obj, false)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate update", "name", newObj.Name)
	if clusterReferenceChanged(oldObj.Spec.ClusterRef, newObj.Spec.ClusterRef, newObj.Namespace) {
		return nil, fmt.Errorf("clusterRef is immutable after creation; create a new GarageKey to manage a key in another GarageCluster")
	}
	if !equality.Semantic.DeepEqual(oldObj.Spec.ImportKey, newObj.Spec.ImportKey) {
		return nil, fmt.Errorf("importKey is immutable after creation; create a new GarageKey to manage different credential material")
	}
	allowLegacySnapshotCollision := garageKeyImportSnapshotCollision(oldObj) &&
		equality.Semantic.DeepEqual(oldObj.Spec.SecretTemplate, newObj.Spec.SecretTemplate)
	oldDefaulted := oldObj.DeepCopy()
	_ = (&GarageKeyDefaulter{}).Default(ctx, oldDefaulted)
	allowUnchangedLegacy := equality.Semantic.DeepEqual(oldDefaulted.Spec, newObj.Spec)
	warnings, err := v.validateGarageKeyWithOptions(ctx, newObj, garageKeyValidationOptions{
		allowLegacySnapshotCollision: allowLegacySnapshotCollision,
		allowUnchangedLegacy:         allowUnchangedLegacy,
	})
	if allowLegacySnapshotCollision && garageKeyImportSnapshotCollision(newObj) {
		warnings = append(warnings, "unchanged legacy secretTemplate.name collision with the internal import snapshot is temporarily tolerated so metadata/finalizers can be repaired or the output Secret can be renamed")
	}
	return warnings, err
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageKeyValidator) ValidateDelete(ctx context.Context, obj *GarageKey) (admission.Warnings, error) {
	garagekeylog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageKeyValidator) validateGarageKey(ctx context.Context, obj *GarageKey, allowLegacySnapshotCollisionOption ...bool) (admission.Warnings, error) {
	options := garageKeyValidationOptions{}
	if len(allowLegacySnapshotCollisionOption) > 0 {
		options.allowLegacySnapshotCollision = allowLegacySnapshotCollisionOption[0]
	}
	return v.validateGarageKeyWithOptions(ctx, obj, options)
}

type garageKeyValidationOptions struct {
	allowLegacySnapshotCollision bool
	allowUnchangedLegacy         bool
}

func (v *GarageKeyValidator) validateGarageKeyWithOptions(ctx context.Context, obj *GarageKey, options garageKeyValidationOptions) (admission.Warnings, error) {
	var warnings admission.Warnings
	if err := validateGarageKeySpecWithOptions(obj, options); err != nil {
		return warnings, err
	}

	// Cross-namespace cluster reference requires a GarageReferenceGrant.
	clusterNS := obj.Spec.ClusterRef.Namespace
	if clusterNS == "" {
		clusterNS = obj.Namespace
	}
	if !options.allowUnchangedLegacy {
		if err := checkReferenceGrant(ctx, v.authorizationReader(), garageKeyKind, obj.Namespace, garageClusterKind, clusterNS, obj.Spec.ClusterRef.Name); err != nil {
			return warnings, err
		}
		for i, permission := range obj.Spec.BucketPermissions {
			if permission.BucketRef == nil {
				continue
			}
			bucketNS := permission.BucketRef.Namespace
			if bucketNS == "" {
				bucketNS = obj.Namespace
			}
			if err := checkReferenceGrant(ctx, v.authorizationReader(), garageKeyKind, obj.Namespace, garageBucketKind, bucketNS, permission.BucketRef.Name); err != nil {
				return warnings, fmt.Errorf("bucketPermissions[%d]: %w", i, err)
			}
		}
	}

	if len(obj.Spec.BucketPermissions) == 0 && obj.Spec.AllBuckets == nil {
		warnings = append(warnings,
			"No bucket permissions defined. The key will not have access to any buckets. "+
				"You can grant access via GarageKey.bucketPermissions, GarageKey.allBuckets, or GarageBucket.keyPermissions.")
	}

	if len(obj.Spec.BucketPermissions) > 0 && obj.Spec.AllBuckets != nil {
		warnings = append(warnings,
			"Both allBuckets and bucketPermissions are set. allBuckets grants a baseline permission set on every bucket; "+
				"bucketPermissions entries are applied on top. Verify this is intentional.")
	}

	return warnings, nil
}

// ValidateGarageKeySpec validates GarageKey fields without performing
// ReferenceGrant reads. Controllers call it before any remote mutation.
func ValidateGarageKeySpec(obj *GarageKey) error {
	return validateGarageKeySpecWithOptions(obj, garageKeyValidationOptions{})
}

func validateGarageKeySpecWithOptions(obj *GarageKey, options garageKeyValidationOptions) error {
	if obj.Spec.ClusterRef.Name == "" {
		return fmt.Errorf("clusterRef.name is required")
	}
	if !options.allowUnchangedLegacy {
		if err := ValidateClusterReference(obj.Spec.ClusterRef, "clusterRef"); err != nil {
			return err
		}
		if err := validateGarageKeyMaterialSpec(obj, options.allowLegacySnapshotCollision); err != nil {
			return err
		}
	}
	if obj.Spec.ExpiresAt != nil && obj.Spec.NeverExpires {
		return fmt.Errorf("expiresAt and neverExpires are mutually exclusive")
	}
	if err := validateBucketPermissionsSpec(obj.Namespace, obj.Spec.BucketPermissions, options.allowUnchangedLegacy); err != nil {
		return err
	}
	return validateAllBuckets(obj.Spec.AllBuckets)
}

// ValidateGarageKeyMaterialSpec validates every field that can read or write
// credential material. It is shared by admission and reconciliation so an old
// or directly persisted object cannot bypass Secret namespace and data-key
// collision protections.
func ValidateGarageKeyMaterialSpec(obj *GarageKey) error {
	return validateGarageKeyMaterialSpec(obj, false)
}

func validateGarageKeyMaterialSpec(obj *GarageKey, allowLegacySnapshotCollision bool) error {
	if err := validateImportKey(obj.Spec.ImportKey); err != nil {
		return err
	}
	if obj.Spec.ImportKey != nil && obj.Spec.ImportKey.SecretRef != nil {
		secretNamespace := obj.Spec.ImportKey.SecretRef.Namespace
		if secretNamespace != "" && secretNamespace != obj.Namespace {
			return fmt.Errorf("importKey.secretRef.namespace must be empty or match metadata.namespace; cross-namespace Secret reads are not permitted")
		}
	}
	if err := validateSecretTemplate(obj.Spec.SecretTemplate); err != nil {
		return err
	}
	if !allowLegacySnapshotCollision && garageKeyImportSnapshotCollision(obj) {
		return fmt.Errorf("secretTemplate.name %q collides with the controller's immutable import material snapshot Secret; choose a different generated Secret name", obj.Spec.SecretTemplate.Name)
	}
	return nil
}

func garageKeyImportSnapshotCollision(obj *GarageKey) bool {
	return obj != nil && obj.Spec.ImportKey != nil && obj.Spec.ImportKey.SecretRef != nil &&
		obj.Spec.SecretTemplate != nil && obj.Spec.SecretTemplate.Name != "" &&
		obj.Spec.SecretTemplate.Name == garageconfig.GarageKeyImportSnapshotName(obj.Name)
}

func validateImportKey(ik *ImportKeyConfig) error {
	if ik == nil {
		return nil
	}

	if ik.SecretRef != nil {
		if ik.AccessKeyID != "" || ik.SecretAccessKey != "" {
			return fmt.Errorf("importKey: specify either secretRef or inline credentials (accessKeyId/secretAccessKey), not both")
		}
		if ik.SecretRef.Name == "" {
			return fmt.Errorf("importKey.secretRef.name is required")
		}
		for field, key := range map[string]string{
			"accessKeyIdKey": ik.AccessKeyIDKey, "secretAccessKeyKey": ik.SecretAccessKeyKey,
		} {
			if key != "" {
				if problems := utilvalidation.IsConfigMapKey(key); len(problems) > 0 {
					return fmt.Errorf("importKey.%s %q is not a valid Secret data key: %s", field, key, strings.Join(problems, "; "))
				}
			}
		}
		if defaultString(ik.AccessKeyIDKey, defaultAccessKeyIDSecretDataKey) == defaultString(ik.SecretAccessKeyKey, defaultSecretAccessKeySecretDataKey) {
			return fmt.Errorf("importKey.accessKeyIdKey and secretAccessKeyKey must use distinct Secret data keys")
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
		return nil
	}

	return fmt.Errorf("importKey: specify secretRef or both accessKeyId and secretAccessKey")
}

func validateSecretTemplate(template *SecretTemplate) error {
	if template == nil {
		return nil
	}
	if template.Name != "" {
		if problems := utilvalidation.IsDNS1123Subdomain(template.Name); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.name %q is invalid: %s", template.Name, strings.Join(problems, "; "))
		}
	}
	profile := defaultString(template.CredentialsFileProfile, defaultCredentialsFileProfile)
	if matched, err := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, profile); err != nil || !matched {
		return fmt.Errorf("secretTemplate.credentialsFileProfile %q must start with an alphanumeric character and contain only alphanumeric characters, dots, underscores, or hyphens (maximum 128 characters)", profile)
	}

	type generatedKey struct {
		field   string
		value   string
		enabled bool
	}
	includeEndpoint := template.IncludeEndpoint == nil || *template.IncludeEndpoint
	includeRegion := template.IncludeRegion == nil || *template.IncludeRegion
	includeBucket := template.IncludeBucketName != nil && *template.IncludeBucketName
	includeCredentialsFile := template.IncludeCredentialsFile != nil && *template.IncludeCredentialsFile
	keys := []generatedKey{
		{field: "accessKeyIdKey", value: defaultString(template.AccessKeyIDKey, defaultAccessKeyIDSecretDataKey), enabled: true},
		{field: "secretAccessKeyKey", value: defaultString(template.SecretAccessKeyKey, defaultSecretAccessKeySecretDataKey), enabled: true},
		{field: "endpointKey", value: defaultString(template.EndpointKey, "endpoint"), enabled: includeEndpoint},
		{field: "hostKey", value: defaultString(template.HostKey, "host"), enabled: includeEndpoint},
		{field: "schemeKey", value: defaultString(template.SchemeKey, "scheme"), enabled: includeEndpoint},
		{field: "regionKey", value: defaultString(template.RegionKey, "region"), enabled: includeRegion},
		{field: "bucketNameKey", value: defaultString(template.BucketNameKey, defaultBucketSecretDataKey), enabled: includeBucket},
		{field: "credentialsFileKey", value: defaultString(template.CredentialsFileKey, defaultCredentialsFileSecretDataKey), enabled: includeCredentialsFile},
	}
	seen := make(map[string]string, len(keys)+len(template.AdditionalData))
	for _, key := range keys {
		if problems := utilvalidation.IsConfigMapKey(key.value); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.%s %q is not a valid Secret data key: %s", key.field, key.value, strings.Join(problems, "; "))
		}
		if !key.enabled {
			continue
		}
		if previous, duplicate := seen[key.value]; duplicate {
			return fmt.Errorf("secretTemplate.%s and %s both use Secret data key %q", key.field, previous, key.value)
		}
		seen[key.value] = key.field
	}
	for key := range template.AdditionalData {
		if problems := utilvalidation.IsConfigMapKey(key); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.additionalData key %q is invalid: %s", key, strings.Join(problems, "; "))
		}
		if previous, collision := seen[key]; collision {
			return fmt.Errorf("secretTemplate.additionalData key %q collides with %s", key, previous)
		}
	}
	for key, value := range template.Labels {
		if problems := utilvalidation.IsQualifiedName(key); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.labels key %q is invalid: %s", key, strings.Join(problems, "; "))
		}
		if problems := utilvalidation.IsValidLabelValue(value); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.labels[%q] value %q is invalid: %s", key, value, strings.Join(problems, "; "))
		}
	}
	for key := range template.Annotations {
		if problems := utilvalidation.IsQualifiedName(key); len(problems) > 0 {
			return fmt.Errorf("secretTemplate.annotations key %q is invalid: %s", key, strings.Join(problems, "; "))
		}
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func validateAllBuckets(ab *AllBucketsPermission) error {
	if ab == nil {
		return nil
	}
	// An all-false object intentionally grants no cluster-wide permissions. It
	// is also a valid result of removing allBuckets from a server-side-applied
	// object when the CRD's nested boolean defaults are retained by the merge.
	// The reconciler treats it as an exact zero-permission baseline and can
	// still apply any explicit bucketPermissions on top.
	return nil
}

// validateBucketPermissionsSpec validates permission shape without performing
// ReferenceGrant reads. Newly strict alias syntax is skipped only for an
// unchanged legacy update.
func validateBucketPermissionsSpec(objectNamespace string, permissions []BucketPermission, allowUnchangedLegacy bool) error {
	seen := make(map[string]bool)
	for i, perm := range permissions {
		refs := 0
		var refKey string
		if perm.BucketRef != nil {
			if perm.BucketRef.Name == "" {
				return fmt.Errorf("bucketPermissions[%d].bucketRef.name is required", i)
			}
			if !allowUnchangedLegacy {
				if err := validateNamespacedObjectReference(perm.BucketRef.Name, perm.BucketRef.Namespace, fmt.Sprintf("bucketPermissions[%d].bucketRef", i)); err != nil {
					return err
				}
			}
			refs++
			bucketNamespace := perm.BucketRef.Namespace
			if bucketNamespace == "" && !allowUnchangedLegacy {
				bucketNamespace = objectNamespace
			}
			refKey = "ref:" + bucketNamespace + "/" + perm.BucketRef.Name
		}
		if perm.BucketID != "" {
			refs++
			refKey = "id:" + perm.BucketID
		}
		if perm.GlobalAlias != "" {
			if !allowUnchangedLegacy {
				if err := validateGarageBucketAlias(perm.GlobalAlias, fmt.Sprintf("bucketPermissions[%d].globalAlias", i)); err != nil {
					return err
				}
			}
			refs++
			refKey = "alias:" + perm.GlobalAlias
		}

		if refs == 0 {
			return fmt.Errorf("bucketPermissions[%d]: must specify bucketRef, bucketId, or globalAlias", i)
		}
		if refs > 1 {
			return fmt.Errorf("bucketPermissions[%d]: specify only one of bucketRef, bucketId, or globalAlias", i)
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
