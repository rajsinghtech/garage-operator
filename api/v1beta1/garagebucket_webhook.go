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
	if err := v.validateBucketIDExclusivity(ctx, obj); err != nil {
		return nil, err
	}
	return v.validateGarageBucket(ctx, obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageBucketValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageBucket) (admission.Warnings, error) {
	garagebucketlog.Info("validate update", "name", newObj.Name)
	if clusterReferenceChanged(oldObj.Spec.ClusterRef, newObj.Spec.ClusterRef, newObj.Namespace) {
		return nil, fmt.Errorf("clusterRef is immutable after creation; create a new GarageBucket to manage a bucket in another GarageCluster")
	}
	// The operator records the resolved bucket identity in status.bucketId. Once
	// recorded, spec.bucketId may be removed (the operator keeps reconciling the
	// recorded bucket from status) or set to the recorded value, but never
	// re-pointed at a different bucket — the mapping itself stays immutable.
	if oldObj.Status.BucketID != "" && newObj.Spec.BucketID != "" &&
		newObj.Spec.BucketID != oldObj.Status.BucketID {
		return nil, fmt.Errorf(
			"spec.bucketId %q does not match the recorded bucket identity %q: after adoption bucketId can only be removed or set to the recorded value, never changed to another bucket",
			newObj.Spec.BucketID, oldObj.Status.BucketID,
		)
	}
	if err := v.validateBucketIDExclusivity(ctx, newObj); err != nil {
		return nil, err
	}
	// Dropping spec.bucketId keeps the recorded identity in status, so it must
	// not launder an out-of-scope adoption into a bucket the resource appears
	// to have created (#588).
	if oldObj.Spec.BucketID != "" && newObj.Spec.BucketID == "" {
		outOfScope, err := BucketAdoptionOutOfScope(ctx, v.authorizationReader(), oldObj)
		if err != nil {
			return nil, err
		}
		if outOfScope {
			return nil, fmt.Errorf("spec.bucketId cannot be removed: %s", BucketAdoptionOutOfScopeMessage(oldObj))
		}
	}
	oldDefaulted := oldObj.DeepCopy()
	_ = (&GarageBucketDefaulter{}).Default(ctx, oldDefaulted)
	warnings, err := v.validateGarageBucketWithOptions(ctx, newObj, equality.Semantic.DeepEqual(oldDefaulted.Spec, newObj.Spec), oldObj.Spec.BucketID)
	return warnings, err
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageBucketValidator) ValidateDelete(ctx context.Context, obj *GarageBucket) (admission.Warnings, error) {
	garagebucketlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageBucketValidator) validateGarageBucket(ctx context.Context, obj *GarageBucket) (admission.Warnings, error) {
	return v.validateGarageBucketWithOptions(ctx, obj, false, "")
}

// validateGarageBucketWithOptions validates obj. previousBucketID is the
// spec.bucketId of the stored object on update ("" on create); an unchanged
// out-of-scope adoption is only warned about so existing resources stay
// editable while the controller keeps them fenced.
func (v *GarageBucketValidator) validateGarageBucketWithOptions(ctx context.Context, obj *GarageBucket, allowUnchangedLegacy bool, previousBucketID string) (admission.Warnings, error) {
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
		if obj.Spec.BucketID != "" {
			outOfScope, err := BucketAdoptionOutOfScope(ctx, v.authorizationReader(), obj)
			if err != nil {
				return warnings, err
			}
			if outOfScope {
				if previousBucketID != obj.Spec.BucketID {
					return warnings, fmt.Errorf("%s", BucketAdoptionOutOfScopeMessage(obj))
				}
				warnings = append(warnings, BucketAdoptionOutOfScopeMessage(obj)+
					"; the operator no longer manages, grants access to, or deletes this bucket for this GarageBucket")
			}
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

// validateBucketIDExclusivity rejects a spec.bucketId that another GarageBucket
// already claims in the same GarageCluster, either by explicit adoption or by a
// recorded status identity. A Garage bucket can only be managed by one
// resource; enforcing that at admission keeps a duplicate claimant from ever
// gaining the deletion finalizer that could remove the rightful owner's bucket.
// The check is best-effort against the informer cache: the bucket controller
// re-checks with the same semantics before every remote mutation.
func (v *GarageBucketValidator) validateBucketIDExclusivity(ctx context.Context, obj *GarageBucket) error {
	if obj.Spec.BucketID == "" || v.Client == nil {
		return nil
	}
	var existing GarageBucketList
	if err := v.Client.List(ctx, &existing); err != nil {
		return fmt.Errorf("failed to check duplicate spec.bucketId claims: %w", err)
	}
	if other := FindBucketClaimConflict(obj, obj.Spec.BucketID, existing.Items); other != nil {
		return fmt.Errorf(
			"spec.bucketId %q is already managed by GarageBucket %s/%s; a Garage bucket can only be managed by one GarageBucket resource",
			obj.Spec.BucketID, other.Namespace, other.Name,
		)
	}
	return nil
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
	if err := validateWebsiteExposure(obj); err != nil {
		return err
	}
	return validateLifecycle(obj.Spec.Lifecycle)
}

// validateWebsiteExposure validates spec.websiteExposure: spec-internal
// invariants only (website enabled, ingress/gateway exclusivity,
// Ingress-same-namespace rule, backendRef referent constraints). The
// hostname semantics (canonical form, URLRewrite for non-canonical hosts)
// are a controller concern — they need the referenced GarageCluster's
// webApi.rootDomain.
func validateWebsiteExposure(obj *GarageBucket) error {
	exposure := obj.Spec.WebsiteExposure
	if exposure == nil {
		return nil
	}
	// An exposure is only meaningful for a website-enabled bucket.
	if website := obj.Spec.Website; website == nil || website.Enabled == nil || !*website.Enabled {
		return fmt.Errorf("websiteExposure requires spec.website.enabled: true")
	}
	if exposure.Ingress != nil && exposure.Gateway != nil {
		return fmt.Errorf("websiteExposure.ingress and websiteExposure.gateway are mutually exclusive; set at most one")
	}
	if exposure.Ingress == nil && exposure.Gateway == nil {
		return fmt.Errorf("websiteExposure requires at least one of websiteExposure.ingress or websiteExposure.gateway")
	}
	// An Ingress backend cannot cross namespaces. The exposure resource lives
	// in the bucket's namespace and routes to the cluster's web Service, so an
	// Ingress is only valid when the bucket and the cluster share a namespace.
	// (The HTTPRoute path reaches the cross-namespace backend through a
	// Gateway API ReferenceGrant, so it is not restricted this way.)
	clusterNS := obj.Spec.ClusterRef.Namespace
	if clusterNS == "" {
		clusterNS = obj.Namespace
	}
	if exposure.Ingress != nil && obj.Namespace != clusterNS {
		return fmt.Errorf("websiteExposure.ingress is not supported when the bucket (%s) and its cluster (%s) are in different namespaces; an Ingress backend cannot cross namespaces. Use websiteExposure.gateway instead", obj.Namespace, clusterNS)
	}
	if exposure.Gateway != nil {
		for i, ref := range exposure.Gateway.ParentRefs {
			if ref.Name == "" {
				return fmt.Errorf("websiteExposure.gateway.parentRefs[%d].name is required", i)
			}
		}
	}
	// Duplicates are rejected here rather than by the CRD schema: structural
	// schemas forbid uniqueItems (quadratic runtime complexity).
	seen := make(map[string]struct{}, len(exposure.Hostnames))
	for _, host := range exposure.Hostnames {
		if _, ok := seen[host]; ok {
			return fmt.Errorf("websiteExposure.hostnames contains the duplicate %q", host)
		}
		seen[host] = struct{}{}
	}
	if ref := exposure.BackendRef; ref != nil {
		if ref.Name == "" {
			return fmt.Errorf("websiteExposure.backendRef.name is required")
		}
		kind := ref.Kind
		if kind == "" {
			kind = "Service"
		}
		if exposure.Ingress != nil && (ref.Group != "" || kind != "Service") {
			return fmt.Errorf("websiteExposure.backendRef must reference a core/v1 Service for an Ingress (got kind %q group %q)", ref.Kind, ref.Group)
		}
		if exposure.Ingress != nil && ref.Namespace != "" && ref.Namespace != obj.Namespace {
			return fmt.Errorf("websiteExposure.backendRef.namespace %q is invalid for an Ingress: the backend Service must live in the bucket's namespace %q (Ingress backends cannot cross namespaces)", ref.Namespace, obj.Namespace)
		}
	}
	return nil
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
