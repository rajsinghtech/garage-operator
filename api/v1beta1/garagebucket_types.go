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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GarageBucketSpec defines the desired state of GarageBucket
// +kubebuilder:validation:XValidation:rule="self.clusterRef.name == oldSelf.clusterRef.name",message="clusterRef.name is immutable after creation"
// +kubebuilder:validation:XValidation:rule="!has(self.clusterRef.__namespace__) || !has(oldSelf.clusterRef.__namespace__) || self.clusterRef.__namespace__ == oldSelf.clusterRef.__namespace__",message="clusterRef.namespace is immutable after creation"
type GarageBucketSpec struct {
	// ClusterRef references the GarageCluster this bucket belongs to
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// DeletionPolicy controls whether deleting this resource also deletes the
	// corresponding Garage bucket. The default is Delete.
	// +kubebuilder:validation:Enum=Delete;Retain
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy BucketDeletionPolicy `json:"deletionPolicy,omitempty"`

	// GlobalAlias is the global alias for this bucket (optional)
	// If not set, the bucket name from metadata.name is used
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// LocalAliases are per-key local aliases for this bucket
	// +optional
	LocalAliases []LocalAlias `json:"localAliases,omitempty"`

	// Quotas configures bucket quotas
	// +optional
	Quotas *BucketQuotas `json:"quotas,omitempty"`

	// Website configures static website hosting for this bucket.
	// Note: Only indexDocument and errorDocument are supported via the Admin API.
	// For advanced features (routing rules, redirectAll), use S3 PutBucketWebsite API directly.
	// +optional
	Website *WebsiteConfig `json:"website,omitempty"`

	// KeyPermissions grants access to specific GarageKeys.
	//
	// Note: Permissions can be granted from either direction:
	// - Here (GarageBucket.keyPermissions): Grant keys access to this bucket
	// - On GarageKey (GarageKey.bucketPermissions): Grant the key access to buckets
	//
	// Both approaches are equivalent and result in the same Garage API calls.
	// Use whichever is more convenient for your workflow:
	// - Bucket-centric: Define all key access on the bucket
	// - Key-centric: Define all bucket access on the key
	//
	// If the same permission is defined in both places, they are merged (not conflicting).
	// +optional
	KeyPermissions []KeyPermission `json:"keyPermissions,omitempty"`

	// BucketID pins this resource to a pre-existing Garage bucket ID.
	// When set, the operator will never create a new bucket — it only manages
	// settings and key permissions for the identified bucket. Takes priority
	// over GlobalAlias-based lookup. Useful for importing existing buckets and
	// for recovery after cluster incidents.
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// WebsiteExposure optionally exposes a website-enabled bucket through
	// Kubernetes HTTP routing: an Ingress or a Gateway API HTTPRoute, created
	// in this bucket's namespace and pointing at the referenced cluster's web
	// API Service. At most one of Ingress and Gateway may be set. Requires
	// spec.website.enabled. See the websiteExposure documentation for the
	// hostname semantics (Garage resolves the bucket from the Host header).
	// +optional
	WebsiteExposure *WebsiteExposureConfig `json:"websiteExposure,omitempty"`

	// Lifecycle configures bucket lifecycle policies (object expiration,
	// abort of incomplete multipart uploads).
	//
	// Garage exposes lifecycle only via the S3 API, not the admin API. The
	// operator applies rules using an internal access key it manages per
	// GarageCluster. Garage supports a strict subset of the AWS S3 lifecycle
	// spec: only Expiration (days or date, no ExpiredObjectDeleteMarker) and
	// AbortIncompleteMultipartUpload. Filters support prefix and object size
	// bounds; tag filters and the deprecated rule-level Prefix are not
	// accepted.
	//
	// Garage's lifecycle worker runs daily at midnight (UTC by default), so
	// rule evaluation is asynchronous from reconciliation.
	// +optional
	Lifecycle *BucketLifecycle `json:"lifecycle,omitempty"`
}

// BucketDeletionPolicy controls the lifecycle of the remote Garage bucket
// when its Kubernetes resource is deleted.
type BucketDeletionPolicy string

const (
	// BucketDeletionPolicyDelete deletes the remote bucket during finalization.
	BucketDeletionPolicyDelete BucketDeletionPolicy = "Delete"
	// BucketDeletionPolicyRetain removes Kubernetes management and preserves
	// the remote bucket unchanged.
	BucketDeletionPolicyRetain BucketDeletionPolicy = "Retain"
)

// EffectiveDeletionPolicy returns the configured policy, preserving the
// historical Delete behavior for objects created before the field existed.
func (s *GarageBucketSpec) EffectiveDeletionPolicy() BucketDeletionPolicy {
	if s == nil || s.DeletionPolicy == "" {
		return BucketDeletionPolicyDelete
	}
	return s.DeletionPolicy
}

// LocalAlias is a bucket alias that is only visible to a specific key.
// Unlike global aliases (which any key can use), a local alias is scoped to one key —
// useful when different teams share the same Garage cluster but use different bucket names.
// The alias is accessible via S3 as a bucket name when authenticated with that key.
type LocalAlias struct {
	// KeyRef is the name of the GarageKey in the same namespace that owns this alias.
	// +required
	KeyRef string `json:"keyRef"`

	// Alias is the bucket name this key will use to access the bucket.
	// Must be unique within the key's alias namespace.
	// +required
	Alias string `json:"alias"`
}

// BucketQuotas configures bucket quotas
type BucketQuotas struct {
	// MaxSize is the maximum bucket size in bytes. Omit it for no size limit:
	// Garage enforces 0 as a hard limit that rejects every write.
	// +optional
	MaxSize *resource.Quantity `json:"maxSize,omitempty"`

	// MaxObjects is the maximum number of objects. Omit it for no object limit:
	// Garage enforces 0 as a hard limit that rejects every new object.
	// +optional
	MaxObjects *int64 `json:"maxObjects,omitempty"`
}

// WebsiteConfig configures static website hosting.
// Only indexDocument and errorDocument are supported via the Garage Admin API.
// For routing rules and redirectAll, use the S3 PutBucketWebsite API directly.
type WebsiteConfig struct {
	// Enabled enables static website hosting.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// IndexDocument is the default index document (default: index.html)
	// +kubebuilder:default="index.html"
	// +optional
	IndexDocument string `json:"indexDocument,omitempty"`

	// ErrorDocument is the error document to serve for 404s
	// +optional
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// WebsiteExposureConfig declares how the operator exposes a website-enabled
// bucket over HTTP routing. The generated resource (Ingress or HTTPRoute) is
// created in the bucket's namespace and controller-owned by the
// GarageBucket. It routes to the referenced cluster's web API Service:
// <cluster>-gateway for unified clusters, <cluster> otherwise, unless
// BackendRef overrides the backend.
//
// An Ingress backend cannot cross namespaces, so Ingress exposure is only
// valid when the bucket and the referenced cluster share a namespace. An
// HTTPRoute backend reference crosses to the cluster's namespace and
// requires a gateway API ReferenceGrant in the cluster's namespace (owned
// by the storage admin) allowing HTTPRoutes from the bucket's namespace.
//
// Garage resolves the served bucket from the request Host header: it uses
// the Host with the cluster's webApi.rootDomain suffix removed when that
// matches, and otherwise falls back to the full Host as the alias. When
// Hostnames is empty, the operator uses the single canonical hostname
// <globalAlias><webApi.rootDomain>. For an HTTPRoute, a hostname that is
// neither canonical nor equal to the global alias is additionally matched
// with a URLRewrite filter rewriting the Host header to the canonical host.
// For an Ingress, which has no such rewrite filter, only the canonical
// hostname and the global alias are accepted; any other hostname is refused
// on the WebsiteExposed condition.
type WebsiteExposureConfig struct {
	// Hostnames are the external hostnames the exposure routes on. When
	// empty, the operator uses the single canonical hostname
	// <globalAlias><webApi.rootDomain>. Wildcards and duplicates are not
	// supported (duplicates are rejected by the validating webhook; the CRD
	// schema cannot express uniqueItems).
	//
	// For an HTTPRoute any hostname is accepted: a hostname that is neither
	// canonical nor the global alias gets a URLRewrite filter rewriting the
	// Host header back to the canonical host, so Garage still resolves it to
	// this bucket. For an Ingress, only the canonical hostname and the
	// global alias are accepted — an Ingress cannot rewrite the Host header,
	// so any other hostname is refused on the WebsiteExposed condition.
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:Items:Type=string
	// +kubebuilder:validation:Items:MinLength=1
	// +kubebuilder:validation:Items:MaxLength=253
	// +kubebuilder:validation:Items:Pattern=`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`
	// +optional
	Hostnames []string `json:"hostnames,omitempty"`

	// BackendRef overrides the Service the exposure routes to. When unset,
	// the operator targets the referenced cluster's web API Service
	// (<cluster>-gateway for unified clusters, <cluster> otherwise). For an
	// Ingress the referent must be a core/v1 Service in the bucket's
	// namespace (Ingress backends cannot cross namespaces). For an
	// HTTPRoute any referent valid for spec.rules[].backendRefs is
	// accepted, including cross-namespace ones (which additionally need a
	// gateway API ReferenceGrant).
	// +optional
	BackendRef *WebsiteExposureBackendReference `json:"backendRef,omitempty"`

	// Ingress configures the generated Kubernetes Ingress. Mutually
	// exclusive with Gateway. Only valid when the bucket and the referenced
	// cluster share a namespace.
	// +optional
	Ingress *WebsiteExposureIngressConfig `json:"ingress,omitempty"`

	// Gateway configures the generated Gateway API HTTPRoute. Mutually
	// exclusive with Ingress. Requires the Gateway API CRDs to be installed;
	// without them the operator reports a condition and does not fail the
	// bucket.
	// +optional
	Gateway *WebsiteExposureGatewayConfig `json:"gateway,omitempty"`
}

// WebsiteExposureBackendReference names the backend the exposure routes to
// instead of the referenced cluster's web API Service. The web port is
// selected by name ("web") for core/v1 Services and by the cluster's
// effective web API port otherwise.
type WebsiteExposureBackendReference struct {
	// Group of the referent. Defaults to "" (the core API group).
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group string `json:"group,omitempty"`

	// Kind of the referent. Defaults to Service.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Kind string `json:"kind,omitempty"`

	// Namespace of the referent. Defaults to the bucket's namespace (the
	// exposure resource's namespace). For an Ingress it must stay the
	// bucket's namespace: Ingress backends cannot cross namespaces.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Name of the referent.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`
}

// WebsiteExposureIngressConfig configures the Ingress the operator creates
// for a website-enabled bucket.
type WebsiteExposureIngressConfig struct {
	// IngressClassName is the ingress class the Ingress must match
	// (spec.ingressClassName). When empty, the Ingress is left without a
	// class so the cluster's default ingress controller picks it up.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	IngressClassName string `json:"ingressClassName,omitempty"`

	// TLSSecretName is the name of a TLS Secret in the bucket's namespace
	// (where the generated Ingress lives), attached to the Ingress
	// (spec.tls). The Secret must already exist; the operator does not
	// provision certificates.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	TLSSecretName string `json:"tlsSecretName,omitempty"`

	// Labels to add to the Ingress. Operator-managed labels take precedence
	// on conflict.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the Ingress (for example the TLS or
	// proxy-protocol annotations your ingress controller expects).
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// WebsiteExposureGatewayConfig configures the Gateway API HTTPRoute the
// operator creates for a website-enabled bucket.
type WebsiteExposureGatewayConfig struct {
	// ParentRefs are passed through verbatim to the HTTPRoute's
	// spec.parentRefs (Gateway names, optional sectionName, and optional
	// cross-namespace references). At least one is required.
	// +kubebuilder:validation:MinItems=1
	// +required
	ParentRefs []gatewayv1.ParentReference `json:"parentRefs"`

	// Labels to add to the HTTPRoute (for example external-dns or
	// argo-rollouts annotations). Operator-managed labels take precedence
	// on conflict.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the HTTPRoute.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// BucketLifecycle is a set of lifecycle rules applied to a bucket.
type BucketLifecycle struct {
	// Rules to apply. The operator replaces the bucket's lifecycle
	// configuration with this exact set on each reconcile.
	// +optional
	Rules []LifecycleRule `json:"rules,omitempty"`
}

// LifecycleRule is a single lifecycle rule. At least one action
// (ExpirationDays, ExpirationDate, AbortIncompleteMultipartUploadDays)
// must be set. ExpirationDays and ExpirationDate are mutually exclusive.
type LifecycleRule struct {
	// ID is the rule identifier. Must be unique within the bucket.
	// +required
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`

	// Status enables or disables this rule. Disabled rules are sent to
	// Garage but skipped by the lifecycle worker.
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +kubebuilder:default=Enabled
	// +optional
	Status string `json:"status,omitempty"`

	// Filter narrows the rule to a subset of objects. If unset, the rule
	// applies to every object in the bucket.
	// +optional
	Filter *LifecycleFilter `json:"filter,omitempty"`

	// ExpirationDays expires current objects this many days after creation.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ExpirationDays *int32 `json:"expirationDays,omitempty"`

	// ExpirationDate expires current objects on or after this UTC date.
	// +optional
	ExpirationDate *metav1.Time `json:"expirationDate,omitempty"`

	// AbortIncompleteMultipartUploadDays aborts multipart uploads that have
	// been pending for at least this many days.
	// +kubebuilder:validation:Minimum=1
	// +optional
	AbortIncompleteMultipartUploadDays *int32 `json:"abortIncompleteMultipartUploadDays,omitempty"`
}

// LifecycleFilter narrows a lifecycle rule to a subset of objects.
type LifecycleFilter struct {
	// Prefix matches object keys starting with this string.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// ObjectSizeGreaterThan matches objects strictly larger than this many
	// bytes.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ObjectSizeGreaterThan *int64 `json:"objectSizeGreaterThan,omitempty"`

	// ObjectSizeLessThan matches objects strictly smaller than this many
	// bytes.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ObjectSizeLessThan *int64 `json:"objectSizeLessThan,omitempty"`
}

// KeyRef is a reference to a GarageKey by name and optional namespace.
// Cross-namespace references require a GarageReferenceGrant in the target namespace.
type KeyRef struct {
	// Name of the GarageKey.
	// +required
	Name string `json:"name"`

	// Namespace of the GarageKey. Defaults to the GarageBucket's namespace.
	// Cross-namespace references require a GarageReferenceGrant in the target namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// KeyPermission grants access to a key
type KeyPermission struct {
	// KeyRef references the GarageKey by name (and optionally namespace).
	// +required
	KeyRef KeyRef `json:"keyRef"`

	// +kubebuilder:default=false
	// Read allows reading objects
	// +optional
	Read bool `json:"read"`

	// +kubebuilder:default=false
	// Write allows writing objects
	// +optional
	Write bool `json:"write"`

	// +kubebuilder:default=false
	// Owner allows bucket owner operations
	// +optional
	Owner bool `json:"owner"`
}

// GarageBucketStatus defines the observed state of GarageBucket
type GarageBucketStatus struct {
	// BucketID is the internal Garage bucket ID
	// +optional
	BucketID string `json:"bucketId,omitempty"`

	// Phase represents the current phase
	// +kubebuilder:validation:Enum=Pending;Creating;Ready;Deleting;Failed;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// GlobalAlias is the assigned global alias
	// +optional
	GlobalAlias string `json:"globalAlias,omitempty"`

	// CreatedAt is when the bucket was created in Garage
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`

	// Size is the current bucket size
	// +optional
	Size string `json:"size,omitempty"`

	// IncompleteUploads is the count of incomplete multipart uploads
	// +optional
	IncompleteUploads int64 `json:"incompleteUploads,omitempty"`

	// IncompleteUploadParts is the count of parts in incomplete multipart uploads
	// +optional
	IncompleteUploadParts int64 `json:"incompleteUploadParts,omitempty"`

	// IncompleteUploadBytes is the total bytes in incomplete multipart uploads
	// +optional
	IncompleteUploadBytes int64 `json:"incompleteUploadBytes,omitempty"`

	// WebsiteEnabled indicates if website hosting is currently enabled
	// +optional
	WebsiteEnabled bool `json:"websiteEnabled"`

	// WebsiteURL is the computed website URL (if website hosting is enabled)
	// +optional
	WebsiteURL string `json:"websiteUrl,omitempty"`

	// WebsiteConfig shows the current website configuration details
	// +optional
	WebsiteConfig *WebsiteConfigStatus `json:"websiteConfig,omitempty"`

	// WebsiteExposure reports the operator-generated HTTP routing resource
	// (Ingress or HTTPRoute) when spec.websiteExposure is set.
	// +optional
	WebsiteExposure *WebsiteExposureStatus `json:"websiteExposure,omitempty"`

	// QuotaUsage shows current quota consumption
	// +optional
	QuotaUsage *QuotaUsageStatus `json:"quotaUsage,omitempty"`

	// Keys contains keys with access to this bucket
	// +optional
	Keys []BucketKeyStatus `json:"keys,omitempty"`

	// ManagedKeyGrants lists access key IDs with reserved or active operator
	// ownership from this bucket's spec.keyPermissions. IDs are recorded before
	// the first remote mutation and removed only after exact convergence, allowing
	// crash-safe revocation when a declaration is dropped without disturbing
	// grants managed through GarageKey or by hand.
	// +optional
	ManagedKeyGrants []string `json:"managedKeyGrants,omitempty"`

	// ManagedGlobalAlias is the global alias reserved or successfully managed from
	// spec.globalAlias (or the bucket name when spec.globalAlias is empty).
	// It is separate from GlobalAlias, which reports observed Garage state, so
	// aliases created outside the operator are never removed accidentally.
	// +optional
	ManagedGlobalAlias string `json:"managedGlobalAlias,omitempty"`

	// PendingGlobalAlias reserves a replacement before its first remote add.
	// ManagedGlobalAlias retains the old alias until the replacement succeeds,
	// so a failed rename never leaves the bucket without its prior alias.
	// +optional
	PendingGlobalAlias string `json:"pendingGlobalAlias,omitempty"`

	// ManagedLocalAliases lists the per-key aliases reserved or successfully
	// managed from spec.localAliases. IDs are recorded before the first remote
	// add so an interrupted add can still be removed safely.
	// +optional
	ManagedLocalAliases []LocalAliasStatus `json:"managedLocalAliases,omitempty"`

	// LocalAliases tracks per-key local aliases for this bucket
	// +optional
	LocalAliases []LocalAliasStatus `json:"localAliases,omitempty"`

	// LifecycleRules summarises lifecycle rules currently applied to the
	// bucket in Garage. Spec is the source of truth for rule contents; this
	// list reports id and enabled state only.
	// +optional
	LifecycleRules []LifecycleRuleStatus `json:"lifecycleRules,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// QuotaUsageStatus shows quota consumption for a bucket
type QuotaUsageStatus struct {
	// SizeBytes is the current size in bytes
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// SizeLimit is the configured size limit in bytes. 0 means no size quota;
	// an explicit spec.quotas.maxSize of 0 (which blocks all writes) also reads 0.
	// +optional
	SizeLimit int64 `json:"sizeLimit,omitempty"`

	// SizePercent is the percentage of size quota used
	// +optional
	SizePercent int32 `json:"sizePercent,omitempty"`

	// ObjectCount is the current object count
	// +optional
	ObjectCount int64 `json:"objectCount,omitempty"`

	// ObjectLimit is the configured object limit. 0 means no object quota;
	// an explicit spec.quotas.maxObjects of 0 (which blocks new objects) also reads 0.
	// +optional
	ObjectLimit int64 `json:"objectLimit,omitempty"`

	// ObjectPercent is the percentage of object quota used
	// +optional
	ObjectPercent int32 `json:"objectPercent,omitempty"`
}

// BucketKeyStatus shows key access status
type BucketKeyStatus struct {
	// KeyID is the access key ID
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// Name is the key name
	// +optional
	Name string `json:"name,omitempty"`

	// Permissions granted to this key
	// +optional
	Permissions BucketKeyPermissions `json:"permissions,omitempty"`
}

// BucketKeyPermissions shows key permissions
type BucketKeyPermissions struct {
	// Read permission
	// +optional
	Read bool `json:"read"`

	// Write permission
	// +optional
	Write bool `json:"write"`

	// Owner permission
	// +optional
	Owner bool `json:"owner"`
}

// LocalAliasStatus shows the status of a local alias for this bucket
type LocalAliasStatus struct {
	// KeyID is the access key ID that owns this alias
	// +optional
	KeyID string `json:"keyId,omitempty"`

	// KeyName is the friendly name of the key
	// +optional
	KeyName string `json:"keyName,omitempty"`

	// Alias is the local alias name
	// +optional
	Alias string `json:"alias,omitempty"`
}

// LifecycleRuleStatus reports the id and enabled state of a lifecycle rule
// currently applied to the bucket.
type LifecycleRuleStatus struct {
	// ID of the rule.
	ID string `json:"id"`

	// Status is Enabled or Disabled.
	// +kubebuilder:validation:Enum=Enabled;Disabled
	Status string `json:"status"`
}

// WebsiteConfigStatus shows the current website configuration from Garage
// Note: Only indexDocument and errorDocument are returned by the Admin API.
// Routing rules and redirectAll are S3-API-only features and not visible here.
type WebsiteConfigStatus struct {
	// IndexDocument is the configured index document
	// +optional
	IndexDocument string `json:"indexDocument,omitempty"`

	// ErrorDocument is the configured error document
	// +optional
	ErrorDocument string `json:"errorDocument,omitempty"`
}

// WebsiteExposureStatus reports the generated websiteExposure routing
// resource. Readiness is carried by the WebsiteExposed condition, derived
// from the route's own status (parents Accepted/ResolvedRefs/Ready) for an
// HTTPRoute and from the successful apply for an Ingress.
type WebsiteExposureStatus struct {
	// Type is the kind of routing resource the operator manages for this
	// bucket: Ingress or HTTPRoute.
	// +kubebuilder:validation:Enum=Ingress;HTTPRoute
	// +optional
	Type string `json:"type,omitempty"`

	// Name is the name of the generated resource, in the bucket's namespace.
	// +optional
	Name string `json:"name,omitempty"`

	// Hostnames are the hostnames the generated resource routes on.
	// +optional
	Hostnames []string `json:"hostnames,omitempty"`

	// Parents mirrors the route's status.parents for an HTTPRoute: the
	// per-parent Accepted/ResolvedRefs/Ready conditions the Gateway
	// controllers publish. Empty for an Ingress, which has no per-parent
	// readiness model.
	// +optional
	Parents []WebsiteParentStatus `json:"parents,omitempty"`
}

// WebsiteParentStatus is the per-parent readiness of a generated HTTPRoute,
// mirroring gateway.networking.k8s.io/v1 RouteParentStatus conditions.
type WebsiteParentStatus struct {
	// Parent is the parent Gateway (or other parent) as namespace/name.
	// +optional
	Parent string `json:"parent,omitempty"`

	// Accepted is true when the parent accepted the route
	// (status.parents[].conditions[Accepted]=True).
	// +optional
	Accepted bool `json:"accepted,omitempty"`

	// ResolvedRefs is true when the route's backend references resolved on
	// that parent (status.parents[].conditions[ResolvedRefs]=True).
	// +optional
	ResolvedRefs bool `json:"resolvedRefs,omitempty"`

	// Ready is true when the parent reports the route Ready
	// (status.parents[].conditions[Ready]=True).
	// +optional
	Ready bool `json:"ready,omitempty"`

	// Message carries the parent's condition message when not ready.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gb,categories=garage
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Alias",type="string",JSONPath=".status.globalAlias"
// +kubebuilder:printcolumn:name="Bucket ID",type="string",JSONPath=".status.bucketId"
// +kubebuilder:printcolumn:name="Size",type="string",JSONPath=".status.size"
// +kubebuilder:printcolumn:name="Objects",type="integer",JSONPath=".status.quotaUsage.objectCount"
// +kubebuilder:printcolumn:name="Website",type="boolean",JSONPath=".status.websiteEnabled"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageBucket is the Schema for the garagebuckets API
type GarageBucket struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageBucketSpec `json:"spec"`

	// +optional
	Status GarageBucketStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageBucketList contains a list of GarageBucket
type GarageBucketList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageBucket `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageBucket{}, &GarageBucketList{})
}
