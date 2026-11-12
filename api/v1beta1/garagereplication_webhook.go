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
	"net/url"
	"strings"

	"github.com/robfig/cron/v3"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	garageReplicationKind = "GarageReplication"

	// ReplicationDefaultAccessKeyIDKey matches the GarageKey Secret default.
	ReplicationDefaultAccessKeyIDKey = "access-key-id"
	// ReplicationDefaultSecretAccessKeyKey matches the GarageKey Secret default.
	ReplicationDefaultSecretAccessKeyKey = "secret-access-key"
	// ReplicationDefaultCABundleKey is the default caBundleRef key.
	ReplicationDefaultCABundleKey = "ca.crt"
	// ReplicationDefaultRegion is Garage's default s3_region.
	ReplicationDefaultRegion = "garage"

	// Field names of the credential key selectors, shared with GarageKey.
	accessKeyIDKeyField     = "accessKeyIdKey"
	secretAccessKeyKeyField = "secretAccessKeyKey"
)

var garagereplicationlog = logf.Log.WithName("garagereplication-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageReplication) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&GarageReplicationValidator{Client: mgr.GetClient(), AuthorizationReader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagereplication,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagereplications,verbs=create;update,versions=v1beta1,name=vgaragereplication.kb.io,admissionReviewVersions=v1
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereplications,verbs=get;list;watch

var _ admission.Validator[*GarageReplication] = &GarageReplicationValidator{}

// +kubebuilder:object:generate=false

// GarageReplicationValidator handles validation for GarageReplication.
//
// Field formats, enums, list keys and the mode/mirror pairing are enforced by
// the CRD schema. The webhook only adds what needs context: the reference
// grant of a cross-namespace clusterRef, destination buckets claimed by
// another GarageReplication, and checks CEL cannot express.
type GarageReplicationValidator struct {
	Client              client.Client
	AuthorizationReader client.Reader
}

func (v *GarageReplicationValidator) authorizationReader() client.Reader {
	if v.AuthorizationReader != nil {
		return v.AuthorizationReader
	}
	return v.Client
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReplicationValidator) ValidateCreate(ctx context.Context, obj *GarageReplication) (admission.Warnings, error) {
	garagereplicationlog.Info("validate create", "name", obj.Name)
	return v.validate(ctx, obj)
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReplicationValidator) ValidateUpdate(ctx context.Context, _, newObj *GarageReplication) (admission.Warnings, error) {
	garagereplicationlog.Info("validate update", "name", newObj.Name)
	return v.validate(ctx, newObj)
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageReplicationValidator) ValidateDelete(_ context.Context, obj *GarageReplication) (admission.Warnings, error) {
	garagereplicationlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

func (v *GarageReplicationValidator) validate(ctx context.Context, obj *GarageReplication) (admission.Warnings, error) {
	warnings, err := ValidateGarageReplicationSpec(obj)
	if err != nil {
		return warnings, err
	}
	for _, side := range []struct {
		field    string
		endpoint ReplicationEndpoint
	}{{"source", obj.Spec.Source}, {"destination", obj.Spec.Destination}} {
		ref := side.endpoint.ClusterRef
		if ref == nil {
			continue
		}
		name, namespace := effectiveClusterReference(*ref, obj.Namespace)
		if err := checkReferenceGrant(ctx, v.authorizationReader(), garageReplicationKind, obj.Namespace, garageClusterKind, namespace, name); err != nil {
			return warnings, fmt.Errorf("spec.%s.clusterRef: %w", side.field, err)
		}
	}
	if err := v.validateDestinationExclusivity(ctx, obj); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// validateDestinationExclusivity rejects a destination bucket another
// GarageReplication already writes: two Mirrors on one bucket would delete
// each other's objects. The check is best-effort against the informer cache
// (it only sees the namespaces the operator watches); the controller applies
// the same rule before starting Jobs.
func (v *GarageReplicationValidator) validateDestinationExclusivity(ctx context.Context, obj *GarageReplication) error {
	if v.Client == nil {
		return nil
	}
	var existing GarageReplicationList
	if err := v.Client.List(ctx, &existing); err != nil {
		return fmt.Errorf("failed to check destination buckets of other GarageReplications: %w", err)
	}
	if other, bucket := FindReplicationDestinationConflict(obj, existing.Items); other != nil {
		return fmt.Errorf("destination bucket %q is already written by GarageReplication %s/%s; a destination bucket can be written by only one GarageReplication",
			bucket, other.Namespace, other.Name)
	}
	return nil
}

// EffectiveReplicationMode returns spec.mode with its default applied.
func EffectiveReplicationMode(spec *GarageReplicationSpec) ReplicationMode {
	if spec.Mode == "" {
		return ReplicationModeCopy
	}
	return spec.Mode
}

// ParseReplicationSchedule parses spec.schedule. An empty schedule returns a
// nil schedule and no error.
func ParseReplicationSchedule(schedule string) (cron.Schedule, error) {
	if strings.TrimSpace(schedule) == "" {
		return nil, nil
	}
	return cron.ParseStandard(schedule)
}

// ValidateGarageReplicationSpec validates what the CRD schema cannot and that
// does not need the API server. It is shared by admission and reconciliation
// so objects persisted without the webhook fail with the same error.
func ValidateGarageReplicationSpec(obj *GarageReplication) (admission.Warnings, error) {
	var warnings admission.Warnings
	spec := &obj.Spec

	for _, side := range []struct {
		field    string
		endpoint ReplicationEndpoint
	}{{"spec.source", spec.Source}, {"spec.destination", spec.Destination}} {
		if (side.endpoint.ClusterRef == nil) == (side.endpoint.Endpoint == nil) {
			return warnings, fmt.Errorf("%s: exactly one of clusterRef or endpoint must be set", side.field)
		}
		if ref := side.endpoint.ClusterRef; ref != nil {
			if err := ValidateClusterReference(*ref, side.field+".clusterRef"); err != nil {
				return warnings, err
			}
		}
	}

	// The schema catches a self-loop between two endpoint URLs that differ at
	// most by case. A clusterRef self-loop (whose namespace may be implicit)
	// and URL spellings differing by a trailing slash or a default port are
	// caught here.
	sameCluster := ReplicationEndpointKey(spec.Source, obj.Namespace) == ReplicationEndpointKey(spec.Destination, obj.Namespace)
	for i, b := range spec.Buckets {
		if sameCluster && b.Source == b.Destination {
			return warnings, fmt.Errorf("spec.buckets[%d] replicates bucket %q onto itself: source and destination are the same cluster", i, b.Source)
		}
	}

	if _, err := ParseReplicationSchedule(spec.Schedule); err != nil {
		return warnings, fmt.Errorf("spec.schedule %q is not a valid cron expression: %w", spec.Schedule, err)
	}

	if pt := spec.PodTemplate; pt != nil {
		for key, value := range pt.Labels {
			if problems := utilvalidation.IsQualifiedName(key); len(problems) > 0 {
				return warnings, fmt.Errorf("spec.podTemplate.labels key %q is invalid: %s", key, strings.Join(problems, "; "))
			}
			if problems := utilvalidation.IsValidLabelValue(value); len(problems) > 0 {
				return warnings, fmt.Errorf("spec.podTemplate.labels[%q] value %q is invalid: %s", key, value, strings.Join(problems, "; "))
			}
		}
		for key := range pt.Annotations {
			if problems := utilvalidation.IsQualifiedName(key); len(problems) > 0 {
				return warnings, fmt.Errorf("spec.podTemplate.annotations key %q is invalid: %s", key, strings.Join(problems, "; "))
			}
		}
	}

	if EffectiveReplicationMode(spec) == ReplicationModeMirror {
		warnings = append(warnings, "mode Mirror deletes destination objects that do not exist on the source (up to spec.mirror.maxDeletes per bucket and run); the first run waits for the garage.rajsingh.info/trigger-sync annotation")
	}
	if sameCluster {
		warnings = append(warnings, "source and destination are the same cluster; this copies between buckets of one cluster and protects against neither cluster loss nor cluster migration")
	}
	return warnings, nil
}

// ReplicationCredentialKeys returns the effective Secret data keys.
func ReplicationCredentialKeys(ref ReplicationCredentialsRef) (string, string) {
	idKey, secretKey := ref.AccessKeyIDKey, ref.SecretAccessKeyKey
	if idKey == "" {
		idKey = ReplicationDefaultAccessKeyIDKey
	}
	if secretKey == "" {
		secretKey = ReplicationDefaultSecretAccessKeyKey
	}
	return idKey, secretKey
}

// ReplicationEndpointKey identifies the cluster an endpoint points at as
// written in the spec: "cluster:<namespace>/<name>" for a clusterRef (the
// namespace defaulted), or the normalized URL for an explicit endpoint.
// A clusterRef and a URL that resolve to the same cluster get different
// keys; the controller compares resolved URLs as well.
func ReplicationEndpointKey(e ReplicationEndpoint, namespace string) string {
	if e.ClusterRef != nil {
		name, ns := effectiveClusterReference(*e.ClusterRef, namespace)
		return "cluster:" + ns + "/" + name
	}
	if e.Endpoint != nil {
		return NormalizeReplicationURL(e.Endpoint.URL)
	}
	return ""
}

// NormalizeReplicationURL lowercases scheme and host and drops a trailing
// slash and the scheme's default port, so spellings of one endpoint compare
// equal.
func NormalizeReplicationURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(strings.ToLower(raw), "/")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

// ReplicationPrecedes orders GarageReplications claiming the same destination
// bucket: the older one keeps it (creation time, then namespace/name). An
// object being created has no creation time yet and loses to every
// existing one.
func ReplicationPrecedes(a, b *GarageReplication) bool {
	at, bt := a.CreationTimestamp, b.CreationTimestamp
	switch {
	case at.IsZero() != bt.IsZero():
		return bt.IsZero()
	case !at.Equal(&bt):
		return at.Before(&bt)
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

// FindReplicationDestinationConflict returns a GarageReplication of items that
// precedes self and writes one of self's destination buckets on the same
// destination cluster, with that bucket. It returns nil when self owns all of
// its destinations.
func FindReplicationDestinationConflict(self *GarageReplication, items []GarageReplication) (*GarageReplication, string) {
	if self == nil {
		return nil, ""
	}
	selfKey := ReplicationEndpointKey(self.Spec.Destination, self.Namespace)
	for i := range items {
		other := &items[i]
		if other.Namespace == self.Namespace && other.Name == self.Name {
			continue
		}
		if ReplicationEndpointKey(other.Spec.Destination, other.Namespace) != selfKey || !ReplicationPrecedes(other, self) {
			continue
		}
		for _, b := range self.Spec.Buckets {
			for _, ob := range other.Spec.Buckets {
				if b.Destination == ob.Destination {
					return other, b.Destination
				}
			}
		}
	}
	return nil, ""
}
