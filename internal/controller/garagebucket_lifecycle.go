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
	"fmt"
	"reflect"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// hardcoded GVK because controller-runtime's typed Get leaves TypeMeta empty.
func garageClusterRef(cluster *garagev1alpha1.GarageCluster) garage.ClusterRef {
	return garage.ClusterRef{
		Name:       cluster.Name,
		Namespace:  cluster.Namespace,
		UID:        cluster.UID,
		APIVersion: garagev1alpha1.GroupVersion.String(),
		Kind:       "GarageCluster",
	}
}

// reconcileLifecycleSafe runs lifecycle reconciliation and stores the
// outcome in bucket.Status (LifecycleRules + LifecycleConfigured condition).
// it never returns an error: lifecycle is auxiliary and must not block the
// bucket from going Ready.
func (r *GarageBucketReconciler) reconcileLifecycleSafe(
	ctx context.Context,
	bucket *garagev1alpha1.GarageBucket,
	cluster *garagev1alpha1.GarageCluster,
	bucketID string,
	bucketAlias string,
	adminClient *garage.Client,
) {
	log := logf.FromContext(ctx)

	if r.shouldSkipLifecycle(bucket) {
		// Nothing on either side; clear any condition lingering from a prior reconcile.
		meta.RemoveStatusCondition(&bucket.Status.Conditions, garagev1alpha1.ConditionLifecycleConfigured)
		bucket.Status.LifecycleRules = nil
		return
	}

	if err := r.applyLifecycle(ctx, bucket, cluster, bucketID, bucketAlias, adminClient); err != nil {
		log.Error(err, "Failed to reconcile bucket lifecycle", "bucket", bucket.Name)
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               garagev1alpha1.ConditionLifecycleConfigured,
			Status:             metav1.ConditionFalse,
			Reason:             "ApplyFailed",
			Message:            err.Error(),
			ObservedGeneration: bucket.Generation,
		})
		return
	}

	bucket.Status.LifecycleRules = lifecycleRulesStatusFromSpec(bucket.Spec.Lifecycle)
	meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
		Type:               garagev1alpha1.ConditionLifecycleConfigured,
		Status:             metav1.ConditionTrue,
		Reason:             "Applied",
		Message:            "Lifecycle rules applied",
		ObservedGeneration: bucket.Generation,
	})
}

// shouldSkipLifecycle returns true when neither spec nor status reports any
// lifecycle state, meaning we have nothing to do.
func (r *GarageBucketReconciler) shouldSkipLifecycle(bucket *garagev1alpha1.GarageBucket) bool {
	specEmpty := bucket.Spec.Lifecycle == nil || len(bucket.Spec.Lifecycle.Rules) == 0
	statusEmpty := len(bucket.Status.LifecycleRules) == 0
	cond := meta.FindStatusCondition(bucket.Status.Conditions, garagev1alpha1.ConditionLifecycleConfigured)
	return specEmpty && statusEmpty && cond == nil
}

// applyLifecycle performs the actual S3 lifecycle reconcile. it requires
// KeyManager and OperatorNamespace to be set.
func (r *GarageBucketReconciler) applyLifecycle(
	ctx context.Context,
	bucket *garagev1alpha1.GarageBucket,
	cluster *garagev1alpha1.GarageCluster,
	bucketID string,
	bucketAlias string,
	adminClient *garage.Client,
) error {
	if r.KeyManager == nil {
		return fmt.Errorf("internal key manager is not configured")
	}

	creds, err := r.KeyManager.EnsureKey(ctx, garageClusterRef(cluster), adminClient)
	if err != nil {
		return fmt.Errorf("ensure internal key: %w", err)
	}

	// Grant the operator key owner permission on this bucket. Garage treats
	// this as a no-op when the key already has owner.
	if _, err := adminClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
		BucketID:    bucketID,
		AccessKeyID: creds.AccessKeyID,
		Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
	}); err != nil {
		return fmt.Errorf("grant internal key owner permission: %w", err)
	}

	s3 := garage.NewS3LifecycleClient(s3EndpointURL(cluster, r.ClusterDomain), s3Region(cluster), creds.AccessKeyID, creds.SecretAccessKey)

	// lifecycle is addressed by the bucket's global alias on the S3 endpoint,
	// not by its internal Garage ID. caller guarantees bucketAlias is non-empty:
	// reconcileBucket falls back to spec-derived alias (bucket.Name or
	// spec.GlobalAlias), both required to be set.
	current, err := s3.GetLifecycle(ctx, bucketAlias)
	if err != nil {
		return fmt.Errorf("get current lifecycle: %w", err)
	}

	desired := buildLifecycleConfiguration(bucket.Spec.Lifecycle)

	switch {
	case desired == nil && current == nil:
		return nil
	case desired == nil && current != nil:
		return s3.DeleteLifecycle(ctx, bucketAlias)
	default:
		if lifecycleEqual(current, desired) {
			return nil
		}
		return s3.PutLifecycle(ctx, bucketAlias, desired)
	}
}

// buildLifecycleConfiguration translates the CRD lifecycle spec into the S3
// XML wire format. returns nil when the spec defines no rules.
func buildLifecycleConfiguration(spec *garagev1alpha1.BucketLifecycle) *garage.LifecycleConfiguration {
	if spec == nil || len(spec.Rules) == 0 {
		return nil
	}
	rules := make([]garage.LifecycleXMLRule, 0, len(spec.Rules))
	for _, rule := range spec.Rules {
		rules = append(rules, buildLifecycleXMLRule(rule))
	}
	// Sort by ID for deterministic comparison against the server.
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return &garage.LifecycleConfiguration{Rules: rules}
}

func buildLifecycleXMLRule(in garagev1alpha1.LifecycleRule) garage.LifecycleXMLRule {
	out := garage.LifecycleXMLRule{
		ID:     in.ID,
		Status: in.Status,
	}
	if out.Status == "" {
		out.Status = "Enabled"
	}
	if in.Filter != nil {
		out.Filter = buildLifecycleXMLFilter(in.Filter)
	}
	if in.ExpirationDays != nil {
		days := *in.ExpirationDays
		out.Expiration = &garage.LifecycleXMLExpiration{Days: &days}
	} else if in.ExpirationDate != nil {
		date := in.ExpirationDate.UTC().Format(time.RFC3339)
		out.Expiration = &garage.LifecycleXMLExpiration{Date: &date}
	}
	if in.AbortIncompleteMultipartUploadDays != nil {
		out.AbortIncompleteMultipartUpload = &garage.LifecycleXMLAbort{
			DaysAfterInitiation: *in.AbortIncompleteMultipartUploadDays,
		}
	}
	return out
}

// buildLifecycleXMLFilter chooses between a single direct child and an And
// block based on how many criteria the spec sets. AWS S3 requires And when
// combining multiple criteria.
func buildLifecycleXMLFilter(in *garagev1alpha1.LifecycleFilter) *garage.LifecycleXMLFilter {
	count := 0
	var prefix *string
	var gt, lt *int64
	if in.Prefix != "" {
		p := in.Prefix
		prefix = &p
		count++
	}
	if in.ObjectSizeGreaterThan != nil {
		v := *in.ObjectSizeGreaterThan
		gt = &v
		count++
	}
	if in.ObjectSizeLessThan != nil {
		v := *in.ObjectSizeLessThan
		lt = &v
		count++
	}
	out := &garage.LifecycleXMLFilter{}
	switch count {
	case 0:
		// Empty filter applies to all objects.
		return out
	case 1:
		out.Prefix = prefix
		out.ObjectSizeGreaterThan = gt
		out.ObjectSizeLessThan = lt
		return out
	default:
		out.And = &garage.LifecycleXMLAnd{
			Prefix:                prefix,
			ObjectSizeGreaterThan: gt,
			ObjectSizeLessThan:    lt,
		}
		return out
	}
}

// lifecycleCanonRule flattens the two wire shapes that vary on round-trip:
// filter shape (single child vs <And>) and date string format.
type lifecycleCanonRule struct {
	ID                                 string
	Status                             string
	HasFilter                          bool // distinguishes nil filter from empty filter
	Prefix                             *string
	ObjectSizeGreaterThan              *int64
	ObjectSizeLessThan                 *int64
	ExpirationDays                     *int32
	ExpirationDate                     *string // canonical RFC3339, UTC, second precision
	ExpirationDateRaw                  *string // set only when the wire date is unparseable
	AbortIncompleteMultipartUploadDays *int32
}

// lifecycleEqual compares semantically: rule order, filter shape, and
// date string format are normalised to suppress no-op re-PUTs.
func lifecycleEqual(a, b *garage.LifecycleConfiguration) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(canonicalizeLifecycle(a), canonicalizeLifecycle(b))
}

func canonicalizeLifecycle(cfg *garage.LifecycleConfiguration) []lifecycleCanonRule {
	out := make([]lifecycleCanonRule, 0, len(cfg.Rules))
	for i := range cfg.Rules {
		out = append(out, canonicalizeLifecycleRule(&cfg.Rules[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func canonicalizeLifecycleRule(in *garage.LifecycleXMLRule) lifecycleCanonRule {
	out := lifecycleCanonRule{ID: in.ID, Status: in.Status}
	if in.Filter != nil {
		out.HasFilter = true
		// lift criteria from either direct child or And block; equivalent shapes collapse
		if in.Filter.And != nil {
			out.Prefix = in.Filter.And.Prefix
			out.ObjectSizeGreaterThan = in.Filter.And.ObjectSizeGreaterThan
			out.ObjectSizeLessThan = in.Filter.And.ObjectSizeLessThan
		} else {
			out.Prefix = in.Filter.Prefix
			out.ObjectSizeGreaterThan = in.Filter.ObjectSizeGreaterThan
			out.ObjectSizeLessThan = in.Filter.ObjectSizeLessThan
		}
	}
	if in.Expiration != nil {
		out.ExpirationDays = in.Expiration.Days
		if in.Expiration.Date != nil {
			if t, ok := parseLifecycleDate(*in.Expiration.Date); ok {
				canonical := t.UTC().Truncate(time.Second).Format(time.RFC3339)
				out.ExpirationDate = &canonical
			} else {
				raw := *in.Expiration.Date
				out.ExpirationDateRaw = &raw
			}
		}
	}
	if in.AbortIncompleteMultipartUpload != nil {
		days := in.AbortIncompleteMultipartUpload.DaysAfterInitiation
		out.AbortIncompleteMultipartUploadDays = &days
	}
	return out
}

func parseLifecycleDate(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// safe to derive from spec: applyLifecycle only returns nil after a
// GetLifecycle round-trip confirmed the server matches desired (built from spec).
func lifecycleRulesStatusFromSpec(spec *garagev1alpha1.BucketLifecycle) []garagev1alpha1.LifecycleRuleStatus {
	if spec == nil || len(spec.Rules) == 0 {
		return nil
	}
	out := make([]garagev1alpha1.LifecycleRuleStatus, 0, len(spec.Rules))
	for _, rule := range spec.Rules {
		status := rule.Status
		if status == "" {
			status = "Enabled"
		}
		out = append(out, garagev1alpha1.LifecycleRuleStatus{
			ID:     rule.ID,
			Status: status,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
