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

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const lifecycleStatusEnabled = "Enabled"

// reconcileLifecycleSafe runs lifecycle reconciliation and stores the
// outcome in bucket.Status (LifecycleRules + LifecycleConfigured condition).
// It never returns an error: lifecycle is auxiliary and must not block the
// bucket from going Ready.
func (r *GarageBucketReconciler) reconcileLifecycleSafe(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	bucketID string,
	adminClient *garage.Client,
) {
	log := logf.FromContext(ctx)

	if r.shouldSkipLifecycle(bucket) {
		meta.RemoveStatusCondition(&bucket.Status.Conditions, garagev1beta1.ConditionLifecycleConfigured)
		bucket.Status.LifecycleRules = nil
		return
	}

	if err := r.applyLifecycle(ctx, bucket, bucketID, adminClient); err != nil {
		log.Error(err, "Failed to reconcile bucket lifecycle", "bucket", bucket.Name)
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionLifecycleConfigured,
			Status:             metav1.ConditionFalse,
			Reason:             "ApplyFailed",
			Message:            err.Error(),
			ObservedGeneration: bucket.Generation,
		})
		return
	}

	bucket.Status.LifecycleRules = lifecycleRulesStatusFromSpec(bucket.Spec.Lifecycle)
	meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionLifecycleConfigured,
		Status:             metav1.ConditionTrue,
		Reason:             "Applied",
		Message:            "Lifecycle rules applied",
		ObservedGeneration: bucket.Generation,
	})
}

// shouldSkipLifecycle returns true when neither spec nor status reports any
// lifecycle state, meaning we have nothing to do.
func (r *GarageBucketReconciler) shouldSkipLifecycle(bucket *garagev1beta1.GarageBucket) bool {
	specEmpty := bucket.Spec.Lifecycle == nil || len(bucket.Spec.Lifecycle.Rules) == 0
	statusEmpty := len(bucket.Status.LifecycleRules) == 0
	cond := meta.FindStatusCondition(bucket.Status.Conditions, garagev1beta1.ConditionLifecycleConfigured)
	return specEmpty && statusEmpty && cond == nil
}

// applyLifecycle uses the Admin API to reconcile lifecycle rules on the bucket.
func (r *GarageBucketReconciler) applyLifecycle(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	bucketID string,
	adminClient *garage.Client,
) error {
	desired := buildAdminLifecycleRules(bucket.Spec.Lifecycle)

	current, err := adminClient.GetBucketLifecycle(ctx, bucketID)
	if err != nil {
		return fmt.Errorf("get current lifecycle: %w", err)
	}

	switch {
	case len(desired) == 0 && len(current) == 0:
		return nil
	case len(desired) == 0:
		return adminClient.SetBucketLifecycle(ctx, bucketID, []garage.AdminLifecycleRule{})
	default:
		if adminLifecycleEqual(current, desired) {
			return nil
		}
		return adminClient.SetBucketLifecycle(ctx, bucketID, desired)
	}
}

// buildAdminLifecycleRules translates the CRD lifecycle spec into Admin API rules.
// Returns nil when the spec defines no rules.
func buildAdminLifecycleRules(spec *garagev1beta1.BucketLifecycle) []garage.AdminLifecycleRule {
	if spec == nil || len(spec.Rules) == 0 {
		return nil
	}
	rules := make([]garage.AdminLifecycleRule, 0, len(spec.Rules))
	for _, rule := range spec.Rules {
		rules = append(rules, buildAdminLifecycleRule(rule))
	}
	sort.Slice(rules, func(i, j int) bool {
		return adminRuleID(rules[i]) < adminRuleID(rules[j])
	})
	return rules
}

func adminRuleID(r garage.AdminLifecycleRule) string {
	if r.ID != nil {
		return *r.ID
	}
	return ""
}

func buildAdminLifecycleRule(in garagev1beta1.LifecycleRule) garage.AdminLifecycleRule {
	id := in.ID
	out := garage.AdminLifecycleRule{
		ID:     &id,
		Status: in.Status,
	}
	if out.Status == "" {
		out.Status = lifecycleStatusEnabled
	}
	if in.Filter != nil {
		f := buildAdminLifecycleFilter(in.Filter)
		// only attach filter if it has at least one criterion
		if f.Prefix != nil || f.ObjectSizeGreaterThan != nil || f.ObjectSizeLessThan != nil {
			out.Filter = f
		}
	}
	if in.ExpirationDays != nil {
		days := *in.ExpirationDays
		out.Expiration = &garage.AdminLifecycleExpiration{Days: &days}
	} else if in.ExpirationDate != nil {
		date := in.ExpirationDate.UTC().Format(time.RFC3339)
		out.Expiration = &garage.AdminLifecycleExpiration{Date: &date}
	}
	if in.AbortIncompleteMultipartUploadDays != nil {
		out.AbortIncompleteMultipartUpload = &garage.AdminLifecycleAbort{
			DaysAfterInitiation: *in.AbortIncompleteMultipartUploadDays,
		}
	}
	return out
}

func buildAdminLifecycleFilter(in *garagev1beta1.LifecycleFilter) *garage.AdminLifecycleFilter {
	f := &garage.AdminLifecycleFilter{}
	if in.Prefix != "" {
		p := in.Prefix
		f.Prefix = &p
	}
	if in.ObjectSizeGreaterThan != nil {
		v := *in.ObjectSizeGreaterThan
		f.ObjectSizeGreaterThan = &v
	}
	if in.ObjectSizeLessThan != nil {
		v := *in.ObjectSizeLessThan
		f.ObjectSizeLessThan = &v
	}
	return f
}

// adminLifecycleCanonRule is the normalised form used for equality comparison.
type adminLifecycleCanonRule struct {
	ID                                 string
	Status                             string
	Prefix                             *string
	ObjectSizeGreaterThan              *int64
	ObjectSizeLessThan                 *int64
	ExpirationDays                     *int32
	ExpirationDate                     *string // canonical RFC3339 UTC, second precision
	ExpirationDateRaw                  *string // set only when the wire date is unparseable
	AbortIncompleteMultipartUploadDays *int32
}

func adminLifecycleEqual(a, b []garage.AdminLifecycleRule) bool {
	if len(a) != len(b) {
		return false
	}
	return reflect.DeepEqual(canonicalizeAdminLifecycle(a), canonicalizeAdminLifecycle(b))
}

func canonicalizeAdminLifecycle(rules []garage.AdminLifecycleRule) []adminLifecycleCanonRule {
	out := make([]adminLifecycleCanonRule, 0, len(rules))
	for i := range rules {
		out = append(out, canonicalizeAdminRule(&rules[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func canonicalizeAdminRule(in *garage.AdminLifecycleRule) adminLifecycleCanonRule {
	out := adminLifecycleCanonRule{
		ID:     adminRuleID(*in),
		Status: in.Status,
	}
	if in.Filter != nil {
		out.Prefix = in.Filter.Prefix
		out.ObjectSizeGreaterThan = in.Filter.ObjectSizeGreaterThan
		out.ObjectSizeLessThan = in.Filter.ObjectSizeLessThan
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

func lifecycleRulesStatusFromSpec(spec *garagev1beta1.BucketLifecycle) []garagev1beta1.LifecycleRuleStatus {
	if spec == nil || len(spec.Rules) == 0 {
		return nil
	}
	out := make([]garagev1beta1.LifecycleRuleStatus, 0, len(spec.Rules))
	for _, rule := range spec.Rules {
		status := rule.Status
		if status == "" {
			status = lifecycleStatusEnabled
		}
		out = append(out, garagev1beta1.LifecycleRuleStatus{
			ID:     rule.ID,
			Status: status,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
