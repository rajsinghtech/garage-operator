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
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func days(n int32) *int32   { return &n }
func bytesP(n int64) *int64 { return &n }

const (
	testLifecycleEnabled  = "Enabled"
	testLifecycleDisabled = "Disabled"
	testPrefix            = "logs/"
)

func TestBuildAdminLifecycleRules_NilOrEmpty(t *testing.T) {
	if rules := buildAdminLifecycleRules(nil); rules != nil {
		t.Fatalf("nil spec should yield nil rules, got %+v", rules)
	}
	if rules := buildAdminLifecycleRules(&garagev1beta1.BucketLifecycle{}); rules != nil {
		t.Fatalf("empty rules should yield nil, got %+v", rules)
	}
}

func TestBuildAdminLifecycleRules_DefaultsStatus(t *testing.T) {
	rules := buildAdminLifecycleRules(&garagev1beta1.BucketLifecycle{
		Rules: []garagev1beta1.LifecycleRule{
			{ID: "r1", ExpirationDays: days(7)},
		},
	})
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", rules)
	}
	if rules[0].Status != testLifecycleEnabled {
		t.Fatalf("default Status should be Enabled, got %q", rules[0].Status)
	}
	if rules[0].Expiration == nil || rules[0].Expiration.Days == nil || *rules[0].Expiration.Days != 7 {
		t.Fatalf("expiration days not set: %+v", rules[0].Expiration)
	}
}

func TestBuildAdminLifecycleRules_SortsByID(t *testing.T) {
	rules := buildAdminLifecycleRules(&garagev1beta1.BucketLifecycle{
		Rules: []garagev1beta1.LifecycleRule{
			{ID: "z", ExpirationDays: days(1)},
			{ID: "a", ExpirationDays: days(1)},
			{ID: "m", ExpirationDays: days(1)},
		},
	})
	if *rules[0].ID != "a" || *rules[1].ID != "m" || *rules[2].ID != "z" {
		t.Fatalf("rules not sorted: %+v", rules)
	}
}

func TestBuildAdminLifecycleFilter_FlatFields(t *testing.T) {
	// single prefix criterion
	rule := buildAdminLifecycleRule(garagev1beta1.LifecycleRule{
		ID:     "r",
		Filter: &garagev1beta1.LifecycleFilter{Prefix: testPrefix},
	})
	if rule.Filter == nil || rule.Filter.Prefix == nil || *rule.Filter.Prefix != testPrefix {
		t.Fatalf("prefix not set: %+v", rule.Filter)
	}

	// multiple criteria → wrapped in <And> (Garage rejects a flat multi-condition
	// filter — src/api/common/xml/lifecycle.rs validate_into_garage_lifecycle_filter).
	rule = buildAdminLifecycleRule(garagev1beta1.LifecycleRule{
		ID: "r",
		Filter: &garagev1beta1.LifecycleFilter{
			Prefix:                testPrefix,
			ObjectSizeGreaterThan: bytesP(0),
			ObjectSizeLessThan:    bytesP(1024),
		},
	})
	if rule.Filter == nil || rule.Filter.And == nil {
		t.Fatalf("multi-criterion filter must be wrapped in And: %+v", rule.Filter)
	}
	// outer filter must carry no sibling conditions alongside And
	if rule.Filter.Prefix != nil || rule.Filter.ObjectSizeGreaterThan != nil || rule.Filter.ObjectSizeLessThan != nil {
		t.Fatalf("outer filter must be empty when And is set: %+v", rule.Filter)
	}
	and := rule.Filter.And
	if and.Prefix == nil || *and.Prefix != testPrefix {
		t.Fatalf("prefix not set inside And: %+v", and)
	}
	if and.ObjectSizeGreaterThan == nil || *and.ObjectSizeGreaterThan != 0 {
		t.Fatal("ObjectSizeGreaterThan not set inside And")
	}
	if and.ObjectSizeLessThan == nil || *and.ObjectSizeLessThan != 1024 {
		t.Fatal("ObjectSizeLessThan not set inside And")
	}

	// exactly two criteria (gt + lt, no prefix) → also wrapped in And
	rule = buildAdminLifecycleRule(garagev1beta1.LifecycleRule{
		ID: "r",
		Filter: &garagev1beta1.LifecycleFilter{
			ObjectSizeGreaterThan: bytesP(10),
			ObjectSizeLessThan:    bytesP(20),
		},
	})
	if rule.Filter == nil || rule.Filter.And == nil {
		t.Fatalf("gt+lt filter must be wrapped in And: %+v", rule.Filter)
	}

	// empty filter → nil filter on rule (Garage treats empty filter == no filter)
	rule = buildAdminLifecycleRule(garagev1beta1.LifecycleRule{
		ID:     "r",
		Filter: &garagev1beta1.LifecycleFilter{},
	})
	if rule.Filter != nil {
		t.Fatalf("empty filter should produce nil Filter on rule, got %+v", rule.Filter)
	}
}

func strPtr(s string) *string { return &s }

// TestAdminLifecycleEqual_AndRoundTrip guards the fix for the perpetual-drift
// bug: Garage returns a multi-condition filter nested under <And>, so the
// desired rule (also And-nested) must compare equal to it, and a flat
// representation of the same conditions must canonicalize identically.
func TestAdminLifecycleEqual_AndRoundTrip(t *testing.T) {
	desired := buildAdminLifecycleRules(&garagev1beta1.BucketLifecycle{
		Rules: []garagev1beta1.LifecycleRule{{
			ID:             "r",
			Status:         testLifecycleEnabled,
			Filter:         &garagev1beta1.LifecycleFilter{Prefix: testPrefix, ObjectSizeLessThan: bytesP(1024)},
			ExpirationDays: days(30),
		}},
	})
	if desired[0].Filter == nil || desired[0].Filter.And == nil {
		t.Fatalf("desired multi-condition filter should be And-nested: %+v", desired[0].Filter)
	}

	// how Garage returns the same rule on read: conditions nested under And.
	current := []garage.AdminLifecycleRule{{
		ID:     strPtr("r"),
		Status: testLifecycleEnabled,
		Filter: &garage.AdminLifecycleFilter{And: &garage.AdminLifecycleFilter{
			Prefix:             strPtr(testPrefix),
			ObjectSizeLessThan: bytesP(1024),
		}},
		Expiration: &garage.AdminLifecycleExpiration{Days: days(30)},
	}}
	if !adminLifecycleEqual(current, desired) {
		t.Fatal("And-nested current must compare equal to desired (else perpetual re-PUT)")
	}

	// a flat representation of the same conditions must canonicalize equal too.
	flat := []garage.AdminLifecycleRule{{
		ID:     strPtr("r"),
		Status: testLifecycleEnabled,
		Filter: &garage.AdminLifecycleFilter{
			Prefix:             strPtr(testPrefix),
			ObjectSizeLessThan: bytesP(1024),
		},
		Expiration: &garage.AdminLifecycleExpiration{Days: days(30)},
	}}
	if !adminLifecycleEqual(flat, desired) {
		t.Fatal("flat and And-nested filters with identical conditions must canonicalize equal")
	}
}

func TestAdminLifecycleEqual_Basic(t *testing.T) {
	a := []garage.AdminLifecycleRule{
		{ID: strPtr("x"), Status: testLifecycleEnabled, Filter: &garage.AdminLifecycleFilter{Prefix: strPtr(testPrefix)}},
	}
	b := []garage.AdminLifecycleRule{
		{ID: strPtr("x"), Status: testLifecycleEnabled, Filter: &garage.AdminLifecycleFilter{Prefix: strPtr(testPrefix)}},
	}
	if !adminLifecycleEqual(a, b) {
		t.Fatal("equal rules should compare equal")
	}

	c := []garage.AdminLifecycleRule{
		{ID: strPtr("x"), Status: testLifecycleDisabled, Filter: &garage.AdminLifecycleFilter{Prefix: strPtr(testPrefix)}},
	}
	if adminLifecycleEqual(a, c) {
		t.Fatal("status diff should not compare equal")
	}

	if !adminLifecycleEqual(nil, nil) {
		t.Fatal("nil/nil should compare equal")
	}
	if adminLifecycleEqual(a, nil) {
		t.Fatal("non-nil/nil should not compare equal")
	}
}

func TestAdminLifecycleEqual_DateNormalised(t *testing.T) {
	mkDate := func(s string) []garage.AdminLifecycleRule {
		return []garage.AdminLifecycleRule{
			{ID: strPtr("x"), Status: testLifecycleEnabled, Expiration: &garage.AdminLifecycleExpiration{Date: &s}},
		}
	}

	if !adminLifecycleEqual(mkDate("2026-04-29T00:00:00Z"), mkDate("2026-04-29T00:00:00+00:00")) {
		t.Fatal("Z and +00:00 spellings should compare equal")
	}
	if !adminLifecycleEqual(mkDate("2026-04-29T00:00:00.000Z"), mkDate("2026-04-29T00:00:00Z")) {
		t.Fatal("fractional-second precision should normalise away")
	}
	if adminLifecycleEqual(mkDate("2026-04-29T00:00:00Z"), mkDate("2026-04-30T00:00:00Z")) {
		t.Fatal("distinct instants must not compare equal")
	}
	if !adminLifecycleEqual(mkDate("not-a-date"), mkDate("not-a-date")) {
		t.Fatal("identical unparseable dates should compare equal")
	}
}

func TestAdminLifecycleEqual_OrderInsensitive(t *testing.T) {
	a := []garage.AdminLifecycleRule{
		{ID: strPtr("a"), Status: testLifecycleEnabled},
		{ID: strPtr("b"), Status: testLifecycleEnabled},
	}
	b := []garage.AdminLifecycleRule{
		{ID: strPtr("b"), Status: testLifecycleEnabled},
		{ID: strPtr("a"), Status: testLifecycleEnabled},
	}
	if !adminLifecycleEqual(a, b) {
		t.Fatal("rule order should not affect equality")
	}
}

func TestLifecycleRulesStatusFromSpec(t *testing.T) {
	spec := &garagev1beta1.BucketLifecycle{
		Rules: []garagev1beta1.LifecycleRule{
			{ID: "r1", ExpirationDays: days(7)}, // status defaulted
			{ID: "r2", Status: testLifecycleDisabled, ExpirationDays: days(7)},
		},
	}
	got := lifecycleRulesStatusFromSpec(spec)
	want := []garagev1beta1.LifecycleRuleStatus{
		{ID: "r1", Status: testLifecycleEnabled},
		{ID: "r2", Status: testLifecycleDisabled},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	if lifecycleRulesStatusFromSpec(nil) != nil {
		t.Fatal("nil spec should return nil")
	}
}

func TestShouldSkipLifecycle(t *testing.T) {
	r := &GarageBucketReconciler{}

	// nothing on either side, no condition: skip
	b := &garagev1beta1.GarageBucket{}
	if !r.shouldSkipLifecycle(b) {
		t.Fatal("should skip when nothing is set")
	}

	// spec set: do not skip
	b.Spec.Lifecycle = &garagev1beta1.BucketLifecycle{Rules: []garagev1beta1.LifecycleRule{
		{ID: "r1", ExpirationDays: days(7)},
	}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when spec has rules")
	}

	// spec cleared but status remembers prior state: do not skip (need to clear)
	b.Spec.Lifecycle = nil
	b.Status.LifecycleRules = []garagev1beta1.LifecycleRuleStatus{{ID: "r1", Status: testLifecycleEnabled}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when status still reports rules")
	}

	// spec cleared but condition lingers: do not skip
	b.Status.LifecycleRules = nil
	b.Status.Conditions = []metav1.Condition{{Type: garagev1beta1.ConditionLifecycleConfigured, Status: metav1.ConditionTrue}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when condition lingers")
	}
}
