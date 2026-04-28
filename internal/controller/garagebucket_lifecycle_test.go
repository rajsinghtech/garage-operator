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

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func days(n int32) *int32   { return &n }
func bytesP(n int64) *int64 { return &n }

func TestBuildLifecycleConfiguration_NilOrEmpty(t *testing.T) {
	if cfg := buildLifecycleConfiguration(nil); cfg != nil {
		t.Fatalf("nil spec should yield nil cfg, got %+v", cfg)
	}
	if cfg := buildLifecycleConfiguration(&garagev1alpha1.BucketLifecycle{}); cfg != nil {
		t.Fatalf("empty rules should yield nil cfg, got %+v", cfg)
	}
}

func TestBuildLifecycleConfiguration_DefaultsStatus(t *testing.T) {
	cfg := buildLifecycleConfiguration(&garagev1alpha1.BucketLifecycle{
		Rules: []garagev1alpha1.LifecycleRule{
			{ID: "r1", ExpirationDays: days(7)},
		},
	})
	if cfg == nil || len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", cfg)
	}
	if cfg.Rules[0].Status != "Enabled" {
		t.Fatalf("default Status should be Enabled, got %q", cfg.Rules[0].Status)
	}
	if cfg.Rules[0].Expiration == nil || cfg.Rules[0].Expiration.Days == nil || *cfg.Rules[0].Expiration.Days != 7 {
		t.Fatalf("expiration days not set: %+v", cfg.Rules[0].Expiration)
	}
}

func TestBuildLifecycleConfiguration_SortsByID(t *testing.T) {
	cfg := buildLifecycleConfiguration(&garagev1alpha1.BucketLifecycle{
		Rules: []garagev1alpha1.LifecycleRule{
			{ID: "z", ExpirationDays: days(1)},
			{ID: "a", ExpirationDays: days(1)},
			{ID: "m", ExpirationDays: days(1)},
		},
	})
	if cfg.Rules[0].ID != "a" || cfg.Rules[1].ID != "m" || cfg.Rules[2].ID != "z" {
		t.Fatalf("rules not sorted: %+v", cfg.Rules)
	}
}

func TestBuildLifecycleXMLFilter_SingleVsAnd(t *testing.T) {
	// single criterion -> direct child
	f := buildLifecycleXMLFilter(&garagev1alpha1.LifecycleFilter{Prefix: "logs/"})
	if f.Prefix == nil || *f.Prefix != "logs/" || f.And != nil {
		t.Fatalf("single should be direct, got %+v", f)
	}

	// multiple criteria -> And block
	f = buildLifecycleXMLFilter(&garagev1alpha1.LifecycleFilter{
		Prefix:                "logs/",
		ObjectSizeGreaterThan: bytesP(0),
		ObjectSizeLessThan:    bytesP(1024),
	})
	if f.Prefix != nil || f.And == nil {
		t.Fatalf("multiple should use And, got %+v", f)
	}
	if f.And.Prefix == nil || *f.And.Prefix != "logs/" {
		t.Fatalf("And prefix lost: %+v", f.And)
	}
	if f.And.ObjectSizeGreaterThan == nil || *f.And.ObjectSizeGreaterThan != 0 {
		t.Fatalf("And gt lost")
	}
	if f.And.ObjectSizeLessThan == nil || *f.And.ObjectSizeLessThan != 1024 {
		t.Fatalf("And lt lost")
	}

	// empty filter -> all-fields-nil filter
	f = buildLifecycleXMLFilter(&garagev1alpha1.LifecycleFilter{})
	if f == nil || f.Prefix != nil || f.And != nil {
		t.Fatalf("empty filter should produce empty struct, got %+v", f)
	}
}

func TestLifecycleEqual(t *testing.T) {
	p := "logs/"
	a := &garage.LifecycleConfiguration{Rules: []garage.LifecycleXMLRule{
		{ID: "x", Status: "Enabled", Filter: &garage.LifecycleXMLFilter{Prefix: &p}},
	}}
	b := &garage.LifecycleConfiguration{Rules: []garage.LifecycleXMLRule{
		{ID: "x", Status: "Enabled", Filter: &garage.LifecycleXMLFilter{Prefix: &p}},
	}}
	if !lifecycleEqual(a, b) {
		t.Fatal("equal configs should compare equal")
	}

	c := &garage.LifecycleConfiguration{Rules: []garage.LifecycleXMLRule{
		{ID: "x", Status: "Disabled", Filter: &garage.LifecycleXMLFilter{Prefix: &p}},
	}}
	if lifecycleEqual(a, c) {
		t.Fatal("status diff should not compare equal")
	}

	if !lifecycleEqual(nil, nil) {
		t.Fatal("nil/nil should compare equal")
	}
	if lifecycleEqual(a, nil) {
		t.Fatal("a/nil should not compare equal")
	}
}

func TestLifecycleEqual_OrderInsensitive(t *testing.T) {
	a := &garage.LifecycleConfiguration{Rules: []garage.LifecycleXMLRule{
		{ID: "a", Status: "Enabled"},
		{ID: "b", Status: "Enabled"},
	}}
	b := &garage.LifecycleConfiguration{Rules: []garage.LifecycleXMLRule{
		{ID: "b", Status: "Enabled"},
		{ID: "a", Status: "Enabled"},
	}}
	if !lifecycleEqual(a, b) {
		t.Fatal("rule order should not affect equality")
	}
}

func TestLifecycleRulesStatusFromSpec(t *testing.T) {
	spec := &garagev1alpha1.BucketLifecycle{
		Rules: []garagev1alpha1.LifecycleRule{
			{ID: "r1", ExpirationDays: days(7)}, // status defaulted
			{ID: "r2", Status: "Disabled", ExpirationDays: days(7)},
		},
	}
	got := lifecycleRulesStatusFromSpec(spec)
	want := []garagev1alpha1.LifecycleRuleStatus{
		{ID: "r1", Status: "Enabled"},
		{ID: "r2", Status: "Disabled"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	if lifecycleRulesStatusFromSpec(nil) != nil {
		t.Fatal("nil spec should return nil")
	}
}

func TestLifecycleBucketName_Fallbacks(t *testing.T) {
	b := &garagev1alpha1.GarageBucket{}
	b.Name = "fallback"
	if got := lifecycleBucketName(b); got != "fallback" {
		t.Fatalf("expected metadata fallback, got %q", got)
	}

	b.Spec.GlobalAlias = "spec-alias"
	if got := lifecycleBucketName(b); got != "spec-alias" {
		t.Fatalf("expected spec alias, got %q", got)
	}

	b.Status.GlobalAlias = "status-alias"
	if got := lifecycleBucketName(b); got != "status-alias" {
		t.Fatalf("expected status alias to win, got %q", got)
	}
}

func TestShouldSkipLifecycle(t *testing.T) {
	r := &GarageBucketReconciler{}

	// nothing on either side, no condition: skip
	b := &garagev1alpha1.GarageBucket{}
	if !r.shouldSkipLifecycle(b) {
		t.Fatal("should skip when nothing is set")
	}

	// spec set: do not skip
	b.Spec.Lifecycle = &garagev1alpha1.BucketLifecycle{Rules: []garagev1alpha1.LifecycleRule{
		{ID: "r1", ExpirationDays: days(7)},
	}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when spec has rules")
	}

	// spec cleared but status remembers prior state: do not skip (need to clear)
	b.Spec.Lifecycle = nil
	b.Status.LifecycleRules = []garagev1alpha1.LifecycleRuleStatus{{ID: "r1", Status: "Enabled"}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when status still reports rules")
	}

	// spec cleared but condition lingers: do not skip
	b.Status.LifecycleRules = nil
	b.Status.Conditions = []metav1.Condition{{Type: garagev1alpha1.ConditionLifecycleConfigured, Status: metav1.ConditionTrue}}
	if r.shouldSkipLifecycle(b) {
		t.Fatal("should not skip when condition lingers")
	}
}
