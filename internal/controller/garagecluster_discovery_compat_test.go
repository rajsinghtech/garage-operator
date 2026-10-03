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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func discoveryCluster(consul, kubernetes bool) *garagev1beta2.GarageCluster {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "ns", Generation: 3}}
	if consul || kubernetes {
		cluster.Spec.Discovery = &garagev1beta2.DiscoveryConfig{}
	}
	if consul {
		cluster.Spec.Discovery.Consul = &garagev1beta2.ConsulDiscoveryConfig{Enabled: ptr.To(true)}
	}
	if kubernetes {
		cluster.Spec.Discovery.Kubernetes = &garagev1beta2.KubernetesDiscoveryConfig{Enabled: ptr.To(true)}
	}
	return cluster
}

func TestDiscoveryCompatibilityCondition(t *testing.T) {
	for _, tc := range []struct {
		name       string
		consul     bool
		kubernetes bool
		versions   []string
		buildInfo  string
		wantKeep   bool
		wantNil    bool
		want       metav1.ConditionStatus
		contains   string
	}{
		{name: "discovery disabled removes the condition", versions: []string{"v2.4.0"}, wantNil: true},
		{name: "consul on v2.4.0", consul: true, versions: []string{"v2.4.0"}, want: metav1.ConditionFalse, contains: "v2.4.0"},
		{name: "kubernetes on v2.3.0", kubernetes: true, versions: []string{"v2.3.0"}, want: metav1.ConditionFalse, contains: "v2.3.0"},
		{name: "fixed release", consul: true, kubernetes: true, versions: []string{"v2.4.1"}, want: metav1.ConditionTrue},
		{name: "mixed rollout reports only the affected release", consul: true,
			versions: []string{"v2.4.1", "v2.4.0", "v2.4.0", "v2.3.0"}, want: metav1.ConditionFalse, contains: "v2.3.0, v2.4.0"},
		{name: "falls back to status.buildInfo", consul: true, buildInfo: "v2.4.0", want: metav1.ConditionFalse, contains: "v2.4.0"},
		{name: "live nodes win over a stale buildInfo", consul: true, versions: []string{"v2.4.1"}, buildInfo: "v2.4.0", want: metav1.ConditionTrue},
		{name: "no version signal keeps the existing condition", consul: true, wantKeep: true, wantNil: true},
		{name: "unparseable dev build is ignored", consul: true, versions: []string{"v2.4.0-5-gabcdef"}, wantKeep: true, wantNil: true},
		{name: "dev build does not mask a known bad release", consul: true,
			versions: []string{"v2.4.0-5-gabcdef", "v2.4.0"}, want: metav1.ConditionFalse},
		{name: "unaffected old floor", kubernetes: true, versions: []string{"v2.0.0"}, want: metav1.ConditionTrue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := discoveryCluster(tc.consul, tc.kubernetes)
			if tc.buildInfo != "" {
				cluster.Status.BuildInfo = &garagev1beta2.GarageBuildInfo{Version: tc.buildInfo}
			}
			cond, keep := discoveryCompatibilityCondition(cluster, tc.versions)
			if keep != tc.wantKeep {
				t.Fatalf("keep = %v, want %v", keep, tc.wantKeep)
			}
			if tc.wantNil {
				if cond != nil {
					t.Fatalf("condition = %+v, want nil", cond)
				}
				return
			}
			if cond == nil || cond.Status != tc.want || cond.Type != garagev1beta1.ConditionDiscoveryCompatible {
				t.Fatalf("condition = %+v, want status %s", cond, tc.want)
			}
			if cond.ObservedGeneration != 3 {
				t.Errorf("observedGeneration = %d, want 3", cond.ObservedGeneration)
			}
			if tc.want == metav1.ConditionFalse && cond.Reason != garagev1beta1.ReasonDiscoveryGarageVersionCrashes {
				t.Errorf("reason = %q", cond.Reason)
			}
			if tc.want == metav1.ConditionTrue && cond.Reason != garagev1beta1.ReasonDiscoveryVersionSupported {
				t.Errorf("reason = %q", cond.Reason)
			}
			if !strings.Contains(cond.Message, tc.contains) {
				t.Errorf("message %q missing %q", cond.Message, tc.contains)
			}
		})
	}
}

func TestApplyDiscoveryCompatibilityLifecycle(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	r := &GarageClusterReconciler{EventRecorder: recorder}
	cluster := discoveryCluster(true, false)

	r.applyDiscoveryCompatibility(cluster, []string{"v2.4.0"})
	cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionDiscoveryCompatible)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("want DiscoveryCompatible=False, got %+v", cond)
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("want one Warning event on the transition, got %d", len(recorder.Events))
	}
	if event := <-recorder.Events; !strings.HasPrefix(event, "Warning DiscoveryIncompatibleGarageVersion") {
		t.Errorf("unexpected event %q", event)
	}

	// Steady state must not re-emit.
	r.applyDiscoveryCompatibility(cluster, []string{"v2.4.0"})
	if len(recorder.Events) != 0 {
		t.Errorf("steady False must not emit another event")
	}

	// A pass with no usable version leaves the verdict alone.
	r.applyDiscoveryCompatibility(cluster, nil)
	if cond = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionDiscoveryCompatible); cond == nil ||
		cond.Status != metav1.ConditionFalse {
		t.Fatalf("an unobservable pass must keep False, got %+v", cond)
	}

	r.applyDiscoveryCompatibility(cluster, []string{"v2.4.1"})
	if cond = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionDiscoveryCompatible); cond == nil ||
		cond.Status != metav1.ConditionTrue {
		t.Fatalf("upgrade must flip to True, got %+v", cond)
	}

	cluster.Spec.Discovery = nil
	r.applyDiscoveryCompatibility(cluster, []string{"v2.4.0"})
	if cond = meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionDiscoveryCompatible); cond != nil {
		t.Fatalf("disabling discovery must remove the condition, got %+v", cond)
	}

	// A nil recorder must not panic.
	(&GarageClusterReconciler{}).applyDiscoveryCompatibility(discoveryCluster(false, true), []string{"v2.3.0"})
}
