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
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garageversion"
)

// clusterDiscoveryEnabled reports whether a rendered [consul_discovery] or
// [kubernetes_discovery] section is present, mirroring the renderers.
func clusterDiscoveryEnabled(cluster *garagev1beta2.GarageCluster) bool {
	d := cluster.Spec.Discovery
	if d == nil {
		return false
	}
	return (d.Consul != nil && d.Consul.Enabled != nil && *d.Consul.Enabled) ||
		(d.Kubernetes != nil && d.Kubernetes.Enabled != nil && *d.Kubernetes.Enabled)
}

// discoveryCompatibilityCondition derives DiscoveryCompatible from the Garage
// versions the cluster reports. versions are the versions of nodes that are up
// in this pass; when none were observed the last recorded status.buildInfo is
// used instead. It returns (nil, false) when the condition should be removed
// (discovery disabled) and (nil, true) when there is no usable version signal
// and the existing condition must be left alone. Unparseable versions (dev
// builds such as v2.4.0-5-gabcdef, which may or may not carry the fix) are
// ignored rather than guessed at.
func discoveryCompatibilityCondition(
	cluster *garagev1beta2.GarageCluster, versions []string,
) (cond *metav1.Condition, keep bool) {
	if !clusterDiscoveryEnabled(cluster) {
		return nil, false
	}
	if len(versions) == 0 && cluster.Status.BuildInfo != nil {
		versions = []string{cluster.Status.BuildInfo.Version}
	}
	seen := map[garageversion.Version]bool{}
	var known, affected []garageversion.Version
	for _, raw := range versions {
		v, ok := garageversion.Parse(raw)
		if !ok || seen[v] {
			continue
		}
		seen[v] = true
		known = append(known, v)
		if v.DiscoveryPanicsAtStart() {
			affected = append(affected, v)
		}
	}
	if len(known) == 0 {
		return nil, true
	}
	sort.Slice(affected, func(i, j int) bool {
		a, b := affected[i], affected[j]
		return a.Minor < b.Minor || (a.Minor == b.Minor && a.Patch < b.Patch)
	})
	if len(affected) > 0 {
		return &metav1.Condition{
			Type:               garagev1beta1.ConditionDiscoveryCompatible,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonDiscoveryGarageVersionCrashes,
			Message:            garageversion.DiscoveryRuntimeMessage(affected),
			ObservedGeneration: cluster.Generation,
		}, false
	}
	return &metav1.Condition{
		Type:               garagev1beta1.ConditionDiscoveryCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonDiscoveryVersionSupported,
		Message:            "no running Garage node reports a release known to panic with peer discovery",
		ObservedGeneration: cluster.Generation,
	}, false
}

// applyDiscoveryCompatibility writes (or removes) DiscoveryCompatible and
// emits a Warning Event on the transition into False.
func (r *GarageClusterReconciler) applyDiscoveryCompatibility(cluster *garagev1beta2.GarageCluster, versions []string) {
	cond, keep := discoveryCompatibilityCondition(cluster, versions)
	if keep {
		return
	}
	if cond == nil {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionDiscoveryCompatible)
		return
	}
	previous := meta.FindStatusCondition(cluster.Status.Conditions, cond.Type)
	wasFalse := previous != nil && previous.Status == metav1.ConditionFalse
	meta.SetStatusCondition(&cluster.Status.Conditions, *cond)
	if cond.Status == metav1.ConditionFalse && !wasFalse {
		emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeWarning, "DiscoveryIncompatibleGarageVersion", "%s", cond.Message)
	}
}
