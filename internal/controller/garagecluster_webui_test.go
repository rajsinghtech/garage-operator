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
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	webUITestHost  = "garage-ui.example.com"
	webUITestRoute = "garage-webui"
)

func webUITestCluster(cfg *garagev1beta2.WebUIConfig) *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "garage",
			Namespace:  "garage-ns",
			UID:        types.UID("cluster-uid-webui"),
			Generation: 3,
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			Admin:   &garagev1beta2.AdminConfig{BindPort: 3913, WebUI: cfg},
		},
	}
}

func webUICondition(t *testing.T, cluster *garagev1beta2.GarageCluster, condType string) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(cluster.Status.Conditions, condType)
	if c == nil {
		t.Fatalf("%s condition not found in %+v", condType, cluster.Status.Conditions)
	}
	return c
}

func TestWebUIURLs(t *testing.T) {
	cluster := webUITestCluster(nil)
	if got, want := webUIInClusterURL(cluster, "cluster.local"), "http://garage.garage-ns.svc.cluster.local:3913/ui/"; got != want {
		t.Fatalf("in-cluster URL = %q, want %q", got, want)
	}
	cases := []struct {
		name string
		cfg  garagev1beta2.WebUIConfig
		want string
	}{
		{"ingress without TLS", garagev1beta2.WebUIConfig{Hostname: webUITestHost, Ingress: &garagev1beta2.WebUIIngressConfig{}}, "http://" + webUITestHost + "/ui/"},
		{"ingress with TLS", garagev1beta2.WebUIConfig{Hostname: webUITestHost, Ingress: &garagev1beta2.WebUIIngressConfig{TLSSecretName: "tls"}}, "https://" + webUITestHost + "/ui/"},
		{"gateway defaults to http", garagev1beta2.WebUIConfig{Hostname: webUITestHost, Gateway: &garagev1beta2.WebUIGatewayConfig{}}, "http://" + webUITestHost + "/ui/"},
		{"explicit scheme wins", garagev1beta2.WebUIConfig{Hostname: webUITestHost, Scheme: "https", Gateway: &garagev1beta2.WebUIGatewayConfig{}}, "https://" + webUITestHost + "/ui/"},
		{"explicit http beats TLS secret", garagev1beta2.WebUIConfig{Hostname: webUITestHost, Scheme: "http", Ingress: &garagev1beta2.WebUIIngressConfig{TLSSecretName: "tls"}}, "http://" + webUITestHost + "/ui/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := webUIExternalURL(&tc.cfg); got != tc.want {
				t.Fatalf("external URL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWebUIAvailabilityCondition(t *testing.T) {
	cluster := webUITestCluster(nil)
	id := func(c byte) string { return strings.Repeat(string(c), 64) }
	withUI := garage.NodeBuildInfo{GarageVersion: "v2.6.0", GarageFeatures: []string{"k2v", "metrics", "webadmin"}}
	withoutUI := garage.NodeBuildInfo{GarageVersion: "v2.5.0", GarageFeatures: []string{"k2v", "metrics"}}

	if cond, keep := webUIAvailabilityCondition(cluster, nil); cond != nil || !keep {
		t.Fatalf("no observation must keep the previous condition, got %+v keep=%v", cond, keep)
	}

	cond, keep := webUIAvailabilityCondition(cluster, map[string]garage.NodeBuildInfo{id('a'): withUI, id('b'): withUI})
	if keep || cond.Status != metav1.ConditionTrue || cond.Reason != garagev1beta1.ReasonWebUIFeaturePresent || cond.ObservedGeneration != 3 {
		t.Fatalf("all nodes with webadmin: %+v keep=%v", cond, keep)
	}

	cond, _ = webUIAvailabilityCondition(cluster, map[string]garage.NodeBuildInfo{id('a'): withUI, id('b'): withoutUI})
	if cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonWebUIFeatureNotPresent {
		t.Fatalf("mixed versions: %+v", cond)
	}
	if !strings.Contains(cond.Message, "1 of 2") || !strings.Contains(cond.Message, strings.Repeat("b", 16)+" (v2.5.0)") ||
		strings.Contains(cond.Message, strings.Repeat("a", 16)) {
		t.Fatalf("message must name only the node without the feature: %q", cond.Message)
	}

	r := &GarageClusterReconciler{}
	r.applyWebUIAvailability(cluster, map[string]garage.NodeBuildInfo{id('a'): withoutUI})
	if c := webUICondition(t, cluster, garagev1beta1.ConditionWebUIAvailable); c.Status != metav1.ConditionFalse {
		t.Fatalf("applied condition = %+v", c)
	}
	r.applyWebUIAvailability(cluster, nil)
	if c := webUICondition(t, cluster, garagev1beta1.ConditionWebUIAvailable); c.Status != metav1.ConditionFalse {
		t.Fatalf("an empty observation must not overwrite the condition: %+v", c)
	}
}

func TestWebUIExposureDisabledKindsReportConditions(t *testing.T) {
	ctx := context.Background()
	cluster := webUITestCluster(&garagev1beta2.WebUIConfig{Hostname: webUITestHost, Ingress: &garagev1beta2.WebUIIngressConfig{}})
	c, scheme := websiteExposureTestClient(t, false, cluster)
	r := &GarageClusterReconciler{Client: c, Scheme: scheme}

	if got := r.reconcileWebUIExposure(ctx, cluster); got != "" {
		t.Fatalf("external URL = %q, want none while Ingress is disabled", got)
	}
	cond := webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed)
	if cond.Status != metav1.ConditionFalse || cond.Reason != webUIReasonIngressDisabled {
		t.Fatalf("condition = %+v, want False/IngressDisabled", cond)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, &networkingv1.Ingress{}); !k8errors.IsNotFound(err) {
		t.Fatalf("no Ingress may be created while disabled, got %v", err)
	}

	cluster.Spec.Admin.WebUI = &garagev1beta2.WebUIConfig{Hostname: webUITestHost, Gateway: &garagev1beta2.WebUIGatewayConfig{
		ParentRefs: []gatewayv1.ParentReference{{Name: "public"}},
	}}
	r.EnableGatewayAPI = true // flag on, but the CRD is absent from the mapper
	if got := r.reconcileWebUIExposure(ctx, cluster); got != "" {
		t.Fatalf("external URL = %q, want none without the Gateway API", got)
	}
	cond = webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed)
	if cond.Status != metav1.ConditionFalse || cond.Reason != webUIReasonGatewayAPIUnavailable {
		t.Fatalf("condition = %+v, want False/GatewayAPIUnavailable", cond)
	}
}

func TestWebUIExposureIngressLifecycle(t *testing.T) {
	ctx := context.Background()
	cluster := webUITestCluster(&garagev1beta2.WebUIConfig{
		Hostname: webUITestHost,
		Ingress: &garagev1beta2.WebUIIngressConfig{
			IngressClassName: "nginx",
			TLSSecretName:    "garage-ui-tls",
			Labels:           map[string]string{"team": "storage", labelCluster: "spoofed"},
			Annotations:      map[string]string{"cert-manager.io/cluster-issuer": "letsencrypt"},
		},
	})
	c, scheme := websiteExposureTestClient(t, true, cluster)
	r := &GarageClusterReconciler{Client: c, Scheme: scheme, EnableIngress: true, EnableGatewayAPI: true}

	if got, want := r.reconcileWebUIExposure(ctx, cluster), "https://"+webUITestHost+"/ui/"; got != want {
		t.Fatalf("external URL = %q, want %q", got, want)
	}
	cond := webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed)
	if cond.Status != metav1.ConditionTrue || cond.Reason != webUIReasonExposed {
		t.Fatalf("condition = %+v, want True/Exposed", cond)
	}

	ing := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, ing); err != nil {
		t.Fatalf("Ingress not created: %v", err)
	}
	if !metav1.IsControlledBy(ing, cluster) {
		t.Fatalf("Ingress must be controlled by the cluster: %+v", ing.OwnerReferences)
	}
	if ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != "nginx" {
		t.Fatalf("ingressClassName = %v", ing.Spec.IngressClassName)
	}
	if len(ing.Spec.TLS) != 1 || ing.Spec.TLS[0].SecretName != "garage-ui-tls" || ing.Spec.TLS[0].Hosts[0] != webUITestHost {
		t.Fatalf("tls = %+v", ing.Spec.TLS)
	}
	rule := ing.Spec.Rules[0]
	path := rule.HTTP.Paths[0]
	if rule.Host != webUITestHost || path.Path != "/" || *path.PathType != networkingv1.PathTypePrefix {
		t.Fatalf("rule = %+v", rule)
	}
	if path.Backend.Service.Name != "garage" || path.Backend.Service.Port.Name != adminPortName {
		t.Fatalf("backend = %+v, want Service garage port %q", path.Backend.Service, adminPortName)
	}
	if ing.Labels["team"] != "storage" || ing.Labels[labelCluster] != "garage" || ing.Labels[labelAppComponent] != webUIComponent {
		t.Fatalf("labels = %v (operator labels must win)", ing.Labels)
	}
	if ing.Annotations["cert-manager.io/cluster-issuer"] != "letsencrypt" {
		t.Fatalf("annotations = %v", ing.Annotations)
	}

	// Switching to an HTTPRoute removes the Ingress.
	cluster.Spec.Admin.WebUI = &garagev1beta2.WebUIConfig{Hostname: webUITestHost, Gateway: &garagev1beta2.WebUIGatewayConfig{
		ParentRefs: []gatewayv1.ParentReference{{Name: "public"}},
	}}
	_ = r.reconcileWebUIExposure(ctx, cluster)
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, &networkingv1.Ingress{}); !k8errors.IsNotFound(err) {
		t.Fatalf("Ingress must be deleted after switching to gateway, got %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, &gatewayv1.HTTPRoute{}); err != nil {
		t.Fatalf("HTTPRoute not created: %v", err)
	}

	// Removing spec.admin.webUI removes the route and the condition.
	cluster.Spec.Admin.WebUI = nil
	if got := r.reconcileWebUIExposure(ctx, cluster); got != "" {
		t.Fatalf("external URL = %q after removal", got)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, &gatewayv1.HTTPRoute{}); !k8errors.IsNotFound(err) {
		t.Fatalf("HTTPRoute must be deleted after removal, got %v", err)
	}
	if meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionWebUIExposed) != nil {
		t.Fatalf("WebUIExposed must be removed: %+v", cluster.Status.Conditions)
	}
}

func TestWebUIExposureHTTPRouteReadiness(t *testing.T) {
	ctx := context.Background()
	section := gatewayv1.SectionName("https")
	otherNS := gatewayv1.Namespace("gateways")
	cluster := webUITestCluster(&garagev1beta2.WebUIConfig{
		Hostname: webUITestHost,
		Scheme:   "https",
		Gateway: &garagev1beta2.WebUIGatewayConfig{
			ParentRefs:  []gatewayv1.ParentReference{{Name: "public", SectionName: &section}, {Name: "shared", Namespace: &otherNS}},
			Annotations: map[string]string{"external-dns.alpha.kubernetes.io/ttl": "60"},
		},
	})
	c, scheme := websiteExposureTestClient(t, true, cluster)
	r := &GarageClusterReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true}

	if got := r.reconcileWebUIExposure(ctx, cluster); got != "" {
		t.Fatalf("external URL = %q before the Gateway accepts the route", got)
	}
	cond := webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed)
	if cond.Status != metav1.ConditionFalse || cond.Reason != webUIReasonNotReady {
		t.Fatalf("condition = %+v, want False/NotReady", cond)
	}

	route := &gatewayv1.HTTPRoute{}
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, route); err != nil {
		t.Fatal(err)
	}
	if len(route.Spec.Hostnames) != 1 || string(route.Spec.Hostnames[0]) != webUITestHost {
		t.Fatalf("hostnames = %v", route.Spec.Hostnames)
	}
	if ns := route.Spec.ParentRefs[0].Namespace; ns == nil || *ns != "garage-ns" {
		t.Fatalf("namespace-less parentRef must default to the cluster namespace, got %v", ns)
	}
	if ns := route.Spec.ParentRefs[1].Namespace; ns == nil || *ns != "gateways" {
		t.Fatalf("explicit parentRef namespace must be kept, got %v", ns)
	}
	backend := route.Spec.Rules[0].BackendRefs[0].BackendRef
	if backend.Name != "garage" || backend.Namespace != nil || backend.Port == nil || *backend.Port != 3913 {
		t.Fatalf("backend = %+v, want same-namespace Service garage port 3913", backend)
	}
	if m := route.Spec.Rules[0].Matches[0].Path; *m.Type != gatewayv1.PathMatchPathPrefix || *m.Value != "/" {
		t.Fatalf("match = %+v", m)
	}
	if route.Annotations["external-dns.alpha.kubernetes.io/ttl"] != "60" || !metav1.IsControlledBy(route, cluster) {
		t.Fatalf("route metadata = %+v", route.ObjectMeta)
	}

	setRouteParentStatus(t, c, cluster.Namespace, webUITestRoute,
		routeParentConditions(metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionTrue, "ok")...)
	if got, want := r.reconcileWebUIExposure(ctx, cluster), "https://"+webUITestHost+"/ui/"; got != want {
		t.Fatalf("external URL = %q, want %q", got, want)
	}
	if cond := webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed); cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v, want True once accepted", cond)
	}
}

func TestWebUIExposureRefusesForeignObject(t *testing.T) {
	ctx := context.Background()
	cluster := webUITestCluster(&garagev1beta2.WebUIConfig{Hostname: webUITestHost, Ingress: &garagev1beta2.WebUIIngressConfig{}})
	foreign := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: webUITestRoute, Namespace: cluster.Namespace}}
	c, scheme := websiteExposureTestClient(t, false, cluster, foreign)
	r := &GarageClusterReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if got := r.reconcileWebUIExposure(ctx, cluster); got != "" {
		t.Fatalf("external URL = %q for a refused exposure", got)
	}
	cond := webUICondition(t, cluster, garagev1beta1.ConditionWebUIExposed)
	if cond.Status != metav1.ConditionFalse || cond.Reason != webUIReasonReconcileFailed || !strings.Contains(cond.Message, "not owned by") {
		t.Fatalf("condition = %+v, want ReconcileFailed naming the foreign owner", cond)
	}
	// Removing the spec leaves the foreign object alone.
	cluster.Spec.Admin.WebUI = nil
	_ = r.reconcileWebUIExposure(ctx, cluster)
	if err := c.Get(ctx, types.NamespacedName{Name: webUITestRoute, Namespace: cluster.Namespace}, &networkingv1.Ingress{}); err != nil {
		t.Fatalf("a foreign Ingress must not be deleted: %v", err)
	}
}
