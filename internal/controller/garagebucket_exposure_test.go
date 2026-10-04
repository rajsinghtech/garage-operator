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

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func websiteExposureTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		networkingv1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
		gatewayv1.Install,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

// websiteExposureTestRESTMapper builds the REST mapper a fake client needs so
// namespace checks and the Gateway API CRD probe behave like the operator's
// real mapper: Ingress is always a built-in, HTTPRoute is known only when
// gatewayAPI is true.
func websiteExposureTestRESTMapper(t *testing.T, gatewayAPI bool) meta.RESTMapper {
	t.Helper()
	// gatewayv1.GroupVersion is a metav1.GroupVersion, not a schema.GroupVersion,
	// so build the schema value from it (SchemeGroupVersion is deprecated).
	gatewayGroupVersion := schema.GroupVersion{Group: gatewayv1.GroupVersion.Group, Version: gatewayv1.GroupVersion.Version}
	defaultGroupVersions := []schema.GroupVersion{networkingv1.SchemeGroupVersion}
	if gatewayAPI {
		defaultGroupVersions = append(defaultGroupVersions, gatewayGroupVersion)
	}
	mapper := meta.NewDefaultRESTMapper(defaultGroupVersions)
	mapper.Add(networkingv1.SchemeGroupVersion.WithKind("Ingress"), meta.RESTScopeNamespace)
	if gatewayAPI {
		mapper.Add(gatewayGroupVersion.WithKind("HTTPRoute"), meta.RESTScopeNamespace)
	}
	return mapper
}

// websiteExposureTestClient builds a fake client whose REST mapper reports
// HTTPRoute as available (or not, when gatewayAPI is false). It returns the
// client and the scheme it was built with.
func websiteExposureTestClient(t *testing.T, gatewayAPI bool, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := websiteExposureTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(websiteExposureTestRESTMapper(t, gatewayAPI)).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}, &gatewayv1.HTTPRoute{}).
		WithObjects(objects...).
		Build()
	return c, scheme
}

func websiteExposureTestBucket(namespace string) *garagev1beta1.GarageBucket {
	return &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "site",
			Namespace:  namespace,
			UID:        types.UID("bucket-uid-1"),
			Generation: 1,
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "garage"},
		},
		Status: garagev1beta1.GarageBucketStatus{
			BucketID:    "bucket-id-1",
			GlobalAlias: "site",
		},
	}
}

// websiteExposureTestCluster returns a unified cluster (storage + gateway
// tiers) whose web API root domain is .example.com and whose effective web
// port is 3902.
func websiteExposureTestCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "garage",
			Namespace:  "garage-ns",
			UID:        types.UID("cluster-uid-1"),
			Generation: 1,
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			Gateway: &garagev1beta2.GatewaySpec{},
			WebAPI: &garagev1beta2.WebAPIConfig{
				RootDomain: ".example.com",
			},
		},
	}
}

func websiteExposureCondition(t *testing.T, bucket *garagev1beta1.GarageBucket) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(bucket.Status.Conditions, garagev1beta1.ConditionWebsiteExposed)
	if c == nil {
		t.Fatalf("WebsiteExposed condition not found in %+v", bucket.Status.Conditions)
	}
	return c
}

// setRouteParentStatus simulates the Gateway controller publishing a parent
// status entry (Accepted/ResolvedRefs/Ready conditions) on the route.
func setRouteParentStatus(t *testing.T, c client.Client, namespace, name string, conditions ...metav1.Condition) {
	t.Helper()
	route := &gatewayv1.HTTPRoute{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, route); err != nil {
		t.Fatalf("getting route for status simulation: %v", err)
	}
	gwNS := gatewayv1.Namespace(namespace)
	route.Status.Parents = []gatewayv1.RouteParentStatus{
		{
			ParentRef:      gatewayv1.ParentReference{Name: "public-gateway", Namespace: &gwNS},
			ControllerName: "example.net/gateway-controller",
			Conditions:     conditions,
		},
	}
	if err := c.Status().Update(context.Background(), route); err != nil {
		t.Fatalf("simulating route parent status: %v", err)
	}
}

func routeParentConditions(accepted, resolved, ready metav1.ConditionStatus, message string) []metav1.Condition {
	gen := int64(1)
	return []metav1.Condition{
		{Type: "Accepted", Status: accepted, Reason: "Test", Message: message, ObservedGeneration: gen},
		{Type: "ResolvedRefs", Status: resolved, Reason: "Test", Message: message, ObservedGeneration: gen},
		{Type: "Ready", Status: ready, Reason: "Test", Message: message, ObservedGeneration: gen},
	}
}

func TestWebsiteExposureIngressDerivedHost(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{
			IngressClassName: "traefik",
		},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	result, err := r.reconcileWebsiteExposure(ctx, bucket, cluster)
	if err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue after successful exposure, got %v", result.RequeueAfter)
	}

	// The Ingress is created in the bucket's own namespace.
	ingress := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, ingress); err != nil {
		t.Fatalf("expected Ingress in the bucket namespace: %v", err)
	}
	if ingress.Spec.IngressClassName == nil || *ingress.Spec.IngressClassName != "traefik" {
		t.Fatalf("ingressClassName = %v, want traefik", ingress.Spec.IngressClassName)
	}
	if len(ingress.Spec.Rules) != 1 || ingress.Spec.Rules[0].Host != "site.example.com" {
		t.Fatalf("rules = %+v, want single rule for site.example.com", ingress.Spec.Rules)
	}
	// Unified cluster: the backend is the gateway-tier Service.
	backend := ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service
	if backend.Name != "garage-gateway" || backend.Port.Name != "web" {
		t.Fatalf("backend = %+v, want service garage-gateway port web", backend)
	}
	if !metav1.IsControlledBy(ingress, bucket) {
		t.Fatalf("ingress is not controlled by the bucket: %+v", ingress.OwnerReferences)
	}

	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionTrue || cond.Reason != "Exposed" {
		t.Fatalf("condition = %+v, want True/Exposed", cond)
	}
	if bucket.Status.WebsiteExposure == nil || bucket.Status.WebsiteExposure.Type != "Ingress" {
		t.Fatalf("status.websiteExposure = %+v, want type Ingress", bucket.Status.WebsiteExposure)
	}
	if len(bucket.Status.WebsiteExposure.Hostnames) != 1 || bucket.Status.WebsiteExposure.Hostnames[0] != "site.example.com" {
		t.Fatalf("status hostnames = %v", bucket.Status.WebsiteExposure.Hostnames)
	}
}

func TestWebsiteExposureIngressStorageOnlyBackend(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	cluster.Spec.Gateway = nil // storage-only cluster: backend is the primary Service
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}
	ingress := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, ingress); err != nil {
		t.Fatal(err)
	}
	if got := ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name; got != "garage" {
		t.Fatalf("storage-only backend = %q, want the primary garage Service", got)
	}
}

func TestWebsiteExposureIngressExplicitHostnamesAndTLS(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		// Both hostnames resolve to the bucket without a Host rewrite: the
		// canonical <alias><rootDomain> form and the bare alias.
		Hostnames: []string{"site.example.com", "site"},
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{
			TLSSecretName: "site-tls",
			Annotations:   map[string]string{"cert-manager.io/cluster-issuer": "letsencrypt"},
			Labels:        map[string]string{"team": "web"},
		},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}

	ingress := &networkingv1.Ingress{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, ingress); err != nil {
		t.Fatal(err)
	}
	if len(ingress.Spec.TLS) != 1 || ingress.Spec.TLS[0].SecretName != "site-tls" ||
		len(ingress.Spec.TLS[0].Hosts) != 2 {
		t.Fatalf("tls = %+v, want one secret covering both hosts", ingress.Spec.TLS)
	}
	if len(ingress.Spec.Rules) != 2 ||
		ingress.Spec.Rules[0].Host != "site.example.com" ||
		ingress.Spec.Rules[1].Host != "site" {
		t.Fatalf("rules = %+v, want one rule per hostname", ingress.Spec.Rules)
	}
	if ingress.Annotations["cert-manager.io/cluster-issuer"] != "letsencrypt" {
		t.Fatalf("annotations = %+v", ingress.Annotations)
	}
	if ingress.Labels["team"] != "web" || ingress.Labels[labelBucketRef] != "site" {
		t.Fatalf("labels = %+v", ingress.Labels)
	}
}

func TestWebsiteExposureIngressCrossNamespaceRejected(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("the refusal must surface on the condition, not error: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, &networkingv1.Ingress{}); !k8errors.IsNotFound(err) {
		t.Fatalf("no Ingress may be created cross-namespace, got err = %v", err)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("condition = %+v, want False/ReconcileFailed", cond)
	}
	if !strings.Contains(cond.Message, "cross namespaces") {
		t.Fatalf("condition message = %q", cond.Message)
	}
}

// TestWebsiteExposureIngressNonCanonicalHostRejected proves that a hostname
// which is neither the canonical <alias><rootDomain> form nor the bare alias
// is refused for an Ingress (no Host rewrite exists): the condition carries
// the reason and no Ingress is created.
func TestWebsiteExposureIngressNonCanonicalHostRejected(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Hostnames: []string{"site.example.com", "www.example.com"},
		Ingress:   &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("the refusal must surface on the condition, not error: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, &networkingv1.Ingress{}); !k8errors.IsNotFound(err) {
		t.Fatalf("no Ingress may be created with a non-canonical hostname, got err = %v", err)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("condition = %+v, want False/ReconcileFailed", cond)
	}
	if !strings.Contains(cond.Message, "www.example.com") || !strings.Contains(cond.Message, "Ingress cannot rewrite") {
		t.Fatalf("condition message = %q", cond.Message)
	}
}

func TestWebsiteExposureWaitingForAlias(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	bucket.Status.GlobalAlias = ""
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	result, err := r.reconcileWebsiteExposure(ctx, bucket, cluster)
	if err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}
	if result.RequeueAfter != RequeueAfterShort {
		t.Fatalf("requeue = %v, want %v while waiting for the alias", result.RequeueAfter, RequeueAfterShort)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "WaitingForAlias" {
		t.Fatalf("condition = %+v, want False/WaitingForAlias", cond)
	}
}

func TestWebsiteExposureIngressDeletedWhenSpecRemoved(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatal(err)
	}

	// Re-fetch from the store: the previous call mutated the in-memory object.
	stored := &garagev1beta1.GarageBucket{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: bucket.Namespace, Name: bucket.Name}, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.WebsiteExposure = nil
	if err := c.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}

	if _, err := r.reconcileWebsiteExposure(ctx, stored, cluster); err != nil {
		t.Fatal(err)
	}
	ingress := &networkingv1.Ingress{}
	err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, ingress)
	if !k8errors.IsNotFound(err) {
		t.Fatalf("expected the Ingress to be deleted: %v", err)
	}
	if stored.Status.WebsiteExposure != nil {
		t.Fatalf("status.websiteExposure = %+v, want cleared", stored.Status.WebsiteExposure)
	}
	if meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionWebsiteExposed) != nil {
		t.Fatalf("WebsiteExposed condition should be removed: %+v", stored.Status.Conditions)
	}
}

func TestWebsiteExposureHTTPRouteCreated(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps") // cross-namespace: allowed for HTTPRoute
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{
				{Name: "public-gateway", SectionName: ptrSection("http")},
			},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}

	// The route lives in the bucket's own namespace, cross-namespace owner
	// refs are gone.
	route := &gatewayv1.HTTPRoute{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, route); err != nil {
		t.Fatalf("expected HTTPRoute in the bucket namespace: %v", err)
	}
	if len(route.Spec.Hostnames) != 1 || route.Spec.Hostnames[0] != "site.example.com" {
		t.Fatalf("hostnames = %v", route.Spec.Hostnames)
	}
	if len(route.Spec.ParentRefs) != 1 || route.Spec.ParentRefs[0].Name != "public-gateway" {
		t.Fatalf("parentRefs = %+v", route.Spec.ParentRefs)
	}
	// Namespace-less parentRef is defaulted to the route's namespace.
	if route.Spec.ParentRefs[0].Namespace == nil || *route.Spec.ParentRefs[0].Namespace != "apps" {
		t.Fatalf("parentRef namespace = %v, want apps", route.Spec.ParentRefs[0].Namespace)
	}
	if route.Spec.ParentRefs[0].SectionName == nil || *route.Spec.ParentRefs[0].SectionName != "http" {
		t.Fatalf("sectionName = %v", route.Spec.ParentRefs[0].SectionName)
	}
	rule := route.Spec.Rules[0]
	if rule.Matches[0].Path == nil || *rule.Matches[0].Path.Type != gatewayv1.PathMatchPathPrefix ||
		rule.Matches[0].Path.Value == nil || *rule.Matches[0].Path.Value != "/" {
		t.Fatalf("matches = %+v", rule.Matches)
	}
	backend := rule.BackendRefs[0].BackendRef
	// Unified cluster: the cross-namespace gateway-tier Service, with the
	// cluster namespace set explicitly (needs a gateway ReferenceGrant).
	if backend.Name != "garage-gateway" {
		t.Fatalf("backend name = %q, want garage-gateway", backend.Name)
	}
	if backend.Namespace == nil || *backend.Namespace != "garage-ns" {
		t.Fatalf("backend namespace = %v, want garage-ns (cross-namespace)", backend.Namespace)
	}
	if backend.Port == nil || *backend.Port != 3902 {
		t.Fatalf("backend port = %v, want 3902", backend.Port)
	}
	// Canonical hostname only: no URLRewrite filter.
	if len(rule.Filters) != 0 {
		t.Fatalf("canonical host must not carry a rewrite filter: %+v", rule.Filters)
	}
	if !metav1.IsControlledBy(route, bucket) {
		t.Fatalf("route is not controlled by the bucket: %+v", route.OwnerReferences)
	}
	// Without a Gateway having processed the route yet, the condition is
	// NotReady and the controller requeues.
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "NotReady" {
		t.Fatalf("condition = %+v, want False/NotReady before the Gateway processes the route", cond)
	}
	if bucket.Status.WebsiteExposure.Type != "HTTPRoute" {
		t.Fatalf("status type = %q", bucket.Status.WebsiteExposure.Type)
	}
}

// TestWebsiteExposureHTTPRouteReadyAfterGatewayStatus simulates the Gateway
// controller publishing the route status, after which the condition must
// flip to True/Exposed and the per-parent status must be mirrored.
func TestWebsiteExposureHTTPRouteReadyAfterGatewayStatus(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Reason != "NotReady" {
		t.Fatalf("condition before Gateway status = %+v, want NotReady", cond)
	}

	// The Gateway accepts the route and resolves the backend ref.
	setRouteParentStatus(t, c, bucket.Namespace, "site-website",
		routeParentConditions(metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionTrue, "ok")...)

	bucket2 := &garagev1beta1.GarageBucket{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: bucket.Namespace, Name: bucket.Name}, bucket2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileWebsiteExposure(ctx, bucket2, cluster); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	cond = websiteExposureCondition(t, bucket2)
	if cond.Status != metav1.ConditionTrue || cond.Reason != "Exposed" {
		t.Fatalf("condition after Gateway status = %+v, want True/Exposed", cond)
	}
	parents := bucket2.Status.WebsiteExposure.Parents
	if len(parents) != 1 || !parents[0].Accepted || !parents[0].ResolvedRefs || !parents[0].Ready {
		t.Fatalf("status parents = %+v, want accepted+resolved+ready", parents)
	}
}

// TestWebsiteExposureHTTPRouteNotAccepted keeps the condition False when the
// Gateway rejects the route (e.g. no matching listener).
func TestWebsiteExposureHTTPRouteNotAccepted(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	setRouteParentStatus(t, c, bucket.Namespace, "site-website",
		routeParentConditions(metav1.ConditionFalse, metav1.ConditionTrue, metav1.ConditionFalse, "no matching listener")...)

	bucket2 := &garagev1beta1.GarageBucket{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: bucket.Namespace, Name: bucket.Name}, bucket2); err != nil {
		t.Fatal(err)
	}
	result, err := r.reconcileWebsiteExposure(ctx, bucket2, cluster)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if result.RequeueAfter != RequeueAfterShort {
		t.Fatalf("requeue = %v, want the short interval to re-check the route", result.RequeueAfter)
	}
	cond := websiteExposureCondition(t, bucket2)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "NotReady" {
		t.Fatalf("condition = %+v, want False/NotReady", cond)
	}
	if !strings.Contains(cond.Message, "no matching listener") {
		t.Fatalf("condition message = %q, want the Gateway reason", cond.Message)
	}
}

// TestWebsiteExposureHTTPRouteURLRewriteForNonCanonicalHost proves that a
// hostname which is neither the canonical <alias><rootDomain> form nor the
// bare alias gets a URLRewrite filter back to the canonical host, while the
// alias itself does not.
func TestWebsiteExposureHTTPRouteURLRewriteForNonCanonicalHost(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Hostnames: []string{"site.example.com", "site", "www.example.com"},
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}
	route := &gatewayv1.HTTPRoute{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, route); err != nil {
		t.Fatal(err)
	}
	if len(route.Spec.Rules) != 3 {
		t.Fatalf("rules = %d, want one per hostname", len(route.Spec.Rules))
	}
	byHost := map[string][]gatewayv1.HTTPRouteFilter{}
	for i, host := range []string{"site.example.com", "site", "www.example.com"} {
		byHost[host] = route.Spec.Rules[i].Filters
	}
	if n := len(byHost["site.example.com"]); n != 0 {
		t.Fatalf("canonical host must not be rewritten, got %d filters", n)
	}
	if n := len(byHost["site"]); n != 0 {
		t.Fatalf("bare alias must not be rewritten (Garage falls back to the full Host as the alias), got %d filters", n)
	}
	filters := byHost["www.example.com"]
	if len(filters) != 1 || filters[0].Type != gatewayv1.HTTPRouteFilterURLRewrite ||
		filters[0].URLRewrite == nil || filters[0].URLRewrite.Hostname == nil ||
		*filters[0].URLRewrite.Hostname != "site.example.com" {
		t.Fatalf("non-canonical host filters = %+v, want URLRewrite to site.example.com", filters)
	}
}

func TestWebsiteExposureHTTPRouteBackendOverride(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
		BackendRef: &garagev1beta1.WebsiteExposureBackendReference{
			Name:      "garage-remote",
			Kind:      "ServiceImport",
			Group:     "multicluster.x-k8s.io",
			Namespace: "federation",
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("reconcileWebsiteExposure: %v", err)
	}
	route := &gatewayv1.HTTPRoute{}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, route); err != nil {
		t.Fatal(err)
	}
	backend := route.Spec.Rules[0].BackendRefs[0].BackendRef
	if backend.Name != "garage-remote" {
		t.Fatalf("backend name = %q, want the ServiceImport override", backend.Name)
	}
	if backend.Kind == nil || *backend.Kind != "ServiceImport" || backend.Group == nil || *backend.Group != "multicluster.x-k8s.io" {
		t.Fatalf("backend kind/group = %v/%v, want ServiceImport/multicluster.x-k8s.io", backend.Kind, backend.Group)
	}
	if backend.Namespace == nil || *backend.Namespace != "federation" {
		t.Fatalf("backend namespace = %v, want federation", backend.Namespace)
	}
	if backend.Port == nil || *backend.Port != 3902 {
		t.Fatalf("backend port = %v, want the effective web port 3902", backend.Port)
	}
}

func TestWebsiteExposureHTTPRouteCRDsUnavailable(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	result, err := r.reconcileWebsiteExposure(ctx, bucket, cluster)
	if err != nil {
		t.Fatalf("missing CRDs must not fail the bucket: %v", err)
	}
	if result.RequeueAfter != RequeueAfterDrift {
		t.Fatalf("requeue = %v, want the drift interval", result.RequeueAfter)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "GatewayAPIUnavailable" {
		t.Fatalf("condition = %+v, want False/GatewayAPIUnavailable", cond)
	}
}

// TestWebsiteExposureHTTPRouteFlagDisabled is the --enable-gateway-api half:
// even with the CRDs installed, a disabled flag reports GatewayAPIUnavailable.
func TestWebsiteExposureHTTPRouteFlagDisabled(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true} // EnableGatewayAPI false

	result, err := r.reconcileWebsiteExposure(ctx, bucket, cluster)
	if err != nil {
		t.Fatalf("disabled flag must not fail the bucket: %v", err)
	}
	if result.RequeueAfter != RequeueAfterDrift {
		t.Fatalf("requeue = %v, want the drift interval", result.RequeueAfter)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "GatewayAPIUnavailable" {
		t.Fatalf("condition = %+v, want False/GatewayAPIUnavailable", cond)
	}
}

func ptrSection(name string) *gatewayv1.SectionName {
	s := gatewayv1.SectionName(name)
	return &s
}

func TestWebsiteExposureForeignObjectRefused(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	foreign := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "site-website", Namespace: bucket.Namespace},
	}
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	c, scheme := websiteExposureTestClient(t, false, bucket, cluster, foreign)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("the refusal must surface on the condition, not as a reconcile error: %v", err)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("condition = %+v, want False/ReconcileFailed", cond)
	}
	if !strings.Contains(cond.Message, "not owned by") {
		t.Fatalf("condition message = %q, want ownership refusal", cond.Message)
	}
	// The foreign object must be untouched: no owner reference added.
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, foreign); err != nil {
		t.Fatal(err)
	}
	if len(foreign.OwnerReferences) != 0 {
		t.Fatalf("foreign Ingress was mutated: %+v", foreign.OwnerReferences)
	}
}

// TestWebsiteExposureSwitchGatewayToIngress proves that switching the spec
// from gateway to ingress deletes the previously generated HTTPRoute (both
// kinds share the name <bucket>-website, so only one may exist).
func TestWebsiteExposureSwitchGatewayToIngress(t *testing.T) {
	ctx := context.Background()
	// Bucket and cluster share a namespace so the Ingress half of the switch
	// is valid.
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: "apps", UID: types.UID("cluster-uid-1"), Generation: 1},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			Gateway: &garagev1beta2.GatewaySpec{},
			WebAPI:  &garagev1beta2.WebAPIConfig{RootDomain: ".example.com"},
		},
	}
	bucket := websiteExposureTestBucket("apps")
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	c, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true, EnableIngress: true}

	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("first reconcile (gateway): %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: "apps"}, &gatewayv1.HTTPRoute{}); err != nil {
		t.Fatalf("expected HTTPRoute after first reconcile: %v", err)
	}

	stored := &garagev1beta1.GarageBucket{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "apps", Name: "site"}, stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	if err := c.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}

	if _, err := r.reconcileWebsiteExposure(ctx, stored, cluster); err != nil {
		t.Fatalf("second reconcile (ingress): %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: "apps"}, &networkingv1.Ingress{}); err != nil {
		t.Fatalf("expected Ingress after the switch: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: "apps"}, &gatewayv1.HTTPRoute{}); !k8errors.IsNotFound(err) {
		t.Fatalf("the previous HTTPRoute must be deleted on the kind switch, got err = %v", err)
	}
}

// TestWebsiteExposureCleanupSurvivesMissingCluster drives the spec-removal
// cleanup with no GarageCluster object at all: the exposure must be removed
// from the bucket's namespace using only spec/status.
func TestWebsiteExposureCleanupSurvivesMissingCluster(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("apps")
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{},
	}
	bucket.Status.WebsiteExposure = &garagev1beta1.WebsiteExposureStatus{
		Type: "Ingress", Name: "site-website",
	}
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "site-website",
			Namespace:       "apps",
			OwnerReferences: []metav1.OwnerReference{{Kind: "GarageBucket", Name: "site", UID: bucket.UID, Controller: ptrBool(true)}},
		},
	}
	// No GarageCluster object in the client at all.
	c, scheme := websiteExposureTestClient(t, false, bucket, ingress)
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableIngress: true}

	if err := r.deleteWebsiteExposureResource(ctx, bucket); err != nil {
		t.Fatalf("cleanup with a missing cluster: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: "apps"}, ingress); !k8errors.IsNotFound(err) {
		t.Fatalf("Ingress must be deleted without the cluster object: get err = %v", err)
	}
}

func ptrBool(b bool) *bool { return &b }

// TestWebsiteExposureIngressFlagDisabled is the --enable-ingress half: with
// the flag off a bucket that sets websiteExposure.ingress reports
// WebsiteExposed=False/IngressDisabled, creates no Ingress, and never reads
// Ingresses (the operator may hold no RBAC for them).
func TestWebsiteExposureIngressFlagDisabled(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Ingress: &garagev1beta1.WebsiteExposureIngressConfig{IngressClassName: "traefik"},
	}
	base, scheme := websiteExposureTestClient(t, false, bucket, cluster)
	c := &ingressForbiddenClient{Client: base}
	r := &GarageBucketReconciler{Client: c, Scheme: scheme} // EnableIngress false

	result, err := r.reconcileWebsiteExposure(ctx, bucket, cluster)
	if err != nil {
		t.Fatalf("disabled flag must not fail the bucket: %v", err)
	}
	if result.RequeueAfter != RequeueAfterDrift {
		t.Fatalf("requeue = %v, want the drift interval", result.RequeueAfter)
	}
	cond := websiteExposureCondition(t, bucket)
	if cond.Status != metav1.ConditionFalse || cond.Reason != "IngressDisabled" {
		t.Fatalf("condition = %+v, want False/IngressDisabled", cond)
	}
	if !strings.Contains(cond.Message, "--enable-ingress") || !strings.Contains(cond.Message, "ingress.enabled") {
		t.Fatalf("message %q should name the flag and the chart value", cond.Message)
	}
	if bucket.Status.WebsiteExposure == nil || bucket.Status.WebsiteExposure.Type != "Ingress" {
		t.Fatalf("status.websiteExposure = %+v, want type Ingress", bucket.Status.WebsiteExposure)
	}
	if c.ingressCalls != 0 {
		t.Fatalf("operator touched Ingresses %d times with Ingress support disabled", c.ingressCalls)
	}
	ingress := &networkingv1.Ingress{}
	if err := base.Get(ctx, types.NamespacedName{Name: "site-website", Namespace: bucket.Namespace}, ingress); !k8errors.IsNotFound(err) {
		t.Fatalf("no Ingress may be created while disabled: %v", err)
	}
}

// TestWebsiteExposureIngressCleanupSkippedWhenDisabled mirrors the
// deleteWebsiteExposureRoute behavior: with Ingress support off the cleanup
// paths (spec removal, switch to gateway, deletion) never touch Ingresses,
// because without RBAC the lookup would be Forbidden.
func TestWebsiteExposureIngressCleanupSkippedWhenDisabled(t *testing.T) {
	ctx := context.Background()
	bucket := websiteExposureTestBucket("garage-ns")
	cluster := websiteExposureTestCluster()
	// A previous exposure is recorded in status, so the cleanup would
	// normally probe for the Ingress.
	bucket.Status.WebsiteExposure = &garagev1beta1.WebsiteExposureStatus{Type: "Ingress", Name: "site-website"}
	base, scheme := websiteExposureTestClient(t, true, bucket, cluster)
	c := &ingressForbiddenClient{Client: base}
	r := &GarageBucketReconciler{Client: c, Scheme: scheme, EnableGatewayAPI: true}

	if err := r.deleteWebsiteExposureIngress(ctx, bucket); err != nil {
		t.Fatalf("deleteWebsiteExposureIngress must be a no-op when disabled: %v", err)
	}
	if err := r.deleteWebsiteExposureResource(ctx, bucket); err != nil {
		t.Fatalf("deleteWebsiteExposureResource must not fail when disabled: %v", err)
	}
	// spec removed, exposure previously recorded
	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("spec removal must not fail when disabled: %v", err)
	}
	// switch to gateway
	bucket.Spec.WebsiteExposure = &garagev1beta1.WebsiteExposureConfig{
		Gateway: &garagev1beta1.WebsiteExposureGatewayConfig{
			ParentRefs: []gatewayv1.ParentReference{{Name: "public-gateway"}},
		},
	}
	if _, err := r.reconcileWebsiteExposure(ctx, bucket, cluster); err != nil {
		t.Fatalf("switch to gateway must not fail when Ingress is disabled: %v", err)
	}
	if c.ingressCalls != 0 {
		t.Fatalf("operator touched Ingresses %d times with Ingress support disabled", c.ingressCalls)
	}
}

// ingressForbiddenClient fails every Ingress call, simulating an operator
// installed without ingress.enabled (no RBAC on networking.k8s.io/ingresses).
type ingressForbiddenClient struct {
	client.Client
	ingressCalls int
}

func (c *ingressForbiddenClient) forbid(obj any) error {
	switch obj.(type) {
	case *networkingv1.Ingress, *networkingv1.IngressList:
		c.ingressCalls++
		return k8errors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "site-website", nil)
	}
	return nil
}

func (c *ingressForbiddenClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.forbid(obj); err != nil {
		return err
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *ingressForbiddenClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.forbid(list); err != nil {
		return err
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *ingressForbiddenClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.forbid(obj); err != nil {
		return err
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *ingressForbiddenClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.forbid(obj); err != nil {
		return err
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *ingressForbiddenClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.forbid(obj); err != nil {
		return err
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *ingressForbiddenClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := c.forbid(obj); err != nil {
		return err
	}
	return c.Client.Delete(ctx, obj, opts...)
}
