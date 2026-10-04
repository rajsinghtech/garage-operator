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
	"errors"
	"fmt"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// The Ingress and HTTPRoute RBAC rules below are the superset; the Helm chart
// only grants them when ingress.enabled / gatewayAPI.enabled are set.
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=create;delete;get;list;patch;update;watch

const (
	// websiteExposureResourceIngress and websiteExposureResourceHTTPRoute are
	// the status.websiteExposure.type values. websiteExposureResourceHTTPRoute
	// doubles as the Gateway API kind name probed for CRD availability.
	websiteExposureResourceIngress   = "Ingress"
	websiteExposureResourceHTTPRoute = "HTTPRoute"

	// HTTPRoute route-status condition types (gateway API v1).
	websiteExposureCondAccepted    = "Accepted"
	websiteExposureCondResolvedRef = "ResolvedRefs"
	websiteExposureCondReady       = "Ready"

	// websiteExposureServiceKind is the default backendRef kind.
	websiteExposureServiceKind = "Service"
)

// websiteExposureResourceName is the name of the operator-generated Ingress
// or HTTPRoute for a bucket. The resource is created in the bucket's own
// namespace, so the name cannot clash between namespaces.
func websiteExposureResourceName(bucket *garagev1beta1.GarageBucket) string {
	return bucket.Name + "-website"
}

// websiteExposureBackend returns the Service the exposure routes to when
// spec.websiteExposure.backendRef is unset: the cluster's gateway-tier
// Service (<cluster>-gateway) for unified clusters, where the S3/Web traffic
// terminates, and the primary <cluster> Service otherwise.
func websiteExposureBackend(cluster *garagev1beta2.GarageCluster) string {
	if cluster.HasStorageTier() && cluster.HasGatewayTier() {
		return cluster.Name + "-gateway"
	}
	return cluster.Name
}

// errWebsiteExposureWaitingForAlias is the transient host-resolution error
// while the bucket's global alias is not yet recorded in status.
var errWebsiteExposureWaitingForAlias = errors.New("waiting for the bucket's global alias to be recorded before the website host can be derived")

// canonicalWebsiteHost derives the canonical website host:
// <globalAlias><webApi.rootDomain>. Garage's web server strips the rootDomain
// suffix from the Host header when it matches and uses the remainder as the
// bucket alias; this form therefore always resolves to the bucket.
func canonicalWebsiteHost(cluster *garagev1beta2.GarageCluster, alias string) (string, error) {
	w := effectiveWebAPI(cluster)
	if w == nil {
		return "", errors.New("the referenced cluster has webApi disabled; no website host can be derived")
	}
	if alias == "" {
		return "", errWebsiteExposureWaitingForAlias
	}
	return alias + w.RootDomain, nil
}

// websiteExposureHostnames resolves the hostnames the exposure routes on:
// the spec hostnames when set, otherwise the single canonical hostname.
//
// Garage's web server falls back to the full Host as the bucket alias
// (host_to_bucket(host).unwrap_or(host)), so a hostname equal to the global
// alias also resolves to the bucket without the rootDomain suffix; the
// canonical form is still preferred. For an Ingress, hostnames that would
// not resolve as-is (see websiteExposureNeedsRewrite) are refused by
// buildIngress. For an HTTPRoute, a hostname that is neither canonical nor
// the alias gets a URLRewrite filter rewriting the Host header to the
// canonical host so the request still resolves to the bucket.
func websiteExposureHostnames(cluster *garagev1beta2.GarageCluster, exposure *garagev1beta1.WebsiteExposureConfig, alias string) ([]string, error) {
	if len(exposure.Hostnames) > 0 {
		return exposure.Hostnames, nil
	}
	canonical, err := canonicalWebsiteHost(cluster, alias)
	if err != nil {
		return nil, err
	}
	return []string{canonical}, nil
}

// websiteExposureNeedsRewrite reports whether an HTTPRoute hostname needs a
// URLRewrite filter (to the canonical host) so that Garage resolves the
// request to the bucket: every hostname except the canonical form and the
// bare alias.
func websiteExposureNeedsRewrite(host, canonical, alias string) bool {
	if alias != "" && host == alias {
		return false
	}
	return host != canonical
}

// reconcileWebsiteExposure creates, updates, or deletes the Ingress or
// HTTPRoute declared by spec.websiteExposure and records the result on the
// WebsiteExposed condition plus status.websiteExposure. It never fails the
// bucket reconcile: exposure problems are surfaced on the condition and
// retried, while the bucket itself stays Ready.
//
// It must run AFTER updateStatusFromGarage: that function snapshots the old
// status for its no-op comparison, so exposure status mutations made before
// it would be silently dropped. This function persists its own status changes
// (skipping the write when nothing changed).
func (r *GarageBucketReconciler) reconcileWebsiteExposure(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	cluster *garagev1beta2.GarageCluster,
) (ctrl.Result, error) {
	// The bucket identity is not recorded yet on the very first cycle; the
	// alias (and therefore any derived host) follows it. Nothing to expose.
	if bucket.Status.BucketID == "" {
		return ctrl.Result{}, nil
	}

	oldStatus := bucket.Status.DeepCopy()
	exposure := bucket.Spec.WebsiteExposure
	// The cluster the exposure routes to (where the default web Service
	// lives), resolved the same way the bucket controller resolves it:
	// spec.clusterRef.namespace when set, otherwise the bucket's namespace.
	clusterNamespace := cluster.Namespace
	if ns := bucket.Spec.ClusterRef.Namespace; ns != "" {
		clusterNamespace = ns
	}
	if exposure == nil {
		if err := r.deleteWebsiteExposureResource(ctx, bucket); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, nil, nil); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Ingress and HTTPRoute share the generated name, so exactly one may
	// exist: when the spec switches kinds (or names neither, handled above),
	// the previously generated resource of the other kind is removed.
	if exposure.Gateway != nil {
		if err := r.deleteWebsiteExposureIngress(ctx, bucket); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.deleteWebsiteExposureRoute(ctx, bucket); err != nil {
			return ctrl.Result{}, err
		}
	}

	// WaitingForAlias is reported while the bucket's global alias is not
	// recorded yet: both resource kinds derive the canonical host from it
	// (Ingress: to verify each hostname resolves to the bucket; HTTPRoute:
	// as the URLRewrite target for non-canonical hostnames).
	waitingForAlias := func(err error) (ctrl.Result, bool) {
		if !errors.Is(err, errWebsiteExposureWaitingForAlias) {
			return ctrl.Result{}, false
		}
		condition := &metav1.Condition{
			Type:               garagev1beta1.ConditionWebsiteExposed,
			Status:             metav1.ConditionFalse,
			Reason:             "WaitingForAlias",
			Message:            "the bucket's global alias is not recorded yet; the derived website host cannot be computed",
			ObservedGeneration: bucket.Generation,
		}
		status := &garagev1beta1.WebsiteExposureStatus{Name: websiteExposureResourceName(bucket)}
		if exposure.Gateway != nil {
			status.Type = websiteExposureResourceHTTPRoute
		} else {
			status.Type = websiteExposureResourceIngress
		}
		if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
			return ctrl.Result{}, true
		}
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, true
	}

	if exposure.Gateway != nil {
		if !r.gatewayAPIEnabled() {
			condition := &metav1.Condition{
				Type:               garagev1beta1.ConditionWebsiteExposed,
				Status:             metav1.ConditionFalse,
				Reason:             "GatewayAPIUnavailable",
				Message:            "spec.websiteExposure.gateway is set but the Gateway API is unavailable (CRDs not installed or the operator is not started with --enable-gateway-api)",
				ObservedGeneration: bucket.Generation,
			}
			status := &garagev1beta1.WebsiteExposureStatus{
				Type: websiteExposureResourceHTTPRoute,
				Name: websiteExposureResourceName(bucket),
			}
			if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
		}
		route, err := r.buildHTTPRoute(bucket, clusterNamespace, cluster, exposure)
		if err != nil {
			if result, done := waitingForAlias(err); done {
				return result, nil
			}
			return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
		}
		if err := r.applyWebsiteExposureResource(ctx, bucket, route); err != nil {
			return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
		}
		fresh := &gatewayv1.HTTPRoute{}
		if err := r.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, fresh); err != nil {
			return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
		}
		ready, message := websiteExposureRouteReady(fresh)
		status := websiteExposureStatusFromRoute(fresh)
		if ready {
			return r.finishWebsiteExposure(ctx, bucket, oldStatus, status, nil, "Exposed",
				fmt.Sprintf("website exposed via HTTPRoute %s/%s", fresh.Namespace, fresh.Name))
		}
		result, err := r.finishWebsiteExposure(ctx, bucket, oldStatus, status, nil, "NotReady", message)
		if err != nil {
			return result, err
		}
		if result.RequeueAfter == 0 {
			result.RequeueAfter = RequeueAfterShort
		}
		return result, nil
	}

	if !r.ingressEnabled() {
		condition := &metav1.Condition{
			Type:               garagev1beta1.ConditionWebsiteExposed,
			Status:             metav1.ConditionFalse,
			Reason:             "IngressDisabled",
			Message:            "spec.websiteExposure.ingress is set but Ingress support is disabled (start the operator with --enable-ingress, or set the chart value ingress.enabled=true)",
			ObservedGeneration: bucket.Generation,
		}
		status := &garagev1beta1.WebsiteExposureStatus{
			Type: websiteExposureResourceIngress,
			Name: websiteExposureResourceName(bucket),
		}
		if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
	}

	ingress, err := r.buildIngress(bucket, clusterNamespace, cluster, exposure)
	if err != nil {
		if result, done := waitingForAlias(err); done {
			return result, nil
		}
		return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
	}
	if err := r.applyWebsiteExposureResource(ctx, bucket, ingress); err != nil {
		return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
	}
	fresh := &networkingv1.Ingress{}
	if err := r.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, fresh); err != nil {
		return r.finishWebsiteExposure(ctx, bucket, oldStatus, nil, err, "ReconcileFailed", err.Error())
	}
	return r.finishWebsiteExposure(ctx, bucket, oldStatus, websiteExposureStatusFromIngress(fresh), nil,
		"Exposed", fmt.Sprintf("website exposed via Ingress %s/%s", fresh.Namespace, fresh.Name))
}

// websiteExposureStatusFromRoute summarizes the generated HTTPRoute for
// status.websiteExposure: kind, name, the hostnames it routes on, and the
// per-parent readiness reported by the route's own status.
func websiteExposureStatusFromRoute(route *gatewayv1.HTTPRoute) *garagev1beta1.WebsiteExposureStatus {
	hostnames := make([]string, 0, len(route.Spec.Hostnames))
	for _, h := range route.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}
	status := &garagev1beta1.WebsiteExposureStatus{
		Type:      websiteExposureResourceHTTPRoute,
		Name:      route.Name,
		Hostnames: hostnames,
	}
	for _, parent := range route.Status.Parents {
		parentStatus := garagev1beta1.WebsiteParentStatus{
			Parent: websiteExposureParentName(parent),
		}
		for _, cond := range parent.Conditions {
			switch cond.Type {
			case websiteExposureCondAccepted:
				parentStatus.Accepted = cond.Status == metav1.ConditionTrue
			case websiteExposureCondResolvedRef:
				parentStatus.ResolvedRefs = cond.Status == metav1.ConditionTrue
			case websiteExposureCondReady:
				parentStatus.Ready = cond.Status == metav1.ConditionTrue
				if cond.Status != metav1.ConditionTrue && cond.Message != "" {
					parentStatus.Message = cond.Message
				}
			}
		}
		status.Parents = append(status.Parents, parentStatus)
	}
	return status
}

// websiteExposureStatusFromIngress summarizes the generated Ingress for
// status.websiteExposure. Ingress has no per-parent readiness model, so only
// kind and hostnames are reported; readiness lives on the condition.
func websiteExposureStatusFromIngress(ingress *networkingv1.Ingress) *garagev1beta1.WebsiteExposureStatus {
	hostnames := make([]string, 0, len(ingress.Spec.Rules))
	for _, rule := range ingress.Spec.Rules {
		if rule.Host != "" {
			hostnames = append(hostnames, rule.Host)
		}
	}
	return &garagev1beta1.WebsiteExposureStatus{
		Type:      websiteExposureResourceIngress,
		Name:      ingress.Name,
		Hostnames: hostnames,
	}
}

// websiteExposureRouteReady derives the exposure readiness from the route's
// status.parents (Accepted / ResolvedRefs / Ready) rather than from the fact
// that the operator wrote the object: a route whose parent Gateway does not
// accept it, or whose backend reference cannot be resolved (missing
// ReferenceGrant, unknown Service), is not ready.
func websiteExposureRouteReady(route *gatewayv1.HTTPRoute) (ready bool, message string) {
	if len(route.Status.Parents) == 0 {
		return false, "the route has no parent status yet; the Gateway controller has not processed it"
	}
	for _, parent := range route.Status.Parents {
		name := websiteExposureParentName(parent)
		accepted := websiteExposureParentCond(parent, websiteExposureCondAccepted)
		if accepted == nil {
			return false, "the parent " + name + " has not reported an Accepted condition yet"
		}
		if accepted.Status != metav1.ConditionTrue {
			return false, "the parent " + name + " does not accept the route: " + accepted.Message
		}
		if resolved := websiteExposureParentCond(parent, websiteExposureCondResolvedRef); resolved != nil && resolved.Status != metav1.ConditionTrue {
			return false, "the route's backend reference is not resolved on " + name + ": " + resolved.Message
		}
		if readyParent := websiteExposureParentCond(parent, websiteExposureCondReady); readyParent != nil && readyParent.Status != metav1.ConditionTrue {
			return false, "the route is not ready on " + name + ": " + readyParent.Message
		}
	}
	return true, "route accepted and its backend reference resolved"
}

func websiteExposureParentName(parent gatewayv1.RouteParentStatus) string {
	ref := parent.ParentRef
	if ref.Namespace == nil {
		return string(ref.Name)
	}
	return string(*ref.Namespace) + "/" + string(ref.Name)
}

func websiteExposureParentCond(parent gatewayv1.RouteParentStatus, condType string) *metav1.Condition {
	for i := range parent.Conditions {
		if parent.Conditions[i].Type == condType {
			return &parent.Conditions[i]
		}
	}
	return nil
}

// finishWebsiteExposure sets the WebsiteExposed condition and mirrors the
// outcome on status.websiteExposure, persisting when changed. status carries
// the observed routing resource (nil when the exposure is removed); err is
// non-nil only for a reconcile error (the condition then takes the
// ReconcileFailed reason), while non-ready-but-expected states are passed as
// reason/message with err nil.
func (r *GarageBucketReconciler) finishWebsiteExposure(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	oldStatus *garagev1beta1.GarageBucketStatus,
	status *garagev1beta1.WebsiteExposureStatus,
	err error,
	reason string,
	message string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	condition := metav1.Condition{
		Type:               garagev1beta1.ConditionWebsiteExposed,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: bucket.Generation,
	}
	if err != nil {
		log.V(1).Info("Website exposure reconcile failed", "bucket", bucket.Name, "error", err.Error())
	} else if reason == "Exposed" {
		condition.Status = metav1.ConditionTrue
	}
	if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, &condition); err != nil {
		return ctrl.Result{}, err
	}
	if err == nil {
		return ctrl.Result{}, nil
	}
	// A foreign object squatting the generated name, or a missing RBAC grant,
	// will not heal by fast retry; back off to the drift interval.
	if strings.Contains(message, "not owned by") || k8errors.IsForbidden(err) {
		return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
	}
	return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
}

// persistWebsiteExposureStatus writes the WebsiteExposed condition and the
// status.websiteExposure block, skipping the status write when nothing
// changed (the informer-driven no-op avoidance pattern used by
// updateStatusFromGarage). status is nil when the exposure spec is gone (both
// are cleared) or could not be observed (only the condition is written, the
// previously recorded status is kept).
func (r *GarageBucketReconciler) persistWebsiteExposureStatus(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	oldStatus *garagev1beta1.GarageBucketStatus,
	status *garagev1beta1.WebsiteExposureStatus,
	condition *metav1.Condition,
) error {
	if status == nil && condition == nil {
		bucket.Status.WebsiteExposure = nil
		conditions := make([]metav1.Condition, 0, len(bucket.Status.Conditions))
		for _, c := range bucket.Status.Conditions {
			if c.Type == garagev1beta1.ConditionWebsiteExposed {
				continue
			}
			conditions = append(conditions, c)
		}
		bucket.Status.Conditions = conditions
	} else {
		if status != nil {
			bucket.Status.WebsiteExposure = status
		}
		if condition != nil {
			meta.SetStatusCondition(&bucket.Status.Conditions, *condition)
		}
	}
	if apiequality.Semantic.DeepEqual(*oldStatus, bucket.Status) {
		return nil
	}
	return UpdateStatusWithRetry(ctx, r.Client, bucket)
}

// websiteExposureBaseLabels returns the operator-set labels for a generated
// exposure resource.
func websiteExposureBaseLabels(bucket *garagev1beta1.GarageBucket) map[string]string {
	return map[string]string{
		labelAppManagedBy: "garage-operator",
		labelBucketRef:    bucket.Name,
	}
}

// websiteExposureBackendRef builds the backend reference for the exposure's
// routing rule: the explicit spec.websiteExposure.backendRef override, or
// the cluster's web API Service (gateway tier for unified clusters). The
// port is always the cluster's effective web API port number. The
// namespace of the default backend is the cluster's (where the Service
// lives); an explicit referent says where it lives itself.
func websiteExposureBackendRef(
	bucket *garagev1beta1.GarageBucket,
	clusterNamespace string,
	cluster *garagev1beta2.GarageCluster,
	ref *garagev1beta1.WebsiteExposureBackendReference,
) gatewayv1.BackendObjectReference {
	group := ""
	kind := websiteExposureServiceKind
	namespace := ""
	name := websiteExposureBackend(cluster)
	if ref != nil {
		group = ref.Group
		if ref.Kind != "" {
			kind = ref.Kind
		}
		namespace = ref.Namespace
		name = ref.Name
	} else {
		namespace = clusterNamespace
	}
	port := getWebPort(cluster)
	backref := gatewayv1.BackendObjectReference{
		Name: gatewayv1.ObjectName(name),
		Port: &port,
	}
	if group != "" {
		g := gatewayv1.Group(group)
		backref.Group = &g
	}
	if kind != websiteExposureServiceKind {
		k := gatewayv1.Kind(kind)
		backref.Kind = &k
	}
	// The exposure lives in the bucket's namespace; an omitted namespace
	// means "same namespace" in Gateway API semantics. Set it explicitly only
	// when the referent genuinely lives elsewhere (a cross-namespace backend
	// then needs the gateway ReferenceGrant the storage admin owns).
	if namespace != "" && namespace != bucket.Namespace {
		ns := gatewayv1.Namespace(namespace)
		backref.Namespace = &ns
	}
	return backref
}

// ingressBackendName resolves the Service name for the Ingress backend
// (Ingress backends are core/v1 Services in the Ingress's namespace, which
// is the bucket's namespace).
func ingressBackendName(bucket *garagev1beta1.GarageBucket, cluster *garagev1beta2.GarageCluster, ref *garagev1beta1.WebsiteExposureBackendReference) (string, error) {
	if ref == nil {
		return websiteExposureBackend(cluster), nil
	}
	if ref.Group != "" || (ref.Kind != "" && ref.Kind != websiteExposureServiceKind) {
		return "", fmt.Errorf("websiteExposure.backendRef must reference a core/v1 Service for an Ingress (got kind %q group %q)", ref.Kind, ref.Group)
	}
	if ref.Namespace != "" && ref.Namespace != bucket.Namespace {
		return "", fmt.Errorf("websiteExposure.backendRef.namespace %q is invalid for an Ingress: the backend Service must live in the bucket's namespace %q (Ingress backends cannot cross namespaces)", ref.Namespace, bucket.Namespace)
	}
	return ref.Name, nil
}

// buildIngress constructs the desired Ingress for a website-enabled bucket.
// The Ingress is created in the bucket's namespace; its backend Service must
// therefore be in that namespace too.
func (r *GarageBucketReconciler) buildIngress(
	bucket *garagev1beta1.GarageBucket,
	clusterNamespace string,
	cluster *garagev1beta2.GarageCluster,
	exposure *garagev1beta1.WebsiteExposureConfig,
) (*networkingv1.Ingress, error) {
	ingressConfig := exposure.Ingress
	if ingressConfig == nil {
		return nil, fmt.Errorf("websiteExposure.ingress is required")
	}
	// Defensive mirror of the validating webhook (which catches this at
	// admission): an Ingress backend cannot cross namespaces, and the
	// exposure Ingress routes to the cluster's web Service — so Ingress
	// exposure is only valid when the bucket and the cluster share a
	// namespace. Cross-namespace exposure is the HTTPRoute path, which
	// reaches the cluster's Service through a gateway ReferenceGrant.
	if clusterNamespace == "" {
		clusterNamespace = bucket.Namespace
	}
	if bucket.Namespace != clusterNamespace {
		return nil, fmt.Errorf("websiteExposure.ingress is not supported when the bucket (%s) and its cluster (%s) are in different namespaces: an Ingress backend cannot cross namespaces. Use websiteExposure.gateway instead", bucket.Namespace, clusterNamespace)
	}
	svcName, err := ingressBackendName(bucket, cluster, exposure.BackendRef)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalWebsiteHost(cluster, bucket.Status.GlobalAlias)
	if err != nil {
		return nil, err
	}
	hostnames, err := websiteExposureHostnames(cluster, exposure, bucket.Status.GlobalAlias)
	if err != nil {
		return nil, err
	}
	// An Ingress has no host-rewrite filter: every hostname it routes on
	// reaches Garage verbatim, so each one must already resolve to the
	// bucket — the canonical <alias><rootDomain> form or the bare alias.
	// Any other hostname is rejected (surfaced on the condition) rather
	// than silently mis-routed; an HTTPRoute can carry it instead, because
	// its URLRewrite filter rewrites the Host back to the canonical host.
	for _, host := range hostnames {
		if websiteExposureNeedsRewrite(host, canonical, bucket.Status.GlobalAlias) {
			return nil, fmt.Errorf("ingress hostname %q does not resolve to the bucket: an Ingress cannot rewrite the Host header, so only the canonical hostname %q or the global alias %q are supported (use websiteExposure.gateway to route other hostnames)", host, canonical, bucket.Status.GlobalAlias)
		}
	}

	pathType := networkingv1.PathTypePrefix
	var tls []networkingv1.IngressTLS
	if ingressConfig.TLSSecretName != "" {
		tls = []networkingv1.IngressTLS{
			{
				Hosts:      hostnames,
				SecretName: ingressConfig.TLSSecretName,
			},
		}
	}
	var className *string
	if ingressConfig.IngressClassName != "" {
		className = &ingressConfig.IngressClassName
	}

	rules := make([]networkingv1.IngressRule, 0, len(hostnames))
	for _, host := range hostnames {
		rules = append(rules, networkingv1.IngressRule{
			Host: host,
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{
						{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: svcName,
									Port: networkingv1.ServiceBackendPort{
										Name: webPortName,
									},
								},
							},
						},
					},
				},
			},
		})
	}

	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        websiteExposureResourceName(bucket),
			Namespace:   bucket.Namespace,
			Labels:      mergeLabels(websiteExposureBaseLabels(bucket), ingressConfig.Labels),
			Annotations: copyStringMap(ingressConfig.Annotations),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: className,
			TLS:              tls,
			Rules:            rules,
		},
	}, nil
}

// buildHTTPRoute constructs the desired Gateway API HTTPRoute for a
// website-enabled bucket. The route is created in the bucket's namespace; a
// backend in another namespace (the cluster's web Service, or an explicit
// cross-namespace backendRef) requires a gateway API ReferenceGrant in the
// backend's namespace.
func (r *GarageBucketReconciler) buildHTTPRoute(
	bucket *garagev1beta1.GarageBucket,
	clusterNamespace string,
	cluster *garagev1beta2.GarageCluster,
	exposure *garagev1beta1.WebsiteExposureConfig,
) (*gatewayv1.HTTPRoute, error) {
	gatewayConfig := exposure.Gateway
	if gatewayConfig == nil {
		return nil, fmt.Errorf("websiteExposure.gateway is required")
	}
	canonical, err := canonicalWebsiteHost(cluster, bucket.Status.GlobalAlias)
	if err != nil {
		return nil, err
	}
	hostnames, err := websiteExposureHostnames(cluster, exposure, bucket.Status.GlobalAlias)
	if err != nil {
		return nil, err
	}
	backendRef := websiteExposureBackendRef(bucket, clusterNamespace, cluster, exposure.BackendRef)

	// spec.parentRefs is embedded upstream gatewayv1 types verbatim; copy so
	// the operator never mutates the spec object it was handed. A parentRef
	// with no namespace defaults to the route's namespace in Gateway API
	// semantics; record it explicitly so the intent is visible on the stored
	// object.
	parentRefs := make([]gatewayv1.ParentReference, len(gatewayConfig.ParentRefs))
	copy(parentRefs, gatewayConfig.ParentRefs)
	for i := range parentRefs {
		if parentRefs[i].Namespace == nil {
			ns := gatewayv1.Namespace(bucket.Namespace)
			parentRefs[i].Namespace = &ns
		}
	}

	pathPrefix := gatewayv1.PathMatchPathPrefix
	pathValue := "/"
	canonicalHostname := gatewayv1.PreciseHostname(canonical)
	rules := make([]gatewayv1.HTTPRouteRule, 0, len(hostnames))
	for _, host := range hostnames {
		var filters []gatewayv1.HTTPRouteFilter
		if websiteExposureNeedsRewrite(host, canonical, bucket.Status.GlobalAlias) {
			// The hostname is neither the canonical <alias><rootDomain> form
			// nor the bare alias: rewrite the Host header so Garage resolves
			// the request to this bucket.
			filters = append(filters, gatewayv1.HTTPRouteFilter{
				Type: gatewayv1.HTTPRouteFilterURLRewrite,
				URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
					Hostname: &canonicalHostname,
				},
			})
		}
		rules = append(rules, gatewayv1.HTTPRouteRule{
			Matches: []gatewayv1.HTTPRouteMatch{
				{
					Path: &gatewayv1.HTTPPathMatch{
						Type:  &pathPrefix,
						Value: &pathValue,
					},
				},
			},
			Filters: filters,
			BackendRefs: []gatewayv1.HTTPBackendRef{
				{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: backendRef,
					},
				},
			},
		})
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      websiteExposureResourceName(bucket),
			Namespace: bucket.Namespace,
			Labels:    mergeLabels(websiteExposureBaseLabels(bucket), gatewayConfig.Labels),
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: parentRefs,
			},
			Hostnames: make([]gatewayv1.Hostname, len(hostnames)),
			Rules:     rules,
		},
	}
	for i, h := range hostnames {
		route.Spec.Hostnames[i] = gatewayv1.Hostname(h)
	}
	if len(gatewayConfig.Annotations) > 0 {
		route.Annotations = copyStringMap(gatewayConfig.Annotations)
	}
	return route, nil
}

// applyWebsiteExposureResource creates or updates the desired exposure
// resource. The exposure lives in the bucket's own namespace, so a
// controller owner reference is always set: garbage collection removes the
// resource with the bucket, and later reconciles recognize the operator's
// object through the owner reference alone. An object not owned by this
// bucket squatting on the generated name is refused, not mutated.
//
// The update is a full replacement of the spec plus an owned-metadata apply:
// the operator owns the whole spec of the generated object (it is the only
// writer that may touch it), while labels and annotations go through
// applyOwnedMetadata so keys stamped by other controllers (external-dns,
// cert-manager, …) survive.
func (r *GarageBucketReconciler) applyWebsiteExposureResource(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	desired client.Object,
) error {
	if err := controllerutil.SetControllerReference(bucket, desired, r.Scheme); err != nil {
		return fmt.Errorf("setting controller reference: %w", err)
	}
	existing := desired.DeepCopyObject().(client.Object)
	err := r.Get(ctx, types.NamespacedName{Name: desired.GetName(), Namespace: desired.GetNamespace()}, existing)
	if k8errors.IsNotFound(err) {
		logf.FromContext(ctx).Info("Creating website exposure resource", "name", desired.GetName())
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("creating website exposure resource %s/%s: %w", desired.GetNamespace(), desired.GetName(), err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(existing, bucket) {
		return fmt.Errorf("refusing to update website exposure resource %s/%s because it is not owned by GarageBucket UID %s",
			existing.GetNamespace(), existing.GetName(), bucket.UID)
	}
	switch d := desired.(type) {
	case *networkingv1.Ingress:
		e := existing.(*networkingv1.Ingress)
		e.OwnerReferences = d.OwnerReferences
		e.Spec = d.Spec
		if err := r.Update(ctx, e); err != nil {
			return fmt.Errorf("updating Ingress: %w", err)
		}
		return applyOwnedMetadata(ctx, r.Client, e, d)
	case *gatewayv1.HTTPRoute:
		e := existing.(*gatewayv1.HTTPRoute)
		e.OwnerReferences = d.OwnerReferences
		// The route status is owned by the Gateway controller; only the spec
		// (and metadata) is the operator's to write.
		e.Spec = d.Spec
		if err := r.Update(ctx, e); err != nil {
			return fmt.Errorf("updating HTTPRoute: %w", err)
		}
		return applyOwnedMetadata(ctx, r.Client, e, d)
	default:
		return fmt.Errorf("unsupported website exposure resource type %T", desired)
	}
}

// deleteWebsiteExposureResource removes both possible exposure resources of
// the bucket. The resources live in the bucket's own namespace and carry a
// controller owner reference, so Kubernetes garbage collection already
// removes them with the bucket; this call additionally covers the
// spec-removal case (bucket still alive) and makes the deletion explicit and
// idempotent on every deletion path. Foreign objects are left untouched.
func (r *GarageBucketReconciler) deleteWebsiteExposureResource(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	if err := r.deleteWebsiteExposureIngress(ctx, bucket); err != nil {
		return err
	}
	return r.deleteWebsiteExposureRoute(ctx, bucket)
}

// deleteWebsiteExposureIngress removes the owned Ingress when it is not the
// kind the spec asks for (spec removal or a switch to gateway). It is a
// no-op when Ingress support is disabled: without --enable-ingress the
// operator has no RBAC on Ingresses, so the lookup would be Forbidden. An
// Ingress created earlier (for example by v0.8.0) is then left in place; it
// is still garbage-collected with the bucket through its owner reference.
func (r *GarageBucketReconciler) deleteWebsiteExposureIngress(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	if !r.ingressEnabled() {
		return nil
	}
	// A bucket that never had a website exposure has nothing to clean up.
	// The status record is the durable marker (the spec field is cleared when
	// the exposure is removed), so both being unset means no resource was
	// ever created and the probe can be skipped.
	if bucket.Spec.WebsiteExposure == nil && bucket.Status.WebsiteExposure == nil {
		return nil
	}

	name := websiteExposureResourceName(bucket)
	ingress := &networkingv1.Ingress{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: bucket.Namespace}, ingress)
	if err == nil {
		if metav1.IsControlledBy(ingress, bucket) {
			logf.FromContext(ctx).Info("Deleting website exposure Ingress", "name", name)
			if err := r.Delete(ctx, ingress); err != nil && !k8errors.IsNotFound(err) {
				return fmt.Errorf("deleting Ingress: %w", err)
			}
		}
	} else if !k8errors.IsNotFound(err) {
		return err
	}
	return nil
}

// deleteWebsiteExposureRoute removes the owned HTTPRoute when it is not the
// kind the spec asks for (spec removal or a switch to ingress). It is a
// no-op when Gateway API is unavailable: the route cannot even be listed.
func (r *GarageBucketReconciler) deleteWebsiteExposureRoute(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	if !r.gatewayAPIEnabled() {
		return nil
	}
	if bucket.Spec.WebsiteExposure == nil && bucket.Status.WebsiteExposure == nil {
		return nil
	}

	name := websiteExposureResourceName(bucket)
	route := &gatewayv1.HTTPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: bucket.Namespace}, route)
	if err == nil {
		if metav1.IsControlledBy(route, bucket) {
			logf.FromContext(ctx).Info("Deleting website exposure HTTPRoute", "name", name)
			if err := r.Delete(ctx, route); err != nil && !k8errors.IsNotFound(err) {
				return fmt.Errorf("deleting HTTPRoute: %w", err)
			}
		}
	} else if !k8errors.IsNotFound(err) {
		return err
	}
	return nil
}

// ingressEnabled reports whether the operator may create Ingresses: the
// --enable-ingress flag (or ENABLE_INGRESS env var, chart value
// ingress.enabled) must be set. Ingress is a built-in API, so unlike the
// Gateway API there is no CRD probe.
func (r *GarageBucketReconciler) ingressEnabled() bool {
	return r.EnableIngress
}

// gatewayAPIEnabled reports whether the operator may create HTTPRoutes:
// the --enable-gateway-api flag (or ENABLE_GATEWAY_API env var) must be set
// AND the Gateway API CRDs must be installed, probed through the REST mapper
// (the same pattern as monitoringCRDExists) so no informer is started when
// the CRD is absent.
func (r *GarageBucketReconciler) gatewayAPIEnabled() bool {
	if !r.EnableGatewayAPI {
		return false
	}
	mapper := r.RESTMapper()
	if mapper == nil {
		return false
	}
	_, err := mapper.RESTMapping(schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: websiteExposureResourceHTTPRoute})
	return err == nil
}
