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
	"slices"
	"sort"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	// webUIFeature is the Garage Cargo feature that embeds the web admin UI.
	webUIFeature = "webadmin"
	// webUIPath is where Garage serves the UI on the Admin API listener.
	webUIPath = "/ui/"
	// webUIComponent labels the generated Ingress/HTTPRoute.
	webUIComponent = "webui"

	webUIReasonExposed               = "Exposed"
	webUIReasonNotReady              = "NotReady"
	webUIReasonIngressDisabled       = "IngressDisabled"
	webUIReasonGatewayAPIUnavailable = "GatewayAPIUnavailable"
	webUIReasonReconcileFailed       = "ReconcileFailed"
)

// webUIResourceName is the name of the Ingress or HTTPRoute generated for
// spec.admin.webUI, in the cluster's namespace.
func webUIResourceName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-" + webUIComponent
}

// webUIConfig returns spec.admin.webUI, or nil.
func webUIConfig(cluster *garagev1beta2.GarageCluster) *garagev1beta2.WebUIConfig {
	if cluster == nil || cluster.Spec.Admin == nil {
		return nil
	}
	return cluster.Spec.Admin.WebUI
}

// webUIInClusterURL is the UI URL on the <cluster> Service's admin port.
func webUIInClusterURL(cluster *garagev1beta2.GarageCluster, clusterDomain string) string {
	return schemeHTTP + "://" + svcFQDN(cluster.Name, cluster.Namespace, getAdminPort(cluster), clusterDomain) + webUIPath
}

// webUIScheme is the scheme published for the external URL: spec.scheme, else
// https when the Ingress carries a TLS Secret, else http.
func webUIScheme(cfg *garagev1beta2.WebUIConfig) string {
	if cfg.Scheme != "" {
		return cfg.Scheme
	}
	if cfg.Ingress != nil && cfg.Ingress.TLSSecretName != "" {
		return "https"
	}
	return schemeHTTP
}

// webUIExternalURL is the UI URL on spec.admin.webUI.hostname.
func webUIExternalURL(cfg *garagev1beta2.WebUIConfig) string {
	return webUIScheme(cfg) + "://" + cfg.Hostname + webUIPath
}

// webUIAvailabilityCondition derives WebUIAvailable from the build features
// each reachable node reports. It returns (nil, true) when no node answered,
// so the previously recorded condition is kept rather than guessed at.
func webUIAvailabilityCondition(cluster *garagev1beta2.GarageCluster, infos map[string]garage.NodeBuildInfo) (*metav1.Condition, bool) {
	if len(infos) == 0 {
		return nil, true
	}
	var missing []string
	for id, info := range infos {
		if slices.Contains(info.GarageFeatures, webUIFeature) {
			continue
		}
		short := id
		if len(short) > 16 {
			short = short[:16]
		}
		version := info.GarageVersion
		if version == "" {
			version = "unknown version"
		}
		missing = append(missing, fmt.Sprintf("%s (%s)", short, version))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return &metav1.Condition{
			Type:   garagev1beta1.ConditionWebUIAvailable,
			Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonWebUIFeatureNotPresent,
			Message: fmt.Sprintf("%d of %d reachable node(s) were built without the %q feature and do not serve %s: %s. "+
				"Official Garage images embed the web admin UI from v2.6.0",
				len(missing), len(infos), webUIFeature, webUIPath, strings.Join(missing, ", ")),
			ObservedGeneration: cluster.Generation,
		}, false
	}
	return &metav1.Condition{
		Type:               garagev1beta1.ConditionWebUIAvailable,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonWebUIFeaturePresent,
		Message:            fmt.Sprintf("all %d reachable node(s) serve the web admin UI at %s on the Admin API port", len(infos), webUIPath),
		ObservedGeneration: cluster.Generation,
	}, false
}

// applyWebUIAvailability writes WebUIAvailable from the observed node build
// info, leaving the previous condition in place when nothing was observed.
func (r *GarageClusterReconciler) applyWebUIAvailability(cluster *garagev1beta2.GarageCluster, infos map[string]garage.NodeBuildInfo) {
	cond, keep := webUIAvailabilityCondition(cluster, infos)
	if keep || cond == nil {
		return
	}
	meta.SetStatusCondition(&cluster.Status.Conditions, *cond)
}

// setWebUIExposed records WebUIExposed in memory; the status pass persists it.
func setWebUIExposed(cluster *garagev1beta2.GarageCluster, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionWebUIExposed,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: cluster.Generation,
	})
}

// reconcileWebUIExposure creates, updates, or deletes the Ingress or
// HTTPRoute declared by spec.admin.webUI and records WebUIExposed on the
// in-memory status. It returns the external UI URL once the exposure is in
// place, or "". It never fails the reconcile: problems are reported on the
// condition and retried on the next status pass. The exposure is created
// regardless of WebUIAvailable, so it is ready when the image is upgraded.
func (r *GarageClusterReconciler) reconcileWebUIExposure(ctx context.Context, cluster *garagev1beta2.GarageCluster) string {
	log := logf.FromContext(ctx)
	cfg := webUIConfig(cluster)
	if cfg == nil || cluster.IsManagementHandle() {
		if err := r.deleteWebUIResources(ctx, cluster, true, true); err != nil {
			log.V(1).Info("Failed to delete the web UI exposure", "error", err)
			return ""
		}
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionWebUIExposed)
		return ""
	}

	// Ingress and HTTPRoute share the generated name: drop the kind the spec
	// no longer asks for.
	if err := r.deleteWebUIResources(ctx, cluster, cfg.Gateway != nil, cfg.Ingress != nil); err != nil {
		setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonReconcileFailed, err.Error())
		return ""
	}

	name := webUIResourceName(cluster)
	if cfg.Gateway != nil {
		if !r.webUIGatewayAPIEnabled() {
			setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonGatewayAPIUnavailable,
				"spec.admin.webUI.gateway is set but the Gateway API is unavailable (CRDs not installed or the operator is not started with --enable-gateway-api)")
			return ""
		}
		route := buildWebUIHTTPRoute(cluster, cfg, r.labelsForCluster(cluster))
		if err := r.applyWebUIResource(ctx, cluster, route); err != nil {
			setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonReconcileFailed, err.Error())
			return ""
		}
		fresh := &gatewayv1.HTTPRoute{}
		if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, fresh); err != nil {
			setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonReconcileFailed, err.Error())
			return ""
		}
		if ready, message := websiteExposureRouteReady(fresh); !ready {
			setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonNotReady, message)
			return ""
		}
		setWebUIExposed(cluster, metav1.ConditionTrue, webUIReasonExposed,
			fmt.Sprintf("web admin UI exposed on %s via HTTPRoute %s/%s", cfg.Hostname, cluster.Namespace, name))
		return webUIExternalURL(cfg)
	}

	if !r.EnableIngress {
		setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonIngressDisabled,
			"spec.admin.webUI.ingress is set but Ingress support is disabled (start the operator with --enable-ingress, or set the chart value ingress.enabled=true)")
		return ""
	}
	ingress := buildWebUIIngress(cluster, cfg, r.labelsForCluster(cluster))
	if err := r.applyWebUIResource(ctx, cluster, ingress); err != nil {
		setWebUIExposed(cluster, metav1.ConditionFalse, webUIReasonReconcileFailed, err.Error())
		return ""
	}
	setWebUIExposed(cluster, metav1.ConditionTrue, webUIReasonExposed,
		fmt.Sprintf("web admin UI exposed on %s via Ingress %s/%s", cfg.Hostname, cluster.Namespace, name))
	return webUIExternalURL(cfg)
}

// buildWebUIIngress routes the whole host to the <cluster> Service's admin
// port (selected by name, so a non-default spec.admin.bindPort follows).
func buildWebUIIngress(cluster *garagev1beta2.GarageCluster, cfg *garagev1beta2.WebUIConfig, baseLabels map[string]string) *networkingv1.Ingress {
	ic := cfg.Ingress
	pathType := networkingv1.PathTypePrefix
	var className *string
	if ic.IngressClassName != "" {
		className = &ic.IngressClassName
	}
	var tls []networkingv1.IngressTLS
	if ic.TLSSecretName != "" {
		tls = []networkingv1.IngressTLS{{Hosts: []string{cfg.Hostname}, SecretName: ic.TLSSecretName}}
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        webUIResourceName(cluster),
			Namespace:   cluster.Namespace,
			Labels:      mergeLabels(webUILabels(baseLabels), ic.Labels),
			Annotations: copyStringMap(ic.Annotations),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: className,
			TLS:              tls,
			Rules: []networkingv1.IngressRule{{
				Host: cfg.Hostname,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: cluster.Name,
									Port: networkingv1.ServiceBackendPort{Name: adminPortName},
								},
							},
						}},
					},
				},
			}},
		},
	}
}

// buildWebUIHTTPRoute routes the whole host to the <cluster> Service's admin
// port. The route and the Service share the cluster's namespace, so no
// ReferenceGrant is needed for the backend.
func buildWebUIHTTPRoute(cluster *garagev1beta2.GarageCluster, cfg *garagev1beta2.WebUIConfig, baseLabels map[string]string) *gatewayv1.HTTPRoute {
	gc := cfg.Gateway
	parentRefs := make([]gatewayv1.ParentReference, len(gc.ParentRefs))
	copy(parentRefs, gc.ParentRefs)
	for i := range parentRefs {
		if parentRefs[i].Namespace == nil {
			ns := gatewayv1.Namespace(cluster.Namespace)
			parentRefs[i].Namespace = &ns
		}
	}
	pathPrefix := gatewayv1.PathMatchPathPrefix
	pathValue := "/"
	port := getAdminPort(cluster)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webUIResourceName(cluster),
			Namespace: cluster.Namespace,
			Labels:    mergeLabels(webUILabels(baseLabels), gc.Labels),
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(cfg.Hostname)},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{
					Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: &pathValue},
				}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(cluster.Name),
							Port: &port,
						},
					},
				}},
			}},
		},
	}
	if len(gc.Annotations) > 0 {
		route.Annotations = copyStringMap(gc.Annotations)
	}
	return route
}

func webUILabels(base map[string]string) map[string]string {
	out := copyStringMap(base)
	if out == nil {
		out = map[string]string{}
	}
	out[labelAppComponent] = webUIComponent
	return out
}

// applyWebUIResource creates or updates the generated Ingress/HTTPRoute. The
// GarageCluster is its controller owner, so it is garbage-collected with the
// cluster. An object of the same name not owned by this cluster is refused.
// The spec is replaced wholesale; labels and annotations go through
// applyOwnedMetadata so keys stamped by other controllers survive.
func (r *GarageClusterReconciler) applyWebUIResource(ctx context.Context, cluster *garagev1beta2.GarageCluster, desired client.Object) error {
	if err := controllerutil.SetControllerReference(cluster, desired, r.Scheme); err != nil {
		return fmt.Errorf("setting controller reference: %w", err)
	}
	existing := desired.DeepCopyObject().(client.Object)
	err := r.Get(ctx, types.NamespacedName{Name: desired.GetName(), Namespace: desired.GetNamespace()}, existing)
	if k8errors.IsNotFound(err) {
		logf.FromContext(ctx).Info("Creating web UI exposure", "kind", fmt.Sprintf("%T", desired), "name", desired.GetName())
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("creating web UI exposure %s/%s: %w", desired.GetNamespace(), desired.GetName(), err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(existing, cluster) {
		return fmt.Errorf("refusing to update %s/%s: it exists but is not owned by GarageCluster %s", existing.GetNamespace(), existing.GetName(), cluster.Name)
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
		e.Spec = d.Spec
		if err := r.Update(ctx, e); err != nil {
			return fmt.Errorf("updating HTTPRoute: %w", err)
		}
		return applyOwnedMetadata(ctx, r.Client, e, d)
	default:
		return fmt.Errorf("unsupported web UI exposure type %T", desired)
	}
}

// deleteWebUIResources removes the owned Ingress and/or HTTPRoute. A kind the
// operator may not use (flag off, CRD absent) is skipped: it has no RBAC for
// it, and anything created earlier is still garbage-collected with the
// cluster. Without a recorded WebUIExposed condition nothing was ever
// created, so the lookups are skipped.
func (r *GarageClusterReconciler) deleteWebUIResources(ctx context.Context, cluster *garagev1beta2.GarageCluster, ingress, route bool) error {
	if webUIConfig(cluster) == nil && meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionWebUIExposed) == nil {
		return nil
	}
	key := types.NamespacedName{Name: webUIResourceName(cluster), Namespace: cluster.Namespace}
	if ingress && r.EnableIngress {
		if err := r.deleteOwnedWebUIObject(ctx, cluster, key, &networkingv1.Ingress{}); err != nil {
			return err
		}
	}
	if route && r.webUIGatewayAPIEnabled() {
		if err := r.deleteOwnedWebUIObject(ctx, cluster, key, &gatewayv1.HTTPRoute{}); err != nil {
			return err
		}
	}
	return nil
}

func (r *GarageClusterReconciler) deleteOwnedWebUIObject(ctx context.Context, cluster *garagev1beta2.GarageCluster, key types.NamespacedName, obj client.Object) error {
	if err := r.Get(ctx, key, obj); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !metav1.IsControlledBy(obj, cluster) {
		return nil
	}
	logf.FromContext(ctx).Info("Deleting web UI exposure", "kind", fmt.Sprintf("%T", obj), "name", key.Name)
	if err := r.Delete(ctx, obj); err != nil && !k8errors.IsNotFound(err) {
		return fmt.Errorf("deleting web UI exposure %s: %w", key, err)
	}
	return nil
}

// webUIGatewayAPIEnabled mirrors GarageBucketReconciler.gatewayAPIEnabled:
// --enable-gateway-api must be set and the HTTPRoute kind must be served.
func (r *GarageClusterReconciler) webUIGatewayAPIEnabled() bool {
	if !r.EnableGatewayAPI || r.Client == nil {
		return false
	}
	mapper := r.RESTMapper()
	if mapper == nil {
		return false
	}
	_, err := mapper.RESTMapping(schema.GroupKind{Group: gatewayv1.GroupName, Kind: websiteExposureResourceHTTPRoute})
	return err == nil
}
