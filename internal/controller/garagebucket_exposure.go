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

// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=create;delete;get;list;patch;update;watch

// websiteExposureResourceName is the name of the operator-generated Ingress
// or HTTPRoute for a bucket.
func websiteExposureResourceName(bucket *garagev1beta1.GarageBucket) string {
	return bucket.Name + "-website"
}

// websiteExposureNamespace is the namespace the exposure resource is created
// in: the cluster's namespace, where the web API Service lives. Ingress
// backends cannot cross namespaces, and an HTTPRoute backendRef to the
// cluster's Service from another namespace would additionally need a
// gateway ReferenceGrant. A controller owner reference to the bucket is only
// possible when the bucket and the cluster share a namespace (Kubernetes
// forbids cross-namespace owner references); in the cross-namespace case the
// bucket controller deletes the exposure resource explicitly.
func websiteExposureNamespace(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Namespace
}

// websiteExposureBackend returns the Service the exposure routes to: the
// cluster's in-cluster API Service (the primary <cr> Service, which carries
// the web port for every cluster shape).
func websiteExposureBackend(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name
}

// websiteExposureHost resolves the hostname the exposure must route on.
// Garage resolves the served bucket from the Host header (the bucket's global
// alias followed by the cluster's webApi.rootDomain), so the only usable host
// for this bucket is the explicit spec host (which must match that pattern)
// or the derived <globalAlias><rootDomain> form.
func websiteExposureHost(cluster *garagev1beta2.GarageCluster, exposure *garagev1beta1.WebsiteExposureConfig, alias string) (string, error) {
	if exposure.Host != "" {
		if !websiteExposureHostMatchesAlias(cluster, exposure.Host, alias) {
			return "", fmt.Errorf(
				"websiteExposure.host %q does not match the bucket's website host pattern <globalAlias><webApi.rootDomain>: "+
					"Garage resolves buckets from the Host header, so any other host would be served as a 404",
				exposure.Host,
			)
		}
		return exposure.Host, nil
	}
	if alias == "" {
		return "", errWebsiteExposureWaitingForAlias
	}
	w := effectiveWebAPI(cluster)
	if w == nil {
		return "", fmt.Errorf("the referenced cluster has webApi disabled; no website host can be derived")
	}
	return alias + w.RootDomain, nil
}

// errWebsiteExposureWaitingForAlias is the transient host-resolution error
// while the bucket's global alias is not yet recorded in status.
var errWebsiteExposureWaitingForAlias = errors.New("waiting for the bucket's global alias to be recorded before the website host can be derived")

// websiteExposureHostMatchesAlias reports whether host is exactly
// <alias><rootDomain> for the cluster's effective webApi configuration.
func websiteExposureHostMatchesAlias(cluster *garagev1beta2.GarageCluster, host, alias string) bool {
	w := effectiveWebAPI(cluster)
	if w == nil || alias == "" {
		return false
	}
	return host == alias+w.RootDomain
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
	if exposure == nil {
		if err := r.deleteWebsiteExposureResource(ctx, bucket, websiteExposureNamespace(cluster)); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, nil); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	alias := bucket.Status.GlobalAlias
	host, hostErr := websiteExposureHost(cluster, exposure, alias)
	if hostErr != nil {
		if errors.Is(hostErr, errWebsiteExposureWaitingForAlias) && exposure.Host == "" {
			condition := metav1.Condition{
				Type:               garagev1beta1.ConditionWebsiteExposed,
				Status:             metav1.ConditionFalse,
				Reason:             "WaitingForAlias",
				Message:            "the bucket's global alias is not recorded yet; the derived website host cannot be computed",
				ObservedGeneration: bucket.Generation,
			}
			status := &garagev1beta1.WebsiteExposureStatus{
				Name:    websiteExposureResourceName(bucket),
				Ready:   false,
				Message: condition.Message,
			}
			if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		return r.finishWebsiteExposure(ctx, bucket, cluster, oldStatus, "", hostErr)
	}

	var (
		resource client.Object
		kind     string
		err      error
	)
	if exposure.Gateway != nil {
		kind = "HTTPRoute"
		if !r.gatewayAPIAvailable() {
			condition := metav1.Condition{
				Type:               garagev1beta1.ConditionWebsiteExposed,
				Status:             metav1.ConditionFalse,
				Reason:             "GatewayAPIUnavailable",
				Message:            "spec.websiteExposure.gateway is set but the gateway.networking.k8s.io HTTPRoute CRD is not installed; install the Gateway API CRDs to enable it",
				ObservedGeneration: bucket.Generation,
			}
			status := &garagev1beta1.WebsiteExposureStatus{
				Type:    kind,
				Name:    websiteExposureResourceName(bucket),
				Host:    host,
				Ready:   false,
				Message: condition.Message,
			}
			if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
		}
		resource, err = r.buildHTTPRoute(bucket, cluster, exposure, host)
	} else {
		kind = "Ingress"
		resource, err = r.buildIngress(bucket, cluster, exposure, host)
	}
	if err != nil {
		return r.finishWebsiteExposure(ctx, bucket, cluster, oldStatus, host, err)
	}

	if err := r.applyWebsiteExposureResource(ctx, bucket, cluster, resource); err != nil {
		return r.finishWebsiteExposure(ctx, bucket, cluster, oldStatus, host, err)
	}
	return r.finishWebsiteExposure(ctx, bucket, cluster, oldStatus, host, nil, kind)
}

// finishWebsiteExposure sets the WebsiteExposed condition, mirrors the
// outcome on status.websiteExposure, and persists it when changed. host is
// the resolved website host (empty when it could not be resolved); kind is
// the resource type on success.
func (r *GarageBucketReconciler) finishWebsiteExposure(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	cluster *garagev1beta2.GarageCluster,
	oldStatus *garagev1beta1.GarageBucketStatus,
	host string,
	err error,
	kind ...string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	name := websiteExposureResourceName(bucket)
	status := &garagev1beta1.WebsiteExposureStatus{Name: name, Namespace: websiteExposureNamespace(cluster), Host: host}
	condition := metav1.Condition{}
	if err != nil {
		log.V(1).Info("Website exposure reconcile failed", "bucket", bucket.Name, "error", err.Error())
		status.Ready = false
		status.Message = err.Error()
		condition = metav1.Condition{
			Type:               garagev1beta1.ConditionWebsiteExposed,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
			Message:            err.Error(),
			ObservedGeneration: bucket.Generation,
		}
	} else if len(kind) == 1 && kind[0] != "" {
		status.Type = kind[0]
		status.Ready = true
		status.Message = "website exposed via " + kind[0] + " " + status.Namespace + "/" + name
		condition = metav1.Condition{
			Type:               garagev1beta1.ConditionWebsiteExposed,
			Status:             metav1.ConditionTrue,
			Reason:             "Exposed",
			Message:            status.Message,
			ObservedGeneration: bucket.Generation,
		}
	}
	if err := r.persistWebsiteExposureStatus(ctx, bucket, oldStatus, status, condition); err != nil {
		return ctrl.Result{}, err
	}
	if err == nil {
		return ctrl.Result{}, nil
	}
	// A foreign object squatting the generated name, or a missing RBAC grant,
	// will not heal by fast retry; back off to the drift interval.
	if strings.Contains(err.Error(), "not owned by") || k8errors.IsForbidden(err) {
		return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
	}
	return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
}

// persistWebsiteExposureStatus writes the WebsiteExposed condition and the
// status.websiteExposure block, skipping the status write when nothing
// changed (the informer-driven no-op avoidance pattern used by
// updateStatusFromGarage). status is nil when the exposure spec is gone and
// both are cleared.
func (r *GarageBucketReconciler) persistWebsiteExposureStatus(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	oldStatus *garagev1beta1.GarageBucketStatus,
	status *garagev1beta1.WebsiteExposureStatus,
	condition ...metav1.Condition,
) error {
	if status == nil {
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
		bucket.Status.WebsiteExposure = status
		if len(condition) == 1 {
			meta.SetStatusCondition(&bucket.Status.Conditions, condition[0])
		}
	}
	if apiequality.Semantic.DeepEqual(*oldStatus, bucket.Status) {
		return nil
	}
	return UpdateStatusWithRetry(ctx, r.Client, bucket)
}

// websiteExposureBaseLabels returns the operator-set labels for a generated
// exposure resource. In the cross-namespace case (where no controller owner
// reference can be set) the bucket's UID is recorded as a durable ownership
// marker so later reconciles and deletions can recognize the operator's own
// object.
func websiteExposureBaseLabels(bucket *garagev1beta1.GarageBucket, cluster *garagev1beta2.GarageCluster) map[string]string {
	labels := map[string]string{
		labelAppManagedBy: "garage-operator",
		labelBucketRef:    bucket.Name,
	}
	if bucket.Namespace != cluster.Namespace {
		labels[labelWebsiteExposureOwner] = string(bucket.UID)
	}
	return labels
}

// isWebsiteExposureOwned reports whether an existing exposure resource is
// owned by the bucket: by controller owner reference (same-namespace) or by
// the durable UID label (cross-namespace, where no owner reference can be
// set).
func isWebsiteExposureOwned(obj client.Object, bucket *garagev1beta1.GarageBucket, cluster *garagev1beta2.GarageCluster) bool {
	if metav1.IsControlledBy(obj, bucket) {
		return true
	}
	if bucket.Namespace == cluster.Namespace {
		return false
	}
	return obj.GetLabels()[labelWebsiteExposureOwner] == string(bucket.UID)
}

// buildIngress constructs the desired Ingress for a website-enabled bucket.
func (r *GarageBucketReconciler) buildIngress(
	bucket *garagev1beta1.GarageBucket,
	cluster *garagev1beta2.GarageCluster,
	exposure *garagev1beta1.WebsiteExposureConfig,
	host string,
) (*networkingv1.Ingress, error) {
	ingressConfig := exposure.Ingress
	if ingressConfig == nil {
		return nil, fmt.Errorf("websiteExposure.ingress is required")
	}
	svcName := websiteExposureBackend(cluster)

	labels := mergeLabels(websiteExposureBaseLabels(bucket, cluster), ingressConfig.Labels)

	pathType := networkingv1.PathTypePrefix
	var tls []networkingv1.IngressTLS
	if exposure.TLSSecretName != "" {
		tls = []networkingv1.IngressTLS{
			{
				Hosts:      []string{host},
				SecretName: exposure.TLSSecretName,
			},
		}
	}
	var className *string
	if ingressConfig.IngressClassName != "" {
		className = &ingressConfig.IngressClassName
	}

	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        websiteExposureResourceName(bucket),
			Namespace:   websiteExposureNamespace(cluster),
			Labels:      labels,
			Annotations: copyStringMap(ingressConfig.Annotations),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: className,
			TLS:              tls,
			Rules: []networkingv1.IngressRule{
				{
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
				},
			},
		},
	}, nil
}

// buildHTTPRoute constructs the desired Gateway API HTTPRoute for a
// website-enabled bucket.
func (r *GarageBucketReconciler) buildHTTPRoute(
	bucket *garagev1beta1.GarageBucket,
	cluster *garagev1beta2.GarageCluster,
	exposure *garagev1beta1.WebsiteExposureConfig,
	host string,
) (*gatewayv1.HTTPRoute, error) {
	gatewayConfig := exposure.Gateway
	if gatewayConfig == nil {
		return nil, fmt.Errorf("websiteExposure.gateway is required")
	}
	svcName := websiteExposureBackend(cluster)

	parentRefs := make([]gatewayv1.ParentReference, 0, len(gatewayConfig.ParentRefs))
	for _, ref := range gatewayConfig.ParentRefs {
		ga := gatewayv1.ParentReference{Name: gatewayv1.ObjectName(ref.Name)}
		if ref.Group != "" {
			group := gatewayv1.Group(ref.Group)
			ga.Group = &group
		}
		if ref.Kind != "" {
			kind := gatewayv1.Kind(ref.Kind)
			ga.Kind = &kind
		}
		if ref.Namespace != "" {
			ns := gatewayv1.Namespace(ref.Namespace)
			ga.Namespace = &ns
		}
		if ref.SectionName != "" {
			section := gatewayv1.SectionName(ref.SectionName)
			ga.SectionName = &section
		}
		parentRefs = append(parentRefs, ga)
	}

	pathPrefix := gatewayv1.PathMatchPathPrefix
	pathValue := "/"
	port := getWebPort(cluster)

	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      websiteExposureResourceName(bucket),
			Namespace: websiteExposureNamespace(cluster),
			Labels:    websiteExposureBaseLabels(bucket, cluster),
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: parentRefs,
			},
			Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(host)},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  &pathPrefix,
								Value: &pathValue,
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName(svcName),
									// The route is created in the cluster's own
									// namespace, so the Service backend is
									// same-namespace and no ReferenceGrant is
									// needed.
									Port: &port,
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

// applyWebsiteExposureResource creates or updates the desired exposure
// resource. The controller owner reference is only set when bucket and
// cluster share a namespace (Kubernetes forbids cross-namespace owner
// references); cross-namespace objects carry the durable
// labelWebsiteExposureOwner UID marker instead. Ownership is enforced by
// exact UID, mirroring reconcileService: a foreign object squatting on the
// generated name is never mutated.
func (r *GarageBucketReconciler) applyWebsiteExposureResource(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	cluster *garagev1beta2.GarageCluster,
	desired client.Object,
) error {
	if bucket.Namespace == cluster.Namespace {
		if err := controllerutil.SetControllerReference(bucket, desired, r.Scheme); err != nil {
			return fmt.Errorf("setting controller reference: %w", err)
		}
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
	if !isWebsiteExposureOwned(existing, bucket, cluster) {
		return fmt.Errorf("refusing to mutate website exposure resource %s/%s because it is not owned by GarageBucket UID %s",
			existing.GetNamespace(), existing.GetName(), bucket.UID)
	}
	// A cross-namespace object created before the UID marker existed (or whose
	// label was stripped) is claimed on update so later reconciles and the
	// cluster-gone deletion path keep recognizing it.
	if bucket.Namespace != cluster.Namespace && existing.GetLabels()[labelWebsiteExposureOwner] == "" {
		if existing.GetLabels() == nil {
			existing.SetLabels(map[string]string{})
		}
		existing.GetLabels()[labelWebsiteExposureOwner] = string(bucket.UID)
	}

	switch d := desired.(type) {
	case *networkingv1.Ingress:
		e := existing.(*networkingv1.Ingress)
		e.OwnerReferences = d.OwnerReferences
		if e.Labels == nil {
			e.Labels = map[string]string{}
		}
		for k, v := range d.Labels {
			e.Labels[k] = v
		}
		e.Spec = d.Spec
		if err := r.Update(ctx, e); err != nil {
			return fmt.Errorf("updating Ingress: %w", err)
		}
		return applyOwnedMetadata(ctx, r.Client, e, d)
	case *gatewayv1.HTTPRoute:
		e := existing.(*gatewayv1.HTTPRoute)
		e.OwnerReferences = d.OwnerReferences
		if e.Labels == nil {
			e.Labels = map[string]string{}
		}
		for k, v := range d.Labels {
			e.Labels[k] = v
		}
		e.Spec = d.Spec
		if err := r.Update(ctx, e); err != nil {
			return fmt.Errorf("updating HTTPRoute: %w", err)
		}
		return applyOwnedMetadata(ctx, r.Client, e, d)
	default:
		return fmt.Errorf("unsupported website exposure resource type %T", desired)
	}
}

// cleanupWebsiteExposureOnDeletion removes the exposure resource when the
// bucket is deleted through a path that does not run the full finalize
// (deletionPolicy: Retain, COSI retain). The cluster namespace is derived
// from spec.clusterRef, so cleanup works even when the cluster object is
// gone or deleting: same-namespace exposures are additionally garbage
// collected via their owner reference, but cross-namespace ones have none.
// A returned error must retain the bucket finalizer and retry — leaving it
// behind would orphan the exposure.
func (r *GarageBucketReconciler) cleanupWebsiteExposureOnDeletion(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	clusterNamespace := bucket.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = bucket.Namespace
	}
	return r.deleteWebsiteExposureResource(ctx, bucket, clusterNamespace)
}

// deleteWebsiteExposureResource removes the exposure resource when
// spec.websiteExposure is unset or the bucket is being deleted. Foreign
// objects are left untouched. When bucket and cluster share a namespace,
// Kubernetes garbage collection also removes the controller-owned resource on
// bucket deletion; this call covers the cross-namespace case, where no owner
// reference can be set (ownership is recognized via the durable UID label),
// and the spec-removal case. namespace is the cluster's namespace (see
// websiteExposureNamespace).
func (r *GarageBucketReconciler) deleteWebsiteExposureResource(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	namespace string,
) error {
	// A bucket that never had a website exposure has nothing to clean up.
	// The status record is the durable marker (the spec field is cleared when
	// the exposure is removed), so both being unset means no resource was
	// ever created and the probe can be skipped.
	if bucket.Spec.WebsiteExposure == nil && bucket.Status.WebsiteExposure == nil {
		return nil
	}

	name := websiteExposureResourceName(bucket)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace},
	}

	ingress := &networkingv1.Ingress{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ingress)
	if err == nil {
		if isWebsiteExposureOwned(ingress, bucket, cluster) {
			logf.FromContext(ctx).Info("Deleting website exposure Ingress", "name", name)
			if err := r.Delete(ctx, ingress); err != nil && !k8errors.IsNotFound(err) {
				return fmt.Errorf("deleting Ingress: %w", err)
			}
		}
	} else if !k8errors.IsNotFound(err) {
		return err
	}

	if r.gatewayAPIAvailable() {
		route := &gatewayv1.HTTPRoute{}
		err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, route)
		if err == nil {
			if isWebsiteExposureOwned(route, bucket, cluster) {
				logf.FromContext(ctx).Info("Deleting website exposure HTTPRoute", "name", name)
				if err := r.Delete(ctx, route); err != nil && !k8errors.IsNotFound(err) {
					return fmt.Errorf("deleting HTTPRoute: %w", err)
				}
			}
		} else if !k8errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// gatewayAPIAvailable probes the REST mapper for the HTTPRoute CRD, the same
// pattern as monitoringCRDExists, so no informer is started when the CRD is
// absent.
func (r *GarageBucketReconciler) gatewayAPIAvailable() bool {
	mapper := r.RESTMapper()
	if mapper == nil {
		return false
	}
	_, err := mapper.RESTMapping(schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"})
	return err == nil
}
