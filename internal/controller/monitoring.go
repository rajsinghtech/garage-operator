package controller

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/monitoring/dashboards"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	defaultGrafanaDashboardLabel      = "grafana_dashboard"
	defaultGrafanaDashboardLabelValue = "1"
	adminPortName                     = "admin"
	metricsPath                       = "/metrics"
)

// reconcileMonitoring creates/updates or deletes the ServiceMonitor and Grafana dashboard
// ConfigMap based on the cluster's monitoring spec.
func (r *GarageClusterReconciler) reconcileMonitoring(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	if err := r.reconcileServiceMonitor(ctx, cluster); err != nil {
		return err
	}
	return r.reconcileGrafanaDashboard(ctx, cluster)
}

// reconcileServiceMonitor creates or deletes a ServiceMonitor for the cluster's admin port.
// It silently skips creation if the monitoring.coreos.com CRD is not installed.
func (r *GarageClusterReconciler) reconcileServiceMonitor(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)

	monitoring := cluster.Spec.Monitoring
	name := cluster.Name + "-garage"
	namespace := cluster.Namespace

	// Check if the ServiceMonitor CRD is installed
	if !r.monitoringCRDExists(ctx) {
		if monitoring != nil && monitoring.Enabled {
			log.Info("spec.monitoring.enabled=true but monitoring.coreos.com CRDs not found; skipping ServiceMonitor")
		}
		return nil
	}

	sm := &monitoringv1.ServiceMonitor{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sm)

	if monitoring == nil || !monitoring.Enabled {
		// Delete if it exists
		if err == nil {
			return r.Delete(ctx, sm)
		}
		return client.IgnoreNotFound(err)
	}

	desired := r.buildServiceMonitor(cluster, name, namespace)
	if errors.IsNotFound(err) {
		log.Info("creating ServiceMonitor", "name", name)
		return r.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("get ServiceMonitor: %w", err)
	}

	// Update endpoint and labels
	sm.Labels = desired.Labels
	sm.Spec = desired.Spec
	return r.Update(ctx, sm)
}

func (r *GarageClusterReconciler) buildServiceMonitor(cluster *garagev1alpha1.GarageCluster, name, namespace string) *monitoringv1.ServiceMonitor {
	monitoring := cluster.Spec.Monitoring

	labels := map[string]string{
		"app.kubernetes.io/name":       "garage",
		"app.kubernetes.io/instance":   cluster.Name,
		"app.kubernetes.io/managed-by": "garage-operator",
	}
	for k, v := range monitoring.AdditionalLabels {
		labels[k] = v
	}

	endpoint := monitoringv1.Endpoint{
		Port: adminPortName,
		Path: metricsPath,
	}
	if monitoring.Interval != "" {
		endpoint.Interval = monitoringv1.Duration(monitoring.Interval)
	}
	// Wire metrics token secret if configured
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsTokenSecretRef != nil {
		ref := cluster.Spec.Admin.MetricsTokenSecretRef
		key := ref.Key
		if key == "" {
			key = "metrics-token"
		}
		endpoint.Authorization = &monitoringv1.SafeAuthorization{
			Type: "Bearer",
			Credentials: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name},
				Key:                  key,
			},
		}
	}

	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     "garage",
					"app.kubernetes.io/instance": cluster.Name,
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{namespace},
			},
			Endpoints: []monitoringv1.Endpoint{endpoint},
		},
	}
	_ = controllerutil.SetControllerReference(cluster, sm, r.Scheme)
	return sm
}

// reconcileGrafanaDashboard creates or deletes a ConfigMap with the Garage dashboard JSON.
func (r *GarageClusterReconciler) reconcileGrafanaDashboard(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)

	monitoring := cluster.Spec.Monitoring
	name := cluster.Name + "-garage-dashboard"

	dashboardEnabled := monitoring != nil && monitoring.GrafanaDashboard != nil && monitoring.GrafanaDashboard.Enabled
	dashboardNamespace := cluster.Namespace
	if dashboardEnabled && monitoring.GrafanaDashboard.Namespace != "" {
		dashboardNamespace = monitoring.GrafanaDashboard.Namespace
	}

	cm := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: dashboardNamespace}, cm)

	if !dashboardEnabled {
		if err == nil {
			return r.Delete(ctx, cm)
		}
		return client.IgnoreNotFound(err)
	}

	desired := r.buildDashboardConfigMap(cluster, name, dashboardNamespace)
	if errors.IsNotFound(err) {
		log.Info("creating Grafana dashboard ConfigMap", "name", name, "namespace", dashboardNamespace)
		return r.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("get dashboard ConfigMap: %w", err)
	}

	cm.Labels = desired.Labels
	cm.Data = desired.Data
	return r.Update(ctx, cm)
}

func (r *GarageClusterReconciler) buildDashboardConfigMap(cluster *garagev1alpha1.GarageCluster, name, namespace string) *corev1.ConfigMap {
	spec := cluster.Spec.Monitoring.GrafanaDashboard

	labels := map[string]string{
		defaultGrafanaDashboardLabel: defaultGrafanaDashboardLabelValue,
	}
	for k, v := range spec.Labels {
		labels[k] = v
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"garage-prometheus.json": string(dashboards.GaragePrometheus),
		},
	}
	// Only set owner ref if dashboard is in the same namespace as the cluster
	if namespace == cluster.Namespace {
		_ = controllerutil.SetControllerReference(cluster, cm, r.Scheme)
	}
	return cm
}

// monitoringCRDExists checks whether the monitoring.coreos.com ServiceMonitor CRD is installed.
func (r *GarageClusterReconciler) monitoringCRDExists(ctx context.Context) bool {
	list := &monitoringv1.ServiceMonitorList{}
	err := r.List(ctx, list, &client.ListOptions{Limit: 1})
	if err == nil {
		return true
	}
	// If the error is "no kind is registered" or "resource not found", CRD isn't installed
	if isNoKindRegistered(err) || errors.IsNotFound(err) {
		return false
	}
	// For other errors (e.g. permission denied), assume CRD exists but we lack access
	return true
}

// isNoKindRegistered returns true if the error indicates an unregistered API group/resource.
func isNoKindRegistered(err error) bool {
	if err == nil {
		return false
	}
	return errors.IsNotFound(err) || errors.ReasonForError(err) == metav1.StatusReasonNotFound
}
