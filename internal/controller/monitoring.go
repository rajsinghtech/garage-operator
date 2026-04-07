package controller

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	adminPortName = "admin"
	metricsPath   = "/metrics"
)

// reconcileMonitoring creates or deletes the ServiceMonitor for the cluster's admin port.
// Silently skips if the monitoring.coreos.com CRD is not installed.
func (r *GarageClusterReconciler) reconcileMonitoring(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)

	monitoring := cluster.Spec.Monitoring
	name := cluster.Name + "-garage"
	namespace := cluster.Namespace

	if !r.monitoringCRDExists(ctx) {
		if monitoring != nil && monitoring.Enabled {
			log.Info("spec.monitoring.enabled=true but monitoring.coreos.com CRDs not found; skipping ServiceMonitor")
		}
		return nil
	}

	sm := &monitoringv1.ServiceMonitor{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sm)

	if monitoring == nil || !monitoring.Enabled {
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

	sm.Labels = desired.Labels
	sm.Spec = desired.Spec
	return r.Update(ctx, sm)
}

func (r *GarageClusterReconciler) buildServiceMonitor(cluster *garagev1alpha1.GarageCluster, name, namespace string) *monitoringv1.ServiceMonitor {
	monitoring := cluster.Spec.Monitoring

	labels := r.labelsForCluster(cluster)
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

	// Selector covers both Auto-mode pods (app.kubernetes.io/name=garage) and
	// Manual-mode GarageNode pods (garage.rajsingh.info/cluster=<name>), which
	// use app.kubernetes.io/name=garagenode and won't match the name label alone.
	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "garage.rajsingh.info/cluster",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{cluster.Name},
					},
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

// monitoringCRDExists checks whether the monitoring.coreos.com ServiceMonitor CRD is installed.
func (r *GarageClusterReconciler) monitoringCRDExists(ctx context.Context) bool {
	list := &monitoringv1.ServiceMonitorList{}
	err := r.List(ctx, list, &client.ListOptions{Limit: 1})
	if err == nil {
		return true
	}
	if apimeta.IsNoMatchError(err) || errors.IsNotFound(err) {
		return false
	}
	return true
}
