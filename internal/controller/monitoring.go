package controller

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	adminPortName   = "admin"
	s3PortName      = "s3"
	k2vPortName     = "k2v"
	webPortName     = "web"
	metricsPath     = "/metrics"
	metricsTokenKey = "metrics-token"
	labelCluster    = "garage.rajsingh.info/cluster"
)

// reconcileMonitoring creates or deletes the ServiceMonitor for the cluster's admin port.
// Silently skips if the monitoring.coreos.com CRD is not installed.
func (r *GarageClusterReconciler) reconcileMonitoring(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	monitoring := cluster.Spec.Monitoring
	name := cluster.Name + "-garage"
	namespace := cluster.Namespace

	if !r.monitoringCRDExists() {
		if monitoring != nil && monitoring.Enabled != nil && *monitoring.Enabled {
			log.Info("spec.monitoring.enabled=true but monitoring.coreos.com CRDs not found; skipping ServiceMonitor")
		}
		return nil
	}

	if monitoring == nil || monitoring.Enabled == nil || !*monitoring.Enabled {
		// Use APIReader (non-cached) so we don't start a cache informer for ServiceMonitor
		// when monitoring is disabled. This avoids log spam when RBAC is missing.
		sm := &monitoringv1.ServiceMonitor{}
		err := r.APIReader.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sm)
		if err == nil {
			if !metav1.IsControlledBy(sm, cluster) {
				log.Info("Leaving foreign same-name ServiceMonitor untouched", "name", name)
				return nil
			}
			return r.Delete(ctx, sm)
		}
		if errors.IsForbidden(err) {
			return nil
		}
		return client.IgnoreNotFound(err)
	}

	sm := &monitoringv1.ServiceMonitor{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sm)

	desired := r.buildServiceMonitor(cluster, name, namespace)
	if token, ready, tokenErr := getReadyOperatorMetricsToken(ctx, r.Client, cluster); tokenErr != nil {
		return tokenErr
	} else if ready && token != "" && len(desired.Spec.Endpoints) > 0 {
		desired.Spec.Endpoints[0].Authorization = &monitoringv1.SafeAuthorization{
			Type: "Bearer",
			Credentials: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: operatorMetricsTokenSecretName(cluster)},
				Key:                  metricsTokenKey,
			},
		}
	}
	if errors.IsNotFound(err) {
		log.Info("creating ServiceMonitor", "name", name)
		return r.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("get ServiceMonitor: %w", err)
	}
	if !metav1.IsControlledBy(sm, cluster) {
		return fmt.Errorf("refusing to mutate ServiceMonitor %s/%s because it is not controlled by GarageCluster UID %s", sm.Namespace, sm.Name, cluster.UID)
	}
	if desiredSnapshot := currentStaticCredentialsSecretName(cluster); desiredSnapshot != "" &&
		len(desired.Spec.Endpoints) > 0 && desired.Spec.Endpoints[0].Authorization != nil &&
		desired.Spec.Endpoints[0].Authorization.Credentials != nil &&
		desired.Spec.Endpoints[0].Authorization.Credentials.Name == desiredSnapshot &&
		len(sm.Spec.Endpoints) > 0 && sm.Spec.Endpoints[0].Authorization != nil &&
		sm.Spec.Endpoints[0].Authorization.Credentials != nil &&
		sm.Spec.Endpoints[0].Authorization.Credentials.Name != desiredSnapshot {
		allCurrent, err := r.allMetricsTargetsUseStaticCredentialSnapshot(ctx, cluster, desiredSnapshot)
		if err != nil {
			return err
		}
		if !allCurrent {
			// Garage reads metrics_api_token only at process start. Preserve the
			// previous scrape bearer until every selectable Pod has moved to the
			// new immutable startup revision.
			desired.Spec.Endpoints[0].Authorization = sm.Spec.Endpoints[0].Authorization.DeepCopy()
		}
	}

	metadataChanged := mergeOwnedMetadata(sm, desired)
	if !metadataChanged && equality.Semantic.DeepEqual(sm.Spec, desired.Spec) {
		return nil
	}
	sm.Spec = desired.Spec
	return r.Update(ctx, sm)
}

func (r *GarageClusterReconciler) allMetricsTargetsUseStaticCredentialSnapshot(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	snapshotName string,
) (bool, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return false, fmt.Errorf("listing metrics target Pods before credential handoff: %w", err)
	}
	found := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !pod.DeletionTimestamp.IsZero() {
			continue
		}
		found = true
		matched := false
		for j := range pod.Spec.Containers {
			if pod.Spec.Containers[j].Name != defaultAppName {
				continue
			}
			for k := range pod.Spec.Containers[j].Env {
				env := &pod.Spec.Containers[j].Env[k]
				if env.Name == envGarageMetricsToken && env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil &&
					env.ValueFrom.SecretKeyRef.Name == snapshotName {
					matched = true
				}
			}
		}
		if !matched {
			return false, nil
		}
	}
	return found, nil
}

func (r *GarageClusterReconciler) buildServiceMonitor(cluster *garagev1beta2.GarageCluster, name, namespace string) *monitoringv1.ServiceMonitor {
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
	if len(monitoring.MetricRelabelings) > 0 {
		endpoint.MetricRelabelConfigs = monitoring.MetricRelabelings
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsTokenSecretRef != nil {
		ref := cluster.Spec.Admin.MetricsTokenSecretRef
		secretName := ref.Name
		key := ref.Key
		if snapshot := currentStaticCredentialsSecretName(cluster); snapshot != "" {
			secretName = snapshot
			key = metricsTokenKey
		} else if key == "" {
			key = metricsTokenKey
		}
		endpoint.Authorization = &monitoringv1.SafeAuthorization{
			Type: "Bearer",
			Credentials: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
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
			// jobLabel tells Prometheus to use the value of app.kubernetes.io/name
			// from the scraped Service as the job label — produces job="garage",
			// which matches the official Garage Grafana dashboard queries.
			JobLabel: labelAppName,
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      labelCluster,
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

// monitoringCRDExists checks whether the monitoring.coreos.com ServiceMonitor CRD is installed
// using REST mapper discovery. This avoids starting a cache informer (which would require RBAC).
func (r *GarageClusterReconciler) monitoringCRDExists() bool {
	_, err := r.RESTMapper().RESTMapping(
		schema.GroupKind{Group: "monitoring.coreos.com", Kind: "ServiceMonitor"},
	)
	return err == nil
}
