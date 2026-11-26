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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

const (
	// namespace is kept so existing queries and honorLabels=true scrapes
	// still work. Prometheus rewrites a "namespace" label to
	// exported_namespace when honorLabels is false (the chart default),
	// which would collide two buckets of the same name in different
	// namespaces and make the chart's quota alerts join on the operator
	// namespace. resource_namespace is the label the chart uses instead.
	bucketQuotaMetricNamespaceLabel         = "namespace"
	bucketQuotaMetricResourceNamespaceLabel = "resource_namespace"
	bucketQuotaMetricBucketLabel            = "bucket"
	bucketQuotaMetricNamespace              = "garage_operator"
	bucketQuotaMetricSubsystem              = "bucket"

	// cluster is "<namespace>/<name>" of the referenced GarageCluster, the
	// same format as the layout metrics, so dashboards can select the buckets
	// of one cluster.
	bucketQuotaMetricClusterLabel = "cluster"
)

var bucketQuotaMetricLabels = []string{
	bucketQuotaMetricNamespaceLabel,
	bucketQuotaMetricResourceNamespaceLabel,
	bucketQuotaMetricBucketLabel,
	bucketQuotaMetricClusterLabel,
}

// bucketQuotaClusters remembers the cluster label each bucket's series were
// last published with, so a changed clusterRef does not leave stale series.
// spec.clusterRef.name is immutable, but clusterRef.namespace may still go
// from unset (the bucket's namespace) to an explicit, different namespace.
var bucketQuotaClusters sync.Map // types.NamespacedName -> string

var (
	bucketQuotaSizeBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "size_bytes",
			Help:      "Current size of a Garage bucket in bytes.",
		},
		bucketQuotaMetricLabels,
	)
	bucketQuotaSizeLimitBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "size_limit_bytes",
			Help:      "Configured size limit of a Garage bucket in bytes; zero means unlimited.",
		},
		bucketQuotaMetricLabels,
	)
	bucketQuotaSizeUtilizationRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "quota_size_utilization_ratio",
			Help:      "Current Garage bucket size divided by its configured size limit; omitted when the limit is zero or less.",
		},
		bucketQuotaMetricLabels,
	)
	bucketQuotaObjectCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "objects",
			Help:      "Current object count in a Garage bucket.",
		},
		bucketQuotaMetricLabels,
	)
	bucketQuotaObjectLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "object_limit",
			Help:      "Configured object limit of a Garage bucket; zero means unlimited.",
		},
		bucketQuotaMetricLabels,
	)
	bucketQuotaObjectUtilizationRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "quota_object_utilization_ratio",
			Help:      "Current Garage bucket object count divided by its configured object limit; omitted when the limit is zero or less.",
		},
		bucketQuotaMetricLabels,
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		bucketQuotaSizeBytes,
		bucketQuotaSizeLimitBytes,
		bucketQuotaSizeUtilizationRatio,
		bucketQuotaObjectCount,
		bucketQuotaObjectLimit,
		bucketQuotaObjectUtilizationRatio,
	)
}

func updateBucketQuotaMetrics(bucket *garagev1beta1.GarageBucket) {
	if bucket == nil || bucket.Status.QuotaUsage == nil {
		if bucket != nil {
			deleteBucketQuotaMetrics(bucket.Namespace, bucket.Name)
		}
		return
	}

	cluster := bucketQuotaClusterLabel(bucket)
	key := types.NamespacedName{Namespace: bucket.Namespace, Name: bucket.Name}
	if previous, ok := bucketQuotaClusters.Load(key); ok && previous.(string) != cluster {
		deleteBucketQuotaMetrics(bucket.Namespace, bucket.Name)
	}
	bucketQuotaClusters.Store(key, cluster)

	labels := prometheus.Labels{
		bucketQuotaMetricNamespaceLabel:         bucket.Namespace,
		bucketQuotaMetricResourceNamespaceLabel: bucket.Namespace,
		bucketQuotaMetricBucketLabel:            bucket.Name,
		bucketQuotaMetricClusterLabel:           cluster,
	}
	usage := bucket.Status.QuotaUsage

	// Keep these metrics as float ratios over the raw Garage observations. The
	// status percentages are truncated int32 values and are only populated when
	// Garage returns a non-nil quota pointer, while these metrics expose a zero
	// limit and omit utilization when that limit is not positive.
	bucketQuotaSizeBytes.With(labels).Set(float64(usage.SizeBytes))
	bucketQuotaSizeLimitBytes.With(labels).Set(float64(usage.SizeLimit))
	if usage.SizeLimit > 0 {
		bucketQuotaSizeUtilizationRatio.With(labels).Set(quotaUtilizationRatio(usage.SizeBytes, usage.SizeLimit))
	} else {
		bucketQuotaSizeUtilizationRatio.Delete(labels)
	}
	bucketQuotaObjectCount.With(labels).Set(float64(usage.ObjectCount))
	bucketQuotaObjectLimit.With(labels).Set(float64(usage.ObjectLimit))
	if usage.ObjectLimit > 0 {
		bucketQuotaObjectUtilizationRatio.With(labels).Set(quotaUtilizationRatio(usage.ObjectCount, usage.ObjectLimit))
	} else {
		bucketQuotaObjectUtilizationRatio.Delete(labels)
	}
}

// bucketQuotaClusterLabel returns "<namespace>/<name>" of the GarageCluster
// the bucket references. An unset clusterRef.namespace means the bucket's own
// namespace.
func bucketQuotaClusterLabel(bucket *garagev1beta1.GarageBucket) string {
	namespace := bucket.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = bucket.Namespace
	}
	return namespace + "/" + bucket.Spec.ClusterRef.Name
}

// deleteBucketQuotaMetrics removes every series of one bucket. It matches on
// the bucket's namespace and name only, so callers that no longer have the
// GarageBucket (deletion) do not need to know its cluster label.
func deleteBucketQuotaMetrics(namespace, name string) {
	match := prometheus.Labels{
		bucketQuotaMetricResourceNamespaceLabel: namespace,
		bucketQuotaMetricBucketLabel:            name,
	}
	bucketQuotaSizeBytes.DeletePartialMatch(match)
	bucketQuotaSizeLimitBytes.DeletePartialMatch(match)
	bucketQuotaSizeUtilizationRatio.DeletePartialMatch(match)
	bucketQuotaObjectCount.DeletePartialMatch(match)
	bucketQuotaObjectLimit.DeletePartialMatch(match)
	bucketQuotaObjectUtilizationRatio.DeletePartialMatch(match)
	bucketQuotaClusters.Delete(types.NamespacedName{Namespace: namespace, Name: name})
}

func quotaUtilizationRatio(usage, limit int64) float64 {
	// Callers only emit this ratio for positive limits. Keep the guard as a
	// defensive fallback for any future caller so an unlimited bucket cannot
	// produce an infinite sample.
	if limit <= 0 {
		return 0
	}
	return float64(usage) / float64(limit)
}
