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
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

const (
	bucketQuotaMetricNamespaceLabel = "namespace"
	bucketQuotaMetricBucketLabel    = "bucket"
	bucketQuotaMetricNamespace      = "garage_operator"
	bucketQuotaMetricSubsystem      = "bucket"
)

var (
	bucketQuotaSizeBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "size_bytes",
			Help:      "Current size of a Garage bucket in bytes.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
	)
	bucketQuotaSizeLimitBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "size_limit_bytes",
			Help:      "Configured size limit of a Garage bucket in bytes; zero means unlimited.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
	)
	bucketQuotaSizeUtilizationRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "quota_size_utilization_ratio",
			Help:      "Current Garage bucket size divided by its configured size limit; omitted when the limit is zero or less.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
	)
	bucketQuotaObjectCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "objects",
			Help:      "Current object count in a Garage bucket.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
	)
	bucketQuotaObjectLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "object_limit",
			Help:      "Configured object limit of a Garage bucket; zero means unlimited.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
	)
	bucketQuotaObjectUtilizationRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: bucketQuotaMetricSubsystem,
			Name:      "quota_object_utilization_ratio",
			Help:      "Current Garage bucket object count divided by its configured object limit; omitted when the limit is zero or less.",
		},
		[]string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricBucketLabel},
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

	labels := prometheus.Labels{
		bucketQuotaMetricNamespaceLabel: bucket.Namespace,
		bucketQuotaMetricBucketLabel:    bucket.Name,
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
		bucketQuotaSizeUtilizationRatio.DeleteLabelValues(bucket.Namespace, bucket.Name)
	}
	bucketQuotaObjectCount.With(labels).Set(float64(usage.ObjectCount))
	bucketQuotaObjectLimit.With(labels).Set(float64(usage.ObjectLimit))
	if usage.ObjectLimit > 0 {
		bucketQuotaObjectUtilizationRatio.With(labels).Set(quotaUtilizationRatio(usage.ObjectCount, usage.ObjectLimit))
	} else {
		bucketQuotaObjectUtilizationRatio.DeleteLabelValues(bucket.Namespace, bucket.Name)
	}
}

func deleteBucketQuotaMetrics(namespace, name string) {
	labels := []string{namespace, name}
	bucketQuotaSizeBytes.DeleteLabelValues(labels...)
	bucketQuotaSizeLimitBytes.DeleteLabelValues(labels...)
	bucketQuotaSizeUtilizationRatio.DeleteLabelValues(labels...)
	bucketQuotaObjectCount.DeleteLabelValues(labels...)
	bucketQuotaObjectLimit.DeleteLabelValues(labels...)
	bucketQuotaObjectUtilizationRatio.DeleteLabelValues(labels...)
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
