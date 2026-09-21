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
	"math"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestUpdateBucketQuotaMetrics(t *testing.T) {
	const (
		namespace = "metrics-test"
		name      = "quota-bucket"
	)

	deleteBucketQuotaMetrics(namespace, name)
	t.Cleanup(func() { deleteBucketQuotaMetrics(namespace, name) })

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: garagev1beta1.GarageBucketStatus{
			QuotaUsage: &garagev1beta1.QuotaUsageStatus{
				SizeBytes:   250,
				SizeLimit:   1000,
				ObjectCount: 4,
				ObjectLimit: 10,
			},
		},
	}
	updateBucketQuotaMetrics(bucket)

	assertGaugeValue(t, bucketQuotaSizeBytes.WithLabelValues(namespace, name), 250)
	assertGaugeValue(t, bucketQuotaSizeLimitBytes.WithLabelValues(namespace, name), 1000)
	assertGaugeValue(t, bucketQuotaSizeUtilizationRatio.WithLabelValues(namespace, name), 0.25)
	assertGaugeValue(t, bucketQuotaObjectCount.WithLabelValues(namespace, name), 4)
	assertGaugeValue(t, bucketQuotaObjectLimit.WithLabelValues(namespace, name), 10)
	assertGaugeValue(t, bucketQuotaObjectUtilizationRatio.WithLabelValues(namespace, name), 0.4)

	// Repeated observations update the existing series rather than creating a
	// second series for the same bucket.
	updateBucketQuotaMetrics(bucket)
	assertGaugeValue(t, bucketQuotaSizeBytes.WithLabelValues(namespace, name), 250)
	assertGaugeValue(t, bucketQuotaObjectCount.WithLabelValues(namespace, name), 4)

	bucket.Status.QuotaUsage.SizeBytes = 750
	bucket.Status.QuotaUsage.ObjectCount = 8
	updateBucketQuotaMetrics(bucket)
	assertGaugeValue(t, bucketQuotaSizeBytes.WithLabelValues(namespace, name), 750)
	assertGaugeValue(t, bucketQuotaSizeUtilizationRatio.WithLabelValues(namespace, name), 0.75)
	assertGaugeValue(t, bucketQuotaObjectCount.WithLabelValues(namespace, name), 8)
	assertGaugeValue(t, bucketQuotaObjectUtilizationRatio.WithLabelValues(namespace, name), 0.8)
}

func TestBucketQuotaMetricNames(t *testing.T) {
	const (
		namespace = "metrics-test"
		name      = "metric-name-bucket"
	)
	t.Cleanup(func() { deleteBucketQuotaMetrics(namespace, name) })

	tests := []struct {
		metric *prometheus.GaugeVec
		name   string
	}{
		{bucketQuotaSizeBytes, "garage_operator_bucket_size_bytes"},
		{bucketQuotaSizeLimitBytes, "garage_operator_bucket_size_limit_bytes"},
		{bucketQuotaSizeUtilizationRatio, "garage_operator_bucket_quota_size_utilization_ratio"},
		{bucketQuotaObjectCount, "garage_operator_bucket_objects"},
		{bucketQuotaObjectLimit, "garage_operator_bucket_object_limit"},
		{bucketQuotaObjectUtilizationRatio, "garage_operator_bucket_quota_object_utilization_ratio"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMetricName(t, tt.metric, namespace, name, tt.name)
		})
	}
}

func TestUpdateBucketQuotaMetricsUnlimitedAndCleared(t *testing.T) {
	const (
		namespace = "metrics-test"
		name      = "unlimited-bucket"
	)

	deleteBucketQuotaMetrics(namespace, name)
	t.Cleanup(func() { deleteBucketQuotaMetrics(namespace, name) })

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: garagev1beta1.GarageBucketStatus{
			QuotaUsage: &garagev1beta1.QuotaUsageStatus{
				SizeBytes:   250,
				ObjectCount: 4,
			},
		},
	}
	updateBucketQuotaMetrics(bucket)

	assertGaugeValue(t, bucketQuotaSizeBytes.WithLabelValues(namespace, name), 250)
	assertGaugeValue(t, bucketQuotaSizeLimitBytes.WithLabelValues(namespace, name), 0)
	assertGaugeAbsent(t, bucketQuotaSizeUtilizationRatio)
	assertGaugeValue(t, bucketQuotaObjectCount.WithLabelValues(namespace, name), 4)
	assertGaugeValue(t, bucketQuotaObjectLimit.WithLabelValues(namespace, name), 0)
	assertGaugeAbsent(t, bucketQuotaObjectUtilizationRatio)

	// Changing a bucket from limited to unlimited must remove the old ratio
	// label set instead of leaving a stale alertable series behind.
	bucket.Status.QuotaUsage.SizeLimit = 1000
	bucket.Status.QuotaUsage.ObjectLimit = 10
	updateBucketQuotaMetrics(bucket)
	assertGaugeValue(t, bucketQuotaSizeUtilizationRatio.WithLabelValues(namespace, name), 0.25)
	assertGaugeValue(t, bucketQuotaObjectUtilizationRatio.WithLabelValues(namespace, name), 0.4)
	bucket.Status.QuotaUsage.SizeLimit = 0
	bucket.Status.QuotaUsage.ObjectLimit = 0
	updateBucketQuotaMetrics(bucket)
	assertGaugeAbsent(t, bucketQuotaSizeUtilizationRatio)
	assertGaugeAbsent(t, bucketQuotaObjectUtilizationRatio)

	bucket.Status.QuotaUsage = nil
	updateBucketQuotaMetrics(bucket)
	for _, metric := range []*prometheus.GaugeVec{
		bucketQuotaSizeBytes,
		bucketQuotaSizeLimitBytes,
		bucketQuotaSizeUtilizationRatio,
		bucketQuotaObjectCount,
		bucketQuotaObjectLimit,
		bucketQuotaObjectUtilizationRatio,
	} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("stale bucket quota series remains: %v", err)
		}
	}
}

func TestUpdateStatusFromGaragePublishesBucketQuotaMetrics(t *testing.T) {
	const (
		namespace = "metrics-test"
		name      = "status-bucket"
		bucketID  = "0123456789abcdef0123456789abcdef"
	)

	deleteBucketQuotaMetrics(namespace, name)
	t.Cleanup(func() { deleteBucketQuotaMetrics(namespace, name) })

	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: bucketID},
	}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).
		Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}

	maxSize := uint64(1000)
	maxObjects := uint64(10)
	snapshot := &garage.Bucket{
		ID:      bucketID,
		Bytes:   250,
		Objects: 4,
		Quotas: &garage.BucketQuotas{
			MaxSize:    &maxSize,
			MaxObjects: &maxObjects,
		},
	}
	if _, err := reconciler.updateStatusFromGarage(
		context.Background(), bucket, nil, &garagev1beta2.GarageCluster{}, snapshot,
	); err != nil {
		t.Fatal(err)
	}

	assertGaugeValue(t, bucketQuotaSizeBytes.WithLabelValues(namespace, name), 250)
	assertGaugeValue(t, bucketQuotaSizeLimitBytes.WithLabelValues(namespace, name), 1000)
	assertGaugeValue(t, bucketQuotaSizeUtilizationRatio.WithLabelValues(namespace, name), 0.25)
	assertGaugeValue(t, bucketQuotaObjectCount.WithLabelValues(namespace, name), 4)
	assertGaugeValue(t, bucketQuotaObjectLimit.WithLabelValues(namespace, name), 10)
	assertGaugeValue(t, bucketQuotaObjectUtilizationRatio.WithLabelValues(namespace, name), 0.4)
}

func TestGarageBucketReconcileRemovesMetricsForDeletedBucket(t *testing.T) {
	const (
		namespace = "metrics-test"
		name      = "deleted-bucket"
	)

	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: garagev1beta1.GarageBucketStatus{
			QuotaUsage: &garagev1beta1.QuotaUsageStatus{SizeBytes: 100, ObjectCount: 2},
		},
	}
	updateBucketQuotaMetrics(bucket)
	t.Cleanup(func() { deleteBucketQuotaMetrics(namespace, name) })

	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
	}); err != nil {
		t.Fatal(err)
	}
	for _, metric := range []*prometheus.GaugeVec{
		bucketQuotaSizeBytes,
		bucketQuotaSizeLimitBytes,
		bucketQuotaSizeUtilizationRatio,
		bucketQuotaObjectCount,
		bucketQuotaObjectLimit,
		bucketQuotaObjectUtilizationRatio,
	} {
		if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
			t.Errorf("deleted bucket quota series remains: %v", err)
		}
	}
}

func assertGaugeValue(t *testing.T, gauge prometheus.Gauge, want float64) {
	t.Helper()
	if got := testutil.ToFloat64(gauge); math.Abs(got-want) > 1e-12 {
		t.Errorf("gauge value=%v, want %v", got, want)
	}
}

func assertGaugeAbsent(t *testing.T, metric *prometheus.GaugeVec) {
	t.Helper()
	if err := testutil.CollectAndCompare(metric, strings.NewReader("")); err != nil {
		t.Errorf("unexpected gauge series: %v", err)
	}
}

func assertMetricName(t *testing.T, metric *prometheus.GaugeVec, namespace, bucket, want string) {
	t.Helper()
	metric.WithLabelValues(namespace, bucket).Set(0)
	if desc := metric.WithLabelValues(namespace, bucket).Desc().String(); !strings.Contains(desc, `fqName: "`+want+`"`) {
		t.Errorf("metric descriptor=%q, want fqName %q", desc, want)
	}
}
