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
	replicationMetricSubsystem = "replication"
	replicationMetricNameLabel = "replication"
)

// Replication metrics are gauges derived from status, so a reconcile can
// recompute them any number of times without double counting.
var (
	replicationMetricLabels = []string{bucketQuotaMetricNamespaceLabel, bucketQuotaMetricResourceNamespaceLabel, replicationMetricNameLabel, "source_bucket", "destination_bucket"}

	replicationLastSuccessTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: replicationMetricSubsystem,
			Name:      "last_success_timestamp_seconds",
			Help:      "Completion time of the last successful replication Job of a bucket; alert when it is older than about two schedule intervals.",
		},
		replicationMetricLabels,
	)
	replicationLastFailed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: replicationMetricSubsystem,
			Name:      "last_failed",
			Help:      "1 when the last replication Job of a bucket failed, else 0.",
		},
		replicationMetricLabels,
	)
	replicationLastBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: replicationMetricSubsystem,
			Name:      "last_transferred_bytes",
			Help:      "Bytes written to the destination by the last replication Job of a bucket, as reported by rclone.",
		},
		replicationMetricLabels,
	)
	replicationHeld = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: bucketQuotaMetricNamespace,
			Subsystem: replicationMetricSubsystem,
			Name:      "held",
			Help:      "1 when a bucket is held (SourceEmpty, MaxDeletesExceeded, AwaitingTrigger) and waits for the trigger-sync annotation.",
		},
		replicationMetricLabels,
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(replicationLastSuccessTimestamp, replicationLastFailed, replicationLastBytes, replicationHeld)
}

func updateReplicationMetrics(repl *garagev1beta1.GarageReplication) {
	deleteReplicationMetrics(repl.Namespace, repl.Name)
	for _, b := range repl.Status.Buckets {
		labels := prometheus.Labels{
			bucketQuotaMetricNamespaceLabel:         repl.Namespace,
			bucketQuotaMetricResourceNamespaceLabel: repl.Namespace,
			replicationMetricNameLabel:              repl.Name,
			"source_bucket":                         b.Source,
			"destination_bucket":                    b.Destination,
		}
		if b.LastSuccessfulTime != nil {
			replicationLastSuccessTimestamp.With(labels).Set(float64(b.LastSuccessfulTime.Unix()))
		}
		if b.LastResult != "" {
			failed := 0.0
			if b.LastResult == garagev1beta1.ReplicationResultFailed {
				failed = 1
			}
			replicationLastFailed.With(labels).Set(failed)
		}
		if b.LastStatistics != nil {
			replicationLastBytes.With(labels).Set(float64(b.LastStatistics.Bytes))
		}
		held := 0.0
		if b.Hold != "" {
			held = 1
		}
		replicationHeld.With(labels).Set(held)
	}
}

func deleteReplicationMetrics(namespace, name string) {
	match := prometheus.Labels{bucketQuotaMetricNamespaceLabel: namespace, replicationMetricNameLabel: name}
	replicationLastSuccessTimestamp.DeletePartialMatch(match)
	replicationLastFailed.DeletePartialMatch(match)
	replicationLastBytes.DeletePartialMatch(match)
	replicationHeld.DeletePartialMatch(match)
}
