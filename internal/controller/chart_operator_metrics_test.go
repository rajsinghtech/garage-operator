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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// operatorMetricCollectors lists every collector the operator registers. The
// source scan in TestChartReferencesOnlyExportedOperatorMetrics keeps it
// complete.
func operatorMetricCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		bucketQuotaSizeBytes, bucketQuotaSizeLimitBytes, bucketQuotaSizeUtilizationRatio,
		bucketQuotaObjectCount, bucketQuotaObjectLimit, bucketQuotaObjectUtilizationRatio,
		replicationLastSuccessTimestamp, replicationLastFailed, replicationLastBytes, replicationHeld,
		layoutWriteBlockedTotal, layoutSiteRoleGauge,
	}
}

var (
	descFQName           = regexp.MustCompile(`fqName: "([^"]+)"`)
	chartOperatorMetric  = regexp.MustCompile(`\bgarage_operator_[a-z0-9_]+`)
	operatorMetricCtorRe = regexp.MustCompile(`prometheus\.New(Gauge|Counter|Histogram|Summary)(Vec)?\(`)
)

// The chart's PrometheusRule and dashboard query garage_operator_* series by
// name. A renamed or removed operator metric still leaves valid PromQL behind:
// the alert silently never fires. Pin every referenced name to a collector.
func TestChartReferencesOnlyExportedOperatorMetrics(t *testing.T) {
	root := repositoryRoot(t)

	ctors := 0
	sources, err := filepath.Glob(filepath.Join(root, "internal", "*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob(filepath.Join(root, "cmd", "*.go"))
	for _, path := range append(sources, more...) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ctors += len(operatorMetricCtorRe.FindAll(raw, -1))
	}
	collectors := operatorMetricCollectors()
	if ctors != len(collectors) {
		t.Fatalf("found %d prometheus.New* constructors in operator sources but operatorMetricCollectors lists %d; add the new collector", ctors, len(collectors))
	}

	exported := map[string]bool{}
	for _, c := range collectors {
		ch := make(chan *prometheus.Desc, 4)
		go func() { c.Describe(ch); close(ch) }()
		for d := range ch {
			m := descFQName.FindStringSubmatch(d.String())
			if m == nil {
				t.Fatalf("cannot read fqName from %s", d.String())
			}
			exported[m[1]] = true
		}
	}

	chart := filepath.Join(root, "charts", "garage-operator")
	files := []string{filepath.Join(chart, "templates", "prometheusrules.yaml")}
	dashboards, err := filepath.Glob(filepath.Join(chart, "dashboards", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, dashboards...)
	referenced := 0
	var missing []string
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range chartOperatorMetric.FindAllString(string(raw), -1) {
			referenced++
			if !exported[name] {
				missing = append(missing, filepath.Base(path)+": "+name)
			}
		}
	}
	if referenced == 0 {
		t.Fatal("chart references no garage_operator_* metrics; the scan is broken")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("chart references operator metrics the operator does not export: %v", missing)
	}
}
