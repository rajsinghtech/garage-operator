//go:build garagecontract

package contract

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// The chart's PrometheusRule and Grafana dashboard query Garage metrics by
// name and label. Garage does not document its metric names as a stable
// contract, and an expression that names a metric Garage never exports (or
// a label it never sets) is still valid PromQL: promtool passes, the alert
// simply never fires. Pin every Garage metric the chart references to the
// real binary.

const (
	chartDir         = "../../charts/garage-operator"
	chartRulesFile   = chartDir + "/templates/prometheusrules.yaml"
	chartDashboardsG = chartDir + "/dashboards/*.json"
)

// Labels the chart's rules or dashboard group or join by, per metric.
var requiredMetricLabels = map[string][]string{
	"garage_local_disk_avail":       {"volume"},
	"garage_local_disk_total":       {"volume"},
	"cluster_layout_node_connected": {"id"},
	"api_s3_request_counter":        {"api_endpoint"},
	"api_s3_error_counter":          {"api_endpoint", "status_code"},
	"rpc_request_counter":           {"rpc_endpoint"},
}

func TestContract_ChartMonitoringMetricsExist(t *testing.T) {
	bin := garageBin(t)
	nd := readyNode(t)
	generateMetricsTraffic(t, nd)

	exprs := chartMonitoringExprs(t)
	names := map[string]bool{}
	for _, e := range exprs {
		for _, n := range promqlMetricNames(e) {
			names[n] = true
		}
	}
	if len(names) < 20 {
		t.Fatalf("extracted only %d metric names from %d chart expressions; the extractor is broken", len(names), len(exprs))
	}

	binary, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	var scraped map[string][]map[string]string
	eventually(t, 30*time.Second, "Garage /metrics to export the S3 API counters", func() (bool, string) {
		scraped = scrapeMetrics(t, nd.adminAddr)
		_, ok := scraped["api_s3_request_counter"]
		return ok, fmt.Sprintf("%d families", len(scraped))
	})

	var missing, fromBinary []string
	for name := range names {
		if name == "up" || strings.HasPrefix(name, "garage_operator_") {
			continue
		}
		if _, ok := scraped[name]; ok {
			continue
		}
		// Counters only appear after their first increment (rpc timeouts,
		// web errors). Fall back to the instrument name compiled into the
		// binary: Garage registers "rpc.timeout_counter", exported with the
		// dot mapped to an underscore.
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
		dotted := strings.Replace(base, "_", ".", 1)
		if bytes.Contains(binary, []byte(dotted)) || bytes.Contains(binary, []byte(base)) {
			fromBinary = append(fromBinary, name)
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	sort.Strings(fromBinary)
	t.Logf("%d Garage metric names referenced by the chart; not yet exported, found in the binary: %v", len(names), fromBinary)
	if len(missing) > 0 {
		t.Fatalf("chart PrometheusRule/dashboard reference Garage metrics this Garage does not export: %v", missing)
	}

	for metric, labels := range requiredMetricLabels {
		if !names[metric] {
			t.Errorf("requiredMetricLabels lists %s but the chart no longer references it; update the test", metric)
			continue
		}
		series, ok := scraped[metric]
		if !ok {
			t.Errorf("%s not exported after traffic", metric)
			continue
		}
		for _, l := range labels {
			found := false
			for _, s := range series {
				if _, ok := s[l]; ok {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s has no %q label (series: %v)", metric, l, series)
			}
		}
	}
}

// generateMetricsTraffic exercises the S3 API (success and error), the block
// store (an object above the inline threshold) and the admin API so the lazily
// registered counters and histograms are exported.
func generateMetricsTraffic(t *testing.T, nd *node) {
	t.Helper()
	ctx := context.Background()
	c := nd.client
	b, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-metrics"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateKey(ctx, "contract-metrics")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{BucketID: b.ID, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}}); err != nil {
		t.Fatal(err)
	}
	full, err := c.GetKey(ctx, garage.GetKeyRequest{ID: k.AccessKeyID, ShowSecretKey: true})
	if err != nil {
		t.Fatal(err)
	}
	s3PutObject(t, nd.s3Addr, full.AccessKeyID, full.SecretAccessKey, "contract-metrics", "big", bytes.Repeat([]byte("g"), 256<<10))
	// An unsigned request is rejected: api_s3_error_counter.
	resp, err := http.Get("http://" + nd.s3Addr + "/contract-metrics/big")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if _, err := c.ListBuckets(ctx); err != nil {
		t.Fatal(err)
	}
}

// scrapeMetrics returns sample name -> label sets from Garage's admin /metrics.
func scrapeMetrics(t *testing.T, adminAddr string) map[string][]map[string]string {
	t.Helper()
	resp, err := http.Get("http://" + adminAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: %s", resp.Status)
	}
	out := map[string][]map[string]string{}
	labelRe := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		end := strings.IndexAny(line, "{ ")
		if end <= 0 {
			continue
		}
		name := line[:end]
		labels := map[string]string{}
		if line[end] == '{' {
			if close := strings.LastIndex(line, "}"); close > end {
				for _, m := range labelRe.FindAllStringSubmatch(line[end+1:close], -1) {
					labels[m[1]] = m[2]
				}
			}
		}
		out[name] = append(out[name], labels)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// chartMonitoringExprs returns every PromQL expression in the chart's
// PrometheusRule template and Grafana dashboards.
func chartMonitoringExprs(t *testing.T) []string {
	t.Helper()
	var exprs []string
	raw, err := os.ReadFile(chartRulesFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "expr:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "expr:"))
		if rest != "|" && rest != ">" && rest != "|-" {
			exprs = append(exprs, rest)
			continue
		}
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		var block []string
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) != "" && len(l)-len(strings.TrimLeft(l, " ")) <= indent {
				break
			}
			block = append(block, strings.TrimSpace(l))
			i = j
		}
		exprs = append(exprs, strings.Join(block, " "))
	}
	if len(exprs) == 0 {
		t.Fatalf("no expr: entries found in %s", chartRulesFile)
	}

	dashboards, err := filepath.Glob(chartDashboardsG)
	if err != nil || len(dashboards) == 0 {
		t.Fatalf("no dashboards matched %s: %v", chartDashboardsG, err)
	}
	for _, path := range dashboards {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s is not valid JSON: %v", path, err)
		}
		var walk func(any)
		walk = func(v any) {
			switch v := v.(type) {
			case map[string]any:
				if e, ok := v["expr"].(string); ok && e != "" {
					exprs = append(exprs, e)
				}
				for _, c := range v {
					walk(c)
				}
			case []any:
				for _, c := range v {
					walk(c)
				}
			}
		}
		walk(doc)
	}
	return exprs
}

var (
	promqlNameMatcher = regexp.MustCompile(`__name__\s*=~?\s*"([^"]*)"`)
	promqlStrings     = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	promqlBraces      = regexp.MustCompile(`\{[^{}]*\}`)
	promqlRanges      = regexp.MustCompile(`\[[^\]]*\]`)
	promqlGrouping    = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)`)
	promqlIdent       = regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*`)
	promqlKeywords    = map[string]bool{
		"and": true, "or": true, "unless": true, "by": true, "without": true, "on": true,
		"ignoring": true, "group_left": true, "group_right": true, "bool": true, "offset": true,
		"inf": true, "nan": true,
	}
)

// promqlMetricNames extracts the metric names an expression selects. It is a
// lexical approximation that suits the chart's expressions: names inside
// {__name__=~"a|b"} matchers, and bare identifiers that are not function
// calls, keywords, label names or Grafana variables.
func promqlMetricNames(expr string) []string {
	var names []string
	for _, m := range promqlNameMatcher.FindAllStringSubmatch(expr, -1) {
		names = append(names, strings.Split(m[1], "|")...)
	}
	s := strings.ReplaceAll(expr, "{{", "")
	s = promqlStrings.ReplaceAllString(s, `""`)
	for promqlBraces.MatchString(s) {
		s = promqlBraces.ReplaceAllString(s, " ")
	}
	s = promqlRanges.ReplaceAllString(s, " ")
	s = promqlGrouping.ReplaceAllString(s, " ")
	for _, loc := range promqlIdent.FindAllStringIndex(s, -1) {
		word := s[loc[0]:loc[1]]
		if promqlKeywords[strings.ToLower(word)] {
			continue
		}
		if loc[0] > 0 && s[loc[0]-1] == '$' {
			continue
		}
		rest := strings.TrimLeft(s[loc[1]:], " \t\n")
		if strings.HasPrefix(rest, "(") {
			continue // function call
		}
		names = append(names, word)
	}
	return names
}
