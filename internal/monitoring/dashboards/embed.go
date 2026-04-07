package dashboards

import _ "embed"

// GaragePrometheus is the official Garage Grafana dashboard for Prometheus metrics.
//
//go:embed garage-prometheus.json
var GaragePrometheus []byte
