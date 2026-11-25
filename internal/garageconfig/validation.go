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

// Package garageconfig contains validation shared by the served API versions
// and by the workload renderer. Keeping these rules in one place prevents an
// admitted Garage listener from disagreeing with its Kubernetes Service.
package garageconfig

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	systemdDurationPattern = regexp.MustCompile(`^(?:\d+(?:\.\d+)?\s*(?:ns|us|ms|s|m|h|d|w|M|y)\s*)+$`)
	systemdDurationPart    = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(ns|us|ms|s|m|h|d|w|M|y)\s*`)
)

// ManagedBindPort validates an operator-managed Garage listener and returns
// its effective TCP port. Garage accepts more listener forms for some APIs,
// but Kubernetes Services and direct Pod probes require a wildcard TCP socket.
func ManagedBindPort(address string, configuredPort, defaultPort int32, field string) (int32, error) {
	if address == "" {
		if configuredPort != 0 {
			return configuredPort, nil
		}
		return defaultPort, nil
	}
	if strings.TrimSpace(address) != address {
		return 0, fmt.Errorf("%s: surrounding whitespace is not allowed", field)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("%s: managed workloads require a wildcard TCP address such as '0.0.0.0:%d' or '[::]:%d'", field, defaultPort, defaultPort)
	}
	if host == "" {
		return 0, fmt.Errorf("%s: an explicit wildcard IP is required; use 0.0.0.0 or [::]", field)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsUnspecified() {
		return 0, fmt.Errorf("%s: host %q is not a wildcard address; managed Services and direct Pod probes require 0.0.0.0 or [::]", field, host)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%s: port %q must be between 1 and 65535", field, portText)
	}
	return int32(port), nil
}

// ListenerPort names one enabled Garage listener and its effective TCP port.
type ListenerPort struct {
	Field string
	Port  int32
}

// ValidateDistinctListenerPorts rejects enabled Garage APIs that would bind
// the same TCP port on the shared wildcard interface.
func ValidateDistinctListenerPorts(listeners []ListenerPort) error {
	seen := make(map[int32]string, len(listeners))
	for _, listener := range listeners {
		if previous, exists := seen[listener.Port]; exists {
			return fmt.Errorf("%s effective TCP port %d conflicts with %s; every enabled Garage listener must use a distinct port", listener.Field, listener.Port, previous)
		}
		seen[listener.Port] = listener.Field
	}
	return nil
}

// ValidateCompressionLevel accepts Garage's special disabled value and every
// zstd integer level supported by upstream Garage.
func ValidateCompressionLevel(value, field string) error {
	if value == "none" {
		return nil
	}
	level, err := strconv.Atoi(value)
	if err != nil || level < -99 || level > 22 {
		return fmt.Errorf("%s must be 'none' or an integer between -99 and 22", field)
	}
	return nil
}

// ValidateRPCDuration rejects values which Garage's millisecond renderer would
// turn into zero and values which cannot deserialize into Garage's u64 fields.
func ValidateRPCDuration(value time.Duration, field string) error {
	if value < time.Millisecond {
		return fmt.Errorf("%s must be at least 1ms", field)
	}
	return nil
}

// ValidateMetadataSnapshotInterval validates the fundu-systemd-compatible
// syntax exposed by the CRD and Garage's upstream minimum of 600 seconds.
func ValidateMetadataSnapshotInterval(value, field string) error {
	if value == "" {
		return nil
	}
	if !systemdDurationPattern.MatchString(value) {
		return fmt.Errorf("%s must be a Garage duration such as '10m', '1h', or '1h 30m'", field)
	}
	seconds := 0.0
	for _, match := range systemdDurationPart.FindAllStringSubmatch(value, -1) {
		amount, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return fmt.Errorf("%s contains an invalid duration component %q", field, match[0])
		}
		seconds += amount * durationUnitSeconds(match[2])
	}
	if seconds < 600 {
		return fmt.Errorf("%s must be at least 600 seconds (10m)", field)
	}
	return nil
}

func durationUnitSeconds(unit string) float64 {
	switch unit {
	case "ns":
		return 1e-9
	case "us":
		return 1e-6
	case "ms":
		return 1e-3
	case "s":
		return 1
	case "m":
		return 60
	case "h":
		return 60 * 60
	case "d":
		return 24 * 60 * 60
	case "w":
		return 7 * 24 * 60 * 60
	case "M":
		return 30.44 * 24 * 60 * 60
	case "y":
		return 365.25 * 24 * 60 * 60
	default:
		return 0
	}
}

// ValidateAdminAPIEndpoint validates endpoints consumed by the Garage Admin
// client. Paths are allowed for reverse-proxy deployments; URL parameters are
// rejected because client request paths cannot preserve them safely.
func ValidateAdminAPIEndpoint(value, field string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute http:// or https:// URL with a host", field)
	}
	if portText := u.Port(); portText != "" {
		port, portErr := strconv.ParseUint(portText, 10, 16)
		if portErr != nil || port == 0 {
			return fmt.Errorf("%s port %q must be between 1 and 65535", field, portText)
		}
	}
	if u.User != nil {
		return fmt.Errorf("%s must not include URL user information", field)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must not include a query string or fragment", field)
	}
	return nil
}

const (
	// DefaultDatabaseEngine is the metadata DB engine Garage and the operator use
	// when spec.database.engine is omitted.
	DefaultDatabaseEngine = "lmdb"
	// AnnotationDatabaseEngineConverted authorizes changing spec.database.engine
	// after create when set to the target engine name (e.g. "fjall", "sqlite").
	AnnotationDatabaseEngineConverted = "garage.rajsingh.info/database-engine-converted"
)

// EffectiveDatabaseEngine returns the active metadata DB engine name for a
// GarageCluster spec.database.engine value (empty defaults to "lmdb").
func EffectiveDatabaseEngine(engine string) string {
	trimmed := strings.TrimSpace(engine)
	if trimmed == "" {
		return DefaultDatabaseEngine
	}
	return trimmed
}

// ValidateDatabaseEngineUpdate rejects post-create changes to spec.database.engine
// unless the target engine is explicitly acknowledged via AnnotationDatabaseEngineConverted.
func ValidateDatabaseEngineUpdate(oldEngineRaw, newEngineRaw string, annotations map[string]string) (string, error) {
	oldEngine := EffectiveDatabaseEngine(oldEngineRaw)
	newEngine := EffectiveDatabaseEngine(newEngineRaw)
	if oldEngine == newEngine {
		return "", nil
	}
	ack := strings.TrimSpace(annotations[AnnotationDatabaseEngineConverted])
	if ack != newEngine {
		return "", fmt.Errorf(
			"spec.database.engine cannot change from %q to %q after create: Garage opens a separate metadata database file per engine (db.%s vs db.%s), so switching engines opens an empty metadata database and causes metadata loss unless every node's metadata DB has been converted offline (garage convert-db). After offline conversion, set annotation %s=%q to allow this update",
			oldEngine, newEngine, oldEngine, newEngine, AnnotationDatabaseEngineConverted, newEngine,
		)
	}
	return fmt.Sprintf(
		"spec.database.engine is changing from %q to %q as acknowledged by %s=%q; ensure offline database conversion (garage convert-db) is complete before pods restart and remove the annotation afterward",
		oldEngine, newEngine, AnnotationDatabaseEngineConverted, newEngine,
	), nil
}
