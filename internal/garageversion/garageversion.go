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

// Package garageversion parses Garage release versions from image references
// and from the version string Garage reports through its Admin API, and encodes
// the few version facts the webhooks and the controller must agree on.
//
// Parsing is deliberately strict: only plain "vMAJOR.MINOR.PATCH" (the "v" is
// optional) is recognised. Anything else (a floating tag such as "latest", a
// digest-only reference, or a build suffix such as "v2.4.0-5-gabcdef") is
// reported as unknown rather than guessed at, so callers can only act on
// versions they actually know.
package garageversion

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a Garage release version.
type Version struct {
	Major, Minor, Patch int
}

// String renders the version in Garage's own "vMAJOR.MINOR.PATCH" form.
func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Garage releases the operator has to reason about.
var (
	// release230 panics at start with Consul discovery (upstream #1416). It
	// links the same two rustls crypto providers as v2.4.0 and never installs
	// one, so Kubernetes discovery is treated as affected too; upstream reports
	// that case only against v2.4.0 (#1532, #1536).
	release230 = Version{2, 3, 0}
	// release240 panics at start with Consul or Kubernetes discovery.
	release240 = Version{2, 4, 0}
	// release241 installs the rustls crypto provider and is the first v2.4 release
	// that is safe with discovery.
	release241 = Version{2, 4, 1}
)

// Parse parses "v2.4.1" or "2.4.1". It returns false for anything else,
// including pre-release or build suffixes.
func Parse(s string) (Version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var nums [3]int
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return Version{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || part[0] == '+' || part[0] == '-' {
			return Version{}, false
		}
		nums[i] = n
	}
	return Version{nums[0], nums[1], nums[2]}, true
}

// FromImage extracts the version from an image reference's tag
// ("repo/garage:v2.4.0" or "repo/garage:v2.4.0@sha256:..."). A digest does not
// change the result: when both a tag and a digest are present the digest is
// authoritative at pull time, but the tag is the only version signal available
// without contacting the registry. A reference with no tag, including a
// digest-only reference, reports false.
func FromImage(image string) (Version, bool) {
	ref := strings.TrimSpace(image)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return Version{}, false
	}
	return Parse(ref[i+1:])
}

// DiscoveryPanicsAtStart reports whether this Garage release is known to panic
// at start when any peer discovery (Consul or Kubernetes) is configured:
// v2.3.0 and v2.4.0 build rustls with two crypto providers and never install
// one; v2.4.1 installs ring explicitly.
func (v Version) DiscoveryPanicsAtStart() bool {
	return v == release230 || v == release240
}

// DiscoveryImageWarning returns the admission warning for a GarageCluster
// whose spec.image resolves to a Garage release that panics with the enabled
// discovery mechanisms, or "" when there is nothing to warn about. The image
// is judged by its tag only, so digest-only and floating references return ""
// and are covered at runtime by the DiscoveryCompatible condition.
func DiscoveryImageWarning(image string, consul, kubernetes bool) string {
	if !consul && !kubernetes {
		return ""
	}
	v, ok := FromImage(image)
	if !ok || !v.DiscoveryPanicsAtStart() {
		return ""
	}
	return fmt.Sprintf("spec.image is Garage %s, which panics at start when peer discovery is enabled "+
		"(%s): upgrade to %s or newer, or disable the discovery section "+
		"(upstream issues #1416, #1526, #1532, #1536)",
		v, enabledDiscoveryNames(consul, kubernetes), release241)
}

func enabledDiscoveryNames(consul, kubernetes bool) string {
	switch {
	case consul && kubernetes:
		return "spec.discovery.consul and spec.discovery.kubernetes are enabled"
	case consul:
		return "spec.discovery.consul is enabled"
	default:
		return "spec.discovery.kubernetes is enabled"
	}
}

// DiscoveryRuntimeMessage describes why a running cluster is affected, given
// the offending versions Garage reported (sorted, de-duplicated by the caller).
func DiscoveryRuntimeMessage(affected []Version) string {
	names := make([]string, len(affected))
	for i, v := range affected {
		names[i] = v.String()
	}
	return fmt.Sprintf("peer discovery is enabled but Garage %s is running; this release panics at start "+
		"when Consul or Kubernetes discovery is configured, so pods restarted with the discovery configuration will crash-loop. "+
		"Set spec.image to %s or newer (or disable spec.discovery) before the next restart",
		strings.Join(names, ", "), release241)
}

// release250 is the first Garage release that accepts s3_api.public_endpoint,
// s3_api.public_endpoint_path_style, and k2v_api.public_endpoint (src/util/config.rs).
var release250 = Version{2, 5, 0}

// release260 is the first Garage release whose official images embed the web
// admin UI (Cargo feature "webadmin", upstream #1562).
var release260 = Version{2, 6, 0}

// AtLeast reports whether v is the same release as other or newer.
func (v Version) AtLeast(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch >= other.Patch
}

// WebUIImageWarning returns the admission warning for a GarageCluster that
// sets spec.admin.webUI while spec.image is tagged with a Garage release older
// than v2.6.0, which does not serve the web admin UI. The exposure is still
// created; digest-only and untagged references return "" and are covered at
// runtime by the WebUIAvailable condition.
func WebUIImageWarning(image string) string {
	v, ok := FromImage(image)
	if !ok || v.AtLeast(release260) {
		return ""
	}
	return fmt.Sprintf("spec.admin.webUI is set but spec.image is Garage %s; the web admin UI is served only by "+
		"Garage %s and newer, so the exposed host will not serve /ui/ until the image is upgraded", v, release260)
}

// PublicEndpointSupported reports whether image is a known Garage release that
// accepts s3_api.public_endpoint, s3_api.public_endpoint_path_style, and
// k2v_api.public_endpoint (v2.5.0+). ok is false for untagged, digest-only, or
// otherwise unparseable references; callers must decide how to treat those.
func PublicEndpointSupported(image string) (supported, ok bool) {
	v, ok := FromImage(image)
	if !ok {
		return false, false
	}
	return v.AtLeast(release250), true
}

// PublicEndpointImageWarning returns the admission warning when any of the
// v2.5+ public-endpoint fields are set on a cluster whose spec.image is tagged
// older than v2.5.0. Digest-only and untagged references return "" so they are
// not guessed at.
func PublicEndpointImageWarning(image string, fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	supported, ok := PublicEndpointSupported(image)
	if !ok || supported {
		return ""
	}
	v, _ := FromImage(image)
	listed := strings.Join(fields, ", ")
	if len(fields) == 1 {
		return fmt.Sprintf("%s is set but spec.image is Garage %s; this key exists only in Garage %s and newer, so it will not be written to garage.toml until the image is upgraded",
			listed, v, release250)
	}
	return fmt.Sprintf("%s are set but spec.image is Garage %s; these keys exist only in Garage %s and newer, so they will not be written to garage.toml until the image is upgraded",
		listed, v, release250)
}

// Garage major versions this operator supports. Garage v2 introduced the /v2
// Admin API the operator speaks; Garage v3 changes it incompatibly (for
// example GetBucketInfo.websiteAccess becomes an object), renames metrics,
// moves to a new fjall on-disk format and replaces the RPC handshake, so v2
// and v3 nodes cannot talk to each other during a rolling upgrade.
const (
	minSupportedMajor = 2
	maxSupportedMajor = 2
)

// MajorFromImage extracts only the major version from an image tag. Unlike
// FromImage it accepts pre-release and build suffixes ("v3.0.0-beta1",
// "v3", "3.1"), because the major version alone decides API compatibility.
// Untagged and digest-only references, and tags that do not start with a
// number (after an optional "v"), report false.
func MajorFromImage(image string) (int, bool) {
	ref := strings.TrimSpace(image)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return 0, false
	}
	tag := strings.TrimPrefix(ref[i+1:], "v")
	end := 0
	for end < len(tag) && tag[end] >= '0' && tag[end] <= '9' {
		end++
	}
	if end == 0 || (end < len(tag) && tag[end] != '.' && tag[end] != '-' && tag[end] != '+') {
		return 0, false
	}
	major, err := strconv.Atoi(tag[:end])
	if err != nil {
		return 0, false
	}
	return major, true
}

// UnsupportedMajorImageWarning returns an admission warning when image is
// tagged with a Garage major version outside the supported range. The image
// is still accepted: the tag is only a hint, and refusing it would block
// specs that merely mention a custom build. Untagged and digest-only
// references return "".
func UnsupportedMajorImageWarning(field, image string) string {
	major, ok := MajorFromImage(image)
	if !ok || (major >= minSupportedMajor && major <= maxSupportedMajor) {
		return ""
	}
	if major > maxSupportedMajor {
		return fmt.Sprintf("%s is tagged as Garage v%d, which this operator does not support yet: Garage v%d changes the Admin API, metric names, "+
			"the fjall on-disk format and the RPC handshake, so bucket and key reconciliation fail and a rolling upgrade from v%d splits the cluster. "+
			"Stay on a Garage v%d release", field, major, major, maxSupportedMajor, maxSupportedMajor)
	}
	return fmt.Sprintf("%s is tagged as Garage v%d; this operator requires Garage v%d (the /v2 Admin API) and cannot manage older releases", field, major, minSupportedMajor)
}
