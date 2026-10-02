/*
Copyright 2026.

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

package v1beta2

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

// ConditionPodExtrasValid is the GarageCluster condition reporting whether the
// user-supplied initContainers, extraContainers and extraVolumes pass strict
// validation. False does not change status.phase by itself.
const ConditionPodExtrasValid = "PodExtrasValid"

// Reasons reported for PodExtrasValid and by PodExtrasIssue.
const (
	PodExtrasReasonValid               = "Valid"
	PodExtrasReasonInvalidContainer    = "InvalidContainer"
	PodExtrasReasonReservedName        = "ReservedName"
	PodExtrasReasonUnknownVolume       = "UnknownVolume"
	PodExtrasReasonOperatorVolumeMount = "OperatorVolumeMount"
	PodExtrasReasonManagedClaimReuse   = "ManagedClaimReuse"
	PodExtrasReasonDecodeError         = "DecodeError"
)

const (
	// MaxPodExtrasBytes bounds the serialised size of the three lists in one
	// template. The CRD cannot bound the preserved objects, and the same JSON is
	// copied into the v1beta1 transport annotations.
	MaxPodExtrasBytes = 64 * 1024

	podExtraOperatorContainerPrefix = "garage-operator-"
	podExtraGarageContainerName     = "garage"
	podExtraPurgeContainerName      = "purge-cluster-layout"
	podExtraRPCSecretVolume         = "rpc-secret"
)

var (
	reservedPodExtraVolumeNames = map[string]struct{}{
		"config": {}, "metadata": {}, "data": {},
		podExtraRPCSecretVolume: {}, "admin-token": {}, "metrics-token": {},
	}
	reservedPodExtraDataVolume = regexp.MustCompile(`^data-[0-9]+$`)
)

// IsReservedPodExtraContainerName reports whether name is an operator-owned
// container name. The authoritative collision check runs against the pod the
// builder produced; this static list is the webhook-independent fast guard.
func IsReservedPodExtraContainerName(name string) bool {
	return name == podExtraGarageContainerName || name == podExtraPurgeContainerName ||
		strings.HasPrefix(name, podExtraOperatorContainerPrefix)
}

// IsReservedPodExtraVolumeName reports whether name is an operator-owned volume.
func IsReservedPodExtraVolumeName(name string) bool {
	if _, ok := reservedPodExtraVolumeNames[name]; ok {
		return true
	}
	return reservedPodExtraDataVolume.MatchString(name)
}

// PodExtrasIssue is one validation failure. Reason is one of the
// PodExtrasReason* constants and feeds the PodExtrasValid condition.
// +kubebuilder:object:generate=false
type PodExtrasIssue struct {
	Reason string
	Path   string
	Detail string
}

// Error implements error.
func (i PodExtrasIssue) Error() string {
	return fmt.Sprintf("%s: %s", i.Path, i.Detail)
}

// PodExtrasIssuesError joins issues into one error, or returns nil for none.
func PodExtrasIssuesError(issues []PodExtrasIssue) error {
	if len(issues) == 0 {
		return nil
	}
	errs := make([]error, 0, len(issues))
	for i := range issues {
		errs = append(errs, issues[i])
	}
	return errors.Join(errs...)
}

// PodExtrasInput describes the three lists of one pod template.
// +kubebuilder:object:generate=false
type PodExtrasInput struct {
	// Field is the path of the template, e.g. "spec.storage".
	Field           string
	InitContainers  []PodExtraContainer
	ExtraContainers []PodExtraContainer
	ExtraVolumes    []PodExtraVolume
	// MountableVolumes, when non-nil, replaces ExtraVolumes as the set of
	// volumes the containers may mount. A GarageNode that inherits the tier's
	// volumes while overriding containers uses this.
	MountableVolumes []PodExtraVolume
	// SkipUnknownMountCheck suppresses UnknownVolume reports when the mountable
	// set cannot be known yet (a GarageNode that inherits the tier's volumes is
	// validated again against the cluster). Mounts of operator-owned volumes are
	// still rejected.
	SkipUnknownMountCheck bool
	// ListenerPorts maps Garage listener ports (TCP) to a description, so a
	// container port cannot shadow them in the shared network namespace.
	ListenerPorts map[int32]string
}

// ResolvedPodExtras holds the strictly decoded lists.
// +kubebuilder:object:generate=false
type ResolvedPodExtras struct {
	InitContainers  []corev1.Container
	ExtraContainers []corev1.Container
	ExtraVolumes    []corev1.Volume
}

// IsEmpty reports whether nothing is configured.
func (r ResolvedPodExtras) IsEmpty() bool {
	return len(r.InitContainers) == 0 && len(r.ExtraContainers) == 0 && len(r.ExtraVolumes) == 0
}

// ResolvePodExtras strictly decodes and validates one template's lists. The
// webhook and the controller call it so the two cannot drift. All issues are
// collected; the resolved value is only meaningful when no issue is returned.
func ResolvePodExtras(in PodExtrasInput) (ResolvedPodExtras, []PodExtrasIssue) {
	v := podExtrasValidator{in: in}
	return v.run()
}

type podExtrasValidator struct {
	in     PodExtrasInput
	issues []PodExtrasIssue
}

func (v *podExtrasValidator) add(reason, path, format string, args ...any) {
	v.issues = append(v.issues, PodExtrasIssue{Reason: reason, Path: path, Detail: fmt.Sprintf(format, args...)})
}

func (v *podExtrasValidator) run() (ResolvedPodExtras, []PodExtrasIssue) {
	in := v.in
	var out ResolvedPodExtras
	if len(in.InitContainers) == 0 && len(in.ExtraContainers) == 0 && len(in.ExtraVolumes) == 0 {
		return out, nil
	}
	base := in.Field
	initPath, extraPath, volPath := base+".initContainers", base+".extraContainers", base+".extraVolumes"

	v.checkSize()

	volumes := v.resolveVolumes(volPath)
	out.ExtraVolumes = volumes

	mountable := volumes
	if in.MountableVolumes != nil {
		mountable = nil
		for i := range in.MountableVolumes {
			resolved, err := in.MountableVolumes[i].Resolve()
			if err == nil {
				mountable = append(mountable, resolved)
			}
		}
	}
	volumeNames := make(map[string]struct{}, len(mountable))
	for i := range mountable {
		volumeNames[mountable[i].Name] = struct{}{}
	}

	containerNames := map[string]string{}
	out.InitContainers = v.resolveContainers(initPath, in.InitContainers, true, containerNames, volumeNames)
	out.ExtraContainers = v.resolveContainers(extraPath, in.ExtraContainers, false, containerNames, volumeNames)
	return out, v.issues
}

func (v *podExtrasValidator) checkSize() {
	total := 0
	for _, list := range []any{v.in.InitContainers, v.in.ExtraContainers, v.in.ExtraVolumes} {
		b, err := json.Marshal(list)
		if err != nil {
			continue
		}
		total += len(b)
	}
	if total > MaxPodExtrasBytes {
		v.add(PodExtrasReasonInvalidContainer, v.in.Field,
			"initContainers, extraContainers and extraVolumes serialise to %d bytes; the limit is %d", total, MaxPodExtrasBytes)
	}
}

func (v *podExtrasValidator) resolveVolumes(path string) []corev1.Volume {
	var out []corev1.Volume
	seen := map[string]struct{}{}
	for i := range v.in.ExtraVolumes {
		item := fmt.Sprintf("%s[%d]", path, i)
		name := v.in.ExtraVolumes[i].Name
		resolved, err := v.in.ExtraVolumes[i].Resolve()
		if err != nil {
			v.add(PodExtrasReasonDecodeError, item, "%v", err)
			continue
		}
		out = append(out, resolved)
		if errs := utilvalidation.IsDNS1123Label(name); len(errs) > 0 {
			v.add(PodExtrasReasonInvalidContainer, item+".name", "%q is not a valid DNS-1123 label: %s", name, strings.Join(errs, "; "))
		}
		if IsReservedPodExtraVolumeName(name) {
			v.add(PodExtrasReasonReservedName, item+".name", "volume name %q is operator-reserved", name)
		}
		if _, dup := seen[name]; dup {
			v.add(PodExtrasReasonInvalidContainer, item+".name", "duplicate volume name %q", name)
		}
		seen[name] = struct{}{}
		if n := countVolumeSources(resolved.VolumeSource); n != 1 {
			v.add(PodExtrasReasonInvalidContainer, item, "volume %q must set exactly one volume source, found %d", name, n)
		}
	}
	return out
}

func countVolumeSources(src corev1.VolumeSource) int {
	n := 0
	rv := reflect.ValueOf(src)
	for i := 0; i < rv.NumField(); i++ {
		if !rv.Field(i).IsNil() {
			n++
		}
	}
	return n
}

func (v *podExtrasValidator) resolveContainers(
	path string, in []PodExtraContainer, initList bool, names map[string]string, volumes map[string]struct{},
) []corev1.Container {
	var out []corev1.Container
	for i := range in {
		item := fmt.Sprintf("%s[%d]", path, i)
		name := in[i].Name
		c, err := in[i].Resolve()
		if err != nil {
			v.add(PodExtrasReasonDecodeError, item, "%v", err)
			continue
		}
		out = append(out, c)
		if errs := utilvalidation.IsDNS1123Label(name); len(errs) > 0 {
			v.add(PodExtrasReasonInvalidContainer, item+".name", "%q is not a valid DNS-1123 label: %s", name, strings.Join(errs, "; "))
		}
		if IsReservedPodExtraContainerName(name) {
			v.add(PodExtrasReasonReservedName, item+".name",
				"container name %q is operator-reserved (garage, purge-cluster-layout and the garage-operator- prefix)", name)
		}
		if prev, dup := names[name]; dup {
			v.add(PodExtrasReasonInvalidContainer, item+".name",
				"container name %q is already used by %s; names must be unique across initContainers and extraContainers", name, prev)
		}
		names[name] = item
		v.checkContainerShape(item, initList, &c)
		v.checkMounts(item, &c, volumes)
	}
	return out
}

func (v *podExtrasValidator) checkContainerShape(item string, initList bool, c *corev1.Container) {
	if strings.TrimSpace(c.Image) == "" {
		v.add(PodExtrasReasonInvalidContainer, item+".image", "image is required")
	}
	switch {
	case initList && c.RestartPolicy != nil && *c.RestartPolicy != corev1.ContainerRestartPolicyAlways:
		v.add(PodExtrasReasonInvalidContainer, item+".restartPolicy",
			"must be unset or %q for an init container", corev1.ContainerRestartPolicyAlways)
	case !initList && c.RestartPolicy != nil:
		v.add(PodExtrasReasonInvalidContainer, item+".restartPolicy",
			"must not be set on extraContainers; Kubernetes only accepts it on init containers")
	}
	if len(c.VolumeDevices) > 0 {
		v.add(PodExtrasReasonInvalidContainer, item+".volumeDevices", "block devices are not supported")
	}
	for j := range c.Ports {
		p := c.Ports[j]
		pp := fmt.Sprintf("%s.ports[%d]", item, j)
		if p.HostPort != 0 {
			v.add(PodExtrasReasonInvalidContainer, pp+".hostPort", "hostPort is not supported")
		}
		if p.ContainerPort < 1 || p.ContainerPort > 65535 {
			v.add(PodExtrasReasonInvalidContainer, pp+".containerPort", "must be between 1 and 65535")
			continue
		}
		if p.Protocol == "" || p.Protocol == corev1.ProtocolTCP {
			if what, clash := v.in.ListenerPorts[p.ContainerPort]; clash {
				v.add(PodExtrasReasonInvalidContainer, pp+".containerPort",
					"%d collides with the Garage %s listener; all containers share one network namespace", p.ContainerPort, what)
			}
		}
	}
}

func (v *podExtrasValidator) checkMounts(item string, c *corev1.Container, volumes map[string]struct{}) {
	for j := range c.VolumeMounts {
		name := c.VolumeMounts[j].Name
		mp := fmt.Sprintf("%s.volumeMounts[%d].name", item, j)
		if _, ok := volumes[name]; ok {
			continue
		}
		if IsReservedPodExtraVolumeName(name) {
			msg := fmt.Sprintf("volume %q is operator-owned and cannot be mounted by extras", name)
			if name == "metadata" || name == "data" {
				msg += "; the metadata volume holds the node's private key (node_key)"
			}
			v.add(PodExtrasReasonOperatorVolumeMount, mp, "%s", msg)
			continue
		}
		if v.in.SkipUnknownMountCheck {
			continue
		}
		v.add(PodExtrasReasonUnknownVolume, mp, "volume %q is not declared in extraVolumes", name)
	}
}

// GarageListenerPorts returns the TCP listener ports Garage binds for this
// cluster (RPC, S3, admin, and the optional K2V and web ports), keyed by port.
// Invalid bind configuration is skipped; other validators report it.
func (r *GarageCluster) GarageListenerPorts() map[int32]string {
	ports := map[int32]string{}
	add := func(address string, configured, def int32, what string) {
		port, err := garageconfig.ManagedBindPort(address, configured, def, what)
		if err == nil {
			ports[port] = what
		}
	}
	add(r.Spec.Network.RPCBindAddress, r.Spec.Network.RPCBindPort, 3901, "RPC")
	if r.Spec.S3API == nil {
		ports[3900] = "S3 API"
	} else {
		add(r.Spec.S3API.BindAddress, r.Spec.S3API.BindPort, 3900, "S3 API")
	}
	if r.Spec.Admin == nil {
		ports[3903] = "admin API"
	} else {
		add(r.Spec.Admin.BindAddress, r.Spec.Admin.BindPort, 3903, "admin API")
	}
	if r.Spec.K2VAPI != nil {
		add(r.Spec.K2VAPI.BindAddress, r.Spec.K2VAPI.BindPort, 3904, "K2V API")
	}
	switch {
	case r.Spec.WebAPI == nil:
		ports[3902] = "web"
	case r.Spec.WebAPI.Enabled == nil || *r.Spec.WebAPI.Enabled:
		add(r.Spec.WebAPI.BindAddress, r.Spec.WebAPI.BindPort, 3902, "web")
	}
	return ports
}

// PodTemplateForNode returns the tier template a GarageNode inherits: the
// gateway tier for a gateway node when declared, the storage tier otherwise,
// with single-tier fallbacks. It returns nil when neither tier is declared.
func (r *GarageCluster) PodTemplateForNode(gateway bool) *PodTemplate {
	switch {
	case gateway && r.HasGatewayTier():
		return &r.Spec.Gateway.PodTemplate
	case !gateway && r.HasStorageTier():
		return &r.Spec.Storage.PodTemplate
	case r.HasStorageTier():
		return &r.Spec.Storage.PodTemplate
	case r.HasGatewayTier():
		return &r.Spec.Gateway.PodTemplate
	}
	return nil
}

// SortedPodExtrasReasons is a test helper-friendly summary of distinct reasons.
func SortedPodExtrasReasons(issues []PodExtrasIssue) []string {
	set := map[string]struct{}{}
	for i := range issues {
		set[issues[i].Reason] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
