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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8sjson "sigs.k8s.io/json"
)

// PodExtraContainer is one user-supplied container. The CRD schema declares
// only name and preserves all other fields; the complete object is validated
// by the admission webhook and re-validated by the controller by strictly
// decoding it into a corev1.Container (Resolve). This keeps the CRD small:
// a fully typed corev1.Container would add ~120 KB per occurrence.
//
// +kubebuilder:pruning:PreserveUnknownFields
// +kubebuilder:object:generate=false
type PodExtraContainer struct {
	// Name of the container. It must be unique across initContainers and
	// extraContainers, a DNS-1123 label, and not an operator-reserved name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	Name string `json:"name"`

	raw json.RawMessage `json:"-"` // the complete JSON object as submitted; never part of the schema
}

// PodExtraVolume is one user-supplied pod volume; same contract as
// PodExtraContainer, resolved as a corev1.Volume.
//
// +kubebuilder:pruning:PreserveUnknownFields
// +kubebuilder:object:generate=false
type PodExtraVolume struct {
	// Name of the volume. It must be unique across extraVolumes, a DNS-1123
	// label, and not an operator-reserved volume name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	Name string `json:"name"`

	raw json.RawMessage `json:"-"`
}

// NewPodExtraContainer wraps a typed container. It panics only if the
// container cannot be marshalled, which corev1.Container never does.
func NewPodExtraContainer(c corev1.Container) PodExtraContainer {
	raw, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Sprintf("marshal corev1.Container: %v", err))
	}
	return PodExtraContainer{Name: c.Name, raw: raw}
}

// NewPodExtraVolume wraps a typed volume.
func NewPodExtraVolume(v corev1.Volume) PodExtraVolume {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal corev1.Volume: %v", err))
	}
	return PodExtraVolume{Name: v.Name, raw: raw}
}

// MarshalJSON returns the complete object as submitted, or only the name when
// the value was built without a payload.
func (c PodExtraContainer) MarshalJSON() ([]byte, error) {
	return marshalPodExtra(c.Name, c.raw)
}

// UnmarshalJSON is intentionally lenient: it keeps the raw object and extracts
// the name. A strict decode would let one malformed object stall list/watch for
// every GarageCluster, so strictness is applied by Resolve instead.
func (c *PodExtraContainer) UnmarshalJSON(b []byte) error {
	c.Name, c.raw = unmarshalPodExtra(b)
	return nil
}

// Resolve strictly decodes the object into a corev1.Container. Unknown or
// duplicate fields are errors, joined into the returned error.
func (c PodExtraContainer) Resolve() (corev1.Container, error) {
	var out corev1.Container
	if err := resolvePodExtra(c.raw, &out); err != nil {
		return corev1.Container{}, err
	}
	return out, nil
}

// DeepCopyInto copies the receiver into out, including the raw payload.
func (c *PodExtraContainer) DeepCopyInto(out *PodExtraContainer) {
	*out = *c
	out.raw = bytes.Clone(c.raw)
}

// DeepCopy returns an independent copy of the receiver.
func (c *PodExtraContainer) DeepCopy() *PodExtraContainer {
	if c == nil {
		return nil
	}
	out := new(PodExtraContainer)
	c.DeepCopyInto(out)
	return out
}

// MarshalJSON returns the complete object as submitted, or only the name when
// the value was built without a payload.
func (v PodExtraVolume) MarshalJSON() ([]byte, error) {
	return marshalPodExtra(v.Name, v.raw)
}

// UnmarshalJSON is intentionally lenient; see PodExtraContainer.UnmarshalJSON.
func (v *PodExtraVolume) UnmarshalJSON(b []byte) error {
	v.Name, v.raw = unmarshalPodExtra(b)
	return nil
}

// Resolve strictly decodes the object into a corev1.Volume. Unknown or
// duplicate fields are errors, joined into the returned error.
func (v PodExtraVolume) Resolve() (corev1.Volume, error) {
	var out corev1.Volume
	if err := resolvePodExtra(v.raw, &out); err != nil {
		return corev1.Volume{}, err
	}
	return out, nil
}

// DeepCopyInto copies the receiver into out, including the raw payload.
func (v *PodExtraVolume) DeepCopyInto(out *PodExtraVolume) {
	*out = *v
	out.raw = bytes.Clone(v.raw)
}

// DeepCopy returns an independent copy of the receiver.
func (v *PodExtraVolume) DeepCopy() *PodExtraVolume {
	if v == nil {
		return nil
	}
	out := new(PodExtraVolume)
	v.DeepCopyInto(out)
	return out
}

// ResolvePodExtraContainers strictly resolves every container, aggregating
// errors with the list index. field is used as the error path prefix.
func ResolvePodExtraContainers(field string, in []PodExtraContainer) ([]corev1.Container, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]corev1.Container, 0, len(in))
	var errs []error
	for i := range in {
		c, err := in[i].Resolve()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s[%d] (%q): %w", field, i, in[i].Name, err))
			continue
		}
		out = append(out, c)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// ResolvePodExtraVolumes strictly resolves every volume; see
// ResolvePodExtraContainers.
func ResolvePodExtraVolumes(field string, in []PodExtraVolume) ([]corev1.Volume, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]corev1.Volume, 0, len(in))
	var errs []error
	for i := range in {
		v, err := in[i].Resolve()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s[%d] (%q): %w", field, i, in[i].Name, err))
			continue
		}
		out = append(out, v)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// NewPodExtraContainers wraps typed containers.
func NewPodExtraContainers(in []corev1.Container) []PodExtraContainer {
	if in == nil {
		return nil
	}
	out := make([]PodExtraContainer, len(in))
	for i := range in {
		out[i] = NewPodExtraContainer(in[i])
	}
	return out
}

// NewPodExtraVolumes wraps typed volumes.
func NewPodExtraVolumes(in []corev1.Volume) []PodExtraVolume {
	if in == nil {
		return nil
	}
	out := make([]PodExtraVolume, len(in))
	for i := range in {
		out[i] = NewPodExtraVolume(in[i])
	}
	return out
}

func marshalPodExtra(name string, raw json.RawMessage) ([]byte, error) {
	if len(raw) > 0 {
		return raw, nil
	}
	return json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
}

func unmarshalPodExtra(b []byte) (string, json.RawMessage) {
	raw := bytes.Clone(b)
	var head struct {
		Name string `json:"name"`
	}
	// Lenient on purpose: a malformed name leaves Name empty and is reported by
	// Resolve and the webhook, never by the informer's decoder.
	_ = json.Unmarshal(raw, &head)
	return head.Name, raw
}

func resolvePodExtra(raw json.RawMessage, into any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return errors.New("object has no payload")
	}
	if trimmed[0] != '{' {
		return errors.New("must be a JSON object")
	}
	strictErrs, err := k8sjson.UnmarshalStrict(trimmed, into)
	if err != nil {
		return errors.Join(append([]error{err}, strictErrs...)...)
	}
	if len(strictErrs) > 0 {
		return errors.Join(strictErrs...)
	}
	return nil
}
