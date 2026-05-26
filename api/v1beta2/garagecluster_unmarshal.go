/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	"bytes"
	"encoding/json"
)

// UnmarshalJSON tolerates pre-#190 v1beta1 storage where `spec.gateway` is a
// bool rather than the v1beta2 GatewaySpec struct. The API server is supposed
// to convert this on read via the conversion webhook, but if the webhook
// Service is misconfigured (cert mismatch, replica=0, endpoints stale) the
// API server may return the raw v1beta1-encoded bytes and the controller
// cache's strict decoder fails the entire LIST with `json: cannot unmarshal
// bool into Go struct field GarageClusterSpec.items.spec.gateway` — fixes #195.
//
// Behavior:
//
//   - `gateway: true`   → `&GatewaySpec{}` (presence-only; the controller
//     reads `cluster.Spec.Replicas` from the v1beta1 endpoint for legacy
//     replica counts, but anything reading via v1beta2 won't have replicas
//     because they're not on this type — that's by design, the proper fix
//     is a storage-version migration sweep)
//   - `gateway: false`  → nil
//   - `gateway: {...}`  → standard struct decode
//   - omitted           → nil
func (s *GarageClusterSpec) UnmarshalJSON(data []byte) error {
	type alias GarageClusterSpec
	aux := struct {
		Gateway json.RawMessage `json:"gateway,omitempty"`
		*alias
	}{alias: (*alias)(s)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	raw := bytes.TrimSpace(aux.Gateway)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		s.Gateway = nil
		return nil
	}
	if bytes.Equal(raw, []byte("true")) {
		s.Gateway = &GatewaySpec{}
		return nil
	}
	if bytes.Equal(raw, []byte("false")) {
		s.Gateway = nil
		return nil
	}
	var g GatewaySpec
	if err := json.Unmarshal(raw, &g); err != nil {
		return err
	}
	s.Gateway = &g
	return nil
}
