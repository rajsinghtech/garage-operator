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
//
// It also salvages the matching v1beta1 storage shape: in v1beta1 `replicas`
// is a top-level field and `spec.storage` is the legacy StorageConfig with no
// Replicas field. When those bytes leak through the v1beta2 endpoint (same
// webhook-hiccup scenario as the gateway bool), the strict decoder would
// otherwise yield `Storage != nil, Storage.Replicas == 0`. `HasStorageTier()`
// returns true on that, and the Auto-mode reconciler computes a desired set
// of zero GarageNodes — deleting every operator-owned storage node. We
// detect a top-level `replicas` in the raw JSON and, when storage is also
// present with replicas zero, copy it across.
func (s *GarageClusterSpec) UnmarshalJSON(data []byte) error {
	type alias GarageClusterSpec
	aux := struct {
		Gateway  json.RawMessage `json:"gateway,omitempty"`
		Replicas *int32          `json:"replicas,omitempty"`
		*alias
	}{alias: (*alias)(s)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	// Salvage v1beta1 leak: top-level replicas + storage block where
	// storage.replicas was not present (decoded to zero).
	if aux.Replicas != nil && s.Storage != nil && s.Storage.Replicas == 0 {
		s.Storage.Replicas = *aux.Replicas
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
