/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	"encoding/json"
	"testing"
)

// TestGarageClusterSpec_UnmarshalJSON_GatewayBool guards #195: when stored
// bytes still carry the v1beta1 bool form (because a misconfigured conversion
// webhook didn't rewrite them), the decoder must accept it instead of
// blowing up the entire LIST.
func TestGarageClusterSpec_UnmarshalJSON_GatewayBool(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		wantNN bool // wantNonNil — was *GatewaySpec populated
	}{
		{name: "bool true (legacy v1beta1 stored bytes)", input: `{"gateway":true}`, wantNN: true},
		{name: "bool false (legacy v1beta1 stored bytes)", input: `{"gateway":false}`, wantNN: false},
		{name: "null", input: `{"gateway":null}`, wantNN: false},
		{name: "omitted", input: `{}`, wantNN: false},
		{name: "empty struct (v1beta2)", input: `{"gateway":{}}`, wantNN: true},
		{name: "populated struct (v1beta2)", input: `{"gateway":{"replicas":3}}`, wantNN: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s GarageClusterSpec
			if err := json.Unmarshal([]byte(tc.input), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := s.Gateway != nil; got != tc.wantNN {
				t.Fatalf("gateway non-nil: got=%v want=%v (input=%q)", got, tc.wantNN, tc.input)
			}
		})
	}
}

func TestGarageClusterSpec_UnmarshalJSON_PreservesOtherFields(t *testing.T) {
	// Sanity: the custom UnmarshalJSON shadows the gateway field via the
	// embedded alias trick; verify other fields still round-trip normally.
	in := `{"zone":"us-east-1","gateway":true}`
	var s GarageClusterSpec
	if err := json.Unmarshal([]byte(in), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Zone != "us-east-1" {
		t.Fatalf("zone: got=%q want=us-east-1", s.Zone)
	}
	if s.Gateway == nil {
		t.Fatal("gateway: nil, want non-nil for legacy bool true")
	}
}

func TestGarageClusterSpec_UnmarshalJSON_GatewayStructPopulated(t *testing.T) {
	// Replicas inside the struct must round-trip; this is the normal v1beta2
	// case and must not regress.
	in := `{"gateway":{"replicas":5,"rpcPublicAddr":"a:1"}}`
	var s GarageClusterSpec
	if err := json.Unmarshal([]byte(in), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Gateway == nil || s.Gateway.Replicas != 5 || s.Gateway.RPCPublicAddr != "a:1" {
		t.Fatalf("gateway: got=%+v", s.Gateway)
	}
}
