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
	"context"
	"strings"
	"testing"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// testGatewayRPCAddr is a sample externally-routable gateway RPC address shared
// by the gateway rpc_public_addr tests.
const testGatewayRPCAddr = "gw.example.com:3901"

// TestWriteRPCConfig_EdgeGatewayRPCPublicAddr guards the fix for the edge-gateway
// rpc_public_addr gap: spec.gateway.rpcPublicAddr — the field the docs call
// "preferred" — must be rendered for a gateway-only (edge) CR, and must NOT leak
// into a unified cluster's storage config.
func TestWriteRPCConfig_EdgeGatewayRPCPublicAddr(t *testing.T) {
	// Edge gateway: gateway tier + connectTo, no storage tier.
	edge := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway:   &garagev1beta2.GatewaySpec{Replicas: 1, RPCPublicAddr: testGatewayRPCAddr},
			ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://storage:3903"},
		},
	}
	var b strings.Builder
	writeRPCConfig(&b, edge, &configContext{})
	if !strings.Contains(b.String(), `rpc_public_addr = "`+testGatewayRPCAddr+`"`) {
		t.Fatalf("edge gateway must render gateway.rpcPublicAddr; got:\n%s", b.String())
	}

	// Unified cluster (storage + gateway): the storage config must NOT inherit the
	// gateway tier's rpcPublicAddr (the case is gated on !HasStorageTier).
	unified := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{Replicas: 3},
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1, RPCPublicAddr: testGatewayRPCAddr},
		},
	}
	var b2 strings.Builder
	writeRPCConfig(&b2, unified, &configContext{})
	if strings.Contains(b2.String(), testGatewayRPCAddr) {
		t.Fatalf("unified storage config must not inherit gateway.rpcPublicAddr; got:\n%s", b2.String())
	}
}

// TestDeriveGatewayExternalAddr_PrefersGatewayRPCPublicAddr verifies the reverse
// ConnectNode address derivation honors spec.gateway.rpcPublicAddr first.
func TestDeriveGatewayExternalAddr_PrefersGatewayRPCPublicAddr(t *testing.T) {
	r := &GarageClusterReconciler{}
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1, RPCPublicAddr: testGatewayRPCAddr},
			Network: garagev1beta2.NetworkConfig{RPCPublicAddr: "net.example.com:3901"},
		},
	}
	if got := r.deriveGatewayExternalAddr(context.TODO(), cluster); got != testGatewayRPCAddr {
		t.Fatalf("expected gateway.rpcPublicAddr to win, got %q", got)
	}
}
