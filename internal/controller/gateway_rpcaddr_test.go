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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
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

// bareEdgeGateway is the #243 topology: a gateway-only CR pointing at an external
// (non-k8s) Garage via adminApiEndpoint, with no rpcPublicAddr and no publicEndpoint —
// the external cluster has no way to dial back to the in-cluster gateway pods.
func bareEdgeGateway() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway:   &garagev1beta2.GatewaySpec{Replicas: 1},
			ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://192.168.1.50:3903"},
		},
	}
}

// TestEdgeGatewayReverseUnroutable covers the predicate that classifies the #243
// topology: bare edge gateway (no routable RPC address) is unroutable; any of the
// three accepted address fields, or the presence of a storage tier, flips it off.
func TestEdgeGatewayReverseUnroutable(t *testing.T) {
	if !edgeGatewayReverseUnroutable(bareEdgeGateway()) {
		t.Fatal("bare edge gateway (no rpcPublicAddr/publicEndpoint) must be unroutable")
	}

	withGatewayAddr := bareEdgeGateway()
	withGatewayAddr.Spec.Gateway.RPCPublicAddr = testGatewayRPCAddr
	if edgeGatewayReverseUnroutable(withGatewayAddr) {
		t.Fatal("gateway.rpcPublicAddr set must NOT be unroutable")
	}

	withNetworkAddr := bareEdgeGateway()
	withNetworkAddr.Spec.Network.RPCPublicAddr = "net.example.com:3901"
	if edgeGatewayReverseUnroutable(withNetworkAddr) {
		t.Fatal("network.rpcPublicAddr set must NOT be unroutable")
	}

	withPublicEndpoint := bareEdgeGateway()
	withPublicEndpoint.Spec.PublicEndpoint = &garagev1beta2.PublicEndpointConfig{}
	if edgeGatewayReverseUnroutable(withPublicEndpoint) {
		t.Fatal("publicEndpoint set must NOT be unroutable")
	}

	// Unified cluster (gateway + storage): not an edge gateway, the reverse path is
	// in-cluster, so the relaxation must not apply even with no rpcPublicAddr.
	unified := bareEdgeGateway()
	unified.Spec.Storage = &garagev1beta2.StorageSpec{Replicas: 3}
	if edgeGatewayReverseUnroutable(unified) {
		t.Fatal("unified gateway+storage cluster must NOT be classified unroutable")
	}
}

// TestGatewayConnectedCondition_ForwardOnly is the #243 regression: a functional bare
// edge gateway connects gateway→external but the reverse ConnectNode is skipped
// (no routable address), so connectedToGateway stays 0. Before the fix this stuck at
// PartiallyConnected/False forever; now it must report Connected/True so the reconcile
// converges and autoApply stops churning layout.
func TestGatewayConnectedCondition_ForwardOnly(t *testing.T) {
	bare := bareEdgeGateway()

	// Forward connected, reverse impossible -> Connected (ForwardOnly).
	cond := gatewayConnectedCondition(bare, 1, 0)
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("bare edge gateway with forward-only connectivity must be True, got %s/%s", cond.Status, cond.Reason)
	}
	if cond.Reason != garagev1beta1.ReasonGatewayForwardOnly {
		t.Fatalf("expected reason %q, got %q", garagev1beta1.ReasonGatewayForwardOnly, cond.Reason)
	}

	// Bidirectional always wins regardless of routability.
	if cond := gatewayConnectedCondition(bare, 1, 1); cond.Status != metav1.ConditionTrue ||
		cond.Reason != garagev1beta1.ReasonGatewayConnected {
		t.Fatalf("bidirectional must be Connected, got %s/%s", cond.Status, cond.Reason)
	}

	// Nothing connected -> NodesOffline.
	if cond := gatewayConnectedCondition(bare, 0, 0); cond.Status != metav1.ConditionFalse ||
		cond.Reason != garagev1beta1.ReasonGatewayNodesOffline {
		t.Fatalf("no connectivity must be NodesOffline/False, got %s/%s", cond.Status, cond.Reason)
	}

	// A gateway WITH a routable address but reverse still failing is a real
	// misconfiguration: keep surfacing PartiallyConnected, do not relax to True.
	routable := bareEdgeGateway()
	routable.Spec.Gateway.RPCPublicAddr = testGatewayRPCAddr
	if cond := gatewayConnectedCondition(routable, 1, 0); cond.Status != metav1.ConditionFalse ||
		cond.Reason != garagev1beta1.ReasonGatewayPartiallyConnected {
		t.Fatalf("forward-only WITH routable addr must stay PartiallyConnected/False, got %s/%s", cond.Status, cond.Reason)
	}
}
