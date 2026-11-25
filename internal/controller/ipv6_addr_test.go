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
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// Garage parses rpc_public_addr and ConnectClusterNodes peers as socket
// addresses, so an IPv6 literal must be bracketed ("[2001:db8::1]:3901").
// "2001:db8::1:3901" is not a valid socket address.
func TestLoadBalancerServiceAddrBracketsIPv6(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "garage-rpc", Namespace: "ns"},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "2001:db8::1"}},
		}},
	}
	r := &GarageClusterReconciler{Client: fake.NewClientBuilder().WithObjects(svc).Build()}
	got := r.loadBalancerServiceAddr(context.Background(), "ns", "garage-rpc", 3901)
	if got != "[2001:db8::1]:3901" {
		t.Fatalf("expected bracketed IPv6 socket address, got %q", got)
	}
	if _, _, err := net.SplitHostPort(got); err != nil {
		t.Fatalf("address %q is not a valid host:port: %v", got, err)
	}
}

func TestDeriveGatewayExternalAddrNodePortIPv6(t *testing.T) {
	r := &GarageClusterReconciler{}
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
				Type:     publicEndpointTypeNodePort,
				NodePort: &garagev1beta2.NodePortEndpointConfig{ExternalAddresses: []string{"2001:db8::2"}},
			},
		},
	}
	if got := r.deriveGatewayExternalAddr(context.Background(), cluster); got != "[2001:db8::2]:30901" {
		t.Fatalf("expected bracketed IPv6 NodePort address, got %q", got)
	}
	cluster.Spec.PublicEndpoint.NodePort.ExternalAddresses = []string{"node.example.com"}
	if got := r.deriveGatewayExternalAddr(context.Background(), cluster); got != "node.example.com:30901" {
		t.Fatalf("hostname form must be unchanged, got %q", got)
	}
}
