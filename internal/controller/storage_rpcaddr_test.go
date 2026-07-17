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
	"errors"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

var _ = Describe("buildAutoModeStorageNode rpc_public_addr per-ordinal (#cross-region storage reachability)", func() {
	makeReconciler := func() *GarageClusterReconciler {
		return &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	}
	makeCluster := func(name, rpcAddr string, ep *garagev1beta2.PublicEndpointConfig) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, UID: testCRUID},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
				Storage: &garagev1beta2.StorageSpec{
					Replicas:      3,
					RPCPublicAddr: rpcAddr,
					Metadata:      &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:          &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication:    &garagev1beta2.ReplicationConfig{Factor: 2},
				PublicEndpoint: ep,
			},
		}
	}

	It("substitutes {ordinal} so each storage pod advertises its own address", func() {
		r := makeReconciler()
		cluster := makeCluster("stg-ord", "stg-{ordinal}.example.ts.net:3901", nil)
		for ord := int32(0); ord < 3; ord++ {
			node, err := r.buildAutoModeStorageNode(cluster, ord, "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(node.Spec.Network).NotTo(BeNil(), "ord=%d must get a per-pod rpc_public_addr", ord)
			Expect(node.Spec.Network.RPCPublicAddr).To(Equal(fmt.Sprintf("stg-%d.example.ts.net:3901", ord)))
		}
	})

	It("uses an address without {ordinal} verbatim", func() {
		r := makeReconciler()
		cluster := makeCluster("stg-verbatim", "shared.example.ts.net:3901", nil)
		node, err := r.buildAutoModeStorageNode(cluster, 1, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.Network).NotTo(BeNil())
		Expect(node.Spec.Network.RPCPublicAddr).To(Equal("shared.example.ts.net:3901"))
	})

	It("does NOT set Network when storage.rpcPublicAddr is unset", func() {
		r := makeReconciler()
		cluster := makeCluster("stg-none", "", nil)
		node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.Network).To(BeNil())
	})

	It("lets a per-node publicEndpoint win over storage.rpcPublicAddr (no Network override)", func() {
		// publicEndpoint LoadBalancer+perNode supplies the live LB ingress address;
		// setting Network would override it in reconcileNodeConfigMap, so we skip it.
		r := makeReconciler()
		cluster := makeCluster("stg-ep-wins", "stg-{ordinal}.example.ts.net:3901",
			&garagev1beta2.PublicEndpointConfig{
				Type:         publicEndpointTypeLoadBalancer,
				LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{PerNode: true},
			})
		node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.PublicEndpoint).NotTo(BeNil(), "publicEndpoint perNode must be propagated")
		Expect(node.Spec.Network).To(BeNil(), "storage.rpcPublicAddr must not override the per-node LB address")
	})
})

// TestParseRemotePodOrdinal verifies ordinal extraction for both tiers from
// layout tags, including the gateway delegation wrapper.
func TestNodeIDFromDiscovery(t *testing.T) {
	discoveryErr := errors.New("pod unavailable")

	if got, fallback, err := nodeIDFromDiscovery("live-id", nil, "stale-id"); got != "live-id" || fallback || err != nil {
		t.Fatalf("live discovery = (%q,%v,%v), want live-id without fallback", got, fallback, err)
	}
	if got, fallback, err := nodeIDFromDiscovery("", discoveryErr, "observed-id"); got != "observed-id" || !fallback || err != nil {
		t.Fatalf("offline fallback = (%q,%v,%v), want observed-id fallback", got, fallback, err)
	}
	if _, _, err := nodeIDFromDiscovery("", discoveryErr, ""); !errors.Is(err, discoveryErr) {
		t.Fatalf("missing fallback error = %v, want discovery error", err)
	}
}

func TestNodeSpecificRPCAddressTags(t *testing.T) {
	original := []string{testGatewayOwnershipTag, testTierStorageTag, nodeRPCAddressTagPrefix + "old.example:3901"}
	tags := desiredNodeRoleTags(original, "new.example:3901")
	if len(tags) != 3 || tags[2] != nodeRPCAddressTagPrefix+"new.example:3901" {
		t.Fatalf("desired tags = %#v, want one current RPC address tag", tags)
	}
	if original[2] != nodeRPCAddressTagPrefix+"old.example:3901" {
		t.Fatalf("desiredNodeRoleTags mutated its input: %#v", original)
	}

	capacity := uint64(1024)
	remote := garagev1beta2.RemoteClusterConfig{Name: testRemoteRoleTag, Zone: "remote-zone"}
	imported := remoteImportTags(remote, "garage", &capacity, tags)
	wantRPC := nodeRPCAddressTagPrefix + "new.example:3901"
	foundRPC := false
	for _, tag := range imported {
		if tag == wantRPC {
			foundRPC = true
		}
		if tag == testGatewayOwnershipTag {
			t.Fatalf("source ownership tag must not survive import: %#v", imported)
		}
	}
	if !foundRPC {
		t.Fatalf("imported tags lost node RPC address: %#v", imported)
	}

	node := garage.NodeInfo{Role: &garage.NodeAssignedRole{Tags: imported}}
	addr, source := remoteNodeRPCAddress(node, "shared.example", 3901)
	if addr != "new.example:3901" || source != "layout-tag" {
		t.Fatalf("address = (%q,%q), want node-specific layout address", addr, source)
	}
}

func TestRemoteNodeRPCAddressFallbacks(t *testing.T) {
	observed := "10.0.0.2:3901"
	node := garage.NodeInfo{Address: &observed}
	if addr, source := remoteNodeRPCAddress(node, "shared.example", 3901); addr != "shared.example:3901" || source != "shared-bootstrap" {
		t.Fatalf("shared fallback = (%q,%q)", addr, source)
	}
	if addr, source := remoteNodeRPCAddress(node, "", 3901); addr != observed || source != "observed-peer" {
		t.Fatalf("observed fallback = (%q,%q)", addr, source)
	}
}

func TestParseRemotePodOrdinal(t *testing.T) {
	storageTags := []string{testGatewayOwnershipTag, testTierStorageTag, "garage-storage-2-0"}
	if got, ok := parseRemotePodOrdinal(storageTags, tierStorage); !ok || got != "2" {
		t.Fatalf("storage ordinal: got (%q,%v), want (\"2\",true)", got, ok)
	}
	// hyphenated cluster name must still parse (prefix derived from ownership tag).
	hyphenTags := []string{"cluster:my-garage-cluster/ns", testTierStorageTag, "my-garage-cluster-storage-0-0"}
	if got, ok := parseRemotePodOrdinal(hyphenTags, tierStorage); !ok || got != "0" {
		t.Fatalf("hyphenated storage ordinal: got (%q,%v), want (\"0\",true)", got, ok)
	}
	// storage tags must not match the gateway tier.
	if _, ok := parseRemotePodOrdinal(storageTags, tierGateway); ok {
		t.Fatalf("storage tags must not parse as gateway")
	}
	// gateway delegation wrapper still works.
	gwTags := []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-3-0"}
	if got, ok := parseRemoteGatewayOrdinal(gwTags); !ok || got != "3" {
		t.Fatalf("gateway ordinal: got (%q,%v), want (\"3\",true)", got, ok)
	}
}

// TestAutoModeStorageNodeNeedsUpdate_NetworkDrift verifies that a change to the
// per-ordinal rpc_public_addr is detected as drift (so the operator rolls it).
func TestAutoModeStorageNodeNeedsUpdate_NetworkDrift(t *testing.T) {
	withAddr := func(addr string) *garagev1beta1.GarageNode {
		n := &garagev1beta1.GarageNode{}
		if addr != "" {
			n.Spec.Network = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: addr}
		}
		return n
	}
	if autoModeStorageNodeNeedsUpdate(withAddr("a:3901"), withAddr("a:3901")) {
		t.Fatal("identical rpc_public_addr must not be drift")
	}
	if !autoModeStorageNodeNeedsUpdate(withAddr("a:3901"), withAddr("b:3901")) {
		t.Fatal("changed rpc_public_addr must be drift")
	}
	if !autoModeStorageNodeNeedsUpdate(withAddr(""), withAddr("b:3901")) {
		t.Fatal("adding rpc_public_addr must be drift")
	}
}
