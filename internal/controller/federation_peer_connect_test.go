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
	"net"
	"net/http"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Federation peering must not redial peers that are already connected and
// must not dial a known peer through the shared (local-DNS-resolved) admin
// host: Garage gossips the address it was asked to dial, so that would seed
// a possibly cross-cluster address into the peer book.
var _ = Describe("Federation - connectToRemoteCluster peer addressing", func() {
	const (
		testNamespace = "federation-peer-test"
		adminToken    = "peer-admin-token"
		upNodeID      = "abcdef0123456789abcdef01remote0a"
		downNodeID    = "abcdef0123456789abcdef01remote0b"
		unknownNodeID = "abcdef0123456789abcdef01remote0c"
		upTagAddr     = "10.9.0.1:3901"
		downTagAddr   = "10.9.0.2:3901"
		knownAddr     = "10.9.0.3:3901"
	)

	var (
		reconciler *GarageClusterReconciler
		cluster    *garagev1beta2.GarageCluster
		remote     garagev1beta2.RemoteClusterConfig
		connects   []string
		mu         sync.Mutex
	)

	BeforeEach(func() {
		_ = k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}})
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: testRemoteAdminToken, Namespace: testNamespace},
			StringData: map[string]string{testAdminTokenSecretKey: adminToken},
		}
		_ = k8sClient.Delete(ctx, secret)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		cluster = &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "local-cluster", Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Zone: testZoneLocal,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		reconciler = &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		connects = nil
	})

	// run executes one federation pass against mock local/remote Admin APIs and
	// returns the "<nodeID>@<addr>" strings handed to ConnectClusterNodes plus
	// the host:port of the remote admin endpoint (the shared host).
	run := func(nodes []garage.NodeInfo) (sharedAddr string) {
		remoteServer := newMockGarageServer(&garageHandler{
			statusResp: func() (int, any) { return http.StatusOK, garage.ClusterStatus{} },
			healthResp: func() (int, any) { return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy} },
		})
		DeferCleanup(remoteServer.Close)
		localServer := newMockGarageServer(&garageHandler{
			statusResp: func() (int, any) { return http.StatusOK, garage.ClusterStatus{} },
			healthResp: func() (int, any) { return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy} },
			connectReq: func(req []string) {
				mu.Lock()
				defer mu.Unlock()
				connects = append(connects, req...)
			},
		})
		DeferCleanup(localServer.Close)

		remote = garagev1beta2.RemoteClusterConfig{
			Name: testTagRemoteCluster,
			Zone: testZoneRemote,
			Connection: garagev1beta2.RemoteClusterConnection{
				AdminAPIEndpoint: remoteServer.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: testRemoteAdminToken},
					Key:                  testAdminTokenSecretKey,
				},
			},
		}
		localStatus := &garage.ClusterStatus{Nodes: append([]garage.NodeInfo{{
			ID:   "abcdef0123456789abcdef01local001",
			IsUp: true,
			Role: &garage.NodeAssignedRole{Zone: testZoneLocal, Tags: []string{testTagLocal}},
		}}, nodes...)}

		Expect(reconciler.connectToRemoteCluster(ctx, cluster, garage.NewClient(localServer.URL, adminToken), localStatus, remote)).To(Succeed())
		mu.Lock()
		defer mu.Unlock()
		return remoteServer.Listener.Addr().String()
	}

	remoteNode := func(id string, up bool, address *string, tags ...string) garage.NodeInfo {
		return garage.NodeInfo{
			ID:      id,
			IsUp:    up,
			Address: address,
			Role:    &garage.NodeAssignedRole{Zone: testZoneRemote, Tags: tags},
		}
	}

	It("skips remote nodes that are already up and still connects the down one", func() {
		run([]garage.NodeInfo{
			remoteNode(upNodeID, true, nil, nodeRPCAddressTagPrefix+upTagAddr),
			remoteNode(downNodeID, false, nil, nodeRPCAddressTagPrefix+downTagAddr),
		})
		Expect(connects).To(Equal([]string{downNodeID + "@" + downTagAddr}),
			"only the down node may be dialed; redialing an up peer can gossip a poisoned address")
	})

	It("does not dial anything when every remote node is up", func() {
		run([]garage.NodeInfo{
			remoteNode(upNodeID, true, nil, nodeRPCAddressTagPrefix+upTagAddr),
		})
		Expect(connects).To(BeEmpty())
	})

	It("never falls back to the shared admin host for a down node with a known address", func() {
		known := knownAddr
		shared := run([]garage.NodeInfo{
			// No rpc-address tag, but the local node already knows this peer's address.
			remoteNode(downNodeID, false, &known),
		})
		Expect(connects).To(Equal([]string{downNodeID + "@" + knownAddr}))
		for _, c := range connects {
			Expect(c).NotTo(ContainSubstring(shared), "shared admin host is resolved by the local cluster's DNS and may point at another cluster")
		}
	})

	It("still uses the shared bootstrap host for a down node with no known address", func() {
		shared := run([]garage.NodeInfo{
			remoteNode(unknownNodeID, false, nil),
		})
		host, _, _ := splitHostPortForTest(shared)
		Expect(connects).To(Equal([]string{unknownNodeID + "@" + host + ":3901"}))
	})
})

func splitHostPortForTest(hostPort string) (string, string, error) {
	return net.SplitHostPort(hostPort)
}
