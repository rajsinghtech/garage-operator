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
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	pathGetClusterStatus    = "/v2/GetClusterStatus"
	pathGetClusterHealth    = "/v2/GetClusterHealth"
	pathGetClusterLayout    = "/v2/GetClusterLayout"
	pathConnectNodes        = "/v2/ConnectClusterNodes"
	pathUpdateLayout        = "/v2/UpdateClusterLayout"
	pathApplyLayout         = "/v2/ApplyClusterLayout"
	testFedNodeID1          = "1111111111111111aaaaaaaaaaaa0001"
	testRemoteAdminToken    = "remote-admin-token"
	testAdminTokenSecretKey = remoteAdminTokenKey
	testZoneLocal           = "zone-local"
	testZoneRemote          = "zone-remote"
	testTagLocal            = "local"
	testTagRemoteCluster    = "remote-cluster"
	testGatewayOwnershipTag = "cluster:garage/garage"
	testTierGatewayTag      = "tier:gateway"
	testTierStorageTag      = "tier:storage"
)

// newMockGarageServer creates a mock Garage Admin API server with configurable
// responses for GetClusterStatus, GetClusterHealth, GetClusterLayout, and
// ConnectClusterNodes endpoints. The handler can be swapped at runtime.
func newMockGarageServer(handler http.Handler) *httptest.Server {
	return httptest.NewServer(handler)
}

// garageHandler builds a standard mux for the Garage admin API endpoints.
type garageHandler struct {
	statusResp  func() (int, any)
	healthResp  func() (int, any)
	layoutResp  func() (int, any)
	connectResp func() (int, any)
	updateResp  func() (int, any)
	applyResp   func() (int, any)
}

func (h *garageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var code int
	var body any

	switch r.URL.Path {
	case pathGetClusterStatus:
		code, body = h.statusResp()
	case pathGetClusterHealth:
		code, body = h.healthResp()
	case pathGetClusterLayout:
		if h.layoutResp != nil {
			code, body = h.layoutResp()
		} else {
			code, body = http.StatusOK, garage.ClusterLayout{Version: 1}
		}
	case pathConnectNodes:
		if h.connectResp != nil {
			code, body = h.connectResp()
		} else {
			code, body = http.StatusOK, []garage.ConnectNodeResult{{Success: true}}
		}
	case pathUpdateLayout:
		if h.updateResp != nil {
			code, body = h.updateResp()
		} else {
			code, body = http.StatusOK, nil
		}
	case pathApplyLayout:
		if h.applyResp != nil {
			code, body = h.applyResp()
		} else {
			code, body = http.StatusOK, nil
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

var _ = Describe("Federation - connectToRemoteCluster", func() {
	const (
		testNamespace = "federation-test"
		clusterName   = "local-cluster"
		adminToken    = "test-admin-token-value"
	)

	var (
		reconciler *GarageClusterReconciler
		cluster    *garagev1beta2.GarageCluster
		ns         *corev1.Namespace
		secret     *corev1.Secret
	)

	BeforeEach(func() {
		ns = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
		}
		_ = k8sClient.Create(ctx, ns) // ignore if already exists

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testRemoteAdminToken,
				Namespace: testNamespace,
			},
			StringData: map[string]string{testAdminTokenSecretKey: adminToken},
		}
		_ = k8sClient.Delete(ctx, secret)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		cluster = &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: testNamespace,
			},
			Spec: garagev1beta2.GarageClusterSpec{
				Zone: testZoneLocal,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{
					Factor: 1,
				},
			},
		}

		reconciler = &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	Context("when local status contains remote nodes (recovery path)", func() {
		It("should use local status and skip querying the remote API", func() {
			var remoteStatusCalled atomic.Int32

			remoteHandler := &garageHandler{
				statusResp: func() (int, any) {
					remoteStatusCalled.Add(1)
					return http.StatusOK, garage.ClusterStatus{
						Nodes: []garage.NodeInfo{{ID: "fedcba9876543210fedcba98remote001"}},
					}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
			}
			remoteServer := newMockGarageServer(remoteHandler)
			defer remoteServer.Close()

			// Local server handles ConnectClusterNodes
			var connectCalls atomic.Int32
			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
				connectResp: func() (int, any) {
					connectCalls.Add(1)
					return http.StatusOK, []garage.ConnectNodeResult{{Success: true}}
				},
			}
			localServer := newMockGarageServer(localHandler)
			defer localServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			// Local status already knows about remote nodes in zone-remote
			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "abcdef0123456789abcdef01local001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal, Tags: []string{testTagLocal}},
					},
					{
						ID:   "abcdef0123456789abcdef01remote01",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Tags: []string{testTagRemoteCluster}},
					},
					{
						ID:   "abcdef0123456789abcdef01remote02",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Tags: []string{testTagRemoteCluster}},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
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

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// The remote API should NOT have been called for GetClusterStatus
			Expect(remoteStatusCalled.Load()).To(Equal(int32(0)),
				"remote GetClusterStatus should not be called when local status has remote nodes")

			// ConnectClusterNodes should be skipped — all remote nodes are already up
			Expect(connectCalls.Load()).To(Equal(int32(0)),
				"should skip ConnectClusterNodes when all remote nodes are already up")
		})

		It("should skip nodes that belong to the local zone", func() {
			var connectCalls atomic.Int32
			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
				connectResp: func() (int, any) {
					connectCalls.Add(1)
					return http.StatusOK, []garage.ConnectNodeResult{{Success: true}}
				},
			}
			localServer := newMockGarageServer(localHandler)
			defer localServer.Close()

			remoteHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
			}
			remoteServer := newMockGarageServer(remoteHandler)
			defer remoteServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			// Only local zone nodes, no nodes matching the remote zone
			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   testFedNodeID1,
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal, Tags: []string{testTagLocal}},
					},
					{
						ID:   "fedcba9876543210fedcba98remote001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Tags: []string{"remote"}},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
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

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// ConnectClusterNodes should be skipped — the remote node is already up.
			Expect(connectCalls.Load()).To(Equal(int32(0)))
		})
	})

	Context("when local status has no remote nodes (bootstrap path)", func() {
		It("should fall back to querying the remote API with a timeout", func() {
			var remoteStatusCalled atomic.Int32

			remoteHandler := &garageHandler{
				statusResp: func() (int, any) {
					remoteStatusCalled.Add(1)
					return http.StatusOK, garage.ClusterStatus{
						Nodes: []garage.NodeInfo{
							{
								ID:   "bbbbbbbbbbbbbbbb0000000000000001",
								IsUp: true,
							},
						},
					}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
			}
			remoteServer := newMockGarageServer(remoteHandler)
			defer remoteServer.Close()

			var connectCalls atomic.Int32
			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
				connectResp: func() (int, any) {
					connectCalls.Add(1)
					return http.StatusOK, []garage.ConnectNodeResult{{Success: true}}
				},
			}
			localServer := newMockGarageServer(localHandler)
			defer localServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			// Empty local status: no remote nodes known yet
			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "1111111111111111aaaaaaaaonly0001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal, Tags: []string{testTagLocal}},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
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

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Remote API should have been queried
			Expect(remoteStatusCalled.Load()).To(Equal(int32(1)),
				"should have called remote GetClusterStatus during bootstrap")

			// And we should have connected to the discovered remote node
			Expect(connectCalls.Load()).To(Equal(int32(1)))
		})

		It("should fail fast when remote health check fails", func() {
			remoteHandler := &garageHandler{
				statusResp: func() (int, any) {
					// This should never be reached
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusServiceUnavailable, map[string]string{"error": "unhealthy"}
				},
			}
			remoteServer := newMockGarageServer(remoteHandler)
			defer remoteServer.Close()

			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
			}
			localServer := newMockGarageServer(localHandler)
			defer localServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "1111111111111111bbbbbbbbonly0001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
				Name: "unreachable-remote",
				Zone: testZoneRemote,
				Connection: garagev1beta2.RemoteClusterConnection{
					AdminAPIEndpoint: remoteServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: testRemoteAdminToken},
						Key:                  testAdminTokenSecretKey,
					},
				},
			}

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("health check failed"))
		})

		It("should not deadlock when remote is completely unreachable", func() {
			// Start a server that hangs indefinitely on status requests
			hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/GetClusterHealth" {
					// Hang forever - simulating a deadlocked remote
					<-r.Context().Done()
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer hangServer.Close()

			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
				},
			}
			localServer := newMockGarageServer(localHandler)
			defer localServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "1111111111111111bbbbbbbbonly0001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
				Name: "hanging-remote",
				Zone: testZoneRemote,
				Connection: garagev1beta2.RemoteClusterConnection{
					AdminAPIEndpoint: hangServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: testRemoteAdminToken},
						Key:                  testAdminTokenSecretKey,
					},
				},
			}

			// Use a context with a generous timeout - the function should return
			// well within this due to its internal 3s health check timeout
			timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			start := time.Now()
			err := reconciler.connectToRemoteCluster(timeoutCtx, cluster, localClient, localStatus, remote)
			elapsed := time.Since(start)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("health check failed"))
			// Should return within the 3s health timeout + some margin, not the full 10s
			Expect(elapsed).To(BeNumerically("<", 8*time.Second),
				"connectToRemoteCluster should not block for the full context timeout")
		})
	})

	Context("self-connection skip", func() {
		It("should skip when remote zone matches local zone", func() {
			localClient := garage.NewClient("http://unused:3903", adminToken)
			localStatus := &garage.ClusterStatus{}

			remote := garagev1beta2.RemoteClusterConfig{
				Name: "self",
				Zone: testZoneLocal, // same as cluster.Spec.Zone
				Connection: garagev1beta2.RemoteClusterConnection{
					AdminAPIEndpoint: "http://unused:3903",
				},
			}

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("Federation - addRemoteNodesToLayout", func() {
	const (
		testNamespace = "federation-layout-test"
		clusterName   = "layout-cluster"
		adminToken    = "test-admin-token-value"
	)

	var (
		reconciler *GarageClusterReconciler
		cluster    *garagev1beta2.GarageCluster
	)

	BeforeEach(func() {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
		}
		_ = k8sClient.Create(ctx, ns)

		cluster = &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: testNamespace,
			},
			Spec: garagev1beta2.GarageClusterSpec{
				Zone: testZoneLocal,
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{
					Factor: 1,
				},
			},
		}

		reconciler = &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	Context("when remoteStatus is nil (recovery path)", func() {
		It("should use localStatus filtered by zone to build layout changes", func() {
			cap := uint64(107374182400) // 100Gi
			var updatedRoles []garage.NodeRoleChange

			// Local server: handles layout queries and update staging
			localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case pathGetClusterLayout:
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
						Version: 1,
						Roles: []garage.LayoutNodeRole{
							{ID: testFedNodeID1, Zone: testZoneLocal, Tags: []string{testTagLocal}},
						},
					})
				case pathUpdateLayout:
					var req garage.UpdateClusterLayoutRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					updatedRoles = req.Roles
				case pathApplyLayout:
					// no-op
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer localServer.Close()
			localClient := garage.NewClient(localServer.URL, adminToken)

			// Remote client: layout query fails (simulating unreachable remote)
			remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer remoteServer.Close()
			remoteClient := garage.NewClient(remoteServer.URL, adminToken)

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   testFedNodeID1,
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneLocal, Tags: []string{testTagLocal}},
					},
					{
						ID:   "fedcba9876543210fedcba98newnode01",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Tags: []string{"remote"}, Capacity: &cap},
					},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
				Name: testTagRemoteCluster,
				Zone: testZoneRemote,
			}

			// nil remoteStatus -> should use localStatus filtered by zone
			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, remoteClient, nil, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Should have staged the remote node from localStatus
			Expect(updatedRoles).To(HaveLen(1))
			Expect(updatedRoles[0].ID).To(Equal("fedcba9876543210fedcba98newnode01"))
			Expect(updatedRoles[0].Zone).To(Equal(testZoneRemote))
			// Recovery path gets the same tag treatment as the remoteStatus path:
			// remote.Name retained + tier derived from capacity (#224).
			Expect(updatedRoles[0].Tags).To(ContainElements("tier:storage", testTagRemoteCluster))
		})

		It("should not stage nodes that are already in the layout", func() {
			cap := uint64(107374182400)
			var updatedRoles []garage.NodeRoleChange

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case pathGetClusterLayout:
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
						Version: 1,
						Roles: []garage.LayoutNodeRole{
							{ID: testFedNodeID1, Zone: testZoneLocal},
							{ID: "fedcba9876543210fedcba98exist001", Zone: testZoneRemote}, // already in layout
						},
					})
				case pathUpdateLayout:
					var req garage.UpdateClusterLayoutRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					updatedRoles = req.Roles
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()

			localClient := garage.NewClient(server.URL, adminToken)

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{ID: testFedNodeID1, IsUp: true, Role: &garage.NodeAssignedRole{Zone: testZoneLocal}},
					{ID: "fedcba9876543210fedcba98exist001", IsUp: true, Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Capacity: &cap}},
				},
			}

			remote := garagev1beta2.RemoteClusterConfig{
				Name: testTagRemoteCluster,
				Zone: testZoneRemote,
			}

			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, nil, nil, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// remote-existing is already in layout, so nothing to stage
			Expect(updatedRoles).To(BeNil())
		})
	})

	Context("when remoteStatus is provided (normal path)", func() {
		It("should use remoteStatus nodes for layout updates", func() {
			cap := uint64(107374182400)
			var updatedRoles []garage.NodeRoleChange

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case pathGetClusterLayout:
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
						Version: 1,
						Roles: []garage.LayoutNodeRole{
							{ID: testFedNodeID1, Zone: testZoneLocal},
						},
					})
				case pathUpdateLayout:
					var req garage.UpdateClusterLayoutRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					updatedRoles = req.Roles
				case pathApplyLayout:
					// no-op
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()

			localClient := garage.NewClient(server.URL, adminToken)

			remoteStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "fedcba9876543210fedcba98fromapi1",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Capacity: &cap}, // storage
					},
					{
						ID:   "fedcba9876543210fedcba98fromapi2",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Capacity: nil}, // gateway
					},
				},
			}

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{ID: testFedNodeID1, IsUp: true, Role: &garage.NodeAssignedRole{Zone: testZoneLocal}},
				},
			}

			// remoteClient used for GetClusterLayout (staged roles check)
			remoteClient := garage.NewClient(server.URL, adminToken)

			remote := garagev1beta2.RemoteClusterConfig{
				Name: testTagRemoteCluster,
				Zone: testZoneRemote,
			}

			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, remoteClient, remoteStatus, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Should have staged both remote nodes from remoteStatus
			Expect(updatedRoles).To(HaveLen(2))
			byID := map[string]garage.NodeRoleChange{}
			for _, role := range updatedRoles {
				byID[role.ID] = role
			}
			Expect(byID).To(HaveKey("fedcba9876543210fedcba98fromapi1"))
			Expect(byID).To(HaveKey("fedcba9876543210fedcba98fromapi2"))
			// Tier derived from capacity; remote.Name retained for removeStaleRemoteNodes;
			// a cluster:<remote>/<ns> ownership tag added so tier-aware logic recognizes it (#224).
			storage := byID["fedcba9876543210fedcba98fromapi1"]
			gateway := byID["fedcba9876543210fedcba98fromapi2"]
			Expect(storage.Tags).To(ContainElements("tier:storage", testTagRemoteCluster))
			Expect(gateway.Tags).To(ContainElements("tier:gateway", testTagRemoteCluster))
			Expect(gateway.Tags).To(ContainElement(HavePrefix("cluster:")))
		})

		It("should skip importing a remote node that is reported down", func() {
			cap := uint64(107374182400)
			var updatedRoles []garage.NodeRoleChange

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case pathGetClusterLayout:
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{
						Version: 1,
						Roles:   []garage.LayoutNodeRole{{ID: testFedNodeID1, Zone: testZoneLocal}},
					})
				case pathUpdateLayout:
					var req garage.UpdateClusterLayoutRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					updatedRoles = req.Roles
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			localClient := garage.NewClient(server.URL, adminToken)

			remoteStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{ID: "fedcba9876543210fedcba98upnode01", IsUp: true, Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Capacity: &cap}},
					{ID: "fedcba9876543210fedcba98downnode1", IsUp: false, Role: &garage.NodeAssignedRole{Zone: testZoneRemote, Capacity: &cap}},
				},
			}
			localStatus := &garage.ClusterStatus{Nodes: []garage.NodeInfo{{ID: testFedNodeID1, IsUp: true, Role: &garage.NodeAssignedRole{Zone: testZoneLocal}}}}
			remote := garagev1beta2.RemoteClusterConfig{Name: testTagRemoteCluster, Zone: testZoneRemote}

			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, garage.NewClient(server.URL, adminToken), remoteStatus, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Only the up node is imported; the down node is skipped (#224: avoids
			// re-importing a just-orphaned node before its removal propagates).
			Expect(updatedRoles).To(HaveLen(1))
			Expect(updatedRoles[0].ID).To(Equal("fedcba9876543210fedcba98upnode01"))
		})
	})

	Context("removeStaleRemoteNodes (#224 regression)", func() {
		It("still matches imported roles by the remote.Name tag after tier tags were added", func() {
			var staged []garage.NodeRoleChange

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case pathGetClusterLayout:
					// Re-fetch after staging: report nothing staged so ApplyStagedLayoutChanges no-ops.
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 2})
				case pathUpdateLayout:
					var req garage.UpdateClusterLayoutRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					staged = req.Roles
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			localClient := garage.NewClient(server.URL, adminToken)

			remote := garagev1beta2.RemoteClusterConfig{Name: testTagRemoteCluster, Zone: testZoneRemote}
			staleID := "fedcba9876543210fedcba98stale001"
			// Imported role carrying the NEW full tag set (ownership + tier:gateway + remote.Name);
			// its node ID is absent from remoteStatus, so it must be flagged stale via remote.Name.
			layout := &garage.ClusterLayout{
				Version: 1,
				Roles: []garage.LayoutNodeRole{
					{ID: staleID, Zone: testZoneRemote, Tags: remoteImportTags(remote, cluster.Namespace, nil)},
				},
			}
			remoteStatus := &garage.ClusterStatus{Nodes: []garage.NodeInfo{
				{ID: "fedcba9876543210fedcba98live0001", IsUp: true},
			}}

			err := reconciler.removeStaleRemoteNodes(ctx, localClient, layout, remoteStatus, remote)
			Expect(err).NotTo(HaveOccurred())
			Expect(staged).To(HaveLen(1))
			Expect(staged[0].ID).To(Equal(staleID))
			Expect(staged[0].Remove).To(BeTrue())
		})
	})
})

var _ = Describe("Federation - connectRemoteGatewayPods", func() {
	const adminToken = "test-admin-token-value"
	var reconciler *GarageClusterReconciler

	BeforeEach(func() {
		reconciler = &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	It("dials each remote gateway pod via the per-ordinal template", func() {
		type connectCall struct {
			id, addr string
		}
		var calls []connectCall

		handler := &garageHandler{
			statusResp: func() (int, any) {
				return http.StatusOK, garage.ClusterStatus{}
			},
			healthResp: func() (int, any) {
				return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
			},
		}
		// Custom handler captures the body to inspect per-call addresses.
		mux := http.NewServeMux()
		mux.HandleFunc(pathConnectNodes, func(w http.ResponseWriter, r *http.Request) {
			var body []string
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, peer := range body {
				at := -1
				for i := 0; i < len(peer); i++ {
					if peer[i] == '@' {
						at = i
						break
					}
				}
				if at > 0 {
					calls = append(calls, connectCall{id: peer[:at], addr: peer[at+1:]})
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]garage.ConnectNodeResult{{Success: true}})
		})
		mux.HandleFunc(pathGetClusterStatus, func(w http.ResponseWriter, r *http.Request) {
			code, body := handler.statusResp()
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(body)
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		localClient := garage.NewClient(server.URL, adminToken)

		// localStatus describes 2 remote gateway pods in zone-remote — one up
		// (should be skipped), one down (should be connected).
		localStatus := &garage.ClusterStatus{
			Nodes: []garage.NodeInfo{
				{
					ID:   "1111111111111111aaaaaaaaaaaaaaaa1111111111111111aaaaaaaaaaaaaaab",
					IsUp: true,
					Role: &garage.NodeAssignedRole{
						Zone: testZoneRemote,
						Tags: []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-0-0"},
					},
				},
				{
					ID:   "2222222222222222bbbbbbbbbbbbbbbb2222222222222222bbbbbbbbbbbbbbbb",
					IsUp: false,
					Role: &garage.NodeAssignedRole{
						Zone: testZoneRemote,
						Tags: []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-1-0"},
					},
				},
				// Storage node in same zone — must be ignored by gateway loop
				{
					ID:   "3333333333333333cccccccccccccccc3333333333333333cccccccccccccccc",
					IsUp: false,
					Role: &garage.NodeAssignedRole{
						Zone: testZoneRemote,
						Tags: []string{testGatewayOwnershipTag, "tier:storage", "garage-0"},
					},
				},
			},
		}

		remote := garagev1beta2.RemoteClusterConfig{
			Name: testTagRemoteCluster,
			Zone: testZoneRemote,
			Connection: garagev1beta2.RemoteClusterConnection{
				AdminAPIEndpoint:           server.URL,
				GatewayRPCEndpointTemplate: "remote-gw-{ordinal}.example.com:3901",
			},
		}

		reconciler.connectRemoteGatewayPods(ctx, localClient, localStatus, remote, remote.Connection.GatewayRPCEndpointTemplate)

		// Only the down gateway pod (ordinal 1) should have triggered a ConnectNode.
		Expect(calls).To(HaveLen(1))
		Expect(calls[0].id).To(Equal("2222222222222222bbbbbbbbbbbbbbbb2222222222222222bbbbbbbbbbbbbbbb"))
		Expect(calls[0].addr).To(Equal("remote-gw-1.example.com:3901"))
	})

	It("is a no-op when GatewayRPCEndpointTemplate is empty", func() {
		var connectCalls atomic.Int32
		handler := &garageHandler{
			statusResp: func() (int, any) {
				return http.StatusOK, garage.ClusterStatus{}
			},
			healthResp: func() (int, any) {
				return http.StatusOK, garage.ClusterHealth{Status: healthStatusHealthy}
			},
			connectResp: func() (int, any) {
				connectCalls.Add(1)
				return http.StatusOK, []garage.ConnectNodeResult{{Success: true}}
			},
		}
		server := newMockGarageServer(handler)
		defer server.Close()

		localClient := garage.NewClient(server.URL, adminToken)
		localStatus := &garage.ClusterStatus{
			Nodes: []garage.NodeInfo{
				{
					ID:   "4444444444444444dddddddddddddddd4444444444444444dddddddddddddddd",
					IsUp: false,
					Role: &garage.NodeAssignedRole{
						Zone: testZoneRemote,
						Tags: []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-0"},
					},
				},
			},
		}
		remote := garagev1beta2.RemoteClusterConfig{
			Name:       testTagRemoteCluster,
			Zone:       testZoneRemote,
			Connection: garagev1beta2.RemoteClusterConnection{AdminAPIEndpoint: server.URL},
		}

		reconciler.connectRemoteGatewayPods(ctx, localClient, localStatus, remote, remote.Connection.GatewayRPCEndpointTemplate)

		Expect(connectCalls.Load()).To(Equal(int32(0)))
	})
})

func TestParseRemoteGatewayOrdinal(t *testing.T) {
	cases := []struct {
		name   string
		tags   []string
		want   string
		wantOK bool
	}{
		{
			name:   "operator-managed pod-name tag (real shape)",
			tags:   []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-1-0"},
			want:   "1",
			wantOK: true,
		},
		{
			name:   "hyphenated cluster name",
			tags:   []string{"cluster:my-cluster/ns", "tier:gateway", "my-cluster-gateway-2-0"},
			want:   "2",
			wantOK: true,
		},
		{
			name:   "legacy bare-ordinal pod-name tag still parses",
			tags:   []string{testGatewayOwnershipTag, testTierGatewayTag, "garage-gateway-3"},
			want:   "3",
			wantOK: true,
		},
		{
			name:   "no ownership tag",
			tags:   []string{"tier:gateway", "garage-gateway-0-0"},
			wantOK: false,
		},
		{
			name:   "storage node (no gateway pod-name tag)",
			tags:   []string{"cluster:garage/garage", "tier:storage", "garage-storage-0-0"},
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRemoteGatewayOrdinal(tc.tags)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("ordinal = %q, want %q", got, tc.want)
			}
		})
	}
}

var _ = Describe("Bootstrap - connectNodes per-call timeout", func() {
	const adminToken = "test-admin-token-value"

	It("does not block on a hung ConnectClusterNodes endpoint", func() {
		hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == pathConnectNodes {
				// Hang until the client's per-call timeout cancels the request.
				// A hard fallback bounds the handler so a cancelled-mid-flight
				// request can never keep this goroutine alive and block the
				// deferred Server.Close() indefinitely (the per-call timeout is
				// 5s; this fallback only fires if that regresses).
				select {
				case <-r.Context().Done():
				case <-time.After(15 * time.Second):
				}
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer hangServer.Close()

		// adminEndpoint() always appends :port via net.JoinHostPort, so split the
		// httptest host:port and feed the port in as adminPort.
		hostport := strings.TrimPrefix(hangServer.URL, "http://")
		host, portStr, err := net.SplitHostPort(hostport)
		Expect(err).NotTo(HaveOccurred())
		port64, err := strconv.Atoi(portStr)
		Expect(err).NotTo(HaveOccurred())

		nodes := []bootstrapNodeInfo{
			{id: "1111111111111111aaaaaaaaaaaa0001", podIP: host, podName: "src"},
			{id: "2222222222222222bbbbbbbbbbbb0002", podIP: host, podName: "dst"},
		}

		done := make(chan struct{})
		start := time.Now()
		go func() {
			connectNodes(ctx, nodes, adminToken, int32(port64), 3901)
			close(done)
		}()
		Eventually(done, 30*time.Second).Should(BeClosed(),
			"connectNodes must return promptly via the 5s per-call timeout, not the 90s client timeout")
		Expect(time.Since(start)).To(BeNumerically("<", 25*time.Second))
	})
})
