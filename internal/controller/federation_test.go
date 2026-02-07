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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	pathGetClusterStatus = "/v2/GetClusterStatus"
	pathGetClusterHealth = "/v2/GetClusterHealth"
	pathGetClusterLayout = "/v2/GetClusterLayout"
	pathConnectNodes     = "/v2/ConnectClusterNodes"
	pathUpdateLayout     = "/v2/UpdateClusterLayout"
	pathApplyLayout      = "/v2/ApplyClusterLayout"
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
		cluster    *garagev1alpha1.GarageCluster
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
				Name:      "remote-admin-token",
				Namespace: testNamespace,
			},
			StringData: map[string]string{"token": adminToken},
		}
		_ = k8sClient.Delete(ctx, secret)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		cluster = &garagev1alpha1.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: testNamespace,
			},
			Spec: garagev1alpha1.GarageClusterSpec{
				Zone:     "zone-local",
				Replicas: 1,
				Replication: garagev1alpha1.ReplicationConfig{
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
						Role: &garage.NodeAssignedRole{Zone: "zone-local", Tags: []string{"local"}},
					},
					{
						ID:   "abcdef0123456789abcdef01remote01",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Tags: []string{"remote-cluster"}},
					},
					{
						ID:   "abcdef0123456789abcdef01remote02",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Tags: []string{"remote-cluster"}},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
				Connection: garagev1alpha1.RemoteClusterConnection{
					AdminAPIEndpoint: remoteServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "remote-admin-token"},
						Key:                  "token",
					},
				},
			}

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// The remote API should NOT have been called for GetClusterStatus
			Expect(remoteStatusCalled.Load()).To(Equal(int32(0)),
				"remote GetClusterStatus should not be called when local status has remote nodes")

			// ConnectClusterNodes should have been called for each remote node
			Expect(connectCalls.Load()).To(Equal(int32(2)),
				"should have called ConnectClusterNodes for both remote nodes")
		})

		It("should skip nodes that belong to the local zone", func() {
			var connectCalls atomic.Int32
			localHandler := &garageHandler{
				statusResp: func() (int, any) {
					return http.StatusOK, garage.ClusterStatus{}
				},
				healthResp: func() (int, any) {
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
				},
			}
			remoteServer := newMockGarageServer(remoteHandler)
			defer remoteServer.Close()

			localClient := garage.NewClient(localServer.URL, adminToken)

			// Only local zone nodes, no nodes matching the remote zone
			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{
						ID:   "1111111111111111aaaaaaaaaaaa0001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-local", Tags: []string{"local"}},
					},
					{
						ID:   "fedcba9876543210fedcba98remote001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Tags: []string{"remote"}},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
				Connection: garagev1alpha1.RemoteClusterConnection{
					AdminAPIEndpoint: remoteServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "remote-admin-token"},
						Key:                  "token",
					},
				},
			}

			err := reconciler.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Only 1 connect call: the remote node. The local node should be skipped.
			Expect(connectCalls.Load()).To(Equal(int32(1)))
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
						Role: &garage.NodeAssignedRole{Zone: "zone-local", Tags: []string{"local"}},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
				Connection: garagev1alpha1.RemoteClusterConnection{
					AdminAPIEndpoint: remoteServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "remote-admin-token"},
						Key:                  "token",
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
						Role: &garage.NodeAssignedRole{Zone: "zone-local"},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "unreachable-remote",
				Zone: "zone-remote",
				Connection: garagev1alpha1.RemoteClusterConnection{
					AdminAPIEndpoint: remoteServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "remote-admin-token"},
						Key:                  "token",
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
					return http.StatusOK, garage.ClusterHealth{Status: "healthy"}
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
						Role: &garage.NodeAssignedRole{Zone: "zone-local"},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "hanging-remote",
				Zone: "zone-remote",
				Connection: garagev1alpha1.RemoteClusterConnection{
					AdminAPIEndpoint: hangServer.URL,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "remote-admin-token"},
						Key:                  "token",
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

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "self",
				Zone: "zone-local", // same as cluster.Spec.Zone
				Connection: garagev1alpha1.RemoteClusterConnection{
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
		cluster    *garagev1alpha1.GarageCluster
	)

	BeforeEach(func() {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
		}
		_ = k8sClient.Create(ctx, ns)

		cluster = &garagev1alpha1.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: testNamespace,
			},
			Spec: garagev1alpha1.GarageClusterSpec{
				Zone:     "zone-local",
				Replicas: 1,
				Replication: garagev1alpha1.ReplicationConfig{
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
							{ID: "1111111111111111aaaaaaaaaaaa0001", Zone: "zone-local", Tags: []string{"local"}},
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
						ID:   "1111111111111111aaaaaaaaaaaa0001",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-local", Tags: []string{"local"}},
					},
					{
						ID:   "fedcba9876543210fedcba98newnode01",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Tags: []string{"remote"}, Capacity: &cap},
					},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
			}

			// nil remoteStatus -> should use localStatus filtered by zone
			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, remoteClient, nil, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Should have staged the remote node from localStatus
			Expect(updatedRoles).To(HaveLen(1))
			Expect(updatedRoles[0].ID).To(Equal("fedcba9876543210fedcba98newnode01"))
			Expect(updatedRoles[0].Zone).To(Equal("zone-remote"))
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
							{ID: "1111111111111111aaaaaaaaaaaa0001", Zone: "zone-local"},
							{ID: "fedcba9876543210fedcba98exist001", Zone: "zone-remote"}, // already in layout
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
					{ID: "1111111111111111aaaaaaaaaaaa0001", IsUp: true, Role: &garage.NodeAssignedRole{Zone: "zone-local"}},
					{ID: "fedcba9876543210fedcba98exist001", IsUp: true, Role: &garage.NodeAssignedRole{Zone: "zone-remote", Capacity: &cap}},
				},
			}

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
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
							{ID: "1111111111111111aaaaaaaaaaaa0001", Zone: "zone-local"},
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
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Capacity: &cap},
					},
					{
						ID:   "fedcba9876543210fedcba98fromapi2",
						IsUp: true,
						Role: &garage.NodeAssignedRole{Zone: "zone-remote", Capacity: &cap},
					},
				},
			}

			localStatus := &garage.ClusterStatus{
				Nodes: []garage.NodeInfo{
					{ID: "1111111111111111aaaaaaaaaaaa0001", IsUp: true, Role: &garage.NodeAssignedRole{Zone: "zone-local"}},
				},
			}

			// remoteClient used for GetClusterLayout (staged roles check)
			remoteClient := garage.NewClient(server.URL, adminToken)

			remote := garagev1alpha1.RemoteClusterConfig{
				Name: "remote-cluster",
				Zone: "zone-remote",
			}

			err := reconciler.addRemoteNodesToLayout(ctx, cluster, localClient, remoteClient, remoteStatus, localStatus, remote)
			Expect(err).NotTo(HaveOccurred())

			// Should have staged both remote nodes from remoteStatus
			Expect(updatedRoles).To(HaveLen(2))
			ids := []string{updatedRoles[0].ID, updatedRoles[1].ID}
			Expect(ids).To(ContainElements("fedcba9876543210fedcba98fromapi1", "fedcba9876543210fedcba98fromapi2"))
		})
	})
})
