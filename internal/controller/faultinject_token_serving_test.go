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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// routeClusterServicesToLoopback sends the shared Admin Service
// (<cluster>.<ns>.svc.cluster.local:<port>) to the same port on 127.0.0.1,
// where the fixture's Pods also answer. Other dials are untouched.
func routeClusterServicesToLoopback(t *testing.T) {
	t.Helper()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && strings.HasSuffix(host, ".svc.cluster.local") {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
}

// gatedNodeLocalKeyScenario is #472 as a fault sweep: GarageKey creation on a
// managed node-local cluster while one pool Pod is held at its scheduling
// gate. Each pass runs the cluster's token reconciliation and then the key
// reconcile, which must authenticate with the dynamic operator token.
func gatedNodeLocalKeyScenario() faultScenario {
	return faultScenario{
		name: "GarageKeyCreateWhileNodeLocalPodGated",
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			cluster, objects, _ := nodeLocalServingFixture()
			id := servingTestDynamicID
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				auth := request.Header.Get("Authorization")
				switch request.URL.Path {
				case "/v2/GetAdminTokenInfo":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
						ID: &id, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
					})
					return
				case "/v2/GetClusterStatus":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 3})
					return
				}
				if auth != "Bearer "+servingTestDynamicToken {
					http.Error(w, `{"code":"AccessDenied","message":"Forbidden: Invalid bearer token"}`, http.StatusForbidden)
					return
				}
				gf.serve(w, request)
			}))
			t.Cleanup(front.Close)
			cluster.Spec.Admin.BindPort = int32(front.Listener.Addr().(*net.TCPAddr).Port)

			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k1", Namespace: cluster.Namespace, UID: "key-uid"},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef:     garagev1beta1.ClusterReference{Name: cluster.Name},
					SecretTemplate: &garagev1beta1.SecretTemplate{IncludeEndpoint: ptr.To(false)},
				},
			}
			rpcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: cluster.Name + "-" + RPCSecretKey, Namespace: cluster.Namespace},
				Data:       map[string][]byte{RPCSecretKey: []byte(fiRPCHex)},
			}
			kube := newFaultKube(t, kf, scheme, append(objects, rpcSecret, key)...)
			clusterReconciler := &GarageClusterReconciler{Client: kube, APIReader: kube, Scheme: scheme}
			keyReconciler := &GarageKeyReconciler{Client: kube, Scheme: scheme, ClusterDomain: "cluster.local"}
			nn := types.NamespacedName{Name: key.Name, Namespace: key.Namespace}
			clusterKey := client.ObjectKeyFromObject(cluster)
			return &faultEnv{
				step: func(ctx context.Context) error {
					live := &garagev1beta2.GarageCluster{}
					if err := kube.Get(ctx, clusterKey, live); err != nil {
						return err
					}
					live.Spec.Admin.BindPort = cluster.Spec.Admin.BindPort
					tokenErr := clusterReconciler.reconcileOperatorAdminToken(ctx, live)
					if _, err := keyReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn}); err != nil {
						return err
					}
					return tokenErr
				},
				done: func(ctx context.Context) bool {
					got := &garagev1beta1.GarageKey{}
					return kube.Get(ctx, nn, got) == nil && got.Status.Phase == PhaseReady
				},
				observe: func(ctx context.Context) string {
					got := &garagev1beta1.GarageKey{}
					if err := kube.Get(ctx, nn, got); err != nil {
						if apierrors.IsNotFound(err) {
							return "key: not found"
						}
						return "key: " + err.Error()
					}
					out := fmt.Sprintf("phase=%s finalizers=%v accessKeyIdSet=%v",
						got.Status.Phase, got.Finalizers, got.Status.AccessKeyID != "")
					for _, c := range got.Status.Conditions {
						if c.Status != metav1.ConditionTrue {
							out += fmt.Sprintf("\ncondition %s=%s %s: %s", c.Type, c.Status, c.Reason, c.Message)
						}
					}
					return out
				},
			}
		},
	}
}

// Issue #472: one node-local Pod held at its scheduling gate must not stop
// GarageKey reconciliation, under any single Kubernetes write or Admin API
// fault along the way.
func TestFaultSweep_GarageKeyCreateWhileNodeLocalPodGated(t *testing.T) {
	routeClusterServicesToLoopback(t)
	sweepFaults(t, gatedNodeLocalKeyScenario())
}
