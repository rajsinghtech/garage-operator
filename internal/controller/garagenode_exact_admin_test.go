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
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestExactManagedGarageNodeAdminClientKeepsMountedStaticCredentialAfterRoleRemoval(t *testing.T) {
	t.Parallel()
	const (
		staticToken = "mounted-static-token"
		selfQuery   = "self"
		testZone    = "zone-a"
	)
	nodeID := strings.Repeat("a", 64)
	controller := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		if got := request.Header.Get("Authorization"); got != "Bearer "+staticToken {
			http.Error(w, `{"code":"AccessDenied","message":"Forbidden: Invalid bearer token"}`, http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v2/GetNodeInfo":
			if request.URL.Query().Get("node") != selfQuery {
				http.Error(w, "expected exact self query", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"success":{"` + nodeID + `":{"nodeId":"` + nodeID + `"}},"error":{}}`))
		case "/v2/GetClusterLayoutHistory":
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: 8,
				Versions: []garage.LayoutVersion{{
					Version: 8,
					Status:  garage.LayoutVersionStatusCurrent,
				}},
			})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	server.Config.SetKeepAlivesEnabled(false)

	namespace := "exact-admin"
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: namespace, UID: types.UID("cluster-uid")},
		Spec: garagev1beta2.GarageClusterSpec{
			Admin: &garagev1beta2.AdminConfig{
				BindPort: int32(server.Listener.Addr().(*net.TCPAddr).Port),
				AdminTokenSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
					Key:                  DefaultAdminTokenKey,
				},
			},
		},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "manual", Namespace: namespace, UID: types.UID("garage-node-uid")},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Zone:       testZone,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: namespace, UID: types.UID("statefulset-uid"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
			Name: node.Name, UID: node.UID, Controller: &controller,
		}},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: namespace, UID: types.UID("pod-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: statefulSet.Name, UID: statefulSet.UID, Controller: &controller,
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testStaticRevisionSecret, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte(staticToken)},
	}

	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		cluster, node, statefulSet, pod, secret,
	).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme}
	direct, err := reconciler.exactManagedGarageNodeAdminClient(context.Background(), node, cluster, nodeID)
	if err != nil {
		t.Fatalf("building exact managed Admin client: %v", err)
	}
	history, err := direct.GetClusterLayoutHistory(context.Background())
	if err != nil {
		t.Fatalf("mounted static credential did not survive the simulated post-removal call: %v", err)
	}
	if history.CurrentVersion != 8 {
		t.Fatalf("layout history version = %d, want 8", history.CurrentVersion)
	}

	if _, err := reconciler.exactManagedGarageNodeAdminClient(
		context.Background(), node, cluster, strings.Repeat("b", 64),
	); err == nil || !strings.Contains(err.Error(), "expected durable identity") {
		t.Fatalf("exact client accepted a mismatched durable identity: %v", err)
	}
}

func TestExactExistingGarageNodeAdminClientUsesSiblingPodAndMountedToken(t *testing.T) {
	t.Parallel()
	const peerToken = "sibling-mounted-token"
	peerID := strings.Repeat("b", 64)
	controller := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		if got := request.Header.Get("Authorization"); got != "Bearer "+peerToken {
			http.Error(w, `{"code":"AccessDenied","message":"Forbidden: Invalid bearer token"}`, http.StatusForbidden)
			return
		}
		if request.URL.Path != "/v2/GetClusterStatus" {
			http.NotFound(w, request)
			return
		}
		_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 12})
	}))
	defer server.Close()
	server.Config.SetKeepAlivesEnabled(false)

	namespace := "exact-peer"
	port := int32(server.Listener.Addr().(*net.TCPAddr).Port)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: namespace, UID: types.UID("cluster-uid")},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort:            port,
			AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "unused"}, Key: DefaultAdminTokenKey},
		}},
	}
	joining := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "joining", Namespace: namespace, UID: types.UID("joining-uid")},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
	}
	sibling := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "peer", Namespace: namespace, UID: types.UID("peer-uid")},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: peerID},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: sibling.Name, Namespace: namespace, UID: types.UID("peer-sts-uid"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
			Name: sibling.Name, UID: sibling.UID, Controller: &controller,
		}},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: sibling.Name + "-0", Namespace: namespace, UID: types.UID("peer-pod-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: statefulSet.Name, UID: statefulSet.UID, Controller: &controller,
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "peer-static"}, Key: DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			PodIP:      "127.0.0.1",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-static", Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte(peerToken)},
	}

	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		cluster, joining, sibling, statefulSet, pod, secret,
	).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme}

	peer, err := reconciler.exactExistingGarageNodeAdminClient(context.Background(), joining, cluster)
	if err != nil {
		t.Fatalf("building exact existing peer Admin client: %v", err)
	}
	wantEndpoint := adminEndpoint("127.0.0.1", port)
	if got := peer.BaseURL(); got != wantEndpoint {
		t.Fatalf("exact peer endpoint = %q, want %q", got, wantEndpoint)
	}
	if _, err := peer.GetClusterStatus(context.Background()); err != nil {
		t.Fatalf("exact peer client did not use the sibling Pod's mounted token: %v", err)
	}
}
