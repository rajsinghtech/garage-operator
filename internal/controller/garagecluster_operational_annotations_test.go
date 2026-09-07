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
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func connectNodesAnnotationTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta1 scheme: %v", err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 scheme: %v", err)
	}
	return scheme
}

func TestConnectNodesAnnotationIsDispatchedDuringRolloutGuard(t *testing.T) {
	const address = "10.0.0.1:3901"
	var requests [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization = %q, want mounted static token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/GetClusterStatus":
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{
				ID: testTerminalNodeID, IsUp: true,
			}}})
		case "/v2/GetClusterHealth":
			_ = json.NewEncoder(w).Encode(garage.ClusterHealth{Status: healthStatusHealthy})
		case "/v2/ConnectClusterNodes":
			var request []string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode ConnectClusterNodes request: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			requests = append(requests, request)
			_ = json.NewEncoder(w).Encode([]garage.ConnectNodeResult{{Success: true}})
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	port := int32(server.Listener.Addr().(*net.TCPAddr).Port)

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "guarded",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationConnectNodes: testTerminalNodeID + "@" + address,
			},
		},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort: port,
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "static-admin"},
				Key:                  DefaultAdminTokenKey,
			},
		}},
		Status: garagev1beta2.GarageClusterStatus{Conditions: []metav1.Condition{{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRolloutWaiting,
			ObservedGeneration: 1,
		}}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "guarded-0",
			Namespace: cluster.Namespace,
			Labels:    map[string]string{labelCluster: cluster.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "static-admin"},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "static-admin", Namespace: cluster.Namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("test-token")},
	}
	scheme := connectNodesAnnotationTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, pod, secret).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient,
		Scheme: scheme,
	}

	// This is the exact helper called by rollout/layout guard return paths. The
	// request must be dispatched even though ordinary layout work is waiting.
	reconciler.tryProcessConnectNodesAnnotationDuringGuard(context.Background(), cluster)

	if len(requests) != 1 || !reflect.DeepEqual(requests[0], []string{testTerminalNodeID + "@" + address}) {
		t.Fatalf("ConnectClusterNodes requests = %#v, want one request for %s", requests, testTerminalNodeID+"@"+address)
	}
	updated := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), updated); err != nil {
		t.Fatalf("get updated GarageCluster: %v", err)
	}
	if _, ok := updated.Annotations[AnnotationConnectNodes]; ok {
		t.Fatal("successful connect-nodes annotation was not consumed during rollout guard")
	}
}

func TestConnectNodesAnnotationIsRetainedWhenRPCRepairFails(t *testing.T) {
	const failure = "connection refused"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization = %q, want mounted static token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/GetClusterStatus":
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{
				ID: testTerminalNodeID, IsUp: true,
			}}})
		case "/v2/GetClusterHealth":
			_ = json.NewEncoder(w).Encode(garage.ClusterHealth{Status: healthStatusHealthy})
		case "/v2/ConnectClusterNodes":
			errorMessage := failure
			_ = json.NewEncoder(w).Encode([]garage.ConnectNodeResult{{Success: false, Error: &errorMessage}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	port := int32(server.Listener.Addr().(*net.TCPAddr).Port)

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "failed-connect",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationConnectNodes: testTerminalNodeID + "@10.0.0.2:3901",
			},
		},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort: port,
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "static-admin"},
				Key:                  DefaultAdminTokenKey,
			},
		}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "failed-connect-0",
			Namespace: cluster.Namespace,
			Labels:    map[string]string{labelCluster: cluster.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "static-admin"},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "static-admin", Namespace: cluster.Namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("test-token")},
	}
	scheme := connectNodesAnnotationTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, pod, secret).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient,
		Scheme: scheme,
	}

	if err := reconciler.processConnectNodesAnnotation(context.Background(), cluster); err == nil {
		t.Fatal("processConnectNodesAnnotation succeeded after Garage rejected ConnectClusterNodes")
	}
	updated := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), updated); err != nil {
		t.Fatalf("get failed-connect GarageCluster: %v", err)
	}
	if got := updated.Annotations[AnnotationConnectNodes]; got == "" {
		t.Fatal("failed connect-nodes annotation was consumed instead of being retained for retry")
	}
}
