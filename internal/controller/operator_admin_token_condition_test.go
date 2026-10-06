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
	stderrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Issue #472: an unready managed Pod blocks the authoritative dynamic token,
// and with it every GarageKey/GarageBucket. The cause must be on the cluster.
func TestOperatorAdminTokenConditionNamesBlockingPodAndRecovers(t *testing.T) {
	const (
		staticToken  = "static-token"
		dynamicID    = "dynamic-id"
		dynamicToken = dynamicID + ".dynamic-secret"
	)
	ctx := context.Background()
	cluster, objects, _ := unprovenTokenFixture()
	var pod *corev1.Pod
	for _, object := range objects {
		if p, ok := object.(*corev1.Pod); ok {
			pod = p
		}
	}
	pod.Status.PodIP = "127.0.0.1"
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}

	dynamicIDValue := dynamicID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/GetAdminTokenInfo":
			if request.Header.Get("Authorization") != "Bearer "+staticToken {
				http.Error(w, "unexpected authorization", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
				ID: &dynamicIDValue, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
			})
		case "/v2/GetClusterStatus":
			if request.Header.Get("Authorization") != "Bearer "+dynamicToken {
				http.Error(w, "unexpected authorization", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 1})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	cluster.Spec.Admin.BindPort = int32(server.Listener.Addr().(*net.TCPAddr).Port)

	scheme := operatorPodSetTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	r := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme}

	tokenErr := r.reconcileOperatorAdminToken(ctx, cluster)
	if tokenErr == nil {
		t.Fatal("unready managed Pod did not block the dynamic token")
	}
	if err := r.setOperatorAdminTokenCondition(ctx, cluster, tokenErr); err != nil {
		t.Fatal(err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady {
		t.Fatalf("condition = %+v, want False/%s", condition, garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady)
	}
	for _, want := range []string{pod.Namespace + "/" + pod.Name, "Ready condition is not True", "blocked"} {
		if !strings.Contains(condition.Message, want) {
			t.Fatalf("condition message %q does not mention %q", condition.Message, want)
		}
	}

	resourceVersion := stored.ResourceVersion
	if err := r.setOperatorAdminTokenCondition(ctx, cluster, r.reconcileOperatorAdminToken(ctx, cluster)); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.ResourceVersion != resourceVersion {
		t.Fatalf("unchanged blocker rewrote status: resourceVersion %s -> %s", resourceVersion, stored.ResourceVersion)
	}

	livePod := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(pod), livePod); err != nil {
		t.Fatal(err)
	}
	livePod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := kubeClient.Status().Update(ctx, livePod); err != nil {
		t.Fatal(err)
	}
	tokenErr = r.reconcileOperatorAdminToken(ctx, cluster)
	if tokenErr != nil {
		t.Fatalf("token was not re-verified after the Pod recovered: %v", tokenErr)
	}
	if err := r.setOperatorAdminTokenCondition(ctx, cluster, tokenErr); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	condition = meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
	if condition == nil || condition.Status != metav1.ConditionTrue ||
		condition.Reason != garagev1beta1.ReasonOperatorAdminTokenVerified {
		t.Fatalf("condition after recovery = %+v, want True/%s", condition, garagev1beta1.ReasonOperatorAdminTokenVerified)
	}
}

func TestOperatorAdminTokenConditionDoesNotClaimBlockBeforeTokenIsAuthoritative(t *testing.T) {
	podSetErr := managedPodNotReady(
		"waiting for exact node-local-pool Pod for GarageNode garage/garage-node-local-storage-node-a")

	blocked := operatorAdminTokenCondition(podSetErr, true)
	if !strings.Contains(blocked.Message, "blocked") ||
		!strings.Contains(blocked.Message, "garage/garage-node-local-storage-node-a") {
		t.Fatalf("authoritative message = %q", blocked.Message)
	}

	bootstrapping := operatorAdminTokenCondition(podSetErr, false)
	if bootstrapping.Reason != garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady ||
		strings.Contains(bootstrapping.Message, "blocked") {
		t.Fatalf("pre-authoritative condition = %+v", bootstrapping)
	}

	other := operatorAdminTokenCondition(stderrors.New("layout not committed"), false)
	if other.Reason != garagev1beta1.ReasonOperatorAdminTokenProvisioning {
		t.Fatalf("pre-authoritative non-Pod failure reason = %q", other.Reason)
	}

	// The create path returns nil before the new token is verified anywhere.
	created := operatorAdminTokenCondition(nil, false)
	if created.Status != metav1.ConditionFalse || created.Reason != garagev1beta1.ReasonOperatorAdminTokenProvisioning {
		t.Fatalf("freshly created token condition = %+v, want False/Provisioning", created)
	}

	integrity := operatorAdminTokenCondition(stderrors.New("cluster Admin Service can route to unaccounted Pod x/y"), true)
	if integrity.Reason != garagev1beta1.ReasonOperatorAdminTokenNotVerified {
		t.Fatalf("non-Pod-readiness failure reason = %q, want NotVerified", integrity.Reason)
	}
}

func TestOperatorAdminPodSetErrorTagsOnlyMissingOrUnreadyPods(t *testing.T) {
	ctx := context.Background()

	cluster, objects := operatorPodSetFixture(2, 0, 2)
	reader := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	var podSetErr *operatorAdminPodSetError
	if _, err := expectedOperatorAdminPodSet(ctx, reader, cluster); !stderrors.As(err, &podSetErr) {
		t.Fatalf("missing StatefulSet ordinal not tagged as a Pod-readiness wait: %v", err)
	}

	cluster, objects = operatorPodSetFixture(1, 0)
	objects = append(objects, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stray", Namespace: cluster.Namespace, UID: "stray-uid",
			Labels: map[string]string{labelCluster: cluster.Name},
		},
	})
	reader = fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	_, err := expectedOperatorAdminPodSet(ctx, reader, cluster)
	if err == nil || stderrors.As(err, &podSetErr) {
		t.Fatalf("integrity failure was reported as a Pod-readiness wait: %v", err)
	}
}

func TestGarageNotReadyPodNamesSchedulingGates(t *testing.T) {
	_, objects := operatorPodSetFixture(1, 0)
	var pod *corev1.Pod
	for _, object := range objects {
		if p, ok := object.(*corev1.Pod); ok {
			pod = p
		}
	}
	pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}}
	pod.Status = corev1.PodStatus{Phase: corev1.PodPending}

	_, err := operatorAdminPodRecord(pod, "")
	var podSetErr *operatorAdminPodSetError
	if !stderrors.As(err, &podSetErr) ||
		!strings.Contains(err.Error(), "held at scheduling gate(s) "+nodeLocalPoolSchedulingGateName) {
		t.Fatalf("gated Pod error = %v", err)
	}
}

func TestOperatorAdminTokenConditionRemovedWhenAdminTokenUnconfigured(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: testOperatorPodSetNamespace},
		Status: garagev1beta2.GarageClusterStatus{Conditions: []metav1.Condition{{
			Type: garagev1beta1.ConditionOperatorAdminTokenReady, Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonOperatorAdminTokenNotVerified, LastTransitionTime: metav1.Now(),
		}}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(cluster).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	r := &GarageClusterReconciler{Client: kubeClient}
	if err := r.setOperatorAdminTokenCondition(context.Background(), cluster, nil); err != nil {
		t.Fatal(err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady) != nil {
		t.Fatal("condition kept on a cluster without an operator Admin token")
	}
}

func TestGarageClientErrorPointsAtClusterCondition(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: "storage"}}
	err := garageClientError(cluster, fmt.Errorf("%w: %w", errAdminTokenUnproven,
		managedPodNotReady("managed Pod storage/garage-0 is not Ready")))
	for _, want := range []string{"GarageCluster storage/garage", garagev1beta1.ConditionOperatorAdminTokenReady,
		"for the blocking Pod", "storage/garage-0"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("dependent error %q does not mention %q", err.Error(), want)
		}
	}
	if !stderrors.Is(err, errAdminTokenUnproven) {
		t.Fatal("wrapped error lost errAdminTokenUnproven")
	}
	if got := garageClientError(cluster, stderrors.New("boom")).Error(); got != "failed to create garage client: boom" {
		t.Fatalf("unrelated client error changed: %q", got)
	}

	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "handle", Namespace: "apps"},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			ClusterRef: &garagev1beta2.ClusterReference{Name: "garage", Namespace: "storage"},
		}},
	}
	unverified := garageClientError(handle, errAdminTokenUnproven).Error()
	if !strings.Contains(unverified, "GarageCluster storage/garage") || strings.Contains(unverified, "blocking Pod") {
		t.Fatalf("unverified-token error via clusterRef = %q", unverified)
	}
}
