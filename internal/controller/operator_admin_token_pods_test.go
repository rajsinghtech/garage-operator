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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testOperatorPodSetNamespace = "tenant-a"
	testStaticRevisionSecret    = "static-revision"
)

func operatorPodSetTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func operatorPodSetFixture(replicas int32, ordinals ...int32) (*garagev1beta2.GarageCluster, []client.Object) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testEdgeValue, Namespace: testOperatorPodSetNamespace, UID: types.UID("cluster-uid")},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: replicas},
		},
	}
	controller := true
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "edge-gateway", Namespace: cluster.Namespace, UID: types.UID("sts-uid"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
				Name: cluster.Name, UID: cluster.UID, Controller: &controller,
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(replicas)},
	}
	objects := make([]client.Object, 0, 2+len(ordinals))
	objects = append(objects, cluster, sts)
	for _, ordinal := range ordinals {
		ordinalText := strconv.FormatInt(int64(ordinal), 10)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: sts.Name + "-" + ordinalText, Namespace: cluster.Namespace,
				UID:    types.UID("pod-uid-" + ordinalText),
				Labels: map[string]string{labelCluster: cluster.Name},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
					Name: sts.Name, UID: sts.UID, Controller: &controller,
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
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning, PodIP: "10.0.0." + strconv.FormatInt(int64(ordinal+1), 10),
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}
		objects = append(objects, pod)
	}
	return cluster, objects
}

func TestExpectedOperatorAdminPodSetSupportsNamespaceScopedReader(t *testing.T) {
	cluster, objects := operatorPodSetFixture(1, 0)
	reader := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	restricted := namespaceOnlyReader{Reader: reader, namespace: cluster.Namespace}

	set, err := expectedOperatorAdminPodSet(context.Background(), restricted, cluster)
	if err != nil {
		t.Fatalf("ordinary namespace-scoped cluster attempted a cluster-wide list: %v", err)
	}
	if len(set.Pods) != 1 || set.Hash == "" {
		t.Fatalf("unexpected exact process set: %+v", set)
	}
}

func TestExpectedOperatorAdminPodSetRejectsStatefulSetOrdinalHole(t *testing.T) {
	cluster, objects := operatorPodSetFixture(2, 0, 2)
	reader := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()

	_, err := expectedOperatorAdminPodSet(context.Background(), reader, cluster)
	if err == nil || !strings.Contains(err.Error(), "missing exact desired Pod edge-gateway-1") {
		t.Fatalf("non-contiguous StatefulSet Pod set was accepted: %v", err)
	}
}

func TestVerifyStaticAdminTokenNeverSendsBearerToUnaccountedPod(t *testing.T) {
	cluster, objects := operatorPodSetFixture(1, 0)
	objects = append(objects, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "credential-capture", Namespace: cluster.Namespace,
			UID: types.UID("attacker-uid"), Labels: map[string]string{labelCluster: cluster.Name},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.0.0.99",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	})
	client := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	probes := 0
	r := &GarageClusterReconciler{
		Client: client,
		staticAdminTokenProbe: func(context.Context, string, string) error {
			probes++
			return nil
		},
	}

	err := r.verifyStaticAdminTokenOnRunningPods(context.Background(), cluster, "must-not-leak")
	if err == nil || !strings.Contains(err.Error(), "unaccounted Pod") {
		t.Fatalf("forged cluster-labelled Pod was not rejected: %v", err)
	}
	if probes != 0 {
		t.Fatalf("static Admin bearer was sent before the Pod set was proven: %d probes", probes)
	}
}

func TestVerifyStaticAdminTokenAllowsGenuinelyEmptyFreshCluster(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh", Namespace: testOperatorPodSetNamespace, UID: types.UID("fresh-uid")},
	}
	client := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(cluster).Build()
	r := &GarageClusterReconciler{
		Client: client,
		staticAdminTokenProbe: func(context.Context, string, string) error {
			t.Fatal("empty cluster must not receive an Admin-token probe")
			return nil
		},
	}
	if err := r.verifyStaticAdminTokenOnRunningPods(context.Background(), cluster, "bootstrap-token"); err != nil {
		t.Fatalf("fresh empty cluster should not be blocked: %v", err)
	}
}

func TestReconcileOperatorAdminTokenRefreshesReplacementPodSetBeforeGarageNodeObservedUID(t *testing.T) {
	const (
		staticToken  = "static-token"
		dynamicID    = "dynamic-id"
		dynamicToken = dynamicID + ".dynamic-secret"
	)
	controller := true
	dynamicIDValue := dynamicID
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage", Namespace: testOperatorPodSetNamespace, UID: types.UID("cluster-uid"),
			Annotations: map[string]string{annotationOperatorAdminTokenID: dynamicID},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			Admin: &garagev1beta2.AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
				Key:                  DefaultAdminTokenKey,
			}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/GetAdminTokenInfo":
			got := request.Header.Get("Authorization")
			if got != "Bearer "+staticToken && got != "Bearer "+dynamicToken {
				http.Error(w, "unexpected authorization", http.StatusUnauthorized)
				return
			}
			if got := request.URL.Query().Get("id"); got != dynamicID {
				http.Error(w, "unexpected token ID", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
				ID: &dynamicIDValue, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
			})
		case "/v2/GetClusterStatus":
			if got := request.Header.Get("Authorization"); got != "Bearer "+dynamicToken {
				http.Error(w, "unexpected dynamic authorization", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 7})
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	cluster.Spec.Admin.BindPort = int32(server.Listener.Addr().(*net.TCPAddr).Port)

	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage-0", Namespace: cluster.Namespace, UID: types.UID("node-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
				Name: cluster.Name, UID: cluster.UID, Controller: &controller,
			}},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Zone: "zone-a",
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testTerminalNodeID,
			// The replacement Pod is already Ready, but its GarageNode has not been
			// able to publish the new UID with the stale dynamic-token Pod-set proof.
			ObservedPodUID: testPreviousPodUID, Connected: true, InLayout: true,
		},
	}
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name, Namespace: node.Namespace, UID: types.UID("statefulset-uid"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: node.Name, UID: node.UID, Controller: &controller,
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
	}
	replacementPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: node.Namespace, UID: types.UID("replacement-pod-uid"),
			Labels: map[string]string{labelCluster: cluster.Name},
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
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "127.0.0.1",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
	staticSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testStaticRevisionSecret, Namespace: cluster.Namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte(staticToken)},
	}
	dynamicSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace,
			Labels: map[string]string{labelOperatorAdminToken: operatorAdminTokenReadyValue},
			Annotations: map[string]string{
				annotationOperatorAdminTokenName:   operatorAdminTokenName(cluster),
				annotationOperatorAdminTokenReady:  operatorAdminTokenReadyValue,
				annotationOperatorAdminTokenPodSet: "previous-pod-set-hash",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
				Name: cluster.Name, UID: cluster.UID, Controller: &controller,
			}},
		},
		Immutable: ptr.To(true),
		Data: map[string][]byte{
			operatorAdminTokenIDKey: []byte(dynamicID), DefaultAdminTokenKey: []byte(dynamicToken),
		},
	}

	scheme := operatorPodSetTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		cluster, node, statefulSet, replacementPod, staticSecret, dynamicSecret,
	).Build()
	expected, err := expectedOperatorAdminPodSet(context.Background(), kubeClient, cluster)
	if err != nil {
		t.Fatalf("building replacement Pod set: %v", err)
	}
	if _, ready, err := getReadyOperatorAdminToken(context.Background(), kubeClient, cluster); err == nil || ready {
		t.Fatalf("stale Pod-set proof unexpectedly returned ready token: ready=%t err=%v", ready, err)
	}
	bridge, err := directVerifiedOperatorAdminClient(
		context.Background(), kubeClient, cluster, cluster.Spec.Admin.BindPort,
	)
	if err != nil {
		t.Fatalf("building exact existing-Pod token bridge while Pod-set proof is stale: %v", err)
	}
	if _, err := bridge.GetClusterStatus(context.Background()); err != nil {
		t.Fatalf("using exact existing-Pod token bridge: %v", err)
	}
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme}
	if err := reconciler.reconcileOperatorAdminToken(context.Background(), cluster); err != nil {
		t.Fatalf("refreshing token proof ahead of GarageNode status: %v", err)
	}

	updatedSecret := &corev1.Secret{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(dynamicSecret), updatedSecret); err != nil {
		t.Fatal(err)
	}
	if got := updatedSecret.Annotations[annotationOperatorAdminTokenPodSet]; got != expected.Hash {
		t.Fatalf("token Pod-set proof = %q, want replacement hash %q", got, expected.Hash)
	}
	updatedNode := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(node), updatedNode); err != nil {
		t.Fatal(err)
	}
	if got := updatedNode.Status.ObservedPodUID; got != testPreviousPodUID {
		t.Fatalf("test precondition changed GarageNode observedPodUid to %q", got)
	}
}

func TestReconcileOperatorAdminTokenClearsLiveProofAfterVerificationFailure(t *testing.T) {
	const (
		staticToken  = "static-token"
		dynamicID    = "dynamic-id"
		dynamicToken = dynamicID + ".dynamic-secret"
	)
	cluster, objects, _ := unprovenTokenFixture()
	cluster.Spec.Admin.BindPort = 0
	for _, object := range objects {
		if pod, ok := object.(*corev1.Pod); ok {
			pod.Status.PodIP = "127.0.0.1"
		}
	}

	dynamicIDValue := dynamicID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v2/GetAdminTokenInfo":
			if request.Header.Get("Authorization") != "Bearer "+staticToken ||
				request.URL.Query().Get("id") != dynamicID {
				http.Error(w, "unexpected bootstrap request", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
				ID: &dynamicIDValue, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
			})
		case "/v2/GetClusterStatus":
			if request.Header.Get("Authorization") != "Bearer "+dynamicToken {
				http.Error(w, "unexpected dynamic request", http.StatusUnauthorized)
				return
			}
			http.Error(w, `{"code":"AccessDenied","message":"Forbidden: Invalid bearer token"}`, http.StatusForbidden)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	cluster.Spec.Admin.BindPort = int32(server.Listener.Addr().(*net.TCPAddr).Port)

	kubeClient := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	reconciler := &GarageClusterReconciler{
		Client:    kubeClient,
		APIReader: kubeClient,
		Scheme:    operatorPodSetTestScheme(t),
	}
	if err := reconciler.reconcileOperatorAdminToken(context.Background(), cluster); err == nil ||
		!stderrors.Is(err, errAdminTokenUnproven) {
		t.Fatalf("verification failure was not reported as an unproven token: %v", err)
	}

	updatedSecret := &corev1.Secret{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace},
	}), updatedSecret); err != nil {
		t.Fatal(err)
	}
	if got := updatedSecret.Annotations[annotationOperatorAdminTokenPodSet]; got != "" {
		t.Fatalf("failed dynamic verification retained live Pod-set proof %q", got)
	}
	if got := updatedSecret.Annotations[annotationOperatorAdminTokenReady]; got != operatorAdminTokenReadyValue {
		t.Fatalf("token intent marker = %q, want %q", got, operatorAdminTokenReadyValue)
	}
	if _, ready, err := getReadyOperatorAdminToken(context.Background(), kubeClient, cluster); ready || err == nil ||
		!stderrors.Is(err, errAdminTokenUnproven) {
		t.Fatalf("cleared proof was still treated as ready: ready=%t err=%v", ready, err)
	}
}

// A factor migration restarts every storage process, so the managed Pod
// incarnation set always changes mid-migration. Once the dynamic operator token
// is authoritative, an Admin client refuses an unverified incarnation set — and
// because Reconcile returns early for an active migration, the ordinary token
// reconciliation further down is never reached. Refreshing the token proof
// before dispatching to the migration is therefore the only thing that lets
// RebuildingLayout ever obtain an Admin client; without it the phase waits
// forever while the per-node controllers sit suspended.
//
// This pins the ordering in Reconcile rather than the token logic itself: the
// deadlock was an ordering bug, and reintroducing it is a one-line edit.
func TestReconcileRefreshesOperatorTokenBeforeDispatchingFactorMigration(t *testing.T) {
	source, err := os.ReadFile("garagecluster_controller.go")
	if err != nil {
		t.Fatalf("reading controller source: %v", err)
	}
	body := string(source)

	dispatch := strings.Index(body, "return r.reconcileFactorMigration(ctx, cluster)")
	if dispatch < 0 {
		t.Fatal("factor-migration dispatch not found; update this guard")
	}
	guardStart := strings.LastIndex(body[:dispatch], "if factorMigrationActive(cluster) {")
	if guardStart < 0 {
		t.Fatal("factorMigrationActive guard not found; update this guard")
	}
	if !strings.Contains(body[guardStart:dispatch], "r.reconcileOperatorAdminToken(ctx, cluster)") {
		t.Fatal("Reconcile dispatches to the factor migration without first refreshing the dynamic " +
			"operator Admin token. The purge changes the managed Pod incarnation set, and this branch " +
			"returns before ordinary token reconciliation, so RebuildingLayout can never obtain an " +
			"Admin client and the migration stalls until its stuck timeout.")
	}
}
