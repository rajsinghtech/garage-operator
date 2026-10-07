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
	"strings"
	"sync/atomic"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	servingTestStaticToken  = "static-token"
	servingTestDynamicID    = "dynamic-id"
	servingTestDynamicToken = servingTestDynamicID + ".dynamic-secret"
	servingTestPool         = "storage"
)

// nodeLocalServingFixture is the #472 topology: one node-local pool with three
// GarageNodes on node-a..node-c. node-a and node-b run Ready Pods; node-c's Pod
// is held at the activation scheduling gate, so it has no Node and no IP. The
// dynamic token is authoritative but its recorded proof predates the gate.
func nodeLocalServingFixture() (*garagev1beta2.GarageCluster, []client.Object, map[string]*corev1.Pod) {
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "garage", Namespace: testOperatorPodSetNamespace, UID: types.UID("cluster-uid"),
			Annotations: map[string]string{annotationOperatorAdminTokenID: servingTestDynamicID},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage: &garagev1beta2.StorageSpec{},
			Admin: &garagev1beta2.AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
				Key:                  DefaultAdminTokenKey,
			}},
		},
		Status: garagev1beta2.GarageClusterStatus{Phase: PhaseRunning},
	}
	clusterOwner := []metav1.OwnerReference{{
		APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
		Name: cluster.Name, UID: cluster.UID, Controller: &controller,
	}}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetName(cluster, servingTestPool), Namespace: cluster.Namespace,
			UID:             types.UID("ds-uid"),
			Labels:          map[string]string{labelCluster: cluster.Name},
			OwnerReferences: clusterOwner,
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3},
	}
	objects := make([]client.Object, 0, 10)
	objects = append(objects, cluster, ds,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: testStaticRevisionSecret, Namespace: cluster.Namespace},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte(servingTestStaticToken)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace,
				Labels: map[string]string{labelOperatorAdminToken: operatorAdminTokenReadyValue},
				Annotations: map[string]string{
					annotationOperatorAdminTokenName:   operatorAdminTokenName(cluster),
					annotationOperatorAdminTokenReady:  operatorAdminTokenReadyValue,
					annotationOperatorAdminTokenPodSet: "proof-from-before-node-c-was-gated",
				},
				OwnerReferences: clusterOwner,
			},
			Immutable: ptr.To(true),
			Data: map[string][]byte{
				operatorAdminTokenIDKey: []byte(servingTestDynamicID),
				DefaultAdminTokenKey:    []byte(servingTestDynamicToken),
			},
		},
	)
	pods := map[string]*corev1.Pod{}
	for i, k8sNode := range []string{"node-a", "node-b", "node-c"} {
		objects = append(objects, &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: cluster.Name + "-" + servingTestPool + "-" + k8sNode, Namespace: cluster.Namespace,
				UID: types.UID("garagenode-" + k8sNode), OwnerReferences: clusterOwner,
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Zone: testZone,
				Backing: garagev1beta1.NodeBackingNodeLocalPool, NodeLocalPoolName: servingTestPool,
				KubernetesNodeName: k8sNode,
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: strings.Repeat(string(rune('a'+i)), 64)},
		})
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: ds.Name + "-" + k8sNode, Namespace: cluster.Namespace, UID: types.UID("pod-" + k8sNode),
				Labels: map[string]string{labelCluster: cluster.Name, labelNodeLocalPool: servingTestPool},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
					Name: ds.Name, UID: ds.UID, Controller: &controller,
				}},
			},
			Spec: corev1.PodSpec{NodeName: k8sNode, Containers: []corev1.Container{{
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
		if k8sNode == "node-c" {
			pod.Spec.NodeName = ""
			pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}}
			pod.Status = corev1.PodStatus{Phase: corev1.PodPending}
		}
		pods[k8sNode] = pod
		objects = append(objects, pod)
	}
	return cluster, objects, pods
}

// servingTestGarage is the Admin API of every fixture Pod. Static auth may
// read token info; GetClusterStatus succeeds only with the dynamic token, and
// only while acceptDynamic is set.
func servingTestGarage(t *testing.T, cluster *garagev1beta2.GarageCluster, acceptDynamic *atomic.Bool) {
	t.Helper()
	id := servingTestDynamicID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := request.Header.Get("Authorization")
		switch request.URL.Path {
		case "/v2/GetAdminTokenInfo":
			if auth != "Bearer "+servingTestStaticToken && auth != "Bearer "+servingTestDynamicToken {
				http.Error(w, "unexpected authorization", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
				ID: &id, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
			})
		case "/v2/GetClusterStatus":
			if auth != "Bearer "+servingTestDynamicToken || !acceptDynamic.Load() {
				http.Error(w, `{"code":"AccessDenied","message":"Forbidden: Invalid bearer token"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 3})
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	cluster.Spec.Admin.BindPort = int32(server.Listener.Addr().(*net.TCPAddr).Port)
}

func podSetUIDs(set *operatorAdminPodSet) []string {
	out := make([]string, 0, len(set.Pods))
	for i := range set.Pods {
		out = append(out, string(set.Pods[i].UID))
	}
	return out
}

// Issue #472: the serving set leaves out a desired process that cannot answer
// through the Admin Service, and becomes the complete set again, with the same
// hash, once every process is Ready.
func TestServingOperatorAdminPodSetSkipsProcessesThatCannotAnswer(t *testing.T) {
	ctx := context.Background()
	cluster, objects, pods := nodeLocalServingFixture()
	kube := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()

	var podSetErr *operatorAdminPodSetError
	if _, err := expectedOperatorAdminPodSet(ctx, kube, cluster); !stderrors.As(err, &podSetErr) {
		t.Fatalf("complete scope must still wait for the gated Pod: %v", err)
	}
	set, err := servingOperatorAdminPodSet(ctx, kube, cluster)
	if err != nil {
		t.Fatalf("gated node-local Pod blocked the serving set: %v", err)
	}
	if got := strings.Join(podSetUIDs(set), ","); got != "pod-node-a,pod-node-b" {
		t.Fatalf("serving set = %s, want pod-node-a,pod-node-b", got)
	}
	gatedHash := set.Hash

	// A Pod whose container stopped, or whose Node was lost, keeps its IP and
	// stays routable but cannot answer: it is still left out of the proof.
	stopped := pods["node-b"].DeepCopy()
	stopped.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	if err := kube.Status().Update(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	set, err = servingOperatorAdminPodSet(ctx, kube, cluster)
	if err != nil {
		t.Fatalf("stopped Pod blocked the serving set: %v", err)
	}
	if got := strings.Join(podSetUIDs(set), ","); got != "pod-node-a" {
		t.Fatalf("serving set with node-b stopped = %s, want pod-node-a", got)
	}

	// Missing entirely (DaemonSet Pod deleted, nothing recreated yet).
	if err := kube.Delete(ctx, pods["node-c"]); err != nil {
		t.Fatal(err)
	}
	if _, err := servingOperatorAdminPodSet(ctx, kube, cluster); err != nil {
		t.Fatalf("missing Pod blocked the serving set: %v", err)
	}

	// Every process back and Ready: the serving set equals the complete set.
	stopped.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := kube.Status().Update(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	ready := pods["node-c"].DeepCopy()
	ready.ResourceVersion = ""
	ready.Spec.SchedulingGates = nil
	ready.Spec.NodeName = "node-c"
	ready.Status = corev1.PodStatus{
		Phase: corev1.PodRunning, PodIP: "127.0.0.1",
		Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
	}
	if err := kube.Create(ctx, ready); err != nil {
		t.Fatal(err)
	}
	complete, err := expectedOperatorAdminPodSet(ctx, kube, cluster)
	if err != nil {
		t.Fatal(err)
	}
	serving, err := servingOperatorAdminPodSet(ctx, kube, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if serving.Hash != complete.Hash || len(serving.Pods) != 3 {
		t.Fatalf("all-Ready serving set differs from the complete set: %v vs %v", podSetUIDs(serving), podSetUIDs(complete))
	}
	if serving.Hash == gatedHash {
		t.Fatal("the returning Pod did not change the serving hash, so its proof would not be re-verified")
	}
}

// The serving scope must never send the bearer to a Pod it cannot account for,
// Ready or not: the Admin Service routes to every addressed Pod.
func TestServingOperatorAdminPodSetStillRejectsForeignPods(t *testing.T) {
	for _, ready := range []corev1.ConditionStatus{corev1.ConditionTrue, corev1.ConditionFalse} {
		cluster, objects, _ := nodeLocalServingFixture()
		objects = append(objects, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "credential-capture", Namespace: cluster.Namespace, UID: "attacker-uid",
				Labels: map[string]string{labelCluster: cluster.Name},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning, PodIP: "10.0.0.99",
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: ready}},
			},
		})
		kube := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
		_, err := servingOperatorAdminPodSet(context.Background(), kube, cluster)
		var podSetErr *operatorAdminPodSetError
		if err == nil || stderrors.As(err, &podSetErr) {
			t.Fatalf("foreign Pod (Ready=%s) was not rejected as an integrity failure: %v", ready, err)
		}
	}
}

// With no Ready process at all there is nothing to prove the token on; the
// blocker still names a Pod, as #476 reports it.
func TestServingOperatorAdminPodSetNamesPodWhenNothingIsReady(t *testing.T) {
	cluster, objects, pods := nodeLocalServingFixture()
	for _, name := range []string{"node-a", "node-b"} {
		pods[name].Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	}
	kube := fake.NewClientBuilder().WithScheme(operatorPodSetTestScheme(t)).WithObjects(objects...).Build()
	_, err := servingOperatorAdminPodSet(context.Background(), kube, cluster)
	var podSetErr *operatorAdminPodSetError
	if !stderrors.As(err, &podSetErr) || !strings.Contains(err.Error(), "Ready condition is not True") ||
		!strings.Contains(err.Error(), cluster.Namespace+"/") {
		t.Fatalf("no-Ready-process error = %v", err)
	}
}

// Issue #472 end to end at the controller level: a node-local Pod held at its
// scheduling gate no longer stops the dynamic token, so GarageKey and
// GarageBucket clients keep working. When the Pod comes back, the token is
// unproven until it is verified there too.
func TestReconcileOperatorAdminTokenProvesServingSetWhileNodeLocalPodIsGated(t *testing.T) {
	ctx := context.Background()
	cluster, objects, pods := nodeLocalServingFixture()
	var acceptDynamic atomic.Bool
	acceptDynamic.Store(true)
	servingTestGarage(t, cluster, &acceptDynamic)
	scheme := operatorPodSetTestScheme(t)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build()
	r := &GarageClusterReconciler{Client: kube, APIReader: kube, Scheme: scheme}

	if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
		t.Fatalf("gated node-local Pod blocked the dynamic token: %v", err)
	}
	token, ready, err := getReadyOperatorAdminToken(ctx, kube, cluster)
	if err != nil || !ready || token != servingTestDynamicToken {
		t.Fatalf("dynamic token not usable while node-c is gated: ready=%t err=%v", ready, err)
	}
	if _, err := GetGarageClient(ctx, kube, cluster, "cluster.local"); err != nil {
		t.Fatalf("GarageKey/GarageBucket client still blocked: %v", err)
	}
	if err := r.setOperatorAdminTokenCondition(ctx, cluster, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := directVerifiedOperatorAdminClient(ctx, kube, cluster, cluster.Spec.Admin.BindPort); err != nil {
		t.Fatalf("exact operator-token bridge blocked by the gated Pod: %v", err)
	}

	// node-c is released and starts, but has not received the token row yet.
	acceptDynamic.Store(false)
	released := pods["node-c"].DeepCopy()
	if err := kube.Get(ctx, client.ObjectKeyFromObject(released), released); err != nil {
		t.Fatal(err)
	}
	released.Spec.SchedulingGates = nil
	released.Spec.NodeName = "node-c"
	if err := kube.Update(ctx, released); err != nil {
		t.Fatal(err)
	}
	released.Status = corev1.PodStatus{
		Phase: corev1.PodRunning, PodIP: "127.0.0.1",
		Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
	}
	if err := kube.Status().Update(ctx, released); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := getReadyOperatorAdminToken(ctx, kube, cluster); ready || !stderrors.Is(err, errAdminTokenUnproven) {
		t.Fatalf("a newly Ready Pod reused the old proof: ready=%t err=%v", ready, err)
	}
	if err := r.reconcileOperatorAdminToken(ctx, cluster); !stderrors.Is(err, errAdminTokenUnproven) {
		t.Fatalf("Pod that rejects the token was not reported as unproven: %v", err)
	}

	acceptDynamic.Store(true)
	if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
		t.Fatalf("token not re-verified after node-c accepted it: %v", err)
	}
	if _, ready, err := getReadyOperatorAdminToken(ctx, kube, cluster); err != nil || !ready {
		t.Fatalf("token not ready on the complete set: ready=%t err=%v", ready, err)
	}
}

// Replacing a lost or unreplicated token is destructive and still waits for
// every managed process, exactly as before #472.
func TestReconcileOperatorAdminTokenReplacementStillNeedsCompleteSet(t *testing.T) {
	ctx := context.Background()
	cluster, objects, _ := nodeLocalServingFixture()
	var acceptDynamic atomic.Bool
	servingTestGarage(t, cluster, &acceptDynamic)
	kept := objects[:0]
	for _, object := range objects {
		if secret, ok := object.(*corev1.Secret); ok && secret.Name == operatorAdminTokenSecretName(cluster) {
			continue // the one-time Secret was lost; the cluster still pins its ID
		}
		kept = append(kept, object)
	}
	scheme := operatorPodSetTestScheme(t)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kept...).Build()
	r := &GarageClusterReconciler{Client: kube, APIReader: kube, Scheme: scheme}
	err := r.reconcileOperatorAdminToken(ctx, cluster)
	var podSetErr *operatorAdminPodSetError
	if !stderrors.As(err, &podSetErr) || !strings.Contains(err.Error(), "complete managed process set") {
		t.Fatalf("token replacement did not wait for the complete set: %v", err)
	}
}
