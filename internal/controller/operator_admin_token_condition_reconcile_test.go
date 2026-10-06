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
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// drainEvents returns every event the fake recorder buffered so far.
func drainEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			return events
		}
	}
}

// operatorAdminTokenConditionWrites counts status writes that change
// ConditionOperatorAdminTokenReady relative to the stored object.
func operatorAdminTokenConditionWrites(base client.WithWatch, writes *int) client.WithWatch {
	return interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if cluster, ok := obj.(*garagev1beta2.GarageCluster); ok && sub == "status" {
				stored := &garagev1beta2.GarageCluster{}
				if err := c.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err == nil {
					before := meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
					after := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
					if (before == nil) != (after == nil) || (before != nil && (before.Status != after.Status ||
						before.Reason != after.Reason || before.Message != after.Message ||
						before.ObservedGeneration != after.ObservedGeneration)) {
						*writes++
					}
				}
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
}

// Raw verification errors carry ephemeral detail (ports, request IDs, timings).
// They must not reach the condition message, or every pass rewrites status and
// the status write re-triggers the GarageCluster watch. The raw error goes to a
// Warning event, emitted only when the condition changes.
func TestOperatorAdminTokenConditionMessageStableAcrossVaryingErrors(t *testing.T) {
	const (
		staticToken  = "static-token"
		dynamicID    = "dynamic-id"
		dynamicToken = dynamicID + ".dynamic-secret"
	)
	ctx := context.Background()
	cluster, objects, _ := unprovenTokenFixture()
	for _, object := range objects {
		if pod, ok := object.(*corev1.Pod); ok {
			pod.Status.PodIP = "127.0.0.1"
		}
	}

	var requests atomic.Int64
	dynamicIDValue := dynamicID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/v2/GetAdminTokenInfo" && request.Header.Get("Authorization") == "Bearer "+staticToken:
			_ = json.NewEncoder(w).Encode(garage.AdminTokenInfo{
				ID: &dynamicIDValue, Name: operatorAdminTokenName(cluster), Scope: []string{"*"},
			})
		case request.URL.Path == "/v2/GetClusterStatus" && request.Header.Get("Authorization") == "Bearer "+dynamicToken:
			// The token row has not reached this process yet; the body differs on
			// every request, like a real transient failure would.
			http.Error(w, fmt.Sprintf("Forbidden: invalid token (request id %d)", requests.Add(1)), http.StatusForbidden)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	cluster.Spec.Admin.BindPort = int32(server.Listener.Addr().(*net.TCPAddr).Port)

	scheme := operatorPodSetTestScheme(t)
	writes := 0
	kubeClient := operatorAdminTokenConditionWrites(fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).Build(), &writes)
	recorder := record.NewFakeRecorder(16)
	r := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme, EventRecorder: recorder}

	var rawErrors []string
	for pass := 0; pass < 3; pass++ {
		tokenErr := r.reconcileOperatorAdminToken(ctx, cluster)
		if !stderrors.Is(tokenErr, errAdminTokenUnproven) {
			t.Fatalf("pass %d: want an unproven-token error, got %v", pass, tokenErr)
		}
		rawErrors = append(rawErrors, tokenErr.Error())
		if err := r.setOperatorAdminTokenCondition(ctx, cluster, tokenErr); err != nil {
			t.Fatal(err)
		}
	}
	if rawErrors[0] == rawErrors[1] {
		t.Fatalf("test server did not vary the raw error text: %q", rawErrors[0])
	}
	if writes != 1 {
		t.Fatalf("condition written %d times across 3 passes with varying error text, want 1", writes)
	}

	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != garagev1beta1.ReasonOperatorAdminTokenNotVerified {
		t.Fatalf("condition = %+v, want False/%s", condition, garagev1beta1.ReasonOperatorAdminTokenNotVerified)
	}
	if strings.Contains(condition.Message, "request id") || strings.Contains(condition.Message, "Forbidden") {
		t.Fatalf("condition message leaks raw error text: %q", condition.Message)
	}

	events := drainEvents(recorder)
	if len(events) != 1 {
		t.Fatalf("events = %q, want exactly one for the single condition change", events)
	}
	if !strings.Contains(events[0], eventReasonOperatorAdminTokenNotReady) || !strings.Contains(events[0], "request id 1") {
		t.Fatalf("event %q does not carry the raw error", events[0])
	}
}

// Every non-Pod-readiness message is fixed per reason, whatever the error says.
func TestOperatorAdminTokenConditionMessageIgnoresRawErrorText(t *testing.T) {
	for _, tc := range []struct {
		name          string
		wrap          func(error) error
		authoritative bool
		reason        string
	}{
		{"unproven", func(err error) error { return fmt.Errorf("%w: %v", errAdminTokenUnproven, err) }, true,
			garagev1beta1.ReasonOperatorAdminTokenNotVerified},
		{"other authoritative failure", func(err error) error { return err }, true,
			garagev1beta1.ReasonOperatorAdminTokenNotVerified},
		{"not provisioned", func(err error) error { return err }, false,
			garagev1beta1.ReasonOperatorAdminTokenProvisioning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := operatorAdminTokenCondition(tc.wrap(stderrors.New("dial tcp 10.0.0.1:3903: i/o timeout after 4.01s")), tc.authoritative)
			second := operatorAdminTokenCondition(tc.wrap(stderrors.New("read tcp 10.0.0.9:51234->10.0.0.1:3903: reset")), tc.authoritative)
			if first.Reason != tc.reason || first != second {
				t.Fatalf("conditions differ or wrong reason:\n first  %+v\n second %+v", first, second)
			}
			if strings.Contains(first.Message, "10.0.0.1") {
				t.Fatalf("message leaks raw error text: %q", first.Message)
			}
		})
	}
}

// One GarageCluster Reconcile tries the token up to twice (before the rollout
// guard and again after it) and several early returns report it. Whatever the
// path, a single loop must write the condition at most once, even when the two
// attempts disagree, and an unchanged blocker must not write at all.
func TestReconcileWritesOperatorAdminTokenConditionAtMostOncePerLoop(t *testing.T) {
	ctx := context.Background()
	cluster, objects, _ := unprovenTokenFixture()
	// No managed Pods at all: the token cannot be proven, deterministically,
	// while the rest of the reconcile reaches the ordinary token path.
	kept := objects[:0]
	for _, object := range objects {
		switch object.(type) {
		case *corev1.Pod, *appsv1.StatefulSet, *garagev1beta1.GarageNode:
			continue
		}
		kept = append(kept, object)
	}
	objects = kept
	// A stale True from an earlier pass must flip exactly once.
	cluster.Status.Conditions = []metav1.Condition{{
		Type: garagev1beta1.ConditionOperatorAdminTokenReady, Status: metav1.ConditionTrue,
		Reason: garagev1beta1.ReasonOperatorAdminTokenVerified, LastTransitionTime: metav1.Now(),
		Message: "dynamic operator Admin token is verified on every managed Garage process",
	}}

	scheme := testSchemeForFault(t)
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	writes := 0
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).Build()
	kubeClient := operatorAdminTokenConditionWrites(base, &writes)
	// The first token attempt of each loop fails differently (an API error,
	// reported as NotVerified) from the retry (no Pods, ManagedPodsNotReady),
	// so reporting both attempts would show up as two writes.
	tokenAttemptLists := 0
	apiReader := interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if calledFromOperatorAdminTokenReconcile() {
				tokenAttemptLists++
				if tokenAttemptLists == 1 {
					return stderrors.New("injected transient API error")
				}
			}
			return c.List(ctx, list, opts...)
		},
	})
	recorder := record.NewFakeRecorder(64)
	r := &GarageClusterReconciler{Client: kubeClient, APIReader: apiReader, Scheme: scheme, EventRecorder: recorder}
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)}

	sawFalse := false
	for pass := 0; pass < 5; pass++ {
		writes, tokenAttemptLists = 0, 0
		if _, err := r.Reconcile(ctx, request); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if writes > 1 {
			t.Fatalf("pass %d wrote OperatorAdminTokenReady %d times, want at most 1", pass, writes)
		}
		stored := &garagev1beta2.GarageCluster{}
		if err := kubeClient.Get(ctx, request.NamespacedName, stored); err != nil {
			t.Fatal(err)
		}
		condition := meta.FindStatusCondition(stored.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
		if condition == nil || condition.Status != metav1.ConditionFalse {
			continue
		}
		if tokenAttemptLists < 2 {
			t.Fatalf("pass %d made %d token attempts, want the first attempt and its retry", pass, tokenAttemptLists)
		}
		if condition.Reason != garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady {
			t.Fatalf("condition = %+v, want the retry's False/%s", condition, garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady)
		}
		if sawFalse && writes != 0 {
			t.Fatalf("pass %d rewrote an unchanged blocker", pass)
		}
		sawFalse = true
	}
	if !sawFalse {
		t.Fatal("reconcile never reported the missing managed Pods on OperatorAdminTokenReady")
	}
	tokenEvents := 0
	for _, event := range drainEvents(recorder) {
		if strings.Contains(event, eventReasonOperatorAdminTokenNotReady) {
			tokenEvents++
		}
	}
	if tokenEvents != 1 {
		t.Fatalf("%d %s events across 5 loops, want 1", tokenEvents, eventReasonOperatorAdminTokenNotReady)
	}
}

func calledFromOperatorAdminTokenReconcile() bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*GarageClusterReconciler).reconcileOperatorAdminToken") {
			return true
		}
		if !more {
			return false
		}
	}
}
