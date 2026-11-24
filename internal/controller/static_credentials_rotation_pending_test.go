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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// #600: a static admin token source change before the table-backed operator
// credential is ready everywhere must keep the pinned snapshot and report a
// pending rotation instead of failing the GarageCluster.
func TestEnsureStaticCredentialSnapshotDefersAdminTokenRotationUntilBridgeReady(t *testing.T) {
	ctx := context.Background()
	scheme := managedPVCTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "default", UID: types.UID("cluster-uid"), Generation: 1},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "admin"}, Key: "admin-token",
			},
		}},
	}
	rpc := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: managedRPCSecretName(cluster), Namespace: "default"},
		Data:       map[string][]byte{RPCSecretKey: []byte(strings.Repeat("ab", 32))},
	}
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "default"},
		Data:       map[string][]byte{"admin-token": []byte("original-token")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(cluster, rpc, source).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		Build()
	recorder := record.NewFakeRecorder(10)
	r := &GarageClusterReconciler{Client: c, Scheme: scheme, EventRecorder: recorder}
	r.staticAdminTokenProbe = func(context.Context, string, string) error { return nil }

	live := func() *garagev1beta2.GarageCluster {
		t.Helper()
		got := &garagev1beta2.GarageCluster{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(cluster), got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	first, err := r.ensureStaticCredentialSnapshot(ctx, live())
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	pinnedRevision := live().Annotations[annotationStaticCredentialsRevision]
	if first == nil || pinnedRevision == "" {
		t.Fatalf("expected a pinned snapshot, got %v revision %q", first, pinnedRevision)
	}

	source.Data["admin-token"] = []byte("rotated-token")
	if err := c.Update(ctx, source); err != nil {
		t.Fatal(err)
	}
	pendingCluster := live()
	snapshot, err := r.ensureStaticCredentialSnapshot(ctx, pendingCluster)
	if err != nil {
		t.Fatalf("a rotation waiting for the operator credential must not fail the cluster: %v", err)
	}
	if snapshot == nil || snapshot.Name != first.Name {
		t.Fatalf("expected the pinned snapshot %s to stay in use, got %v", first.Name, snapshot)
	}
	got := live()
	if rev := got.Annotations[annotationStaticCredentialsRevision]; rev != pinnedRevision {
		t.Fatalf("pinned revision moved from %q to %q before the bridge was ready", pinnedRevision, rev)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, garagev1beta1.ConditionStaticCredentialsRotationPending)
	if cond == nil || cond.Status != metav1.ConditionTrue ||
		cond.Reason != garagev1beta1.ReasonStaticCredentialsWaitingForOperatorAdminToken ||
		!strings.Contains(cond.Message, first.Name) {
		t.Fatalf("expected StaticCredentialsRotationPending=True/WaitingForOperatorAdminToken naming %s, got %+v", first.Name, cond)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, garagev1beta1.ConditionStaticCredentialsRotationPending) {
			t.Fatalf("unexpected event %q", event)
		}
	default:
		t.Fatal("expected a StaticCredentialsRotationPending event")
	}

	// A repeat reconcile while still pending neither rewrites nor re-emits.
	if _, err := r.ensureStaticCredentialSnapshot(ctx, live()); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("unexpected repeat event %q", event)
	default:
	}

	// Restoring the pinned value ends the pending rotation.
	source.Data["admin-token"] = []byte("original-token")
	if err := c.Update(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ensureStaticCredentialSnapshot(ctx, live()); err != nil {
		t.Fatal(err)
	}
	if cond := meta.FindStatusCondition(live().Status.Conditions, garagev1beta1.ConditionStaticCredentialsRotationPending); cond != nil {
		t.Fatalf("expected the pending condition to be removed, got %+v", cond)
	}
}
