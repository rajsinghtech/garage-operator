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
	"maps"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestServerSideApplyDoesNotForceForeignMetadataConflict(t *testing.T) {
	scheme := runtimeSchemeForServerSideApplyTest(t)
	foreign := metav1.ManagedFieldsEntry{
		Manager:    "foreign-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "v1",
		FieldsType: "FieldsV1",
		FieldsV1:   metav1.NewFieldsV1(`{"f:metadata":{"f:labels":{"f:managed":{}}}}`),
	}
	existing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "ssa-conflict", Namespace: "default",
		Labels:        map[string]string{"managed": "foreign-value"},
		ManagedFields: []metav1.ManagedFieldsEntry{foreign},
	}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).WithReturnManagedFields().Build()
	live := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(existing), live); err != nil {
		t.Fatal(err)
	}
	err := applyOwnedMetadata(context.Background(), base, live, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "ssa-conflict", Namespace: "default", Labels: map[string]string{"managed": "operator-value"},
	}})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("foreign metadata conflict error = %v, want SSA conflict", err)
	}
	got := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(existing), got); err != nil {
		t.Fatal(err)
	}
	if got.Labels["managed"] != "foreign-value" {
		t.Fatalf("foreign metadata changed after conflict: %v", got.Labels)
	}
}

func TestServerSideApplyMigratesEscapedUpdateOwnedMetadata(t *testing.T) {
	scheme := runtimeSchemeForServerSideApplyTest(t)
	existing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      "ssa-escaped-update",
		Namespace: "default",
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "legacy-manager",
			"foreign.example/keep":         "yes",
		},
		ManagedFields: []metav1.ManagedFieldsEntry{{
			Manager:    "foreign-update",
			Operation:  metav1.ManagedFieldsOperationUpdate,
			APIVersion: "v1",
			FieldsType: "FieldsV1",
			FieldsV1: metav1.NewFieldsV1(
				`{"f:metadata":{"f:labels":{"f:app.kubernetes.io~1managed-by":{},"f:foreign.example~1keep":{}}}}`,
			),
		}},
	}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).WithReturnManagedFields().Build()
	live := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(existing), live); err != nil {
		t.Fatal(err)
	}

	desired := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      existing.Name,
		Namespace: existing.Namespace,
		Labels:    map[string]string{labelAppManagedBy: operatorName},
	}}
	if err := applyOwnedMetadata(context.Background(), base, live, desired); err != nil {
		t.Fatal(err)
	}

	got := &corev1.Secret{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(existing), got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[labelAppManagedBy] != operatorName || got.Labels["foreign.example/keep"] != "yes" {
		t.Fatalf("labels after escaped Update migration = %v", got.Labels)
	}
	ownedLabels, _ := appliedOwnedMetadata(got)
	if !maps.Equal(ownedLabels, map[string]string{labelAppManagedBy: operatorName}) {
		t.Fatalf("SSA-owned labels after escaped Update migration = %v", ownedLabels)
	}
}

func TestServerSideApplyMapLevelOwnershipDoesNotChurnForeignKeys(t *testing.T) {
	object := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Labels: map[string]string{"owned": "yes", "foreign": "keep"},
		ManagedFields: []metav1.ManagedFieldsEntry{{
			Manager:    garageOperatorFieldManager,
			Operation:  metav1.ManagedFieldsOperationApply,
			APIVersion: "v1",
			FieldsType: "FieldsV1",
			FieldsV1:   metav1.NewFieldsV1(`{"f:metadata":{"f:labels":{".":{},"f:owned":{}}}}`),
		}},
	}}
	desired := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"owned": "yes"}}}
	if metadataNeedsApply(object, desired) {
		t.Fatal("map-level ownership caused a foreign metadata no-op to require apply")
	}
	labels, annotations := appliedOwnedMetadata(object)
	if !maps.Equal(labels, map[string]string{"owned": "yes"}) || len(annotations) != 0 {
		t.Fatalf("applied metadata = labels %v annotations %v, want only owned key", labels, annotations)
	}
}

func runtimeSchemeForServerSideApplyTest(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}
