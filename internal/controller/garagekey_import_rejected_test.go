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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Garage v2.0 to v2.2 answer 400 to an ImportKey whose ID or secret is not the
// shape Garage generates. The text must reach the Ready condition with its own
// reason, name the grammar of each Garage line, say which Garage version the
// cluster reports, and never carry credential material.
func TestImportKeyRejectedSurfacesGarage400InReadyCondition(t *testing.T) {
	const (
		keyID     = "AKIAIOSFODNN7EXAMPLE"
		keySecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		garageMsg = "The specified key ID is not a valid Garage key ID (starts with `GK`, followed by 12 hex-encoded bytes)"
	)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-key", Namespace: "tenant", UID: "aws-key-uid", Generation: 2},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			AccessKeyID: keyID, SecretAccessKey: keySecret,
		}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).WithObjects(key).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}

	// Garage echoes the secret in no response, but a hostile or buggy proxy
	// might: the redaction must hold anyway.
	body := `{"code":"InvalidRequest","message":"` + garageMsg + ` (secret ` + keySecret + `)","path":"/v2/ImportKey"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/GetKeyInfo":
			w.WriteHeader(http.StatusNotFound)
		case "/v2/ImportKey":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cluster := &garagev1beta2.GarageCluster{Status: garagev1beta2.GarageClusterStatus{
		BuildInfo: &garagev1beta2.GarageBuildInfo{Version: "v2.2.0"},
	}}
	_, _, err := reconciler.importKey(t.Context(), key, garage.NewClient(server.URL, "token"), key.Name)
	err = annotateImportKeyRejection(err, cluster)
	if err == nil {
		t.Fatal("ImportKey 400 returned no error")
	}
	if !garage.IsBadRequest(err) {
		t.Errorf("the rejection must still unwrap to the Garage APIError: %v", err)
	}

	if _, updateErr := reconciler.updateStatus(t.Context(), key, PhaseFailed, err); updateErr != nil {
		t.Fatal(updateErr)
	}
	stored := &garagev1beta1.GarageKey{}
	if getErr := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(key), stored); getErr != nil {
		t.Fatal(getErr)
	}
	ready := meta.FindStatusCondition(stored.Status.Conditions, PhaseReady)
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %+v", ready)
	}
	if ready.Reason != garagev1beta1.ReasonImportKeyRejected {
		t.Errorf("reason = %q, want %q", ready.Reason, garagev1beta1.ReasonImportKeyRejected)
	}
	for _, want := range []string{"HTTP 400", garageMsg, "GK", "24 hex", "at least 8 characters", "Garage v2.2.0", "<redacted>"} {
		if !strings.Contains(ready.Message, want) {
			t.Errorf("message missing %q: %s", want, ready.Message)
		}
	}
	if strings.Contains(ready.Message, keySecret) {
		t.Errorf("credential material leaked into the condition: %s", ready.Message)
	}
	if strings.Contains(ready.Message, `"code"`) {
		t.Errorf("the raw JSON body must be reduced to Garage's message: %s", ready.Message)
	}
}

func TestImportKeyNon400ErrorsKeepReconcileFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/GetKeyInfo" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = garagev1beta1.AddToScheme(scheme)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: "tenant", UID: "k-uid"},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			AccessKeyID: "GK0123456789abcdef01234567", SecretAccessKey: strings.Repeat("ab", 32),
		}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).WithObjects(key).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}

	_, _, err := reconciler.importKey(t.Context(), key, garage.NewClient(server.URL, "token"), key.Name)
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, updateErr := reconciler.updateStatus(t.Context(), key, PhaseFailed, annotateImportKeyRejection(err, nil)); updateErr != nil {
		t.Fatal(updateErr)
	}
	stored := &garagev1beta1.GarageKey{}
	if getErr := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(key), stored); getErr != nil {
		t.Fatal(getErr)
	}
	if ready := meta.FindStatusCondition(stored.Status.Conditions, PhaseReady); ready == nil ||
		ready.Reason != garagev1beta1.ReasonReconcileFailed {
		t.Fatalf("a non-400 failure must keep ReconcileFailed, got %+v", ready)
	}
}
