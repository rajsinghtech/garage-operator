/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Garage's ImportKey answers KeyAlreadyExists for a deleted key's tombstone
// while GetKeyInfo hides it, so the conflict must name the real cause rather
// than a bare "could not be verified: 404".
func TestImportKeyConflictWithDeletedKeyNamesTombstone(t *testing.T) {
	const (
		keyID     = "GKdeletedbefore"
		keySecret = "deleted-key-secret-material"
	)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "reimport", Namespace: "tenant", UID: "reimport-uid"},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			AccessKeyID: keyID, SecretAccessKey: keySecret,
		}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key).Build()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/ImportKey":
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, _, err := (&GarageKeyReconciler{Client: kubeClient, Scheme: scheme}).importKey(t.Context(), key, garage.NewClient(server.URL, "token"), key.Name)
	if err == nil {
		t.Fatal("import of a tombstoned access key ID succeeded")
	}
	if !strings.Contains(err.Error(), "deleted key") || !strings.Contains(err.Error(), keyID) {
		t.Fatalf("error does not name the deleted-key cause: %v", err)
	}
}
