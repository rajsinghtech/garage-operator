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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestGetOrCreateKeyRecoversExactDeterministicSecretWhenGarageOmitsIt(t *testing.T) {
	const namespace = "tenant"
	rpcSecretHex := strings.Repeat("a1", 32)
	rpcSecret, err := hex.DecodeString(rpcSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	accessKeyID, expectedSecret := deriveKeyMaterial(rpcSecret, namespace, "app-key")
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "app-key", Namespace: namespace},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: accessKeyID},
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: namespace}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		key,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: managedRPCSecretName(cluster), Namespace: namespace},
			Data:       map[string][]byte{RPCSecretKey: []byte(rpcSecretHex)},
		},
	).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/GetKeyInfo" || req.URL.Query().Get("id") != accessKeyID || req.URL.Query().Get("showSecretKey") != "true" {
			t.Errorf("unexpected GetKey request: %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Model Garage returning the key identity but omitting the one-time secret.
		_ = json.NewEncoder(w).Encode(garage.Key{AccessKeyID: accessKeyID, Name: key.Name})
	}))
	defer server.Close()

	got, secret, err := reconciler.getOrCreateKey(context.Background(), key, cluster, garage.NewClient(server.URL, "token"), key.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != accessKeyID || secret != expectedSecret {
		t.Fatalf("recovered key ID=%q and secret match=%t, want exact deterministic identity", got.AccessKeyID, secret == expectedSecret)
	}
	if got := reconciler.recoverSecretAccessKey(context.Background(), key, cluster, accessKeyID+"-other"); got != "" {
		t.Fatal("recovery returned credential material for a different remote key ID")
	}

	legacyKey := key.DeepCopy()
	legacyKey.Spec.Name = "old-display-name"
	legacyID, legacySecret := deriveKeyMaterial(rpcSecret, namespace, legacyKey.Spec.Name)
	legacyKey.Status.AccessKeyID = legacyID
	if got := reconciler.recoverSecretAccessKey(context.Background(), legacyKey, cluster, legacyID); got != legacySecret {
		t.Fatal("recovery did not support the exact legacy spec.name-bound identity")
	}
}

func TestRecoverSecretAccessKeyUsesImmutableImportSnapshotOnly(t *testing.T) {
	const (
		namespace = "tenant"
		keyID     = "GKimported"
		secret    = "snapshot-test-material"
	)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "imported", Namespace: namespace, UID: types.UID("imported-uid")},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			SecretRef: &corev1.SecretReference{Name: "source"},
		}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	immutable := true
	snapshot := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      importKeySnapshotName(key),
			Namespace: namespace,
			Labels:    map[string]string{keyImportSnapshotLabel: keyImportSnapshotLabelValue},
		},
		Immutable: &immutable,
		Data: map[string][]byte{
			defaultAccessKeyIDKey:     []byte(keyID),
			defaultSecretAccessKeyKey: []byte(secret),
		},
	}
	if err := controllerutil.SetControllerReference(key, snapshot, scheme); err != nil {
		t.Fatal(err)
	}
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: namespace},
		Data: map[string][]byte{
			defaultAccessKeyIDKey:     []byte(keyID),
			defaultSecretAccessKeyKey: []byte("mutable-source-material"),
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, snapshot, source).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}

	if got := reconciler.recoverSecretAccessKey(context.Background(), key, nil, keyID); got != secret {
		t.Fatalf("recovered material match=%t, want immutable snapshot material", got == secret)
	}

	if err := kubeClient.Delete(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.recoverSecretAccessKey(context.Background(), key, nil, keyID); got != "" {
		t.Fatal("recovery used mutable import source after the immutable snapshot was removed")
	}
}

func TestReconcileSecretRefusesToPublishMissingSecretAccessKey(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "app-key", Namespace: testNamespace, UID: types.UID("app-key-uid")},
		Spec: garagev1beta1.GarageKeySpec{SecretTemplate: &garagev1beta1.SecretTemplate{
			IncludeEndpoint: boolPtr(false),
			IncludeRegion:   boolPtr(false),
		}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: "GKowned"},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: testNamespace}}

	err := reconciler.reconcileSecret(context.Background(), key, cluster, "")
	if err == nil || !strings.Contains(err.Error(), "without recoverable secret access key material") {
		t.Fatalf("err = %v, want fail-closed missing-credential error", err)
	}
	secret := &corev1.Secret{}
	if getErr := kubeClient.Get(context.Background(), client.ObjectKey{Name: key.Name, Namespace: key.Namespace}, secret); getErr == nil {
		t.Fatal("reconcile created a partial credential Secret")
	} else if !apierrors.IsNotFound(getErr) {
		t.Fatalf("Secret lookup error = %v, want NotFound", getErr)
	}
}

func TestReconcileSecretLeavesOwnedPartialSecretUntouched(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "app-key", Namespace: testNamespace, UID: types.UID("app-key-uid")},
		Spec: garagev1beta1.GarageKeySpec{SecretTemplate: &garagev1beta1.SecretTemplate{
			IncludeEndpoint: boolPtr(false),
			IncludeRegion:   boolPtr(false),
		}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: "GKowned"},
	}
	cfg := resolveSecretConfig(key)
	cfg.labels[keyGeneratedSecretOwnerLabel] = string(key.UID)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cfg.name, Namespace: cfg.namespace, Labels: cfg.labels},
		Data:       map[string][]byte{cfg.accessKeyIDKey: []byte(key.Status.AccessKeyID)},
	}
	if err := controllerutil.SetControllerReference(key, existing, scheme); err != nil {
		t.Fatal(err)
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, existing).Build()
	reconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: testNamespace}}

	err := reconciler.reconcileSecret(context.Background(), key, cluster, "")
	if err == nil || !strings.Contains(err.Error(), "without recoverable secret access key material") {
		t.Fatalf("err = %v, want fail-closed missing-credential error", err)
	}
	got := &corev1.Secret{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(existing), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 1 || string(got.Data[cfg.accessKeyIDKey]) != key.Status.AccessKeyID {
		t.Fatalf("partial Secret changed after failed reconcile: data key count=%d", len(got.Data))
	}
}
