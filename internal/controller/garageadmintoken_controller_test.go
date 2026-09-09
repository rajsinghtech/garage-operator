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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func garageAdminTokenTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
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

func garageAdminTokenFixture() (*garagev1beta1.GarageAdminToken, *garagev1beta2.GarageCluster) {
	token := &garagev1beta1.GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap-source", Namespace: testGarageValue, UID: types.UID("token-uid")},
		Spec: garagev1beta1.GarageAdminTokenSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: "store"},
			SecretTemplate: &garagev1beta1.AdminTokenSecretTemplate{
				Name: "garage-admin-bootstrap", TokenKey: DefaultAdminTokenKey,
			},
		},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: token.Namespace, UID: types.UID("cluster-uid")},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: token.Spec.SecretTemplate.Name},
				Key:                  DefaultAdminTokenKey,
			},
		}},
	}
	return token, cluster
}

func garageAdminTokenTestReconciler(t *testing.T, objects ...client.Object) (*GarageAdminTokenReconciler, client.Client) {
	t.Helper()
	scheme := garageAdminTokenTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return &GarageAdminTokenReconciler{Client: c, Scheme: scheme, ClusterDomain: "cluster.local"}, c
}

func TestGarageAdminTokenCreatesImmutableHashedSource(t *testing.T) {
	token, cluster := garageAdminTokenFixture()
	r, c := garageAdminTokenTestReconciler(t, cluster)
	if err := r.reconcileSecret(context.Background(), token, cluster); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: token.Spec.SecretTemplate.Name, Namespace: token.Namespace}
	if err := c.Get(context.Background(), key, secret); err != nil {
		t.Fatal(err)
	}
	if secret.Immutable == nil || !*secret.Immutable {
		t.Fatal("generated static bootstrap source is mutable")
	}
	raw := secret.Data[DefaultAdminTokenKey]
	if len(raw) == 0 || token.Status.TokenDigest != staticBootstrapTokenDigest(raw) ||
		secret.Annotations[annotationStaticBootstrapTokenDigest] != token.Status.TokenDigest {
		t.Fatalf("generated source did not persist its full integrity digest: status=%+v annotations=%v", token.Status, secret.Annotations)
	}
	if strings.Contains(token.Status.TokenID, string(raw[:8])) || !strings.HasPrefix(token.Status.TokenID, "sha256:") {
		t.Fatalf("status.tokenId exposed bearer bytes instead of a hash fingerprint: %q", token.Status.TokenID)
	}
}

func TestGarageAdminTokenRefusesUnownedSecretCollision(t *testing.T) {
	token, cluster := garageAdminTokenFixture()
	collision := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: token.Spec.SecretTemplate.Name, Namespace: token.Namespace,
	}, Data: map[string][]byte{DefaultAdminTokenKey: []byte(strings.Repeat("a", 64))}}
	r, _ := garageAdminTokenTestReconciler(t, cluster, collision)
	if err := r.reconcileSecret(context.Background(), token, cluster); err == nil || !strings.Contains(err.Error(), "refusing to read, overwrite, or adopt") {
		t.Fatalf("unowned Secret collision was adopted or exposed: %v", err)
	}
}

func TestGarageAdminTokenPreservesForeignSecretMetadata(t *testing.T) {
	token, cluster := garageAdminTokenFixture()
	r, c := garageAdminTokenTestReconciler(t, cluster)
	ctx := context.Background()
	key := types.NamespacedName{Name: token.Spec.SecretTemplate.Name, Namespace: token.Namespace}
	reconcileAndGet := func() *corev1.Secret {
		t.Helper()
		if err := r.reconcileSecret(ctx, token, cluster); err != nil {
			t.Fatal(err)
		}
		secret := &corev1.Secret{}
		if err := c.Get(ctx, key, secret); err != nil {
			t.Fatal(err)
		}
		return secret
	}

	// Another controller stamps its own metadata on the generated Secret, as
	// Kyverno does on every clone source.
	secret := reconcileAndGet()
	secret.Labels["example.com/foreign"] = "keep"
	secret.Annotations["generate.kyverno.io/clone-source"] = ""
	if err := c.Update(ctx, secret); err != nil {
		t.Fatal(err)
	}

	secret = reconcileAndGet()
	if _, foreignAnnotation := secret.Annotations["generate.kyverno.io/clone-source"]; !foreignAnnotation ||
		secret.Labels["example.com/foreign"] != "keep" ||
		secret.Labels[labelAppManagedBy] != "garage-operator" ||
		secret.Annotations[annotationStaticBootstrapTokenDigest] != token.Status.TokenDigest {
		t.Fatalf("reconcile did not merge metadata: labels=%v annotations=%v", secret.Labels, secret.Annotations)
	}

	// A converged Secret must not be rewritten, or the Owns() watch re-fires
	// and the operator loops against the foreign controller forever.
	if before := secret.ResourceVersion; reconcileAndGet().ResourceVersion != before {
		t.Fatalf("no-op reconcile rewrote the Secret (resourceVersion %s)", before)
	}
}

func TestGarageAdminTokenLegacySourceMigratesOnceThenFailsClosedOnDrift(t *testing.T) {
	token, cluster := garageAdminTokenFixture()
	raw := []byte(strings.Repeat("ab", 32))
	token.Status.TokenID = string(raw[:8]) + "..."
	controller := true
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: token.Spec.SecretTemplate.Name, Namespace: token.Namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageAdminToken,
				Name: token.Name, UID: token.UID, Controller: &controller,
			}},
		},
		Data: map[string][]byte{DefaultAdminTokenKey: raw},
	}
	r, c := garageAdminTokenTestReconciler(t, cluster, legacy)
	if err := r.reconcileSecret(context.Background(), token, cluster); err != nil {
		t.Fatalf("valid legacy source did not migrate to immutable digest contract: %v", err)
	}
	migrated := &corev1.Secret{}
	key := types.NamespacedName{Name: legacy.Name, Namespace: legacy.Namespace}
	if err := c.Get(context.Background(), key, migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Immutable == nil || !*migrated.Immutable || token.Status.TokenDigest == "" {
		t.Fatalf("legacy migration did not establish immutable integrity state: secret=%+v status=%+v", migrated, token.Status)
	}

	drifted := migrated.DeepCopy()
	drifted.Data[DefaultAdminTokenKey] = []byte(strings.Repeat("cd", 32))
	if err := validateGarageAdminTokenSecretDigest(token, drifted, drifted.Data[DefaultAdminTokenKey]); err == nil || !strings.Contains(err.Error(), "status.tokenDigest") {
		t.Fatalf("post-migration credential drift was accepted: %v", err)
	}
}

func TestGarageAdminTokenFinalizerWaitsForDereferenceAndHandlesMissingCluster(t *testing.T) {
	token, cluster := garageAdminTokenFixture()
	controller := true
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: token.Spec.SecretTemplate.Name, Namespace: token.Namespace,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageAdminToken,
			Name: token.Name, UID: token.UID, Controller: &controller,
		}},
	}}
	r, c := garageAdminTokenTestReconciler(t, cluster, secret)
	if err := r.finalize(context.Background(), token); err == nil || !strings.Contains(err.Error(), "still consumes") {
		t.Fatalf("live cluster reference did not hold the static source finalizer: %v", err)
	}
	cluster.Spec.Admin.AdminTokenSecretRef.Name = "replacement"
	if err := c.Update(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if err := r.finalize(context.Background(), token); err != nil {
		t.Fatalf("dereferenced source did not finalize: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned dereferenced Secret still exists: %v", err)
	}

	missingClusterToken, _ := garageAdminTokenFixture()
	missingClusterSecret := secret.DeepCopy()
	missingClusterSecret.ResourceVersion = ""
	r, c = garageAdminTokenTestReconciler(t, missingClusterSecret)
	if err := r.finalize(context.Background(), missingClusterToken); err != nil {
		t.Fatalf("missing GarageCluster stranded the token finalizer: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(missingClusterSecret), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("missing-cluster source Secret still exists: %v", err)
	}
}
