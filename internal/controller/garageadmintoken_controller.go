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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	garageAdminTokenFinalizer            = "garageadmintoken.garage.rajsingh.info/finalizer"
	annotationStaticBootstrapTokenDigest = "garage.rajsingh.info/static-bootstrap-token-sha256"
)

// GarageAdminTokenReconciler reconciles a GarageAdminToken object
type GarageAdminTokenReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClusterDomain string
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageadmintokens,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageadmintokens/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageadmintokens/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *GarageAdminTokenReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	token := &garagev1beta1.GarageAdminToken{}
	if err := r.Get(ctx, req.NamespacedName, token); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if token.DeletionTimestamp.IsZero() {
		if err := garagev1beta1.ValidateClusterReference(token.Spec.ClusterRef, "spec.clusterRef"); err != nil {
			return r.updateStatus(ctx, token, PhaseFailed, err)
		}
		if token.Spec.ClusterRef.Namespace != "" && token.Spec.ClusterRef.Namespace != token.Namespace {
			return r.updateStatus(ctx, token, PhaseFailed, fmt.Errorf(
				"spec.clusterRef.namespace must match metadata.namespace: GarageAdminToken provisions namespace-local static bootstrap material",
			))
		}
		if err := garagev1beta1.ValidateGarageAdminTokenMaterialSpec(token); err != nil {
			return r.updateStatus(ctx, token, PhaseFailed, err)
		}
	}

	// Deletion must run before resolving the cluster. A cluster that was already
	// removed cannot be allowed to strand this resource's finalizer and Secret.
	if !token.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(token, garageAdminTokenFinalizer) {
			if err := r.finalize(ctx, token); err != nil {
				log.Error(err, "Failed to finalize admin token, will retry")
				_, _ = r.updateStatus(ctx, token, PhaseDeleting, fmt.Errorf("finalization failed: %w", err))
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
			controllerutil.RemoveFinalizer(token, garageAdminTokenFinalizer)
			if err := r.Update(ctx, token); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Get the cluster reference (for context/validation)
	cluster := &garagev1beta2.GarageCluster{}
	clusterNamespace := token.Namespace
	if token.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = token.Spec.ClusterRef.Namespace
	}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      token.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		if errors.IsNotFound(err) {
			return r.updateStatusWaiting(ctx, token, nil)
		}
		return r.updateStatus(ctx, token, PhaseFailed, fmt.Errorf("cluster not found: %w", err))
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(token, garageAdminTokenFinalizer) {
		controllerutil.AddFinalizer(token, garageAdminTokenFinalizer)
		if err := r.Update(ctx, token); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the admin token secret
	if err := r.reconcileSecret(ctx, token, cluster); err != nil {
		// The same transient-looking error shape also covers a permanent
		// misconfiguration (e.g. an unresolvable cluster-domain) that will
		// retry forever without ever becoming a PhaseFailed, so keep the real
		// error text on the condition — it's the only place that distinction
		// is visible to the user.
		if isTransientConnectivityError(err) {
			return r.updateStatusWaiting(ctx, token, err)
		}
		return r.updateStatus(ctx, token, PhaseFailed, err)
	}

	return r.updateStatus(ctx, token, PhaseReady, nil)
}

func (r *GarageAdminTokenReconciler) reconcileSecret(ctx context.Context, token *garagev1beta1.GarageAdminToken, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	if token.Spec.ClusterRef.Namespace != "" && token.Spec.ClusterRef.Namespace != token.Namespace {
		return fmt.Errorf("cross-namespace GarageAdminToken is unsupported for static bootstrap material")
	}
	if token.Spec.Name != "" || token.Spec.ExpiresAt != nil {
		return fmt.Errorf("spec.name and spec.expiresAt are unsupported: GarageAdminToken provisions static bootstrap material, not a Garage-assigned token row")
	}

	secretName, tokenKey := garageAdminTokenSecretIdentity(token)
	secretNamespace := token.Namespace

	// Determine the optional endpoint key.
	endpointKey := "admin-endpoint"
	if token.Spec.SecretTemplate != nil {
		if token.Spec.SecretTemplate.EndpointKey != "" {
			endpointKey = token.Spec.SecretTemplate.EndpointKey
		}
	}
	if !garageClusterConsumesAdminTokenSource(cluster, token) {
		if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
			return fmt.Errorf("garageCluster %s/%s must set spec.admin.adminTokenSecretRef to generated Secret %q before this static bootstrap token can be used", cluster.Namespace, cluster.Name, secretName)
		}
		return fmt.Errorf("garageCluster %s/%s does not consume this static bootstrap source: spec.admin.adminTokenSecretRef must be %s/%s:%s", cluster.Namespace, cluster.Name, token.Namespace, secretName, tokenKey)
	}

	// Check if secret exists
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, existing)
	secretExists := err == nil
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("checking static bootstrap Secret: %w", err)
	}
	if secretExists && !metav1.IsControlledBy(existing, token) {
		return fmt.Errorf("secret %s/%s already exists without this GarageAdminToken as its exact controller; refusing to read, overwrite, or adopt the collision", secretNamespace, secretName)
	}

	var adminToken string
	if secretExists {
		raw, ok := existing.Data[tokenKey]
		if !ok || len(raw) == 0 {
			return fmt.Errorf("owned static bootstrap Secret %s/%s lost token key %q; restore it instead of silently generating a new cluster credential", secretNamespace, secretName, tokenKey)
		}
		// Reuse existing token
		canonical, err := canonicalStaticBearer(raw)
		if err != nil {
			return fmt.Errorf("owned static bootstrap Secret %s/%s has an invalid token: %w", secretNamespace, secretName, err)
		}
		adminToken = string(canonical)
		if err := validateGarageAdminTokenSecretDigest(token, existing, canonical); err != nil {
			return fmt.Errorf("owned static bootstrap Secret %s/%s failed credential-integrity validation: %w", secretNamespace, secretName, err)
		}
		log.Info("Using existing admin token from secret", "secret", secretName)
	} else {
		// Generate new token
		adminToken, err = generateSecureToken(32)
		if err != nil {
			return fmt.Errorf("failed to generate admin token: %w", err)
		}
		log.Info("Generated new admin token", "secret", secretName)
	}

	digest := staticBootstrapTokenDigest([]byte(adminToken))
	// Preserve the public status field for compatibility, but never put bearer
	// bytes in it. The full digest is persisted separately for drift detection.
	token.Status.TokenID = shortStaticBootstrapFingerprint(digest)
	token.Status.TokenDigest = digest

	// Build secret data
	secretData := map[string][]byte{
		tokenKey: []byte(adminToken),
	}

	// Add endpoint if configured (defaults to true if not explicitly set to false)
	includeEndpoint := true
	if token.Spec.SecretTemplate != nil && token.Spec.SecretTemplate.IncludeEndpoint != nil {
		includeEndpoint = *token.Spec.SecretTemplate.IncludeEndpoint
	}
	if includeEndpoint {
		adminPort := getAdminPort(cluster)
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		secretData[endpointKey] = []byte(endpoint)
	}

	// Build labels
	labels := map[string]string{}
	if token.Spec.SecretTemplate != nil && token.Spec.SecretTemplate.Labels != nil {
		for k, v := range token.Spec.SecretTemplate.Labels {
			labels[k] = v
		}
	}
	labels[labelAppManagedBy] = "garage-operator"
	labels["garage.rajsingh.info/admintoken"] = token.Name

	// Build annotations
	annotations := map[string]string{}
	if token.Spec.SecretTemplate != nil && token.Spec.SecretTemplate.Annotations != nil {
		for key, value := range token.Spec.SecretTemplate.Annotations {
			annotations[key] = value
		}
	}
	annotations["garage.rajsingh.info/credential-kind"] = "static-bootstrap"
	annotations[annotationStaticBootstrapTokenDigest] = digest

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   secretNamespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque, Immutable: ptr.To(true), Data: secretData,
	}

	// Only set owner reference if in same namespace
	if secretNamespace == token.Namespace {
		if err := controllerutil.SetControllerReference(token, secret, r.Scheme); err != nil {
			return err
		}
	}

	if !secretExists {
		log.Info("Creating admin token secret", "name", secretName, "namespace", secretNamespace)
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	} else {
		// An immutable source cannot be silently rotated by a generic Secret
		// writer. Metadata remains reconcilable, but any data drift after the
		// immutable contract was established fails closed.
		if existing.Immutable != nil && *existing.Immutable && !equality.Semantic.DeepEqual(existing.Data, secretData) {
			return fmt.Errorf("immutable static bootstrap Secret %s/%s data differs from its declared contract; create a replacement GarageAdminToken and rotate the GarageCluster reference", secretNamespace, secretName)
		}
		if equality.Semantic.DeepEqual(existing.Data, secretData) &&
			equality.Semantic.DeepEqual(existing.Labels, labels) &&
			equality.Semantic.DeepEqual(existing.Annotations, annotations) && existing.Type == secret.Type &&
			existing.Immutable != nil && *existing.Immutable {
			token.Status.SecretRef = &corev1.SecretReference{Name: secretName, Namespace: secretNamespace}
			return nil
		}
		existing.Data = secretData
		existing.Labels = labels
		existing.Annotations = annotations
		existing.Type = secret.Type
		existing.Immutable = ptr.To(true)
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
	}

	token.Status.SecretRef = &corev1.SecretReference{
		Name:      secretName,
		Namespace: secretNamespace,
	}

	return nil
}

func (r *GarageAdminTokenReconciler) finalize(ctx context.Context, token *garagev1beta1.GarageAdminToken) error {
	log := logf.FromContext(ctx)
	clusterNamespace := token.Namespace
	if token.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = token.Spec.ClusterRef.Namespace
	}
	cluster := &garagev1beta2.GarageCluster{}
	err := r.Get(ctx, types.NamespacedName{Name: token.Spec.ClusterRef.Name, Namespace: clusterNamespace}, cluster)
	if err == nil && garageClusterConsumesAdminTokenSource(cluster, token) {
		secretName, tokenKey := garageAdminTokenSecretIdentity(token)
		return fmt.Errorf("garageCluster %s/%s still consumes Secret %s/%s:%s; rotate or remove spec.admin.adminTokenSecretRef before deleting its source", cluster.Namespace, cluster.Name, token.Namespace, secretName, tokenKey)
	}
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("checking whether GarageCluster still consumes static bootstrap material: %w", err)
	}

	// Derive the Secret from immutable spec identity so a crash before the first
	// status write cannot orphan it. Status is accepted only when it points to
	// that same local object.
	secretName, _ := garageAdminTokenSecretIdentity(token)
	if token.Status.SecretRef != nil &&
		(token.Status.SecretRef.Namespace != token.Namespace || token.Status.SecretRef.Name != secretName) {
		return fmt.Errorf("status.secretRef %s/%s differs from immutable Secret identity %s/%s", token.Status.SecretRef.Namespace, token.Status.SecretRef.Name, token.Namespace, secretName)
	}

	secret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: token.Namespace}, secret)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	if metav1.IsControlledBy(secret, token) {
		log.Info("Deleting admin token secret", "name", secret.Name)
		return r.Delete(ctx, secret)
	}
	return fmt.Errorf("refusing to delete Secret %s/%s because it is no longer controlled by this GarageAdminToken", secret.Namespace, secret.Name)
}

func garageAdminTokenSecretIdentity(token *garagev1beta1.GarageAdminToken) (string, string) {
	name := token.Name
	key := DefaultAdminTokenKey
	if token.Spec.SecretTemplate != nil {
		if token.Spec.SecretTemplate.Name != "" {
			name = token.Spec.SecretTemplate.Name
		}
		if token.Spec.SecretTemplate.TokenKey != "" {
			key = token.Spec.SecretTemplate.TokenKey
		}
	}
	return name, key
}

func garageClusterConsumesAdminTokenSource(cluster *garagev1beta2.GarageCluster, token *garagev1beta1.GarageAdminToken) bool {
	if cluster == nil || token == nil || cluster.Namespace != token.Namespace ||
		cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return false
	}
	name, key := garageAdminTokenSecretIdentity(token)
	ref := cluster.Spec.Admin.AdminTokenSecretRef
	refKey := ref.Key
	if refKey == "" {
		refKey = DefaultAdminTokenKey
	}
	return ref.Name == name && refKey == key
}

func staticBootstrapTokenDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func shortStaticBootstrapFingerprint(digest string) string {
	const prefix = "sha256:"
	hexDigest := strings.TrimPrefix(digest, prefix)
	if len(hexDigest) > 12 {
		hexDigest = hexDigest[:12]
	}
	return prefix + hexDigest
}

func validateGarageAdminTokenSecretDigest(token *garagev1beta1.GarageAdminToken, secret *corev1.Secret, canonical []byte) error {
	actual := staticBootstrapTokenDigest(canonical)
	if token.Status.TokenDigest != "" && token.Status.TokenDigest != actual {
		return fmt.Errorf("status.tokenDigest is %q, actual digest is %q", token.Status.TokenDigest, actual)
	}
	if expected := secret.Annotations[annotationStaticBootstrapTokenDigest]; expected != "" && expected != actual {
		return fmt.Errorf("secret digest annotation is %q, actual digest is %q", expected, actual)
	}
	// Legacy releases stored the literal first eight bearer characters followed
	// by "..." in status.tokenId. Use that only as a one-time upgrade check,
	// then replace it with a SHA-256 fingerprint and persist the full digest.
	if token.Status.TokenDigest == "" && strings.HasSuffix(token.Status.TokenID, "...") {
		legacyPrefix := strings.TrimSuffix(token.Status.TokenID, "...")
		if legacyPrefix == "" || !strings.HasPrefix(string(canonical), legacyPrefix) {
			return fmt.Errorf("legacy status.tokenId does not match the current bearer prefix; refusing an unverifiable upgrade")
		}
	}
	return nil
}

// updateStatusWaiting records a ClusterNotReady wait. cause, when non-nil, is
// the connectivity error that triggered the wait; its text is folded into the
// condition message (see waitingForClusterMessage) so a permanent
// misconfiguration (e.g. an unresolvable cluster-domain) is visible on the CR
// itself rather than only in operator debug logs.
func (r *GarageAdminTokenReconciler) updateStatusWaiting(ctx context.Context, token *garagev1beta1.GarageAdminToken, cause error) (ctrl.Result, error) {
	token.Status.Phase = PhasePending
	meta.SetStatusCondition(&token.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonClusterNotReady,
		Message:            waitingForClusterMessage(cause),
		ObservedGeneration: token.Generation,
	})
	if statusErr := r.Status().Update(ctx, token); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
}

func (r *GarageAdminTokenReconciler) updateStatus(ctx context.Context, token *garagev1beta1.GarageAdminToken, phase string, err error) (ctrl.Result, error) {
	token.Status.Phase = phase
	token.Status.ObservedGeneration = token.Generation

	// Static configured tokens have no Garage-side expiry record.
	token.Status.ExpiresAt = nil

	conditionStatus := metav1.ConditionTrue
	reason := "StaticBootstrapReady"
	message := "Static Admin bootstrap material is ready and referenced by the GarageCluster; deletion does not revoke credentials already loaded by Garage"

	if err != nil {
		conditionStatus = metav1.ConditionFalse
		reason = garagev1beta1.ReasonReconcileFailed
		message = err.Error()
	}

	meta.SetStatusCondition(&token.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: token.Generation,
	})

	if statusErr := r.Status().Update(ctx, token); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageAdminTokenReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageAdminToken{}).
		Owns(&corev1.Secret{}).
		Named("garageadmintoken").
		Complete(r)
}
