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
	"encoding/hex"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

const (
	garageAdminTokenFinalizer = "garageadmintoken.garage.rajsingh.info/finalizer"
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

	// Get the cluster reference (for context/validation)
	cluster := &garagev1beta1.GarageCluster{}
	clusterNamespace := token.Namespace
	if token.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = token.Spec.ClusterRef.Namespace
	}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      token.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		if errors.IsNotFound(err) {
			return r.updateStatusWaiting(ctx, token)
		}
		return r.updateStatus(ctx, token, PhaseFailed, fmt.Errorf("cluster not found: %w", err))
	}

	// Handle deletion
	if !token.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(token, garageAdminTokenFinalizer) {
			if err := r.finalize(ctx, token); err != nil {
				log.Error(err, "Failed to finalize admin token, will retry")
				// Surface the finalization error in status before requeuing
				_, _ = r.updateStatus(ctx, token, "Deleting", fmt.Errorf("finalization failed: %w", err))
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
			controllerutil.RemoveFinalizer(token, garageAdminTokenFinalizer)
			if err := r.Update(ctx, token); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
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
		if isTransientConnectivityError(err) {
			return r.updateStatusWaiting(ctx, token)
		}
		return r.updateStatus(ctx, token, PhaseFailed, err)
	}

	// Check expiration
	if token.Spec.ExpiresAt != nil && !token.Spec.NeverExpires && time.Now().After(token.Spec.ExpiresAt.Time) {
		token.Status.Expired = true
		return r.updateStatus(ctx, token, "Expired", nil)
	}

	return r.updateStatus(ctx, token, PhaseReady, nil)
}

func (r *GarageAdminTokenReconciler) reconcileSecret(ctx context.Context, token *garagev1beta1.GarageAdminToken, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)

	// Determine secret name and namespace
	secretName := token.Name
	secretNamespace := token.Namespace
	if token.Spec.SecretTemplate != nil {
		if token.Spec.SecretTemplate.Name != "" {
			secretName = token.Spec.SecretTemplate.Name
		}
	}

	// Determine key names
	tokenKey := DefaultAdminTokenKey
	endpointKey := "admin-endpoint"
	if token.Spec.SecretTemplate != nil {
		if token.Spec.SecretTemplate.TokenKey != "" {
			tokenKey = token.Spec.SecretTemplate.TokenKey
		}
		if token.Spec.SecretTemplate.EndpointKey != "" {
			endpointKey = token.Spec.SecretTemplate.EndpointKey
		}
	}

	// Check if secret exists
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, existing)
	secretExists := err == nil

	var adminToken string
	if secretExists && len(existing.Data[tokenKey]) > 0 {
		// Reuse existing token
		adminToken = string(existing.Data[tokenKey])
		log.Info("Using existing admin token from secret", "secret", secretName)
	} else {
		// Generate new token
		adminToken, err = generateSecureToken(32)
		if err != nil {
			return fmt.Errorf("failed to generate admin token: %w", err)
		}
		log.Info("Generated new admin token", "secret", secretName)
	}

	// Store token ID (just use first 8 chars as identifier)
	if len(adminToken) >= 8 {
		token.Status.TokenID = adminToken[:8] + "..."
	}

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
		adminPort := int32(3903)
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		secretData[endpointKey] = []byte(endpoint)
	}

	// Build labels
	labels := map[string]string{
		labelAppManagedBy:                 "garage-operator",
		"garage.rajsingh.info/admintoken": token.Name,
	}
	if token.Spec.SecretTemplate != nil && token.Spec.SecretTemplate.Labels != nil {
		for k, v := range token.Spec.SecretTemplate.Labels {
			labels[k] = v
		}
	}

	// Build annotations
	annotations := map[string]string{}
	if token.Spec.SecretTemplate != nil && token.Spec.SecretTemplate.Annotations != nil {
		annotations = token.Spec.SecretTemplate.Annotations
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   secretNamespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
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
		// Update secret
		existing.Data = secretData
		existing.Labels = labels
		existing.Annotations = annotations
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

	// Delete the secret if it exists and is in the same namespace
	if token.Status.SecretRef == nil {
		return nil
	}

	// Only delete if in same namespace (we own it)
	if token.Status.SecretRef.Namespace != token.Namespace {
		log.Info("Secret in different namespace, not deleting", "secret", token.Status.SecretRef.Name)
		return nil
	}

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      token.Status.SecretRef.Name,
		Namespace: token.Status.SecretRef.Namespace,
	}, secret)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Check if we own this secret
	for _, ref := range secret.OwnerReferences {
		if ref.UID == token.UID {
			log.Info("Deleting admin token secret", "name", secret.Name)
			return r.Delete(ctx, secret)
		}
	}

	return nil
}

func (r *GarageAdminTokenReconciler) updateStatusWaiting(ctx context.Context, token *garagev1beta1.GarageAdminToken) (ctrl.Result, error) {
	token.Status.Phase = PhasePending
	meta.SetStatusCondition(&token.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonClusterNotReady,
		Message:            msgWaitingForCluster,
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

	token.Status.ExpiresAt = token.Spec.ExpiresAt

	conditionStatus := metav1.ConditionTrue
	reason := "TokenReady"
	message := "Admin token is ready"

	if err != nil {
		conditionStatus = metav1.ConditionFalse
		reason = garagev1beta1.ReasonReconcileFailed
		message = err.Error()
	} else if token.Status.Expired {
		conditionStatus = metav1.ConditionFalse
		reason = "Expired"
		message = "Admin token has expired"
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

	// If token has expiration, requeue before it expires
	if token.Spec.ExpiresAt != nil && !token.Status.Expired {
		until := time.Until(token.Spec.ExpiresAt.Time)
		if until > 0 {
			return ctrl.Result{RequeueAfter: until + time.Minute}, nil
		}
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
