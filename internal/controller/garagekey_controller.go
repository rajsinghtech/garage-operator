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
	"bytes"
	"context"
	"fmt"
	"maps"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageKeyFinalizer = "garagekey.garage.rajsingh.info/finalizer"
)

// GarageKeyReconciler reconciles a GarageKey object
type GarageKeyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClusterDomain string
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *GarageKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	key := &garagev1beta1.GarageKey{}
	if err := r.Get(ctx, req.NamespacedName, key); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Get the cluster reference
	cluster := &garagev1beta1.GarageCluster{}
	clusterNamespace := key.Namespace
	if key.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = key.Spec.ClusterRef.Namespace
	}
	clusterErr := r.Get(ctx, types.NamespacedName{
		Name:      key.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster)

	// Handle deletion - check this early so we can handle cluster-gone case
	if !key.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
			// If cluster is gone, skip finalization and just remove finalizer
			if clusterErr != nil && errors.IsNotFound(clusterErr) {
				log.Info("Cluster is gone, skipping key finalization", "cluster", key.Spec.ClusterRef.Name)
				controllerutil.RemoveFinalizer(key, garageKeyFinalizer)
				if err := r.Update(ctx, key); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
		}
	}

	// Now check cluster error for non-deletion cases
	if clusterErr != nil {
		if errors.IsNotFound(clusterErr) {
			return r.updateStatusWaiting(ctx, key)
		}
		return r.updateStatus(ctx, key, "Error", fmt.Errorf("cluster not found: %w", clusterErr))
	}

	// Guard against calling the Garage API before the cluster layout has converged.
	if !key.DeletionTimestamp.IsZero() {
		// Allow deletions to proceed regardless of cluster health.
	} else if cluster.Status.Phase != PhaseRunning {
		msg := "waiting for cluster to reach Running phase"
		meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ClusterNotReady",
			Message:            msg,
			ObservedGeneration: key.Generation,
		})
		key.Status.Phase = PhasePending
		if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// Get garage client
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return r.updateStatus(ctx, key, "Error", fmt.Errorf("failed to create garage client: %w", err))
	}

	// Handle deletion (cluster exists at this point)
	if !key.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
			if err := r.finalize(ctx, key, garageClient); err != nil {
				// Check if we've exceeded max retries
				if ShouldSkipFinalization(key) {
					log.Info("Finalization failed too many times, removing finalizer anyway",
						"retries", GetFinalizationRetryCount(key), "error", err)
				} else {
					IncrementFinalizationRetryCount(key)
					log.Error(err, "Failed to finalize key, will retry",
						"retries", GetFinalizationRetryCount(key))
					// Surface the finalization error in status before requeuing
					_, _ = r.updateStatus(ctx, key, PhaseDeleting, fmt.Errorf("finalization failed: %w", err))
					if updateErr := r.Update(ctx, key); updateErr != nil {
						log.Error(updateErr, "Failed to update retry count annotation")
					}
					return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
				}
			}
			controllerutil.RemoveFinalizer(key, garageKeyFinalizer)
			if err := r.Update(ctx, key); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
		controllerutil.AddFinalizer(key, garageKeyFinalizer)
		if err := r.Update(ctx, key); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the key
	secretAccessKey, keyErr := r.reconcileKey(ctx, key, cluster, garageClient)

	// Transient connectivity errors (DNS not ready, connection refused) are
	// expected while the cluster Service is being created. Treat them as a
	// waiting state rather than a permanent error.
	if keyErr != nil && isTransientConnectivityError(keyErr) {
		return r.updateStatusWaiting(ctx, key)
	}

	// Only create/update the Kubernetes secret if the key was successfully created
	// (either in this reconciliation or previously). This prevents creating a secret
	// with incomplete data if key creation failed.
	if key.Status.AccessKeyID != "" {
		if err := r.reconcileSecret(ctx, key, cluster, secretAccessKey); err != nil {
			return r.updateStatus(ctx, key, PhaseError, err)
		}
	}

	// Now handle any key reconciliation error (permission issues)
	if keyErr != nil {
		return r.updateStatus(ctx, key, PhaseError, keyErr)
	}

	return r.updateStatusFromGarage(ctx, key, garageClient)
}

func (r *GarageKeyReconciler) reconcileKey(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta1.GarageCluster, garageClient *garage.Client) (string, error) {
	keyName := key.Name
	if key.Spec.Name != "" {
		keyName = key.Spec.Name
	}

	garageKey, secretAccessKey, err := r.getOrCreateKey(ctx, key, cluster, garageClient, keyName)
	if err != nil {
		return "", err
	}

	key.Status.AccessKeyID = garageKey.AccessKeyID
	key.Status.KeyID = garageKey.AccessKeyID

	if err := r.reconcileAllBuckets(ctx, key, garageClient, garageKey); err != nil {
		return secretAccessKey, err
	}

	if err := r.reconcileBucketPermissions(ctx, key, garageClient, garageKey); err != nil {
		return secretAccessKey, err
	}

	return secretAccessKey, nil
}

func (r *GarageKeyReconciler) getOrCreateKey(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta1.GarageCluster, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)

	// If we already have an AccessKeyID in status, try to fetch that key
	if key.Status.AccessKeyID != "" {
		existing, err := garageClient.GetKey(ctx, garage.GetKeyRequest{
			ID:            key.Status.AccessKeyID,
			ShowSecretKey: true,
		})
		if err == nil {
			if err := r.updateKeyIfNeeded(ctx, key, garageClient, existing); err != nil {
				return nil, "", err
			}
			if existing.SecretAccessKey == "" {
				log.V(1).Info("Garage did not return secret key despite showSecretKey=true, preserving existing K8s secret",
					"accessKeyId", existing.AccessKeyID)
			}
			return existing, existing.SecretAccessKey, nil
		}
		// If key was not found (404), it was deleted externally - we can recreate it
		// For any other error (network, timeout, etc.), return the error to retry later
		// This prevents creating duplicate keys on transient failures
		if !garage.IsNotFound(err) {
			return nil, "", fmt.Errorf("failed to get existing key %s: %w", key.Status.AccessKeyID, err)
		}
		log.Info("Key not found in Garage, will search by name or create new", "accessKeyId", key.Status.AccessKeyID)
	}

	// Recover from external deletion: if status.AccessKeyID was just cleared (key deleted
	// in Garage externally), check for an existing key before creating a new one.
	existingKey, err := r.findKeyByName(ctx, garageClient, keyName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to search for existing key by name: %w", err)
	}
	if existingKey != nil {
		log.Info("Found existing key by name, adopting it", "name", keyName, "accessKeyId", existingKey.AccessKeyID)
		if err := r.updateKeyIfNeeded(ctx, key, garageClient, existingKey); err != nil {
			return nil, "", err
		}
		return existingKey, existingKey.SecretAccessKey, nil
	}

	if key.Spec.ImportKey != nil {
		return r.importKey(ctx, key, garageClient, keyName)
	}

	// Always use deterministic key derivation: derive (access_key_id, secret_access_key)
	// from the cluster's RPC secret (user-provided for federation, auto-generated otherwise).
	// This guarantees idempotent creation regardless of how many operators are running.
	return r.createOrAdoptDeterministic(ctx, key, cluster, garageClient, keyName)
}

// findKeyByName searches for an existing key with the given name
// Returns nil if no matching key is found or if multiple keys match (ambiguous)
func (r *GarageKeyReconciler) findKeyByName(ctx context.Context, garageClient *garage.Client, keyName string) (*garage.Key, error) {
	log := logf.FromContext(ctx)

	// List all keys and find exact name match
	keys, err := garageClient.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var matches []garage.KeyListItem
	for _, k := range keys {
		if k.Name == keyName {
			matches = append(matches, k)
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	if len(matches) > 1 {
		// Multiple keys share this name — legacy state from before deterministic creation.
		// Adopt the first match; the deterministic path prevents new duplicates.
		log.Info("Multiple keys found with same name, adopting first match",
			"name", keyName, "count", len(matches), "adoptingId", matches[0].ID)
	}

	// Fetch full key info including secret
	return garageClient.GetKey(ctx, garage.GetKeyRequest{
		ID:            matches[0].ID,
		ShowSecretKey: true,
	})
}

func (r *GarageKeyReconciler) importKey(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)
	log.Info("Importing existing key", "name", keyName)

	accessKeyID := key.Spec.ImportKey.AccessKeyID
	secretKey := key.Spec.ImportKey.SecretAccessKey

	if key.Spec.ImportKey.SecretRef != nil {
		importSecret := &corev1.Secret{}
		importNamespace := key.Spec.ImportKey.SecretRef.Namespace
		if importNamespace == "" {
			importNamespace = key.Namespace
		}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      key.Spec.ImportKey.SecretRef.Name,
			Namespace: importNamespace,
		}, importSecret); err != nil {
			return nil, "", fmt.Errorf("failed to get import secret: %w", err)
		}
		if importSecret.Data == nil {
			return nil, "", fmt.Errorf("import secret %s has no data", key.Spec.ImportKey.SecretRef.Name)
		}
		akKey := defaultAccessKeyIDKey
		skKey := defaultSecretAccessKeyKey
		if key.Spec.ImportKey.AccessKeyIDKey != "" {
			akKey = key.Spec.ImportKey.AccessKeyIDKey
		}
		if key.Spec.ImportKey.SecretAccessKeyKey != "" {
			skKey = key.Spec.ImportKey.SecretAccessKeyKey
		}
		accessKeyIDData, ok := importSecret.Data[akKey]
		if !ok {
			return nil, "", fmt.Errorf("import secret %s missing %s", key.Spec.ImportKey.SecretRef.Name, akKey)
		}
		secretKeyData, ok := importSecret.Data[skKey]
		if !ok {
			return nil, "", fmt.Errorf("import secret %s missing %s", key.Spec.ImportKey.SecretRef.Name, skKey)
		}
		accessKeyID = string(accessKeyIDData)
		secretKey = string(secretKeyData)
	}

	imported, err := garageClient.ImportKey(ctx, garage.ImportKeyRequest{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		Name:            keyName,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to import key: %w", err)
	}
	return imported, secretKey, nil
}

// createOrAdoptDeterministic derives key material from the shared RPC secret and
// calls ImportKey. If another operator already created it (409 Conflict), the key
// is adopted directly — no list scan needed, no race possible.
func (r *GarageKeyReconciler) createOrAdoptDeterministic(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta1.GarageCluster, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)

	rpcSecret, err := GetRPCSecret(ctx, r.Client, cluster)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read RPC secret for key derivation: %w", err)
	}

	if len(rpcSecret) == 0 {
		return nil, "", fmt.Errorf("RPC secret is empty; cannot derive deterministic key material")
	}

	accessKeyID, secretKey := deriveKeyMaterial(rpcSecret, key.Namespace, keyName)
	log.Info("Creating key with deterministic material", "name", keyName, "accessKeyId", accessKeyID)

	imported, err := garageClient.ImportKey(ctx, garage.ImportKeyRequest{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		Name:            keyName,
	})
	if err == nil {
		return imported, secretKey, nil
	}

	// 409: either another operator already imported it (live key), or it was previously
	// deleted and a tombstone remains (Garage prevents re-importing the same key_id).
	if garage.IsConflict(err) {
		existing, fetchErr := garageClient.GetKey(ctx, garage.GetKeyRequest{
			ID:            accessKeyID,
			ShowSecretKey: true,
		})
		if fetchErr == nil {
			// Live key — another operator created it, adopt it.
			// Use the locally-derived secretKey: ImportKey guarantees the stored secret
			// matches what we submitted, so the derived value is always authoritative.
			log.Info("Key already exists (created by another operator), adopting", "accessKeyId", accessKeyID)
			return existing, secretKey, nil
		}
		if garage.IsNotFound(fetchErr) {
			// Tombstone: the derived key_id was previously deleted. Garage's CRDT stores a
			// deletion marker that blocks re-import with the same ID. Create a fresh random key.
			log.Info("Derived key ID has tombstone, creating with fresh random ID", "tombstonedId", accessKeyID)
			created, createErr := garageClient.CreateKeyWithOptions(ctx, garage.CreateKeyRequest{Name: keyName})
			if createErr != nil {
				return nil, "", fmt.Errorf("failed to create key after tombstone (derived ID %s): %w", accessKeyID, createErr)
			}
			return created, created.SecretAccessKey, nil
		}
		return nil, "", fmt.Errorf("conflict on deterministic import but key not fetchable: %w", fetchErr)
	}

	return nil, "", fmt.Errorf("deterministic import failed: %w", err)
}

func (r *GarageKeyReconciler) updateKeyIfNeeded(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	needsUpdate := false
	updateReq := garage.UpdateKeyRequest{ID: garageKey.AccessKeyID}

	// Only send updates when the key's current state doesn't match the spec
	isNeverExpires := garageKey.Expiration != nil && *garageKey.Expiration == "never"
	if key.Spec.NeverExpires && !isNeverExpires {
		updateReq.Body.NeverExpires = true
		needsUpdate = true
	} else if key.Spec.Expiration != "" {
		currentExp := ""
		if garageKey.Expiration != nil {
			currentExp = *garageKey.Expiration
		}
		if currentExp != key.Spec.Expiration {
			updateReq.Body.Expiration = &key.Spec.Expiration
			needsUpdate = true
		}
	}

	if key.Spec.Permissions != nil && key.Spec.Permissions.CreateBucket && !garageKey.Permissions.CreateBucket {
		updateReq.Body.Allow = &garage.KeyPermissions{CreateBucket: true}
		needsUpdate = true
	}

	if needsUpdate {
		if _, err := garageClient.UpdateKey(ctx, updateReq); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}
	}
	return nil
}

func (r *GarageKeyReconciler) reconcileBucketPermissions(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	log := logf.FromContext(ctx)
	var permissionErrors []string
	pendingBuckets := false

	// Build lookup of current permissions by bucket ID
	currentPerms := make(map[string]garage.BucketKeyPerms, len(garageKey.Buckets))
	for _, b := range garageKey.Buckets {
		currentPerms[b.ID] = b.Permissions
	}

	for _, bucketPerm := range key.Spec.BucketPermissions {
		bucketID, bucketRef, pending, err := r.resolveBucketID(ctx, key.Namespace, bucketPerm, garageClient)
		if err != nil {
			permissionErrors = append(permissionErrors, fmt.Sprintf("%s: %v", bucketRef, err))
			continue
		}
		if pending {
			pendingBuckets = true
			continue
		}
		if bucketID == "" {
			continue
		}

		desired := garage.BucketKeyPerms{Read: bucketPerm.Read, Write: bucketPerm.Write, Owner: bucketPerm.Owner}
		if cur, ok := currentPerms[bucketID]; ok && cur == desired {
			continue
		}

		_, err = garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    bucketID,
			AccessKeyID: garageKey.AccessKeyID,
			Permissions: desired,
		})
		if err != nil {
			log.Error(err, "Failed to set bucket permission", "bucket", bucketRef)
			permissionErrors = append(permissionErrors, fmt.Sprintf("%s: %v", bucketRef, err))
		}
	}

	if pendingBuckets {
		return fmt.Errorf("waiting for buckets to be ready before granting permissions")
	}
	if len(permissionErrors) > 0 {
		return fmt.Errorf("failed to set permissions for buckets: %v", permissionErrors)
	}
	return nil
}

func (r *GarageKeyReconciler) reconcileAllBuckets(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	log := logf.FromContext(ctx)
	accessKeyID := garageKey.AccessKeyID

	// Build lookup of current permissions by bucket ID
	currentPerms := make(map[string]garage.BucketKeyPerms, len(garageKey.Buckets))
	for _, b := range garageKey.Buckets {
		currentPerms[b.ID] = b.Permissions
	}

	// allBuckets removed but was previously active: revoke all permissions.
	// reconcileBucketPermissions runs after and re-applies any per-bucket grants.
	if key.Spec.AllBuckets == nil {
		if !key.Status.ClusterWide {
			return nil
		}
		log.Info("allBuckets removed, revoking cluster-wide permissions", "accessKeyId", accessKeyID)
		buckets, err := garageClient.ListBuckets(ctx)
		if err != nil {
			return fmt.Errorf("failed to list buckets for cluster-wide revocation: %w", err)
		}
		var permErrors []string
		for _, b := range buckets {
			// Skip if key has no permissions on this bucket
			cur, has := currentPerms[b.ID]
			if !has || cur == (garage.BucketKeyPerms{}) {
				continue
			}
			_, err := garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
				BucketID:    b.ID,
				AccessKeyID: accessKeyID,
				Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
			})
			if err != nil && !garage.IsNotFound(err) {
				log.Error(err, "Failed to revoke cluster-wide permission", "bucketId", b.ID)
				permErrors = append(permErrors, fmt.Sprintf("%s: %v", b.ID, err))
			}
		}
		if len(permErrors) > 0 {
			return fmt.Errorf("failed to revoke cluster-wide permissions for %d/%d buckets: %v", len(permErrors), len(buckets), permErrors)
		}
		return nil
	}

	// allBuckets present: deny complement then allow desired permissions.
	log.V(1).Info("Reconciling cluster-wide bucket permissions", "accessKeyId", accessKeyID)
	buckets, err := garageClient.ListBuckets(ctx)
	if err != nil {
		return fmt.Errorf("failed to list buckets for cluster-wide permissions: %w", err)
	}

	desired := garage.BucketKeyPerms{
		Read:  key.Spec.AllBuckets.Read,
		Write: key.Spec.AllBuckets.Write,
		Owner: key.Spec.AllBuckets.Owner,
	}
	denyPerms := garage.BucketKeyPerms{
		Read:  !desired.Read,
		Write: !desired.Write,
		Owner: !desired.Owner,
	}
	needsDeny := denyPerms.Read || denyPerms.Write || denyPerms.Owner

	var permErrors []string
	for _, b := range buckets {
		cur, has := currentPerms[b.ID]

		// Check if deny is needed: only if the key currently has a permission we want to deny
		if needsDeny {
			denyNeeded := (!desired.Read && has && cur.Read) ||
				(!desired.Write && has && cur.Write) ||
				(!desired.Owner && has && cur.Owner)
			if denyNeeded {
				_, err := garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
					BucketID:    b.ID,
					AccessKeyID: accessKeyID,
					Permissions: denyPerms,
				})
				if err != nil && !garage.IsNotFound(err) {
					log.Error(err, "Failed to deny cluster-wide permission on bucket", "bucketId", b.ID)
					permErrors = append(permErrors, fmt.Sprintf("%s: deny: %v", b.ID, err))
					continue
				}
			}
		}

		// Skip allow if permissions already match
		if has && cur == desired {
			continue
		}

		_, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    b.ID,
			AccessKeyID: accessKeyID,
			Permissions: desired,
		})
		if err != nil {
			log.Error(err, "Failed to allow cluster-wide permission on bucket", "bucketId", b.ID)
			permErrors = append(permErrors, fmt.Sprintf("%s: allow: %v", b.ID, err))
		}
	}

	if len(permErrors) > 0 {
		return fmt.Errorf("failed to set cluster-wide permissions for %d/%d buckets: %v", len(permErrors), len(buckets), permErrors)
	}

	log.V(1).Info("Cluster-wide permissions applied", "bucketCount", len(buckets))
	return nil
}

func (r *GarageKeyReconciler) resolveBucketID(ctx context.Context, namespace string, bucketPerm garagev1beta1.BucketPermission, garageClient *garage.Client) (bucketID, bucketRef string, pending bool, err error) {
	log := logf.FromContext(ctx)

	if bucketPerm.BucketRef != "" {
		bucketRef = bucketPerm.BucketRef
		ns := namespace
		if bucketPerm.BucketNamespace != "" {
			ns = bucketPerm.BucketNamespace
		}
		bucket := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucketPerm.BucketRef, Namespace: ns}, bucket); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Bucket not found, will retry", "bucketRef", bucketPerm.BucketRef, "namespace", ns)
				return "", bucketRef, true, nil
			}
			return "", bucketRef, false, fmt.Errorf("failed to get bucket %s/%s: %w", ns, bucketPerm.BucketRef, err)
		}
		if bucket.Status.BucketID == "" {
			log.Info("Bucket not yet created in Garage, will retry", "bucketRef", bucketPerm.BucketRef, "namespace", ns)
			return "", bucketRef, true, nil
		}
		return bucket.Status.BucketID, bucketRef, false, nil
	}

	if bucketPerm.BucketID != "" {
		return bucketPerm.BucketID, bucketPerm.BucketID, false, nil
	}

	if bucketPerm.GlobalAlias != "" {
		bucketRef = bucketPerm.GlobalAlias
		bucket, err := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: bucketPerm.GlobalAlias})
		if err != nil {
			log.Error(err, "Failed to get bucket by alias", "alias", bucketPerm.GlobalAlias)
			return "", bucketRef, false, err
		}
		return bucket.ID, bucketRef, false, nil
	}

	return "", "", false, nil
}

// secretConfig holds resolved secret configuration from SecretTemplate
type secretConfig struct {
	name               string
	namespace          string
	accessKeyIDKey     string
	secretAccessKeyKey string
	endpointKey        string
	hostKey            string
	schemeKey          string
	regionKey          string
	includeEndpoint    bool
	includeRegion      bool
	additionalData     map[string]string
	labels             map[string]string
	annotations        map[string]string
	secretType         corev1.SecretType
}

// resolveSecretConfig extracts and defaults secret configuration from the key spec
func resolveSecretConfig(key *garagev1beta1.GarageKey) secretConfig {
	cfg := secretConfig{
		name:               key.Name,
		namespace:          key.Namespace,
		accessKeyIDKey:     defaultAccessKeyIDKey,
		secretAccessKeyKey: defaultSecretAccessKeyKey,
		endpointKey:        "endpoint",
		hostKey:            "host",
		schemeKey:          defaultSchemeKey,
		regionKey:          defaultRegionKey,
		includeEndpoint:    true,
		includeRegion:      true,
		labels: map[string]string{
			"app.kubernetes.io/managed-by": "garage-operator",
			"garage.rajsingh.info/key":     key.Name,
		},
		annotations: map[string]string{},
		secretType:  corev1.SecretTypeOpaque,
	}

	tmpl := key.Spec.SecretTemplate
	if tmpl == nil {
		return cfg
	}

	if tmpl.Name != "" {
		cfg.name = tmpl.Name
	}
	if tmpl.AccessKeyIDKey != "" {
		cfg.accessKeyIDKey = tmpl.AccessKeyIDKey
	}
	if tmpl.SecretAccessKeyKey != "" {
		cfg.secretAccessKeyKey = tmpl.SecretAccessKeyKey
	}
	if tmpl.EndpointKey != "" {
		cfg.endpointKey = tmpl.EndpointKey
	}
	if tmpl.HostKey != "" {
		cfg.hostKey = tmpl.HostKey
	}
	if tmpl.SchemeKey != "" {
		cfg.schemeKey = tmpl.SchemeKey
	}
	if tmpl.RegionKey != "" {
		cfg.regionKey = tmpl.RegionKey
	}
	if tmpl.IncludeEndpoint != nil {
		cfg.includeEndpoint = *tmpl.IncludeEndpoint
	}
	if tmpl.IncludeRegion != nil {
		cfg.includeRegion = *tmpl.IncludeRegion
	}
	if tmpl.AdditionalData != nil {
		cfg.additionalData = tmpl.AdditionalData
	}
	maps.Copy(cfg.labels, tmpl.Labels)
	if tmpl.Annotations != nil {
		cfg.annotations = tmpl.Annotations
	}
	if tmpl.Type != "" {
		cfg.secretType = tmpl.Type
	}

	return cfg
}

// buildSecretData constructs the secret data map based on configuration
func buildSecretData(cfg secretConfig, key *garagev1beta1.GarageKey, cluster *garagev1beta1.GarageCluster, secretAccessKey, clusterDomain string) map[string][]byte {
	data := map[string][]byte{
		cfg.accessKeyIDKey: []byte(key.Status.AccessKeyID),
	}

	if secretAccessKey != "" {
		data[cfg.secretAccessKeyKey] = []byte(secretAccessKey)
	}

	if cfg.includeEndpoint {
		s3Port := int32(3900)
		if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
			s3Port = cluster.Spec.S3API.BindPort
		}
		host := svcFQDN(cluster.Name, cluster.Namespace, s3Port, clusterDomain)
		scheme := "http"
		endpoint := fmt.Sprintf("%s://%s", scheme, host)
		data[cfg.endpointKey] = []byte(endpoint)
		data[cfg.hostKey] = []byte(host)
		data[cfg.schemeKey] = []byte(scheme)
	}

	if cfg.includeRegion {
		region := defaultS3Region
		if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
			region = cluster.Spec.S3API.Region
		}
		data[cfg.regionKey] = []byte(region)
	}

	for k, v := range cfg.additionalData {
		data[k] = []byte(v)
	}

	return data
}

// secretDataEqual returns true if two secret data maps have identical keys and values.
func secretDataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !bytes.Equal(v, bv) {
			return false
		}
	}
	return true
}

// mapsEqual returns true if two string maps have identical keys and values.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || v != bv {
			return false
		}
	}
	return true
}

func (r *GarageKeyReconciler) reconcileSecret(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta1.GarageCluster, secretAccessKey string) error {
	log := logf.FromContext(ctx)

	cfg := resolveSecretConfig(key)
	secretData := buildSecretData(cfg, key, cluster, secretAccessKey, r.ClusterDomain)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cfg.name,
			Namespace:   cfg.namespace,
			Labels:      cfg.labels,
			Annotations: cfg.annotations,
		},
		Type: cfg.secretType,
		Data: secretData,
	}

	if cfg.namespace == key.Namespace {
		if err := controllerutil.SetControllerReference(key, secret, r.Scheme); err != nil {
			return err
		}
	}

	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: cfg.name, Namespace: cfg.namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating secret", "name", cfg.name, "namespace", cfg.namespace)
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		key.Status.SecretRef = &corev1.SecretReference{Name: cfg.name, Namespace: cfg.namespace}
		return nil
	}
	if err != nil {
		return err
	}

	// Preserve existing secretAccessKey if we don't have a new one
	if secretAccessKey == "" && existing.Data[cfg.secretAccessKeyKey] != nil {
		secretData[cfg.secretAccessKeyKey] = existing.Data[cfg.secretAccessKeyKey]
	} else if secretAccessKey != "" && existing.Data[cfg.secretAccessKeyKey] != nil {
		existingSecret := string(existing.Data[cfg.secretAccessKeyKey])
		if existingSecret != secretAccessKey {
			log.V(1).Info("Syncing secret with value from Garage",
				"secret", cfg.name, "namespace", cfg.namespace)
		}
	}

	// Skip update if nothing changed — avoids triggering Owns() watch and re-reconciliation
	if secretDataEqual(existing.Data, secretData) &&
		mapsEqual(existing.Labels, cfg.labels) &&
		mapsEqual(existing.Annotations, cfg.annotations) {
		key.Status.SecretRef = &corev1.SecretReference{Name: cfg.name, Namespace: cfg.namespace}
		return nil
	}

	existing.Data = secretData
	existing.Labels = cfg.labels
	existing.Annotations = cfg.annotations
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	key.Status.SecretRef = &corev1.SecretReference{Name: cfg.name, Namespace: cfg.namespace}
	return nil
}

func (r *GarageKeyReconciler) finalize(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	if key.Status.AccessKeyID == "" {
		return nil
	}

	log.Info("Deleting key", "accessKeyID", key.Status.AccessKeyID)

	if err := garageClient.DeleteKey(ctx, key.Status.AccessKeyID); err != nil {
		// Check if key doesn't exist (404) - that's okay, we can proceed
		if garage.IsNotFound(err) {
			log.Info("Key already deleted or not found", "accessKeyID", key.Status.AccessKeyID)
			return nil
		}
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

func (r *GarageKeyReconciler) updateStatusWaiting(ctx context.Context, key *garagev1beta1.GarageKey) (ctrl.Result, error) {
	key.Status.Phase = PhasePending
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonClusterNotReady,
		Message:            "waiting for cluster to be reachable",
		ObservedGeneration: key.Generation,
	})
	if statusErr := UpdateStatusWithRetry(ctx, r.Client, key); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
}

func (r *GarageKeyReconciler) updateStatus(ctx context.Context, key *garagev1beta1.GarageKey, phase string, err error) (ctrl.Result, error) {
	key.Status.Phase = phase
	// Only set ObservedGeneration when reconciliation succeeded
	if err == nil {
		key.Status.ObservedGeneration = key.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "Error",
			Message:            err.Error(),
			ObservedGeneration: key.Generation,
		})
	}

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, key); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	return ctrl.Result{}, nil
}

func (r *GarageKeyReconciler) updateStatusFromGarage(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client) (ctrl.Result, error) {
	if key.Status.AccessKeyID == "" {
		return r.updateStatus(ctx, key, "Pending", nil)
	}

	garageKey, err := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: key.Status.AccessKeyID})
	if err != nil {
		if isTransientConnectivityError(err) {
			return r.updateStatusWaiting(ctx, key)
		}
		if garage.IsNotFound(err) {
			// Key was deleted externally. Clear the cached ID so the next reconcile
			// re-derives/re-imports it rather than looping on a known-missing ID.
			log := logf.FromContext(ctx)
			log.Info("Key no longer exists in Garage, clearing status for re-creation", "accessKeyId", key.Status.AccessKeyID)
			key.Status.AccessKeyID = ""
			key.Status.KeyID = ""
			if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return r.updateStatus(ctx, key, "Error", fmt.Errorf("failed to get key info: %w", err))
	}

	// Capture old status before modifications to detect no-op updates
	oldStatus := key.Status.DeepCopy()

	key.Status.Phase = "Ready"
	key.Status.ObservedGeneration = key.Generation
	key.Status.Permissions = &garagev1beta1.KeyPermissions{
		CreateBucket: garageKey.Permissions.CreateBucket,
	}

	// Parse creation timestamp
	if garageKey.Created != nil && *garageKey.Created != "" {
		if t, err := time.Parse(time.RFC3339, *garageKey.Created); err == nil {
			key.Status.CreatedAt = &metav1.Time{Time: t}
		}
	}

	// Update expiration info
	if garageKey.Expiration != nil {
		key.Status.Expiration = *garageKey.Expiration
	} else {
		key.Status.Expiration = ""
	}
	key.Status.Expired = garageKey.Expired
	key.Status.ClusterWide = key.Spec.AllBuckets != nil

	// Update bucket access list, sorted by ID for deterministic comparison
	key.Status.Buckets = make([]garagev1beta1.KeyBucketAccess, 0, len(garageKey.Buckets))
	for _, b := range garageKey.Buckets {
		access := garagev1beta1.KeyBucketAccess{
			BucketID: b.ID,
			Read:     b.Permissions.Read,
			Write:    b.Permissions.Write,
			Owner:    b.Permissions.Owner,
		}
		if len(b.GlobalAliases) > 0 {
			access.GlobalAlias = b.GlobalAliases[0]
		}
		if len(b.LocalAliases) > 0 {
			access.LocalAlias = b.LocalAliases[0]
		}
		key.Status.Buckets = append(key.Status.Buckets, access)
	}
	sort.Slice(key.Status.Buckets, func(i, j int) bool {
		return key.Status.Buckets[i].BucketID < key.Status.Buckets[j].BucketID
	})

	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "KeyReady",
		Message:            "Key is ready",
		ObservedGeneration: key.Generation,
	})

	// Skip status update if nothing changed — avoids ResourceVersion bump
	// which would trigger informer watch event and re-enqueue (infinite loop).
	// Use drift interval to periodically re-check Garage-side credentials even when idle.
	if apiequality.Semantic.DeepEqual(*oldStatus, key.Status) {
		return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
		return ctrl.Result{}, err
	}

	// Status updated — the informer watch event will re-enqueue for immediate verification.
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageKey{}).
		Owns(&corev1.Secret{}).
		Named("garagekey").
		Complete(r)
}
