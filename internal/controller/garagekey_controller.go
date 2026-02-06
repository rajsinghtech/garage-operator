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

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageKeyFinalizer = "garagekey.garage.rajsingh.info/finalizer"
)

// GarageKeyReconciler reconciles a GarageKey object
type GarageKeyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *GarageKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	key := &garagev1alpha1.GarageKey{}
	if err := r.Get(ctx, req.NamespacedName, key); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Get the cluster reference
	cluster := &garagev1alpha1.GarageCluster{}
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
		return r.updateStatus(ctx, key, "Error", fmt.Errorf("cluster not found: %w", clusterErr))
	}

	// Get garage client
	garageClient, err := GetGarageClient(ctx, r.Client, cluster)
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
	secretAccessKey, keyErr := r.reconcileKey(ctx, key, garageClient)

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

func (r *GarageKeyReconciler) reconcileKey(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client) (string, error) {
	keyName := key.Name
	if key.Spec.Name != "" {
		keyName = key.Spec.Name
	}

	garageKey, secretAccessKey, err := r.getOrCreateKey(ctx, key, garageClient, keyName)
	if err != nil {
		return "", err
	}

	key.Status.AccessKeyID = garageKey.AccessKeyID
	key.Status.KeyID = garageKey.AccessKeyID

	if err := r.reconcileAllBuckets(ctx, key, garageClient, garageKey.AccessKeyID); err != nil {
		return secretAccessKey, err
	}

	if err := r.reconcileBucketPermissions(ctx, key, garageClient, garageKey.AccessKeyID); err != nil {
		return secretAccessKey, err
	}

	return secretAccessKey, nil
}

func (r *GarageKeyReconciler) getOrCreateKey(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
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

	// Search for existing key by name to support multi-cluster federation
	// This prevents duplicate keys when multiple operators manage the same Garage cluster
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

	return r.createKey(ctx, key, garageClient, keyName)
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
		log.Info("Multiple keys found with same name, cannot adopt automatically",
			"name", keyName, "count", len(matches))
		// Return nil to trigger creation of a new key - user should clean up duplicates
		return nil, nil
	}

	// Fetch full key info including secret
	return garageClient.GetKey(ctx, garage.GetKeyRequest{
		ID:            matches[0].ID,
		ShowSecretKey: true,
	})
}

func (r *GarageKeyReconciler) importKey(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)
	log.Info("Importing existing key", "name", keyName)

	accessKeyID := key.Spec.ImportKey.AccessKeyID
	secretKey := key.Spec.ImportKey.SecretAccessKey

	if key.Spec.ImportKey.SecretRef != nil {
		importSecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      key.Spec.ImportKey.SecretRef.Name,
			Namespace: key.Spec.ImportKey.SecretRef.Namespace,
		}, importSecret); err != nil {
			return nil, "", fmt.Errorf("failed to get import secret: %w", err)
		}
		if importSecret.Data == nil {
			return nil, "", fmt.Errorf("import secret %s has no data", key.Spec.ImportKey.SecretRef.Name)
		}
		accessKeyIDData, ok := importSecret.Data["access-key-id"]
		if !ok {
			return nil, "", fmt.Errorf("import secret %s missing access-key-id", key.Spec.ImportKey.SecretRef.Name)
		}
		secretKeyData, ok := importSecret.Data["secret-access-key"]
		if !ok {
			return nil, "", fmt.Errorf("import secret %s missing secret-access-key", key.Spec.ImportKey.SecretRef.Name)
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

func (r *GarageKeyReconciler) createKey(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)
	log.Info("Creating new key", "name", keyName)

	createReq := garage.CreateKeyRequest{Name: keyName}
	if key.Spec.NeverExpires {
		createReq.NeverExpires = true
	} else if key.Spec.Expiration != "" {
		createReq.Expiration = &key.Spec.Expiration
	}
	if key.Spec.Permissions != nil && key.Spec.Permissions.CreateBucket {
		createReq.Allow = &garage.KeyPermissions{CreateBucket: true}
	}

	created, err := garageClient.CreateKeyWithOptions(ctx, createReq)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create key: %w", err)
	}
	return created, created.SecretAccessKey, nil
}

func (r *GarageKeyReconciler) updateKeyIfNeeded(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	needsUpdate := false
	updateReq := garage.UpdateKeyRequest{ID: garageKey.AccessKeyID}

	if key.Spec.NeverExpires {
		updateReq.Body.NeverExpires = true
		needsUpdate = true
	} else if key.Spec.Expiration != "" {
		updateReq.Body.Expiration = &key.Spec.Expiration
		needsUpdate = true
	}

	if key.Spec.Permissions != nil && key.Spec.Permissions.CreateBucket {
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

func (r *GarageKeyReconciler) reconcileBucketPermissions(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, accessKeyID string) error {
	log := logf.FromContext(ctx)
	var permissionErrors []string
	pendingBuckets := false

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

		_, err = garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    bucketID,
			AccessKeyID: accessKeyID,
			Permissions: garage.BucketKeyPerms{Read: bucketPerm.Read, Write: bucketPerm.Write, Owner: bucketPerm.Owner},
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

func (r *GarageKeyReconciler) reconcileAllBuckets(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client, accessKeyID string) error {
	log := logf.FromContext(ctx)

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
		if needsDeny {
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

func (r *GarageKeyReconciler) resolveBucketID(ctx context.Context, namespace string, bucketPerm garagev1alpha1.BucketPermission, garageClient *garage.Client) (bucketID, bucketRef string, pending bool, err error) {
	log := logf.FromContext(ctx)

	if bucketPerm.BucketRef != "" {
		bucketRef = bucketPerm.BucketRef
		bucket := &garagev1alpha1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucketPerm.BucketRef, Namespace: namespace}, bucket); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Bucket not found, will retry", "bucketRef", bucketPerm.BucketRef)
				return "", bucketRef, true, nil
			}
			return "", bucketRef, false, fmt.Errorf("failed to get bucket %s: %w", bucketPerm.BucketRef, err)
		}
		if bucket.Status.BucketID == "" {
			log.Info("Bucket not yet created in Garage, will retry", "bucketRef", bucketPerm.BucketRef)
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
func resolveSecretConfig(key *garagev1alpha1.GarageKey) secretConfig {
	cfg := secretConfig{
		name:               key.Name,
		namespace:          key.Namespace,
		accessKeyIDKey:     "access-key-id",
		secretAccessKeyKey: "secret-access-key",
		endpointKey:        "endpoint",
		hostKey:            "host",
		schemeKey:          "scheme",
		regionKey:          "region",
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
	if tmpl.Namespace != "" {
		cfg.namespace = tmpl.Namespace
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
	if tmpl.Labels != nil {
		for k, v := range tmpl.Labels {
			cfg.labels[k] = v
		}
	}
	if tmpl.Annotations != nil {
		cfg.annotations = tmpl.Annotations
	}
	if tmpl.Type != "" {
		cfg.secretType = tmpl.Type
	}

	return cfg
}

// buildSecretData constructs the secret data map based on configuration
func buildSecretData(cfg secretConfig, key *garagev1alpha1.GarageKey, cluster *garagev1alpha1.GarageCluster, secretAccessKey string) map[string][]byte {
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
		host := fmt.Sprintf("%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, s3Port)
		scheme := "http"
		endpoint := fmt.Sprintf("%s://%s", scheme, host)
		data[cfg.endpointKey] = []byte(endpoint)
		data[cfg.hostKey] = []byte(host)
		data[cfg.schemeKey] = []byte(scheme)
	}

	if cfg.includeRegion {
		region := "garage"
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

func (r *GarageKeyReconciler) reconcileSecret(ctx context.Context, key *garagev1alpha1.GarageKey, cluster *garagev1alpha1.GarageCluster, secretAccessKey string) error {
	log := logf.FromContext(ctx)

	cfg := resolveSecretConfig(key)
	secretData := buildSecretData(cfg, key, cluster, secretAccessKey)

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
		// Check if K8s secret differs from Garage - this can happen due to:
		// 1. Actual credential drift (key recreated externally)
		// 2. Race condition during initial key creation
		// 3. Normal sync after operator restart
		// Log at debug level to avoid noise from normal operations
		existingSecret := string(existing.Data[cfg.secretAccessKeyKey])
		if existingSecret != secretAccessKey {
			log.V(1).Info("Syncing secret with value from Garage",
				"secret", cfg.name, "namespace", cfg.namespace)
		}
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

func (r *GarageKeyReconciler) finalize(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client) error {
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

func (r *GarageKeyReconciler) updateStatus(ctx context.Context, key *garagev1alpha1.GarageKey, phase string, err error) (ctrl.Result, error) {
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

func (r *GarageKeyReconciler) updateStatusFromGarage(ctx context.Context, key *garagev1alpha1.GarageKey, garageClient *garage.Client) (ctrl.Result, error) {
	if key.Status.AccessKeyID == "" {
		return r.updateStatus(ctx, key, "Pending", nil)
	}

	garageKey, err := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: key.Status.AccessKeyID})
	if err != nil {
		return r.updateStatus(ctx, key, "Error", fmt.Errorf("failed to get key info: %w", err))
	}

	key.Status.Phase = "Ready"
	key.Status.ObservedGeneration = key.Generation
	key.Status.Permissions = &garagev1alpha1.KeyPermissions{
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

	// Update bucket access list
	key.Status.Buckets = make([]garagev1alpha1.KeyBucketAccess, 0, len(garageKey.Buckets))
	for _, b := range garageKey.Buckets {
		access := garagev1alpha1.KeyBucketAccess{
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

	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "KeyReady",
		Message:            "Key is ready",
		ObservedGeneration: key.Generation,
	})

	if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1alpha1.GarageKey{}).
		Owns(&corev1.Secret{}).
		Named("garagekey").
		Complete(r)
}
