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
	"net/url"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

const (
	garageKeyFinalizer              = garagev1beta1.GarageKeyFinalizer
	keyReplacementNonceAnnotation   = "garage.rajsingh.info/key-replacement-nonce"
	keyResolvedImportIDAnnotation   = "garage.rajsingh.info/resolved-import-access-key-id"
	keyImportSnapshotLabel          = "garage.rajsingh.info/key-import-snapshot"
	keyImportSnapshotLabelValue     = "true"
	keyGeneratedSecretOwnerLabel    = "garage.rajsingh.info/generated-key-secret-owner"
	keyReplacementIdentitySeparator = "\x00replacement:"
)

// GarageKeyReconciler reconciles a GarageKey object
type GarageKeyReconciler struct {
	client.Client
	AuthorizationReader client.Reader
	Scheme              *runtime.Scheme
	ClusterDomain       string
}

func (r *GarageKeyReconciler) authorizationReader() client.Reader {
	if r.AuthorizationReader != nil {
		return r.AuthorizationReader
	}
	return r.Client
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
	if key.DeletionTimestamp.IsZero() {
		if err := garagev1beta1.ValidateGarageKeySpec(key); err != nil {
			return r.updateStatus(ctx, key, PhaseFailed, err)
		}
		if key.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStatePending {
			// COSI owns the pending exact-identity import and will bind it after the
			// remote write. Generating or importing here would race that handoff.
			if !controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
				controllerutil.AddFinalizer(key, garageKeyFinalizer)
				if err := r.Update(ctx, key); err != nil {
					return ctrl.Result{}, err
				}
			}
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		clusterNamespace := key.Spec.ClusterRef.Namespace
		if clusterNamespace == "" {
			clusterNamespace = key.Namespace
		}
		if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), garageKeyKind, key.Namespace,
			"GarageCluster", clusterNamespace, key.Spec.ClusterRef.Name); err != nil {
			return r.updateStatus(ctx, key, PhaseFailed, err)
		}
	}

	// Get the cluster reference
	cluster := &garagev1beta2.GarageCluster{}
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
			// A COSI shadow can have a durable remote reservation before its parent
			// publishes status. Never discard that identity merely because its
			// management handle is temporarily absent.
			if clusterErr != nil && errors.IsNotFound(clusterErr) {
				if isCOSIManagedPendingOrBoundShadow(key) {
					log.Info("COSI key shadow is waiting for its missing GarageCluster before finalization",
						"cluster", key.Spec.ClusterRef.Name)
					return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
				}
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
			return r.updateStatusWaiting(ctx, key, nil)
		}
		return r.updateStatus(ctx, key, PhaseFailed, fmt.Errorf("cluster not found: %w", clusterErr))
	}

	// Guard against calling the Garage API before the cluster has any pods at all
	// (Pending = all pods down, admin API unreachable) or when the cluster has failed.
	// Degraded (readyReplicas < desired but > 0) is intentionally allowed: the admin
	// API is still reachable via running pods, so key provisioning succeeds. Blocking
	// on Phase != Running prevents key operations during routine rolling restarts or
	// when dead gateway peers cause a cosmetic Degraded (gateway peers don't affect
	// write quorum or the admin API).
	if !key.DeletionTimestamp.IsZero() {
		// Allow deletions to proceed regardless of cluster health.
	} else if !cluster.DeletionTimestamp.IsZero() || cluster.Status.Phase == PhasePending || cluster.Status.Phase == PhaseFailed {
		msg := "waiting for cluster to start (phase: " + cluster.Status.Phase + ")"
		if !cluster.DeletionTimestamp.IsZero() {
			msg = "garage cluster is being deleted"
		}
		meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonClusterNotReady,
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
	var garageClient *garage.Client
	var err error
	if key.DeletionTimestamp.IsZero() {
		garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	} else {
		garageClient, err = GetGarageClientForCleanup(ctx, r.Client, cluster, r.ClusterDomain)
	}
	if err != nil {
		return r.updateStatus(ctx, key, PhaseFailed, fmt.Errorf("failed to create garage client: %w", err))
	}

	// Handle deletion (cluster exists at this point)
	if !key.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
			if err := r.finalize(ctx, key, cluster, garageClient); err != nil {
				patch := client.MergeFrom(key.DeepCopy())
				IncrementFinalizationRetryCount(key)
				if patchErr := r.Patch(ctx, key, patch); patchErr != nil {
					if errors.IsNotFound(patchErr) {
						return ctrl.Result{}, nil
					}
					log.Error(patchErr, "Failed to update retry count annotation")
				}
				log.Error(err, "Failed to finalize key, retaining finalizer",
					"retries", GetFinalizationRetryCount(key))
				// Cleanup ownership is never abandoned automatically. An administrator
				// can still remove the finalizer explicitly after accepting the leak.
				_, _ = r.updateStatus(ctx, key, PhaseDeleting, fmt.Errorf("finalization failed: %w", err))
				return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
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
	// waiting state rather than a permanent error, but keep the real error
	// text on the condition: the same error shape also covers a permanent
	// misconfiguration (e.g. an unresolvable cluster-domain) that will retry
	// forever without ever becoming a PhaseFailed, so the message is the only
	// place that distinction is visible to the user.
	if keyErr != nil && isTransientConnectivityError(keyErr) {
		return r.updateStatusWaiting(ctx, key, keyErr)
	}

	// Only create/update the Kubernetes secret if the key was successfully created
	// (either in this reconciliation or previously). This prevents creating a secret
	// with incomplete data if key creation failed.
	if key.Status.AccessKeyID != "" {
		if isCOSIManagedShadowKey(key) {
			if err := r.cleanupCOSIManagedShadowCredentials(ctx, key); err != nil {
				return r.updateStatus(ctx, key, PhaseFailed, err)
			}
		} else {
			if err := r.reconcileSecret(ctx, key, cluster, secretAccessKey); err != nil {
				return r.updateStatus(ctx, key, PhaseFailed, err)
			}
		}
	}

	// Now handle any key reconciliation error (permission issues)
	if keyErr != nil {
		return r.updateStatus(ctx, key, PhaseFailed, keyErr)
	}

	return r.updateStatusFromGarage(ctx, key, garageClient)
}

func isCOSIManagedShadowKey(key *garagev1beta1.GarageKey) bool {
	return key != nil && key.Labels[garagev1beta1.LabelCOSIManaged] == annotationTrue &&
		(key.Annotations[garagev1beta1.AnnotationCOSIReservationOwner] != "" ||
			key.Annotations[garagev1beta1.AnnotationCOSIAccountID] != "")
}

func (r *GarageKeyReconciler) cleanupCOSIManagedShadowCredentials(ctx context.Context, key *garagev1beta1.GarageKey) error {
	candidates := map[types.NamespacedName]struct{}{
		{Name: key.Name, Namespace: key.Namespace}: {},
	}
	if ref := key.Status.SecretRef; ref != nil && ref.Namespace == key.Namespace {
		candidates[types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}] = struct{}{}
	}
	for objectKey := range candidates {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, objectKey, secret); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("reading legacy COSI shadow credential Secret %s: %w", objectKey, err)
		}
		if !metav1.IsControlledBy(secret, key) {
			continue
		}
		uid := secret.UID
		if err := r.Delete(ctx, secret, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting legacy COSI shadow credential Secret %s: %w", objectKey, err)
		}
	}
	if err := r.cleanupStaleGeneratedSecrets(ctx, key, nil); err != nil {
		return err
	}
	key.Status.SecretRef = nil
	return nil
}

func (r *GarageKeyReconciler) reconcileKey(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, garageClient *garage.Client) (string, error) {
	keyName := key.Name
	if key.Spec.Name != "" {
		keyName = key.Spec.Name
	}

	previousAccessKeyID := key.Status.AccessKeyID
	garageKey, secretAccessKey, err := r.getOrCreateKey(ctx, key, cluster, garageClient, keyName)
	if err != nil {
		return "", err
	}

	key.Status.AccessKeyID = garageKey.AccessKeyID
	key.Status.KeyID = garageKey.AccessKeyID
	// Persist the remote identity before any permission or Secret work. This
	// keeps a retry pinned to the exact key, especially for the random fallback
	// used when Garage retains a tombstone for the deterministic ID.
	if key.Status.AccessKeyID != previousAccessKeyID {
		if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
			return secretAccessKey, fmt.Errorf("failed to persist Garage access key ID: %w", err)
		}
	}

	if err := r.reconcileManagedBucketPermissions(ctx, key, garageClient, garageKey); err != nil {
		return secretAccessKey, err
	}

	return secretAccessKey, nil
}

func (r *GarageKeyReconciler) getOrCreateKey(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)

	// COSI persists status.accessKeyId before its remote write. The annotation is
	// a handoff consistency check, never independent authority to adopt a key.
	if cosiAccountID := key.Annotations[garagev1beta1.AnnotationCOSIAccountID]; cosiAccountID != "" {
		if key.Status.AccessKeyID == "" {
			return nil, "", fmt.Errorf("refusing COSI-annotated account ID %q without controller-owned status.accessKeyId", cosiAccountID)
		}
		if key.Status.AccessKeyID != cosiAccountID {
			return nil, "", fmt.Errorf("COSI-annotated account ID %q disagrees with status.accessKeyId %q", cosiAccountID, key.Status.AccessKeyID)
		}
	}

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
		if key.Annotations[garagev1beta1.AnnotationCOSIAccountID] != "" {
			return nil, "", fmt.Errorf("COSI-bound key ID %s no longer exists; refusing deterministic or import replacement creation", key.Status.AccessKeyID)
		}
		log.Info("Key not found in Garage, will recreate from an explicit or deterministic identity", "accessKeyId", key.Status.AccessKeyID)
	}

	if key.Spec.ImportKey != nil {
		return r.importKey(ctx, key, garageClient, keyName)
	}

	// Always use deterministic key derivation: derive (access_key_id, secret_access_key)
	// from the cluster's RPC secret (user-provided for federation, auto-generated otherwise).
	// This guarantees idempotent creation regardless of how many operators are running.
	return r.createOrAdoptDeterministic(ctx, key, cluster, garageClient, keyName)
}

func (r *GarageKeyReconciler) importKey(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)
	log.Info("Importing existing key", "name", keyName)

	accessKeyID := key.Spec.ImportKey.AccessKeyID
	secretKey := key.Spec.ImportKey.SecretAccessKey

	if key.Spec.ImportKey.SecretRef != nil {
		var err error
		accessKeyID, secretKey, err = r.ensureImportKeySnapshot(ctx, key)
		if err != nil {
			return nil, "", err
		}
	}

	// A persisted identity pin is a consistency check and crash-recovery hint,
	// never independent authorization to delete a Garage key.
	if pinned := key.Annotations[keyResolvedImportIDAnnotation]; pinned != "" {
		if pinned != accessKeyID {
			return nil, "", fmt.Errorf("configured import resolves access key ID %q, but GarageKey is pinned to %q", accessKeyID, pinned)
		}
	}

	// Both inline and Secret-backed imports have an exact durable identity.
	// Resolve it before ImportKey so a crash after a committed import but before
	// status persistence, or a concurrent reconcile, adopts only matching key
	// material instead of wedging forever on Garage's KeyAlreadyExists response.
	existing, err := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: accessKeyID, ShowSecretKey: true})
	if err == nil {
		if existing.AccessKeyID != accessKeyID {
			return nil, "", fmt.Errorf("resolved import access key ID %q returned unexpected key %q", accessKeyID, existing.AccessKeyID)
		}
		if existing.SecretAccessKey != secretKey {
			return nil, "", fmt.Errorf("garage key %q secret does not match configured import material", accessKeyID)
		}
		return existing, secretKey, nil
	}
	if !garage.IsNotFound(err) {
		return nil, "", fmt.Errorf("checking imported key %q: %w", accessKeyID, err)
	}

	// Persist the non-sensitive identity before ImportKey. A read-only adoption
	// needs no extra mutation because inline spec or the immutable snapshot is
	// already authoritative; a new remote write must be crash-recoverable.
	if key.Annotations[keyResolvedImportIDAnnotation] == "" {
		patch := client.MergeFrom(key.DeepCopy())
		annotations := maps.Clone(key.GetAnnotations())
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[keyResolvedImportIDAnnotation] = accessKeyID
		key.SetAnnotations(annotations)
		if err := r.Patch(ctx, key, patch); err != nil {
			return nil, "", fmt.Errorf("persisting resolved import access key ID: %w", err)
		}
	}

	imported, err := garageClient.ImportKey(ctx, garage.ImportKeyRequest{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		Name:            keyName,
	})
	if err != nil {
		if garage.IsConflict(err) {
			existing, fetchErr := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: accessKeyID, ShowSecretKey: true})
			if fetchErr == nil && existing.AccessKeyID == accessKeyID && existing.SecretAccessKey == secretKey {
				return existing, secretKey, nil
			}
			if fetchErr != nil {
				return nil, "", fmt.Errorf("import conflict for key %q but exact key could not be verified: %w", accessKeyID, fetchErr)
			}
			return nil, "", fmt.Errorf("import conflict for key %q resolved to different key material", accessKeyID)
		}
		return nil, "", fmt.Errorf("failed to import key: %w", err)
	}
	return imported, secretKey, nil
}

func importKeySnapshotName(key *garagev1beta1.GarageKey) string {
	return garageconfig.GarageKeyImportSnapshotName(key.Name)
}

func (r *GarageKeyReconciler) importKeySnapshotMaterial(key *garagev1beta1.GarageKey, snapshot *corev1.Secret) (string, string, error) {
	objectKey := client.ObjectKeyFromObject(snapshot)
	if snapshot.Labels[keyImportSnapshotLabel] != keyImportSnapshotLabelValue || !metav1.IsControlledBy(snapshot, key) {
		return "", "", fmt.Errorf("refusing to use non-matching import material snapshot Secret %s", objectKey)
	}
	if snapshot.Immutable == nil || !*snapshot.Immutable {
		return "", "", fmt.Errorf("refusing mutable import material snapshot Secret %s", objectKey)
	}
	accessKeyID := string(snapshot.Data[defaultAccessKeyIDKey])
	secretKey := string(snapshot.Data[defaultSecretAccessKeyKey])
	if accessKeyID == "" || secretKey == "" {
		return "", "", fmt.Errorf("import material snapshot Secret %s is missing exact key material", objectKey)
	}
	return accessKeyID, secretKey, nil
}

// ensureImportKeySnapshot copies mutable Secret-backed import material into an
// immutable, GarageKey-owned Secret before any remote write. Once the snapshot
// exists, retries never consult the source Secret again: a source update or
// deletion cannot change the credential used to recover or recreate the key.
func (r *GarageKeyReconciler) ensureImportKeySnapshot(ctx context.Context, key *garagev1beta1.GarageKey) (string, string, error) {
	objectKey := types.NamespacedName{Name: importKeySnapshotName(key), Namespace: key.Namespace}
	existing := &corev1.Secret{}
	if err := r.Get(ctx, objectKey, existing); err == nil {
		return r.importKeySnapshotMaterial(key, existing)
	} else if !errors.IsNotFound(err) {
		return "", "", fmt.Errorf("reading import material snapshot Secret %s: %w", objectKey, err)
	}

	ref := key.Spec.ImportKey.SecretRef
	importNamespace := ref.Namespace
	if importNamespace == "" {
		importNamespace = key.Namespace
	}
	importSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: importNamespace}, importSecret); err != nil {
		return "", "", fmt.Errorf("failed to get import secret: %w", err)
	}
	if importSecret.Data == nil {
		return "", "", fmt.Errorf("import secret %s has no data", ref.Name)
	}
	akKey := defaultAccessKeyIDKey
	skKey := defaultSecretAccessKeyKey
	if key.Spec.ImportKey.AccessKeyIDKey != "" {
		akKey = key.Spec.ImportKey.AccessKeyIDKey
	}
	if key.Spec.ImportKey.SecretAccessKeyKey != "" {
		skKey = key.Spec.ImportKey.SecretAccessKeyKey
	}
	accessKeyID := string(importSecret.Data[akKey])
	if accessKeyID == "" {
		return "", "", fmt.Errorf("import secret %s missing %s", ref.Name, akKey)
	}
	secretKey := string(importSecret.Data[skKey])
	if secretKey == "" {
		return "", "", fmt.Errorf("import secret %s missing %s", ref.Name, skKey)
	}

	immutable := true
	snapshot := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      objectKey.Name,
			Namespace: objectKey.Namespace,
			Labels:    map[string]string{keyImportSnapshotLabel: keyImportSnapshotLabelValue},
		},
		Immutable: &immutable,
		Type:      corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			defaultAccessKeyIDKey:     []byte(accessKeyID),
			defaultSecretAccessKeyKey: []byte(secretKey),
		},
	}
	if err := controllerutil.SetControllerReference(key, snapshot, r.Scheme); err != nil {
		return "", "", fmt.Errorf("owning import material snapshot Secret: %w", err)
	}
	if err := r.Create(ctx, snapshot); err == nil {
		return accessKeyID, secretKey, nil
	} else if !errors.IsAlreadyExists(err) {
		return "", "", fmt.Errorf("creating import material snapshot Secret %s: %w", objectKey, err)
	}

	// A concurrent reconcile may have won with material read just before the
	// source changed. Its durable snapshot is authoritative for every retry.
	if err := r.Get(ctx, objectKey, existing); err != nil {
		return "", "", fmt.Errorf("reading concurrent import material snapshot Secret %s: %w", objectKey, err)
	}
	return r.importKeySnapshotMaterial(key, existing)
}

// createOrAdoptDeterministic derives key material from the shared RPC secret and
// calls ImportKey. If another operator already created it (409 Conflict), the key
// is adopted directly — no list scan needed, no race possible.
func (r *GarageKeyReconciler) createOrAdoptDeterministic(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, garageClient *garage.Client, keyName string) (*garage.Key, string, error) {
	log := logf.FromContext(ctx)

	rpcSecret, err := GetRPCSecret(ctx, r.Client, cluster)
	if err != nil {
		// A management handle (#269) has no operator-generated <cluster>-rpc-secret,
		// so deterministic derivation cannot work unless the user points at the
		// external cluster's RPC secret. Existing keys must be selected explicitly
		// through importKey; display names are non-unique and are not ownership.
		if cluster.IsManagementHandle() {
			return nil, "", fmt.Errorf("cannot derive key material on a management handle: set spec.importKey with existing credentials, or set spec.network.rpcSecretRef/spec.connectTo.rpcSecretRef on the GarageCluster to the external cluster's RPC secret (%w)", err)
		}
		return nil, "", fmt.Errorf("failed to read RPC secret for key derivation: %w", err)
	}

	if len(rpcSecret) == 0 {
		return nil, "", fmt.Errorf("RPC secret is empty; cannot derive deterministic key material")
	}

	// Before v0.7.4 deterministic material used the mutable Garage display name.
	// During an upgrade, a legacy ImportKey may have committed immediately before
	// a crash that left status empty. Probe that one exact legacy identity before
	// creating the metadata.name-bound identity, and adopt only after the secret
	// proves it came from this cluster's RPC material.
	if key.Status.AccessKeyID == "" && keyName != "" && keyName != key.Name {
		legacyID, legacySecret := deriveKeyMaterial(rpcSecret, key.Namespace, legacyDeterministicKeyName(key, keyName))
		legacy, lookupErr := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: legacyID, ShowSecretKey: true})
		if lookupErr == nil {
			if legacy.AccessKeyID == legacyID && legacy.SecretAccessKey == legacySecret {
				if err := r.updateKeyIfNeeded(ctx, key, garageClient, legacy); err != nil {
					return nil, "", err
				}
				return legacy, legacySecret, nil
			}
			log.Info("Legacy deterministic key ID exists with different material; using canonical identity", "accessKeyId", legacyID)
		} else if !garage.IsNotFound(lookupErr) {
			return nil, "", fmt.Errorf("checking legacy deterministic key %s before canonical import: %w", legacyID, lookupErr)
		}
	}

	// Remote credential identity is bound to immutable Kubernetes identity, not
	// the mutable Garage display name. Status continues to pin legacy keys that
	// were derived from spec.name by older controller versions.
	accessKeyID, secretKey := deriveKeyMaterial(rpcSecret, key.Namespace, deterministicKeyName(key))
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
			// Live key — adopt only after proving that the exact stored material
			// matches this object's deterministic derivation. A conflicting actor can
			// pre-create a guessed ID with a different secret; ID equality alone is
			// not ownership and would publish unusable credentials.
			if existing.AccessKeyID != accessKeyID || existing.SecretAccessKey != secretKey {
				return nil, "", fmt.Errorf("deterministic key ID %s already exists with different key material", accessKeyID)
			}
			if err := r.updateKeyIfNeeded(ctx, key, garageClient, existing); err != nil {
				return nil, "", err
			}
			log.Info("Key already exists (created by another operator), adopting", "accessKeyId", accessKeyID)
			return existing, secretKey, nil
		}
		if garage.IsNotFound(fetchErr) {
			// Garage retains a tombstone which permanently blocks this exact key ID.
			// Persist a fresh nonce before attempting another remote write. The next
			// reconcile deterministically imports the replacement identity; a crash
			// after that import can therefore replay and adopt the exact same key.
			patch := client.MergeFrom(key.DeepCopy())
			annotations := key.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[keyReplacementNonceAnnotation] = string(uuid.NewUUID())
			key.SetAnnotations(annotations)
			if patchErr := r.Patch(ctx, key, patch); patchErr != nil {
				return nil, "", fmt.Errorf("persisting replacement identity after tombstoned key %s: %w", accessKeyID, patchErr)
			}
			return nil, "", fmt.Errorf("garage key ID %s is tombstoned; persisted a replacement identity for retry", accessKeyID)
		}
		return nil, "", fmt.Errorf("conflict on deterministic import but key not fetchable: %w", fetchErr)
	}

	return nil, "", fmt.Errorf("deterministic import failed: %w", err)
}

func deterministicKeyName(key *garagev1beta1.GarageKey) string {
	if nonce := key.Annotations[keyReplacementNonceAnnotation]; nonce != "" {
		return key.Name + keyReplacementIdentitySeparator + nonce
	}
	return key.Name
}

func legacyDeterministicKeyName(key *garagev1beta1.GarageKey, keyName string) string {
	if nonce := key.Annotations[keyReplacementNonceAnnotation]; nonce != "" {
		return keyName + keyReplacementIdentitySeparator + nonce
	}
	return keyName
}

func (r *GarageKeyReconciler) updateKeyIfNeeded(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	needsUpdate := false
	updateReq := garage.UpdateKeyRequest{ID: garageKey.AccessKeyID}
	desiredName := key.Name
	if key.Spec.Name != "" {
		desiredName = key.Spec.Name
	}
	if garageKey.Name != desiredName {
		updateReq.Body.Name = desiredName
		needsUpdate = true
	}

	// Only send updates when the key's current state doesn't match the spec
	isNeverExpires := garageKey.Expiration != nil && *garageKey.Expiration == "never"
	if key.Spec.NeverExpires && !isNeverExpires {
		updateReq.Body.NeverExpires = true
		needsUpdate = true
	} else if key.Spec.ExpiresAt != nil {
		desired := key.Spec.ExpiresAt.UTC().Format(time.RFC3339)
		currentExp := ""
		if garageKey.Expiration != nil {
			currentExp = *garageKey.Expiration
		}
		if currentExp != desired {
			updateReq.Body.Expiration = &desired
			needsUpdate = true
		}
	}

	if key.Spec.Permissions != nil && key.Spec.Permissions.CreateBucket != garageKey.Permissions.CreateBucket {
		if key.Spec.Permissions.CreateBucket {
			updateReq.Body.Allow = &garage.KeyPermissions{CreateBucket: true}
		} else {
			updateReq.Body.Deny = &garage.KeyPermissions{CreateBucket: true}
		}
		needsUpdate = true
	}

	if needsUpdate {
		if _, err := garageClient.UpdateKey(ctx, updateReq); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}
	}
	return nil
}

// reconcileManagedBucketPermissions converges the exact union of permissions
// declared from GarageKey and GarageBucket resources. It targets only current
// or previously operator-managed relations, preserving unrelated manual grants.
func (r *GarageKeyReconciler) reconcileManagedBucketPermissions(ctx context.Context, key *garagev1beta1.GarageKey, garageClient *garage.Client, garageKey *garage.Key) error {
	current := make(map[string]garage.BucketKeyPerms, len(garageKey.Buckets))
	for _, b := range garageKey.Buckets {
		current[b.ID] = b.Permissions
	}

	keyDesired := make(map[string]garage.BucketKeyPerms)
	explicitlyManaged := make(map[string]struct{})
	unauthorizedTargets := make(map[string]struct{})
	var permissionErrors []string
	if key.Spec.AllBuckets != nil {
		buckets, err := garageClient.ListBuckets(ctx)
		if err != nil {
			return fmt.Errorf("failed to list buckets for allBuckets permissions: %w", err)
		}
		p := garage.BucketKeyPerms{Read: key.Spec.AllBuckets.Read, Write: key.Spec.AllBuckets.Write, Owner: key.Spec.AllBuckets.Owner}
		for _, b := range buckets {
			keyDesired[b.ID] = mergeBucketPerms(keyDesired[b.ID], p)
		}
	}
	for i, p := range key.Spec.BucketPermissions {
		if p.BucketRef != nil {
			bucketNamespace := p.BucketRef.Namespace
			if bucketNamespace == "" {
				bucketNamespace = key.Namespace
			}
			if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), garageKeyKind, key.Namespace,
				"GarageBucket", bucketNamespace, p.BucketRef.Name); err != nil {
				permissionErrors = append(permissionErrors, fmt.Sprintf("spec.bucketPermissions[%d]: %v", i, err))
				bucketID, ref, pending, resolveErr := r.resolveBucketID(ctx, key, p, garageClient)
				if resolveErr != nil {
					permissionErrors = append(permissionErrors, fmt.Sprintf("resolving unauthorized bucket %s for cleanup: %v", ref, resolveErr))
				} else if !pending && bucketID != "" {
					unauthorizedTargets[bucketID] = struct{}{}
				}
				continue
			}
		}
		bucketID, ref, pending, err := r.resolveBucketID(ctx, key, p, garageClient)
		if err != nil {
			return fmt.Errorf("resolving bucket %s: %w", ref, err)
		}
		if pending {
			return fmt.Errorf("waiting for bucket %s to be ready before reconciling permissions", ref)
		}
		if bucketID != "" {
			keyDesired[bucketID] = mergeBucketPerms(keyDesired[bucketID], garage.BucketKeyPerms{Read: p.Read, Write: p.Write, Owner: p.Owner})
			explicitlyManaged[bucketID] = struct{}{}
		}
	}
	keyManaged := make([]string, 0, len(explicitlyManaged))
	for id := range explicitlyManaged {
		keyManaged = append(keyManaged, id)
	}
	sort.Strings(keyManaged)
	reservedManaged := mergeManagedGrantIDs(key.Status.ManagedBucketGrants, keyManaged)
	reservedClusterWide := key.Status.ClusterWide || key.Spec.AllBuckets != nil
	var permissionDenials []string

	desired := make(map[string]garage.BucketKeyPerms, len(keyDesired))
	targets := make(map[string]struct{})
	for id, p := range keyDesired {
		desired[id] = p
		targets[id] = struct{}{}
	}
	for _, id := range reservedManaged {
		targets[id] = struct{}{}
	}
	for id := range unauthorizedTargets {
		targets[id] = struct{}{}
	}
	// A previous allBuckets grant owns every current relation, whether or not
	// explicit per-bucket IDs are also recorded. Target them all when allBuckets
	// is removed or downgraded so stale cluster-wide grants cannot survive.
	if key.Status.ClusterWide {
		for id := range current {
			targets[id] = struct{}{}
		}
	}

	bucketList := &garagev1beta1.GarageBucketList{}
	if err := r.List(ctx, bucketList); err != nil {
		return fmt.Errorf("listing buckets for permission union: %w", err)
	}
	for i := range bucketList.Items {
		bucket := &bucketList.Items[i]
		if !sameClusterForBucketAndKey(bucket, key) {
			continue
		}
		bucketID := bucket.Status.BucketID
		if bucketID == "" {
			bucketID = bucket.Spec.BucketID
		}
		if bucketID == "" {
			continue
		}
		reverseReserved := stringSliceContains(bucket.Status.ManagedKeyGrants, garageKey.AccessKeyID)
		if reverseReserved {
			targets[bucketID] = struct{}{}
		}
		if p, ok := bucketPermissionsForKey(bucket, key); ok {
			if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), "GarageBucket", bucket.Namespace,
				garageKeyKind, key.Namespace, key.Name); err != nil {
				detail := fmt.Sprintf("GarageBucket %s/%s: %v", bucket.Namespace, bucket.Name, err)
				if garagev1beta1.IsReferenceGrantDenied(err) {
					permissionDenials = append(permissionDenials, detail)
				} else {
					permissionErrors = append(permissionErrors, detail)
				}
				continue
			}
			// The GarageBucket controller owns this declaration's durable
			// reservation. It must record the target before either controller may
			// perform the first remote allow.
			if !reverseReserved {
				continue
			}
			desired[bucketID] = mergeBucketPerms(desired[bucketID], p)
			targets[bucketID] = struct{}{}
		}
	}

	// A denied reverse cross-namespace reference is a per-key authorization
	// result, not a failure to reconcile this key. Record it before reserving
	// ownership so the warning survives a crash before the first remote
	// permission mutation. Explicit key-owned declarations remain fatal above.
	if len(permissionDenials) > 0 {
		setKeyPermissionsCondition(key, permissionDenials)
	}
	if !stringSlicesEqual(key.Status.ManagedBucketGrants, reservedManaged) || key.Status.ClusterWide != reservedClusterWide || len(permissionDenials) > 0 {
		key.Status.ManagedBucketGrants = reservedManaged
		key.Status.ClusterWide = reservedClusterWide
		if err := r.Status().Update(ctx, key); err != nil {
			return fmt.Errorf("failed to reserve managed bucket grants: %w", err)
		}
	}

	for bucketID := range targets {
		if err := reconcileExactBucketKeyPermissions(ctx, garageClient, bucketID, garageKey.AccessKeyID, current[bucketID], desired[bucketID]); err != nil {
			permissionErrors = append(permissionErrors, fmt.Sprintf("%s: %v", bucketID, err))
		}
	}
	if len(permissionErrors) > 0 {
		if len(permissionDenials) == 0 {
			setKeyPermissionsReconcileFailure(key, permissionErrors)
		}
		return fmt.Errorf("failed to reconcile bucket permissions: %v", permissionErrors)
	}
	setKeyPermissionsCondition(key, permissionDenials)

	// allBuckets ownership is represented compactly by status.clusterWide;
	// recording every Garage bucket ID here would make status grow without bound.
	desiredClusterWide := key.Spec.AllBuckets != nil
	if !stringSlicesEqual(key.Status.ManagedBucketGrants, keyManaged) || key.Status.ClusterWide != desiredClusterWide {
		key.Status.ManagedBucketGrants = keyManaged
		key.Status.ClusterWide = desiredClusterWide
		if err := r.Status().Update(ctx, key); err != nil {
			return fmt.Errorf("failed to persist managed bucket grants: %w", err)
		}
	}
	return nil
}

func setKeyPermissionsCondition(key *garagev1beta1.GarageKey, denied []string) {
	condition := metav1.Condition{
		Type:               garagev1beta1.ConditionPermissionsConfigured,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonReconcileSuccess,
		Message:            "All declared bucket permissions are configured",
		ObservedGeneration: key.Generation,
	}
	if len(denied) > 0 {
		details := append([]string(nil), denied...)
		sort.Strings(details)
		condition.Status = metav1.ConditionFalse
		condition.Reason = garagev1beta1.ReasonReferenceGrantDenied
		condition.Message = "Some bucket permission references were denied: " + strings.Join(details, "; ")
	}
	meta.SetStatusCondition(&key.Status.Conditions, condition)
}

func setKeyPermissionsReconcileFailure(key *garagev1beta1.GarageKey, failures []string) {
	details := append([]string(nil), failures...)
	sort.Strings(details)
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionPermissionsConfigured,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonReconcileFailed,
		Message:            "Bucket permissions could not be configured: " + strings.Join(details, "; "),
		ObservedGeneration: key.Generation,
	})
}

func bucketPermissionsForKey(bucket *garagev1beta1.GarageBucket, key *garagev1beta1.GarageKey) (garage.BucketKeyPerms, bool) {
	var desired garage.BucketKeyPerms
	found := false
	for _, p := range bucket.Spec.KeyPermissions {
		ns := bucket.Namespace
		if p.KeyRef.Namespace != "" {
			ns = p.KeyRef.Namespace
		}
		if p.KeyRef.Name == key.Name && ns == key.Namespace {
			desired = mergeBucketPerms(desired, garage.BucketKeyPerms{Read: p.Read, Write: p.Write, Owner: p.Owner})
			found = true
		}
	}
	return desired, found
}

func (r *GarageKeyReconciler) resolveBucketID(ctx context.Context, key *garagev1beta1.GarageKey, bucketPerm garagev1beta1.BucketPermission, garageClient *garage.Client) (bucketID, bucketRef string, pending bool, err error) {
	log := logf.FromContext(ctx)

	if bucketPerm.BucketRef != nil {
		bucketRef = bucketPerm.BucketRef.Name
		ns := key.Namespace
		if bucketPerm.BucketRef.Namespace != "" {
			ns = bucketPerm.BucketRef.Namespace
		}
		bucket := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: bucketPerm.BucketRef.Name, Namespace: ns}, bucket); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Bucket not found, will retry", "bucketRef", bucketPerm.BucketRef.Name, "namespace", ns)
				return "", bucketRef, true, nil
			}
			return "", bucketRef, false, fmt.Errorf("failed to get bucket %s/%s: %w", ns, bucketPerm.BucketRef.Name, err)
		}
		if bucket.Status.BucketID == "" {
			log.Info("Bucket not yet created in Garage, will retry", "bucketRef", bucketPerm.BucketRef.Name, "namespace", ns)
			return "", bucketRef, true, nil
		}
		if !sameClusterForBucketAndKey(bucket, key) {
			return "", bucketRef, false, fmt.Errorf("GarageBucket %s/%s targets a different GarageCluster", bucket.Namespace, bucket.Name)
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
	name                   string
	namespace              string
	accessKeyIDKey         string
	secretAccessKeyKey     string
	endpointKey            string
	hostKey                string
	schemeKey              string
	regionKey              string
	bucketNameKey          string
	credentialsFileKey     string
	credentialsFileProfile string
	includeEndpoint        bool
	includeRegion          bool
	includeBucketName      bool
	includeCredentialsFile bool
	additionalData         map[string]string
	labels                 map[string]string
	annotations            map[string]string
	secretType             corev1.SecretType
}

// resolveSecretConfig extracts and defaults secret configuration from the key spec
func resolveSecretConfig(key *garagev1beta1.GarageKey) secretConfig {
	cfg := secretConfig{
		name:                   key.Name,
		namespace:              key.Namespace,
		accessKeyIDKey:         defaultAccessKeyIDKey,
		secretAccessKeyKey:     defaultSecretAccessKeyKey,
		endpointKey:            defaultEndpointKey,
		hostKey:                defaultHostKey,
		schemeKey:              defaultSchemeKey,
		regionKey:              defaultRegionKey,
		bucketNameKey:          defaultBucketNameKey,
		credentialsFileKey:     defaultCredentialsFileKey,
		credentialsFileProfile: defaultCredentialsProfile,
		includeEndpoint:        true,
		includeRegion:          true,
		labels: map[string]string{
			labelAppManagedBy:          "garage-operator",
			"garage.rajsingh.info/key": key.Name,
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
	if tmpl.BucketNameKey != "" {
		cfg.bucketNameKey = tmpl.BucketNameKey
	}
	if tmpl.CredentialsFileKey != "" {
		cfg.credentialsFileKey = tmpl.CredentialsFileKey
	}
	if tmpl.CredentialsFileProfile != "" {
		cfg.credentialsFileProfile = tmpl.CredentialsFileProfile
	}
	if tmpl.IncludeEndpoint != nil {
		cfg.includeEndpoint = *tmpl.IncludeEndpoint
	}
	if tmpl.IncludeRegion != nil {
		cfg.includeRegion = *tmpl.IncludeRegion
	}
	if tmpl.IncludeBucketName != nil {
		cfg.includeBucketName = *tmpl.IncludeBucketName
	}
	if tmpl.IncludeCredentialsFile != nil {
		cfg.includeCredentialsFile = *tmpl.IncludeCredentialsFile
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

// buildSecretData constructs the secret data map based on configuration.
// s3 is nil when the Secret carries no endpoint keys.
func (r *GarageKeyReconciler) buildSecretData(ctx context.Context, cfg secretConfig, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, secretAccessKey string, s3 *url.URL) map[string][]byte {
	data := map[string][]byte{
		cfg.accessKeyIDKey: []byte(key.Status.AccessKeyID),
	}

	if secretAccessKey != "" {
		data[cfg.secretAccessKeyKey] = []byte(secretAccessKey)
	}

	if cfg.includeEndpoint && s3 != nil {
		data[cfg.endpointKey] = []byte(s3.String())
		data[cfg.hostKey] = []byte(s3.Host)
		data[cfg.schemeKey] = []byte(s3.Scheme)
	}

	if cfg.includeRegion {
		region := defaultS3Region
		if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
			region = cluster.Spec.S3API.Region
		}
		data[cfg.regionKey] = []byte(region)
	}

	if cfg.includeBucketName {
		if name, ok := r.singleBucketName(ctx, key); ok {
			data[cfg.bucketNameKey] = []byte(name)
		}
	}

	for k, v := range cfg.additionalData {
		data[k] = []byte(v)
	}

	writeCredentialsFile(data, cfg, key.Status.AccessKeyID, secretAccessKey)

	return data
}

// writeCredentialsFile writes the standard AWS shared credentials file when
// enabled and both generated credential values are available.
func writeCredentialsFile(data map[string][]byte, cfg secretConfig, accessKeyID, secretAccessKey string) {
	if !cfg.includeCredentialsFile || accessKeyID == "" || secretAccessKey == "" {
		return
	}
	data[cfg.credentialsFileKey] = []byte(fmt.Sprintf(
		"[%s]\naws_access_key_id=%s\naws_secret_access_key=%s\n",
		cfg.credentialsFileProfile,
		accessKeyID,
		secretAccessKey,
	))
}

// singleBucketName returns the bucket name when the key references exactly one
// bucket via bucketRef (with a name) or globalAlias. It returns ("", false) for
// the ambiguous cases: zero permissions, more than one permission, allBuckets,
// or a single permission that carries neither a bucketRef name nor a globalAlias.
func (r *GarageKeyReconciler) singleBucketName(ctx context.Context, key *garagev1beta1.GarageKey) (string, bool) {
	if key.Spec.AllBuckets != nil {
		return "", false
	}
	perms := key.Spec.BucketPermissions
	if len(perms) != 1 {
		return "", false
	}
	p := perms[0]
	if p.GlobalAlias != "" {
		return p.GlobalAlias, true
	}
	if p.BucketRef != nil && p.BucketRef.Name != "" {
		ns := p.BucketRef.Namespace
		if ns == "" {
			ns = key.Namespace
		}
		bucket := &garagev1beta1.GarageBucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: p.BucketRef.Name, Namespace: ns}, bucket); err == nil {
			if bucket.Spec.GlobalAlias != "" {
				return bucket.Spec.GlobalAlias, true
			}
		}
		return p.BucketRef.Name, true
	}
	return "", false
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

func (r *GarageKeyReconciler) reconcileSecret(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, secretAccessKey string) error {
	log := logf.FromContext(ctx)
	var previousRef *corev1.SecretReference
	if key.Status.SecretRef != nil {
		copy := *key.Status.SecretRef
		previousRef = &copy
	}

	cfg := resolveSecretConfig(key)
	var s3 *url.URL
	if cfg.includeEndpoint {
		var err error
		if s3, err = ResolveS3Endpoint(cluster, r.ClusterDomain); err != nil {
			return fmt.Errorf("%w; set secretTemplate.includeEndpoint=false and configure the consumer's explicit S3 endpoint", err)
		}
	}
	if key.UID == "" {
		return fmt.Errorf("cannot reconcile generated Secret before GarageKey UID is assigned")
	}
	// This protected marker is written to both sides of a rename before status
	// advances. If deletion then fails or the process crashes, the next reconcile
	// can discover and remove the stale exact-owned credential without another
	// status field. Import snapshots and COSI reservation Secrets never receive it.
	cfg.labels[keyGeneratedSecretOwnerLabel] = string(key.UID)
	if err := r.markPreviousGeneratedSecret(ctx, key, previousRef); err != nil {
		return err
	}
	secretData := r.buildSecretData(ctx, cfg, key, cluster, secretAccessKey, s3)

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
		return r.finishGarageKeySecretHandoff(ctx, key, previousRef)
	}
	if err != nil {
		return err
	}
	controllerRef := metav1.GetControllerOf(existing)
	if controllerRef == nil || key.UID == "" || controllerRef.UID != key.UID {
		return fmt.Errorf("refusing to overwrite Secret %s/%s because it is not controlled by GarageKey %s/%s", cfg.namespace, cfg.name, key.Namespace, key.Name)
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
	// Rebuild the composed value from the effective credential material. This
	// keeps it in sync both when a new secret is returned and when the existing
	// secret access key is preserved during an ordinary reconciliation.
	writeCredentialsFile(secretData, cfg, key.Status.AccessKeyID, string(secretData[cfg.secretAccessKeyKey]))

	// Skip update if nothing changed — avoids triggering Owns() watch and re-reconciliation
	if secretDataEqual(existing.Data, secretData) &&
		mapsEqual(existing.Labels, cfg.labels) &&
		mapsEqual(existing.Annotations, cfg.annotations) {
		key.Status.SecretRef = &corev1.SecretReference{Name: cfg.name, Namespace: cfg.namespace}
		return r.finishGarageKeySecretHandoff(ctx, key, previousRef)
	}

	existing.Data = secretData
	existing.Labels = cfg.labels
	existing.Annotations = cfg.annotations
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	key.Status.SecretRef = &corev1.SecretReference{Name: cfg.name, Namespace: cfg.namespace}
	return r.finishGarageKeySecretHandoff(ctx, key, previousRef)
}

// finishGarageKeySecretHandoff persists the new exact Secret identity before
// deleting the prior exact-owned Secret. A crash can therefore leave two
// recoverable copies temporarily, but never an untracked live credential.
func (r *GarageKeyReconciler) finishGarageKeySecretHandoff(ctx context.Context, key *garagev1beta1.GarageKey, previous *corev1.SecretReference) error {
	current := key.Status.SecretRef
	if current == nil {
		return fmt.Errorf("generated GarageKey Secret identity is empty")
	}
	changed := previous == nil || previous.Name != current.Name || previous.Namespace != current.Namespace
	if changed {
		if err := UpdateStatusWithRetry(ctx, r.Client, key); err != nil {
			return fmt.Errorf("persisting generated Secret handoff: %w", err)
		}
	}
	return r.cleanupStaleGeneratedSecrets(ctx, key, current)
}

func (r *GarageKeyReconciler) markPreviousGeneratedSecret(ctx context.Context, key *garagev1beta1.GarageKey, previous *corev1.SecretReference) error {
	if previous == nil {
		return nil
	}
	if previous.Namespace != key.Namespace {
		return fmt.Errorf("refusing to mark previous generated Secret outside GarageKey namespace: %s/%s", previous.Namespace, previous.Name)
	}
	old := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: previous.Name, Namespace: previous.Namespace}, old); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading previous generated Secret before handoff: %w", err)
	}
	if !metav1.IsControlledBy(old, key) {
		return fmt.Errorf("refusing to mark previous Secret %s/%s because it is not controlled by GarageKey %s/%s", old.Namespace, old.Name, key.Namespace, key.Name)
	}
	if old.Labels == nil {
		old.Labels = map[string]string{}
	}
	if old.Labels[keyGeneratedSecretOwnerLabel] == string(key.UID) {
		return nil
	}
	old.Labels[keyGeneratedSecretOwnerLabel] = string(key.UID)
	if err := r.Update(ctx, old); err != nil {
		return fmt.Errorf("marking previous generated Secret %s/%s for handoff cleanup: %w", old.Namespace, old.Name, err)
	}
	return nil
}

func (r *GarageKeyReconciler) cleanupStaleGeneratedSecrets(ctx context.Context, key *garagev1beta1.GarageKey, current *corev1.SecretReference) error {
	secrets := &corev1.SecretList{}
	if err := r.List(ctx, secrets, client.InNamespace(key.Namespace), client.MatchingLabels{
		keyGeneratedSecretOwnerLabel: string(key.UID),
	}); err != nil {
		return fmt.Errorf("listing generated GarageKey Secrets for handoff cleanup: %w", err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if current != nil && secret.Name == current.Name && secret.Namespace == current.Namespace {
			continue
		}
		if !metav1.IsControlledBy(secret, key) {
			continue
		}
		uid := secret.UID
		if err := r.Delete(ctx, secret, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting stale generated Secret %s/%s: %w", secret.Namespace, secret.Name, err)
		}
	}
	return nil
}

func (r *GarageKeyReconciler) finalize(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	accessKeyIDs, resolvedDeterministic, err := r.deterministicGarageKeyFinalizationIDs(ctx, key, cluster, garageClient)
	if err != nil {
		return err
	}
	if !resolvedDeterministic {
		accessKeyID, resolveErr := r.garageKeyFinalizationID(ctx, key, cluster)
		if resolveErr != nil {
			return resolveErr
		}
		if accessKeyID == "" {
			return nil
		}
		accessKeyIDs = []string{accessKeyID}
	}

	// Pre-revoke every per-bucket grant the operator believes this key has before
	// calling DeleteKey. Upstream DeleteKey iterates state.authorized_buckets
	// sequentially and calls set_bucket_key_permissions per bucket — if a single
	// bucket is wedged (e.g. its RPC lookup never returns), DeleteKey hangs
	// forever and our client's request-level timeout is the only escape. By
	// clearing the grants first, with a fresh short timeout per call, one stuck
	// bucket can't poison the whole finalize. Each iteration has its own
	// context so we keep making progress even when some calls time out.
	bucketIDs := make(map[string]struct{}, len(key.Status.Buckets)+len(key.Status.ManagedBucketGrants)+len(key.Spec.BucketPermissions))
	for _, bucket := range key.Status.Buckets {
		if bucket.BucketID != "" {
			bucketIDs[bucket.BucketID] = struct{}{}
		}
	}
	for _, bucketID := range key.Status.ManagedBucketGrants {
		if bucketID != "" {
			bucketIDs[bucketID] = struct{}{}
		}
	}
	for _, permission := range key.Spec.BucketPermissions {
		if permission.BucketID != "" {
			bucketIDs[permission.BucketID] = struct{}{}
		}
	}
	orderedBucketIDs := make([]string, 0, len(bucketIDs))
	for bucketID := range bucketIDs {
		orderedBucketIDs = append(orderedBucketIDs, bucketID)
	}
	sort.Strings(orderedBucketIDs)
	for _, accessKeyID := range accessKeyIDs {
		for _, bucketID := range orderedBucketIDs {
			denyCtx, cancel := context.WithTimeout(ctx, finalizeRPCTimeout)
			_, denyErr := garageClient.DenyBucketKey(denyCtx, garage.DenyBucketKeyRequest{
				BucketID:    bucketID,
				AccessKeyID: accessKeyID,
				Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
			})
			cancel()
			if denyErr != nil {
				if garage.IsNotFound(denyErr) {
					continue
				}
				log.Info("Pre-revoke of bucket grant failed; continuing",
					"bucketID", bucketID, "accessKeyID", accessKeyID, "error", denyErr)
			}
		}

		log.Info("Deleting key", "accessKeyID", accessKeyID)
		delCtx, cancel := context.WithTimeout(ctx, finalizeRPCTimeout)
		deleteErr := garageClient.DeleteKey(delCtx, accessKeyID)
		cancel()
		if deleteErr != nil {
			if garage.IsNotFound(deleteErr) {
				log.Info("Key already deleted or not found", "accessKeyID", accessKeyID)
				continue
			}
			return fmt.Errorf("failed to delete key %s: %w", accessKeyID, deleteErr)
		}
	}

	return nil
}

// deterministicGarageKeyFinalizationIDs resolves the pre-v0.7.4 mutable
// display-name identity versus the metadata.name-bound identity. Empty status
// can mean either remote write committed immediately before a crash, so probe
// both exact IDs and accept only material derived from this cluster's RPC
// secret. If both exist (for example during a mixed-version race), both are
// owned and must be removed.
func (r *GarageKeyReconciler) deterministicGarageKeyFinalizationIDs(
	ctx context.Context,
	key *garagev1beta1.GarageKey,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
) ([]string, bool, error) {
	if cluster == nil || key.Spec.ImportKey != nil || key.Status.AccessKeyID != "" ||
		key.Annotations[garagev1beta1.AnnotationCOSIAccountID] != "" ||
		key.Annotations[keyResolvedImportIDAnnotation] != "" {
		return nil, false, nil
	}
	rpcSecret, err := GetRPCSecret(ctx, r.Client, cluster)
	if err != nil {
		return nil, true, fmt.Errorf("deriving deterministic finalization identities: %w", err)
	}
	type candidate struct {
		id     string
		secret string
	}
	canonicalID, canonicalSecret := deriveKeyMaterial(rpcSecret, key.Namespace, deterministicKeyName(key))
	candidates := []candidate{{id: canonicalID, secret: canonicalSecret}}
	if key.Spec.Name != "" && key.Spec.Name != key.Name {
		legacyID, legacySecret := deriveKeyMaterial(rpcSecret, key.Namespace, legacyDeterministicKeyName(key, key.Spec.Name))
		if legacyID != canonicalID {
			candidates = append([]candidate{{id: legacyID, secret: legacySecret}}, candidates...)
		}
	}
	resolved := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		existing, lookupErr := garageClient.GetKey(ctx, garage.GetKeyRequest{ID: candidate.id, ShowSecretKey: true})
		if garage.IsNotFound(lookupErr) {
			continue
		}
		if lookupErr != nil {
			return nil, true, fmt.Errorf("verifying deterministic finalization identity %s: %w", candidate.id, lookupErr)
		}
		if existing.AccessKeyID != candidate.id || existing.SecretAccessKey != candidate.secret {
			return nil, true, fmt.Errorf("refusing deterministic GarageKey finalization because remote key %s has different secret material", candidate.id)
		}
		resolved = append(resolved, candidate.id)
	}
	return resolved, true, nil
}

func (r *GarageKeyReconciler) garageKeyFinalizationID(ctx context.Context, key *garagev1beta1.GarageKey, cluster *garagev1beta2.GarageCluster) (string, error) {
	candidates := map[string]string{
		"status.accessKeyId": key.Status.AccessKeyID,
	}
	if key.Spec.ImportKey != nil {
		candidates["spec.importKey.accessKeyId"] = key.Spec.ImportKey.AccessKeyID
		if ref := key.Spec.ImportKey.SecretRef; ref != nil {
			snapshot := &corev1.Secret{}
			snapshotKey := types.NamespacedName{Name: importKeySnapshotName(key), Namespace: key.Namespace}
			snapshotErr := r.Get(ctx, snapshotKey, snapshot)
			if snapshotErr == nil {
				accessKeyID, _, err := r.importKeySnapshotMaterial(key, snapshot)
				if err != nil {
					return "", err
				}
				candidates["import material snapshot"] = accessKeyID
			} else if !errors.IsNotFound(snapshotErr) {
				return "", fmt.Errorf("reading import material snapshot for finalization identity: %w", snapshotErr)
			}

			if errors.IsNotFound(snapshotErr) && key.Status.AccessKeyID == "" &&
				key.Annotations[garagev1beta1.AnnotationCOSIAccountID] == "" {
				return "", fmt.Errorf("refusing GarageKey finalization without an immutable import snapshot or recorded access key ID; mutable source Secret %s cannot prove remote ownership", ref.Name)
			}
		}
	} else if cluster != nil && key.Status.AccessKeyID == "" && key.Annotations[garagev1beta1.AnnotationCOSIAccountID] == "" {
		rpcSecret, err := GetRPCSecret(ctx, r.Client, cluster)
		if err != nil {
			return "", fmt.Errorf("deriving deterministic finalization identity: %w", err)
		}
		derivedID, _ := deriveKeyMaterial(rpcSecret, key.Namespace, deterministicKeyName(key))
		candidates["deterministic RPC identity"] = derivedID
	}

	var resolved string
	for source, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if resolved != "" && candidate != resolved {
			return "", fmt.Errorf("refusing GarageKey finalization because %s=%q disagrees with resolved access key ID %q", source, candidate, resolved)
		}
		resolved = candidate
	}
	if pinned := key.Annotations[keyResolvedImportIDAnnotation]; pinned != "" {
		if resolved == "" {
			return "", fmt.Errorf("refusing GarageKey finalization because resolved-import-access-key-id annotation %q has no authoritative status, spec, or snapshot identity", pinned)
		}
		if pinned != resolved {
			return "", fmt.Errorf("refusing GarageKey finalization because resolved-import-access-key-id annotation %q disagrees with authoritative access key ID %q", pinned, resolved)
		}
	}
	if cosiAccountID := key.Annotations[garagev1beta1.AnnotationCOSIAccountID]; cosiAccountID != "" {
		if resolved == "" {
			return "", fmt.Errorf("refusing GarageKey finalization because COSI account ID annotation %q has no controller-owned status identity", cosiAccountID)
		}
		if cosiAccountID != resolved {
			return "", fmt.Errorf("refusing GarageKey finalization because COSI account ID annotation %q disagrees with authoritative access key ID %q", cosiAccountID, resolved)
		}
	}
	return resolved, nil
}

// updateStatusWaiting records a ClusterNotReady wait. cause, when non-nil, is
// the connectivity error that triggered the wait; its text is folded into the
// condition message (see waitingForClusterMessage) so a permanent
// misconfiguration (e.g. an unresolvable cluster-domain) is visible on the CR
// itself rather than only in operator debug logs.
func (r *GarageKeyReconciler) updateStatusWaiting(ctx context.Context, key *garagev1beta1.GarageKey, cause error) (ctrl.Result, error) {
	key.Status.Phase = PhasePending
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonClusterNotReady,
		Message:            waitingForClusterMessage(cause),
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
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
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
			return r.updateStatusWaiting(ctx, key, err)
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
		return r.updateStatus(ctx, key, PhaseFailed, fmt.Errorf("failed to get key info: %w", err))
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
		if t, err := time.Parse(time.RFC3339, *garageKey.Expiration); err == nil {
			mt := metav1.NewTime(t)
			key.Status.ExpiresAt = &mt
		} else {
			key.Status.ExpiresAt = nil
		}
	} else {
		key.Status.ExpiresAt = nil
	}
	if key.Spec.ExpiresAt != nil && time.Now().After(key.Spec.ExpiresAt.Time) {
		key.Status.Phase = PhaseExpired
	}
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
		Type:               PhaseReady,
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
