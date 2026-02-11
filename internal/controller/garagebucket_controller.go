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
	"sort"
	"time"

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

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageBucketFinalizer = "garagebucket.garage.rajsingh.info/finalizer"
)

// GarageBucketReconciler reconciles a GarageBucket object
type GarageBucketReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets/finalizers,verbs=update
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=get;list;watch

func (r *GarageBucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	bucket := &garagev1alpha1.GarageBucket{}
	if err := r.Get(ctx, req.NamespacedName, bucket); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Get the cluster reference
	cluster := &garagev1alpha1.GarageCluster{}
	clusterNamespace := bucket.Namespace
	if bucket.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = bucket.Spec.ClusterRef.Namespace
	}
	clusterErr := r.Get(ctx, types.NamespacedName{
		Name:      bucket.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster)

	// Handle deletion - check this early so we can handle cluster-gone case
	if !bucket.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
			// If cluster is gone, skip finalization and just remove finalizer
			if clusterErr != nil && errors.IsNotFound(clusterErr) {
				log.Info("Cluster is gone, skipping bucket finalization", "cluster", bucket.Spec.ClusterRef.Name)
				controllerutil.RemoveFinalizer(bucket, garageBucketFinalizer)
				if err := r.Update(ctx, bucket); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
		}
	}

	// Now check cluster error for non-deletion cases
	if clusterErr != nil {
		return r.updateStatus(ctx, bucket, "Error", fmt.Errorf("cluster not found: %w", clusterErr))
	}

	// Get garage client
	garageClient, err := GetGarageClient(ctx, r.Client, cluster)
	if err != nil {
		return r.updateStatus(ctx, bucket, "Error", fmt.Errorf("failed to create garage client: %w", err))
	}

	// Handle deletion (cluster exists at this point)
	if !bucket.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
			if err := r.finalize(ctx, bucket, garageClient); err != nil {
				// Check if we've exceeded max retries
				if ShouldSkipFinalization(bucket) {
					log.Info("Finalization failed too many times, removing finalizer anyway",
						"retries", GetFinalizationRetryCount(bucket), "error", err)
				} else {
					IncrementFinalizationRetryCount(bucket)
					log.Error(err, "Failed to finalize bucket, will retry",
						"retries", GetFinalizationRetryCount(bucket))
					// Surface the finalization error in status before requeuing
					_, _ = r.updateStatus(ctx, bucket, PhaseDeleting, fmt.Errorf("finalization failed: %w", err))
					if updateErr := r.Update(ctx, bucket); updateErr != nil {
						log.Error(updateErr, "Failed to update retry count annotation")
					}
					return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
				}
			}
			controllerutil.RemoveFinalizer(bucket, garageBucketFinalizer)
			if err := r.Update(ctx, bucket); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
		controllerutil.AddFinalizer(bucket, garageBucketFinalizer)
		if err := r.Update(ctx, bucket); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the bucket
	if err := r.reconcileBucket(ctx, bucket, garageClient); err != nil {
		return r.updateStatus(ctx, bucket, "Error", err)
	}

	return r.updateStatusFromGarage(ctx, bucket, garageClient)
}

func (r *GarageBucketReconciler) reconcileBucket(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	alias := bucket.Name
	if bucket.Spec.GlobalAlias != "" {
		alias = bucket.Spec.GlobalAlias
	}

	existingBucket, err := r.getOrCreateBucket(ctx, bucket, garageClient, alias)
	if err != nil {
		return err
	}

	if err := r.updateBucketSettings(ctx, bucket, garageClient, existingBucket); err != nil {
		return err
	}

	if err := r.reconcileKeyPermissions(ctx, bucket, garageClient, existingBucket.ID); err != nil {
		return err
	}

	if err := r.reconcileLocalAliases(ctx, bucket, garageClient, existingBucket.ID); err != nil {
		return err
	}

	if err := r.reconcileClusterWideKeys(ctx, bucket, garageClient, existingBucket.ID); err != nil {
		return err
	}

	log.V(1).Info("Bucket reconciled successfully", "bucketID", existingBucket.ID)
	return nil
}

func (r *GarageBucketReconciler) getOrCreateBucket(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client, alias string) (*garage.Bucket, error) {
	log := logf.FromContext(ctx)

	if bucket.Status.BucketID != "" {
		existing, err := garageClient.GetBucket(ctx, garage.GetBucketRequest{ID: bucket.Status.BucketID})
		if err == nil {
			return existing, nil
		}
	}

	existing, err := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: alias})
	if err == nil {
		bucket.Status.BucketID = existing.ID
		return existing, nil
	}

	log.Info("Creating bucket", "alias", alias)
	created, err := garageClient.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: alias})
	if err != nil {
		if garage.IsConflict(err) {
			log.Info("Bucket creation conflict, checking if it was created by another controller", "alias", alias)
			existing, getErr := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: alias})
			if getErr != nil {
				return nil, fmt.Errorf("failed to create bucket (conflict) and failed to get existing bucket: %w (original: %v)", getErr, err)
			}
			bucket.Status.BucketID = existing.ID
			return existing, nil
		}
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	bucket.Status.BucketID = created.ID
	return created, nil
}

func (r *GarageBucketReconciler) updateBucketSettings(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client, existingBucket *garage.Bucket) error {
	updateReq := garage.UpdateBucketRequest{ID: existingBucket.ID}
	needsUpdate := false

	if websiteAccess := buildWebsiteAccess(bucket.Spec.Website, existingBucket); websiteAccess != nil {
		updateReq.Body.WebsiteAccess = websiteAccess
		needsUpdate = true
	}

	if quotas := buildQuotasUpdate(bucket.Spec.Quotas, existingBucket.Quotas); quotas != nil {
		updateReq.Body.Quotas = quotas
		needsUpdate = true
	}

	if needsUpdate {
		if _, err := garageClient.UpdateBucket(ctx, updateReq); err != nil {
			return fmt.Errorf("failed to update bucket: %w", err)
		}
	}
	return nil
}

func buildWebsiteAccess(spec *garagev1alpha1.WebsiteConfig, existing *garage.Bucket) *garage.UpdateBucketWebsiteAccess {
	// If spec is nil but website is currently enabled, disable it
	if spec == nil {
		if existing.WebsiteAccess {
			return &garage.UpdateBucketWebsiteAccess{
				Enabled: false,
			}
		}
		return nil
	}
	indexDoc := spec.IndexDocument
	if spec.Enabled && indexDoc == "" {
		indexDoc = "index.html"
	}

	currentIndex := ""
	currentError := ""
	if existing.WebsiteConfig != nil {
		currentIndex = existing.WebsiteConfig.IndexDocument
		currentError = existing.WebsiteConfig.ErrorDocument
	}

	if spec.Enabled != existing.WebsiteAccess ||
		(spec.Enabled && (indexDoc != currentIndex || spec.ErrorDocument != currentError)) {
		return &garage.UpdateBucketWebsiteAccess{
			Enabled:       spec.Enabled,
			IndexDocument: indexDoc,
			ErrorDocument: spec.ErrorDocument,
		}
	}
	return nil
}

func buildQuotasUpdate(spec *garagev1alpha1.BucketQuotas, current *garage.BucketQuotas) *garage.BucketQuotas {
	// If spec is nil but quotas are currently set, clear them
	if spec == nil {
		if current != nil && (current.MaxSize != nil || current.MaxObjects != nil) {
			return &garage.BucketQuotas{MaxSize: nil, MaxObjects: nil}
		}
		return nil
	}
	var desiredMaxSize, desiredMaxObjects *uint64
	if spec.MaxSize != nil {
		v := uint64(spec.MaxSize.Value())
		desiredMaxSize = &v
	}
	if spec.MaxObjects != nil {
		v := uint64(*spec.MaxObjects)
		desiredMaxObjects = &v
	}

	if !quotasChanged(current, desiredMaxSize, desiredMaxObjects) {
		return nil
	}
	return &garage.BucketQuotas{MaxSize: desiredMaxSize, MaxObjects: desiredMaxObjects}
}

func quotasChanged(current *garage.BucketQuotas, desiredSize, desiredObjects *uint64) bool {
	if current == nil {
		return desiredSize != nil || desiredObjects != nil
	}
	if (desiredSize == nil) != (current.MaxSize == nil) {
		return true
	}
	if desiredSize != nil && current.MaxSize != nil && *desiredSize != *current.MaxSize {
		return true
	}
	if (desiredObjects == nil) != (current.MaxObjects == nil) {
		return true
	}
	if desiredObjects != nil && current.MaxObjects != nil && *desiredObjects != *current.MaxObjects {
		return true
	}
	return false
}

func (r *GarageBucketReconciler) reconcileKeyPermissions(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client, bucketID string) error {
	log := logf.FromContext(ctx)
	var permissionErrors []string
	pendingKeys := false

	for _, keyPerm := range bucket.Spec.KeyPermissions {
		key := &garagev1alpha1.GarageKey{}
		if err := r.Get(ctx, types.NamespacedName{Name: keyPerm.KeyRef, Namespace: bucket.Namespace}, key); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Key not found, will retry", "keyRef", keyPerm.KeyRef)
				pendingKeys = true
				continue
			}
			return fmt.Errorf("failed to get key %s: %w", keyPerm.KeyRef, err)
		}

		if key.Status.AccessKeyID == "" {
			log.Info("Key not yet created, will retry", "keyRef", keyPerm.KeyRef)
			pendingKeys = true
			continue
		}

		_, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    bucketID,
			AccessKeyID: key.Status.AccessKeyID,
			Permissions: garage.BucketKeyPerms{Read: keyPerm.Read, Write: keyPerm.Write, Owner: keyPerm.Owner},
		})
		if err != nil {
			log.Error(err, "Failed to set key permissions", "keyRef", keyPerm.KeyRef)
			permissionErrors = append(permissionErrors, fmt.Sprintf("%s: %v", keyPerm.KeyRef, err))
		}
	}

	if pendingKeys {
		return fmt.Errorf("waiting for keys to be ready before granting permissions")
	}
	if len(permissionErrors) > 0 {
		return fmt.Errorf("failed to set permissions for keys: %v", permissionErrors)
	}
	return nil
}

func (r *GarageBucketReconciler) reconcileLocalAliases(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client, bucketID string) error {
	log := logf.FromContext(ctx)
	var aliasErrors []string
	pendingAliasKeys := false

	for _, localAlias := range bucket.Spec.LocalAliases {
		key := &garagev1alpha1.GarageKey{}
		if err := r.Get(ctx, types.NamespacedName{Name: localAlias.KeyRef, Namespace: bucket.Namespace}, key); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Key for local alias not found, will retry", "keyRef", localAlias.KeyRef, "alias", localAlias.Alias)
				pendingAliasKeys = true
				continue
			}
			return fmt.Errorf("failed to get key %s for local alias: %w", localAlias.KeyRef, err)
		}

		if key.Status.AccessKeyID == "" {
			log.Info("Key for local alias not yet created, will retry", "keyRef", localAlias.KeyRef, "alias", localAlias.Alias)
			pendingAliasKeys = true
			continue
		}

		_, err := garageClient.AddBucketAlias(ctx, garage.AddBucketAliasRequest{
			BucketID:    bucketID,
			LocalAlias:  localAlias.Alias,
			AccessKeyID: key.Status.AccessKeyID,
		})
		if err != nil && !garage.IsConflict(err) {
			log.Error(err, "Failed to add local alias", "keyRef", localAlias.KeyRef, "alias", localAlias.Alias)
			aliasErrors = append(aliasErrors, fmt.Sprintf("%s:%s: %v", localAlias.KeyRef, localAlias.Alias, err))
		}
	}

	if pendingAliasKeys {
		return fmt.Errorf("waiting for keys to be ready before creating local aliases")
	}
	if len(aliasErrors) > 0 {
		return fmt.Errorf("failed to create local aliases: %v", aliasErrors)
	}
	return nil
}

func (r *GarageBucketReconciler) reconcileClusterWideKeys(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client, bucketID string) error {
	log := logf.FromContext(ctx)

	keyList := &garagev1alpha1.GarageKeyList{}
	if err := r.List(ctx, keyList, client.InNamespace(bucket.Namespace)); err != nil {
		return fmt.Errorf("failed to list keys for cluster-wide grants: %w", err)
	}

	// Resolve the bucket's effective cluster namespace
	bucketClusterNs := bucket.Namespace
	if bucket.Spec.ClusterRef.Namespace != "" {
		bucketClusterNs = bucket.Spec.ClusterRef.Namespace
	}

	var permErrors []string
	for i := range keyList.Items {
		key := &keyList.Items[i]
		if key.Spec.AllBuckets == nil {
			continue
		}
		// Skip keys targeting a different cluster (compare both name and resolved namespace)
		keyClusterNs := key.Namespace
		if key.Spec.ClusterRef.Namespace != "" {
			keyClusterNs = key.Spec.ClusterRef.Namespace
		}
		if key.Spec.ClusterRef.Name != bucket.Spec.ClusterRef.Name || keyClusterNs != bucketClusterNs {
			continue
		}
		if key.Status.AccessKeyID == "" {
			log.Info("Skipping cluster-wide key with no AccessKeyID yet", "key", key.Name)
			continue
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

		if denyPerms.Read || denyPerms.Write || denyPerms.Owner {
			_, err := garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{
				BucketID:    bucketID,
				AccessKeyID: key.Status.AccessKeyID,
				Permissions: denyPerms,
			})
			if err != nil && !garage.IsNotFound(err) {
				log.Error(err, "Failed to deny cluster-wide key permissions on bucket", "key", key.Name, "bucketId", bucketID)
				permErrors = append(permErrors, fmt.Sprintf("%s: deny: %v", key.Name, err))
				continue
			}
		}

		_, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
			BucketID:    bucketID,
			AccessKeyID: key.Status.AccessKeyID,
			Permissions: desired,
		})
		if err != nil {
			log.Error(err, "Failed to grant cluster-wide key access to bucket", "key", key.Name, "bucketId", bucketID)
			permErrors = append(permErrors, fmt.Sprintf("%s: allow: %v", key.Name, err))
		}
	}

	if len(permErrors) > 0 {
		return fmt.Errorf("failed to grant cluster-wide key access: %v", permErrors)
	}
	return nil
}

func (r *GarageBucketReconciler) finalize(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	if bucket.Status.BucketID == "" {
		return nil
	}

	log.Info("Deleting bucket", "bucketID", bucket.Status.BucketID)

	// Note: Garage requires bucket to be empty before deletion
	// The operator doesn't delete objects - that's the user's responsibility
	if err := garageClient.DeleteBucket(ctx, bucket.Status.BucketID); err != nil {
		// Check if bucket doesn't exist (404) - that's okay, we can proceed
		if garage.IsNotFound(err) {
			log.Info("Bucket already deleted or not found", "bucketID", bucket.Status.BucketID)
			return nil
		}
		// Specific error for bucket not empty - give user actionable message
		if garage.IsBucketNotEmpty(err) {
			return fmt.Errorf("bucket %q is not empty - delete all objects before removing the GarageBucket resource", bucket.Name)
		}
		// For other errors, return generic message
		return fmt.Errorf("failed to delete bucket: %w", err)
	}

	return nil
}

func (r *GarageBucketReconciler) updateStatus(ctx context.Context, bucket *garagev1alpha1.GarageBucket, phase string, err error) (ctrl.Result, error) {
	bucket.Status.Phase = phase
	// Only set ObservedGeneration when reconciliation succeeded
	if err == nil {
		bucket.Status.ObservedGeneration = bucket.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "Error",
			Message:            err.Error(),
			ObservedGeneration: bucket.Generation,
		})
	}

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, bucket); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	return ctrl.Result{}, nil
}

func (r *GarageBucketReconciler) updateStatusFromGarage(ctx context.Context, bucket *garagev1alpha1.GarageBucket, garageClient *garage.Client) (ctrl.Result, error) {
	if bucket.Status.BucketID == "" {
		return r.updateStatus(ctx, bucket, "Pending", nil)
	}

	// Get bucket info from Garage
	garageBucket, err := garageClient.GetBucket(ctx, garage.GetBucketRequest{ID: bucket.Status.BucketID})
	if err != nil {
		return r.updateStatus(ctx, bucket, "Error", fmt.Errorf("failed to get bucket info: %w", err))
	}

	// Capture old status before modifications to detect no-op updates
	oldStatus := bucket.Status.DeepCopy()

	// Update status
	bucket.Status.Phase = PhaseReady
	bucket.Status.ObservedGeneration = bucket.Generation
	bucket.Status.ObjectCount = garageBucket.Objects
	bucket.Status.Size = formatBytes(garageBucket.Bytes)

	// Parse creation timestamp
	if garageBucket.Created != "" {
		if t, err := time.Parse(time.RFC3339, garageBucket.Created); err == nil {
			bucket.Status.CreatedAt = &metav1.Time{Time: t}
		}
	}

	// Update incomplete upload stats
	bucket.Status.IncompleteUploads = garageBucket.UnfinishedMultipartUploads
	bucket.Status.IncompleteUploadParts = garageBucket.UnfinishedMultipartUploadParts
	bucket.Status.IncompleteUploadBytes = garageBucket.UnfinishedMultipartUploadBytes

	// Update website status
	bucket.Status.WebsiteEnabled = garageBucket.WebsiteAccess
	if garageBucket.WebsiteConfig != nil {
		bucket.Status.WebsiteConfig = &garagev1alpha1.WebsiteConfigStatus{
			IndexDocument: garageBucket.WebsiteConfig.IndexDocument,
			ErrorDocument: garageBucket.WebsiteConfig.ErrorDocument,
		}
	} else {
		bucket.Status.WebsiteConfig = nil
	}

	// Update quota usage status
	bucket.Status.QuotaUsage = &garagev1alpha1.QuotaUsageStatus{
		SizeBytes:   garageBucket.Bytes,
		ObjectCount: garageBucket.Objects,
	}
	if garageBucket.Quotas != nil {
		if garageBucket.Quotas.MaxSize != nil {
			bucket.Status.QuotaUsage.SizeLimit = int64(*garageBucket.Quotas.MaxSize)
			if *garageBucket.Quotas.MaxSize > 0 {
				// Use float64 to avoid int64 overflow with large bucket sizes
				bucket.Status.QuotaUsage.SizePercent = int32(float64(garageBucket.Bytes) / float64(*garageBucket.Quotas.MaxSize) * 100)
			}
		}
		if garageBucket.Quotas.MaxObjects != nil {
			bucket.Status.QuotaUsage.ObjectLimit = int64(*garageBucket.Quotas.MaxObjects)
			if *garageBucket.Quotas.MaxObjects > 0 {
				// Use float64 to avoid int64 overflow with large object counts
				bucket.Status.QuotaUsage.ObjectPercent = int32(float64(garageBucket.Objects) / float64(*garageBucket.Quotas.MaxObjects) * 100)
			}
		}
	}

	if len(garageBucket.GlobalAliases) > 0 {
		bucket.Status.GlobalAlias = garageBucket.GlobalAliases[0]
	}

	// Update key status and collect local aliases, sorted for deterministic comparison
	bucket.Status.Keys = make([]garagev1alpha1.BucketKeyStatus, 0, len(garageBucket.Keys))
	bucket.Status.LocalAliases = nil // Reset local aliases
	for _, k := range garageBucket.Keys {
		bucket.Status.Keys = append(bucket.Status.Keys, garagev1alpha1.BucketKeyStatus{
			KeyID: k.AccessKeyID,
			Name:  k.Name,
			Permissions: garagev1alpha1.BucketKeyPermissions{
				Read:  k.Permissions.Read,
				Write: k.Permissions.Write,
				Owner: k.Permissions.Owner,
			},
		})
		// Collect local aliases from this key
		for _, alias := range k.BucketLocalAliases {
			bucket.Status.LocalAliases = append(bucket.Status.LocalAliases, garagev1alpha1.LocalAliasStatus{
				KeyID:   k.AccessKeyID,
				KeyName: k.Name,
				Alias:   alias,
			})
		}
	}
	sort.Slice(bucket.Status.Keys, func(i, j int) bool {
		return bucket.Status.Keys[i].KeyID < bucket.Status.Keys[j].KeyID
	})
	sort.Slice(bucket.Status.LocalAliases, func(i, j int) bool {
		if bucket.Status.LocalAliases[i].KeyID != bucket.Status.LocalAliases[j].KeyID {
			return bucket.Status.LocalAliases[i].KeyID < bucket.Status.LocalAliases[j].KeyID
		}
		return bucket.Status.LocalAliases[i].Alias < bucket.Status.LocalAliases[j].Alias
	})

	meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "BucketReady",
		Message:            "Bucket is ready",
		ObservedGeneration: bucket.Generation,
	})

	// Skip status update if nothing changed — avoids ResourceVersion bump
	// which would trigger informer watch event and re-enqueue (infinite loop)
	if apiequality.Semantic.DeepEqual(*oldStatus, bucket.Status) {
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageBucketReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1alpha1.GarageBucket{}).
		Named("garagebucket").
		Complete(r)
}
