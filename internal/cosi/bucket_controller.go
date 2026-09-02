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

package cosi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagecontroller "github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=buckets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=buckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=buckets/finalizers,verbs=update
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketclaims,verbs=get
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketclaims/status,verbs=get;update;patch

// BucketReconciler reconciles cosiv1alpha2.Bucket objects whose Spec.DriverName
// matches DriverName. It manages the protection finalizer and delegates
// Garage-side bucket lifecycle to Provisioner.
type BucketReconciler struct {
	client.Client
	APIReader   client.Reader
	Scheme      *runtime.Scheme
	DriverName  string
	Namespace   string // namespace for shadow GarageBucket resources
	Provisioner *Provisioner
	// WatchNamespaces limits new provisioning to BucketClaims in the manager's
	// configured namespace scope. Empty means cluster-wide.
	WatchNamespaces []string
}

func (r *BucketReconciler) safetyReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *BucketReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cosiv1alpha2.Bucket{}).
		WithEventFilter(driverNameMatches(r.DriverName)).
		Named("cosi-bucket").
		Complete(r)
}

func (r *BucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	logger := ctrl.LoggerFrom(ctx, "driverName", r.DriverName)
	bucket := &cosiv1alpha2.Bucket{}
	if err := r.Get(ctx, req.NamespacedName, bucket); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if bucket.Spec.DriverName != r.DriverName {
		return reconcile.Result{}, nil
	}
	if !r.watchesNamespace(bucket.Spec.BucketClaimRef.Namespace) {
		// Buckets are cluster-scoped, so namespace-scoped manager caches still see
		// objects owned by other operator instances using the same driver. Ignore
		// them completely: writing even an error status causes the instances to
		// fight over the shared object and can erase the owning instance's Ready
		// status.
		if bucket.DeletionTimestamp.IsZero() {
			return reconcile.Result{}, nil
		}
		owned, err := r.Provisioner.OwnsBucketCleanup(ctx, bucket.Name, bucket.Status.BucketID)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("prove out-of-scope Bucket cleanup ownership: %w", err)
		}
		if !owned {
			return reconcile.Result{}, nil
		}
		logger.Info("Continuing cleanup for previously managed Bucket after namespace scope change",
			"claimNamespace", bucket.Spec.BucketClaimRef.Namespace, "bucketId", bucket.Status.BucketID)
	}
	if !bucket.GetDeletionTimestamp().IsZero() && bucket.Spec.DeletionPolicy == cosiv1alpha2.BucketDeletionPolicyRetain {
		done, err := r.Provisioner.RetainBucketProvisioning(ctx, bucket.Name, bucket.Status.BucketID)
		if err != nil {
			return r.fail(ctx, bucket, fmt.Errorf("retain bucket: %w", err))
		}
		if !done {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		r.removeCleanupFinalizers(bucket)
		if err := r.Update(ctx, bucket); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("Bucket retained", "bucketId", bucket.Status.BucketID)
		return reconcile.Result{}, nil
	}
	if !bucket.GetDeletionTimestamp().IsZero() && bucket.Status.BucketID == "" {
		done, err := r.Provisioner.CancelBucketProvisioning(ctx, bucket.Name)
		if err != nil {
			return r.fail(ctx, bucket, fmt.Errorf("cancel pending bucket provisioning: %w", err))
		}
		if !done {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		r.removeCleanupFinalizers(bucket)
		if err := r.Update(ctx, bucket); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("Pending Bucket provisioning cancelled")
		return reconcile.Result{}, nil
	}

	params, err := ParseBucketClassParameters(bucket.Spec.Parameters, r.Namespace)
	if err != nil {
		if bucket.DeletionTimestamp.IsZero() || bucket.Status.BucketID == "" {
			return r.fail(ctx, bucket, fmt.Errorf("parse parameters: %w", err))
		}
		// Provisioning-only parameters may have been valid in an older release
		// but be rejected now. A provisioned Bucket must remain deletable: keep
		// only the cluster identity needed for cleanup and ignore quotas,
		// website flags, and unknown legacy keys. If even that identity is gone,
		// DeleteBucket recovers it from the bound shadow by exact bucket ID.
		params = bucketDeletionParameters(bucket.Spec.Parameters, r.Namespace)
	}

	if !bucket.GetDeletionTimestamp().IsZero() {
		if bucket.Status.BucketID != "" {
			if err := r.Provisioner.DeleteBucket(ctx, bucket.Status.BucketID, params); err != nil {
				if garage.IsBucketNotEmpty(err) {
					return r.handleBucketNotEmpty(ctx, bucket)
				}
				return r.fail(ctx, bucket, err)
			}
		}
		r.removeCleanupFinalizers(bucket)
		if err := r.Update(ctx, bucket); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("Bucket deleted", "bucketId", bucket.Status.BucketID)
		return reconcile.Result{}, nil
	}

	if bucket.Spec.ExistingBucketID != "" {
		return r.fail(ctx, bucket, errors.New("static provisioning not supported"))
	}
	if err := validateS3BucketProtocols(bucket.Spec.Protocols); err != nil {
		return r.fail(ctx, bucket, err)
	}
	if err := validateDynamicBucketClaimRef(bucket.Spec.BucketClaimRef); err != nil {
		return r.fail(ctx, bucket, err)
	}

	if ctrlutil.AddFinalizer(bucket, GarageProtectionFinalizer) {
		if err := r.Update(ctx, bucket); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	result, err := r.Provisioner.EnsureBucket(ctx, bucket.Name, params)
	if err != nil {
		return r.fail(ctx, bucket, err)
	}

	desiredStatus := cosiv1alpha2.BucketStatus{
		ReadyToUse: ptr.To(true),
		BucketID:   result.BucketID,
		Protocols:  []cosiv1alpha2.ObjectProtocol{cosiv1alpha2.ObjectProtocolS3},
		BucketInfo: map[string]string{
			string(cosiv1alpha2.BucketInfoVar_S3_BucketId):        result.GlobalAlias,
			string(cosiv1alpha2.BucketInfoVar_S3_Endpoint):        result.Endpoint,
			string(cosiv1alpha2.BucketInfoVar_S3_Region):          result.Region,
			string(cosiv1alpha2.BucketInfoVar_S3_AddressingStyle): "path",
		},
	}
	if !equality.Semantic.DeepEqual(bucket.Status, desiredStatus) {
		bucket.Status = desiredStatus
		if err := r.Status().Update(ctx, bucket); err != nil {
			return reconcile.Result{}, err
		}
	}
	claimReady, err := r.syncBoundBucketClaimReady(ctx, bucket)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !claimReady {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}
	logger.Info("Bucket ready", "bucketId", result.BucketID)
	return reconcile.Result{}, nil
}

// syncBoundBucketClaimReady closes a gap in the pinned upstream COSI
// controller: BucketClaimReconciler does not watch Bucket status changes and
// relies on error backoff while provisioning is pending. A long provisioning
// or restart-recovery window can therefore leave a successfully provisioned
// BucketClaim false for many minutes. Mirror only a successful Bucket status
// into the exact UID-bound, already-bound claim; the upstream controller keeps
// ownership of binding, deletion, and all failure states.
func (r *BucketReconciler) syncBoundBucketClaimReady(
	ctx context.Context, bucket *cosiv1alpha2.Bucket,
) (bool, error) {
	ref := bucket.Spec.BucketClaimRef
	if ref.Name == "" || ref.Namespace == "" || ref.UID == "" {
		return false, fmt.Errorf("cannot publish Bucket readiness without an exact BucketClaim reference")
	}

	ready := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		claim := &cosiv1alpha2.BucketClaim{}
		key := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
		if err := r.safetyReader().Get(ctx, key, claim); err != nil {
			if apierrors.IsNotFound(err) {
				// Claim deletion races with Bucket deletion. There is no readiness
				// consumer left to wake, and the Bucket finalizer will handle cleanup.
				ready = true
				return nil
			}
			return err
		}
		if claim.UID != ref.UID {
			return fmt.Errorf("bucket %s references BucketClaim %s UID %s, current UID is %s",
				bucket.Name, key, ref.UID, claim.UID)
		}
		if !claim.DeletionTimestamp.IsZero() {
			ready = true
			return nil
		}
		if claim.Status.BoundBucketName == "" {
			// Binding is owned by the upstream controller. Requeue this Bucket
			// briefly and publish readiness once that exact binding exists.
			return nil
		}
		if claim.Status.BoundBucketName != bucket.Name {
			return fmt.Errorf("bucket claim %s UID %s is bound to %q, not Bucket %q",
				key, claim.UID, claim.Status.BoundBucketName, bucket.Name)
		}
		if ptr.Deref(claim.Status.ReadyToUse, false) &&
			slices.Equal(claim.Status.Protocols, bucket.Status.Protocols) &&
			claim.Status.Error == nil {
			ready = true
			return nil
		}

		claim.Status.ReadyToUse = ptr.To(true)
		claim.Status.Protocols = append([]cosiv1alpha2.ObjectProtocol(nil), bucket.Status.Protocols...)
		claim.Status.Error = nil
		if err := r.Status().Update(ctx, claim); err != nil {
			return err
		}
		ready = true
		return nil
	})
	return ready, err
}

func (r *BucketReconciler) watchesNamespace(namespace string) bool {
	return len(r.WatchNamespaces) == 0 || slices.Contains(r.WatchNamespaces, namespace)
}

func bucketDeletionParameters(params map[string]string, defaultNamespace string) *BucketClassParameters {
	clusterRef := params[paramClusterRef]
	if clusterRef == "" {
		return nil
	}
	clusterNamespace := params[paramClusterNamespace]
	if clusterNamespace == "" {
		clusterNamespace = defaultNamespace
	}
	return &BucketClassParameters{ClusterRef: clusterRef, ClusterNamespace: clusterNamespace}
}

func validateS3BucketProtocols(protocols []cosiv1alpha2.ObjectProtocol) error {
	if len(protocols) != 1 || protocols[0] != cosiv1alpha2.ObjectProtocolS3 {
		return fmt.Errorf("garage requires exactly one bucket protocol, S3; got %q", protocols)
	}
	return nil
}

func validateDynamicBucketClaimRef(ref cosiv1alpha2.BucketClaimReference) error {
	if ref.Name == "" || ref.Namespace == "" || ref.UID == "" {
		return fmt.Errorf("dynamic provisioning requires bucketClaimRef name, namespace, and UID")
	}
	return nil
}

// removeCleanupFinalizers releases the Garage-owned finalizer and the shared
// COSI protection finalizer used by older garage-operator releases. Unlike the
// BucketAccess handoff, the pinned COSI controller does not reconcile Bucket
// finalization; upgraded Buckets would otherwise remain terminating after
// Garage cleanup succeeds.
func (r *BucketReconciler) removeCleanupFinalizers(bucket *cosiv1alpha2.Bucket) {
	ctrlutil.RemoveFinalizer(bucket, GarageProtectionFinalizer)
	ctrlutil.RemoveFinalizer(bucket, cosiv1alpha2.ProtectionFinalizer)
}

func (r *BucketReconciler) fail(ctx context.Context, bucket *cosiv1alpha2.Bucket, in error) (reconcile.Result, error) {
	bucket.Status.ReadyToUse = ptr.To(false)
	bucket.Status.Error = cosiv1alpha2.NewTimestampedError(time.Now(), in.Error())
	if statusErr := r.Status().Update(ctx, bucket); statusErr != nil {
		// Keep the original reconcile failure as the primary diagnostic while
		// surfacing the status persistence failure as well. Returning a non-nil
		// error causes controller-runtime to retry this reconcile.
		return reconcile.Result{}, errors.Join(in, fmt.Errorf("update failure status: %w", statusErr))
	}
	return reconcile.Result{}, in
}

func (r *BucketReconciler) handleBucketNotEmpty(ctx context.Context, bucket *cosiv1alpha2.Bucket) (reconcile.Result, error) {
	retryCount, err := recordFinalizationRetry(ctx, r.Client, bucket)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("record non-empty bucket cleanup retry: %w", err)
	}
	message := fmt.Sprintf(
		"bucket %q is not empty; remove all objects and incomplete multipart uploads before deleting it. "+
			"The operator never empties buckets automatically; choose deletionPolicy: Retain before deletion when the data must be preserved.",
		bucket.Name,
	)
	apply := func() {
		bucket.Status.ReadyToUse = ptr.To(false)
		bucket.Status.Error = cosiv1alpha2.NewTimestampedError(time.Now(), message)
	}
	apply()
	if err := garagecontroller.UpdateStatusWithRetry(ctx, r.Client, bucket, apply); err != nil {
		return reconcile.Result{}, fmt.Errorf("record non-empty bucket status: %w", err)
	}
	return reconcile.Result{RequeueAfter: garagecontroller.FinalizationRetryDelay(retryCount)}, nil
}
