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
	stderrors "errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
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
	garageBucketFinalizer = garagev1beta1.GarageBucketFinalizer

	// BucketLookupStuckThreshold is the number of consecutive GetBucketInfo
	// timeouts after which we set the BucketLookupStuck status condition.
	BucketLookupStuckThreshold = 3

	// BucketDecodeErrorThreshold is the number of consecutive GetBucketInfo
	// decode errors after which the operator auto-triggers Repair:Tables on
	// the parent GarageCluster.
	BucketDecodeErrorThreshold = 3
)

// getBucketInfoTimeout caps each individual GetBucketInfo admin API call
// from the bucket controller. Upstream Garage admin API can hang
// indefinitely on a single bucket whose authorized_keys contains a stale
// node entry (netapp::try_connect has no TCP timeout). Without a per-call
// cap, one poisoned bucket wedges the bucket workqueue.
//
// Declared as a var (not const) so tests can shorten it without waiting 15s.
var getBucketInfoTimeout = 15 * time.Second

// errBucketInfoTimeout is the sentinel returned by getBucketWithTimeout when
// the per-call deadline fires. Callers treat this distinctly from other
// GetBucket errors so they can bail the reconcile gracefully and let the
// stuck-bucket tracker increment its counter.
var errBucketInfoTimeout = stderrors.New("GetBucketInfo timed out")

// GarageBucketReconciler reconciles a GarageBucket object
type GarageBucketReconciler struct {
	client.Client
	AuthorizationReader client.Reader
	Scheme              *runtime.Scheme
	ClusterDomain       string
	COSIDriverName      string
}

func (r *GarageBucketReconciler) authorizationReader() client.Reader {
	if r.AuthorizationReader != nil {
		return r.AuthorizationReader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets/finalizers,verbs=update
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=get;list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters,verbs=get;patch

func (r *GarageBucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	bucket := &garagev1beta1.GarageBucket{}
	if err := r.Get(ctx, req.NamespacedName, bucket); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if retain, err := r.validatedCOSIRetain(ctx, bucket); err != nil {
		return ctrl.Result{}, err
	} else if retain {
		if bucket.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, bucket); err != nil && !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		if controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
			controllerutil.RemoveFinalizer(bucket, garageBucketFinalizer)
			if err := r.Update(ctx, bucket); err != nil && !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !bucket.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
		policy := bucket.Spec.EffectiveDeletionPolicy()
		if policy == garagev1beta1.BucketDeletionPolicyRetain && !isCOSIManagedPendingOrBoundShadow(bucket) {
			log.Info("Retaining Garage bucket", "bucketID", bucket.Status.BucketID)
			controllerutil.RemoveFinalizer(bucket, garageBucketFinalizer)
			if err := r.Update(ctx, bucket); err != nil && !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		if policy != garagev1beta1.BucketDeletionPolicyDelete {
			return r.updateStatus(ctx, bucket, PhaseDeleting, fmt.Errorf("unsupported deletionPolicy %q", bucket.Spec.DeletionPolicy))
		}
	}
	if bucket.DeletionTimestamp.IsZero() {
		if err := garagev1beta1.ValidateGarageBucketSpec(bucket); err != nil {
			return r.updateStatus(ctx, bucket, PhaseFailed, err)
		}
		if bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] == garagev1beta1.COSIProvisioningStatePending {
			// COSI persists this shadow before creating the remote bucket. Only the
			// provisioner may bind its exact ID; normal reconciliation would duplicate it.
			if !controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
				controllerutil.AddFinalizer(bucket, garageBucketFinalizer)
				if err := r.Update(ctx, bucket); err != nil {
					return ctrl.Result{}, err
				}
			}
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		clusterNamespace := bucket.Spec.ClusterRef.Namespace
		if clusterNamespace == "" {
			clusterNamespace = bucket.Namespace
		}
		if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), "GarageBucket", bucket.Namespace,
			"GarageCluster", clusterNamespace, bucket.Spec.ClusterRef.Name); err != nil {
			return r.updateStatus(ctx, bucket, PhaseFailed, err)
		}
	}

	// Get the cluster reference
	cluster := &garagev1beta2.GarageCluster{}
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
			// COSI pending/bound shadows can already represent a remotely created
			// bucket even when their parent status is still empty. Keep that exact
			// cleanup identity until its management handle is restored.
			if clusterErr != nil && errors.IsNotFound(clusterErr) {
				if isCOSIManagedPendingOrBoundShadow(bucket) {
					log.Info("COSI bucket shadow is waiting for its missing GarageCluster before finalization",
						"cluster", bucket.Spec.ClusterRef.Name)
					return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
				}
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
		if errors.IsNotFound(clusterErr) {
			log.Info("Referenced cluster not found, waiting", "cluster", bucket.Spec.ClusterRef.Name, "namespace", clusterNamespace)
			return r.updateStatusWaiting(ctx, bucket)
		}
		return r.updateStatus(ctx, bucket, PhaseFailed, fmt.Errorf("failed to get cluster: %w", clusterErr))
	}

	// Set owner reference from bucket to cluster so the bucket is GC'd when the cluster is deleted.
	// Kubernetes forbids cross-namespace owner references, so only set if same namespace.
	// Skip if the cluster is being deleted — setting an ownerRef to a deleting object is
	// pointless and we want the ClusterDeleting guard below to run without interference.
	if bucket.DeletionTimestamp.IsZero() && clusterNamespace == bucket.Namespace && cluster.DeletionTimestamp.IsZero() {
		if !ownerRefExists(bucket, cluster.UID) {
			if err := controllerutil.SetOwnerReference(cluster, bucket, r.Scheme); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to set owner reference: %w", err)
			}
			if err := r.Update(ctx, bucket); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update bucket with owner reference: %w", err)
			}
			// Re-enqueue so we continue with the updated object.
			return ctrl.Result{Requeue: true}, nil
		}
	} else if clusterNamespace != bucket.Namespace {
		log.V(1).Info("Skipping owner reference: bucket and cluster are in different namespaces",
			"bucketNamespace", bucket.Namespace, "clusterNamespace", clusterNamespace)
	}

	// Guard against calling the Garage API before the cluster layout has converged.
	// Garage returns HTTP 500 "Layout not ready" for any API call when the ring
	// assignment is inconsistent (not all expected nodes are in the layout yet).
	// also bail on a deleting cluster: EnsureKey would race the finalizer
	// and leak a fresh cross-namespace Secret under the dying UID.
	if !bucket.DeletionTimestamp.IsZero() {
		// Allow deletions to proceed regardless of cluster health.
	} else if !cluster.DeletionTimestamp.IsZero() {
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonClusterDeleting,
			Message:            "referenced cluster is being deleted",
			ObservedGeneration: bucket.Generation,
		})
		bucket.Status.Phase = PhasePending
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	} else if cluster.Status.Phase != PhaseRunning {
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonClusterNotReady,
			Message:            "waiting for cluster to reach Running phase",
			ObservedGeneration: bucket.Generation,
		})
		bucket.Status.Phase = PhasePending
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// Get garage client
	var garageClient *garage.Client
	var err error
	if bucket.DeletionTimestamp.IsZero() {
		garageClient, err = GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	} else {
		garageClient, err = GetGarageClientForCleanup(ctx, r.Client, cluster, r.ClusterDomain)
	}
	if err != nil {
		return r.updateStatus(ctx, bucket, PhaseFailed, fmt.Errorf("failed to create garage client: %w", err))
	}

	// Handle deletion (cluster exists at this point)
	if !bucket.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
			if err := r.finalize(ctx, bucket, garageClient); err != nil {
				// Patch annotation first — Patch avoids ResourceVersion conflicts with
				// the subsequent status update, ensuring the retry counter is persisted
				// even if updateStatus re-fetches the object internally.
				patch := client.MergeFrom(bucket.DeepCopy())
				IncrementFinalizationRetryCount(bucket)
				if patchErr := r.Patch(ctx, bucket, patch); patchErr != nil {
					if errors.IsNotFound(patchErr) {
						return ctrl.Result{}, nil
					}
					log.Error(patchErr, "Failed to update retry count annotation")
				}
				log.Error(err, "Failed to finalize bucket, retaining finalizer",
					"retries", GetFinalizationRetryCount(bucket))
				_, _ = r.updateStatus(ctx, bucket, PhaseDeleting, fmt.Errorf("finalization failed: %w", err))
				return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
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

	if err := r.handleBucketAnnotations(ctx, bucket, garageClient); err != nil {
		log.Error(err, "Failed to handle bucket annotation")
		// Keep the one-shot annotation and retry explicitly. Continuing would
		// make a failed cleanup look successful and could lose the trigger.
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}

	// Reconcile the bucket
	reconcileSnapshot, err := r.reconcileBucket(ctx, bucket, garageClient)
	if err != nil {
		// A wedged GetBucketInfo is informational, not a reconcile failure.
		// Bail with a stuck-bucket signal instead of marking PhaseFailed; the
		// rest of the reconcile (cluster ref, owner ref, finalizer) already
		// ran above and persisted.
		if isBucketLookupTimeout(err) {
			return r.handleBucketLookupTimeout(ctx, bucket)
		}
		// A metadata decode error means key_table entries can't be deserialized.
		// Auto-trigger Repair:Tables on the parent cluster after threshold hits.
		if garage.IsMetadataDecodeError(err) {
			return r.handleBucketDecodeError(ctx, bucket, cluster)
		}
		return r.updateStatus(ctx, bucket, PhaseFailed, err)
	}

	return r.updateStatusFromGarage(ctx, bucket, garageClient, cluster, reconcileSnapshot)
}

func isCOSIManagedPendingOrBoundShadow(object metav1.Object) bool {
	if object == nil || object.GetLabels()[garagev1beta1.LabelCOSIManaged] != annotationTrue {
		return false
	}
	annotations := object.GetAnnotations()
	owner := annotations[garagev1beta1.AnnotationCOSIReservationOwner]
	if owner == "" || object.GetName() != garageconfig.COSIShadowResourceName(owner) {
		return false
	}
	state := annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	return state == garagev1beta1.COSIProvisioningStatePending ||
		state == garagev1beta1.COSIProvisioningStateBound
}

func (r *GarageBucketReconciler) validatedCOSIRetain(ctx context.Context, bucket *garagev1beta1.GarageBucket) (bool, error) {
	marker := bucket.Annotations[garagev1beta1.AnnotationCOSIRetain]
	if marker == "" {
		return false, nil
	}
	expected, err := garagev1beta1.UIDBoundReservationAlias("cosi-retain-", bucket.Namespace, bucket.Name, bucket.UID)
	if err != nil || marker != expected {
		return false, fmt.Errorf("refusing invalid COSI retain marker %q on GarageBucket %s/%s", marker, bucket.Namespace, bucket.Name)
	}
	if bucket.Labels[garagev1beta1.LabelCOSIManaged] != annotationTrue ||
		bucket.Annotations[garagev1beta1.AnnotationCOSIReservationOwner] == "" {
		return false, fmt.Errorf("refusing COSI retain marker on non-COSI GarageBucket %s/%s", bucket.Namespace, bucket.Name)
	}
	owner := bucket.Annotations[garagev1beta1.AnnotationCOSIReservationOwner]
	if bucket.Name != garageconfig.COSIShadowResourceName(owner) {
		return false, fmt.Errorf("refusing COSI retain marker on GarageBucket %s/%s whose name does not match reservation owner %q", bucket.Namespace, bucket.Name, owner)
	}
	if r.COSIDriverName == "" || r.authorizationReader() == nil {
		return false, fmt.Errorf("cannot verify COSI retain parent for GarageBucket %s/%s", bucket.Namespace, bucket.Name)
	}
	parent := &cosiv1alpha2.Bucket{}
	if err := r.authorizationReader().Get(ctx, types.NamespacedName{Name: owner}, parent); err != nil {
		return false, fmt.Errorf("verify deleting COSI Bucket %q before retain: %w", owner, err)
	}
	if parent.DeletionTimestamp.IsZero() || parent.Spec.DriverName != r.COSIDriverName ||
		parent.Spec.DeletionPolicy != cosiv1alpha2.BucketDeletionPolicyRetain {
		return false, fmt.Errorf("refusing COSI retain marker without a live deleting Retain Bucket for driver %q", r.COSIDriverName)
	}
	state := bucket.Annotations[garagev1beta1.AnnotationCOSIProvisioningState]
	switch state {
	case garagev1beta1.COSIProvisioningStateBound:
		resolved, resolveErr := garageBucketFinalizationID(bucket)
		cosiID := bucket.Annotations[garagev1beta1.AnnotationCOSIBucketID]
		if resolveErr != nil || cosiID == "" || resolved != cosiID {
			return false, fmt.Errorf("refusing COSI retain marker without matching bound bucket identity on GarageBucket %s/%s", bucket.Namespace, bucket.Name)
		}
		if parent.Status.BucketID != cosiID {
			return false, fmt.Errorf("COSI Bucket %q status ID %q does not match retained Garage bucket ID %q", parent.Name, parent.Status.BucketID, cosiID)
		}
	case garagev1beta1.COSIProvisioningStatePending:
		if parent.Status.BucketID != "" {
			return false, fmt.Errorf("pending COSI shadow has no bound identity but Bucket %q records ID %q", parent.Name, parent.Status.BucketID)
		}
		resolved, resolveErr := garageBucketFinalizationID(bucket)
		if resolveErr != nil {
			return false, resolveErr
		}
		if resolved != "" {
			if cosiID := bucket.Annotations[garagev1beta1.AnnotationCOSIBucketID]; cosiID != "" && cosiID != resolved {
				return false, fmt.Errorf("refusing COSI retain marker with conflicting pending bucket identity on GarageBucket %s/%s", bucket.Namespace, bucket.Name)
			}
			return true, nil
		}
		alias := bucket.Annotations[garagev1beta1.AnnotationCOSIReservationAlias]
		if alias == "" {
			if bucket.Annotations[garagev1beta1.AnnotationCOSIReservationReady] == annotationTrue {
				return false, fmt.Errorf("refusing COSI retain marker for authorized reservation without an exact alias on GarageBucket %s/%s", bucket.Namespace, bucket.Name)
			}
			return true, nil
		}
		expectedAlias, aliasErr := garagev1beta1.UIDBoundReservationAlias("cosi-rsv-", bucket.Namespace, bucket.Name, bucket.UID)
		if aliasErr != nil || alias != expectedAlias || bucket.Annotations[garagev1beta1.AnnotationCOSIReservationReady] != annotationTrue {
			return false, fmt.Errorf("refusing COSI retain marker with invalid reservation alias on GarageBucket %s/%s", bucket.Namespace, bucket.Name)
		}
	default:
		return false, fmt.Errorf("refusing COSI retain marker with provisioning state %q on GarageBucket %s/%s", state, bucket.Namespace, bucket.Name)
	}
	return true, nil
}

func (r *GarageBucketReconciler) reconcileBucket(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client) (*garage.Bucket, error) {
	log := logf.FromContext(ctx)

	alias := bucket.Name
	if bucket.Spec.GlobalAlias != "" {
		alias = bucket.Spec.GlobalAlias
	}

	prevBucketID := bucket.Status.BucketID
	existingBucket, err := r.getOrCreateBucket(ctx, bucket, garageClient, alias)
	if err != nil {
		return nil, err
	}

	// Persist status.BucketID immediately whenever it is newly learned or created.
	// Without this, a crash between creation and the end-of-reconcile status write
	// causes the next reconcile to lose track of the bucket and create a duplicate.
	if bucket.Status.BucketID != prevBucketID {
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return nil, fmt.Errorf("failed to persist bucket ID: %w", err)
		}
	}

	// Ensure the global alias is set. This is an explicit idempotent step because
	// CreateBucket no longer sets the alias atomically — see getOrCreateBucket for why.
	if err := r.reconcileGlobalAlias(ctx, bucket, garageClient, existingBucket.ID, alias, existingBucket.GlobalAliases); err != nil {
		return nil, err
	}
	if err := r.clearBucketReservationAlias(ctx, bucket, garageClient, existingBucket, alias); err != nil {
		return nil, err
	}

	if err := r.updateBucketSettings(ctx, bucket, garageClient, existingBucket); err != nil {
		return nil, err
	}

	if err := r.reconcileKeyPermissions(ctx, bucket, garageClient, existingBucket); err != nil {
		return nil, err
	}

	aliasSnapshot, err := r.reconcileLocalAliases(ctx, bucket, garageClient, existingBucket.ID, existingBucket.Keys)
	if err != nil {
		return nil, err
	}

	// lifecycle is auxiliary: failures flip the LifecycleConfigured condition
	// but must not block the bucket from going Ready.
	r.reconcileLifecycleSafe(ctx, bucket, existingBucket.ID, garageClient)

	log.V(1).Info("Bucket reconciled successfully", "bucketID", existingBucket.ID)
	return aliasSnapshot, nil
}

func (r *GarageBucketReconciler) getOrCreateBucket(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, alias string) (*garage.Bucket, error) {
	log := logf.FromContext(ctx)

	// COSI's UID-bound reservation alias fences its remote create; Bind then
	// persists status.bucketId. The annotation is a handoff consistency check,
	// never independent authority to adopt a bucket.
	if cosiBucketID := bucket.Annotations[garagev1beta1.AnnotationCOSIBucketID]; cosiBucketID != "" {
		trustedID := bucket.Status.BucketID
		if trustedID == "" {
			trustedID = bucket.Spec.BucketID
		}
		if trustedID == "" {
			return nil, fmt.Errorf("refusing COSI-annotated bucket ID %q without status.bucketId or explicit spec.bucketId ownership", cosiBucketID)
		}
		if trustedID != cosiBucketID {
			return nil, fmt.Errorf("COSI-annotated bucket ID %q disagrees with trusted bucket ID %q", cosiBucketID, trustedID)
		}
	}

	// Resolve a persisted UID-bound create reservation before accepting any
	// later explicit identity. A remote create may have committed immediately
	// before status persistence; spec.bucketId must not bypass that evidence and
	// strand the bucket created by this object.
	reservationAlias := bucket.Annotations[garagev1beta1.AnnotationBucketReservationAlias]
	var expectedReservationAlias string
	if reservationAlias != "" {
		var err error
		expectedReservationAlias, err = garageBucketReservationAlias(bucket)
		if err != nil {
			return nil, err
		}
		if reservationAlias != expectedReservationAlias {
			return nil, fmt.Errorf("refusing unbound bucket reservation alias %q; expected %q for GarageBucket UID %s", reservationAlias, expectedReservationAlias, bucket.UID)
		}
		reserved, lookupErr := getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{GlobalAlias: reservationAlias})
		if lookupErr == nil {
			if bucket.Spec.BucketID != "" && bucket.Spec.BucketID != reserved.ID {
				return nil, fmt.Errorf("spec.bucketId %q disagrees with UID-bound reservation bucket %q", bucket.Spec.BucketID, reserved.ID)
			}
			if bucket.Status.BucketID != "" && bucket.Status.BucketID != reserved.ID {
				return nil, fmt.Errorf("status.bucketId %q disagrees with UID-bound reservation bucket %q", bucket.Status.BucketID, reserved.ID)
			}
			bucket.Status.BucketID = reserved.ID
			return reserved, nil
		}
		if isBucketLookupTimeout(lookupErr) {
			return nil, lookupErr
		}
		if !garage.IsNotFound(lookupErr) {
			return nil, fmt.Errorf("failed to recover bucket reservation alias %q: %w", reservationAlias, lookupErr)
		}
	}

	// spec.bucketId takes absolute priority — never create, never guess.
	if bucket.Spec.BucketID != "" {
		existing, err := getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{ID: bucket.Spec.BucketID})
		if err != nil {
			if isBucketLookupTimeout(err) {
				return nil, err
			}
			return nil, fmt.Errorf("spec.bucketId %s not found or unreachable: %w", bucket.Spec.BucketID, err)
		}
		bucket.Status.BucketID = existing.ID
		return existing, nil
	}

	// If we have a tracked bucket ID, use it. Only fall through to alias
	// lookup on a genuine 404 — not on transient errors (5xx, network).
	// Treating transient errors as "not found" is what caused duplicate
	// buckets to be created during Garage cluster recovery.
	if bucket.Status.BucketID != "" {
		existing, err := getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{ID: bucket.Status.BucketID})
		if err == nil {
			return existing, nil
		}
		if isBucketLookupTimeout(err) {
			return nil, err
		}
		if !garage.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get bucket by ID %s: %w", bucket.Status.BucketID, err)
		}
		if bucket.Annotations[garagev1beta1.AnnotationCOSIBucketID] != "" {
			return nil, fmt.Errorf("COSI-bound bucket ID %s no longer exists; refusing ordinary alias fallback or replacement creation", bucket.Status.BucketID)
		}
		// Genuine 404 — bucket was deleted; fall through to alias lookup.
		log.Info("Tracked bucket ID not found, falling back to alias lookup", "bucketID", bucket.Status.BucketID, "alias", alias)
	}

	existing, err := getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{GlobalAlias: alias})
	if err == nil {
		return nil, fmt.Errorf("bucket alias %q is already owned by untracked Garage bucket %s; set spec.bucketId explicitly to manage an existing bucket", alias, existing.ID)
	}
	if isBucketLookupTimeout(err) {
		return nil, err
	}
	if !garage.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get bucket by alias %s: %w", alias, err)
	}

	if reservationAlias == "" {
		var err error
		expectedReservationAlias, err = garageBucketReservationAlias(bucket)
		if err != nil {
			return nil, err
		}
		reservationAlias = expectedReservationAlias
		patch := client.MergeFrom(bucket.DeepCopy())
		annotations := bucket.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[garagev1beta1.AnnotationBucketReservationAlias] = reservationAlias
		bucket.SetAnnotations(annotations)
		if err := r.Patch(ctx, bucket, patch); err != nil {
			return nil, fmt.Errorf("persist bucket reservation alias: %w", err)
		}
	}

	// Garage main-v2 inserts the bucket record before assigning the supplied
	// alias. The persisted high-entropy alias makes successful creates and most
	// ambiguous responses recoverable; an upstream failure between those two
	// Garage writes remains an API-level limitation.
	log.Info("Creating bucket", "alias", alias)
	created, err := garageClient.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: reservationAlias})
	if err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	bucket.Status.BucketID = created.ID
	return created, nil
}

func garageBucketReservationAlias(bucket *garagev1beta1.GarageBucket) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("GarageBucket UID is required before reserving a remote bucket identity")
	}
	return garagev1beta1.UIDBoundReservationAlias("garage-rsv-", bucket.Namespace, bucket.Name, bucket.UID)
}

func (r *GarageBucketReconciler) clearBucketReservationAlias(
	ctx context.Context,
	bucket *garagev1beta1.GarageBucket,
	garageClient *garage.Client,
	existing *garage.Bucket,
	desiredAlias string,
) error {
	reservationAlias := bucket.Annotations[garagev1beta1.AnnotationBucketReservationAlias]
	if reservationAlias == "" {
		return nil
	}
	if reservationAlias != desiredAlias {
		for _, current := range existing.GlobalAliases {
			if current != reservationAlias {
				continue
			}
			if _, err := garageClient.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{
				BucketID: existing.ID, GlobalAlias: reservationAlias,
			}); err != nil && !garage.IsNotFound(err) {
				return fmt.Errorf("remove bucket reservation alias %q: %w", reservationAlias, err)
			}
			break
		}
	}
	patch := client.MergeFrom(bucket.DeepCopy())
	delete(bucket.Annotations, garagev1beta1.AnnotationBucketReservationAlias)
	if err := r.Patch(ctx, bucket, patch); err != nil {
		return fmt.Errorf("clear bucket reservation alias: %w", err)
	}
	return nil
}

func (r *GarageBucketReconciler) reconcileGlobalAlias(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, bucketID, alias string, currentAliases []string) error {
	found := slices.Contains(currentAliases, alias)

	// Clean an abandoned reserved add before replacing its durable identity.
	if pending := bucket.Status.PendingGlobalAlias; pending != "" && pending != alias && pending != bucket.Status.ManagedGlobalAlias {
		for _, current := range currentAliases {
			if current != pending {
				continue
			}
			if _, err := garageClient.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{
				BucketID: bucketID, GlobalAlias: pending,
			}); err != nil && !garage.IsNotFound(err) {
				return fmt.Errorf("failed to remove abandoned reserved global alias %q from bucket %s: %w", pending, bucketID, err)
			}
			break
		}
		bucket.Status.PendingGlobalAlias = ""
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return fmt.Errorf("failed to clear abandoned global alias reservation: %w", err)
		}
	}
	// Reserve only when the add is actually about to happen. The reservation
	// exists to record intent before mutating remote state; when the alias is
	// already live there is nothing to record, and writing it here would be
	// undone by the handoff below on every single reconcile.
	if !found && bucket.Status.PendingGlobalAlias != alias {
		bucket.Status.PendingGlobalAlias = alias
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return fmt.Errorf("failed to reserve global alias: %w", err)
		}
	}

	if !found {
		_, err := garageClient.AddBucketAlias(ctx, garage.AddBucketAliasRequest{
			BucketID:    bucketID,
			GlobalAlias: alias,
		})
		if err != nil {
			if !garage.IsConflict(err) {
				return fmt.Errorf("failed to set global alias %q on bucket %s: %w", alias, bucketID, err)
			}
			// Conflict is idempotent only when the alias already resolves to this
			// exact bucket. Otherwise removing the previous managed alias below
			// would turn a failed rename into an alias-less bucket.
			resolved, lookupErr := garageClient.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: alias})
			if lookupErr != nil || resolved.ID != bucketID {
				return fmt.Errorf("global alias %q conflicts with another bucket: add failed: %w", alias, err)
			}
		}
	}
	// Remove only the previous exact-managed alias after the replacement has
	// succeeded. Any other aliases may be user-managed and are preserved.
	if previous := bucket.Status.ManagedGlobalAlias; previous != "" && previous != alias {
		for _, current := range currentAliases {
			if current != previous {
				continue
			}
			if _, err := garageClient.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{
				BucketID: bucketID, GlobalAlias: previous,
			}); err != nil && !garage.IsNotFound(err) {
				return fmt.Errorf("failed to remove previously managed global alias %q from bucket %s: %w", previous, bucketID, err)
			}
			break
		}
	}
	if bucket.Status.ManagedGlobalAlias != alias || bucket.Status.PendingGlobalAlias != "" {
		bucket.Status.ManagedGlobalAlias = alias
		bucket.Status.PendingGlobalAlias = ""
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return fmt.Errorf("failed to complete managed global alias handoff: %w", err)
		}
	}

	return nil
}

func (r *GarageBucketReconciler) updateBucketSettings(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, existingBucket *garage.Bucket) error {
	updateReq := garage.UpdateBucketRequest{ID: existingBucket.ID}
	needsUpdate := false

	if websiteAccess := buildWebsiteAccess(bucket.Spec.Website, existingBucket); websiteAccess != nil {
		updateReq.Body.WebsiteAccess = websiteAccess
		needsUpdate = true
	}

	quotas, err := buildQuotasUpdate(bucket.Spec.Quotas, existingBucket.Quotas)
	if err != nil {
		return err
	}
	if quotas != nil {
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

func buildWebsiteAccess(spec *garagev1beta1.WebsiteConfig, existing *garage.Bucket) *garage.UpdateBucketWebsiteAccess {
	// If spec is nil but website is currently enabled, disable it
	if spec == nil {
		if existing.WebsiteAccess {
			return &garage.UpdateBucketWebsiteAccess{
				Enabled: false,
			}
		}
		return nil
	}
	enabled := spec.Enabled != nil && *spec.Enabled
	indexDoc := spec.IndexDocument
	if enabled && indexDoc == "" {
		indexDoc = "index.html"
	}

	currentIndex := ""
	currentError := ""
	if existing.WebsiteConfig != nil {
		currentIndex = existing.WebsiteConfig.IndexDocument
		currentError = existing.WebsiteConfig.ErrorDocument
	}

	if enabled != existing.WebsiteAccess ||
		(enabled && (indexDoc != currentIndex || spec.ErrorDocument != currentError)) {
		return &garage.UpdateBucketWebsiteAccess{
			Enabled:       enabled,
			IndexDocument: indexDoc,
			ErrorDocument: spec.ErrorDocument,
		}
	}
	return nil
}

func buildQuotasUpdate(spec *garagev1beta1.BucketQuotas, current *garage.BucketQuotas) (*garage.BucketQuotas, error) {
	// If spec is nil but quotas are currently set, clear them
	if spec == nil {
		if current != nil && (current.MaxSize != nil || current.MaxObjects != nil) {
			return &garage.BucketQuotas{MaxSize: nil, MaxObjects: nil}, nil
		}
		return nil, nil
	}
	var desiredMaxSize, desiredMaxObjects *uint64
	if spec.MaxSize != nil {
		value := spec.MaxSize.Value()
		if value < 0 {
			return nil, fmt.Errorf("bucket quota maxSize must be >= 0")
		}
		v := uint64(value)
		desiredMaxSize = &v
	}
	if spec.MaxObjects != nil {
		if *spec.MaxObjects < 0 {
			return nil, fmt.Errorf("bucket quota maxObjects must be >= 0")
		}
		v := uint64(*spec.MaxObjects)
		desiredMaxObjects = &v
	}

	if !quotasChanged(current, desiredMaxSize, desiredMaxObjects) {
		return nil, nil
	}
	return &garage.BucketQuotas{MaxSize: desiredMaxSize, MaxObjects: desiredMaxObjects}, nil
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

func (r *GarageBucketReconciler) reconcileKeyPermissions(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, existingBucket *garage.Bucket) error {
	log := logf.FromContext(ctx)
	bucketID := existingBucket.ID

	currentPerms := make(map[string]garage.BucketKeyPerms, len(existingBucket.Keys))
	for _, k := range existingBucket.Keys {
		currentPerms[k.AccessKeyID] = k.Permissions
	}

	// Build the bucket-owned portion first. A declared all-false relation is
	// still managed: it means exact removal of all three permission bits.
	bucketDesired := make(map[string]garage.BucketKeyPerms, len(bucket.Spec.KeyPermissions))
	unauthorizedTargets := make(map[string]struct{})
	var permissionErrors []string
	var permissionDenials []string
	for i, keyPerm := range bucket.Spec.KeyPermissions {
		keyNS := bucket.Namespace
		if keyPerm.KeyRef.Namespace != "" {
			keyNS = keyPerm.KeyRef.Namespace
		}
		if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), "GarageBucket", bucket.Namespace,
			garageKeyKind, keyNS, keyPerm.KeyRef.Name); err != nil {
			detail := fmt.Sprintf("spec.keyPermissions[%d] GarageKey %s/%s: %v", i, keyNS, keyPerm.KeyRef.Name, err)
			if garagev1beta1.IsReferenceGrantDenied(err) {
				permissionDenials = append(permissionDenials, detail)
			} else {
				permissionErrors = append(permissionErrors, detail)
			}
			// Resolve only enough exact identity to revoke a grant that may have
			// committed before its managed-status write. Never preserve desired
			// permissions from an unauthorized declaration.
			key := &garagev1beta1.GarageKey{}
			if getErr := r.Get(ctx, types.NamespacedName{Name: keyPerm.KeyRef.Name, Namespace: keyNS}, key); getErr == nil && key.Status.AccessKeyID != "" {
				unauthorizedTargets[key.Status.AccessKeyID] = struct{}{}
			} else if getErr != nil && !errors.IsNotFound(getErr) {
				permissionErrors = append(permissionErrors, fmt.Sprintf("resolving unauthorized key %s/%s for cleanup: %v", keyNS, keyPerm.KeyRef.Name, getErr))
			}
			continue
		}
		key := &garagev1beta1.GarageKey{}
		if err := r.Get(ctx, types.NamespacedName{Name: keyPerm.KeyRef.Name, Namespace: keyNS}, key); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Key not found, will retry", "keyRef", keyPerm.KeyRef.Name, "namespace", keyNS)
				return fmt.Errorf("waiting for key %s/%s to be ready before reconciling permissions", keyNS, keyPerm.KeyRef.Name)
			}
			return fmt.Errorf("failed to get key %s: %w", keyPerm.KeyRef.Name, err)
		}

		if key.Status.AccessKeyID == "" {
			log.Info("Key not yet created, will retry", "keyRef", keyPerm.KeyRef.Name)
			return fmt.Errorf("waiting for key %s/%s to be ready before reconciling permissions", keyNS, keyPerm.KeyRef.Name)
		}
		if !sameClusterForBucketAndKey(bucket, key) {
			permissionErrors = append(permissionErrors, fmt.Sprintf(
				"spec.keyPermissions[%d]: GarageKey %s/%s targets a different GarageCluster", i, keyNS, key.Name,
			))
			continue
		}

		desired := garage.BucketKeyPerms{Read: keyPerm.Read, Write: keyPerm.Write, Owner: keyPerm.Owner}
		bucketDesired[key.Status.AccessKeyID] = mergeBucketPerms(bucketDesired[key.Status.AccessKeyID], desired)
	}
	bucketManaged := make([]string, 0, len(bucketDesired))
	for id := range bucketDesired {
		bucketManaged = append(bucketManaged, id)
	}
	sort.Strings(bucketManaged)
	// Reserve ownership before the first remote permission mutation. If an
	// allow commits and the process dies before the remainder of reconciliation,
	// a later spec removal still has an exact durable target to revoke.
	reservedManaged := mergeManagedGrantIDs(bucket.Status.ManagedKeyGrants, bucketManaged)

	// Merge the GarageKey-owned portion. The exact desired Garage state is the
	// union of both CR directions, which avoids controller-order flap wars.
	desired := make(map[string]garage.BucketKeyPerms, len(bucketDesired))
	targets := make(map[string]struct{})
	for id, perms := range bucketDesired {
		desired[id] = perms
		targets[id] = struct{}{}
	}
	for _, id := range reservedManaged {
		targets[id] = struct{}{}
	}
	for id := range unauthorizedTargets {
		targets[id] = struct{}{}
	}

	keyList := &garagev1beta1.GarageKeyList{}
	if err := r.List(ctx, keyList); err != nil {
		return fmt.Errorf("listing keys for permission union: %w", err)
	}
	for i := range keyList.Items {
		key := &keyList.Items[i]
		if key.Status.AccessKeyID == "" || !sameClusterForBucketAndKey(bucket, key) {
			continue
		}
		reverseReserved := key.Status.ClusterWide || stringSliceContains(key.Status.ManagedBucketGrants, bucketID)
		for _, id := range key.Status.ManagedBucketGrants {
			if id == bucketID {
				targets[key.Status.AccessKeyID] = struct{}{}
				break
			}
		}
		// Legacy allBuckets ownership predates ManagedBucketGrants.
		if key.Status.ClusterWide {
			targets[key.Status.AccessKeyID] = struct{}{}
		}
		if perms, ok := keyPermissionsForBucket(key, bucket, existingBucket); ok {
			if err := garagev1beta1.CheckReferenceGrant(ctx, r.authorizationReader(), garageKeyKind, key.Namespace,
				"GarageBucket", bucket.Namespace, bucket.Name); err != nil {
				detail := fmt.Sprintf("GarageKey %s/%s: %v", key.Namespace, key.Name, err)
				if garagev1beta1.IsReferenceGrantDenied(err) {
					permissionDenials = append(permissionDenials, detail)
				} else {
					permissionErrors = append(permissionErrors, detail)
				}
				continue
			}
			// The GarageKey controller owns this declaration's durable
			// reservation. Until it has recorded that ownership, preserve current
			// state and let that controller perform the first remote mutation.
			if !reverseReserved {
				continue
			}
			desired[key.Status.AccessKeyID] = mergeBucketPerms(desired[key.Status.AccessKeyID], perms)
			targets[key.Status.AccessKeyID] = struct{}{}
		}
	}

	// A denied cross-namespace reference is a per-key authorization result, not
	// a failure to reconcile this bucket. Record it before reserving ownership so
	// the warning survives a crash before the first remote permission mutation.
	setBucketPermissionsCondition(bucket, permissionDenials)
	if !stringSlicesEqual(bucket.Status.ManagedKeyGrants, reservedManaged) {
		bucket.Status.ManagedKeyGrants = reservedManaged
		if err := r.Status().Update(ctx, bucket); err != nil {
			return fmt.Errorf("failed to reserve managed key grants: %w", err)
		}
	}

	for accessKeyID := range targets {
		if err := reconcileExactBucketKeyPermissions(ctx, garageClient, bucketID, accessKeyID, currentPerms[accessKeyID], desired[accessKeyID]); err != nil {
			log.Error(err, "Failed to reconcile exact key permissions", "accessKeyId", accessKeyID, "bucketId", bucketID)
			permissionErrors = append(permissionErrors, fmt.Sprintf("%s: %v", accessKeyID, err))
		}
	}
	if len(permissionErrors) > 0 {
		return fmt.Errorf("failed to set permissions for keys: %v", permissionErrors)
	}
	setBucketPermissionsCondition(bucket, permissionDenials)

	if !stringSlicesEqual(bucket.Status.ManagedKeyGrants, bucketManaged) {
		bucket.Status.ManagedKeyGrants = bucketManaged
		if err := r.Status().Update(ctx, bucket); err != nil {
			return fmt.Errorf("failed to persist managed key grants: %w", err)
		}
	}
	return nil
}

func setBucketPermissionsCondition(bucket *garagev1beta1.GarageBucket, denied []string) {
	condition := metav1.Condition{
		Type:               garagev1beta1.ConditionPermissionsConfigured,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonReconcileSuccess,
		Message:            "All declared key permissions are configured",
		ObservedGeneration: bucket.Generation,
	}
	if len(denied) > 0 {
		details := append([]string(nil), denied...)
		sort.Strings(details)
		condition.Status = metav1.ConditionFalse
		condition.Reason = garagev1beta1.ReasonReferenceGrantDenied
		condition.Message = "Some key permission references were denied: " + strings.Join(details, "; ")
	}
	meta.SetStatusCondition(&bucket.Status.Conditions, condition)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mergeManagedGrantIDs(existing, additions []string) []string {
	merged := make(map[string]struct{}, len(existing)+len(additions))
	for _, value := range existing {
		if value != "" {
			merged[value] = struct{}{}
		}
	}
	for _, value := range additions {
		if value != "" {
			merged[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(merged))
	for value := range merged {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func mergeBucketPerms(a, b garage.BucketKeyPerms) garage.BucketKeyPerms {
	return garage.BucketKeyPerms{Read: a.Read || b.Read, Write: a.Write || b.Write, Owner: a.Owner || b.Owner}
}

func reconcileExactBucketKeyPermissions(ctx context.Context, garageClient *garage.Client, bucketID, accessKeyID string, current, desired garage.BucketKeyPerms) error {
	deny := garage.BucketKeyPerms{
		Read:  current.Read && !desired.Read,
		Write: current.Write && !desired.Write,
		Owner: current.Owner && !desired.Owner,
	}
	if deny != (garage.BucketKeyPerms{}) {
		if _, err := garageClient.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: bucketID, AccessKeyID: accessKeyID, Permissions: deny}); err != nil && !garage.IsNotFound(err) {
			return fmt.Errorf("deny permissions: %w", err)
		}
	}
	allow := garage.BucketKeyPerms{
		Read:  desired.Read && !current.Read,
		Write: desired.Write && !current.Write,
		Owner: desired.Owner && !current.Owner,
	}
	if allow != (garage.BucketKeyPerms{}) {
		if _, err := garageClient.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{BucketID: bucketID, AccessKeyID: accessKeyID, Permissions: allow}); err != nil {
			return fmt.Errorf("allow permissions: %w", err)
		}
	}
	return nil
}

func sameClusterForBucketAndKey(bucket *garagev1beta1.GarageBucket, key *garagev1beta1.GarageKey) bool {
	bucketNS := bucket.Namespace
	if bucket.Spec.ClusterRef.Namespace != "" {
		bucketNS = bucket.Spec.ClusterRef.Namespace
	}
	keyNS := key.Namespace
	if key.Spec.ClusterRef.Namespace != "" {
		keyNS = key.Spec.ClusterRef.Namespace
	}
	return bucket.Spec.ClusterRef.Name == key.Spec.ClusterRef.Name && bucketNS == keyNS
}

func keyPermissionsForBucket(key *garagev1beta1.GarageKey, bucket *garagev1beta1.GarageBucket, existing *garage.Bucket) (garage.BucketKeyPerms, bool) {
	var desired garage.BucketKeyPerms
	found := false
	if key.Spec.AllBuckets != nil {
		desired = mergeBucketPerms(desired, garage.BucketKeyPerms{Read: key.Spec.AllBuckets.Read, Write: key.Spec.AllBuckets.Write, Owner: key.Spec.AllBuckets.Owner})
		found = true
	}
	effectiveAlias := bucket.Name
	if bucket.Spec.GlobalAlias != "" {
		effectiveAlias = bucket.Spec.GlobalAlias
	}
	for _, p := range key.Spec.BucketPermissions {
		matches := false
		switch {
		case p.BucketRef != nil:
			ns := key.Namespace
			if p.BucketRef.Namespace != "" {
				ns = p.BucketRef.Namespace
			}
			matches = p.BucketRef.Name == bucket.Name && ns == bucket.Namespace
		case p.BucketID != "":
			matches = p.BucketID == existing.ID
		case p.GlobalAlias != "":
			matches = p.GlobalAlias == effectiveAlias
			if !matches {
				for _, alias := range existing.GlobalAliases {
					if p.GlobalAlias == alias {
						matches = true
						break
					}
				}
			}
		}
		if matches {
			desired = mergeBucketPerms(desired, garage.BucketKeyPerms{Read: p.Read, Write: p.Write, Owner: p.Owner})
			found = true
		}
	}
	return desired, found
}

func (r *GarageBucketReconciler) reconcileLocalAliases(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, bucketID string, currentKeys []garage.BucketKeyInfo) (*garage.Bucket, error) {
	log := logf.FromContext(ctx)
	desired := make(map[string]garagev1beta1.LocalAliasStatus, len(bucket.Spec.LocalAliases))
	var authoritativeSnapshot *garage.Bucket

	for _, localAlias := range bucket.Spec.LocalAliases {
		key := &garagev1beta1.GarageKey{}
		if err := r.Get(ctx, types.NamespacedName{Name: localAlias.KeyRef, Namespace: bucket.Namespace}, key); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Key for local alias not found, will retry", "keyRef", localAlias.KeyRef, "alias", localAlias.Alias)
				return nil, fmt.Errorf("waiting for key %s to be ready before reconciling local aliases", localAlias.KeyRef)
			}
			return nil, fmt.Errorf("failed to get key %s for local alias: %w", localAlias.KeyRef, err)
		}

		if key.Status.AccessKeyID == "" {
			log.Info("Key for local alias not yet created, will retry", "keyRef", localAlias.KeyRef, "alias", localAlias.Alias)
			return nil, fmt.Errorf("waiting for key %s to be ready before reconciling local aliases", localAlias.KeyRef)
		}
		if !sameClusterForBucketAndKey(bucket, key) {
			return nil, fmt.Errorf("local alias key GarageKey %s/%s targets a different GarageCluster", key.Namespace, key.Name)
		}
		desired[key.Status.AccessKeyID+"\x00"+localAlias.Alias] = garagev1beta1.LocalAliasStatus{KeyID: key.Status.AccessKeyID, Alias: localAlias.Alias}
	}

	managed := make([]garagev1beta1.LocalAliasStatus, 0, len(desired))
	for _, item := range desired {
		managed = append(managed, item)
	}
	sortLocalAliasStatuses(managed)
	reserved := mergeLocalAliasStatuses(bucket.Status.ManagedLocalAliases, managed)
	if !apiequality.Semantic.DeepEqual(bucket.Status.ManagedLocalAliases, reserved) {
		bucket.Status.ManagedLocalAliases = reserved
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return nil, fmt.Errorf("failed to reserve managed local aliases: %w", err)
		}
	}

	// Add before removing so a rename never leaves the bucket without an alias.
	for _, item := range desired {
		updated, err := garageClient.AddBucketAlias(ctx, garage.AddBucketAliasRequest{
			BucketID:    bucketID,
			LocalAlias:  item.Alias,
			AccessKeyID: item.KeyID,
		})
		if err != nil {
			if !garage.IsConflict(err) {
				return nil, fmt.Errorf("failed to add local alias %s:%s: %w", item.KeyID, item.Alias, err)
			}
			resolved, lookupErr := garageClient.GetBucket(ctx, garage.GetBucketRequest{ID: bucketID})
			if lookupErr != nil || resolved.ID != bucketID || !bucketHasLocalAlias(resolved.Keys, item.KeyID, item.Alias) {
				return nil, fmt.Errorf("local alias %s:%s conflicts with another bucket: add failed: %w", item.KeyID, item.Alias, err)
			}
			authoritativeSnapshot = resolved
		} else if updated != nil && updated.ID == bucketID {
			// AddBucketAlias returns the post-mutation bucket from the Garage node
			// that committed the write. Preserve it for status publication: an
			// immediate GetBucketInfo through the Service can hit another replica
			// before that replica observes the alias.
			authoritativeSnapshot = updated
		}
	}

	for _, previous := range bucket.Status.ManagedLocalAliases {
		if _, ok := desired[previous.KeyID+"\x00"+previous.Alias]; ok {
			continue
		}
		previousExists := false
		for _, key := range currentKeys {
			if key.AccessKeyID != previous.KeyID {
				continue
			}
			for _, alias := range key.BucketLocalAliases {
				if alias == previous.Alias {
					previousExists = true
					break
				}
			}
			break
		}
		if !previousExists {
			continue
		}
		updated, err := garageClient.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{
			BucketID: bucketID, LocalAlias: previous.Alias, AccessKeyID: previous.KeyID,
		})
		if err != nil && !garage.IsNotFound(err) {
			return nil, fmt.Errorf("failed to remove previously managed local alias %s:%s: %w", previous.KeyID, previous.Alias, err)
		}
		if err == nil && updated != nil && updated.ID == bucketID {
			authoritativeSnapshot = updated
		}
	}

	if !apiequality.Semantic.DeepEqual(bucket.Status.ManagedLocalAliases, managed) {
		bucket.Status.ManagedLocalAliases = managed
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
			return nil, fmt.Errorf("failed to persist managed local aliases: %w", err)
		}
	}
	return authoritativeSnapshot, nil
}

func sortLocalAliasStatuses(aliases []garagev1beta1.LocalAliasStatus) {
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].KeyID != aliases[j].KeyID {
			return aliases[i].KeyID < aliases[j].KeyID
		}
		return aliases[i].Alias < aliases[j].Alias
	})
}

func mergeLocalAliasStatuses(existing, additions []garagev1beta1.LocalAliasStatus) []garagev1beta1.LocalAliasStatus {
	merged := make(map[string]garagev1beta1.LocalAliasStatus, len(existing)+len(additions))
	for _, item := range existing {
		if item.KeyID != "" && item.Alias != "" {
			merged[item.KeyID+"\x00"+item.Alias] = item
		}
	}
	for _, item := range additions {
		if item.KeyID != "" && item.Alias != "" {
			merged[item.KeyID+"\x00"+item.Alias] = item
		}
	}
	result := make([]garagev1beta1.LocalAliasStatus, 0, len(merged))
	for _, item := range merged {
		result = append(result, item)
	}
	sortLocalAliasStatuses(result)
	return result
}

func bucketHasLocalAlias(keys []garage.BucketKeyInfo, keyID, alias string) bool {
	for _, key := range keys {
		if key.AccessKeyID != keyID {
			continue
		}
		for _, current := range key.BucketLocalAliases {
			if current == alias {
				return true
			}
		}
		return false
	}
	return false
}

func (r *GarageBucketReconciler) finalize(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	bucketID, err := garageBucketFinalizationID(bucket)
	if err != nil {
		return err
	}
	// A private reservation may have committed the Garage create but crashed
	// before binding its ID. Resolve both ordinary and COSI reservation forms;
	// every durable identity must agree before any bucket can be deleted.
	for _, reservation := range []struct {
		alias  string
		prefix string
	}{
		{alias: bucket.Annotations[garagev1beta1.AnnotationBucketReservationAlias], prefix: "garage-rsv-"},
		{alias: bucket.Annotations[garagev1beta1.AnnotationCOSIReservationAlias], prefix: "cosi-rsv-"},
	} {
		alias := reservation.alias
		if alias == "" {
			continue
		}
		expected, expectedErr := garagev1beta1.UIDBoundReservationAlias(reservation.prefix, bucket.Namespace, bucket.Name, bucket.UID)
		if expectedErr != nil {
			return expectedErr
		}
		if alias != expected {
			return fmt.Errorf("refusing GarageBucket finalization because reservation alias %q is not bound to GarageBucket UID %s", alias, bucket.UID)
		}
		reserved, lookupErr := getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{GlobalAlias: alias})
		if lookupErr != nil {
			if !garage.IsNotFound(lookupErr) {
				return fmt.Errorf("resolving bucket reservation alias %q: %w", alias, lookupErr)
			}
		} else {
			if bucketID != "" && bucketID != reserved.ID {
				return fmt.Errorf("refusing GarageBucket finalization because reservation alias %q resolves to bucket %q, not recorded bucket %q", alias, reserved.ID, bucketID)
			}
			bucketID = reserved.ID
		}
	}
	if cosiBucketID := bucket.Annotations[garagev1beta1.AnnotationCOSIBucketID]; cosiBucketID != "" {
		if bucketID == "" {
			return fmt.Errorf("refusing GarageBucket finalization because COSI bucket ID annotation %q has no authoritative status, spec, or UID-bound reservation identity", cosiBucketID)
		}
		if bucketID != cosiBucketID {
			return fmt.Errorf("refusing GarageBucket finalization because COSI bucket ID annotation %q disagrees with authoritative bucket ID %q", cosiBucketID, bucketID)
		}
	}
	if bucketID == "" {
		return nil
	}

	log.Info("Deleting bucket", "bucketID", bucketID)

	// Note: Garage requires bucket to be empty before deletion
	// The operator doesn't delete objects - that's the user's responsibility
	delCtx, cancel := context.WithTimeout(ctx, finalizeRPCTimeout)
	defer cancel()
	if err := garageClient.DeleteBucket(delCtx, bucketID); err != nil {
		// Check if bucket doesn't exist (404) - that's okay, we can proceed
		if garage.IsNotFound(err) {
			log.Info("Bucket already deleted or not found", "bucketID", bucketID)
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

func garageBucketFinalizationID(bucket *garagev1beta1.GarageBucket) (string, error) {
	var resolved string
	for source, candidate := range map[string]string{
		"status.bucketId": bucket.Status.BucketID,
		"spec.bucketId":   bucket.Spec.BucketID,
	} {
		if candidate == "" {
			continue
		}
		if resolved != "" && candidate != resolved {
			return "", fmt.Errorf("refusing GarageBucket finalization because %s=%q disagrees with resolved bucket ID %q", source, candidate, resolved)
		}
		resolved = candidate
	}
	return resolved, nil
}

func (r *GarageBucketReconciler) updateStatusWaiting(ctx context.Context, bucket *garagev1beta1.GarageBucket) (ctrl.Result, error) {
	bucket.Status.Phase = PhasePending
	meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonClusterNotReady,
		Message:            msgWaitingForCluster,
		ObservedGeneration: bucket.Generation,
	})
	if statusErr := UpdateStatusWithRetry(ctx, r.Client, bucket); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
}

func (r *GarageBucketReconciler) updateStatus(ctx context.Context, bucket *garagev1beta1.GarageBucket, phase string, err error) (ctrl.Result, error) {
	bucket.Status.Phase = phase
	// Only set ObservedGeneration when reconciliation succeeded
	if err == nil {
		bucket.Status.ObservedGeneration = bucket.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&bucket.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
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

func (r *GarageBucketReconciler) updateStatusFromGarage(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client, cluster *garagev1beta2.GarageCluster, reconcileSnapshot *garage.Bucket) (ctrl.Result, error) {
	if bucket.Status.BucketID == "" {
		return r.updateStatus(ctx, bucket, "Pending", nil)
	}

	garageBucket := reconcileSnapshot
	if garageBucket == nil {
		// No mutation response is available, so read the current Garage state.
		var err error
		garageBucket, err = getBucketWithTimeout(ctx, garageClient, garage.GetBucketRequest{ID: bucket.Status.BucketID})
		if err != nil {
			if isBucketLookupTimeout(err) {
				return r.handleBucketLookupTimeout(ctx, bucket)
			}
			if garage.IsMetadataDecodeError(err) {
				return r.handleBucketDecodeError(ctx, bucket, cluster)
			}
			return r.updateStatus(ctx, bucket, PhaseFailed, fmt.Errorf("failed to get bucket info: %w", err))
		}
	}
	// First success after one or more timeouts/decode errors → reset counters
	// and clear transient conditions so they self-heal.
	if err := r.clearBucketLookupTimeouts(ctx, bucket); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to clear bucket-lookup-timeouts annotation")
	}
	if err := r.clearBucketDecodeErrors(ctx, bucket); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to clear bucket-decode-errors annotation")
	}

	// Capture old status before modifications to detect no-op updates
	oldStatus := bucket.Status.DeepCopy()

	// Update status
	bucket.Status.Phase = PhaseReady
	bucket.Status.ObservedGeneration = bucket.Generation
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
		bucket.Status.WebsiteConfig = &garagev1beta1.WebsiteConfigStatus{
			IndexDocument: garageBucket.WebsiteConfig.IndexDocument,
			ErrorDocument: garageBucket.WebsiteConfig.ErrorDocument,
		}
	} else {
		bucket.Status.WebsiteConfig = nil
	}

	// Update quota usage status
	bucket.Status.QuotaUsage = &garagev1beta1.QuotaUsageStatus{
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

	bucket.Status.WebsiteURL = ""
	if garageBucket.WebsiteAccess {
		if w := effectiveWebAPI(cluster); w != nil && bucket.Status.GlobalAlias != "" {
			bucket.Status.WebsiteURL = "http://" + bucket.Status.GlobalAlias + w.RootDomain
		}
	}

	// Update key status and collect local aliases, sorted for deterministic comparison
	bucket.Status.Keys = make([]garagev1beta1.BucketKeyStatus, 0, len(garageBucket.Keys))
	bucket.Status.LocalAliases = nil // Reset local aliases
	for _, k := range garageBucket.Keys {
		bucket.Status.Keys = append(bucket.Status.Keys, garagev1beta1.BucketKeyStatus{
			KeyID: k.AccessKeyID,
			Name:  k.Name,
			Permissions: garagev1beta1.BucketKeyPermissions{
				Read:  k.Permissions.Read,
				Write: k.Permissions.Write,
				Owner: k.Permissions.Owner,
			},
		})
		// Collect local aliases from this key
		for _, alias := range k.BucketLocalAliases {
			bucket.Status.LocalAliases = append(bucket.Status.LocalAliases, garagev1beta1.LocalAliasStatus{
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
		Type:               PhaseReady,
		Status:             metav1.ConditionTrue,
		Reason:             "BucketReady",
		Message:            "Bucket is ready",
		ObservedGeneration: bucket.Generation,
	})

	// Skip status update if nothing changed — avoids ResourceVersion bump
	// which would trigger informer watch event and re-enqueue (infinite loop).
	// Use drift interval to periodically re-check Garage-side state even when idle.
	if apiequality.Semantic.DeepEqual(*oldStatus, bucket.Status) {
		return ctrl.Result{RequeueAfter: RequeueAfterDrift}, nil
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, bucket); err != nil {
		return ctrl.Result{}, err
	}

	// Status updated — the informer watch event will re-enqueue for immediate verification.
	return ctrl.Result{}, nil
}

// getBucketWithTimeout wraps garageClient.GetBucket with a per-call deadline.
// Returns errBucketInfoTimeout when the call exceeds getBucketInfoTimeout —
// callers use that sentinel to bump the stuck-bucket counter and bail
// gracefully without surfacing a generic API error.
func getBucketWithTimeout(ctx context.Context, garageClient *garage.Client, req garage.GetBucketRequest) (*garage.Bucket, error) {
	callCtx, cancel := context.WithTimeout(ctx, getBucketInfoTimeout)
	defer cancel()
	b, err := garageClient.GetBucket(callCtx, req)
	if err != nil && isTimeoutErr(err) && ctx.Err() == nil {
		// Distinguish per-call timeout from parent-ctx cancellation. We only
		// want to count it as a "stuck" signal when our own deadline fired,
		// not when the controller is shutting down. We classify both our
		// own context.DeadlineExceeded and net/http transport timeouts
		// (http.Client.Timeout) as stuck signals — the latter surface as a
		// *url.Error wrapping a net.Error with Timeout()==true and do NOT
		// match errors.Is(err, context.DeadlineExceeded).
		return nil, errBucketInfoTimeout
	}
	return b, err
}

// isTimeoutErr returns true for any error that indicates a timeout —
// either our per-call ctx deadline or a transport-level timeout from
// net/http (when http.Client.Timeout fires before the ctx deadline).
//
// We check:
//  1. errors.Is(err, context.DeadlineExceeded) — our own per-call ctx fired
//  2. net.Error.Timeout() — *url.Error / *net.OpError expose this
//  3. string fallback — wrapped errors that don't expose net.Error but
//     still carry timeout substrings in their message (defence in depth).
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "timeout awaiting response headers") ||
		strings.Contains(msg, "context deadline exceeded")
}

// isBucketLookupTimeout returns true if err originated from a per-call
// GetBucketInfo deadline. Used by callers to decide whether to bail with a
// stuck-bucket signal vs. propagate the error.
func isBucketLookupTimeout(err error) bool {
	return stderrors.Is(err, errBucketInfoTimeout)
}

// readTimeoutCounter parses the AnnotationBucketLookupTimeouts annotation
// into an int. Returns 0 for missing, malformed, or negative values.
func readTimeoutCounter(bucket *garagev1beta1.GarageBucket) int {
	if bucket.Annotations == nil {
		return 0
	}
	v, ok := bucket.Annotations[garagev1beta1.AnnotationBucketLookupTimeouts]
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// recordBucketLookupTimeout increments the consecutive-timeout counter
// annotation via a Patch (avoids ResourceVersion conflicts with subsequent
// status updates). Returns the new count.
func (r *GarageBucketReconciler) recordBucketLookupTimeout(ctx context.Context, bucket *garagev1beta1.GarageBucket) (int, error) {
	current := readTimeoutCounter(bucket) + 1
	patch := client.MergeFrom(bucket.DeepCopy())
	if bucket.Annotations == nil {
		bucket.Annotations = map[string]string{}
	}
	bucket.Annotations[garagev1beta1.AnnotationBucketLookupTimeouts] = strconv.Itoa(current)
	if err := r.Patch(ctx, bucket, patch); err != nil {
		return current, err
	}
	return current, nil
}

// clearBucketLookupTimeouts removes the counter annotation and the
// BucketLookupStuck condition if either is set. Idempotent. Called on the
// first successful GetBucket so a transient stall self-heals.
func (r *GarageBucketReconciler) clearBucketLookupTimeouts(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	hadAnno := false
	if bucket.Annotations != nil {
		_, hadAnno = bucket.Annotations[garagev1beta1.AnnotationBucketLookupTimeouts]
	}
	hadCond := meta.FindStatusCondition(bucket.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck) != nil
	if !hadAnno && !hadCond {
		return nil
	}
	if hadAnno {
		patch := client.MergeFrom(bucket.DeepCopy())
		delete(bucket.Annotations, garagev1beta1.AnnotationBucketLookupTimeouts)
		if err := r.Patch(ctx, bucket, patch); err != nil {
			return err
		}
	}
	if hadCond {
		meta.RemoveStatusCondition(&bucket.Status.Conditions, garagev1beta1.ConditionBucketLookupStuck)
	}
	return nil
}

// handleBucketLookupTimeout is called when a GetBucketInfo call from this
// reconcile timed out. Increments the counter and, on reaching
// BucketLookupStuckThreshold consecutive timeouts, sets the
// BucketLookupStuck status condition pointing operators at the
// trigger-repair=Aliases workaround. Returns a Result that requeues on the
// unhealthy interval — the timeout is informational, never a workqueue
// error.
func (r *GarageBucketReconciler) handleBucketLookupTimeout(ctx context.Context, bucket *garagev1beta1.GarageBucket) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	count, patchErr := r.recordBucketLookupTimeout(ctx, bucket)
	if patchErr != nil {
		log.Error(patchErr, "Failed to record bucket-lookup-timeouts annotation")
		// Keep going — counter is best-effort; the condition is the durable signal.
	}
	log.Info("GetBucketInfo timed out; the bucket may be wedged on a stale authorized_keys entry",
		"bucket", bucket.Name, "consecutiveTimeouts", count, "threshold", BucketLookupStuckThreshold)

	if count >= BucketLookupStuckThreshold {
		// TODO: auto-trigger Aliases repair on the parent cluster with a cooldown (see #190 follow-ups)
		alias := bucket.Spec.GlobalAlias
		if alias == "" {
			alias = bucket.Name
		}
		cond := metav1.Condition{
			Type:   garagev1beta1.ConditionBucketLookupStuck,
			Status: metav1.ConditionTrue,
			Reason: garagev1beta1.ReasonBucketLookupStuck,
			Message: fmt.Sprintf(
				"GetBucketInfo for bucket %q timed out %d consecutive times. "+
					"Likely cause: stale entry in authorized_keys whose RPC lookup hangs. "+
					"Manual recovery: set annotation %s=%s on the parent GarageCluster.",
				alias, count,
				garagev1beta1.AnnotationTriggerRepair,
				garagev1beta1.RepairTypeAliases,
			),
			ObservedGeneration: bucket.Generation,
		}
		// Apply the condition. The mutate closure re-applies it after a
		// conflict-driven re-fetch — without it, the helper would re-read the
		// stored object and silently overwrite this in-memory condition before
		// the next Update attempt, so the admin-recovery hint from #194 would
		// never surface on a Conflict.
		apply := func() {
			meta.SetStatusCondition(&bucket.Status.Conditions, cond)
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket, apply); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
}

// handleBucketDecodeError is called when GetBucketInfo returns a Garage
// InternalError "Unable to decode entry of key". This means a key_table entry
// cannot be deserialized by the running Garage version — typically after an
// upgrade or cross-version write. The reconciler increments a counter and,
// on reaching BucketDecodeErrorThreshold, auto-triggers Repair:Tables on the
// parent GarageCluster to re-sync key_table entries across all nodes.
func (r *GarageBucketReconciler) handleBucketDecodeError(ctx context.Context, bucket *garagev1beta1.GarageBucket, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	count, patchErr := r.recordBucketDecodeError(ctx, bucket)
	if patchErr != nil {
		log.Error(patchErr, "Failed to record bucket-decode-errors annotation")
	}
	log.Info("GetBucketInfo returned metadata decode error; key_table entry may be malformed",
		"bucket", bucket.Name, "consecutiveErrors", count, "threshold", BucketDecodeErrorThreshold)

	if count >= BucketDecodeErrorThreshold {
		alias := bucket.Spec.GlobalAlias
		if alias == "" {
			alias = bucket.Name
		}

		// Auto-trigger Repair:Tables on the parent cluster if not already pending.
		// The cluster controller consumes and removes this annotation after running,
		// so checking its presence is sufficient dedup without a separate cooldown.
		if cluster.Annotations[garagev1beta1.AnnotationTriggerRepair] == "" {
			patch := client.MergeFrom(cluster.DeepCopy())
			if cluster.Annotations == nil {
				cluster.Annotations = make(map[string]string)
			}
			cluster.Annotations[garagev1beta1.AnnotationTriggerRepair] = garagev1beta1.RepairTypeTables
			if err := r.Patch(ctx, cluster, patch); err != nil {
				log.Error(err, "Failed to auto-trigger Repair:Tables on parent cluster")
			} else {
				log.Info("Auto-triggered Repair:Tables on parent cluster to fix key_table decode errors",
					"cluster", cluster.Name, "bucket", bucket.Name)
			}
		}

		cond := metav1.Condition{
			Type:   garagev1beta1.ConditionBucketMetadataDegraded,
			Status: metav1.ConditionTrue,
			Reason: garagev1beta1.ReasonMetadataDecodeError,
			Message: fmt.Sprintf(
				"GetBucketInfo for bucket %q failed to decode key_table entry %d consecutive times. "+
					"Repair:Tables has been triggered on cluster %q to re-sync key_table entries. "+
					"This condition clears automatically on the next successful GetBucketInfo.",
				alias, count, cluster.Name,
			),
			ObservedGeneration: bucket.Generation,
		}
		apply := func() {
			meta.SetStatusCondition(&bucket.Status.Conditions, cond)
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, bucket, apply); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
}

// recordBucketDecodeError increments the consecutive decode-error counter
// annotation on the bucket and returns the new count.
func (r *GarageBucketReconciler) recordBucketDecodeError(ctx context.Context, bucket *garagev1beta1.GarageBucket) (int, error) {
	current := 0
	if v, ok := bucket.Annotations[garagev1beta1.AnnotationBucketDecodeErrors]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			current = n
		}
	}
	current++
	patch := client.MergeFrom(bucket.DeepCopy())
	if bucket.Annotations == nil {
		bucket.Annotations = make(map[string]string)
	}
	bucket.Annotations[garagev1beta1.AnnotationBucketDecodeErrors] = strconv.Itoa(current)
	return current, r.Patch(ctx, bucket, patch)
}

// clearBucketDecodeErrors removes the consecutive decode-error counter and
// the BucketMetadataDegraded condition on first success after prior failures.
func (r *GarageBucketReconciler) clearBucketDecodeErrors(ctx context.Context, bucket *garagev1beta1.GarageBucket) error {
	hadAnno := bucket.Annotations[garagev1beta1.AnnotationBucketDecodeErrors] != ""
	hadCond := meta.FindStatusCondition(bucket.Status.Conditions, garagev1beta1.ConditionBucketMetadataDegraded) != nil
	if !hadAnno && !hadCond {
		return nil
	}
	if hadAnno {
		patch := client.MergeFrom(bucket.DeepCopy())
		delete(bucket.Annotations, garagev1beta1.AnnotationBucketDecodeErrors)
		if err := r.Patch(ctx, bucket, patch); err != nil {
			return err
		}
	}
	if hadCond {
		meta.RemoveStatusCondition(&bucket.Status.Conditions, garagev1beta1.ConditionBucketMetadataDegraded)
	}
	return nil
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

// parseMPUOlderThan converts a duration string (e.g. "24h", "30m") to seconds.
// Returns the default of 86400 (24h) for empty, invalid, or non-positive values.
// Note: "d" suffix is not supported by time.ParseDuration; use "24h" instead.
func parseMPUOlderThan(s string) uint64 {
	const defaultSecs uint64 = 86400
	if s == "" {
		return defaultSecs
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultSecs
	}
	return uint64(d.Seconds())
}

// handleBucketAnnotations processes one-shot operational annotations on GarageBucket.
func (r *GarageBucketReconciler) handleBucketAnnotations(ctx context.Context, bucket *garagev1beta1.GarageBucket, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	if bucket.Annotations == nil {
		return nil
	}

	if _, ok := bucket.Annotations[garagev1beta1.AnnotationCleanupMPU]; !ok {
		return nil
	}

	if bucket.Status.BucketID == "" {
		log.Info("cleanup-mpu: bucket not yet provisioned, retaining annotation for retry")
		return nil
	}

	olderThan := parseMPUOlderThan(bucket.Annotations[garagev1beta1.AnnotationCleanupMPUOlderThan])
	result, err := garageClient.CleanupIncompleteUploads(ctx, bucket.Status.BucketID, olderThan)
	if err != nil {
		return fmt.Errorf("cleanup-mpu failed: %w", err)
	}
	log.Info("Incomplete multipart uploads cleaned up",
		"bucketID", bucket.Status.BucketID,
		"olderThanSecs", olderThan,
		"uploadsDeleted", result.UploadsDeleted)

	delete(bucket.Annotations, garagev1beta1.AnnotationCleanupMPU)
	delete(bucket.Annotations, garagev1beta1.AnnotationCleanupMPUOlderThan)
	if err := r.Update(ctx, bucket); err != nil {
		return fmt.Errorf("failed to remove cleanup-mpu annotations after successful cleanup: %w", err)
	}
	return nil
}

// ownerRefExists reports whether obj already has an owner reference with the given UID.
func ownerRefExists(obj client.Object, uid types.UID) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageBucketReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageBucket{}).
		Named("garagebucket").
		Complete(r)
}
