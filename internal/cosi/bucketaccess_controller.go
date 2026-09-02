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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagecontroller "github.com/rajsinghtech/garage-operator/internal/controller"
)

// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketaccesses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketaccesses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketaccesses/finalizers,verbs=update
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=bucketclaims,verbs=get;list;watch
// +kubebuilder:rbac:groups=objectstorage.k8s.io,resources=buckets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// BucketAccessReconciler reconciles cosiv1alpha2.BucketAccess objects whose
// Status.DriverName matches DriverName. It manages the protection finalizer,
// reserves/populates per-claim credential Secrets, and delegates the Garage-side
// key lifecycle to Provisioner.
type BucketAccessReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	DriverName  string
	Namespace   string // namespace for shadow GarageKey resources
	Provisioner *Provisioner
}

func (r *BucketAccessReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cosiv1alpha2.BucketAccess{}).
		WithEventFilter(driverNameMatches(r.DriverName)).
		Named("cosi-bucketaccess").
		Complete(r)
}

func (r *BucketAccessReconciler) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	logger := ctrl.LoggerFrom(ctx, "driverName", r.DriverName)
	access := &cosiv1alpha2.BucketAccess{}
	if err := r.Get(ctx, req.NamespacedName, access); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// The cluster-wide COSI controller fills Status.DriverName from the
	// referenced BucketAccessClass. We can only reconcile once that's set.
	if access.Status.DriverName == "" {
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if access.Status.DriverName != r.DriverName {
		return reconcile.Result{}, nil
	}
	if !access.GetDeletionTimestamp().IsZero() && ctrlutil.ContainsFinalizer(access, GarageProtectionFinalizer) {
		bucketName, err := r.findDeletingBucketForAccess(ctx, access)
		if err != nil {
			return r.fail(ctx, access, fmt.Errorf("check referenced bucket cleanup before revoking access: %w", err))
		}
		if bucketName != "" {
			return r.deferAccessRevocation(ctx, access, bucketName)
		}
	}
	identity, err := r.Provisioner.ResolveBucketAccessIdentity(
		ctx, access.Namespace, access.Name, string(access.UID), access.Status.AccountID, r.DriverName,
	)
	if err != nil {
		return r.fail(ctx, access, fmt.Errorf("resolve BucketAccess identity: %w", err))
	}
	if identity.DuplicateCanonicalIdentity != "" {
		done, err := r.Provisioner.CleanupDuplicateAccessIdentity(ctx, identity.DuplicateCanonicalIdentity)
		if err != nil {
			return r.fail(ctx, access, fmt.Errorf("clean duplicate BucketAccess identity: %w", err))
		}
		if !done {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		return reconcile.Result{Requeue: true}, nil
	}
	accessIdentity := identity.Identity
	ownsLegacyAccount := identity.OwnsLegacyAccount
	sharedLegacyAccount := identity.SharedLegacyAccount
	if !access.GetDeletionTimestamp().IsZero() && access.Status.AccountID == "" {
		done, err := r.Provisioner.CancelAccessProvisioning(ctx, accessIdentity)
		if err != nil {
			return r.fail(ctx, access, fmt.Errorf("cancel pending access provisioning: %w", err))
		}
		if !done {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		r.completeCleanupHandoff(access)
		if err := r.Update(ctx, access); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("Pending BucketAccess provisioning cancelled")
		return reconcile.Result{}, nil
	}

	// Parameters are copied onto Status.Parameters by the upstream controller.
	params, err := ParseBucketAccessClassParameters(access.Status.Parameters, r.Namespace)
	if err != nil {
		if access.DeletionTimestamp.IsZero() {
			return r.fail(ctx, access, fmt.Errorf("parse params: %w", err))
		}
		// Older sidecars could omit Parameters on revoke. RevokeAccess can
		// recover the cluster from the authoritative shadow account ID.
		params = nil
	}

	if !access.GetDeletionTimestamp().IsZero() {
		if access.Status.AccountID != "" {
			if !sharedLegacyAccount {
				bucketIDs := r.resolveBucketIDs(ctx, access)
				if err := r.Provisioner.RevokeAccess(ctx, access.Status.AccountID, bucketIDs, params); err != nil {
					return r.fail(ctx, access, err)
				}
			}
		}
		r.completeCleanupHandoff(access)
		if err := r.Update(ctx, access); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("BucketAccess deleted", "accountId", access.Status.AccountID)
		return reconcile.Result{}, nil
	}
	// Garage does not support ServiceAccount-based authentication. Validate this
	// only for provisioning; an old malformed object must still be deletable.
	if access.Status.AuthenticationType == cosiv1alpha2.BucketAccessAuthenticationTypeServiceAccount {
		return r.fail(ctx, access, errors.New("ServiceAccount auth not supported by Garage"))
	}
	if err := validateS3AccessProtocol(access.Spec.Protocol); err != nil {
		return r.fail(ctx, access, err)
	}
	if sharedLegacyAccount && !ownsLegacyAccount {
		return r.fail(ctx, access, fmt.Errorf("legacy Garage account %s is shared by multiple same-name BucketAccesses; delete and recreate this non-owning BucketAccess to rotate credentials safely", access.Status.AccountID))
	}

	if ctrlutil.AddFinalizer(access, GarageProtectionFinalizer) {
		if err := r.Update(ctx, access); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	// Reserve secrets first — any race condition fails before we mutate Garage state.
	if err := validateUniqueAccessSecretNames(access.Spec.BucketClaims); err != nil {
		return r.fail(ctx, access, err)
	}
	for _, bca := range access.Spec.BucketClaims {
		if err := r.reserveSecret(ctx, access, bca.AccessSecretName); err != nil {
			return r.fail(ctx, access, fmt.Errorf("reserve secret %s: %w", bca.AccessSecretName, err))
		}
	}

	// Resolve BucketClaim → bound Bucket → Garage bucketID, paired with each claim's AccessMode.
	slots, accessedBuckets, err := r.resolveBuckets(ctx, access)
	if err != nil {
		return r.fail(ctx, access, err)
	}
	if err := r.Provisioner.ValidateBucketAccessCluster(ctx, slots, params); err != nil {
		return r.fail(ctx, access, err)
	}

	result, err := r.Provisioner.GrantAccess(ctx, accessIdentity, access.Status.AccountID, slots, params, access.Spec.ServiceAccountName)
	if err != nil {
		return r.fail(ctx, access, err)
	}

	// Populate each reserved Secret with credentials + that bucket's info.
	for i, bca := range access.Spec.BucketClaims {
		if err := r.populateSecret(ctx, access, bca.AccessSecretName, result.PerBucket[i], result); err != nil {
			return r.fail(ctx, access, err)
		}
	}

	access.Status.ReadyToUse = ptr.To(true)
	access.Status.AccountID = result.AccountID
	access.Status.AccessedBuckets = accessedBuckets
	access.Status.Error = nil
	if err := r.Status().Update(ctx, access); err != nil {
		return reconcile.Result{}, err
	}
	logger.Info("BucketAccess ready", "accountId", result.AccountID)
	return reconcile.Result{}, nil
}

func validateS3AccessProtocol(protocol cosiv1alpha2.ObjectProtocol) error {
	if protocol != cosiv1alpha2.ObjectProtocolS3 {
		return fmt.Errorf("garage supports only the S3 protocol, not %q", protocol)
	}
	return nil
}

func validateUniqueAccessSecretNames(claims []cosiv1alpha2.BucketClaimAccess) error {
	secretNames := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		if _, duplicate := secretNames[claim.AccessSecretName]; duplicate {
			return fmt.Errorf("multiple referenced BucketClaims use the same accessSecretName %q", claim.AccessSecretName)
		}
		secretNames[claim.AccessSecretName] = struct{}{}
	}
	return nil
}

// completeCleanupHandoff records the pinned COSI sidecar-to-controller deletion
// handoff and releases only Garage's private cleanup finalizer. The upstream
// controller owns objectstorage.k8s.io/protection and removes it after its
// BucketClaim bookkeeping completes. Both metadata changes belong in one
// update so either finalizer keeps the object alive across a process crash.
func (r *BucketAccessReconciler) completeCleanupHandoff(access *cosiv1alpha2.BucketAccess) {
	if access.Annotations == nil {
		access.Annotations = make(map[string]string)
	}
	access.Annotations[cosiv1alpha2.SidecarCleanupFinishedAnnotation] = ""
	ctrlutil.RemoveFinalizer(access, GarageProtectionFinalizer)
}

// resolveBuckets walks Spec.BucketClaims, looks up the bound Bucket for each,
// and pairs each Garage bucketID with that claim's AccessMode.
func (r *BucketAccessReconciler) resolveBuckets(ctx context.Context, access *cosiv1alpha2.BucketAccess) ([]BucketAccessSlot, []cosiv1alpha2.AccessedBucket, error) {
	slots := make([]BucketAccessSlot, 0, len(access.Spec.BucketClaims))
	out := make([]cosiv1alpha2.AccessedBucket, 0, len(access.Spec.BucketClaims))
	for _, bca := range access.Spec.BucketClaims {
		claim := &cosiv1alpha2.BucketClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: bca.BucketClaimName, Namespace: access.Namespace}, claim); err != nil {
			return nil, nil, fmt.Errorf("get bucketclaim %s: %w", bca.BucketClaimName, err)
		}
		if claim.Status.BoundBucketName == "" {
			return nil, nil, fmt.Errorf("bucketclaim %s not yet bound", bca.BucketClaimName)
		}
		bucket := &cosiv1alpha2.Bucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: claim.Status.BoundBucketName}, bucket); err != nil {
			return nil, nil, fmt.Errorf("get bucket %s: %w", claim.Status.BoundBucketName, err)
		}
		if bucket.Status.BucketID == "" {
			return nil, nil, fmt.Errorf("bucket %s not yet provisioned", bucket.Name)
		}
		if bucket.Spec.DriverName != r.DriverName {
			return nil, nil, fmt.Errorf("bucket %s belongs to driver %q, not %q", bucket.Name, bucket.Spec.DriverName, r.DriverName)
		}
		if !bucket.DeletionTimestamp.IsZero() {
			return nil, nil, fmt.Errorf("bucket %s is deleting", bucket.Name)
		}
		if _, deleting := bucket.Annotations[cosiv1alpha2.BucketClaimBeingDeletedAnnotation]; deleting {
			return nil, nil, fmt.Errorf("BucketClaim for bucket %s is deleting", bucket.Name)
		}
		ref := bucket.Spec.BucketClaimRef
		if ref.Name != claim.Name || ref.Namespace != claim.Namespace || ref.UID == "" || ref.UID != claim.UID {
			return nil, nil, fmt.Errorf("bucket %s does not belong to BucketClaim %s/%s UID %s", bucket.Name, claim.Namespace, claim.Name, claim.UID)
		}
		slots = append(slots, BucketAccessSlot{
			BucketID:   bucket.Status.BucketID,
			AccessMode: mapAccessModeFromAPI(bca.AccessMode),
		})
		out = append(out, cosiv1alpha2.AccessedBucket{
			BucketName:      bucket.Name,
			BucketID:        bucket.Status.BucketID,
			BucketClaimName: bca.BucketClaimName,
		})
	}
	return slots, out, nil
}

// resolveBucketIDs is a best-effort helper used during deletion — returns nil
// if resolution fails (Provisioner.RevokeAccess still deletes the key).
func (r *BucketAccessReconciler) resolveBucketIDs(ctx context.Context, access *cosiv1alpha2.BucketAccess) []string {
	slots, _, err := r.resolveBuckets(ctx, access)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(slots))
	for _, s := range slots {
		ids = append(ids, s.BucketID)
	}
	return ids
}

// findDeletingBucketForAccess uses the COSI status mapping as its primary
// source because BucketClaims may already be gone when namespace deletion
// drives cleanup. It falls back to live claims for older accesses whose
// status was not recorded by an earlier operator version.
func (r *BucketAccessReconciler) findDeletingBucketForAccess(ctx context.Context, access *cosiv1alpha2.BucketAccess) (string, error) {
	if access.Status.AccountID == "" {
		return "", nil
	}

	if len(access.Status.AccessedBuckets) > 0 {
		for _, reference := range access.Status.AccessedBuckets {
			if reference.BucketName == "" || reference.BucketID == "" {
				continue
			}
			bucket := &cosiv1alpha2.Bucket{}
			if err := r.Get(ctx, types.NamespacedName{Name: reference.BucketName}, bucket); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return "", err
			}
			if bucket.Status.BucketID != reference.BucketID ||
				bucket.Spec.DriverName != r.DriverName ||
				bucket.Spec.BucketClaimRef.Namespace != access.Namespace ||
				bucket.Spec.BucketClaimRef.Name != reference.BucketClaimName {
				continue
			}
			if bucketNeedsAccessPreserved(bucket) && ctrlutil.ContainsFinalizer(bucket, GarageProtectionFinalizer) {
				return bucket.Name, nil
			}
		}
		return "", nil
	}

	for _, reference := range access.Spec.BucketClaims {
		claim := &cosiv1alpha2.BucketClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: reference.BucketClaimName, Namespace: access.Namespace}, claim); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", err
		}
		if claim.Status.BoundBucketName == "" {
			continue
		}
		bucket := &cosiv1alpha2.Bucket{}
		if err := r.Get(ctx, types.NamespacedName{Name: claim.Status.BoundBucketName}, bucket); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", err
		}
		if bucket.Status.BucketID == "" || bucket.Spec.DriverName != r.DriverName ||
			bucket.Spec.BucketClaimRef.Namespace != claim.Namespace ||
			bucket.Spec.BucketClaimRef.Name != claim.Name ||
			(bucket.Spec.BucketClaimRef.UID != "" && bucket.Spec.BucketClaimRef.UID != claim.UID) {
			continue
		}
		if bucketNeedsAccessPreserved(bucket) && ctrlutil.ContainsFinalizer(bucket, GarageProtectionFinalizer) {
			return bucket.Name, nil
		}
	}
	return "", nil
}

func bucketNeedsAccessPreserved(bucket *cosiv1alpha2.Bucket) bool {
	if bucket.Spec.DeletionPolicy == cosiv1alpha2.BucketDeletionPolicyRetain {
		return false
	}
	_, claimBeingDeleted := bucket.Annotations[cosiv1alpha2.BucketClaimBeingDeletedAnnotation]
	return !bucket.GetDeletionTimestamp().IsZero() || claimBeingDeleted
}

func (r *BucketAccessReconciler) deferAccessRevocation(ctx context.Context, access *cosiv1alpha2.BucketAccess, bucketName string) (reconcile.Result, error) {
	retryCount, err := recordFinalizationRetry(ctx, r.Client, access)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("record blocked BucketAccess cleanup retry: %w", err)
	}
	message := fmt.Sprintf(
		"BucketAccess deletion is waiting for Bucket %q: its Garage bucket is not empty. "+
			"remove all objects and incomplete multipart uploads using this access, then cleanup will continue. "+
			"The operator never empties bucket contents automatically.",
		bucketName,
	)
	apply := func() {
		access.Status.ReadyToUse = ptr.To(false)
		access.Status.Error = cosiv1alpha2.NewTimestampedError(time.Now(), message)
	}
	apply()
	if err := garagecontroller.UpdateStatusWithRetry(ctx, r.Client, access, apply); err != nil {
		return reconcile.Result{}, fmt.Errorf("record blocked BucketAccess status: %w", err)
	}
	return reconcile.Result{RequeueAfter: garagecontroller.FinalizationRetryDelay(retryCount)}, nil
}

// reserveSecret creates an empty owner-ref'd Secret. If a Secret of that name
// already exists, it must already be owned by this BucketAccess; otherwise we
// refuse to hijack it (someone else's data).
func (r *BucketAccessReconciler) reserveSecret(ctx context.Context, access *cosiv1alpha2.BucketAccess, name string) error {
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: access.Namespace}, existing)
	if err == nil {
		return validateAccessSecretOwnership(existing, access)
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: access.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(access, cosiv1alpha2.GroupVersion.WithKind("BucketAccess")),
			},
		},
	}
	if err := r.Create(ctx, sec); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return err
	}
	// A different actor can win the Get/Create race. Re-read and verify exact
	// controller ownership before treating AlreadyExists as a reservation.
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: access.Namespace}, existing); err != nil {
		return err
	}
	return validateAccessSecretOwnership(existing, access)
}

func (r *BucketAccessReconciler) populateSecret(ctx context.Context, access *cosiv1alpha2.BucketAccess, name string, b BucketResult, a *AccessResult) error {
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: access.Namespace}, sec); err != nil {
		return err
	}
	// Ownership can change if the originally reserved Secret is deleted and
	// recreated while Garage provisioning is in flight. Never write credentials
	// into a replacement object that this BucketAccess does not control.
	if err := validateAccessSecretOwnership(sec, access); err != nil {
		return err
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data["S3_BUCKET_ID"] = []byte(b.GlobalAlias)
	sec.Data["S3_ENDPOINT"] = []byte(b.Endpoint)
	sec.Data["S3_REGION"] = []byte(b.Region)
	sec.Data["S3_ACCESS_KEY_ID"] = []byte(a.AccessKeyID)
	sec.Data["S3_ACCESS_SECRET_KEY"] = []byte(a.SecretAccessKey)
	// Canonical v1alpha2 names. Keep the historical S3_* aliases above so an
	// in-place operator upgrade does not break existing consumers.
	sec.Data[string(cosiv1alpha2.BucketInfoVar_Protocol)] = []byte(cosiv1alpha2.ObjectProtocolS3)
	sec.Data[string(cosiv1alpha2.BucketInfoVar_S3_BucketId)] = []byte(b.GlobalAlias)
	sec.Data[string(cosiv1alpha2.BucketInfoVar_S3_Endpoint)] = []byte(b.Endpoint)
	sec.Data[string(cosiv1alpha2.BucketInfoVar_S3_Region)] = []byte(b.Region)
	sec.Data[string(cosiv1alpha2.BucketInfoVar_S3_AddressingStyle)] = []byte("path")
	sec.Data[string(cosiv1alpha2.CredentialVar_S3_AccessKeyId)] = []byte(a.AccessKeyID)
	sec.Data[string(cosiv1alpha2.CredentialVar_S3_AccessSecretKey)] = []byte(a.SecretAccessKey)
	return r.Update(ctx, sec)
}

func validateAccessSecretOwnership(secret *corev1.Secret, access *cosiv1alpha2.BucketAccess) error {
	controller := metav1.GetControllerOf(secret)
	if controller == nil || !metav1.IsControlledBy(secret, access) ||
		controller.APIVersion != cosiv1alpha2.GroupVersion.String() || controller.Kind != "BucketAccess" ||
		controller.Name != access.Name || controller.UID != access.UID {
		return fmt.Errorf("secret %s exists and is not controlled by this BucketAccess", client.ObjectKeyFromObject(secret))
	}
	return nil
}

func mapAccessModeFromAPI(m cosiv1alpha2.BucketAccessMode) AccessMode {
	switch m {
	case cosiv1alpha2.BucketAccessModeReadOnly:
		return AccessModeReadOnly
	case cosiv1alpha2.BucketAccessModeWriteOnly:
		return AccessModeWriteOnly
	default:
		return AccessModeReadWrite
	}
}

func (r *BucketAccessReconciler) fail(ctx context.Context, access *cosiv1alpha2.BucketAccess, in error) (reconcile.Result, error) {
	access.Status.ReadyToUse = ptr.To(false)
	access.Status.Error = cosiv1alpha2.NewTimestampedError(time.Now(), in.Error())
	_ = r.Status().Update(ctx, access)
	return reconcile.Result{}, in
}
