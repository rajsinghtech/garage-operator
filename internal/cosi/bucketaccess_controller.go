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

	// Garage does not support ServiceAccount-based authentication.
	if access.Status.AuthenticationType == cosiv1alpha2.BucketAccessAuthenticationTypeServiceAccount {
		return r.fail(ctx, access, errors.New("ServiceAccount auth not supported by Garage"))
	}

	// Parameters are copied onto Status.Parameters by the upstream controller.
	params, err := ParseBucketAccessClassParameters(access.Status.Parameters, r.Namespace)
	if err != nil {
		return r.fail(ctx, access, fmt.Errorf("parse params: %w", err))
	}

	if !access.GetDeletionTimestamp().IsZero() {
		if access.Status.AccountID != "" {
			bucketIDs := r.resolveBucketIDs(ctx, access)
			if err := r.Provisioner.RevokeAccess(ctx, access.Status.AccountID, bucketIDs, params); err != nil {
				return r.fail(ctx, access, err)
			}
		}
		ctrlutil.RemoveFinalizer(access, cosiv1alpha2.ProtectionFinalizer)
		if err := r.Update(ctx, access); err != nil {
			return reconcile.Result{}, err
		}
		logger.Info("BucketAccess deleted", "accountId", access.Status.AccountID)
		return reconcile.Result{}, nil
	}

	if ctrlutil.AddFinalizer(access, cosiv1alpha2.ProtectionFinalizer) {
		if err := r.Update(ctx, access); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	// Reserve secrets first — any race condition fails before we mutate Garage state.
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

	result, err := r.Provisioner.GrantAccess(ctx, access.Name, access.Status.AccountID, slots, params, access.Spec.ServiceAccountName)
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

// reserveSecret creates an empty owner-ref'd Secret. If a Secret of that name
// already exists, it must already be owned by this BucketAccess; otherwise we
// refuse to hijack it (someone else's data).
func (r *BucketAccessReconciler) reserveSecret(ctx context.Context, access *cosiv1alpha2.BucketAccess, name string) error {
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: access.Namespace}, existing)
	if err == nil {
		for _, ref := range existing.OwnerReferences {
			if ref.UID == access.UID && ref.Kind == "BucketAccess" {
				return nil
			}
		}
		return fmt.Errorf("secret %s exists and is not owned by this BucketAccess", name)
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
	if err := r.Create(ctx, sec); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *BucketAccessReconciler) populateSecret(ctx context.Context, access *cosiv1alpha2.BucketAccess, name string, b BucketResult, a *AccessResult) error {
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: access.Namespace}, sec); err != nil {
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
	return r.Update(ctx, sec)
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
