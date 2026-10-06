/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	operatorAdminTokenIDKey              = "token-id"
	annotationOperatorAdminTokenReady    = "garage.rajsingh.info/operator-admin-token-ready"
	annotationOperatorAdminTokenID       = "garage.rajsingh.info/operator-admin-token-id"
	annotationOperatorAdminTokenName     = "garage.rajsingh.info/operator-admin-token-name"
	labelOperatorAdminToken              = "garage.rajsingh.info/operator-admin-token"
	operatorAdminTokenReadyValue         = "true"
	operatorAdminTokenVerificationTimout = 5 * time.Second
)

func operatorAdminTokenSecretName(cluster *garagev1beta2.GarageCluster) string {
	return internalOperatorCredentialSecretName(cluster, "operator")
}

func internalOperatorCredentialSecretName(cluster *garagev1beta2.GarageCluster, kind string) string {
	identity := ""
	clusterName := defaultAppName
	if cluster != nil {
		clusterName = cluster.Name
		identity = cluster.Namespace + "/" + cluster.Name + ":" + string(cluster.UID)
	}
	digest := sha256.Sum256([]byte(identity))
	shortHash := hex.EncodeToString(digest[:4])
	infix := "-" + kind + "-"
	suffix := infix + shortHash
	maxPrefix := 63 - len(suffix)
	prefix := strings.Trim(clusterName, "-")
	if len(prefix) > maxPrefix {
		prefix = strings.TrimRight(prefix[:maxPrefix], "-")
	}
	return prefix + suffix
}

func operatorAdminTokenName(cluster *garagev1beta2.GarageCluster) string {
	return fmt.Sprintf("garage-operator:%s/%s:%s", cluster.Namespace, cluster.Name, cluster.UID)
}

func canonicalDynamicAdminToken(raw []byte, expectedID string) (string, error) {
	value := strings.TrimSpace(string(raw))
	prefix, suffix, ok := strings.Cut(value, ".")
	if !ok || prefix == "" || suffix == "" {
		return "", fmt.Errorf("garage dynamic admin token must have <id>.<secret> form")
	}
	if expectedID != "" && prefix != expectedID {
		return "", fmt.Errorf("dynamic admin token prefix %q does not match token ID %q", prefix, expectedID)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return "", fmt.Errorf("dynamic admin token contains a non-visible-ASCII byte")
		}
	}
	return value, nil
}

func validateManagedAdminTokenInfo(info *garage.AdminTokenInfo, id, name string, scope []string) error {
	if info == nil || info.ID == nil || *info.ID != id || info.Name != name || info.Expired || info.Expiration != nil {
		return fmt.Errorf("admin token %q does not match its exact ID/name/non-expiring contract", id)
	}
	if len(info.Scope) != len(scope) {
		return fmt.Errorf("admin token %q has scope %v, want exactly %v", id, info.Scope, scope)
	}
	for i := range scope {
		if info.Scope[i] != scope[i] {
			return fmt.Errorf("admin token %q has scope %v, want exactly %v", id, info.Scope, scope)
		}
	}
	return nil
}

// errAdminTokenUnproven separates the two failure classes of dynamic token
// resolution. Integrity failures (a Secret that lost immutability, ownership,
// shape, name, or its pinned ID) mean something tampered with the credential and
// must stay fatal. This sentinel marks the other class: the credential is
// intact, but the operator has not proven it authenticates against the Pod
// incarnations that are live right now — because they were just replaced, or
// because they are not all Ready yet.
//
// That distinction is load-bearing. Any deliberate whole-cluster restart
// invalidates the recorded Pod-set hash, and re-proving it reads the replicated
// admin-token table. A replication-factor purge wipes cluster_layout, so that
// table is unreadable ("Layout not ready") until a layout is committed — and
// committing one needs an Admin client. Treating an unproven-but-intact token as
// fatal closes that loop and the migration deadlocks in RebuildingLayout
// forever. Callers that gate a credential rotation still refuse to proceed on
// this error; only Admin-client construction falls back, to the same mounted
// static bootstrap credential it already uses before a dynamic token exists.
var errAdminTokenUnproven = stderrors.New("dynamic operator Admin token is intact but unproven on the live Pod incarnation set")

// eventReasonOperatorAdminTokenNotReady carries the raw token error that the
// condition message deliberately leaves out.
const eventReasonOperatorAdminTokenNotReady = "OperatorAdminTokenNotReady"

// operatorAdminTokenCondition maps the outcome of reconcileOperatorAdminToken
// to ConditionOperatorAdminTokenReady. authoritative reports whether the
// dynamic token already gates the shared Admin client: before that, a failure
// does not block dependents because they still use the static credential.
//
// The message must be a pure function of the blocking cause, never of raw
// error text: network errors carry ephemeral ports, timings, and request IDs,
// and any change would cost a status write on every pass (and a watch event for
// every GarageCluster watcher). Only
// ManagedPodsNotReady includes detail, because that detail is the Kubernetes
// object state the operator derived it from (the blocking Pod/GarageNode name
// and why it is not Ready). The raw error goes to the operator log and, when
// the condition changes, to a Warning event on the GarageCluster.
func operatorAdminTokenCondition(tokenErr error, authoritative bool) metav1.Condition {
	condition := metav1.Condition{Type: garagev1beta1.ConditionOperatorAdminTokenReady}
	if tokenErr == nil && authoritative {
		condition.Status = metav1.ConditionTrue
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenVerified
		condition.Message = "dynamic operator Admin token is verified on every managed Garage process"
		return condition
	}
	condition.Status = metav1.ConditionFalse
	effect := "GarageKey and GarageBucket reconciliation is blocked until then"
	if !authoritative {
		effect = "GarageKey and GarageBucket reconciliation continues on the static bootstrap token meanwhile"
	}
	const seeEvents = "; see the " + eventReasonOperatorAdminTokenNotReady +
		" events on this GarageCluster or the operator log for the underlying error"
	var podSetErr *operatorAdminPodSetError
	switch {
	case tokenErr == nil:
		// The create path returns before the new token is verified anywhere.
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenProvisioning
		condition.Message = fmt.Sprintf(
			"dynamic operator Admin token was created and awaits verification on every managed Garage process (%s)", effect)
	case stderrors.As(tokenErr, &podSetErr):
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenManagedPodsNotReady
		condition.Message = fmt.Sprintf(
			"dynamic operator Admin token needs every managed Garage Pod Ready (%s): %v", effect, podSetErr)
	case authoritative && stderrors.Is(tokenErr, errAdminTokenUnproven):
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenNotVerified
		condition.Message = fmt.Sprintf(
			"dynamic operator Admin token is intact but not yet accepted by every managed Garage process (%s)%s", effect, seeEvents)
	case authoritative:
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenNotVerified
		condition.Message = fmt.Sprintf(
			"dynamic operator Admin token could not be verified on every managed Garage process (%s)%s", effect, seeEvents)
	default:
		condition.Reason = garagev1beta1.ReasonOperatorAdminTokenProvisioning
		condition.Message = fmt.Sprintf(
			"dynamic operator Admin token is not provisioned yet (%s)%s", effect, seeEvents)
	}
	condition.Message = limitStatusConditionMessage(condition.Message)
	return condition
}

// operatorAdminTokenAuthoritative reports whether the dynamic token Secret
// carries its ready marker. The cached read is enough except right after
// reconcileOperatorAdminToken succeeded: that path may have just created the
// Secret or patched the marker to ready, which the informer may not show yet.
// Only then is the uncached read needed. The failure paths never set the
// marker, so a stale cache there can at worst show NotVerified instead of
// Provisioning for one pass after a token-recovery delete, and the Secret
// watch corrects it.
func (r *GarageClusterReconciler) operatorAdminTokenAuthoritative(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	tokenErr error,
) (bool, error) {
	key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	read := func(reader client.Reader) (bool, error) {
		secret := &corev1.Secret{}
		if err := reader.Get(ctx, key, secret); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return secret.Annotations[annotationOperatorAdminTokenReady] == operatorAdminTokenReadyValue, nil
	}
	ready, err := read(r.Client)
	if err != nil || ready || tokenErr != nil {
		return ready, err
	}
	return read(r.safetyReader())
}

// setOperatorAdminTokenCondition records the outcome of the last
// reconcileOperatorAdminToken call, writing status only when it changed.
func (r *GarageClusterReconciler) setOperatorAdminTokenCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	tokenErr error,
) error {
	if cluster == nil {
		return nil
	}
	existing := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
	if cluster.IsManagementHandle() || cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		if existing == nil {
			return nil
		}
		apply := func() {
			meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionOperatorAdminTokenReady)
		}
		apply()
		return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
	}
	authoritative, err := r.operatorAdminTokenAuthoritative(ctx, cluster, tokenErr)
	if err != nil {
		return err
	}
	condition := operatorAdminTokenCondition(tokenErr, authoritative)
	condition.ObservedGeneration = cluster.Generation
	if existing != nil && existing.Status == condition.Status && existing.Reason == condition.Reason &&
		existing.Message == condition.Message && existing.ObservedGeneration == condition.ObservedGeneration {
		return nil
	}
	apply := func() { meta.SetStatusCondition(&cluster.Status.Conditions, condition) }
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		return err
	}
	// Events are emitted only when the condition changes, so they stay bounded
	// while still recording the error that caused the change.
	if tokenErr != nil {
		emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeWarning, eventReasonOperatorAdminTokenNotReady,
			"%s: %s", condition.Reason, limitStatusConditionMessage(tokenErr.Error()))
	}
	return nil
}

// reportOperatorAdminTokenCondition is the non-fatal Reconcile wrapper: the
// condition is informational and must not abort reconciliation.
func (r *GarageClusterReconciler) reportOperatorAdminTokenCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	tokenErr error,
) {
	if err := r.setOperatorAdminTokenCondition(ctx, cluster, tokenErr); err != nil {
		logf.FromContext(ctx).V(1).Info("Could not update OperatorAdminTokenReady", "error", err.Error())
	}
}

// garageClientError points GarageKey/GarageBucket status at the cluster
// condition that names the blocker when the dynamic operator token is unproven.
func garageClientError(cluster *garagev1beta2.GarageCluster, err error) error {
	if !stderrors.Is(err, errAdminTokenUnproven) {
		return fmt.Errorf("failed to create garage client: %w", err)
	}
	owner := "the referenced GarageCluster"
	if cluster != nil {
		namespace, name := cluster.Namespace, cluster.Name
		if ref := cluster.Spec.ConnectTo; ref != nil && ref.ClusterRef != nil {
			name = ref.ClusterRef.Name
			if ref.ClusterRef.Namespace != "" {
				namespace = ref.ClusterRef.Namespace
			}
		}
		owner = fmt.Sprintf("GarageCluster %s/%s", namespace, name)
	}
	detail := ""
	var podSetErr *operatorAdminPodSetError
	if stderrors.As(err, &podSetErr) {
		detail = " for the blocking Pod"
	}
	return fmt.Errorf("waiting for the operator Admin token of %s; see its %s condition%s: %w",
		owner, garagev1beta1.ConditionOperatorAdminTokenReady, detail, err)
}

func getReadyOperatorAdminToken(
	ctx context.Context,
	c client.Client,
	cluster *garagev1beta2.GarageCluster,
) (string, bool, error) {
	if cluster == nil || cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil || cluster.IsManagementHandle() {
		return "", false, nil
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	if err := c.Get(ctx, key, secret); err != nil {
		if errors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading operator dynamic admin token Secret %s: %w", key, err)
	}
	if secret.Immutable == nil || !*secret.Immutable || !metav1.IsControlledBy(secret, cluster) ||
		secret.Labels[labelOperatorAdminToken] != operatorAdminTokenReadyValue || len(secret.Data) != 2 ||
		secret.Annotations[annotationOperatorAdminTokenName] != operatorAdminTokenName(cluster) {
		return "", false, fmt.Errorf("operator dynamic admin token Secret %s lost its exact immutable ownership/data/name contract", key)
	}
	id := string(secret.Data[operatorAdminTokenIDKey])
	token, err := canonicalDynamicAdminToken(secret.Data[DefaultAdminTokenKey], id)
	if err != nil {
		return "", false, fmt.Errorf("validating operator dynamic admin token Secret %s: %w", key, err)
	}
	if pinned := cluster.Annotations[annotationOperatorAdminTokenID]; pinned != id {
		return "", false, fmt.Errorf("operator dynamic admin token Secret %s has ID %q while GarageCluster pins %q", key, id, pinned)
	}
	if secret.Annotations[annotationOperatorAdminTokenReady] != operatorAdminTokenReadyValue {
		return "", false, nil
	}
	set, err := getOperatorAdminPodSet(ctx, c, cluster)
	if err != nil {
		return "", false, fmt.Errorf(
			"%w: operator dynamic token is authoritative but the complete managed Pod set is not ready: %w",
			errAdminTokenUnproven, err)
	}
	if verified := secret.Annotations[annotationOperatorAdminTokenPodSet]; verified == "" || verified != set.Hash {
		return "", false, fmt.Errorf(
			"%w: operator dynamic token has not been directly verified on the current managed Pod incarnation set",
			errAdminTokenUnproven)
	}
	return token, true, nil
}

// retireUndesiredOperatorTokens runs before workload reconciliation so the
// last process carrying a usable static startup credential is not scaled away
// before internally generated table-backed credentials are revoked.
func (r *GarageClusterReconciler) retireUndesiredOperatorTokens(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if cluster == nil || cluster.IsManagementHandle() {
		return nil
	}
	adminConfigured := cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil
	if !adminConfigured {
		secret := &corev1.Secret{}
		key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
		err := r.Get(ctx, key, secret)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		if err == nil || cluster.Annotations[annotationOperatorAdminTokenID] != "" {
			if err := r.revokeOperatorAdminToken(ctx, cluster); err != nil {
				return fmt.Errorf("retiring operator Admin token before removing bootstrap auth: %w", err)
			}
		}
	}

	if !wantsOperatorMetricsToken(cluster) {
		secret := &corev1.Secret{}
		key := types.NamespacedName{Name: operatorMetricsTokenSecretName(cluster), Namespace: cluster.Namespace}
		err := r.Get(ctx, key, secret)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		if err == nil || cluster.Annotations[annotationOperatorMetricsTokenIntent] != "" {
			if err := r.revokeOperatorMetricsToken(ctx, cluster); err != nil {
				return fmt.Errorf("retiring operator metrics token before disabling authenticated monitoring: %w", err)
			}
		}
	}
	return nil
}

func (r *GarageClusterReconciler) operatorAdminTokenRotationBridgeReady(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	token, ready, err := getReadyOperatorAdminToken(ctx, r.Client, cluster)
	if err != nil || !ready {
		return ready, err
	}
	set, err := getOperatorAdminPodSet(ctx, r.safetyReader(), cluster)
	if err != nil {
		return false, err
	}
	if err := verifyDynamicAdminTokenOnPods(ctx, set.Pods, getAdminPort(cluster), token); err != nil {
		return false, err
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	if err := r.Get(ctx, key, secret); err != nil {
		return false, err
	}
	id := string(secret.Data[operatorAdminTokenIDKey])
	bootstrap, err := r.staticGarageClientForPod(ctx, &set.Pods[0], getAdminPort(cluster))
	if err != nil {
		return false, err
	}
	info, err := bootstrap.GetAdminTokenInfo(ctx, id, "")
	if err != nil {
		return false, err
	}
	if err := validateManagedAdminTokenInfo(info, id, operatorAdminTokenName(cluster), []string{"*"}); err != nil {
		return false, err
	}
	return true, nil
}

func (r *GarageClusterReconciler) persistOperatorAdminTokenID(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	id string,
) error {
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster UID or generation changed while pinning its operator Admin token")
		}
		if current := fresh.Annotations[annotationOperatorAdminTokenID]; current != "" && current != id {
			return fmt.Errorf("garageCluster already pins operator Admin token ID %q, refusing %q", current, id)
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string)
		}
		if fresh.Annotations[annotationOperatorAdminTokenID] == id {
			updated = fresh
			return nil
		}
		fresh.Annotations[annotationOperatorAdminTokenID] = id
		if err := r.Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting operator Admin token ID: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) clearOperatorAdminTokenID(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expectedID string,
) error {
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster UID or generation changed while clearing its operator Admin token ID")
		}
		current := fresh.Annotations[annotationOperatorAdminTokenID]
		if current == "" {
			updated = fresh
			return nil
		}
		if current != expectedID {
			return fmt.Errorf("garageCluster pins operator Admin token ID %q, refusing to clear expected ID %q", current, expectedID)
		}
		delete(fresh.Annotations, annotationOperatorAdminTokenID)
		if err := r.Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing recovered operator Admin token ID: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) staticGarageClientForPod(
	ctx context.Context,
	pod *corev1.Pod,
	adminPort int32,
) (*garage.Client, error) {
	token, err := mountedStaticAdminToken(ctx, r.safetyReader(), pod)
	if err != nil {
		return nil, err
	}
	return garage.NewClient(adminEndpoint(pod.Status.PodIP, adminPort), token), nil
}

// operatorTokenRevocationClient reaches the replicated Admin-token table with
// a credential other than the token being deleted. Prefer an exact local Pod's
// mounted static bearer. A gateway-only site may legitimately have scaled its
// last Pod to zero, so fall back to the referenced surviving storage Admin API.
func (r *GarageClusterReconciler) operatorTokenRevocationClient(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*garage.Client, error) {
	localSet, localErr := getOperatorAdminPodSet(ctx, r.safetyReader(), cluster)
	if localErr == nil && len(localSet.Pods) > 0 {
		local, err := r.staticGarageClientForPod(ctx, &localSet.Pods[0], getAdminPort(cluster))
		if err == nil {
			return local, nil
		}
		localErr = err
	}

	if cluster != nil && cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil {
		var (
			remote *garage.Client
			err    error
		)
		switch {
		case cluster.Spec.ConnectTo.ClusterRef != nil:
			remote, err = r.getStorageClusterClient(ctx, cluster)
		case cluster.Spec.ConnectTo.AdminAPIEndpoint != "":
			remote, err = r.getExternalStorageClient(ctx, cluster)
		}
		if err == nil && remote != nil {
			return remote, nil
		}
		if err != nil {
			return nil, fmt.Errorf("no exact local Pod is available (%v), and the surviving storage Admin API is unreachable: %w", localErr, err)
		}
	}
	return nil, fmt.Errorf("no exact local Pod or referenced surviving storage Admin API is available for token revocation: %v", localErr)
}

func (r *GarageClusterReconciler) verifyMountedStaticAdminTokensOnPods(
	ctx context.Context,
	pods []corev1.Pod,
	adminPort int32,
) error {
	for i := range pods {
		c, err := r.staticGarageClientForPod(ctx, &pods[i], adminPort)
		if err != nil {
			return err
		}
		probeCtx, cancel := context.WithTimeout(ctx, operatorAdminTokenVerificationTimout)
		_, err = c.GetClusterStatus(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("mounted static token is not accepted by Pod %s/%s: %w", pods[i].Namespace, pods[i].Name, err)
		}
	}
	return nil
}

func verifyDynamicAdminTokenOnPods(
	ctx context.Context,
	pods []corev1.Pod,
	adminPort int32,
	token string,
) error {
	if len(pods) == 0 {
		return fmt.Errorf("waiting for at least one running managed Garage process")
	}
	for i := range pods {
		probeCtx, cancel := context.WithTimeout(ctx, operatorAdminTokenVerificationTimout)
		_, err := garage.NewClient(adminEndpoint(pods[i].Status.PodIP, adminPort), token).GetClusterStatus(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("dynamic operator token has not reached Pod %s/%s: %w", pods[i].Namespace, pods[i].Name, err)
		}
	}
	return nil
}

// directVerifiedOperatorAdminClient returns an exact managed Pod endpoint that
// already accepts the table-backed operator token. It is intentionally narrower
// than GetGarageClient: callers use it only to bridge a Pod-set transition where
// the immutable token Secret is authoritative on the previous set but a fresh,
// not-yet-assigned process cannot receive that FullReplication row until a
// GarageNode adds it to the layout. Probing the exact endpoint avoids sending a
// static or only-partially-replicated credential through a load-balanced Service.
func directVerifiedOperatorAdminClient(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	adminPort int32,
) (*garage.Client, error) {
	if cluster == nil || reader == nil {
		return nil, fmt.Errorf("cluster and Kubernetes reader are required for an exact operator-token client")
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	if err := reader.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("reading operator dynamic admin token Secret %s: %w", key, err)
	}
	if secret.Immutable == nil || !*secret.Immutable || !metav1.IsControlledBy(secret, cluster) ||
		secret.Labels[labelOperatorAdminToken] != operatorAdminTokenReadyValue || len(secret.Data) != 2 ||
		secret.Annotations[annotationOperatorAdminTokenName] != operatorAdminTokenName(cluster) ||
		secret.Annotations[annotationOperatorAdminTokenReady] != operatorAdminTokenReadyValue {
		return nil, fmt.Errorf("operator dynamic admin token Secret %s is not authoritative", key)
	}
	id := string(secret.Data[operatorAdminTokenIDKey])
	token, err := canonicalDynamicAdminToken(secret.Data[DefaultAdminTokenKey], id)
	if err != nil {
		return nil, fmt.Errorf("validating operator dynamic admin token Secret %s: %w", key, err)
	}
	if pinned := cluster.Annotations[annotationOperatorAdminTokenID]; pinned != id {
		return nil, fmt.Errorf("operator dynamic admin token Secret %s has ID %q while GarageCluster pins %q", key, id, pinned)
	}

	set, err := getOperatorAdminPodSet(ctx, reader, cluster)
	if err != nil {
		return nil, fmt.Errorf("proving the managed Pod set for an exact operator-token client: %w", err)
	}
	var lastErr error
	for i := range set.Pods {
		candidate := garage.NewClient(adminEndpoint(set.Pods[i].Status.PodIP, adminPort), token)
		probeCtx, cancel := context.WithTimeout(ctx, operatorAdminTokenVerificationTimout)
		status, probeErr := candidate.GetClusterStatus(probeCtx)
		if probeErr == nil && status.LayoutVersion == 0 {
			probeErr = fmt.Errorf("pod reports uninitialized layout version 0")
		}
		if probeErr == nil {
			var info *garage.AdminTokenInfo
			info, probeErr = candidate.GetAdminTokenInfo(probeCtx, id, "")
			if probeErr == nil {
				probeErr = validateManagedAdminTokenInfo(info, id, operatorAdminTokenName(cluster), []string{"*"})
			}
		}
		cancel()
		if probeErr == nil {
			return candidate, nil
		}
		lastErr = fmt.Errorf("pod %s/%s: %w", set.Pods[i].Namespace, set.Pods[i].Name, probeErr)
	}
	return nil, fmt.Errorf("dynamic operator token is not accepted by any exact managed Pod with a committed layout: %w", lastErr)
}

func (r *GarageClusterReconciler) requireOperatorTokenBootstrapLayout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pods []corev1.Pod,
	bootstrap *garage.Client,
) error {
	layout, err := bootstrap.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("reading layout before operator token creation: %w", err)
	}
	if layout.Version == 0 || len(layout.Roles) == 0 {
		return fmt.Errorf("waiting for a committed nonempty Garage layout before creating a FullReplication Admin token")
	}
	if err := requireSettledLayoutHistory(ctx, bootstrap); err != nil {
		return fmt.Errorf("waiting for settled layout history before creating operator token: %w", err)
	}
	roleIDs := make(map[string]struct{}, len(layout.Roles))
	for i := range layout.Roles {
		roleIDs[canonicalGarageNodeID(layout.Roles[i].ID)] = struct{}{}
	}
	seenSelf := make(map[string]string, len(pods))
	for i := range pods {
		podClient, err := r.staticGarageClientForPod(ctx, &pods[i], getAdminPort(cluster))
		if err != nil {
			return err
		}
		probeCtx, cancel := context.WithTimeout(ctx, operatorAdminTokenVerificationTimout)
		status, err := podClient.GetClusterStatus(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("discovering exact self identity for Pod %s/%s: %w", pods[i].Namespace, pods[i].Name, err)
		}
		selfID, ok := findSelfNode(status.Nodes)
		if !ok {
			if byIP, found := findNodeByIPs(status.Nodes, []string{pods[i].Status.PodIP}); found {
				selfID, ok = byIP, true
			}
		}
		selfID = canonicalGarageNodeID(selfID)
		if !ok || selfID == "" {
			return fmt.Errorf("could not prove self identity for Pod %s/%s before operator token creation", pods[i].Namespace, pods[i].Name)
		}
		if previous, duplicate := seenSelf[selfID]; duplicate {
			return fmt.Errorf("pods %s and %s/%s report the same Garage identity %s", previous, pods[i].Namespace, pods[i].Name, selfID)
		}
		seenSelf[selfID] = pods[i].Namespace + "/" + pods[i].Name
		if _, assigned := roleIDs[selfID]; !assigned {
			return fmt.Errorf("pod %s/%s self identity %s has no role in committed layout version %d", pods[i].Namespace, pods[i].Name, selfID, layout.Version)
		}
	}
	return nil
}

// reconcileOperatorAdminToken bootstraps a full-scope table-backed token after
// initial layout formation. It is deliberately crash-recoverable: the friendly
// name is deterministic, and an API token found without its one-time Secret is
// tombstoned before retrying creation.
func (r *GarageClusterReconciler) reconcileOperatorAdminToken(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if cluster == nil || cluster.IsManagementHandle() || cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return nil
	}
	podSet, err := getOperatorAdminPodSet(ctx, r.safetyReader(), cluster)
	if err != nil {
		return fmt.Errorf("proving complete managed process set for dynamic operator token: %w", err)
	}
	bootstrap, err := r.staticGarageClientForPod(ctx, &podSet.Pods[0], getAdminPort(cluster))
	if err != nil {
		return fmt.Errorf("building exact-Pod static bootstrap Admin client: %w", err)
	}
	secretKey := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	secret := &corev1.Secret{}
	secretErr := r.Get(ctx, secretKey, secret)
	if secretErr != nil && !errors.IsNotFound(secretErr) {
		return fmt.Errorf("reading dynamic operator token Secret %s: %w", secretKey, secretErr)
	}

	if secretErr == nil {
		if secret.Immutable == nil || !*secret.Immutable || !metav1.IsControlledBy(secret, cluster) ||
			secret.Labels[labelOperatorAdminToken] != operatorAdminTokenReadyValue || len(secret.Data) != 2 ||
			secret.Annotations[annotationOperatorAdminTokenName] != operatorAdminTokenName(cluster) {
			return fmt.Errorf("dynamic operator token Secret %s lost its exact immutable ownership/data/name contract", secretKey)
		}
		id := string(secret.Data[operatorAdminTokenIDKey])
		token, err := canonicalDynamicAdminToken(secret.Data[DefaultAdminTokenKey], id)
		if err != nil {
			return fmt.Errorf("validating dynamic operator token Secret %s: %w", secretKey, err)
		}
		if err := r.persistOperatorAdminTokenID(ctx, cluster, id); err != nil {
			return err
		}
		if secret.Annotations[annotationOperatorAdminTokenReady] != operatorAdminTokenReadyValue {
			if err := r.requireOperatorTokenBootstrapLayout(ctx, cluster, podSet.Pods, bootstrap); err != nil {
				return err
			}
		}
		info, err := bootstrap.GetAdminTokenInfo(ctx, id, "")
		if garage.IsNotFound(err) {
			if err := r.verifyMountedStaticAdminTokensOnPods(ctx, podSet.Pods, getAdminPort(cluster)); err != nil {
				return fmt.Errorf("unrecoverable operator token cannot be replaced safely: %w", err)
			}
			if err := bootstrap.DeleteAdminToken(ctx, id); err != nil && !garage.IsNotFound(err) {
				return fmt.Errorf("tombstoning unrecoverable operator Admin token %s: %w", id, err)
			}
			if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("deleting unrecoverable operator token Secret %s: %w", secretKey, err)
			}
			if err := r.clearOperatorAdminTokenID(ctx, cluster, id); err != nil {
				return err
			}
			return fmt.Errorf("recovered a missing/unreplicated operator token row; waiting to create a replicated replacement")
		}
		if err != nil {
			return fmt.Errorf("checking operator Admin token %s: %w", id, err)
		}
		if err := validateManagedAdminTokenInfo(info, id, operatorAdminTokenName(cluster), []string{"*"}); err != nil {
			return err
		}
		if err := verifyDynamicAdminTokenOnPods(ctx, podSet.Pods, getAdminPort(cluster), token); err != nil {
			// The token row and Secret can remain intact while a layout transition
			// temporarily makes the bearer unavailable on one or more processes. Do
			// not leave the old Pod-set proof authoritative in that state: shared
			// clients would keep routing the unproven token through the Service and
			// turn a retryable 403 into a persistent stale-health snapshot. Keeping
			// the ready marker while removing its proof makes getReadyOperatorAdminToken
			// fail closed until this exact live Pod set accepts the token again.
			if secret.Annotations[annotationOperatorAdminTokenReady] == operatorAdminTokenReadyValue &&
				secret.Annotations[annotationOperatorAdminTokenPodSet] != "" {
				before := secret.DeepCopy()
				delete(secret.Annotations, annotationOperatorAdminTokenPodSet)
				if err := r.Patch(ctx, secret, client.MergeFrom(before)); err != nil {
					return fmt.Errorf("dynamic operator token is unproven and clearing its live Pod-set proof: %w", err)
				}
			}
			return fmt.Errorf("%w: %v", errAdminTokenUnproven, err)
		}
		if secret.Annotations[annotationOperatorAdminTokenReady] != operatorAdminTokenReadyValue ||
			secret.Annotations[annotationOperatorAdminTokenPodSet] != podSet.Hash {
			before := secret.DeepCopy()
			if secret.Annotations == nil {
				secret.Annotations = make(map[string]string)
			}
			secret.Annotations[annotationOperatorAdminTokenReady] = operatorAdminTokenReadyValue
			secret.Annotations[annotationOperatorAdminTokenPodSet] = podSet.Hash
			if err := r.Patch(ctx, secret, client.MergeFrom(before)); err != nil {
				return fmt.Errorf("activating dynamic operator token after exact process-set verification: %w", err)
			}
		}
		return nil
	}

	// If Kubernetes lost an already-pinned one-time Secret, first prove the
	// exact mounted static revision authenticates every process. Only then can
	// we tombstone and replace the now-unrecoverable dynamic token.
	if lostID := cluster.Annotations[annotationOperatorAdminTokenID]; lostID != "" {
		if err := r.verifyMountedStaticAdminTokensOnPods(ctx, podSet.Pods, getAdminPort(cluster)); err != nil {
			return fmt.Errorf("dynamic operator token Secret was deleted and static recovery is not safe: %w", err)
		}
		if err := bootstrap.DeleteAdminToken(ctx, lostID); err != nil && !garage.IsNotFound(err) {
			return fmt.Errorf("deleting unrecoverable dynamic operator token %s: %w", lostID, err)
		}
		if err := r.clearOperatorAdminTokenID(ctx, cluster, lostID); err != nil {
			return err
		}
		return fmt.Errorf("deleted unrecoverable dynamic operator token %s after static-token verification; waiting to recreate", lostID)
	}

	// Gate on a committed layout BEFORE touching the admin-token table. The table
	// is replicated, so it cannot be enumerated until a layout exists — Garage
	// answers "Layout not ready" with a 500, which is not a NotFound and turns
	// what is really "not yet" into a hard error on every reconcile of a fresh
	// cluster and of one whose layout was just purged. The gate below is the
	// designated wait signal for exactly that state, and CreateAdminToken (the
	// only reason to sweep residue) sits behind it regardless.
	if err := r.requireOperatorTokenBootstrapLayout(ctx, cluster, podSet.Pods, bootstrap); err != nil {
		return err
	}

	tokens, err := bootstrap.ListAdminTokens(ctx)
	if err != nil {
		return fmt.Errorf("listing dynamic Admin tokens before operator bootstrap: %w", err)
	}
	friendlyName := operatorAdminTokenName(cluster)
	removedResidue := false
	for i := range tokens {
		if tokens[i].ID == nil || tokens[i].Name != friendlyName {
			continue
		}
		if err := bootstrap.DeleteAdminToken(ctx, *tokens[i].ID); err != nil && !garage.IsNotFound(err) {
			return fmt.Errorf("deleting crash-residue operator Admin token %s: %w", *tokens[i].ID, err)
		}
		removedResidue = true
	}
	if removedResidue {
		return fmt.Errorf("removed operator Admin token whose one-time Secret was not persisted; waiting to recreate")
	}

	scope := []string{"*"}
	created, err := bootstrap.CreateAdminToken(ctx, garage.AdminTokenUpdate{
		Name: &friendlyName, NeverExpires: true, Scope: &scope,
	})
	if err != nil {
		return fmt.Errorf("creating table-backed operator Admin token: %w", err)
	}
	if created.ID == nil || *created.ID == "" {
		return fmt.Errorf("garage returned a table-backed operator Admin token without an ID")
	}
	id := *created.ID
	if _, err := canonicalDynamicAdminToken([]byte(created.SecretToken), id); err != nil {
		return fmt.Errorf("garage returned invalid table-backed operator Admin token: %w", err)
	}
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretKey.Name, Namespace: secretKey.Namespace,
			Labels: mergeLabels(r.labelsForCluster(cluster), map[string]string{
				labelOperatorAdminToken: operatorAdminTokenReadyValue,
			}),
			Annotations: map[string]string{
				annotationOperatorAdminTokenReady: "false",
				annotationOperatorAdminTokenName:  friendlyName,
			},
		},
		Type: corev1.SecretTypeOpaque, Immutable: ptr.To(true),
		Data: map[string][]byte{
			DefaultAdminTokenKey:    []byte(created.SecretToken),
			operatorAdminTokenIDKey: []byte(id),
		},
	}
	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, secret); err != nil {
		return fmt.Errorf("persisting one-time table-backed operator Admin token Secret %s: %w", secretKey, err)
	}
	return r.persistOperatorAdminTokenID(ctx, cluster, id)
}

// revokeOperatorAdminToken removes the table-backed credential before a
// federated site leaves the surviving layout. Deleting a token with itself is
// safe: Garage authenticates the request before applying its table tombstone.
func (r *GarageClusterReconciler) revokeOperatorAdminToken(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: operatorAdminTokenSecretName(cluster), Namespace: cluster.Namespace}
	secretErr := r.Get(ctx, key, secret)
	if secretErr != nil && !errors.IsNotFound(secretErr) {
		return secretErr
	}
	id := cluster.Annotations[annotationOperatorAdminTokenID]
	if secretErr == nil {
		secretID, _, err := func() (string, string, error) {
			if secret.Immutable == nil || !*secret.Immutable || !metav1.IsControlledBy(secret, cluster) || len(secret.Data) != 2 {
				return "", "", fmt.Errorf("operator Admin token Secret %s lost its exact contract", key)
			}
			secretID := string(secret.Data[operatorAdminTokenIDKey])
			token, err := canonicalDynamicAdminToken(secret.Data[DefaultAdminTokenKey], secretID)
			return secretID, token, err
		}()
		if err != nil {
			return err
		}
		if id != "" && id != secretID {
			return fmt.Errorf("operator Admin token Secret ID %q differs from pinned ID %q", secretID, id)
		}
		id = secretID
	}
	if id == "" {
		return nil
	}
	bootstrap, err := r.operatorTokenRevocationClient(ctx, cluster)
	if err != nil {
		return err
	}
	if err := bootstrap.DeleteAdminToken(ctx, id); err != nil && !garage.IsNotFound(err) {
		// The DELETE may have committed before its response was lost. Verify with
		// static auth so self-revocation cannot turn an ambiguous success into a
		// permanent 403 finalizer wedge.
		if _, checkErr := bootstrap.GetAdminTokenInfo(ctx, id, ""); !garage.IsNotFound(checkErr) {
			return err
		}
	}
	if secretErr == nil {
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting revoked operator Admin token Secret %s: %w", key, err)
		}
	}
	if cluster.DeletionTimestamp.IsZero() {
		if err := r.clearOperatorAdminTokenID(ctx, cluster, id); err != nil {
			return err
		}
	}
	return nil
}

func (r *GarageClusterReconciler) abandonLocalOperatorTokenSecrets(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	for _, name := range []string{operatorMetricsTokenSecretName(cluster), operatorAdminTokenSecretName(cluster)} {
		secret := &corev1.Secret{}
		key := types.NamespacedName{Name: name, Namespace: cluster.Namespace}
		if err := r.Get(ctx, key, secret); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return err
		}
		if !metav1.IsControlledBy(secret, cluster) {
			return fmt.Errorf("refusing to abandon colliding operator credential Secret %s because it is not controlled by GarageCluster %s/%s", key, cluster.Namespace, cluster.Name)
		}
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
