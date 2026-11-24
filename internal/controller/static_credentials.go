/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
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
	annotationStaticCredentialsRevision = "garage.rajsingh.info/static-credentials-revision"
	annotationStaticCredentialsSecret   = "garage.rajsingh.info/static-credentials-secret"
	annotationStaticCredentialsSources  = "garage.rajsingh.info/static-credentials-sources"
	annotationConsulRotationReady       = "garage.rajsingh.info/consul-credential-rotation-ready"
	labelStaticCredentialsSnapshot      = "garage.rajsingh.info/static-credentials-snapshot"

	staticCredentialConsulTokenKey = "consul-token"
)

type staticCredentialSource struct {
	logicalKey string
	ref        *corev1.SecretKeySelector
	defaultKey string
	bearer     bool
}

func staticCredentialSources(cluster *garagev1beta2.GarageCluster) []staticCredentialSource {
	if cluster == nil {
		return nil
	}
	var sources []staticCredentialSource
	if cluster.Spec.Admin != nil {
		if cluster.Spec.Admin.AdminTokenSecretRef != nil {
			sources = append(sources, staticCredentialSource{
				logicalKey: DefaultAdminTokenKey,
				ref:        cluster.Spec.Admin.AdminTokenSecretRef,
				defaultKey: DefaultAdminTokenKey,
				bearer:     true,
			})
		}
		if cluster.Spec.Admin.MetricsTokenSecretRef != nil {
			sources = append(sources, staticCredentialSource{
				logicalKey: metricsTokenVolumeName,
				ref:        cluster.Spec.Admin.MetricsTokenSecretRef,
				defaultKey: metricsTokenVolumeName,
				bearer:     true,
			})
		}
	}
	if cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil &&
		cluster.Spec.Discovery.Consul.Enabled != nil && *cluster.Spec.Discovery.Consul.Enabled {
		consul := cluster.Spec.Discovery.Consul
		for _, source := range []staticCredentialSource{
			{logicalKey: consulCACertKey, ref: consul.CACertSecretRef, defaultKey: consulCACertKey},
			{logicalKey: consulClientCertKey, ref: consul.ClientCertSecretRef, defaultKey: consulClientCertKey},
			{logicalKey: consulClientKeyKey, ref: consul.ClientKeySecretRef, defaultKey: consulClientKeyKey},
			{logicalKey: staticCredentialConsulTokenKey, ref: consul.TokenSecretRef, defaultKey: remoteAdminTokenKey},
		} {
			if source.ref != nil {
				sources = append(sources, source)
			}
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].logicalKey < sources[j].logicalKey })
	return sources
}

func staticCredentialSourceDescriptor(namespace string, source staticCredentialSource) string {
	key := source.ref.Key
	if key == "" {
		key = source.defaultKey
	}
	return namespace + "/" + source.ref.Name + ":" + key
}

func staticCredentialSourceDescriptors(cluster *garagev1beta2.GarageCluster) map[string]string {
	descriptors := make(map[string]string)
	for _, source := range staticCredentialSources(cluster) {
		descriptors[source.logicalKey] = staticCredentialSourceDescriptor(cluster.Namespace, source)
	}
	return descriptors
}

// canonicalStaticBearer mirrors upstream Garage's hash_bearer_token(token.trim()).
// A dot is forbidden because Garage interprets every dotted bearer as a dynamic
// admin-table token and never compares it with the configured static hash.
func canonicalStaticBearer(raw []byte) ([]byte, error) {
	value, err := canonicalHeaderCredential(raw)
	if err != nil {
		return nil, err
	}
	if strings.Contains(value, ".") {
		return nil, fmt.Errorf("static Garage bearer tokens cannot contain '.'; Garage reserves dotted tokens for dynamic Admin API tokens")
	}
	return []byte(value), nil
}

func canonicalHeaderCredential(raw []byte) (string, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("token is empty after trimming whitespace")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return "", fmt.Errorf("token must contain only visible ASCII characters accepted by an HTTP header")
		}
	}
	return value, nil
}

func staticCredentialsRevision(data map[string][]byte, descriptors map[string]string, rpcSecret []byte) string {
	keys := make([]string, 0, len(descriptors))
	for key := range descriptors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	mac := hmac.New(sha256.New, rpcSecret)
	_, _ = mac.Write([]byte("garage-operator/static-credentials/v1\x00"))
	for _, key := range keys {
		_, _ = mac.Write([]byte(key))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(descriptors[key]))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write(data[key])
		_, _ = mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func staticCredentialsSnapshotName(clusterName, revision string) string {
	const suffixLength = 16
	shortRevision := revision
	if len(shortRevision) > suffixLength {
		shortRevision = shortRevision[:suffixLength]
	}
	const infix = "-credentials-"
	raw := clusterName + infix + shortRevision
	if len(raw) <= 63 {
		return raw
	}
	clusterDigest := garageConfigHash(clusterName)[:8]
	const digestSeparator = "-"
	maxPrefix := 63 - len(infix) - len(shortRevision) - len(digestSeparator) - len(clusterDigest)
	prefix := strings.Trim(clusterName, "-")
	if len(prefix) > maxPrefix {
		prefix = strings.TrimRight(prefix[:maxPrefix], "-")
	}
	return prefix + digestSeparator + clusterDigest + infix + shortRevision
}

func currentStaticCredentialsSecretName(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil || cluster.Annotations == nil {
		return ""
	}
	return cluster.Annotations[annotationStaticCredentialsSecret]
}

func mountedStaticAdminTokenRef(pod *corev1.Pod) (*corev1.SecretKeySelector, error) {
	if pod == nil {
		return nil, fmt.Errorf("pod is nil")
	}
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		if container.Name != defaultAppName {
			continue
		}
		for j := range container.Env {
			env := &container.Env[j]
			if env.Name == envGarageAdminToken && env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				return env.ValueFrom.SecretKeyRef.DeepCopy(), nil
			}
		}
	}
	// Upgrade compatibility for Pods rendered before the operator moved the
	// startup bearer from *_TOKEN_FILE to a SecretKeyRef environment variable.
	for i := range pod.Spec.Volumes {
		volume := &pod.Spec.Volumes[i]
		if volume.Name != DefaultAdminTokenKey || volume.Secret == nil || volume.Secret.SecretName == "" {
			continue
		}
		key := DefaultAdminTokenKey
		if len(volume.Secret.Items) == 1 && volume.Secret.Items[0].Key != "" {
			key = volume.Secret.Items[0].Key
		}
		return &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: volume.Secret.SecretName},
			Key:                  key,
		}, nil
	}
	return nil, fmt.Errorf("pod %s/%s has no operator-managed static Admin token reference", pod.Namespace, pod.Name)
}

func mountedStaticAdminToken(
	ctx context.Context,
	reader client.Reader,
	pod *corev1.Pod,
) (string, error) {
	ref, err := mountedStaticAdminTokenRef(pod)
	if err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = DefaultAdminTokenKey
	}
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: ref.Name, Namespace: pod.Namespace}
	if err := reader.Get(ctx, secretKey, secret); err != nil {
		return "", fmt.Errorf("reading Pod %s/%s mounted static Admin token %s: %w", pod.Namespace, pod.Name, secretKey, err)
	}
	raw, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("pod %s/%s mounted static Admin token Secret %s has no key %q", pod.Namespace, pod.Name, secretKey, key)
	}
	canonical, err := canonicalStaticBearer(raw)
	if err != nil {
		return "", fmt.Errorf("validating Pod %s/%s mounted static Admin token: %w", pod.Namespace, pod.Name, err)
	}
	return string(canonical), nil
}

func decodeStaticCredentialSources(raw string) (map[string]string, error) {
	if raw == "" {
		return map[string]string{}, nil
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func encodeStaticCredentialSources(sources map[string]string) (string, error) {
	raw, err := json.Marshal(sources)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (r *GarageClusterReconciler) resolveStaticCredentials(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string][]byte, map[string]string, error) {
	data := make(map[string][]byte)
	descriptors := staticCredentialSourceDescriptors(cluster)
	for _, source := range staticCredentialSources(cluster) {
		key := source.ref.Key
		if key == "" {
			key = source.defaultKey
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: source.ref.Name, Namespace: cluster.Namespace}, secret); err != nil {
			return nil, descriptors, fmt.Errorf("reading static Garage credential source %s: %w", descriptors[source.logicalKey], err)
		}
		raw, ok := secret.Data[key]
		if !ok {
			return nil, descriptors, fmt.Errorf("static Garage credential source %s has no key %q", source.ref.Name, key)
		}
		value := append([]byte(nil), raw...)
		if source.bearer {
			canonical, err := canonicalStaticBearer(value)
			if err != nil {
				return nil, descriptors, fmt.Errorf("validating %s from %s: %w", source.logicalKey, descriptors[source.logicalKey], err)
			}
			value = canonical
		} else if source.logicalKey == staticCredentialConsulTokenKey {
			canonical, err := canonicalHeaderCredential(value)
			if err != nil {
				return nil, descriptors, fmt.Errorf("validating Consul token from %s: %w", descriptors[source.logicalKey], err)
			}
			value = []byte(canonical)
		}
		data[source.logicalKey] = value
	}
	return data, descriptors, nil
}

func staticCredentialMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func consulStaticCredentialsChanged(current, desired map[string][]byte) bool {
	for _, key := range []string{consulCACertKey, consulClientCertKey, consulClientKeyKey, staticCredentialConsulTokenKey} {
		if !bytes.Equal(current[key], desired[key]) {
			return true
		}
	}
	return false
}

func hasDesiredConsulCredentials(descriptors map[string]string) bool {
	for _, key := range []string{consulCACertKey, consulClientCertKey, consulClientKeyKey, staticCredentialConsulTokenKey} {
		if _, ok := descriptors[key]; ok {
			return true
		}
	}
	return false
}

func validateStaticCredentialSnapshot(
	cluster *garagev1beta2.GarageCluster,
	snapshot *corev1.Secret,
	revision string,
	descriptors map[string]string,
	rpcSecret []byte,
	expectedData map[string][]byte,
) error {
	if cluster == nil || snapshot == nil || revision == "" {
		return fmt.Errorf("static credential snapshot validation requires a cluster, Secret, and revision")
	}
	expectedName := staticCredentialsSnapshotName(cluster.Name, revision)
	if snapshot.Namespace != cluster.Namespace || snapshot.Name != expectedName {
		return fmt.Errorf("snapshot identity %s/%s does not match revision-derived identity %s/%s",
			snapshot.Namespace, snapshot.Name, cluster.Namespace, expectedName)
	}
	if snapshot.Immutable == nil || !*snapshot.Immutable || !metav1.IsControlledBy(snapshot, cluster) ||
		snapshot.Annotations[annotationStaticCredentialsRevision] != revision ||
		snapshot.Labels[labelStaticCredentialsSnapshot] != annotationTrue || len(snapshot.Data) != len(descriptors) {
		return fmt.Errorf("snapshot lost its exact immutable ownership/data contract")
	}
	for logicalKey := range descriptors {
		if _, ok := snapshot.Data[logicalKey]; !ok {
			return fmt.Errorf("snapshot is missing logical key %q", logicalKey)
		}
	}
	if got := staticCredentialsRevision(snapshot.Data, descriptors, rpcSecret); got != revision {
		return fmt.Errorf("snapshot bytes or source descriptors do not match pinned revision %q", revision)
	}
	if expectedData != nil {
		if len(expectedData) != len(snapshot.Data) {
			return fmt.Errorf("snapshot data does not match resolved source data")
		}
		for key, value := range expectedData {
			if !bytes.Equal(snapshot.Data[key], value) {
				return fmt.Errorf("snapshot key %q does not match resolved source data", key)
			}
		}
	}
	return nil
}

func (r *GarageClusterReconciler) persistStaticCredentialRevision(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	revision, secretName, encodedSources string,
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
			return fmt.Errorf("garageCluster UID or generation changed while publishing its static credential revision")
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string)
		}
		if fresh.Annotations[annotationStaticCredentialsRevision] == revision &&
			fresh.Annotations[annotationStaticCredentialsSecret] == secretName &&
			fresh.Annotations[annotationStaticCredentialsSources] == encodedSources {
			updated = fresh
			return nil
		}
		fresh.Annotations[annotationStaticCredentialsRevision] = revision
		if secretName == "" {
			delete(fresh.Annotations, annotationStaticCredentialsSecret)
		} else {
			fresh.Annotations[annotationStaticCredentialsSecret] = secretName
		}
		fresh.Annotations[annotationStaticCredentialsSources] = encodedSources
		if err := r.Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting static Garage credential revision: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

// staticCredentialRotationPending is returned by publishStaticCredentialSnapshot
// when a source changed but the change cannot be adopted yet without breaking
// a running process. It is a wait, not a failure: the pinned snapshot stays in
// use (#600).
type staticCredentialRotationPending struct {
	reason  string
	message string
}

func (e *staticCredentialRotationPending) Error() string { return e.message }

func newStaticCredentialRotationPending(reason, what, pinned string, cause error) *staticCredentialRotationPending {
	message := fmt.Sprintf("%s; keeping pinned static credential snapshot %s until it is ready, then the new source value is adopted automatically", what, pinned)
	if cause != nil {
		message += ": " + cause.Error()
	}
	return &staticCredentialRotationPending{reason: reason, message: limitStatusConditionMessage(message)}
}

// ensureStaticCredentialSnapshot publishes the current static credential
// revision. A token rotation that has to wait for its table-backed bridge keeps
// the pinned snapshot and is reported in StaticCredentialsRotationPending
// instead of failing the GarageCluster.
func (r *GarageClusterReconciler) ensureStaticCredentialSnapshot(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*corev1.Secret, error) {
	snapshot, err := r.publishStaticCredentialSnapshot(ctx, cluster)
	var pending *staticCredentialRotationPending
	if stderrors.As(err, &pending) {
		r.reportStaticCredentialsRotationPending(ctx, cluster, pending)
		return snapshot, nil
	}
	if err != nil {
		return nil, err
	}
	r.reportStaticCredentialsRotationPending(ctx, cluster, nil)
	return snapshot, nil
}

// reportStaticCredentialsRotationPending writes or removes
// StaticCredentialsRotationPending, only when it changed. It is informational:
// a failed status write is logged and retried by the next reconcile.
func (r *GarageClusterReconciler) reportStaticCredentialsRotationPending(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pending *staticCredentialRotationPending,
) {
	conditionType := garagev1beta1.ConditionStaticCredentialsRotationPending
	existing := meta.FindStatusCondition(cluster.Status.Conditions, conditionType)
	var apply func()
	switch {
	case pending == nil && existing == nil:
		return
	case pending == nil:
		apply = func() { meta.RemoveStatusCondition(&cluster.Status.Conditions, conditionType) }
	default:
		condition := metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			Reason:             pending.reason,
			Message:            pending.message,
			ObservedGeneration: cluster.Generation,
		}
		if existing != nil && existing.Status == condition.Status && existing.Reason == condition.Reason &&
			existing.Message == condition.Message && existing.ObservedGeneration == condition.ObservedGeneration {
			return
		}
		apply = func() { meta.SetStatusCondition(&cluster.Status.Conditions, condition) }
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		logf.FromContext(ctx).V(1).Info("Could not update StaticCredentialsRotationPending", "error", err.Error())
		return
	}
	if pending != nil && (existing == nil || existing.Reason != pending.reason) {
		emitLayoutEvent(r.EventRecorder, cluster, corev1.EventTypeNormal, conditionType, "%s: %s", pending.reason, pending.message)
	}
}

func (r *GarageClusterReconciler) publishStaticCredentialSnapshot(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*corev1.Secret, error) {
	desiredDescriptors := staticCredentialSourceDescriptors(cluster)
	currentDescriptors, err := decodeStaticCredentialSources(cluster.Annotations[annotationStaticCredentialsSources])
	if err != nil {
		return nil, fmt.Errorf("decoding persisted static credential sources: %w", err)
	}
	currentName := currentStaticCredentialsSecretName(cluster)
	current := &corev1.Secret{}
	var currentErr error = errors.NewNotFound(corev1.Resource("secrets"), currentName)
	if currentName != "" {
		currentErr = r.Get(ctx, types.NamespacedName{Name: currentName, Namespace: cluster.Namespace}, current)
		if currentErr != nil && !errors.IsNotFound(currentErr) {
			return nil, fmt.Errorf("reading current static credential snapshot %s/%s: %w", cluster.Namespace, currentName, currentErr)
		}
	}
	rpcSecret, err := GetRPCSecret(ctx, r.Client, cluster)
	if err != nil {
		return nil, fmt.Errorf("validating static credentials against pinned RPC identity: %w", err)
	}
	currentRevision := cluster.Annotations[annotationStaticCredentialsRevision]
	currentValidated := false
	if currentErr == nil {
		if err := validateStaticCredentialSnapshot(cluster, current, currentRevision, currentDescriptors, rpcSecret, nil); err != nil {
			return nil, fmt.Errorf("current static credential snapshot %s/%s is invalid: %w", current.Namespace, current.Name, err)
		}
		currentValidated = true
	}

	data, descriptors, resolveErr := r.resolveStaticCredentials(ctx, cluster)
	if resolveErr != nil {
		// A source may disappear after publication. Continue from the immutable
		// snapshot only while the typed references still describe exactly the
		// persisted sources; a ref edit plus a missing source is not a rotation.
		if currentValidated && staticCredentialMapsEqual(desiredDescriptors, currentDescriptors) {
			return current, nil
		}
		return nil, resolveErr
	}
	revision := staticCredentialsRevision(data, descriptors, rpcSecret)
	name := ""
	if len(data) > 0 {
		name = staticCredentialsSnapshotName(cluster.Name, revision)
	}
	encodedSources, err := encodeStaticCredentialSources(descriptors)
	if err != nil {
		return nil, fmt.Errorf("encoding static credential sources: %w", err)
	}

	if currentRevision == revision && currentName == name && currentValidated {
		if len(data) == 0 {
			return nil, nil
		}
		if err := validateStaticCredentialSnapshot(cluster, current, revision, descriptors, rpcSecret, data); err != nil {
			return nil, fmt.Errorf("static credential snapshot %s/%s is invalid: %w", cluster.Namespace, name, err)
		}
		return current, nil
	}
	// If the pinned snapshot disappeared while its source simultaneously moved to
	// a new revision, no old bytes remain to compare. Only the universally
	// verified table-backed token can bridge old running processes to the new
	// startup credential. Recreating the exact same revision from its source is
	// safe and is handled by the normal create path below.
	if currentName != "" && errors.IsNotFound(currentErr) &&
		(currentRevision != revision || currentName != name) {
		ready, readyErr := r.operatorAdminTokenRotationBridgeReady(ctx, cluster)
		if readyErr != nil {
			return nil, readyErr
		}
		if !ready {
			return nil, fmt.Errorf("pinned static credential snapshot %s/%s is missing and the source resolves to a different revision; restore the snapshot or wait for a universally verified operator token before rotating", cluster.Namespace, currentName)
		}
		if wantsOperatorMetricsToken(cluster) {
			metricsReady, metricsErr := r.operatorMetricsTokenRotationBridgeReady(ctx, cluster)
			if metricsErr != nil {
				return nil, metricsErr
			}
			if !metricsReady {
				return nil, fmt.Errorf("pinned static credential snapshot %s/%s is missing and the metrics bridge is not universally ready; restore the snapshot before rotating", cluster.Namespace, currentName)
			}
		}
		if hasDesiredConsulCredentials(descriptors) && cluster.Annotations[annotationConsulRotationReady] != revision {
			return nil, fmt.Errorf("pinned static credential snapshot %s/%s is missing and Consul credentials may have changed; configure Consul to accept both revisions, then set annotation %s=%s", cluster.Namespace, currentName, annotationConsulRotationReady, revision)
		}
	}

	// On first upgrade, prove the source token is what every already-running
	// process actually accepted before switching templates from the mutable
	// source to a content-addressed Secret. This closes the projected-volume
	// versus startup-only-read race.
	if cluster.Annotations[annotationStaticCredentialsRevision] == "" && len(data[DefaultAdminTokenKey]) > 0 {
		if err := r.verifyStaticAdminTokenOnRunningPods(ctx, cluster, string(data[DefaultAdminTokenKey])); err != nil {
			return nil, fmt.Errorf("refusing first static credential snapshot: %w", err)
		}
	}

	// Rotating the local static admin token is safe only after the operator has
	// a table-backed token that remains valid on both old and new processes.
	if currentValidated && !bytes.Equal(current.Data[DefaultAdminTokenKey], data[DefaultAdminTokenKey]) {
		// The pinned snapshot is still what every running process accepts, so
		// keep reconciling with it and adopt the new value once the bridge is
		// ready instead of failing the cluster (#600).
		ready, err := r.operatorAdminTokenRotationBridgeReady(ctx, cluster)
		if err != nil || !ready {
			return current, newStaticCredentialRotationPending(
				garagev1beta1.ReasonStaticCredentialsWaitingForOperatorAdminToken,
				"static admin token source changed before the table-backed operator credential became ready on every running process",
				current.Name, err)
		}
	}
	if currentValidated && !bytes.Equal(current.Data[metricsTokenKey], data[metricsTokenKey]) && wantsOperatorMetricsToken(cluster) {
		ready, err := r.operatorMetricsTokenRotationBridgeReady(ctx, cluster)
		if err != nil || !ready {
			return current, newStaticCredentialRotationPending(
				garagev1beta1.ReasonStaticCredentialsWaitingForOperatorMetricsToken,
				"static metrics token source changed before the scoped table-backed metrics credential became ready on every managed process",
				current.Name, err)
		}
	}
	if currentValidated && hasDesiredConsulCredentials(descriptors) && consulStaticCredentialsChanged(current.Data, data) &&
		cluster.Annotations[annotationConsulRotationReady] != revision {
		return nil, fmt.Errorf("consul startup credentials changed; configure the Consul server to accept both old and new credentials during the serialized Pod rollout, then set annotation %s=%s", annotationConsulRotationReady, revision)
	}

	var snapshot *corev1.Secret
	if len(data) > 0 {
		snapshot = &corev1.Secret{}
		key := types.NamespacedName{Name: name, Namespace: cluster.Namespace}
		if err := r.Get(ctx, key, snapshot); err == nil {
			if err := validateStaticCredentialSnapshot(cluster, snapshot, revision, descriptors, rpcSecret, data); err != nil {
				return nil, fmt.Errorf("refusing colliding static credential snapshot %s: %w", key, err)
			}
		} else if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("checking static credential snapshot %s: %w", key, err)
		} else {
			snapshot = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: name, Namespace: cluster.Namespace,
					Labels: mergeLabels(r.labelsForCluster(cluster), map[string]string{
						labelStaticCredentialsSnapshot: annotationTrue,
					}),
					Annotations: map[string]string{annotationStaticCredentialsRevision: revision},
				},
				Type: corev1.SecretTypeOpaque, Immutable: ptr.To(true), Data: data,
			}
			if err := controllerutil.SetControllerReference(cluster, snapshot, r.Scheme); err != nil {
				return nil, err
			}
			if err := r.Create(ctx, snapshot); err != nil {
				return nil, fmt.Errorf("creating immutable static credential snapshot %s: %w", key, err)
			}
		}
	}
	if err := r.persistStaticCredentialRevision(ctx, cluster, revision, name, encodedSources); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (r *GarageClusterReconciler) verifyStaticAdminTokenOnRunningPods(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	token string,
) error {
	set, err := expectedOperatorAdminPodSetAllowEmpty(ctx, r.safetyReader(), cluster, true)
	if err != nil {
		return fmt.Errorf("proving the exact existing managed Pod set before sending the source token: %w", err)
	}
	probe := r.staticAdminTokenProbe
	if probe == nil {
		probe = func(probeCtx context.Context, endpoint, bearer string) error {
			_, err := garage.NewClient(endpoint, bearer).GetClusterStatus(probeCtx)
			return err
		}
	}
	for i := range set.Pods {
		pod := &set.Pods[i]
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := probe(probeCtx, adminEndpoint(pod.Status.PodIP, getAdminPort(cluster)), token)
		cancel()
		if err != nil {
			return fmt.Errorf("source token is not accepted by existing Pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func (r *GarageClusterReconciler) cleanupUnusedStaticCredentialSnapshots(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	inUse := map[string]struct{}{}
	// The reconcile object can have been replaced by a conflict-driven cached
	// status read after ensureStaticCredentialSnapshot published a new annotation.
	// Cleanup is destructive, so establish the current pin again through the
	// uncached reader and retain both views. Retaining one obsolete revision for
	// another reconcile is safe; deleting the freshly published revision is not.
	if current := currentStaticCredentialsSecretName(cluster); current != "" {
		inUse[current] = struct{}{}
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	clusterKey := client.ObjectKeyFromObject(cluster)
	if err := r.safetyReader().Get(ctx, clusterKey, freshCluster); err != nil {
		return fmt.Errorf("re-reading GarageCluster before static credential cleanup: %w", err)
	}
	if freshCluster.UID != cluster.UID {
		return fmt.Errorf("GarageCluster %s was recreated before static credential cleanup", clusterKey)
	}
	if current := currentStaticCredentialsSecretName(freshCluster); current != "" {
		inUse[current] = struct{}{}
	}

	retainPodSpecSecrets := func(spec corev1.PodSpec) {
		for i := range spec.Volumes {
			if secret := spec.Volumes[i].Secret; secret != nil && secret.SecretName != "" {
				inUse[secret.SecretName] = struct{}{}
			}
		}
		for i := range spec.ImagePullSecrets {
			if spec.ImagePullSecrets[i].Name != "" {
				inUse[spec.ImagePullSecrets[i].Name] = struct{}{}
			}
		}
		retainContainerSecrets := func(env []corev1.EnvVar, envFrom []corev1.EnvFromSource) {
			for i := range env {
				if source := env[i].ValueFrom; source != nil && source.SecretKeyRef != nil && source.SecretKeyRef.Name != "" {
					inUse[source.SecretKeyRef.Name] = struct{}{}
				}
			}
			for i := range envFrom {
				if source := envFrom[i].SecretRef; source != nil && source.Name != "" {
					inUse[source.Name] = struct{}{}
				}
			}
		}
		for i := range spec.InitContainers {
			retainContainerSecrets(spec.InitContainers[i].Env, spec.InitContainers[i].EnvFrom)
		}
		for i := range spec.Containers {
			retainContainerSecrets(spec.Containers[i].Env, spec.Containers[i].EnvFrom)
		}
		for i := range spec.EphemeralContainers {
			retainContainerSecrets(spec.EphemeralContainers[i].Env, spec.EphemeralContainers[i].EnvFrom)
		}
	}
	pods := &corev1.PodList{}
	if err := r.safetyReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return err
	}
	for i := range pods.Items {
		retainPodSpecSecrets(pods.Items[i].Spec)
	}
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.safetyReader().List(ctx, statefulSets,
		client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name},
	); err != nil {
		return err
	}
	for i := range statefulSets.Items {
		retainPodSpecSecrets(statefulSets.Items[i].Spec.Template.Spec)
	}
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.safetyReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name},
	); err != nil {
		return err
	}
	for i := range daemonSets.Items {
		retainPodSpecSecrets(daemonSets.Items[i].Spec.Template.Spec)
	}
	deployments := &appsv1.DeploymentList{}
	if err := r.safetyReader().List(ctx, deployments,
		client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name},
	); err != nil {
		return err
	}
	for i := range deployments.Items {
		retainPodSpecSecrets(deployments.Items[i].Spec.Template.Spec)
	}
	secrets := &corev1.SecretList{}
	if err := r.safetyReader().List(ctx, secrets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelStaticCredentialsSnapshot: annotationTrue,
		}),
	); err != nil {
		return err
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if _, retained := inUse[secret.Name]; retained || !metav1.IsControlledBy(secret, cluster) {
			continue
		}
		// Recheck the cross-object publication immediately before deletion. This
		// also protects HA operators if another reconciler rotates back to an
		// existing content-addressed snapshot after the initial inventory.
		latest := &garagev1beta2.GarageCluster{}
		if err := r.safetyReader().Get(ctx, clusterKey, latest); err != nil {
			return fmt.Errorf("re-reading GarageCluster before deleting static credential snapshot %s/%s: %w", secret.Namespace, secret.Name, err)
		}
		if latest.UID != cluster.UID {
			return fmt.Errorf("GarageCluster %s was recreated before deleting static credential snapshot %s/%s", clusterKey, secret.Namespace, secret.Name)
		}
		if currentStaticCredentialsSecretName(latest) == secret.Name {
			continue
		}
		uid := secret.UID
		if err := r.Delete(ctx, secret, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting unused static credential snapshot %s/%s: %w", secret.Namespace, secret.Name, err)
		}
	}
	return nil
}
