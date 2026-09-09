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
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// storageRolloutInputToken is an object-metadata acknowledgment that the
// GarageNode owner rendered an OnDelete StatefulSet from one exact parent/node
// input revision. The parent requires it before trusting the template hashes,
// so asynchronous controller ordering cannot produce a false Ready condition.
func storageRolloutInputToken(
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	podSpecHash, configHash string,
) string {
	if cluster == nil || node == nil || podSpecHash == "" || configHash == "" {
		return ""
	}
	payload := fmt.Sprintf("cluster\x00%s\x00%d\x00static\x00%s\x00%s\x00node\x00%s\x00%d\x00pod\x00%s\x00config\x00%s",
		cluster.UID,
		cluster.Generation,
		currentStaticCredentialsSecretName(cluster),
		cluster.Annotations[annotationStaticCredentialsRevision],
		node.UID,
		node.Generation,
		podSpecHash,
		configHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("sha256:%x", sum[:])
}

func (r *GarageClusterReconciler) storageRolloutPersistentVolumeClaimsForPod(
	ctx context.Context,
	pod *corev1.Pod,
) ([]garagev1beta2.StorageRolloutPersistentVolumeClaimStatus, error) {
	if pod == nil {
		return nil, fmt.Errorf("cannot capture persistent storage identity from an empty Pod")
	}
	claimNames := make(map[string]struct{})
	for i := range pod.Spec.Volumes {
		claim := pod.Spec.Volumes[i].PersistentVolumeClaim
		if claim != nil && claim.ClaimName != "" {
			claimNames[claim.ClaimName] = struct{}{}
		}
	}
	names := make([]string, 0, len(claimNames))
	for name := range claimNames {
		names = append(names, name)
	}
	sort.Strings(names)
	claims := make([]garagev1beta2.StorageRolloutPersistentVolumeClaimStatus, 0, len(names))
	for _, name := range names {
		claim := &corev1.PersistentVolumeClaim{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: pod.Namespace, Name: name,
		}, claim); err != nil {
			return nil, fmt.Errorf("reading exact PVC %s/%s mounted by Pod %s: %w", pod.Namespace, name, pod.Name, err)
		}
		if claim.UID == "" || !claim.DeletionTimestamp.IsZero() {
			return nil, fmt.Errorf("PVC %s/%s mounted by Pod %s has no durable UID or is deleting", pod.Namespace, name, pod.Name)
		}
		claims = append(claims, garagev1beta2.StorageRolloutPersistentVolumeClaimStatus{
			Name: name, UID: string(claim.UID),
		})
	}
	return claims, nil
}

func (r *GarageClusterReconciler) validateStorageRolloutPersistentVolumeClaims(
	ctx context.Context,
	namespace string,
	record nodeLocalPoolRolloutRecord,
) error {
	if record.GarageNodeName == "" {
		if len(record.PersistentVolumeClaims) != 0 {
			return fmt.Errorf("node-local-pool HostPath rollout actor unexpectedly records StatefulSet PVC identities")
		}
		return nil
	}
	for i := range record.PersistentVolumeClaims {
		expected := &record.PersistentVolumeClaims[i]
		claim := &corev1.PersistentVolumeClaim{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: namespace, Name: expected.Name,
		}, claim); err != nil {
			return fmt.Errorf("reading persisted rollout PVC %s/%s: %w", namespace, expected.Name, err)
		}
		if string(claim.UID) != expected.UID || !claim.DeletionTimestamp.IsZero() {
			return fmt.Errorf("persisted rollout PVC %s/%s was recreated or is deleting; expected UID %s, got %s", namespace, expected.Name, expected.UID, claim.UID)
		}
	}
	return nil
}

func (r *GarageClusterReconciler) requireStorageRolloutPersistentVolumeClaimProtection(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) error {
	if err := r.requireStorageRolloutPVCAdmission(record); err != nil {
		return err
	}
	if err := r.validateStorageRolloutPersistentVolumeClaims(ctx, cluster.Namespace, record); err != nil {
		return err
	}
	if len(record.PersistentVolumeClaims) == 0 {
		return nil
	}
	finalizer := storageRolloutPVCFinalizer(cluster)
	if finalizer == "" {
		return fmt.Errorf("cannot verify storage rollout PVC protection without an immutable GarageCluster UID")
	}
	for i := range record.PersistentVolumeClaims {
		expected := &record.PersistentVolumeClaims[i]
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: cluster.Namespace, Name: expected.Name}
		if err := r.nodeLocalPoolReader().Get(ctx, key, claim); err != nil {
			return fmt.Errorf("re-reading protected storage rollout PVC %s: %w", key.String(), err)
		}
		if string(claim.UID) != expected.UID || !claim.DeletionTimestamp.IsZero() ||
			!controllerutil.ContainsFinalizer(claim, finalizer) {
			return fmt.Errorf("persisted rollout PVC %s UID %s lost exact transaction protection", key.String(), expected.UID)
		}
	}
	return nil
}

func storageRolloutPVCFinalizer(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil || cluster.UID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cluster.UID))
	return nodeLocalPoolActivationLabelDomain + storageRolloutPVCFinalizerPrefix + fmt.Sprintf("%x", sum[:8])
}

func statefulSetWorkloadRecreationSafe(statefulSet *appsv1.StatefulSet) bool {
	if statefulSet == nil || len(statefulSet.Spec.VolumeClaimTemplates) == 0 ||
		statefulSet.Spec.PersistentVolumeClaimRetentionPolicy == nil {
		return true
	}
	return statefulSet.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted != appsv1.DeletePersistentVolumeClaimRetentionPolicyType
}

func (r *GarageClusterReconciler) requireStorageRolloutPVCAdmission(record nodeLocalPoolRolloutRecord) error {
	if r.ManagedPVCAdmissionDisabled && len(record.PersistentVolumeClaims) > 0 {
		return errors.NewBadRequest("PVC-backed storage rollout and recovery require enabled admission webhooks to protect exact claim identities")
	}
	return nil
}

func (r *GarageClusterReconciler) protectStorageRolloutPersistentVolumeClaims(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) error {
	if err := r.requireStorageRolloutPVCAdmission(record); err != nil {
		return err
	}
	if len(record.PersistentVolumeClaims) == 0 {
		return nil
	}
	finalizer := storageRolloutPVCFinalizer(cluster)
	if finalizer == "" {
		return fmt.Errorf("cannot protect storage rollout PVCs without an immutable GarageCluster UID")
	}
	for i := range record.PersistentVolumeClaims {
		expected := &record.PersistentVolumeClaims[i]
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: cluster.Namespace, Name: expected.Name}
		if err := r.nodeLocalPoolReader().Get(ctx, key, claim); err != nil {
			return fmt.Errorf("reading PVC %s before adding storage rollout protection: %w", key.String(), err)
		}
		if string(claim.UID) != expected.UID || !claim.DeletionTimestamp.IsZero() {
			return fmt.Errorf("PVC %s changed UID or began deletion before storage rollout protection", key.String())
		}
		if controllerutil.ContainsFinalizer(claim, finalizer) && claim.Labels[labelAppManagedBy] == operatorName {
			continue
		}
		before := claim.DeepCopy()
		// The finalizer is only enforced by the webhook on claims carrying this label.
		metav1.SetMetaDataLabel(&claim.ObjectMeta, labelAppManagedBy, operatorName)
		controllerutil.AddFinalizer(claim, finalizer)
		if err := r.Patch(ctx, claim, client.MergeFrom(before)); err != nil {
			return fmt.Errorf("adding storage rollout protection to exact PVC %s UID %s: %w", key.String(), claim.UID, err)
		}
	}
	return r.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, record)
}

func (r *GarageClusterReconciler) releaseStorageRolloutPersistentVolumeClaims(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) error {
	finalizer := storageRolloutPVCFinalizer(cluster)
	if finalizer == "" || len(record.PersistentVolumeClaims) == 0 {
		return nil
	}
	for i := range record.PersistentVolumeClaims {
		expected := &record.PersistentVolumeClaims[i]
		claim := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Namespace: cluster.Namespace, Name: expected.Name}
		if err := r.nodeLocalPoolReader().Get(ctx, key, claim); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return err
		}
		if string(claim.UID) != expected.UID || !controllerutil.ContainsFinalizer(claim, finalizer) {
			continue
		}
		before := claim.DeepCopy()
		controllerutil.RemoveFinalizer(claim, finalizer)
		if err := r.Patch(ctx, claim, client.MergeFrom(before)); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("releasing storage rollout protection from PVC %s: %w", key.String(), err)
		}
	}
	return nil
}

func (r *GarageClusterReconciler) releaseAllStorageRolloutPersistentVolumeClaims(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	finalizer := storageRolloutPVCFinalizer(cluster)
	if finalizer == "" {
		return nil
	}
	claims := &corev1.PersistentVolumeClaimList{}
	if err := r.nodeLocalPoolReader().List(ctx, claims, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing PVCs for stale storage rollout protection: %w", err)
	}
	for i := range claims.Items {
		claim := &claims.Items[i]
		if !controllerutil.ContainsFinalizer(claim, finalizer) {
			continue
		}
		before := claim.DeepCopy()
		controllerutil.RemoveFinalizer(claim, finalizer)
		if err := r.Patch(ctx, claim, client.MergeFrom(before)); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("releasing stale storage rollout protection from PVC %s/%s: %w", claim.Namespace, claim.Name, err)
		}
	}
	return nil
}

// cancelStorageRolloutForDestroy releases a persisted managed-Pod handoff when
// the owning storage cluster is being torn down with deletionPolicy: Destroy.
// Destroy intentionally discards the local store, so waiting for the old Pod's
// identity or for a replacement to become healthy would make teardown depend on
// the rollout it is supposed to remove. Drain never uses this path: its delete
// admission requires a completed drain proof and therefore cannot arrive here
// with an active storage rollout.
func (r *GarageClusterReconciler) cancelStorageRolloutForDestroy(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if cluster == nil || cluster.DeletionTimestamp.IsZero() ||
		cluster.EffectiveDeletionPolicy() != garagev1beta2.DeletionPolicyDestroy ||
		!cluster.HasStorageTier() {
		return nil
	}

	layoutOwner, err := resolveGarageLayoutOwnerForCleanup(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner: %w", err)
	}
	key := layoutOwnerKey(layoutOwner)
	coordinator := r.layoutMutationCoordinator()
	activeMarker, _ := coordinator.NodeLocalPoolRolloutSourceActive(key, cluster.UID)
	if cluster.Status.StorageRollout == nil && !nodeLocalPoolRolloutConditionActive(cluster) && !activeMarker {
		return nil
	}

	expectedUID := cluster.UID
	var updated *garagev1beta2.GarageCluster
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.DeletionTimestamp.IsZero() ||
			fresh.EffectiveDeletionPolicy() != garagev1beta2.DeletionPolicyDestroy ||
			!fresh.HasStorageTier() {
			return fmt.Errorf("GarageCluster deletion state or Destroy policy changed while canceling storage rollout")
		}
		if fresh.Status.StorageRollout == nil && !nodeLocalPoolRolloutConditionActive(fresh) {
			updated = fresh
			return nil
		}
		fresh.Status.StorageRollout = nil
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageRolloutReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRolloutWaiting,
			Message:            "managed Pod rollout canceled because deletionPolicy: Destroy owns cluster teardown",
			ObservedGeneration: fresh.Generation,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing persisted storage rollout state: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
		return fmt.Errorf("releasing storage rollout PVC protection: %w", err)
	}
	// EndNodeLocalPoolRollout is source-UID scoped, so a deleting storage owner
	// cannot clear a concurrent gateway source's marker on the same layout.
	coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
	return nil
}

// validateStorageRolloutPublication reconstructs one candidate's exact desired
// workload revision from live API state. It is called while the layout
// coordinator is held and again after the status CAS, before DELETE, closing
// the otherwise asynchronous GarageNode/parent template-publication window.
func (r *GarageClusterReconciler) validateStorageRolloutPublication(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expectedNode *garagev1beta1.GarageNode,
	nodeLocalPoolName, kubernetesNodeName string,
	workloadUID, kubernetesNodeUID types.UID,
	desiredPodSpecHash, desiredConfigHash string,
) error {
	if cluster == nil || expectedNode == nil || cluster.UID == "" || expectedNode.UID == "" ||
		workloadUID == "" || desiredPodSpecHash == "" || desiredConfigHash == "" {
		return fmt.Errorf("storage rollout publication proof is missing an exact object identity or desired hash")
	}
	node := &garagev1beta1.GarageNode{}
	if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(expectedNode), node); err != nil {
		return fmt.Errorf("re-reading GarageNode %s publication: %w", expectedNode.Name, err)
	}
	if node.UID != expectedNode.UID || node.Generation != expectedNode.Generation || !node.DeletionTimestamp.IsZero() ||
		node.Spec.ClusterRef.Name != cluster.Name ||
		(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) {
		return fmt.Errorf("garageNode %s identity, generation, deletion state, or parent changed after rollout enumeration", expectedNode.Name)
	}

	var podSpec corev1.PodSpec
	var configBaseName string
	var configOwner client.Object
	var desiredPool *garagev1beta2.NodeLocalPoolSpec
	if nodeLocalPoolName == "" {
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: node.Namespace, Name: node.Name,
		}, statefulSet); err != nil {
			return fmt.Errorf("re-reading StatefulSet %s publication: %w", node.Name, err)
		}
		if statefulSet.UID != workloadUID || !statefulSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(statefulSet, node) ||
			statefulSet.Spec.UpdateStrategy.Type != appsv1.OnDeleteStatefulSetStrategyType {
			return fmt.Errorf("StatefulSet %s UID, owner, deletion state, or OnDelete strategy changed after rollout enumeration", statefulSet.Name)
		}
		if statefulSet.Spec.Template.Annotations[annotationPodSpecHash] != desiredPodSpecHash ||
			statefulSet.Spec.Template.Annotations[annotationConfigHash] != desiredConfigHash {
			return fmt.Errorf("StatefulSet %s desired template hashes changed after rollout enumeration", statefulSet.Name)
		}
		expectedInput := storageRolloutInputToken(cluster, node, desiredPodSpecHash, desiredConfigHash)
		if expectedInput == "" || statefulSet.Annotations[annotationStorageRolloutInput] != expectedInput {
			return fmt.Errorf("StatefulSet %s no longer acknowledges the exact GarageCluster/GarageNode generation and desired hashes", statefulSet.Name)
		}
		podSpec = statefulSet.Spec.Template.Spec
		configBaseName = cluster.Name + "-config"
		configOwner = cluster
		if nodeHasConfigOverrides(node) {
			configBaseName = garageNodeConfigBaseName(cluster, node)
			configOwner = node
		}
	} else {
		if !isNodeLocalPoolBacked(node) || node.Spec.NodeLocalPoolName != nodeLocalPoolName ||
			node.Spec.KubernetesNodeName != kubernetesNodeName || kubernetesNodeUID == "" {
			return fmt.Errorf("garageNode %s no longer describes exact pool %q Kubernetes Node %q", node.Name, nodeLocalPoolName, kubernetesNodeName)
		}
		kubernetesNode := &corev1.Node{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: kubernetesNodeName}, kubernetesNode); err != nil {
			return fmt.Errorf("re-reading Kubernetes Node %s publication: %w", kubernetesNodeName, err)
		}
		daemonSet := &appsv1.DaemonSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, nodeLocalPoolName),
		}, daemonSet); err != nil {
			return fmt.Errorf("re-reading DaemonSet for pool %s publication: %w", nodeLocalPoolName, err)
		}
		activationLabel := nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName)
		activationValue := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
		if kubernetesNode.UID != kubernetesNodeUID ||
			!nodeLocalPoolActivationValueIsActive(activationValue) ||
			kubernetesNode.Labels[activationLabel] != activationValue {
			return fmt.Errorf("kubernetes Node %s UID or pool activation changed after rollout enumeration", kubernetesNodeName)
		}
		if daemonSet.UID != workloadUID || !daemonSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(daemonSet, cluster) ||
			daemonSet.Spec.UpdateStrategy.Type != appsv1.OnDeleteDaemonSetStrategyType ||
			daemonSet.Annotations[annotationRolloutAdoptionFence] != "" ||
			daemonSet.Annotations[annotationNodeLocalPoolActivationLabel] != activationLabel ||
			daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] != activationValue {
			return fmt.Errorf("DaemonSet %s UID, owner, deletion state, OnDelete strategy, or activation fence changed after rollout enumeration", daemonSet.Name)
		}
		if daemonSet.Spec.Template.Annotations[annotationPodSpecHash] != desiredPodSpecHash ||
			daemonSet.Spec.Template.Annotations[annotationConfigHash] != desiredConfigHash {
			return fmt.Errorf("DaemonSet %s desired template hashes changed after rollout enumeration", daemonSet.Name)
		}
		podSpec = daemonSet.Spec.Template.Spec
		if cluster.Spec.Storage != nil {
			for i := range cluster.Spec.Storage.NodeLocalPools {
				if cluster.Spec.Storage.NodeLocalPools[i].Name == nodeLocalPoolName {
					desiredPool = &cluster.Spec.Storage.NodeLocalPools[i]
					break
				}
			}
		}
		if desiredPool == nil {
			return fmt.Errorf("node-local pool %q disappeared before its rollout publication could be verified", nodeLocalPoolName)
		}
		if err := validateNodeLocalPoolWorkloadDiskLayoutPublication(daemonSet, desiredPool); err != nil {
			return fmt.Errorf("validating DaemonSet %s disk publication: %w", daemonSet.Name, err)
		}
		configBaseName = storageDaemonSetConfigMapName(cluster, nodeLocalPoolName)
		configOwner = cluster
	}
	return r.validateMountedGarageConfigPublication(
		ctx, cluster, configOwner, podSpec, configBaseName, desiredPool, desiredConfigHash,
	)
}

// validateMountedGarageConfigPublication proves that a workload template mounts
// the exact immutable, non-deleting ConfigMap-or-Secret revision represented by
// its desired config annotation. It is shared by ordinary rollout, recovery
// adoption, and unfencing so no recovery-only path can trust hash annotations
// without proving their underlying object.
func (r *GarageClusterReconciler) validateMountedGarageConfigPublication(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	owner client.Object,
	podSpec corev1.PodSpec,
	configBaseName string,
	pool *garagev1beta2.NodeLocalPoolSpec,
	desiredConfigHash string,
) error {
	if cluster == nil || owner == nil || configBaseName == "" || desiredConfigHash == "" {
		return fmt.Errorf("mounted Garage config publication proof is missing an exact owner, base name, or desired revision")
	}
	configName, secretBacked, err := mountedGarageConfigResource(podSpec)
	if err != nil {
		return err
	}
	if secretBacked != garageConfigUsesSecret(cluster) {
		return fmt.Errorf("workload mounts Garage config resource %q with the wrong kind", configName)
	}
	body, configObject, err := readGarageConfigResource(
		ctx, r.nodeLocalPoolReader(), cluster.Namespace, configName, secretBacked,
	)
	if err != nil {
		return fmt.Errorf("re-reading mounted Garage config resource %s publication: %w", configName, err)
	}
	if !configObject.GetDeletionTimestamp().IsZero() {
		return fmt.Errorf("mounted Garage config resource %s is deleting", configName)
	}
	if !garageConfigResourceIsImmutable(configObject) {
		return fmt.Errorf("mounted Garage config resource %s is mutable", configName)
	}
	if !metav1.IsControlledBy(configObject, owner) {
		return fmt.Errorf("mounted Garage config resource %s is not controlled by exact owner %s/%s UID %s", configName, owner.GetNamespace(), owner.GetName(), owner.GetUID())
	}
	if configObject.GetAnnotations()[annotationGarageConfigBaseName] != configBaseName {
		return fmt.Errorf("mounted Garage config resource %s does not record exact base name %s", configName, configBaseName)
	}
	liveConfigRevision, err := garageConfigRevision(ctx, r.nodeLocalPoolReader(), cluster, body)
	if err != nil {
		return fmt.Errorf("deriving mounted Garage config resource %s revision: %w", configName, err)
	}
	expectedName := garageConfigRevisionName(configBaseName, liveConfigRevision)
	liveConfigHash := liveConfigRevision
	if pool != nil {
		expectedName = storageDaemonSetConfigResourceName(cluster, pool, desiredConfigHash)
		expectedDiskLayout, err := marshalStorageDiskLayout(storageDiskLayoutForPool(pool))
		if err != nil {
			return err
		}
		if configObject.GetAnnotations()[annotationStorageDiskLayout] != expectedDiskLayout {
			return fmt.Errorf("mounted Garage config resource %s does not record the exact node-local-pool disk layout", configName)
		}
		if configObject.GetLabels()[labelCluster] != cluster.Name || configObject.GetLabels()[labelNodeLocalPool] != pool.Name {
			return fmt.Errorf("mounted Garage config resource %s does not carry exact cluster/pool identity labels", configName)
		}
	} else {
		liveConfigHash, err = garageConfigAnnotationRevision(ctx, r.nodeLocalPoolReader(), cluster, body)
		if err != nil {
			return fmt.Errorf("deriving mounted Garage config resource %s annotation revision: %w", configName, err)
		}
	}
	if configName != expectedName {
		return fmt.Errorf("workload mounts Garage config resource %s, expected exact content-addressed revision %s", configName, expectedName)
	}
	if liveConfigHash != desiredConfigHash {
		return fmt.Errorf("mounted Garage config resource %s content hash %s does not match desired revision %s", configName, liveConfigHash, desiredConfigHash)
	}
	if secretBacked && configObject.GetAnnotations()[annotationSensitiveGarageConfig] != annotationTrue {
		return fmt.Errorf("mounted sensitive Garage config Secret %s lacks its managed sensitivity marker", configName)
	}
	return nil
}

func validateNodeLocalPoolWorkloadDiskLayoutPublication(
	daemonSet *appsv1.DaemonSet,
	pool *garagev1beta2.NodeLocalPoolSpec,
) error {
	if daemonSet == nil || pool == nil {
		return fmt.Errorf("node-local-pool workload disk publication requires an exact DaemonSet and pool")
	}
	expected := storageDiskLayoutForPool(pool)
	expectedAnnotation, err := marshalStorageDiskLayout(expected)
	if err != nil {
		return err
	}
	if daemonSet.Annotations[annotationStorageDiskLayout] != expectedAnnotation {
		return fmt.Errorf("annotation %q does not match the exact desired node-local-pool disk layout", annotationStorageDiskLayout)
	}
	actual, err := storageDiskLayoutFromDaemonSet(daemonSet)
	if err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(actual, expected) {
		return fmt.Errorf("DaemonSet HostPath mounts do not match the exact desired node-local-pool disk layout")
	}
	return nil
}

func nodeLocalPoolSpecByName(
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
) *garagev1beta2.NodeLocalPoolSpec {
	if cluster == nil || cluster.Spec.Storage == nil {
		return nil
	}
	for i := range cluster.Spec.Storage.NodeLocalPools {
		if cluster.Spec.Storage.NodeLocalPools[i].Name == nodeLocalPoolName {
			return &cluster.Spec.Storage.NodeLocalPools[i]
		}
	}
	return nil
}

func (r *GarageClusterReconciler) validateStorageRolloutTemplateConfigPublication(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	nodeLocalPoolName string,
	podSpec corev1.PodSpec,
	desiredConfigHash string,
) error {
	if node == nil {
		return fmt.Errorf("storage rollout config publication has no exact GarageNode owner")
	}
	if nodeLocalPoolName != "" {
		pool := nodeLocalPoolSpecByName(cluster, nodeLocalPoolName)
		if pool == nil {
			return fmt.Errorf("node-local pool %q disappeared before its config publication could be verified", nodeLocalPoolName)
		}
		return r.validateMountedGarageConfigPublication(
			ctx, cluster, cluster, podSpec,
			storageDaemonSetConfigMapName(cluster, nodeLocalPoolName), pool, desiredConfigHash,
		)
	}
	owner := client.Object(cluster)
	baseName := cluster.Name + "-config"
	if nodeHasConfigOverrides(node) {
		owner = node
		baseName = garageNodeConfigBaseName(cluster, node)
	}
	return r.validateMountedGarageConfigPublication(
		ctx, cluster, owner, podSpec, baseName, nil, desiredConfigHash,
	)
}

// nodeLocalPoolGarageNodeName returns a stable name keyed by cluster, pool, and
// Kubernetes Node. The pool infix keeps multiple node-local pools disjoint without
// exposing their current workload implementation.
func nodeLocalPoolGarageNodeName(clusterName, nodeLocalPoolName, k8sNodeName string) string {
	return boundedGarageNodeName(clusterName + "-node-local-" + nodeLocalPoolName + "-" + k8sNodeName)
}

func nodeLocalPoolKey(nodeLocalPoolName, nodeName string) string {
	return nodeLocalPoolName + "\x00" + nodeName
}

// storageRolloutInputs reconstructs the node-local-pool half of the generic
// cluster-wide rollout from live ownership. StatefulSet-backed GarageNodes are
// discovered by reconcileNodeLocalPoolRollout itself. Keeping this read-only input
// builder separate from pool membership reconciliation lets the same sequencer
// run for PVC-only, Manual/SMB-only, node-local-pool-only, and mixed clusters.
func (r *GarageClusterReconciler) storageRolloutInputs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]*nodeLocalPoolState, map[string]*garagev1beta1.GarageNode, error) {
	existing, collisions, err := r.listNodeLocalPoolStorageNodes(ctx, cluster)
	if err != nil {
		return nil, nil, err
	}
	if len(collisions) > 0 {
		return nil, nil, stderrors.New(summarizeNodeLocalPoolItems(
			"duplicate durable Garage identities block storage rollout", collisions,
		))
	}

	states := make(map[string]*nodeLocalPoolState)
	daemonSetUIDs := make(map[string]types.UID)
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, nil, fmt.Errorf("listing node-local-pool workloads for storage rollout: %w", err)
	}
	for i := range daemonSets.Items {
		daemonSet := &daemonSets.Items[i]
		nodeLocalPoolName := daemonSet.Labels[labelNodeLocalPool]
		if nodeLocalPoolName == "" || daemonSet.Name != storageDaemonSetName(cluster, nodeLocalPoolName) ||
			!metav1.IsControlledBy(daemonSet, cluster) {
			continue
		}
		states[nodeLocalPoolName] = &nodeLocalPoolState{
			pool:               nodeLocalPoolSpecByName(cluster, nodeLocalPoolName),
			activationLabel:    nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName),
			activationValue:    nodeLocalPoolActivationValueForDaemonSet(daemonSet),
			configHash:         daemonSet.Spec.Template.Annotations[annotationConfigHash],
			desiredPodSpecHash: daemonSet.Spec.Template.Annotations[annotationPodSpecHash],
			workloadUID:        daemonSet.UID,
			desiredNodes:       make(map[string]*corev1.Node),
			activePods:         make(map[string]*corev1.Pod),
			terminatingPods:    make(map[string]*corev1.Pod),
		}
		daemonSetUIDs[nodeLocalPoolName] = daemonSet.UID
	}

	existingByPair := make(map[string]*garagev1beta1.GarageNode, len(existing))
	for _, node := range existing {
		key := nodeLocalPoolKey(node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)
		if previous := existingByPair[key]; previous != nil && previous.Name != node.Name {
			return nil, nil, fmt.Errorf(
				"multiple node-local-pool GarageNodes claim pool %q on Kubernetes Node %q: %s and %s",
				node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName, previous.Name, node.Name,
			)
		}
		existingByPair[key] = node
		if state := states[node.Spec.NodeLocalPoolName]; state != nil {
			kubernetesNode := &corev1.Node{}
			if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: node.Spec.KubernetesNodeName}, kubernetesNode); err != nil {
				if !errors.IsNotFound(err) {
					return nil, nil, fmt.Errorf("reading exact Kubernetes Node %q for storage rollout: %w", node.Spec.KubernetesNodeName, err)
				}
				// Keep the member visible to the sequencer so it fails closed with
				// an explicit lost-actor wait instead of silently omitting a durable
				// HostPath identity whose Kubernetes Node disappeared.
				kubernetesNode.Name = node.Spec.KubernetesNodeName
			}
			state.desiredNodes[node.Spec.KubernetesNodeName] = kubernetesNode
		}
	}

	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, nil, fmt.Errorf("listing node-local-pool pods for storage rollout: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		nodeLocalPoolName := pod.Labels[labelNodeLocalPool]
		state := states[nodeLocalPoolName]
		if state == nil || pod.Spec.NodeName == "" ||
			!isStorageDaemonSetPodForPoolUID(cluster, nodeLocalPoolName, daemonSetUIDs[nodeLocalPoolName], pod) {
			continue
		}
		if !pod.DeletionTimestamp.IsZero() {
			state.terminatingPods[pod.Spec.NodeName] = pod
			continue
		}
		if current := state.activePods[pod.Spec.NodeName]; current == nil ||
			current.CreationTimestamp.Before(&pod.CreationTimestamp) {
			state.activePods[pod.Spec.NodeName] = pod
		}
	}
	return states, existingByPair, nil
}

func (r *GarageClusterReconciler) reconcileStorageRollout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, string, error) {
	if condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady); condition != nil &&
		condition.Status != metav1.ConditionTrue && condition.Reason != garagev1beta1.ReasonNodeLocalPoolWaitingForDrainSafety {
		return false, "waiting for node-local-pool membership to converge before replacing any managed Garage pod: " + condition.Message, nil
	}
	states, existingByPair, err := r.storageRolloutInputs(ctx, cluster)
	if err != nil {
		return false, "", err
	}
	return r.reconcileNodeLocalPoolRollout(ctx, cluster, states, existingByPair)
}

func (r *GarageClusterReconciler) recoverStorageRollout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return true, fmt.Errorf("resolving canonical Garage layout owner for storage rollout recovery: %w", err)
	}
	if !nodeLocalPoolRolloutConditionActive(cluster) {
		coordinator := r.layoutMutationCoordinator()
		key := layoutOwnerKey(layoutOwner)
		owned, confirmed := coordinator.NodeLocalPoolRolloutSourceActive(key, cluster.UID)
		if owned && confirmed {
			// Status was durably cleared but the process crashed before End. Source
			// identity makes this tail cleanup safe even on a shared canonical owner.
			if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
				return true, err
			}
			coordinator.EndNodeLocalPoolRollout(key, cluster.UID)
		} else if owned {
			// Another worker has begun the marker->status publication head. Do not
			// mistake its not-yet-visible actor for a completed transaction.
			return true, nil
		}
		// A gateway-only cluster can share this key with a referenced storage
		// cluster. A different source's transaction must remain untouched.
		if coordinator.NodeLocalPoolRolloutActive(key) {
			return true, nil
		}
		if err := r.releaseAllStorageRolloutPersistentVolumeClaims(ctx, cluster); err != nil {
			return true, err
		}
		return false, nil
	}
	existing, collisions, err := r.listNodeLocalPoolStorageNodes(ctx, cluster)
	if err != nil {
		return true, err
	}
	if len(collisions) > 0 {
		return true, stderrors.New(summarizeNodeLocalPoolItems(
			"duplicate durable Garage identities block storage rollout recovery", collisions,
		))
	}
	return r.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
}

type storageRolloutActorSnapshot struct {
	node               *garagev1beta1.GarageNode
	currentPod         *corev1.Pod
	kubernetesNode     *corev1.Node
	desiredPodSpecHash string
	desiredConfigHash  string
	garageNodeUID      types.UID
	workloadUID        types.UID
	kubernetesNodeUID  types.UID
	activationLabel    string
	activationValue    string
}

// rollForwardStorageRollout republishes only the exact persisted actor's
// workload/config template after an operator supplies a new recovery nonce.
// A recovery-safe GarageCluster or exact GarageNode spec generation is itself
// an atomic correction request. The GarageCluster nonce is reserved for
// retrying an unchanged desired revision (for example after fixing a referenced
// Secret). Before DELETE, status records the failed replacement Pod name+UID,
// so a crash can only re-drive that one request and never delete its successor.
func (r *GarageClusterReconciler) rollForwardStorageRollout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if cluster != nil && cluster.Status.StorageRollout != nil &&
		cluster.Status.StorageRollout.NodeLocalPoolName != "" {
		if err := r.assertNodeLocalPoolPrerequisites(ctx, cluster); err != nil {
			return err
		}
	}
	record, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil || record == nil {
		return err
	}
	if err := r.requireStorageRolloutPVCAdmission(*record); err != nil {
		return err
	}
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner for rollout recovery: %w", err)
	}
	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(r.layoutMutationCoordinator(), layoutOwner)
	if err != nil {
		return err
	}
	defer release()

	if record.RecoveryPodUID != "" {
		pending, err := r.redriveStorageRolloutRecoveryPod(ctx, cluster, *record)
		if err != nil {
			return err
		}
		if pending {
			return nil
		}
		// Absence (or name reuse with a different UID) completes only the
		// persisted retry-delete phase. Stop here so a concurrently submitted
		// nonce is evaluated from a fresh parent/actor snapshot next reconcile.
		return r.clearStorageRolloutRecoveryPod(ctx, cluster, *record)
	}
	adopted, err := r.ensureStorageRolloutWorkload(ctx, cluster, *record)
	if err != nil {
		return err
	}
	if adopted {
		return nil
	}
	if record.WorkloadFenced {
		return r.unfenceAdoptedStorageRolloutWorkload(ctx, cluster, *record)
	}
	snapshot, err := r.readStorageRolloutActorSnapshot(ctx, cluster, *record)
	if err != nil {
		return err
	}
	if pod := snapshot.currentPod; pod != nil && pod.DeletionTimestamp.IsZero() &&
		string(pod.UID) != record.PreviousPodUID &&
		(pod.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
			pod.Annotations[annotationConfigHash] != record.DesiredConfigHash) {
		// A workload controller can create the previous desired revision between
		// publishing a corrected template and the no-Pod snapshot used by that
		// correction. Never consume the request and then wait forever on that
		// incarnation: first persist its exact name+UID, then delete only it.
		next, err := r.selectStorageRolloutRecoveryPod(ctx, cluster, *record, pod)
		if err != nil {
			return err
		}
		_, err = r.redriveStorageRolloutRecoveryPod(ctx, cluster, next)
		return err
	}

	clusterRequest := cluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout]
	clusterSpecRequested := cluster.Generation != record.ClusterGeneration
	nodeSpecRequested := snapshot.node.Generation != record.GarageNodeGeneration
	retryRequested := clusterRequest != "" && clusterRequest != record.RecoveryRequest
	if !clusterSpecRequested && !nodeSpecRequested && !retryRequested {
		return nil
	}

	_, poolConfigHashes, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return fmt.Errorf("publishing corrected Garage configuration: %w", err)
	}

	if record.NodeLocalPoolName != "" {
		var pool *garagev1beta2.NodeLocalPoolSpec
		if cluster.Spec.Storage != nil {
			for i := range cluster.Spec.Storage.NodeLocalPools {
				if cluster.Spec.Storage.NodeLocalPools[i].Name == record.NodeLocalPoolName {
					pool = &cluster.Spec.Storage.NodeLocalPools[i]
					break
				}
			}
		}
		if pool == nil {
			return fmt.Errorf("persisted rollout pool %q is no longer declared; membership changes are not a rollout-recovery operation", record.NodeLocalPoolName)
		}
		if err := r.reconcileNodeLocalPoolDaemonSet(
			ctx, cluster, pool, nodeLocalPoolActivationLabel(cluster, pool.Name), poolConfigHashes[pool.Name],
		); err != nil {
			return fmt.Errorf("publishing corrected node-local-pool template %q: %w", pool.Name, err)
		}
	} else {
		node := snapshot.node.DeepCopy()
		// Auto-owned nodes persist inherited environment in their GarageNode
		// spec. Propagate it only for a cluster-sourced correction; Manual nodes
		// retain their exact, atomically patched overrides.
		if clusterSpecRequested && metav1.IsControlledBy(node, cluster) {
			var desiredEnv []corev1.EnvVar
			var desiredEnvFrom []corev1.EnvFromSource
			if node.Spec.Gateway && cluster.Spec.Gateway != nil {
				desiredEnv = cluster.Spec.Gateway.Env
				desiredEnvFrom = cluster.Spec.Gateway.EnvFrom
			} else if cluster.Spec.Storage != nil {
				desiredEnv = cluster.Spec.Storage.Env
				desiredEnvFrom = cluster.Spec.Storage.EnvFrom
			}
			if !equality.Semantic.DeepEqual(node.Spec.Env, desiredEnv) ||
				!equality.Semantic.DeepEqual(node.Spec.EnvFrom, desiredEnvFrom) {
				node.Spec.Env = append([]corev1.EnvVar(nil), desiredEnv...)
				node.Spec.EnvFrom = append([]corev1.EnvFromSource(nil), desiredEnvFrom...)
				if err := r.Update(ctx, node); err != nil {
					return fmt.Errorf("publishing corrected inherited environment to GarageNode %q: %w", node.Name, err)
				}
				if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), node); err != nil {
					return fmt.Errorf("re-reading corrected GarageNode %q: %w", node.Name, err)
				}
			}
		}
		nodeReconciler := &GarageNodeReconciler{
			Client: r.Client, APIReader: r.APIReader, Scheme: r.Scheme,
			ClusterDomain: r.ClusterDomain, DefaultImage: r.DefaultImage,
			ManagedPVCAdmissionDisabled: r.ManagedPVCAdmissionDisabled,
			ClusterScoped:               r.ClusterScoped, LayoutMutations: r.LayoutMutations,
		}
		if nodeHasConfigOverrides(node) {
			if err := nodeReconciler.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
				return fmt.Errorf("publishing corrected GarageNode config %q: %w", node.Name, err)
			}
		}
		if err := nodeReconciler.reconcileStatefulSet(ctx, node, cluster); err != nil {
			return fmt.Errorf("publishing corrected GarageNode workload %q: %w", node.Name, err)
		}
	}

	snapshot, err = r.readStorageRolloutActorSnapshot(ctx, cluster, *record)
	if err != nil {
		return fmt.Errorf("re-reading corrected storage rollout actor: %w", err)
	}
	next := *record
	next.ClusterGeneration = cluster.Generation
	next.GarageNodeGeneration = snapshot.node.Generation
	next.DesiredPodSpecHash = snapshot.desiredPodSpecHash
	next.DesiredConfigHash = snapshot.desiredConfigHash
	if retryRequested {
		next.RecoveryRequest = clusterRequest
	}
	next.RecoveryPodName = ""
	next.RecoveryPodUID = ""
	var staleReplacement *corev1.Pod
	if pod := snapshot.currentPod; pod != nil && !pod.DeletionTimestamp.IsZero() {
		// A controller/involuntary replacement is already in flight. The revised
		// desired template is durable; wait for its successor without selecting a
		// second Pod for deletion.
	} else if pod := snapshot.currentPod; pod != nil && string(pod.UID) != record.PreviousPodUID &&
		(pod.Annotations[annotationPodSpecHash] != next.DesiredPodSpecHash ||
			pod.Annotations[annotationConfigHash] != next.DesiredConfigHash) {
		staleReplacement = pod
	}
	if next.DesiredPodSpecHash == "" {
		return fmt.Errorf("corrected rollout actor has no desired pod-spec hash")
	}
	if err := r.advanceStorageRolloutRecord(
		ctx, cluster, *record, next, clusterRequest,
	); err != nil {
		return err
	}
	if staleReplacement == nil {
		return nil
	}
	selected, err := r.selectStorageRolloutRecoveryPod(ctx, cluster, next, staleReplacement)
	if err != nil {
		return err
	}
	_, err = r.redriveStorageRolloutRecoveryPod(ctx, cluster, selected)
	return err
}

// ensureStorageRolloutWorkload recovers only a deleted workload-controller
// incarnation. GarageNode and Kubernetes Node UIDs remain immutable fail-closed
// identity boundaries. The replacement controller is created unable to start a
// Pod, then its UID and desired hashes are CAS-adopted before a later reconcile
// removes the fence.
func (r *GarageClusterReconciler) ensureStorageRolloutWorkload(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) (bool, error) {
	if err := r.requireStorageRolloutPVCAdmission(record); err != nil {
		return false, err
	}
	node, kubernetesNode, err := r.readStorageRolloutActorIdentity(ctx, cluster, record)
	if err != nil {
		return false, err
	}
	if record.GarageNodeName != "" {
		statefulSet := &appsv1.StatefulSet{}
		err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, statefulSet)
		if err == nil {
			if string(statefulSet.UID) == record.WorkloadUID {
				if !statefulSet.DeletionTimestamp.IsZero() {
					return true, nil
				}
				return false, nil
			}
			if !statefulSet.DeletionTimestamp.IsZero() {
				return true, nil
			}
			if !metav1.IsControlledBy(statefulSet, node) || statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 0 {
				return false, fmt.Errorf("same-name StatefulSet %s replaced persisted workload UID %s without the rollout adoption fence", statefulSet.Name, record.WorkloadUID)
			}
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("checking persisted StatefulSet rollout workload: %w", err)
		}
		if !record.StatefulSetWorkloadRecreationSafe {
			return false, fmt.Errorf("refusing to recreate missing StatefulSet %s because its recorded whenDeleted PVC retention policy was Delete; restore the exact controller and claims under supervision", record.GarageNodeName)
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
		}, pod); err == nil {
			return false, fmt.Errorf("waiting for old StatefulSet actor Pod %s UID %s to disappear before recreating its controller", pod.Name, pod.UID)
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("checking for old StatefulSet actor Pod: %w", err)
		}
	} else {
		daemonSet := &appsv1.DaemonSet{}
		key := types.NamespacedName{Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, record.NodeLocalPoolName)}
		err := r.nodeLocalPoolReader().Get(ctx, key, daemonSet)
		if err == nil {
			if string(daemonSet.UID) == record.WorkloadUID {
				if !daemonSet.DeletionTimestamp.IsZero() {
					return true, nil
				}
				return false, nil
			}
			if !daemonSet.DeletionTimestamp.IsZero() {
				return true, nil
			}
			if !metav1.IsControlledBy(daemonSet, cluster) || daemonSet.Annotations[annotationRolloutAdoptionFence] != annotationTrue {
				return false, fmt.Errorf("same-name DaemonSet %s replaced persisted workload UID %s without the rollout adoption fence", daemonSet.Name, record.WorkloadUID)
			}
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("checking persisted node-local-pool DaemonSet rollout workload: %w", err)
		}
		if err := r.fenceNodeLocalPoolActivationNodes(ctx, cluster, record.NodeLocalPoolName, nodeLocalPoolActivationQuarantineValue); err != nil {
			return false, err
		}
		pending, err := r.waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear(
			ctx, cluster, record.NodeLocalPoolName,
			append(append([]string(nil), record.RetiredWorkloadUIDs...), record.WorkloadUID),
			"",
		)
		if err != nil || pending {
			return pending, err
		}
	}

	nextRetiredWorkloadUIDs := appendUniqueWorkloadUID(record.RetiredWorkloadUIDs, record.WorkloadUID)
	if len(nextRetiredWorkloadUIDs) > maximumStorageRolloutRetiredWorkloadUIDs {
		return false, fmt.Errorf(
			"refusing to add workload UID %s to status.storageRollout.retiredWorkloadUids: the supported maximum of %d excluded controller incarnations is already retained; the transaction remains intact for supervised recovery and no replacement workload was created or adopted",
			record.WorkloadUID, maximumStorageRolloutRetiredWorkloadUIDs,
		)
	}

	_, poolConfigHashes, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("publishing configuration before fenced workload recovery: %w", err)
	}
	if record.GarageNodeName != "" {
		nodeReconciler := &GarageNodeReconciler{
			Client: r.Client, APIReader: r.APIReader, Scheme: r.Scheme,
			ClusterDomain: r.ClusterDomain, DefaultImage: r.DefaultImage,
			ManagedPVCAdmissionDisabled: r.ManagedPVCAdmissionDisabled,
			ClusterScoped:               r.ClusterScoped, LayoutMutations: r.LayoutMutations,
		}
		if nodeHasConfigOverrides(node) {
			if err := nodeReconciler.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
				return false, fmt.Errorf("publishing GarageNode config before fenced workload recovery: %w", err)
			}
		}
		if err := nodeReconciler.reconcileStatefulSetWithRecoveryFence(ctx, node, cluster, true); err != nil {
			return false, fmt.Errorf("creating fenced replacement StatefulSet: %w", err)
		}
	} else {
		var pool *garagev1beta2.NodeLocalPoolSpec
		if cluster.Spec.Storage != nil {
			for i := range cluster.Spec.Storage.NodeLocalPools {
				if cluster.Spec.Storage.NodeLocalPools[i].Name == record.NodeLocalPoolName {
					pool = &cluster.Spec.Storage.NodeLocalPools[i]
					break
				}
			}
		}
		if pool == nil {
			return false, fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
		}
		if kubernetesNode == nil {
			return false, fmt.Errorf("persisted rollout pool %q has no exact Kubernetes Node actor", record.NodeLocalPoolName)
		}
		if err := r.reconcileNodeLocalPoolDaemonSetWithRecoveryFence(
			ctx, cluster, pool, nodeLocalPoolActivationLabel(cluster, pool.Name), poolConfigHashes[pool.Name], true,
		); err != nil {
			return false, fmt.Errorf("creating fenced replacement DaemonSet: %w", err)
		}
	}

	// A prior manager may have created the fenced controller and crashed before
	// the adoption CAS. Re-read and refresh that exact no-Pod object above, then
	// adopt it through the same path as a fresh create.
	replacement, err := r.readFencedStorageRolloutWorkload(ctx, cluster, record, node)
	if err != nil {
		return false, err
	}
	next := record
	next.RetiredWorkloadUIDs = nextRetiredWorkloadUIDs
	next.WorkloadUID = string(replacement.uid)
	next.WorkloadFenced = true
	next.ClusterGeneration = cluster.Generation
	next.GarageNodeGeneration = node.Generation
	next.DesiredPodSpecHash = replacement.podSpecHash
	next.DesiredConfigHash = replacement.configHash
	next.RecoveryRequest = cluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout]
	next.RecoveryPodName = ""
	next.RecoveryPodUID = ""
	if err := r.adoptStorageRolloutWorkload(ctx, cluster, record, next); err != nil {
		return false, err
	}
	return true, nil
}

type fencedStorageRolloutWorkload struct {
	uid         types.UID
	podSpecHash string
	configHash  string
}

func appendUniqueWorkloadUID(existing []string, uid string) []string {
	result := append([]string(nil), existing...)
	if uid == "" {
		return result
	}
	for _, current := range result {
		if current == uid {
			return result
		}
	}
	return append(result, uid)
}

// fenceNodeLocalPoolActivationNodes changes every existing activation for one
// pool to a value no ordinary DaemonSet incarnation uses. Kubernetes evaluates
// Pod node selectors at scheduling time, so even a late Pod create from a
// deleted controller remains unschedulable after this API-persisted fence.
func (r *GarageClusterReconciler) fenceNodeLocalPoolActivationNodes(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName, value string,
) error {
	activationLabel := nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName)
	nodes := &corev1.NodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes); err != nil {
		return fmt.Errorf("listing Kubernetes Nodes before fencing node-local-pool workload adoption: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if _, activated := node.Labels[activationLabel]; !activated || node.Labels[activationLabel] == value {
			continue
		}
		before := node.DeepCopy()
		node.Labels[activationLabel] = value
		if err := r.Patch(ctx, node, client.MergeFrom(before)); err != nil {
			return fmt.Errorf("fencing node-local-pool activation on Kubernetes Node %q: %w", node.Name, err)
		}
	}
	return nil
}

// waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear validates every remaining
// pool Pod against exact workload-controller UIDs and then waits without
// deleting it. A DaemonSet is one controller for the whole pool: deleting its
// surviving Pods during controller-incarnation recovery would turn an
// out-of-band DaemonSet deletion into an operator-caused pool-wide outage.
// Kubernetes garbage collection (or an explicitly supervised administrator)
// must remove retired Pods before the replacement controller can be enabled.
func (r *GarageClusterReconciler) waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
	workloadUIDs []string,
	allowedRunningUID string,
) (bool, error) {
	allowed := make(map[types.UID]struct{}, len(workloadUIDs))
	for _, uid := range workloadUIDs {
		if uid != "" {
			allowed[types.UID(uid)] = struct{}{}
		}
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods, client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName,
		})); err != nil {
		return true, fmt.Errorf("listing fenced node-local-pool Pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return false, nil
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	retiredPending := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != daemonSetKind {
			return true, fmt.Errorf("refusing to delete fenced node-local-pool Pod %s without an exact DaemonSet controller", pod.Name)
		}
		if allowedRunningUID != "" && string(owner.UID) == allowedRunningUID {
			continue
		}
		if _, ok := allowed[owner.UID]; !ok {
			return true, fmt.Errorf("refusing to recover fenced node-local-pool workload while Pod %s is owned by unrecorded DaemonSet UID %s", pod.Name, owner.UID)
		}
		retiredPending = true
	}
	return retiredPending, nil
}

func (r *GarageClusterReconciler) readFencedStorageRolloutWorkload(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
	node *garagev1beta1.GarageNode,
) (*fencedStorageRolloutWorkload, error) {
	if record.GarageNodeName != "" {
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, statefulSet); err != nil {
			return nil, fmt.Errorf("reading fenced replacement StatefulSet: %w", err)
		}
		if !statefulSet.DeletionTimestamp.IsZero() || !metav1.IsControlledBy(statefulSet, node) ||
			statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 0 {
			return nil, fmt.Errorf("replacement StatefulSet %s is not exact GarageNode-owned replicas=0 fence", statefulSet.Name)
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
		}, pod); err == nil {
			return nil, fmt.Errorf("fenced replacement StatefulSet unexpectedly created Pod %s", pod.Name)
		} else if !errors.IsNotFound(err) {
			return nil, err
		}
		result := &fencedStorageRolloutWorkload{
			uid:         statefulSet.UID,
			podSpecHash: statefulSet.Spec.Template.Annotations[annotationPodSpecHash],
			configHash:  statefulSet.Spec.Template.Annotations[annotationConfigHash],
		}
		if result.podSpecHash == "" || result.configHash == "" {
			return nil, fmt.Errorf("fenced replacement StatefulSet %s has empty desired revision hashes", statefulSet.Name)
		}
		if err := r.validateStorageRolloutTemplateConfigPublication(
			ctx, cluster, node, "", statefulSet.Spec.Template.Spec, result.configHash,
		); err != nil {
			return nil, fmt.Errorf("validating fenced replacement StatefulSet config publication: %w", err)
		}
		return result, nil
	}
	daemonSet := &appsv1.DaemonSet{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, record.NodeLocalPoolName),
	}, daemonSet); err != nil {
		return nil, fmt.Errorf("reading fenced replacement DaemonSet: %w", err)
	}
	activationLabel := nodeLocalPoolActivationLabel(cluster, record.NodeLocalPoolName)
	if !daemonSet.DeletionTimestamp.IsZero() || !metav1.IsControlledBy(daemonSet, cluster) ||
		daemonSet.Annotations[annotationRolloutAdoptionFence] != annotationTrue ||
		daemonSet.Annotations[annotationNodeLocalPoolActivationLabel] != activationLabel ||
		daemonSet.Annotations[annotationNodeLocalPoolActivationValue] != nodeLocalPoolActivationFenceValue ||
		daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] != nodeLocalPoolActivationFenceValue {
		return nil, fmt.Errorf("replacement DaemonSet %s is not exact GarageCluster-owned scheduling fence", daemonSet.Name)
	}
	if err := r.requireNoNodeLocalPoolPods(ctx, cluster, record.NodeLocalPoolName); err != nil {
		return nil, err
	}
	result := &fencedStorageRolloutWorkload{
		uid:         daemonSet.UID,
		podSpecHash: daemonSet.Spec.Template.Annotations[annotationPodSpecHash],
		configHash:  daemonSet.Spec.Template.Annotations[annotationConfigHash],
	}
	if result.podSpecHash == "" || result.configHash == "" {
		return nil, fmt.Errorf("fenced replacement DaemonSet %s has empty desired revision hashes", daemonSet.Name)
	}
	pool := nodeLocalPoolSpecByName(cluster, record.NodeLocalPoolName)
	if pool == nil {
		return nil, fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
	}
	if err := validateNodeLocalPoolWorkloadDiskLayoutPublication(daemonSet, pool); err != nil {
		return nil, fmt.Errorf("validating fenced replacement DaemonSet disk publication: %w", err)
	}
	if err := r.validateStorageRolloutTemplateConfigPublication(
		ctx, cluster, node, record.NodeLocalPoolName, daemonSet.Spec.Template.Spec, result.configHash,
	); err != nil {
		return nil, fmt.Errorf("validating fenced replacement DaemonSet config publication: %w", err)
	}
	return result, nil
}

func (r *GarageClusterReconciler) readStorageRolloutActorIdentity(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) (*garagev1beta1.GarageNode, *corev1.Node, error) {
	if record.GarageNodeName != "" {
		node := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, node); err != nil {
			return nil, nil, fmt.Errorf("reading persisted GarageNode actor identity: %w", err)
		}
		if string(node.UID) != record.GarageNodeUID || node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) {
			return nil, nil, fmt.Errorf("persisted GarageNode actor identity was recreated or retargeted")
		}
		if node.Status.NodeID != record.GarageNodeID {
			return nil, nil, fmt.Errorf("persisted GarageNode actor changed Garage identity; expected %s, got %s", shortID(record.GarageNodeID), shortID(node.Status.NodeID))
		}
		if err := r.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, record); err != nil {
			return nil, nil, err
		}
		return node, nil, nil
	}
	kubernetesNode := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: record.KubernetesNodeName}, kubernetesNode); err != nil {
		return nil, nil, fmt.Errorf("reading persisted Kubernetes Node actor identity: %w", err)
	}
	if string(kubernetesNode.UID) != record.KubernetesNodeUID {
		return nil, nil, fmt.Errorf("persisted Kubernetes Node actor was recreated; expected UID %s, got %s", record.KubernetesNodeUID, kubernetesNode.UID)
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, nil, err
	}
	var found *garagev1beta1.GarageNode
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name == cluster.Name && isNodeLocalPoolBacked(node) &&
			node.Spec.NodeLocalPoolName == record.NodeLocalPoolName && node.Spec.KubernetesNodeName == record.KubernetesNodeName {
			if found != nil {
				return nil, nil, fmt.Errorf("multiple GarageNodes claim persisted node-local-pool rollout actor")
			}
			found = node
		}
	}
	if found == nil || string(found.UID) != record.GarageNodeUID {
		return nil, nil, fmt.Errorf("persisted node-local-pool GarageNode actor was recreated; expected UID %s", record.GarageNodeUID)
	}
	if found.Status.NodeID != record.GarageNodeID {
		return nil, nil, fmt.Errorf("persisted node-local-pool actor changed Garage identity; expected %s, got %s", shortID(record.GarageNodeID), shortID(found.Status.NodeID))
	}
	return found, kubernetesNode, nil
}

func (r *GarageClusterReconciler) requireNoNodeLocalPoolPods(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
) error {
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods, client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName,
		})); err != nil {
		return fmt.Errorf("listing old node-local-pool Pods before workload adoption: %w", err)
	}
	if len(pods.Items) > 0 {
		sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
		return fmt.Errorf("waiting for old node-local-pool Pod %s UID %s to disappear before recreating its DaemonSet", pods.Items[0].Name, pods.Items[0].UID)
	}
	return nil
}

func (r *GarageClusterReconciler) adoptStorageRolloutWorkload(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expected, next nodeLocalPoolRolloutRecord,
) error {
	expectedClusterUID := cluster.UID
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedClusterUID || fresh.Generation != next.ClusterGeneration ||
			fresh.Annotations[garagev1beta1.AnnotationRecoverStorageRollout] != next.RecoveryRequest {
			return fmt.Errorf("garageCluster changed while adopting fenced storage rollout workload")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, expected) {
			return fmt.Errorf("storage rollout state changed while adopting fenced workload")
		}
		node, _, err := r.readStorageRolloutActorIdentity(ctx, fresh, expected)
		if err != nil {
			return err
		}
		if node.Generation != next.GarageNodeGeneration {
			return fmt.Errorf("garageNode generation changed while adopting fenced workload")
		}
		replacement, err := r.readFencedStorageRolloutWorkload(ctx, fresh, expected, node)
		if err != nil {
			return err
		}
		if string(replacement.uid) != next.WorkloadUID || replacement.podSpecHash != next.DesiredPodSpecHash ||
			replacement.configHash != next.DesiredConfigHash {
			return fmt.Errorf("fenced workload UID or desired hashes changed before adoption")
		}
		copy := next
		fresh.Status.StorageRollout = &copy
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRollingOut,
			Message:            fmt.Sprintf("adopted replacement workload UID %s behind a scheduling fence; enabling its exact actor next", next.WorkloadUID),
			ObservedGeneration: fresh.Generation,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting fenced storage rollout workload adoption: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) unfenceAdoptedStorageRolloutWorkload(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) error {
	if err := r.requireStorageRolloutPVCAdmission(record); err != nil {
		return err
	}
	node, _, err := r.readStorageRolloutActorIdentity(ctx, cluster, record)
	if err != nil {
		return err
	}
	clusterRequest := cluster.Annotations[garagev1beta1.AnnotationRecoverStorageRollout]
	correctionPending := cluster.Generation != record.ClusterGeneration ||
		node.Generation != record.GarageNodeGeneration ||
		(clusterRequest != "" && clusterRequest != record.RecoveryRequest)
	if record.GarageNodeName != "" {
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, statefulSet); err != nil {
			return err
		}
		if statefulSet.UID != types.UID(record.WorkloadUID) || !statefulSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(statefulSet, node) || statefulSet.Spec.Replicas == nil {
			return fmt.Errorf("replacement StatefulSet %s is not the exact live CAS-adopted workload", statefulSet.Name)
		}
		if !correctionPending {
			if err := r.validateStorageRolloutTemplateConfigPublication(
				ctx, cluster, node, "", statefulSet.Spec.Template.Spec, record.DesiredConfigHash,
			); err != nil {
				return fmt.Errorf("validating CAS-adopted StatefulSet config before unfencing: %w", err)
			}
		}
		switch *statefulSet.Spec.Replicas {
		case 0:
			if (statefulSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
				statefulSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash) && !correctionPending {
				return fmt.Errorf("fenced replacement StatefulSet template changed without a pending recovery correction")
			}
			pod := &corev1.Pod{}
			err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
				Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
			}, pod)
			if err == nil {
				owner := metav1.GetControllerOf(pod)
				retired := false
				for _, uid := range record.RetiredWorkloadUIDs {
					if owner != nil && string(owner.UID) == uid {
						retired = true
						break
					}
				}
				if !retired {
					return fmt.Errorf("fenced replacement StatefulSet unexpectedly has Pod %s owned by an unrecorded controller", pod.Name)
				}
				if pod.DeletionTimestamp.IsZero() {
					uid := pod.UID
					if err := r.Delete(ctx, pod, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil &&
						!errors.IsNotFound(err) && !errors.IsConflict(err) {
						return fmt.Errorf("deleting exact retired StatefulSet Pod %s: %w", pod.Name, err)
					}
				}
				return nil
			}
			if !errors.IsNotFound(err) {
				return err
			}
		case 1:
			if statefulSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
				statefulSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash {
				return fmt.Errorf("enabled replacement StatefulSet template changed before its workload-fence status was cleared")
			}
			pod := &corev1.Pod{}
			if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
				Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
			}, pod); err == nil {
				owner := metav1.GetControllerOf(pod)
				if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
					return fmt.Errorf("enabled replacement StatefulSet Pod %s is owned by an unrecorded controller", pod.Name)
				}
			} else if !errors.IsNotFound(err) {
				return err
			}
			// The enable Update reached Kubernetes and only the status clear was
			// lost. Clear the flag before considering a concurrent h2 correction;
			// scaling this live workload back to zero would be an unrecorded outage.
			return r.clearStorageRolloutWorkloadFence(ctx, cluster, record)
		default:
			return fmt.Errorf("CAS-adopted StatefulSet %s has unsupported replicas=%d", statefulSet.Name, *statefulSet.Spec.Replicas)
		}
	} else {
		daemonSet := &appsv1.DaemonSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, record.NodeLocalPoolName),
		}, daemonSet); err != nil {
			return err
		}
		activationLabel := nodeLocalPoolActivationLabel(cluster, record.NodeLocalPoolName)
		activationValue := daemonSet.Annotations[annotationNodeLocalPoolActivationValue]
		token := nodeLocalPoolActivationValueForWorkloadUID(daemonSet.UID)
		if daemonSet.UID != types.UID(record.WorkloadUID) || !daemonSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(daemonSet, cluster) || daemonSet.Annotations[annotationNodeLocalPoolActivationLabel] != activationLabel {
			return fmt.Errorf("replacement DaemonSet %s is not the exact live CAS-adopted workload", daemonSet.Name)
		}
		if !correctionPending {
			pool := nodeLocalPoolSpecByName(cluster, record.NodeLocalPoolName)
			if pool == nil {
				return fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
			}
			if err := validateNodeLocalPoolWorkloadDiskLayoutPublication(daemonSet, pool); err != nil {
				return fmt.Errorf("validating CAS-adopted DaemonSet disk publication before unfencing: %w", err)
			}
			if err := r.validateStorageRolloutTemplateConfigPublication(
				ctx, cluster, node, record.NodeLocalPoolName, daemonSet.Spec.Template.Spec, record.DesiredConfigHash,
			); err != nil {
				return fmt.Errorf("validating CAS-adopted DaemonSet config before unfencing: %w", err)
			}
		}
		fenced := daemonSet.Annotations[annotationRolloutAdoptionFence] == annotationTrue &&
			activationValue == nodeLocalPoolActivationFenceValue &&
			daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] == nodeLocalPoolActivationFenceValue
		enabled := daemonSet.Annotations[annotationRolloutAdoptionFence] == "" &&
			activationValue == token && daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] == token
		switch {
		case enabled:
			if daemonSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
				daemonSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash {
				return fmt.Errorf("enabled replacement DaemonSet template changed before its workload-fence status was cleared")
			}
			pending, err := r.waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear(
				ctx, cluster, record.NodeLocalPoolName, record.RetiredWorkloadUIDs, record.WorkloadUID,
			)
			if err != nil || pending {
				return err
			}
			return r.clearStorageRolloutWorkloadFence(ctx, cluster, record)
		case fenced:
			if (daemonSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
				daemonSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash) && !correctionPending {
				return fmt.Errorf("fenced replacement DaemonSet template changed without a pending recovery correction")
			}
			// Do not enable W2 while a surviving W1 process may still have the
			// HostPath mounted. Quarantine keeps any late W1 create unschedulable;
			// recovery observes old Pods but never expands this exceptional outage.
			pending, err := r.waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear(
				ctx, cluster, record.NodeLocalPoolName, record.RetiredWorkloadUIDs, "",
			)
			if err != nil || pending {
				return err
			}
			// Retoken Nodes only after every old process is absent. A late W1 Pod
			// still carries W1's old selector and cannot schedule after this point.
			if err := r.fenceNodeLocalPoolActivationNodes(ctx, cluster, record.NodeLocalPoolName, token); err != nil {
				return err
			}
		default:
			return fmt.Errorf("CAS-adopted DaemonSet %s is in a mixed or unrecorded scheduling-fence state", daemonSet.Name)
		}
	}
	if cluster.Generation != record.ClusterGeneration || node.Generation != record.GarageNodeGeneration ||
		(clusterRequest != "" && clusterRequest != record.RecoveryRequest) {
		// Keep the controller fenced while publishing a correction submitted
		// during adoption. Only after the revised hashes/generations are durable
		// may the first replacement Pod schedule.
		_, poolConfigHashes, err := r.reconcileConfigMap(ctx, cluster)
		if err != nil {
			return err
		}
		if record.GarageNodeName != "" {
			nodeReconciler := &GarageNodeReconciler{
				Client: r.Client, APIReader: r.APIReader, Scheme: r.Scheme,
				ClusterDomain: r.ClusterDomain, DefaultImage: r.DefaultImage,
				ManagedPVCAdmissionDisabled: r.ManagedPVCAdmissionDisabled,
				ClusterScoped:               r.ClusterScoped, LayoutMutations: r.LayoutMutations,
			}
			if nodeHasConfigOverrides(node) {
				if err := nodeReconciler.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
					return err
				}
			}
			if err := nodeReconciler.reconcileStatefulSetWithRecoveryFence(ctx, node, cluster, true); err != nil {
				return err
			}
		} else {
			var pool *garagev1beta2.NodeLocalPoolSpec
			if cluster.Spec.Storage != nil {
				for i := range cluster.Spec.Storage.NodeLocalPools {
					if cluster.Spec.Storage.NodeLocalPools[i].Name == record.NodeLocalPoolName {
						pool = &cluster.Spec.Storage.NodeLocalPools[i]
						break
					}
				}
			}
			if pool == nil {
				return fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
			}
			if err := r.reconcileNodeLocalPoolDaemonSetWithRecoveryFence(
				ctx, cluster, pool, nodeLocalPoolActivationLabel(cluster, pool.Name), poolConfigHashes[pool.Name], true,
			); err != nil {
				return err
			}
		}
		replacement, err := r.readFencedStorageRolloutWorkload(ctx, cluster, record, node)
		if err != nil {
			return err
		}
		next := record
		next.ClusterGeneration = cluster.Generation
		next.GarageNodeGeneration = node.Generation
		next.DesiredPodSpecHash = replacement.podSpecHash
		next.DesiredConfigHash = replacement.configHash
		if clusterRequest != "" {
			next.RecoveryRequest = clusterRequest
		}
		return r.advanceStorageRolloutRecord(ctx, cluster, record, next, clusterRequest)
	}

	if record.GarageNodeName != "" {
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, statefulSet); err != nil {
			return err
		}
		if string(statefulSet.UID) != record.WorkloadUID || !statefulSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(statefulSet, node) || statefulSet.Spec.Replicas == nil ||
			statefulSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
			statefulSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash {
			return fmt.Errorf("refusing to enable replacement StatefulSet with unrecorded UID, owner, lifecycle, or desired hashes")
		}
		if *statefulSet.Spec.Replicas == 1 {
			pod := &corev1.Pod{}
			if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
				Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
			}, pod); err == nil {
				owner := metav1.GetControllerOf(pod)
				if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
					return fmt.Errorf("enabled replacement StatefulSet Pod %s is owned by an unrecorded controller", pod.Name)
				}
			} else if !errors.IsNotFound(err) {
				return err
			}
			return r.clearStorageRolloutWorkloadFence(ctx, cluster, record)
		}
		if *statefulSet.Spec.Replicas != 0 {
			return fmt.Errorf("refusing to enable replacement StatefulSet from unexpected replicas=%d", *statefulSet.Spec.Replicas)
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName + "-0",
		}, pod); err == nil {
			return fmt.Errorf("refusing to enable fenced replacement StatefulSet while Pod %s UID %s still exists", pod.Name, pod.UID)
		} else if !errors.IsNotFound(err) {
			return err
		}
		if err := r.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, record); err != nil {
			return fmt.Errorf("refusing to enable replacement StatefulSet without exact protected claims: %w", err)
		}
		if err := r.validateStorageRolloutTemplateConfigPublication(
			ctx, cluster, node, "", statefulSet.Spec.Template.Spec, record.DesiredConfigHash,
		); err != nil {
			return fmt.Errorf("refusing to enable replacement StatefulSet without exact config publication: %w", err)
		}
		one := int32(1)
		statefulSet.Spec.Replicas = &one
		if err := r.Update(ctx, statefulSet); err != nil {
			return fmt.Errorf("enabling CAS-adopted StatefulSet: %w", err)
		}
	} else {
		daemonSet := &appsv1.DaemonSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, record.NodeLocalPoolName),
		}, daemonSet); err != nil {
			return err
		}
		activationLabel := nodeLocalPoolActivationLabel(cluster, record.NodeLocalPoolName)
		activationValue := nodeLocalPoolActivationValueForWorkloadUID(daemonSet.UID)
		if string(daemonSet.UID) != record.WorkloadUID || !daemonSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(daemonSet, cluster) ||
			daemonSet.Annotations[annotationNodeLocalPoolActivationLabel] != activationLabel ||
			daemonSet.Spec.Template.Annotations[annotationPodSpecHash] != record.DesiredPodSpecHash ||
			daemonSet.Spec.Template.Annotations[annotationConfigHash] != record.DesiredConfigHash {
			return fmt.Errorf("refusing to enable replacement DaemonSet with unrecorded UID, owner, lifecycle, activation label, or desired hashes")
		}
		alreadyEnabled := daemonSet.Annotations[annotationRolloutAdoptionFence] == "" &&
			daemonSet.Annotations[annotationNodeLocalPoolActivationValue] == activationValue &&
			daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] == activationValue
		if alreadyEnabled {
			pending, err := r.waitForNodeLocalPoolPodsOwnedByWorkloadsToDisappear(
				ctx, cluster, record.NodeLocalPoolName, record.RetiredWorkloadUIDs, record.WorkloadUID,
			)
			if err != nil || pending {
				return err
			}
			return r.clearStorageRolloutWorkloadFence(ctx, cluster, record)
		}
		if daemonSet.Annotations[annotationRolloutAdoptionFence] != annotationTrue ||
			daemonSet.Annotations[annotationNodeLocalPoolActivationValue] != nodeLocalPoolActivationFenceValue ||
			daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] != nodeLocalPoolActivationFenceValue {
			return fmt.Errorf("refusing to enable replacement DaemonSet from a mixed or unrecorded scheduling fence")
		}
		if err := r.requireNoNodeLocalPoolPods(ctx, cluster, record.NodeLocalPoolName); err != nil {
			return err
		}
		pool := nodeLocalPoolSpecByName(cluster, record.NodeLocalPoolName)
		if pool == nil {
			return fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
		}
		if err := validateNodeLocalPoolWorkloadDiskLayoutPublication(daemonSet, pool); err != nil {
			return fmt.Errorf("refusing to enable replacement DaemonSet without exact disk publication: %w", err)
		}
		if err := r.validateStorageRolloutTemplateConfigPublication(
			ctx, cluster, node, record.NodeLocalPoolName, daemonSet.Spec.Template.Spec, record.DesiredConfigHash,
		); err != nil {
			return fmt.Errorf("refusing to enable replacement DaemonSet without exact config publication: %w", err)
		}
		daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] = activationValue
		daemonSet.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
		if daemonSet.Spec.Template.Annotations == nil {
			daemonSet.Spec.Template.Annotations = make(map[string]string)
		}
		daemonSet.Spec.Template.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
		delete(daemonSet.Annotations, annotationRolloutAdoptionFence)
		if err := r.Update(ctx, daemonSet); err != nil {
			return fmt.Errorf("enabling CAS-adopted DaemonSet: %w", err)
		}
	}

	return r.clearStorageRolloutWorkloadFence(ctx, cluster, record)
}

func (r *GarageClusterReconciler) clearStorageRolloutWorkloadFence(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expected nodeLocalPoolRolloutRecord,
) error {
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != cluster.UID {
			return fmt.Errorf("garageCluster was recreated while clearing workload adoption fence")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, expected) {
			return fmt.Errorf("storage rollout state changed while clearing workload adoption fence")
		}
		copy := *current
		copy.WorkloadFenced = false
		fresh.Status.StorageRollout = &copy
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing storage rollout workload adoption fence: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) readStorageRolloutActorSnapshot(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) (*storageRolloutActorSnapshot, error) {
	snapshot := &storageRolloutActorSnapshot{}
	if record.GarageNodeName != "" {
		node := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: cluster.Namespace, Name: record.GarageNodeName,
		}, node); err != nil {
			return nil, fmt.Errorf("reading persisted GarageNode rollout actor %q: %w", record.GarageNodeName, err)
		}
		if string(node.UID) != record.GarageNodeUID || node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			!node.DeletionTimestamp.IsZero() {
			return nil, fmt.Errorf("persisted GarageNode rollout actor %q no longer has exact UID %s and parent", node.Name, record.GarageNodeUID)
		}
		if node.Status.NodeID != record.GarageNodeID {
			return nil, fmt.Errorf("persisted GarageNode rollout actor %q changed Garage identity; expected %s, got %s", node.Name, shortID(record.GarageNodeID), shortID(node.Status.NodeID))
		}
		if err := r.requireStorageRolloutPersistentVolumeClaimProtection(ctx, cluster, record); err != nil {
			return nil, err
		}
		statefulSet := &appsv1.StatefulSet{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: node.Namespace, Name: node.Name,
		}, statefulSet); err != nil {
			if errors.IsNotFound(err) {
				return nil, fmt.Errorf("%w: StatefulSet %s", errStorageRolloutWorkloadMissing, node.Name)
			}
			return nil, fmt.Errorf("reading persisted StatefulSet rollout actor %q: %w", node.Name, err)
		}
		if string(statefulSet.UID) != record.WorkloadUID || !statefulSet.DeletionTimestamp.IsZero() ||
			!metav1.IsControlledBy(statefulSet, node) || statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 1 ||
			statefulSet.Spec.UpdateStrategy.Type != appsv1.OnDeleteStatefulSetStrategyType {
			return nil, fmt.Errorf("StatefulSet %s is not the exact non-deleting OnDelete replicas=1 workload UID %s controlled by GarageNode UID %s", statefulSet.Name, record.WorkloadUID, record.GarageNodeUID)
		}
		snapshot.node = node
		snapshot.garageNodeUID = node.UID
		snapshot.workloadUID = statefulSet.UID
		snapshot.desiredPodSpecHash = statefulSet.Spec.Template.Annotations[annotationPodSpecHash]
		snapshot.desiredConfigHash = statefulSet.Spec.Template.Annotations[annotationConfigHash]
		if snapshot.desiredPodSpecHash == "" || snapshot.desiredConfigHash == "" {
			return nil, fmt.Errorf("persisted StatefulSet rollout actor %q has empty desired revision hashes", statefulSet.Name)
		}
		if err := r.validateStorageRolloutTemplateConfigPublication(
			ctx, cluster, node, "", statefulSet.Spec.Template.Spec, snapshot.desiredConfigHash,
		); err != nil {
			return nil, fmt.Errorf("validating persisted StatefulSet rollout config publication: %w", err)
		}
		pod := &corev1.Pod{}
		if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
			Namespace: node.Namespace, Name: node.Name + "-0",
		}, pod); err != nil {
			if errors.IsNotFound(err) {
				return snapshot, nil
			}
			return nil, fmt.Errorf("reading current Pod for GarageNode %q: %w", node.Name, err)
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
			return nil, fmt.Errorf("pod %s is not controlled by exact persisted StatefulSet UID %s", pod.Name, record.WorkloadUID)
		}
		snapshot.currentPod = pod
		return snapshot, nil
	}

	kubernetesNode := &corev1.Node{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: record.KubernetesNodeName}, kubernetesNode); err != nil {
		return nil, fmt.Errorf("reading persisted Kubernetes Node rollout actor %q: %w", record.KubernetesNodeName, err)
	}
	if string(kubernetesNode.UID) != record.KubernetesNodeUID {
		return nil, fmt.Errorf("kubernetes Node %q was recreated with UID %s; persisted HostPath actor UID is %s", kubernetesNode.Name, kubernetesNode.UID, record.KubernetesNodeUID)
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, fmt.Errorf("listing node-local-pool GarageNodes for persisted rollout actor: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			!isNodeLocalPoolBacked(node) || node.Spec.NodeLocalPoolName != record.NodeLocalPoolName ||
			node.Spec.KubernetesNodeName != record.KubernetesNodeName {
			continue
		}
		if snapshot.node != nil {
			return nil, fmt.Errorf("multiple GarageNodes claim persisted rollout pool %q on Kubernetes Node %q", record.NodeLocalPoolName, record.KubernetesNodeName)
		}
		snapshot.node = node
	}
	if snapshot.node == nil || string(snapshot.node.UID) != record.GarageNodeUID {
		return nil, fmt.Errorf("node-local-pool rollout actor no longer has exact GarageNode UID %s", record.GarageNodeUID)
	}
	if !snapshot.node.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("node-local-pool rollout GarageNode actor %s is deleting", snapshot.node.Name)
	}
	if snapshot.node.Status.NodeID != record.GarageNodeID {
		return nil, fmt.Errorf("node-local-pool rollout actor changed Garage identity; expected %s, got %s", shortID(record.GarageNodeID), shortID(snapshot.node.Status.NodeID))
	}
	daemonSet := &appsv1.DaemonSet{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Namespace: cluster.Namespace, Name: storageDaemonSetName(cluster, record.NodeLocalPoolName),
	}, daemonSet); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: DaemonSet %s", errStorageRolloutWorkloadMissing, storageDaemonSetName(cluster, record.NodeLocalPoolName))
		}
		return nil, fmt.Errorf("reading persisted node-local-pool DaemonSet %q: %w", record.NodeLocalPoolName, err)
	}
	activationLabel := nodeLocalPoolActivationLabel(cluster, record.NodeLocalPoolName)
	activationValue := nodeLocalPoolActivationValueForDaemonSet(daemonSet)
	if !nodeLocalPoolActivationValueIsActive(activationValue) ||
		kubernetesNode.Labels[activationLabel] != activationValue ||
		string(daemonSet.UID) != record.WorkloadUID || !daemonSet.DeletionTimestamp.IsZero() ||
		!metav1.IsControlledBy(daemonSet, cluster) ||
		daemonSet.Spec.UpdateStrategy.Type != appsv1.OnDeleteDaemonSetStrategyType ||
		daemonSet.Annotations[annotationRolloutAdoptionFence] != "" ||
		daemonSet.Annotations[annotationNodeLocalPoolActivationLabel] != activationLabel ||
		daemonSet.Spec.Template.Spec.NodeSelector[activationLabel] != activationValue {
		return nil, fmt.Errorf("DaemonSet %s is not exact non-deleting enabled OnDelete workload UID %s controlled by GarageCluster UID %s", daemonSet.Name, record.WorkloadUID, cluster.UID)
	}
	snapshot.garageNodeUID = snapshot.node.UID
	snapshot.workloadUID = daemonSet.UID
	snapshot.kubernetesNodeUID = kubernetesNode.UID
	snapshot.kubernetesNode = kubernetesNode
	snapshot.activationLabel = activationLabel
	snapshot.activationValue = activationValue
	snapshot.desiredPodSpecHash = daemonSet.Spec.Template.Annotations[annotationPodSpecHash]
	snapshot.desiredConfigHash = daemonSet.Spec.Template.Annotations[annotationConfigHash]
	if snapshot.desiredPodSpecHash == "" || snapshot.desiredConfigHash == "" {
		return nil, fmt.Errorf("persisted node-local-pool DaemonSet %q has empty desired revision hashes", daemonSet.Name)
	}
	pool := nodeLocalPoolSpecByName(cluster, record.NodeLocalPoolName)
	if pool == nil {
		return nil, fmt.Errorf("persisted rollout pool %q is no longer declared", record.NodeLocalPoolName)
	}
	if err := validateNodeLocalPoolWorkloadDiskLayoutPublication(daemonSet, pool); err != nil {
		return nil, fmt.Errorf("validating persisted node-local-pool DaemonSet disk publication: %w", err)
	}
	if err := r.validateStorageRolloutTemplateConfigPublication(
		ctx, cluster, snapshot.node, record.NodeLocalPoolName, daemonSet.Spec.Template.Spec, snapshot.desiredConfigHash,
	); err != nil {
		return nil, fmt.Errorf("validating persisted node-local-pool DaemonSet config publication: %w", err)
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods, client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: record.NodeLocalPoolName,
		})); err != nil {
		return nil, fmt.Errorf("listing Pods for persisted node-local-pool rollout actor: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		targetsActor := pod.Spec.NodeName == record.KubernetesNodeName
		if pod.Spec.NodeName == "" {
			targets, bounded := nodeLocalPoolPodTargetNodeNames(pod)
			_, exact := targets[record.KubernetesNodeName]
			targetsActor = bounded && exact && len(targets) == 1
		}
		if !targetsActor {
			continue
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != daemonSetKind || owner.UID != daemonSet.UID {
			return nil, fmt.Errorf("pod %s on persisted node-local-pool actor is not controlled by exact DaemonSet UID %s", pod.Name, record.WorkloadUID)
		}
		if snapshot.currentPod == nil {
			snapshot.currentPod = pod
			continue
		}
		if !snapshot.currentPod.DeletionTimestamp.IsZero() && pod.DeletionTimestamp.IsZero() {
			snapshot.currentPod = pod
			continue
		}
		if !pod.DeletionTimestamp.IsZero() || !snapshot.currentPod.DeletionTimestamp.IsZero() {
			continue
		}
		return nil, fmt.Errorf("multiple active Pods exist for persisted node-local-pool rollout actor %q on Kubernetes Node %q", record.NodeLocalPoolName, record.KubernetesNodeName)
	}
	return snapshot, nil
}

// selectStorageRolloutRecoveryPod persists one exact stale replacement Pod
// before deleting it. Unlike advanceStorageRolloutRecord, this transition is
// intentionally allowed while the GarageCluster or GarageNode generation (or
// recovery nonce) moves forward: the selected Pod still runs the record's old
// revision and must disappear before any newer correction can be evaluated.
// The durable rollout record itself is otherwise retained byte-for-byte.
func (r *GarageClusterReconciler) selectStorageRolloutRecoveryPod(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expected nodeLocalPoolRolloutRecord,
	stalePod *corev1.Pod,
) (nodeLocalPoolRolloutRecord, error) {
	if stalePod == nil || stalePod.Name == "" || stalePod.UID == "" {
		return nodeLocalPoolRolloutRecord{}, fmt.Errorf("cannot select an empty storage rollout recovery Pod")
	}
	if expected.RecoveryPodName != "" || expected.RecoveryPodUID != "" {
		return nodeLocalPoolRolloutRecord{}, fmt.Errorf("storage rollout already has an exact recovery Pod selected")
	}
	expectedClusterUID := cluster.UID
	selectedName := stalePod.Name
	selectedUID := stalePod.UID
	var updated *garagev1beta2.GarageCluster
	var selected nodeLocalPoolRolloutRecord
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedClusterUID {
			return fmt.Errorf("garageCluster was recreated while selecting an exact stale rollout Pod")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, expected) {
			return fmt.Errorf("storage rollout actor or recovery state changed before the stale Pod was selected")
		}
		// Reconstruct the exact actor from live owner UIDs. Generation changes are
		// deliberately accepted, but Pod name reuse and controller replacement are
		// not: readStorageRolloutActorSnapshot validates both ownership boundaries.
		snapshot, err := r.readStorageRolloutActorSnapshot(ctx, fresh, expected)
		if err != nil {
			return err
		}
		pod := snapshot.currentPod
		if pod == nil || pod.Name != selectedName || pod.UID != selectedUID || !pod.DeletionTimestamp.IsZero() {
			return fmt.Errorf("stale storage rollout Pod changed before its exact UID could be persisted")
		}
		if string(pod.UID) == expected.PreviousPodUID ||
			(pod.Annotations[annotationPodSpecHash] == expected.DesiredPodSpecHash &&
				pod.Annotations[annotationConfigHash] == expected.DesiredConfigHash) {
			return fmt.Errorf("refusing to select Pod %s UID %s because it is not a stale successor of the persisted rollout revision", pod.Name, pod.UID)
		}
		selected = *current
		selected.RecoveryPodName = pod.Name
		selected.RecoveryPodUID = string(pod.UID)
		fresh.Status.StorageRollout = &selected
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonStorageRollingOut,
			Message: fmt.Sprintf(
				"removing exact stale replacement Pod %s UID %s before evaluating GarageCluster generation %d and GarageNode generation %d",
				pod.Name, pod.UID, fresh.Generation, snapshot.node.Generation,
			),
			ObservedGeneration: fresh.Generation,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return nodeLocalPoolRolloutRecord{}, fmt.Errorf("persisting exact stale storage rollout Pod before retry deletion: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return selected, nil
}

func (r *GarageClusterReconciler) advanceStorageRolloutRecord(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expected, next nodeLocalPoolRolloutRecord,
	expectedClusterRequest string,
) error {
	expectedClusterUID := cluster.UID
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedClusterUID || fresh.Generation != next.ClusterGeneration ||
			fresh.Annotations[garagev1beta1.AnnotationRecoverStorageRollout] != expectedClusterRequest {
			return fmt.Errorf("garageCluster UID, generation, or recovery nonce changed while rendering the retry")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, expected) {
			return fmt.Errorf("storage rollout actor or desired revision changed while publishing recovery; re-read before retrying")
		}
		snapshot, err := r.readStorageRolloutActorSnapshot(ctx, fresh, expected)
		if err != nil {
			return err
		}
		if snapshot.node.Generation != next.GarageNodeGeneration ||
			snapshot.desiredPodSpecHash != next.DesiredPodSpecHash ||
			snapshot.desiredConfigHash != next.DesiredConfigHash {
			return fmt.Errorf("garageNode generation/nonce or exact workload template changed while rendering the retry")
		}
		copy := next
		fresh.Status.StorageRollout = &copy
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonStorageRollingOut,
			Message:            fmt.Sprintf("rolling forward exact managed Pod actor at GarageCluster generation %d, GarageNode generation %d, recovery request %q", next.ClusterGeneration, next.GarageNodeGeneration, next.RecoveryRequest),
			ObservedGeneration: fresh.Generation,
		})
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting corrected storage rollout revision before retry: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) redriveStorageRolloutRecoveryPod(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	record nodeLocalPoolRolloutRecord,
) (bool, error) {
	if record.RecoveryPodName == "" || record.RecoveryPodUID == "" {
		return false, nil
	}
	pod := &corev1.Pod{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Namespace: cluster.Namespace, Name: record.RecoveryPodName,
	}, pod); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return true, fmt.Errorf("reading exact failed storage rollout Pod %s: %w", record.RecoveryPodName, err)
	}
	if string(pod.UID) != record.RecoveryPodUID {
		return false, nil
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || string(owner.UID) != record.WorkloadUID {
		return true, fmt.Errorf("refusing to delete recovery Pod %s UID %s because its controller is not exact persisted workload UID %s", pod.Name, pod.UID, record.WorkloadUID)
	}
	if record.GarageNodeName != "" {
		if owner.Kind != kindStatefulSet || pod.Name != record.GarageNodeName+"-0" {
			return true, fmt.Errorf("refusing to delete recovery Pod %s because it is not the exact StatefulSet actor", pod.Name)
		}
	} else if owner.Kind != daemonSetKind || pod.Spec.NodeName != record.KubernetesNodeName ||
		pod.Labels[labelCluster] != cluster.Name || pod.Labels[labelNodeLocalPool] != record.NodeLocalPoolName {
		return true, fmt.Errorf("refusing to delete recovery Pod %s because it is not the exact node-local-pool actor", pod.Name)
	}
	if !pod.DeletionTimestamp.IsZero() {
		return true, nil
	}
	snapshot, err := r.readStorageRolloutActorSnapshot(ctx, cluster, record)
	if err != nil {
		return true, fmt.Errorf("revalidating exact workload publication before recovery Pod deletion: %w", err)
	}
	if snapshot.currentPod == nil || snapshot.currentPod.UID != pod.UID ||
		snapshot.desiredPodSpecHash != record.DesiredPodSpecHash ||
		snapshot.desiredConfigHash != record.DesiredConfigHash {
		return true, fmt.Errorf("refusing to delete recovery Pod %s because its exact workload publication changed after selection", pod.Name)
	}
	uid := pod.UID
	if err := r.Delete(ctx, pod, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
		return true, fmt.Errorf("deleting exact failed storage rollout Pod %s: %w", pod.Name, err)
	}
	return true, nil
}

func (r *GarageClusterReconciler) clearStorageRolloutRecoveryPod(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	expected nodeLocalPoolRolloutRecord,
) error {
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != cluster.UID {
			return fmt.Errorf("garageCluster was recreated while clearing exact recovery Pod state")
		}
		current, err := nodeLocalPoolRolloutRecordForCluster(fresh)
		if err != nil {
			return err
		}
		if current == nil || !equality.Semantic.DeepEqual(*current, expected) {
			return fmt.Errorf("storage rollout recovery state changed while clearing completed retry deletion")
		}
		copy := *current
		copy.RecoveryPodName = ""
		copy.RecoveryPodUID = ""
		fresh.Status.StorageRollout = &copy
		if err := r.Status().Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("clearing completed exact recovery Pod deletion: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}
