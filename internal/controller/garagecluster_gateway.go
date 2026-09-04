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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

// gatewayDefaultMetadataSize is the default capacity of the gateway metadata PVC
// when the user does not override `spec.gateway.metadata.size`. Gateway metadata
// holds the Ed25519 node_key plus a small index — 1Gi is generous.
var gatewayDefaultMetadataSize = resource.MustParse("1Gi")

func gatewayPVCRetentionPolicy(policy *garagev1beta2.PVCRetentionPolicy) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
	if policy != nil {
		return translatePVCRetentionPolicy(policy)
	}
	return &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
		WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
		WhenScaled:  appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
	}
}

const (
	gatewayDataMarkerVolumeName    = "gateway-data-marker"
	gatewayDataMarkerFile          = "garage-marker"
	annotationGatewayDataMarker    = "garage.rajsingh.info/gateway-data-marker"
	gatewayDataMarkerFieldPath     = "metadata.annotations['" + annotationGatewayDataMarker + "']"
	gatewayDataMarkerLegacyContent = ""
)

// gatewayWorkloadName is the canonical name for the gateway-tier workload
// (StatefulSet from v0.5.6 onwards; Deployment in older versions).
func gatewayWorkloadName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-gateway"
}

// reconcileGatewayStatefulSet creates/updates the gateway-tier StatefulSet.
//
// Gateway pods get a small metadata PVC so the Ed25519 node identity Garage
// stores under metadata_dir survives pod restarts. Data dir stays EmptyDir —
// gateways do not store object blocks. PVC retention defaults to Delete/Delete
// to keep the established edge-gateway lifecycle, but an explicit gateway
// retention policy (including the released v1beta1 field) is honored.
//
// As a one-shot upgrade aid, any pre-existing Deployment with the same name
// (from v0.5.5 and earlier) is removed before the StatefulSet is created.
//
// Gateway pods DO participate in the cluster layout with capacity=nil
// (matching upstream `garage layout assign --gateway`). This is required by
// the S3 sig-auth path which uses get_local() — see
// src/api/common/signature/payload.rs:413 in upstream Garage. Without a
// layout entry, FullReplication writes (key_table etc.) never reach the
// gateway's local DB and every S3 request returns 403 "No such key".
func (r *GarageClusterReconciler) reconcileGatewayStatefulSet(ctx context.Context, cluster *garagev1beta2.GarageCluster, configHash string) error {
	log := logf.FromContext(ctx)
	gw := cluster.Spec.Gateway
	if gw == nil {
		return nil
	}
	name := gatewayWorkloadName(cluster)
	preexisting := &appsv1.StatefulSet{}
	preexistingErr := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, preexisting)
	if preexistingErr != nil && !errors.IsNotFound(preexistingErr) {
		return preexistingErr
	}
	if errors.IsNotFound(preexistingErr) {
		if err := validateEdgeGatewayPodNames(cluster); err != nil {
			return fmt.Errorf("refusing to create edge gateway StatefulSet: %w", err)
		}
	}

	// One-shot migration: pre-v0.5.6 deployed the gateway as a Deployment with
	// the same name. Delete it before we provision the StatefulSet so the two
	// don't race for pods.
	if err := r.deletePreviousGatewayDeployment(ctx, cluster); err != nil {
		return err
	}

	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)
	replicas := gw.Replicas

	containerPorts := buildContainerPorts(cluster)
	volumes, volumeMounts := buildGatewayVolumesAndMounts(cluster, configHash)
	volumeClaimTemplates := buildGatewayVolumeClaimTemplates(cluster)

	podSpec := buildGaragePodSpec(PodSpecConfig{
		Image:                     image,
		ImagePullPolicy:           cluster.Spec.ImagePullPolicy,
		ImagePullSecrets:          cluster.Spec.ImagePullSecrets,
		Resources:                 gw.Resources,
		NodeSelector:              gw.NodeSelector,
		Tolerations:               gw.Tolerations,
		Affinity:                  gw.Affinity,
		PriorityClassName:         gw.PriorityClassName,
		ServiceAccountName:        cluster.Spec.ServiceAccountName,
		SecurityContext:           gw.SecurityContext,
		ContainerSecurityContext:  gw.ContainerSecurityContext,
		TopologySpreadConstraints: gw.TopologySpreadConstraints,
		IsGateway:                 true,
		ReadinessProbe:            gw.ReadinessProbe,
		Logging:                   cluster.Spec.Logging,
		Env:                       gw.Env,
		EnvFrom:                   gw.EnvFrom,
	}, volumes, volumeMounts, containerPorts)
	if err := validateGarageCredentialFileAccess(cluster, podSpec, "spec.gateway"); err != nil {
		return err
	}

	userPodLabels := workloadidentity.UserPodLabels(gw.PodLabels)
	podLabels := make(map[string]string, len(userPodLabels)+4)
	for key, value := range userPodLabels {
		podLabels[key] = value
	}
	for key, value := range r.labelsForTier(cluster, tierGateway) {
		podLabels[key] = value
	}
	// Add labelCluster to the pod template (NOT the STS selector — that's immutable
	// for existing rollouts) so the cluster-scoped headless RPC service and primary
	// API service (post-#190, selecting via labelCluster) include gateway pods.
	podLabels[labelCluster] = cluster.Name

	// Hash user-provided podAnnotations/podLabels alongside the pod spec so changes to those
	// trigger an update (the update gate compares only the hash annotations).
	podSpecHashStr := computePodSpecHash(podSpec, gw.PodAnnotations, userPodLabels)

	podAnnotations := make(map[string]string)
	for k, v := range gw.PodAnnotations {
		podAnnotations[k] = v
	}
	// Released gateway workloads created an empty garage-marker before Garage
	// persisted its content in metadata/data_layout. Keep that byte-for-byte
	// value across upgrades; a Pod-name marker would make every retained gateway
	// metadata volume fail Garage's marker check on its next restart.
	podAnnotations[annotationGatewayDataMarker] = gatewayDataMarkerLegacyContent
	podAnnotations[annotationConfigHash] = configHash
	podAnnotations[annotationPodSpecHash] = podSpecHashStr

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForTier(cluster, tierGateway),
		},
		Spec: appsv1.StatefulSetSpec{
			// Re-use the shared headless RPC service. It selects pods by the
			// cluster-scoped label which is already present on gateway pods.
			ServiceName:                          cluster.Name + "-headless",
			Replicas:                             &replicas,
			Selector:                             &metav1.LabelSelector{MatchLabels: r.selectorLabelsForTier(cluster, tierGateway)},
			PodManagementPolicy:                  appsv1.ParallelPodManagement,
			UpdateStrategy:                       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
			VolumeClaimTemplates:                 volumeClaimTemplates,
			PersistentVolumeClaimRetentionPolicy: gatewayPVCRetentionPolicy(gw.PVCRetentionPolicy),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return err
	}

	existing := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating gateway StatefulSet", "name", name)
		return r.Create(ctx, sts)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(existing, cluster) {
		return fmt.Errorf("refusing to mutate gateway StatefulSet %s/%s because it is not controlled by GarageCluster UID %s", existing.Namespace, existing.Name, cluster.UID)
	}

	// VolumeClaimTemplates are immutable. Admission allows an edge gateway's
	// PVC shape/size to change only after replicas reached zero. Do not trust the
	// desired count alone: the user can submit the second update before the
	// StatefulSet controller removes old Pods and claims. First drive the old
	// StatefulSet to zero, then require exact old-UID Pods and every derived claim
	// to disappear before orphan-deleting the controller. The next reconcile can
	// then publish the new immutable template without overlapping identities or
	// silently reusing an old claim.
	if gatewayVolumeClaimTemplatesChanged(existing.Spec.VolumeClaimTemplates, volumeClaimTemplates) {
		if err := validateEdgeGatewayPodNames(cluster); err != nil {
			return fmt.Errorf("refusing to recreate edge gateway StatefulSet: %w", err)
		}
		if replicas != 0 {
			return fmt.Errorf("refusing to recreate gateway StatefulSet %s for a metadata template change while desired replicas is %d", name, replicas)
		}
		if existing.Spec.Replicas == nil || *existing.Spec.Replicas != 0 {
			existing.Spec.Replicas = ptr.To[int32](0)
			log.Info("Scaling old gateway StatefulSet to zero before metadata template recreation", "name", name)
			return r.Update(ctx, existing)
		}
		clear, reason, err := r.edgeGatewayStatefulSetStorageRetired(ctx, existing)
		if err != nil {
			return err
		}
		if !clear {
			log.Info("Waiting for old gateway storage incarnation to retire before metadata template recreation", "name", name, "reason", reason)
			return nil
		}
		log.Info("Gateway VolumeClaimTemplate changed, recreating StatefulSet with orphan propagation", "name", name)
		propagation := metav1.DeletePropagationOrphan
		if err := r.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete gateway StatefulSet for VCT recreation: %w", err)
		}
		return nil
	}

	needsUpdate := existing.Spec.Replicas == nil || *existing.Spec.Replicas != *sts.Spec.Replicas
	if !equality.Semantic.DeepEqual(existing.Labels, sts.Labels) || !metav1.IsControlledBy(existing, cluster) {
		needsUpdate = true
	}
	if existing.Spec.Template.Annotations[annotationConfigHash] != configHash ||
		existing.Spec.Template.Annotations[annotationPodSpecHash] != podSpecHashStr {
		needsUpdate = true
	}
	if gw.PVCRetentionPolicy != nil && !equality.Semantic.DeepEqual(
		existing.Spec.PersistentVolumeClaimRetentionPolicy,
		sts.Spec.PersistentVolumeClaimRetentionPolicy,
	) {
		needsUpdate = true
	}
	if !needsUpdate {
		return nil
	}
	if err := validateEdgeGatewayPodNames(cluster); err != nil {
		return fmt.Errorf("refusing to roll edge gateway StatefulSet: %w", err)
	}
	existing.Spec.Replicas = sts.Spec.Replicas
	existing.Spec.Template = sts.Spec.Template
	if gw.PVCRetentionPolicy != nil {
		existing.Spec.PersistentVolumeClaimRetentionPolicy = sts.Spec.PersistentVolumeClaimRetentionPolicy
	}
	// Re-assert operator labels + controllerRef so ownerRef/label drift
	// self-heals (the STS selector is immutable and is intentionally left
	// untouched). sts already had SetControllerReference applied above.
	existing.Labels = sts.Labels
	existing.OwnerReferences = sts.OwnerReferences
	log.Info("Updating gateway StatefulSet", "name", name)
	return r.Update(ctx, existing)
}

func validateEdgeGatewayPodNames(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil || cluster.Spec.Gateway == nil {
		return nil
	}
	for ordinal := int32(0); ordinal < cluster.Spec.Gateway.Replicas; ordinal++ {
		podName := fmt.Sprintf("%s-%d", gatewayWorkloadName(cluster), ordinal)
		if errs := utilvalidation.IsValidLabelValue(podName); len(errs) > 0 {
			return fmt.Errorf("StatefulSet Pod label %q is invalid: %s", podName, strings.Join(errs, "; "))
		}
	}
	return nil
}

// edgeGatewayStatefulSetStorageRetired proves that a zero-replica edge
// StatefulSet has no exact old-controller Pod and no PVC derived from one of
// its immutable claim templates. It never deletes a claim: an unexpectedly
// retained PVC blocks recreation for explicit operator inspection.
func (r *GarageClusterReconciler) edgeGatewayStatefulSetStorageRetired(
	ctx context.Context,
	statefulSet *appsv1.StatefulSet,
) (bool, string, error) {
	if statefulSet == nil || statefulSet.UID == "" {
		return false, "StatefulSet UID is not observable", nil
	}

	pods := &corev1.PodList{}
	if err := r.safetyReader().List(ctx, pods, client.InNamespace(statefulSet.Namespace)); err != nil {
		return false, "", fmt.Errorf("listing Pods before gateway StatefulSet metadata recreation: %w", err)
	}
	for i := range pods.Items {
		owner := metav1.GetControllerOf(&pods.Items[i])
		if owner != nil && owner.Kind == kindStatefulSet && owner.UID == statefulSet.UID {
			return false, fmt.Sprintf("Pod %s owned by old StatefulSet UID %s still exists", pods.Items[i].Name, statefulSet.UID), nil
		}
	}

	claims := &corev1.PersistentVolumeClaimList{}
	if err := r.safetyReader().List(ctx, claims, client.InNamespace(statefulSet.Namespace)); err != nil {
		return false, "", fmt.Errorf("listing PVCs before gateway StatefulSet metadata recreation: %w", err)
	}
	for i := range claims.Items {
		for j := range statefulSet.Spec.VolumeClaimTemplates {
			prefix := statefulSet.Spec.VolumeClaimTemplates[j].Name + "-" + statefulSet.Name + "-"
			if strings.HasPrefix(claims.Items[i].Name, prefix) {
				return false, fmt.Sprintf("PVC %s from the old immutable claim template still exists", claims.Items[i].Name), nil
			}
		}
	}

	return true, "", nil
}

// deletePreviousGatewayDeployment removes any pre-v0.5.6 Deployment with the
// gateway workload name so it does not coexist with the new StatefulSet.
func (r *GarageClusterReconciler) deletePreviousGatewayDeployment(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	name := gatewayWorkloadName(cluster)
	old := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, old); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !metav1.IsControlledBy(old, cluster) {
		log.Info("Leaving foreign same-name legacy gateway Deployment untouched", "name", name)
		return nil
	}
	log.Info("Removing pre-v0.5.6 gateway Deployment so the StatefulSet can take over", "name", name)
	return r.Delete(ctx, old)
}

// deleteGatewayStatefulSet removes the gateway StatefulSet when the user has
// removed the `spec.gateway` block from the CR. The associated metadata PVCs
// are deleted automatically via the StatefulSet's PVC retention policy
// (WhenDeleted=Delete). The function also clears any pre-v0.5.6 gateway
// Deployment that might still be around.
func (r *GarageClusterReconciler) deleteGatewayStatefulSet(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	name := gatewayWorkloadName(cluster)

	if err := r.deletePreviousGatewayDeployment(ctx, cluster); err != nil {
		return err
	}

	existing := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !metav1.IsControlledBy(existing, cluster) {
		log.Info("Leaving foreign same-name gateway StatefulSet untouched", "name", name)
		return nil
	}
	log.Info("Removing gateway StatefulSet (gateway tier no longer declared)", "name", name)
	return r.Delete(ctx, existing)
}

// deleteStorageStatefulSet removes the storage StatefulSet when the user has
// removed the `spec.storage` block from the CR. PVCs are NOT deleted automatically;
// the user must clean them up manually.
func (r *GarageClusterReconciler) deleteStorageStatefulSet(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	existing := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, existing); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if !metav1.IsControlledBy(existing, cluster) {
		log.Info("Leaving foreign same-name storage StatefulSet untouched", "name", existing.Name)
		return nil
	}
	log.Info("Removing storage StatefulSet (storage tier no longer declared)", "name", cluster.Name)
	return r.Delete(ctx, existing)
}

// buildGatewayVolumesAndMounts builds the volumes and mounts for the
// cluster-owned edge-gateway StatefulSet. Unified gateway identities are
// GarageNode-owned and receive their exact per-node config revision through the
// GarageNode renderer; this builder always consumes the shared cluster config.
//
// Persistent metadata is provisioned via a StatefulSet volumeClaimTemplate
// (see buildGatewayVolumeClaimTemplates), so it does not appear in the volumes
// list here. An explicit metadata.type=EmptyDir instead renders a real
// metadata volume and no claim template. The data dir always stays EmptyDir
// because gateways do not store object blocks. RPC secret comes from the
// connected storage cluster when set; otherwise from the gateway cluster's own
// RPC secret (auto-generated or referenced).
func buildGatewayVolumesAndMounts(cluster *garagev1beta2.GarageCluster, configHash ...string) ([]corev1.Volume, []corev1.VolumeMount) {
	credentialVolumes, credentialMounts := buildGarageCredentialVolumesAndMounts(cluster, true)
	mounts := make([]corev1.VolumeMount, 0, 3+len(credentialMounts))
	mounts = append(mounts,
		corev1.VolumeMount{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
		corev1.VolumeMount{Name: metadataVolName, MountPath: metadataPath},
		corev1.VolumeMount{Name: dataVolName, MountPath: dataPath},
		gatewayDataMarkerMount(),
	)

	// Edge gateways consume the shared cluster revision. The historical
	// <name>-gateway-config resource is no longer published; selecting that base
	// for a unified cluster would construct a name that can never exist.
	configName := cluster.Name + "-config"
	if len(configHash) > 0 && configHash[0] != "" {
		configName = garageConfigRevisionName(configName, configHash[0])
	}

	volumes := make([]corev1.Volume, 0, 2+len(credentialVolumes))
	volumes = append(volumes,
		corev1.Volume{
			Name:         configVolumeName,
			VolumeSource: garageConfigVolumeSource(cluster, configName),
		},
		// metadata is provisioned via volumeClaimTemplates, not here.
		corev1.Volume{
			Name: dataVolName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		gatewayDataMarkerVolume(),
	)
	if cluster.Spec.Gateway != nil {
		if metadata := cluster.Spec.Gateway.Metadata; metadata != nil && metadata.Type == garagev1beta2.VolumeTypeEmptyDir {
			emptyDir := &corev1.EmptyDirVolumeSource{}
			if metadata.Size != nil && !metadata.Size.IsZero() {
				sizeLimit := metadata.Size.DeepCopy()
				emptyDir.SizeLimit = &sizeLimit
			}
			volumes = append(volumes, corev1.Volume{
				Name: metadataVolName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: emptyDir,
				},
			})
		}
	}

	volumes = append(volumes, credentialVolumes...)
	mounts = append(mounts, credentialMounts...)

	return volumes, mounts
}

// Garage accepts an existing read-only marker and persists its exact content in
// the metadata layout. Released gateway workloads used `touch`, so that content
// is the empty string. Projecting an operator-owned empty Pod annotation removes
// the separate BusyBox init image without invalidating retained metadata PVCs.
func gatewayDataMarkerVolume() corev1.Volume {
	return corev1.Volume{
		Name: gatewayDataMarkerVolumeName,
		VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{
			Items: []corev1.DownwardAPIVolumeFile{{
				Path: gatewayDataMarkerFile,
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  gatewayDataMarkerFieldPath,
				},
			}},
		}},
	}
}

func gatewayDataMarkerMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      gatewayDataMarkerVolumeName,
		MountPath: dataPath + "/" + gatewayDataMarkerFile,
		SubPath:   gatewayDataMarkerFile,
		ReadOnly:  true,
	}
}

// buildGatewayVolumeClaimTemplates returns the PVC templates for the gateway
// StatefulSet. Only the metadata claim is templated — the data dir stays
// EmptyDir on a gateway pod.
func buildGatewayVolumeClaimTemplates(cluster *garagev1beta2.GarageCluster) []corev1.PersistentVolumeClaim {
	if cluster.Spec.Gateway == nil {
		return nil
	}
	if metadata := cluster.Spec.Gateway.Metadata; metadata != nil && metadata.Type == garagev1beta2.VolumeTypeEmptyDir {
		return nil
	}

	size := gatewayDefaultMetadataSize
	var sc *string
	var accessModes []corev1.PersistentVolumeAccessMode
	var selector *metav1.LabelSelector
	var labels map[string]string
	var annotations map[string]string

	if md := cluster.Spec.Gateway.Metadata; md != nil {
		if md.Size != nil && !md.Size.IsZero() {
			size = *md.Size
		}
		sc = md.StorageClassName
		accessModes = md.AccessModes
		selector = md.Selector
		labels = md.Labels
		annotations = md.Annotations
	}

	pvc := buildBasePVC(metadataVolName, size, sc, accessModes)
	if selector != nil {
		pvc.Spec.Selector = selector
	}
	if len(labels) > 0 {
		pvc.Labels = labels
	}
	if len(annotations) > 0 {
		pvc.Annotations = annotations
	}
	if md := cluster.Spec.Gateway.Metadata; md != nil && md.DataSourceRef != nil {
		pvc.Spec.DataSourceRef = md.DataSourceRef.DeepCopy()
	}
	return []corev1.PersistentVolumeClaim{pvc}
}

// reconcileGatewayTombstones removes stale gateway layout entries left behind
// by scaled-down or removed gateway replicas. With persistent gateway
// identity (v0.5.6+) a routine rollout keeps the same node_id, so this only
// has work to do on genuine scale-down events (the StatefulSet's
// WhenScaled=Delete retention policy deletes the PVC and therefore the
// node_key).
//
// When `layoutManagement.autoApply` is true the removal is staged AND applied.
// Otherwise stale entries are surfaced via the GatewayTombstones condition and
// PendingGatewayTombstones status field, but are neither staged nor applied;
// users must remove those exact roles with the Garage CLI or enable autoApply.
func (r *GarageClusterReconciler) reconcileGatewayTombstones(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)
	if !cluster.HasGatewayTier() {
		return
	}

	// Forward-only edge gateways cannot be reported isUp by the external cluster.
	// Keep inspecting the layout so an intentional scale-down can retire exact-UID
	// ordinals outside the desired range, but suppress dwell-based reaping of
	// desired ordinals below. Edge gateway replicas have no per-ordinal GarageNode
	// finalizer, so scale-down cleanup belongs here.
	forwardOnlyEdge := edgeGatewayReverseUnroutable(cluster)

	layoutClient, err := r.gatewayLayoutClient(ctx, cluster)
	if err != nil {
		log.V(1).Info("Skipping gateway tombstone cleanup (admin client not ready)", "error", err)
		return
	}
	layoutOwner, err := resolveGarageLayoutOwner(ctx, r.safetyReader(), cluster)
	if err != nil {
		log.V(1).Info("Waiting to resolve canonical layout owner before gateway tombstone cleanup", "reason", err.Error())
		return
	}
	release, err := acquireLayoutMutation(r.layoutMutationCoordinator(), layoutOwner)
	if err != nil {
		log.V(1).Info("Waiting to inspect gateway tombstones behind another layout writer", "reason", err.Error())
		return
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, layoutClient); err != nil {
		log.V(1).Info("Waiting for settled layout history before gateway tombstone cleanup", "reason", err.Error())
		return
	}

	layout, err := layoutClient.GetClusterLayout(ctx)
	if err != nil {
		log.V(1).Info("Skipping gateway tombstone cleanup (could not fetch layout)", "error", err)
		return
	}
	status, err := layoutClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Skipping gateway tombstone cleanup (could not fetch status)", "error", err)
		return
	}

	live := make(map[string]bool, len(status.Nodes))
	// sustainedDown prevents native edge-gateway rolling updates and transient
	// federation disconnects from looking like abandoned identities. Every
	// automatic tombstone removal requires the same dwell used by PeerUnreachable.
	sustainedDown := make(map[string]bool)
	for _, n := range status.Nodes {
		if n.IsUp {
			live[n.ID] = true
			continue
		}
		if !forwardOnlyEdge && n.LastSeenSecsAgo != nil && time.Duration(*n.LastSeenSecsAgo)*time.Second >= peerUnreachableThreshold {
			sustainedDown[n.ID] = true
		}
	}

	// In a unified cluster the gateway tier runs as per-node GarageNodes, whose
	// finalizers own layout-role removal on delete. A node that just restarted
	// is briefly not "isUp" yet its CR (and role) are valid — removing it here
	// would fight the per-node controller. So preserve any role claimed by a live
	// operator-owned gateway GarageNode CR (via status.nodeId). Edge gateways have
	// no such CRs, so this set is empty there and the isUp check governs alone.
	claimed := make(map[string]bool)
	gwNodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, gwNodes,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      cluster.Name,
			labelTier:         tierGateway,
			labelAppManagedBy: managedByOperatorValue,
		}),
	); err == nil {
		for i := range gwNodes.Items {
			if id := gwNodes.Items[i].Status.NodeID; id != "" {
				claimed[id] = true
			}
		}
	}

	// Name, namespace, and zone are not unique in a federation. Only the
	// cluster-uid tag written from this exact Kubernetes object authorizes
	// automatic removal. Legacy/tag-stripped roles remain visible for explicit
	// cleanup instead of risking another site's gateway.
	var edgeDesiredReplicas *int32
	if !cluster.HasStorageTier() && cluster.Spec.Gateway != nil {
		edgeDesiredReplicas = &cluster.Spec.Gateway.Replicas
	}
	stale := staleGatewayRoles(
		layout.Roles,
		localGatewayZone(cluster),
		string(cluster.UID),
		live,
		claimed,
		sustainedDown,
		edgeDesiredReplicas,
	)

	if len(stale) == 0 {
		if len(cluster.Status.PendingGatewayTombstones) > 0 {
			cluster.Status.PendingGatewayTombstones = nil
		}
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones)
		return
	}
	sort.Strings(stale)

	autoApply := cluster.Spec.LayoutManagement != nil && cluster.Spec.LayoutManagement.AutoApply
	if !autoApply {
		cluster.Status.PendingGatewayTombstones = stale
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    garagev1beta1.ConditionGatewayTombstones,
			Status:  metav1.ConditionTrue,
			Reason:  garagev1beta1.ReasonGatewayTombstonesPending,
			Message: fmt.Sprintf("%d stale gateway entries pending; set spec.layoutManagement.autoApply: true or remove the exact roles with the Garage CLI", len(stale)),
		})
		log.Info("Stale gateway entries pending (autoApply disabled)", "count", len(stale))
		return
	}

	changes := make([]garage.NodeRoleChange, 0, len(stale))
	for _, id := range stale {
		changes = append(changes, garage.NodeRoleChange{ID: id, Remove: true})
	}
	// Persist the exact identities before Apply. A crash after Garage commits the
	// removal must leave an operator-visible recovery boundary. Surviving current
	// members normally converge the version; if another peer/history version
	// blocks it, Garage exposes only a cluster-wide recovery API, never a
	// target-scoped one.
	persistPending := func() {
		cluster.Status.PendingGatewayTombstones = append([]string(nil), stale...)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:   garagev1beta1.ConditionGatewayTombstones,
			Status: metav1.ConditionTrue,
			Reason: garagev1beta1.ReasonGatewayTombstonesPending,
			Message: fmt.Sprintf(
				"%d stale gateway role removal(s) are pending normal layout convergence; if a dead identity blocks ACK, assess the entire layout before using the explicit skip-dead-nodes annotation",
				len(stale),
			),
		})
	}
	persistPending()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, persistPending); err != nil {
		log.Error(err, "Could not persist exact gateway tombstone targets before Garage Apply")
		return
	}
	if _, err := stageAndApplyExclusiveLayout(ctx, layoutClient, layout, changes, nil, func() error {
		if err := layoutClient.UpdateClusterLayout(ctx, changes); err != nil {
			return fmt.Errorf("staging stale gateway entry removal: %w", err)
		}
		return nil
	}); err != nil {
		if !garage.IsReplicationConstraint(err) {
			log.Error(err, "Refusing or failing gateway tombstone removal")
		}
		return
	}
	// Re-read only for diagnostics. Never invoke skip-dead-nodes automatically:
	// upstream force-ACKs every peer the serving node currently sees as down, not
	// just the exact tombstone identities persisted above.
	newVersion, ok := reReadLayoutVersion(ctx, layoutClient)
	if ok {
		log.Info("Removed stale gateway entries from layout; waiting for normal ACK or explicit cluster-wide recovery",
			"count", len(stale), "version", newVersion)
	} else {
		log.Info("Removed stale gateway entries from layout; committed version is not observable yet", "count", len(stale))
	}
}

// gatewayLayoutClient returns the admin API client whose layout the gateway entries
// live in. For unified clusters (gateway + storage in the same CR) that's the local
// admin API. For edge gateways (gateway-only + connectTo) it's the remote storage
// cluster.
func (r *GarageClusterReconciler) gatewayLayoutClient(ctx context.Context, cluster *garagev1beta2.GarageCluster) (*garage.Client, error) {
	if cluster.HasStorageTier() {
		adminToken, err := r.getAdminToken(ctx, cluster)
		if err != nil {
			return nil, err
		}
		if adminToken == "" {
			return nil, fmt.Errorf("admin token not configured")
		}
		adminPort := getAdminPort(cluster)
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		return garage.NewClient(endpoint, adminToken), nil
	}

	if cluster.Spec.ConnectTo == nil {
		return nil, fmt.Errorf("gateway-only cluster missing connectTo")
	}
	if cluster.Spec.ConnectTo.ClusterRef != nil {
		return r.getStorageClusterClient(ctx, cluster)
	}
	if cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		return r.getExternalStorageClient(ctx, cluster)
	}
	return nil, fmt.Errorf("connectTo missing clusterRef or adminApiEndpoint")
}

// localGatewayZone returns the layout zone the operator assigns to this
// cluster's gateway roles. It mirrors the defaulting in
// buildAutoModeGatewayNode (empty spec.zone => defaultZoneName) so the
// tombstone reaper matches its own roles even when spec.zone is unset.
func localGatewayZone(cluster *garagev1beta2.GarageCluster) string {
	if cluster.Spec.Zone == "" {
		return defaultZoneName
	}
	return cluster.Spec.Zone
}

// staleGatewayRoles returns the IDs of gateway layout roles owned by this
// cluster that are no longer backed by a live or operator-claimed gateway node
// and are therefore safe to remove. A role qualifies only when it carries the
// exact cluster UID and tier:gateway tags, sits in localZone, has remained down
// past the safety dwell, and is not claimed by a live GarageNode CR. During an
// edge-gateway scale-down, an exact-UID role whose pod ordinal is outside the
// desired replica range is immediately retired; desired ordinals still require
// the dwell so a native StatefulSet rollout cannot churn their persistent role.
func staleGatewayRoles(
	roles []garage.LayoutNodeRole,
	localZone,
	clusterUID string,
	live,
	claimed,
	sustainedDown map[string]bool,
	edgeDesiredReplicas *int32,
) []string {
	tierTag := "tier:" + tierGateway
	var stale []string
	for _, role := range roles {
		if role.Zone != localZone {
			continue
		}
		isGatewayTier := false
		for _, tag := range role.Tags {
			if tag == tierTag {
				isGatewayTier = true
			}
		}
		retiredEdgeOrdinal := false
		if edgeDesiredReplicas != nil {
			if ordinalText, ok := parseRemotePodOrdinal(role.Tags, tierGateway); ok {
				ordinal, err := strconv.Atoi(ordinalText)
				retiredEdgeOrdinal = err == nil && int32(ordinal) >= *edgeDesiredReplicas
			}
		}
		if !isGatewayTier || !nodeBelongsToClusterUID(role.Tags, clusterUID) ||
			(!retiredEdgeOrdinal && !sustainedDown[role.ID]) {
			continue
		}
		if live[role.ID] || claimed[role.ID] {
			continue
		}
		stale = append(stale, role.ID)
	}
	return stale
}
