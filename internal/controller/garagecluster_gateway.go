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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// gatewayTierTag is the layout role tag identifying a node entry as belonging
// to the gateway tier. Used by the one-shot migration that removes legacy
// gateway-tier role entries from the cluster layout.
const gatewayTierTag = "tier:" + tierGateway

// gatewayDeploymentName is the canonical name for the gateway-tier Deployment.
func gatewayDeploymentName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-gateway"
}

// reconcileGatewayDeployment creates/updates the gateway-tier Deployment.
//
// Gateway pods are ephemeral: EmptyDir for both metadata and data, RollingUpdate
// strategy, no PVCs. Their node identity rotates per pod restart. Gateway nodes
// do NOT participate in the cluster layout — they join the cluster purely via
// ConnectClusterNodes. See migrateGatewayOutOfLayout for the one-shot removal
// of legacy gateway-tier role entries from upgraded clusters.
func (r *GarageClusterReconciler) reconcileGatewayDeployment(ctx context.Context, cluster *garagev1beta2.GarageCluster, configHash string) error {
	log := logf.FromContext(ctx)
	gw := cluster.Spec.Gateway
	if gw == nil {
		return nil
	}

	name := gatewayDeploymentName(cluster)
	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)
	replicas := gw.Replicas

	containerPorts := buildContainerPorts(cluster)
	volumes, volumeMounts := buildGatewayVolumesAndMounts(cluster)

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
		Logging:                   cluster.Spec.Logging,
	}, volumes, volumeMounts, containerPorts)

	podLabels := r.selectorLabelsForTier(cluster, tierGateway)
	for k, v := range gw.PodLabels {
		podLabels[k] = v
	}

	// Hash user-provided podAnnotations/podLabels alongside the pod spec so changes to those
	// trigger a Deployment update (the update gate compares only the hash annotations).
	podSpecHashStr := computePodSpecHash(podSpec, gw.PodAnnotations, gw.PodLabels)

	podAnnotations := make(map[string]string)
	for k, v := range gw.PodAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations["garage.rajsingh.info/config-hash"] = configHash
	podAnnotations["garage.rajsingh.info/pod-spec-hash"] = podSpecHashStr

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForTier(cluster, tierGateway),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: r.selectorLabelsForTier(cluster, tierGateway)},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       ptrIntOrStringPercent(25),
					MaxUnavailable: ptrIntOrStringPercent(25),
				},
			},
			ProgressDeadlineSeconds: ptr.To[int32](600),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, deploy, r.Scheme); err != nil {
		return err
	}

	existing := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating gateway Deployment", "name", name)
		return r.Create(ctx, deploy)
	}
	if err != nil {
		return err
	}

	needsUpdate := existing.Spec.Replicas == nil || *existing.Spec.Replicas != *deploy.Spec.Replicas
	if existing.Spec.Template.Annotations["garage.rajsingh.info/config-hash"] != configHash ||
		existing.Spec.Template.Annotations["garage.rajsingh.info/pod-spec-hash"] != podSpecHashStr {
		needsUpdate = true
	}
	if !needsUpdate {
		return nil
	}
	existing.Spec = deploy.Spec
	log.Info("Updating gateway Deployment", "name", name)
	return r.Update(ctx, existing)
}

// deleteGatewayDeployment removes the gateway Deployment when the user has
// removed the `spec.gateway` block from the CR.
func (r *GarageClusterReconciler) deleteGatewayDeployment(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	name := gatewayDeploymentName(cluster)
	existing := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	log.Info("Removing gateway Deployment (gateway tier no longer declared)", "name", name)
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
	log.Info("Removing storage StatefulSet (storage tier no longer declared)", "name", cluster.Name)
	return r.Delete(ctx, existing)
}

// buildGatewayVolumesAndMounts builds the volumes and mounts for a gateway pod.
// Gateway pods always use EmptyDir for both metadata and data — no PVC under any
// circumstance. RPC secret comes from the connected storage cluster when set; else
// from the gateway cluster's own RPC secret (auto-generated or referenced).
func buildGatewayVolumesAndMounts(cluster *garagev1beta2.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	mounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
		{Name: RPCSecretKey, MountPath: rpcSecretMountPath, ReadOnly: true},
		{Name: metadataVolName, MountPath: metadataPath},
		{Name: dataVolName, MountPath: dataPath},
	}

	rpcSecretName := cluster.Name + "-rpc-secret"
	rpcSecretKey := RPCSecretKey
	if cluster.Spec.Network.RPCSecretRef != nil {
		rpcSecretName = cluster.Spec.Network.RPCSecretRef.Name
		if cluster.Spec.Network.RPCSecretRef.Key != "" {
			rpcSecretKey = cluster.Spec.Network.RPCSecretRef.Key
		}
	}
	if cluster.Spec.ConnectTo != nil {
		if cluster.Spec.ConnectTo.RPCSecretRef != nil {
			rpcSecretName = cluster.Spec.ConnectTo.RPCSecretRef.Name
			if cluster.Spec.ConnectTo.RPCSecretRef.Key != "" {
				rpcSecretKey = cluster.Spec.ConnectTo.RPCSecretRef.Key
			}
		} else if cluster.Spec.ConnectTo.ClusterRef != nil {
			rpcSecretName = cluster.Spec.ConnectTo.ClusterRef.Name + "-rpc-secret"
		}
	}

	// Use the gateway-specific ConfigMap when the operator created one
	// (spec.gateway.rpcPublicAddr is set alongside spec.storage). Otherwise
	// fall back to the shared <name>-config map.
	configMapName := cluster.Name + "-config"
	if cluster.HasStorageTier() && cluster.HasGatewayTier() && cluster.Spec.Gateway.RPCPublicAddr != "" {
		configMapName = cluster.Name + "-gateway-config"
	}

	volumes := []corev1.Volume{
		{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
				},
			},
		},
		{
			Name: RPCSecretKey,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  rpcSecretName,
					DefaultMode: ptr.To[int32](0600),
					Items:       []corev1.KeyToPath{{Key: rpcSecretKey, Path: RPCSecretKey}},
				},
			},
		},
		{
			Name: metadataVolName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: dataVolName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		adminTokenKey := DefaultAdminTokenKey
		if cluster.Spec.Admin.AdminTokenSecretRef.Key != "" {
			adminTokenKey = cluster.Spec.Admin.AdminTokenSecretRef.Key
		}
		volumes = append(volumes, corev1.Volume{
			Name: DefaultAdminTokenKey,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  cluster.Spec.Admin.AdminTokenSecretRef.Name,
					DefaultMode: ptr.To[int32](0600),
					Items:       []corev1.KeyToPath{{Key: adminTokenKey, Path: DefaultAdminTokenKey}},
				},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      DefaultAdminTokenKey,
			MountPath: adminSecretMountPath,
			ReadOnly:  true,
		})
	}

	return volumes, mounts
}

// ptrIntOrStringPercent returns a pointer to an IntOrString carrying a percentage value.
func ptrIntOrStringPercent(p int) *intstr.IntOrString {
	v := intstr.FromString(fmt.Sprintf("%d%%", p))
	return &v
}

// migrateGatewayOutOfLayout removes any pre-existing tier:gateway role entries
// from the cluster layout. Gateway pods no longer participate in the layout —
// they join the cluster purely via ConnectClusterNodes, which keeps the cluster
// node_id_vec storage-tier-only and prevents the per-restart Draining-version
// pileup that ephemeral gateway identity used to cause.
//
// This is a one-shot migration: on a freshly upgraded cluster it finds legacy
// gateway role entries tagged "tier:gateway" + the cluster ownership tag,
// stages a Remove for each, applies the layout, and calls skip-dead-nodes on
// the new version. Subsequent reconciles see nothing to remove and the call is
// effectively a no-op. The migration does NOT touch already-accumulated
// Draining versions whose storage_sets contain ghost UUIDs — that requires an
// upstream Garage fix.
//
// Errors are logged but never returned: failure here must not block the
// primary reconciliation loop. On failure the migration retries on the next
// reconcile.
func (r *GarageClusterReconciler) migrateGatewayOutOfLayout(ctx context.Context, layoutClient *garage.Client, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)
	if layoutClient == nil {
		return
	}

	layout, err := layoutClient.GetClusterLayout(ctx)
	if err != nil {
		log.V(1).Info("Skipping gateway-out-of-layout migration (could not fetch layout)", "error", err)
		return
	}

	gatewayOwnershipTag := fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace)
	// Skip roles already staged for removal so we don't double-stage on retries.
	alreadyStagedForRemoval := make(map[string]bool, len(layout.StagedRoleChanges))
	for _, change := range layout.StagedRoleChanges {
		if change.Remove {
			alreadyStagedForRemoval[change.ID] = true
		}
	}

	var staleIDs []string
	for _, role := range layout.Roles {
		ownsThis := false
		isGatewayTier := false
		for _, tag := range role.Tags {
			if tag == gatewayOwnershipTag {
				ownsThis = true
			}
			if tag == gatewayTierTag {
				isGatewayTier = true
			}
		}
		if !ownsThis || !isGatewayTier {
			continue
		}
		if alreadyStagedForRemoval[role.ID] {
			continue
		}
		staleIDs = append(staleIDs, role.ID)
	}

	// Stop writing PendingGatewayTombstones (deprecated) and clear any leftover
	// surfacing from a previous operator version.
	//nolint:staticcheck // SA1019: intentional read+clear of the deprecated field
	if len(cluster.Status.PendingGatewayTombstones) > 0 {
		cluster.Status.PendingGatewayTombstones = nil //nolint:staticcheck // SA1019
	}

	if len(staleIDs) == 0 {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones)
		return
	}
	sort.Strings(staleIDs)

	changes := make([]garage.NodeRoleChange, 0, len(staleIDs))
	for _, id := range staleIDs {
		changes = append(changes, garage.NodeRoleChange{ID: id, Remove: true})
	}
	if err := layoutClient.UpdateClusterLayout(ctx, changes); err != nil {
		log.Error(err, "Failed to stage gateway-out-of-layout migration removal", "count", len(staleIDs))
		return
	}
	layout, err = layoutClient.GetClusterLayout(ctx)
	if err != nil {
		log.Error(err, "Failed to refresh layout after staging gateway migration removal")
		return
	}
	newVersion := layout.Version + 1
	if err := layoutClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if !garage.IsReplicationConstraint(err) {
			log.Error(err, "Failed to apply gateway-out-of-layout migration")
		}
		return
	}
	log.Info("Migrated gateway tier out of layout",
		"removed", len(staleIDs), "version", newVersion)

	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               garagev1beta1.ConditionGatewayTombstones,
		Status:             metav1.ConditionFalse,
		Reason:             garagev1beta1.ReasonGatewayTombstonesPending,
		Message:            fmt.Sprintf("Migrated gateway tier out of layout (removed %d entries)", len(staleIDs)),
		ObservedGeneration: cluster.Generation,
	})

	// skip-dead-nodes on the freshly applied layout — gateway IDs we just
	// removed are dead by definition. Single-version layouts return 400 which
	// is expected on stable clusters; log at debug only.
	skipReq := garage.SkipDeadNodesRequest{Version: newVersion, AllowMissingData: true}
	if _, err := layoutClient.ClusterLayoutSkipDeadNodes(ctx, skipReq); err != nil && !garage.IsBadRequest(err) {
		log.V(1).Info("skip-dead-nodes after gateway migration failed", "error", err)
	}
}
