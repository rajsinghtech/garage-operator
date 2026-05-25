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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// gatewayDefaultMetadataSize is the default capacity of the gateway metadata PVC
// when the user does not override `spec.gateway.metadata.size`. Gateway metadata
// holds the Ed25519 node_key plus a small index — 1Gi is generous.
var gatewayDefaultMetadataSize = resource.MustParse("1Gi")

// gatewayWorkloadName is the canonical name for the gateway-tier workload
// (StatefulSet from v0.5.6 onwards; Deployment in older versions).
func gatewayWorkloadName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-gateway"
}

// reconcileGatewayStatefulSet creates/updates the gateway-tier StatefulSet.
//
// Gateway pods get a small metadata PVC so the Ed25519 node identity Garage
// stores under metadata_dir survives pod restarts. Data dir stays EmptyDir —
// gateways do not store object blocks. PVC retention is Delete/Delete to keep
// the existing "ephemeral semantics" of the gateway tier (PVCs vanish on
// scale-down and CR deletion).
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

	// One-shot migration: pre-v0.5.6 deployed the gateway as a Deployment with
	// the same name. Delete it before we provision the StatefulSet so the two
	// don't race for pods.
	if err := r.deletePreviousGatewayDeployment(ctx, cluster); err != nil {
		return err
	}

	name := gatewayWorkloadName(cluster)
	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)
	replicas := gw.Replicas

	containerPorts := buildContainerPorts(cluster)
	volumes, volumeMounts := buildGatewayVolumesAndMounts(cluster)
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
		Logging:                   cluster.Spec.Logging,
		Env:                       gw.Env,
		EnvFrom:                   gw.EnvFrom,
	}, volumes, volumeMounts, containerPorts)

	podLabels := r.selectorLabelsForTier(cluster, tierGateway)
	// Add labelCluster to the pod template (NOT the STS selector — that's immutable
	// for existing rollouts) so the cluster-scoped headless RPC service and primary
	// API service (post-#190, selecting via labelCluster) include gateway pods.
	podLabels[labelCluster] = cluster.Name
	for k, v := range gw.PodLabels {
		podLabels[k] = v
	}

	// Hash user-provided podAnnotations/podLabels alongside the pod spec so changes to those
	// trigger an update (the update gate compares only the hash annotations).
	podSpecHashStr := computePodSpecHash(podSpec, gw.PodAnnotations, gw.PodLabels)

	podAnnotations := make(map[string]string)
	for k, v := range gw.PodAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations["garage.rajsingh.info/config-hash"] = configHash
	podAnnotations["garage.rajsingh.info/pod-spec-hash"] = podSpecHashStr

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForTier(cluster, tierGateway),
		},
		Spec: appsv1.StatefulSetSpec{
			// Re-use the shared headless RPC service. It selects pods by the
			// cluster-scoped label which is already present on gateway pods.
			ServiceName:          cluster.Name + "-headless",
			Replicas:             &replicas,
			Selector:             &metav1.LabelSelector{MatchLabels: r.selectorLabelsForTier(cluster, tierGateway)},
			PodManagementPolicy:  appsv1.ParallelPodManagement,
			UpdateStrategy:       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
			VolumeClaimTemplates: volumeClaimTemplates,
			PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
				WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
				WhenScaled:  appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
			},
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

	// VolumeClaimTemplates are immutable; if the metadata storageClass changes,
	// orphan-delete the StatefulSet and let the next reconcile re-create it.
	if vctStorageClassChanged(existing.Spec.VolumeClaimTemplates, volumeClaimTemplates) {
		log.Info("Gateway VolumeClaimTemplate storageClass changed, recreating StatefulSet (orphan cascade — delete old PVCs manually)", "name", name)
		propagation := metav1.DeletePropagationOrphan
		if err := r.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete gateway StatefulSet for VCT recreation: %w", err)
		}
		return nil
	}

	needsUpdate := existing.Spec.Replicas == nil || *existing.Spec.Replicas != *sts.Spec.Replicas
	if existing.Spec.Template.Annotations["garage.rajsingh.info/config-hash"] != configHash ||
		existing.Spec.Template.Annotations["garage.rajsingh.info/pod-spec-hash"] != podSpecHashStr {
		needsUpdate = true
	}
	if !needsUpdate {
		return nil
	}
	existing.Spec.Replicas = sts.Spec.Replicas
	existing.Spec.Template = sts.Spec.Template
	log.Info("Updating gateway StatefulSet", "name", name)
	return r.Update(ctx, existing)
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
	log.Info("Removing storage StatefulSet (storage tier no longer declared)", "name", cluster.Name)
	return r.Delete(ctx, existing)
}

// buildGatewayVolumesAndMounts builds the volumes and mounts for a gateway pod.
//
// Metadata is provisioned via a StatefulSet volumeClaimTemplate (see
// buildGatewayVolumeClaimTemplates) so it does NOT appear in the volumes list
// here. The data dir stays EmptyDir because gateways do not store object
// blocks. RPC secret comes from the connected storage cluster when set; else
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
		// metadata is provisioned via volumeClaimTemplates, not here.
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

// buildGatewayVolumeClaimTemplates returns the PVC templates for the gateway
// StatefulSet. Only the metadata claim is templated — the data dir stays
// EmptyDir on a gateway pod.
func buildGatewayVolumeClaimTemplates(cluster *garagev1beta2.GarageCluster) []corev1.PersistentVolumeClaim {
	if cluster.Spec.Gateway == nil {
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
// PendingGatewayTombstones status field for manual approval (via the
// force-layout-apply annotation).
func (r *GarageClusterReconciler) reconcileGatewayTombstones(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)
	if !cluster.HasGatewayTier() {
		return
	}

	layoutClient, err := r.gatewayLayoutClient(ctx, cluster)
	if err != nil {
		log.V(1).Info("Skipping gateway tombstone cleanup (admin client not ready)", "error", err)
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
	for _, n := range status.Nodes {
		if n.IsUp {
			live[n.ID] = true
		}
	}

	gatewayOwnershipTag := fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace)
	gatewayTierTag := "tier:" + tierGateway
	var stale []string
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
		if live[role.ID] {
			continue
		}
		stale = append(stale, role.ID)
	}

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
			Message: fmt.Sprintf("%d stale gateway entries pending; set spec.layoutManagement.autoApply: true or use the force-layout-apply annotation", len(stale)),
		})
		log.Info("Stale gateway entries pending (autoApply disabled)", "count", len(stale))
		return
	}

	changes := make([]garage.NodeRoleChange, 0, len(stale))
	for _, id := range stale {
		changes = append(changes, garage.NodeRoleChange{ID: id, Remove: true})
	}
	if err := layoutClient.UpdateClusterLayout(ctx, changes); err != nil {
		log.Error(err, "Failed to stage stale gateway entry removal")
		return
	}
	layout, err = layoutClient.GetClusterLayout(ctx)
	if err != nil {
		log.Error(err, "Failed to refresh layout after staging tombstone removal")
		return
	}
	newVersion := layout.Version + 1
	if err := layoutClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if !garage.IsReplicationConstraint(err) {
			log.Error(err, "Failed to apply gateway tombstone removal")
		}
		return
	}
	log.Info("Removed stale gateway entries from layout", "count", len(stale), "version", newVersion)

	skipReq := garage.SkipDeadNodesRequest{Version: newVersion, AllowMissingData: true}
	if _, err := layoutClient.ClusterLayoutSkipDeadNodes(ctx, skipReq); err != nil && !garage.IsBadRequest(err) {
		log.V(1).Info("skip-dead-nodes after tombstone removal failed", "error", err)
	}

	cluster.Status.PendingGatewayTombstones = nil
	meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones)
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
