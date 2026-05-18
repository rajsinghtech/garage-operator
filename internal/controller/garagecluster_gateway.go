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

// gatewayDeploymentName is the canonical name for the gateway-tier Deployment.
func gatewayDeploymentName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-gateway"
}

// reconcileGatewayDeployment creates/updates the gateway-tier Deployment.
//
// Gateway pods are ephemeral: EmptyDir for both metadata and data, RollingUpdate
// strategy, no PVCs. Their node identity rotates per pod restart and the operator
// garbage-collects stale layout entries via reconcileGatewayTombstones.
func (r *GarageClusterReconciler) reconcileGatewayDeployment(ctx context.Context, cluster *garagev1beta2.GarageCluster, configHash string) error {
	log := logf.FromContext(ctx)
	gw := cluster.Spec.Gateway
	if gw == nil {
		return nil
	}

	name := gatewayDeploymentName(cluster)
	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)
	replicas := gw.Replicas
	if replicas == 0 {
		replicas = 2
	}

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

	volumes := []corev1.Volume{
		{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: cluster.Name + "-config"},
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

// reconcileGatewayTombstones removes stale gateway layout entries.
//
// Gateway pods generate a fresh node identity on every restart (no PVC), so the
// Garage layout fills up with dead entries over time. On each reconcile we:
//
//  1. Query the layout via the appropriate admin API (local for unified clusters,
//     remote for edge gateways).
//  2. Filter entries to those carrying the `tier:gateway` ownership tag for this CR.
//  3. Cross-reference with the live gateway pods' current node IDs (via the same
//     admin API's GetClusterStatus).
//  4. Stage removal of entries whose ID is not currently running.
//
// When `layoutManagement.autoApply` is true the removal is staged AND applied.
// Otherwise we stage and surface pending removals via the GatewayTombstones
// condition and PendingGatewayTombstones status field for human approval (via
// the existing force-layout-apply annotation).
func (r *GarageClusterReconciler) reconcileGatewayTombstones(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)
	if !cluster.HasGatewayTier() {
		return
	}

	// Determine which admin endpoint to query.
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
	var stale []string
	for _, role := range layout.Roles {
		// Match by ownership tag AND tier:gateway tag.
		ownsThis := false
		isGatewayTier := false
		for _, tag := range role.Tags {
			if tag == gatewayOwnershipTag {
				ownsThis = true
			}
			if tag == "tier:"+tierGateway {
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
		// Clear any pending-tombstones surfacing.
		if len(cluster.Status.PendingGatewayTombstones) > 0 {
			cluster.Status.PendingGatewayTombstones = nil
		}
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionGatewayTombstones)
		return
	}
	sort.Strings(stale)

	autoApply := cluster.Spec.LayoutManagement != nil && cluster.Spec.LayoutManagement.AutoApply
	if !autoApply {
		// Surface stale entries but don't apply.
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

	// AutoApply: stage and apply removal.
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

	// Skip-dead-nodes on the freshly applied layout — these gateway IDs are dead by
	// definition (we removed them because no pod still owns them).
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
		// Layout lives locally.
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

	// Edge gateway: layout lives on a remote storage cluster.
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
