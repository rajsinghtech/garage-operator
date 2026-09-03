/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// v1beta2AnnotationGatewayTierPresent is added to a v1beta1 view of a
// v1beta2 CR when the v1beta2 CR has BOTH spec.storage AND spec.gateway set —
// the v1beta1 shape cannot represent both tiers in one CR, so the gateway tier
// is elided from the output. Clients writing v1beta1 should not assume the
// gateway tier has been removed; they must read v1beta2 to manage it.
const v1beta2AnnotationGatewayTierPresent = "garage.rajsingh.info/v1beta2-only"

// v1beta2AnnotationNodeLocalPoolsPresent is the
// v1beta2AnnotationGatewayTierPresent value (or comma-separated component)
// marking a v1beta1 view whose v1beta2-only additive node-local pools are
// preserved in a transport annotation.
const v1beta2AnnotationNodeLocalPoolsPresent = "node-local-pools-present"

// v1beta2AnnotationNodeLocalPoolsData carries only the v1beta2-only
// nodeLocalPools list through a v1beta1 read/write. The default StatefulSet/PVC group
// remains directly editable through v1beta1; this payload prevents a legacy
// client from silently deleting node-local pools it cannot represent.
const v1beta2AnnotationNodeLocalPoolsData = "garage.rajsingh.info/v1beta2-node-local-pools"

const (
	v1beta2AnnotationGatewayTierComponent = "gateway-tier-present"
	v1beta2AnnotationGatewayTierData      = "garage.rajsingh.info/v1beta2-gateway-tier"
)

// ConvertTo converts this v1beta1 GarageCluster to the v1beta2 hub.
//
// Mapping:
//
//	spec.gateway==false              -> v1beta2.spec.storage{replicas, metadata, data, podTemplate=top-level scheduling fields}
//	spec.gateway==true + connectTo   -> v1beta2.spec.gateway{replicas, podTemplate=top-level scheduling fields} + spec.connectTo
//	spec.replicas                    -> storage.replicas (storage mode) or gateway.replicas (gateway mode)
//	top-level resources/nodeSelector -> podTemplate.* of whichever tier is active
//	everything else (network/s3Api/k2vApi/webApi/admin/discovery/security/logging/zone/replication/...) -> identical copy
//
// The v1beta1 webhook ensures gateway=true implies connectTo is set, so this
// is a lossless conversion for every CR that v1beta1's validation lets through.
func (src *GarageCluster) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*v1beta2.GarageCluster)
	if !ok {
		return fmt.Errorf("ConvertTo: unexpected hub type %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	if err := copyViaJSON(&src.Status, &dst.Status); err != nil {
		return fmt.Errorf("convert status: %w", err)
	}
	if dst.Status.StorageDrain != nil {
		if dst.Status.StorageDrain.RoleRemovalNodeIDs == nil {
			dst.Status.StorageDrain.RoleRemovalNodeIDs = []string{}
		}
		if dst.Status.StorageDrain.RemovedStorageNodeIDs == nil {
			dst.Status.StorageDrain.RemovedStorageNodeIDs = []string{}
		}
	}

	dst.Spec = v1beta2.GarageClusterSpec{
		Image:              src.Spec.Image,
		ImageRepository:    src.Spec.ImageRepository,
		ImagePullPolicy:    src.Spec.ImagePullPolicy,
		ImagePullSecrets:   src.Spec.ImagePullSecrets,
		ServiceAccountName: src.Spec.ServiceAccountName,
		Zone:               src.Spec.Zone,
		LayoutPolicy:       src.Spec.LayoutPolicy,
		DeletionPolicy:     v1beta2.DeletionPolicy(src.Spec.DeletionPolicy),
		DefaultNodeTags:    src.Spec.DefaultNodeTags,
	}
	if src.Spec.ZoneFrom != nil {
		dst.Spec.ZoneFrom = &v1beta2.ZoneSource{NodeLabel: src.Spec.ZoneFrom.NodeLabel}
	}

	if err := copyJSON(src.Spec.Replication, &dst.Spec.Replication); err != nil {
		return err
	}
	if err := copyJSON(&src.Spec.Network, &dst.Spec.Network); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.S3API, &dst.Spec.S3API); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.K2VAPI, &dst.Spec.K2VAPI); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.WebAPI, &dst.Spec.WebAPI); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Admin, &dst.Spec.Admin); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Database, &dst.Spec.Database); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Blocks, &dst.Spec.Blocks); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Discovery, &dst.Spec.Discovery); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Security, &dst.Spec.Security); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Logging, &dst.Spec.Logging); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.PublicEndpoint, &dst.Spec.PublicEndpoint); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.RemoteClusters, &dst.Spec.RemoteClusters); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.LayoutManagement, &dst.Spec.LayoutManagement); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Monitoring, &dst.Spec.Monitoring); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Maintenance, &dst.Spec.Maintenance); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Workers, &dst.Spec.Workers); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.ConnectTo, &dst.Spec.ConnectTo); err != nil {
		return err
	}

	podTemplate := v1beta2.PodTemplate{
		Resources:                 src.Spec.Resources,
		NodeSelector:              src.Spec.NodeSelector,
		Tolerations:               src.Spec.Tolerations,
		Affinity:                  src.Spec.Affinity,
		TopologySpreadConstraints: src.Spec.TopologySpreadConstraints,
		PodAnnotations:            src.Spec.PodAnnotations,
		PodLabels:                 src.Spec.PodLabels,
		PriorityClassName:         src.Spec.PriorityClassName,
		SecurityContext:           src.Spec.SecurityContext,
		ContainerSecurityContext:  src.Spec.ContainerSecurityContext,
	}

	switch {
	case src.isManagementHandle():
		// Management handle (#269): connectTo only, no tiers. Leave both
		// dst.Spec.Storage and dst.Spec.Gateway nil so v1beta2 sees a handle
		// (dst.Spec.ConnectTo is already populated above).
	case src.Spec.Gateway:
		dst.Spec.Gateway = &v1beta2.GatewaySpec{
			Replicas:            src.Spec.Replicas,
			PodDisruptionBudget: v1Beta1PodDisruptionBudgetToV2(src.Spec.PodDisruptionBudget),
			PodTemplate:         podTemplate,
		}
		if err := copyJSON(src.Spec.Storage.Metadata, &dst.Spec.Gateway.Metadata); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.PVCRetentionPolicy, &dst.Spec.Gateway.PVCRetentionPolicy); err != nil {
			return err
		}
		// Edge gateways (gateway=true) under v1beta1 always require connectTo to be set
		// (validated by the v1beta1 webhook), so dst.Spec.ConnectTo is already populated.
	default:
		storage := &v1beta2.StorageSpec{
			Replicas:                     src.Spec.Replicas,
			PodTemplate:                  podTemplate,
			RPCPublicAddr:                src.Spec.Storage.RPCPublicAddr,
			LayoutPolicy:                 src.Spec.Storage.LayoutPolicy,
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
			CapacityReservePercent:       src.Spec.CapacityReservePercent,
			DataSourceRef:                src.Spec.Storage.DataSourceRef,
			AllowDataSourceRef:           src.Spec.Storage.AllowDataSourceRef,
		}
		storage.Env = append(storage.Env, src.Spec.Storage.Env...)
		if src.Spec.Storage.EnvFrom != nil {
			storage.EnvFrom = src.Spec.Storage.EnvFrom
		}
		if err := copyJSON(src.Spec.Storage.Metadata, &storage.Metadata); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.Data, &storage.Data); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.PVCRetentionPolicy, &storage.PVCRetentionPolicy); err != nil {
			return err
		}
		// Move PodDisruptionBudget into the storage tier (v1beta2 owns it there).
		if src.Spec.PodDisruptionBudget != nil {
			if err := copyJSON(src.Spec.PodDisruptionBudget, &storage.PodDisruptionBudget); err != nil {
				return err
			}
		}
		dst.Spec.Storage = storage
	}

	if err := src.restoreNodeLocalPools(dst); err != nil {
		return err
	}
	return src.restoreGatewayTier(dst)
}

// ConvertFrom converts a v1beta2 GarageCluster (hub) into this v1beta1 form.
//
// When v1beta2 has BOTH spec.storage and spec.gateway set, v1beta1 cannot
// represent both tiers directly. We render the editable v1beta1 form as a
// storage cluster and carry the complete gateway tier in reserved conversion
// annotations. A v1beta1 read/write therefore round-trips the unified shape
// without allowing the legacy client to mutate fields it cannot represent.
//
// All other shapes round-trip losslessly:
//
//	storage-only -> spec.gateway=false, storage fields populated
//	gateway-only (with connectTo) -> spec.gateway=true, spec.replicas from gateway tier
func (dst *GarageCluster) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*v1beta2.GarageCluster)
	if !ok {
		return fmt.Errorf("ConvertFrom: unexpected hub type %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	if err := copyViaJSON(&src.Status, &dst.Status); err != nil {
		return fmt.Errorf("convert status: %w", err)
	}
	if dst.Status.StorageDrain != nil {
		if dst.Status.StorageDrain.RoleRemovalNodeIDs == nil {
			dst.Status.StorageDrain.RoleRemovalNodeIDs = []string{}
		}
		if dst.Status.StorageDrain.RemovedStorageNodeIDs == nil {
			dst.Status.StorageDrain.RemovedStorageNodeIDs = []string{}
		}
	}

	dst.Spec = GarageClusterSpec{
		Image:              src.Spec.Image,
		ImageRepository:    src.Spec.ImageRepository,
		ImagePullPolicy:    src.Spec.ImagePullPolicy,
		ImagePullSecrets:   src.Spec.ImagePullSecrets,
		ServiceAccountName: src.Spec.ServiceAccountName,
		Zone:               src.Spec.Zone,
		LayoutPolicy:       src.Spec.LayoutPolicy,
		DeletionPolicy:     DeletionPolicy(src.Spec.DeletionPolicy),
		DefaultNodeTags:    src.Spec.DefaultNodeTags,
	}
	if src.Spec.ZoneFrom != nil {
		dst.Spec.ZoneFrom = &ZoneSource{NodeLabel: src.Spec.ZoneFrom.NodeLabel}
	}
	if src.Spec.Storage != nil {
		dst.Spec.CapacityReservePercent = src.Spec.Storage.CapacityReservePercent
	}

	if err := copyJSON(src.Spec.Replication, &dst.Spec.Replication); err != nil {
		return err
	}
	if err := copyJSON(&src.Spec.Network, &dst.Spec.Network); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.S3API, &dst.Spec.S3API); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.K2VAPI, &dst.Spec.K2VAPI); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.WebAPI, &dst.Spec.WebAPI); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Admin, &dst.Spec.Admin); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Database, &dst.Spec.Database); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Blocks, &dst.Spec.Blocks); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Discovery, &dst.Spec.Discovery); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Security, &dst.Spec.Security); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Logging, &dst.Spec.Logging); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.PublicEndpoint, &dst.Spec.PublicEndpoint); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.RemoteClusters, &dst.Spec.RemoteClusters); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.LayoutManagement, &dst.Spec.LayoutManagement); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Monitoring, &dst.Spec.Monitoring); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Maintenance, &dst.Spec.Maintenance); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.Workers, &dst.Spec.Workers); err != nil {
		return err
	}
	if err := copyJSON(src.Spec.ConnectTo, &dst.Spec.ConnectTo); err != nil {
		return err
	}

	hasStorage := src.Spec.Storage != nil
	hasGateway := src.Spec.Gateway != nil

	// Choose tier source for top-level scheduling fields.
	// Prefer storage when present (the common case); fall back to gateway for
	// edge-gateway-only clusters.
	var tpl *v1beta2.PodTemplate
	switch {
	case hasStorage:
		tpl = &src.Spec.Storage.PodTemplate
	case hasGateway:
		tpl = &src.Spec.Gateway.PodTemplate
	}
	if tpl != nil {
		dst.Spec.Resources = tpl.Resources
		dst.Spec.NodeSelector = tpl.NodeSelector
		dst.Spec.Tolerations = tpl.Tolerations
		dst.Spec.Affinity = tpl.Affinity
		dst.Spec.TopologySpreadConstraints = tpl.TopologySpreadConstraints
		dst.Spec.PodAnnotations = tpl.PodAnnotations
		dst.Spec.PodLabels = tpl.PodLabels
		dst.Spec.PriorityClassName = tpl.PriorityClassName
		dst.Spec.SecurityContext = tpl.SecurityContext
		dst.Spec.ContainerSecurityContext = tpl.ContainerSecurityContext
	}

	switch {
	case hasStorage && !hasGateway:
		dst.Spec.Gateway = false
		dst.Spec.Replicas = src.Spec.Storage.Replicas
		dst.Spec.Storage = StorageConfig{
			RPCPublicAddr:                src.Spec.Storage.RPCPublicAddr,
			LayoutPolicy:                 src.Spec.Storage.LayoutPolicy,
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
			DataSourceRef:                src.Spec.Storage.DataSourceRef,
			AllowDataSourceRef:           src.Spec.Storage.AllowDataSourceRef,
			Env:                          src.Spec.Storage.Env,
			EnvFrom:                      src.Spec.Storage.EnvFrom,
		}
		if err := copyJSON(src.Spec.Storage.Metadata, &dst.Spec.Storage.Metadata); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.Data, &dst.Spec.Storage.Data); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.PVCRetentionPolicy, &dst.Spec.Storage.PVCRetentionPolicy); err != nil {
			return err
		}
		if src.Spec.Storage.PodDisruptionBudget != nil {
			if err := copyJSON(src.Spec.Storage.PodDisruptionBudget, &dst.Spec.PodDisruptionBudget); err != nil {
				return err
			}
		}
	case hasGateway && !hasStorage:
		dst.Spec.Gateway = true
		dst.Spec.Replicas = src.Spec.Gateway.Replicas
		if src.Spec.Gateway.PodDisruptionBudget != nil {
			if err := copyJSON(src.Spec.Gateway.PodDisruptionBudget, &dst.Spec.PodDisruptionBudget); err != nil {
				return err
			}
		}
		if err := copyJSON(src.Spec.Gateway.Metadata, &dst.Spec.Storage.Metadata); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Gateway.PVCRetentionPolicy, &dst.Spec.Storage.PVCRetentionPolicy); err != nil {
			return err
		}
		// Gateway-only edge: storage stays zero; ConnectTo (already copied) carries the link.
	case hasStorage && hasGateway:
		// v1beta1 cannot represent both tiers. Emit its editable storage form and
		// preserve the gateway payload below for a lossless hub round-trip.
		dst.Spec.Gateway = false
		dst.Spec.Replicas = src.Spec.Storage.Replicas
		dst.Spec.Storage = StorageConfig{
			RPCPublicAddr:                src.Spec.Storage.RPCPublicAddr,
			LayoutPolicy:                 src.Spec.Storage.LayoutPolicy,
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
			DataSourceRef:                src.Spec.Storage.DataSourceRef,
			AllowDataSourceRef:           src.Spec.Storage.AllowDataSourceRef,
			Env:                          src.Spec.Storage.Env,
			EnvFrom:                      src.Spec.Storage.EnvFrom,
		}
		if err := copyJSON(src.Spec.Storage.Metadata, &dst.Spec.Storage.Metadata); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.Data, &dst.Spec.Storage.Data); err != nil {
			return err
		}
		if err := copyJSON(src.Spec.Storage.PVCRetentionPolicy, &dst.Spec.Storage.PVCRetentionPolicy); err != nil {
			return err
		}
		if src.Spec.Storage.PodDisruptionBudget != nil {
			if err := copyJSON(src.Spec.Storage.PodDisruptionBudget, &dst.Spec.PodDisruptionBudget); err != nil {
				return err
			}
		}
	}

	// Unified clusters always need a payload because the whole gateway tier is
	// hidden by the editable v1beta1 storage projection. An edge gateway needs a
	// payload only when it actually uses v1beta2-only fields. Avoiding a reserved
	// annotation for the ordinary v1beta1-representable edge shape is important:
	// admission converts a v1beta1 CREATE to the hub and back, and must not
	// mistake its own round-trip annotation for a user-forged reserved payload.
	if hasStorage || gatewayTierRequiresV1Beta2Payload(src.Spec.Gateway, dst) {
		if err := dst.preserveGatewayTier(src); err != nil {
			return err
		}
	}
	// Additive node-local pools are v1beta2-only. Preserve only the list in an
	// annotation; the default StatefulSet/PVC group remains a normal, schema-valid
	// v1beta1 projection and may still be edited by legacy clients.
	return dst.preserveNodeLocalPools(src)
}

func gatewayTierRequiresV1Beta2Payload(gateway *v1beta2.GatewaySpec, view *GarageCluster) bool {
	if gateway == nil || view == nil {
		return false
	}
	projected := &v1beta2.GatewaySpec{
		Replicas:            view.Spec.Replicas,
		PodDisruptionBudget: v1Beta1PodDisruptionBudgetToV2(view.Spec.PodDisruptionBudget),
		PodTemplate: v1beta2.PodTemplate{
			Resources:                 view.Spec.Resources,
			NodeSelector:              view.Spec.NodeSelector,
			Tolerations:               view.Spec.Tolerations,
			Affinity:                  view.Spec.Affinity,
			TopologySpreadConstraints: view.Spec.TopologySpreadConstraints,
			PodAnnotations:            view.Spec.PodAnnotations,
			PodLabels:                 view.Spec.PodLabels,
			PriorityClassName:         view.Spec.PriorityClassName,
			SecurityContext:           view.Spec.SecurityContext,
			ContainerSecurityContext:  view.Spec.ContainerSecurityContext,
		},
	}
	if err := copyJSON(view.Spec.Storage.Metadata, &projected.Metadata); err != nil {
		// Known API structs should always marshal. Preserve the full payload on
		// any unexpected conversion error rather than risk a lossy projection.
		return true
	}
	if err := copyJSON(view.Spec.Storage.PVCRetentionPolicy, &projected.PVCRetentionPolicy); err != nil {
		return true
	}
	return !equality.Semantic.DeepEqual(gateway, projected)
}

func v1Beta1PodDisruptionBudgetToV2(src *PodDisruptionBudgetConfig) *v1beta2.PodDisruptionBudgetConfig {
	if src == nil {
		return nil
	}
	return &v1beta2.PodDisruptionBudgetConfig{
		Enabled:        src.Enabled,
		MinAvailable:   src.MinAvailable,
		MaxUnavailable: src.MaxUnavailable,
	}
}

func (dst *GarageCluster) preserveGatewayTier(src *v1beta2.GarageCluster) error {
	if src.Spec.Gateway == nil {
		return nil
	}
	if dst.Annotations == nil {
		dst.Annotations = map[string]string{}
	}
	data, err := json.Marshal(src.Spec.Gateway)
	if err != nil {
		return fmt.Errorf("preserve gateway tier in %s annotation: %w", v1beta2AnnotationGatewayTierData, err)
	}
	dst.Annotations[v1beta2AnnotationGatewayTierData] = string(data)
	dst.Annotations[v1beta2AnnotationGatewayTierPresent] = appendAnnotationComponent(
		dst.Annotations[v1beta2AnnotationGatewayTierPresent],
		v1beta2AnnotationGatewayTierComponent,
	)
	return nil
}

// preserveNodeLocalPools transports the v1beta2-only pool list through the
// v1beta1 view and stamps v1beta2-only (appending to any existing component,
// such as gateway-tier-present).
func (dst *GarageCluster) preserveNodeLocalPools(src *v1beta2.GarageCluster) error {
	if src.Spec.Storage == nil || len(src.Spec.Storage.NodeLocalPools) == 0 {
		return nil
	}
	if dst.Annotations == nil {
		dst.Annotations = map[string]string{}
	}
	data, err := json.Marshal(src.Spec.Storage.NodeLocalPools)
	if err != nil {
		return fmt.Errorf("preserve node-local pools in %s annotation: %w", v1beta2AnnotationNodeLocalPoolsData, err)
	}
	dst.Annotations[v1beta2AnnotationNodeLocalPoolsData] = string(data)
	dst.Annotations[v1beta2AnnotationGatewayTierPresent] = appendAnnotationComponent(
		dst.Annotations[v1beta2AnnotationGatewayTierPresent],
		v1beta2AnnotationNodeLocalPoolsPresent,
	)
	return nil
}

// restoreNodeLocalPools reconstructs the v1beta2-only additive pool list after
// a v1beta1 client writes back an object produced by ConvertFrom.
func (src *GarageCluster) restoreNodeLocalPools(dst *v1beta2.GarageCluster) error {
	if src.Annotations == nil {
		return nil
	}
	raw := src.Annotations[v1beta2AnnotationNodeLocalPoolsData]
	if raw == "" {
		return nil
	}

	var preserved []v1beta2.NodeLocalPoolSpec
	if err := json.Unmarshal([]byte(raw), &preserved); err != nil {
		return fmt.Errorf("restore node-local pools from %s annotation: %w", v1beta2AnnotationNodeLocalPoolsData, err)
	}
	if dst.Spec.Storage == nil {
		return fmt.Errorf("restore node-local pools from %s annotation: v1beta1 view no longer contains a storage tier", v1beta2AnnotationNodeLocalPoolsData)
	}
	dst.Spec.Storage.NodeLocalPools = preserved

	// The preservation payload is a conversion transport detail, not durable
	// hub state. ConvertFrom recreates it whenever a v1beta1 view is requested.
	delete(dst.Annotations, v1beta2AnnotationNodeLocalPoolsData)
	remaining := removeAnnotationComponent(
		dst.Annotations[v1beta2AnnotationGatewayTierPresent],
		v1beta2AnnotationNodeLocalPoolsPresent,
	)
	if remaining == "" {
		delete(dst.Annotations, v1beta2AnnotationGatewayTierPresent)
	} else {
		dst.Annotations[v1beta2AnnotationGatewayTierPresent] = remaining
	}
	return nil
}

// restoreGatewayTier makes the otherwise lossy unified v1beta2→v1beta1
// projection round-trip safe. The v1beta1 storage fields remain editable while
// the complete v1beta2 gateway tier is carried as a reserved payload.
func (src *GarageCluster) restoreGatewayTier(dst *v1beta2.GarageCluster) error {
	if src.Annotations == nil {
		return nil
	}
	raw := src.Annotations[v1beta2AnnotationGatewayTierData]
	if raw == "" {
		return nil
	}
	var gateway v1beta2.GatewaySpec
	if err := json.Unmarshal([]byte(raw), &gateway); err != nil {
		return fmt.Errorf("restore gateway tier from %s annotation: %w", v1beta2AnnotationGatewayTierData, err)
	}
	if src.Spec.Gateway {
		// Merge the fields v1beta1 can represent over the preserved full gateway
		// object. Do not replace the embedded PodTemplate wholesale: Env/EnvFrom
		// exist only in v1beta2 and must survive a legacy read/write.
		gateway.Replicas = src.Spec.Replicas
		gateway.Resources = src.Spec.Resources
		gateway.NodeSelector = src.Spec.NodeSelector
		gateway.Tolerations = src.Spec.Tolerations
		gateway.Affinity = src.Spec.Affinity
		gateway.TopologySpreadConstraints = src.Spec.TopologySpreadConstraints
		gateway.PodAnnotations = src.Spec.PodAnnotations
		gateway.PodLabels = src.Spec.PodLabels
		gateway.PriorityClassName = src.Spec.PriorityClassName
		gateway.SecurityContext = src.Spec.SecurityContext
		gateway.ContainerSecurityContext = src.Spec.ContainerSecurityContext
		gateway.PodDisruptionBudget = v1Beta1PodDisruptionBudgetToV2(src.Spec.PodDisruptionBudget)
		if err := copyJSON(src.Spec.Storage.Metadata, &gateway.Metadata); err != nil {
			return fmt.Errorf("restore editable v1beta1 gateway metadata: %w", err)
		}
		if err := copyJSON(src.Spec.Storage.PVCRetentionPolicy, &gateway.PVCRetentionPolicy); err != nil {
			return fmt.Errorf("restore editable v1beta1 gateway PVC retention policy: %w", err)
		}
	} else if dst.Spec.Storage == nil {
		return fmt.Errorf("restore gateway tier from %s annotation: v1beta1 view contains neither an edge gateway nor unified storage tier", v1beta2AnnotationGatewayTierData)
	}
	dst.Spec.Gateway = &gateway
	delete(dst.Annotations, v1beta2AnnotationGatewayTierData)
	remaining := removeAnnotationComponent(
		dst.Annotations[v1beta2AnnotationGatewayTierPresent],
		v1beta2AnnotationGatewayTierComponent,
	)
	if remaining == "" {
		delete(dst.Annotations, v1beta2AnnotationGatewayTierPresent)
	} else {
		dst.Annotations[v1beta2AnnotationGatewayTierPresent] = remaining
	}
	return nil
}

func appendAnnotationComponent(current, component string) string {
	for _, existing := range strings.Split(current, ",") {
		if existing == component {
			return current
		}
	}
	if current == "" {
		return component
	}
	return current + "," + component
}

func removeAnnotationComponent(current, component string) string {
	kept := make([]string, 0)
	for _, existing := range strings.Split(current, ",") {
		if existing != "" && existing != component {
			kept = append(kept, existing)
		}
	}
	return strings.Join(kept, ",")
}

// copyJSON copies src into dst (a pointer) by JSON round-trip. Returns nil and
// leaves dst unset when src is a nil pointer / nil interface.
func copyJSON(src, dst interface{}) error {
	if src == nil {
		return nil
	}
	// Detect a typed nil pointer like (*SomeType)(nil) without reflection by
	// marshaling: JSON null indicates a nil pointer.
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	if string(b) == "null" {
		return nil
	}
	return json.Unmarshal(b, dst)
}

// copyViaJSON copies src into dst (a pointer) always (used for status structs
// where dst is a value type).
func copyViaJSON(src, dst interface{}) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}
