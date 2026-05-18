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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// v1beta2AnnotationGatewayTierPresent is added to a v1beta1 view of a
// v1beta2 CR when the v1beta2 CR has BOTH spec.storage AND spec.gateway set —
// the v1beta1 shape cannot represent both tiers in one CR, so the gateway tier
// is elided from the output. Clients writing v1beta1 should not assume the
// gateway tier has been removed; they must read v1beta2 to manage it.
const v1beta2AnnotationGatewayTierPresent = "garage.rajsingh.info/v1beta2-only"

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

	dst.Spec = v1beta2.GarageClusterSpec{
		Image:              src.Spec.Image,
		ImageRepository:    src.Spec.ImageRepository,
		ImagePullPolicy:    src.Spec.ImagePullPolicy,
		ImagePullSecrets:   src.Spec.ImagePullSecrets,
		ServiceAccountName: src.Spec.ServiceAccountName,
		Zone:               src.Spec.Zone,
		LayoutPolicy:       src.Spec.LayoutPolicy,
		DefaultNodeTags:    src.Spec.DefaultNodeTags,
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

	if src.Spec.Gateway {
		dst.Spec.Gateway = &v1beta2.GatewaySpec{
			Replicas:    src.Spec.Replicas,
			PodTemplate: podTemplate,
		}
		// Edge gateways (gateway=true) under v1beta1 always require connectTo to be set
		// (validated by the v1beta1 webhook), so dst.Spec.ConnectTo is already populated.
	} else {
		storage := &v1beta2.StorageSpec{
			Replicas:                     src.Spec.Replicas,
			PodTemplate:                  podTemplate,
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
			CapacityReservePercent:       src.Spec.CapacityReservePercent,
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

	return nil
}

// ConvertFrom converts a v1beta2 GarageCluster (hub) into this v1beta1 form.
//
// This is necessarily lossy when v1beta2 has BOTH spec.storage and spec.gateway
// set: v1beta1 cannot represent both tiers in one CR. In that case we render
// the v1beta1 form as a storage cluster (storage tier becomes spec.storage and
// spec.replicas), and annotate the object with
// `garage.rajsingh.info/v1beta2-only=gateway-tier-present` so external tooling
// knows the gateway tier was elided.
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

	dst.Spec = GarageClusterSpec{
		Image:              src.Spec.Image,
		ImageRepository:    src.Spec.ImageRepository,
		ImagePullPolicy:    src.Spec.ImagePullPolicy,
		ImagePullSecrets:   src.Spec.ImagePullSecrets,
		ServiceAccountName: src.Spec.ServiceAccountName,
		Zone:               src.Spec.Zone,
		LayoutPolicy:       src.Spec.LayoutPolicy,
		DefaultNodeTags:    src.Spec.DefaultNodeTags,
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
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
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
		// Gateway-only edge: storage stays zero; ConnectTo (already copied) carries the link.
	case hasStorage && hasGateway:
		// Lossy: v1beta1 can't represent both tiers. Emit storage form and mark the
		// object so consumers know data was elided.
		dst.Spec.Gateway = false
		dst.Spec.Replicas = src.Spec.Storage.Replicas
		dst.Spec.Storage = StorageConfig{
			MetadataSnapshotsDir:         src.Spec.Storage.MetadataSnapshotsDir,
			MetadataAutoSnapshotInterval: src.Spec.Storage.MetadataAutoSnapshotInterval,
			MetadataFsync:                src.Spec.Storage.MetadataFsync,
			DataFsync:                    src.Spec.Storage.DataFsync,
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
		if dst.Annotations == nil {
			dst.Annotations = map[string]string{}
		}
		dst.Annotations[v1beta2AnnotationGatewayTierPresent] = "gateway-tier-present"
	}

	return nil
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

// ensure corev1 import is referenced (some tooling drops unused imports).
var _ = corev1.PodSpec{}
