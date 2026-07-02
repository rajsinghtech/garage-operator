/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

// HasStorageTier returns true when the cluster declares a storage tier
// (StatefulSet + PVCs are reconciled).
func (g *GarageCluster) HasStorageTier() bool {
	return g != nil && g.Spec.Storage != nil
}

// HasGatewayTier returns true when the cluster declares a gateway tier
// (Deployment + EmptyDir is reconciled).
func (g *GarageCluster) HasGatewayTier() bool {
	return g != nil && g.Spec.Gateway != nil
}

// EffectiveStorageLayoutPolicy returns the layout policy governing the STORAGE
// tier: spec.storage.layoutPolicy when set, otherwise the cluster-level
// spec.layoutPolicy. This lets a cluster hand-manage storage GarageNodes
// (Manual) while the gateway tier follows the cluster policy (e.g. stays Auto).
func (g *GarageCluster) EffectiveStorageLayoutPolicy() string {
	if g == nil {
		return ""
	}
	if g.Spec.Storage != nil && g.Spec.Storage.LayoutPolicy != "" {
		return g.Spec.Storage.LayoutPolicy
	}
	return g.Spec.LayoutPolicy
}

// IsManagementHandle returns true when this cluster is a pure connection handle
// to an external Garage cluster: only spec.connectTo is set, with neither a
// storage nor a gateway tier. The operator reconciles no workload for such a CR;
// it only manages Admin-API state (buckets, keys, layout) against the endpoint
// resolved from spec.connectTo. See issue #269.
func (g *GarageCluster) IsManagementHandle() bool {
	return g != nil && g.Spec.Storage == nil && g.Spec.Gateway == nil && g.Spec.ConnectTo != nil
}

// IsEdgeGateway returns true when this cluster is a gateway-only cluster that
// connects to a remote storage cluster (no local storage tier, but `connectTo`
// references an external Garage cluster).
func (g *GarageCluster) IsEdgeGateway() bool {
	if g == nil {
		return false
	}
	return g.Spec.Storage == nil && g.Spec.Gateway != nil && g.Spec.ConnectTo != nil
}

// StorageReplicas returns the desired storage-tier replica count, or zero
// when there is no storage tier.
func (g *GarageCluster) StorageReplicas() int32 {
	if !g.HasStorageTier() {
		return 0
	}
	return g.Spec.Storage.Replicas
}

// GatewayReplicas returns the desired gateway-tier replica count, or zero
// when there is no gateway tier.
func (g *GarageCluster) GatewayReplicas() int32 {
	if !g.HasGatewayTier() {
		return 0
	}
	return g.Spec.Gateway.Replicas
}

// TotalReplicas returns the sum of storage and gateway replicas.
func (g *GarageCluster) TotalReplicas() int32 {
	return g.StorageReplicas() + g.GatewayReplicas()
}
