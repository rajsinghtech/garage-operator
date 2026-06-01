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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// autoModeGatewayNodeName returns the canonical name for an operator-generated
// gateway GarageNode in Auto mode for a given gateway-tier ordinal. Mirrors the
// storage-tier convention (<cluster>-storage-<N>) so tooling and tags stay
// symmetric across tiers.
func autoModeGatewayNodeName(clusterName string, ordinal int32) string {
	return fmt.Sprintf("%s-gateway-%d", clusterName, ordinal)
}

// reconcileAutoModeGatewayNodes generates and reconciles one gateway GarageNode
// CR per gateway replica when the cluster is in Auto mode with a UNIFIED
// (storage + gateway) topology. Each GarageNode owns its own single-replica
// StatefulSet via the GarageNode controller, which assigns it a capacity=nil
// layout role — making key_table/bucket_table full-replicated locally so the S3
// sig-auth get_local() path resolves keys without a per-request quorum RPC to the
// storage tier (and keeps the gateway authenticating even while storage is
// degraded). This is the fix for the unified-cluster gateway gap (#209).
//
// Edge gateways (gateway-only clusters with spec.connectTo) are NOT handled here
// — their layout lives on a remote storage cluster and is managed by the
// cluster-level gateway connection path. Only unified clusters reach this code.
func (r *GarageClusterReconciler) reconcileAutoModeGatewayNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	if !cluster.HasGatewayTier() || !cluster.HasStorageTier() {
		return nil
	}

	desiredReplicas := cluster.GatewayReplicas()

	existing, err := r.listAutoModeGatewayNodes(ctx, cluster)
	if err != nil {
		return fmt.Errorf("listing operator-owned gateway GarageNodes: %w", err)
	}

	desiredByName := make(map[string]bool, desiredReplicas)
	for i := int32(0); i < desiredReplicas; i++ {
		desiredByName[autoModeGatewayNodeName(cluster.Name, i)] = true

		desired, err := r.buildAutoModeGatewayNode(cluster, i, "")
		if err != nil {
			return fmt.Errorf("building desired gateway GarageNode for ordinal %d: %w", i, err)
		}

		current, found := existing[desired.Name]
		if !found {
			log.Info("Creating Auto-mode gateway GarageNode", "name", desired.Name)
			if err := r.Create(ctx, desired); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("creating gateway GarageNode %s: %w", desired.Name, err)
			}
			continue
		}

		if autoModeGatewayNodeNeedsUpdate(current, desired) {
			log.Info("Updating Auto-mode gateway GarageNode (drift detected)", "name", desired.Name)
			current.Spec.Zone = desired.Spec.Zone
			current.Spec.Tags = desired.Spec.Tags
			current.Spec.Network = desired.Spec.Network
			if current.Spec.Storage == nil {
				current.Spec.Storage = desired.Spec.Storage
			} else if desired.Spec.Storage != nil && desired.Spec.Storage.Metadata != nil {
				if current.Spec.Storage.Metadata == nil {
					current.Spec.Storage.Metadata = desired.Spec.Storage.Metadata
				} else if current.Spec.Storage.Metadata.ExistingClaim == "" {
					current.Spec.Storage.Metadata.Size = desired.Spec.Storage.Metadata.Size
					current.Spec.Storage.Metadata.StorageClassName = desired.Spec.Storage.Metadata.StorageClassName
				}
			}
			if err := r.Update(ctx, current); err != nil {
				return fmt.Errorf("updating gateway GarageNode %s: %w", current.Name, err)
			}
		}
	}

	for name, n := range existing {
		if desiredByName[name] {
			continue
		}
		log.Info("Deleting Auto-mode gateway GarageNode (scale-down)", "name", name)
		if err := r.Delete(ctx, n); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting gateway GarageNode %s: %w", name, err)
		}
	}

	return nil
}

// listAutoModeGatewayNodes returns operator-owned gateway GarageNodes for this
// cluster, keyed by name.
func (r *GarageClusterReconciler) listAutoModeGatewayNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) (map[string]*garagev1beta1.GarageNode, error) {
	nodeList := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodeList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      cluster.Name,
			labelTier:         tierGateway,
			labelAppManagedBy: managedByOperatorValue,
		}),
	); err != nil {
		return nil, err
	}
	out := make(map[string]*garagev1beta1.GarageNode, len(nodeList.Items))
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		out[n.Name] = n
	}
	return out, nil
}

// buildAutoModeGatewayNode constructs the desired gateway GarageNode for an
// ordinal. Gateway nodes carry capacity=nil (gateway role), a small metadata PVC
// for persistent identity, and EmptyDir data (no object blocks). The gateway's
// own rpc_public_addr, when set, flows through spec.network so the node never
// inherits the storage tier's address.
//
// When adoptedMetadataPVC is non-empty the node binds that existing metadata PVC
// (legacy-STS gateway migration) so Garage's node_key — and thus node identity —
// survives the v0.6.6 upgrade from a cluster-level gateway STS to per-node
// GarageNodes. Otherwise a fresh metadata PVC is provisioned via the per-node
// StatefulSet's volumeClaimTemplate.
func (r *GarageClusterReconciler) buildAutoModeGatewayNode(cluster *garagev1beta2.GarageCluster, ordinal int32, adoptedMetadataPVC string) (*garagev1beta1.GarageNode, error) {
	name := autoModeGatewayNodeName(cluster.Name, ordinal)

	zone := cluster.Spec.Zone
	if zone == "" {
		zone = defaultZoneName
	}

	podName := fmt.Sprintf("%s-%d", name, 0)
	tags := buildNodeTags(cluster.Name, cluster.Namespace, tierGateway, cluster.Spec.DefaultNodeTags, podName)

	var storage *garagev1beta1.NodeStorageConfig
	if adoptedMetadataPVC != "" {
		// Migration: bind the legacy cluster-level gateway STS's metadata PVC by
		// name. The node_key under metadata_dir is what determines the node ID, so
		// adopting the PVC keeps the gateway's identity stable across the upgrade.
		storage = &garagev1beta1.NodeStorageConfig{
			Metadata: &garagev1beta1.NodeVolumeConfig{ExistingClaim: adoptedMetadataPVC},
		}
	} else {
		// Metadata PVC sizing: gateway.metadata.size when set, else the 1Gi default.
		metaSize := gatewayDefaultMetadataSize
		var metaSC *string
		if gw := cluster.Spec.Gateway; gw != nil && gw.Metadata != nil {
			if gw.Metadata.Size != nil && !gw.Metadata.Size.IsZero() {
				metaSize = *gw.Metadata.Size
			}
			metaSC = gw.Metadata.StorageClassName
		}
		mSize := metaSize.DeepCopy()
		storage = &garagev1beta1.NodeStorageConfig{
			Metadata: &garagev1beta1.NodeVolumeConfig{
				Size:             &mSize,
				StorageClassName: metaSC,
			},
		}
	}

	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierGateway,
				labelAppManagedBy: managedByOperatorValue,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Zone:       zone,
			Gateway:    true,
			Tags:       tags,
			Storage:    storage,
		},
	}

	// Carry the gateway tier's rpc_public_addr (if any) onto the node so the
	// per-node ConfigMap advertises it. Even when empty, gateway nodes get a
	// dedicated ConfigMap (nodeHasConfigOverrides returns true for gateways) so
	// they never inherit the storage tier's rpc_public_addr.
	if gw := cluster.Spec.Gateway; gw != nil && gw.RPCPublicAddr != "" {
		node.Spec.Network = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: gw.RPCPublicAddr}
	}

	if err := controllerutil.SetControllerReference(cluster, node, r.Scheme); err != nil {
		return nil, err
	}

	return node, nil
}

// autoModeGatewayNodeNeedsUpdate reports whether the desired gateway GarageNode
// differs from the current one on a field the operator owns.
func autoModeGatewayNodeNeedsUpdate(current, desired *garagev1beta1.GarageNode) bool {
	if current.Spec.Zone != desired.Spec.Zone {
		return true
	}
	if !tagSetEqual(current.Spec.Tags, desired.Spec.Tags) {
		return true
	}
	cn, dn := current.Spec.Network, desired.Spec.Network
	if (cn == nil) != (dn == nil) {
		return true
	}
	if cn != nil && dn != nil && cn.RPCPublicAddr != dn.RPCPublicAddr {
		return true
	}
	// Metadata size drift (only when not pinned to an existingClaim).
	if cs, ds := current.Spec.Storage, desired.Spec.Storage; cs != nil && ds != nil {
		if cm, dm := cs.Metadata, ds.Metadata; cm != nil && dm != nil && cm.ExistingClaim == "" {
			if (cm.Size == nil) != (dm.Size == nil) {
				return true
			}
			if cm.Size != nil && dm.Size != nil && cm.Size.Cmp(*dm.Size) != 0 {
				return true
			}
		}
	}
	return false
}

// deleteAutoModeGatewayNodes deletes all operator-owned gateway GarageNodes for
// this cluster. Used when the gateway tier is removed entirely or the cluster
// stops being unified (e.g. storage tier dropped).
func (r *GarageClusterReconciler) deleteAutoModeGatewayNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	existing, err := r.listAutoModeGatewayNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range existing {
		log.Info("Deleting Auto-mode gateway GarageNode (gateway tier removed)", "name", name)
		if err := r.Delete(ctx, n); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting gateway GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// ejectAutoModeGatewayNodes drops the operator's controllerOwnerRef and managed-by
// label from each operator-owned gateway GarageNode (Auto→Manual hand-off),
// mirroring ejectAutoModeStorageNodes.
func (r *GarageClusterReconciler) ejectAutoModeGatewayNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	existing, err := r.listAutoModeGatewayNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range existing {
		newOwners := n.OwnerReferences[:0]
		for _, ref := range n.OwnerReferences {
			if ref.UID == cluster.UID {
				continue
			}
			newOwners = append(newOwners, ref)
		}
		n.OwnerReferences = newOwners
		delete(n.Labels, labelAppManagedBy)

		log.Info("Ejecting Auto-mode gateway GarageNode (Auto→Manual)", "name", name)
		if err := r.Update(ctx, n); err != nil {
			return fmt.Errorf("ejecting gateway GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// migrateLegacyGatewaySTSIfNeeded adopts the metadata PVCs of a pre-#210
// cluster-level gateway StatefulSet (`<cr>-gateway`) into per-node gateway
// GarageNodes before that STS is removed, so the Ed25519 node_key Garage stores
// under metadata_dir — and therefore the gateway node identity — survives the
// upgrade. Without this, deleteGatewayStatefulSet cascade-deletes the old STS
// whose PVC retention policy is WhenDeleted:Delete, the STS GC reaps the
// metadata PVCs, and reconcileAutoModeGatewayNodes provisions fresh PVCs with
// brand-new node IDs (the #221 v0.6.6-upgrade identity loss).
//
// Only runs for UNIFIED clusters (storage + gateway). Idempotent: once the old
// STS is gone there is nothing to adopt and this is a no-op. Edge gateways keep
// their cluster-level STS, so this never touches them.
func (r *GarageClusterReconciler) migrateLegacyGatewaySTSIfNeeded(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	if !cluster.HasGatewayTier() || !cluster.HasStorageTier() {
		return nil
	}

	name := gatewayWorkloadName(cluster) // <cr>-gateway
	legacySTS := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, legacySTS); err != nil {
		if errors.IsNotFound(err) {
			return nil // already migrated / never existed
		}
		return fmt.Errorf("checking for legacy gateway StatefulSet: %w", err)
	}

	replicas := int32(0)
	if legacySTS.Spec.Replicas != nil {
		replicas = *legacySTS.Spec.Replicas
	}

	// Adopt each replica's metadata PVC into a per-node gateway GarageNode. The
	// legacy STS named its metadata volumeClaimTemplate `metadata`, so the PVCs
	// are `metadata-<cr>-gateway-<ord>`. The per-node node is `<cr>-gateway-<ord>`.
	for ord := int32(0); ord < replicas; ord++ {
		legacyPVC := fmt.Sprintf("%s-%s-%d", metadataVolName, name, ord)

		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: legacyPVC, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				// Nothing to adopt for this ordinal (already cleaned up, or the
				// gateway never had persistent metadata). Skip — a fresh node is
				// created by reconcileAutoModeGatewayNodes.
				continue
			}
			return fmt.Errorf("get legacy gateway metadata PVC %q: %w", legacyPVC, err)
		}

		// Strip the old STS's controllerRef off the PVC so the orphan-delete below
		// (and the STS GC) cannot reap it. Mirrors the intent of the storage
		// migration's orphan delete, which leaves PVCs controllerRef-free.
		if stripStatefulSetOwnerRef(pvc, legacySTS.UID) {
			if err := r.Update(ctx, pvc); err != nil {
				return fmt.Errorf("detaching legacy STS ownerRef from PVC %q: %w", legacyPVC, err)
			}
		}

		desired, err := r.buildAutoModeGatewayNode(cluster, ord, legacyPVC)
		if err != nil {
			return fmt.Errorf("building migrated gateway GarageNode for ordinal %d: %w", ord, err)
		}

		existing := &garagev1beta1.GarageNode{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing); err == nil {
			log.Info("Gateway migration: GarageNode already exists, leaving in place", "name", desired.Name)
		} else if errors.IsNotFound(err) {
			log.Info("Gateway migration: creating GarageNode bound to legacy metadata PVC", "name", desired.Name, "metadataPVC", legacyPVC)
			if createErr := r.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
				return fmt.Errorf("gateway migration: creating GarageNode %s: %w", desired.Name, createErr)
			}
		} else {
			return fmt.Errorf("gateway migration: checking for existing GarageNode %s: %w", desired.Name, err)
		}
	}

	// Orphan-delete the legacy STS so its metadata PVCs survive for the new
	// per-node STSes to adopt via existingClaim. Cascade (the default) would
	// reap them via the WhenDeleted:Delete retention policy.
	log.Info("Gateway migration: orphan-deleting legacy cluster-level gateway StatefulSet", "name", name)
	orphan := metav1.DeletePropagationOrphan
	if err := r.Delete(ctx, legacySTS, &client.DeleteOptions{PropagationPolicy: &orphan}); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("orphan-deleting legacy gateway STS: %w", err)
	}

	// Delete the legacy gateway pods (<cr>-gateway-<ord>) so the kubelet releases
	// the RWO metadata PVCs for the new per-node STS pods (<cr>-gateway-<ord>-0).
	for ord := int32(0); ord < replicas; ord++ {
		podName := fmt.Sprintf("%s-%d", name, ord)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: cluster.Namespace}}
		if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting legacy gateway pod %s: %w", podName, err)
		}
	}

	return nil
}

// stripStatefulSetOwnerRef removes the ownerReference pointing at the given
// StatefulSet UID from a PVC (if present) and reports whether it changed. Used
// during gateway migration so an orphan-deleted legacy STS cannot cascade-delete
// the metadata PVC the new per-node node is about to adopt.
func stripStatefulSetOwnerRef(pvc *corev1.PersistentVolumeClaim, stsUID types.UID) bool {
	if len(pvc.OwnerReferences) == 0 {
		return false
	}
	kept := pvc.OwnerReferences[:0]
	changed := false
	for _, ref := range pvc.OwnerReferences {
		if ref.UID == stsUID {
			changed = true
			continue
		}
		kept = append(kept, ref)
	}
	pvc.OwnerReferences = kept
	return changed
}
