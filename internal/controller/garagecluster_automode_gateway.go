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
	"maps"
	"sort"
	"strconv"
	"strings"

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

func parseAutoModeGatewayOrdinal(nodeName, clusterName string) (int32, bool) {
	prefix := clusterName + "-gateway-"
	if !strings.HasPrefix(nodeName, prefix) {
		return 0, false
	}
	ordinal, err := strconv.ParseInt(nodeName[len(prefix):], 10, 32)
	if err != nil || ordinal < 0 {
		return 0, false
	}
	return int32(ordinal), true
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
	if adopted, err := r.ensureAutoModeCycleOwnership(ctx, cluster, existing, tierGateway); err != nil {
		return err
	} else if adopted {
		return nil
	}

	type pendingGatewayUpdate struct {
		current *garagev1beta1.GarageNode
		desired *garagev1beta1.GarageNode
	}
	desiredByName := make(map[string]bool, desiredReplicas)
	var toCreate []*garagev1beta1.GarageNode
	var toUpdate []pendingGatewayUpdate
	for i := int32(0); i < desiredReplicas; i++ {
		desiredByName[autoModeGatewayNodeName(cluster.Name, i)] = true

		desired, err := r.buildAutoModeGatewayNode(cluster, i, "")
		if err != nil {
			return fmt.Errorf("building desired gateway GarageNode for ordinal %d: %w", i, err)
		}

		// Repeated cycles accumulate exact -cycle suffixes. Keep deleting
		// ancestors out of the parent scale loop and let the sole live promoted
		// descendant satisfy this ordinal.
		descendantNames, current, err := resolveAutoModeCycleSlot(existing, desired.Name)
		if err != nil {
			return fmt.Errorf("resolving promoted gateway cycle for ordinal %d: %w", i, err)
		}
		for _, name := range descendantNames {
			desiredByName[name] = true
		}
		if current != nil {
			changed, handoffErr := r.reconcileCurrentAutoModePVCHandoffs(ctx, cluster, current, desired.Name)
			if handoffErr != nil {
				return fmt.Errorf("reconciling retained PVC handoff for gateway ordinal %d: %w", i, handoffErr)
			}
			if changed {
				return nil
			}
		}
		if current == nil {
			if nameErr := validateManagedGarageNodeName(desired); nameErr != nil {
				return fmt.Errorf("refusing to create Auto gateway GarageNode ordinal %d: %w", i, nameErr)
			}
			toCreate = append(toCreate, desired)
			continue
		}

		if autoModeGatewayNodeNeedsUpdate(current, desired) {
			if nameErr := validateManagedGarageNodeName(desired); nameErr != nil {
				return fmt.Errorf("refusing to roll Auto gateway GarageNode ordinal %d: %w", i, nameErr)
			}
			toUpdate = append(toUpdate, pendingGatewayUpdate{current: current, desired: desired})
		}
	}

	if len(toCreate) > 0 || len(toUpdate) > 0 {
		// Gateway identities are never the empty-cluster bootstrap. The storage
		// tier must establish the Admin API and settle first, after which gateway
		// additions and role-affecting updates are admitted one at a time.
		ready, _, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, false)
		if barrierErr != nil {
			waitingMessage = "refusing to start an Auto-mode gateway addition/update until Garage layout convergence can be verified: " + barrierErr.Error()
		}
		if barrierErr != nil || !ready {
			log.Info("Waiting to reconcile Auto-mode gateway topology", "reason", waitingMessage)
			return nil
		}
		if len(toCreate) > 0 {
			toCreate = toCreate[:1]
			toUpdate = nil
		} else {
			toUpdate = toUpdate[:1]
		}
		for _, desired := range toCreate {
			hasHandoff, handoffErr := r.reserveAutoModeReplacement(ctx, cluster, desired)
			if handoffErr != nil {
				return fmt.Errorf("reserving retained PVC handoff for gateway GarageNode %s: %w", desired.Name, handoffErr)
			}
			log.Info("Creating Auto-mode gateway GarageNode (serialized topology change)", "name", desired.Name)
			if err := r.Create(ctx, desired); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("creating gateway GarageNode %s: %w", desired.Name, err)
			}
			if hasHandoff {
				if desired.UID == "" {
					return fmt.Errorf("creating gateway GarageNode %s returned an empty UID for retained PVC handoff", desired.Name)
				}
				if err := r.bindAutoModeReplacement(ctx, cluster, desired, desired.Name); err != nil {
					return fmt.Errorf("binding retained PVC handoff to gateway GarageNode %s: %w", desired.Name, err)
				}
			}
		}
		for _, update := range toUpdate {
			log.Info("Updating Auto-mode gateway GarageNode (serialized topology change)", "name", update.current.Name)
			applyAutoModeGatewayNodeUpdate(update.current, update.desired)
			if err := r.Update(ctx, update.current); err != nil {
				return fmt.Errorf("updating gateway GarageNode %s: %w", update.current.Name, err)
			}
		}
		// Let this batch join and settle before a scale-down or another tier
		// changes the shared Garage layout.
		return nil
	}

	var toDelete []*garagev1beta1.GarageNode
	for name, n := range existing {
		if desiredByName[name] {
			continue
		}
		toDelete = append(toDelete, n)
	}
	sort.Slice(toDelete, func(i, j int) bool {
		left, leftOK := parseAutoModeGatewayOrdinal(autoNodeSlotForCycle(toDelete[i]), cluster.Name)
		right, rightOK := parseAutoModeGatewayOrdinal(autoNodeSlotForCycle(toDelete[j]), cluster.Name)
		if leftOK && rightOK && left != right {
			return left > right
		}
		return toDelete[i].Name > toDelete[j].Name
	})
	if len(toDelete) > 0 {
		candidate := toDelete[0]
		ready, _, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, false, candidate.Name)
		if barrierErr != nil {
			waitingMessage = "refusing to start an Auto-mode gateway drain until Garage layout convergence can be verified: " + barrierErr.Error()
		}
		if barrierErr != nil || !ready {
			log.Info("Waiting to drain Auto-mode gateway GarageNode", "node", candidate.Name, "reason", waitingMessage)
			return nil
		}
		log.Info("Deleting one Auto-mode gateway GarageNode (serialized scale-down)", "name", candidate.Name)
		if err := r.prepareRetainedAutoModePVCHandoffs(ctx, cluster, candidate); err != nil {
			return fmt.Errorf("preparing retained PVC handoff for gateway GarageNode %s: %w", candidate.Name, err)
		}
		if err := r.Delete(ctx, candidate); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting gateway GarageNode %s: %w", candidate.Name, err)
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

func (r *GarageClusterReconciler) prepareRetainedAutoModePVCHandoffs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) error {
	policy := stsPVCRetentionPolicy(cluster, node)
	if policy != nil && policy.WhenDeleted == appsv1.DeletePersistentVolumeClaimRetentionPolicyType {
		return nil
	}
	if !metav1.IsControlledBy(node, cluster) || node.Labels[labelAutoNodeSlot] == "" ||
		node.Labels[labelAppManagedBy] != managedByOperatorValue ||
		(node.Labels[labelTier] != tierGateway && node.Labels[labelTier] != tierStorage) {
		return fmt.Errorf("refusing to publish retained PVC handoff for GarageNode without exact Auto-mode ownership")
	}

	slot := node.Labels[labelAutoNodeSlot]
	prepared := make([]garagev1beta2.AutoModePVCHandoffStatus, 0, len(node.Status.ManagedPVCs))
	for i := range node.Status.ManagedPVCs {
		record := node.Status.ManagedPVCs[i]
		pvc := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Name: record.Name, Namespace: node.Namespace}
		if err := r.safetyReader().Get(ctx, key, pvc); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("reading managed PVC %s before retained handoff: %w", key, err)
		}
		if pvc.UID == "" || pvc.Annotations[managedPVCNodeUIDAnnotation] != string(node.UID) {
			return fmt.Errorf("refusing retained handoff for PVC %s/%s without its exact GarageNode UID correlation", pvc.Namespace, pvc.Name)
		}
		switch {
		case record.UID != "":
			if record.UID != pvc.UID {
				return fmt.Errorf("refusing retained handoff for PVC %s/%s UID %s because GarageNode status records %s", pvc.Namespace, pvc.Name, pvc.UID, record.UID)
			}
		case record.PendingReservationHash != "":
			if !managedNodePVCNonceMatches(pvc, record.PendingReservationHash) {
				return fmt.Errorf("refusing retained handoff for PVC %s/%s because its reservation nonce does not match GarageNode status", pvc.Namespace, pvc.Name)
			}
		default:
			return fmt.Errorf("refusing malformed retained PVC handoff record for %q", record.Name)
		}
		prepared = append(prepared, garagev1beta2.AutoModePVCHandoffStatus{
			SlotName:              slot,
			PVCName:               pvc.Name,
			PVCUID:                string(pvc.UID),
			PreviousGarageNodeUID: string(node.UID),
		})
	}
	if len(prepared) == 0 {
		return nil
	}

	return r.updateAutoModePVCHandoffs(ctx, cluster, func(current []garagev1beta2.AutoModePVCHandoffStatus) ([]garagev1beta2.AutoModePVCHandoffStatus, error) {
		for _, wanted := range prepared {
			found := false
			for i := range current {
				if current[i].PVCName != wanted.PVCName {
					continue
				}
				found = true
				if current[i].SlotName != wanted.SlotName || current[i].PVCUID != wanted.PVCUID ||
					current[i].PreviousGarageNodeUID != wanted.PreviousGarageNodeUID {
					return nil, fmt.Errorf("refusing to replace conflicting retained PVC handoff for %q", wanted.PVCName)
				}
			}
			if !found {
				current = append(current, wanted)
			}
		}
		sort.Slice(current, func(i, j int) bool { return current[i].PVCName < current[j].PVCName })
		return current, nil
	})
}

func (r *GarageClusterReconciler) reserveAutoModeReplacement(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	desired *garagev1beta1.GarageNode,
) (bool, error) {
	slot := desired.Labels[labelAutoNodeSlot]
	handoffs := autoModePVCHandoffsForSlot(cluster.Status.AutoModePVCHandoffs, slot)
	if len(handoffs) == 0 {
		return false, nil
	}
	missing := map[string]struct{}{}
	for i := range handoffs {
		pvc := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Name: handoffs[i].PVCName, Namespace: desired.Namespace}
		if err := r.safetyReader().Get(ctx, key, pvc); err != nil {
			if errors.IsNotFound(err) {
				missing[handoffs[i].PVCName] = struct{}{}
				continue
			}
			return false, fmt.Errorf("checking retained PVC %s before replacement: %w", key, err)
		}
		if string(pvc.UID) != handoffs[i].PVCUID {
			return false, fmt.Errorf("refusing replacement for retained PVC %s: expected UID %s, got %s", key, handoffs[i].PVCUID, pvc.UID)
		}
		if !pvc.DeletionTimestamp.IsZero() {
			return false, fmt.Errorf("waiting for retained PVC %s UID %s to finish terminating", key, pvc.UID)
		}
	}
	if len(missing) > 0 {
		if err := r.updateAutoModePVCHandoffs(ctx, cluster, func(current []garagev1beta2.AutoModePVCHandoffStatus) ([]garagev1beta2.AutoModePVCHandoffStatus, error) {
			kept := current[:0]
			for i := range current {
				if current[i].SlotName == slot {
					if _, absent := missing[current[i].PVCName]; absent {
						continue
					}
				}
				kept = append(kept, current[i])
			}
			return kept, nil
		}); err != nil {
			return false, err
		}
		handoffs = autoModePVCHandoffsForSlot(cluster.Status.AutoModePVCHandoffs, slot)
		if len(handoffs) == 0 {
			return false, nil
		}
	}
	absent, err := authoritativeObjectAbsent(ctx, r.safetyReader(), client.ObjectKeyFromObject(desired), &garagev1beta1.GarageNode{})
	if err != nil {
		return false, fmt.Errorf("checking replacement GarageNode absence: %w", err)
	}
	if !absent {
		return false, fmt.Errorf("refusing to reserve a replacement nonce while GarageNode %s/%s already exists", desired.Namespace, desired.Name)
	}
	nonce, hash, err := newManagedNodePVCNonce()
	if err != nil {
		return false, err
	}
	if desired.Annotations == nil {
		desired.Annotations = map[string]string{}
	}
	desired.Annotations[autoModePVCHandoffNonceAnnotation] = nonce
	if err := r.updateAutoModePVCHandoffs(ctx, cluster, func(current []garagev1beta2.AutoModePVCHandoffStatus) ([]garagev1beta2.AutoModePVCHandoffStatus, error) {
		found := false
		for i := range current {
			if current[i].SlotName != slot {
				continue
			}
			found = true
			current[i].ReplacementReservationHash = hash
			current[i].ReplacementGarageNodeUID = ""
		}
		if !found {
			return nil, fmt.Errorf("retained PVC handoff for Auto-mode slot %q disappeared before replacement reservation", slot)
		}
		return current, nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

func (r *GarageClusterReconciler) bindAutoModeReplacement(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	slot string,
) error {
	if node.UID == "" || !metav1.IsControlledBy(node, cluster) || node.Labels[labelAutoNodeSlot] != slot {
		return fmt.Errorf("replacement GarageNode does not have exact Auto-mode ownership")
	}
	return r.updateAutoModePVCHandoffs(ctx, cluster, func(current []garagev1beta2.AutoModePVCHandoffStatus) ([]garagev1beta2.AutoModePVCHandoffStatus, error) {
		found := false
		for i := range current {
			if current[i].SlotName != slot {
				continue
			}
			found = true
			if !managedNodePVCNonceMatchesNode(node, current[i].ReplacementReservationHash) {
				return nil, fmt.Errorf("replacement GarageNode nonce does not match the durable handoff commitment")
			}
			if current[i].ReplacementGarageNodeUID != "" && current[i].ReplacementGarageNodeUID != string(node.UID) {
				return nil, fmt.Errorf("retained PVC handoff is already bound to GarageNode UID %s", current[i].ReplacementGarageNodeUID)
			}
			current[i].ReplacementGarageNodeUID = string(node.UID)
		}
		if !found {
			return nil, fmt.Errorf("retained PVC handoff for Auto-mode slot %q disappeared before UID binding", slot)
		}
		return current, nil
	})
}

func (r *GarageClusterReconciler) reconcileCurrentAutoModePVCHandoffs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	slot string,
) (bool, error) {
	handoffs := autoModePVCHandoffsForSlot(cluster.Status.AutoModePVCHandoffs, slot)
	if len(handoffs) == 0 {
		return false, nil
	}
	if !metav1.IsControlledBy(node, cluster) || node.Labels[labelAutoNodeSlot] != slot {
		return false, fmt.Errorf("GarageNode %s/%s does not have exact ownership for retained slot %q", node.Namespace, node.Name, slot)
	}
	if string(node.UID) == handoffs[0].PreviousGarageNodeUID {
		if !node.DeletionTimestamp.IsZero() {
			return false, nil
		}
		if err := r.clearAutoModePVCHandoffsForSlot(ctx, cluster, slot); err != nil {
			return false, err
		}
		return true, nil
	}
	for i := range handoffs {
		if handoffs[i].PreviousGarageNodeUID != handoffs[0].PreviousGarageNodeUID ||
			handoffs[i].ReplacementGarageNodeUID != handoffs[0].ReplacementGarageNodeUID ||
			handoffs[i].ReplacementReservationHash != handoffs[0].ReplacementReservationHash {
			return false, fmt.Errorf("retained slot %q has inconsistent GarageNode identity commitments", slot)
		}
	}
	if handoffs[0].ReplacementGarageNodeUID == "" {
		if err := r.bindAutoModeReplacement(ctx, cluster, node, slot); err != nil {
			return false, err
		}
		return true, nil
	}
	if handoffs[0].ReplacementGarageNodeUID != string(node.UID) {
		return false, fmt.Errorf("retained slot %q authorizes GarageNode UID %s, not %s", slot, handoffs[0].ReplacementGarageNodeUID, node.UID)
	}

	for i := range handoffs {
		record, found, err := managedNodePVCReservation(node, handoffs[i].PVCName)
		if err != nil {
			return false, err
		}
		if !found || record.UID != types.UID(handoffs[i].PVCUID) {
			return false, nil
		}
		pvc := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Name: handoffs[i].PVCName, Namespace: node.Namespace}
		if err := r.safetyReader().Get(ctx, key, pvc); err != nil {
			return false, fmt.Errorf("verifying consumed retained PVC handoff %s: %w", key, err)
		}
		if string(pvc.UID) != handoffs[i].PVCUID || pvc.Annotations[managedPVCNodeUIDAnnotation] != string(node.UID) {
			return false, nil
		}
	}
	if err := r.clearAutoModePVCHandoffsForSlot(ctx, cluster, slot); err != nil {
		return false, err
	}
	return true, nil
}

func (r *GarageClusterReconciler) clearAutoModePVCHandoffsForSlot(
	ctx context.Context, cluster *garagev1beta2.GarageCluster, slot string,
) error {
	return r.updateAutoModePVCHandoffs(ctx, cluster, func(current []garagev1beta2.AutoModePVCHandoffStatus) ([]garagev1beta2.AutoModePVCHandoffStatus, error) {
		kept := current[:0]
		for i := range current {
			if current[i].SlotName != slot {
				kept = append(kept, current[i])
			}
		}
		return kept, nil
	})
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

	// spec.zoneFrom (#294) is intentionally NOT propagated to gateway nodes.
	// Upstream computes ZoneRedundancy::Maximum as min(distinct zones over ALL
	// roles, replication_factor) — gateways included, since a capacity:nil role
	// still carries a zone — but then requires that many distinct zones among
	// *non-gateway* nodes (../garage src/rpc/layout/version.rs:
	// effective_zone_redundancy vs generate_nongateway_zone_ids). Scattering
	// gateways across per-node zones would inflate the requirement past what
	// storage can satisfy and every layout apply would fail with "The number of
	// zones with non-gateway nodes (N) is smaller than the redundancy parameter".
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
	} else if gw := cluster.Spec.Gateway; gw != nil && gw.Metadata != nil && gw.Metadata.Type == garagev1beta2.VolumeTypeEmptyDir {
		// Fully-ephemeral gateway metadata (#283): EmptyDir, no PVC. Node identity
		// is not persisted across restarts — acceptable for throwaway gateways and
		// already flagged by the cluster webhook's identity warning. Only carry an
		// explicit size (as the EmptyDir sizeLimit); do NOT inject the 1Gi PVC
		// default, which would silently bound the tmpfs the user never sized.
		meta := &garagev1beta1.NodeVolumeConfig{Type: garagev1beta1.VolumeTypeEmptyDir}
		if gw.Metadata.Size != nil && !gw.Metadata.Size.IsZero() {
			s := gw.Metadata.Size.DeepCopy()
			meta.Size = &s
		}
		storage = &garagev1beta1.NodeStorageConfig{Metadata: meta}
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
		if gw := cluster.Spec.Gateway; gw != nil && gw.Metadata != nil {
			storage.Metadata.AccessModes = append([]corev1.PersistentVolumeAccessMode(nil), gw.Metadata.AccessModes...)
			if gw.Metadata.Selector != nil {
				storage.Metadata.Selector = gw.Metadata.Selector.DeepCopy()
			}
			storage.Metadata.Labels = maps.Clone(gw.Metadata.Labels)
			storage.Metadata.Annotations = maps.Clone(gw.Metadata.Annotations)
			if gw.Metadata.DataSourceRef != nil {
				storage.Metadata.DataSourceRef = gw.Metadata.DataSourceRef.DeepCopy()
			}
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
				labelAutoNodeSlot: name,
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
	//
	// A multi-pod gateway tier needs a PER-ORDINAL advertised address: a single
	// shared rpc_public_addr makes every pod's HelloMessage hand remote regions
	// the same hostname, which can route to at most one pod — the others are then
	// unreachable cross-region ("never seen"). Substitute {ordinal} (symmetric
	// with the consumer side's remoteClusters[].gatewayRpcEndpointTemplate) so each
	// pod advertises its own address; addresses without the placeholder are used
	// verbatim (fine for a single-replica gateway tier).
	if gw := cluster.Spec.Gateway; gw != nil && gw.RPCPublicAddr != "" {
		addr := strings.ReplaceAll(gw.RPCPublicAddr, "{ordinal}", strconv.Itoa(int(ordinal)))
		node.Spec.Network = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: addr}
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

func applyAutoModeGatewayNodeUpdate(current, desired *garagev1beta1.GarageNode) {
	current.Spec.Zone = desired.Spec.Zone
	current.Spec.Tags = desired.Spec.Tags
	current.Spec.Network = desired.Spec.Network
	if current.Spec.Storage == nil {
		current.Spec.Storage = desired.Spec.Storage
		return
	}
	if desired.Spec.Storage == nil || desired.Spec.Storage.Metadata == nil {
		return
	}
	if current.Spec.Storage.Metadata == nil {
		current.Spec.Storage.Metadata = desired.Spec.Storage.Metadata
	} else if current.Spec.Storage.Metadata.ExistingClaim == "" {
		current.Spec.Storage.Metadata.Size = desired.Spec.Storage.Metadata.Size
		current.Spec.Storage.Metadata.StorageClassName = desired.Spec.Storage.Metadata.StorageClassName
	}
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
	if len(existing) == 0 {
		return nil
	}
	candidates := make([]*garagev1beta1.GarageNode, 0, len(existing))
	for _, node := range existing {
		candidates = append(candidates, node)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, leftOK := parseAutoModeGatewayOrdinal(autoNodeSlotForCycle(candidates[i]), cluster.Name)
		right, rightOK := parseAutoModeGatewayOrdinal(autoNodeSlotForCycle(candidates[j]), cluster.Name)
		if leftOK && rightOK && left != right {
			return left > right
		}
		return candidates[i].Name > candidates[j].Name
	})
	candidate := candidates[0]
	ready, _, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, false, candidate.Name)
	if barrierErr != nil {
		waitingMessage = "refusing to drain the removed Auto-mode gateway tier until Garage layout convergence can be verified: " + barrierErr.Error()
	}
	if barrierErr != nil || !ready {
		log.Info("Waiting to drain removed Auto-mode gateway GarageNode", "node", candidate.Name, "reason", waitingMessage)
		return nil
	}
	log.Info("Deleting one Auto-mode gateway GarageNode (gateway tier removed)", "name", candidate.Name)
	if err := r.prepareRetainedAutoModePVCHandoffs(ctx, cluster, candidate); err != nil {
		return fmt.Errorf("preparing retained PVC handoff for removed gateway GarageNode %s: %w", candidate.Name, err)
	}
	if err := r.Delete(ctx, candidate); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting gateway GarageNode %s: %w", candidate.Name, err)
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
