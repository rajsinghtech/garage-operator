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
	"sort"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	// managedByOperatorValue marks a GarageNode CR as operator-owned in Auto mode.
	managedByOperatorValue = "operator"
)

// autoModeGarageNodeName returns the canonical name for an operator-generated
// GarageNode in Auto mode for a given storage-tier ordinal.
func autoModeGarageNodeName(clusterName string, ordinal int32) string {
	return fmt.Sprintf("%s-storage-%d", clusterName, ordinal)
}

// reconcileAutoModeStorageNodes generates and reconciles one GarageNode CR per
// storage replica when the cluster is in Auto mode with a storage tier. Each
// GarageNode owns its own single-replica StatefulSet via the GarageNode
// controller — there is no cluster-level storage STS in Auto mode (post-#190).
//
// The reconciler:
//
//   - Creates missing GarageNodes for ordinals 0..replicas-1
//   - Updates existing GarageNodes when zone, capacity, tags, or storage drifts
//   - Deletes GarageNodes for ordinals >= replicas (scale-down)
//
// Deletion of a GarageNode triggers its own finalizer, which handles layout
// removal and waits appropriately. We simply call Delete() and let the
// finalizer do its work.
func (r *GarageClusterReconciler) reconcileAutoModeStorageNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	if !cluster.HasStorageTier() {
		return nil
	}

	desiredReplicas := cluster.StorageReplicas()

	// List existing operator-owned GarageNodes for this cluster's storage tier.
	existing, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return fmt.Errorf("listing operator-owned storage GarageNodes: %w", err)
	}

	desiredByName := make(map[string]bool, desiredReplicas)
	for i := int32(0); i < desiredReplicas; i++ {
		desiredByName[autoModeGarageNodeName(cluster.Name, i)] = true

		desired, err := r.buildAutoModeStorageNode(cluster, i, "" /* no node ID for fresh creates */, "" /* no existingClaim */, "")
		if err != nil {
			return fmt.Errorf("building desired GarageNode for ordinal %d: %w", i, err)
		}

		current, found := existing[desired.Name]
		if !found {
			log.Info("Creating Auto-mode GarageNode", "name", desired.Name)
			if err := r.Create(ctx, desired); err != nil {
				return fmt.Errorf("creating GarageNode %s: %w", desired.Name, err)
			}
			continue
		}

		// Update on drift. We compare a small set of fields the operator cares
		// about; the rest (resources, scheduling) are inherited at reconcile
		// time from the cluster and aren't worth diffing here.
		if autoModeStorageNodeNeedsUpdate(current, desired) {
			log.Info("Updating Auto-mode GarageNode (drift detected)", "name", desired.Name)
			current.Spec.Zone = desired.Spec.Zone
			current.Spec.Capacity = desired.Spec.Capacity
			current.Spec.Tags = desired.Spec.Tags
			// We intentionally do not overwrite Storage.{Metadata,Data}.ExistingClaim
			// when it's already set — that's used by migration to bind the new
			// GarageNode to legacy PVCs, and overwriting would re-create from
			// scratch and lose the data.
			if current.Spec.Storage == nil {
				current.Spec.Storage = desired.Spec.Storage
			} else {
				// Update sizes/storage class but preserve existingClaim values.
				if desired.Spec.Storage != nil {
					if current.Spec.Storage.Metadata == nil {
						current.Spec.Storage.Metadata = desired.Spec.Storage.Metadata
					} else if current.Spec.Storage.Metadata.ExistingClaim == "" {
						current.Spec.Storage.Metadata.Size = desired.Spec.Storage.Metadata.Size
						current.Spec.Storage.Metadata.StorageClassName = desired.Spec.Storage.Metadata.StorageClassName
					}
					if current.Spec.Storage.Data == nil {
						current.Spec.Storage.Data = desired.Spec.Storage.Data
					} else if current.Spec.Storage.Data.ExistingClaim == "" {
						current.Spec.Storage.Data.Size = desired.Spec.Storage.Data.Size
						current.Spec.Storage.Data.StorageClassName = desired.Spec.Storage.Data.StorageClassName
					}
				}
			}
			if err := r.Update(ctx, current); err != nil {
				return fmt.Errorf("updating GarageNode %s: %w", current.Name, err)
			}
		}
	}

	// Delete any operator-owned GarageNodes that fall outside the desired range.
	for name, n := range existing {
		if desiredByName[name] {
			continue
		}
		log.Info("Deleting Auto-mode GarageNode (scale-down)", "name", name)
		if err := r.Delete(ctx, n); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting GarageNode %s: %w", name, err)
		}
	}

	return nil
}

// listAutoModeStorageNodes returns operator-owned GarageNodes for the storage
// tier of this cluster, keyed by name.
func (r *GarageClusterReconciler) listAutoModeStorageNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) (map[string]*garagev1beta1.GarageNode, error) {
	nodeList := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodeList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      cluster.Name,
			labelTier:         tierStorage,
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

// buildAutoModeStorageNode constructs the desired GarageNode for a given ordinal.
// nodeID is set only during migration (to lock the new GarageNode to the legacy
// pod's identity). metadataPVC and dataPVC bind to pre-existing PVCs when set;
// otherwise the GarageNode controller uses VolumeClaimTemplates to provision
// fresh PVCs.
func (r *GarageClusterReconciler) buildAutoModeStorageNode(
	cluster *garagev1beta2.GarageCluster,
	ordinal int32,
	nodeID, metadataPVC, dataPVC string,
) (*garagev1beta1.GarageNode, error) {
	name := autoModeGarageNodeName(cluster.Name, ordinal)

	// Capacity from the cluster's storage.data.size with reserve applied.
	capacity := r.calculateNodeCapacity(cluster)
	reserve := 0
	if cluster.HasStorageTier() {
		reserve = cluster.Spec.Storage.CapacityReservePercent
	}
	effective := calculateEffectiveCapacity(capacity, reserve)
	cap := resource.NewQuantity(int64(effective), resource.BinarySI)

	zone := cluster.Spec.Zone
	if zone == "" {
		zone = defaultZoneName
	}

	// Pod name for tag-based identification matches the legacy STS pod name
	// (<name>-<ordinal>) so existing layout-tag tooling continues to work.
	podName := fmt.Sprintf("%s-%d", name, 0)
	tags := buildNodeTags(cluster.Name, cluster.Namespace, tierStorage, cluster.Spec.DefaultNodeTags, podName)

	storage := &garagev1beta1.NodeStorageConfig{
		Metadata: &garagev1beta1.NodeVolumeConfig{},
		Data:     &garagev1beta1.NodeVolumeConfig{},
	}

	// Metadata volume: use existingClaim for migration, otherwise pass through
	// the cluster's metadata size + storage class so the GarageNode controller
	// provisions a fresh PVC via volumeClaimTemplates.
	if metadataPVC != "" {
		storage.Metadata.ExistingClaim = metadataPVC
	} else if cluster.Spec.Storage.Metadata != nil {
		if cluster.Spec.Storage.Metadata.Size != nil {
			s := cluster.Spec.Storage.Metadata.Size.DeepCopy()
			storage.Metadata.Size = &s
		}
		storage.Metadata.StorageClassName = cluster.Spec.Storage.Metadata.StorageClassName
		storage.Metadata.AccessModes = cluster.Spec.Storage.Metadata.AccessModes
	}

	// Data volume: same logic as metadata.
	if dataPVC != "" {
		storage.Data.ExistingClaim = dataPVC
	} else if cluster.Spec.Storage.Data != nil {
		if cluster.Spec.Storage.Data.Size != nil {
			s := cluster.Spec.Storage.Data.Size.DeepCopy()
			storage.Data.Size = &s
		}
		storage.Data.StorageClassName = cluster.Spec.Storage.Data.StorageClassName
		storage.Data.AccessModes = cluster.Spec.Storage.Data.AccessModes
	}

	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierStorage,
				labelAppManagedBy: managedByOperatorValue,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{
				Name: cluster.Name,
			},
			NodeID:   nodeID,
			Zone:     zone,
			Capacity: cap,
			Tags:     tags,
			Storage:  storage,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, node, r.Scheme); err != nil {
		return nil, err
	}

	return node, nil
}

// autoModeStorageNodeNeedsUpdate returns true when the desired GarageNode spec
// differs from the current one on a field the operator owns.
func autoModeStorageNodeNeedsUpdate(current, desired *garagev1beta1.GarageNode) bool {
	if current.Spec.Zone != desired.Spec.Zone {
		return true
	}
	if (current.Spec.Capacity == nil) != (desired.Spec.Capacity == nil) {
		return true
	}
	if current.Spec.Capacity != nil && desired.Spec.Capacity != nil {
		if current.Spec.Capacity.Cmp(*desired.Spec.Capacity) != 0 {
			return true
		}
	}
	if !tagsEqualCluster(current.Spec.Tags, desired.Spec.Tags) {
		return true
	}
	// Storage size / storage class drift only meaningful when not bound to existingClaim.
	if current.Spec.Storage != nil && desired.Spec.Storage != nil {
		if cm, dm := current.Spec.Storage.Metadata, desired.Spec.Storage.Metadata; cm != nil && dm != nil && cm.ExistingClaim == "" && dm.ExistingClaim == "" {
			if (cm.Size == nil) != (dm.Size == nil) {
				return true
			}
			if cm.Size != nil && dm.Size != nil && cm.Size.Cmp(*dm.Size) != 0 {
				return true
			}
		}
		if cd, dd := current.Spec.Storage.Data, desired.Spec.Storage.Data; cd != nil && dd != nil && cd.ExistingClaim == "" && dd.ExistingClaim == "" {
			if (cd.Size == nil) != (dd.Size == nil) {
				return true
			}
			if cd.Size != nil && dd.Size != nil && cd.Size.Cmp(*dd.Size) != 0 {
				return true
			}
		}
	}
	return false
}

// deleteAutoModeStorageNodes deletes all operator-owned storage GarageNodes for
// this cluster. Used when the storage tier is removed entirely from the spec.
func (r *GarageClusterReconciler) deleteAutoModeStorageNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	existing, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range existing {
		log.Info("Deleting Auto-mode GarageNode (storage tier removed)", "name", name)
		if err := r.Delete(ctx, n); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// ejectAutoModeStorageNodes removes the operator's controllerOwnerRef from each
// operator-owned storage GarageNode in this cluster, then strips the operator's
// managed-by label. This is called when the user flips Auto→Manual: the
// GarageNodes are handed over to the user, who manages them directly going
// forward. The user is then free to delete/modify them at will.
func (r *GarageClusterReconciler) ejectAutoModeStorageNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	existing, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range existing {
		// Strip the controllerOwnerRef pointing at the GarageCluster.
		newOwners := n.OwnerReferences[:0]
		for _, ref := range n.OwnerReferences {
			if ref.UID == cluster.UID {
				continue
			}
			newOwners = append(newOwners, ref)
		}
		n.OwnerReferences = newOwners
		// Strip the managed-by label so subsequent listAutoModeStorageNodes
		// calls don't pick this up again (the user now owns it).
		delete(n.Labels, labelAppManagedBy)

		log.Info("Ejecting Auto-mode GarageNode (Auto→Manual)", "name", name)
		if err := r.Update(ctx, n); err != nil {
			return fmt.Errorf("ejecting GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// migrateLegacyStorageSTSIfNeeded migrates a pre-#190 cluster-level storage
// StatefulSet to per-GarageNode workloads by orphan-adopting the legacy STS's
// PVCs. The metadata PVC carries the Garage node_key so node identity survives.
//
// This is idempotent and resumable via cluster.Status.Migration:
//
//   - On a fresh cluster (no legacy STS), Phase=Completed immediately.
//   - On a multi-HDD cluster (PVCs like data-N-<cluster>-<idx>), Phase=Skipped
//     with a clear message — the admin must migrate by hand. (Issue #190 covers
//     the single-disk case; multi-HDD migration is out of scope.)
//   - Otherwise the migration proceeds ordinal by ordinal, creating a
//     GarageNode with `spec.storage.{metadata,data}.existingClaim` bound to the
//     legacy PVCs. Once all ordinals are migrated, the legacy STS is
//     orphan-deleted so the new GarageNode STSes can take ownership of the
//     RWO PVCs as their old pods terminate.
func (r *GarageClusterReconciler) migrateLegacyStorageSTSIfNeeded(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	// Short-circuit on terminal states.
	if cluster.Status.Migration != nil {
		switch cluster.Status.Migration.Phase {
		case garagev1beta2.MigrationPhaseCompleted, garagev1beta2.MigrationPhaseSkipped:
			return nil
		}
	}

	// Check for legacy STS.
	legacySTS := &appsv1.StatefulSet{}
	stsKey := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
	err := r.Get(ctx, stsKey, legacySTS)
	if errors.IsNotFound(err) {
		// Fresh cluster (or already-migrated, STS gone) — mark complete.
		return r.setMigrationStatus(ctx, cluster, garagev1beta2.MigrationPhaseCompleted, "no legacy StatefulSet detected", nil)
	}
	if err != nil {
		return fmt.Errorf("checking for legacy storage StatefulSet: %w", err)
	}

	// Multi-HDD detection: look for any PVC matching `data-<idx>-<cluster>-N`.
	// We do this before starting the migration so we don't half-migrate.
	pvcList := &corev1.PersistentVolumeClaimList{}
	if err := r.List(ctx, pvcList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing PVCs for multi-HDD detection: %w", err)
	}
	for _, pvc := range pvcList.Items {
		if isMultiHDDDataPVC(pvc.Name, cluster.Name) {
			msg := fmt.Sprintf("multi-HDD PVCs detected (e.g. %q); auto-migration to per-node GarageNodes is not supported for multi-HDD clusters. Please migrate manually — see issue #190.", pvc.Name)
			log.Info("Multi-HDD cluster detected, skipping auto-migration", "samplePVC", pvc.Name)
			return r.setMigrationStatus(ctx, cluster, garagev1beta2.MigrationPhaseSkipped, msg, nil)
		}
	}

	// Begin / resume migration.
	if cluster.Status.Migration == nil || cluster.Status.Migration.Phase == garagev1beta2.MigrationPhaseNotStarted {
		now := metav1.Now()
		if err := r.setMigrationStatus(ctx, cluster, garagev1beta2.MigrationPhaseInProgress, "migrating legacy storage StatefulSet to per-node GarageNodes", &now); err != nil {
			return err
		}
	}

	migrated := make(map[int32]bool)
	if cluster.Status.Migration != nil {
		for _, o := range cluster.Status.Migration.MigratedOrdinals {
			migrated[o] = true
		}
	}

	// Determine the set of ordinals to migrate. We use the STS spec's replicas
	// as the source of truth — that's what was actually deployed.
	replicas := int32(0)
	if legacySTS.Spec.Replicas != nil {
		replicas = *legacySTS.Spec.Replicas
	}

	// Try to discover node IDs from live cluster layout (best effort: identity
	// also survives via the node_key in the metadata PVC, so this is
	// belt-and-suspenders).
	nodeIDByOrdinal := r.discoverLegacyNodeIDsByOrdinal(ctx, cluster, replicas)

	for ord := int32(0); ord < replicas; ord++ {
		if migrated[ord] {
			continue
		}

		metadataPVC := fmt.Sprintf("%s-%s-%d", metadataVolName, cluster.Name, ord)
		dataPVC := fmt.Sprintf("%s-%s-%d", dataVolName, cluster.Name, ord)

		// Verify the PVCs exist; abort if they don't (we can't blindly attach
		// new GarageNodes to non-existent claims).
		mPVC := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: metadataPVC, Namespace: cluster.Namespace}, mPVC); err != nil {
			msg := fmt.Sprintf("ordinal %d: metadata PVC %q not found: %v", ord, metadataPVC, err)
			return r.failMigration(ctx, cluster, msg)
		}
		dPVC := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: dataPVC, Namespace: cluster.Namespace}, dPVC); err != nil {
			msg := fmt.Sprintf("ordinal %d: data PVC %q not found: %v", ord, dataPVC, err)
			return r.failMigration(ctx, cluster, msg)
		}

		desired, err := r.buildAutoModeStorageNode(cluster, ord, nodeIDByOrdinal[ord], metadataPVC, dataPVC)
		if err != nil {
			return fmt.Errorf("building migrated GarageNode for ordinal %d: %w", ord, err)
		}

		// Create or update — a previous reconcile may have created it but
		// crashed before recording the status; we tolerate that here.
		existing := &garagev1beta1.GarageNode{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing); err == nil {
			log.Info("Migration: GarageNode already exists, leaving in place", "name", desired.Name)
		} else if errors.IsNotFound(err) {
			log.Info("Migration: creating GarageNode bound to legacy PVCs", "name", desired.Name, "metadataPVC", metadataPVC, "dataPVC", dataPVC, "nodeID", nodeIDByOrdinal[ord])
			if createErr := r.Create(ctx, desired); createErr != nil {
				return fmt.Errorf("migration: creating GarageNode %s: %w", desired.Name, createErr)
			}
		} else {
			return fmt.Errorf("migration: checking for existing GarageNode %s: %w", desired.Name, err)
		}

		migrated[ord] = true
		// Persist intermediate progress so a crash mid-migration resumes correctly.
		ordinals := make([]int32, 0, len(migrated))
		for o := range migrated {
			ordinals = append(ordinals, o)
		}
		sort.Slice(ordinals, func(i, j int) bool { return ordinals[i] < ordinals[j] })
		if err := r.updateMigratedOrdinals(ctx, cluster, ordinals); err != nil {
			return fmt.Errorf("updating migrated ordinals: %w", err)
		}
	}

	// All ordinals migrated — orphan-delete the legacy STS so the new
	// GarageNode STSes can take ownership of the RWO PVCs when the old pods terminate.
	log.Info("Migration: orphan-deleting legacy storage StatefulSet", "name", cluster.Name)
	orphan := metav1.DeletePropagationOrphan
	if err := r.Delete(ctx, legacySTS, &client.DeleteOptions{PropagationPolicy: &orphan}); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("orphan-deleting legacy STS: %w", err)
	}

	return r.setMigrationStatus(ctx, cluster, garagev1beta2.MigrationPhaseCompleted, fmt.Sprintf("migrated %d ordinals from legacy StatefulSet to per-node GarageNodes", replicas), nil)
}

// isMultiHDDDataPVC reports whether a PVC name matches the multi-HDD layout
// pattern produced by the legacy STS — `data-<idx>-<cluster>-<ord>`, where
// `<idx>` is a non-negative integer. Single-HDD PVCs are `data-<cluster>-<ord>`.
func isMultiHDDDataPVC(pvcName, clusterName string) bool {
	// Multi-HDD: data-0-<cluster>-0, data-1-<cluster>-0, ... etc.
	prefix := dataVolName + "-"
	if len(pvcName) <= len(prefix) {
		return false
	}
	rest := pvcName[len(prefix):]
	// rest should start with "<idx>-<cluster>-..." where idx is digits.
	// Single-HDD form starts with "<cluster>-..." directly.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '-' {
			head := rest[:i]
			if head == "" {
				return false
			}
			if _, err := strconv.Atoi(head); err != nil {
				return false
			}
			// digit-only head — check the rest starts with the cluster name + "-"
			tail := rest[i+1:]
			if len(tail) > len(clusterName)+1 && tail[:len(clusterName)+1] == clusterName+"-" {
				return true
			}
			return false
		}
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return false
}

// discoverLegacyNodeIDsByOrdinal fetches the Garage cluster layout and maps
// pod-name tags to ordinals so the migrated GarageNodes can lock to the same
// node IDs as the legacy pods. Returns an empty map on any error — the
// metadata PVC's node_key is the canonical source of identity, so this is
// strictly belt-and-suspenders.
func (r *GarageClusterReconciler) discoverLegacyNodeIDsByOrdinal(ctx context.Context, cluster *garagev1beta2.GarageCluster, replicas int32) map[int32]string {
	out := map[int32]string{}
	log := logf.FromContext(ctx)

	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		log.V(1).Info("Migration: admin client unavailable for legacy node-ID discovery; identity will be supplied by metadata PVC", "error", err)
		return out
	}
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		log.V(1).Info("Migration: layout unreachable for legacy node-ID discovery; identity will be supplied by metadata PVC", "error", err)
		return out
	}
	for _, role := range layout.Roles {
		// Look for "cluster:<name>/<ns>" tag and a `<cluster>-<ord>` pod-name tag.
		if !nodeBelongsToCluster(role.Tags, cluster.Name, cluster.Namespace) {
			continue
		}
		for _, tag := range role.Tags {
			// Legacy pod names are <cluster>-<N> for N in 0..replicas-1.
			for ord := int32(0); ord < replicas; ord++ {
				if tag == fmt.Sprintf("%s-%d", cluster.Name, ord) {
					out[ord] = role.ID
				}
			}
		}
	}
	return out
}

// setMigrationStatus updates cluster.Status.Migration on the API server.
// When startedAt is non-nil it sets StartedAt; CompletedAt is set automatically
// for terminal phases.
func (r *GarageClusterReconciler) setMigrationStatus(ctx context.Context, cluster *garagev1beta2.GarageCluster, phase, message string, startedAt *metav1.Time) error {
	if cluster.Status.Migration == nil {
		cluster.Status.Migration = &garagev1beta2.StorageMigrationStatus{}
	}
	cluster.Status.Migration.Phase = phase
	cluster.Status.Migration.Message = message
	if startedAt != nil {
		cluster.Status.Migration.StartedAt = startedAt
	}
	switch phase {
	case garagev1beta2.MigrationPhaseCompleted, garagev1beta2.MigrationPhaseFailed, garagev1beta2.MigrationPhaseSkipped:
		now := metav1.Now()
		cluster.Status.Migration.CompletedAt = &now
	}
	return UpdateStatusWithRetry(ctx, r.Client, cluster)
}

// updateMigratedOrdinals persists the running list of migrated ordinals.
func (r *GarageClusterReconciler) updateMigratedOrdinals(ctx context.Context, cluster *garagev1beta2.GarageCluster, ordinals []int32) error {
	if cluster.Status.Migration == nil {
		cluster.Status.Migration = &garagev1beta2.StorageMigrationStatus{Phase: garagev1beta2.MigrationPhaseInProgress}
	}
	cluster.Status.Migration.MigratedOrdinals = ordinals
	return UpdateStatusWithRetry(ctx, r.Client, cluster)
}

// failMigration records a Failed phase and returns an error to trigger requeue.
func (r *GarageClusterReconciler) failMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, message string) error {
	_ = r.setMigrationStatus(ctx, cluster, garagev1beta2.MigrationPhaseFailed, message, nil)
	return fmt.Errorf("storage migration failed: %s", message)
}
