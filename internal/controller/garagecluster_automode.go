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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// Reasons for the LegacySTSMigrated status condition.
const (
	migrationReasonCompleted  = "Completed"
	migrationReasonInProgress = "InProgress"
	migrationReasonFailed     = "Failed"
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

		desired, err := r.buildAutoModeStorageNode(cluster, i, "" /* no node ID for fresh creates */, "" /* no existingClaim */, nil)
		if err != nil {
			return fmt.Errorf("building desired GarageNode for ordinal %d: %w", i, err)
		}

		current, found := existing[desired.Name]
		if !found {
			log.Info("Creating Auto-mode GarageNode", "name", desired.Name)
			if err := r.Create(ctx, desired); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("creating GarageNode %s: %w", desired.Name, err)
			}
			// On AlreadyExists (stale informer cache or pre-existing user-created
			// GarageNode), the next reconcile's list+diff loop will handle drift.
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
			} else if desired.Spec.Storage != nil {
				// Update sizes/storage class but preserve existingClaim values.
				if current.Spec.Storage.Metadata == nil {
					current.Spec.Storage.Metadata = desired.Spec.Storage.Metadata
				} else if current.Spec.Storage.Metadata.ExistingClaim == "" && desired.Spec.Storage.Metadata != nil {
					current.Spec.Storage.Metadata.Size = desired.Spec.Storage.Metadata.Size
					current.Spec.Storage.Metadata.StorageClassName = desired.Spec.Storage.Metadata.StorageClassName
				}
				// Single-HDD data drift.
				if desired.Spec.Storage.Data != nil {
					if current.Spec.Storage.Data == nil {
						current.Spec.Storage.Data = desired.Spec.Storage.Data
					} else if current.Spec.Storage.Data.ExistingClaim == "" {
						current.Spec.Storage.Data.Size = desired.Spec.Storage.Data.Size
						current.Spec.Storage.Data.StorageClassName = desired.Spec.Storage.Data.StorageClassName
					}
				}
				// Multi-HDD: replace DataPaths only when current entries are not
				// pinned to existingClaim (which is set by migration).
				if len(desired.Spec.Storage.DataPaths) > 0 {
					pinned := false
					for _, p := range current.Spec.Storage.DataPaths {
						if p.ExistingClaim != "" {
							pinned = true
							break
						}
					}
					if !pinned {
						current.Spec.Storage.DataPaths = desired.Spec.Storage.DataPaths
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
// pod's identity). metadataPVC binds to a pre-existing metadata PVC when set;
// dataPVCs is the list of pre-existing data PVCs in path-index order (len 1 →
// single-HDD via storage.data.existingClaim; len > 1 → multi-HDD via
// storage.dataPaths[].existingClaim). Empty/nil arguments tell the GarageNode
// controller to provision fresh PVCs via volumeClaimTemplates from the
// cluster's storage spec.
func (r *GarageClusterReconciler) buildAutoModeStorageNode(
	cluster *garagev1beta2.GarageCluster,
	ordinal int32,
	nodeID, metadataPVC string,
	dataPVCs []string,
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

	// Data volume(s):
	//   * len(dataPVCs) > 1  → multi-HDD migration: one DataPaths[] entry per legacy PVC.
	//   * len(dataPVCs) == 1 → single-HDD migration: storage.data.existingClaim.
	//   * len(dataPVCs) == 0 → fresh create: pass through cluster.Spec.Storage.Data
	//                          (or its Paths[]) so the GarageNode controller provisions
	//                          via volumeClaimTemplates.
	switch {
	case len(dataPVCs) > 1:
		paths := make([]garagev1beta1.NodeVolumeConfig, 0, len(dataPVCs))
		for _, pvc := range dataPVCs {
			paths = append(paths, garagev1beta1.NodeVolumeConfig{ExistingClaim: pvc})
		}
		storage.DataPaths = paths
	case len(dataPVCs) == 1:
		storage.Data = &garagev1beta1.NodeVolumeConfig{ExistingClaim: dataPVCs[0]}
	default:
		// Fresh create — mirror cluster's Data spec. Multi-path on the cluster
		// projects to per-node DataPaths[] (one PVC per path on each node).
		if cluster.Spec.Storage.Data != nil && len(cluster.Spec.Storage.Data.Paths) > 0 {
			paths := make([]garagev1beta1.NodeVolumeConfig, 0, len(cluster.Spec.Storage.Data.Paths))
			topLevel := cluster.Spec.Storage.Data
			for _, p := range cluster.Spec.Storage.Data.Paths {
				v := garagev1beta1.NodeVolumeConfig{}
				switch {
				case p.Volume != nil && p.Volume.Size != nil && !p.Volume.Size.IsZero():
					s := p.Volume.Size.DeepCopy()
					v.Size = &s
				case p.Capacity != nil && !p.Capacity.IsZero():
					c := p.Capacity.DeepCopy()
					v.Size = &c
				case topLevel.Size != nil && !topLevel.Size.IsZero():
					s := topLevel.Size.DeepCopy()
					v.Size = &s
				}
				if p.Volume != nil && p.Volume.StorageClassName != nil {
					v.StorageClassName = p.Volume.StorageClassName
				} else {
					v.StorageClassName = topLevel.StorageClassName
				}
				if p.Volume != nil && len(p.Volume.AccessModes) > 0 {
					v.AccessModes = p.Volume.AccessModes
				} else {
					v.AccessModes = topLevel.AccessModes
				}
				paths = append(paths, v)
			}
			storage.DataPaths = paths
		} else if cluster.Spec.Storage.Data != nil {
			storage.Data = &garagev1beta1.NodeVolumeConfig{}
			if cluster.Spec.Storage.Data.Size != nil {
				s := cluster.Spec.Storage.Data.Size.DeepCopy()
				storage.Data.Size = &s
			}
			storage.Data.StorageClassName = cluster.Spec.Storage.Data.StorageClassName
			storage.Data.AccessModes = cluster.Spec.Storage.Data.AccessModes
		}
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
		// Multi-HDD drift: count mismatch or per-path size drift (only when
		// neither side is pinned to existingClaim).
		if cdp, ddp := current.Spec.Storage.DataPaths, desired.Spec.Storage.DataPaths; len(cdp) > 0 || len(ddp) > 0 {
			cPinned := len(cdp) > 0 && cdp[0].ExistingClaim != ""
			dPinned := len(ddp) > 0 && ddp[0].ExistingClaim != ""
			if !cPinned && !dPinned {
				if len(cdp) != len(ddp) {
					return true
				}
				for i := range cdp {
					if (cdp[i].Size == nil) != (ddp[i].Size == nil) {
						return true
					}
					if cdp[i].Size != nil && ddp[i].Size != nil && cdp[i].Size.Cmp(*ddp[i].Size) != 0 {
						return true
					}
				}
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
// Progress is surfaced on a single status Condition (LegacySTSMigrated):
//
//   - On a fresh cluster (no legacy STS), Status=True/Reason=Completed.
//   - On a single-HDD cluster the migration creates a GarageNode per ordinal
//     with `spec.storage.{metadata,data}.existingClaim` bound to the legacy
//     PVCs (`metadata-<cluster>-<N>`, `data-<cluster>-<N>`).
//   - On a multi-HDD cluster (PVCs like `data-<idx>-<cluster>-<N>`) the
//     migration creates a GarageNode per ordinal with `spec.storage.dataPaths[]`
//     bound to each per-disk PVC in index order. Metadata still flows through
//     `spec.storage.metadata.existingClaim` from `metadata-<cluster>-<N>`.
//
// Once all ordinals are migrated, the legacy STS is orphan-deleted so the new
// GarageNode STSes can take ownership of the RWO PVCs as their old pods
// terminate.
//
// Resumability: the function is idempotent. The Condition's Status=True acts
// as the short-circuit; a partial run is re-driven from the live cluster state
// (existing GarageNodes are left in place, missing ones are created).
func (r *GarageClusterReconciler) migrateLegacyStorageSTSIfNeeded(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	// Retry escape hatch: when the user sets the retry-migration annotation,
	// remove the LegacySTSMigrated condition and the annotation so the next
	// reconcile (and this one, below) starts from scratch. This is the only
	// supported way to re-drive the migration without manually patching status.
	if cluster.Annotations[garagev1beta1.AnnotationRetryMigration] == annotationTrue {
		log.Info("Migration: retry-migration annotation set, clearing LegacySTSMigrated condition")
		apply := func() {
			meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated)
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
			return fmt.Errorf("clearing migration condition for retry: %w", err)
		}
		delete(cluster.Annotations, garagev1beta1.AnnotationRetryMigration)
		if err := r.Update(ctx, cluster); err != nil {
			return fmt.Errorf("removing retry-migration annotation: %w", err)
		}
	}

	// Short-circuit when the condition reports Completed.
	if cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionLegacySTSMigrated); cond != nil &&
		cond.Status == metav1.ConditionTrue && cond.Reason == migrationReasonCompleted {
		return nil
	}

	// Check for legacy STS.
	legacySTS := &appsv1.StatefulSet{}
	stsKey := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
	err := r.Get(ctx, stsKey, legacySTS)
	if errors.IsNotFound(err) {
		// Fresh cluster (or already-migrated, STS gone) — mark complete.
		return r.setMigrationCondition(ctx, cluster, metav1.ConditionTrue, migrationReasonCompleted, "no legacy StatefulSet detected")
	}
	if err != nil {
		return fmt.Errorf("checking for legacy storage StatefulSet: %w", err)
	}

	// List PVCs once and bucket them by ordinal. Both single-HDD
	// (`data-<cluster>-<N>`) and multi-HDD (`data-<idx>-<cluster>-<N>`) layouts
	// are supported; multi-HDD ordinals get a sorted list of per-disk PVCs that
	// project to the new GarageNode's `spec.storage.dataPaths[]`.
	pvcList := &corev1.PersistentVolumeClaimList{}
	if err := r.List(ctx, pvcList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing PVCs for migration: %w", err)
	}
	dataPVCsByOrdinal := bucketLegacyDataPVCs(pvcList.Items, cluster.Name)

	// Mark InProgress when entering the migration path. This is informational —
	// the condition is updated to Completed once everything is in place.
	if err := r.setMigrationCondition(ctx, cluster, metav1.ConditionFalse, migrationReasonInProgress, "migrating legacy storage StatefulSet to per-node GarageNodes"); err != nil {
		return err
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
		metadataPVC := fmt.Sprintf("%s-%s-%d", metadataVolName, cluster.Name, ord)

		// Verify the metadata PVC exists; abort if not.
		mPVC := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: metadataPVC, Namespace: cluster.Namespace}, mPVC); err != nil {
			msg := fmt.Sprintf("ordinal %d: metadata PVC %q not found: %v", ord, metadataPVC, err)
			return r.failMigration(ctx, cluster, msg)
		}

		// Resolve the data PVCs for this ordinal. Prefer the multi-HDD layout
		// when present; otherwise fall back to the single-HDD name.
		dataPVCs := dataPVCsByOrdinal[ord]
		if len(dataPVCs) == 0 {
			single := fmt.Sprintf("%s-%s-%d", dataVolName, cluster.Name, ord)
			dPVC := &corev1.PersistentVolumeClaim{}
			if err := r.Get(ctx, types.NamespacedName{Name: single, Namespace: cluster.Namespace}, dPVC); err != nil {
				msg := fmt.Sprintf("ordinal %d: data PVC %q not found: %v", ord, single, err)
				return r.failMigration(ctx, cluster, msg)
			}
			dataPVCs = []string{single}
		}

		desired, err := r.buildAutoModeStorageNode(cluster, ord, nodeIDByOrdinal[ord], metadataPVC, dataPVCs)
		if err != nil {
			return fmt.Errorf("building migrated GarageNode for ordinal %d: %w", ord, err)
		}

		// Create or update — a previous reconcile may have created it but
		// crashed before recording the status; we tolerate that here.
		existing := &garagev1beta1.GarageNode{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing); err == nil {
			log.Info("Migration: GarageNode already exists, leaving in place", "name", desired.Name)
		} else if errors.IsNotFound(err) {
			log.Info("Migration: creating GarageNode bound to legacy PVCs", "name", desired.Name, "metadataPVC", metadataPVC, "dataPVCs", dataPVCs, "nodeID", nodeIDByOrdinal[ord])
			if createErr := r.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
				return fmt.Errorf("migration: creating GarageNode %s: %w", desired.Name, createErr)
			}
		} else {
			return fmt.Errorf("migration: checking for existing GarageNode %s: %w", desired.Name, err)
		}
	}

	// All ordinals migrated — orphan-delete the legacy STS so the new
	// GarageNode STSes can take ownership of the RWO PVCs when the old pods terminate.
	log.Info("Migration: orphan-deleting legacy storage StatefulSet", "name", cluster.Name)
	orphan := metav1.DeletePropagationOrphan
	if err := r.Delete(ctx, legacySTS, &client.DeleteOptions{PropagationPolicy: &orphan}); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("orphan-deleting legacy STS: %w", err)
	}

	// After orphan-Delete of the STS, the legacy pods (<cluster>-0..N-1) are still
	// running and still hold RWO PVCs. Without explicit pod deletion the new
	// GarageNode-owned STSes would hit Multi-Attach errors trying to mount the
	// same metadata-/data- PVCs via ExistingClaim. Delete the legacy pods so the
	// kubelet releases the volumes for the new pods to attach.
	for ord := int32(0); ord < replicas; ord++ {
		podName := fmt.Sprintf("%s-%d", cluster.Name, ord)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: cluster.Namespace}}
		if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting legacy pod %s: %w", podName, err)
		}
	}

	return r.setMigrationCondition(ctx, cluster, metav1.ConditionTrue, migrationReasonCompleted, fmt.Sprintf("migrated %d ordinals from legacy StatefulSet to per-node GarageNodes", replicas))
}

// bucketLegacyDataPVCs scans a list of PVCs and returns a map of ordinal to
// the sorted list of multi-HDD data PVC names (`data-<idx>-<cluster>-<ord>`)
// belonging to that ordinal, ordered by idx ascending. Single-HDD PVCs
// (`data-<cluster>-<ord>`) are not returned here — the caller handles those by
// direct name lookup. PVCs with names that don't match the multi-HDD layout
// are silently ignored.
func bucketLegacyDataPVCs(pvcs []corev1.PersistentVolumeClaim, clusterName string) map[int32][]string {
	type entry struct {
		idx  int
		name string
	}
	tmp := map[int32][]entry{}
	prefix := dataVolName + "-"
	clusterMarker := "-" + clusterName + "-"
	for _, pvc := range pvcs {
		name := pvc.Name
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := name[len(prefix):]
		dash := strings.Index(rest, "-")
		if dash <= 0 {
			continue
		}
		idxStr := rest[:dash]
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			continue
		}
		// After the index, expect "-<cluster>-<ord>".
		tail := rest[dash:]
		if !strings.HasPrefix(tail, clusterMarker) {
			continue
		}
		ordStr := tail[len(clusterMarker):]
		ord64, err := strconv.ParseInt(ordStr, 10, 32)
		if err != nil {
			continue
		}
		ord := int32(ord64)
		tmp[ord] = append(tmp[ord], entry{idx: idx, name: name})
	}
	out := make(map[int32][]string, len(tmp))
	for ord, entries := range tmp {
		sort.Slice(entries, func(i, j int) bool { return entries[i].idx < entries[j].idx })
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.name
		}
		out[ord] = names
	}
	return out
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

// setMigrationCondition sets the LegacySTSMigrated status condition. The
// mutate closure is passed to UpdateStatusWithRetry so a conflict-driven
// re-fetch re-applies the intended condition (otherwise the freshly-fetched
// object would overwrite our pending change).
func (r *GarageClusterReconciler) setMigrationCondition(ctx context.Context, cluster *garagev1beta2.GarageCluster, status metav1.ConditionStatus, reason, message string) error {
	apply := func() {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionLegacySTSMigrated,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: cluster.Generation,
		})
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}

// failMigration records a Failed condition and returns an error to trigger requeue.
func (r *GarageClusterReconciler) failMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, message string) error {
	_ = r.setMigrationCondition(ctx, cluster, metav1.ConditionFalse, migrationReasonFailed, message)
	return fmt.Errorf("storage migration failed: %s", message)
}
