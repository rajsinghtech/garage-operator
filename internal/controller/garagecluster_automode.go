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
	"encoding/json"
	"fmt"
	"maps"
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
	"k8s.io/client-go/util/retry"
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

// parseAutoModeOrdinal extracts the storage-tier ordinal embedded in a
// GarageNode name produced by autoModeGarageNodeName. Returns (ordinal, true)
// when the name matches `<cluster>-storage-<N>` for a non-negative integer N;
// otherwise (0, false).
func parseAutoModeOrdinal(nodeName, clusterName string) (int32, bool) {
	prefix := clusterName + "-storage-"
	if !strings.HasPrefix(nodeName, prefix) {
		return 0, false
	}
	ord, err := strconv.ParseInt(nodeName[len(prefix):], 10, 32)
	if err != nil || ord < 0 {
		return 0, false
	}
	return int32(ord), true
}

// clusterOwnsAutoModePerNodeService reports whether the cluster controller
// owns the per-pod RPC LoadBalancer Service for this node (in which case the
// GarageNode controller must not create a duplicate). True when the GarageNode
// CR carries the operator-managed label AND occupies an Auto storage ordinal
// AND has publicEndpoint configured as LoadBalancer (the only shape for which
// reconcilePerNodeLoadBalancerServices creates `<cluster>-<ord>-rpc`).
func clusterOwnsAutoModePerNodeService(node *garagev1beta1.GarageNode) bool {
	if node == nil || node.Spec.PublicEndpoint == nil {
		return false
	}
	if node.Spec.PublicEndpoint.Type != publicEndpointTypeLoadBalancer {
		return false
	}
	if node.Spec.PublicEndpoint.LoadBalancer == nil || !node.Spec.PublicEndpoint.LoadBalancer.PerNode {
		return false
	}
	if node.Labels[labelAppManagedBy] != managedByOperatorValue {
		return false
	}
	if _, ok := parseAutoModeOrdinal(autoNodeSlotForCycle(node), node.Spec.ClusterRef.Name); !ok {
		return false
	}
	return true
}

// effectiveNodeRPCServiceName returns the Service name from which to derive
// rpc_public_addr for this GarageNode. For operator-owned auto-mode nodes the
// cluster controller provisions the per-pod Service at `<cluster>-<ord>-rpc`
// (see perNodeRPCServiceName); other nodes use the GarageNode-controller-owned
// `<node>-rpc` name.
func effectiveNodeRPCServiceName(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) string {
	if clusterOwnsAutoModePerNodeService(node) {
		if ord, ok := parseAutoModeOrdinal(autoNodeSlotForCycle(node), cluster.Name); ok {
			return perNodeRPCServiceName(cluster.Name, ord)
		}
	}
	return boundedDNS1123LabelName(node.Name + "-rpc")
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
//   - Drains GarageNodes for ordinals >= replicas one at a time (scale-down)
//
// Deletion of a GarageNode triggers its own finalizer, which handles layout
// removal and waits appropriately. Before calling Delete(), this reconciler
// verifies that no storage-node finalizer or Garage layout transition is
// already active. This serializes scale-down with additive node-local-pool
// drains and prevents overlapping partition moves.
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
	if adopted, err := r.ensureAutoModeCycleOwnership(ctx, cluster, existing, tierStorage); err != nil {
		return err
	} else if adopted {
		return nil
	}

	type pendingUpdate struct {
		current *garagev1beta1.GarageNode
		desired *garagev1beta1.GarageNode
	}
	desiredByName := make(map[string]bool, desiredReplicas)
	var toCreate []*garagev1beta1.GarageNode
	var toUpdate []pendingUpdate
	for i := int32(0); i < desiredReplicas; i++ {
		desiredByName[autoModeGarageNodeName(cluster.Name, i)] = true

		desired, err := r.buildAutoModeStorageNode(cluster, i, "" /* no node ID for fresh creates */, "" /* no existingClaim */, nil)
		if err != nil {
			return fmt.Errorf("building desired GarageNode for ordinal %d: %w", i, err)
		}

		// A completed cycle may leave one or more historical -cycle suffixes after
		// repeated replacements. Keep deleting ancestors out of the parent scale
		// loop and let the sole live promoted descendant satisfy this ordinal.
		descendantNames, current, err := resolveAutoModeCycleSlot(existing, desired.Name)
		if err != nil {
			return fmt.Errorf("resolving promoted storage cycle for ordinal %d: %w", i, err)
		}
		for _, name := range descendantNames {
			desiredByName[name] = true
		}
		if current != nil {
			changed, handoffErr := r.reconcileCurrentAutoModePVCHandoffs(ctx, cluster, current, desired.Name)
			if handoffErr != nil {
				return fmt.Errorf("reconciling retained PVC handoff for storage ordinal %d: %w", i, handoffErr)
			}
			if changed {
				return nil
			}
		}
		if current == nil {
			if nameErr := validateManagedGarageNodeName(desired); nameErr != nil {
				return fmt.Errorf("refusing to create Auto storage GarageNode ordinal %d: %w", i, nameErr)
			}
			toCreate = append(toCreate, desired)
			continue
		}

		// Update on drift. We compare a small set of fields the operator cares
		// about; the rest (resources, scheduling) are inherited at reconcile
		// time from the cluster and aren't worth diffing here.
		if autoModeStorageNodeNeedsUpdate(current, desired) {
			if nameErr := validateManagedGarageNodeName(desired); nameErr != nil {
				return fmt.Errorf("refusing to roll Auto storage GarageNode ordinal %d: %w", i, nameErr)
			}
			toUpdate = append(toUpdate, pendingUpdate{current: current, desired: desired})
		}
	}

	// Additions and role-affecting updates are one topology batch. Do not issue
	// it while any earlier storage, gateway, or remote-originated layout version
	// is still active. The very first batch is allowed before an Admin API
	// exists; its newly created GarageNodes become the barrier for every later
	// tier in this reconciliation.
	if len(toCreate) > 0 || len(toUpdate) > 0 {
		ready, storageBootstrap, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, true)
		if barrierErr != nil {
			waitingMessage = "refusing to start an Auto-mode storage addition/update until Garage layout convergence can be verified: " + barrierErr.Error()
		}
		if barrierErr != nil || !ready {
			if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonScaleDownSafe, "no storage scale-down is in progress"); err != nil {
				return err
			}
			return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync, waitingMessage)
		}
		if !storageBootstrap {
			if len(toCreate) > 0 {
				toCreate = toCreate[:1]
				toUpdate = nil
			} else {
				toUpdate = toUpdate[:1]
			}
		}

		changedNames := make([]string, 0, len(toCreate)+len(toUpdate))
		for _, desired := range toCreate {
			hasHandoff, handoffErr := r.reserveAutoModeReplacement(ctx, cluster, desired)
			if handoffErr != nil {
				return fmt.Errorf("reserving retained PVC handoff for storage GarageNode %s: %w", desired.Name, handoffErr)
			}
			log.Info("Creating Auto-mode GarageNode (serialized topology batch)", "name", desired.Name)
			if err := r.Create(ctx, desired); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("creating GarageNode %s: %w", desired.Name, err)
			}
			if hasHandoff {
				if desired.UID == "" {
					return fmt.Errorf("creating storage GarageNode %s returned an empty UID for retained PVC handoff", desired.Name)
				}
				if err := r.bindAutoModeReplacement(ctx, cluster, desired, desired.Name); err != nil {
					return fmt.Errorf("binding retained PVC handoff to storage GarageNode %s: %w", desired.Name, err)
				}
			}
			// On AlreadyExists (stale informer cache or pre-existing user-created
			// GarageNode), the next reconcile's list+diff loop handles drift.
			changedNames = append(changedNames, desired.Name)
		}
		for _, update := range toUpdate {
			log.Info("Updating Auto-mode GarageNode (serialized topology batch)", "name", update.current.Name)
			applyAutoModeStorageNodeUpdate(update.current, update.desired)
			if err := r.Update(ctx, update.current); err != nil {
				return fmt.Errorf("updating GarageNode %s: %w", update.current.Name, err)
			}
			changedNames = append(changedNames, update.current.Name)
		}
		sort.Strings(changedNames)
		if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonScaleDownSafe, "no storage scale-down is in progress"); err != nil {
			return err
		}
		return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageTopologyAdding,
			"waiting for Auto-mode storage GarageNode changes to enter a settled Garage layout: "+strings.Join(changedNames, ", "))
	}

	// Collect operator-owned GarageNodes that fall outside the desired range.
	var toDelete []*garagev1beta1.GarageNode
	for name, n := range existing {
		if desiredByName[name] {
			continue
		}
		toDelete = append(toDelete, n)
	}
	sort.Slice(toDelete, func(i, j int) bool {
		left, leftOK := parseAutoModeOrdinal(autoNodeSlotForCycle(toDelete[i]), cluster.Name)
		right, rightOK := parseAutoModeOrdinal(autoNodeSlotForCycle(toDelete[j]), cluster.Name)
		if leftOK && rightOK && left != right {
			// Retire the highest ordinal first, matching StatefulSet scale-down
			// semantics and keeping the lowest stable identities.
			return left > right
		}
		return toDelete[i].Name > toDelete[j].Name
	})

	// Refuse a scale-down that would drop the cluster below its replication
	// factor. The per-node finalizer cannot remove a layout role once fewer
	// roled nodes than the factor remain (Garage returns IsReplicationConstraint
	// and the finalizer retains the CR for retry), so keep the excess nodes and
	// surface the block before starting needless deletion. The keep-set
	// creates/updates above already ran.
	// The proactive guard applies only to a standalone (non-federated) cluster:
	// in a federation the replication factor is satisfied across ALL regions'
	// storage nodes, so a count of this region's nodes alone is not authoritative
	// and would wrongly wedge a legitimate local scale-down. Federated clusters
	// rely on the per-node finalizer's IsReplicationConstraint backstop, which
	// retains the CR and retries a layout-role removal that would actually drop
	// below the factor.
	if len(toDelete) > 0 && len(cluster.Spec.RemoteClusters) == 0 {
		factor := replicationFactorOf(cluster)
		surviving := countLiveStorageNodes(existing, desiredByName)
		if factor > 0 && surviving < factor {
			msg := fmt.Sprintf("refusing to scale storage down to %d GarageNode(s): %d live node(s) with positive capacity would remain, below replication.factor %d "+
				"(removing them would orphan their Garage layout roles). Lower spec.replication.factor or restore replicas; the excess GarageNode(s) are kept.",
				len(desiredByName), surviving, factor)
			log.Info("Auto-mode storage scale-down blocked", "survivingLiveNodes", surviving, "replicationFactor", factor)
			if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionTrue, garagev1beta1.ReasonScaleDownWouldBreakQuorum, msg); err != nil {
				return err
			}
			return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonScaleDownWouldBreakQuorum, msg)
		}
	}

	if len(toDelete) > 0 {
		candidate := toDelete[0]
		ready, _, waitingMessage, err := r.clusterLayoutReadyForMutation(ctx, cluster, false, candidate.Name)
		if err != nil {
			waitingMessage = "refusing to start an Auto-mode storage drain until Garage layout convergence can be verified: " + err.Error()
		}
		if err != nil || !ready {
			if statusErr := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonScaleDownSafe, "storage scale-down is waiting, not safety-blocked"); statusErr != nil {
				return statusErr
			}
			return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync, waitingMessage)
		}
		if err := r.prepareGarageNodeDeletionDrain(ctx, cluster, candidate); err != nil {
			if statusErr := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonScaleDownSafe, "storage scale-down is waiting for reversible drain preflight"); statusErr != nil {
				return statusErr
			}
			if statusErr := r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
				garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync,
				"refusing to mark GarageNode terminating until storage-drain preflight succeeds: "+err.Error()); statusErr != nil {
				return statusErr
			}
			// Keep reconciling so the generic OnDelete rollout can converge a newly
			// requested consistent configuration before this reversible preflight is
			// retried.
			return nil
		}

		log.Info("Deleting one Auto-mode GarageNode (serialized scale-down)", "name", candidate.Name)
		if err := r.prepareRetainedAutoModePVCHandoffs(ctx, cluster, candidate); err != nil {
			return fmt.Errorf("preparing retained PVC handoff for storage GarageNode %s: %w", candidate.Name, err)
		}
		if err := r.Delete(ctx, candidate); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting GarageNode %s: %w", candidate.Name, err)
		}
		if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonScaleDownSafe, "storage scale-down is progressing safely"); err != nil {
			return err
		}
		return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageTopologyDraining,
			fmt.Sprintf("draining Auto-mode storage GarageNode %s; the next ordinal remains online until this Garage layout transition finishes", candidate.Name))
	}

	// Desired object membership is converged. It is not safe to report topology
	// readiness until every desired GarageNode has completed reconciliation and
	// Garage has retired every older layout version.
	if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse, garagev1beta1.ReasonScaleDownSafe, "storage scale-down within replication factor"); err != nil {
		return err
	}
	if desiredReplicas == 0 && len(existing) == 0 {
		return r.clearStorageTopologyReadyCondition(ctx, cluster)
	}
	ready, _, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, false)
	if barrierErr != nil {
		waitingMessage = "Auto-mode storage membership exists, but Garage layout convergence cannot be verified: " + barrierErr.Error()
	}
	if barrierErr != nil || !ready {
		return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync, waitingMessage)
	}
	return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionTrue,
		garagev1beta1.ReasonStorageTopologyConverged,
		"Auto-mode storage GarageNodes match the desired membership and Garage reports no active data migration")
}

// countLiveStorageNodes counts operator-owned storage GarageNodes that would
// survive a scale-down to the desired set: a node is counted when it is in the
// keep-set (desiredByName), is not being deleted, and carries a positive
// capacity. Capacity nil/zero means it contributes no roled storage to Garage's
// replication accounting, so it does not help satisfy the factor.
func countLiveStorageNodes(existing map[string]*garagev1beta1.GarageNode, desiredByName map[string]bool) int {
	n := 0
	for name, node := range existing {
		if !desiredByName[name] {
			continue
		}
		if !node.DeletionTimestamp.IsZero() {
			continue
		}
		if node.Spec.Capacity == nil || node.Spec.Capacity.IsZero() {
			continue
		}
		n++
	}
	return n
}

// setScaleDownBlockedCondition sets the StorageScaleDownBlocked condition via
// the conflict-retrying status writer. When set False it also clears any
// previously-recorded blocked condition so a recovered cluster's status is
// clean. The mutate closure is re-applied on conflict re-fetch.
func (r *GarageClusterReconciler) setScaleDownBlockedCondition(ctx context.Context, cluster *garagev1beta2.GarageCluster, status metav1.ConditionStatus, reason, message string) error {
	apply := func() {
		if status == metav1.ConditionFalse {
			// Only keep the cleared condition if it already existed; avoid adding
			// a noisy False condition to clusters that never tripped the guard.
			if meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageScaleDownBlocked) == nil {
				return
			}
		}
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageScaleDownBlocked,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: cluster.Generation,
		})
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}

func (r *GarageClusterReconciler) setStorageTopologyReadyCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	apply := func() {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionStorageTopologyReady,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: cluster.Generation,
		})
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
}

func (r *GarageClusterReconciler) clearStorageTopologyReadyCondition(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageTopologyReady) == nil {
		return nil
	}
	apply := func() {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionStorageTopologyReady)
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, cluster, apply)
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
		// Named node-local pools are operator-owned too, but their lifecycle is
		// independent of the default Auto/Manual pool. Never scale or eject
		// them through the default-pool ordinal reconciler.
		if n.Spec.Backing == garagev1beta1.NodeBackingNodeLocalPool {
			continue
		}
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
// legacyDataPVC is the {name, size} pair the migration path threads from
// listed PVCs into buildAutoModeStorageNode so the resulting GarageNode's
// DataPaths[i].Size mirrors the legacy PVC's requested storage. Without
// Size the per-node ConfigMap renders multi-HDD data_dir entries without
// a capacity field, which Garage's parser rejects (#205).
type legacyDataPVC struct {
	name string
	size *resource.Quantity
}

func (r *GarageClusterReconciler) buildAutoModeStorageNode(
	cluster *garagev1beta2.GarageCluster,
	ordinal int32,
	nodeID, metadataPVC string,
	dataPVCs []legacyDataPVC,
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

	// spec.zoneFrom (#294) is carried down to the node so the per-node
	// controller can resolve it once its pod is scheduled — the zone is a
	// property of where the pod landed, which nothing knows at generation time.
	// Deliberately storage-only: see buildAutoModeGatewayNode.
	var zoneFrom *garagev1beta1.ZoneSource
	if cluster.Spec.ZoneFrom != nil {
		zoneFrom = &garagev1beta1.ZoneSource{NodeLabel: cluster.Spec.ZoneFrom.NodeLabel}
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
		if cluster.Spec.Storage.Metadata.Selector != nil {
			storage.Metadata.Selector = cluster.Spec.Storage.Metadata.Selector.DeepCopy()
		}
		storage.Metadata.Labels = maps.Clone(cluster.Spec.Storage.Metadata.Labels)
		storage.Metadata.Annotations = maps.Clone(cluster.Spec.Storage.Metadata.Annotations)
		// Propagate the volume type so `storage.metadata.type: EmptyDir` reaches
		// the per-node GarageNode (#283). Without this the node controller sees a
		// bare `{}` metadata volume and either produces an invalid StatefulSet
		// (no size → no PVC template, no EmptyDir, but the pod still mounts `meta`)
		// or silently provisions a PVC (size set). Mirrors the multi-path branch.
		if cluster.Spec.Storage.Metadata.Type != "" {
			storage.Metadata.Type = garagev1beta1.VolumeType(cluster.Spec.Storage.Metadata.Type)
		}
	}

	// Data volume(s):
	//   * len(dataPVCs) > 1  → multi-HDD migration: one DataPaths[] entry per legacy PVC.
	//   * len(dataPVCs) == 1 → single-HDD migration: storage.data.existingClaim.
	//   * len(dataPVCs) == 0 → fresh create: pass through cluster.Spec.Storage.Data
	//                          (or its Paths[]) so the GarageNode controller provisions
	//                          via volumeClaimTemplates.
	// clusterPaths is the index-aligned source of per-disk path/readOnly when
	// the cluster spec declared a multi-HDD layout. Migration uses these to
	// preserve the user's original mount paths so Garage's on-disk DataLayout
	// (../garage src/block/layout.rs `update`) sees the same paths it indexed
	// pre-upgrade — otherwise partitions get reassigned and blocks are
	// refetched from peers even though they live at the new mount.
	var clusterPaths []garagev1beta2.DataPath
	if cluster.Spec.Storage.Data != nil {
		clusterPaths = cluster.Spec.Storage.Data.Paths
	}

	switch {
	case len(dataPVCs) > 1:
		paths := make([]garagev1beta1.NodeVolumeConfig, 0, len(dataPVCs))
		for i, pvc := range dataPVCs {
			entry := garagev1beta1.NodeVolumeConfig{ExistingClaim: pvc.name}
			// Garage rejects multi-`data_dir` entries with no capacity
			// (config.rs DataDir requires capacity unless read_only=true).
			// Carry the legacy PVC's requested storage forward so the per-node
			// ConfigMap renderer emits `capacity = "<size>"`.
			if pvc.size != nil && !pvc.size.IsZero() {
				s := pvc.size.DeepCopy()
				entry.Size = &s
			}
			if i < len(clusterPaths) {
				entry.Path = clusterPaths[i].Path
				entry.ReadOnly = clusterPaths[i].ReadOnly
			}
			paths = append(paths, entry)
		}
		storage.DataPaths = paths
	case len(dataPVCs) == 1:
		storage.Data = &garagev1beta1.NodeVolumeConfig{ExistingClaim: dataPVCs[0].name}
	default:
		// Fresh create — mirror cluster's Data spec. Multi-path on the cluster
		// projects to per-node DataPaths[] (one PVC per path on each node).
		if cluster.Spec.Storage.Data != nil && len(cluster.Spec.Storage.Data.Paths) > 0 {
			paths := make([]garagev1beta1.NodeVolumeConfig, 0, len(cluster.Spec.Storage.Data.Paths))
			topLevel := cluster.Spec.Storage.Data
			for _, p := range cluster.Spec.Storage.Data.Paths {
				v := garagev1beta1.NodeVolumeConfig{Path: p.Path, ReadOnly: p.ReadOnly}
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
				if p.Volume != nil && p.Volume.Selector != nil {
					v.Selector = p.Volume.Selector.DeepCopy()
				} else if topLevel.Selector != nil {
					v.Selector = topLevel.Selector.DeepCopy()
				}
				if p.Volume != nil && len(p.Volume.Labels) > 0 {
					v.Labels = maps.Clone(p.Volume.Labels)
				} else {
					v.Labels = maps.Clone(topLevel.Labels)
				}
				if p.Volume != nil && len(p.Volume.Annotations) > 0 {
					v.Annotations = maps.Clone(p.Volume.Annotations)
				} else {
					v.Annotations = maps.Clone(topLevel.Annotations)
				}
				// Propagate Volume.Type so cluster-level `type: EmptyDir` on a
				// per-disk volume reaches the GarageNode unchanged (audit #4).
				if p.Volume != nil && p.Volume.Type != "" {
					v.Type = garagev1beta1.VolumeType(p.Volume.Type)
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
			if cluster.Spec.Storage.Data.Selector != nil {
				storage.Data.Selector = cluster.Spec.Storage.Data.Selector.DeepCopy()
			}
			storage.Data.Labels = maps.Clone(cluster.Spec.Storage.Data.Labels)
			storage.Data.Annotations = maps.Clone(cluster.Spec.Storage.Data.Annotations)
			// Propagate the volume type so `storage.data.type: EmptyDir` reaches
			// the per-node GarageNode (#283) — same rationale as the metadata
			// block above and the multi-path branch. On EmptyDir any `size` is
			// carried through as the EmptyDir sizeLimit by the node controller.
			if cluster.Spec.Storage.Data.Type != "" {
				storage.Data.Type = garagev1beta1.VolumeType(cluster.Spec.Storage.Data.Type)
			}
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
				labelAutoNodeSlot: name,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{
				Name: cluster.Name,
			},
			NodeID:   nodeID,
			Zone:     zone,
			ZoneFrom: zoneFrom,
			Capacity: cap,
			Tags:     tags,
			Storage:  storage,
			Env:      cluster.Spec.Storage.Env,
			EnvFrom:  cluster.Spec.Storage.EnvFrom,
		},
	}

	// Propagate the cluster's publicEndpoint onto each operator-owned GarageNode
	// so the GarageNode controller can derive rpc_public_addr from the per-pod
	// LoadBalancer Service the cluster controller already provisions at
	// `<cluster>-<ord>-rpc`. Without this, pods come up with no rpc_public_addr
	// and peers learn the pod's TCP source IP — the `known_addrs` pollution
	// failure mode that drops cross-cluster RPC reliability.
	//
	// Only LoadBalancer with perNode=true gives each pod its own externally
	// routable address; the other PublicEndpoint shapes (single shared LB,
	// shared NodePort) don't change behavior per-pod, so we skip propagation
	// to avoid having the GarageNode controller create redundant per-node
	// Services that overlap with the cluster-owned one.
	if ep := cluster.Spec.PublicEndpoint; ep != nil &&
		ep.Type == publicEndpointTypeLoadBalancer &&
		ep.LoadBalancer != nil && ep.LoadBalancer.PerNode {
		nodeEP, err := convertClusterPublicEndpointToNode(ep)
		if err != nil {
			return nil, fmt.Errorf("converting publicEndpoint for GarageNode %s: %w", name, err)
		}
		node.Spec.PublicEndpoint = nodeEP
	}

	// Per-ordinal storage rpc_public_addr (symmetric with the gateway tier). A
	// single shared address can only route to one of N storage pods cross-region;
	// {ordinal} substitution gives each pod its own advertised address. Skip when
	// a per-node publicEndpoint already supplies one — its LoadBalancer ingress
	// address wins (NodeNetworkConfig.RPCPublicAddr would otherwise override the
	// live LB address in reconcileNodeConfigMap).
	if node.Spec.PublicEndpoint == nil {
		if s := cluster.Spec.Storage; s != nil && s.RPCPublicAddr != "" {
			addr := strings.ReplaceAll(s.RPCPublicAddr, "{ordinal}", strconv.Itoa(int(ordinal)))
			node.Spec.Network = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: addr}
		}
	}

	if err := controllerutil.SetControllerReference(cluster, node, r.Scheme); err != nil {
		return nil, err
	}

	return node, nil
}

// publicEndpointsEqual returns true when two GarageNode publicEndpoint configs
// have the same observable shape. JSON marshaling normalizes ordering and
// nil/empty distinctions, which is sufficient for drift detection on a field
// the operator overwrites wholesale.
func publicEndpointsEqual(a, b *garagev1beta1.PublicEndpointConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}

// convertClusterPublicEndpointToNode copies a v1beta2.PublicEndpointConfig into
// a v1beta1.PublicEndpointConfig by JSON round-trip. The two structures are
// field-compatible (see api/v1beta1/garagecluster_conversion.go for the
// authoritative use of this same pattern); a JSON round-trip avoids hand-coding
// the conversion and ensures we automatically pick up any new fields added on
// either side.
func convertClusterPublicEndpointToNode(src *garagev1beta2.PublicEndpointConfig) (*garagev1beta1.PublicEndpointConfig, error) {
	if src == nil {
		return nil, nil
	}
	b, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	dst := &garagev1beta1.PublicEndpointConfig{}
	if err := json.Unmarshal(b, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

// envVarsEqual returns true when two EnvVar slices are semantically equal
// (order-independent comparison of Name + Value + ValueFrom).
func envVarsEqual(a, b []corev1.EnvVar) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	byName := make(map[string]corev1.EnvVar, len(a))
	for _, e := range a {
		byName[e.Name] = e
	}
	for _, e := range b {
		got, ok := byName[e.Name]
		if !ok {
			return false
		}
		if got.Value != e.Value {
			return false
		}
		if (got.ValueFrom == nil) != (e.ValueFrom == nil) {
			return false
		}
		if got.ValueFrom != nil && *got.ValueFrom != *e.ValueFrom {
			return false
		}
	}
	return true
}

// envFromSourcesEqual returns true when two EnvFromSource slices are
// semantically equal (order-independent comparison of Prefix + ConfigMapRef
// + SecretRef).
func envFromSourcesEqual(a, b []corev1.EnvFromSource) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	type key struct {
		prefix    string
		configMap string
		secret    string
	}
	buildKey := func(s corev1.EnvFromSource) key {
		k := key{prefix: s.Prefix}
		if s.ConfigMapRef != nil {
			k.configMap = s.ConfigMapRef.Name
		}
		if s.SecretRef != nil {
			k.secret = s.SecretRef.Name
		}
		return k
	}
	index := make(map[key]int, len(a))
	for _, s := range a {
		index[buildKey(s)]++
	}
	for _, s := range b {
		k := buildKey(s)
		index[k]--
		if index[k] < 0 {
			return false
		}
	}
	return true
}

// zoneSourcesEqual compares two optional ZoneSources.
func zoneSourcesEqual(a, b *garagev1beta1.ZoneSource) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || a.NodeLabel == b.NodeLabel
}

// applyAutoModeStorageNodeUpdate copies the fields owned by the default
// Auto-mode pool while preserving migration-pinned existingClaim references.
func applyAutoModeStorageNodeUpdate(current, desired *garagev1beta1.GarageNode) {
	current.Spec.Zone = desired.Spec.Zone
	current.Spec.ZoneFrom = desired.Spec.ZoneFrom
	current.Spec.Capacity = desired.Spec.Capacity
	current.Spec.Tags = desired.Spec.Tags
	current.Spec.Env = desired.Spec.Env
	current.Spec.EnvFrom = desired.Spec.EnvFrom
	current.Spec.PublicEndpoint = desired.Spec.PublicEndpoint
	current.Spec.Network = desired.Spec.Network.DeepCopy()

	if current.Spec.Storage == nil {
		current.Spec.Storage = desired.Spec.Storage
		return
	}
	if desired.Spec.Storage == nil {
		return
	}

	if current.Spec.Storage.Metadata == nil {
		current.Spec.Storage.Metadata = desired.Spec.Storage.Metadata
	} else if current.Spec.Storage.Metadata.ExistingClaim == "" && desired.Spec.Storage.Metadata != nil {
		current.Spec.Storage.Metadata.Size = desired.Spec.Storage.Metadata.Size
		current.Spec.Storage.Metadata.StorageClassName = desired.Spec.Storage.Metadata.StorageClassName
	}
	if desired.Spec.Storage.Data != nil {
		if current.Spec.Storage.Data == nil {
			current.Spec.Storage.Data = desired.Spec.Storage.Data
		} else if current.Spec.Storage.Data.ExistingClaim == "" {
			current.Spec.Storage.Data.Size = desired.Spec.Storage.Data.Size
			current.Spec.Storage.Data.StorageClassName = desired.Spec.Storage.Data.StorageClassName
		}
	}
	if len(desired.Spec.Storage.DataPaths) == 0 {
		return
	}
	for _, path := range current.Spec.Storage.DataPaths {
		if path.ExistingClaim != "" {
			return
		}
	}
	current.Spec.Storage.DataPaths = desired.Spec.Storage.DataPaths
}

// autoModeStorageNodeNeedsUpdate returns true when the desired GarageNode spec
// differs from the current one on a field the operator owns.
func autoModeStorageNodeNeedsUpdate(current, desired *garagev1beta1.GarageNode) bool {
	if current.Spec.Zone != desired.Spec.Zone {
		return true
	}
	if !zoneSourcesEqual(current.Spec.ZoneFrom, desired.Spec.ZoneFrom) {
		return true
	}
	// Per-ordinal rpc_public_addr drift (spec.storage.rpcPublicAddr changes).
	cn, dn := current.Spec.Network, desired.Spec.Network
	if (cn == nil) != (dn == nil) {
		return true
	}
	if cn != nil && dn != nil && cn.RPCPublicAddr != dn.RPCPublicAddr {
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
	if !tagSetEqual(current.Spec.Tags, desired.Spec.Tags) {
		return true
	}
	if !publicEndpointsEqual(current.Spec.PublicEndpoint, desired.Spec.PublicEndpoint) {
		return true
	}
	// Storage size / storage class drift only meaningful when not bound to existingClaim.
	if !envVarsEqual(current.Spec.Env, desired.Spec.Env) {
		return true
	}
	if !envFromSourcesEqual(current.Spec.EnvFrom, desired.Spec.EnvFrom) {
		return true
	}
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
	if len(existing) == 0 {
		if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonScaleDownSafe, "removed Auto-mode storage membership is fully drained"); err != nil {
			return err
		}
		return r.clearStorageTopologyReadyCondition(ctx, cluster)
	}

	candidates := make([]*garagev1beta1.GarageNode, 0, len(existing))
	for _, node := range existing {
		candidates = append(candidates, node)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, leftOK := parseAutoModeOrdinal(autoNodeSlotForCycle(candidates[i]), cluster.Name)
		right, rightOK := parseAutoModeOrdinal(autoNodeSlotForCycle(candidates[j]), cluster.Name)
		if leftOK && rightOK && left != right {
			return left > right
		}
		return candidates[i].Name > candidates[j].Name
	})

	ready, _, waitingMessage, barrierErr := r.clusterLayoutReadyForMutation(ctx, cluster, false, candidates[0].Name)
	if barrierErr != nil {
		waitingMessage = "refusing to drain the removed Auto-mode storage tier until Garage layout convergence can be verified: " + barrierErr.Error()
	}
	if barrierErr != nil || !ready {
		if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonScaleDownSafe, "removed storage tier drain is waiting, not safety-blocked"); err != nil {
			return err
		}
		return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync, waitingMessage)
	}

	candidate := candidates[0]
	if err := r.prepareGarageNodeDeletionDrain(ctx, cluster, candidate); err != nil {
		if statusErr := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonScaleDownSafe, "removed storage tier drain is waiting for reversible preparation"); statusErr != nil {
			return statusErr
		}
		return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
			garagev1beta1.ReasonStorageTopologyWaitingForLayoutSync,
			"refusing to mark removed-tier GarageNode terminating until storage-drain preparation succeeds: "+err.Error())
	}
	log.Info("Deleting one Auto-mode GarageNode (storage tier removed)", "name", candidate.Name)
	if err := r.Delete(ctx, candidate); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting GarageNode %s: %w", candidate.Name, err)
	}
	if err := r.setScaleDownBlockedCondition(ctx, cluster, metav1.ConditionFalse,
		garagev1beta1.ReasonScaleDownSafe, "removed storage tier drain is progressing safely"); err != nil {
		return err
	}
	return r.setStorageTopologyReadyCondition(ctx, cluster, metav1.ConditionFalse,
		garagev1beta1.ReasonStorageTopologyDraining,
		fmt.Sprintf("draining removed Auto-mode storage GarageNode %s before retiring another member", candidate.Name))
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
	return r.clearStorageTopologyReadyCondition(ctx, cluster)
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
		// Strip the retry annotation with conflict retry. Without retry, a
		// competing reconcile that bumped ResourceVersion between the status
		// write above and this Update would 409 and the annotation persists —
		// the next reconcile would clear the condition again, looping forever
		// with no user-visible signal.
		key := client.ObjectKeyFromObject(cluster)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &garagev1beta2.GarageCluster{}
			if err := r.Get(ctx, key, latest); err != nil {
				return err
			}
			if _, ok := latest.Annotations[garagev1beta1.AnnotationRetryMigration]; !ok {
				// Already stripped by a concurrent actor; nothing to do.
				return nil
			}
			delete(latest.Annotations, garagev1beta1.AnnotationRetryMigration)
			return r.Update(ctx, latest)
		}); err != nil {
			return fmt.Errorf("removing retry-migration annotation: %w", err)
		}
		// Keep the in-memory cluster in sync so the rest of this reconcile pass
		// sees the annotation as removed.
		delete(cluster.Annotations, garagev1beta1.AnnotationRetryMigration)
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
		// Legacy STS is gone, but a prior migration run may have orphan-deleted
		// the STS and then failed to terminate the (now orphan) legacy pods. If
		// any pod matching the legacy naming `<cluster>-<N>` is still around,
		// it'll multi-mount the RWO PVCs along with the new per-node STSes
		// (local-path / hostPath bypasses RWO enforcement), producing
		// concurrent LMDB writers, EAGAIN errors, and divergent node identities.
		// Sweep them up here before claiming Completed so the function is
		// idempotently safe across restarts.
		if err := r.deleteOrphanLegacyStoragePods(ctx, cluster); err != nil {
			return fmt.Errorf("sweeping orphan legacy storage pods: %w", err)
		}
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

	// replicas=0 + matching legacy PVCs is dangerous: the loop would iterate
	// zero times, the STS would be orphan-deleted, the migration marked
	// Completed, and the metadata/data PVCs would be left stranded with no
	// controller. Refuse and surface a clear status condition so the user
	// can either scale the STS back up (to migrate) or delete the leftover
	// PVCs intentionally before re-running. (audit #6)
	if replicas == 0 && legacyStorageHasLeftoverPVCs(pvcList.Items, cluster.Name, dataPVCsByOrdinal) {
		return r.failMigration(ctx, cluster, "legacy storage StatefulSet has replicas=0 but legacy PVCs still exist; scale the StatefulSet back up to its original replica count before the operator can migrate, or delete the leftover PVCs to abandon their data")
	}

	// Try to discover node IDs from live cluster layout (best effort: identity
	// also survives via the node_key in the metadata PVC, so this is
	// belt-and-suspenders).
	nodeIDByOrdinal := r.discoverLegacyNodeIDsByOrdinal(ctx, cluster, replicas)

	// Whether the legacy STS provisioned each volume via a volumeClaimTemplate.
	// A pre-v0.6 EmptyDir cluster (#286) has no volumeClaimTemplates, so there
	// is nothing to adopt — migration for those volumes is "create fresh" and
	// buildAutoModeStorageNode renders EmptyDir from spec.storage (post-#284).
	// This is spec-independent: it reflects what the running workload actually
	// has, so a cluster whose spec drifted still migrates against reality. A
	// PVC-backed legacy volume is always adopted (preserving data + the
	// node_key that fixes node identity) regardless of the current spec type.
	legacyVCTNames := map[string]bool{}
	for i := range legacySTS.Spec.VolumeClaimTemplates {
		legacyVCTNames[legacySTS.Spec.VolumeClaimTemplates[i].Name] = true
	}
	metadataIsPVC := legacyVCTNames[metadataVolName]
	dataIsPVC := legacyVCTNames[dataVolName]

	for ord := int32(0); ord < replicas; ord++ {
		nodeID := nodeIDByOrdinal[ord]

		// Metadata: adopt the legacy PVC by name only when the legacy STS was
		// PVC-backed. For EmptyDir metadata there is no PVC and no persisted
		// node_key, so leave metadataPVC empty (fresh EmptyDir volume) and drop
		// any discovered node ID — it is stale the moment the fresh pod boots
		// with a new identity.
		metadataPVC := ""
		if metadataIsPVC {
			metadataPVC = fmt.Sprintf("%s-%s-%d", metadataVolName, cluster.Name, ord)
			mPVC := &corev1.PersistentVolumeClaim{}
			if err := r.Get(ctx, types.NamespacedName{Name: metadataPVC, Namespace: cluster.Namespace}, mPVC); err != nil {
				msg := fmt.Sprintf("ordinal %d: metadata PVC %q not found: %v", ord, metadataPVC, err)
				return r.failMigration(ctx, cluster, msg)
			}
		} else {
			nodeID = ""
		}

		// Resolve the data PVCs for this ordinal. Prefer the multi-HDD layout
		// when present; otherwise fall back to the single-HDD name — but only
		// when the legacy data volume was PVC-backed. EmptyDir data has nothing
		// to adopt, so leave dataPVCs empty (fresh EmptyDir volume via spec).
		dataPVCs := dataPVCsByOrdinal[ord]
		if len(dataPVCs) == 0 && dataIsPVC {
			single := fmt.Sprintf("%s-%s-%d", dataVolName, cluster.Name, ord)
			dPVC := &corev1.PersistentVolumeClaim{}
			if err := r.Get(ctx, types.NamespacedName{Name: single, Namespace: cluster.Namespace}, dPVC); err != nil {
				msg := fmt.Sprintf("ordinal %d: data PVC %q not found: %v", ord, single, err)
				return r.failMigration(ctx, cluster, msg)
			}
			dataPVCs = []legacyDataPVC{{name: single, size: pvcRequestedStorage(dPVC)}}
		}

		desired, err := r.buildAutoModeStorageNode(cluster, ord, nodeID, metadataPVC, dataPVCs)
		if err != nil {
			return fmt.Errorf("building migrated GarageNode for ordinal %d: %w", ord, err)
		}

		// Create or update — a previous reconcile may have created it but
		// crashed before recording the status; we tolerate that here.
		existing := &garagev1beta1.GarageNode{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing); err == nil {
			log.Info("Migration: GarageNode already exists, leaving in place", "name", desired.Name)
		} else if errors.IsNotFound(err) {
			dataPVCNames := make([]string, len(dataPVCs))
			for i, p := range dataPVCs {
				dataPVCNames[i] = p.name
			}
			log.Info("Migration: creating GarageNode bound to legacy PVCs", "name", desired.Name, "metadataPVC", metadataPVC, "dataPVCs", dataPVCNames, "nodeID", nodeIDByOrdinal[ord])
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

// deleteOrphanLegacyStoragePods reaps pods whose names match the legacy
// per-ordinal naming `<cluster>-<N>` and which carry no controllerRef. They
// originate from the pre-#190 cluster-level StatefulSet that an earlier
// migration run orphan-deleted; if the subsequent pod-delete step failed to
// terminate them (timing, finalizer, kubelet busy), they keep running
// forever and dual-mount the RWO metadata/data PVCs alongside the new
// per-node STS pods. On local-path / hostPath PVs (where RWO is not enforced
// at the kernel) that produces concurrent LMDB writers, EAGAIN errors, and
// in the worst case mismatched node identities between the in-memory and
// on-disk node_key. Idempotent: NotFound is fine.
func (r *GarageClusterReconciler) deleteOrphanLegacyStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}
	prefix := cluster.Name + "-"
	for i := range podList.Items {
		pod := &podList.Items[i]
		name := pod.Name
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		// Ordinal suffix must be a non-negative integer (`<cluster>-0`,
		// `<cluster>-1`, ...). This avoids matching `<cluster>-storage-0-0`
		// and other valid per-node STS pods.
		suffix := name[len(prefix):]
		if _, err := strconv.Atoi(suffix); err != nil {
			continue
		}
		// Only sweep orphan pods (no controllerRef). A live cluster-level STS
		// is impossible at this point — the caller already verified it's
		// absent — but be defensive: never delete a pod that another
		// controller still owns.
		if metav1.GetControllerOf(pod) != nil {
			continue
		}
		log.Info("Migration: sweeping orphan legacy storage pod", "pod", name)
		if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting orphan legacy pod %s: %w", name, err)
		}
	}
	return nil
}

// legacyStorageHasLeftoverPVCs reports whether any legacy-shape PVCs for the
// cluster still exist in the namespace. Used to refuse migration when the
// legacy STS has replicas=0 but PVCs remain (audit #6). Both metadata
// (`metadata-<cluster>-<N>`) and data (single-HDD `data-<cluster>-<N>`,
// multi-HDD `data-<idx>-<cluster>-<N>`) shapes count.
func legacyStorageHasLeftoverPVCs(pvcs []corev1.PersistentVolumeClaim, clusterName string, multiHDD map[int32][]legacyDataPVC) bool {
	if len(multiHDD) > 0 {
		return true
	}
	metaPrefix := metadataVolName + "-" + clusterName + "-"
	singleDataPrefix := dataVolName + "-" + clusterName + "-"
	for i := range pvcs {
		name := pvcs[i].Name
		if !strings.HasPrefix(name, metaPrefix) && !strings.HasPrefix(name, singleDataPrefix) {
			continue
		}
		var suffix string
		switch {
		case strings.HasPrefix(name, metaPrefix):
			suffix = name[len(metaPrefix):]
		default:
			suffix = name[len(singleDataPrefix):]
		}
		if _, err := strconv.Atoi(suffix); err == nil {
			return true
		}
	}
	return false
}

// bucketLegacyDataPVCs scans a list of PVCs and returns a map of ordinal to
// the sorted list of multi-HDD data PVCs (`data-<idx>-<cluster>-<ord>`)
// belonging to that ordinal, ordered by idx ascending. Single-HDD PVCs
// (`data-<cluster>-<ord>`) are not returned here — the caller handles those by
// direct name lookup. PVCs with names that don't match the multi-HDD layout
// are silently ignored. Each returned entry carries the PVC's requested
// storage so the migration can populate `DataPaths[i].Size`.
func bucketLegacyDataPVCs(pvcs []corev1.PersistentVolumeClaim, clusterName string) map[int32][]legacyDataPVC {
	type entry struct {
		idx int
		pvc legacyDataPVC
	}
	tmp := map[int32][]entry{}
	prefix := dataVolName + "-"
	clusterMarker := "-" + clusterName + "-"
	for i := range pvcs {
		pvc := &pvcs[i]
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
		// After the index, expect exactly "-<cluster>-<ord>" where <ord> is a
		// pure non-negative integer with no further '-'. Requiring the ordinal
		// token to be the WHOLE remaining tail (no embedded dash) prevents
		// adopting a foreign cluster's PVC whose name happens to prefix-match
		// this cluster's name, e.g. clusterName="c" must not bucket
		// `data-0-c-extra-2` (a PVC of some other cluster "c-extra").
		tail := rest[dash:]
		if !strings.HasPrefix(tail, clusterMarker) {
			continue
		}
		ordStr := tail[len(clusterMarker):]
		if ordStr == "" || strings.ContainsRune(ordStr, '-') {
			continue
		}
		ord64, err := strconv.ParseInt(ordStr, 10, 32)
		if err != nil {
			continue
		}
		ord := int32(ord64)
		tmp[ord] = append(tmp[ord], entry{idx: idx, pvc: legacyDataPVC{name: name, size: pvcRequestedStorage(pvc)}})
	}
	out := make(map[int32][]legacyDataPVC, len(tmp))
	for ord, entries := range tmp {
		sort.Slice(entries, func(i, j int) bool { return entries[i].idx < entries[j].idx })
		items := make([]legacyDataPVC, len(entries))
		for i, e := range entries {
			items[i] = e.pvc
		}
		out[ord] = items
	}
	return out
}

// pvcRequestedStorage returns the storage request from a PVC spec, or nil
// when unset. The migration prefers spec.resources.requests over
// status.capacity because:
//   - spec is the user-declared size, which matches what Garage was
//     configured with originally;
//   - status.capacity may be larger after a resize, which is fine, but it
//     can also be unset if the PVC is still Pending.
//
// The fallback in the per-node ConfigMap renderer (garagenode_controller.go)
// independently looks up PVCs by name at render time, so a nil here is not
// catastrophic — it just means the heal happens at config render rather
// than at migration time.
func pvcRequestedStorage(pvc *corev1.PersistentVolumeClaim) *resource.Quantity {
	if pvc == nil {
		return nil
	}
	if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok && !req.IsZero() {
		q := req.DeepCopy()
		return &q
	}
	if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok && !cap.IsZero() {
		q := cap.DeepCopy()
		return &q
	}
	return nil
}

// discoverLegacyNodeIDsByOrdinal fetches the Garage cluster layout and maps
// pod-name tags to ordinals so the migrated GarageNodes can lock to the same
// node IDs as the legacy pods. Returns an empty map on any error — the
// metadata PVC's node_key is the canonical source of identity, so this is
// strictly belt-and-suspenders. Federated clusters deliberately skip this
// heuristic: sites may share namespace, cluster name, and ordinal tags, making
// a legacy layout-only match ambiguous across Kubernetes clusters.
func (r *GarageClusterReconciler) discoverLegacyNodeIDsByOrdinal(ctx context.Context, cluster *garagev1beta2.GarageCluster, replicas int32) map[int32]string {
	out := map[int32]string{}
	log := logf.FromContext(ctx)
	if len(cluster.Spec.RemoteClusters) > 0 {
		log.V(1).Info("Migration: skipping ambiguous layout-based node-ID discovery for federated cluster; identity will be supplied by metadata PVC")
		return out
	}

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
