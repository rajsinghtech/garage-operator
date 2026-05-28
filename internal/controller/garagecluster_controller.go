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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageClusterFinalizer = "garagecluster.garage.rajsingh.info/finalizer"
	defaultGarageImage     = "dxflrs/garage:v2.3.0"
	defaultGarageTag       = "v2.3.0"
	defaultS3Region        = "garage"
	defaultAppName         = "garage"

	// envGarageNodeHost is the name of the env var Garage reads at startup to
	// learn its own externally-routable host (set from the pod IP via downward API).
	envGarageNodeHost = "GARAGE_NODE_HOST"

	// Garage, by default looks for a config file at /etc/garage.toml
	// Exposing the config map there is not possible without a subPath mount, meaning
	// changes to the configmap would not be propagated to existing pods.
	// So we use a different path and set the appropriate env var instead
	envGarageConfigFile      = "GARAGE_CONFIG_FILE"
	garageConfigFileLocation = configMountPath + "/" + configFileName

	// Health status constants
	healthStatusHealthy = "healthy"

	// connectErrUnknown is the fallback message when ConnectClusterNodes
	// returns Success=false without an explicit error string.
	connectErrUnknown = "unknown"
)

// GarageClusterReconciler reconciles a GarageCluster object
type GarageClusterReconciler struct {
	client.Client
	APIReader     client.Reader
	Scheme        *runtime.Scheme
	ClusterDomain string
	DefaultImage  string
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

func (r *GarageClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	_ = log // Used in sub-functions via context

	cluster := &garagev1beta2.GarageCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !cluster.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(cluster, garageClusterFinalizer) {
			if err := r.finalize(ctx, cluster); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(cluster, garageClusterFinalizer)
			if err := r.Update(ctx, cluster); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(cluster, garageClusterFinalizer) {
		controllerutil.AddFinalizer(cluster, garageClusterFinalizer)
		if err := r.Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if cluster.Spec.Maintenance != nil && cluster.Spec.Maintenance.Suspended {
		log.Info("Reconciliation paused")
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	// Ensure RPC secret exists
	if _, err := r.ensureRPCSecret(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update ConfigMap(s) and get config hashes for pod restart triggering.
	// Storage and gateway tiers may use different rpc_public_addr values when both
	// are declared with a gateway-specific spec.gateway.rpcPublicAddr.
	//
	// storageConfigHash is consumed by per-node GarageNode reconciles (operator-
	// owned in Auto mode, user-owned in Manual mode). The cluster-level Reconcile
	// no longer drives a storage STS directly, but the ConfigMap must still be
	// reconciled here so the per-node STSes pick it up.
	_, gatewayConfigHash, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update headless Service for RPC
	if err := r.reconcileHeadlessService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update API Service (primary <cr>, scoped to storage tier when
	// present, else to the gateway tier for edge-gateway clusters)
	if err := r.reconcileAPIService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Reconcile PodDisruptionBudget for the storage tier (covers all per-node
	// STSes via cluster+tier label selector, since each per-node STS has 1
	// replica and a per-STS PDB would be meaningless).
	if err := r.reconcileTierPodDisruptionBudget(ctx, cluster, tierStorage); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}
	// Reconcile PodDisruptionBudget for the gateway tier (gateway pods serve
	// S3/Admin traffic but hold no data, so a PDB protects request availability
	// across node drains, not durability).
	if err := r.reconcileTierPodDisruptionBudget(ctx, cluster, tierGateway); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Per-tier gateway Service is created only for unified clusters (both
	// storage + gateway). Without a storage tier the primary <cr> already
	// targets the gateway pods, so a sibling Service would be redundant.
	if cluster.HasStorageTier() && cluster.HasGatewayTier() {
		if err := r.reconcileGatewayAPIService(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}
	} else {
		if err := r.deleteGatewayAPIService(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}
	}

	// Create, update, or delete the dedicated external RPC service for publicEndpoint
	if err := r.reconcilePublicEndpointService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Reconcile workloads for each declared tier.
	//
	// Layout policy semantics (post-#190):
	//   - Manual: user-managed GarageNode CRs own each node's StatefulSet; the
	//     operator skips storage-tier workload reconciliation entirely.
	//   - Auto:   operator-managed GarageNode CRs (one per storage replica) own
	//     each node's StatefulSet. Existing pre-#190 single-STS clusters are
	//     migrated automatically on first reconcile.
	//
	// In both cases the cluster-level storage StatefulSet (`<name>`) is no
	// longer created post-#190. The gateway tier is untouched and continues to
	// use a single Deployment with EmptyDir.
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		// Auto mode: migrate any pre-#190 legacy storage STS, then reconcile
		// the per-node GarageNodes that replace it.
		if cluster.HasStorageTier() {
			if err := r.migrateLegacyStorageSTSIfNeeded(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("legacy STS migration: %w", err))
			}
			if err := r.reconcileAutoModeStorageNodes(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		} else {
			// No storage tier declared — clean up any leftover legacy STS plus
			// operator-owned child GarageNodes.
			if err := r.deleteStorageStatefulSet(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
			if err := r.deleteAutoModeStorageNodes(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		}

		if cluster.HasGatewayTier() {
			if err := r.reconcileGatewayStatefulSet(ctx, cluster, gatewayConfigHash); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		} else {
			if err := r.deleteGatewayStatefulSet(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		}
	} else {
		// Manual mode: if the previous policy was Auto and operator-owned
		// GarageNodes still exist, eject them so the user can take over.
		if err := r.ejectAutoModeStorageNodes(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("ejecting Auto-mode GarageNodes: %w", err))
		}
	}

	// Bootstrap cluster nodes if pods are running but cluster isn't formed.
	// Storage-tier clusters now also enter this path (issue #203): per-pod RPC
	// addresses change across restarts, Garage's on-disk peer_list cache holds
	// the stale IPs, and bootstrap_peers in garage.toml is empty unless the
	// user set spec.network.bootstrapPeers. Without a periodic ConnectClusterNodes
	// nudge from the operator, post-restart pods see siblings with addr: null
	// and never reconverge. bootstrapCluster skips layout assignment for
	// storage-tier clusters internally (the per-GarageNode controller owns it),
	// so only the connect-nodes half runs here.
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		if err := r.bootstrapCluster(ctx, cluster); err != nil {
			log.Error(err, "Failed to bootstrap cluster (will retry)")
			// Don't fail reconciliation, just log and continue
		}
	}

	// Connect to remote clusters for multi-cluster federation
	r.reconcileFederation(ctx, cluster)

	// Connect gateway tier pods to storage (local or remote). Gateway pods
	// participate in the layout with capacity=nil so FullReplication writes
	// reach their local DB — required by the S3 sig-auth get_local() path.
	if cluster.HasGatewayTier() {
		r.reconcileGatewayConnection(ctx, cluster)
		r.reconcileGatewayTombstones(ctx, cluster)
	}

	// Handle operational annotations — return error so controller-runtime requeues with backoff.
	// The annotation is retained on failure so the next reconcile retries the operation.
	if err := r.handleOperationalAnnotations(ctx, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// Reconcile worker variables (scrub/resync tuning) from spec.workers
	if err := r.reconcileWorkers(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile worker variables")
		// Non-fatal: worker tuning failure shouldn't block storage reconciliation
	}

	// Reconcile Prometheus ServiceMonitor
	if err := r.reconcileMonitoring(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile monitoring resources")
		// Non-fatal: monitoring failure shouldn't block storage reconciliation
	}

	// Update status with cluster health
	return r.updateStatusFromCluster(ctx, cluster)
}

func (r *GarageClusterReconciler) finalize(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	log.Info("Finalizing GarageCluster", "name", cluster.Name)

	// Collect node IDs from GarageNode CRs before they get deleted.
	// These are used as a fallback when tag-based matching fails (e.g., nodes
	// registered with legacy tags that don't include the cluster ownership tag).
	knownNodeIDs := r.collectGarageNodeIDs(ctx, cluster)

	// Remove nodes from Garage layout before deleting K8s resources.
	// This ensures nodes are properly deregistered from the cluster.
	if err := r.removeNodesFromLayout(ctx, cluster, knownNodeIDs); err != nil {
		// Log but don't fail finalization - nodes can be manually cleaned up
		log.Error(err, "Failed to remove nodes from layout (continuing with cleanup)")
	}

	// Delete owned resources in order: StatefulSet/Deployment, Services, ConfigMap
	// Note: Secret is auto-deleted via owner reference if controller-generated

	// Delete StatefulSet (for storage clusters)
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err == nil {
		log.Info("Deleting StatefulSet", "name", sts.Name)
		if err := r.Delete(ctx, sts); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete StatefulSet: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete operator-owned child GarageNodes (Auto-mode per-node CRs).
	// They'd also be cascade-deleted via ownerRef, but explicit Delete ensures
	// the GarageNode finalizer fires in a predictable order with respect to
	// the cluster-level layout cleanup above.
	gnList := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, gnList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:      cluster.Name,
			labelAppManagedBy: managedByOperatorValue,
		}),
	); err == nil {
		for i := range gnList.Items {
			n := &gnList.Items[i]
			log.Info("Deleting child GarageNode", "name", n.Name)
			if err := r.Delete(ctx, n); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete child GarageNode %s: %w", n.Name, err)
			}
		}
	}

	// Delete Deployment (for gateway clusters)
	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, deploy); err == nil {
		log.Info("Deleting Deployment", "name", deploy.Name)
		if err := r.Delete(ctx, deploy); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Deployment: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete API Services (primary + per-tier gateway sibling)
	for _, svcName := range []string{cluster.Name, cluster.Name + "-gateway"} {
		apiSvc := &corev1.Service{}
		if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, apiSvc); err == nil {
			log.Info("Deleting API Service", "name", apiSvc.Name)
			if err := r.Delete(ctx, apiSvc); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete API Service: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return err
		}
	}

	// Delete Headless Service
	headlessSvc := &corev1.Service{}
	headlessSvcName := cluster.Name + "-headless"
	if err := r.Get(ctx, types.NamespacedName{Name: headlessSvcName, Namespace: cluster.Namespace}, headlessSvc); err == nil {
		log.Info("Deleting Headless Service", "name", headlessSvc.Name)
		if err := r.Delete(ctx, headlessSvc); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Headless Service: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete ConfigMap(s)
	for _, cmName := range []string{cluster.Name + "-config", cluster.Name + "-gateway-config"} {
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm); err == nil {
			log.Info("Deleting ConfigMap", "name", cm.Name)
			if err := r.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete ConfigMap: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return err
		}
	}

	// Delete per-tier PodDisruptionBudgets (storage: "<cluster>", gateway:
	// "<cluster>-gateway"). OwnerReferences would trigger GC anyway, but the
	// explicit delete keeps finalization deterministic even if the ownerRef
	// got severed by an admin.
	for _, name := range []string{cluster.Name, cluster.Name + "-gateway"} {
		pdb := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, pdb)
		if errors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		log.Info("Deleting PDB", "name", pdb.Name)
		if err := r.Delete(ctx, pdb); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete PDB: %w", err)
		}
	}

	log.Info("GarageCluster finalization complete", "name", cluster.Name)
	return nil
}

// collectGarageNodeIDs collects node IDs from GarageNode CRs that belong to this cluster.
// Called before deletion so node IDs are available for layout cleanup even if tags don't match.
func (r *GarageClusterReconciler) collectGarageNodeIDs(ctx context.Context, cluster *garagev1beta2.GarageCluster) map[string]bool {
	log := logf.FromContext(ctx)
	nodeIDs := make(map[string]bool)

	nodeList := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodeList, client.InNamespace(cluster.Namespace)); err != nil {
		log.Error(err, "Failed to list GarageNodes for cleanup")
		return nodeIDs
	}

	for _, node := range nodeList.Items {
		if node.Spec.ClusterRef.Name != cluster.Name {
			continue
		}
		// Prefer status (auto-discovered), fall back to spec (manually set)
		if node.Status.NodeID != "" {
			nodeIDs[node.Status.NodeID] = true
		} else if node.Spec.NodeID != "" {
			nodeIDs[node.Spec.NodeID] = true
		}
	}

	if len(nodeIDs) > 0 {
		log.Info("Collected node IDs from GarageNode CRs", "count", len(nodeIDs))
	}
	return nodeIDs
}

// removeNodesFromLayout removes all nodes belonging to this cluster from the Garage layout.
// For gateway clusters, this connects to the storage cluster's admin API.
// For storage clusters, this connects to its own admin API.
func (r *GarageClusterReconciler) removeNodesFromLayout(ctx context.Context, cluster *garagev1beta2.GarageCluster, knownNodeIDs map[string]bool) error {
	log := logf.FromContext(ctx)

	// Determine which cluster's layout to modify and get the appropriate client
	var garageClient *garage.Client
	var err error

	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		// Gateway cluster with clusterRef: remove nodes from the storage cluster's layout
		garageClient, err = r.getStorageClusterClient(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to get storage cluster client: %w", err)
		}
		log.Info("Removing gateway nodes from storage cluster layout",
			"storageCluster", cluster.Spec.ConnectTo.ClusterRef.Name)
	} else if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		// Gateway cluster with external admin API: remove nodes from the external storage cluster's layout
		garageClient, err = r.getExternalStorageClient(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to get external storage cluster client: %w", err)
		}
		log.Info("Removing gateway nodes from external storage cluster layout",
			"endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint)
	} else {
		// Storage cluster: remove nodes from its own layout
		adminToken, err := r.getAdminToken(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to get admin token: %w", err)
		}
		if adminToken == "" {
			log.Info("Admin API not configured, skipping layout cleanup")
			return nil
		}

		adminPort := DefaultAdminPort
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		garageClient = garage.NewClient(endpoint, adminToken)
	}

	// Get current layout
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Find all nodes belonging to this cluster.
	// Primary: match by cluster ownership tag in the format "cluster:<name>/<namespace>".
	// Fallback: match by node IDs collected from GarageNode CRs before deletion.
	// This handles nodes registered with legacy tags (e.g., zone name only).
	nodesToRemove := make([]garage.NodeRoleChange, 0)
	for _, role := range layout.Roles {
		if !nodeBelongsToCluster(role.Tags, cluster.Name, cluster.Namespace) && !knownNodeIDs[role.ID] {
			continue
		}
		// Check if already staged for removal
		alreadyStaged := false
		for _, staged := range layout.StagedRoleChanges {
			if staged.ID == role.ID && staged.Remove {
				alreadyStaged = true
				break
			}
		}
		if !alreadyStaged {
			shortID := role.ID
			if len(shortID) > 16 {
				shortID = shortID[:16] + "..."
			}
			log.Info("Staging node for removal", "nodeId", shortID, "tags", role.Tags)
			nodesToRemove = append(nodesToRemove, garage.NodeRoleChange{
				ID:     role.ID,
				Remove: true,
			})
		}
	}

	if len(nodesToRemove) == 0 {
		log.Info("No nodes to remove from layout")
		return nil
	}

	// Stage the removals
	if err := garageClient.UpdateClusterLayout(ctx, nodesToRemove); err != nil {
		return fmt.Errorf("failed to stage node removals: %w", err)
	}

	// Get updated layout with staged changes
	layout, err = garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get updated layout: %w", err)
	}

	// Apply the layout changes
	newVersion := layout.Version + 1
	if err := garageClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if garage.IsConflict(err) {
			log.Info("Layout version conflict during finalization, will retry", "attemptedVersion", newVersion)
			return fmt.Errorf("layout version conflict: %w", err)
		}
		if garage.IsReplicationConstraint(err) {
			log.Info("Cannot remove nodes: would violate replication constraints. "+
				"Nodes will remain in layout until more nodes are added or replication factor is reduced.",
				"nodesToRemove", len(nodesToRemove))
			return nil
		}
		return fmt.Errorf("failed to apply layout removal: %w", err)
	}

	log.Info("Removed nodes from layout", "count", len(nodesToRemove), "version", newVersion)

	// For gateway clusters, immediately skip dead nodes since gateways never store data.
	// This prevents the removed gateway nodes from getting stuck in Draining state,
	// which would cause quorum calculation to include unreachable nodes.
	if cluster.HasGatewayTier() {
		skipReq := garage.SkipDeadNodesRequest{
			Version:          newVersion,
			AllowMissingData: true, // Safe for gateways - they never have data
		}
		result, err := garageClient.ClusterLayoutSkipDeadNodes(ctx, skipReq)
		if err != nil {
			// Don't fail finalization if skip fails - log and continue
			// This can happen if there's only one layout version (nothing to skip)
			if !garage.IsBadRequest(err) {
				log.Error(err, "Failed to skip dead gateway nodes (will be cleaned up on next reconcile)")
			}
		} else {
			log.Info("Skipped dead gateway nodes to prevent draining stall",
				"ackUpdated", len(result.AckUpdated),
				"syncUpdated", len(result.SyncUpdated))
		}
	}

	return nil
}

func (r *GarageClusterReconciler) ensureRPCSecret(ctx context.Context, cluster *garagev1beta2.GarageCluster) (*corev1.Secret, error) {
	log := logf.FromContext(ctx)

	// If secret ref is provided, use it
	if cluster.Spec.Network.RPCSecretRef != nil {
		secret := &corev1.Secret{}
		secretName := types.NamespacedName{
			Name:      cluster.Spec.Network.RPCSecretRef.Name,
			Namespace: cluster.Namespace,
		}
		if err := r.Get(ctx, secretName, secret); err != nil {
			return nil, fmt.Errorf("failed to get RPC secret: %w", err)
		}
		return secret, nil
	}

	// For gateway clusters connecting to a storage cluster via clusterRef,
	// use the storage cluster's RPC secret so they can communicate
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		storageCluster := &garagev1beta2.GarageCluster{}
		storageNN := types.NamespacedName{
			Name:      cluster.Spec.ConnectTo.ClusterRef.Name,
			Namespace: cluster.Namespace,
		}
		if cluster.Spec.ConnectTo.ClusterRef.Namespace != "" {
			storageNN.Namespace = cluster.Spec.ConnectTo.ClusterRef.Namespace
		}
		if err := r.Get(ctx, storageNN, storageCluster); err != nil {
			return nil, fmt.Errorf("failed to get storage cluster for RPC secret: %w", err)
		}

		// Use the storage cluster's RPC secret
		storageSecretName := storageCluster.Name + "-rpc-secret"
		if storageCluster.Spec.Network.RPCSecretRef != nil {
			storageSecretName = storageCluster.Spec.Network.RPCSecretRef.Name
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: storageSecretName, Namespace: storageNN.Namespace}, secret); err != nil {
			return nil, fmt.Errorf("failed to get storage cluster RPC secret: %w", err)
		}
		log.Info("Using storage cluster RPC secret for gateway", "storageCluster", storageNN.Name, "secret", storageSecretName)
		return secret, nil
	}

	// Generate a new RPC secret
	secretName := cluster.Name + "-rpc-secret"
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret)
	if err == nil {
		return secret, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	// Generate 32-byte random hex secret
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	rpcSecret := hex.EncodeToString(randomBytes)

	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			RPCSecretKey: rpcSecret,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return nil, err
	}

	log.Info("Creating RPC secret", "name", secretName)
	if err := r.Create(ctx, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

// reconcileConfigMap creates/updates the ConfigMap(s) and returns config hashes
// for pod restart triggering. Garage does NOT support hot-reload of config
// (SIGHUP is explicitly ignored in src/garage/server.rs). All config changes
// require pod restarts, which we trigger via the checksum annotation.
//
// Returns (storageHash, gatewayHash). When the gateway tier sets its own
// rpc_public_addr, a second ConfigMap <name>-gateway-config is reconciled so
// gateway pods advertise the gateway address instead of inheriting the storage
// tier's. Otherwise both hashes refer to the single <name>-config map.
func (r *GarageClusterReconciler) reconcileConfigMap(ctx context.Context, cluster *garagev1beta2.GarageCluster) (string, string, error) {
	log := logf.FromContext(ctx)

	// Validate bootstrap peers format before generating config
	// Garage requires format: "<64-hex-nodeid>@<hostname>:<port>"
	// Invalid entries are silently ignored by Garage, so warn users here
	validateBootstrapPeers(log, cluster.Spec.Network.BootstrapPeers)

	// Build config context with resolved secrets
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		log.V(1).Info("Warning: could not build config context", "error", err)
		cfgCtx = &configContext{} // Use empty context if secrets can't be read
	}

	// Auto-populate intra-cluster bootstrap_peers from sibling GarageNodes so
	// pods can rediscover one another after a restart even when the on-disk
	// peer_list cache holds stale IPs. The list is empty until at least one
	// sibling's node ID is known — that's expected for fresh clusters; the
	// next reconcile picks them up. Failure to list is non-fatal: the config
	// just lacks auto-peers and falls back to user-supplied peers + cached
	// peer_list, which is the pre-fix behavior.
	autoPeers, err := computeIntraClusterBootstrapPeers(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		log.V(1).Info("Could not compute intra-cluster bootstrap_peers", "error", err)
	}
	cfgCtx.IntraClusterBootstrapPeers = autoPeers

	// Default ConfigMap (used by storage pods, and by gateway pods when no
	// gateway-specific rpc_public_addr override is set).
	storageHash, err := r.writeConfigMap(ctx, cluster, cluster.Name+"-config", generateGarageConfig(cluster, cfgCtx))
	if err != nil {
		return "", "", err
	}
	gatewayHash := storageHash

	// Gateway-specific ConfigMap: only needed when gateway tier exists alongside
	// storage AND has its own externally-routable rpc_public_addr. Without this
	// override, gateway pods inherit the storage tier's address, which is the
	// storage LB hostname — peers RPC'ing them by node ID land on the storage
	// pods instead, and the handshake fails with "secret box" errors.
	if cluster.HasStorageTier() && cluster.HasGatewayTier() && cluster.Spec.Gateway.RPCPublicAddr != "" {
		gwCfgCtx := *cfgCtx
		gwCfgCtx.TierRPCPublicAddrOverride = cluster.Spec.Gateway.RPCPublicAddr
		gatewayHash, err = r.writeConfigMap(ctx, cluster, cluster.Name+"-gateway-config", generateGarageConfig(cluster, &gwCfgCtx))
		if err != nil {
			return "", "", err
		}
	} else {
		// No gateway-specific config required — make sure no stale gateway CM
		// lingers from a previous spec.
		stale := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name + "-gateway-config", Namespace: cluster.Namespace}, stale); err == nil {
			if err := r.Delete(ctx, stale); err != nil && !errors.IsNotFound(err) {
				return "", "", fmt.Errorf("failed to delete stale gateway ConfigMap: %w", err)
			}
		}
	}

	return storageHash, gatewayHash, nil
}

func (r *GarageClusterReconciler) writeConfigMap(ctx context.Context, cluster *garagev1beta2.GarageCluster, name, body string) (string, error) {
	log := logf.FromContext(ctx)
	configHash := sha256.Sum256([]byte(body))
	hashStr := hex.EncodeToString(configHash[:])

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Data: map[string]string{configFileName: body},
	}
	if err := controllerutil.SetControllerReference(cluster, cm, r.Scheme); err != nil {
		return "", err
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating ConfigMap", "name", name)
		return hashStr, r.Create(ctx, cm)
	}
	if err != nil {
		return "", err
	}
	existing.Data = cm.Data
	return hashStr, r.Update(ctx, existing)
}

// configContext holds resolved secret values needed for config generation.
// This allows config generation functions to remain pure while still
// incorporating secret values that must be read from the API.
type configContext struct {
	// ConsulToken is the resolved Consul ACL token from TokenSecretRef
	ConsulToken string
	// RPCPublicAddr is the auto-derived rpc_public_addr from publicEndpoint.
	// Only set when publicEndpoint is configured and an address can be resolved.
	// Explicit network.rpcPublicAddr takes precedence over this field.
	RPCPublicAddr string
	// MetadataFsync overrides the cluster-level storage.metadataFsync setting.
	// Only used when set (non-nil); nil means fall back to the cluster spec.
	MetadataFsync *bool
	// DataFsync overrides the cluster-level storage.dataFsync setting.
	// Only used when set (non-nil); nil means fall back to the cluster spec.
	DataFsync *bool
	// NodeRPCPublicAddr is a per-node rpc_public_addr that takes highest priority,
	// overriding even cluster.Spec.Network.RPCPublicAddr. Used by the GarageNode
	// controller to ensure each node advertises its own externally-routable address
	// even when the cluster also has a static RPCPublicAddr configured.
	NodeRPCPublicAddr string
	// TierRPCPublicAddrOverride, when set, overrides cluster.Spec.Network.RPCPublicAddr
	// for this tier's ConfigMap. Used to generate a gateway-specific config that
	// advertises spec.gateway.rpcPublicAddr instead of inheriting the storage tier's
	// address — gateways otherwise advertise the storage LB hostname, which routes
	// peers to the wrong node ID on RPC and breaks the handshake.
	TierRPCPublicAddrOverride string
	// NodeDataDirPaths, when non-empty, replaces the cluster-level data_dir with a
	// per-node TOML array (one entry per mount). Used by the GarageNode controller
	// for multi-HDD nodes. Capacity (e.g. "100Gi") is optional; when set it is
	// emitted as the per-path `capacity` so Garage knows the disk size.
	NodeDataDirPaths []NodeDataDirPath
	// NodeMetadataSnapshotsDir overrides storage.metadataSnapshotsDir for this node's
	// garage.toml. Empty means inherit from cluster spec.
	NodeMetadataSnapshotsDir string
	// NodeMetadataAutoSnapshotInterval overrides storage.metadataAutoSnapshotInterval
	// for this node's garage.toml. Empty means inherit from cluster spec.
	NodeMetadataAutoSnapshotInterval string
	// IntraClusterBootstrapPeers is the operator-computed list of
	// `<nodeID>@<headless-DNS>:<rpcPort>` entries for sibling GarageNodes in
	// this cluster (see helpers.go:computeIntraClusterBootstrapPeers). The
	// network-section writer appends these to cluster.Spec.Network.BootstrapPeers
	// so Garage's discovery loop can re-resolve stable per-pod DNS instead of
	// relying solely on its stale on-disk peer_list cache (#203).
	IntraClusterBootstrapPeers []string
}

// NodeDataDirPath is one mount path in a per-node multi-HDD garage.toml data_dir array.
type NodeDataDirPath struct {
	Path     string
	Capacity string // optional; if empty, the entry is emitted without a capacity attribute
}

// buildConfigContext creates a configContext by resolving secrets referenced in the cluster spec.
// This reads secrets that need to be embedded inline in the config (e.g., Consul token which
// doesn't support file-based loading in Garage).
func buildConfigContext(ctx context.Context, cl client.Client, cluster *garagev1beta2.GarageCluster) (*configContext, error) {
	cfgCtx := &configContext{}

	// Read Consul token if configured
	if cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil &&
		cluster.Spec.Discovery.Consul.Enabled != nil && *cluster.Spec.Discovery.Consul.Enabled && cluster.Spec.Discovery.Consul.TokenSecretRef != nil {

		tokenRef := cluster.Spec.Discovery.Consul.TokenSecretRef
		secret := &corev1.Secret{}
		if err := cl.Get(ctx, types.NamespacedName{
			Name:      tokenRef.Name,
			Namespace: cluster.Namespace,
		}, secret); err != nil {
			return nil, fmt.Errorf("failed to get Consul token secret %s: %w", tokenRef.Name, err)
		}

		tokenKey := remoteAdminTokenKey
		if tokenRef.Key != "" {
			tokenKey = tokenRef.Key
		}

		if tokenData, ok := secret.Data[tokenKey]; ok {
			cfgCtx.ConsulToken = string(tokenData)
		} else {
			return nil, fmt.Errorf("consul token key %q not found in secret %s", tokenKey, tokenRef.Name)
		}
	}

	// Derive rpc_public_addr from publicEndpoint if configured and network.rpcPublicAddr is not set.
	if cluster.Spec.PublicEndpoint != nil && cluster.Spec.Network.RPCPublicAddr == "" {
		rpcPort := DefaultRPCPort
		if cluster.Spec.Network.RPCBindPort != 0 {
			rpcPort = cluster.Spec.Network.RPCBindPort
		}
		switch cluster.Spec.PublicEndpoint.Type {
		case publicEndpointTypeLoadBalancer:
			if cluster.Spec.PublicEndpoint.LoadBalancer == nil || !cluster.Spec.PublicEndpoint.LoadBalancer.PerNode {
				svc := &corev1.Service{}
				if err := cl.Get(ctx, types.NamespacedName{
					Name:      cluster.Name + "-rpc",
					Namespace: cluster.Namespace,
				}, svc); err == nil {
					for _, ing := range svc.Status.LoadBalancer.Ingress {
						addr := ing.IP
						if addr == "" {
							addr = ing.Hostname
						}
						if addr != "" {
							cfgCtx.RPCPublicAddr = fmt.Sprintf("%s:%d", addr, rpcPort)
							break
						}
					}
				}
			}
		case publicEndpointTypeNodePort:
			if ep := cluster.Spec.PublicEndpoint.NodePort; ep != nil && len(ep.ExternalAddresses) > 0 {
				basePort := ep.BasePort
				if basePort == 0 {
					basePort = 30901
				}
				cfgCtx.RPCPublicAddr = fmt.Sprintf("%s:%d", ep.ExternalAddresses[0], basePort)
			}
		}
	}

	return cfgCtx, nil
}

func generateGarageConfig(cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) string {
	var config strings.Builder

	// Both storage and gateway clusters use /data paths for consistency.
	// Gateway clusters use StatefulSet with metadata PVC (for node identity persistence)
	// and EmptyDir for data (since gateways don't store blocks).
	config.WriteString("metadata_dir = \"/data/metadata\"\n")
	writeDataDirConfig(&config, cluster, cfgCtx)
	config.WriteString("\n")

	writeDBConfig(&config, cluster)
	writeReplicationConfig(&config, cluster)
	writeStorageConfig(&config, cluster, cfgCtx)
	writeBlockConfig(&config, cluster)
	writeSecurityConfig(&config, cluster)
	writeRPCConfig(&config, cluster, cfgCtx)
	writeS3APIConfig(&config, cluster)
	writeK2VAPIConfig(&config, cluster)
	writeWebAPIConfig(&config, cluster)
	writeAdminConfig(&config, cluster)
	writeKubernetesDiscoveryConfig(&config, cluster)
	writeConsulDiscoveryConfig(&config, cluster, cfgCtx)

	return config.String()
}

// writeDataDirConfig writes the data_dir configuration, supporting both single path
// and multi-path configurations. Garage supports multiple data directories since v0.9.0
// with format: data_dir = [{ path = "/path", capacity = "2T" }, ...]
func writeDataDirConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) {
	// Per-node multi-HDD override takes precedence over cluster-level paths.
	if cfgCtx != nil && len(cfgCtx.NodeDataDirPaths) > 0 {
		config.WriteString("data_dir = [\n")
		for i, p := range cfgCtx.NodeDataDirPaths {
			fmt.Fprintf(config, "    { path = \"%s\"", p.Path)
			if p.Capacity != "" {
				fmt.Fprintf(config, ", capacity = \"%s\"", p.Capacity)
			}
			config.WriteString(" }")
			if i < len(cfgCtx.NodeDataDirPaths)-1 {
				config.WriteString(",")
			}
			config.WriteString("\n")
		}
		config.WriteString("]\n")
		return
	}
	if cluster.HasStorageTier() && cluster.Spec.Storage.Data != nil && len(cluster.Spec.Storage.Data.Paths) > 0 {
		// Multi-path configuration
		paths := cluster.Spec.Storage.Data.Paths
		config.WriteString("data_dir = [\n")
		for i, path := range paths {
			config.WriteString("    { path = \"")
			config.WriteString(path.Path)
			config.WriteString("\"")
			if path.ReadOnly {
				config.WriteString(", read_only = true")
			} else {
				// Garage requires every entry to set either capacity or read_only.
				// Prefer the per-path Capacity, then fall back to volume.size (the
				// PVC size is the disk size).
				cap := path.Capacity
				if cap == nil && path.Volume != nil && path.Volume.Size != nil {
					cap = path.Volume.Size
				}
				if cap != nil {
					fmt.Fprintf(config, ", capacity = \"%s\"", cap.String())
				}
			}
			config.WriteString(" }")
			if i < len(paths)-1 {
				config.WriteString(",")
			}
			config.WriteString("\n")
		}
		config.WriteString("]\n")
	} else {
		// Single path (default) — also used for gateway pods which write nothing here.
		config.WriteString("data_dir = \"/data/data\"\n")
	}
}

func writeDBConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	dbEngine := "lmdb"
	if cluster.Spec.Database != nil && cluster.Spec.Database.Engine != "" {
		dbEngine = cluster.Spec.Database.Engine
	}
	fmt.Fprintf(config, "db_engine = \"%s\"\n", dbEngine)

	if cluster.Spec.Database != nil {
		if cluster.Spec.Database.LMDBMapSize != nil {
			fmt.Fprintf(config, "lmdb_map_size = %d\n", cluster.Spec.Database.LMDBMapSize.Value())
		}
		if cluster.Spec.Database.FjallBlockCacheSize != nil {
			fmt.Fprintf(config, "fjall_block_cache_size = %d\n", cluster.Spec.Database.FjallBlockCacheSize.Value())
		}
	}
}

func writeReplicationConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	r := cluster.Spec.Replication
	if r == nil {
		r = &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
	}
	fmt.Fprintf(config, "replication_factor = %d\n", r.Factor)
	if r.ConsistencyMode != "" {
		fmt.Fprintf(config, "consistency_mode = \"%s\"\n", r.ConsistencyMode)
	}
}

func writeStorageConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) {
	st := cluster.Spec.Storage
	var (
		metadataFsync                bool
		dataFsync                    bool
		metadataSnapshotsDir         string
		metadataAutoSnapshotInterval string
	)
	if st != nil {
		metadataFsync = st.MetadataFsync
		dataFsync = st.DataFsync
		metadataSnapshotsDir = st.MetadataSnapshotsDir
		metadataAutoSnapshotInterval = st.MetadataAutoSnapshotInterval
	}
	// Node-level overrides take precedence over cluster-level settings.
	if cfgCtx != nil && cfgCtx.MetadataFsync != nil {
		metadataFsync = *cfgCtx.MetadataFsync
	}
	if cfgCtx != nil && cfgCtx.DataFsync != nil {
		dataFsync = *cfgCtx.DataFsync
	}
	if cfgCtx != nil && cfgCtx.NodeMetadataSnapshotsDir != "" {
		metadataSnapshotsDir = cfgCtx.NodeMetadataSnapshotsDir
	}
	if cfgCtx != nil && cfgCtx.NodeMetadataAutoSnapshotInterval != "" {
		metadataAutoSnapshotInterval = cfgCtx.NodeMetadataAutoSnapshotInterval
	}

	if metadataFsync {
		config.WriteString("metadata_fsync = true\n")
	}
	if dataFsync {
		config.WriteString("data_fsync = true\n")
	}
	if metadataSnapshotsDir != "" {
		fmt.Fprintf(config, "metadata_snapshots_dir = \"%s\"\n", metadataSnapshotsDir)
	}
	if metadataAutoSnapshotInterval != "" {
		fmt.Fprintf(config, "metadata_auto_snapshot_interval = \"%s\"\n", metadataAutoSnapshotInterval)
	}
}

func writeBlockConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	if cluster.Spec.Blocks == nil {
		return
	}
	if cluster.Spec.Blocks.Size != nil {
		fmt.Fprintf(config, "block_size = %d\n", cluster.Spec.Blocks.Size.Value())
	}
	if cluster.Spec.Blocks.RAMBufferMax != nil {
		fmt.Fprintf(config, "block_ram_buffer_max = %d\n", cluster.Spec.Blocks.RAMBufferMax.Value())
	}
	if cluster.Spec.Blocks.MaxConcurrentReads != nil {
		fmt.Fprintf(config, "block_max_concurrent_reads = %d\n", *cluster.Spec.Blocks.MaxConcurrentReads)
	}
	if cluster.Spec.Blocks.MaxConcurrentWritesPerRequest != nil {
		fmt.Fprintf(config, "block_max_concurrent_writes_per_request = %d\n", *cluster.Spec.Blocks.MaxConcurrentWritesPerRequest)
	}
	if cluster.Spec.Blocks.CompressionLevel != nil {
		level := *cluster.Spec.Blocks.CompressionLevel
		if level == "none" {
			config.WriteString("compression_level = \"none\"\n")
		} else {
			fmt.Fprintf(config, "compression_level = %s\n", level)
		}
	}
	if cluster.Spec.Blocks.DisableScrub {
		config.WriteString("disable_scrub = true\n")
	}
	if cluster.Spec.Blocks.UseLocalTZ {
		config.WriteString("use_local_tz = true\n")
	}
}

func writeSecurityConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	if cluster.Spec.Security == nil {
		return
	}
	if cluster.Spec.Security.AllowInsecureSecretPermissions {
		config.WriteString("allow_world_readable_secrets = true\n")
	}
	if cluster.Spec.Security.AllowPunycode {
		config.WriteString("allow_punycode = true\n")
	}
}

func writeRPCConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) {
	if cluster.Spec.Network.RPCBindAddress != "" {
		fmt.Fprintf(config, "rpc_bind_addr = \"%s\"\n", cluster.Spec.Network.RPCBindAddress)
	} else {
		rpcPort := int32(3901)
		if cluster.Spec.Network.RPCBindPort != 0 {
			rpcPort = cluster.Spec.Network.RPCBindPort
		}
		fmt.Fprintf(config, "rpc_bind_addr = \"[::]:%d\"\n", rpcPort)
	}
	config.WriteString("rpc_secret_file = \"/secrets/rpc/rpc-secret\"\n")

	// Priority: per-node override > per-tier override > cluster static > publicEndpoint-derived
	switch {
	case cfgCtx != nil && cfgCtx.NodeRPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cfgCtx.NodeRPCPublicAddr)
	case cfgCtx != nil && cfgCtx.TierRPCPublicAddrOverride != "":
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cfgCtx.TierRPCPublicAddrOverride)
	case cluster.Spec.Network.RPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cluster.Spec.Network.RPCPublicAddr)
	case cfgCtx != nil && cfgCtx.RPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cfgCtx.RPCPublicAddr)
	}
	if cluster.Spec.Network.RPCPublicAddrSubnet != "" {
		fmt.Fprintf(config, "rpc_public_addr_subnet = \"%s\"\n", cluster.Spec.Network.RPCPublicAddrSubnet)
	}
	if cluster.Spec.Network.RPCBindOutgoing {
		config.WriteString("rpc_bind_outgoing = true\n")
	}
	if cluster.Spec.Network.RPCPingTimeout != nil {
		fmt.Fprintf(config, "rpc_ping_timeout_msec = %d\n", cluster.Spec.Network.RPCPingTimeout.Milliseconds())
	}
	if cluster.Spec.Network.RPCTimeout != nil {
		fmt.Fprintf(config, "rpc_timeout_msec = %d\n", cluster.Spec.Network.RPCTimeout.Milliseconds())
	}

	// Bootstrap peers for multi-cluster federation.
	// IMPORTANT: Garage REQUIRES the format "<nodeid>@<addr>:<port>" where nodeid is
	// the 64-character hex node ID. Peers without node IDs are silently ignored.
	// For multi-cluster setups:
	//   1. Discover node IDs via 'garage node id' or Admin API on each cluster
	//   2. Configure bootstrap_peers with full "<nodeid>@<addr>:<port>" format
	//   3. Use ExternalName services for DNS resolution across clusters
	// The operator handles intra-cluster node discovery via Admin API; bootstrap peers
	// are primarily for initial cross-cluster connectivity.
	var autoPeers []string
	if cfgCtx != nil {
		autoPeers = cfgCtx.IntraClusterBootstrapPeers
	}
	mergedPeers := mergeBootstrapPeers(cluster.Spec.Network.BootstrapPeers, autoPeers)
	if len(mergedPeers) > 0 {
		quotedPeers := make([]string, 0, len(mergedPeers))
		for _, peer := range mergedPeers {
			quotedPeers = append(quotedPeers, fmt.Sprintf("\"%s\"", peer))
		}
		fmt.Fprintf(config, "bootstrap_peers = [%s]\n", strings.Join(quotedPeers, ", "))
	} else {
		fmt.Fprintf(config, "bootstrap_peers = []\n")
	}
}

// validateBootstrapPeers checks that bootstrap peers are in the correct format
// and logs warnings for invalid entries. Garage requires format: "<64-hex-nodeid>@<hostname>:<port>"
// Invalid entries are silently ignored by Garage (see src/rpc/system.rs), so we warn users here.
func validateBootstrapPeers(log logr.Logger, peers []string) {
	for _, peer := range peers {
		// Check for @ separator (required for nodeid@addr format)
		atIdx := strings.Index(peer, "@")
		if atIdx == -1 {
			log.Info("WARNING: bootstrap_peer missing '@' separator - will be ignored by Garage",
				"peer", peer,
				"expectedFormat", "<64-hex-nodeid>@<hostname>:<port>")
			continue
		}

		nodeID := peer[:atIdx]
		addr := peer[atIdx+1:]

		// Node ID should be 64 hex characters (32 bytes = Ed25519 public key)
		if len(nodeID) != 64 {
			log.Info("WARNING: bootstrap_peer has invalid node ID length - will be ignored by Garage",
				"peer", peer,
				"nodeIdLength", len(nodeID),
				"expectedLength", 64)
			continue
		}

		// Check that node ID is valid hex
		if _, err := hex.DecodeString(nodeID); err != nil {
			log.Info("WARNING: bootstrap_peer has invalid node ID (not hex) - will be ignored by Garage",
				"peer", peer,
				"nodeId", nodeID)
			continue
		}

		// Check for port in address
		if !strings.Contains(addr, ":") {
			log.Info("WARNING: bootstrap_peer address missing port - will be ignored by Garage",
				"peer", peer,
				"address", addr,
				"expectedFormat", "<hostname>:<port>")
		}
	}
}

func writeS3APIConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	// NOTE: [s3_api] section is REQUIRED by Garage - it's not an Option<T> in the config schema.
	// Garage will fail to start if this section is missing.
	config.WriteString("\n[s3_api]\n")
	s3Port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		s3Port = cluster.Spec.S3API.BindPort
	}
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = \"%s\"\n", cluster.Spec.S3API.BindAddress)
	} else {
		fmt.Fprintf(config, "api_bind_addr = \"[::]:%d\"\n", s3Port)
	}
	region := defaultS3Region
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		region = cluster.Spec.S3API.Region
	}
	fmt.Fprintf(config, "s3_region = \"%s\"\n", region)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.RootDomain != "" {
		fmt.Fprintf(config, "root_domain = \"%s\"\n", cluster.Spec.S3API.RootDomain)
	}
}

func writeK2VAPIConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	if cluster.Spec.K2VAPI == nil {
		return
	}
	config.WriteString("\n[k2v_api]\n")
	if cluster.Spec.K2VAPI.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = \"%s\"\n", cluster.Spec.K2VAPI.BindAddress)
	} else {
		k2vPort := int32(3904)
		if cluster.Spec.K2VAPI.BindPort != 0 {
			k2vPort = cluster.Spec.K2VAPI.BindPort
		}
		fmt.Fprintf(config, "api_bind_addr = \"[::]:%d\"\n", k2vPort)
	}
}

// effectiveWebAPI returns the effective WebAPI config for the cluster,
// applying defaults without mutating the original spec.
// Returns nil if web hosting should be disabled.
func effectiveWebAPI(cluster *garagev1beta2.GarageCluster) *garagev1beta2.WebAPIConfig {
	w := cluster.Spec.WebAPI
	// Explicitly disabled via Enabled: false
	if w != nil && w.Enabled != nil && !*w.Enabled {
		return nil
	}
	// Web hosting enabled by default; compute effective config.
	eff := &garagev1beta2.WebAPIConfig{}
	if w != nil {
		eff = w.DeepCopy()
	}
	if eff.RootDomain == "" {
		eff.RootDomain = fmt.Sprintf(".%s.%s.svc", cluster.Name, cluster.Namespace)
	}
	return eff
}

func writeWebAPIConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	w := effectiveWebAPI(cluster)
	if w == nil {
		return
	}
	config.WriteString("\n[s3_web]\n")
	if w.BindAddress != "" {
		fmt.Fprintf(config, "bind_addr = \"%s\"\n", w.BindAddress)
	} else {
		webPort := int32(3902)
		if w.BindPort != 0 {
			webPort = w.BindPort
		}
		fmt.Fprintf(config, "bind_addr = \"[::]:%d\"\n", webPort)
	}
	fmt.Fprintf(config, "root_domain = \"%s\"\n", w.RootDomain)
	if w.AddHostToMetrics {
		config.WriteString("add_host_to_metrics = true\n")
	}
}

func writeAdminConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	config.WriteString("\n[admin]\n")
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = \"%s\"\n", cluster.Spec.Admin.BindAddress)
	} else {
		adminPort := int32(3903)
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		fmt.Fprintf(config, "api_bind_addr = \"[::]:%d\"\n", adminPort)
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		config.WriteString("admin_token_file = \"/secrets/admin/admin-token\"\n")
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsTokenSecretRef != nil {
		config.WriteString("metrics_token_file = \"/secrets/metrics/metrics-token\"\n")
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsRequireToken {
		config.WriteString("metrics_require_token = true\n")
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.TraceSink != "" {
		fmt.Fprintf(config, "trace_sink = \"%s\"\n", cluster.Spec.Admin.TraceSink)
	}
}

func writeKubernetesDiscoveryConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	if cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Kubernetes == nil ||
		cluster.Spec.Discovery.Kubernetes.Enabled == nil || !*cluster.Spec.Discovery.Kubernetes.Enabled {
		return
	}
	k8s := cluster.Spec.Discovery.Kubernetes
	config.WriteString("\n[kubernetes_discovery]\n")
	if k8s.Namespace != "" {
		fmt.Fprintf(config, "namespace = \"%s\"\n", k8s.Namespace)
	} else {
		fmt.Fprintf(config, "namespace = \"%s\"\n", cluster.Namespace)
	}
	if k8s.ServiceName != "" {
		fmt.Fprintf(config, "service_name = \"%s\"\n", k8s.ServiceName)
	} else {
		fmt.Fprintf(config, "service_name = \"%s\"\n", cluster.Name)
	}
	if k8s.SkipCRD {
		config.WriteString("skip_crd = true\n")
	}
}

func writeConsulDiscoveryConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) {
	if cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Consul == nil ||
		cluster.Spec.Discovery.Consul.Enabled == nil || !*cluster.Spec.Discovery.Consul.Enabled {
		return
	}
	consul := cluster.Spec.Discovery.Consul
	config.WriteString("\n[consul_discovery]\n")
	if consul.API != "" {
		fmt.Fprintf(config, "api = \"%s\"\n", consul.API)
	}
	if consul.HTTPAddr != "" {
		fmt.Fprintf(config, "consul_http_addr = \"%s\"\n", consul.HTTPAddr)
	}
	if consul.ServiceName != "" {
		fmt.Fprintf(config, "service_name = \"%s\"\n", consul.ServiceName)
	}

	// CA certificate: prefer secret ref over inline value
	if consul.CACertSecretRef != nil {
		config.WriteString("ca_cert = \"/secrets/consul/ca/ca.crt\"\n")
	} else if consul.CACert != "" {
		fmt.Fprintf(config, "ca_cert = \"%s\"\n", consul.CACert)
	}

	// Client certificate (for mTLS with Consul)
	if consul.ClientCertSecretRef != nil {
		config.WriteString("client_cert = \"/secrets/consul/client-cert/tls.crt\"\n")
	}

	// Client key (for mTLS with Consul)
	if consul.ClientKeySecretRef != nil {
		config.WriteString("client_key = \"/secrets/consul/client-key/tls.key\"\n")
	}

	// Consul ACL token: Garage requires the actual token string (no token_file support)
	// The token is read from the secret and passed via configContext
	if cfgCtx != nil && cfgCtx.ConsulToken != "" {
		fmt.Fprintf(config, "token = \"%s\"\n", cfgCtx.ConsulToken)
	}

	if consul.TLSSkipVerify {
		config.WriteString("tls_skip_verify = true\n")
	}
	if len(consul.Tags) > 0 {
		config.WriteString("tags = [")
		for i, tag := range consul.Tags {
			if i > 0 {
				config.WriteString(", ")
			}
			fmt.Fprintf(config, "\"%s\"", tag)
		}
		config.WriteString("]\n")
	}
	if len(consul.Meta) > 0 {
		config.WriteString("[consul_discovery.meta]\n")
		for k, v := range consul.Meta {
			fmt.Fprintf(config, "%s = \"%s\"\n", k, v)
		}
	}
	if len(consul.Datacenters) > 0 {
		config.WriteString("datacenters = [")
		for i, dc := range consul.Datacenters {
			if i > 0 {
				config.WriteString(", ")
			}
			fmt.Fprintf(config, "\"%s\"", dc)
		}
		config.WriteString("]\n")
	}
}

func (r *GarageClusterReconciler) reconcileHeadlessService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name + "-headless"

	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector:  r.selectorLabelsForCluster(cluster),
			Ports: []corev1.ServicePort{
				{
					Name:       rpcPortName,
					Port:       rpcPort,
					TargetPort: intstr.FromInt32(rpcPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			PublishNotReadyAddresses: true,
		},
	}

	log.Info("Reconciling headless Service", "name", serviceName)
	return reconcileService(ctx, r.Client, svc, cluster, r.Scheme)
}

// apiServicePorts returns the S3 / Admin / K2V / Web ServicePort set shared by
// both the primary (<cr>) and gateway (<cr>-gateway) in-cluster API Services.
// The port set is identical across tiers — only the selector differs.
func apiServicePorts(cluster *garagev1beta2.GarageCluster) []corev1.ServicePort {
	ports := make([]corev1.ServicePort, 0, 4)

	// S3 API port (always enabled - Garage requires the [s3_api] section)
	s3Port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		s3Port = cluster.Spec.S3API.BindPort
	}
	ports = append(ports, corev1.ServicePort{
		Name:       s3PortName,
		Port:       s3Port,
		TargetPort: intstr.FromInt32(s3Port),
		Protocol:   corev1.ProtocolTCP,
	})

	// Admin API port
	adminPort := int32(3903)
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		adminPort = cluster.Spec.Admin.BindPort
	}
	ports = append(ports, corev1.ServicePort{
		Name:       adminPortName,
		Port:       adminPort,
		TargetPort: intstr.FromInt32(adminPort),
		Protocol:   corev1.ProtocolTCP,
	})

	// K2V API port (only when enabled)
	if cluster.Spec.K2VAPI != nil {
		k2vPort := int32(3904)
		if cluster.Spec.K2VAPI.BindPort != 0 {
			k2vPort = cluster.Spec.K2VAPI.BindPort
		}
		ports = append(ports, corev1.ServicePort{
			Name:       "k2v",
			Port:       k2vPort,
			TargetPort: intstr.FromInt32(k2vPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	// Web API port (when not explicitly disabled)
	if w := effectiveWebAPI(cluster); w != nil {
		webPort := int32(3902)
		if w.BindPort != 0 {
			webPort = w.BindPort
		}
		ports = append(ports, corev1.ServicePort{
			Name:       "web",
			Port:       webPort,
			TargetPort: intstr.FromInt32(webPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return ports
}

// apiServiceSelector returns the pod-selector used by the in-cluster API
// Service for the given cluster shape.
//
//   - Storage tier: pods are owned by per-node GarageNode StatefulSets in both
//     Manual and Auto modes (post-#190). They carry {labelCluster, labelTier}
//     but not the unified {name=garage, instance=<cluster>} labels, so the
//     selector must be cluster+tier scoped.
//   - Gateway tier: still a Deployment with the unified tier labels, so the
//     tier-scoped selector matches as before.
func (r *GarageClusterReconciler) apiServiceSelector(cluster *garagev1beta2.GarageCluster, tier string) map[string]string {
	if tier == tierStorage {
		return map[string]string{
			labelCluster: cluster.Name,
			labelTier:    tierStorage,
		}
	}
	return r.selectorLabelsForTier(cluster, tier)
}

// reconcileAPIService reconciles the primary in-cluster API Service (<cr>).
//
// Selector targets the storage tier when one is declared, otherwise the gateway
// tier (edge-gateway clusters). The gateway-tier Deployment gets its own
// dedicated Service via reconcileGatewayAPIService.
func (r *GarageClusterReconciler) reconcileAPIService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name

	// Primary Service prefers the storage tier; falls back to gateway for
	// edge-gateway clusters (no local storage).
	primaryTier := tierStorage
	if !cluster.HasStorageTier() {
		primaryTier = tierGateway
	}

	serviceType := corev1.ServiceTypeClusterIP
	if cluster.Spec.Network.Service != nil && cluster.Spec.Network.Service.Type != "" {
		serviceType = cluster.Spec.Network.Service.Type
	}

	var svcMeta garagev1beta2.ServiceMeta
	if cluster.Spec.Network.Service != nil {
		svcMeta = cluster.Spec.Network.Service.ServiceMeta
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        serviceName,
			Namespace:   cluster.Namespace,
			Labels:      mergeLabels(r.labelsForCluster(cluster), svcMeta.Labels),
			Annotations: svcMeta.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType,
			Selector: r.apiServiceSelector(cluster, primaryTier),
			Ports:    apiServicePorts(cluster),
			// Enable routing to pods even when not ready, essential for multi-cluster
			// federation during bootstrap when pods are waiting for the cluster to be healthy
			PublishNotReadyAddresses: true,
		},
	}

	log.Info("Reconciling API Service", "name", serviceName, "tier", primaryTier)
	return reconcileService(ctx, r.Client, svc, cluster, r.Scheme)
}

// reconcileTierPodDisruptionBudget creates/updates a PDB covering one tier of
// the cluster (storage or gateway) when spec.<tier>.podDisruptionBudget.enabled
// is true. Deletes the PDB if it exists but is no longer wanted (tier dropped,
// scaled to zero, or enabled flipped to false).
//
// Storage tier regression context (#196): the previous storage-tier reconcile
// was deleted in #192 along with the legacy cluster-level StatefulSet, but the
// spec field and its CRD validation stayed in place, silently no-op'ing user
// PDB configs.
//
// Storage selector matches pre-#192 ({labelAppName, labelAppInstance,
// labelTier}) so existing PDBs upgrade in place without hitting the
// spec.selector immutability error. Gateway tier has no legacy shape — the
// gateway PDB is named "<cluster>-gateway" so it can coexist with the storage
// PDB and so a foreign PDB squatting on "<cluster>" doesn't block both.
func (r *GarageClusterReconciler) reconcileTierPodDisruptionBudget(ctx context.Context, cluster *garagev1beta2.GarageCluster, tier string) error {
	log := logf.FromContext(ctx)

	var (
		pdbName  string
		pdbCfg   *garagev1beta2.PodDisruptionBudgetConfig
		replicas int32
		wantPDB  bool
	)
	switch tier {
	case tierStorage:
		pdbName = cluster.Name
		if cluster.HasStorageTier() {
			pdbCfg = cluster.Spec.Storage.PodDisruptionBudget
			replicas = cluster.StorageReplicas()
		}
		wantPDB = cluster.HasStorageTier() && pdbCfg != nil && pdbCfg.Enabled
	case tierGateway:
		pdbName = cluster.Name + "-gateway"
		if cluster.HasGatewayTier() {
			pdbCfg = cluster.Spec.Gateway.PodDisruptionBudget
			replicas = cluster.Spec.Gateway.Replicas
		}
		// Gateway with replicas=0 is a paused tier — no pods to protect, so no PDB.
		wantPDB = cluster.HasGatewayTier() && pdbCfg != nil && pdbCfg.Enabled && replicas > 0
	default:
		return fmt.Errorf("unknown tier for PDB reconcile: %q", tier)
	}

	pdbKey := types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}

	if !wantPDB {
		existing := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, pdbKey, existing)
		if errors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		// Don't touch a PDB we don't own — could be user- or policy-engine-managed.
		if !metav1.IsControlledBy(existing, cluster) {
			return nil
		}
		log.Info("Deleting PDB (no longer requested)", "name", pdbName, "tier", tier)
		if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting PDB: %w", err)
		}
		return nil
	}

	spec := policyv1.PodDisruptionBudgetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: r.selectorLabelsForTier(cluster, tier)},
	}
	switch {
	case pdbCfg.MinAvailable != nil:
		spec.MinAvailable = pdbCfg.MinAvailable
	case pdbCfg.MaxUnavailable != nil:
		spec.MaxUnavailable = pdbCfg.MaxUnavailable
	default:
		// Default to (replicas-1) with a floor of 1. For storage this preserves
		// quorum on drain for 3+ replica clusters and matches the pre-#192 default
		// and the warning emitted by the v1beta1/v1beta2 validating webhooks. For
		// gateway it pins at least one pod available, which is what users want
		// during node drains.
		effective := replicas
		if effective < 2 {
			effective = 2
		}
		minAvail := intstr.FromInt(int(effective - 1))
		spec.MinAvailable = &minAvail
	}

	desired := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pdbName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForTier(cluster, tier),
		},
		Spec: spec,
	}
	if err := controllerutil.SetControllerReference(cluster, desired, r.Scheme); err != nil {
		return err
	}

	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, pdbKey, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating PDB", "name", pdbName, "tier", tier)
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	// If a foreign PDB already squats on our name, leave it alone rather than
	// fight a policy engine. The operator surfaces this via the reconcile log;
	// users can rename the foreign PDB or disable the tier's podDisruptionBudget.
	if existing.UID != "" && len(existing.OwnerReferences) > 0 && !metav1.IsControlledBy(existing, cluster) {
		log.Info("PDB exists but is not controlled by this GarageCluster; skipping update", "name", pdbName, "tier", tier)
		return nil
	}
	if equality.Semantic.DeepEqual(existing.Spec, desired.Spec) &&
		equality.Semantic.DeepEqual(existing.Labels, desired.Labels) &&
		metav1.IsControlledBy(existing, cluster) {
		return nil
	}
	existing.Labels = desired.Labels
	existing.OwnerReferences = desired.OwnerReferences
	existing.Spec = desired.Spec
	log.Info("Updating PDB", "name", pdbName, "tier", tier)
	if err := r.Update(ctx, existing); err != nil {
		// PDB selector is immutable post-creation. If an upgrade-from-old-shape
		// PDB has a different selector, recreate it so the new selector lands.
		if errors.IsInvalid(err) {
			log.Info("PDB update rejected (likely selector immutable); recreating", "name", pdbName, "tier", tier)
			if delErr := r.Delete(ctx, existing); delErr != nil && !errors.IsNotFound(delErr) {
				return fmt.Errorf("deleting PDB for recreate: %w", delErr)
			}
			return r.Create(ctx, desired)
		}
		return err
	}
	return nil
}

// reconcileGatewayAPIService reconciles a tier-scoped <cr>-gateway Service so
// in-cluster clients (operator's bucket/key controllers, WebUI, …) can target
// either tier explicitly. Created only when the cluster has both a storage tier
// AND a gateway tier — i.e. a unified cluster. For storage-only and
// edge-gateway shapes the primary <cr> Service already points at the correct
// (only) tier and a sibling gateway Service would be redundant.
func (r *GarageClusterReconciler) reconcileGatewayAPIService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name + "-gateway"

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForTier(cluster, tierGateway),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: r.selectorLabelsForTier(cluster, tierGateway),
			Ports:    apiServicePorts(cluster),
			// Gateway pods carry a /health readiness probe (see
			// buildGaragePodSpec). PublishNotReadyAddresses: false makes
			// kube-proxy honor it — surge pods during a rollout don't
			// receive S3 traffic until they've joined the cluster, and
			// terminating pods drop out of the endpoint slice as soon as
			// the readiness probe fails.
			PublishNotReadyAddresses: false,
		},
	}

	log.Info("Reconciling gateway API Service", "name", serviceName)
	return reconcileService(ctx, r.Client, svc, cluster, r.Scheme)
}

// deleteGatewayAPIService removes the <cr>-gateway Service when the gateway
// tier is no longer declared (e.g. user removed spec.gateway from a unified
// CR, or the cluster never had a gateway tier).
func (r *GarageClusterReconciler) deleteGatewayAPIService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	name := cluster.Name + "-gateway"
	existing := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	log.Info("Removing gateway API Service (gateway tier no longer declared)", "name", name)
	return r.Delete(ctx, existing)
}

// reconcilePublicEndpointService manages a dedicated RPC service (<name>-rpc) used to expose
// the Garage RPC port externally for multi-cluster federation via publicEndpoint.
// The service is created/updated when publicEndpoint is set and deleted when it is removed.
func (r *GarageClusterReconciler) reconcilePublicEndpointService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	svcName := cluster.Name + "-rpc"

	if cluster.Spec.PublicEndpoint == nil {
		return r.deletePublicEndpointServices(ctx, cluster)
	}

	ep := cluster.Spec.PublicEndpoint
	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	var svcType corev1.ServiceType
	var svcMeta garagev1beta2.ServiceMeta
	var nodePort int32

	switch ep.Type {
	case publicEndpointTypeLoadBalancer:
		if ep.LoadBalancer != nil && ep.LoadBalancer.PerNode {
			if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
				if err := r.deletePublicEndpointServices(ctx, cluster); err != nil {
					return err
				}
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               garagev1beta1.ConditionPublicEndpointReady,
					Status:             metav1.ConditionFalse,
					Reason:             garagev1beta1.ReasonPerNodeNotImplemented,
					Message:            "GarageCluster publicEndpoint.loadBalancer.perNode is not supported in Manual layout mode; set spec.publicEndpoint on each GarageNode instead",
					ObservedGeneration: cluster.Generation,
				})
				return nil
			}
			if err := r.reconcilePerNodeLoadBalancerServices(ctx, cluster, rpcPort, ep.LoadBalancer.ServiceMeta); err != nil {
				return err
			}
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionPublicEndpointReady,
				Status:             metav1.ConditionTrue,
				Reason:             garagev1beta1.ReasonReconcileSuccess,
				Message:            "Per-node LoadBalancer RPC services are reconciled",
				ObservedGeneration: cluster.Generation,
			})
			return nil
		}
		svcType = corev1.ServiceTypeLoadBalancer
		if ep.LoadBalancer != nil {
			svcMeta = ep.LoadBalancer.ServiceMeta
		}
	case publicEndpointTypeNodePort:
		svcType = corev1.ServiceTypeNodePort
		if ep.NodePort != nil {
			svcMeta = ep.NodePort.ServiceMeta
			if ep.NodePort.BasePort != 0 {
				nodePort = ep.NodePort.BasePort
			}
		}
	default:
		log.Info("publicEndpoint type is not yet implemented; use network.rpcPublicAddr", "type", ep.Type)
		return nil
	}

	port := corev1.ServicePort{
		Name:       rpcPortName,
		Port:       rpcPort,
		TargetPort: intstr.FromInt32(rpcPort),
		Protocol:   corev1.ProtocolTCP,
	}
	if nodePort != 0 {
		port.NodePort = nodePort
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        svcName,
			Namespace:   cluster.Namespace,
			Labels:      mergeLabels(r.labelsForCluster(cluster), svcMeta.Labels),
			Annotations: svcMeta.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                     svcType,
			Selector:                 r.selectorLabelsForCluster(cluster),
			Ports:                    []corev1.ServicePort{port},
			PublishNotReadyAddresses: true,
		},
	}

	log.Info("Reconciling public endpoint RPC service", "name", svcName, "type", svcType)
	return reconcileService(ctx, r.Client, svc, cluster, r.Scheme)
}

func (r *GarageClusterReconciler) reconcilePerNodeLoadBalancerServices(ctx context.Context, cluster *garagev1beta2.GarageCluster, rpcPort int32, svcMeta garagev1beta2.ServiceMeta) error {
	log := logf.FromContext(ctx)

	if err := r.deletePublicEndpointService(ctx, cluster, cluster.Name+"-rpc"); err != nil {
		return err
	}

	// Honor an explicit replicas=0 so operators can pause the storage tier
	// without removing the tier definition (PVCs, capacity, etc. are preserved).
	replicas := cluster.StorageReplicas()
	desired := make(map[string]struct{}, replicas)

	// Per-#190, storage pods are owned by per-GarageNode StatefulSets named
	// `<cluster>-storage-<i>` with pod `<cluster>-storage-<i>-0`. Select pods via
	// the stable `garage.rajsingh.info/node` label written by the GarageNode
	// controller — this avoids hard-coding the pod-name convention and works
	// regardless of GarageNode renames or single-pod STS naming.
	for i := int32(0); i < replicas; i++ {
		nodeName := autoModeGarageNodeName(cluster.Name, i)
		svcName := perNodeRPCServiceName(cluster.Name, i)
		desired[svcName] = struct{}{}

		selector := map[string]string{
			labelCluster:    cluster.Name,
			labelGarageNode: nodeName,
		}

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        svcName,
				Namespace:   cluster.Namespace,
				Labels:      mergeLabels(r.labelsForCluster(cluster), svcMeta.Labels),
				Annotations: svcMeta.Annotations,
			},
			Spec: corev1.ServiceSpec{
				Type:                     corev1.ServiceTypeLoadBalancer,
				Selector:                 selector,
				Ports:                    []corev1.ServicePort{rpcServicePort(rpcPort, 0)},
				PublishNotReadyAddresses: true,
			},
		}

		log.Info("Reconciling per-node public endpoint RPC service", "name", svcName, "node", nodeName, "type", corev1.ServiceTypeLoadBalancer)
		if err := reconcileService(ctx, r.Client, svc, cluster, r.Scheme); err != nil {
			return err
		}
	}

	serviceList := &corev1.ServiceList{}
	if err := r.List(ctx, serviceList, client.InNamespace(cluster.Namespace), client.MatchingLabels(r.labelsForCluster(cluster))); err != nil {
		return err
	}
	for i := range serviceList.Items {
		svc := &serviceList.Items[i]
		if !isClusterPerNodeRPCServiceName(cluster.Name, svc.Name) {
			continue
		}
		if _, ok := desired[svc.Name]; ok {
			continue
		}
		log.Info("Deleting stale per-node public endpoint RPC service", "name", svc.Name)
		if err := r.Delete(ctx, svc); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func (r *GarageClusterReconciler) deletePublicEndpointServices(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	if err := r.deletePublicEndpointService(ctx, cluster, cluster.Name+"-rpc"); err != nil {
		return err
	}

	serviceList := &corev1.ServiceList{}
	if err := r.List(ctx, serviceList, client.InNamespace(cluster.Namespace), client.MatchingLabels(r.labelsForCluster(cluster))); err != nil {
		return err
	}
	for i := range serviceList.Items {
		svc := &serviceList.Items[i]
		if !isClusterPerNodeRPCServiceName(cluster.Name, svc.Name) {
			continue
		}
		if err := r.Delete(ctx, svc); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (r *GarageClusterReconciler) deletePublicEndpointService(ctx context.Context, cluster *garagev1beta2.GarageCluster, name string) error {
	existing := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing); err == nil {
		return r.Delete(ctx, existing)
	} else if !errors.IsNotFound(err) {
		return err
	}
	return nil
}

func rpcServicePort(rpcPort, nodePort int32) corev1.ServicePort {
	port := corev1.ServicePort{
		Name:       rpcPortName,
		Port:       rpcPort,
		TargetPort: intstr.FromInt32(rpcPort),
		Protocol:   corev1.ProtocolTCP,
	}
	if nodePort != 0 {
		port.NodePort = nodePort
	}
	return port
}

// perNodeRPCServiceName is the canonical name for the per-pod LoadBalancer RPC
// Service that fronts a single storage pod. The format `<cluster>-<i>-rpc` is
// kept stable across the #190 migration so external systems (DNS, federation)
// don't need to chase a rename — the underlying pod selector changed but the
// Service name did not. Decoded by isClusterPerNodeRPCServiceName.
func perNodeRPCServiceName(clusterName string, ordinal int32) string {
	return fmt.Sprintf("%s-%d-rpc", clusterName, ordinal)
}

func isClusterPerNodeRPCServiceName(clusterName, serviceName string) bool {
	prefix := clusterName + "-"
	suffix := "-rpc"
	if !strings.HasPrefix(serviceName, prefix) || !strings.HasSuffix(serviceName, suffix) {
		return false
	}
	ordinal := strings.TrimSuffix(strings.TrimPrefix(serviceName, prefix), suffix)
	if ordinal == "" {
		return false
	}
	_, err := strconv.Atoi(ordinal)
	return err == nil
}

// resolveGarageImage determines the container image from image/imageRepository fields.
// Priority: image > imageRepository + default tag > operatorDefault > hardcoded default.
func resolveGarageImage(image, imageRepository, operatorDefault string) string {
	if image != "" {
		return image
	}
	if imageRepository != "" {
		return imageRepository + ":" + defaultGarageTag
	}
	if operatorDefault != "" {
		return operatorDefault
	}
	return defaultGarageImage
}

// mergeNodeImage merges cluster and node image fields, then resolves the final image.
// If a node sets imageRepository without image, it clears any inherited cluster image
// so the repo override takes effect.
func mergeNodeImage(clusterImage, clusterRepo, nodeImage, nodeRepo, operatorDefault string) string {
	img, repo := clusterImage, clusterRepo
	if nodeImage != "" {
		img = nodeImage
	}
	if nodeRepo != "" {
		repo = nodeRepo
		if nodeImage == "" {
			img = ""
		}
	}
	return resolveGarageImage(img, repo, operatorDefault)
}

// buildContainerPorts returns the container ports for the Garage StatefulSet
func buildContainerPorts(cluster *garagev1beta2.GarageCluster) []corev1.ContainerPort {
	ports := []corev1.ContainerPort{}

	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}
	ports = append(ports, corev1.ContainerPort{Name: rpcPortName, ContainerPort: rpcPort})

	// S3 API port (always enabled - Garage requires the [s3_api] section)
	s3Port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		s3Port = cluster.Spec.S3API.BindPort
	}
	ports = append(ports, corev1.ContainerPort{Name: s3PortName, ContainerPort: s3Port})

	{
		adminPort := int32(3903)
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: adminPortName, ContainerPort: adminPort})
	}

	// K2V API port
	if cluster.Spec.K2VAPI != nil {
		k2vPort := int32(3904)
		if cluster.Spec.K2VAPI.BindPort != 0 {
			k2vPort = cluster.Spec.K2VAPI.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "k2v", ContainerPort: k2vPort})
	}

	// Web API port
	if w := effectiveWebAPI(cluster); w != nil {
		webPort := int32(3902)
		if w.BindPort != 0 {
			webPort = w.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "web", ContainerPort: webPort})
	}

	return ports
}

// dataPathPVCName returns the deterministic PVC template name for the i-th
// data path in a multi-HDD configuration (issue #188). Naming is
// `data-<index>` so existing single-path clusters keep using the legacy
// `data` PVC name and don't see a destructive rename.
//
//nolint:unused // shared helper retained for parity with garagenode_controller naming
func dataPathPVCName(i int) string {
	return fmt.Sprintf("%s-%d", dataVolName, i)
}

// hasMultipleDataPaths reports whether the cluster declares an explicit
// list of data paths (`storage.data.paths[]`). When true, the operator emits
// one PVC + one volumeMount per path; otherwise it falls back to the legacy
// single-PVC layout mounted at /data/data.
//
//nolint:unused // shared cluster-shape helper retained for tests and future use
func hasMultipleDataPaths(cluster *garagev1beta2.GarageCluster) bool {
	if !cluster.HasStorageTier() {
		return false
	}
	return cluster.Spec.Storage.Data != nil && len(cluster.Spec.Storage.Data.Paths) > 0
}

// buildVolumesAndMounts returns volumes and volume mounts for the Garage StatefulSet.
// For gateway clusters, data volume is EmptyDir since gateways don't store blocks.
// Metadata volume comes from PVC (via VolumeClaimTemplates) for both gateway and storage.
//
// Post-#190: the cluster-level storage STS no longer exists; this helper is
// retained for unit tests that exercise the cluster-shape volume/mount logic.
// The live storage path uses garagenode_controller's per-node builders.
//
//nolint:unused,unparam // retained for tests; per-node builders live in garagenode_controller.go
func buildVolumesAndMounts(cluster *garagev1beta2.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
		{Name: RPCSecretKey, MountPath: rpcSecretMountPath, ReadOnly: true},
		{Name: metadataVolName, MountPath: metadataPath},
	}

	// Data mounts: one per declared path when paths[] is set, otherwise the
	// legacy single mount at /data/data. EmptyDir clusters still get exactly
	// one mount (paths[] is rejected by the webhook with type=EmptyDir).
	if hasMultipleDataPaths(cluster) && !isDataEmptyDir(cluster) {
		for i, p := range cluster.Spec.Storage.Data.Paths {
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      dataPathPVCName(i),
				MountPath: p.Path,
				ReadOnly:  p.ReadOnly,
			})
		}
	} else {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{Name: dataVolName, MountPath: dataPath})
	}

	rpcSecretName := cluster.Name + "-rpc-secret"
	if cluster.Spec.Network.RPCSecretRef != nil {
		rpcSecretName = cluster.Spec.Network.RPCSecretRef.Name
	}
	// For gateway clusters connecting to storage via clusterRef, use storage cluster's RPC secret
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil {
		if cluster.Spec.ConnectTo.RPCSecretRef != nil {
			rpcSecretName = cluster.Spec.ConnectTo.RPCSecretRef.Name
		} else if cluster.Spec.ConnectTo.ClusterRef != nil {
			// Auto-derive storage cluster's RPC secret name
			rpcSecretName = cluster.Spec.ConnectTo.ClusterRef.Name + "-rpc-secret"
		}
	}
	rpcSecretKey := RPCSecretKey
	if cluster.Spec.Network.RPCSecretRef != nil && cluster.Spec.Network.RPCSecretRef.Key != "" {
		rpcSecretKey = cluster.Spec.Network.RPCSecretRef.Key
	}
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.RPCSecretRef != nil && cluster.Spec.ConnectTo.RPCSecretRef.Key != "" {
		rpcSecretKey = cluster.Spec.ConnectTo.RPCSecretRef.Key
	}

	volumes := []corev1.Volume{
		{
			Name: "config",
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
	}

	// Handle metadata volume for EmptyDir type.
	if isMetadataEmptyDir(cluster) {
		emptyDir := &corev1.EmptyDirVolumeSource{}
		if cluster.Spec.Storage.Metadata.Size != nil {
			emptyDir.SizeLimit = cluster.Spec.Storage.Metadata.Size
		}
		volumes = append(volumes, corev1.Volume{
			Name:         "metadata",
			VolumeSource: corev1.VolumeSource{EmptyDir: emptyDir},
		})
	}
	// else: metadata comes from VolumeClaimTemplate (storage tier).

	// Handle data volume for EmptyDir type. Storage clusters with a real PVC get the
	// volume injected via VolumeClaimTemplate so we skip them here.
	if isDataEmptyDir(cluster) {
		emptyDir := &corev1.EmptyDirVolumeSource{}
		if cluster.Spec.Storage.Data != nil && cluster.Spec.Storage.Data.Size != nil {
			emptyDir.SizeLimit = cluster.Spec.Storage.Data.Size
		}
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolName,
			VolumeSource: corev1.VolumeSource{EmptyDir: emptyDir},
		})
	}
	// else: data comes from VolumeClaimTemplate.

	// Add admin token secret volume and mount if configured
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
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      DefaultAdminTokenKey,
			MountPath: adminSecretMountPath,
			ReadOnly:  true,
		})
	}

	// Add metrics token secret volume and mount if configured separately from admin token
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsTokenSecretRef != nil {
		metricsTokenKey := metricsTokenVolumeName
		if cluster.Spec.Admin.MetricsTokenSecretRef.Key != "" {
			metricsTokenKey = cluster.Spec.Admin.MetricsTokenSecretRef.Key
		}
		volumes = append(volumes, corev1.Volume{
			Name: metricsTokenVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  cluster.Spec.Admin.MetricsTokenSecretRef.Name,
					DefaultMode: ptr.To[int32](0600),
					Items:       []corev1.KeyToPath{{Key: metricsTokenKey, Path: metricsTokenVolumeName}},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      metricsTokenVolumeName,
			MountPath: "/secrets/metrics",
			ReadOnly:  true,
		})
	}

	// Add Consul discovery TLS secret volumes and mounts
	if cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil &&
		cluster.Spec.Discovery.Consul.Enabled != nil && *cluster.Spec.Discovery.Consul.Enabled {
		consul := cluster.Spec.Discovery.Consul

		// CA certificate from secret
		if consul.CACertSecretRef != nil {
			caCertKey := consulCACertKey
			if consul.CACertSecretRef.Key != "" {
				caCertKey = consul.CACertSecretRef.Key
			}
			volumes = append(volumes, corev1.Volume{
				Name: consulCACertVolume,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  consul.CACertSecretRef.Name,
						DefaultMode: ptr.To[int32](0600),
						Items:       []corev1.KeyToPath{{Key: caCertKey, Path: consulCACertKey}},
					},
				},
			})
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      consulCACertVolume,
				MountPath: "/secrets/consul/ca",
				ReadOnly:  true,
			})
		}

		// Client certificate from secret
		if consul.ClientCertSecretRef != nil {
			clientCertKey := consulClientCertKey
			if consul.ClientCertSecretRef.Key != "" {
				clientCertKey = consul.ClientCertSecretRef.Key
			}
			volumes = append(volumes, corev1.Volume{
				Name: consulClientCertVolume,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  consul.ClientCertSecretRef.Name,
						DefaultMode: ptr.To[int32](0600),
						Items:       []corev1.KeyToPath{{Key: clientCertKey, Path: consulClientCertKey}},
					},
				},
			})
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      consulClientCertVolume,
				MountPath: "/secrets/consul/client-cert",
				ReadOnly:  true,
			})
		}

		// Client key from secret
		if consul.ClientKeySecretRef != nil {
			clientKeyKey := consulClientKeyKey
			if consul.ClientKeySecretRef.Key != "" {
				clientKeyKey = consul.ClientKeySecretRef.Key
			}
			volumes = append(volumes, corev1.Volume{
				Name: consulClientKeyVolume,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  consul.ClientKeySecretRef.Name,
						DefaultMode: ptr.To[int32](0600),
						Items:       []corev1.KeyToPath{{Key: clientKeyKey, Path: consulClientKeyKey}},
					},
				},
			})
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      consulClientKeyVolume,
				MountPath: "/secrets/consul/client-key",
				ReadOnly:  true,
			})
		}

		// NOTE: Consul token is NOT mounted as a volume because Garage doesn't support
		// token_file - it requires the actual token string inline in the config.
		// The token is read from the secret in buildConfigContext() and embedded directly.
	}

	return volumes, volumeMounts
}

// vctStorageClassChanged returns true if any VolumeClaimTemplate in desired has a different
// storageClassName than the corresponding template in existing (matched by name). Kubernetes
// treats VCTs as immutable, so a storageClass change requires deleting and recreating the STS.
func vctStorageClassChanged(existing, desired []corev1.PersistentVolumeClaim) bool {
	existingByName := make(map[string]*string, len(existing))
	for i := range existing {
		existingByName[existing[i].Name] = existing[i].Spec.StorageClassName
	}
	for i := range desired {
		existingSC, ok := existingByName[desired[i].Name]
		if !ok {
			continue
		}
		desiredSC := desired[i].Spec.StorageClassName
		// Both nil → no change. One nil, one non-nil → changed. Both non-nil → compare values.
		if (existingSC == nil) != (desiredSC == nil) {
			return true
		}
		if existingSC != nil && *existingSC != *desiredSC {
			return true
		}
	}
	return false
}

func (r *GarageClusterReconciler) updateStatus(ctx context.Context, cluster *garagev1beta2.GarageCluster, phase string, err error) (ctrl.Result, error) {
	cluster.Status.Phase = phase
	// Only set ObservedGeneration when reconciliation succeeded
	if err == nil {
		cluster.Status.ObservedGeneration = cluster.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
			Message:            err.Error(),
			ObservedGeneration: cluster.Generation,
		})
	}

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, cluster); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	return ctrl.Result{}, nil
}

func (r *GarageClusterReconciler) updateStatusFromCluster(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Get workload status
	var readyReplicas int32
	var desiredReplicas int32

	isManualMode := cluster.Spec.LayoutPolicy == LayoutPolicyManual

	if isManualMode {
		// Manual mode: count ready GarageNodes that reference this cluster
		nodeList := &garagev1beta1.GarageNodeList{}
		if err := r.List(ctx, nodeList, client.InNamespace(cluster.Namespace)); err != nil {
			log.Error(err, "Failed to list GarageNodes")
		} else {
			for _, node := range nodeList.Items {
				if node.Spec.ClusterRef.Name == cluster.Name {
					desiredReplicas++
					if node.Status.Connected {
						readyReplicas++
					}
				}
			}
		}
	} else {
		// Auto mode: aggregate across the storage and gateway tiers.
		//
		// Post-#190 the storage tier is N × per-GarageNode StatefulSets — there is
		// no single cluster-named storage STS to query. Mirror the Manual path and
		// count the operator-owned GarageNodes by their .status.connected. The
		// gateway tier remains a single Deployment/StatefulSet named via
		// gatewayWorkloadName(cluster) and is still queried directly.
		var storageDesired, storageReady int32
		var gatewayDesired, gatewayReady int32

		if cluster.HasStorageTier() || cluster.HasGatewayTier() {
			storageDesired = cluster.StorageReplicas()
			gatewayDesired = cluster.GatewayReplicas()

			gnList := &garagev1beta1.GarageNodeList{}
			if err := r.List(ctx, gnList,
				client.InNamespace(cluster.Namespace),
				client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
			); err != nil {
				log.Error(err, "Failed to list child GarageNodes for status aggregation")
			} else {
				for _, n := range gnList.Items {
					if n.Spec.ClusterRef.Name != cluster.Name {
						continue
					}
					if !n.Status.Connected {
						continue
					}
					if n.Spec.Gateway {
						gatewayReady++
					} else {
						storageReady++
					}
				}
			}
		}

		// Gateway tier is reconciled by the cluster controller as a single
		// Deployment/StatefulSet — when no per-pod GarageNode CRs exist (the
		// common case), fall back to the workload's ReadyReplicas so the count
		// reflects the gateway pods' rollout state.
		if cluster.HasGatewayTier() && gatewayReady == 0 {
			gwSts := &appsv1.StatefulSet{}
			if err := r.Get(ctx, types.NamespacedName{Name: gatewayWorkloadName(cluster), Namespace: cluster.Namespace}, gwSts); err != nil {
				if !errors.IsNotFound(err) {
					return ctrl.Result{}, err
				}
			} else {
				gatewayReady = gwSts.Status.ReadyReplicas
			}
		}

		cluster.Status.StorageReplicas = storageDesired
		cluster.Status.StorageReadyReplicas = storageReady
		cluster.Status.GatewayReplicas = gatewayDesired
		cluster.Status.GatewayReadyReplicas = gatewayReady
		desiredReplicas = storageDesired + gatewayDesired
		readyReplicas = storageReady + gatewayReady

		if desiredReplicas == 0 {
			return r.updateStatus(ctx, cluster, "Pending", nil)
		}
	}

	cluster.Status.ReadyReplicas = readyReplicas
	cluster.Status.Replicas = desiredReplicas
	cluster.Status.Selector = metav1.FormatLabelSelector(&metav1.LabelSelector{
		MatchLabels: r.selectorLabelsForCluster(cluster),
	})

	// Try to get cluster health from Garage Admin API
	adminPort := getAdminPort(cluster)
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
	adminToken := ""

	// Get admin token from secret
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      cluster.Spec.Admin.AdminTokenSecretRef.Name,
			Namespace: cluster.Namespace,
		}, secret); err == nil && secret.Data != nil {
			key := DefaultAdminTokenKey
			if cluster.Spec.Admin.AdminTokenSecretRef.Key != "" {
				key = cluster.Spec.Admin.AdminTokenSecretRef.Key
			}
			if tokenData, ok := secret.Data[key]; ok {
				adminToken = string(tokenData)
			}
		}
	}

	if adminToken != "" && readyReplicas > 0 {
		garageClient := garage.NewClient(adminEndpoint, adminToken)
		health, err := garageClient.GetClusterHealth(ctx)
		if err != nil {
			log.V(1).Info("Failed to get cluster health", "error", err)
		} else {
			cluster.Status.Health = &garagev1beta2.ClusterHealth{
				Status:           health.Status,
				Healthy:          health.StorageNodesUp == health.StorageNodes,
				Available:        health.PartitionsQuorum == health.Partitions,
				KnownNodes:       health.KnownNodes,
				ConnectedNodes:   health.ConnectedNodes,
				StorageNodes:     health.StorageNodes,
				StorageNodesOK:   health.StorageNodesUp,
				Partitions:       health.Partitions,
				PartitionsQuorum: health.PartitionsQuorum,
				PartitionsAllOK:  health.PartitionsAllOK,
			}
		}

		status, err := garageClient.GetClusterStatus(ctx)
		if err != nil {
			log.V(1).Info("Failed to get cluster status", "error", err)
		} else {
			// Use a stable cluster identifier:
			// - Keep existing ClusterID if still present in the cluster
			// - Otherwise use the lexicographically smallest node ID for consistency
			if len(status.Nodes) > 0 {
				existingIDFound := false
				if cluster.Status.ClusterID != "" {
					for _, node := range status.Nodes {
						if node.ID == cluster.Status.ClusterID {
							existingIDFound = true
							break
						}
					}
				}
				if !existingIDFound {
					// Find lexicographically smallest node ID for stability
					smallestID := status.Nodes[0].ID
					for _, node := range status.Nodes[1:] {
						if node.ID < smallestID {
							smallestID = node.ID
						}
					}
					cluster.Status.ClusterID = smallestID
				}

				// Populate BuildInfo from the first connected node
				for _, node := range status.Nodes {
					if node.IsUp && node.GarageVersion != nil {
						cluster.Status.BuildInfo = &garagev1beta2.GarageBuildInfo{
							Version: *node.GarageVersion,
						}
						break
					}
				}

				// Calculate storage stats and draining node count from all nodes
				var totalData, availableData uint64
				var drainingCount int
				for _, node := range status.Nodes {
					if node.DataPartition != nil {
						totalData += node.DataPartition.Total
						availableData += node.DataPartition.Available
					}
					if node.Draining {
						drainingCount++
					}
				}
				if totalData > 0 {
					cluster.Status.StorageStats = &garagev1beta2.ClusterStorageStats{
						TotalCapacity:     resource.NewQuantity(int64(totalData), resource.BinarySI),
						UsedCapacity:      resource.NewQuantity(int64(totalData-availableData), resource.BinarySI),
						AvailableCapacity: resource.NewQuantity(int64(availableData), resource.BinarySI),
					}
				}
				cluster.Status.DrainingNodes = drainingCount
			}
			cluster.Status.LayoutVersion = int64(status.LayoutVersion)
		}

		// Fetch layout history to track draining versions
		history, err := garageClient.GetClusterLayoutHistory(ctx)
		if err != nil {
			log.V(1).Info("Failed to get cluster layout history", "error", err)
		} else {
			cluster.Status.LayoutHistory = &garagev1beta2.LayoutHistoryStatus{
				CurrentVersion: int64(history.CurrentVersion),
				MinAck:         int64(history.MinAck),
			}
			for _, v := range history.Versions {
				cluster.Status.LayoutHistory.Versions = append(cluster.Status.LayoutHistory.Versions, garagev1beta2.LayoutVersionInfo{
					Version:      int64(v.Version),
					Status:       string(v.Status),
					StorageNodes: v.StorageNodes,
					GatewayNodes: v.GatewayNodes,
				})
			}

			// Auto-skip dead draining nodes to prevent stuck layout versions
			// This happens when a node is removed/replaced but its old identity is still draining
			if drainingVersions := history.GetDrainingVersions(); len(drainingVersions) > 0 && status != nil {
				// Find dead draining nodes (offline nodes that are still draining)
				var deadDrainingNodes []string
				for _, node := range status.Nodes {
					if node.Draining && !node.IsUp {
						deadDrainingNodes = append(deadDrainingNodes, node.ID)
					}
				}

				if len(deadDrainingNodes) > 0 {
					log.Info("Found dead draining nodes, automatically calling skip-dead-nodes",
						"deadNodes", deadDrainingNodes,
						"drainingVersions", len(drainingVersions),
						"currentVersion", history.CurrentVersion)

					skipReq := garage.SkipDeadNodesRequest{
						Version:          history.CurrentVersion,
						AllowMissingData: false, // Safe mode: only update ACK for dead nodes
					}
					result, err := garageClient.ClusterLayoutSkipDeadNodes(ctx, skipReq)
					if err != nil {
						if garage.IsBadRequest(err) {
							// Single layout version, nothing to skip
							log.V(1).Info("Skip-dead-nodes: single layout version, nothing to skip")
						} else {
							log.Error(err, "Failed to skip dead nodes (will retry on next reconcile)")
						}
					} else if len(result.AckUpdated) > 0 || len(result.SyncUpdated) > 0 {
						log.Info("Successfully skipped dead draining nodes",
							"ackUpdated", result.AckUpdated,
							"syncUpdated", result.SyncUpdated,
							"version", history.CurrentVersion)
					}
				} else {
					// Draining versions exist but no dead nodes - nodes are still syncing
					for _, dv := range drainingVersions {
						log.V(1).Info("Layout version in Draining state - nodes still syncing",
							"version", dv.Version,
							"storageNodes", dv.StorageNodes,
							"gatewayNodes", dv.GatewayNodes)
					}
				}
			}
		}
	}

	// Update phase based on readiness
	// Note: desiredReplicas is already computed above (from Spec.Replicas or from GarageNodes in Manual mode)

	phase := "Running"
	if readyReplicas == 0 {
		phase = "Pending"
	} else if readyReplicas < desiredReplicas {
		phase = "Degraded"
	}

	cluster.Status.Phase = phase
	cluster.Status.ObservedGeneration = cluster.Generation

	// Set ready condition
	readyStatus := metav1.ConditionTrue
	readyReason := "ClusterReady"
	readyMessage := "All replicas are ready"
	if readyReplicas < desiredReplicas {
		readyStatus = metav1.ConditionFalse
		readyReason = "NotAllReplicasReady"
		readyMessage = fmt.Sprintf("%d/%d replicas ready", readyReplicas, desiredReplicas)
	} else if cluster.Status.Health != nil && !cluster.Status.Health.Healthy {
		readyStatus = metav1.ConditionFalse
		readyReason = "LayoutNotReady"
		readyMessage = fmt.Sprintf("cluster layout not converged: %d/%d storage nodes ok",
			cluster.Status.Health.StorageNodesOK, cluster.Status.Health.StorageNodes)
	}

	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             readyStatus,
		Reason:             readyReason,
		Message:            readyMessage,
		ObservedGeneration: cluster.Generation,
	})

	// Update endpoints using configured ports
	s3Port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		s3Port = cluster.Spec.S3API.BindPort
	}
	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}
	cluster.Status.Endpoints = &garagev1beta2.ClusterEndpoints{
		S3:    svcFQDN(cluster.Name, cluster.Namespace, s3Port, r.ClusterDomain),
		Admin: svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain),
		RPC:   svcFQDN(cluster.Name+"-headless", cluster.Namespace, rpcPort, r.ClusterDomain),
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// External gateway clusters back off to 5m regardless of health: gateways may show
	// "unavailable" by design (no data stored locally) and that's expected. The drift
	// check in isExternalGatewayConnected handles reconnection within that window.
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	// Requeue faster when cluster is unhealthy to speed up recovery
	if cluster.Status.Health != nil && cluster.Status.Health.Status != healthStatusHealthy {
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

// labelsForCluster returns the default operator-managed labels for cluster-scoped
// resources (ConfigMap, headless service, API service, RPC secret) that span both
// storage and gateway tiers. Component is taken from whichever tier exists; when
// both tiers exist, "storage" wins.
func (r *GarageClusterReconciler) labelsForCluster(cluster *garagev1beta2.GarageCluster) map[string]string {
	component := tierStorage
	if !cluster.HasStorageTier() && cluster.HasGatewayTier() {
		component = tierGateway
	}
	return map[string]string{
		labelAppName:      defaultAppName,
		labelAppInstance:  cluster.Name,
		labelAppManagedBy: operatorName,
		labelAppComponent: component,
		labelCluster:      cluster.Name,
	}
}

func (r *GarageClusterReconciler) selectorLabelsForCluster(cluster *garagev1beta2.GarageCluster) map[string]string {
	// Post-#190, both Manual and Auto storage tiers are GarageNode-owned per-node
	// StatefulSets. Those pods carry app.kubernetes.io/name=garagenode and
	// app.kubernetes.io/instance=<node-name> (not the cluster name), so the only
	// stable selector that spans the tier is the shared ownership label.
	// Gateway-tier Deployments are unaffected — they keep the unified labels and
	// are reached via tier-specific selectors (selectorLabelsForTier).
	return map[string]string{
		labelCluster: cluster.Name,
	}
}

// bootstrapNodeInfo holds discovered node information
type bootstrapNodeInfo struct {
	id      string
	podIP   string
	podName string
	// tier is the cluster tier the pod belongs to (tierStorage or tierGateway),
	// derived from the pod's labelTier label. Empty when neither label is set.
	// Layout entries get a "tier:<tier>" tag for diagnostics and to scope
	// per-tier reconciliation (e.g. capacity assignment).
	tier string
}

// layoutConfig holds configuration for auto-managed node layout
type layoutConfig struct {
	zone                   string
	capacity               uint64
	tags                   []string
	capacityReservePercent int
	replicationFactor      int
	hasRemoteClusters      bool                   // Skip replication check if federation will bring nodes
	forceLayoutApply       bool                   // Manual override via annotation
	isGateway              bool                   // Gateway clusters have nil capacity
	clusterName            string                 // Cluster name used to identify nodes belonging to this cluster (via exact tag match)
	namespace              string                 // Namespace used together with clusterName for unique node identification
	zoneRedundancy         *garage.ZoneRedundancy // Zone redundancy setting from cluster spec
	skipStaleDetection     bool                   // Skip stale node removal when some pods are not yet identified
}

// getAdminPort returns the configured admin port for the cluster
func getAdminPort(cluster *garagev1beta2.GarageCluster) int32 {
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		return cluster.Spec.Admin.BindPort
	}
	return 3903
}

// getRPCPort returns the configured RPC port for the cluster
func getRPCPort(cluster *garagev1beta2.GarageCluster) int32 {
	if cluster.Spec.Network.RPCBindPort != 0 {
		return cluster.Spec.Network.RPCBindPort
	}
	return 3901
}

// discoverNodes discovers Garage node IDs from running pods
func discoverNodes(ctx context.Context, pods []corev1.Pod, adminToken string, adminPort int32) []bootstrapNodeInfo {
	log := logf.FromContext(ctx)
	nodes := make([]bootstrapNodeInfo, 0, len(pods))

	for _, pod := range pods {
		endpoint := adminEndpoint(pod.Status.PodIP, adminPort)
		garageClient := garage.NewClient(endpoint, adminToken)

		status, err := garageClient.GetClusterStatus(ctx)
		if err != nil {
			log.V(1).Info("Failed to get status from pod", "pod", pod.Name, "error", err)
			continue
		}

		log.V(1).Info("Got cluster status from pod", "pod", pod.Name, "nodeCount", len(status.Nodes))

		// Find the local node (the one running on this pod).
		// Garage's peering layer marks the local node as PeerConnState::Ourself, which
		// means isUp=true but lastSeenSecsAgo=nil (the node never pings itself).
		// Connected remote peers always have lastSeenSecsAgo set to a value.
		// This is the only reliable identification method in federated clusters where:
		// - IP matching fails due to rpc_public_addr (Tailscale VIP != pod ClusterIP)
		// - IP matching fails due to gossip address pollution (remote nodes show local IPs)
		// - Hostname matching is ambiguous (all pods are named "garage-0")
		var foundNode *garage.NodeInfo
		var ipFallback *garage.NodeInfo
		var ourselfCandidates int
		for i := range status.Nodes {
			node := &status.Nodes[i]
			log.V(1).Info("Checking node", "nodeId", node.ID, "isUp", node.IsUp, "hasAddress", node.Address != nil, "addr", node.Address, "lastSeenSecsAgo", node.LastSeenSecsAgo)

			if !node.IsUp {
				continue
			}
			// The local node (PeerConnState::Ourself) is always up but never pinged.
			// In freshly started clusters, newly connected peers may also briefly have
			// lastSeenSecsAgo=nil before their first ping completes, so we count matches
			// and only use this method when unambiguous.
			if node.LastSeenSecsAgo == nil {
				ourselfCandidates++
				foundNode = node
			}
			// Track IP match as fallback
			if ipFallback == nil && node.Address != nil {
				nodeIP := *node.Address
				if colonIdx := strings.LastIndex(nodeIP, ":"); colonIdx > 0 {
					nodeIP = nodeIP[:colonIdx]
				}
				if nodeIP == pod.Status.PodIP {
					ipFallback = node
				}
			}
		}
		// If multiple nodes match Ourself heuristic (pre-first-ping window),
		// prefer IP fallback which is reliable before gossip pollution accumulates
		if ourselfCandidates != 1 {
			foundNode = nil
		}
		if foundNode == nil && ipFallback != nil {
			foundNode = ipFallback
			log.V(1).Info("Matched node by IP fallback", "nodeId", foundNode.ID, "podIP", pod.Status.PodIP)
		}

		if foundNode == nil {
			log.V(1).Info("Pod not yet matched to any node, will retry on next reconciliation", "pod", pod.Name, "podIP", pod.Status.PodIP)
			continue
		}

		nodes = append(nodes, bootstrapNodeInfo{
			id:      foundNode.ID,
			podIP:   pod.Status.PodIP,
			podName: pod.Name,
			tier:    pod.Labels[labelTier],
		})
	}
	return nodes
}

// findReachableClient finds the first reachable admin endpoint
func findReachableClient(ctx context.Context, nodes []bootstrapNodeInfo, adminToken string, adminPort int32) *garage.Client {
	for _, node := range nodes {
		endpoint := adminEndpoint(node.podIP, adminPort)
		garageClient := garage.NewClient(endpoint, adminToken)
		if _, err := garageClient.GetClusterHealth(ctx); err == nil {
			return garageClient
		}
	}
	return nil
}

// connectNodes connects all nodes together via RPC by having each node connect to all others
// This ensures that when a pod restarts with a new IP, all nodes learn about the new address
func connectNodes(ctx context.Context, nodes []bootstrapNodeInfo, adminToken string, adminPort, rpcPort int32) {
	log := logf.FromContext(ctx)
	// Have each node tell the cluster about all other nodes
	// This ensures IP address changes propagate to all nodes
	for _, sourceNode := range nodes {
		endpoint := adminEndpoint(sourceNode.podIP, adminPort)
		nodeClient := garage.NewClient(endpoint, adminToken)

		for _, targetNode := range nodes {
			if targetNode.id == sourceNode.id {
				continue // Skip self
			}
			addr := rpcAddr(targetNode.podIP, rpcPort)
			result, err := nodeClient.ConnectNode(ctx, targetNode.id, addr)
			if err != nil {
				log.V(1).Info("Failed to connect node (API error)", "source", sourceNode.podName, "target", targetNode.podName, "error", err)
				continue
			}
			if !result.Success {
				errMsg := "unknown error"
				if result.Error != nil {
					errMsg = *result.Error
				}
				log.V(1).Info("Failed to connect node", "source", sourceNode.podName, "target", targetNode.podName, "error", errMsg)
			}
		}
	}
}

// calculateEffectiveCapacity computes capacity with reserve percentage applied
func calculateEffectiveCapacity(capacity uint64, reservePercent int) uint64 {
	if reservePercent > 0 && reservePercent <= 50 {
		return capacity * uint64(100-reservePercent) / 100
	}
	return capacity
}

// findStaleNodes identifies nodes in layout that are no longer running.
// It only considers nodes that belong to this cluster (identified by exact clusterName tag match).
// This prevents accidentally removing nodes from other clusters (e.g., a gateway cluster
// shouldn't remove storage nodes, and vice versa).
func findStaleNodes(ctx context.Context, layout *garage.ClusterLayout, zone string, runningNodes map[string]bool, clusterName, namespace string) []garage.NodeRoleChange {
	log := logf.FromContext(ctx)

	// Build maps of nodes already staged for removal or addition.
	// We skip nodes that are already staged to avoid duplicate operations.
	alreadyStagedForRemoval := make(map[string]bool)
	alreadyStagedForAddition := make(map[string]bool)
	for _, change := range layout.StagedRoleChanges {
		if change.Remove {
			alreadyStagedForRemoval[change.ID] = true
		} else {
			alreadyStagedForAddition[change.ID] = true
		}
	}

	staleRoles := make([]garage.NodeRoleChange, 0)
	for _, role := range layout.Roles {
		// Only consider nodes in the same zone that aren't running
		if role.Zone != zone {
			continue
		}
		if runningNodes[role.ID] {
			continue
		}
		if alreadyStagedForRemoval[role.ID] {
			continue
		}
		// Skip nodes that are being re-added (e.g., after a pod restart with new config).
		// This prevents race conditions where we'd try to remove a node that's
		// simultaneously being updated.
		if alreadyStagedForAddition[role.ID] {
			continue
		}

		// Only remove nodes that belong to this cluster (identified by exact tag match).
		// Uses exact match to prevent clusters with prefix-overlapping names from
		// accidentally removing each other's nodes.
		if !nodeBelongsToCluster(role.Tags, clusterName, namespace) {
			continue
		}

		shortID := role.ID
		if len(shortID) > 16 {
			shortID = shortID[:16] + "..."
		}
		log.Info("Found stale node in layout", "nodeId", shortID, "zone", role.Zone, "tags", role.Tags)
		staleRoles = append(staleRoles, garage.NodeRoleChange{
			ID:     role.ID,
			Remove: true,
		})
	}
	return staleRoles
}

// countTotalNodesAfterApply calculates how many nodes will exist after staged changes are applied.
// Stale Remove entries (targeting node IDs not present in layout.Roles) are ignored — Garage drops
// them silently during apply (see upstream src/rpc/layout/version.rs calculate_next_version), so
// counting them here would falsely report a smaller post-apply node count and deadlock the gate
// in applyLayoutAfterAssignment.
func countTotalNodesAfterApply(layout *garage.ClusterLayout) int {
	existing := make(map[string]bool, len(layout.Roles))
	for _, role := range layout.Roles {
		existing[role.ID] = true
	}
	total := len(layout.Roles)
	for _, change := range layout.StagedRoleChanges {
		if change.Remove {
			if existing[change.ID] {
				total--
			}
		} else {
			if !existing[change.ID] {
				total++
			}
		}
	}
	return total
}

// assignNewNodesToLayout assigns undiscovered nodes to the cluster layout and fixes config drift.
//
// Both storage- and gateway-tier pods are staged into the layout. Gateways
// receive capacity=nil (matching `garage layout assign --gateway` upstream),
// so they're excluded from ring_assignment_data but ARE included in
// layout.all_nodes() — which is what FullReplication (key_table,
// bucket_table, bucket_alias_table, admin_token_table) uses to decide
// where to write. Without a layout entry the gateway's local DB never
// receives those writes, and Garage's S3 sig-auth path
// (src/api/common/signature/payload.rs:413, get_local()) returns
// "No such key" on every request.
func assignNewNodesToLayout(ctx context.Context, garageClient *garage.Client, nodes []bootstrapNodeInfo, cfg layoutConfig) error {
	log := logf.FromContext(ctx)

	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Build map of existing roles by ID for drift detection
	existingRoles := make(map[string]*garage.LayoutNodeRole)
	for i := range layout.Roles {
		existingRoles[layout.Roles[i].ID] = &layout.Roles[i]
	}
	// Also track staged changes
	stagedNodes := make(map[string]bool)
	for _, change := range layout.StagedRoleChanges {
		if !change.Remove {
			stagedNodes[change.ID] = true
		}
	}

	effectiveCapacity := calculateEffectiveCapacity(cfg.capacity, cfg.capacityReservePercent)

	// Validate minimum capacity - Garage requires at least 1024 bytes (1 KB).
	// Only enforce when there's any storage-tier pod in this batch; pure
	// gateway-only clusters legitimately have no capacity.
	// See: src/api/admin/layout.rs - "Capacity should be at least 1K (1024)"
	const minCapacity uint64 = 1024
	hasStorageNode := false
	for _, n := range nodes {
		if n.tier == tierStorage {
			hasStorageNode = true
			break
		}
	}
	if hasStorageNode && effectiveCapacity < minCapacity {
		return fmt.Errorf("effective capacity %d bytes is below minimum of %d bytes (1 KB); "+
			"check storage.data.size and capacityReservePercent settings", effectiveCapacity, minCapacity)
	}

	zone := cfg.zone
	if zone == "" {
		zone = "default"
	}

	// Find new nodes to add and detect config drift on existing nodes
	newRoles := make([]garage.NodeRoleChange, 0, len(nodes))
	driftRoles := make([]garage.NodeRoleChange, 0)
	for _, node := range nodes {
		// Build desired tags for this node
		desiredTags := buildNodeTags(cfg.clusterName, cfg.namespace, node.tier, cfg.tags, node.podName)
		// Capacity is per-tier: storage pods own real data, gateways do not.
		// The cluster-wide cfg.isGateway flag is only correct for pure gateway-only
		// clusters; for unified storage+gateway CRs we must look at each pod's tier
		// so gateway pods never enter storage_sets with phantom capacity.
		var desiredCapacity *uint64
		if node.tier == tierStorage || (node.tier == "" && !cfg.isGateway) {
			cap := effectiveCapacity
			desiredCapacity = &cap
		}

		// Check if node already exists in layout
		existingRole, exists := existingRoles[node.id]
		if exists {
			// Check for config drift
			if detectNodeConfigDrift(existingRole, zone, desiredTags, desiredCapacity) {
				log.Info("Config drift detected on node, updating",
					"nodeId", node.id[:16],
					"podName", node.podName,
					"existingZone", existingRole.Zone,
					"desiredZone", zone,
					"existingTags", existingRole.Tags,
					"desiredTags", desiredTags)
				driftRoles = append(driftRoles, garage.NodeRoleChange{
					ID:       node.id,
					Zone:     zone,
					Tags:     desiredTags,
					Capacity: desiredCapacity,
				})
			} else {
				log.V(1).Info("Node already in layout with correct config", "nodeId", node.id, "podName", node.podName)
			}
			continue
		}

		// Check if already staged
		if stagedNodes[node.id] {
			log.V(1).Info("Node already staged", "nodeId", node.id, "podName", node.podName)
			continue
		}

		// New node - add to layout
		role := garage.NodeRoleChange{
			ID:       node.id,
			Zone:     zone,
			Tags:     desiredTags,
			Capacity: desiredCapacity,
		}
		newRoles = append(newRoles, role)
	}

	// Build running nodes map for stale detection
	runningNodes := make(map[string]bool)
	for _, node := range nodes {
		runningNodes[node.id] = true
	}

	// Find stale nodes only when all running pods have been successfully identified.
	// If any pod couldn't be resolved to a node ID (still starting), we'd wrongly
	// mark its layout entry as stale and destroy the cluster layout on restart.
	var staleRoles []garage.NodeRoleChange
	if !cfg.skipStaleDetection {
		staleRoles = findStaleNodes(ctx, layout, zone, runningNodes, cfg.clusterName, cfg.namespace)
	}

	// Combine all changes: new nodes, drift fixes, and stale node removals
	allChanges := make([]garage.NodeRoleChange, 0, len(newRoles)+len(driftRoles)+len(staleRoles))
	allChanges = append(allChanges, newRoles...)
	allChanges = append(allChanges, driftRoles...)
	allChanges = append(allChanges, staleRoles...)

	// Stage changes if any
	if len(allChanges) > 0 {
		if len(newRoles) > 0 {
			log.Info("Adding nodes to cluster layout", "count", len(newRoles))
		}
		if len(driftRoles) > 0 {
			log.Info("Fixing config drift on existing nodes", "count", len(driftRoles))
		}
		if len(staleRoles) > 0 {
			log.Info("Removing stale nodes from cluster layout", "count", len(staleRoles))
		}

		// Build layout update request with zone redundancy if configured
		layoutReq := garage.UpdateClusterLayoutRequest{Roles: allChanges}
		if cfg.zoneRedundancy != nil {
			layoutReq.Parameters = &garage.LayoutParameters{ZoneRedundancy: cfg.zoneRedundancy}
			log.V(1).Info("Including zone redundancy in layout update", "zoneRedundancy", cfg.zoneRedundancy)
		}

		if err := garageClient.UpdateClusterLayoutWithParams(ctx, layoutReq); err != nil {
			return fmt.Errorf("failed to update cluster layout: %w", err)
		}
		layout, err = garageClient.GetClusterLayout(ctx)
		if err != nil {
			return fmt.Errorf("failed to get updated layout: %w", err)
		}
	}

	if len(layout.StagedRoleChanges) == 0 {
		log.V(1).Info("No staged layout changes to apply")
		return nil
	}

	totalNodesAfterApply := countTotalNodesAfterApply(layout)

	// Check replication factor requirements
	// Skip this check if:
	// 1. remoteClusters is configured (federation will bring in additional nodes)
	// 2. force-layout-apply annotation is set (manual override)
	// This prevents the multi-cluster deadlock where each cluster waits for
	// replication factor nodes but can't federate because layout isn't applied
	if cfg.replicationFactor > 0 && totalNodesAfterApply < cfg.replicationFactor &&
		!cfg.hasRemoteClusters && !cfg.forceLayoutApply {
		log.Info("Waiting for more nodes before applying layout",
			"currentNodes", totalNodesAfterApply,
			"replicationFactor", cfg.replicationFactor,
			"stagedCount", len(layout.StagedRoleChanges))
		return nil
	}
	if cfg.hasRemoteClusters && totalNodesAfterApply < cfg.replicationFactor {
		log.Info("Applying layout despite insufficient nodes (remoteClusters configured, federation will bring more)",
			"currentNodes", totalNodesAfterApply,
			"replicationFactor", cfg.replicationFactor)
	}

	// Apply staged changes
	log.Info("Applying staged layout changes", "stagedCount", len(layout.StagedRoleChanges), "totalNodes", totalNodesAfterApply, "currentVersion", layout.Version)
	newVersion := layout.Version + 1
	if err := garageClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if garage.IsConflict(err) {
			log.Info("Layout version conflict, requeueing to retry", "attemptedVersion", newVersion)
			return fmt.Errorf("layout version conflict (version %d): %w", newVersion, err)
		}
		return fmt.Errorf("failed to apply cluster layout: %w", err)
	}
	log.Info("Applied cluster layout", "version", newVersion)
	return nil
}

// bootstrapCluster handles initial cluster formation by connecting nodes via the
// Admin API and, for clusters whose layout the cluster controller owns
// (gateway-only and Auto-mode pre-#190), assigning new nodes to the layout.
//
// Scope:
//   - Reconnect half (discover pods, call ConnectClusterNodes when peers are
//     down) runs for every Auto-mode cluster including storage-tier. This
//     gives us a runtime nudge after pod restarts when the on-disk peer_list
//     cache has stale IPs and bootstrap_peers can't reach known nodes yet.
//   - Layout-assignment half runs only when the cluster controller still owns
//     the layout — i.e. NOT for storage-tier clusters, which now have per-node
//     GarageNode reconcilers managing their own layout entries.
func (r *GarageClusterReconciler) bootstrapCluster(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		log.V(1).Info("Admin API not configured, skipping bootstrap")
		return nil
	}

	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get admin token: %w", err)
	}
	if adminToken == "" {
		return nil
	}

	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForCluster(cluster)),
	); err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	var runningPods []corev1.Pod
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			runningPods = append(runningPods, pod)
		}
	}

	if len(runningPods) == 0 {
		log.V(1).Info("No running pods yet, skipping bootstrap")
		return nil
	}

	adminPort := getAdminPort(cluster)
	rpcPort := getRPCPort(cluster)

	nodes := discoverNodes(ctx, runningPods, adminToken, adminPort)
	if len(nodes) == 0 {
		log.V(1).Info("No nodes discovered yet from running pods")
		return nil
	}

	log.Info("Discovered garage nodes", "count", len(nodes))

	// If some running pods couldn't be identified yet (still starting up),
	// skip stale node detection. Removing layout entries for pods whose node
	// IDs we can't yet resolve would wrongly destroy the cluster layout.
	skipStale := len(nodes) < len(runningPods)
	if skipStale {
		log.Info("Some pods not yet identified — skipping stale node detection to avoid premature layout removals",
			"identified", len(nodes), "running", len(runningPods))
	}

	bootstrapClient := findReachableClient(ctx, nodes, adminToken, adminPort)
	if bootstrapClient == nil {
		return fmt.Errorf("no reachable admin endpoint found")
	}

	// Check cluster health - if all nodes are already connected, skip connect step
	health, err := bootstrapClient.GetClusterHealth(ctx)
	if err != nil {
		log.V(1).Info("Failed to get cluster health during bootstrap", "error", err)
	}

	// Run connectNodes if cluster is unhealthy or not all nodes are connected.
	// We also reconnect when health status is "degraded" because a pod restart
	// may have changed its IP, and even if connectedNodes == len(nodes),
	// Garage might still be trying to reach the old IP addresses.
	// For gateway clusters, skip the health-status reconnect trigger: gateways may
	// permanently show "unavailable" (no data stored) and that's expected. Only
	// reconnect when a pod is actually disconnected (connectedNodes < expected).
	var connectedNodes int
	var healthStatus string
	if health != nil {
		connectedNodes = health.ConnectedNodes
		healthStatus = health.Status
	}
	needsReconnect := health == nil || connectedNodes < len(nodes) || (!cluster.HasGatewayTier() && healthStatus != healthStatusHealthy)
	if needsReconnect {
		log.Info("Cluster needs node reconnection", "connected", connectedNodes, "expected", len(nodes), "status", healthStatus)
		connectNodes(ctx, nodes, adminToken, adminPort, rpcPort)
	}

	// Storage-tier clusters delegate layout management to the per-GarageNode
	// reconciler — adding storage pods to the layout here would race with that
	// controller (and overwrite per-node zone/tag overrides). Stop after the
	// reconnect nudge.
	if cluster.HasStorageTier() {
		return nil
	}

	// Build layout config from cluster spec.
	// CapacityReservePercent lives on the storage tier; gateway-only clusters use 0.
	capacityReserve := 0
	if cluster.HasStorageTier() {
		capacityReserve = cluster.Spec.Storage.CapacityReservePercent
	}
	cfg := layoutConfig{
		zone:                   cluster.Spec.Zone,
		tags:                   cluster.Spec.DefaultNodeTags,
		capacityReservePercent: capacityReserve,
		replicationFactor:      3, // Default
		hasRemoteClusters:      len(cluster.Spec.RemoteClusters) > 0,
		// isGateway here reflects whether the layout entries this bootstrap is producing
		// should be tagged gateway-only. Storage-tier pods always advertise storage capacity;
		// pure edge-gateway clusters (no storage tier locally) advertise gateway-only.
		isGateway: !cluster.HasStorageTier(),
		// Cluster name and namespace are used to uniquely identify which nodes belong to this cluster.
		clusterName:    cluster.Name,
		namespace:      cluster.Namespace,
		zoneRedundancy: buildZoneRedundancy(cluster.Spec.Replication),
	}
	if cluster.Spec.Replication != nil && cluster.Spec.Replication.Factor > 0 {
		cfg.replicationFactor = cluster.Spec.Replication.Factor
	}
	// Check for force-layout-apply annotation
	if cluster.Annotations != nil {
		if val, ok := cluster.Annotations[garagev1beta1.AnnotationForceLayoutApply]; ok && val == annotationTrue {
			cfg.forceLayoutApply = true
		}
	}
	cfg.skipStaleDetection = skipStale

	// Calculate capacity from storage config
	cfg.capacity = r.calculateNodeCapacity(cluster)

	// For gateway clusters, use the storage cluster's Admin API for layout operations.
	// The layout is a shared global state, so we need to modify the storage cluster's layout,
	// not create a new one on the gateway. This applies whether connecting via clusterRef
	// (in-cluster) or adminApiEndpoint (external storage).
	layoutClient := bootstrapClient
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil {
		var storageClusterClient *garage.Client
		var err error
		if cluster.Spec.ConnectTo.ClusterRef != nil {
			storageClusterClient, err = r.getStorageClusterClient(ctx, cluster)
		} else if cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
			storageClusterClient, err = r.getExternalStorageClient(ctx, cluster)
		}
		if err != nil {
			// CRITICAL: Don't add gateway nodes to the gateway's own layout!
			// If we can't reach the storage cluster, skip layout management entirely.
			// The gateway will be added to the storage cluster's layout on the next reconcile
			// when the storage cluster becomes reachable.
			log.Info("Waiting for storage cluster to be reachable before adding gateway to layout", "error", err)
			return nil
		}
		if storageClusterClient != nil {
			layoutClient = storageClusterClient
			log.V(1).Info("Using storage cluster Admin API for layout operations")
		}
	}

	return assignNewNodesToLayout(ctx, layoutClient, nodes, cfg)
}

// calculateNodeCapacity determines node capacity from cluster storage config.
// For EmptyDir volumes, uses the specified size limit or defaults to 10GB.
// For PVC volumes, uses the PVC size request.
func (r *GarageClusterReconciler) calculateNodeCapacity(cluster *garagev1beta2.GarageCluster) uint64 {
	// Default to 10GB if no storage config (also used for EmptyDir without size limit)
	const defaultCapacity uint64 = 10 * 1024 * 1024 * 1024

	if !cluster.HasStorageTier() {
		return defaultCapacity
	}

	if cluster.Spec.Storage.Data != nil {
		// Use size if specified (works for both PVC storage request and EmptyDir sizeLimit)
		if cluster.Spec.Storage.Data.Size != nil {
			return uint64(cluster.Spec.Storage.Data.Size.Value())
		}
		// Sum capacity from data paths if using multiple paths (PVC mode only)
		if len(cluster.Spec.Storage.Data.Paths) > 0 {
			var total uint64
			for _, path := range cluster.Spec.Storage.Data.Paths {
				if path.Capacity != nil {
					total += uint64(path.Capacity.Value())
				} else if path.Volume != nil && path.Volume.Size != nil && !path.Volume.Size.IsZero() {
					total += uint64(path.Volume.Size.Value())
				}
			}
			if total > 0 {
				return total
			}
		}
	}

	return defaultCapacity
}

// getExternalStorageClient returns an Admin API client for an external storage cluster
// using the adminApiEndpoint and adminTokenSecretRef from connectTo config.
func (r *GarageClusterReconciler) getExternalStorageClient(ctx context.Context, cluster *garagev1beta2.GarageCluster) (*garage.Client, error) {
	if cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.AdminAPIEndpoint == "" {
		return nil, fmt.Errorf("no adminApiEndpoint configured")
	}

	if cluster.Spec.ConnectTo.AdminTokenSecretRef == nil {
		return nil, fmt.Errorf("adminTokenSecretRef is required when using adminApiEndpoint")
	}

	secret := &corev1.Secret{}
	secretRef := cluster.Spec.ConnectTo.AdminTokenSecretRef
	if err := r.Get(ctx, types.NamespacedName{Name: secretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get external admin token secret: %w", err)
	}
	key := secretRef.Key
	if key == "" {
		key = DefaultAdminTokenKey
	}
	adminToken := string(secret.Data[key])
	if adminToken == "" {
		return nil, fmt.Errorf("external admin token secret %s has empty %s", secretRef.Name, key)
	}

	client := garage.NewClient(cluster.Spec.ConnectTo.AdminAPIEndpoint, adminToken)

	if _, err := client.GetClusterStatus(ctx); err != nil {
		return nil, fmt.Errorf("external storage cluster not reachable (will retry): %w", err)
	}

	return client, nil
}

// getStorageClusterClient returns an Admin API client for the storage cluster
// that this gateway cluster is connected to. It verifies connectivity before returning.
func (r *GarageClusterReconciler) getStorageClusterClient(ctx context.Context, cluster *garagev1beta2.GarageCluster) (*garage.Client, error) {
	if cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.ClusterRef == nil {
		return nil, fmt.Errorf("no clusterRef configured")
	}

	// Get the storage cluster
	storageCluster := &garagev1beta2.GarageCluster{}
	storageClusterName := types.NamespacedName{
		Name:      cluster.Spec.ConnectTo.ClusterRef.Name,
		Namespace: cluster.Spec.ConnectTo.ClusterRef.Namespace,
	}
	if storageClusterName.Namespace == "" {
		storageClusterName.Namespace = cluster.Namespace
	}

	if err := r.Get(ctx, storageClusterName, storageCluster); err != nil {
		return nil, fmt.Errorf("failed to get storage cluster: %w", err)
	}

	// Get admin token for the storage cluster
	adminToken, err := r.getAdminToken(ctx, storageCluster)
	if err != nil || adminToken == "" {
		return nil, fmt.Errorf("failed to get storage cluster admin token: %w", err)
	}

	// Build endpoint for storage cluster's admin API
	adminPort := getAdminPort(storageCluster)
	endpoint := "http://" + svcFQDN(storageCluster.Name, storageCluster.Namespace, adminPort, r.ClusterDomain)

	client := garage.NewClient(endpoint, adminToken)

	// Verify the client can actually reach the storage cluster.
	// This prevents adding gateway nodes to an isolated layout when the storage cluster isn't ready.
	// This is a transient condition - the gateway will be added on the next reconcile when
	// the storage cluster becomes reachable.
	if _, err := client.GetClusterStatus(ctx); err != nil {
		return nil, fmt.Errorf("storage cluster not reachable (will retry): %w", err)
	}

	return client, nil
}

// reconcileGatewayConnection connects a gateway cluster to its storage cluster.
// It discovers the storage cluster's nodes and connects the gateway nodes to them.
// Errors are logged but not returned to avoid blocking reconciliation.
func (r *GarageClusterReconciler) reconcileGatewayConnection(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)

	if !cluster.HasGatewayTier() || cluster.Spec.ConnectTo == nil {
		return
	}

	// Get the gateway cluster's admin client
	gatewayAdminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || gatewayAdminToken == "" {
		log.Info("Gateway connectTo requires spec.admin.adminTokenSecretRef — connection skipped until configured",
			"gateway", cluster.Name)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonAdminTokenMissing,
			Message:            "spec.admin.adminTokenSecretRef is required for gateway connectTo; the operator needs admin API access to issue ConnectNode commands",
			ObservedGeneration: cluster.Generation,
		})
		return
	}

	adminPort := getAdminPort(cluster)

	// Find a reachable gateway pod to use as the client
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForCluster(cluster)),
	); err != nil {
		log.V(1).Info("Failed to list gateway pods", "error", err)
		return
	}

	var gatewayClient *garage.Client
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			endpoint := adminEndpoint(pod.Status.PodIP, adminPort)
			testClient := garage.NewClient(endpoint, gatewayAdminToken)
			if _, err := testClient.GetClusterStatus(ctx); err == nil {
				gatewayClient = testClient
				break
			}
		}
	}

	if gatewayClient == nil {
		log.V(1).Info("No reachable gateway pods for connection")
		return
	}

	// Connect based on configuration
	if cluster.Spec.ConnectTo.ClusterRef != nil {
		r.connectGatewayToClusterRef(ctx, cluster, gatewayClient)
	} else if len(cluster.Spec.ConnectTo.BootstrapPeers) > 0 {
		// Connect using bootstrap peers directly (format: nodeId@address:port)
		for _, peer := range cluster.Spec.ConnectTo.BootstrapPeers {
			parts := strings.SplitN(peer, "@", 2)
			if len(parts) != 2 {
				log.V(1).Info("Invalid bootstrap peer format", "peer", peer)
				continue
			}
			nodeID := parts[0]
			address := parts[1]
			if _, err := gatewayClient.ConnectNode(ctx, nodeID, address); err != nil {
				log.V(1).Info("Failed to connect to bootstrap peer", "peer", peer, "error", err)
			} else {
				log.V(1).Info("Connected to bootstrap peer", "peer", peer)
			}
		}
	} else if cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		// When the gateway is already connected, do a lightweight isUp check before
		// issuing ConnectNode calls. Garage marks peers Abandoned after 10 retries and
		// never retries again, so the operator must rescue dead connections — but we
		// only need to act when something is actually down.
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionGatewayConnected)
		if cond != nil && cond.Status == metav1.ConditionTrue {
			if r.isExternalGatewayConnected(ctx, cluster, gatewayClient) {
				return
			}
			log.Info("External gateway connection degraded, re-establishing", "endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint)
		}
		r.connectGatewayToExternalCluster(ctx, cluster, gatewayClient)
	}
}

// isExternalGatewayConnected checks whether all gateway nodes appear as isUp in the
// external cluster's view. Returns false on any API error or if any node is offline,
// which triggers a full reconnect via connectGatewayToExternalCluster.
func (r *GarageClusterReconciler) isExternalGatewayConnected(ctx context.Context, cluster *garagev1beta2.GarageCluster, gatewayClient *garage.Client) bool {
	externalClient, err := r.getExternalStorageClient(ctx, cluster)
	if err != nil {
		return false
	}
	gatewayStatus, err := gatewayClient.GetClusterStatus(ctx)
	if err != nil || len(gatewayStatus.Nodes) == 0 {
		return false
	}
	externalStatus, err := externalClient.GetClusterStatus(ctx)
	if err != nil {
		return false
	}
	upInExternal := make(map[string]bool, len(externalStatus.Nodes))
	for _, n := range externalStatus.Nodes {
		if n.IsUp {
			upInExternal[n.ID] = true
		}
	}
	for _, n := range gatewayStatus.Nodes {
		if !upInExternal[n.ID] {
			return false
		}
	}
	return true
}

// connectGatewayToClusterRef connects a gateway to a storage cluster referenced by clusterRef.
// It establishes bidirectional connectivity: gateway → storage AND storage → gateway.
// This is important when gateway pods restart with new IPs - the storage cluster needs
// to learn the gateway's new address to re-establish the connection.
func (r *GarageClusterReconciler) connectGatewayToClusterRef(ctx context.Context, cluster *garagev1beta2.GarageCluster, gatewayClient *garage.Client) {
	log := logf.FromContext(ctx)

	storageCluster := &garagev1beta2.GarageCluster{}
	storageNN := types.NamespacedName{
		Name:      cluster.Spec.ConnectTo.ClusterRef.Name,
		Namespace: cluster.Namespace,
	}
	if cluster.Spec.ConnectTo.ClusterRef.Namespace != "" {
		storageNN.Namespace = cluster.Spec.ConnectTo.ClusterRef.Namespace
	}

	if err := r.Get(ctx, storageNN, storageCluster); err != nil {
		log.V(1).Info("Failed to get storage cluster", "name", storageNN.Name, "error", err)
		return
	}

	// Get storage cluster's admin client
	storageAdminToken, err := r.getAdminToken(ctx, storageCluster)
	if err != nil || storageAdminToken == "" {
		log.V(1).Info("Storage cluster admin token not available")
		return
	}

	storageAdminPort := getAdminPort(storageCluster)

	// Find a reachable storage pod
	storagePods := &corev1.PodList{}
	if err := r.List(ctx, storagePods,
		client.InNamespace(storageCluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForCluster(storageCluster)),
	); err != nil {
		log.V(1).Info("Failed to list storage pods", "error", err)
		return
	}

	var storageClient *garage.Client
	for _, pod := range storagePods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			endpoint := adminEndpoint(pod.Status.PodIP, storageAdminPort)
			testClient := garage.NewClient(endpoint, storageAdminToken)
			if _, err := testClient.GetClusterStatus(ctx); err == nil {
				storageClient = testClient
				break
			}
		}
	}

	if storageClient == nil {
		log.V(1).Info("No reachable storage pods for connection")
		return
	}

	// Get storage cluster status to discover nodes
	storageStatus, err := storageClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Failed to get storage cluster status", "error", err)
		return
	}

	// Connect gateway to each storage node (gateway → storage)
	connectedToStorage := 0
	for _, node := range storageStatus.Nodes {
		if node.Address != nil && *node.Address != "" {
			if _, err := gatewayClient.ConnectNode(ctx, node.ID, *node.Address); err != nil {
				log.V(1).Info("Failed to connect gateway to storage node", "nodeID", node.ID[:16]+"...", "address", *node.Address, "error", err)
			} else {
				connectedToStorage++
			}
		}
	}

	// Get gateway cluster status to discover gateway nodes
	gatewayStatus, err := gatewayClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Failed to get gateway cluster status", "error", err)
		// Still log partial success if we connected gateway → storage
		if connectedToStorage > 0 {
			log.Info("Gateway connected to storage cluster (one-way)", "storageCluster", storageNN.Name, "nodesConnected", connectedToStorage)
		}
		return
	}

	// Connect storage to each gateway node (storage → gateway)
	// This ensures bidirectional connectivity, especially after gateway pod restarts
	// where the gateway has a new IP that the storage cluster doesn't know about.
	connectedToGateway := 0
	for _, node := range gatewayStatus.Nodes {
		if node.Address != nil && *node.Address != "" {
			if _, err := storageClient.ConnectNode(ctx, node.ID, *node.Address); err != nil {
				log.V(1).Info("Failed to connect storage to gateway node", "nodeID", node.ID[:16]+"...", "address", *node.Address, "error", err)
			} else {
				connectedToGateway++
			}
		}
	}

	if connectedToStorage > 0 || connectedToGateway > 0 {
		log.Info("Gateway-storage bidirectional connection established",
			"storageCluster", storageNN.Name,
			"gatewayToStorage", connectedToStorage,
			"storageToGateway", connectedToGateway)
	}
}

// deriveGatewayExternalAddr returns the externally-routable RPC address for this gateway cluster
// as known to the operator (from publicEndpoint service status or nodePort config).
// Returns empty when the address cannot be determined — the caller should then trust whatever
// Garage itself reports. When network.rpcPublicAddr is set, Garage already advertises the correct
// address via HelloMessage, so no override is needed.
func (r *GarageClusterReconciler) deriveGatewayExternalAddr(ctx context.Context, cluster *garagev1beta2.GarageCluster) string {
	if cluster.Spec.Network.RPCPublicAddr != "" {
		// Garage advertises rpcPublicAddr via HelloMessage to peers, but GetClusterStatus
		// returns an empty address for the local node itself. Return it directly so the
		// operator can pass it to the external cluster's ConnectNode call.
		return cluster.Spec.Network.RPCPublicAddr
	}
	if cluster.Spec.PublicEndpoint == nil {
		return ""
	}

	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	switch cluster.Spec.PublicEndpoint.Type {
	case publicEndpointTypeLoadBalancer:
		if cluster.Spec.PublicEndpoint.LoadBalancer != nil && cluster.Spec.PublicEndpoint.LoadBalancer.PerNode {
			return r.loadBalancerServiceAddr(ctx, cluster.Namespace, cluster.Name+"-0-rpc", rpcPort)
		}
		return r.loadBalancerServiceAddr(ctx, cluster.Namespace, cluster.Name+"-rpc", rpcPort)
	case publicEndpointTypeNodePort:
		if ep := cluster.Spec.PublicEndpoint.NodePort; ep != nil && len(ep.ExternalAddresses) > 0 {
			basePort := ep.BasePort
			if basePort == 0 {
				basePort = 30901
			}
			return fmt.Sprintf("%s:%d", ep.ExternalAddresses[0], basePort)
		}
	}

	return ""
}

func (r *GarageClusterReconciler) deriveGatewayExternalAddrForNode(ctx context.Context, cluster *garagev1beta2.GarageCluster, node garage.NodeInfo) string {
	if cluster.Spec.Network.RPCPublicAddr != "" {
		return cluster.Spec.Network.RPCPublicAddr
	}
	if cluster.Spec.PublicEndpoint == nil ||
		cluster.Spec.PublicEndpoint.Type != publicEndpointTypeLoadBalancer ||
		cluster.Spec.PublicEndpoint.LoadBalancer == nil ||
		!cluster.Spec.PublicEndpoint.LoadBalancer.PerNode {
		return r.deriveGatewayExternalAddr(ctx, cluster)
	}

	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	if node.Hostname != nil && *node.Hostname != "" {
		return r.loadBalancerServiceAddr(ctx, cluster.Namespace, *node.Hostname+"-rpc", rpcPort)
	}
	return r.loadBalancerServiceAddr(ctx, cluster.Namespace, cluster.Name+"-0-rpc", rpcPort)
}

// externalRPCFallbackAddr returns "<host>:<rpcPort>" derived from the cluster's
// connectTo.adminApiEndpoint. Used when an external storage node advertises an
// unrouteable rpc_public_addr (unspecified bind wildcard, docker bridge IP, etc.).
// Returns empty when adminApiEndpoint is not configured or unparseable.
func (r *GarageClusterReconciler) externalRPCFallbackAddr(cluster *garagev1beta2.GarageCluster) string {
	if cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.AdminAPIEndpoint == "" {
		return ""
	}
	u, err := url.Parse(cluster.Spec.ConnectTo.AdminAPIEndpoint)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}
	return rpcAddr(u.Hostname(), rpcPort)
}

func (r *GarageClusterReconciler) loadBalancerServiceAddr(ctx context.Context, namespace, name string, rpcPort int32) string {
	svc := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, svc); err != nil {
		return ""
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		addr := ing.IP
		if addr == "" {
			addr = ing.Hostname
		}
		if addr != "" {
			return fmt.Sprintf("%s:%d", addr, rpcPort)
		}
	}
	return ""
}

// connectGatewayToExternalCluster connects a gateway to an external storage cluster via Admin API endpoint.
// Bidirectional: gateway → external nodes AND external cluster → gateway nodes.
func (r *GarageClusterReconciler) connectGatewayToExternalCluster(ctx context.Context, cluster *garagev1beta2.GarageCluster, gatewayClient *garage.Client) {
	log := logf.FromContext(ctx)

	externalClient, err := r.getExternalStorageClient(ctx, cluster)
	if err != nil {
		log.V(1).Info("Failed to connect to external storage cluster", "error", err)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonAdminUnreachable,
			Message:            fmt.Sprintf("External cluster admin API unreachable: %v", err),
			ObservedGeneration: cluster.Generation,
		})
		return
	}

	// Get external cluster status for node discovery
	externalStatus, err := externalClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Failed to get external cluster status", "endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint, "error", err)
		return
	}

	// Connect gateway → each external node.
	// External nodes may advertise an unrouteable rpc_public_addr (unspecified bind
	// wildcard, docker bridge IP, etc.). When that happens, fall back to the host
	// from adminApiEndpoint with the configured RPC port — same defense as the
	// federation path in connectToRemoteCluster.
	externalFallback := r.externalRPCFallbackAddr(cluster)
	connectedToExternal := 0
	for _, node := range externalStatus.Nodes {
		addr := ""
		if node.Address != nil {
			addr = *node.Address
		}
		if addr == "" || isLikelyInternalAddr(addr) {
			if externalFallback == "" {
				if addr == "" {
					continue
				}
				log.V(1).Info("External node advertises unrouteable address and no adminApiEndpoint fallback available",
					"nodeID", node.ID[:16]+"...", "address", addr)
			} else {
				if addr != "" {
					log.V(1).Info("External node advertises unrouteable address; using adminApiEndpoint host",
						"nodeID", node.ID[:16]+"...", "reported", addr, "fallback", externalFallback)
				}
				addr = externalFallback
			}
		}
		if _, err := gatewayClient.ConnectNode(ctx, node.ID, addr); err != nil {
			log.V(1).Info("Failed to connect gateway to external node", "nodeID", node.ID[:16]+"...", "address", addr, "error", err)
		} else {
			connectedToExternal++
		}
	}

	// Connect external cluster → each gateway node (reverse direction).
	// Without this, the external cluster never learns the gateway's address and
	// shows it as offline even after the gateway successfully reaches out.
	gatewayStatus, err := gatewayClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Failed to get gateway cluster status for reverse connection", "error", err)
		if connectedToExternal > 0 {
			log.Info("Gateway connected to external storage cluster (one-way)", "endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint, "nodesConnected", connectedToExternal)
		}
		return
	}

	connectedToGateway := 0
	for _, node := range gatewayStatus.Nodes {
		// Derive the operator-known external address for this gateway node. Used to
		// override internal (pod/service) IPs or an empty self-address from Garage.
		overrideAddr := r.deriveGatewayExternalAddrForNode(ctx, cluster, node)

		addr := ""
		if node.Address != nil {
			addr = *node.Address
		}

		if isLikelyInternalAddr(addr) {
			if overrideAddr != "" {
				log.V(1).Info("Gateway node has internal address; using operator-derived external address",
					"nodeID", node.ID[:16]+"...", "reported", addr, "override", overrideAddr)
				addr = overrideAddr
			} else {
				log.V(1).Info("Gateway node address is internal and no publicEndpoint configured; skipping reverse connect",
					"nodeID", node.ID[:16]+"...", "address", addr)
				continue
			}
		} else if addr == "" {
			if overrideAddr != "" {
				addr = overrideAddr
			} else {
				continue
			}
		}

		if _, err := externalClient.ConnectNode(ctx, node.ID, addr); err != nil {
			log.V(1).Info("Failed to connect external cluster to gateway node", "nodeID", node.ID[:16]+"...", "address", addr, "error", err)
		} else {
			connectedToGateway++
		}
	}

	if connectedToExternal > 0 || connectedToGateway > 0 {
		log.Info("Gateway-external bidirectional connection established",
			"endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint,
			"gatewayToExternal", connectedToExternal,
			"externalToGateway", connectedToGateway)
	}

	switch {
	case connectedToGateway > 0:
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonGatewayConnected,
			Message:            fmt.Sprintf("Bidirectional connection established (%d gateway→external, %d external→gateway)", connectedToExternal, connectedToGateway),
			ObservedGeneration: cluster.Generation,
		})
	case connectedToExternal > 0:
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayPartiallyConnected,
			Message:            "Gateway can reach external cluster but external cluster cannot reach gateway — check publicEndpoint or network.rpcPublicAddr",
			ObservedGeneration: cluster.Generation,
		})
	default:
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayNodesOffline,
			Message:            "No nodes connected between gateway and external cluster",
			ObservedGeneration: cluster.Generation,
		})
	}
}

// reconcileFederation connects this cluster to remote Garage clusters.
// It queries remote Admin APIs to discover node IDs and connects them.
// Errors are logged but not returned to avoid blocking reconciliation.
func (r *GarageClusterReconciler) reconcileFederation(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)

	if len(cluster.Spec.RemoteClusters) == 0 {
		return
	}

	// Get admin token
	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		log.V(1).Info("Admin token not available, skipping federation")
		return
	}

	adminPort := getAdminPort(cluster)

	// Find a reachable local pod to use as the client
	// We use pod IPs directly because Service won't route to unready pods
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForCluster(cluster)),
	); err != nil {
		log.V(1).Info("Failed to list pods for federation", "error", err)
		return
	}

	var localClient *garage.Client
	var localStatus *garage.ClusterStatus
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			endpoint := adminEndpoint(pod.Status.PodIP, adminPort)
			testClient := garage.NewClient(endpoint, adminToken)
			// Short timeout per pod: if the admin API is hanging due to RPC lock
			// contention (broken mesh), skip this pod and try the next one.
			podCtx, podCancel := context.WithTimeout(ctx, 5*time.Second)
			if status, err := testClient.GetClusterStatus(podCtx); err == nil {
				podCancel()
				localClient = testClient
				localStatus = status
				break
			}
			podCancel()
		}
	}

	if localClient == nil {
		log.V(1).Info("No reachable local pods for federation")
		return
	}

	// Process each remote cluster - don't require local cluster to be healthy
	// Federation is needed to BECOME healthy in multi-cluster setups
	for _, remote := range cluster.Spec.RemoteClusters {
		if err := r.connectToRemoteCluster(ctx, cluster, localClient, localStatus, remote); err != nil {
			log.V(1).Info("Failed to connect to remote cluster", "name", remote.Name, "error", err)
			// Continue with other remotes
		}
	}
}

// connectToRemoteCluster discovers nodes from a remote cluster and connects them.
// It uses localStatus to find remote node IDs (by zone match) without querying the
// remote API, which avoids deadlocking when the RPC mesh is broken. Falls back to
// querying the remote with a short timeout only during bootstrap (no remote nodes
// in local layout yet).
func (r *GarageClusterReconciler) connectToRemoteCluster(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	localClient *garage.Client,
	localStatus *garage.ClusterStatus,
	remote garagev1beta2.RemoteClusterConfig,
) error {
	log := logf.FromContext(ctx)

	// Skip self-connection: if remote zone matches local zone, this is likely
	// the same cluster listed in remoteClusters (common in templated deployments)
	if remote.Zone == cluster.Spec.Zone {
		log.Info("Skipping self-connection (remote zone matches local zone)", "zone", remote.Zone)
		return nil
	}

	// Get remote admin token
	remoteToken, err := r.getRemoteAdminToken(ctx, cluster, remote)
	if err != nil {
		return fmt.Errorf("failed to get remote admin token: %w", err)
	}

	// Determine remote endpoint
	remoteEndpoint := remote.Connection.AdminAPIEndpoint
	if remoteEndpoint == "" {
		log.V(1).Info("No admin API endpoint configured for remote cluster", "name", remote.Name)
		return nil
	}

	log.Info("Connecting to remote cluster", "name", remote.Name, "endpoint", remoteEndpoint)

	// Extract hostname from admin endpoint to construct RPC address
	// Admin endpoint format: http://hostname:port or https://hostname:port
	// We use the same hostname for RPC since Tailscale routes to the same service
	var remoteRPCHost string
	if u, err := url.Parse(remoteEndpoint); err == nil && u.Host != "" {
		host := u.Hostname() // Strips port
		remoteRPCHost = host
	}

	// Try local status first: nodes whose zone matches the remote zone are remote nodes.
	// This avoids calling remoteClient.GetClusterStatus which deadlocks when the RPC
	// mesh is broken (the whole reason we need to call ConnectClusterNodes).
	var remoteNodes []garage.NodeInfo
	for _, node := range localStatus.Nodes {
		if node.Role != nil && node.Role.Zone == remote.Zone {
			remoteNodes = append(remoteNodes, node)
		}
	}

	// Skip ConnectNode only in the non-bootstrap path: when localStatus already knows
	// about all remote nodes AND they're all up, the RPC connection is established.
	// In the bootstrap path (remoteNodes empty) we must always connect.
	needsConnect := len(remoteNodes) == 0
	for _, node := range remoteNodes {
		if !node.IsUp {
			needsConnect = true
			break
		}
	}

	var remoteStatus *garage.ClusterStatus
	var remoteClient *garage.Client

	if len(remoteNodes) == 0 {
		// Bootstrap case: no remote nodes in local layout yet, must query remote.
		// Use a short timeout so we don't block forever if remote is unreachable.
		remoteClient = garage.NewClient(remoteEndpoint, remoteToken)

		// Quick reachability pre-check: GetClusterHealth is a lightweight endpoint
		// that responds fast under normal conditions. With a short timeout it acts
		// as a network-level probe — if the remote is down (connection refused) we
		// fail instantly instead of waiting for the longer GetClusterStatus timeout.
		healthCtx, healthCancel := context.WithTimeout(ctx, 3*time.Second)
		defer healthCancel()
		if _, err := remoteClient.GetClusterHealth(healthCtx); err != nil {
			return fmt.Errorf("remote cluster unreachable (health check failed): %w", err)
		}

		shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		remoteStatus, err = remoteClient.GetClusterStatus(shortCtx)
		if err != nil {
			return fmt.Errorf("no remote nodes in local status and remote unreachable: %w", err)
		}
		remoteNodes = remoteStatus.Nodes
	}

	// Determine RPC port from cluster spec or use default
	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	// Connect to each node in the remote cluster unless all are already up.
	// Note: We connect to ALL nodes, including those without a role.
	// During bootstrap, nodes may not be in the layout yet but we still
	// need to establish connections so they can be discovered and added.
	connectedCount := 0
	if needsConnect {
		for _, node := range remoteNodes {
			// IMPORTANT: We use the remote cluster's hostname (from adminApiEndpoint)
			// instead of the node's advertised address. This is because:
			// 1. Nodes may advertise their local proxy IP which isn't routable cross-cluster
			// 2. The admin endpoint hostname is the Tailscale service that routes to all nodes
			// 3. Tailscale handles the actual routing to the correct pod
			var addr string
			if remoteRPCHost != "" {
				addr = rpcAddr(remoteRPCHost, rpcPort)
			} else if node.Address != nil && *node.Address != "" {
				addr = *node.Address
			} else {
				log.V(1).Info("Remote node has no address", "nodeID", node.ID[:16]+"...")
				continue
			}

			// Use a short per-call timeout so a stale/unreachable node ID (e.g. after
			// metadata wipe) doesn't block the whole reconcile. Garage v2.2.0 had no TCP
			// connect timeout, making ConnectNode hang indefinitely on broken peers.
			connectCtx, connectCancel := context.WithTimeout(ctx, 5*time.Second)
			result, err := localClient.ConnectNode(connectCtx, node.ID, addr)
			connectCancel()
			if err != nil {
				log.V(1).Info("Failed to connect to remote node", "nodeID", node.ID[:16]+"...", "addr", addr, "error", err)
				continue
			}

			if result.Success {
				connectedCount++
				log.V(1).Info("Connected to remote node", "nodeID", node.ID[:16]+"...", "addr", addr)
			} else {
				errMsg := connectErrUnknown
				if result.Error != nil {
					errMsg = *result.Error
				}
				log.V(1).Info("Failed to connect to remote node", "nodeID", node.ID[:16]+"...", "addr", addr, "error", errMsg)
			}
		}
		if connectedCount > 0 {
			log.Info("Connected to remote cluster nodes", "name", remote.Name, "connected", connectedCount)
		}
	} else {
		log.V(1).Info("All remote nodes already up, skipping connect", "cluster", remote.Name)
	}

	// Per-pod cross-region gateway peering. The storage-tier connect loop above
	// uses ONE shared remote hostname (admin endpoint host) for every node,
	// which means a Tailscale-fronted multi-pod gateway tier only ever lands
	// one of N pods. Without all gateway pods being reachable, FullReplication
	// quorum reads/writes for key_table / bucket_table / admin_token_table
	// time out and operations like GetKeyInfo, DeleteKey, and cluster-wide
	// key resync fail.
	//
	// Requires remote.Connection.GatewayRPCEndpointTemplate to be set; the
	// template substitutes {ordinal} with each remote gateway pod's ordinal
	// parsed from its pod-name layout tag (e.g. "garage-gateway-0").
	if tmpl := remote.Connection.GatewayRPCEndpointTemplate; tmpl != "" {
		r.connectRemoteGatewayPods(ctx, localClient, localStatus, remote, tmpl)
	}

	// Add remote nodes to local layout for data replication (best-effort with timeout)
	if remoteClient == nil {
		remoteClient = garage.NewClient(remoteEndpoint, remoteToken)
	}
	layoutCtx, layoutCancel := context.WithTimeout(ctx, 5*time.Second)
	defer layoutCancel()
	if err := r.addRemoteNodesToLayout(layoutCtx, cluster, localClient, remoteClient, remoteStatus, localStatus, remote); err != nil {
		log.Error(err, "Failed to add remote nodes to layout", "cluster", remote.Name)
		// Don't return error - connection succeeded, layout update is best-effort
		// Will retry on next reconciliation
	}

	return nil
}

// connectRemoteGatewayPods peers the local cluster with each gateway pod in a
// remote region. The storage-tier connect loop only reaches one pod per
// Tailscale-fronted remote (because they share an admin hostname); this loop
// uses GatewayRPCEndpointTemplate to dial each remote gateway pod by its
// ordinal-stable external address.
//
// Iterates layout roles tagged tier:gateway in the remote zone, parses the
// ordinal from the pod-name tag, substitutes it into the template, and
// calls ConnectClusterNodes. Best-effort; errors are logged and skipped.
func (r *GarageClusterReconciler) connectRemoteGatewayPods(
	ctx context.Context,
	localClient *garage.Client,
	localStatus *garage.ClusterStatus,
	remote garagev1beta2.RemoteClusterConfig,
	template string,
) {
	if template == "" {
		return
	}
	log := logf.FromContext(ctx)
	if !strings.Contains(template, "{ordinal}") {
		log.Info("gatewayRpcEndpointTemplate missing {ordinal} placeholder — all remote gateway pods will share the same address",
			"remote", remote.Name, "template", template)
	}

	for _, node := range localStatus.Nodes {
		if node.Role == nil || node.Role.Zone != remote.Zone {
			continue
		}
		isGateway := false
		var podName string
		for _, tag := range node.Role.Tags {
			if tag == "tier:"+tierGateway {
				isGateway = true
			}
			if strings.HasPrefix(tag, "garage-gateway-") {
				podName = tag
			}
		}
		if !isGateway || podName == "" {
			continue
		}
		if node.IsUp {
			continue
		}
		ordinalStr := strings.TrimPrefix(podName, "garage-gateway-")
		if _, err := strconv.Atoi(ordinalStr); err != nil {
			log.V(1).Info("Skipping remote gateway with non-numeric ordinal", "podName", podName)
			continue
		}
		addr := strings.ReplaceAll(template, "{ordinal}", ordinalStr)

		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		result, err := localClient.ConnectNode(connectCtx, node.ID, addr)
		cancel()
		if err != nil {
			log.V(1).Info("Failed to connect remote gateway pod",
				"nodeID", node.ID[:16]+"...", "addr", addr, "error", err)
			continue
		}
		if !result.Success {
			errMsg := connectErrUnknown
			if result.Error != nil {
				errMsg = *result.Error
			}
			log.V(1).Info("ConnectNode returned failure for remote gateway pod",
				"nodeID", node.ID[:16]+"...", "addr", addr, "error", errMsg)
			continue
		}
		log.Info("Connected to remote gateway pod",
			"nodeID", node.ID[:16]+"...", "addr", addr, "podName", podName)
	}
}

// addRemoteNodesToLayout adds remote cluster nodes to the local cluster's layout.
// This ensures remote nodes participate in data replication with proper zone assignment.
// It also propagates the cluster's zone redundancy settings to ensure consistent layout parameters.
//
// The function handles the bootstrap race condition where remote nodes may not have committed
// roles yet (their controller hasn't applied the layout). In this case, it checks the remote
// cluster's staged role changes to find nodes that are about to be committed.
//
// When remoteStatus is nil (recovery case where the remote API is unreachable), it falls back
// to localStatus filtered by zone to identify remote nodes already known to the local cluster.
func (r *GarageClusterReconciler) addRemoteNodesToLayout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	localClient *garage.Client,
	remoteClient *garage.Client,
	remoteStatus *garage.ClusterStatus,
	localStatus *garage.ClusterStatus,
	remote garagev1beta2.RemoteClusterConfig,
) error {
	log := logf.FromContext(ctx)

	// Get local layout
	layout, err := localClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Build map of existing nodes (current + staged) in local layout
	existingNodes := make(map[string]bool)
	for _, role := range layout.Roles {
		existingNodes[role.ID] = true
	}
	for _, staged := range layout.StagedRoleChanges {
		existingNodes[staged.ID] = true
	}

	// Get remote layout to check for staged role changes (best-effort).
	// Only attempt this when we have a fresh remoteStatus, meaning the remote
	// API was reachable. When remoteStatus is nil we're in the recovery path
	// (using local status) and the remote API is likely hanging — skip to avoid
	// a wasted timeout on every reconciliation.
	var remoteLayout *garage.ClusterLayout
	if remoteStatus != nil && remoteClient != nil {
		remoteLayout, err = remoteClient.GetClusterLayout(ctx)
		if err != nil {
			log.V(1).Info("Failed to get remote layout, will use committed roles only", "error", err)
			remoteLayout = nil
		}
	}

	// Build map of staged roles in remote cluster for quick lookup
	remoteStagedRoles := make(map[string]*garage.NodeRoleChange)
	if remoteLayout != nil {
		for i := range remoteLayout.StagedRoleChanges {
			staged := &remoteLayout.StagedRoleChanges[i]
			if !staged.Remove {
				remoteStagedRoles[staged.ID] = staged
			}
		}
	}

	// Determine the set of remote nodes to process.
	// Prefer remoteStatus (queried from remote API) when available.
	// Fall back to localStatus filtered by zone (recovery path when remote is unreachable).
	var nodesToProcess []garage.NodeInfo
	if remoteStatus != nil {
		nodesToProcess = remoteStatus.Nodes
	} else {
		for _, node := range localStatus.Nodes {
			if node.Role != nil && node.Role.Zone == remote.Zone {
				nodesToProcess = append(nodesToProcess, node)
			}
		}
	}

	// Build role changes for missing remote nodes
	newRoles := make([]garage.NodeRoleChange, 0, len(nodesToProcess))
	for _, node := range nodesToProcess {
		if existingNodes[node.ID] {
			continue // Already in local layout
		}

		var role garage.NodeRoleChange

		if node.Role != nil {
			// Node has a committed role - use it
			role = garage.NodeRoleChange{
				ID:       node.ID,
				Zone:     remote.Zone,           // Use configured zone from CRD
				Tags:     []string{remote.Name}, // Tag with cluster name
				Capacity: node.Role.Capacity,    // nil = gateway, non-nil = storage
			}
		} else if stagedRole, ok := remoteStagedRoles[node.ID]; ok {
			// Node doesn't have a committed role but IS in staged changes
			// This handles the bootstrap race condition where remote controller
			// has staged nodes but hasn't applied the layout yet
			log.V(1).Info("Using staged role for remote node", "nodeId", node.ID[:16]+"...", "zone", remote.Zone)
			role = garage.NodeRoleChange{
				ID:       node.ID,
				Zone:     remote.Zone,           // Use configured zone from CRD
				Tags:     []string{remote.Name}, // Tag with cluster name
				Capacity: stagedRole.Capacity,   // Use capacity from staged role
			}
		} else {
			// Node has no committed or staged role - skip it
			// It will be picked up on the next reconciliation after the remote
			// controller stages/commits its local nodes
			log.V(1).Info("Skipping remote node without committed or staged role", "nodeId", node.ID[:16]+"...")
			continue
		}

		newRoles = append(newRoles, role)
	}

	if len(newRoles) == 0 {
		log.V(1).Info("All remote nodes already in layout", "cluster", remote.Name)
		return nil
	}

	// Stage changes with zone redundancy parameters from cluster spec
	log.Info("Adding remote nodes to layout", "cluster", remote.Name, "count", len(newRoles))

	// Build layout update request with zone redundancy if configured
	layoutReq := garage.UpdateClusterLayoutRequest{
		Roles: newRoles,
	}

	// Include zone redundancy from cluster spec for consistency
	if zr := buildZoneRedundancy(cluster.Spec.Replication); zr != nil {
		layoutReq.Parameters = &garage.LayoutParameters{ZoneRedundancy: zr}
		log.V(1).Info("Including zone redundancy in layout update", "zoneRedundancy", zr)
	}

	if err := localClient.UpdateClusterLayoutWithParams(ctx, layoutReq); err != nil {
		return fmt.Errorf("failed to stage remote nodes: %w", err)
	}

	// Re-fetch layout to get current version
	layout, err = localClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get updated layout: %w", err)
	}

	if len(layout.StagedRoleChanges) == 0 {
		return nil // Nothing to apply
	}

	// Apply layout
	newVersion := layout.Version + 1
	if err := localClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if garage.IsConflict(err) {
			log.Info("Layout version conflict, will retry on next reconciliation", "version", newVersion)
			return nil
		}
		return fmt.Errorf("failed to apply layout: %w", err)
	}

	log.Info("Applied federated layout", "cluster", remote.Name, "version", newVersion, "nodesAdded", len(newRoles))

	// After adding nodes, check for stale remote nodes that were removed from the remote cluster.
	// Only possible when we have a fresh remote status to compare against.
	if remoteStatus != nil {
		if err := r.removeStaleRemoteNodes(ctx, localClient, layout, remoteStatus, remote); err != nil {
			// Don't fail the reconcile for stale node cleanup - just log
			log.Error(err, "Failed to remove stale remote nodes", "cluster", remote.Name)
		}
	}

	return nil
}

// removeStaleRemoteNodes detects and removes nodes from the local layout that were
// previously added from a remote cluster but no longer exist in that remote cluster.
// This prevents orphaned remote nodes from causing stuck Draining layout versions.
func (r *GarageClusterReconciler) removeStaleRemoteNodes(
	ctx context.Context,
	localClient *garage.Client,
	layout *garage.ClusterLayout,
	remoteStatus *garage.ClusterStatus,
	remote garagev1beta2.RemoteClusterConfig,
) error {
	log := logf.FromContext(ctx)

	// Build set of node IDs that exist in remote cluster
	remoteNodeIDs := make(map[string]bool)
	for _, node := range remoteStatus.Nodes {
		remoteNodeIDs[node.ID] = true
	}

	// Find nodes in local layout that are tagged with remote cluster name but don't exist in remote
	var staleNodes []garage.NodeRoleChange
	for _, role := range layout.Roles {
		// Check if this node is tagged as belonging to the remote cluster
		isFromRemote := false
		for _, tag := range role.Tags {
			if tag == remote.Name {
				isFromRemote = true
				break
			}
		}

		if isFromRemote && !remoteNodeIDs[role.ID] {
			shortID := role.ID
			if len(shortID) > 16 {
				shortID = shortID[:16] + "..."
			}
			log.Info("Found stale remote node in layout (no longer exists in remote cluster)",
				"nodeID", shortID, "remoteCluster", remote.Name, "zone", role.Zone)
			staleNodes = append(staleNodes, garage.NodeRoleChange{
				ID:     role.ID,
				Remove: true,
			})
		}
	}

	if len(staleNodes) == 0 {
		return nil
	}

	// Stage removal of stale nodes
	if err := localClient.UpdateClusterLayout(ctx, staleNodes); err != nil {
		return fmt.Errorf("failed to stage stale node removal: %w", err)
	}

	// Re-fetch layout to get current version
	layout, err := localClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get updated layout: %w", err)
	}

	// Apply layout
	newVersion := layout.Version + 1
	if err := localClient.ApplyClusterLayout(ctx, newVersion); err != nil {
		if garage.IsConflict(err) {
			log.Info("Layout version conflict during stale node removal, will retry", "version", newVersion)
			return nil
		}
		if garage.IsReplicationConstraint(err) {
			log.Info("Cannot remove stale remote nodes: would violate replication constraints",
				"staleCount", len(staleNodes))
			return nil
		}
		return fmt.Errorf("failed to apply stale node removal: %w", err)
	}

	log.Info("Removed stale remote nodes from layout",
		"count", len(staleNodes), "remoteCluster", remote.Name, "version", newVersion)

	// After removing stale remote nodes, call skip-dead-nodes to prevent draining stalls.
	// Remote nodes are typically unreachable after removal, so they can't acknowledge sync.
	// Use allowMissingData=true since we've confirmed these nodes no longer exist in the remote cluster.
	skipReq := garage.SkipDeadNodesRequest{
		Version:          newVersion,
		AllowMissingData: true, // Safe - nodes confirmed removed from remote cluster
	}
	result, err := localClient.ClusterLayoutSkipDeadNodes(ctx, skipReq)
	if err != nil {
		if !garage.IsBadRequest(err) {
			log.Error(err, "Failed to skip dead remote nodes after removal")
		}
	} else if len(result.AckUpdated) > 0 || len(result.SyncUpdated) > 0 {
		log.Info("Skipped dead remote nodes to prevent draining stall",
			"ackUpdated", len(result.AckUpdated),
			"syncUpdated", len(result.SyncUpdated))
	}

	return nil
}

// getRemoteAdminToken retrieves the admin token for a remote cluster.
func (r *GarageClusterReconciler) getRemoteAdminToken(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	remote garagev1beta2.RemoteClusterConfig,
) (string, error) {
	// Use remote-specific token if configured
	if remote.Connection.AdminTokenSecretRef != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      remote.Connection.AdminTokenSecretRef.Name,
			Namespace: cluster.Namespace,
		}, secret); err != nil {
			return "", err
		}

		key := DefaultAdminTokenKey
		if remote.Connection.AdminTokenSecretRef.Key != "" {
			key = remote.Connection.AdminTokenSecretRef.Key
		}

		if secret.Data != nil {
			if tokenData, ok := secret.Data[key]; ok {
				return string(tokenData), nil
			}
		}
		return "", fmt.Errorf("admin token key %s not found in secret", key)
	}

	// Fall back to local admin token (for shared-secret setups)
	return r.getAdminToken(ctx, cluster)
}

// getAdminToken retrieves the admin token from the configured secret
func (r *GarageClusterReconciler) getAdminToken(ctx context.Context, cluster *garagev1beta2.GarageCluster) (string, error) {
	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return "", nil
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Admin.AdminTokenSecretRef.Name,
		Namespace: cluster.Namespace,
	}, secret); err != nil {
		return "", err
	}

	if secret.Data == nil {
		return "", nil
	}

	key := DefaultAdminTokenKey
	if cluster.Spec.Admin.AdminTokenSecretRef.Key != "" {
		key = cluster.Spec.Admin.AdminTokenSecretRef.Key
	}
	tokenData, ok := secret.Data[key]
	if !ok {
		return "", nil
	}
	return string(tokenData), nil
}

// Annotation keys for operational commands
const (
	AnnotationConnectNodes = "garage.rajsingh.info/connect-nodes"
)

// handleOperationalAnnotations processes annotations that trigger operational commands.
// These annotations are removed after processing to prevent re-execution.
func (r *GarageClusterReconciler) handleOperationalAnnotations(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	if cluster.Annotations == nil {
		return nil
	}

	// Handle connect-nodes annotation: "nodeId@addr:port,nodeId2@addr2:port2,..."
	if connectNodesVal, ok := cluster.Annotations[AnnotationConnectNodes]; ok && connectNodesVal != "" {
		if err := r.handleConnectNodes(ctx, cluster, connectNodesVal); err != nil {
			return err
		}

		// Remove annotation after processing
		delete(cluster.Annotations, AnnotationConnectNodes)
		if err := r.Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to remove connect-nodes annotation")
			return err
		}
		log.Info("Processed and removed connect-nodes annotation")
	}

	// Handle skip-dead-nodes annotation: marks dead nodes as synced to unblock draining versions
	if _, ok := cluster.Annotations[garagev1beta1.AnnotationSkipDeadNodes]; ok {
		if err := r.handleSkipDeadNodes(ctx, cluster); err != nil {
			return err
		}

		// Remove annotations after processing
		delete(cluster.Annotations, garagev1beta1.AnnotationSkipDeadNodes)
		delete(cluster.Annotations, garagev1beta1.AnnotationAllowMissingData)
		if err := r.Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to remove skip-dead-nodes annotation")
			return err
		}
		log.Info("Processed and removed skip-dead-nodes annotation")
	}

	// Build a Garage client if any API-calling annotations are set.
	needsClient := cluster.Annotations[garagev1beta1.AnnotationTriggerSnapshot] != "" ||
		cluster.Annotations[garagev1beta1.AnnotationTriggerRepair] != "" ||
		cluster.Annotations[garagev1beta1.AnnotationScrubCommand] != "" ||
		cluster.Annotations[garagev1beta1.AnnotationRevertLayout] != "" ||
		cluster.Annotations[garagev1beta1.AnnotationRetryBlockResync] != "" ||
		cluster.Annotations[garagev1beta1.AnnotationPurgeBlocks] != ""

	var garageClient *garage.Client
	if needsClient {
		adminToken, err := r.getAdminToken(ctx, cluster)
		if err != nil || adminToken == "" {
			return fmt.Errorf("admin token required for operational annotation: %w", err)
		}
		adminPort := getAdminPort(cluster)
		adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		garageClient = garage.NewClient(adminEndpoint, adminToken)
	}

	// recordOp updates status.lastOperation with the result of a triggered operation.
	// On failure the annotation is kept (caller returns the error to trigger a retry).
	// Uses UpdateStatusWithRetry so conflicts are retried and ResourceVersion stays current.
	recordOp := func(opType string, opErr error) {
		now := metav1.Now()
		apply := func() {
			cluster.Status.LastOperation = &garagev1beta2.LastOperationStatus{
				Type:        opType,
				TriggeredAt: &now,
				Succeeded:   opErr == nil,
			}
			if opErr != nil {
				cluster.Status.LastOperation.Error = opErr.Error()
			}
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
			log.Error(err, "Failed to update lastOperation status")
		}
	}

	var toDelete []string

	// trigger-snapshot: triggers metadata snapshot on all nodes. Value must be "true".
	if v, ok := cluster.Annotations[garagev1beta1.AnnotationTriggerSnapshot]; ok {
		if v != annotationTrue {
			recordOp("Snapshot", fmt.Errorf("invalid value %q (expected %q)", v, annotationTrue))
		} else if err := garageClient.CreateMetadataSnapshot(ctx, "*"); err != nil {
			recordOp("Snapshot", err)
			return fmt.Errorf("trigger-snapshot failed: %w", err)
		} else {
			log.Info("Metadata snapshot triggered on all nodes")
			recordOp("Snapshot", nil)
		}
		toDelete = append(toDelete, garagev1beta1.AnnotationTriggerSnapshot)
	}

	// trigger-repair: triggers a repair operation on all nodes.
	// Valid values: Tables, Blocks, Versions, MultipartUploads, BlockRefs, BlockRc,
	// Rebalance, Aliases, ClearResyncQueue. "Scrub" is rejected — use scrub-command.
	if repairType, ok := cluster.Annotations[garagev1beta1.AnnotationTriggerRepair]; ok {
		if repairType == garagev1beta1.RepairTypeScrub {
			recordOp("Repair:Scrub", fmt.Errorf("use scrub-command annotation instead"))
		} else if !validRepairTypes[repairType] {
			recordOp("Repair:"+repairType, fmt.Errorf("invalid repair type %q", repairType))
		} else if err := garageClient.LaunchRepair(ctx, "*", repairType); err != nil {
			recordOp("Repair:"+repairType, err)
			return fmt.Errorf("trigger-repair failed: %w", err)
		} else {
			log.Info("Repair operation launched on all nodes", "repairType", repairType)
			recordOp("Repair:"+repairType, nil)
		}
		toDelete = append(toDelete, garagev1beta1.AnnotationTriggerRepair)
	}

	// scrub-command: controls the scrub worker on all nodes.
	// Valid values: start, pause, resume, cancel.
	if cmd, ok := cluster.Annotations[garagev1beta1.AnnotationScrubCommand]; ok {
		if !validScrubCommands[cmd] {
			recordOp("Scrub:"+cmd, fmt.Errorf("invalid scrub command %q", cmd))
		} else if err := garageClient.LaunchScrubCommand(ctx, "*", cmd); err != nil {
			recordOp("Scrub:"+cmd, err)
			return fmt.Errorf("scrub-command failed: %w", err)
		} else {
			log.Info("Scrub command sent to all nodes", "command", cmd)
			recordOp("Scrub:"+cmd, nil)
		}
		toDelete = append(toDelete, garagev1beta1.AnnotationScrubCommand)
	}

	// revert-layout: discards staged layout changes. Value must be "true".
	// Note: this only reverts the staging area — it does not undo an already-applied layout version.
	if v, ok := cluster.Annotations[garagev1beta1.AnnotationRevertLayout]; ok {
		if v != annotationTrue {
			recordOp("RevertLayout", fmt.Errorf("invalid value %q (expected %q)", v, annotationTrue))
		} else if err := garageClient.RevertClusterLayout(ctx); err != nil {
			recordOp("RevertLayout", err)
			return fmt.Errorf("revert-layout failed: %w", err)
		} else {
			log.Info("Staged layout changes reverted")
			recordOp("RevertLayout", nil)
		}
		toDelete = append(toDelete, garagev1beta1.AnnotationRevertLayout)
	}

	// retry-block-resync: clears resync backoff so blocks are retried immediately.
	// Value: "true" to retry all errored blocks, or comma-separated 64-hex-char block hashes.
	if v, ok := cluster.Annotations[garagev1beta1.AnnotationRetryBlockResync]; ok {
		var retryErr error
		var retryCount uint64
		if v == annotationTrue {
			result, err := garageClient.RetryBlockResync(ctx, "*", true, nil)
			if err != nil {
				retryErr = err
			} else {
				retryCount = result.Count
			}
		} else {
			hashes := splitTrimmed(v)
			if len(hashes) == 0 {
				retryErr = fmt.Errorf("invalid value: must be %q or comma-separated block hashes", annotationTrue)
			} else {
				result, err := garageClient.RetryBlockResync(ctx, "*", false, hashes)
				if err != nil {
					retryErr = err
				} else {
					retryCount = result.Count
				}
			}
		}
		if retryErr != nil {
			recordOp("RetryBlockResync", retryErr)
			return fmt.Errorf("retry-block-resync failed: %w", retryErr)
		}
		log.Info("Block resync retry triggered", "count", retryCount)
		recordOp(fmt.Sprintf("RetryBlockResync:%d", retryCount), nil)
		toDelete = append(toDelete, garagev1beta1.AnnotationRetryBlockResync)
	}

	// purge-blocks: permanently deletes all S3 objects referencing the given blocks.
	// Value: comma-separated 64-hex-char block hashes. WARNING: irreversible data loss.
	if v, ok := cluster.Annotations[garagev1beta1.AnnotationPurgeBlocks]; ok {
		hashes := splitTrimmed(v)
		if len(hashes) == 0 {
			recordOp("PurgeBlocks", fmt.Errorf("invalid value: must be comma-separated block hashes"))
		} else {
			log.Info("Purging blocks — THIS IS IRREVERSIBLE", "count", len(hashes))
			result, err := garageClient.PurgeBlocks(ctx, "*", hashes)
			if err != nil {
				recordOp("PurgeBlocks", err)
				return fmt.Errorf("purge-blocks failed: %w", err)
			}
			log.Info("Blocks purged",
				"blocksPurged", result.BlocksPurged,
				"objectsDeleted", result.ObjectsDeleted,
				"versionsDeleted", result.VersionsDeleted,
			)
			recordOp(fmt.Sprintf("PurgeBlocks:%d-objects", result.ObjectsDeleted), nil)
		}
		toDelete = append(toDelete, garagev1beta1.AnnotationPurgeBlocks)
	}

	for _, k := range toDelete {
		delete(cluster.Annotations, k)
	}
	if len(toDelete) > 0 {
		return r.Update(ctx, cluster)
	}
	return nil
}

// reconcileWorkers applies spec.workers settings to all nodes via SetWorkerVariable.
// Called on every reconcile; idempotent — Garage persists variables to disk so
// re-setting the same value is a no-op in effect.
func (r *GarageClusterReconciler) reconcileWorkers(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	if cluster.Spec.Workers == nil {
		return nil
	}
	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		return fmt.Errorf("admin token required for worker variable reconciliation: %w", err)
	}
	adminPort := getAdminPort(cluster)
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
	c := garage.NewClient(adminEndpoint, adminToken)

	w := cluster.Spec.Workers
	type workerVar struct {
		name  string
		value *int32
	}
	vars := []workerVar{
		{"scrub-tranquility", w.ScrubTranquility},
		{"resync-worker-count", w.ResyncWorkerCount},
		{"resync-tranquility", w.ResyncTranquility},
	}
	for _, v := range vars {
		if v.value == nil {
			continue
		}
		if err := c.SetWorkerVariable(ctx, "*", v.name, fmt.Sprintf("%d", *v.value)); err != nil {
			return fmt.Errorf("failed to set worker variable %q: %w", v.name, err)
		}
	}
	return nil
}

// handleConnectNodes connects the cluster to external nodes specified in the annotation.
// Format: "nodeId@addr:port,nodeId2@addr2:port2,..."
// This is useful for multi-cluster federation where node IDs are known.
func (r *GarageClusterReconciler) handleConnectNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster, connections string) error {
	log := logf.FromContext(ctx)

	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		return fmt.Errorf("admin token required for connect-nodes operation")
	}

	adminPort := getAdminPort(cluster)
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
	garageClient := garage.NewClient(adminEndpoint, adminToken)

	// Parse comma-separated connection strings
	for _, conn := range strings.Split(connections, ",") {
		conn = strings.TrimSpace(conn)
		if conn == "" {
			continue
		}

		// Parse nodeId@addr:port format
		atIdx := strings.Index(conn, "@")
		if atIdx == -1 {
			log.Info("Skipping invalid connection string (missing @)", "connection", conn)
			continue
		}

		nodeID := conn[:atIdx]
		addr := conn[atIdx+1:]

		if nodeID == "" || addr == "" {
			log.Info("Skipping invalid connection string", "connection", conn)
			continue
		}

		log.Info("Connecting to external node", "nodeID", nodeID[:16]+"...", "addr", addr)
		result, err := garageClient.ConnectNode(ctx, nodeID, addr)
		if err != nil {
			log.Error(err, "Failed to connect to node", "nodeID", nodeID[:16]+"...", "addr", addr)
			continue
		}

		if result.Success {
			log.Info("Successfully connected to external node", "nodeID", nodeID[:16]+"...", "addr", addr)
		} else {
			errMsg := connectErrUnknown
			if result.Error != nil {
				errMsg = *result.Error
			}
			log.Info("Connection to external node failed", "nodeID", nodeID[:16]+"...", "addr", addr, "error", errMsg)
		}
	}

	return nil
}

// handleSkipDeadNodes marks dead/removed nodes as synced to unblock draining layout versions.
// This is called when the skip-dead-nodes annotation is set.
// If allow-missing-data annotation is also set, it will force sync even if quorum is missing.
func (r *GarageClusterReconciler) handleSkipDeadNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		return fmt.Errorf("admin token required for skip-dead-nodes operation")
	}

	adminPort := getAdminPort(cluster)
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
	garageClient := garage.NewClient(adminEndpoint, adminToken)

	// Get current layout to determine version
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Check if allow-missing-data annotation is set
	allowMissingData := false
	if val, ok := cluster.Annotations[garagev1beta1.AnnotationAllowMissingData]; ok && val == annotationTrue {
		allowMissingData = true
		log.Info("Allow-missing-data annotation is set, will force sync update")
	}

	req := garage.SkipDeadNodesRequest{
		Version:          layout.Version,
		AllowMissingData: allowMissingData,
	}

	result, err := garageClient.ClusterLayoutSkipDeadNodes(ctx, req)
	if err != nil {
		// If bad request, might be single layout version (nothing to skip)
		if garage.IsBadRequest(err) {
			log.Info("Skip-dead-nodes: no draining versions to process (single layout version)")
			return nil
		}
		return fmt.Errorf("failed to skip dead nodes: %w", err)
	}

	log.Info("Skip-dead-nodes completed",
		"ackUpdated", len(result.AckUpdated),
		"syncUpdated", len(result.SyncUpdated),
		"version", layout.Version)

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// PVCs are created by the StatefulSet's volumeClaimTemplates and are therefore not
	// directly owned by GarageCluster (the ownerRef points to the StatefulSet). Use a
	// label-based mapper so PVC status changes (e.g., resize completing) retrigger
	// reconciliation of the owning cluster without waiting for the next scheduled requeue.
	pvcMapper := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
		clusterName, ok := obj.GetLabels()[labelCluster]
		if !ok || clusterName == "" {
			return nil
		}
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{Name: clusterName, Namespace: obj.GetNamespace()},
		}}
	})

	// GarageNode status changes (especially status.NodeID becoming non-empty
	// after first reconcile) must retrigger the owning cluster so the
	// cluster-shared ConfigMap can refresh its auto-populated bootstrap_peers
	// list with the newly-known sibling (#203).
	nodeMapper := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
		gn, ok := obj.(*garagev1beta1.GarageNode)
		if !ok || gn.Spec.ClusterRef.Name == "" {
			return nil
		}
		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{Name: gn.Spec.ClusterRef.Name, Namespace: gn.Namespace},
		}}
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta2.GarageCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Watches(&corev1.PersistentVolumeClaim{}, pvcMapper).
		Watches(&garagev1beta1.GarageNode{}, nodeMapper).
		Named("garagecluster").
		Complete(r)
}

// Tier identifiers used in labels and tags.
const (
	tierStorage = "storage"
	tierGateway = "gateway"
)

// labelTier is the operator's per-tier label key.
const labelTier = "garage.rajsingh.info/tier"

// labelGarageNode is the per-pod label written by the GarageNode controller
// onto its StatefulSet's pod template. Stable across pod restarts and
// independent of the StatefulSet's pod-name convention, so it's the right
// selector for per-pod Services (e.g. per-node LoadBalancer RPC).
const labelGarageNode = "garage.rajsingh.info/node"

// labelsForTier returns operator-managed labels scoped to a single tier. Use this
// when labelling tier-owned resources (StatefulSet / Deployment / per-tier service /
// PDB) so the label selectors can target one tier without matching the other.
func (r *GarageClusterReconciler) labelsForTier(cluster *garagev1beta2.GarageCluster, tier string) map[string]string {
	return map[string]string{
		labelAppName:      defaultAppName,
		labelAppInstance:  cluster.Name,
		labelAppManagedBy: operatorName,
		labelAppComponent: tier,
		labelTier:         tier,
		labelCluster:      cluster.Name,
	}
}

// selectorLabelsForTier returns the minimal label set used in StatefulSet / Deployment
// selectors and pod templates for a given tier.
func (r *GarageClusterReconciler) selectorLabelsForTier(cluster *garagev1beta2.GarageCluster, tier string) map[string]string {
	return map[string]string{
		labelAppName:     defaultAppName,
		labelAppInstance: cluster.Name,
		labelTier:        tier,
	}
}

// isMetadataEmptyDir returns true when the storage tier's metadata volume is
// configured as EmptyDir. Returns false when there's no storage tier (gateway-only
// clusters), since gateway pods always use EmptyDir without going through this path.
//
//nolint:unused // used by buildVolumesAndMounts (test-only post-#190)
func isMetadataEmptyDir(cluster *garagev1beta2.GarageCluster) bool {
	if !cluster.HasStorageTier() {
		return false
	}
	return cluster.Spec.Storage.Metadata != nil &&
		cluster.Spec.Storage.Metadata.Type == garagev1beta2.VolumeTypeEmptyDir
}

// isDataEmptyDir returns true when the storage tier's data volume is configured
// as EmptyDir. Returns false when there's no storage tier.
//
//nolint:unused // used by buildVolumesAndMounts (test-only post-#190)
func isDataEmptyDir(cluster *garagev1beta2.GarageCluster) bool {
	if !cluster.HasStorageTier() {
		return false
	}
	return cluster.Spec.Storage.Data != nil &&
		cluster.Spec.Storage.Data.Type == garagev1beta2.VolumeTypeEmptyDir
}

// nodeBelongsToCluster checks if a node belongs to a cluster by examining its tags.
// It looks for the cluster ownership tag in the format "cluster:<name>/<namespace>".
// For backwards compatibility, it also matches on the first tag being an exact match
// of the cluster name (legacy format).
func nodeBelongsToCluster(tags []string, clusterName, namespace string) bool {
	// Primary format: "cluster:<name>/<namespace>" for unique identification
	ownershipTag := fmt.Sprintf("cluster:%s/%s", clusterName, namespace)
	for _, tag := range tags {
		if tag == ownershipTag {
			return true
		}
	}

	// Legacy format: first tag is exact cluster name (for backwards compatibility)
	// This allows existing clusters to continue working without requiring layout rebuild
	if len(tags) > 0 && tags[0] == clusterName {
		return true
	}

	return false
}

// buildNodeTags creates the tags list for a node including the cluster ownership tag.
// Format: ["cluster:<name>/<namespace>", "tier:<tier>" (if tier non-empty), <cluster.Spec.DefaultNodeTags...>, <podName>]
// The "tier:<tier>" tag distinguishes storage from gateway entries in the
// layout for diagnostics and per-tier reconciliation logic.
func buildNodeTags(clusterName, namespace, tier string, defaultTags []string, podName string) []string {
	tags := make([]string, 0, 3+len(defaultTags))
	// Ownership tag for unique cluster identification
	tags = append(tags, fmt.Sprintf("cluster:%s/%s", clusterName, namespace))
	// Tier tag so the operator can identify storage vs gateway entries in a layout
	// that mixes both (unified clusters in particular).
	if tier != "" {
		tags = append(tags, "tier:"+tier)
	}
	// User-defined tags
	tags = append(tags, defaultTags...)
	// Pod name for debugging
	tags = append(tags, podName)
	return tags
}

// detectNodeConfigDrift checks if a node's current configuration differs from desired.
// Returns true if zone, tags, or capacity have drifted from the desired state.
func detectNodeConfigDrift(existing *garage.LayoutNodeRole, desiredZone string, desiredTags []string, desiredCapacity *uint64) bool {
	// Check zone drift
	if existing.Zone != desiredZone {
		return true
	}

	// Check capacity drift
	if (existing.Capacity == nil) != (desiredCapacity == nil) {
		return true
	}
	if desiredCapacity != nil && existing.Capacity != nil && *existing.Capacity != *desiredCapacity {
		return true
	}

	// Check tag drift
	if !tagsEqualCluster(existing.Tags, desiredTags) {
		return true
	}

	return false
}

// tagsEqualCluster compares two tag slices for equality using set-based comparison.
// Tags are considered equal if they contain the same elements, regardless of order.
// This prevents false config drift detection when Garage or external tools reorder tags.
func tagsEqualCluster(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Build a set of tags from slice a
	tagSet := make(map[string]int, len(a))
	for _, tag := range a {
		tagSet[tag]++
	}
	// Check that all tags in b exist in a with same count (handles duplicates)
	for _, tag := range b {
		if tagSet[tag] <= 0 {
			return false
		}
		tagSet[tag]--
	}
	return true
}

// buildZoneRedundancy converts ReplicationConfig zone fields to a *garage.ZoneRedundancy.
func buildZoneRedundancy(r *garagev1beta2.ReplicationConfig) *garage.ZoneRedundancy {
	if r == nil {
		return nil
	}
	switch r.ZoneRedundancyMode {
	case "AtLeast":
		if r.ZoneRedundancyMinZones != nil {
			n := *r.ZoneRedundancyMinZones
			return &garage.ZoneRedundancy{AtLeast: &n}
		}
	case "Maximum":
		return &garage.ZoneRedundancy{Maximum: true}
	}
	return nil
}

// computePodSpecHash returns a stable 16-char hex hash of the pod spec plus the user-provided
// podAnnotations/podLabels. Adding the maps to the hash makes podAnnotation/podLabel changes
// trigger a StatefulSet/Deployment update — without this, the update gate (which only compares
// the three hash annotations) would early-return and never propagate the new metadata to the
// pod template.
//
// Pass the USER-PROVIDED maps (from spec.{storage,gateway}.PodAnnotations / .PodLabels), NOT
// the merged maps that the caller writes onto the workload — the merged annotations already
// contain config-hash and this hash itself, which would be circular.
//
// encoding/json marshals Go maps in sorted key order, so the result is deterministic.
func computePodSpecHash(spec corev1.PodSpec, podAnnotations, podLabels map[string]string) string {
	hashInput := struct {
		Spec        corev1.PodSpec
		Annotations map[string]string
		Labels      map[string]string
	}{
		Spec:        spec,
		Annotations: podAnnotations,
		Labels:      podLabels,
	}
	b, _ := json.Marshal(hashInput)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
