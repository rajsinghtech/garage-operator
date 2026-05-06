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
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageClusterFinalizer = "garagecluster.garage.rajsingh.info/finalizer"
	defaultGarageImage     = "dxflrs/garage:v2.3.0"
	defaultGarageTag       = "v2.3.0"
	defaultS3Region        = "garage"
	defaultAppName         = "garage"

	// Health status constants
	healthStatusHealthy  = "healthy"
	healthStatusDegraded = "degraded"
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
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

func (r *GarageClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	_ = log // Used in sub-functions via context

	cluster := &garagev1beta1.GarageCluster{}
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

	// Create or update ConfigMap and get config hash for pod restart triggering
	configHash, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update headless Service for RPC
	if err := r.reconcileHeadlessService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update API Service
	if err := r.reconcileAPIService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create, update, or delete the dedicated external RPC service for publicEndpoint
	if err := r.reconcilePublicEndpointService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Create or update StatefulSet for Auto layout policy clusters.
	// For Manual layout policy, GarageNode resources create their own StatefulSets.
	// Note: Garage does NOT support hot-reload - all config changes require pod restart.
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		if err := r.reconcileStatefulSet(ctx, cluster, configHash); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}

		// Clean up old Deployment if it exists (migration from previous gateway implementation)
		if cluster.Spec.Gateway {
			if err := r.cleanupOldDeployment(ctx, cluster); err != nil {
				log.Error(err, "Failed to cleanup old Deployment")
				// Don't fail reconciliation, just log
			}
		}

		// Create or update PodDisruptionBudget if enabled (only for Auto mode)
		if err := r.reconcilePDB(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}

		// Expand PVCs if spec requests a larger size than what was originally provisioned.
		// StatefulSet VolumeClaimTemplates are immutable, so we patch PVCs directly.
		if err := r.reconcilePVCExpansion(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}
	}

	// Bootstrap cluster nodes if pods are running but cluster isn't formed
	// Skip for Manual layout policy - GarageNode controller handles layout
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		if err := r.bootstrapCluster(ctx, cluster); err != nil {
			log.Error(err, "Failed to bootstrap cluster (will retry)")
			// Don't fail reconciliation, just log and continue
		}
	}

	// Connect to remote clusters for multi-cluster federation
	r.reconcileFederation(ctx, cluster)

	// Connect gateway cluster to storage cluster
	if cluster.Spec.Gateway {
		r.reconcileGatewayConnection(ctx, cluster)
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

func (r *GarageClusterReconciler) finalize(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
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

	// Delete API Service
	apiSvc := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, apiSvc); err == nil {
		log.Info("Deleting API Service", "name", apiSvc.Name)
		if err := r.Delete(ctx, apiSvc); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete API Service: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
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

	// Delete ConfigMap
	cm := &corev1.ConfigMap{}
	cmName := cluster.Name + "-config"
	if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm); err == nil {
		log.Info("Deleting ConfigMap", "name", cm.Name)
		if err := r.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ConfigMap: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete PodDisruptionBudget
	pdb := &policyv1.PodDisruptionBudget{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, pdb); err == nil {
		log.Info("Deleting PDB", "name", pdb.Name)
		if err := r.Delete(ctx, pdb); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete PDB: %w", err)
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	log.Info("GarageCluster finalization complete", "name", cluster.Name)
	return nil
}

// collectGarageNodeIDs collects node IDs from GarageNode CRs that belong to this cluster.
// Called before deletion so node IDs are available for layout cleanup even if tags don't match.
func (r *GarageClusterReconciler) collectGarageNodeIDs(ctx context.Context, cluster *garagev1beta1.GarageCluster) map[string]bool {
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
func (r *GarageClusterReconciler) removeNodesFromLayout(ctx context.Context, cluster *garagev1beta1.GarageCluster, knownNodeIDs map[string]bool) error {
	log := logf.FromContext(ctx)

	// Determine which cluster's layout to modify and get the appropriate client
	var garageClient *garage.Client
	var err error

	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		// Gateway cluster with clusterRef: remove nodes from the storage cluster's layout
		garageClient, err = r.getStorageClusterClient(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to get storage cluster client: %w", err)
		}
		log.Info("Removing gateway nodes from storage cluster layout",
			"storageCluster", cluster.Spec.ConnectTo.ClusterRef.Name)
	} else if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
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
	if cluster.Spec.Gateway {
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

func (r *GarageClusterReconciler) ensureRPCSecret(ctx context.Context, cluster *garagev1beta1.GarageCluster) (*corev1.Secret, error) {
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
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		storageCluster := &garagev1beta1.GarageCluster{}
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

// reconcileConfigMap creates/updates the ConfigMap and returns the config hash for pod restart triggering.
// Garage does NOT support hot-reload of config (SIGHUP is explicitly ignored in src/garage/server.rs).
// All config changes require pod restarts, which we trigger via the checksum annotation.
func (r *GarageClusterReconciler) reconcileConfigMap(ctx context.Context, cluster *garagev1beta1.GarageCluster) (string, error) {
	log := logf.FromContext(ctx)
	configMapName := cluster.Name + "-config"

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

	garageConfig := generateGarageConfig(cluster, cfgCtx)

	// Compute SHA256 hash of config for pod restart triggering
	configHash := sha256.Sum256([]byte(garageConfig))
	configHashStr := hex.EncodeToString(configHash[:])

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Data: map[string]string{
			"garage.toml": garageConfig,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return "", err
	}

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating ConfigMap", "name", configMapName)
		return configHashStr, r.Create(ctx, configMap)
	}
	if err != nil {
		return "", err
	}

	existing.Data = configMap.Data
	return configHashStr, r.Update(ctx, existing)
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
}

// buildConfigContext creates a configContext by resolving secrets referenced in the cluster spec.
// This reads secrets that need to be embedded inline in the config (e.g., Consul token which
// doesn't support file-based loading in Garage).
func buildConfigContext(ctx context.Context, cl client.Client, cluster *garagev1beta1.GarageCluster) (*configContext, error) {
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

func generateGarageConfig(cluster *garagev1beta1.GarageCluster, cfgCtx *configContext) string {
	var config strings.Builder

	// Both storage and gateway clusters use /data paths for consistency.
	// Gateway clusters use StatefulSet with metadata PVC (for node identity persistence)
	// and EmptyDir for data (since gateways don't store blocks).
	config.WriteString("metadata_dir = \"/data/metadata\"\n")
	writeDataDirConfig(&config, cluster)
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
func writeDataDirConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
	if cluster.Spec.Storage.Data != nil && len(cluster.Spec.Storage.Data.Paths) > 0 {
		// Multi-path configuration
		config.WriteString("data_dir = [\n")
		for i, path := range cluster.Spec.Storage.Data.Paths {
			config.WriteString("    { path = \"")
			config.WriteString(path.Path)
			config.WriteString("\"")
			if path.ReadOnly {
				config.WriteString(", read_only = true")
			} else if path.Capacity != nil {
				// Capacity is required for read-write paths
				fmt.Fprintf(config, ", capacity = \"%s\"", path.Capacity.String())
			}
			config.WriteString(" }")
			if i < len(cluster.Spec.Storage.Data.Paths)-1 {
				config.WriteString(",")
			}
			config.WriteString("\n")
		}
		config.WriteString("]\n")
	} else {
		// Single path (default)
		config.WriteString("data_dir = \"/data/data\"\n")
	}
}

func writeDBConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeReplicationConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
	r := cluster.Spec.Replication
	if r == nil {
		r = &garagev1beta1.ReplicationConfig{Factor: 3, ConsistencyMode: "consistent"}
	}
	fmt.Fprintf(config, "replication_factor = %d\n", r.Factor)
	if r.ConsistencyMode != "" {
		fmt.Fprintf(config, "consistency_mode = \"%s\"\n", r.ConsistencyMode)
	}
}

func writeStorageConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster, cfgCtx *configContext) {
	// Node-level overrides take precedence over cluster-level settings.
	metadataFsync := cluster.Spec.Storage.MetadataFsync
	if cfgCtx != nil && cfgCtx.MetadataFsync != nil {
		metadataFsync = *cfgCtx.MetadataFsync
	}
	dataFsync := cluster.Spec.Storage.DataFsync
	if cfgCtx != nil && cfgCtx.DataFsync != nil {
		dataFsync = *cfgCtx.DataFsync
	}

	if metadataFsync {
		config.WriteString("metadata_fsync = true\n")
	}
	if dataFsync {
		config.WriteString("data_fsync = true\n")
	}
	if cluster.Spec.Storage.MetadataSnapshotsDir != "" {
		fmt.Fprintf(config, "metadata_snapshots_dir = \"%s\"\n", cluster.Spec.Storage.MetadataSnapshotsDir)
	}
	if cluster.Spec.Storage.MetadataAutoSnapshotInterval != "" {
		fmt.Fprintf(config, "metadata_auto_snapshot_interval = \"%s\"\n", cluster.Spec.Storage.MetadataAutoSnapshotInterval)
	}
}

func writeBlockConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeSecurityConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeRPCConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster, cfgCtx *configContext) {
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

	// Priority: per-node override > cluster static > publicEndpoint-derived
	switch {
	case cfgCtx != nil && cfgCtx.NodeRPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cfgCtx.NodeRPCPublicAddr)
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
	if len(cluster.Spec.Network.BootstrapPeers) > 0 {
		quotedPeers := make([]string, 0, len(cluster.Spec.Network.BootstrapPeers))
		for _, peer := range cluster.Spec.Network.BootstrapPeers {
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

func writeS3APIConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeK2VAPIConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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
func effectiveWebAPI(cluster *garagev1beta1.GarageCluster) *garagev1beta1.WebAPIConfig {
	w := cluster.Spec.WebAPI
	// Explicitly disabled via Enabled: false
	if w != nil && w.Enabled != nil && !*w.Enabled {
		return nil
	}
	// Web hosting enabled by default; compute effective config.
	eff := &garagev1beta1.WebAPIConfig{}
	if w != nil {
		eff = w.DeepCopy()
	}
	if eff.RootDomain == "" {
		eff.RootDomain = fmt.Sprintf(".%s.%s.svc", cluster.Name, cluster.Namespace)
	}
	return eff
}

func writeWebAPIConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeAdminConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeKubernetesDiscoveryConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster) {
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

func writeConsulDiscoveryConfig(config *strings.Builder, cluster *garagev1beta1.GarageCluster, cfgCtx *configContext) {
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

func (r *GarageClusterReconciler) reconcileHeadlessService(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name + "-headless"

	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	// For Manual mode, use cluster label selector so GarageNode pods are selected.
	// For Auto mode, use the standard cluster selector labels.
	selector := r.selectorLabelsForCluster(cluster)
	if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		selector = map[string]string{
			labelCluster: cluster.Name,
		}
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector:  selector,
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

func (r *GarageClusterReconciler) reconcileAPIService(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name

	ports := []corev1.ServicePort{}

	// S3 API port (always enabled - Garage requires the [s3_api] section)
	s3Port := int32(3900)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		s3Port = cluster.Spec.S3API.BindPort
	}
	ports = append(ports, corev1.ServicePort{
		Name:       "s3",
		Port:       s3Port,
		TargetPort: intstr.FromInt32(s3Port),
		Protocol:   corev1.ProtocolTCP,
	})

	// Admin API port
	{
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
	}

	// K2V API port
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

	// Web API port
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

	serviceType := corev1.ServiceTypeClusterIP
	if cluster.Spec.Network.Service != nil && cluster.Spec.Network.Service.Type != "" {
		serviceType = cluster.Spec.Network.Service.Type
	}

	var svcMeta garagev1beta1.ServiceMeta
	if cluster.Spec.Network.Service != nil {
		svcMeta = cluster.Spec.Network.Service.ServiceMeta
	}

	// For Manual mode, use cluster label selector so GarageNode pods are selected.
	// For Auto mode, use the standard cluster selector labels.
	selector := r.selectorLabelsForCluster(cluster)
	if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		selector = map[string]string{
			labelCluster: cluster.Name,
		}
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
			Selector: selector,
			Ports:    ports,
			// Enable routing to pods even when not ready, essential for multi-cluster
			// federation during bootstrap when pods are waiting for the cluster to be healthy
			PublishNotReadyAddresses: true,
		},
	}

	log.Info("Reconciling API Service", "name", serviceName)
	return reconcileService(ctx, r.Client, svc, cluster, r.Scheme)
}

// reconcilePublicEndpointService manages a dedicated RPC service (<name>-rpc) used to expose
// the Garage RPC port externally for multi-cluster federation via publicEndpoint.
// The service is created/updated when publicEndpoint is set and deleted when it is removed.
func (r *GarageClusterReconciler) reconcilePublicEndpointService(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)
	svcName := cluster.Name + "-rpc"

	if cluster.Spec.PublicEndpoint == nil {
		// Clean up any existing -rpc service if publicEndpoint was removed
		existing := &corev1.Service{}
		if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, existing); err == nil {
			log.Info("Deleting public endpoint RPC service (publicEndpoint removed)", "name", svcName)
			return r.Delete(ctx, existing)
		}
		return nil
	}

	ep := cluster.Spec.PublicEndpoint
	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	var svcType corev1.ServiceType
	var svcMeta garagev1beta1.ServiceMeta
	var nodePort int32

	switch ep.Type {
	case publicEndpointTypeLoadBalancer:
		if ep.LoadBalancer != nil && ep.LoadBalancer.PerNode {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionPublicEndpointReady,
				Status:             metav1.ConditionFalse,
				Reason:             garagev1beta1.ReasonPerNodeNotImplemented,
				Message:            "publicEndpoint.loadBalancer.perNode is not yet implemented; set network.rpcPublicAddr to the externally-routable RPC address",
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
func buildContainerPorts(cluster *garagev1beta1.GarageCluster) []corev1.ContainerPort {
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
	ports = append(ports, corev1.ContainerPort{Name: "s3", ContainerPort: s3Port})

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

// buildVolumesAndMounts returns volumes and volume mounts for the Garage StatefulSet.
// For gateway clusters, data volume is EmptyDir since gateways don't store blocks.
// Metadata volume comes from PVC (via VolumeClaimTemplates) for both gateway and storage.
func buildVolumesAndMounts(cluster *garagev1beta1.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: "config", MountPath: "/etc/garage", ReadOnly: true},
		{Name: RPCSecretKey, MountPath: "/secrets/rpc", ReadOnly: true},
		{Name: metadataVolName, MountPath: "/data/metadata"},
		{Name: dataVolName, MountPath: dataPath},
	}

	rpcSecretName := cluster.Name + "-rpc-secret"
	if cluster.Spec.Network.RPCSecretRef != nil {
		rpcSecretName = cluster.Spec.Network.RPCSecretRef.Name
	}
	// For gateway clusters connecting to storage via clusterRef, use storage cluster's RPC secret
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil {
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
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.RPCSecretRef != nil && cluster.Spec.ConnectTo.RPCSecretRef.Key != "" {
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

	// Handle metadata volume for EmptyDir type
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
	// else: metadata comes from VolumeClaimTemplate

	// Handle data volume for gateway clusters or EmptyDir type
	if cluster.Spec.Gateway || isDataEmptyDir(cluster) {
		// Gateway clusters use EmptyDir for data since they don't store blocks.
		// EmptyDir type also uses EmptyDir volume (ephemeral storage).
		emptyDir := &corev1.EmptyDirVolumeSource{}
		if cluster.Spec.Storage.Data != nil && cluster.Spec.Storage.Data.Size != nil {
			emptyDir.SizeLimit = cluster.Spec.Storage.Data.Size
		}
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolName,
			VolumeSource: corev1.VolumeSource{EmptyDir: emptyDir},
		})
	}
	// else: data comes from VolumeClaimTemplate

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
			MountPath: "/secrets/admin",
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

// buildVolumeClaimTemplates returns PVC templates for the Garage StatefulSet.
// For storage clusters: creates separate PVCs for metadata and data (unless EmptyDir).
// For gateway clusters: creates only a small metadata PVC (for node identity persistence).
// EmptyDir volumes don't need PVC templates - they're created as regular volumes.
func buildVolumeClaimTemplates(cluster *garagev1beta1.GarageCluster) []corev1.PersistentVolumeClaim {
	var templates []corev1.PersistentVolumeClaim

	// Only create metadata PVC if not using EmptyDir
	if !isMetadataEmptyDir(cluster) {
		metadataPVC := buildMetadataPVC(cluster)
		templates = append(templates, metadataPVC)
	}

	// Only create data PVC if not using EmptyDir and not a gateway cluster
	// (gateways don't store data blocks, they use EmptyDir implicitly)
	if !cluster.Spec.Gateway && !isDataEmptyDir(cluster) {
		dataPVC := buildDataPVC(cluster)
		templates = append(templates, dataPVC)
	}

	return templates
}

// buildMetadataPVC creates the metadata PVC template
func buildMetadataPVC(cluster *garagev1beta1.GarageCluster) corev1.PersistentVolumeClaim {
	var size resource.Quantity
	if cluster.Spec.Gateway {
		size = resource.MustParse("1Gi")
	} else {
		size = resource.MustParse("10Gi")
	}

	var sc *string
	var accessModes []corev1.PersistentVolumeAccessMode
	if meta := cluster.Spec.Storage.Metadata; meta != nil {
		if meta.Size != nil && !meta.Size.IsZero() {
			size = *meta.Size
		}
		sc = meta.StorageClassName
		accessModes = meta.AccessModes
	}

	pvc := buildBasePVC(metadataVolName, size, sc, accessModes)

	if meta := cluster.Spec.Storage.Metadata; meta != nil {
		if meta.Selector != nil {
			pvc.Spec.Selector = meta.Selector
		}
		if len(meta.Labels) > 0 {
			pvc.Labels = meta.Labels
		}
		if len(meta.Annotations) > 0 {
			pvc.Annotations = meta.Annotations
		}
	}

	return pvc
}

// buildDataPVC creates the data PVC template
func buildDataPVC(cluster *garagev1beta1.GarageCluster) corev1.PersistentVolumeClaim {
	size := resource.MustParse("100Gi")

	var sc *string
	var accessModes []corev1.PersistentVolumeAccessMode
	if data := cluster.Spec.Storage.Data; data != nil {
		if data.Size != nil && !data.Size.IsZero() {
			size = *data.Size
		}
		sc = data.StorageClassName
		accessModes = data.AccessModes
	}

	pvc := buildBasePVC(dataVolName, size, sc, accessModes)

	if data := cluster.Spec.Storage.Data; data != nil {
		if data.Selector != nil {
			pvc.Spec.Selector = data.Selector
		}
		if len(data.Labels) > 0 {
			pvc.Labels = data.Labels
		}
		if len(data.Annotations) > 0 {
			pvc.Annotations = data.Annotations
		}
	}

	return pvc
}

// buildPVCRetentionPolicy returns the PVC retention policy for the StatefulSet.
// This controls whether PVCs are deleted when the StatefulSet is deleted or scaled down.
// Defaults to Retain for both policies (preserving existing behavior).
func buildPVCRetentionPolicy(cluster *garagev1beta1.GarageCluster) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
	whenDeleted := appsv1.RetainPersistentVolumeClaimRetentionPolicyType
	whenScaled := appsv1.RetainPersistentVolumeClaimRetentionPolicyType

	if cluster.Spec.Storage.PVCRetentionPolicy != nil {
		if cluster.Spec.Storage.PVCRetentionPolicy.WhenDeleted == "Delete" {
			whenDeleted = appsv1.DeletePersistentVolumeClaimRetentionPolicyType
		}
		if cluster.Spec.Storage.PVCRetentionPolicy.WhenScaled == "Delete" {
			whenScaled = appsv1.DeletePersistentVolumeClaimRetentionPolicyType
		}
	}

	return &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
		WhenDeleted: whenDeleted,
		WhenScaled:  whenScaled,
	}
}

// reconcileStatefulSet creates/updates the StatefulSet for Garage pods.
// The configHash parameter is used to trigger rolling restarts when config changes,
// since Garage does NOT support hot-reload (config is only read at startup).
func (r *GarageClusterReconciler) reconcileStatefulSet(ctx context.Context, cluster *garagev1beta1.GarageCluster, configHash string) error {
	log := logf.FromContext(ctx)
	stsName := cluster.Name

	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)

	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	containerPorts := buildContainerPorts(cluster)
	volumes, volumeMounts := buildVolumesAndMounts(cluster)
	volumeClaimTemplates := buildVolumeClaimTemplates(cluster)

	podSpec := buildGaragePodSpec(PodSpecConfig{
		Image:                     image,
		ImagePullPolicy:           cluster.Spec.ImagePullPolicy,
		ImagePullSecrets:          cluster.Spec.ImagePullSecrets,
		Resources:                 cluster.Spec.Resources,
		NodeSelector:              cluster.Spec.NodeSelector,
		Tolerations:               cluster.Spec.Tolerations,
		Affinity:                  cluster.Spec.Affinity,
		PriorityClassName:         cluster.Spec.PriorityClassName,
		ServiceAccountName:        cluster.Spec.ServiceAccountName,
		SecurityContext:           cluster.Spec.SecurityContext,
		ContainerSecurityContext:  cluster.Spec.ContainerSecurityContext,
		TopologySpreadConstraints: cluster.Spec.TopologySpreadConstraints,
		IsGateway:                 cluster.Spec.Gateway,
		Logging:                   cluster.Spec.Logging,
	}, volumes, volumeMounts, containerPorts)

	podLabels := r.selectorLabelsForCluster(cluster)
	for k, v := range cluster.Spec.PodLabels {
		podLabels[k] = v
	}

	// Compute pod-spec-hash from the PodSpec to detect changes to probes, image, resources, etc.
	// This is separate from config-hash (which only covers the ConfigMap content).
	// When either hash changes, the StatefulSet will be updated and pods will restart.
	podSpecBytes, _ := json.Marshal(podSpec)
	podSpecHash := sha256.Sum256(podSpecBytes)
	podSpecHashStr := hex.EncodeToString(podSpecHash[:8]) // First 8 bytes = 16 hex chars

	// Build pod annotations with checksums to trigger rolling restart on changes.
	// This is required because Garage does NOT support hot-reload - SIGHUP is explicitly
	// ignored and config is only read at startup. When hashes change, Kubernetes
	// detects the annotation change and triggers a rolling update of the StatefulSet.
	podAnnotations := make(map[string]string)
	for k, v := range cluster.Spec.PodAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations["garage.rajsingh.info/config-hash"] = configHash
	podAnnotations["garage.rajsingh.info/pod-spec-hash"] = podSpecHashStr

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: cluster.Name + "-headless",
			Replicas:    &replicas,
			Selector:    &metav1.LabelSelector{MatchLabels: r.selectorLabelsForCluster(cluster)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
			VolumeClaimTemplates:                 volumeClaimTemplates,
			PodManagementPolicy:                  appsv1.ParallelPodManagement,
			UpdateStrategy:                       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
			PersistentVolumeClaimRetentionPolicy: buildPVCRetentionPolicy(cluster),
		},
	}

	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return err
	}

	existing := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating StatefulSet", "name", stsName)
		return r.Create(ctx, sts)
	}
	if err != nil {
		return err
	}

	// VolumeClaimTemplates are immutable in Kubernetes. If the storageClassName of any
	// VCT changed, delete the StatefulSet (orphan cascade, preserving PVCs) and return.
	// The next reconcile will create a new StatefulSet with the correct VCTs. The operator
	// does NOT auto-delete the old PVCs — the user must delete them manually so the new
	// StatefulSet can provision fresh PVCs with the correct storageClass.
	if vctStorageClassChanged(existing.Spec.VolumeClaimTemplates, volumeClaimTemplates) {
		log.Info("VolumeClaimTemplate storageClass changed, recreating StatefulSet (orphan cascade — delete old PVCs manually)", "name", stsName)
		propagation := metav1.DeletePropagationOrphan
		if err := r.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete StatefulSet for VCT recreation: %w", err)
		}
		return nil
	}

	// Check if update is needed by comparing key fields
	needsUpdate := existing.Spec.Replicas == nil || *existing.Spec.Replicas != *sts.Spec.Replicas

	// Check config hash annotation (indicates ConfigMap/TOML changes)
	existingConfigHash := existing.Spec.Template.Annotations["garage.rajsingh.info/config-hash"]
	newConfigHash := sts.Spec.Template.Annotations["garage.rajsingh.info/config-hash"]
	if existingConfigHash != newConfigHash {
		log.Info("Config hash changed, updating StatefulSet", "old", existingConfigHash, "new", newConfigHash)
		needsUpdate = true
	}

	// Check pod-spec-hash annotation (detects changes to probes, image, resources, etc.)
	existingPodSpecHash := existing.Spec.Template.Annotations["garage.rajsingh.info/pod-spec-hash"]
	newPodSpecHash := sts.Spec.Template.Annotations["garage.rajsingh.info/pod-spec-hash"]
	if existingPodSpecHash != newPodSpecHash {
		log.Info("Pod spec hash changed, updating StatefulSet", "old", existingPodSpecHash, "new", newPodSpecHash)
		needsUpdate = true
	}

	if !needsUpdate {
		log.V(1).Info("StatefulSet is up to date", "name", stsName)
		return nil
	}

	existing.Spec.Replicas = sts.Spec.Replicas
	existing.Spec.Template = sts.Spec.Template
	log.Info("Updating StatefulSet", "name", stsName)
	return r.Update(ctx, existing)
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

// reconcilePVCExpansion expands existing PVCs when the spec requests a larger size.
// StatefulSet VolumeClaimTemplates are immutable in Kubernetes, so resizing requires
// patching the individual PVC objects directly.
func (r *GarageClusterReconciler) reconcilePVCExpansion(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)

	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	if !isMetadataEmptyDir(cluster) {
		desiredSize := buildMetadataPVC(cluster).Spec.Resources.Requests[corev1.ResourceStorage]
		for i := int32(0); i < replicas; i++ {
			pvcName := fmt.Sprintf("metadata-%s-%d", cluster.Name, i)
			if err := r.maybeExpandPVC(ctx, log, cluster.Namespace, pvcName, desiredSize); err != nil {
				return err
			}
		}
	}

	if !cluster.Spec.Gateway && !isDataEmptyDir(cluster) {
		desiredSize := buildDataPVC(cluster).Spec.Resources.Requests[corev1.ResourceStorage]
		for i := int32(0); i < replicas; i++ {
			pvcName := fmt.Sprintf("data-%s-%d", cluster.Name, i)
			if err := r.maybeExpandPVC(ctx, log, cluster.Namespace, pvcName, desiredSize); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *GarageClusterReconciler) maybeExpandPVC(ctx context.Context, log logr.Logger, namespace, pvcName string, desiredSize resource.Quantity) error {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := r.Get(ctx, types.NamespacedName{Name: pvcName, Namespace: namespace}, pvc); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if desiredSize.Cmp(currentSize) <= 0 {
		return nil
	}

	// Check if the storage class supports volume expansion before attempting.
	// If the SC is not found or doesn't have allowVolumeExpansion, skip rather than
	// attempt a patch that Kubernetes will reject (static PVCs, missing SC, etc.).
	if scName := pvc.Spec.StorageClassName; scName != nil && *scName != "" {
		sc := &storagev1.StorageClass{}
		if err := r.Get(ctx, types.NamespacedName{Name: *scName}, sc); err != nil {
			if errors.IsNotFound(err) {
				log.Info("Skipping PVC expansion: storage class not found", "name", pvcName, "storageClass", *scName)
				return nil
			}
			return err
		}
		if sc.AllowVolumeExpansion == nil || !*sc.AllowVolumeExpansion {
			log.Info("Skipping PVC expansion: storage class does not support resize", "name", pvcName, "storageClass", *scName)
			return nil
		}
	}

	log.Info("Expanding PVC", "name", pvcName, "namespace", namespace, "from", currentSize.String(), "to", desiredSize.String())
	patch := client.MergeFrom(pvc.DeepCopy())
	pvc.Spec.Resources.Requests[corev1.ResourceStorage] = desiredSize
	return r.Patch(ctx, pvc, patch)
}

// cleanupOldDeployment removes the old Deployment that was used for gateway clusters
// before switching to StatefulSet. This handles migration from the old implementation.
func (r *GarageClusterReconciler) cleanupOldDeployment(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)
	deployName := cluster.Name

	existing := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		return nil // No old Deployment to clean up
	}
	if err != nil {
		return err
	}

	log.Info("Cleaning up old Deployment (migrating gateway to StatefulSet)", "name", deployName)
	return r.Delete(ctx, existing)
}

func (r *GarageClusterReconciler) reconcilePDB(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)

	// Check if PDB is enabled
	if cluster.Spec.PodDisruptionBudget == nil || !cluster.Spec.PodDisruptionBudget.Enabled {
		// PDB not enabled, delete if exists
		pdb := &policyv1.PodDisruptionBudget{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, pdb); err == nil {
			log.Info("Deleting PDB (disabled)", "name", cluster.Name)
			return r.Delete(ctx, pdb)
		}
		return nil
	}

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForCluster(cluster),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.selectorLabelsForCluster(cluster),
			},
		},
	}

	// Set MinAvailable or MaxUnavailable
	if cluster.Spec.PodDisruptionBudget.MinAvailable != nil {
		pdb.Spec.MinAvailable = cluster.Spec.PodDisruptionBudget.MinAvailable
	} else if cluster.Spec.PodDisruptionBudget.MaxUnavailable != nil {
		pdb.Spec.MaxUnavailable = cluster.Spec.PodDisruptionBudget.MaxUnavailable
	} else {
		// Default: require at least (replicas - 1) to maintain quorum
		replicas := int32(3)
		if cluster.Spec.Replicas > 0 {
			replicas = cluster.Spec.Replicas
		}
		minAvail := replicas - 1
		if minAvail < 1 {
			minAvail = 1
		}
		pdb.Spec.MinAvailable = &intstr.IntOrString{Type: intstr.Int, IntVal: minAvail}
	}

	// Set controller reference
	if err := controllerutil.SetControllerReference(cluster, pdb, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if PDB exists
	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Creating PDB", "name", cluster.Name)
			return r.Create(ctx, pdb)
		}
		return err
	}

	// Update if spec differs
	if !apiequality.Semantic.DeepEqual(existing.Spec.MinAvailable, pdb.Spec.MinAvailable) ||
		!apiequality.Semantic.DeepEqual(existing.Spec.MaxUnavailable, pdb.Spec.MaxUnavailable) {
		existing.Spec = pdb.Spec
		log.Info("Updating PDB", "name", cluster.Name)
		return r.Update(ctx, existing)
	}

	return nil
}

func (r *GarageClusterReconciler) updateStatus(ctx context.Context, cluster *garagev1beta1.GarageCluster, phase string, err error) (ctrl.Result, error) {
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

func (r *GarageClusterReconciler) updateStatusFromCluster(ctx context.Context, cluster *garagev1beta1.GarageCluster) (ctrl.Result, error) {
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
		// Auto mode: get status from StatefulSet
		desiredReplicas = cluster.Spec.Replicas
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
			if errors.IsNotFound(err) {
				return r.updateStatus(ctx, cluster, "Pending", nil)
			}
			return ctrl.Result{}, err
		}
		readyReplicas = sts.Status.ReadyReplicas
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
			cluster.Status.Health = &garagev1beta1.ClusterHealth{
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
						cluster.Status.BuildInfo = &garagev1beta1.GarageBuildInfo{
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
					cluster.Status.StorageStats = &garagev1beta1.ClusterStorageStats{
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
			cluster.Status.LayoutHistory = &garagev1beta1.LayoutHistoryStatus{
				CurrentVersion: int64(history.CurrentVersion),
				MinAck:         int64(history.MinAck),
			}
			for _, v := range history.Versions {
				cluster.Status.LayoutHistory.Versions = append(cluster.Status.LayoutHistory.Versions, garagev1beta1.LayoutVersionInfo{
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
	cluster.Status.Endpoints = &garagev1beta1.ClusterEndpoints{
		S3:    svcFQDN(cluster.Name, cluster.Namespace, s3Port, r.ClusterDomain),
		Admin: svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain),
		RPC:   svcFQDN(cluster.Name+"-headless", cluster.Namespace, rpcPort, r.ClusterDomain),
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue faster when cluster is unhealthy to speed up recovery
	if cluster.Status.Health != nil && cluster.Status.Health.Status != healthStatusHealthy {
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// Back off to 5m for healthy external gateway clusters to avoid hammering the
	// external admin API. The drift check in isExternalGatewayConnected handles
	// reconnection within that window when Garage marks a peer as Abandoned.
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

func (r *GarageClusterReconciler) labelsForCluster(cluster *garagev1beta1.GarageCluster) map[string]string {
	component := "storage"
	if cluster.Spec.Gateway {
		component = "gateway"
	}
	return map[string]string{
		"app.kubernetes.io/name":     defaultAppName,
		"app.kubernetes.io/instance": cluster.Name,
		labelAppManagedBy:            operatorName,
		labelAppComponent:            component,
		labelCluster:                 cluster.Name,
	}
}

func (r *GarageClusterReconciler) selectorLabelsForCluster(cluster *garagev1beta1.GarageCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     defaultAppName,
		"app.kubernetes.io/instance": cluster.Name,
	}
}

// bootstrapNodeInfo holds discovered node information
type bootstrapNodeInfo struct {
	id      string
	podIP   string
	podName string
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
func getAdminPort(cluster *garagev1beta1.GarageCluster) int32 {
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		return cluster.Spec.Admin.BindPort
	}
	return 3903
}

// getRPCPort returns the configured RPC port for the cluster
func getRPCPort(cluster *garagev1beta1.GarageCluster) int32 {
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

// countTotalNodesAfterApply calculates how many nodes will exist after staged changes are applied
func countTotalNodesAfterApply(layout *garage.ClusterLayout) int {
	total := len(layout.Roles)
	for _, change := range layout.StagedRoleChanges {
		if change.Remove {
			total--
		} else {
			isNew := true
			for _, role := range layout.Roles {
				if role.ID == change.ID {
					isNew = false
					break
				}
			}
			if isNew {
				total++
			}
		}
	}
	return total
}

// assignNewNodesToLayout assigns undiscovered nodes to the cluster layout and fixes config drift
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

	// Validate minimum capacity - Garage requires at least 1024 bytes (1 KB)
	// See: src/api/admin/layout.rs - "Capacity should be at least 1K (1024)"
	const minCapacity uint64 = 1024
	if !cfg.isGateway && effectiveCapacity < minCapacity {
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
		desiredTags := buildNodeTags(cfg.clusterName, cfg.namespace, cfg.tags, node.podName)
		var desiredCapacity *uint64
		if !cfg.isGateway {
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

// bootstrapCluster handles the initial cluster formation by connecting nodes via Admin API
func (r *GarageClusterReconciler) bootstrapCluster(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
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
	var connectedNodes int
	var healthStatus string
	if health != nil {
		connectedNodes = health.ConnectedNodes
		healthStatus = health.Status
	}
	needsReconnect := health == nil || connectedNodes < len(nodes) || healthStatus != healthStatusHealthy
	if needsReconnect {
		log.Info("Cluster needs node reconnection", "connected", connectedNodes, "expected", len(nodes), "status", healthStatus)
		connectNodes(ctx, nodes, adminToken, adminPort, rpcPort)
	}

	// Build layout config from cluster spec
	cfg := layoutConfig{
		zone:                   cluster.Spec.Zone,
		tags:                   cluster.Spec.DefaultNodeTags,
		capacityReservePercent: cluster.Spec.CapacityReservePercent,
		replicationFactor:      3, // Default
		hasRemoteClusters:      len(cluster.Spec.RemoteClusters) > 0,
		isGateway:              cluster.Spec.Gateway,
		// Cluster name and namespace are used to uniquely identify which nodes belong to this cluster.
		// Uses exact tag match to prevent clusters with prefix-overlapping names from interfering.
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
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil {
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
func (r *GarageClusterReconciler) calculateNodeCapacity(cluster *garagev1beta1.GarageCluster) uint64 {
	// Default to 10GB if no storage config (also used for EmptyDir without size limit)
	const defaultCapacity uint64 = 10 * 1024 * 1024 * 1024

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
func (r *GarageClusterReconciler) getExternalStorageClient(ctx context.Context, cluster *garagev1beta1.GarageCluster) (*garage.Client, error) {
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
func (r *GarageClusterReconciler) getStorageClusterClient(ctx context.Context, cluster *garagev1beta1.GarageCluster) (*garage.Client, error) {
	if cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.ClusterRef == nil {
		return nil, fmt.Errorf("no clusterRef configured")
	}

	// Get the storage cluster
	storageCluster := &garagev1beta1.GarageCluster{}
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
func (r *GarageClusterReconciler) reconcileGatewayConnection(ctx context.Context, cluster *garagev1beta1.GarageCluster) {
	log := logf.FromContext(ctx)

	if !cluster.Spec.Gateway || cluster.Spec.ConnectTo == nil {
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
func (r *GarageClusterReconciler) isExternalGatewayConnected(ctx context.Context, cluster *garagev1beta1.GarageCluster, gatewayClient *garage.Client) bool {
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
func (r *GarageClusterReconciler) connectGatewayToClusterRef(ctx context.Context, cluster *garagev1beta1.GarageCluster, gatewayClient *garage.Client) {
	log := logf.FromContext(ctx)

	storageCluster := &garagev1beta1.GarageCluster{}
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
func (r *GarageClusterReconciler) deriveGatewayExternalAddr(ctx context.Context, cluster *garagev1beta1.GarageCluster) string {
	if cluster.Spec.Network.RPCPublicAddr != "" {
		return "" // Garage reports this correctly already
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
			return "" // not yet implemented
		}
		svc := &corev1.Service{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name + "-rpc", Namespace: cluster.Namespace}, svc); err == nil {
			for _, ing := range svc.Status.LoadBalancer.Ingress {
				addr := ing.IP
				if addr == "" {
					addr = ing.Hostname
				}
				if addr != "" {
					return fmt.Sprintf("%s:%d", addr, rpcPort)
				}
			}
		}
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

// connectGatewayToExternalCluster connects a gateway to an external storage cluster via Admin API endpoint.
// Bidirectional: gateway → external nodes AND external cluster → gateway nodes.
func (r *GarageClusterReconciler) connectGatewayToExternalCluster(ctx context.Context, cluster *garagev1beta1.GarageCluster, gatewayClient *garage.Client) {
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

	// Connect gateway → each external node
	connectedToExternal := 0
	for _, node := range externalStatus.Nodes {
		if node.Address != nil && *node.Address != "" {
			if _, err := gatewayClient.ConnectNode(ctx, node.ID, *node.Address); err != nil {
				log.V(1).Info("Failed to connect gateway to external node", "nodeID", node.ID[:16]+"...", "address", *node.Address, "error", err)
			} else {
				connectedToExternal++
			}
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

	// Derive the operator-known external address for this gateway cluster.
	// Used to override internal (pod/service) IPs that Garage may report when
	// rpc_public_addr is not set — such addresses are unreachable from external clusters.
	overrideAddr := r.deriveGatewayExternalAddr(ctx, cluster)

	connectedToGateway := 0
	for _, node := range gatewayStatus.Nodes {
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
func (r *GarageClusterReconciler) reconcileFederation(ctx context.Context, cluster *garagev1beta1.GarageCluster) {
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
	cluster *garagev1beta1.GarageCluster,
	localClient *garage.Client,
	localStatus *garage.ClusterStatus,
	remote garagev1beta1.RemoteClusterConfig,
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
				errMsg := "unknown"
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
	cluster *garagev1beta1.GarageCluster,
	localClient *garage.Client,
	remoteClient *garage.Client,
	remoteStatus *garage.ClusterStatus,
	localStatus *garage.ClusterStatus,
	remote garagev1beta1.RemoteClusterConfig,
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
	remote garagev1beta1.RemoteClusterConfig,
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
	cluster *garagev1beta1.GarageCluster,
	remote garagev1beta1.RemoteClusterConfig,
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
func (r *GarageClusterReconciler) getAdminToken(ctx context.Context, cluster *garagev1beta1.GarageCluster) (string, error) {
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
func (r *GarageClusterReconciler) handleOperationalAnnotations(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
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
			cluster.Status.LastOperation = &garagev1beta1.LastOperationStatus{
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
func (r *GarageClusterReconciler) reconcileWorkers(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
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
func (r *GarageClusterReconciler) handleConnectNodes(ctx context.Context, cluster *garagev1beta1.GarageCluster, connections string) error {
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
			errMsg := "unknown"
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
func (r *GarageClusterReconciler) handleSkipDeadNodes(ctx context.Context, cluster *garagev1beta1.GarageCluster) error {
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Watches(&corev1.PersistentVolumeClaim{}, pvcMapper).
		Named("garagecluster").
		Complete(r)
}

// isMetadataEmptyDir returns true if metadata storage uses EmptyDir
func isMetadataEmptyDir(cluster *garagev1beta1.GarageCluster) bool {
	return cluster.Spec.Storage.Metadata != nil &&
		cluster.Spec.Storage.Metadata.Type == garagev1beta1.VolumeTypeEmptyDir
}

// isDataEmptyDir returns true if data storage uses EmptyDir
func isDataEmptyDir(cluster *garagev1beta1.GarageCluster) bool {
	return cluster.Spec.Storage.Data != nil &&
		cluster.Spec.Storage.Data.Type == garagev1beta1.VolumeTypeEmptyDir
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
// Format: ["cluster:<name>/<namespace>", <cluster.Spec.DefaultNodeTags...>, <podName>]
func buildNodeTags(clusterName, namespace string, defaultTags []string, podName string) []string {
	tags := make([]string, 0, 2+len(defaultTags))
	// Ownership tag for unique cluster identification
	tags = append(tags, fmt.Sprintf("cluster:%s/%s", clusterName, namespace))
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
func buildZoneRedundancy(r *garagev1beta1.ReplicationConfig) *garage.ZoneRedundancy {
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
