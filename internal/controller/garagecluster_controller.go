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
	"reflect"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageClusterFinalizer = "garagecluster.garage.rajsingh.info/finalizer"
	defaultGarageImage     = "dxflrs/garage:v2.2.0"

	// Health status constants
	healthStatusHealthy  = "healthy"
	healthStatusDegraded = "degraded"
)

// GarageClusterReconciler reconciles a GarageCluster object
type GarageClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create

func (r *GarageClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	_ = log // Used in sub-functions via context

	cluster := &garagev1alpha1.GarageCluster{}
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

	// Ensure RPC secret exists
	if _, err := r.ensureRPCSecret(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, "Error", err)
	}

	// Create or update ConfigMap and get config hash for pod restart triggering
	configHash, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return r.updateStatus(ctx, cluster, "Error", err)
	}

	// Create or update headless Service for RPC
	if err := r.reconcileHeadlessService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, "Error", err)
	}

	// Create or update API Service
	if err := r.reconcileAPIService(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, "Error", err)
	}

	// Create or update StatefulSet for Auto layout policy clusters.
	// For Manual layout policy, GarageNode resources create their own StatefulSets.
	// Note: Garage does NOT support hot-reload - all config changes require pod restart.
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		if err := r.reconcileStatefulSet(ctx, cluster, configHash); err != nil {
			return r.updateStatus(ctx, cluster, "Error", err)
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
			return r.updateStatus(ctx, cluster, "Error", err)
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

	// Handle operational annotations
	if err := r.handleOperationalAnnotations(ctx, cluster); err != nil {
		log.Error(err, "Failed to handle operational annotation")
		// Don't fail reconciliation, just log
	}

	// Update status with cluster health
	return r.updateStatusFromCluster(ctx, cluster)
}

func (r *GarageClusterReconciler) finalize(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)
	log.Info("Finalizing GarageCluster", "name", cluster.Name)

	// First, remove nodes from Garage layout before deleting K8s resources.
	// This ensures nodes are properly deregistered from the cluster.
	if err := r.removeNodesFromLayout(ctx, cluster); err != nil {
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

// removeNodesFromLayout removes all nodes belonging to this cluster from the Garage layout.
// For gateway clusters, this connects to the storage cluster's admin API.
// For storage clusters, this connects to its own admin API.
func (r *GarageClusterReconciler) removeNodesFromLayout(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)

	// Determine which cluster's layout to modify and get the appropriate client
	var garageClient *garage.Client
	var err error

	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		// Gateway cluster: remove nodes from the storage cluster's layout
		garageClient, err = r.getStorageClusterClient(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to get storage cluster client: %w", err)
		}
		log.Info("Removing gateway nodes from storage cluster layout",
			"storageCluster", cluster.Spec.ConnectTo.ClusterRef.Name)
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
		endpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d",
			cluster.Name, cluster.Namespace, adminPort)
		garageClient = garage.NewClient(endpoint, adminToken)
	}

	// Get current layout
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Find all nodes belonging to this cluster (identified by exact cluster name tag match).
	// Uses exact match to prevent clusters with prefix-overlapping names (e.g., "garage" and
	// "garage-gateway") from accidentally removing each other's nodes.
	nodesToRemove := make([]garage.NodeRoleChange, 0)
	for _, role := range layout.Roles {
		if !nodeBelongsToCluster(role.Tags, cluster.Name, cluster.Namespace) {
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

func (r *GarageClusterReconciler) ensureRPCSecret(ctx context.Context, cluster *garagev1alpha1.GarageCluster) (*corev1.Secret, error) {
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
		storageCluster := &garagev1alpha1.GarageCluster{}
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
			"rpc-secret": rpcSecret,
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
func (r *GarageClusterReconciler) reconcileConfigMap(ctx context.Context, cluster *garagev1alpha1.GarageCluster) (string, error) {
	log := logf.FromContext(ctx)
	configMapName := cluster.Name + "-config"

	garageConfig := r.generateGarageConfig(cluster)

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
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, existing)
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

func (r *GarageClusterReconciler) generateGarageConfig(cluster *garagev1alpha1.GarageCluster) string {
	var config strings.Builder

	// Both storage and gateway clusters use /data paths for consistency.
	// Gateway clusters use StatefulSet with metadata PVC (for node identity persistence)
	// and EmptyDir for data (since gateways don't store blocks).
	config.WriteString("metadata_dir = \"/data/metadata\"\n")
	config.WriteString("data_dir = \"/data/data\"\n")
	config.WriteString("\n")

	writeDBConfig(&config, cluster)
	writeReplicationConfig(&config, cluster)
	writeStorageConfig(&config, cluster)
	writeBlockConfig(&config, cluster)
	writeSecurityConfig(&config, cluster)
	writeWorkersConfig(&config, cluster)
	writeRPCConfig(&config, cluster)
	writeS3APIConfig(&config, cluster)
	writeK2VAPIConfig(&config, cluster)
	writeWebAPIConfig(&config, cluster)
	writeAdminConfig(&config, cluster)
	writeKubernetesDiscoveryConfig(&config, cluster)
	writeConsulDiscoveryConfig(&config, cluster)

	return config.String()
}

func writeDBConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
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

func writeReplicationConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	fmt.Fprintf(config, "replication_factor = %d\n", cluster.Spec.Replication.Factor)
	if cluster.Spec.Replication.ConsistencyMode != "" {
		fmt.Fprintf(config, "consistency_mode = \"%s\"\n", cluster.Spec.Replication.ConsistencyMode)
	}
}

func writeStorageConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Storage.MetadataFsync {
		config.WriteString("metadata_fsync = true\n")
	}
	if cluster.Spec.Storage.DataFsync {
		config.WriteString("data_fsync = true\n")
	}
	if cluster.Spec.Storage.MetadataSnapshotsDir != "" {
		fmt.Fprintf(config, "metadata_snapshots_dir = \"%s\"\n", cluster.Spec.Storage.MetadataSnapshotsDir)
	}
	if cluster.Spec.Storage.MetadataAutoSnapshotInterval != "" {
		fmt.Fprintf(config, "metadata_auto_snapshot_interval = \"%s\"\n", cluster.Spec.Storage.MetadataAutoSnapshotInterval)
	}
}

func writeBlockConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
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

func writeSecurityConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Security == nil {
		return
	}
	if cluster.Spec.Security.AllowWorldReadableSecrets {
		config.WriteString("allow_world_readable_secrets = true\n")
	}
	if cluster.Spec.Security.AllowPunycode {
		config.WriteString("allow_punycode = true\n")
	}
}

func writeWorkersConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Workers == nil {
		return
	}
	if cluster.Spec.Workers.ScrubTranquility != nil {
		fmt.Fprintf(config, "scrub_tranquility = %d\n", *cluster.Spec.Workers.ScrubTranquility)
	}
	if cluster.Spec.Workers.ResyncTranquility != nil {
		fmt.Fprintf(config, "resync_tranquility = %d\n", *cluster.Spec.Workers.ResyncTranquility)
	}
	if cluster.Spec.Workers.ResyncWorkerCount != nil {
		fmt.Fprintf(config, "resync_worker_count = %d\n", *cluster.Spec.Workers.ResyncWorkerCount)
	}
}

func writeRPCConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}
	fmt.Fprintf(config, "rpc_bind_addr = \"[::]:%d\"\n", rpcPort)
	config.WriteString("rpc_secret_file = \"/secrets/rpc/rpc-secret\"\n")

	if cluster.Spec.Network.RPCPublicAddr != "" {
		fmt.Fprintf(config, "rpc_public_addr = \"%s\"\n", cluster.Spec.Network.RPCPublicAddr)
	}
	if cluster.Spec.Network.RPCPublicAddrSubnet != "" {
		fmt.Fprintf(config, "rpc_public_addr_subnet = \"%s\"\n", cluster.Spec.Network.RPCPublicAddrSubnet)
	}
	if cluster.Spec.Network.RPCBindOutgoing {
		config.WriteString("rpc_bind_outgoing = true\n")
	}
	if cluster.Spec.Network.RPCPingTimeoutMs != nil {
		fmt.Fprintf(config, "rpc_ping_timeout_msec = %d\n", *cluster.Spec.Network.RPCPingTimeoutMs)
	}
	if cluster.Spec.Network.RPCTimeoutMs != nil {
		fmt.Fprintf(config, "rpc_timeout_msec = %d\n", *cluster.Spec.Network.RPCTimeoutMs)
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

func writeS3APIConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.S3API != nil && !cluster.Spec.S3API.Enabled {
		return
	}
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
	region := "garage"
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		region = cluster.Spec.S3API.Region
	}
	fmt.Fprintf(config, "s3_region = \"%s\"\n", region)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.RootDomain != "" {
		fmt.Fprintf(config, "root_domain = \"%s\"\n", cluster.Spec.S3API.RootDomain)
	}
}

func writeK2VAPIConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.K2VAPI == nil || !cluster.Spec.K2VAPI.Enabled {
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

func writeWebAPIConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.WebAPI == nil || !cluster.Spec.WebAPI.Enabled || cluster.Spec.WebAPI.RootDomain == "" {
		return
	}
	config.WriteString("\n[s3_web]\n")
	if cluster.Spec.WebAPI.BindAddress != "" {
		fmt.Fprintf(config, "bind_addr = \"%s\"\n", cluster.Spec.WebAPI.BindAddress)
	} else {
		webPort := int32(3902)
		if cluster.Spec.WebAPI.BindPort != 0 {
			webPort = cluster.Spec.WebAPI.BindPort
		}
		fmt.Fprintf(config, "bind_addr = \"[::]:%d\"\n", webPort)
	}
	fmt.Fprintf(config, "root_domain = \"%s\"\n", cluster.Spec.WebAPI.RootDomain)
	if cluster.Spec.WebAPI.AddHostToMetrics {
		config.WriteString("add_host_to_metrics = true\n")
	}
}

func writeAdminConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Admin != nil && !cluster.Spec.Admin.Enabled {
		return
	}
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

func writeKubernetesDiscoveryConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Kubernetes == nil || !cluster.Spec.Discovery.Kubernetes.Enabled {
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

func writeConsulDiscoveryConfig(config *strings.Builder, cluster *garagev1alpha1.GarageCluster) {
	if cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Consul == nil || !cluster.Spec.Discovery.Consul.Enabled {
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
	if consul.CACert != "" {
		fmt.Fprintf(config, "ca_cert = \"%s\"\n", consul.CACert)
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

func (r *GarageClusterReconciler) reconcileHeadlessService(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
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
			"garage.rajsingh.info/cluster": cluster.Name,
		}
	}

	service := &corev1.Service{
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
					Name:       "rpc",
					Port:       rpcPort,
					TargetPort: intstr.FromInt32(rpcPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			PublishNotReadyAddresses: true,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return err
	}

	existing := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating headless Service", "name", serviceName)
		return r.Create(ctx, service)
	}
	if err != nil {
		return err
	}

	existing.Spec.Ports = service.Spec.Ports
	existing.Spec.Selector = service.Spec.Selector
	return r.Update(ctx, existing)
}

func (r *GarageClusterReconciler) reconcileAPIService(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name

	ports := []corev1.ServicePort{}

	// S3 API port
	if cluster.Spec.S3API == nil || cluster.Spec.S3API.Enabled {
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
	}

	// Admin API port
	if cluster.Spec.Admin == nil || cluster.Spec.Admin.Enabled {
		adminPort := int32(3903)
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		ports = append(ports, corev1.ServicePort{
			Name:       "admin",
			Port:       adminPort,
			TargetPort: intstr.FromInt32(adminPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	// K2V API port
	if cluster.Spec.K2VAPI != nil && cluster.Spec.K2VAPI.Enabled {
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
	if cluster.Spec.WebAPI != nil && cluster.Spec.WebAPI.Enabled {
		webPort := int32(3902)
		if cluster.Spec.WebAPI.BindPort != 0 {
			webPort = cluster.Spec.WebAPI.BindPort
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

	annotations := map[string]string{}
	if cluster.Spec.Network.Service != nil && cluster.Spec.Network.Service.Annotations != nil {
		annotations = cluster.Spec.Network.Service.Annotations
	}

	// For Manual mode, use cluster label selector so GarageNode pods are selected.
	// For Auto mode, use the standard cluster selector labels.
	selector := r.selectorLabelsForCluster(cluster)
	if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		selector = map[string]string{
			"garage.rajsingh.info/cluster": cluster.Name,
		}
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        serviceName,
			Namespace:   cluster.Namespace,
			Labels:      r.labelsForCluster(cluster),
			Annotations: annotations,
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

	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return err
	}

	existing := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating API Service", "name", serviceName)
		return r.Create(ctx, service)
	}
	if err != nil {
		return err
	}

	existing.Spec.Type = service.Spec.Type
	existing.Spec.Selector = service.Spec.Selector
	existing.Spec.Ports = service.Spec.Ports
	existing.Spec.PublishNotReadyAddresses = service.Spec.PublishNotReadyAddresses
	existing.Annotations = service.Annotations
	return r.Update(ctx, existing)
}

// buildContainerPorts returns the container ports for the Garage StatefulSet
func buildContainerPorts(cluster *garagev1alpha1.GarageCluster) []corev1.ContainerPort {
	ports := []corev1.ContainerPort{}

	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}
	ports = append(ports, corev1.ContainerPort{Name: "rpc", ContainerPort: rpcPort})

	if cluster.Spec.S3API == nil || cluster.Spec.S3API.Enabled {
		s3Port := int32(3900)
		if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
			s3Port = cluster.Spec.S3API.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "s3", ContainerPort: s3Port})
	}

	if cluster.Spec.Admin == nil || cluster.Spec.Admin.Enabled {
		adminPort := int32(3903)
		if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "admin", ContainerPort: adminPort})
	}

	// K2V API port
	if cluster.Spec.K2VAPI != nil && cluster.Spec.K2VAPI.Enabled {
		k2vPort := int32(3904)
		if cluster.Spec.K2VAPI.BindPort != 0 {
			k2vPort = cluster.Spec.K2VAPI.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "k2v", ContainerPort: k2vPort})
	}

	// Web API port
	if cluster.Spec.WebAPI != nil && cluster.Spec.WebAPI.Enabled {
		webPort := int32(3902)
		if cluster.Spec.WebAPI.BindPort != 0 {
			webPort = cluster.Spec.WebAPI.BindPort
		}
		ports = append(ports, corev1.ContainerPort{Name: "web", ContainerPort: webPort})
	}

	return ports
}

// buildVolumesAndMounts returns volumes and volume mounts for the Garage StatefulSet.
// For gateway clusters, data volume is EmptyDir since gateways don't store blocks.
// Metadata volume comes from PVC (via VolumeClaimTemplates) for both gateway and storage.
func buildVolumesAndMounts(cluster *garagev1alpha1.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: "config", MountPath: "/etc/garage", ReadOnly: true},
		{Name: "rpc-secret", MountPath: "/secrets/rpc", ReadOnly: true},
		{Name: "metadata", MountPath: "/data/metadata"},
		{Name: "data", MountPath: "/data/data"},
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
	rpcSecretKey := "rpc-secret"
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
			Name: "rpc-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  rpcSecretName,
					DefaultMode: ptrInt32(0600),
					Items:       []corev1.KeyToPath{{Key: rpcSecretKey, Path: "rpc-secret"}},
				},
			},
		},
	}

	// Handle data volume for gateway clusters (EmptyDir since they don't store blocks)
	if cluster.Spec.Gateway {
		// Gateway clusters use EmptyDir for data since they don't store blocks.
		// The metadata PVC is provided via VolumeClaimTemplates for node identity persistence.
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	// Add admin token secret volume and mount if configured
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		adminTokenKey := DefaultAdminTokenKey
		if cluster.Spec.Admin.AdminTokenSecretRef.Key != "" {
			adminTokenKey = cluster.Spec.Admin.AdminTokenSecretRef.Key
		}
		volumes = append(volumes, corev1.Volume{
			Name: "admin-token",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  cluster.Spec.Admin.AdminTokenSecretRef.Name,
					DefaultMode: ptrInt32(0600),
					Items:       []corev1.KeyToPath{{Key: adminTokenKey, Path: "admin-token"}},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "admin-token",
			MountPath: "/secrets/admin",
			ReadOnly:  true,
		})
	}

	// Add metrics token secret volume and mount if configured separately from admin token
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.MetricsTokenSecretRef != nil {
		metricsTokenKey := "metrics-token"
		if cluster.Spec.Admin.MetricsTokenSecretRef.Key != "" {
			metricsTokenKey = cluster.Spec.Admin.MetricsTokenSecretRef.Key
		}
		volumes = append(volumes, corev1.Volume{
			Name: "metrics-token",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  cluster.Spec.Admin.MetricsTokenSecretRef.Name,
					DefaultMode: ptrInt32(0600),
					Items:       []corev1.KeyToPath{{Key: metricsTokenKey, Path: "metrics-token"}},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "metrics-token",
			MountPath: "/secrets/metrics",
			ReadOnly:  true,
		})
	}

	return volumes, volumeMounts
}

// buildVolumeClaimTemplates returns PVC templates for the Garage StatefulSet.
// For storage clusters: creates separate PVCs for metadata and data.
// For gateway clusters: creates only a small metadata PVC (for node identity persistence).
func buildVolumeClaimTemplates(cluster *garagev1alpha1.GarageCluster) []corev1.PersistentVolumeClaim {
	var templates []corev1.PersistentVolumeClaim

	// Gateway clusters only need a small metadata PVC for node identity (node_key files).
	// Data is stored in EmptyDir since gateways don't store blocks.
	if cluster.Spec.Gateway {
		// Default to 1Gi for gateway metadata - only stores node_key, peer_list, cluster_layout
		metadataStorageSize := resource.MustParse("1Gi")
		if cluster.Spec.Storage.Metadata != nil && !cluster.Spec.Storage.Metadata.Size.IsZero() {
			metadataStorageSize = cluster.Spec.Storage.Metadata.Size
		}

		metadataPVC := corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata"},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: metadataStorageSize,
					},
				},
			},
		}

		if cluster.Spec.Storage.Metadata != nil && cluster.Spec.Storage.Metadata.StorageClassName != nil {
			metadataPVC.Spec.StorageClassName = cluster.Spec.Storage.Metadata.StorageClassName
		}

		templates = append(templates, metadataPVC)
		return templates
	}

	// Storage clusters need both metadata and data PVCs

	// Metadata PVC - smaller, benefits from fast storage (SSD)
	metadataStorageSize := resource.MustParse("10Gi")
	if cluster.Spec.Storage.Metadata != nil && !cluster.Spec.Storage.Metadata.Size.IsZero() {
		metadataStorageSize = cluster.Spec.Storage.Metadata.Size
	}

	metadataPVC := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "metadata"},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: metadataStorageSize,
				},
			},
		},
	}

	// Set metadata storage class
	if cluster.Spec.Storage.Metadata != nil && cluster.Spec.Storage.Metadata.StorageClassName != nil {
		metadataPVC.Spec.StorageClassName = cluster.Spec.Storage.Metadata.StorageClassName
	}

	templates = append(templates, metadataPVC)

	// Data PVC - larger, can use cheaper storage (HDD)
	dataStorageSize := resource.MustParse("100Gi")
	if cluster.Spec.Storage.Data != nil && cluster.Spec.Storage.Data.Size != nil && !cluster.Spec.Storage.Data.Size.IsZero() {
		dataStorageSize = *cluster.Spec.Storage.Data.Size
	}

	dataPVC := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data"},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: dataStorageSize,
				},
			},
		},
	}

	// Set data storage class
	if cluster.Spec.Storage.Data != nil && cluster.Spec.Storage.Data.StorageClassName != nil {
		dataPVC.Spec.StorageClassName = cluster.Spec.Storage.Data.StorageClassName
	}

	templates = append(templates, dataPVC)

	return templates
}

// buildPVCRetentionPolicy returns the PVC retention policy for the StatefulSet.
// This controls whether PVCs are deleted when the StatefulSet is deleted or scaled down.
// Defaults to Retain for both policies (preserving existing behavior).
func buildPVCRetentionPolicy(cluster *garagev1alpha1.GarageCluster) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
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
func (r *GarageClusterReconciler) reconcileStatefulSet(ctx context.Context, cluster *garagev1alpha1.GarageCluster, configHash string) error {
	log := logf.FromContext(ctx)
	stsName := cluster.Name

	image := defaultGarageImage
	if cluster.Spec.Image != "" {
		image = cluster.Spec.Image
	}

	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	containerPorts := buildContainerPorts(cluster)
	volumes, volumeMounts := buildVolumesAndMounts(cluster)
	volumeClaimTemplates := buildVolumeClaimTemplates(cluster)

	env := []corev1.EnvVar{{
		Name:      "GARAGE_NODE_HOST",
		ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}},
	}}

	// Add logging environment variables
	if cluster.Spec.Logging != nil {
		if cluster.Spec.Logging.Level != "" {
			env = append(env, corev1.EnvVar{Name: "RUST_LOG", Value: cluster.Spec.Logging.Level})
		}
		if cluster.Spec.Logging.Syslog {
			env = append(env, corev1.EnvVar{Name: "GARAGE_LOG_TO_SYSLOG", Value: "1"})
		}
		if cluster.Spec.Logging.Journald {
			env = append(env, corev1.EnvVar{Name: "GARAGE_LOG_TO_JOURNALD", Value: "1"})
		}
	}

	container := corev1.Container{
		Name:            "garage",
		Image:           image,
		ImagePullPolicy: cluster.Spec.ImagePullPolicy,
		Command:         []string{"/garage", "-c", "/etc/garage/garage.toml", "server"},
		Ports:           containerPorts,
		VolumeMounts:    volumeMounts,
		Env:             env,
		Resources:       cluster.Spec.Resources,
	}

	if cluster.Spec.ContainerSecurityContext != nil {
		container.SecurityContext = cluster.Spec.ContainerSecurityContext
	}

	podSpec := corev1.PodSpec{
		Containers:         []corev1.Container{container},
		Volumes:            volumes,
		ServiceAccountName: cluster.Spec.ServiceAccountName,
		NodeSelector:       cluster.Spec.NodeSelector,
		Tolerations:        cluster.Spec.Tolerations,
		Affinity:           cluster.Spec.Affinity,
		ImagePullSecrets:   cluster.Spec.ImagePullSecrets,
	}

	// For gateway clusters using EmptyDir for data, we need to create the garage-marker file
	// that Garage requires to prevent accidental data directory confusion.
	// We use busybox because the Garage image is distroless (no shell utilities).
	if cluster.Spec.Gateway {
		initContainer := corev1.Container{
			Name:    "init-marker",
			Image:   "busybox:1.37",
			Command: []string{"touch", "/data/data/garage-marker"},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "data", MountPath: "/data/data"},
			},
			SecurityContext: buildInitContainerSecurityContext(cluster),
		}
		podSpec.InitContainers = []corev1.Container{initContainer}
	}

	if cluster.Spec.SecurityContext != nil {
		podSpec.SecurityContext = cluster.Spec.SecurityContext
	}
	if cluster.Spec.PriorityClassName != "" {
		podSpec.PriorityClassName = cluster.Spec.PriorityClassName
	}
	if len(cluster.Spec.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = cluster.Spec.TopologySpreadConstraints
	}

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

// cleanupOldDeployment removes the old Deployment that was used for gateway clusters
// before switching to StatefulSet. This handles migration from the old implementation.
func (r *GarageClusterReconciler) cleanupOldDeployment(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
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

func (r *GarageClusterReconciler) reconcilePDB(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
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
		val := intstr.Parse(*cluster.Spec.PodDisruptionBudget.MinAvailable)
		pdb.Spec.MinAvailable = &val
	} else if cluster.Spec.PodDisruptionBudget.MaxUnavailable != nil {
		val := intstr.Parse(*cluster.Spec.PodDisruptionBudget.MaxUnavailable)
		pdb.Spec.MaxUnavailable = &val
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
	if !reflect.DeepEqual(existing.Spec.MinAvailable, pdb.Spec.MinAvailable) ||
		!reflect.DeepEqual(existing.Spec.MaxUnavailable, pdb.Spec.MaxUnavailable) {
		existing.Spec = pdb.Spec
		log.Info("Updating PDB", "name", cluster.Name)
		return r.Update(ctx, existing)
	}

	return nil
}

func (r *GarageClusterReconciler) updateStatus(ctx context.Context, cluster *garagev1alpha1.GarageCluster, phase string, err error) (ctrl.Result, error) {
	cluster.Status.Phase = phase
	// Only set ObservedGeneration when reconciliation succeeded
	if err == nil {
		cluster.Status.ObservedGeneration = cluster.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "Error",
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

func (r *GarageClusterReconciler) updateStatusFromCluster(ctx context.Context, cluster *garagev1alpha1.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Get workload status
	var readyReplicas int32
	var desiredReplicas int32

	isManualMode := cluster.Spec.LayoutPolicy == LayoutPolicyManual

	if isManualMode {
		// Manual mode: count ready GarageNodes that reference this cluster
		nodeList := &garagev1alpha1.GarageNodeList{}
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

	// Try to get cluster health from Garage Admin API
	adminPort := getAdminPort(cluster)
	adminEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, adminPort)
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
			cluster.Status.Health = &garagev1alpha1.ClusterHealth{
				Status:           health.Status,
				Healthy:          health.ConnectedNodes == health.StorageNodes,
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
						cluster.Status.BuildInfo = &garagev1alpha1.GarageBuildInfo{
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
					cluster.Status.StorageStats = &garagev1alpha1.ClusterStorageStats{
						TotalCapacity:     *resource.NewQuantity(int64(totalData), resource.BinarySI),
						UsedCapacity:      *resource.NewQuantity(int64(totalData-availableData), resource.BinarySI),
						AvailableCapacity: *resource.NewQuantity(int64(availableData), resource.BinarySI),
					}
				}
				cluster.Status.DrainingNodes = drainingCount
			}
			cluster.Status.LayoutVersion = status.LayoutVersion
		}

		// Fetch layout history to track draining versions
		history, err := garageClient.GetClusterLayoutHistory(ctx)
		if err != nil {
			log.V(1).Info("Failed to get cluster layout history", "error", err)
		} else {
			cluster.Status.LayoutHistory = &garagev1alpha1.LayoutHistoryStatus{
				CurrentVersion: history.CurrentVersion,
				MinAck:         history.MinAck,
			}
			for _, v := range history.Versions {
				cluster.Status.LayoutHistory.Versions = append(cluster.Status.LayoutHistory.Versions, garagev1alpha1.LayoutVersionInfo{
					Version:      v.Version,
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
	}

	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               "Ready",
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
	cluster.Status.Endpoints = &garagev1alpha1.ClusterEndpoints{
		S3:    fmt.Sprintf("%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, s3Port),
		Admin: fmt.Sprintf("%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, adminPort),
		RPC:   fmt.Sprintf("%s-headless.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, rpcPort),
	}

	if err := UpdateStatusWithRetry(ctx, r.Client, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue faster when cluster is unhealthy to speed up recovery
	if cluster.Status.Health != nil && cluster.Status.Health.Status != healthStatusHealthy {
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// Requeue for periodic health checks
	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

func (r *GarageClusterReconciler) labelsForCluster(cluster *garagev1alpha1.GarageCluster) map[string]string {
	component := "storage"
	if cluster.Spec.Gateway {
		component = "gateway"
	}
	return map[string]string{
		"app.kubernetes.io/name":       "garage",
		"app.kubernetes.io/instance":   cluster.Name,
		"app.kubernetes.io/managed-by": "garage-operator",
		"app.kubernetes.io/component":  component,
	}
}

func (r *GarageClusterReconciler) selectorLabelsForCluster(cluster *garagev1alpha1.GarageCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "garage",
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
	hasRemoteClusters      bool   // Skip replication check if federation will bring nodes
	forceLayoutApply       bool   // Manual override via annotation
	isGateway              bool   // Gateway clusters have nil capacity
	clusterName            string // Cluster name used to identify nodes belonging to this cluster (via exact tag match)
	namespace              string // Namespace used together with clusterName for unique node identification
}

// getAdminPort returns the configured admin port for the cluster
func getAdminPort(cluster *garagev1alpha1.GarageCluster) int32 {
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		return cluster.Spec.Admin.BindPort
	}
	return 3903
}

// getRPCPort returns the configured RPC port for the cluster
func getRPCPort(cluster *garagev1alpha1.GarageCluster) int32 {
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
		endpoint := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, adminPort)
		garageClient := garage.NewClient(endpoint, adminToken)

		status, err := garageClient.GetClusterStatus(ctx)
		if err != nil {
			log.V(1).Info("Failed to get status from pod", "pod", pod.Name, "error", err)
			continue
		}

		log.V(1).Info("Got cluster status from pod", "pod", pod.Name, "nodeCount", len(status.Nodes))

		// Find the node that corresponds to this pod by matching IP address
		// In a federated cluster, the queried pod sees all nodes as IsUp, so we must
		// match the node's advertised address to the pod's IP to find the correct node ID
		var foundNode *garage.NodeInfo
		for i := range status.Nodes {
			node := &status.Nodes[i]
			hasAddr := node.Address != nil
			log.V(1).Info("Checking node", "nodeId", node.ID, "isUp", node.IsUp, "hasAddress", hasAddr, "addr", node.Address)

			if !node.IsUp {
				continue
			}

			// Match by IP address - the node's address contains IP:port, extract IP
			if node.Address != nil {
				nodeIP := *node.Address
				if colonIdx := strings.LastIndex(nodeIP, ":"); colonIdx > 0 {
					nodeIP = nodeIP[:colonIdx]
				}
				if nodeIP == pod.Status.PodIP {
					foundNode = node
					break
				}
			}
		}

		// If no IP match found, try hostname matching (pod name == garage hostname)
		// This handles cases where the node hasn't advertised its address yet
		if foundNode == nil {
			for i := range status.Nodes {
				node := &status.Nodes[i]
				if node.IsUp && node.Hostname != nil && *node.Hostname == pod.Name {
					foundNode = node
					log.V(1).Info("Matched node by hostname", "nodeId", foundNode.ID, "hostname", pod.Name)
					break
				}
			}
		}

		// If still no match, skip this pod - it hasn't fully joined the cluster yet
		// Don't use fallback to "first IsUp node" as that can pick wrong nodes in federated clusters
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
		endpoint := fmt.Sprintf("http://%s:%d", node.podIP, adminPort)
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
		endpoint := fmt.Sprintf("http://%s:%d", sourceNode.podIP, adminPort)
		nodeClient := garage.NewClient(endpoint, adminToken)

		for _, targetNode := range nodes {
			if targetNode.id == sourceNode.id {
				continue // Skip self
			}
			addr := fmt.Sprintf("%s:%d", targetNode.podIP, rpcPort)
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

// buildExistingNodesMap creates a map of nodes that already exist in layout or staged changes
func buildExistingNodesMap(layout *garage.ClusterLayout) map[string]bool {
	existingNodes := make(map[string]bool)
	for _, role := range layout.Roles {
		existingNodes[role.ID] = true
	}
	for _, change := range layout.StagedRoleChanges {
		if !change.Remove {
			existingNodes[change.ID] = true
		}
	}
	return existingNodes
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

// assignNewNodesToLayout assigns undiscovered nodes to the cluster layout
func assignNewNodesToLayout(ctx context.Context, garageClient *garage.Client, nodes []bootstrapNodeInfo, cfg layoutConfig) error {
	log := logf.FromContext(ctx)

	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	existingNodes := buildExistingNodesMap(layout)
	effectiveCapacity := calculateEffectiveCapacity(cfg.capacity, cfg.capacityReservePercent)

	zone := cfg.zone
	if zone == "" {
		zone = "default"
	}

	// Find new nodes to add
	newRoles := make([]garage.NodeRoleChange, 0, len(nodes))
	for _, node := range nodes {
		if existingNodes[node.id] {
			log.V(1).Info("Node already in layout or staged", "nodeId", node.id, "podName", node.podName)
			continue
		}
		// Build tags with cluster ownership tag for unique identification
		tags := buildNodeTags(cfg.clusterName, cfg.namespace, cfg.tags, node.podName)
		role := garage.NodeRoleChange{
			ID:   node.id,
			Zone: zone,
			Tags: tags,
		}
		// Gateway nodes have nil capacity (they don't store data)
		if cfg.isGateway {
			role.Capacity = nil
		} else {
			capacity := effectiveCapacity
			role.Capacity = &capacity
		}
		newRoles = append(newRoles, role)
	}

	// Build running nodes map for stale detection
	runningNodes := make(map[string]bool)
	for _, node := range nodes {
		runningNodes[node.id] = true
	}

	// Find stale nodes that belong to this cluster (identified by exact clusterName tag match).
	// This prevents accidentally removing nodes from other clusters (e.g., a gateway cluster
	// shouldn't remove storage nodes, and vice versa).
	staleRoles := findStaleNodes(ctx, layout, zone, runningNodes, cfg.clusterName, cfg.namespace)
	allChanges := append(newRoles, staleRoles...)

	// Stage changes if any
	if len(allChanges) > 0 {
		if len(newRoles) > 0 {
			log.Info("Adding nodes to cluster layout", "count", len(newRoles))
		}
		if len(staleRoles) > 0 {
			log.Info("Removing stale nodes from cluster layout", "count", len(staleRoles))
		}
		if err := garageClient.UpdateClusterLayout(ctx, allChanges); err != nil {
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
func (r *GarageClusterReconciler) bootstrapCluster(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
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
		clusterName: cluster.Name,
		namespace:   cluster.Namespace,
	}
	if cluster.Spec.Replication.Factor > 0 {
		cfg.replicationFactor = cluster.Spec.Replication.Factor
	}
	// Check for force-layout-apply annotation
	if cluster.Annotations != nil {
		if val, ok := cluster.Annotations[garagev1alpha1.AnnotationForceLayoutApply]; ok && val == "true" {
			cfg.forceLayoutApply = true
		}
	}

	// Calculate capacity from storage config
	cfg.capacity = r.calculateNodeCapacity(cluster)

	// For gateway clusters with clusterRef, use the storage cluster's Admin API for layout operations.
	// The layout is a shared global state, so we need to modify the storage cluster's layout,
	// not create a new one on the gateway.
	layoutClient := bootstrapClient
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		storageClusterClient, err := r.getStorageClusterClient(ctx, cluster)
		if err != nil {
			// CRITICAL: Don't add gateway nodes to the gateway's own layout!
			// If we can't reach the storage cluster, skip layout management entirely.
			// The gateway will be added to the storage cluster's layout on the next reconcile
			// when the storage cluster becomes reachable.
			log.Info("Waiting for storage cluster to be reachable before adding gateway to layout", "error", err)
			return nil
		}
		if storageClusterClient == nil {
			log.Info("Storage cluster client is nil, skipping layout management")
			return nil
		}
		layoutClient = storageClusterClient
		log.V(1).Info("Using storage cluster Admin API for layout operations")
	}

	return assignNewNodesToLayout(ctx, layoutClient, nodes, cfg)
}

// calculateNodeCapacity determines node capacity from cluster storage config
func (r *GarageClusterReconciler) calculateNodeCapacity(cluster *garagev1alpha1.GarageCluster) uint64 {
	// Default to 10GB if no storage config
	const defaultCapacity uint64 = 10 * 1024 * 1024 * 1024

	if cluster.Spec.Storage.Data != nil {
		if cluster.Spec.Storage.Data.Size != nil {
			return uint64(cluster.Spec.Storage.Data.Size.Value())
		}
		// Sum capacity from data paths if using multiple paths
		if len(cluster.Spec.Storage.Data.Paths) > 0 {
			var total uint64
			for _, path := range cluster.Spec.Storage.Data.Paths {
				if path.Capacity != nil {
					total += uint64(path.Capacity.Value())
				} else if path.Volume != nil && !path.Volume.Size.IsZero() {
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

// getStorageClusterClient returns an Admin API client for the storage cluster
// that this gateway cluster is connected to. It verifies connectivity before returning.
func (r *GarageClusterReconciler) getStorageClusterClient(ctx context.Context, cluster *garagev1alpha1.GarageCluster) (*garage.Client, error) {
	if cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.ClusterRef == nil {
		return nil, fmt.Errorf("no clusterRef configured")
	}

	// Get the storage cluster
	storageCluster := &garagev1alpha1.GarageCluster{}
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
	endpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d",
		storageCluster.Name, storageCluster.Namespace, adminPort)

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
func (r *GarageClusterReconciler) reconcileGatewayConnection(ctx context.Context, cluster *garagev1alpha1.GarageCluster) {
	log := logf.FromContext(ctx)

	if !cluster.Spec.Gateway || cluster.Spec.ConnectTo == nil {
		return
	}

	// Get the gateway cluster's admin client
	gatewayAdminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || gatewayAdminToken == "" {
		log.V(1).Info("Gateway admin token not available, skipping connection")
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
			endpoint := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, adminPort)
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
		r.connectGatewayToExternalCluster(ctx, cluster, gatewayClient)
	}
}

// connectGatewayToClusterRef connects a gateway to a storage cluster referenced by clusterRef.
// It establishes bidirectional connectivity: gateway → storage AND storage → gateway.
// This is important when gateway pods restart with new IPs - the storage cluster needs
// to learn the gateway's new address to re-establish the connection.
func (r *GarageClusterReconciler) connectGatewayToClusterRef(ctx context.Context, cluster *garagev1alpha1.GarageCluster, gatewayClient *garage.Client) {
	log := logf.FromContext(ctx)

	storageCluster := &garagev1alpha1.GarageCluster{}
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
			endpoint := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, storageAdminPort)
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

// connectGatewayToExternalCluster connects a gateway to an external storage cluster via Admin API endpoint.
func (r *GarageClusterReconciler) connectGatewayToExternalCluster(ctx context.Context, cluster *garagev1alpha1.GarageCluster, gatewayClient *garage.Client) {
	log := logf.FromContext(ctx)

	// Get admin token for external cluster
	var adminToken string
	if cluster.Spec.ConnectTo.AdminTokenSecretRef != nil {
		secret := &corev1.Secret{}
		secretRef := cluster.Spec.ConnectTo.AdminTokenSecretRef
		if err := r.Get(ctx, types.NamespacedName{Name: secretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
			log.V(1).Info("Failed to get external admin token secret", "error", err)
			return
		}
		key := secretRef.Key
		if key == "" {
			key = "admin-token"
		}
		adminToken = string(secret.Data[key])
	}

	if adminToken == "" {
		log.V(1).Info("No admin token for external storage cluster")
		return
	}

	// Create client for external cluster
	externalClient := garage.NewClient(cluster.Spec.ConnectTo.AdminAPIEndpoint, adminToken)

	// Get external cluster status
	status, err := externalClient.GetClusterStatus(ctx)
	if err != nil {
		log.V(1).Info("Failed to get external cluster status", "endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint, "error", err)
		return
	}

	// Connect gateway to each external node
	connectedCount := 0
	for _, node := range status.Nodes {
		if node.Address != nil && *node.Address != "" {
			if _, err := gatewayClient.ConnectNode(ctx, node.ID, *node.Address); err != nil {
				log.V(1).Info("Failed to connect to external node", "nodeID", node.ID[:16]+"...", "address", *node.Address, "error", err)
			} else {
				connectedCount++
			}
		}
	}

	if connectedCount > 0 {
		log.Info("Gateway connected to external storage cluster", "endpoint", cluster.Spec.ConnectTo.AdminAPIEndpoint, "nodesConnected", connectedCount)
	}
}

// reconcileFederation connects this cluster to remote Garage clusters.
// It queries remote Admin APIs to discover node IDs and connects them.
// Errors are logged but not returned to avoid blocking reconciliation.
func (r *GarageClusterReconciler) reconcileFederation(ctx context.Context, cluster *garagev1alpha1.GarageCluster) {
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
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			endpoint := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, adminPort)
			testClient := garage.NewClient(endpoint, adminToken)
			// Try to reach this pod - don't require healthy, just reachable
			if _, err := testClient.GetClusterStatus(ctx); err == nil {
				localClient = testClient
				break
			}
		}
	}

	if localClient == nil {
		log.V(1).Info("No reachable local pods for federation")
		return
	}

	// Process each remote cluster - don't require local cluster to be healthy
	// Federation is needed to BECOME healthy in multi-cluster setups
	for _, remote := range cluster.Spec.RemoteClusters {
		if err := r.connectToRemoteCluster(ctx, cluster, localClient, remote); err != nil {
			log.V(1).Info("Failed to connect to remote cluster", "name", remote.Name, "error", err)
			// Continue with other remotes
		}
	}
}

// connectToRemoteCluster discovers nodes from a remote cluster and connects them.
func (r *GarageClusterReconciler) connectToRemoteCluster(
	ctx context.Context,
	cluster *garagev1alpha1.GarageCluster,
	localClient *garage.Client,
	remote garagev1alpha1.RemoteClusterConfig,
) error {
	log := logf.FromContext(ctx)

	// Skip self-connection: if remote zone matches local zone, this is likely
	// the same cluster listed in remoteClusters (common in templated deployments)
	if remote.Zone == cluster.Spec.Zone {
		log.V(1).Info("Skipping self-connection (remote zone matches local zone)", "zone", remote.Zone)
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

	// Query remote cluster for nodes
	remoteClient := garage.NewClient(remoteEndpoint, remoteToken)
	remoteStatus, err := remoteClient.GetClusterStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get remote cluster status: %w", err)
	}

	// Determine RPC port from cluster spec or use default
	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	// Connect to each node in the remote cluster
	// Note: We connect to ALL nodes, including those without a role.
	// During bootstrap, nodes may not be in the layout yet but we still
	// need to establish connections so they can be discovered and added.
	connectedCount := 0
	for _, node := range remoteStatus.Nodes {
		// Determine the address to use for connection
		// IMPORTANT: We use the remote cluster's hostname (from adminApiEndpoint)
		// instead of the node's advertised address. This is because:
		// 1. Nodes may advertise their local proxy IP which isn't routable cross-cluster
		// 2. The admin endpoint hostname is the Tailscale service that routes to all nodes
		// 3. Tailscale handles the actual routing to the correct pod
		var addr string
		if remoteRPCHost != "" {
			// Use the remote cluster's hostname for cross-cluster connectivity
			addr = fmt.Sprintf("%s:%d", remoteRPCHost, rpcPort)
		} else if node.Address != nil && *node.Address != "" {
			// Fall back to node's advertised address if we can't parse the endpoint
			addr = *node.Address
		} else {
			log.V(1).Info("Remote node has no address", "nodeID", node.ID[:16]+"...")
			continue
		}

		// Connect local cluster to this remote node
		result, err := localClient.ConnectNode(ctx, node.ID, addr)
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

	// Add remote nodes to local layout for data replication
	if err := r.addRemoteNodesToLayout(ctx, cluster, localClient, remoteClient, remoteStatus, remote); err != nil {
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
func (r *GarageClusterReconciler) addRemoteNodesToLayout(
	ctx context.Context,
	cluster *garagev1alpha1.GarageCluster,
	localClient *garage.Client,
	remoteClient *garage.Client,
	remoteStatus *garage.ClusterStatus,
	remote garagev1alpha1.RemoteClusterConfig,
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

	// Get remote layout to check for staged role changes
	// This helps during bootstrap when remote nodes haven't been committed yet
	remoteLayout, err := remoteClient.GetClusterLayout(ctx)
	if err != nil {
		log.V(1).Info("Failed to get remote layout, will use committed roles only", "error", err)
		remoteLayout = nil
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

	// Build role changes for missing remote nodes
	newRoles := make([]garage.NodeRoleChange, 0, len(remoteStatus.Nodes))
	for _, node := range remoteStatus.Nodes {
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

	// Parse and include zone redundancy from cluster spec for consistency
	if cluster.Spec.Replication.ZoneRedundancy != "" {
		zr, err := garage.ParseZoneRedundancy(cluster.Spec.Replication.ZoneRedundancy)
		if err != nil {
			log.V(1).Info("Invalid zone redundancy in spec, ignoring", "value", cluster.Spec.Replication.ZoneRedundancy, "error", err)
		} else {
			layoutReq.Parameters = &garage.LayoutParameters{
				ZoneRedundancy: zr,
			}
			log.V(1).Info("Including zone redundancy in layout update", "zoneRedundancy", cluster.Spec.Replication.ZoneRedundancy)
		}
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

	// After adding nodes, check for stale remote nodes that were removed from the remote cluster
	if err := r.removeStaleRemoteNodes(ctx, localClient, layout, remoteStatus, remote); err != nil {
		// Don't fail the reconcile for stale node cleanup - just log
		log.Error(err, "Failed to remove stale remote nodes", "cluster", remote.Name)
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
	remote garagev1alpha1.RemoteClusterConfig,
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
	cluster *garagev1alpha1.GarageCluster,
	remote garagev1alpha1.RemoteClusterConfig,
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

		key := "admin-token"
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
func (r *GarageClusterReconciler) getAdminToken(ctx context.Context, cluster *garagev1alpha1.GarageCluster) (string, error) {
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
func (r *GarageClusterReconciler) handleOperationalAnnotations(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
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
	if _, ok := cluster.Annotations[garagev1alpha1.AnnotationSkipDeadNodes]; ok {
		if err := r.handleSkipDeadNodes(ctx, cluster); err != nil {
			return err
		}

		// Remove annotations after processing
		delete(cluster.Annotations, garagev1alpha1.AnnotationSkipDeadNodes)
		delete(cluster.Annotations, garagev1alpha1.AnnotationAllowMissingData)
		if err := r.Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to remove skip-dead-nodes annotation")
			return err
		}
		log.Info("Processed and removed skip-dead-nodes annotation")
	}

	return nil
}

// handleConnectNodes connects the cluster to external nodes specified in the annotation.
// Format: "nodeId@addr:port,nodeId2@addr2:port2,..."
// This is useful for multi-cluster federation where node IDs are known.
func (r *GarageClusterReconciler) handleConnectNodes(ctx context.Context, cluster *garagev1alpha1.GarageCluster, connections string) error {
	log := logf.FromContext(ctx)

	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		return fmt.Errorf("admin token required for connect-nodes operation")
	}

	adminPort := getAdminPort(cluster)
	adminEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, adminPort)
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
func (r *GarageClusterReconciler) handleSkipDeadNodes(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := logf.FromContext(ctx)

	adminToken, err := r.getAdminToken(ctx, cluster)
	if err != nil || adminToken == "" {
		return fmt.Errorf("admin token required for skip-dead-nodes operation")
	}

	adminPort := getAdminPort(cluster)
	adminEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", cluster.Name, cluster.Namespace, adminPort)
	garageClient := garage.NewClient(adminEndpoint, adminToken)

	// Get current layout to determine version
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Check if allow-missing-data annotation is set
	allowMissingData := false
	if val, ok := cluster.Annotations[garagev1alpha1.AnnotationAllowMissingData]; ok && val == "true" {
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1alpha1.GarageCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Named("garagecluster").
		Complete(r)
}

// ptrInt32 returns a pointer to an int32
func ptrInt32(i int32) *int32 {
	return &i
}

// ptrInt64 returns a pointer to an int64
func ptrInt64(i int64) *int64 {
	return &i
}

// ptrBool returns a pointer to a bool
func ptrBool(b bool) *bool {
	return &b
}

// buildInitContainerSecurityContext returns the security context for init containers.
// Uses the user's ContainerSecurityContext if specified, otherwise returns a hardened default.
func buildInitContainerSecurityContext(cluster *garagev1alpha1.GarageCluster) *corev1.SecurityContext {
	if cluster.Spec.ContainerSecurityContext != nil {
		return cluster.Spec.ContainerSecurityContext
	}
	// Default hardened security context matching distroless nonroot user
	return &corev1.SecurityContext{
		RunAsNonRoot:             ptrBool(true),
		RunAsUser:                ptrInt64(65532), // nonroot user in distroless
		AllowPrivilegeEscalation: ptrBool(false),
		ReadOnlyRootFilesystem:   ptrBool(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
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
