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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	garageNodeFinalizer = "garagenode.garage.rajsingh.info/finalizer"
)

// GarageNodeReconciler reconciles a GarageNode object
type GarageNodeReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClusterDomain string
	DefaultImage  string
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create

func (r *GarageNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	node := &garagev1beta1.GarageNode{}
	if err := r.Get(ctx, req.NamespacedName, node); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Get the cluster reference
	cluster := &garagev1beta1.GarageCluster{}
	clusterNamespace := node.Namespace
	if node.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = node.Spec.ClusterRef.Namespace
	}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      node.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cluster not found: %w", err))
	}

	// Handle deletion
	if !node.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
			// Get garage client for finalization
			garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
			if err != nil {
				log.Error(err, "Failed to get garage client for finalization")
			} else {
				if err := r.finalize(ctx, node, garageClient); err != nil {
					if ShouldSkipFinalization(node) {
						log.Info("Finalization failed too many times, removing finalizer anyway",
							"retries", GetFinalizationRetryCount(node), "error", err)
					} else {
						IncrementFinalizationRetryCount(node)
						retryCount := GetFinalizationRetryCount(node)
						log.Error(err, "Failed to finalize node, will retry",
							"retries", retryCount)
						if updateErr := r.Update(ctx, node); updateErr != nil {
							log.Error(updateErr, "Failed to update retry count annotation")
						}
						_, _ = r.updateStatus(ctx, node, PhaseDeleting, fmt.Errorf("finalization failed (retry %d/%d): %w", retryCount, FinalizationMaxRetries, err))
						return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
					}
				}
			}
			controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
			if err := r.Update(ctx, node); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
		controllerutil.AddFinalizer(node, garageNodeFinalizer)
		if err := r.Update(ctx, node); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile per-node RPC service when publicEndpoint is configured
	if node.Spec.External == nil && node.Spec.PublicEndpoint != nil {
		if err := r.reconcileNodeService(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("reconciling node service: %w", err))
		}
	}

	// Reconcile per-node ConfigMap when any node-specific config overrides are present
	if node.Spec.External == nil && nodeHasConfigOverrides(node) {
		if err := r.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("reconciling node config: %w", err))
		}
	}

	// For managed nodes (not external), create/update the StatefulSet
	if node.Spec.External == nil {
		if err := r.reconcileStatefulSet(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, err)
		}
	}

	// Get garage client for layout management
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to create garage client: %w", err))
	}

	// Reconcile the node layout
	if err := r.reconcileNode(ctx, node, cluster, garageClient); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, err)
	}

	return r.updateStatusFromGarage(ctx, node, garageClient)
}

// reconcileStatefulSet creates/updates the StatefulSet for a managed GarageNode.
// Each GarageNode creates its own StatefulSet with replica 1.
func (r *GarageNodeReconciler) reconcileStatefulSet(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) error {
	log := logf.FromContext(ctx)
	stsName := node.Name

	// Build merged pod config (cluster defaults + node overrides)
	image := mergeNodeImage(cluster.Spec.Image, cluster.Spec.ImageRepository, node.Spec.Image, node.Spec.ImageRepository, r.DefaultImage)

	resources := cluster.Spec.Resources
	if node.Spec.Resources != nil {
		resources = *node.Spec.Resources
	}

	nodeSelector := cluster.Spec.NodeSelector
	if node.Spec.NodeSelector != nil {
		nodeSelector = node.Spec.NodeSelector
	}

	tolerations := cluster.Spec.Tolerations
	if node.Spec.Tolerations != nil {
		tolerations = node.Spec.Tolerations
	}

	affinity := cluster.Spec.Affinity
	if node.Spec.Affinity != nil {
		affinity = node.Spec.Affinity
	}

	priorityClassName := cluster.Spec.PriorityClassName
	if node.Spec.PriorityClassName != "" {
		priorityClassName = node.Spec.PriorityClassName
	}

	// Build container ports (same as cluster)
	containerPorts := buildContainerPorts(cluster)

	// Build volumes and mounts for this node
	volumes, volumeMounts := r.buildNodeVolumesAndMounts(node, cluster)
	volumeClaimTemplates := r.buildNodeVolumeClaimTemplates(node)

	// Node-level pod config overrides (node takes precedence over cluster)
	imagePullPolicy := cluster.Spec.ImagePullPolicy
	if node.Spec.ImagePullPolicy != "" {
		imagePullPolicy = node.Spec.ImagePullPolicy
	}

	imagePullSecrets := cluster.Spec.ImagePullSecrets
	if node.Spec.ImagePullSecrets != nil {
		imagePullSecrets = node.Spec.ImagePullSecrets
	}

	serviceAccountName := cluster.Spec.ServiceAccountName
	if node.Spec.ServiceAccountName != "" {
		serviceAccountName = node.Spec.ServiceAccountName
	}

	containerSecurityContext := cluster.Spec.ContainerSecurityContext
	if node.Spec.ContainerSecurityContext != nil {
		containerSecurityContext = node.Spec.ContainerSecurityContext
	}

	securityContext := cluster.Spec.SecurityContext
	if node.Spec.SecurityContext != nil {
		securityContext = node.Spec.SecurityContext
	}

	topologySpreadConstraints := cluster.Spec.TopologySpreadConstraints
	if node.Spec.TopologySpreadConstraints != nil {
		topologySpreadConstraints = node.Spec.TopologySpreadConstraints
	}

	podSpec := buildGaragePodSpec(PodSpecConfig{
		Image:                     image,
		ImagePullPolicy:           imagePullPolicy,
		ImagePullSecrets:          imagePullSecrets,
		Resources:                 resources,
		NodeSelector:              nodeSelector,
		Tolerations:               tolerations,
		Affinity:                  affinity,
		PriorityClassName:         priorityClassName,
		ServiceAccountName:        serviceAccountName,
		SecurityContext:           securityContext,
		ContainerSecurityContext:  containerSecurityContext,
		TopologySpreadConstraints: topologySpreadConstraints,
		IsGateway:                 node.Spec.Gateway,
		Logging:                   cluster.Spec.Logging,
	}, volumes, volumeMounts, containerPorts)

	// Build labels: merge cluster labels + node-specific labels
	podLabels := r.labelsForNode(node, cluster)
	for k, v := range cluster.Spec.PodLabels {
		podLabels[k] = v
	}
	for k, v := range node.Spec.PodLabels {
		podLabels[k] = v
	}

	// Compute pod-spec-hash for change detection
	podSpecBytes, _ := json.Marshal(podSpec)
	podSpecHash := sha256.Sum256(podSpecBytes)
	podSpecHashStr := hex.EncodeToString(podSpecHash[:8])

	// Build annotations: merge cluster annotations + node-specific annotations
	podAnnotations := make(map[string]string)
	for k, v := range cluster.Spec.PodAnnotations {
		podAnnotations[k] = v
	}
	for k, v := range node.Spec.PodAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations["garage.rajsingh.info/pod-spec-hash"] = podSpecHashStr

	// Include the node ConfigMap content hash so pods restart when any per-node config changes.
	// Must match the hasNodeConfigOverrides condition used in buildNodeVolumesAndMounts.
	if nodeHasConfigOverrides(node) {
		nodeCM := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: node.Name + "-config", Namespace: cluster.Namespace}, nodeCM); err == nil {
			h := sha256.Sum256([]byte(nodeCM.Data["garage.toml"]))
			podAnnotations["garage.rajsingh.info/config-hash"] = hex.EncodeToString(h[:8])
		}
	}

	replicas := int32(1)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForNode(node, cluster),
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: cluster.Name + "-headless",
			Replicas:    &replicas,
			Selector:    &metav1.LabelSelector{MatchLabels: r.selectorLabelsForNode(node)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
			VolumeClaimTemplates: volumeClaimTemplates,
			PodManagementPolicy:  appsv1.ParallelPodManagement,
			UpdateStrategy:       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
		},
	}

	if err := controllerutil.SetControllerReference(node, sts, r.Scheme); err != nil {
		return err
	}

	existing := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating StatefulSet for GarageNode", "name", stsName)
		return r.Create(ctx, sts)
	}
	if err != nil {
		return err
	}

	// Check if update is needed
	needsUpdate := false
	existingPodSpecHash := existing.Spec.Template.Annotations["garage.rajsingh.info/pod-spec-hash"]
	if existingPodSpecHash != podSpecHashStr {
		log.Info("Pod spec hash changed, updating StatefulSet", "old", existingPodSpecHash, "new", podSpecHashStr)
		needsUpdate = true
	}
	// Also detect config-only changes (e.g. LB IP assigned, fsync override toggled)
	if !needsUpdate {
		existingConfigHash := existing.Spec.Template.Annotations["garage.rajsingh.info/config-hash"]
		newConfigHash := sts.Spec.Template.Annotations["garage.rajsingh.info/config-hash"]
		if existingConfigHash != newConfigHash {
			log.Info("Config hash changed, updating StatefulSet", "old", existingConfigHash, "new", newConfigHash)
			needsUpdate = true
		}
	}

	if !needsUpdate {
		return nil
	}

	existing.Spec.Template = sts.Spec.Template
	log.Info("Updating StatefulSet for GarageNode", "name", stsName)
	return r.Update(ctx, existing)
}

// buildNodeVolumesAndMounts returns volumes and volume mounts for a GarageNode's StatefulSet.
func (r *GarageNodeReconciler) buildNodeVolumesAndMounts(node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: "/etc/garage", ReadOnly: true},
		{Name: RPCSecretKey, MountPath: "/secrets/rpc", ReadOnly: true},
		{Name: metadataVolName, MountPath: "/data/metadata"},
		{Name: dataVolName, MountPath: dataPath},
	}

	// RPC secret: gateway clusters with ConnectTo use the storage cluster's RPC secret.
	// This mirrors the logic in buildVolumesAndMounts in garagecluster_controller.go.
	rpcSecretName := cluster.Name + "-rpc-secret"
	rpcSecretKey := RPCSecretKey
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil {
		if cluster.Spec.ConnectTo.RPCSecretRef != nil {
			rpcSecretName = cluster.Spec.ConnectTo.RPCSecretRef.Name
			if cluster.Spec.ConnectTo.RPCSecretRef.Key != "" {
				rpcSecretKey = cluster.Spec.ConnectTo.RPCSecretRef.Key
			}
		}
	} else if cluster.Spec.Network.RPCSecretRef != nil {
		rpcSecretName = cluster.Spec.Network.RPCSecretRef.Name
		if cluster.Spec.Network.RPCSecretRef.Key != "" {
			rpcSecretKey = cluster.Spec.Network.RPCSecretRef.Key
		}
	}

	// Use a per-node ConfigMap when any node-specific garage.toml overrides are present.
	// Otherwise fall back to the shared cluster ConfigMap.
	configMapName := cluster.Name + "-config"
	if nodeHasConfigOverrides(node) {
		configMapName = node.Name + "-config"
	}

	volumes := []corev1.Volume{
		{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
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

	// Handle data volume: gateway or EmptyDir type → EmptyDir; existingClaim → PVC inline; else → VolumeClaimTemplate
	if node.Spec.Gateway || (node.Spec.Storage != nil && node.Spec.Storage.Data != nil && node.Spec.Storage.Data.Type == garagev1beta1.VolumeTypeEmptyDir) {
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolName,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
	} else if node.Spec.Storage != nil && node.Spec.Storage.Data != nil && node.Spec.Storage.Data.ExistingClaim != "" {
		volumes = append(volumes, corev1.Volume{
			Name: dataVolName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: node.Spec.Storage.Data.ExistingClaim},
			},
		})
	}
	// else: data comes from VolumeClaimTemplate

	// Handle metadata volume: EmptyDir type → EmptyDir; existingClaim → PVC inline; else → VolumeClaimTemplate
	if node.Spec.Storage != nil && node.Spec.Storage.Metadata != nil {
		switch {
		case node.Spec.Storage.Metadata.Type == garagev1beta1.VolumeTypeEmptyDir:
			volumes = append(volumes, corev1.Volume{
				Name:         metadataVolName,
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			})
		case node.Spec.Storage.Metadata.ExistingClaim != "":
			volumes = append(volumes, corev1.Volume{
				Name: metadataVolName,
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: node.Spec.Storage.Metadata.ExistingClaim},
				},
			})
		}
	}
	// else: metadata comes from VolumeClaimTemplate

	// Add admin token secret volume and mount if configured on cluster
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

	// Add metrics token secret volume and mount if configured
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
	}

	return volumes, volumeMounts
}

// buildNodeVolumeClaimTemplates returns PVC templates for a GarageNode's StatefulSet.
func (r *GarageNodeReconciler) buildNodeVolumeClaimTemplates(node *garagev1beta1.GarageNode) []corev1.PersistentVolumeClaim {
	var templates []corev1.PersistentVolumeClaim

	if node.Spec.Storage == nil {
		return templates
	}

	// Metadata PVC (if not using existingClaim and not EmptyDir)
	if meta := node.Spec.Storage.Metadata; meta != nil {
		if meta.ExistingClaim == "" && meta.Type != garagev1beta1.VolumeTypeEmptyDir && meta.Size != nil {
			templates = append(templates, buildBasePVC(metadataVolName, *meta.Size, meta.StorageClassName, meta.AccessModes))
		}
	} else {
		// Default metadata PVC when storage is specified but metadata config is omitted
		templates = append(templates, buildBasePVC(metadataVolName, resource.MustParse("10Gi"), nil, nil))
	}

	// Data PVC (if not gateway, not existingClaim, and not EmptyDir)
	if !node.Spec.Gateway {
		if data := node.Spec.Storage.Data; data != nil && data.ExistingClaim == "" && data.Type != garagev1beta1.VolumeTypeEmptyDir && data.Size != nil {
			templates = append(templates, buildBasePVC(dataVolName, *data.Size, data.StorageClassName, data.AccessModes))
		}
	}

	return templates
}

// labelsForNode returns labels for a GarageNode's resources.
func (r *GarageNodeReconciler) labelsForNode(node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) map[string]string {
	return map[string]string{
		labelAppName:                "garagenode",
		labelAppInstance:            node.Name,
		labelAppComponent:           "node",
		labelAppManagedBy:           operatorName,
		labelCluster:                cluster.Name,
		"garage.rajsingh.info/node": node.Name,
	}
}

// selectorLabelsForNode returns selector labels for a GarageNode's pods.
func (r *GarageNodeReconciler) selectorLabelsForNode(node *garagev1beta1.GarageNode) map[string]string {
	return map[string]string{
		labelAppName:                "garagenode",
		labelAppInstance:            node.Name,
		"garage.rajsingh.info/node": node.Name,
	}
}

func (r *GarageNodeReconciler) reconcileNode(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	// Discover or use provided node ID
	nodeID := node.Spec.NodeID
	if nodeID == "" {
		discovered, err := r.discoverNodeID(ctx, node, cluster)
		if err != nil {
			return fmt.Errorf("failed to discover node ID: %w", err)
		}
		nodeID = discovered
	}

	// If node ID is still empty, try to discover from Admin API using pod IPs.
	// All pod IPs are used for address matching to handle dual-stack clusters where
	// Garage may use a different IP family than the primary pod IP.
	if nodeID == "" {
		podIPs, err := r.getPodIPs(ctx, node, cluster)
		if err != nil {
			return fmt.Errorf("failed to get pod IPs for node discovery: %w", err)
		}

		discovered, err := r.discoverNodeIDFromAdminAPI(ctx, garageClient, podIPs)
		if err != nil {
			// Node might not be connected to the cluster yet.
			// Try to discover its ID by connecting directly to the pod's Admin API.
			log.Info("Node not found in cluster status, trying direct discovery", "podIPs", podIPs)
			discovered, err = r.discoverNodeIDDirect(ctx, cluster, podIPs)
			if err != nil {
				return fmt.Errorf("failed to discover node ID: %w", err)
			}

			// Connect this node to the cluster so other nodes can see it
			log.Info("Connecting node to cluster", "nodeID", discovered, "podIPs", podIPs)
			if err := r.connectNodeToCluster(ctx, garageClient, discovered, podIPs[0], cluster); err != nil {
				return fmt.Errorf("failed to connect node to cluster: %w", err)
			}
		}
		nodeID = discovered
	}

	if nodeID == "" {
		return fmt.Errorf("node ID not found and could not be discovered")
	}

	node.Status.NodeID = nodeID

	// Get current layout
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Check if node is already in layout with correct settings
	var existingRole *garage.LayoutRole
	for i := range layout.Roles {
		if layout.Roles[i].ID == nodeID {
			existingRole = &layout.Roles[i]
			break
		}
	}

	// Determine capacity
	var capacity *uint64
	if !node.Spec.Gateway {
		if node.Spec.Capacity == nil {
			return fmt.Errorf("capacity is required for non-gateway nodes")
		}
		nodeCapacity := uint64(node.Spec.Capacity.Value())
		if nodeCapacity < 1024 {
			return fmt.Errorf("capacity must be at least 1024 bytes (1 KB), got %d", nodeCapacity)
		}
		capacity = &nodeCapacity
	}

	// Ensure tags is never nil (Garage API requires tags field to be present)
	desiredTags := node.Spec.Tags
	if desiredTags == nil {
		desiredTags = []string{}
	}

	// Check if update is needed
	needsUpdate := false
	var updateReason string
	if existingRole == nil {
		needsUpdate = true
		updateReason = "node not in layout"
		log.Info("Node not in layout, will add", "nodeID", nodeID)
	} else {
		if existingRole.Zone != node.Spec.Zone {
			needsUpdate = true
			updateReason = "zone changed"
		}
		if (existingRole.Capacity == nil) != (capacity == nil) {
			needsUpdate = true
			updateReason = "capacity changed"
		} else if capacity != nil && existingRole.Capacity != nil && *existingRole.Capacity != *capacity {
			needsUpdate = true
			updateReason = "capacity changed"
		}
		// Check for tag drift
		if !tagsEqual(existingRole.Tags, desiredTags) {
			needsUpdate = true
			updateReason = "tags changed"
			log.Info("Tag drift detected on node",
				"nodeID", nodeID,
				"existingTags", existingRole.Tags,
				"desiredTags", desiredTags)
		}
	}

	if needsUpdate {
		log.Info("Updating node in layout", "nodeID", nodeID, "zone", node.Spec.Zone, "reason", updateReason)

		if len(layout.StagedRoleChanges) > 0 {
			alreadyStaged := false
			for _, staged := range layout.StagedRoleChanges {
				if staged.ID == nodeID {
					alreadyStaged = true
					break
				}
			}
			if alreadyStaged {
				log.Info("Node already has staged changes, adding to existing staged layout")
			} else {
				log.Info("Adding to existing staged layout changes", "existingStagedCount", len(layout.StagedRoleChanges))
			}
		}

		stagedVersion := layout.Version + 1

		updates := []garage.NodeRoleChange{{
			ID:       nodeID,
			Zone:     node.Spec.Zone,
			Capacity: capacity,
			Tags:     desiredTags,
		}}

		if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
			return fmt.Errorf("failed to update layout: %w", err)
		}

		if err := garageClient.ApplyClusterLayout(ctx, stagedVersion); err != nil {
			if garage.IsConflict(err) {
				log.Info("Layout version mismatch, will retry on next reconciliation", "attemptedVersion", stagedVersion)
				return nil
			}
			return fmt.Errorf("failed to apply layout: %w", err)
		}

		log.Info("Applied layout update", "version", stagedVersion)
	}

	return nil
}

func (r *GarageNodeReconciler) discoverNodeID(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) (string, error) {
	log := logf.FromContext(ctx)

	// If external node, we can't discover - must be provided
	if node.Spec.External != nil {
		return "", fmt.Errorf("external nodes must have nodeId specified")
	}

	// For managed nodes, the pod name is the same as the node name with -0 suffix
	podName := node.Name + "-0"

	log.Info("Attempting to discover node ID from pod", "pod", podName)
	return r.getNodeIDFromPod(ctx, cluster.Namespace, podName)
}

// getPodIPs returns all IP addresses assigned to the node's pod.
// The first element is the primary IP (pod.Status.PodIP). On dual-stack clusters
// additional IPs (IPv4 or IPv6) are appended from pod.Status.PodIPs.
func (r *GarageNodeReconciler) getPodIPs(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) ([]string, error) {
	if node.Spec.External != nil {
		return nil, fmt.Errorf("external nodes must have nodeId specified")
	}

	podName := node.Name + "-0"

	pod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: podName, Namespace: cluster.Namespace}, pod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s: %w", podName, err)
	}

	if pod.Status.PodIP == "" {
		return nil, fmt.Errorf("pod %s has no IP address yet", podName)
	}

	seen := map[string]bool{pod.Status.PodIP: true}
	ips := []string{pod.Status.PodIP}
	for _, pip := range pod.Status.PodIPs {
		if pip.IP != "" && !seen[pip.IP] {
			seen[pip.IP] = true
			ips = append(ips, pip.IP)
		}
	}
	return ips, nil
}

func (r *GarageNodeReconciler) discoverNodeIDFromAdminAPI(ctx context.Context, garageClient *garage.Client, podIPs []string) (string, error) {
	log := logf.FromContext(ctx)

	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get cluster status: %w", err)
	}

	if id, ok := findNodeByIPs(status.Nodes, podIPs); ok {
		log.Info("Discovered node ID from Admin API", "nodeID", id, "podIPs", podIPs)
		return id, nil
	}

	return "", fmt.Errorf("no node found with IPs %v in cluster status (cluster has %d nodes)", podIPs, len(status.Nodes))
}

// extractIPFromAddress extracts the IP address from an address string.
// Handles both IPv4 (ip:port) and IPv6 ([ip]:port) formats.

func (r *GarageNodeReconciler) getNodeIDFromPod(ctx context.Context, namespace, podName string) (string, error) {
	pod := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, pod); err != nil {
		return "", fmt.Errorf("failed to get pod %s: %w", podName, err)
	}

	// Check if pod has the node ID annotation
	if nodeID, ok := pod.Annotations["garage.rajsingh.info/node-id"]; ok && nodeID != "" {
		return nodeID, nil
	}

	// Pod must be running for discovery
	if pod.Status.Phase != corev1.PodRunning {
		return "", fmt.Errorf("pod %s is not running (phase: %s)", podName, pod.Status.Phase)
	}

	if pod.Status.PodIP == "" {
		return "", fmt.Errorf("pod %s has no IP address yet", podName)
	}

	// Node ID will be discovered from Admin API in reconcileNode using pod IP
	return "", nil
}

// discoverNodeIDDirect discovers a node's ID by connecting directly to the pod's Admin API.
// This is used when the node hasn't yet connected to the cluster and isn't visible in cluster status.
// discoverNodeIDDirect discovers a node's ID by connecting directly to the pod's Admin API.
// This is used when the node hasn't yet connected to the cluster and isn't visible in cluster status.
// podIPs[0] is the primary IP used to reach the pod; all IPs are tried for address matching.
func (r *GarageNodeReconciler) discoverNodeIDDirect(ctx context.Context, cluster *garagev1beta1.GarageCluster, podIPs []string) (string, error) {
	log := logf.FromContext(ctx)

	adminToken, err := GetAdminToken(ctx, r.Client, cluster)
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %w", err)
	}

	adminPort := int32(3903)
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		adminPort = cluster.Spec.Admin.BindPort
	}
	directEndpoint := adminEndpoint(podIPs[0], adminPort)
	directClient := garage.NewClient(directEndpoint, adminToken)

	status, err := directClient.GetClusterStatus(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get status from pod directly: %w", err)
	}

	// First try matching by any pod IP address (works when rpc_public_addr is configured).
	if id, ok := findNodeByIPs(status.Nodes, podIPs); ok {
		log.Info("Discovered node ID from direct pod connection (by address)", "nodeID", id, "podIPs", podIPs)
		return id, nil
	}

	// Fall back to identifying the self-node by its unique peer state: isUp && lastSeenSecsAgo==nil.
	// Garage sets PeerConnState::Ourself for the local node, which has no lastSeenSecsAgo and no
	// address when rpc_public_addr is not configured — the common case for in-cluster pods.
	if id, ok := findSelfNode(status.Nodes); ok {
		log.Info("Discovered node ID from direct pod connection (as self)", "nodeID", id, "podIPs", podIPs)
		return id, nil
	}

	return "", fmt.Errorf("node not found in its own cluster status")
}

// connectNodeToCluster connects a new node to the cluster by calling ConnectNode.
// This allows the cluster to discover the new node.
func (r *GarageNodeReconciler) connectNodeToCluster(ctx context.Context, garageClient *garage.Client, nodeID, podIP string, cluster *garagev1beta1.GarageCluster) error {
	rpcPort := int32(3901)
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	nodeAddr := rpcAddr(podIP, rpcPort)
	result, err := garageClient.ConnectNode(ctx, nodeID, nodeAddr)
	if err != nil {
		return err
	}
	if !result.Success && result.Error != nil {
		return fmt.Errorf("failed to connect node: %s", *result.Error)
	}
	return nil
}

func (r *GarageNodeReconciler) finalize(ctx context.Context, node *garagev1beta1.GarageNode, garageClient *garage.Client) error {
	log := logf.FromContext(ctx)

	if node.Status.NodeID == "" {
		return nil
	}

	log.Info("Removing node from layout", "nodeID", node.Status.NodeID)

	// Get current layout
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Check if node is in layout
	inLayout := false
	var nodeRole *garage.LayoutRole
	storageNodeCount := 0
	for i, role := range layout.Roles {
		if role.Capacity != nil && *role.Capacity > 0 {
			storageNodeCount++
		}
		if role.ID == node.Status.NodeID {
			inLayout = true
			nodeRole = &layout.Roles[i]
		}
	}

	if !inLayout {
		log.Info("Node not in layout, nothing to remove")
		return nil
	}

	isStorageNode := nodeRole != nil && nodeRole.Capacity != nil && *nodeRole.Capacity > 0
	if isStorageNode && storageNodeCount <= 1 {
		log.Info("Cannot remove last storage node from layout, skipping layout removal",
			"nodeID", node.Status.NodeID, "storageNodes", storageNodeCount)
		return nil
	}

	// Stage removal
	updates := []garage.NodeRoleChange{{
		ID:     node.Status.NodeID,
		Remove: true,
	}}

	if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
		return fmt.Errorf("failed to stage node removal: %w", err)
	}

	stagedVersion := layout.Version + 1
	if len(layout.StagedRoleChanges) > 0 {
		log.Info("Adding removal to existing staged layout changes", "existingStagedCount", len(layout.StagedRoleChanges))
	}

	if err := garageClient.ApplyClusterLayout(ctx, stagedVersion); err != nil {
		if garage.IsConflict(err) {
			log.Info("Layout version mismatch during removal, will retry", "attemptedVersion", stagedVersion)
			return fmt.Errorf("layout version mismatch, retry needed: %w", err)
		}
		if garage.IsReplicationConstraint(err) {
			log.Info("Cannot remove node: would violate replication factor constraints. "+
				"The node will be removed from Kubernetes but will remain in the Garage layout. "+
				"Add more storage nodes or reduce the replication factor to fully remove this node.",
				"nodeID", node.Status.NodeID, "storageNodes", storageNodeCount)
			return nil
		}
		return fmt.Errorf("failed to apply layout removal: %w", err)
	}

	log.Info("Removed node from layout", "version", stagedVersion)

	// For gateway nodes, immediately skip dead nodes
	if node.Spec.Gateway {
		skipReq := garage.SkipDeadNodesRequest{
			Version:          stagedVersion,
			AllowMissingData: true,
		}
		result, err := garageClient.ClusterLayoutSkipDeadNodes(ctx, skipReq)
		if err != nil {
			if !garage.IsBadRequest(err) {
				log.Error(err, "Failed to skip dead gateway node (will be cleaned up later)")
			}
		} else if len(result.AckUpdated) > 0 || len(result.SyncUpdated) > 0 {
			log.Info("Skipped dead gateway node to prevent draining stall",
				"ackUpdated", len(result.AckUpdated),
				"syncUpdated", len(result.SyncUpdated))
		}
	}

	return nil
}

func (r *GarageNodeReconciler) updateStatus(ctx context.Context, node *garagev1beta1.GarageNode, phase string, err error) (ctrl.Result, error) {
	node.Status.Phase = phase
	if err == nil {
		node.Status.ObservedGeneration = node.Generation
	}

	if err != nil {
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
			Message:            err.Error(),
			ObservedGeneration: node.Generation,
		})
	}

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, node); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	return ctrl.Result{}, nil
}

func (r *GarageNodeReconciler) updateStatusFromGarage(ctx context.Context, node *garagev1beta1.GarageNode, garageClient *garage.Client) (ctrl.Result, error) {
	if node.Status.NodeID == "" {
		return r.updateStatus(ctx, node, "Pending", nil)
	}

	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to get cluster status: %w", err))
	}

	var nodeInfo *garage.NodeInfo
	for i := range status.Nodes {
		if status.Nodes[i].ID == node.Status.NodeID {
			nodeInfo = &status.Nodes[i]
			break
		}
	}

	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to get cluster layout: %w", err))
	}

	var layoutRole *garage.LayoutRole
	for i := range layout.Roles {
		if layout.Roles[i].ID == node.Status.NodeID {
			layoutRole = &layout.Roles[i]
			break
		}
	}

	node.Status.Phase = PhaseReady
	node.Status.ObservedGeneration = node.Generation
	node.Status.InLayout = layoutRole != nil

	if layoutRole != nil {
		node.Status.LayoutVersion = int64(layout.Version)
	}

	if nodeInfo != nil {
		node.Status.Connected = nodeInfo.IsUp
		if nodeInfo.Address != nil {
			node.Status.Address = *nodeInfo.Address
		}
		if nodeInfo.IsUp {
			now := metav1.Now()
			node.Status.LastSeen = &now
		}
	}

	conditionStatus := metav1.ConditionTrue
	reason := "NodeReady"
	message := "Node is ready and in layout"

	if !node.Status.InLayout {
		conditionStatus = metav1.ConditionFalse
		reason = "NotInLayout"
		message = "Node is not yet in the cluster layout"
	} else if nodeInfo != nil && !nodeInfo.IsUp {
		conditionStatus = metav1.ConditionFalse
		reason = "NodeDisconnected"
		message = "Node is in layout but not connected"
	}

	meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
		Type:               PhaseReady,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: node.Generation,
	})

	if err := UpdateStatusWithRetry(ctx, r.Client, node); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

// tagsEqual compares two tag slices for equality using set-based comparison.
// Tags are considered equal if they contain the same elements, regardless of order.
// This prevents false config drift detection when Garage or external tools reorder tags.
func tagsEqual(a, b []string) bool {
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

// reconcileNodeService creates or updates a per-node LoadBalancer/NodePort service for
// exposing the RPC port externally. Only called when spec.network.publicEndpoint is set.
func (r *GarageNodeReconciler) reconcileNodeService(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) error {
	ep := node.Spec.PublicEndpoint
	svcName := node.Name + "-rpc"

	rpcPort := DefaultRPCPort
	if cluster.Spec.Network.RPCBindPort != 0 {
		rpcPort = cluster.Spec.Network.RPCBindPort
	}

	var svcType corev1.ServiceType
	var svcMeta garagev1beta1.ServiceMeta
	var nodePort int32

	switch ep.Type {
	case publicEndpointTypeLoadBalancer:
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

	baseLabels := map[string]string{
		labelAppName:      defaultAppName,
		labelAppInstance:  cluster.Name,
		labelAppComponent: node.Name,
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        svcName,
			Namespace:   cluster.Namespace,
			Labels:      mergeLabels(baseLabels, svcMeta.Labels),
			Annotations: svcMeta.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                     svcType,
			Selector:                 r.selectorLabelsForNode(node),
			Ports:                    []corev1.ServicePort{port},
			PublishNotReadyAddresses: true,
		},
	}
	return reconcileService(ctx, r.Client, svc, node, r.Scheme)
}

// reconcileNodeConfigMap generates a per-node garage.toml ConfigMap by building a configContext
// with node-specific overrides and calling the shared config generator.
func (r *GarageNodeReconciler) reconcileNodeConfigMap(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta1.GarageCluster) error {
	// Start with a base context (resolves Consul token, cluster-level publicEndpoint, etc.)
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		cfgCtx = &configContext{}
	}

	// Apply node-level rpc_public_addr via NodeRPCPublicAddr — this takes highest priority
	// in writeRPCConfig, overriding even cluster.Spec.Network.RPCPublicAddr.
	if node.Spec.Network != nil && node.Spec.Network.RPCPublicAddr != "" {
		cfgCtx.NodeRPCPublicAddr = node.Spec.Network.RPCPublicAddr
	} else if node.Spec.PublicEndpoint != nil {
		rpcPort := DefaultRPCPort
		if cluster.Spec.Network.RPCBindPort != 0 {
			rpcPort = cluster.Spec.Network.RPCBindPort
		}
		switch node.Spec.PublicEndpoint.Type {
		case publicEndpointTypeLoadBalancer:
			svc := &corev1.Service{}
			if err := r.Get(ctx, types.NamespacedName{Name: node.Name + "-rpc", Namespace: cluster.Namespace}, svc); err == nil {
				for _, ing := range svc.Status.LoadBalancer.Ingress {
					addr := ing.IP
					if addr == "" {
						addr = ing.Hostname
					}
					if addr != "" {
						cfgCtx.NodeRPCPublicAddr = fmt.Sprintf("%s:%d", addr, rpcPort)
						break
					}
				}
			}
		case publicEndpointTypeNodePort:
			if ep := node.Spec.PublicEndpoint.NodePort; ep != nil && len(ep.ExternalAddresses) > 0 {
				basePort := ep.BasePort
				if basePort == 0 {
					basePort = 30901
				}
				cfgCtx.NodeRPCPublicAddr = fmt.Sprintf("%s:%d", ep.ExternalAddresses[0], basePort)
			}
		}
	}

	// Apply node-level fsync overrides.
	if node.Spec.Storage != nil {
		cfgCtx.MetadataFsync = node.Spec.Storage.MetadataFsync
		cfgCtx.DataFsync = node.Spec.Storage.DataFsync
	}

	nodeConfig := generateGarageConfig(cluster, cfgCtx)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      node.Name + "-config",
			Namespace: cluster.Namespace,
		},
		Data: map[string]string{"garage.toml": nodeConfig},
	}
	if err := controllerutil.SetControllerReference(node, cm, r.Scheme); err != nil {
		return err
	}

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, cm)
	}
	if err != nil {
		return err
	}
	existing.Data = cm.Data
	return r.Update(ctx, existing)
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageNode{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Named("garagenode").
		Complete(r)
}
