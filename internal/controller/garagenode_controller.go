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
	"fmt"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// finalizeOrphanedTimeout caps the best-effort layout-removal call made when
// the parent GarageCluster CR has already vanished. We don't want a hung
// external admin API to deadlock GarageNode finalization, so cap aggressively.
const finalizeOrphanedTimeout = 5 * time.Second

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
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch

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
	cluster := &garagev1beta2.GarageCluster{}
	clusterNamespace := node.Namespace
	if node.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = node.Spec.ClusterRef.Namespace
	}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      node.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		// Cluster gone (the cluster-level finalizer ran ahead of GC catching up to
		// this GarageNode) → no admin API to talk to via the cluster spec; for
		// unified clusters the layout entries were already drained by the cluster
		// finalizer's removeNodesFromLayout call, so nothing to do. For edge
		// gateways (spec.connectTo.adminApiEndpoint), the layout entry still lives
		// on the *remote* cluster — make a best-effort attempt against the admin
		// endpoint we captured on the last successful reconcile so we don't leave
		// a dead layout entry on the federated peer. Either way, never block
		// finalizer release indefinitely — the worst case is a manual
		// `garage layout remove` on the remote.
		if errors.IsNotFound(err) && !node.DeletionTimestamp.IsZero() {
			if controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
				if err := r.attemptOrphanedFinalize(ctx, node); err != nil {
					log.Info("Best-effort layout cleanup against captured admin endpoint failed; releasing finalizer anyway",
						"node", node.Name, "endpoint", node.Status.ClusterAdminEndpoint, "error", err.Error())
				} else if node.Status.ClusterAdminEndpoint != "" {
					log.Info("Removed node from layout via captured admin endpoint after parent cluster deletion",
						"node", node.Name, "endpoint", node.Status.ClusterAdminEndpoint)
				} else {
					log.Info("Parent cluster already deleted; releasing GarageNode finalizer", "node", node.Name)
				}
				controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
				if updateErr := r.Update(ctx, node); updateErr != nil {
					return ctrl.Result{}, updateErr
				}
			}
			return ctrl.Result{}, nil
		}
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("cluster not found: %w", err))
	}
	// User-created GarageNodes still require Manual layout — operator-managed CRs
	// (controllerOwnerRef on the GarageCluster, generated by Auto mode in #190)
	// are allowed regardless of policy.
	isOperatorOwned := metav1.IsControlledBy(node, cluster)
	if !isOperatorOwned && cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("user-created GarageNode requires parent GarageCluster spec.layoutPolicy: Manual"))
	}

	// Handle deletion
	if !node.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
			// If the parent cluster is also being deleted, the cluster's finalizer
			// already called removeNodesFromLayout for every node. Skip the per-node
			// admin-API call — it would just retry against a Service that's about to
			// disappear, blocking namespace teardown for FinalizationMaxRetries × backoff.
			if !cluster.DeletionTimestamp.IsZero() {
				log.Info("Parent cluster is being deleted, skipping per-node layout cleanup")
				controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
				if err := r.Update(ctx, node); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
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

	// Maintenance mode: skip ALL reconciliation (STS, ConfigMap, Service, layout) so
	// operators can perform PVC swaps or hardware work without the operator fighting them.
	// Runs AFTER the deletion/finalizer block so a suspended node can still be deleted.
	if node.Spec.Maintenance != nil && node.Spec.Maintenance.Suspended {
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               "Suspended",
			Status:             metav1.ConditionTrue,
			Reason:             "MaintenanceSuspended",
			Message:            "Reconciliation paused by spec.maintenance.suspended",
			ObservedGeneration: node.Generation,
		})
		if err := r.Status().Update(ctx, node); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("GarageNode reconciliation paused")
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}
	// Clear Suspended condition when not suspended.
	meta.RemoveStatusCondition(&node.Status.Conditions, "Suspended")

	// TODO(#190): per-node `garage.rajsingh.info/cycle: true` annotation —
	// provision sibling GarageNode, wait for sync_map_min, swap. Deferred from #190.

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
		// Expand bound PVCs first if the spec grew. StatefulSet selectors are
		// immutable but PVCs can be resized in place when the StorageClass has
		// allowVolumeExpansion=true. Order matters: the STS template carries the
		// new size, so without expanding the existing PVCs first the new
		// template would silently disagree with the bound claims.
		if err := r.expandNodePVCs(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("expanding PVCs: %w", err))
		}
		if err := r.reconcileStatefulSet(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, err)
		}
	}

	// Get garage client for layout management
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to create garage client: %w", err))
	}

	// Capture the resolved admin endpoint + token ref on status so the
	// orphaned-finalize path can still reach the right Garage admin API
	// (especially the *remote* one for edge gateways) when the parent
	// GarageCluster CR has been deleted before we get a chance to clean up.
	captureAdminEndpoint(node, cluster, r.ClusterDomain)

	// Reconcile the node layout
	if err := r.reconcileNode(ctx, node, cluster, garageClient); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, err)
	}

	return r.updateStatusFromGarage(ctx, node, garageClient)
}

// reconcileStatefulSet creates/updates the StatefulSet for a managed GarageNode.
// Each GarageNode creates its own StatefulSet with replica 1.
func (r *GarageNodeReconciler) reconcileStatefulSet(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	stsName := node.Name

	// Build merged pod config (cluster defaults + node overrides)
	image := mergeNodeImage(cluster.Spec.Image, cluster.Spec.ImageRepository, node.Spec.Image, node.Spec.ImageRepository, r.DefaultImage)

	// Cluster-level fallback scheduling values come from the storage tier when set
	// (manual-layout GarageNodes are functionally storage nodes). Edge gateway clusters
	// don't have a storage tier; in that case we fall back to gateway-tier values.
	var tierTemplate *garagev1beta2.PodTemplate
	if cluster.HasStorageTier() {
		tierTemplate = &cluster.Spec.Storage.PodTemplate
	} else if cluster.HasGatewayTier() {
		tierTemplate = &cluster.Spec.Gateway.PodTemplate
	}

	var (
		clusterResources                 corev1.ResourceRequirements
		clusterNodeSelector              map[string]string
		clusterTolerations               []corev1.Toleration
		clusterAffinity                  *corev1.Affinity
		clusterPriorityClassName         string
		clusterSecurityContext           *corev1.PodSecurityContext
		clusterContainerSecurityContext  *corev1.SecurityContext
		clusterTopologySpreadConstraints []corev1.TopologySpreadConstraint
		clusterPodLabels                 map[string]string
		clusterPodAnnotations            map[string]string
		clusterEnv                       []corev1.EnvVar
		clusterEnvFrom                   []corev1.EnvFromSource
	)
	if tierTemplate != nil {
		clusterResources = tierTemplate.Resources
		clusterNodeSelector = tierTemplate.NodeSelector
		clusterTolerations = tierTemplate.Tolerations
		clusterAffinity = tierTemplate.Affinity
		clusterPriorityClassName = tierTemplate.PriorityClassName
		clusterSecurityContext = tierTemplate.SecurityContext
		clusterContainerSecurityContext = tierTemplate.ContainerSecurityContext
		clusterTopologySpreadConstraints = tierTemplate.TopologySpreadConstraints
		clusterPodLabels = tierTemplate.PodLabels
		clusterPodAnnotations = tierTemplate.PodAnnotations
		clusterEnv = tierTemplate.Env
		clusterEnvFrom = tierTemplate.EnvFrom
	}

	resources := clusterResources
	if node.Spec.Resources != nil {
		resources = *node.Spec.Resources
	}

	nodeSelector := clusterNodeSelector
	if node.Spec.NodeSelector != nil {
		nodeSelector = node.Spec.NodeSelector
	}

	tolerations := clusterTolerations
	if node.Spec.Tolerations != nil {
		tolerations = node.Spec.Tolerations
	}

	affinity := clusterAffinity
	if node.Spec.Affinity != nil {
		affinity = node.Spec.Affinity
	}

	priorityClassName := clusterPriorityClassName
	if node.Spec.PriorityClassName != "" {
		priorityClassName = node.Spec.PriorityClassName
	}

	// Build container ports (same as cluster)
	containerPorts := buildContainerPorts(cluster)

	// Build volumes and mounts for this node
	volumes, volumeMounts := r.buildNodeVolumesAndMounts(node, cluster)
	volumeClaimTemplates := r.buildNodeVolumeClaimTemplates(node, cluster)

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

	containerSecurityContext := clusterContainerSecurityContext
	if node.Spec.ContainerSecurityContext != nil {
		containerSecurityContext = node.Spec.ContainerSecurityContext
	}

	securityContext := clusterSecurityContext
	if node.Spec.SecurityContext != nil {
		securityContext = node.Spec.SecurityContext
	}

	topologySpreadConstraints := clusterTopologySpreadConstraints
	if node.Spec.TopologySpreadConstraints != nil {
		topologySpreadConstraints = node.Spec.TopologySpreadConstraints
	}

	// Merge cluster-level env with per-node env. Node entries take precedence on
	// key collision; we drop the cluster entry and replace it with the node one.
	mergedEnv := mergeNodeEnv(clusterEnv, node.Spec.Env)
	// EnvFrom is replaced wholesale when the node sets it; otherwise inherit cluster.
	mergedEnvFrom := clusterEnvFrom
	if node.Spec.EnvFrom != nil {
		mergedEnvFrom = node.Spec.EnvFrom
	}

	// Per-node logging override beats cluster-level Logging.
	effectiveLogging := effectiveNodeLogging(cluster.Spec.Logging, node.Spec.Logging)

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
		Logging:                   effectiveLogging,
		Env:                       mergedEnv,
		EnvFrom:                   mergedEnvFrom,
	}, volumes, volumeMounts, containerPorts)

	// Build labels: merge cluster labels + node-specific labels
	podLabels := r.labelsForNode(node, cluster)
	for k, v := range clusterPodLabels {
		podLabels[k] = v
	}
	for k, v := range node.Spec.PodLabels {
		podLabels[k] = v
	}

	// Build annotations: merge cluster annotations + node-specific annotations.
	// We assemble the user-provided portion first so it can feed the pod-spec-hash;
	// the internal hash annotations are appended below.
	userAnnotations := make(map[string]string)
	for k, v := range clusterPodAnnotations {
		userAnnotations[k] = v
	}
	for k, v := range node.Spec.PodAnnotations {
		userAnnotations[k] = v
	}
	// Same idea for labels: collect the user-provided ones so hash sees them.
	// (podLabels above already includes the operator-managed selector labels — pass
	// only the user portion to keep the hash stable.)
	userLabels := make(map[string]string)
	for k, v := range clusterPodLabels {
		userLabels[k] = v
	}
	for k, v := range node.Spec.PodLabels {
		userLabels[k] = v
	}

	// Compute pod-spec-hash from the pod spec plus user-provided podAnnotations/podLabels so
	// changes to those trigger a StatefulSet update.
	podSpecHashStr := computePodSpecHash(podSpec, userAnnotations, userLabels)

	podAnnotations := make(map[string]string)
	for k, v := range userAnnotations {
		podAnnotations[k] = v
	}
	podAnnotations["garage.rajsingh.info/pod-spec-hash"] = podSpecHashStr

	// Include the mounted ConfigMap's content hash so pods restart when config changes.
	// Per-node override CM when present (must match the buildNodeVolumesAndMounts logic),
	// otherwise the shared cluster CM — without this, changes to cluster.spec.* never
	// roll the per-node pods.
	cmName := cluster.Name + "-config"
	if nodeHasConfigOverrides(node) {
		cmName = node.Name + "-config"
	}
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm); err == nil {
		h := sha256.Sum256([]byte(cm.Data["garage.toml"]))
		podAnnotations["garage.rajsingh.info/config-hash"] = hex.EncodeToString(h[:8])
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
			VolumeClaimTemplates:                 volumeClaimTemplates,
			PodManagementPolicy:                  appsv1.ParallelPodManagement,
			UpdateStrategy:                       appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType},
			PersistentVolumeClaimRetentionPolicy: stsPVCRetentionPolicy(cluster, node),
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

// stsPVCRetentionPolicy translates spec.storage.pvcRetentionPolicy into the
// StatefulSet PVC retention policy. Returns nil for clusters that don't set
// the field, which leaves K8s' default of "Retain" — safe for stateful data
// and matches the v1beta2 type defaults. #196 follow-up: this was a silent
// no-op on storage STSes after #192 (the gateway STS already wires it).
// pvcRetentionDelete is the API string for "delete PVCs when the STS is
// deleted/scaled" — matches the enum value in the v1beta2 CRD.
const pvcRetentionDelete = "Delete"

func stsPVCRetentionPolicy(cluster *garagev1beta2.GarageCluster, node *garagev1beta1.GarageNode) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
	if node.Spec.Gateway || !cluster.HasStorageTier() || cluster.Spec.Storage.PVCRetentionPolicy == nil {
		return nil
	}
	rp := cluster.Spec.Storage.PVCRetentionPolicy
	out := &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
		WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
		WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
	}
	if rp.WhenDeleted == pvcRetentionDelete {
		out.WhenDeleted = appsv1.DeletePersistentVolumeClaimRetentionPolicyType
	}
	if rp.WhenScaled == pvcRetentionDelete {
		out.WhenScaled = appsv1.DeletePersistentVolumeClaimRetentionPolicyType
	}
	return out
}

// expandNodePVCs resizes bound PVCs in-place when spec.storage.{metadata,data}.size
// grows. Required because StatefulSet.volumeClaimTemplates is immutable: a
// fresh template with a larger size won't propagate to existing PVCs without
// an explicit Update. Shrink is not supported and silently skipped — the
// underlying StorageClass would reject it anyway.
//
// #196 follow-up: PVC expansion was deleted in #192 with the legacy
// reconcileStatefulSet and never reimplemented; bumping size silently no-op'd.
func (r *GarageNodeReconciler) expandNodePVCs(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	if node.Spec.Storage == nil {
		return nil
	}
	log := logf.FromContext(ctx)
	stsName := node.Name

	// Build a list of (PVC-name-prefix, desired size). PVCs created from
	// volumeClaimTemplates follow the convention <template-name>-<sts>-<ord>;
	// for our 1-replica per-node STS that's <template>-<stsName>-0. Skip any
	// volume backed by existingClaim (migration adoption) — those PVCs are
	// user-managed; we don't own their size policy.
	type want struct {
		name string
		size resource.Quantity
	}
	var wants []want
	if m := node.Spec.Storage.Metadata; m != nil && m.ExistingClaim == "" && m.Type != garagev1beta1.VolumeTypeEmptyDir && m.Size != nil {
		wants = append(wants, want{name: fmt.Sprintf("%s-%s-0", metadataVolName, stsName), size: *m.Size})
	}
	if !node.Spec.Gateway {
		switch {
		case nodeHasMultiHDD(node):
			for i, dp := range node.Spec.Storage.DataPaths {
				if dp.ExistingClaim != "" || dp.Type == garagev1beta1.VolumeTypeEmptyDir || dp.Size == nil {
					continue
				}
				wants = append(wants, want{name: fmt.Sprintf("%s-%s-0", nodeMultiHDDDataVolName(i), stsName), size: *dp.Size})
			}
		default:
			if d := node.Spec.Storage.Data; d != nil && d.ExistingClaim == "" && d.Type != garagev1beta1.VolumeTypeEmptyDir && d.Size != nil {
				wants = append(wants, want{name: fmt.Sprintf("%s-%s-0", dataVolName, stsName), size: *d.Size})
			}
		}
	}

	for _, w := range wants {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{Name: w.name, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("get PVC %s: %w", w.name, err)
		}
		current, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
		if !ok || current.Cmp(w.size) >= 0 {
			continue
		}
		log.Info("Expanding PVC", "pvc", w.name, "from", current.String(), "to", w.size.String())
		if pvc.Spec.Resources.Requests == nil {
			pvc.Spec.Resources.Requests = corev1.ResourceList{}
		}
		pvc.Spec.Resources.Requests[corev1.ResourceStorage] = w.size
		if err := r.Update(ctx, pvc); err != nil {
			// Surface but don't fatal — likely the StorageClass disallows
			// expansion; admin can resolve out-of-band.
			log.Error(err, "PVC expand rejected", "pvc", w.name)
		}
	}
	return nil
}

// nodeMultiHDDDataPath returns the default mount path for the i-th data volume
// on a multi-HDD GarageNode when the spec carries no explicit Path. Single-HDD
// nodes continue to use the legacy `/data/data` (see helpers.go `dataPath`).
// Multi-HDD mount paths are sibling directories under /data so they match the
// cluster-tier multi-HDD layout.
func nodeMultiHDDDataPath(i int) string {
	return fmt.Sprintf("/data/data-%d", i)
}

// effectiveDataPathMount returns the in-container mount path for the i-th
// multi-HDD data volume: the user-provided dp.Path when set, otherwise the
// default `/data/data-<i>`. Used by both the StatefulSet volumeMounts and the
// per-node ConfigMap renderer so the K8s mount path and Garage's
// `data_dir = [{ path = ... }]` always agree.
func effectiveDataPathMount(dp garagev1beta1.NodeVolumeConfig, i int) string {
	if dp.Path != "" {
		return dp.Path
	}
	return nodeMultiHDDDataPath(i)
}

// nodeMultiHDDDataVolName returns the volume/PVC-template name for the i-th
// data volume on a multi-HDD GarageNode.
func nodeMultiHDDDataVolName(i int) string {
	return fmt.Sprintf("%s-%d", dataVolName, i)
}

// nodeHasMultiHDD reports whether the GarageNode uses the multi-HDD layout
// (storage.dataPaths). False for gateways, single-Data, or unset storage.
func nodeHasMultiHDD(node *garagev1beta1.GarageNode) bool {
	if node.Spec.Gateway || node.Spec.Storage == nil {
		return false
	}
	return len(node.Spec.Storage.DataPaths) > 0
}

// lookupPVCCapacity returns a TOML-ready capacity string (e.g. "10Gi") for
// the named PVC, preferring its spec.resources.requests.storage and falling
// back to status.capacity.storage. Returns "" if neither is set or the PVC
// is not found. Used by the per-node ConfigMap renderer to heal multi-HDD
// GarageNodes whose `spec.storage.dataPaths[].size` is unset — a state the
// pre-#205 legacy-STS migration would leave behind, causing Garage to
// reject `data_dir` (no capacity) and the storage pod to crashloop.
func (r *GarageNodeReconciler) lookupPVCCapacity(ctx context.Context, ns, name string) string {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, pvc); err != nil {
		return ""
	}
	if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok && !req.IsZero() {
		return req.String()
	}
	if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok && !cap.IsZero() {
		return cap.String()
	}
	return ""
}

// buildNodeVolumesAndMounts returns volumes and volume mounts for a GarageNode's StatefulSet.
func (r *GarageNodeReconciler) buildNodeVolumesAndMounts(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
		{Name: RPCSecretKey, MountPath: rpcSecretMountPath, ReadOnly: true},
		{Name: metadataVolName, MountPath: metadataPath},
	}
	if nodeHasMultiHDD(node) {
		for i, dp := range node.Spec.Storage.DataPaths {
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      nodeMultiHDDDataVolName(i),
				MountPath: effectiveDataPathMount(dp, i),
			})
		}
	} else {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{Name: dataVolName, MountPath: dataPath})
	}

	// RPC secret: gateway clusters with ConnectTo use the storage cluster's RPC secret.
	// This mirrors the logic in buildVolumesAndMounts in garagecluster_controller.go.
	rpcSecretName := cluster.Name + "-rpc-secret"
	rpcSecretKey := RPCSecretKey
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil {
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

	// Handle data volume(s):
	//  * multi-HDD: one entry per dataPaths[] — EmptyDir, existingClaim, or PVC template
	//  * single-HDD: gateway or EmptyDir type → EmptyDir; existingClaim → PVC inline; else → PVC template
	switch {
	case nodeHasMultiHDD(node):
		for i, dp := range node.Spec.Storage.DataPaths {
			vol := corev1.Volume{Name: nodeMultiHDDDataVolName(i)}
			switch {
			case dp.Type == garagev1beta1.VolumeTypeEmptyDir:
				vol.VolumeSource = corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
				volumes = append(volumes, vol)
			case dp.ExistingClaim != "":
				vol.VolumeSource = corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: dp.ExistingClaim},
				}
				volumes = append(volumes, vol)
			}
			// else: dynamically provisioned via VolumeClaimTemplate (no Volume entry needed)
		}
	case node.Spec.Gateway || (node.Spec.Storage != nil && node.Spec.Storage.Data != nil && node.Spec.Storage.Data.Type == garagev1beta1.VolumeTypeEmptyDir):
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolName,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
	case node.Spec.Storage != nil && node.Spec.Storage.Data != nil && node.Spec.Storage.Data.ExistingClaim != "":
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
			MountPath: adminSecretMountPath,
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
// PVCs inherit the per-node labels so e2e selectors and observability tooling can
// filter "all PVCs of cluster X" via garage.rajsingh.info/cluster=<name>.
func (r *GarageNodeReconciler) buildNodeVolumeClaimTemplates(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) []corev1.PersistentVolumeClaim {
	var templates []corev1.PersistentVolumeClaim
	labels := r.labelsForNode(node, cluster)

	addLabels := func(pvc corev1.PersistentVolumeClaim) corev1.PersistentVolumeClaim {
		if pvc.Labels == nil {
			pvc.Labels = map[string]string{}
		}
		for k, v := range labels {
			pvc.Labels[k] = v
		}
		return pvc
	}

	if node.Spec.Storage == nil {
		return templates
	}

	// Metadata PVC (if not using existingClaim and not EmptyDir)
	if meta := node.Spec.Storage.Metadata; meta != nil {
		if meta.ExistingClaim == "" && meta.Type != garagev1beta1.VolumeTypeEmptyDir && meta.Size != nil {
			templates = append(templates, addLabels(buildBasePVC(metadataVolName, *meta.Size, meta.StorageClassName, meta.AccessModes)))
		}
	} else {
		// Default metadata PVC when storage is specified but metadata config is omitted
		templates = append(templates, addLabels(buildBasePVC(metadataVolName, resource.MustParse("10Gi"), nil, nil)))
	}

	// Data PVC(s)
	if !node.Spec.Gateway {
		switch {
		case nodeHasMultiHDD(node):
			for i, dp := range node.Spec.Storage.DataPaths {
				if dp.ExistingClaim != "" || dp.Type == garagev1beta1.VolumeTypeEmptyDir || dp.Size == nil {
					continue
				}
				templates = append(templates, addLabels(buildBasePVC(nodeMultiHDDDataVolName(i), *dp.Size, dp.StorageClassName, dp.AccessModes)))
			}
		default:
			if data := node.Spec.Storage.Data; data != nil && data.ExistingClaim == "" && data.Type != garagev1beta1.VolumeTypeEmptyDir && data.Size != nil {
				templates = append(templates, addLabels(buildBasePVC(dataVolName, *data.Size, data.StorageClassName, data.AccessModes)))
			}
		}
	}

	return templates
}

// labelsForNode returns labels for a GarageNode's resources.
//
// The tier label is critical: post-#190 the cluster-level API Service selects
// storage pods via {labelCluster, labelTier=storage}. Without it, the Service
// has no endpoints and admin/S3 traffic to <cluster>.<ns>.svc fails.
//
// Storage pods carry the cluster-level {labelAppName=garage, labelAppInstance=<cluster>}
// pair so externally-defined Services (Tailscale LBs, etc.) selecting on the
// pre-#190 convention {name=garage, instance=<cluster>, tier=storage} keep
// matching after the per-node refactor. The unique-per-STS identity comes from
// labelGarageNode, not from labelAppName/Instance.
func (r *GarageNodeReconciler) labelsForNode(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) map[string]string {
	tier := tierStorage
	if node.Spec.Gateway {
		tier = tierGateway
	}
	return map[string]string{
		labelAppName:      defaultAppName,
		labelAppInstance:  cluster.Name,
		labelAppComponent: "node",
		labelAppManagedBy: operatorName,
		labelCluster:      cluster.Name,
		labelTier:         tier,
		labelGarageNode:   node.Name,
	}
}

// selectorLabelsForNode returns the per-STS selector. It must be unique per
// GarageNode (so each per-node STS owns exactly its own pod) and immutable for
// the lifetime of the STS. labelGarageNode is unique per node by construction;
// labelAppManagedBy is added as a defense-in-depth scope so the selector never
// matches a pod from an unrelated workload that happens to reuse the same node
// name. labelAppName/Instance are deliberately omitted — they carry
// cluster-shared values for external Service compatibility (see labelsForNode).
func (r *GarageNodeReconciler) selectorLabelsForNode(node *garagev1beta1.GarageNode) map[string]string {
	return map[string]string{
		labelAppManagedBy: operatorName,
		labelGarageNode:   node.Name,
	}
}

func (r *GarageNodeReconciler) reconcileNode(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster, garageClient *garage.Client) error {
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

func (r *GarageNodeReconciler) discoverNodeID(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) (string, error) {
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
func (r *GarageNodeReconciler) getPodIPs(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) ([]string, error) {
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
func (r *GarageNodeReconciler) discoverNodeIDDirect(ctx context.Context, cluster *garagev1beta2.GarageCluster, podIPs []string) (string, error) {
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
func (r *GarageNodeReconciler) connectNodeToCluster(ctx context.Context, garageClient *garage.Client, nodeID, podIP string, cluster *garagev1beta2.GarageCluster) error {
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

// attemptOrphanedFinalize tries a best-effort layout removal when the parent
// GarageCluster CR has already been deleted. Returns nil when there is nothing
// to do (no captured endpoint, no node ID, or remote token secret already
// gone). Returns an error on a real RPC failure so the caller can log it, but
// the caller MUST release the finalizer regardless — we never block teardown
// on this best-effort cleanup.
func (r *GarageNodeReconciler) attemptOrphanedFinalize(ctx context.Context, node *garagev1beta1.GarageNode) error {
	if node.Status.NodeID == "" {
		return nil
	}
	if node.Status.ClusterAdminEndpoint == "" || node.Status.ClusterAdminTokenSecretRef == nil {
		// No captured endpoint to call. For unified clusters this is fine —
		// the cluster finalizer already removed the layout entry. For edge
		// gateways this means we never reached a successful reconcile that
		// captured the endpoint; a manual `garage layout remove` is needed.
		return nil
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      node.Status.ClusterAdminTokenSecretRef.Name,
		Namespace: node.Namespace,
	}, secret); err != nil {
		if errors.IsNotFound(err) {
			// Secret is already gone — we can't authenticate to the remote
			// admin API. Nothing more to do.
			return nil
		}
		return fmt.Errorf("get admin token secret %s: %w", node.Status.ClusterAdminTokenSecretRef.Name, err)
	}
	tokenKey := node.Status.ClusterAdminTokenSecretRef.Key
	if tokenKey == "" {
		tokenKey = DefaultAdminTokenKey
	}
	tokenData, ok := secret.Data[tokenKey]
	if !ok || len(tokenData) == 0 {
		return fmt.Errorf("admin token secret %s missing key %q", secret.Name, tokenKey)
	}

	cctx, cancel := context.WithTimeout(ctx, finalizeOrphanedTimeout)
	defer cancel()

	client := garage.NewClient(node.Status.ClusterAdminEndpoint, string(tokenData))
	return r.removeNodeFromExternalLayout(cctx, node, client)
}

// removeNodeFromExternalLayout stages and applies a layout removal for the
// node against an arbitrary admin client. Mirrors the relevant logic in
// finalize() but without the "last storage node" / gateway-specific
// skip-dead-nodes guard rails — when called from the orphaned path, the
// parent cluster is already gone and the remote cluster will reconcile
// independently.
func (r *GarageNodeReconciler) removeNodeFromExternalLayout(ctx context.Context, node *garagev1beta1.GarageNode, garageClient *garage.Client) error {
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("get cluster layout: %w", err)
	}

	inLayout := false
	for _, role := range layout.Roles {
		if role.ID == node.Status.NodeID {
			inLayout = true
			break
		}
	}
	if !inLayout {
		return nil
	}

	updates := []garage.NodeRoleChange{{ID: node.Status.NodeID, Remove: true}}
	if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
		return fmt.Errorf("stage node removal: %w", err)
	}
	stagedVersion := layout.Version + 1
	if err := garageClient.ApplyClusterLayout(ctx, stagedVersion); err != nil {
		if garage.IsConflict(err) {
			return fmt.Errorf("layout version mismatch: %w", err)
		}
		if garage.IsReplicationConstraint(err) {
			// Best-effort cleanup; admin will need to add capacity or
			// reduce replication to actually drop this entry.
			return nil
		}
		return fmt.Errorf("apply layout removal: %w", err)
	}
	return nil
}

// captureAdminEndpoint stores the resolved admin endpoint + token reference
// on the GarageNode status so a delete-time finalizer can still attempt a
// layout removal against an external cluster after the parent GarageCluster
// CR has been deleted. For unified clusters this captures the in-cluster svc
// FQDN; the captured value is still useful for diagnostics (e.g. `kubectl
// describe garagenode`) even when no orphaned-finalize attempt fires.
func captureAdminEndpoint(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster, clusterDomain string) {
	// Edge-gateway: layout lives on the external storage cluster.
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		if cluster.Spec.ConnectTo.AdminTokenSecretRef == nil {
			return
		}
		node.Status.ClusterAdminEndpoint = cluster.Spec.ConnectTo.AdminAPIEndpoint
		ref := *cluster.Spec.ConnectTo.AdminTokenSecretRef
		node.Status.ClusterAdminTokenSecretRef = &ref
		return
	}
	// Unified / storage-only: layout lives on the local cluster admin.
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		adminPort := DefaultAdminPort
		if cluster.Spec.Admin.BindPort != 0 {
			adminPort = cluster.Spec.Admin.BindPort
		}
		node.Status.ClusterAdminEndpoint = "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, clusterDomain)
		ref := *cluster.Spec.Admin.AdminTokenSecretRef
		node.Status.ClusterAdminTokenSecretRef = &ref
	}
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
// exposing the RPC port externally. Only called when spec.publicEndpoint is set.
//
// When this GarageNode is operator-owned in Auto mode (the cluster controller
// stamped publicEndpoint onto us as part of buildAutoModeStorageNode), the
// cluster controller already provisions the per-pod LoadBalancer Service at
// `<cluster>-<ord>-rpc` via reconcilePerNodeLoadBalancerServices. Creating a
// second Service from here would race with that one and split traffic across
// two different LB IPs. Skip the create in that case — reconcileNodeConfigMap
// still derives rpc_public_addr from the cluster-owned Service via
// effectiveNodeRPCServiceName.
func (r *GarageNodeReconciler) reconcileNodeService(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	if clusterOwnsAutoModePerNodeService(node) {
		return nil
	}
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
func (r *GarageNodeReconciler) reconcileNodeConfigMap(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
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
			svcName := effectiveNodeRPCServiceName(node, cluster)
			if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, svc); err == nil {
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

	// Apply node-level fsync + snapshot overrides.
	if node.Spec.Storage != nil {
		cfgCtx.MetadataFsync = node.Spec.Storage.MetadataFsync
		cfgCtx.DataFsync = node.Spec.Storage.DataFsync
		cfgCtx.NodeMetadataSnapshotsDir = node.Spec.Storage.MetadataSnapshotsDir
		cfgCtx.NodeMetadataAutoSnapshotInterval = node.Spec.Storage.MetadataAutoSnapshotInterval

		// Multi-HDD data_dir: one TOML entry per mounted disk. Capacity is taken
		// from the PVC Size when present (the disk size). When Size is unset
		// and the entry is pinned to an existing PVC (the legacy-STS migration
		// path before #205 left Size empty), fall back to the PVC's requested
		// storage so Garage's parser accepts the data_dir block — upstream
		// `make_data_dirs` rejects entries with no capacity unless read_only
		// is set (../garage src/block/layout.rs).
		if len(node.Spec.Storage.DataPaths) > 0 {
			paths := make([]NodeDataDirPath, 0, len(node.Spec.Storage.DataPaths))
			for i, dp := range node.Spec.Storage.DataPaths {
				p := NodeDataDirPath{Path: effectiveDataPathMount(dp, i), ReadOnly: dp.ReadOnly}
				if !dp.ReadOnly {
					switch {
					case dp.Size != nil && !dp.Size.IsZero():
						p.Capacity = dp.Size.String()
					case dp.ExistingClaim != "":
						if cap := r.lookupPVCCapacity(ctx, cluster.Namespace, dp.ExistingClaim); cap != "" {
							p.Capacity = cap
						}
					}
				}
				paths = append(paths, p)
			}
			cfgCtx.NodeDataDirPaths = paths
		}
	}

	nodeConfig := generateGarageConfig(cluster, cfgCtx)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      node.Name + "-config",
			Namespace: cluster.Namespace,
		},
		Data: map[string]string{configFileName: nodeConfig},
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

// mergeNodeEnv merges cluster-level env with per-node env. Entries from `node`
// override entries from `cluster` with the same Name. The resulting slice
// preserves the cluster order for retained cluster entries, followed by node
// entries in their declared order. Both inputs may be nil/empty.
func mergeNodeEnv(cluster, node []corev1.EnvVar) []corev1.EnvVar {
	if len(node) == 0 {
		return cluster
	}
	overrides := make(map[string]bool, len(node))
	for _, e := range node {
		overrides[e.Name] = true
	}
	out := make([]corev1.EnvVar, 0, len(cluster)+len(node))
	for _, e := range cluster {
		if overrides[e.Name] {
			continue
		}
		out = append(out, e)
	}
	out = append(out, node...)
	return out
}

// effectiveNodeLogging computes the LoggingConfig actually applied to a
// GarageNode pod by overlaying NodeLoggingConfig (per-node) over the cluster's
// LoggingConfig. A nil node override returns the cluster value unchanged. A
// non-nil node override wins per-field; nil pointer fields fall through to
// cluster values, while empty string fields explicitly clear the cluster value
// (the user opted into "no level set").
func effectiveNodeLogging(cluster *garagev1beta2.LoggingConfig, override *garagev1beta1.NodeLoggingConfig) *garagev1beta2.LoggingConfig {
	if override == nil {
		return cluster
	}
	eff := garagev1beta2.LoggingConfig{}
	if cluster != nil {
		eff = *cluster
	}
	if override.Level != "" {
		eff.Level = override.Level
	}
	if override.Syslog != nil {
		eff.Syslog = *override.Syslog
	}
	if override.Journald != nil {
		eff.Journald = *override.Journald
	}
	return &eff
}

// SetupWithManager sets up the controller with the Manager.
//
// Watches in addition to the per-node Owns:
//
//   - GarageCluster (with GenerationChangedPredicate): cluster-level spec
//     changes that rewrite the cluster-shared ConfigMap need to fan out so
//     every per-node StatefulSet picks up the new config-hash annotation.
//     Not every spec change goes through a CM regen (e.g.,
//     spec.replication.factor, layoutManagement toggles) — watching the CR
//     covers those too.
//
//   - corev1.ConfigMap (label-gated): the cluster-shared CM `<cluster>-config`
//     is owned by the cluster controller, not by GarageNode, so the
//     controller's own Owns(ConfigMap) (which is for the per-node override
//     CM, absent on Auto-mode nodes without overrides) does NOT wake us
//     when the cluster CM is rewritten. Without this, a CM rewrite would
//     have to wait for the GarageCluster generation bump to fan out, which
//     means a CM edit by hand or by a non-spec-changing code path would sit
//     unrolled until the next periodic requeue.
//
// Both predicates are intentionally narrow — generation predicate on the CR
// + label gating in the CM mapper — to avoid waking GarageNode reconciles
// for unrelated objects.
func (r *GarageNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageNode{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Watches(
			&garagev1beta2.GarageCluster{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForClusterConfigMap),
		).
		Named("garagenode").
		Complete(r)
}

// nodesForCluster maps a GarageCluster event to reconcile requests for every
// GarageNode whose ClusterRef points at it.
func (r *GarageNodeReconciler) nodesForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	cluster, ok := obj.(*garagev1beta2.GarageCluster)
	if !ok {
		return nil
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range nodes.Items {
		n := &nodes.Items[i]
		// Cross-namespace ClusterRef is supported, but the common case keeps
		// node + cluster co-located. Match by name (and matching namespace
		// when ClusterRef.Namespace is explicitly set).
		if n.Spec.ClusterRef.Name != cluster.Name {
			continue
		}
		if n.Spec.ClusterRef.Namespace != "" && n.Spec.ClusterRef.Namespace != cluster.Namespace {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: n.Name, Namespace: n.Namespace}})
	}
	return out
}

// nodesForClusterConfigMap maps a cluster-shared ConfigMap (<cluster>-config)
// to reconcile requests for every GarageNode in the same namespace whose
// ClusterRef matches. Gated on operator-stamped labels so unrelated CMs in
// the namespace don't wake every GarageNode on every CM change.
//
// Naming: the cluster controller writes the shared CM as `<cluster>-config`
// (see labelsForCluster + writeConfigMap in garagecluster_controller.go),
// labelled with {labelCluster: <cluster>, labelAppManagedBy: operator}. We
// match on the labels first to avoid useless wake-ups, then verify the
// name matches the cluster-shared convention so we don't fan out for the
// `<cluster>-gateway-config` CM (which only the gateway Deployment consumes).
func (r *GarageNodeReconciler) nodesForClusterConfigMap(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}
	labels := cm.GetLabels()
	clusterName := labels[labelCluster]
	if clusterName == "" || labels[labelAppManagedBy] != operatorName {
		return nil
	}
	// Per-node override CMs are already covered by Owns(ConfigMap); skip
	// the gateway-only CM since no GarageNode consumes it.
	if cm.Name != clusterName+"-config" {
		return nil
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(cm.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range nodes.Items {
		n := &nodes.Items[i]
		if n.Spec.ClusterRef.Name != clusterName {
			continue
		}
		if n.Spec.ClusterRef.Namespace != "" && n.Spec.ClusterRef.Namespace != cm.Namespace {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: n.Name, Namespace: n.Namespace}})
	}
	return out
}
