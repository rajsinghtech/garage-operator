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
	stderrors "errors"
	"fmt"
	"net/url"
	"sort"
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
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

const (
	garageClusterFinalizer = "garagecluster.garage.rajsingh.info/finalizer"
	defaultGarageImage     = "dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690"
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

	annotationRPCIdentitySHA256 = "garage.rajsingh.info/rpc-identity-sha256"
	annotationRPCIdentitySource = "garage.rajsingh.info/rpc-identity-source"
)

// GarageClusterReconciler reconciles a GarageCluster object
type GarageClusterReconciler struct {
	client.Client
	APIReader     client.Reader
	Scheme        *runtime.Scheme
	ClusterDomain string
	DefaultImage  string
	// ManagedPVCAdmissionDisabled is propagated to GarageNode workload and
	// storage-rollout recovery paths when the PVC finalizer admission boundary
	// is not installed.
	ManagedPVCAdmissionDisabled bool
	// LayoutMutations is shared with GarageNodeReconciler so every same-cluster
	// Garage layout writer uses one critical section.
	LayoutMutations *LayoutMutationCoordinator
	// NodeLocalPoolPrerequisites proves that the API server implements the Pod
	// scheduling-gate behavior used as the HostPath activation boundary.
	NodeLocalPoolPrerequisites NodeLocalPoolPrerequisiteChecker
	// layoutHistoryGetter is a test seam for the automatic layout-mutation
	// barrier. Production reconcilers leave it nil and read Garage's live Admin
	// API through GetGarageClient.
	layoutHistoryGetter func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error)
	// nodeLocalPoolLayoutGetter is a test seam for cold-start recovery. Production
	// uses Garage's live committed layout to identify selected HostPath members
	// whose roles already exist and whose processes therefore need to start
	// together before that layout can converge.
	nodeLocalPoolLayoutGetter func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error)
	// nodeLocalPoolRolloutStateGetter is a test seam for the live Garage evidence
	// required before an OnDelete node-local-pool rollout stops one identity.
	nodeLocalPoolRolloutStateGetter func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error)
	// Test seams for the upstream object-block migration barrier. Production
	// reads workers from every current storage node, launches exact Blocks repair
	// transactions, and uses the RPC-derived default quiet period.
	blockResyncObservationGetter func(context.Context, *garage.Client) (*blockResyncObservation, error)
	blockRepairLauncher          func(context.Context, *garage.Client, string) error
	clusterHealthGetter          func(context.Context, *garage.Client) (*garage.ClusterHealth, error)
	blockResyncQuietPeriod       time.Duration
	// Test seam for first-upgrade static Admin-token verification. Production
	// sends the token only to the exact ownership-proven Pod set.
	staticAdminTokenProbe func(context.Context, string, string) error
	// ClusterScoped is true when the manager caches/watches all namespaces
	// (no --watch-namespaces). A namespace-scoped Role cannot authorize
	// access to the cluster-scoped Node resource, so the Node watch/List used
	// by clusters with DaemonSet node-local pools is only safe to use when this is true.
	ClusterScoped bool
	// WatchNamespaces is the exact namespace set configured on a namespace-scoped
	// manager. Finalization uses it for authoritative per-namespace APIReader
	// discovery without requiring an unauthorized cluster-wide List.
	WatchNamespaces []string
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// ReplicaSets are read-only: the released-environment migration walks
// Deployment -> ReplicaSet -> Pod to prove which live Garage processes share an
// RPC identity. The operator never creates or mutates a ReplicaSet.
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

func (r *GarageClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx = withNodeLocalPoolPrerequisiteSession(ctx)
	log := logf.FromContext(ctx)
	_ = log // Used in sub-functions via context

	cluster := &garagev1beta2.GarageCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	// Finalization can persist a storage-drain transaction and immediately be
	// requeued by an older informer event. Re-read deleting objects directly from
	// the API server so a stale cached snapshot cannot forget that transaction and
	// release workloads while Garage's role-removal layout is still draining.
	if !cluster.DeletionTimestamp.IsZero() && r.APIReader != nil {
		authoritative := &garagev1beta2.GarageCluster{}
		if err := r.APIReader.Get(ctx, req.NamespacedName, authoritative); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("re-reading deleting GarageCluster from the API server: %w", err)
		}
		adoptGarageClusterSnapshot(cluster, authoritative)
	}
	if cluster.DeletionTimestamp.IsZero() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		if cluster.Spec.ConnectTo.ClusterRef.KubeConfigSecretRef != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf(
				"spec.connectTo.clusterRef.kubeConfigSecretRef is not supported; the operator can reference GarageClusters only through its configured Kubernetes client",
			))
		}
		if namespace := cluster.Spec.ConnectTo.ClusterRef.Namespace; namespace != "" && namespace != cluster.Namespace {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf(
				"spec.connectTo.clusterRef.namespace must be empty or match metadata.namespace",
			))
		}
		if err := garageconfig.ValidateNamespacedObjectReference(
			cluster.Spec.ConnectTo.ClusterRef.Name,
			cluster.Spec.ConnectTo.ClusterRef.Namespace,
			"spec.connectTo.clusterRef",
		); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}
	}
	if cluster.DeletionTimestamp.IsZero() {
		if err := validateGarageClusterRuntimeConfig(cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("invalid Garage configuration: %w", err))
		}
	}
	referencedLayoutBoundaryActive, err := r.rehydrateLayoutOwnerRollout(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !cluster.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(cluster, garageClusterFinalizer) {
			blocked, retryAfter, prerequisiteErr := r.blockForNodeLocalPoolPrerequisites(ctx, cluster)
			if prerequisiteErr != nil {
				return ctrl.Result{}, prerequisiteErr
			}
			if blocked {
				if retryAfter <= 0 {
					retryAfter = RequeueAfterLong
				}
				return ctrl.Result{RequeueAfter: retryAfter}, nil
			}
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
	prerequisiteBlocked, prerequisiteRetryAfter, err := r.blockForNodeLocalPoolPrerequisites(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if prerequisiteBlocked {
		if prerequisiteRetryAfter <= 0 {
			prerequisiteRetryAfter = RequeueAfterLong
		}
		return ctrl.Result{RequeueAfter: prerequisiteRetryAfter}, nil
	}
	// Explicit dead-node recovery must remain reachable while the durable drain
	// it is intended to unblock is active. Process it before ordinary rollout and
	// drain boundaries, then remove the one-shot annotations only after Garage
	// confirms the cluster-wide operation.
	if cluster.Annotations != nil {
		if _, requested := cluster.Annotations[garagev1beta1.AnnotationSkipDeadNodes]; requested {
			if err := r.handleSkipDeadNodes(ctx, cluster); err != nil {
				return ctrl.Result{}, err
			}
			delete(cluster.Annotations, garagev1beta1.AnnotationSkipDeadNodes)
			delete(cluster.Annotations, garagev1beta1.AnnotationAllowMissingData)
			if err := r.Update(ctx, cluster); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing processed skip-dead-nodes annotations: %w", err)
			}
			return ctrl.Result{Requeue: true}, nil
		}
	}
	if referencedLayoutBoundaryActive {
		// A clusterRef edge/management object shares the referenced Garage layout.
		// Freeze all ordinary reconciliation—including repair annotations and worker
		// variables—while that durable owner rolls a process or proves a removal.
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}

	// deletionPolicy: Drain is prepared while the GarageCluster is still a
	// normal, editable object. The annotation freezes ordinary reconciliation,
	// removes every exact local role while all processes remain online, and
	// holds here until the source/destination proof is terminal. DELETE admission
	// requires that proof, eliminating an irreversible deletionTimestamp failure
	// if Garage rejects Apply or a source disappears.
	if cluster.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue {
		prepared, err := r.prepareGarageClusterDrain(ctx, cluster)
		if err != nil {
			if stderrors.Is(err, errLayoutMutationPending) || stderrors.Is(err, errLayoutRoleDraining) ||
				stderrors.Is(err, errUnsafeLayoutRoleRemoval) {
				return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
			}
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("preparing GarageCluster Drain deletion: %w", err))
		}
		if prepared {
			return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
		}
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}

	// A positive-capacity removal owns the whole layout and freezes every
	// ordinary workload, federation, worker, annotation, and factor-migration
	// mutation. The GarageNode actor advances it; this controller only recovers
	// the post-finalizer crash window described by recoverOrphanedStorageDrain.
	storageDrainBlocked, err := r.recoverOrphanedStorageDrain(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if storageDrainBlocked {
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}
	legacyEnvironmentMigration := legacyEnvironmentMigrationState{}
	legacyEnvironmentCheckNeeded, err := r.legacyEnvironmentMigrationNeeded(ctx, cluster, true)
	if err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed,
			fmt.Errorf("inventorying released Garage environments: %w", err))
	}
	if legacyEnvironmentCheckNeeded {
		legacyEnvironmentMigration, err = r.evaluateLegacyEnvironmentMigration(ctx, cluster, false)
		if err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed,
				fmt.Errorf("released Garage environment migration is blocked: %w", err))
		}
		if legacyEnvironmentMigration.blocked {
			return r.updateStatus(ctx, cluster, PhaseFailed,
				fmt.Errorf("released Garage environment migration is waiting: %s", legacyEnvironmentMigration.message))
		}
	}
	if err := validateGarageClusterRuntimeSafety(cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed,
			fmt.Errorf("refusing ordinary reconciliation of a released unsafe GarageCluster: %w", err))
	}

	// Replay a persisted pod handoff before rendering ConfigMaps or workload
	// templates. This ordering makes recovery stable across manager/operator
	// upgrades: the recorded desired hashes remain authoritative until the exact
	// h1 replacement completes, then normal reconciliation may render h2.
	if cluster.Status.StorageRollout != nil {
		if err := r.rollForwardStorageRollout(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("rolling forward failed storage workload: %w", err))
		}
		// A replacement normally retains its metadata, but storage backends are
		// heterogeneous and need not preserve the full-copy token row. Reconnect
		// the rolled-forward process with its mounted static credential before
		// asking that exact Pod set to authenticate dynamically.
		if clusterControllerOwnsBootstrap(cluster) && garageNodesOwnStorageLayout(cluster) {
			if err := r.bootstrapCluster(ctx, cluster); err != nil {
				log.V(1).Info("Local storage peers are not connected on the active rollout Pod set yet", "error", err)
			}
		}
		// A replacement GarageNode publishes its new observedPodUid through an
		// Admin client. Once a dynamic operator token is authoritative, that
		// client deliberately rejects a Pod set whose exact UID hash has not yet
		// been verified. Refresh the token proof before rollout recovery waits on
		// the GarageNode status, otherwise both controllers wait on one another:
		// the node needs the refreshed token to publish the UID, and recovery
		// needs the published UID before normal token reconciliation can resume.
		// Verification is retryable just like the ordinary post-bootstrap path;
		// the durable rollout actor remains the safety boundary while the token
		// row reaches the replacement process.
		if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
			log.V(1).Info("Operator dynamic Admin token is not ready on the active storage rollout Pod set", "error", err)
		}
	}
	rolloutBlocked, err := r.recoverStorageRollout(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if rolloutBlocked {
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}

	if cluster.Spec.Maintenance != nil && cluster.Spec.Maintenance.Suspended {
		log.Info("Reconciliation paused")
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}
	usesNodeDerivedZones := cluster.Spec.ZoneFrom != nil &&
		(hasNodeLocalPools(cluster) || (cluster.HasStorageTier() &&
			effectiveStorageLayoutPolicy(cluster) != LayoutPolicyManual && cluster.Spec.Storage.Replicas > 0))
	if usesNodeDerivedZones && !r.ClusterScoped {
		return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf(
			"spec.zoneFrom requires a cluster-scoped operator install because Kubernetes Node labels are the topology source; redeploy without --watch-namespaces/WATCH_NAMESPACE",
		))
	}

	// Management handle (#269): spec.connectTo only, no storage/gateway tier. The
	// operator owns no workload here — it only manages the external Garage's
	// Admin-API state (buckets/keys/layout). Handle it before the tier reconcile,
	// which would otherwise try to build a managed Service, ConfigMap, RPC secret,
	// and StatefulSets that must not exist for a handle.
	if cluster.IsManagementHandle() {
		return r.reconcileManagementHandle(ctx, cluster)
	}
	// Ensure RPC secret exists
	if _, err := r.ensureRPCSecret(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}
	if legacyEnvironmentMigration.completeRPCSnapshot {
		if err := r.completeLegacyRPCEnvironmentMigration(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	// Create or update ConfigMap(s) and get config hashes for pod restart triggering.
	// Storage and gateway tiers may use different rpc_public_addr values when both
	// are declared with a gateway-specific spec.gateway.rpcPublicAddr.
	//
	// This deliberately runs before the first static credential snapshot. The
	// snapshot's first-upgrade proof requires the exact managed StatefulSet/Pod
	// set, while a manually declared GarageNode cannot create that workload until
	// this immutable ConfigMap revision exists. buildConfigContext is safe here:
	// without a persisted snapshot it reads the configured Consul source directly,
	// and the RPC identity was ensured above. This ordering lets one GitOps wave
	// make progress instead of leaving the cluster and nodes waiting on each other.
	// The cluster-level Reconcile no longer drives a default storage STS
	// directly, but its ConfigMap must still be reconciled so per-node
	// StatefulSets pick it up. Named node-local pools receive independent hashes.
	gatewayConfigHash, nodeLocalPoolConfigHashes, err := r.reconcileConfigMap(ctx, cluster)
	if err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}

	// Garage reads static admin/metrics and Consul credentials only at startup.
	// Publish one immutable content-addressed revision before rendering any
	// workload so kubelet source projection cannot change bytes underneath a
	// process that will never reload them. The first pass above intentionally
	// makes the workload possible; if publishing the snapshot changes the pin,
	// render once more so credential rotation and the first successful bootstrap
	// use the new snapshot in the same reconcile.
	pinnedRevisionBeforeSnapshot := cluster.Annotations[annotationStaticCredentialsRevision]
	if _, err := r.ensureStaticCredentialSnapshot(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}
	if err := r.retireUndesiredOperatorTokens(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}
	if cluster.Annotations[annotationStaticCredentialsRevision] != pinnedRevisionBeforeSnapshot {
		gatewayConfigHash, nodeLocalPoolConfigHashes, err = r.reconcileConfigMap(ctx, cluster)
		if err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, err)
		}
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

	// Coordinated replication-factor migration (purge-cluster-layout). When active,
	// the operator owns the storage StatefulSets and drives a multi-phase purge +
	// layout rebuild. It runs AFTER the ConfigMap is refreshed with the new factor
	// (so restarted pods read it) but BEFORE the per-tier workload reconciliation,
	// returning early so the normal path does not race the purge.
	if factorMigrationActive(cluster) {
		// Refresh the dynamic operator token proof first, for the same reason
		// rollout recovery does above: once that token is authoritative, an Admin
		// client rejects a Pod set whose exact UID hash has not been verified. The
		// purge deliberately restarts every storage process, so the incarnation set
		// always changes — and because this branch returns early, the ordinary token
		// reconciliation below is never reached. Without this, RebuildingLayout
		// waits forever for an Admin client that nothing can re-verify while the
		// per-node controllers are suspended. Best-effort: during ScalingDown and
		// Purging the pods are intentionally gone, so failure here is expected and
		// the phase handlers keep their own retry/stuck bounds.
		if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
			log.V(1).Info("Operator dynamic Admin token is not ready on the factor-migration Pod set", "error", err)
		}
		return r.reconcileFactorMigration(ctx, cluster)
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
	// longer created post-#190. Unified gateways likewise use one GarageNode-owned
	// StatefulSet per identity; edge gateways retain one cluster-level StatefulSet.
	// Default StatefulSet/PVC group — gated on the STORAGE tier's effective layout
	// policy (spec.storage.layoutPolicy, else the cluster default). Named
	// node-local pools are additive and reconciled independently below, so a
	// Manual default pool (for SMB/heterogeneous GarageNodes) can coexist with
	// operator-managed local-disk pools.
	if effectiveStorageLayoutPolicy(cluster) != LayoutPolicyManual {
		switch {
		case cluster.HasStorageTier():
			// Auto mode: migrate any pre-#190 legacy storage STS, then reconcile
			// the per-node GarageNodes that replace it.
			if err := r.migrateLegacyStorageSTSIfNeeded(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("legacy STS migration: %w", err))
			}
			if err := r.reconcileAutoModeStorageNodes(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		default:
			// No storage tier declared — clean up any leftover legacy STS and
			// default-pool operator-owned child GarageNodes. Retired DaemonSet
			// pools drain through their independent reconciler below.
			if err := r.deleteStorageStatefulSet(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
			if err := r.deleteAutoModeStorageNodes(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		}
	} else if err := r.ejectAutoModeStorageNodes(ctx, cluster); err != nil {
		// Manual storage: if the previous policy was Auto and operator-owned
		// storage GarageNodes still exist, eject them so the user can take over.
		return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("ejecting Auto-mode storage GarageNodes: %w", err))
	}
	if storageDrainConditionActive(cluster) {
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}

	// Named local-disk pools remain operator-managed under either Auto or
	// Manual default-pool policy. Calling this with an empty desired list is
	// intentional: removed pools keep their pods online while GarageNode
	// finalizers drain roles, then their activation labels/resources are
	// cleaned up.
	if err := r.reconcileNodeLocalPools(ctx, cluster, nodeLocalPoolConfigHashes); err != nil {
		if stderrors.Is(err, errLayoutMutationPending) {
			return r.updateStatusAfterNodeLocalPoolContention(ctx, cluster, err)
		}
		return r.updateStatus(ctx, cluster, PhaseFailed, err)
	}
	if storageDrainConditionActive(cluster) {
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}

	// Gateway tier — gated on the cluster-level layout policy (no per-tier
	// override; the gateway tier follows spec.layoutPolicy).
	//   - Unified cluster (storage + gateway): the gateway tier runs as
	//     per-node GarageNodes (gateway:true) whose layout lives on the LOCAL
	//     cluster, exactly like the storage tier. The legacy cluster-level
	//     gateway StatefulSet is removed; gateway pods get capacity=nil layout
	//     roles via the GarageNode controller (the #209 fix).
	//   - Edge / standalone gateway (gateway-only + connectTo): the layout
	//     lives on a REMOTE storage cluster, so we keep the cluster-level
	//     StatefulSet + gateway-connection path that already handles remote
	//     admin routing.
	if cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		if cluster.HasGatewayTier() {
			if cluster.HasStorageTier() {
				// #221: before tearing down the pre-#210 cluster-level gateway STS,
				// adopt its metadata PVCs into per-node GarageNodes so the gateway
				// node_key (identity) survives the upgrade. The migration
				// orphan-deletes the old STS itself, so the subsequent
				// deleteGatewayStatefulSet is a no-op (NotFound) on the happy path.
				if err := r.migrateLegacyGatewaySTSIfNeeded(ctx, cluster); err != nil {
					return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("legacy gateway STS migration: %w", err))
				}
				if err := r.deleteGatewayStatefulSet(ctx, cluster); err != nil {
					return r.updateStatus(ctx, cluster, PhaseFailed, err)
				}
				if err := r.reconcileAutoModeGatewayNodes(ctx, cluster); err != nil {
					return r.updateStatus(ctx, cluster, PhaseFailed, err)
				}
			} else {
				if err := r.deleteAutoModeGatewayNodes(ctx, cluster); err != nil {
					return r.updateStatus(ctx, cluster, PhaseFailed, err)
				}
				if err := r.reconcileGatewayStatefulSet(ctx, cluster, gatewayConfigHash); err != nil {
					return r.updateStatus(ctx, cluster, PhaseFailed, err)
				}
			}
		} else {
			if err := r.deleteGatewayStatefulSet(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
			if err := r.deleteAutoModeGatewayNodes(ctx, cluster); err != nil {
				return r.updateStatus(ctx, cluster, PhaseFailed, err)
			}
		}
	} else if err := r.ejectAutoModeGatewayNodes(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("ejecting Auto-mode gateway GarageNodes: %w", err))
	}

	// New local storage processes must join the RPC mesh before Garage can
	// replicate and verify the table-backed operator token on them. Do this with
	// each Pod's mounted static credential before rollout readiness can return
	// early. bootstrapCluster delegates all layout writes back to GarageNode for
	// these topologies, so this is only a peer-connect nudge across Auto,
	// Manual/SMB, and named node-local pools.
	storagePeerBootstrapAttempted := false
	if clusterControllerOwnsBootstrap(cluster) && garageNodesOwnStorageLayout(cluster) {
		storagePeerBootstrapAttempted = true
		if err := r.bootstrapCluster(ctx, cluster); err != nil {
			log.V(1).Info("Local storage peers are not connected on the desired managed Pod set yet", "error", err)
		}
	}

	// GarageNode and node-local-pool reconciliation authenticates through the
	// dynamic operator token once it is authoritative. Refresh its exact Pod-set
	// proof after all desired workloads have been rendered but before rollout
	// readiness can return early. This covers additive scale-out, whose new
	// GarageNode/Pod is an initializing topology member rather than a persisted
	// replacement actor: without this boundary the node cannot publish its first
	// observedPodUid, while rollout readiness waits for exactly that status.
	operatorAdminTokenReady := false
	if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
		log.V(1).Info("Operator dynamic Admin token is not ready on the desired managed Pod set", "error", err)
	} else {
		operatorAdminTokenReady = true
	}

	// Every GarageNode StatefulSet and node-local-pool DaemonSet is OnDelete. Drive one
	// cluster-wide handoff for PVC, Manual SMB, node-local, mixed, and unified
	// GarageNode topologies after all controllers have published their desired
	// templates. A cluster-level edge gateway StatefulSet has no per-ordinal
	// GarageNode identity record, so it retains Kubernetes' ordered Ready-gated
	// RollingUpdate behavior in this API version.
	transitionBoundary := storageRolloutMutationBoundaryActive(cluster)
	rolloutActorWasActive := cluster.Status.StorageRollout != nil
	rolloutComplete, rolloutMessage, err := r.reconcileStorageRollout(ctx, cluster)
	if err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("reconciling storage rollout: %w", err))
	}
	if !rolloutComplete {
		if cluster.Status.StorageRollout != nil {
			// ensureNodeLocalPoolRolloutExclusion already persisted the exact actor and
			// RollingOut condition atomically. Do not run bootstrap, federation, or
			// operational layout actions after beginning the outage.
			if !rolloutActorWasActive {
				// Cross an immediate reconciliation boundary after the status write.
				// Durability comes from the persisted actor, not from sleeping for the
				// periodic safety interval before deleting its old Pod.
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		reason := garagev1beta1.ReasonStorageRolloutInitializing
		if transitionBoundary {
			reason = garagev1beta1.ReasonStorageRolloutWaiting
		}
		if err := r.setStorageRolloutCondition(ctx, cluster, metav1.ConditionFalse,
			reason, rolloutMessage); err != nil {
			return ctrl.Result{}, err
		}
		if transitionBoundary {
			// Do not let federation, tombstones, operational annotations, or
			// worker mutations overtake a configuration generation whose managed
			// processes have not converged.
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
	} else {
		if err := r.setStorageRolloutCondition(ctx, cluster, metav1.ConditionTrue,
			garagev1beta1.ReasonStorageRolloutConverged,
			"all GarageNode and node-local-pool identities are Ready on the desired workload and configuration revisions"); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.finishNodeLocalPoolRolloutExclusion(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.cleanupObsoleteGarageConfigResources(ctx, cluster); err != nil {
			return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("cleaning obsolete Garage config resources: %w", err))
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
	if clusterControllerOwnsBootstrap(cluster) && !storagePeerBootstrapAttempted {
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

	// Once the initial layout and federation connections exist, bootstrap a
	// table-backed full-scope token for operator control. Failure is reported and
	// retried, but does not prevent the static bootstrap token from continuing to
	// form/connect the cluster on this pass.
	if !operatorAdminTokenReady {
		if err := r.reconcileOperatorAdminToken(ctx, cluster); err != nil {
			log.Error(err, "Operator dynamic Admin token is not ready yet")
		}
	}
	if err := r.reconcileOperatorMetricsToken(ctx, cluster); err != nil {
		log.Error(err, "Operator dynamic metrics token is not ready yet")
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
	monitoringErr := r.reconcileMonitoring(ctx, cluster)
	if monitoringErr != nil {
		log.Error(monitoringErr, "Failed to reconcile monitoring resources")
		// Non-fatal: monitoring failure shouldn't block storage reconciliation
	} else if err := r.cleanupUnusedStaticCredentialSnapshots(ctx, cluster); err != nil {
		return r.updateStatus(ctx, cluster, PhaseFailed, fmt.Errorf("cleaning obsolete static credential revisions: %w", err))
	}

	// Update status with cluster health
	return r.updateStatusFromCluster(ctx, cluster)
}

func clusterControllerOwnsBootstrap(cluster *garagev1beta2.GarageCluster) bool {
	if cluster == nil {
		return false
	}
	// Manual/SMB and node-local processes need the same RPC reconnect nudge as
	// Auto storage. This does not transfer layout ownership: bootstrapCluster
	// stops after peer connection for every GarageNode-owned storage topology.
	localStorageNodes := garageNodesOwnStorageLayout(cluster)
	gatewayAuto := cluster.HasGatewayTier() && cluster.Spec.LayoutPolicy != LayoutPolicyManual
	return localStorageNodes || gatewayAuto
}

func garageNodesOwnStorageLayout(cluster *garagev1beta2.GarageCluster) bool {
	return cluster != nil && (cluster.HasStorageTier() || cluster.HasNodeLocalPools())
}

// rehydrateLayoutOwnerRollout closes the manager-restart ordering gap for an
// edge gateway whose layout owner is another in-cluster GarageCluster. The
// gateway object does not carry the storage cluster's durable rollout or drain
// status, so load it before any gateway finalizer/tombstone/bootstrap path can
// acquire that shared layout key.
func (r *GarageClusterReconciler) rehydrateLayoutOwnerRollout(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	owner, err := resolveGarageLayoutOwner(ctx, r.safetyReader(), cluster)
	if err != nil {
		// Deletion must still reach finalize when a referenced storage CR was
		// removed first. A management handle owns nothing locally, and an edge
		// gateway's finalizer already treats unreachable referenced layout
		// cleanup as best effort. Live reconciliation remains fail closed.
		if errors.IsNotFound(err) && !cluster.DeletionTimestamp.IsZero() {
			return false, nil
		}
		return false, fmt.Errorf("reading canonical layout-owner GarageCluster before reconciliation: %w", err)
	}
	referencedOwner := owner.UID != cluster.UID || owner.Name != cluster.Name || owner.Namespace != cluster.Namespace
	coordinator := r.layoutMutationCoordinator()
	key := layoutOwnerKey(owner)
	if err := rehydrateNodeLocalPoolRolloutsForOwner(ctx, r.safetyReader(), coordinator, owner, r.ClusterScoped); err != nil {
		return false, err
	}
	if err := rehydrateStorageDrainsForOwner(ctx, r.safetyReader(), coordinator, owner, r.ClusterScoped, r.APIReader != nil); err != nil {
		return false, err
	}
	markerOwnedBySource, markerStatusConfirmed := coordinator.NodeLocalPoolRolloutSourceActive(key, cluster.UID)
	markerBlocksSource := coordinator.NodeLocalPoolRolloutActive(key) &&
		(!markerOwnedBySource || !markerStatusConfirmed)
	return markerBlocksSource || referencedOwner && (coordinator.StorageDrainActive(key) ||
		storageRolloutMutationBoundaryActive(owner)), nil
}

func completedCapacitylessGatewayRetirement(cluster *garagev1beta2.GarageCluster) bool {
	if cluster == nil || !cluster.HasGatewayTier() || cluster.HasStorageTier() || cluster.HasNodeLocalPools() {
		return false
	}
	proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
	return proof != nil && proof.CompletedAt != nil && len(proof.RemovedStorageNodeIDs) == 0 &&
		sameStorageDrainActor(proof.Actor, storageDrainActorForCluster(cluster))
}

func (r *GarageClusterReconciler) finalize(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	log.Info("Finalizing GarageCluster", "name", cluster.Name)
	requiresNodeLocalCapability, err := r.nodeLocalPoolPrerequisitesRequired(ctx, cluster)
	if err != nil {
		return err
	}
	if requiresNodeLocalCapability {
		if err := r.assertNodeLocalPoolPrerequisites(ctx, cluster); err != nil {
			return err
		}
	} else if err := r.deleteRetainedNodeLocalPoolSchedulerProbe(ctx, cluster); err != nil {
		return err
	}

	// GarageBucket/GarageKey finalizers require the cluster's Admin connection.
	// Enumerate and wait for every referencing dependent before dismantling any
	// kind of cluster, not only management handles. Owner references cannot span
	// namespaces and background GC does not make an owner wait for dependent
	// finalizers, so relying on GC would let the cluster disappear first and make
	// the children's cluster-missing fast path abandon remote cleanup.
	pending, err := r.deleteGarageResourceDependents(ctx, cluster)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("waiting for GarageBucket and GarageKey dependents to finalize through cluster %s/%s", cluster.Namespace, cluster.Name)
	}
	// A management handle (#269) owns no K8s workload and no Garage layout roles;
	// after its dependents are gone there is nothing else to finalize.
	if cluster.IsManagementHandle() {
		return nil
	}
	if storageRolloutMutationBoundaryActive(cluster) {
		existing, _, err := r.listNodeLocalPoolStorageNodes(ctx, cluster)
		if err != nil {
			return fmt.Errorf("checking node-local-pool identities before cluster finalization: %w", err)
		}
		blocked, err := r.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
		if err != nil {
			return err
		}
		if blocked {
			return fmt.Errorf("%w: waiting for the active managed pod replacement before deleting cluster workloads", errLayoutMutationPending)
		}
	} else if r.layoutMutationCoordinator().NodeLocalPoolRolloutActive(layoutOwnerKey(cluster)) {
		return fmt.Errorf("%w: waiting for the referenced storage cluster's active managed pod replacement", errLayoutMutationPending)
	}

	// Drain is an explicit federated-site retirement workflow. Destroy is a
	// whole-store teardown and deliberately skips Garage's impossible empty
	// storage-layout transition. Gateway-only clusters always clean their
	// capacity-less roles from the referenced surviving storage layout.
	drainLayout := !cluster.HasStorageTier() ||
		cluster.EffectiveDeletionPolicy() == garagev1beta2.DeletionPolicyDrain
	completedClusterDrain, err := completedGarageClusterDrainAuthorizesFinalization(cluster)
	if err != nil {
		return fmt.Errorf("validating terminal GarageCluster drain handoff: %w", err)
	}
	if drainLayout && !completedClusterDrain {
		// Collect every referencing GarageNode ID before those dependent objects
		// are deleted. This includes user-authored Manual/SMB nodes.
		knownNodeIDs, err := r.collectGarageNodeIDs(ctx, cluster)
		if err != nil {
			return fmt.Errorf("building exact local identity inventory for Drain cleanup: %w", err)
		}
		// An operator upgrade can be followed immediately by deletion before the
		// legacy cluster-owned storage StatefulSet has migrated to GarageNodes or
		// its roles have acquired UID tags. Discover each live, exactly owned pod;
		// if any desired ordinal cannot identify itself, Drain must fail closed.
		if cluster.HasStorageTier() {
			legacyStorageNodeIDs, discoverErr := r.collectLiveLegacyStorageNodeIDs(ctx, cluster)
			if discoverErr != nil {
				return fmt.Errorf("building exact legacy storage identity inventory for Drain cleanup: %w", discoverErr)
			}
			for id := range legacyStorageNodeIDs {
				knownNodeIDs[id] = true
			}
		}
		// Pre-GarageNode edge gateway StatefulSets have no per-ordinal CR status,
		// and their legacy layout roles predate the cluster-uid tag. While their
		// pods are still alive behind this finalizer, query each exact owned pod's
		// local Admin API and add its self identity to the deletion inventory. If
		// discovery is unavailable, modern UID-tag cleanup still works and the
		// gateway-only best-effort policy below remains unchanged; ambiguous dead
		// legacy roles are never guessed from name/namespace tags.
		if cluster.HasGatewayTier() && !cluster.HasStorageTier() {
			gatewayNodeIDs, discoverErr := r.collectLiveEdgeGatewayNodeIDs(ctx, cluster)
			if discoverErr != nil {
				log.V(1).Info("Could not discover live legacy edge gateway identities during finalization", "error", discoverErr)
			} else {
				for id := range gatewayNodeIDs {
					knownNodeIDs[id] = true
				}
			}
		}
		if err := r.removeNodesFromLayout(ctx, cluster, knownNodeIDs); err != nil {
			// A storage role may still own the only copy of partitions in an active
			// layout. Fail closed: child GarageNode finalizers intentionally skip
			// their own removal once the parent is deleting, so continuing here would
			// stop storage without any remaining layout safety gate.
			if cluster.HasStorageTier() || cluster.HasNodeLocalPools() {
				return fmt.Errorf("waiting for safe Garage layout cleanup before deleting storage workloads: %w", err)
			}
			// A coordinator exclusion or an unsafe role classification is a
			// retryable safety decision, not an unreachable-remote best-effort
			// case. Releasing the finalizer here would permanently orphan the
			// exact role after the competing layout operation finishes.
			if stderrors.Is(err, errLayoutMutationPending) ||
				stderrors.Is(err, errLayoutRoleDraining) ||
				stderrors.Is(err, errUnsafeLayoutRoleRemoval) {
				return fmt.Errorf("waiting for safe Garage layout cleanup before deleting gateway workloads: %w", err)
			}
			// Gateway-only roles carry no object blocks. Preserve the historical
			// best-effort teardown for an unreachable external storage cluster.
			log.Error(err, "Failed to remove gateway nodes from layout (continuing with cleanup)")
		}
	} else if !drainLayout {
		log.Info("Destroy cleanup selected; skipping Garage layout mutation for whole-store teardown")
	} else {
		// The exact terminal proof is a durable authorization to finish local
		// Kubernetes cleanup. A restart may land here after the Admin Service or
		// some target pods are already gone; do not make their expected absence a
		// new prerequisite for completing deletion.
		log.Info("Resuming Kubernetes cleanup after completed Garage storage drain",
			"transaction", cluster.Status.StorageDrain.TransactionID)
	}
	survivingLayout := (!cluster.HasStorageTier() && cluster.HasGatewayTier()) ||
		(cluster.HasStorageTier() && cluster.EffectiveDeletionPolicy() == garagev1beta2.DeletionPolicyDrain)
	if survivingLayout {
		var revocationErrors []error
		if err := r.revokeOperatorMetricsToken(ctx, cluster); err != nil {
			revocationErrors = append(revocationErrors, fmt.Errorf("metrics token: %w", err))
		}
		if err := r.revokeOperatorAdminToken(ctx, cluster); err != nil {
			revocationErrors = append(revocationErrors, fmt.Errorf("full-scope operator token: %w", err))
		}
		if len(revocationErrors) > 0 {
			joined := stderrors.Join(revocationErrors...)
			if cluster.Annotations[garagev1beta1.AnnotationForceDeleteUnrevokedOperatorTokens] != annotationTrue {
				return fmt.Errorf(
					"revoking site-owned dynamic credentials before federated teardown failed: %w; restore a surviving Admin endpoint or explicitly set %s=true to delete only the local one-time Secrets and accept that any copied bearer may remain valid remotely",
					joined,
					garagev1beta1.AnnotationForceDeleteUnrevokedOperatorTokens,
				)
			}
			log.Error(joined, "Forcing teardown with unrevoked remote operator credential rows")
			if err := r.abandonLocalOperatorTokenSecrets(ctx, cluster); err != nil {
				return fmt.Errorf("abandoning local operator credential Secrets after explicit force: %w", err)
			}
		}
	}

	// Delete owned resources in order: current workloads, legacy Deployment,
	// Services, ConfigMap.
	// Note: Secret is auto-deleted via owner reference if controller-generated

	// Delete StatefulSet (for storage clusters)
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err == nil {
		if !metav1.IsControlledBy(sts, cluster) {
			log.Info("Leaving foreign same-name StatefulSet untouched during finalization", "name", sts.Name)
		} else {
			log.Info("Deleting StatefulSet", "name", sts.Name)
			if err := r.Delete(ctx, sts); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete StatefulSet: %w", err)
			}
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete additive node-local pool DaemonSets. HostPath data on the Nodes is
	// intentionally left in place.
	if err := r.deleteStorageDaemonSet(ctx, cluster); err != nil {
		return fmt.Errorf("failed to delete storage DaemonSet: %w", err)
	}

	// GarageNodes are logical dependents even in Manual mode, where they are
	// intentionally not owner-referenced. Delete all referencing nodes with
	// foreground propagation and keep shared config/services until their
	// StatefulSets are gone.
	pendingGarageNodes, err := r.deleteReferencingGarageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	if pendingGarageNodes {
		return fmt.Errorf("%w: waiting for referencing GarageNodes and their workloads to terminate", errLayoutMutationPending)
	}

	// Delete any legacy gateway Deployment left by a pre-StatefulSet operator.
	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, deploy); err == nil {
		if !metav1.IsControlledBy(deploy, cluster) {
			log.Info("Leaving foreign same-name Deployment untouched during finalization", "name", deploy.Name)
		} else {
			log.Info("Deleting Deployment", "name", deploy.Name)
			if err := r.Delete(ctx, deploy); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete Deployment: %w", err)
			}
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Delete API Services (primary + per-tier gateway sibling)
	for _, svcName := range []string{cluster.Name, cluster.Name + "-gateway"} {
		apiSvc := &corev1.Service{}
		if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, apiSvc); err == nil {
			if !metav1.IsControlledBy(apiSvc, cluster) {
				log.Info("Leaving foreign same-name API Service untouched during finalization", "name", apiSvc.Name)
				continue
			}
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
		if !metav1.IsControlledBy(headlessSvc, cluster) {
			log.Info("Leaving foreign same-name headless Service untouched during finalization", "name", headlessSvc.Name)
		} else {
			log.Info("Deleting Headless Service", "name", headlessSvc.Name)
			if err := r.Delete(ctx, headlessSvc); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete Headless Service: %w", err)
			}
		}
	} else if !errors.IsNotFound(err) {
		return err
	}

	// ConfigMap and Secret config revisions are exact controller-owned children.
	// Owner-reference garbage collection removes both kinds after this finalizer
	// releases the GarageCluster. Never delete a fixed same-name object here: a
	// reconcile-blocking user collision is still not ours to destroy.

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
		if !metav1.IsControlledBy(pdb, cluster) {
			log.Info("Leaving foreign same-name PDB untouched during finalization", "name", pdb.Name)
			continue
		}
		log.Info("Deleting PDB", "name", pdb.Name)
		if err := r.Delete(ctx, pdb); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete PDB: %w", err)
		}
	}

	// A foreground-deletion capability probe is intentionally ownerless so the
	// garbage collector cannot remove it while this finalizer still needs the
	// scheduler proof. Namespace-cached evidence can let this terminal pass skip
	// reading the probe, so explicit cleanup must happen after every retained
	// node-local artifact has been retired and before the parent finalizer is
	// released.
	if err := r.deleteRetainedNodeLocalPoolSchedulerProbe(ctx, cluster); err != nil {
		return err
	}

	log.Info("GarageCluster finalization complete", "name", cluster.Name)
	return nil
}

func (r *GarageClusterReconciler) deleteGarageResourceDependents(ctx context.Context, cluster *garagev1beta2.GarageCluster) (bool, error) {
	// Namespace-scoped Roles cannot authorize an all-namespace List. Read every
	// configured namespace separately through the uncached APIReader so this
	// terminal barrier is authoritative without broadening RBAC. Cluster-scoped
	// installs retain one authoritative all-namespace List.
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if !r.ClusterScoped && len(r.WatchNamespaces) == 0 {
		return false, fmt.Errorf("namespace-scoped GarageCluster finalization requires the configured watch namespace set")
	}
	pending := false
	targets, err := r.transitiveGarageResourceDependencyTargets(ctx, reader, cluster)
	if err != nil {
		return false, err
	}

	keys := &garagev1beta1.GarageKeyList{}
	if r.ClusterScoped {
		if err := reader.List(ctx, keys); err != nil {
			return false, fmt.Errorf("listing GarageKeys that reference management handle: %w", err)
		}
	} else {
		for _, namespace := range r.WatchNamespaces {
			page := &garagev1beta1.GarageKeyList{}
			if err := reader.List(ctx, page, client.InNamespace(namespace)); err != nil {
				return false, fmt.Errorf("listing GarageKeys in watched namespace %q that reference management handle: %w", namespace, err)
			}
			keys.Items = append(keys.Items, page.Items...)
		}
	}
	for i := range keys.Items {
		key := &keys.Items[i]
		if !clusterReferenceTargetsAny(key.Spec.ClusterRef, key.Namespace, targets) {
			continue
		}
		pending = true
		if key.DeletionTimestamp.IsZero() {
			if !controllerutil.ContainsFinalizer(key, garageKeyFinalizer) {
				controllerutil.AddFinalizer(key, garageKeyFinalizer)
				if err := r.Update(ctx, key); err != nil {
					return false, fmt.Errorf("adding cleanup finalizer to dependent GarageKey %s/%s: %w", key.Namespace, key.Name, err)
				}
				continue
			}
			if err := r.Delete(ctx, key); err != nil && !errors.IsNotFound(err) {
				return false, fmt.Errorf("deleting dependent GarageKey %s/%s: %w", key.Namespace, key.Name, err)
			}
		}
	}

	buckets := &garagev1beta1.GarageBucketList{}
	if r.ClusterScoped {
		if err := reader.List(ctx, buckets); err != nil {
			return false, fmt.Errorf("listing GarageBuckets that reference management handle: %w", err)
		}
	} else {
		for _, namespace := range r.WatchNamespaces {
			page := &garagev1beta1.GarageBucketList{}
			if err := reader.List(ctx, page, client.InNamespace(namespace)); err != nil {
				return false, fmt.Errorf("listing GarageBuckets in watched namespace %q that reference management handle: %w", namespace, err)
			}
			buckets.Items = append(buckets.Items, page.Items...)
		}
	}
	for i := range buckets.Items {
		bucket := &buckets.Items[i]
		if !clusterReferenceTargetsAny(bucket.Spec.ClusterRef, bucket.Namespace, targets) {
			continue
		}
		pending = true
		if bucket.DeletionTimestamp.IsZero() {
			if !controllerutil.ContainsFinalizer(bucket, garageBucketFinalizer) {
				controllerutil.AddFinalizer(bucket, garageBucketFinalizer)
				if err := r.Update(ctx, bucket); err != nil {
					return false, fmt.Errorf("adding cleanup finalizer to dependent GarageBucket %s/%s: %w", bucket.Namespace, bucket.Name, err)
				}
				continue
			}
			if err := r.Delete(ctx, bucket); err != nil && !errors.IsNotFound(err) {
				return false, fmt.Errorf("deleting dependent GarageBucket %s/%s: %w", bucket.Namespace, bucket.Name, err)
			}
		}
	}

	return pending, nil
}

func (r *GarageClusterReconciler) transitiveGarageResourceDependencyTargets(
	ctx context.Context, reader client.Reader, cluster *garagev1beta2.GarageCluster,
) (map[types.NamespacedName]struct{}, error) {
	targets := map[types.NamespacedName]struct{}{
		{Namespace: cluster.Namespace, Name: cluster.Name}: {},
	}
	clusters := &garagev1beta2.GarageClusterList{}
	if r.ClusterScoped {
		if err := reader.List(ctx, clusters); err != nil {
			return nil, fmt.Errorf("listing GarageCluster dependency handles: %w", err)
		}
	} else {
		for _, namespace := range r.WatchNamespaces {
			page := &garagev1beta2.GarageClusterList{}
			if err := reader.List(ctx, page, client.InNamespace(namespace)); err != nil {
				return nil, fmt.Errorf("listing GarageCluster dependency handles in watched namespace %q: %w", namespace, err)
			}
			clusters.Items = append(clusters.Items, page.Items...)
		}
	}

	for changed := true; changed; {
		changed = false
		for i := range clusters.Items {
			candidate := &clusters.Items[i]
			candidateKey := client.ObjectKeyFromObject(candidate)
			if _, known := targets[candidateKey]; known || candidate.Spec.ConnectTo == nil ||
				candidate.Spec.ConnectTo.ClusterRef == nil || candidate.Spec.ConnectTo.ClusterRef.KubeConfigSecretRef != nil {
				continue
			}
			ref := candidate.Spec.ConnectTo.ClusterRef
			refNamespace := ref.Namespace
			if refNamespace == "" {
				refNamespace = candidate.Namespace
			}
			if _, reachesTarget := targets[types.NamespacedName{Name: ref.Name, Namespace: refNamespace}]; reachesTarget {
				targets[candidateKey] = struct{}{}
				changed = true
			}
		}
	}
	return targets, nil
}

func clusterReferenceTargetsAny(
	ref garagev1beta1.ClusterReference, objectNamespace string, targets map[types.NamespacedName]struct{},
) bool {
	if ref.KubeConfigSecretRef != nil {
		return false
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = objectNamespace
	}
	_, found := targets[types.NamespacedName{Name: ref.Name, Namespace: namespace}]
	return found
}

// collectGarageNodeIDs collects node IDs from every GarageNode that belongs to this cluster.
// Called before deletion so node IDs are available for layout cleanup even if tags don't match.
func (r *GarageClusterReconciler) collectGarageNodeIDs(ctx context.Context, cluster *garagev1beta2.GarageCluster) (map[string]bool, error) {
	log := logf.FromContext(ctx)
	nodeIDs := make(map[string]bool)
	knownNodeLocalPoolNames := make(map[string]struct{})
	generatedNodeLocalPoolIDsByKubernetesNode := make(map[string]map[string]string)
	if cluster.Spec.Storage != nil {
		for i := range cluster.Spec.Storage.NodeLocalPools {
			knownNodeLocalPoolNames[cluster.Spec.Storage.NodeLocalPools[i].Name] = struct{}{}
		}
	}

	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	targets, err := r.transitiveGarageResourceDependencyTargets(ctx, reader, cluster)
	if err != nil {
		return nil, err
	}
	nodeList := &garagev1beta1.GarageNodeList{}
	if err := reader.List(ctx, nodeList, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, fmt.Errorf("listing GarageNodes for cleanup: %w", err)
	}

	for _, node := range nodeList.Items {
		if !clusterReferenceTargetsAny(node.Spec.ClusterRef, node.Namespace, targets) {
			continue
		}
		// A recreated node-local-pool child may know its retained HostPath identity
		// only through the controller-owned recovery annotation. Treat that pin as
		// a first-class Drain inventory source and reject any disagreement with a
		// status/spec identity rather than silently orphaning one of the roles.
		nodeID, err := node.ResolvedGarageNodeID()
		if err != nil {
			return nil, fmt.Errorf("resolving GarageNode %s/%s identity: %w", node.Namespace, node.Name, err)
		}
		pinnedNodeID, err := node.TrustedNodeLocalPoolRecoveryNodeID()
		if err != nil {
			return nil, fmt.Errorf("validating GarageNode %s/%s retained identity pin: %w", node.Namespace, node.Name, err)
		}
		if nodeID != "" && pinnedNodeID != "" && nodeID != pinnedNodeID {
			return nil, fmt.Errorf(
				"garageNode %s/%s reports identity %s but its retained HostPath pin is %s",
				node.Namespace, node.Name, shortID(nodeID), shortID(pinnedNodeID),
			)
		}
		if nodeID == "" {
			return nil, fmt.Errorf("garageNode %s/%s has no discovered status.nodeId or spec.nodeId", node.Namespace, node.Name)
		}
		nodeID = canonicalGarageNodeID(nodeID)
		if isNodeLocalPoolBacked(&node) {
			if node.Spec.NodeLocalPoolName == "" || node.Spec.KubernetesNodeName == "" {
				return nil, fmt.Errorf(
					"generated node-local-pool GarageNode %s/%s has incomplete pool or Kubernetes Node identity",
					node.Namespace, node.Name,
				)
			}
			if !metav1.IsControlledBy(&node, cluster) {
				return nil, fmt.Errorf(
					"node-local-pool GarageNode %s/%s is not controlled by exact GarageCluster UID %s",
					node.Namespace, node.Name, cluster.UID,
				)
			}
			knownNodeLocalPoolNames[node.Spec.NodeLocalPoolName] = struct{}{}
			byPool := generatedNodeLocalPoolIDsByKubernetesNode[node.Spec.KubernetesNodeName]
			if byPool == nil {
				byPool = make(map[string]string)
				generatedNodeLocalPoolIDsByKubernetesNode[node.Spec.KubernetesNodeName] = byPool
			}
			if previousNodeID, duplicate := byPool[node.Spec.NodeLocalPoolName]; duplicate {
				return nil, fmt.Errorf(
					"multiple generated GarageNodes claim node-local pool %q on Kubernetes Node %q with identities %s and %s",
					node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName, shortID(previousNodeID), shortID(nodeID),
				)
			}
			byPool[node.Spec.NodeLocalPoolName] = nodeID
		}
		nodeIDs[nodeID] = true
	}

	// Recovery pins live on Kubernetes Nodes specifically so they survive a
	// force-deleted GarageCluster and the gap before replacement children are
	// materialized. Include them even when the current selector matches no Node.
	if r.ClusterScoped {
		kubernetesNodes := &corev1.NodeList{}
		if err := r.safetyReader().List(ctx, kubernetesNodes); err != nil {
			return nil, fmt.Errorf("listing Kubernetes Nodes for retained node-local-pool identity inventory: %w", err)
		}
		for i := range kubernetesNodes.Items {
			retainedNodeIDs, err := retainedNodeLocalPoolIdentityIDs(
				cluster, &kubernetesNodes.Items[i], knownNodeLocalPoolNames,
				generatedNodeLocalPoolIDsByKubernetesNode[kubernetesNodes.Items[i].Name],
			)
			if err != nil {
				return nil, err
			}
			for _, nodeID := range retainedNodeIDs {
				nodeIDs[nodeID] = true
			}
		}
	} else if hasNodeLocalPools(cluster) {
		return nil, fmt.Errorf("node-local-pool Drain requires cluster-scoped Kubernetes Node access to inventory retained identity pins")
	}

	if len(nodeIDs) > 0 {
		log.Info("Collected node IDs from GarageNode CRs", "count", len(nodeIDs))
	}
	return nodeIDs, nil
}

// collectLiveEdgeGatewayNodeIDs discovers exact identities from pods owned by
// this edge cluster's gateway StatefulSet. It exists only for safe deletion of
// legacy roles created before cluster-uid tags; it never uses ambiguous layout
// tags as an ownership signal.
func (r *GarageClusterReconciler) collectLiveEdgeGatewayNodeIDs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]bool, error) {
	nodeIDs := make(map[string]bool)
	if cluster == nil || !cluster.HasGatewayTier() || cluster.HasStorageTier() {
		return nodeIDs, nil
	}

	statefulSet := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: gatewayWorkloadName(cluster), Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, statefulSet); err != nil {
		if errors.IsNotFound(err) {
			return nodeIDs, nil
		}
		return nil, fmt.Errorf("reading edge gateway StatefulSet: %w", err)
	}
	if !metav1.IsControlledBy(statefulSet, cluster) {
		return nil, fmt.Errorf("edge gateway StatefulSet %s is not controlled by GarageCluster %s", statefulSet.Name, cluster.Name)
	}

	pods := &corev1.PodList{}
	if err := r.safetyReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForTier(cluster, tierGateway)),
	); err != nil {
		return nil, fmt.Errorf("listing edge gateway pods: %w", err)
	}
	ownedRunning := make([]corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID ||
			pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
			continue
		}
		ownedRunning = append(ownedRunning, *pod)
	}
	for _, discovered := range r.discoverNodesWithMountedStaticCredentials(ctx, ownedRunning, getAdminPort(cluster)) {
		if discovered.id != "" {
			nodeIDs[discovered.id] = true
		}
	}
	return nodeIDs, nil
}

// collectLiveLegacyStorageNodeIDs closes the upgrade/delete window before the
// old cluster-owned storage StatefulSet has been converted to per-node
// GarageNodes. Only pods controlled by that exact StatefulSet UID are trusted.
func (r *GarageClusterReconciler) collectLiveLegacyStorageNodeIDs(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]bool, error) {
	nodeIDs := make(map[string]bool)
	if cluster == nil || !cluster.HasStorageTier() {
		return nodeIDs, nil
	}
	statefulSet := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, statefulSet); err != nil {
		if errors.IsNotFound(err) {
			return nodeIDs, nil
		}
		return nil, fmt.Errorf("reading legacy storage StatefulSet: %w", err)
	}
	if !metav1.IsControlledBy(statefulSet, cluster) {
		// A per-node/user workload that happens to share the historical name is
		// represented by its GarageNode status and is not legacy cluster state.
		return nodeIDs, nil
	}

	desiredReplicas := int32(1)
	if statefulSet.Spec.Replicas != nil {
		desiredReplicas = *statefulSet.Spec.Replicas
	}
	if desiredReplicas == 0 {
		return nodeIDs, nil
	}
	pods := &corev1.PodList{}
	if err := r.safetyReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(r.selectorLabelsForTier(cluster, tierStorage)),
	); err != nil {
		return nil, fmt.Errorf("listing legacy storage pods: %w", err)
	}
	ownedRunning := make([]corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
			continue
		}
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" && pod.DeletionTimestamp.IsZero() {
			ownedRunning = append(ownedRunning, *pod)
		}
	}
	for _, discovered := range r.discoverNodesWithMountedStaticCredentials(ctx, ownedRunning, getAdminPort(cluster)) {
		if discovered.id != "" {
			nodeIDs[discovered.id] = true
		}
	}
	if int32(len(nodeIDs)) < desiredReplicas {
		return nil, fmt.Errorf(
			"legacy StatefulSet still desires %d storage identities but only %d exact live node IDs were discovered; wait for migration/readiness before deleting with Drain",
			desiredReplicas, len(nodeIDs),
		)
	}
	return nodeIDs, nil
}

func (r *GarageClusterReconciler) deleteReferencingGarageNodes(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	targets, err := r.transitiveGarageResourceDependencyTargets(ctx, reader, cluster)
	if err != nil {
		return false, err
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := reader.List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return false, fmt.Errorf("listing GarageNodes for cluster deletion: %w", err)
	}
	pending := false
	foreground := metav1.DeletePropagationForeground
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !clusterReferenceTargetsAny(node.Spec.ClusterRef, node.Namespace, targets) {
			continue
		}
		// GarageNodes are logical dependents even when Manual/SMB or External
		// registrations are intentionally user-authored without an ownerReference.
		// Destroy is an explicit whole-store teardown, so leaving those CRs behind
		// would also leave their StatefulSets running against a deleted Service and
		// make their fail-closed storage finalizers impossible to complete. Drain
		// reaches this point only after its durable all-role proof is terminal.
		pending = true
		if !node.DeletionTimestamp.IsZero() {
			continue
		}
		logf.FromContext(ctx).Info("Deleting referencing GarageNode", "name", node.Name)
		if err := r.Delete(ctx, node, &client.DeleteOptions{PropagationPolicy: &foreground}); err != nil && !errors.IsNotFound(err) {
			return true, fmt.Errorf("deleting referencing GarageNode %s: %w", node.Name, err)
		}
	}
	return pending, nil
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
			return fmt.Errorf("deletionPolicy Drain requires a configured, readable Admin API token; refusing to stop storage without proving its roles left the surviving layout")
		}

		adminPort := getAdminPort(cluster)
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		garageClient = garage.NewClient(endpoint, adminToken)
	}

	mutate := func() error {
		return r.removeNodesFromLayoutLocked(ctx, cluster, knownNodeIDs, garageClient)
	}
	if cluster.HasGatewayTier() && !cluster.HasStorageTier() {
		// Garage permits multiple live layout versions and gateway roles never
		// participate in ring_assignment_data. Removing an exact capacity-less
		// role is therefore the cleanup operation that may advance an otherwise
		// draining history after that gateway disappears. Preserve the global
		// staging-area ownership check and every rollout/drain exclusion, but do
		// not require old layout versions to settle first. Positive-capacity roles
		// remain protected by removeNodesFromLayoutLocked's drain authorization.
		return runResolvedCapacitylessRoleRetirementMutation(
			ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster, mutate,
		)
	}
	if storageDrainActorMatches(cluster.Status.StorageDrain, storageDrainActorForCluster(cluster)) {
		return runLayoutMutationIgnoringStorageDrain(
			ctx, r.layoutMutationCoordinator(), cluster, storageDrainActorForCluster(cluster), garageClient, mutate,
		)
	}
	return runResolvedLayoutMutation(
		ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster, garageClient, mutate,
	)
}

func (r *GarageClusterReconciler) removeNodesFromLayoutLocked(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	knownNodeIDs map[string]bool,
	garageClient *garage.Client,
) error {
	log := logf.FromContext(ctx)

	// Get current layout
	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster layout: %w", err)
	}

	// Find only exact local identities. Federated sites commonly use the same
	// GarageCluster name/namespace, so the historical cluster:<name>/<namespace>
	// tag is not a safe ownership boundary in a replicated layout. New roles also
	// carry cluster-uid:<kubernetes-uid>; the GarageNode inventory covers roles
	// created before that tag was introduced.
	nodesToRemove := make([]garage.NodeRoleChange, 0)
	intendedRemovals := make([]garage.NodeRoleChange, 0)
	storageNodeIDsToRemove := make([]string, 0)
	roleNodeIDsToRemove := make([]string, 0)
	removesStorageRole := false
	hasLayoutRoleToRemove := false
	for _, role := range layout.Roles {
		if !knownNodeIDs[canonicalGarageNodeID(role.ID)] && !nodeBelongsToClusterUID(role.Tags, string(cluster.UID)) {
			continue
		}
		hasLayoutRoleToRemove = true
		roleNodeIDsToRemove = append(roleNodeIDsToRemove, role.ID)
		intendedRemovals = append(intendedRemovals, garage.NodeRoleChange{ID: role.ID, Remove: true})
		if role.Capacity != nil && *role.Capacity > 0 {
			removesStorageRole = true
			storageNodeIDsToRemove = append(storageNodeIDsToRemove, role.ID)
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
			log.Info("Staging node for removal", "nodeId", shortID(role.ID), "tags", role.Tags)
			nodesToRemove = append(nodesToRemove, garage.NodeRoleChange{
				ID:     role.ID,
				Remove: true,
			})
		}
	}

	if !hasLayoutRoleToRemove {
		proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
		// A previous reconcile may have applied this gateway's exact role
		// removal and crashed before observing the resulting layout history.
		// Only the exact durable role-only intent proves this history belongs to
		// the deleting gateway; a never-joined gateway must not wait on unrelated
		// layout history. Keep the still-live workload behind its finalizer until
		// normal Garage ACK/sync convergence completes.
		if cluster.HasGatewayTier() && !cluster.HasStorageTier() {
			actor := storageDrainActorForCluster(cluster)
			if proof != nil {
				if !sameStorageDrainActor(proof.Actor, actor) || len(proof.RemovedStorageNodeIDs) != 0 {
					return fmt.Errorf("%w: gateway retirement found a non-role-only or differently owned durable drain", errLayoutMutationPending)
				}
				if len(proof.RoleRemovalNodeIDs) > 0 {
					if err := requireCapacitylessGatewayRetirementSettled(ctx, garageClient); err != nil {
						return err
					}
					if proof.CompletedAt == nil {
						if err := completeRoleOnlyClusterDrain(ctx, r.Client, cluster, layout); err != nil {
							return err
						}
						proof = clusterStorageDrainProof(cluster.Status.StorageDrain)
					}
					if proof != nil && proof.CompletedAt != nil {
						owner, err := resolveGarageLayoutOwner(ctx, r.safetyReader(), cluster)
						if err != nil {
							return fmt.Errorf("resolving canonical Garage layout owner before completing gateway retirement: %w", err)
						}
						r.layoutMutationCoordinator().EndStorageDrain(
							layoutOwnerKey(owner), layoutRolloutOwnerID(owner), actor.UID,
							proof.TransactionID, proof.TargetHash,
						)
					}
				}
			}
		}
		if proof == nil && cluster.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue &&
			cluster.EffectiveDeletionPolicy() == garagev1beta2.DeletionPolicyDrain {
			if err := r.ensureClusterBlockResyncIntent(ctx, cluster, layout, nil, nil); err != nil {
				return err
			}
			proof = clusterStorageDrainProof(cluster.Status.StorageDrain)
		}
		// A previous reconcile may have crashed immediately after Apply, when the
		// target roles are already absent but before any post-layout observation.
		// The pre-Apply status intent is the durable transaction boundary: never
		// interpret an empty current-role scan as proof that blocks finished moving.
		if proof != nil {
			if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
				return fmt.Errorf("%w: keeping storage workloads online after recorded role removal: %v", errLayoutMutationPending, err)
			}
			if len(proof.RemovedStorageNodeIDs) > 0 {
				if err := r.requireBlockResyncQuiet(ctx, cluster, garageClient); err != nil {
					return fmt.Errorf("keeping storage workloads online after recorded role removal: %w", err)
				}
			} else if sameStorageDrainActor(proof.Actor, storageDrainActorForCluster(cluster)) && proof.CompletedAt == nil {
				if err := completeRoleOnlyClusterDrain(ctx, r.Client, cluster, layout); err != nil {
					return err
				}
			}
		}
		log.Info("No nodes to remove from layout")
		return nil
	}
	// Record every positive-capacity target before staging or applying Garage's
	// global layout transaction. This write closes the crash window between
	// Apply and the first layout-history/ListWorkers observation.
	capacitylessGatewayRetirement := cluster.HasGatewayTier() && !cluster.HasStorageTier() && !removesStorageRole
	if capacitylessGatewayRetirement {
		if err := r.ensureCapacitylessGatewayRetirementIntent(ctx, cluster, roleNodeIDsToRemove); err != nil {
			return err
		}
	} else if err := r.ensureClusterBlockResyncIntent(ctx, cluster, layout, roleNodeIDsToRemove, storageNodeIDsToRemove); err != nil {
		return err
	}
	storageDrainProtectedApply := len(storageNodeIDsToRemove) > 0 ||
		storageDrainActorMatches(cluster.Status.StorageDrain, storageDrainActorForCluster(cluster))
	if storageDrainProtectedApply {
		if err := requireStorageDrainAuthorizedTargets(
			cluster, storageDrainActorForCluster(cluster), roleNodeIDsToRemove, storageNodeIDsToRemove,
		); err != nil {
			return err
		}
	}
	// Stage any removals that are not already present. If all target removals
	// were staged by an interrupted earlier reconcile, still apply them below;
	// treating "nothing new to stage" as completion would tear workloads down
	// while their roles remained active.
	var beforeApply func(*garage.ClusterLayout) error
	if len(storageNodeIDsToRemove) > 0 {
		beforeApply = func(staged *garage.ClusterLayout) error {
			return requireStorageDrainBeforeApply(
				ctx, r.Client, r.safetyReader(), cluster, garageClient, staged, r.clusterHealthGetter,
			)
		}
	}
	_, err = stageAndApplyExclusiveLayoutWithCheck(ctx, garageClient, layout, intendedRemovals, nil, func() error {
		if len(nodesToRemove) == 0 {
			return nil
		}
		if err := garageClient.UpdateClusterLayout(ctx, nodesToRemove); err != nil {
			return fmt.Errorf("failed to stage node removals: %w", err)
		}
		return nil
	}, beforeApply)
	if err != nil {
		recoveredErr := r.recoverClusterDrainApplyFailure(ctx, cluster, garageClient, intendedRemovals, err)
		if stderrors.Is(recoveredErr, errLayoutMutationPending) {
			return recoveredErr
		}
		if garage.IsReplicationConstraint(err) {
			return fmt.Errorf("%w: Garage rejected removal of %d node(s) because it would violate replication constraints: %v", errUnsafeLayoutRoleRemoval, len(nodesToRemove), recoveredErr)
		}
		return fmt.Errorf("failed to apply layout removal: %w", recoveredErr)
	}
	log.Info("Removed nodes from layout", "count", len(nodesToRemove))

	// Keep a capacity-less gateway workload alive until normal Garage metadata
	// ACK/sync convergence settles the version that removed it. Never call
	// ClusterLayoutSkipDeadNodes here: upstream applies that request globally to
	// every node the serving peer currently sees as down, so a gateway deletion
	// must not force-ACK an unrelated partitioned storage or gateway node.
	activeStorageRemoval := clusterStorageDrainProof(cluster.Status.StorageDrain)
	if cluster.HasGatewayTier() && !removesStorageRole &&
		(activeStorageRemoval == nil || len(activeStorageRemoval.RemovedStorageNodeIDs) == 0) {
		if err := requireCapacitylessGatewayRetirementSettled(ctx, garageClient); err != nil {
			return err
		}
		return fmt.Errorf("%w: capacity-less gateway role is absent and its layout history settled; recording the durable terminal handoff on the next reconcile", errLayoutMutationPending)
	}

	// Applying a storage-role removal leaves the previous layout active while
	// Garage synchronizes metadata. Historical versions can still serve object
	// blocks after the layout-history trackers clear, so keep every workload
	// online until the removed sources and current destinations also report a durable zero
	// block-resync window. The proof is status-backed across manager restarts.
	if removesStorageRole || (activeStorageRemoval != nil && len(activeStorageRemoval.RemovedStorageNodeIDs) > 0) {
		if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
			return fmt.Errorf("%w: keeping storage workloads online after layout removal: %v", errLayoutMutationPending, err)
		}
		if err := r.requireBlockResyncQuiet(ctx, cluster, garageClient); err != nil {
			return fmt.Errorf("keeping storage workloads online after layout removal: %w", err)
		}
	}

	return nil
}

// requireCapacitylessGatewayRetirementSettled is the post-Apply half of edge
// gateway removal. The mutation is allowed to start while older history is
// draining because deleting this exact capacity-less role can be what advances
// that history. Once applied, however, its predecessor must leave Garage's live
// history before the finalizer releases and deletes the workload. Garage's
// full-copy metadata tables include gateways, so even a capacity-less role
// removal must finish its normal metadata sync. Never call skip-dead-nodes here:
// upstream force-ACKs every node the serving daemon sees as down, and there is
// no target-scoped form of that API.
func requireCapacitylessGatewayRetirementSettled(
	ctx context.Context,
	garageClient *garage.Client,
) error {
	appliedVersion, versionOK := reReadLayoutVersion(ctx, garageClient)
	if !versionOK {
		return fmt.Errorf("%w: waiting to read the committed capacity-less gateway removal version", errLayoutMutationPending)
	}
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return fmt.Errorf("%w: keeping gateway workload online until role-removal layout version %d settles: %v",
			errLayoutMutationPending, appliedVersion, err)
	}
	return nil
}

type resolvedRPCSecretSource struct {
	namespace string
	name      string
	key       string
}

func (s resolvedRPCSecretSource) descriptor() string {
	return s.namespace + "/" + s.name + ":" + s.key
}

func canonicalRPCIdentity(raw []byte) ([]byte, string, error) {
	value := strings.TrimRight(string(raw), " \t\r\n")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		if err == nil {
			err = fmt.Errorf("decoded length is %d bytes, want 32", len(decoded))
		}
		return nil, "", fmt.Errorf("RPC secret must be exactly 32 bytes encoded as 64 hexadecimal characters: %w", err)
	}
	canonical := []byte(hex.EncodeToString(decoded))
	digest := sha256.Sum256(decoded)
	return canonical, hex.EncodeToString(digest[:]), nil
}

func (r *GarageClusterReconciler) resolveRPCSecretSource(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*resolvedRPCSecretSource, error) {
	selectorSource := func(namespace string, selector *corev1.SecretKeySelector) *resolvedRPCSecretSource {
		if selector == nil {
			return nil
		}
		key := selector.Key
		if key == "" {
			key = RPCSecretKey
		}
		return &resolvedRPCSecretSource{namespace: namespace, name: selector.Name, key: key}
	}
	// An explicit network credential is authoritative for every tier, including
	// an edge gateway. Every explicit ref remains an untouched user/GitOps-owned
	// source, even when it happens to use the historical generated Secret name.
	// Only absence of a ref authorizes the operator to generate that target.
	if cluster.Spec.Network.RPCSecretRef != nil {
		return selectorSource(cluster.Namespace, cluster.Spec.Network.RPCSecretRef), nil
	}
	if cluster.Spec.ConnectTo == nil {
		return nil, nil
	}
	if cluster.Spec.ConnectTo.RPCSecretRef != nil {
		return selectorSource(cluster.Namespace, cluster.Spec.ConnectTo.RPCSecretRef), nil
	}
	if cluster.Spec.ConnectTo.ClusterRef == nil {
		return nil, nil
	}
	if namespace := cluster.Spec.ConnectTo.ClusterRef.Namespace; namespace != "" && namespace != cluster.Namespace {
		return nil, fmt.Errorf("connectTo.clusterRef namespace %q must match GarageCluster namespace %q; cross-namespace RPC identity inheritance is not permitted", namespace, cluster.Namespace)
	}
	storageNN := types.NamespacedName{
		Name: cluster.Spec.ConnectTo.ClusterRef.Name, Namespace: cluster.Namespace,
	}
	storageCluster := &garagev1beta2.GarageCluster{}
	if err := r.Get(ctx, storageNN, storageCluster); err != nil {
		return nil, fmt.Errorf("getting referenced storage GarageCluster %s for RPC identity: %w", storageNN, err)
	}
	if storageCluster.IsManagementHandle() {
		return nil, fmt.Errorf("connectTo.clusterRef %s is a management handle and owns no Garage workload RPC identity; set spec.connectTo.rpcSecretRef or spec.network.rpcSecretRef explicitly", storageNN)
	}
	// Consume the storage cluster's already-pinned identity, not its possibly
	// mutable external source. The gateway snapshots it locally so every
	// workload mounts an immutable credential owned by its GarageCluster.
	return &resolvedRPCSecretSource{
		namespace: storageNN.Namespace,
		name:      managedRPCSecretName(storageCluster),
		key:       RPCSecretKey,
	}, nil
}

func (r *GarageClusterReconciler) persistRPCIdentityFingerprint(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	fingerprint string,
) error {
	expectedUID := cluster.UID
	expectedGeneration := cluster.Generation
	var updated *garagev1beta2.GarageCluster
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID || fresh.Generation != expectedGeneration {
			return fmt.Errorf("garageCluster UID or generation changed while pinning its RPC identity")
		}
		if current := fresh.Annotations[annotationRPCIdentitySHA256]; current != "" {
			if current != fingerprint {
				return fmt.Errorf("garageCluster pins RPC identity %s but the mounted Secret contains %s; restore the original RPC Secret", current, fingerprint)
			}
			updated = fresh
			return nil
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string)
		}
		fresh.Annotations[annotationRPCIdentitySHA256] = fingerprint
		if err := r.Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return fmt.Errorf("persisting immutable RPC identity fingerprint: %w", err)
	}
	if updated != nil {
		adoptGarageClusterSnapshot(cluster, updated)
	}
	return nil
}

func (r *GarageClusterReconciler) ensureRPCSecret(ctx context.Context, cluster *garagev1beta2.GarageCluster) (*corev1.Secret, error) {
	log := logf.FromContext(ctx)
	targetKey := types.NamespacedName{Name: managedRPCSecretName(cluster), Namespace: cluster.Namespace}
	source, err := r.resolveRPCSecretSource(ctx, cluster)
	if err != nil {
		return nil, err
	}
	generated := source == nil

	target := &corev1.Secret{}
	targetErr := r.Get(ctx, targetKey, target)
	if targetErr != nil && !errors.IsNotFound(targetErr) {
		return nil, fmt.Errorf("getting pinned RPC identity Secret %s: %w", targetKey, targetErr)
	}

	var sourceSecret *corev1.Secret
	var sourceCanonical []byte
	var sourceFingerprint string
	if !generated {
		sourceSecret = &corev1.Secret{}
		sourceKey := types.NamespacedName{Name: source.name, Namespace: source.namespace}
		if err := r.Get(ctx, sourceKey, sourceSecret); err != nil {
			if !errors.IsNotFound(err) || targetErr != nil {
				return nil, fmt.Errorf("getting RPC identity source %s: %w", source.descriptor(), err)
			}
			log.Info("RPC identity source is unavailable; continuing from the immutable pinned snapshot",
				"source", source.descriptor(), "snapshot", targetKey.String())
			sourceSecret = nil
		} else {
			raw, found := sourceSecret.Data[source.key]
			if !found {
				return nil, fmt.Errorf("RPC identity source %s has no key %q", sourceKey, source.key)
			}
			sourceCanonical, sourceFingerprint, err = canonicalRPCIdentity(raw)
			if err != nil {
				return nil, fmt.Errorf("validating RPC identity source %s: %w", source.descriptor(), err)
			}
		}
	}

	if targetErr == nil {
		if !metav1.IsControlledBy(target, cluster) {
			return nil, fmt.Errorf("pinned RPC identity Secret %s collides with an object not controlled by GarageCluster %s/%s; refusing to adopt or mutate it", targetKey, cluster.Namespace, cluster.Name)
		}
		raw, found := target.Data[RPCSecretKey]
		if !found {
			return nil, fmt.Errorf("pinned RPC identity Secret %s has no canonical key %q", targetKey, RPCSecretKey)
		}
		canonical, fingerprint, err := canonicalRPCIdentity(raw)
		if err != nil {
			return nil, fmt.Errorf("validating pinned RPC identity Secret %s: %w", targetKey, err)
		}
		if pinned := cluster.Annotations[annotationRPCIdentitySHA256]; pinned != "" && pinned != fingerprint {
			return nil, fmt.Errorf("pinned RPC identity Secret %s changed from fingerprint %s to %s; restore the original Secret", targetKey, pinned, fingerprint)
		}
		if source != nil {
			recorded := target.Annotations[annotationRPCIdentitySource]
			if recorded == "" && sourceSecret != nil && sourceFingerprint == fingerprint &&
				string(sourceCanonical) == string(canonical) && len(target.Data) == 1 {
				// Released operators mounted the mutable generated-name Secret
				// directly and recorded no source descriptor. A staged legacy-env
				// migration may point spec.network.rpcSecretRef at that same Secret
				// (or an exact-copy source). Adopt it only when both credential
				// bytes already match; never overwrite a mismatched live identity.
				if target.Annotations == nil {
					target.Annotations = make(map[string]string)
				}
				target.Annotations[annotationRPCIdentitySource] = source.descriptor()
				target.Annotations[annotationRPCIdentitySHA256] = fingerprint
				target.Immutable = ptr.To(true)
				if err := r.Update(ctx, target); err != nil {
					return nil, fmt.Errorf("adopting released RPC identity snapshot %s: %w", targetKey, err)
				}
				if err := r.persistRPCIdentityFingerprint(ctx, cluster, fingerprint); err != nil {
					return nil, err
				}
				return target, nil
			}
			if recorded != source.descriptor() {
				return nil, fmt.Errorf("RPC identity source changed from %s to %s; live RPC credential rotation is unsupported", recorded, source.descriptor())
			}
			if sourceSecret != nil && (sourceFingerprint != fingerprint || string(sourceCanonical) != string(canonical)) {
				return nil, fmt.Errorf("RPC identity source %s no longer matches immutable snapshot %s; restore the original source value instead of rotating a live Garage mesh", source.descriptor(), targetKey)
			}
			if target.Immutable == nil || !*target.Immutable ||
				target.Annotations[annotationRPCIdentitySHA256] != fingerprint ||
				len(target.Data) != 1 || string(raw) != string(canonical) {
				return nil, fmt.Errorf("RPC identity snapshot %s lost its exact immutable ownership/source/data contract; restore the operator-created Secret", targetKey)
			}
			if err := r.persistRPCIdentityFingerprint(ctx, cluster, fingerprint); err != nil {
				return nil, err
			}
			return target, nil
		}
		needsUpdate := target.Immutable == nil || !*target.Immutable ||
			target.Annotations[annotationRPCIdentitySHA256] != fingerprint || string(raw) != string(canonical)
		if needsUpdate {
			if target.Annotations == nil {
				target.Annotations = make(map[string]string)
			}
			if target.Immutable == nil || !*target.Immutable {
				target.Data[RPCSecretKey] = canonical
			}
			target.Immutable = ptr.To(true)
			target.Annotations[annotationRPCIdentitySHA256] = fingerprint
			if err := r.Update(ctx, target); err != nil {
				return nil, fmt.Errorf("making RPC identity Secret %s immutable: %w", targetKey, err)
			}
		}
		if err := r.persistRPCIdentityFingerprint(ctx, cluster, fingerprint); err != nil {
			return nil, err
		}
		return target, nil
	}

	if pinned := cluster.Annotations[annotationRPCIdentitySHA256]; generated && pinned != "" {
		return nil, fmt.Errorf("generated RPC identity Secret %s was deleted after bootstrap; refusing to generate a different identity for fingerprint %s—restore the original Secret", targetKey, pinned)
	}
	var canonical []byte
	var fingerprint string
	if generated {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, fmt.Errorf("generating RPC identity: %w", err)
		}
		canonical = []byte(hex.EncodeToString(randomBytes))
		digest := sha256.Sum256(randomBytes)
		fingerprint = hex.EncodeToString(digest[:])
	} else {
		canonical = sourceCanonical
		fingerprint = sourceFingerprint
		if pinned := cluster.Annotations[annotationRPCIdentitySHA256]; pinned != "" && pinned != fingerprint {
			return nil, fmt.Errorf("RPC identity source %s has fingerprint %s, but GarageCluster pins %s; restore the original source value", source.descriptor(), fingerprint, pinned)
		}
	}
	target = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: targetKey.Name, Namespace: targetKey.Namespace,
			Labels:      r.labelsForCluster(cluster),
			Annotations: map[string]string{annotationRPCIdentitySHA256: fingerprint},
		},
		Type:      corev1.SecretTypeOpaque,
		Immutable: ptr.To(true),
		Data:      map[string][]byte{RPCSecretKey: canonical},
	}
	if source != nil {
		target.Annotations[annotationRPCIdentitySource] = source.descriptor()
	}
	if err := controllerutil.SetControllerReference(cluster, target, r.Scheme); err != nil {
		return nil, err
	}
	log.Info("Creating immutable pinned RPC identity Secret", "name", targetKey.Name, "source", target.Annotations[annotationRPCIdentitySource])
	if err := r.Create(ctx, target); err != nil {
		return nil, fmt.Errorf("creating pinned RPC identity Secret %s: %w", targetKey, err)
	}
	if err := r.persistRPCIdentityFingerprint(ctx, cluster, fingerprint); err != nil {
		return nil, err
	}
	return target, nil
}

// reconcileConfigMap creates/updates the ConfigMap(s) and returns config hashes
// for pod restart triggering. Garage does NOT support hot-reload of config
// (SIGHUP is explicitly ignored in src/garage/server.rs). All config changes
// require pod restarts, which we trigger via the checksum annotation.
//
// Returns (edgeGatewayHash, poolHashes). A cluster-owned edge gateway consumes
// the shared revision. Unified gateway identities are GarageNode-owned and get
// per-node revisions from the GarageNode reconciler. Every named node-local pool
// has an independent revision because its data_dir shape can differ.
func (r *GarageClusterReconciler) reconcileConfigMap(ctx context.Context, cluster *garagev1beta2.GarageCluster) (string, map[string]string, error) {
	log := logf.FromContext(ctx)

	// Validate bootstrap peers format before generating config
	// Garage requires format: "<64-hex-nodeid>@<hostname>:<port>"
	// Invalid entries are silently ignored by Garage, so warn users here
	validateBootstrapPeers(log, cluster.Spec.Network.BootstrapPeers)

	// Build config context with resolved secrets. Do NOT fall back to an empty
	// context on error: that silently drops the resolved Consul token and any
	// publicEndpoint-derived rpc_public_addr, then rolls every pod onto the
	// degraded config (a v0.5.3-class peering break) with no signal. A missing
	// secret is "config not ready" — return the error so the reconcile requeues.
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		return "", nil, fmt.Errorf("building cluster config context (config not ready): %w", err)
	}

	// Default config revision (used by storage pods, and by gateway pods when no
	// gateway-specific rpc_public_addr override is set).
	storageBody := generateGarageConfig(cluster, cfgCtx)
	storageExpectedHash, err := garageConfigRevision(ctx, r.safetyReader(), cluster, storageBody)
	if err != nil {
		return "", nil, err
	}
	storageBaseName := cluster.Name + "-config"
	storageHash, err := r.writeConfigMapWithLabels(
		ctx,
		cluster,
		garageConfigRevisionName(storageBaseName, storageExpectedHash),
		storageBody,
		nil,
		garageConfigRevisionAnnotations(storageBaseName, nil),
	)
	if err != nil {
		return "", nil, err
	}
	gatewayHash := storageHash
	// Unified gateway identities use GarageNode-specific revisions so each can
	// advertise its own RPC address; edge gateway StatefulSets consume the shared
	// revision. The historical <cluster>-gateway-config resource has no current
	// consumer and is retired by reference-aware cleanup after legacy Pods leave.

	poolHashes := make(map[string]string)
	if cluster.Spec.Storage != nil {
		for i := range cluster.Spec.Storage.NodeLocalPools {
			pool := &cluster.Spec.Storage.NodeLocalPools[i]
			poolCfgCtx := nodeLocalPoolConfigContext(cfgCtx, pool)
			body := generateGarageConfig(cluster, poolCfgCtx)
			configHash, err := garageConfigRevision(ctx, r.safetyReader(), cluster, body)
			if err != nil {
				return "", nil, fmt.Errorf("deriving node-local pool %q Garage config revision: %w", pool.Name, err)
			}
			if err := r.cleanupObsoleteNodeLocalPoolConfigMapsForDeployedDaemonSet(
				ctx,
				cluster,
				pool.Name,
			); err != nil {
				return "", nil, fmt.Errorf(
					"cleaning completed node-local pool %q ConfigMap rollout: %w",
					pool.Name,
					err,
				)
			}
			diskLayout := storageDiskLayoutForPool(pool)
			diskLayoutAnnotation, err := marshalStorageDiskLayout(diskLayout)
			if err != nil {
				return "", nil, fmt.Errorf(
					"building node-local pool %q disk-layout guard: %w",
					pool.Name,
					err,
				)
			}
			if err := r.validateNodeLocalPoolDiskLayoutBeforeConfigUpdate(
				ctx,
				cluster,
				pool.Name,
				diskLayout,
			); err != nil {
				return "", nil, fmt.Errorf(
					"validating node-local pool %q before ConfigMap update: %w",
					pool.Name,
					err,
				)
			}
			baseName := storageDaemonSetConfigMapName(cluster, pool.Name)
			hash, err := r.writeConfigMapWithLabels(
				ctx,
				cluster,
				storageDaemonSetConfigResourceName(cluster, pool, configHash),
				body,
				map[string]string{labelNodeLocalPool: pool.Name},
				garageConfigRevisionAnnotations(baseName, map[string]string{annotationStorageDiskLayout: diskLayoutAnnotation}),
			)
			if err != nil {
				return "", nil, fmt.Errorf("reconciling node-local pool %q ConfigMap: %w", pool.Name, err)
			}
			poolHashes[pool.Name] = hash
		}
	}

	return gatewayHash, poolHashes, nil
}

func nodeLocalPoolConfigContext(
	base *configContext,
	pool *garagev1beta2.NodeLocalPoolSpec,
) *configContext {
	poolContext := configContext{}
	if base != nil {
		poolContext = *base
	}
	// Every pod in a pool shares this ConfigMap, so neither the default
	// node-local pool's nor the cluster-wide shared rpc_public_addr can be correct
	// for all identities. Per-node addresses travel in layout tags instead.
	poolContext.OmitClusterRPCPublicAddr = true
	poolContext.TierRPCPublicAddrOverride = ""
	poolContext.RPCPublicAddr = ""
	poolContext.NodeRPCPublicAddr = ""
	poolContext.NodeDataDirPaths = nil
	poolContext.ForceSingleDataDir = pool != nil && pool.Data != nil
	if pool != nil && len(pool.DataPaths) > 0 {
		poolContext.ForceSingleDataDir = false
		poolContext.NodeDataDirPaths = make([]NodeDataDirPath, 0, len(pool.DataPaths))
		dataPaths := sortedNodeLocalPoolDataPaths(pool)
		for i := range dataPaths {
			dataPath := &dataPaths[i]
			entry := NodeDataDirPath{Path: dataPath.Path, ReadOnly: dataPath.ReadOnly}
			if dataPath.Capacity != nil {
				entry.Capacity = garageBytesize(dataPath.Capacity)
			}
			poolContext.NodeDataDirPaths = append(poolContext.NodeDataDirPaths, entry)
		}
	}
	return &poolContext
}

func sortedNodeLocalPoolDataPaths(pool *garagev1beta2.NodeLocalPoolSpec) []garagev1beta2.NodeLocalPoolDataPath {
	if pool == nil || len(pool.DataPaths) == 0 {
		return nil
	}
	dataPaths := append([]garagev1beta2.NodeLocalPoolDataPath(nil), pool.DataPaths...)
	sort.Slice(dataPaths, func(i, j int) bool { return dataPaths[i].Path < dataPaths[j].Path })
	return dataPaths
}

func (r *GarageClusterReconciler) writeConfigMapWithLabels(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	name,
	body string,
	extraLabels map[string]string,
	managedAnnotations map[string]string,
) (string, error) {
	labels := mergeLabels(r.labelsForCluster(cluster), extraLabels)
	revision, err := garageConfigRevision(ctx, r.safetyReader(), cluster, body)
	if err != nil {
		return "", err
	}
	if garageConfigUsesSecret(cluster) {
		return reconcileGarageConfigSecret(
			ctx,
			r.Client,
			r.Scheme,
			cluster,
			cluster.Namespace,
			name,
			body,
			revision,
			labels,
			managedAnnotations,
			true,
		)
	}
	return reconcileGarageConfigMap(
		ctx,
		r.Client,
		r.Scheme,
		cluster,
		cluster.Namespace,
		name,
		body,
		revision,
		labels,
		managedAnnotations,
		true,
	)
}

func garageConfigHash(body string) string {
	configHash := sha256.Sum256([]byte(body))
	return hex.EncodeToString(configHash[:])
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
	// OmitClusterRPCPublicAddr suppresses the cluster.Spec.Network.RPCPublicAddr
	// fallback in writeRPCConfig. Set for gateway nodes so they never inherit the
	// storage tier's rpc_public_addr when the gateway tier has none of its own
	// (the v0.5.3 outage). A higher-priority Node/Tier override still wins.
	OmitClusterRPCPublicAddr bool
	// NodeDataDirPaths, when non-empty, replaces the cluster-level data_dir with a
	// per-node TOML array (one entry per mount). Used by the GarageNode controller
	// for multi-HDD nodes. Capacity (e.g. "100Gi") is optional; when set it is
	// emitted as the per-path `capacity` so Garage knows the disk size.
	NodeDataDirPaths []NodeDataDirPath
	// ForceSingleDataDir makes the node use the universally mounted /data/data
	// directory even when the cluster's storage tier has a multi-disk data_dir.
	// Unified-cluster gateway nodes need this: they do not mount storage disks.
	ForceSingleDataDir bool
	// NodeMetadataSnapshotsDir overrides storage.metadataSnapshotsDir for this node's
	// garage.toml. Empty means inherit from cluster spec.
	NodeMetadataSnapshotsDir string
	// NodeMetadataAutoSnapshotInterval overrides storage.metadataAutoSnapshotInterval
	// for this node's garage.toml. Empty means inherit from cluster spec.
	NodeMetadataAutoSnapshotInterval string
}

// NodeDataDirPath is one mount path in a per-node multi-HDD garage.toml data_dir array.
type NodeDataDirPath struct {
	Path     string
	Capacity string // optional; if empty and ReadOnly is false the entry has no capacity attribute
	ReadOnly bool   // emits `read_only = true`; mutually exclusive with Capacity per Garage's parser
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
		secretName := tokenRef.Name
		tokenKey := remoteAdminTokenKey
		if snapshot := currentStaticCredentialsSecretName(cluster); snapshot != "" {
			secretName = snapshot
			tokenKey = staticCredentialConsulTokenKey
		} else if tokenRef.Key != "" {
			tokenKey = tokenRef.Key
		}
		if err := cl.Get(ctx, types.NamespacedName{
			Name:      secretName,
			Namespace: cluster.Namespace,
		}, secret); err != nil {
			return nil, fmt.Errorf("failed to get Consul token secret %s: %w", secretName, err)
		}

		if tokenData, ok := secret.Data[tokenKey]; ok {
			cfgCtx.ConsulToken = strings.TrimSpace(string(tokenData))
		} else {
			return nil, fmt.Errorf("consul token key %q not found in secret %s", tokenKey, secretName)
		}
	}

	// Derive rpc_public_addr from publicEndpoint if configured and network.rpcPublicAddr is not set.
	if cluster.Spec.PublicEndpoint != nil && cluster.Spec.Network.RPCPublicAddr == "" {
		rpcPort := getRPCPort(cluster)
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
			} else if !cluster.HasStorageTier() && cluster.HasGatewayTier() {
				// Edge-gateway (gateway-only) cluster with perNode=true: derive
				// rpc_public_addr from the ordinal-0 per-node service. All pods share
				// a single cluster-level ConfigMap, so ordinal 0's IP is used as a
				// best-effort address for single-replica gateways; multi-replica edge
				// gateways with perNode would need per-pod ConfigMaps to be exact.
				svc := &corev1.Service{}
				if err := cl.Get(ctx, types.NamespacedName{
					Name:      perNodeRPCServiceName(cluster.Name, 0),
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

// tomlQuote emits one TOML basic string without relying on Go's %q: Go may use
// \xNN escapes, which TOML does not accept. Quoting every user-controlled TOML
// string and key prevents malformed configuration and structural injection.
func tomlQuote(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, char := range value {
		switch char {
		case '\b':
			quoted.WriteString(`\b`)
		case '\t':
			quoted.WriteString(`\t`)
		case '\n':
			quoted.WriteString(`\n`)
		case '\f':
			quoted.WriteString(`\f`)
		case '\r':
			quoted.WriteString(`\r`)
		case '"':
			quoted.WriteString(`\"`)
		case '\\':
			quoted.WriteString(`\\`)
		default:
			if char < 0x20 || char == 0x7f {
				fmt.Fprintf(&quoted, `\u%04X`, char)
			} else {
				quoted.WriteRune(char)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

// writeDataDirConfig writes the data_dir configuration, supporting both single path
// and multi-path configurations. Garage supports multiple data directories since v0.9.0
// with format: data_dir = [{ path = "/path", capacity = "2T" }, ...]
func writeDataDirConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster, cfgCtx *configContext) {
	if cfgCtx != nil && cfgCtx.ForceSingleDataDir {
		config.WriteString("data_dir = \"/data/data\"\n")
		return
	}
	// Per-node multi-HDD override takes precedence over cluster-level paths.
	if cfgCtx != nil && len(cfgCtx.NodeDataDirPaths) > 0 {
		config.WriteString("data_dir = [\n")
		for i, p := range cfgCtx.NodeDataDirPaths {
			fmt.Fprintf(config, "    { path = %s", tomlQuote(p.Path))
			switch {
			case p.ReadOnly:
				config.WriteString(", read_only = true")
			case p.Capacity != "":
				fmt.Fprintf(config, ", capacity = %s", tomlQuote(p.Capacity))
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
			config.WriteString("    { path = ")
			config.WriteString(tomlQuote(path.Path))
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
					fmt.Fprintf(config, ", capacity = %s", tomlQuote(garageBytesize(cap)))
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
	fmt.Fprintf(config, "db_engine = %s\n", tomlQuote(dbEngine))

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
		r = &garagev1beta2.ReplicationConfig{Factor: 3, ConsistencyMode: consistencyModeConsistent}
	}
	fmt.Fprintf(config, "replication_factor = %d\n", r.Factor)
	if r.ConsistencyMode != "" {
		fmt.Fprintf(config, "consistency_mode = %s\n", tomlQuote(r.ConsistencyMode))
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
		fmt.Fprintf(config, "metadata_snapshots_dir = %s\n", tomlQuote(metadataSnapshotsDir))
	}
	if metadataAutoSnapshotInterval != "" {
		fmt.Fprintf(config, "metadata_auto_snapshot_interval = %s\n", tomlQuote(metadataAutoSnapshotInterval))
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
		fmt.Fprintf(config, "rpc_bind_addr = %s\n", tomlQuote(cluster.Spec.Network.RPCBindAddress))
	} else {
		rpcPort := getRPCPort(cluster)
		fmt.Fprintf(config, "rpc_bind_addr = \"[::]:%d\"\n", rpcPort)
	}
	config.WriteString("rpc_secret_file = \"/secrets/rpc/rpc-secret\"\n")

	// Priority: edge-gateway tier addr > per-node override > per-tier override >
	// cluster static > publicEndpoint-derived.
	switch {
	case cluster.HasGatewayTier() && !cluster.HasStorageTier() && cluster.Spec.Gateway != nil && cluster.Spec.Gateway.RPCPublicAddr != "":
		// Edge gateway (gateway-only CR connecting to remote storage): the
		// gateway tier's own rpcPublicAddr is the documented "preferred" field and
		// must reach the rendered config, otherwise Garage advertises the
		// unroutable pod IP and the remote cluster can never dial back (the
		// v0.5.3 outage class). It has no storage tier to inherit from.
		fmt.Fprintf(config, "rpc_public_addr = %s\n", tomlQuote(cluster.Spec.Gateway.RPCPublicAddr))
	case cfgCtx != nil && cfgCtx.NodeRPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = %s\n", tomlQuote(cfgCtx.NodeRPCPublicAddr))
	case cfgCtx != nil && cfgCtx.TierRPCPublicAddrOverride != "":
		fmt.Fprintf(config, "rpc_public_addr = %s\n", tomlQuote(cfgCtx.TierRPCPublicAddrOverride))
	case cluster.Spec.Network.RPCPublicAddr != "" && (cfgCtx == nil || !cfgCtx.OmitClusterRPCPublicAddr):
		fmt.Fprintf(config, "rpc_public_addr = %s\n", tomlQuote(cluster.Spec.Network.RPCPublicAddr))
	case cfgCtx != nil && cfgCtx.RPCPublicAddr != "":
		fmt.Fprintf(config, "rpc_public_addr = %s\n", tomlQuote(cfgCtx.RPCPublicAddr))
	}
	if cluster.Spec.Network.RPCPublicAddrSubnet != "" {
		fmt.Fprintf(config, "rpc_public_addr_subnet = %s\n", tomlQuote(cluster.Spec.Network.RPCPublicAddrSubnet))
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
			quotedPeers = append(quotedPeers, tomlQuote(peer))
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
	s3Port := getS3Port(cluster)
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = %s\n", tomlQuote(cluster.Spec.S3API.BindAddress))
	} else {
		fmt.Fprintf(config, "api_bind_addr = \"[::]:%d\"\n", s3Port)
	}
	region := defaultS3Region
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		region = cluster.Spec.S3API.Region
	}
	fmt.Fprintf(config, "s3_region = %s\n", tomlQuote(region))
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.RootDomain != "" {
		fmt.Fprintf(config, "root_domain = %s\n", tomlQuote(cluster.Spec.S3API.RootDomain))
	}
}

func writeK2VAPIConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	if cluster.Spec.K2VAPI == nil {
		return
	}
	config.WriteString("\n[k2v_api]\n")
	if cluster.Spec.K2VAPI.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = %s\n", tomlQuote(cluster.Spec.K2VAPI.BindAddress))
	} else {
		k2vPort := getK2VPort(cluster)
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
		fmt.Fprintf(config, "bind_addr = %s\n", tomlQuote(w.BindAddress))
	} else {
		webPort := getWebPort(cluster)
		fmt.Fprintf(config, "bind_addr = \"[::]:%d\"\n", webPort)
	}
	fmt.Fprintf(config, "root_domain = %s\n", tomlQuote(w.RootDomain))
	if w.AddHostToMetrics {
		config.WriteString("add_host_to_metrics = true\n")
	}
}

func writeAdminConfig(config *strings.Builder, cluster *garagev1beta2.GarageCluster) {
	config.WriteString("\n[admin]\n")
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindAddress != "" {
		fmt.Fprintf(config, "api_bind_addr = %s\n", tomlQuote(cluster.Spec.Admin.BindAddress))
	} else {
		adminPort := getAdminPort(cluster)
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
		fmt.Fprintf(config, "trace_sink = %s\n", tomlQuote(cluster.Spec.Admin.TraceSink))
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
		fmt.Fprintf(config, "namespace = %s\n", tomlQuote(k8s.Namespace))
	} else {
		fmt.Fprintf(config, "namespace = %s\n", tomlQuote(cluster.Namespace))
	}
	if k8s.ServiceName != "" {
		fmt.Fprintf(config, "service_name = %s\n", tomlQuote(k8s.ServiceName))
	} else {
		fmt.Fprintf(config, "service_name = %s\n", tomlQuote(cluster.Name))
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
		fmt.Fprintf(config, "api = %s\n", tomlQuote(consul.API))
	}
	if consul.HTTPAddr != "" {
		fmt.Fprintf(config, "consul_http_addr = %s\n", tomlQuote(consul.HTTPAddr))
	}
	if consul.ServiceName != "" {
		fmt.Fprintf(config, "service_name = %s\n", tomlQuote(consul.ServiceName))
	}

	// CA certificate: prefer secret ref over inline value
	if consul.CACertSecretRef != nil {
		config.WriteString("ca_cert = \"/secrets/consul/ca/ca.crt\"\n")
	} else if consul.CACert != "" {
		fmt.Fprintf(config, "ca_cert = %s\n", tomlQuote(consul.CACert))
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
		fmt.Fprintf(config, "token = %s\n", tomlQuote(cfgCtx.ConsulToken))
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
			config.WriteString(tomlQuote(tag))
		}
		config.WriteString("]\n")
	}
	// Parent-table keys must be emitted before opening [consul_discovery.meta].
	// TOML table headers retain scope; writing datacenters afterward would make
	// it meta.datacenters (an array where Garage expects meta values to be
	// strings) and can prevent the process from starting.
	if len(consul.Datacenters) > 0 {
		config.WriteString("datacenters = [")
		for i, dc := range consul.Datacenters {
			if i > 0 {
				config.WriteString(", ")
			}
			config.WriteString(tomlQuote(dc))
		}
		config.WriteString("]\n")
	}
	if len(consul.Meta) > 0 {
		config.WriteString("[consul_discovery.meta]\n")
		// Sort keys so the rendered TOML is deterministic. Iterating the map
		// directly produces a different field order on every reconcile, which
		// churns the config hash and drives an endless StatefulSet rolling-update
		// loop even though the config is logically unchanged.
		keys := make([]string, 0, len(consul.Meta))
		for k := range consul.Meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(config, "%s = %s\n", tomlQuote(k), tomlQuote(consul.Meta[k]))
		}
	}
}

func (r *GarageClusterReconciler) reconcileHeadlessService(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)
	serviceName := cluster.Name + "-headless"
	if err := validateManagedHeadlessServiceName(cluster.Name); err != nil {
		return fmt.Errorf("refusing to publish an invalid managed discovery Service: %w", err)
	}

	rpcPort := getRPCPort(cluster)

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
	s3Port := getS3Port(cluster)
	ports = append(ports, corev1.ServicePort{
		Name:       s3PortName,
		Port:       s3Port,
		TargetPort: intstr.FromInt32(s3Port),
		Protocol:   corev1.ProtocolTCP,
	})

	// Admin API port
	adminPort := getAdminPort(cluster)
	ports = append(ports, corev1.ServicePort{
		Name:       adminPortName,
		Port:       adminPort,
		TargetPort: intstr.FromInt32(adminPort),
		Protocol:   corev1.ProtocolTCP,
	})

	// K2V API port (only when enabled)
	if cluster.Spec.K2VAPI != nil {
		k2vPort := getK2VPort(cluster)
		ports = append(ports, corev1.ServicePort{
			Name:       k2vPortName,
			Port:       k2vPort,
			TargetPort: intstr.FromInt32(k2vPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	// Web API port (when not explicitly disabled)
	if w := effectiveWebAPI(cluster); w != nil {
		webPort := getWebPort(cluster)
		ports = append(ports, corev1.ServicePort{
			Name:       webPortName,
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
//   - Gateway tier: unified per-node and edge cluster-level StatefulSets both
//     carry the tier labels, so the same tier-scoped selector covers them.
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
// tier (edge-gateway clusters). The gateway-tier workloads get their own
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
	var loadBalancerIP string
	var loadBalancerSourceRanges []string
	var externalTrafficPolicy corev1.ServiceExternalTrafficPolicy
	if cluster.Spec.Network.Service != nil {
		svcMeta = cluster.Spec.Network.Service.ServiceMeta
		loadBalancerIP = cluster.Spec.Network.Service.LoadBalancerIP
		loadBalancerSourceRanges = append([]string(nil), cluster.Spec.Network.Service.LoadBalancerSourceRanges...)
		externalTrafficPolicy = cluster.Spec.Network.Service.ExternalTrafficPolicy
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        serviceName,
			Namespace:   cluster.Namespace,
			Labels:      mergeLabels(r.labelsForCluster(cluster), svcMeta.Labels),
			Annotations: svcMeta.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                     serviceType,
			Selector:                 r.apiServiceSelector(cluster, primaryTier),
			Ports:                    apiServicePorts(cluster),
			LoadBalancerIP:           loadBalancerIP,
			LoadBalancerSourceRanges: loadBalancerSourceRanges,
			ExternalTrafficPolicy:    externalTrafficPolicy,
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
		pdbName           string
		pdbCfg            *garagev1beta2.PodDisruptionBudgetConfig
		replicas          int32
		wantPDB           bool
		dynamicMembership bool
	)
	switch tier {
	case tierStorage:
		pdbName = cluster.Name
		if cluster.HasStorageTier() {
			pdbCfg = cluster.Spec.Storage.PodDisruptionBudget
			replicas = cluster.StorageReplicas()
			dynamicMembership = hasNodeLocalPools(cluster) || cluster.EffectiveStorageLayoutPolicy() == LayoutPolicyManual
		}
		wantPDB = cluster.HasStorageTier() && pdbCfg != nil && pdbCfg.Enabled
	case tierGateway:
		pdbName = cluster.Name + "-gateway"
		if cluster.HasGatewayTier() {
			pdbCfg = cluster.Spec.Gateway.PodDisruptionBudget
			replicas = cluster.Spec.Gateway.Replicas
			dynamicMembership = cluster.Spec.LayoutPolicy == LayoutPolicyManual
		}
		// Auto gateway replicas=0 is paused. Manual replicas are ignored and the
		// requested PDB protects dynamically declared gateway GarageNodes.
		wantPDB = cluster.HasGatewayTier() && pdbCfg != nil && pdbCfg.Enabled && (replicas > 0 || dynamicMembership)
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
	case dynamicMembership:
		// Manual GarageNodes and node-local selectors have dynamic cardinality;
		// ignored replica fields cannot supply an honest minAvailable default.
		// Protect voluntary drains one pod at a time across the whole tier.
		maxUnavail := intstr.FromInt(1)
		spec.MaxUnavailable = &maxUnavail
	case replicas <= 1:
		// A single-replica tier (a lone stateless gateway, or a 1-node storage
		// tier) cannot use minAvailable=1: that permits zero voluntary
		// disruptions and makes the only pod undrainable, wedging node drains
		// and cluster-autoscaler scale-downs. maxUnavailable=1 still records
		// the PDB intent while letting the pod be evicted and rescheduled.
		maxUnavail := intstr.FromInt(1)
		spec.MaxUnavailable = &maxUnavail
	default:
		// Default to (replicas-1). For storage this preserves quorum on drain
		// for 3+ replica clusters and matches the pre-#192 default and the
		// warning emitted by the v1beta1/v1beta2 validating webhooks. For
		// gateway it pins at least one pod available, which is what users want
		// during node drains.
		minAvail := intstr.FromInt(int(replicas - 1))
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
	if !metav1.IsControlledBy(existing, cluster) {
		return fmt.Errorf("refusing to mutate PodDisruptionBudget %s/%s because it is not controlled by GarageCluster UID %s", existing.Namespace, existing.Name, cluster.UID)
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
			// Gateway pods carry a bind-only TCP readiness probe (see
			// buildGaragePodSpec; overridable via spec.gateway.readinessProbe).
			// PublishNotReadyAddresses: false makes kube-proxy honor it — surge
			// pods during a rollout don't receive S3 traffic until Garage has
			// bound :3900, and terminating pods drop out of the endpoint slice.
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
	if !metav1.IsControlledBy(existing, cluster) {
		log.Info("Leaving foreign same-name gateway Service untouched", "name", name)
		return nil
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
	rpcPort := getRPCPort(cluster)

	var svcType corev1.ServiceType
	var svcMeta garagev1beta2.ServiceMeta
	var nodePort int32

	switch ep.Type {
	case publicEndpointTypeLoadBalancer:
		if ep.LoadBalancer != nil && ep.LoadBalancer.PerNode {
			if cluster.EffectiveStorageLayoutPolicy() == LayoutPolicyManual {
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

	publicSelector := map[string]string{
		labelCluster: cluster.Name,
	}
	if cluster.HasStorageTier() {
		// A node-local-pool identity needs a Service that selects its exact Kubernetes
		// Node. Keep the cluster publicEndpoint scoped to the default PVC/manual
		// storage group in mixed clusters.
		publicSelector[labelTier] = tierStorage
		publicSelector[labelStorageGroup] = storageGroupDefault
	} else {
		publicSelector[labelTier] = tierGateway
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
			Selector:                 publicSelector,
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

	// Determine replicas and pod selectors based on which tier is present.
	// Storage clusters use the GarageNode-controller-written label; edge-gateway
	// clusters (no storage tier) use the Kubernetes-added pod-name label on the
	// cluster-level gateway StatefulSet.
	type perNodeEntry struct {
		svcName  string
		podLabel string // value for the per-pod selector key
		selector map[string]string
	}
	var entries []perNodeEntry

	if cluster.HasStorageTier() {
		// Per-#190, storage pods live behind per-GarageNode StatefulSets named
		// `<cluster>-storage-<i>`. Select via the stable `garage.rajsingh.info/node`
		// label written by the GarageNode controller.
		existing, err := r.listAutoModeStorageNodes(ctx, cluster)
		if err != nil {
			return fmt.Errorf("listing Auto storage GarageNodes for per-node RPC Services: %w", err)
		}
		replicas := cluster.StorageReplicas()
		for i := int32(0); i < replicas; i++ {
			canonicalName := autoModeGarageNodeName(cluster.Name, i)
			nodeName := canonicalName
			_, current, err := resolveAutoModeCycleSlot(existing, canonicalName)
			if err != nil {
				return fmt.Errorf("resolving Auto storage ordinal %d for per-node RPC Service: %w", i, err)
			}
			if current != nil && hasExactGarageClusterControllerReference(current, cluster) {
				nodeName = current.Name
			} else if current != nil && current.Name == canonicalName {
				return fmt.Errorf(
					"canonical Auto storage GarageNode %s is not controlled by the exact GarageCluster UID; refusing an untrusted RPC Service selector",
					canonicalName,
				)
			}
			entries = append(entries, perNodeEntry{
				svcName:  perNodeRPCServiceName(cluster.Name, i),
				podLabel: nodeName,
				selector: map[string]string{
					labelCluster:    cluster.Name,
					labelGarageNode: nodeName,
				},
			})
		}
	} else if cluster.HasGatewayTier() {
		// Edge-gateway (gateway-only) cluster: the gateway StatefulSet pods carry
		// the Kubernetes-added `statefulset.kubernetes.io/pod-name` label, which
		// is the only stable per-pod handle available without per-GarageNode CRs.
		replicas := cluster.GatewayReplicas()
		stsName := gatewayWorkloadName(cluster)
		for i := int32(0); i < replicas; i++ {
			podName := fmt.Sprintf("%s-%d", stsName, i)
			entries = append(entries, perNodeEntry{
				svcName:  perNodeRPCServiceName(cluster.Name, i),
				podLabel: podName,
				selector: map[string]string{
					labelCluster:                         cluster.Name,
					"statefulset.kubernetes.io/pod-name": podName,
				},
			})
		}
	}

	desired := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		desired[e.svcName] = struct{}{}
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        e.svcName,
				Namespace:   cluster.Namespace,
				Labels:      mergeLabels(r.labelsForCluster(cluster), svcMeta.Labels),
				Annotations: svcMeta.Annotations,
			},
			Spec: corev1.ServiceSpec{
				Type:                     corev1.ServiceTypeLoadBalancer,
				Selector:                 e.selector,
				Ports:                    []corev1.ServicePort{rpcServicePort(rpcPort, 0)},
				PublishNotReadyAddresses: true,
			},
		}
		log.Info("Reconciling per-node public endpoint RPC service", "name", e.svcName, "pod", e.podLabel, "type", corev1.ServiceTypeLoadBalancer)
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
		if !metav1.IsControlledBy(svc, cluster) {
			log.Info("Leaving foreign stale per-node RPC Service untouched", "name", svc.Name)
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
		if !metav1.IsControlledBy(svc, cluster) {
			logf.FromContext(ctx).Info("Leaving foreign per-node RPC Service untouched", "name", svc.Name)
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
		if !metav1.IsControlledBy(existing, cluster) {
			logf.FromContext(ctx).Info("Leaving foreign same-name public endpoint Service untouched", "name", name)
			return nil
		}
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

	rpcPort := getRPCPort(cluster)
	ports = append(ports, corev1.ContainerPort{Name: rpcPortName, ContainerPort: rpcPort})

	// S3 API port (always enabled - Garage requires the [s3_api] section)
	s3Port := getS3Port(cluster)
	ports = append(ports, corev1.ContainerPort{Name: s3PortName, ContainerPort: s3Port})

	ports = append(ports, corev1.ContainerPort{Name: adminPortName, ContainerPort: getAdminPort(cluster)})

	// K2V API port
	if cluster.Spec.K2VAPI != nil {
		k2vPort := getK2VPort(cluster)
		ports = append(ports, corev1.ContainerPort{Name: "k2v", ContainerPort: k2vPort})
	}

	// Web API port
	if w := effectiveWebAPI(cluster); w != nil {
		webPort := getWebPort(cluster)
		ports = append(ports, corev1.ContainerPort{Name: "web", ContainerPort: webPort})
	}

	return ports
}

// gatewayVolumeClaimTemplatesChanged compares every gateway PVC-template field
// the public API supports. Kubernetes treats the template as immutable, so a
// zero-replica edge gateway must recreate its StatefulSet to publish any of
// these changes. VolumeMode and other full-template fields are intentionally
// ignored because gateway.metadata.volumeClaimTemplateSpec is rejected.
func gatewayVolumeClaimTemplatesChanged(existing, desired []corev1.PersistentVolumeClaim) bool {
	if len(existing) != len(desired) {
		return true
	}
	existingByName := make(map[string]*corev1.PersistentVolumeClaim, len(existing))
	for i := range existing {
		existingByName[existing[i].Name] = &existing[i]
	}
	for i := range desired {
		current, ok := existingByName[desired[i].Name]
		if !ok {
			return true
		}
		candidate := &desired[i]
		if !equality.Semantic.DeepEqual(current.Spec.StorageClassName, candidate.Spec.StorageClassName) ||
			!equality.Semantic.DeepEqual(current.Spec.AccessModes, candidate.Spec.AccessModes) ||
			!equality.Semantic.DeepEqual(current.Spec.Selector, candidate.Spec.Selector) ||
			!equality.Semantic.DeepEqual(current.Spec.Resources, candidate.Spec.Resources) ||
			!equality.Semantic.DeepEqual(current.Labels, candidate.Labels) ||
			!equality.Semantic.DeepEqual(current.Annotations, candidate.Annotations) {
			return true
		}
	}
	return false
}

// reconcileManagementHandle reconciles a connection-only GarageCluster (#269):
// spec.connectTo with no storage/gateway tier. It provisions no workload — it
// resolves the external Admin API from spec.connectTo, probes reachability, and
// reflects the result on Status.Phase (Running/Pending) plus the
// ManagementHandleReady condition. Dependent GarageBucket/GarageKey CRs gate on
// Phase == Running, so this is what makes them start managing the external
// cluster's state.
func (r *GarageClusterReconciler) reconcileManagementHandle(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Endpoints has no in-cluster Service to derive from for a management
	// handle; set by the caller before the terminal setPhase(PhaseRunning, ...)
	// call so it survives UpdateStatusWithRetry's re-fetch-and-reapply.
	var endpoints *garagev1beta2.ClusterEndpoints
	setPhase := func(phase string, cond metav1.Condition) (ctrl.Result, error) {
		apply := func() {
			cluster.Status.Phase = phase
			cond.ObservedGeneration = cluster.Generation
			meta.SetStatusCondition(&cluster.Status.Conditions, cond)
			if phase == PhaseRunning {
				cluster.Status.ObservedGeneration = cluster.Generation
			}
			if endpoints != nil {
				cluster.Status.Endpoints = endpoints
			}
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
			return ctrl.Result{}, err
		}
		if phase == PhaseRunning {
			return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
		}
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// A handle does not need an RPC identity merely to manage buckets, imported
	// keys, or layout through the Admin API. When the user does provide one,
	// however, generated GarageKey credentials must derive from the exact same
	// immutable bytes as the external cluster. Pin that source before declaring
	// the handle ready, just as managed workloads do, without inventing a
	// meaningless identity for Admin-only handles.
	rpcSource, err := r.resolveRPCSecretSource(ctx, cluster)
	if err != nil {
		return setPhase(PhasePending, metav1.Condition{
			Type:    garagev1beta1.ConditionManagementHandleReady,
			Status:  metav1.ConditionFalse,
			Reason:  garagev1beta1.ReasonReconcileFailed,
			Message: fmt.Sprintf("failed to resolve the external Garage RPC identity: %v", err),
		})
	}
	if rpcSource != nil {
		if _, err := r.ensureRPCSecret(ctx, cluster); err != nil {
			return setPhase(PhasePending, metav1.Condition{
				Type:    garagev1beta1.ConditionManagementHandleReady,
				Status:  metav1.ConditionFalse,
				Reason:  garagev1beta1.ReasonReconcileFailed,
				Message: fmt.Sprintf("failed to pin the external Garage RPC identity: %v", err),
			})
		}
	}

	client, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		log.Info("Management handle: cannot build admin client", "error", err.Error())
		return setPhase(PhasePending, metav1.Condition{
			Type:    garagev1beta1.ConditionManagementHandleReady,
			Status:  metav1.ConditionFalse,
			Reason:  garagev1beta1.ReasonAdminTokenMissing,
			Message: fmt.Sprintf("failed to build admin client from spec.connectTo: %v", err),
		})
	}

	if _, err := client.GetClusterStatus(ctx); err != nil {
		log.Info("Management handle: external Garage Admin API not reachable", "error", err.Error())
		return setPhase(PhasePending, metav1.Condition{
			Type:    garagev1beta1.ConditionManagementHandleReady,
			Status:  metav1.ConditionFalse,
			Reason:  garagev1beta1.ReasonAdminUnreachable,
			Message: fmt.Sprintf("external Garage Admin API not reachable (will retry): %v", err),
		})
	}

	// Derive the S3 endpoint from the Admin API host (same host, S3 port)
	// so COSI's getS3Endpoint has something to read. Best effort: assumes
	// both APIs share a host, which doesn't hold for every topology.
	if cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		if adminURL, err := url.Parse(cluster.Spec.ConnectTo.AdminAPIEndpoint); err == nil && adminURL.Hostname() != "" {
			s3URL := *adminURL
			s3URL.Host = fmt.Sprintf("%s:%d", adminURL.Hostname(), getS3Port(cluster))
			endpoints = &garagev1beta2.ClusterEndpoints{
				S3:    s3URL.String(),
				Admin: cluster.Spec.ConnectTo.AdminAPIEndpoint,
			}
		} else if err != nil {
			log.Info("could not derive S3 endpoint from spec.connectTo.adminApiEndpoint", "error", err.Error())
		}
	}

	return setPhase(PhaseRunning, metav1.Condition{
		Type:    garagev1beta1.ConditionManagementHandleReady,
		Status:  metav1.ConditionTrue,
		Reason:  garagev1beta1.ReasonReconcileSuccess,
		Message: "external Garage Admin API reachable; managing buckets/keys/layout via spec.connectTo",
	})
}

// updateStatusAfterNodeLocalPoolContention handles the expected overlap between
// a GarageNode health pass and the parent controller's node-local activation
// revalidation. The losing reconciler must retry without presenting the healthy
// cluster as Failed. If this generation had already converged, preserve that
// durable condition and refresh the ordinary live status projection. During an
// actual membership transition, publish an explicit waiting condition instead.
func (r *GarageClusterReconciler) updateStatusAfterNodeLocalPoolContention(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	cause error,
) (ctrl.Result, error) {
	logf.FromContext(ctx).V(1).Info(
		"Node-local pool reconciliation is waiting for the active Garage layout operation",
		"error", cause.Error(),
	)

	condition := findNodeLocalPoolsReadyCondition(cluster)
	converged := condition != nil &&
		condition.Status == metav1.ConditionTrue &&
		condition.ObservedGeneration == cluster.Generation
	if !converged {
		if err := r.setNodeLocalPoolsCondition(
			ctx,
			cluster,
			metav1.ConditionFalse,
			garagev1beta1.ReasonNodeLocalPoolWaitingForLayoutSync,
			"waiting for the active Garage layout operation before continuing node-local-pool reconciliation",
		); err != nil {
			return ctrl.Result{}, fmt.Errorf("recording node-local-pool layout contention: %w", err)
		}
	}

	result, err := r.updateStatusFromCluster(ctx, cluster)
	if err != nil {
		return result, err
	}
	if result.RequeueAfter == 0 || result.RequeueAfter > RequeueAfterError {
		result.RequeueAfter = RequeueAfterError
	}
	return result, nil
}

func (r *GarageClusterReconciler) updateStatus(ctx context.Context, cluster *garagev1beta2.GarageCluster, phase string, err error) (ctrl.Result, error) {
	// Assemble the desired status inside a closure so a conflict-driven
	// re-fetch in UpdateStatusWithRetry re-applies it instead of pushing back
	// the stale server copy.
	apply := func() {
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
	}
	apply()

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	return ctrl.Result{}, nil
}

func (r *GarageClusterReconciler) updateStatusFromCluster(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	scale, err := r.observeGarageClusterScale(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("observe GarageCluster scale status: %w", err)
	}

	// Get workload status
	var readyReplicas int32
	var desiredReplicas int32

	var storageDesired, storageReady int32
	var gatewayDesired, gatewayReady int32
	if cluster.HasStorageTier() && cluster.EffectiveStorageLayoutPolicy() != LayoutPolicyManual {
		storageDesired = cluster.StorageReplicas()
	}
	if cluster.HasGatewayTier() && cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		gatewayDesired = cluster.GatewayReplicas()
	}

	// Match by spec.clusterRef rather than labels: hand-written Manual
	// GarageNodes are not required to carry operator labels. Default-pool
	// Manual nodes contribute their actual declared count; node-local-pool-backed
	// nodes are counted separately against their dynamic workload cardinality.
	gnList := &garagev1beta1.GarageNodeList{}
	var nodeLocalPoolNodeCount int32
	if err := r.List(ctx, gnList, client.InNamespace(cluster.Namespace)); err != nil {
		log.Error(err, "Failed to list child GarageNodes for status aggregation")
	} else {
		for i := range gnList.Items {
			node := &gnList.Items[i]
			if node.Spec.ClusterRef.Name != cluster.Name {
				continue
			}
			switch {
			case node.Spec.Gateway:
				if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
					gatewayDesired++
				}
				if garageNodeLayoutReady(node) {
					gatewayReady++
				}
			case node.Spec.Backing == garagev1beta1.NodeBackingNodeLocalPool:
				nodeLocalPoolNodeCount++
				if garageNodeLayoutReady(node) {
					storageReady++
				}
			default:
				if cluster.EffectiveStorageLayoutPolicy() == LayoutPolicyManual {
					storageDesired++
				}
				if garageNodeLayoutReady(node) {
					storageReady++
				}
			}
		}
	}

	// Include every owned pool DaemonSet, including one being retired. Its
	// desired-number-scheduled remains the workload cardinality while old roles
	// drain. GarageNode connectivity plus committed-layout membership, not
	// Kubernetes pod readiness alone, is the authoritative ready signal.
	poolDesired := int32(0)
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return ctrl.Result{}, err
	}
	for i := range daemonSets.Items {
		ds := &daemonSets.Items[i]
		if ds.Labels[labelNodeLocalPool] == "" || !metav1.IsControlledBy(ds, cluster) {
			continue
		}
		poolDesired += ds.Status.DesiredNumberScheduled
	}
	if nodeLocalPoolNodeCount > poolDesired {
		// Status can lag immediately after activation, and a retiring pool keeps
		// a GarageNode until its finalizer completes. Never report fewer desired
		// pool members than identities currently under management.
		poolDesired = nodeLocalPoolNodeCount
	}
	storageDesired += poolDesired

	// Edge gateways use one cluster-owned StatefulSet rather than per-node
	// GarageNodes. Fall back to its rollout status when there are no connected
	// gateway GarageNodes.
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

	// Scale-down finalizers can leave an extra connected role briefly. Status
	// readiness should never exceed its desired cardinality.
	if storageReady > storageDesired {
		storageReady = storageDesired
	}
	if gatewayReady > gatewayDesired {
		gatewayReady = gatewayDesired
	}
	cluster.Status.StorageReplicas = storageDesired
	cluster.Status.StorageReadyReplicas = storageReady
	cluster.Status.GatewayReplicas = gatewayDesired
	cluster.Status.GatewayReadyReplicas = gatewayReady
	desiredReplicas = storageDesired + gatewayDesired
	readyReplicas = storageReady + gatewayReady
	cluster.Status.ReadyReplicas = readyReplicas
	cluster.Status.Replicas = desiredReplicas
	cluster.Status.ScaleReplicas = scale.replicas
	cluster.Status.ScaleSelector = scale.selector
	cluster.Status.Selector = metav1.FormatLabelSelector(&metav1.LabelSelector{
		MatchLabels: r.selectorLabelsForCluster(cluster),
	})

	if desiredReplicas == 0 {
		// Both tiers scaled to 0: owned resources still need periodic drift
		// reconciliation.
		if res, err := r.updateStatus(ctx, cluster, "Pending", nil); err != nil {
			return res, err
		}
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	// Try to get cluster health from Garage Admin API. Prefer the universally
	// verified table-backed token. During initial bootstrap or a static-token
	// rollout, route to one exact Pod with the immutable startup bearer that Pod
	// actually mounts; rereading the mutable source would fail both after source
	// deletion and while different Pod incarnations legitimately use different
	// revisions.
	adminPort := getAdminPort(cluster)
	garageClient := r.healthStatusGarageClient(ctx, cluster, adminPort)
	healthObservationExpected := cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil
	healthReadSucceeded := false
	if garageClient != nil && readyReplicas > 0 {
		health, err := garageClient.GetClusterHealth(ctx)
		if err != nil {
			log.V(1).Info("Failed to get cluster health", "error", err)
		} else {
			healthReadSucceeded = true
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
			// Sustained-unreachable peer detection: the admin API exposes only
			// is_up + lastSeenSecsAgo (not Garage's internal Abandoned state), so
			// we flag peers down longer than the threshold. Transient restarts
			// (below the threshold) don't trip it.
			cluster.Status.UnreachablePeers = computeUnreachablePeers(status.Nodes)

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
			for _, v := range reportedLayoutHistoryVersions(history.Versions) {
				cluster.Status.LayoutHistory.Versions = append(cluster.Status.LayoutHistory.Versions, garagev1beta2.LayoutVersionInfo{
					Version:      int64(v.Version),
					Status:       string(v.Status),
					StorageNodes: v.StorageNodes,
					GatewayNodes: v.GatewayNodes,
				})
			}

			// A draining version with a dead peer requires explicit recovery. Garage's
			// skip-dead-nodes API is global: one call ACKs every peer the serving
			// daemon currently sees as down, not only the node that prompted it. Status
			// reconciliation therefore observes and reports this state but never
			// manufactures authorization to advance unrelated layout trackers.
			if drainingVersions := history.GetDrainingVersions(); len(drainingVersions) > 0 && status != nil {
				var deadDrainingNodes []string
				for _, node := range status.Nodes {
					if node.Draining && !node.IsUp {
						deadDrainingNodes = append(deadDrainingNodes, node.ID)
					}
				}
				if len(deadDrainingNodes) > 0 {
					log.Info("Garage layout history is waiting on dead draining nodes; explicit upstream recovery is required",
						"deadNodes", deadDrainingNodes,
						"drainingVersions", len(drainingVersions),
						"currentVersion", history.CurrentVersion)
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
	} else if topologyCondition := meta.FindStatusCondition(
		cluster.Status.Conditions,
		garagev1beta1.ConditionStorageTopologyReady,
	); topologyCondition != nil && topologyCondition.Status != metav1.ConditionTrue {
		readyStatus = metav1.ConditionFalse
		readyReason = "StorageTopologyNotReady"
		readyMessage = topologyCondition.Message
	} else if poolCondition := meta.FindStatusCondition(
		cluster.Status.Conditions,
		garagev1beta1.ConditionNodeLocalPoolsReady,
	); poolCondition != nil && poolCondition.Status != metav1.ConditionTrue {
		readyStatus = metav1.ConditionFalse
		readyReason = "NodeLocalPoolsNotReady"
		readyMessage = fmt.Sprintf("node-local pools are not ready: %s; see the NodeLocalPoolsReady condition and generated GarageNodes for detail", poolCondition.Reason)
	} else if rolloutCondition := meta.FindStatusCondition(
		cluster.Status.Conditions,
		garagev1beta1.ConditionStorageRolloutReady,
	); rolloutCondition != nil && rolloutCondition.Status != metav1.ConditionTrue {
		readyStatus = metav1.ConditionFalse
		readyReason = "StorageRolloutNotReady"
		readyMessage = rolloutCondition.Message
	} else if scaleDownCondition := meta.FindStatusCondition(
		cluster.Status.Conditions,
		garagev1beta1.ConditionStorageScaleDownBlocked,
	); scaleDownCondition != nil && scaleDownCondition.Status == metav1.ConditionTrue {
		readyStatus = metav1.ConditionFalse
		readyReason = "StorageScaleDownBlocked"
		readyMessage = scaleDownCondition.Message
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

	// Detect operator-owned gateway GarageNodes that have lost their layout role
	// (status.inLayout == false). In a unified cluster the gateway tier runs as
	// per-node GarageNodes with a capacity:nil role; if that role is dropped the
	// node loses its locally replicated authentication records and signed requests
	// can fail with "No such key" (#209). Only meaningful for unified
	// clusters — edge gateways own no gateway GarageNodes, so the list is empty.
	cluster.Status.GatewayNodesNotInLayout = nil
	if cluster.HasStorageTier() && cluster.HasGatewayTier() {
		gwNodes := &garagev1beta1.GarageNodeList{}
		if err := r.List(ctx, gwNodes,
			client.InNamespace(cluster.Namespace),
			client.MatchingLabels(map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierGateway,
				labelAppManagedBy: managedByOperatorValue,
			}),
		); err != nil {
			log.V(1).Info("Failed to list gateway GarageNodes for layout-degraded check", "error", err)
		} else {
			for i := range gwNodes.Items {
				n := &gwNodes.Items[i]
				if n.Spec.ClusterRef.Name != cluster.Name {
					continue
				}
				// Only judge nodes that have discovered their identity; a node
				// still coming up (no NodeID yet) hasn't had a chance to join.
				if n.Status.NodeID != "" && !n.Status.InLayout {
					cluster.Status.GatewayNodesNotInLayout = append(cluster.Status.GatewayNodesNotInLayout, n.Name)
				}
			}
		}
	}

	// Derive the actionable health conditions (QuorumAtRisk, RemoteClustersHealthy,
	// FederationConfigured, GatewayLayoutDegraded) + the one-line LayoutDiagnosis
	// from the populated status. Runs after Health + RemoteClusters are set above.
	setClusterHealthConditions(cluster, gnList.Items)

	// Update endpoints using configured ports
	s3Port := getS3Port(cluster)
	rpcPort := getRPCPort(cluster)
	cluster.Status.Endpoints = &garagev1beta2.ClusterEndpoints{
		S3:    svcFQDN(cluster.Name, cluster.Namespace, s3Port, r.ClusterDomain),
		Admin: svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain),
		RPC:   svcFQDN(cluster.Name+"-headless", cluster.Namespace, rpcPort, r.ClusterDomain),
	}

	// The full controller-owned health/status projection is assembled above.
	// A GarageNode may concurrently advance the durable storage-drain CAS, and
	// rollout/factor-migration writers own adjacent transaction fields. Preserve
	// those fields and their conditions from the freshly fetched object on a
	// conflict instead of rewinding them with this reconcile's stale snapshot.
	desiredStatus := cluster.DeepCopy()
	apply := func() {
		cluster.Status = mergeComputedClusterStatus(desiredStatus, cluster)
	}
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		return ctrl.Result{}, err
	}

	// A ready workload without a successful live health observation is still
	// converging (or has lost Admin API access). Retry promptly even for edge
	// gateways: their normal five-minute interval otherwise turns Garage's brief
	// post-layout "Layout not ready" window into several minutes of empty or stale
	// status and can also delay recovery from credential or endpoint failures.
	if healthObservationExpected && readyReplicas > 0 && !healthReadSucceeded {
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	// Edge gateway clusters (clusterRef OR adminApiEndpoint) back off to 5m
	// regardless of health: a gateway shows "unavailable" by design (no data
	// stored locally), and the isUp drift check (isClusterRefGatewayConnected /
	// isExternalGatewayConnected) re-establishes dead connections within that
	// window. Without this, a storage-less gateway falls to the 10s unhealthy
	// requeue and re-runs the full O(storage×gateway) connect loop every 10s.
	if cluster.HasGatewayTier() && cluster.Spec.ConnectTo != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}

	// Requeue faster when cluster is unhealthy to speed up recovery
	if cluster.Status.Health != nil && cluster.Status.Health.Status != healthStatusHealthy {
		return ctrl.Result{RequeueAfter: RequeueAfterUnhealthy}, nil
	}

	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

func mergeComputedClusterStatus(
	desired *garagev1beta2.GarageCluster,
	fresh *garagev1beta2.GarageCluster,
) garagev1beta2.GarageClusterStatus {
	merged := desired.DeepCopy().Status
	freshStatus := fresh.DeepCopy().Status
	merged.StorageDrain = freshStatus.StorageDrain
	merged.StorageRollout = freshStatus.StorageRollout
	merged.FactorMigration = freshStatus.FactorMigration
	merged.AutoModePVCHandoffs = freshStatus.AutoModePVCHandoffs

	protectedConditions := map[string]struct{}{
		garagev1beta1.ConditionStorageDrainReady:   {},
		garagev1beta1.ConditionStorageRolloutReady: {},
	}
	conditions := make([]metav1.Condition, 0, len(merged.Conditions)+2)
	for i := range merged.Conditions {
		if _, protected := protectedConditions[merged.Conditions[i].Type]; !protected {
			conditions = append(conditions, merged.Conditions[i])
		}
	}
	for i := range freshStatus.Conditions {
		if _, protected := protectedConditions[freshStatus.Conditions[i].Type]; protected {
			conditions = append(conditions, freshStatus.Conditions[i])
		}
	}
	merged.Conditions = conditions
	return merged
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
	// Gateway-tier workloads keep the shared cluster/tier labels and are reached
	// via tier-specific selectors (selectorLabelsForTier).
	return map[string]string{
		labelCluster: cluster.Name,
	}
}

// bootstrapNodeInfo holds discovered node information
type bootstrapNodeInfo struct {
	id      string
	podIP   string
	podName string
	// adminToken is the exact static startup bearer referenced by this Pod.
	// During a credential rollout different Pod incarnations legitimately use
	// different immutable snapshots, so direct calls cannot share one token.
	adminToken string
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
	clusterUID             string                 // Globally unique site ownership tag for federated layouts
	zoneRedundancy         *garage.ZoneRedundancy // Zone redundancy setting from cluster spec
	skipStaleDetection     bool                   // Skip stale node removal when some pods are not yet identified
}

// managedAdminPort resolves the one TCP port used by Garage, Services, direct
// Pod probes, and generated credentials. A custom bindAddress takes precedence
// over bindPort, matching Garage's configuration semantics.
func managedAdminPort(cluster *garagev1beta2.GarageCluster) (int32, error) {
	if cluster == nil || cluster.Spec.Admin == nil {
		return DefaultAdminPort, nil
	}
	return garageconfig.ManagedBindPort(
		cluster.Spec.Admin.BindAddress,
		cluster.Spec.Admin.BindPort,
		DefaultAdminPort,
		"spec.admin.bindAddress",
	)
}

func validateManagedListenerPorts(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil {
		return nil
	}
	listeners := make([]garageconfig.ListenerPort, 0, 5)
	add := func(address string, configuredPort, defaultPort int32, field string) error {
		port, err := garageconfig.ManagedBindPort(address, configuredPort, defaultPort, field)
		if err != nil {
			return err
		}
		listeners = append(listeners, garageconfig.ListenerPort{Field: field, Port: port})
		return nil
	}
	if err := add(cluster.Spec.Network.RPCBindAddress, cluster.Spec.Network.RPCBindPort, DefaultRPCPort, "spec.network.rpcBindAddress"); err != nil {
		return err
	}
	if cluster.Spec.S3API == nil {
		listeners = append(listeners, garageconfig.ListenerPort{Field: "spec.s3Api.bindAddress", Port: DefaultS3Port})
	} else if err := add(cluster.Spec.S3API.BindAddress, cluster.Spec.S3API.BindPort, DefaultS3Port, "spec.s3Api.bindAddress"); err != nil {
		return err
	}
	if cluster.Spec.K2VAPI != nil {
		if err := add(cluster.Spec.K2VAPI.BindAddress, cluster.Spec.K2VAPI.BindPort, DefaultK2VPort, "spec.k2vApi.bindAddress"); err != nil {
			return err
		}
	}
	if w := effectiveWebAPI(cluster); w != nil {
		if err := add(w.BindAddress, w.BindPort, DefaultWebPort, "spec.webApi.bindAddress"); err != nil {
			return err
		}
	}
	adminPort, err := managedAdminPort(cluster)
	if err != nil {
		return err
	}
	listeners = append(listeners, garageconfig.ListenerPort{Field: "spec.admin.bindAddress", Port: adminPort})
	return garageconfig.ValidateDistinctListenerPorts(listeners)
}

func validateGarageClusterRuntimeConfig(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil {
		return nil
	}
	if err := garagev1beta2.ValidateSupportedPublicEndpoint(cluster.Spec.PublicEndpoint, "spec.publicEndpoint"); err != nil {
		return err
	}
	if service := cluster.Spec.Network.Service; service != nil {
		serviceType := service.Type
		if serviceType == "" {
			serviceType = corev1.ServiceTypeClusterIP
		}
		if (service.LoadBalancerIP != "" || len(service.LoadBalancerSourceRanges) > 0) && serviceType != corev1.ServiceTypeLoadBalancer {
			return fmt.Errorf("spec.network.service loadBalancerIP and loadBalancerSourceRanges require type: LoadBalancer")
		}
		if service.ExternalTrafficPolicy != "" {
			if service.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster && service.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
				return fmt.Errorf("spec.network.service.externalTrafficPolicy must be Cluster or Local")
			}
			if serviceType != corev1.ServiceTypeLoadBalancer && serviceType != corev1.ServiceTypeNodePort {
				return fmt.Errorf("spec.network.service.externalTrafficPolicy requires type: LoadBalancer or NodePort")
			}
		}
	}
	if !cluster.IsManagementHandle() {
		if err := validateManagedListenerPorts(cluster); err != nil {
			return fmt.Errorf("managed listener: %w", err)
		}
	}
	if cluster.Spec.Network.RPCPingTimeout != nil {
		if err := garageconfig.ValidateRPCDuration(cluster.Spec.Network.RPCPingTimeout.Duration, "spec.network.rpcPingTimeout"); err != nil {
			return err
		}
	}
	if cluster.Spec.Network.RPCTimeout != nil {
		if err := garageconfig.ValidateRPCDuration(cluster.Spec.Network.RPCTimeout.Duration, "spec.network.rpcTimeout"); err != nil {
			return err
		}
	}
	if cluster.Spec.Storage != nil {
		if err := garageconfig.ValidateMetadataSnapshotInterval(
			cluster.Spec.Storage.MetadataAutoSnapshotInterval,
			"spec.storage.metadataAutoSnapshotInterval",
		); err != nil {
			return err
		}
	}
	if cluster.Spec.Database != nil {
		if err := validatePositiveRuntimeQuantity(cluster.Spec.Database.LMDBMapSize, "spec.database.lmdbMapSize"); err != nil {
			return err
		}
		if err := validatePositiveRuntimeQuantity(cluster.Spec.Database.FjallBlockCacheSize, "spec.database.fjallBlockCacheSize"); err != nil {
			return err
		}
	}
	if cluster.Spec.Blocks != nil {
		if err := validatePositiveRuntimeQuantity(cluster.Spec.Blocks.Size, "spec.blocks.size"); err != nil {
			return err
		}
		if err := validatePositiveRuntimeQuantity(cluster.Spec.Blocks.RAMBufferMax, "spec.blocks.ramBufferMax"); err != nil {
			return err
		}
		if cluster.Spec.Blocks.CompressionLevel != nil {
			if err := garageconfig.ValidateCompressionLevel(*cluster.Spec.Blocks.CompressionLevel, "spec.blocks.compressionLevel"); err != nil {
				return err
			}
		}
	}
	if cluster.Spec.ConnectTo != nil {
		if err := garageconfig.ValidateAdminAPIEndpoint(cluster.Spec.ConnectTo.AdminAPIEndpoint, "spec.connectTo.adminApiEndpoint"); err != nil {
			return err
		}
	}
	for i := range cluster.Spec.RemoteClusters {
		if cluster.Spec.RemoteClusters[i].DefaultCapacity != nil {
			return fmt.Errorf("spec.remoteClusters[%d].defaultCapacity is not supported; remote role capacity is owned by the source cluster layout", i)
		}
		if err := garageconfig.ValidateAdminAPIEndpoint(
			cluster.Spec.RemoteClusters[i].Connection.AdminAPIEndpoint,
			fmt.Sprintf("spec.remoteClusters[%d].connection.adminApiEndpoint", i),
		); err != nil {
			return err
		}
	}
	return nil
}

func validatePositiveRuntimeQuantity(value *resource.Quantity, field string) error {
	if value != nil && value.Sign() <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}
	return nil
}

// getAdminPort is used after admission/reconcile validation at endpoint
// construction sites whose existing signatures do not return an error.
func getAdminPort(cluster *garagev1beta2.GarageCluster) int32 {
	port, err := managedAdminPort(cluster)
	if err != nil {
		return DefaultAdminPort
	}
	return port
}

// getRPCPort returns the configured RPC port for the cluster
func getRPCPort(cluster *garagev1beta2.GarageCluster) int32 {
	if cluster == nil {
		return DefaultRPCPort
	}
	port, err := garageconfig.ManagedBindPort(cluster.Spec.Network.RPCBindAddress, cluster.Spec.Network.RPCBindPort, DefaultRPCPort, "spec.network.rpcBindAddress")
	if err != nil {
		return DefaultRPCPort
	}
	return port
}

func getS3Port(cluster *garagev1beta2.GarageCluster) int32 {
	if cluster == nil || cluster.Spec.S3API == nil {
		return DefaultS3Port
	}
	port, err := garageconfig.ManagedBindPort(cluster.Spec.S3API.BindAddress, cluster.Spec.S3API.BindPort, DefaultS3Port, "spec.s3Api.bindAddress")
	if err != nil {
		return DefaultS3Port
	}
	return port
}

func getK2VPort(cluster *garagev1beta2.GarageCluster) int32 {
	if cluster == nil || cluster.Spec.K2VAPI == nil {
		return DefaultK2VPort
	}
	port, err := garageconfig.ManagedBindPort(cluster.Spec.K2VAPI.BindAddress, cluster.Spec.K2VAPI.BindPort, DefaultK2VPort, "spec.k2vApi.bindAddress")
	if err != nil {
		return DefaultK2VPort
	}
	return port
}

func getWebPort(cluster *garagev1beta2.GarageCluster) int32 {
	w := effectiveWebAPI(cluster)
	if w == nil {
		return DefaultWebPort
	}
	port, err := garageconfig.ManagedBindPort(w.BindAddress, w.BindPort, DefaultWebPort, "spec.webApi.bindAddress")
	if err != nil {
		return DefaultWebPort
	}
	return port
}

// discoverNodes discovers Garage node IDs from running pods
func discoverNodes(ctx context.Context, pods []corev1.Pod, adminToken string, adminPort int32) []bootstrapNodeInfo {
	log := logf.FromContext(ctx)
	nodes := make([]bootstrapNodeInfo, 0, len(pods))

	for _, pod := range pods {
		endpoint := adminEndpoint(pod.Status.PodIP, adminPort)
		garageClient := garage.NewClient(endpoint, adminToken)

		// Bound each probe so one hung pod can't pin the single-worker reconciler
		// for the full 90s client timeout (mirrors connectToRemoteCluster).
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		status, err := garageClient.GetClusterStatus(cctx)
		cancel()
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
			id:         foundNode.ID,
			podIP:      pod.Status.PodIP,
			podName:    pod.Name,
			adminToken: adminToken,
			tier:       pod.Labels[labelTier],
		})
	}
	return nodes
}

func (r *GarageClusterReconciler) discoverNodesWithMountedStaticCredentials(
	ctx context.Context,
	pods []corev1.Pod,
	adminPort int32,
) []bootstrapNodeInfo {
	log := logf.FromContext(ctx)
	nodes := make([]bootstrapNodeInfo, 0, len(pods))
	for i := range pods {
		token, err := mountedStaticAdminToken(ctx, r.safetyReader(), &pods[i])
		if err != nil {
			log.V(1).Info("Could not resolve exact Pod startup Admin token", "pod", pods[i].Name, "error", err)
			continue
		}
		nodes = append(nodes, discoverNodes(ctx, []corev1.Pod{pods[i]}, token, adminPort)...)
	}
	return nodes
}

// findReachableClient finds the first reachable admin endpoint
func findReachableClient(ctx context.Context, nodes []bootstrapNodeInfo, adminToken string, adminPort int32) *garage.Client {
	for _, node := range nodes {
		endpoint := adminEndpoint(node.podIP, adminPort)
		token := node.adminToken
		if token == "" {
			token = adminToken
		}
		garageClient := garage.NewClient(endpoint, token)
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := garageClient.GetClusterHealth(cctx)
		cancel()
		if err == nil {
			return garageClient
		}
	}
	return nil
}

func (r *GarageClusterReconciler) healthStatusGarageClient(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	adminPort int32,
) *garage.Client {
	log := logf.FromContext(ctx)
	if token, ready, err := getReadyOperatorAdminToken(ctx, r.Client, cluster); err != nil {
		log.V(1).Info("Universally verified operator Admin token is temporarily unavailable for status", "error", err)
	} else if ready && token != "" {
		endpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, r.ClusterDomain)
		return garage.NewClient(endpoint, token)
	}

	pods := &corev1.PodList{}
	if err := r.safetyReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		log.V(1).Info("Could not list exact managed Pods for status", "error", err)
		return nil
	}
	running := make([]corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" && pod.DeletionTimestamp.IsZero() {
			running = append(running, *pod)
		}
	}
	nodes := r.discoverNodesWithMountedStaticCredentials(ctx, running, adminPort)
	return findReachableClient(ctx, nodes, "", adminPort)
}

// connectNodes connects all nodes together via RPC by having each node connect to all others
// This ensures that when a pod restarts with a new IP, all nodes learn about the new address
func connectNodes(ctx context.Context, nodes []bootstrapNodeInfo, adminToken string, adminPort, rpcPort int32) {
	log := logf.FromContext(ctx)
	// Have each node tell the cluster about all other nodes
	// This ensures IP address changes propagate to all nodes
	for _, sourceNode := range nodes {
		endpoint := adminEndpoint(sourceNode.podIP, adminPort)
		token := sourceNode.adminToken
		if token == "" {
			token = adminToken
		}
		nodeClient := garage.NewClient(endpoint, token)

		for _, targetNode := range nodes {
			if targetNode.id == sourceNode.id {
				continue // Skip self
			}
			addr := rpcAddr(targetNode.podIP, rpcPort)
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			result, err := nodeClient.ConnectNode(cctx, targetNode.id, addr)
			cancel()
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
func findStaleNodes(ctx context.Context, layout *garage.ClusterLayout, zone string, runningNodes map[string]bool, clusterUID string) []garage.NodeRoleChange {
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

		// Only a globally unique Kubernetes object UID is authoritative here.
		// Federated sites commonly reuse name, namespace, and even zone; the
		// historical cluster:<name>/<namespace> tag cannot prove which controller
		// owns a disconnected identity. Legacy roles without a UID are left for an
		// explicit drain after live roles have been retagged.
		if !nodeBelongsToClusterUID(role.Tags, clusterUID) {
			continue
		}

		log.Info("Found stale node in layout", "nodeId", shortID(role.ID), "zone", role.Zone, "tags", role.Tags)
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
	stagedNodes := make(map[string]garage.NodeRoleChange)
	for _, change := range layout.StagedRoleChanges {
		if !change.Remove {
			stagedNodes[change.ID] = change
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
		zone = defaultZoneName
	}

	// Find new nodes to add and detect config drift on existing nodes
	newRoles := make([]garage.NodeRoleChange, 0, len(nodes))
	resumedRoles := make([]garage.NodeRoleChange, 0, len(nodes))
	driftRoles := make([]garage.NodeRoleChange, 0)
	for _, node := range nodes {
		// Build desired tags for this node
		desiredTags := buildNodeTags(cfg.clusterName, cfg.namespace, node.tier, cfg.tags, node.podName, cfg.clusterUID)
		// Capacity is per-tier: storage pods own real data, gateways do not.
		// The cluster-wide cfg.isGateway flag is only correct for pure gateway-only
		// clusters; for unified storage+gateway CRs we must look at each pod's tier
		// so gateway pods never enter storage_sets with phantom capacity.
		var desiredCapacity *uint64
		if node.tier == tierStorage || (node.tier == "" && !cfg.isGateway) {
			cap := effectiveCapacity
			desiredCapacity = &cap
		}

		desiredRole := garage.NodeRoleChange{
			ID:       node.id,
			Zone:     zone,
			Tags:     desiredTags,
			Capacity: desiredCapacity,
		}

		// Check if node already exists in layout
		existingRole, exists := existingRoles[node.id]
		if exists {
			// Check for config drift
			legacyUIDOnly := existingRole.Zone == zone &&
				sameRoleCapacity(existingRole.Capacity, desiredCapacity) &&
				legacyRoleOnlyMissingClusterUID(existingRole.Tags, desiredTags, cfg.clusterUID)
			if detectNodeConfigDrift(existingRole, zone, desiredTags, desiredCapacity) && !legacyUIDOnly {
				log.Info("Config drift detected on node, updating",
					"nodeId", node.id[:16],
					"podName", node.podName,
					"existingZone", existingRole.Zone,
					"desiredZone", zone,
					"existingTags", existingRole.Tags,
					"desiredTags", desiredTags)
				driftRoles = append(driftRoles, desiredRole)
			} else {
				log.V(1).Info("Node already in layout with correct config", "nodeId", node.id, "podName", node.podName)
			}
			continue
		}

		// Check if already staged
		if staged, stagedAlready := stagedNodes[node.id]; stagedAlready {
			if !sameStagedRoleChange(staged, desiredRole) {
				return fmt.Errorf("%w: staged bootstrap role for node %s does not match the current discovered identity", errLayoutMutationPending, shortID(node.id))
			}
			log.V(1).Info("Node already staged", "nodeId", node.id, "podName", node.podName)
			resumedRoles = append(resumedRoles, desiredRole)
			continue
		}

		// New node - add to layout
		newRoles = append(newRoles, desiredRole)
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
		staleRoles = findStaleNodes(ctx, layout, zone, runningNodes, cfg.clusterUID)
	}

	// Combine all changes: new nodes, drift fixes, and stale node removals
	allChanges := make([]garage.NodeRoleChange, 0, len(newRoles)+len(driftRoles)+len(staleRoles))
	allChanges = append(allChanges, newRoles...)
	allChanges = append(allChanges, driftRoles...)
	allChanges = append(allChanges, staleRoles...)
	intendedChanges := make([]garage.NodeRoleChange, 0, len(resumedRoles)+len(allChanges))
	intendedChanges = append(intendedChanges, resumedRoles...)
	intendedChanges = append(intendedChanges, allChanges...)
	var desiredParameters *garage.LayoutParameters
	if cfg.zoneRedundancy != nil {
		desiredParameters = &garage.LayoutParameters{ZoneRedundancy: cfg.zoneRedundancy}
	}

	if len(intendedChanges) == 0 && desiredParameters == nil &&
		len(layout.StagedRoleChanges) == 0 && layout.StagedParameters == nil {
		log.V(1).Info("No staged layout changes to apply")
		return nil
	}

	// Stage changes if any.
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

	}
	deferred := false
	_, err = stageAndApplyExclusiveLayoutWithCheck(
		ctx, garageClient, layout, intendedChanges, desiredParameters,
		func() error {
			if len(allChanges) == 0 && desiredParameters == nil {
				return nil
			}
			if desiredParameters != nil {
				log.V(1).Info("Including zone redundancy in layout update", "zoneRedundancy", cfg.zoneRedundancy)
			}
			if err := garageClient.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{
				Roles: allChanges, Parameters: desiredParameters,
			}); err != nil {
				return fmt.Errorf("failed to update cluster layout: %w", err)
			}
			return nil
		},
		func(staged *garage.ClusterLayout) error {
			totalNodesAfterApply := countTotalNodesAfterApply(staged)
			if cfg.replicationFactor > 0 && totalNodesAfterApply < cfg.replicationFactor &&
				!cfg.hasRemoteClusters && !cfg.forceLayoutApply {
				deferred = true
				log.Info("Waiting for more nodes before applying layout",
					"currentNodes", totalNodesAfterApply,
					"replicationFactor", cfg.replicationFactor,
					"stagedCount", len(staged.StagedRoleChanges))
				return errLayoutMutationPending
			}
			if cfg.hasRemoteClusters && totalNodesAfterApply < cfg.replicationFactor {
				log.Info("Applying layout despite insufficient nodes (remoteClusters configured, federation will bring more)",
					"currentNodes", totalNodesAfterApply,
					"replicationFactor", cfg.replicationFactor)
			}
			log.Info("Applying exclusively owned staged layout changes",
				"stagedCount", len(staged.StagedRoleChanges), "totalNodes", totalNodesAfterApply, "currentVersion", staged.Version)
			return nil
		},
	)
	if deferred {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to apply cluster layout: %w", err)
	}
	log.Info("Applied cluster layout")
	return nil
}

// bootstrapCluster handles initial cluster formation by connecting nodes via the
// Admin API and, for clusters whose layout the cluster controller owns
// (gateway-only and Auto-mode pre-#190), assigning new nodes to the layout.
//
// Scope:
//   - Reconnect half (discover pods, call ConnectClusterNodes when peers are
//     down) runs for every locally managed topology, including Auto storage,
//     Manual/SMB GarageNodes, and named node-local pools. This gives us a runtime
//     nudge after pod changes when the on-disk peer_list cache has stale IPs and
//     bootstrap_peers can't reach known nodes yet.
//   - Layout-assignment half runs only when the cluster controller still owns
//     the layout — i.e. NOT for storage-tier clusters, which now have per-node
//     GarageNode reconcilers managing their own layout entries.
func (r *GarageClusterReconciler) bootstrapCluster(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		log.V(1).Info("Admin API not configured, skipping bootstrap")
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

	nodes := r.discoverNodesWithMountedStaticCredentials(ctx, runningPods, adminPort)
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

	bootstrapClient := findReachableClient(ctx, nodes, "", adminPort)
	if bootstrapClient == nil {
		return fmt.Errorf("no reachable admin endpoint found")
	}

	// Check cluster health - if all nodes are already connected, skip connect step
	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	health, err := bootstrapClient.GetClusterHealth(healthCtx)
	healthCancel()
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
	// Reconnect when:
	//   - Health probe failed entirely
	//   - Some local nodes are disconnected (the actual #203 trigger)
	//   - Storage-only cluster shows non-healthy AND we have no remote
	//     clusters configured. In federated setups the local view is
	//     permanently "unavailable" until remote peers join, so the
	//     health-status trigger here would otherwise call ConnectClusterNodes
	//     on every reconcile against an already-converged local quorum.
	needsReconnect := health == nil ||
		connectedNodes < len(nodes) ||
		(!cluster.HasGatewayTier() && healthStatus != healthStatusHealthy && len(cluster.Spec.RemoteClusters) == 0)
	if needsReconnect {
		log.Info("Cluster needs node reconnection", "connected", connectedNodes, "expected", len(nodes), "status", healthStatus)
		connectNodes(ctx, nodes, "", adminPort, rpcPort)
	}

	// Storage-tier clusters delegate layout management to the per-GarageNode
	// reconciler — adding storage pods to the layout here would race with that
	// controller (and overwrite per-node zone/tag overrides). Stop after the
	// reconnect nudge.
	if garageNodesOwnStorageLayout(cluster) {
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
		clusterUID:     string(cluster.UID),
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

	return runResolvedLayoutMutation(ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster, layoutClient, func() error {
		return assignNewNodesToLayout(ctx, layoutClient, nodes, cfg)
	})
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

	// Resolve through the shared helper rather than assuming clusterRef names a
	// locally managed Service. A connection-only management handle is the
	// canonical durable owner for multiple local edge CRs sharing one external
	// Garage layout.
	client, err := GetGarageClient(ctx, r.Client, storageCluster, r.ClusterDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve storage cluster admin client: %w", err)
	}

	// Verify the client can actually reach the storage cluster.
	// This prevents adding gateway nodes to an isolated layout when the storage cluster isn't ready.
	// This is a transient condition - the gateway will be added on the next reconcile when
	// the storage cluster becomes reachable.
	if _, err := client.GetClusterStatus(ctx); err != nil {
		return nil, fmt.Errorf("storage cluster not reachable (will retry): %w", err)
	}

	return client, nil
}

func (r *GarageClusterReconciler) reachableAdminClientWithMountedStaticCredentials(
	ctx context.Context,
	pods []corev1.Pod,
	adminPort int32,
) *garage.Client {
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" || !pod.DeletionTimestamp.IsZero() {
			continue
		}
		token, err := mountedStaticAdminToken(ctx, r.safetyReader(), pod)
		if err != nil {
			continue
		}
		c := garage.NewClient(adminEndpoint(pod.Status.PodIP, adminPort), token)
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = c.GetClusterStatus(probeCtx)
		cancel()
		if err == nil {
			return c
		}
	}
	return nil
}

// reconcileGatewayConnection connects a gateway cluster to its storage cluster.
// It discovers the storage cluster's nodes and connects the gateway nodes to them.
// Errors are logged but not returned to avoid blocking reconciliation.
func (r *GarageClusterReconciler) reconcileGatewayConnection(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)

	if !cluster.HasGatewayTier() || cluster.Spec.ConnectTo == nil {
		return
	}

	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
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

	gatewayClient := r.reachableAdminClientWithMountedStaticCredentials(ctx, pods.Items, adminPort)
	if gatewayClient == nil {
		log.V(1).Info("No reachable gateway pods for connection")
		return
	}

	// Connect based on configuration
	if cluster.Spec.ConnectTo.ClusterRef != nil {
		// Skip the full bidirectional connect loop when already converged — same
		// isUp short-circuit the AdminAPIEndpoint branch uses. Without this the
		// clusterRef path re-runs the O(storage×gateway) connect every reconcile
		// (every ~10s for a storage-less gateway), churning the Admin API.
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionGatewayConnected)
		if cond != nil && cond.Status == metav1.ConditionTrue && r.isClusterRefGatewayConnected(ctx, cluster, gatewayClient) {
			return
		}
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
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := gatewayClient.ConnectNode(cctx, nodeID, address)
			cancel()
			if err != nil {
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
	// Forward-only edge gateway (#243): the external cluster has no address to dial
	// the gateway on, so it will never report the gateway as isUp. Probing for reverse
	// reachability here would always fail and re-drive the full connect loop every
	// reconcile (re-staging layout churn under autoApply). The forward connection is
	// the only one that exists or matters for a dataless gateway — treat it as
	// converged so the reconcile backs off to the long requeue.
	if edgeGatewayReverseUnroutable(cluster) {
		return true
	}
	externalClient, err := r.getExternalStorageClient(ctx, cluster)
	if err != nil {
		return false
	}
	return gatewayPeersUp(ctx, gatewayClient, externalClient)
}

// isClusterRefGatewayConnected is the clusterRef counterpart of
// isExternalGatewayConnected: a cheap "already connected" probe so the
// clusterRef path can skip the full bidirectional connect loop when every
// gateway node is already is_up in the storage cluster's view.
func (r *GarageClusterReconciler) isClusterRefGatewayConnected(ctx context.Context, cluster *garagev1beta2.GarageCluster, gatewayClient *garage.Client) bool {
	storageClient, err := r.getStorageClusterClient(ctx, cluster)
	if err != nil {
		return false
	}
	return gatewayPeersUp(ctx, gatewayClient, storageClient)
}

// gatewayPeersUp reports whether every gateway node appears is_up in the storage
// cluster's view. Both status calls are deadline-bounded so the probe can't pin
// the reconcile worker on the 90s client timeout.
func gatewayPeersUp(ctx context.Context, gatewayClient, storageClient *garage.Client) bool {
	gwCtx, gwCancel := context.WithTimeout(ctx, 5*time.Second)
	gatewayStatus, err := gatewayClient.GetClusterStatus(gwCtx)
	gwCancel()
	if err != nil || len(gatewayStatus.Nodes) == 0 {
		return false
	}
	stCtx, stCancel := context.WithTimeout(ctx, 5*time.Second)
	storageStatus, err := storageClient.GetClusterStatus(stCtx)
	stCancel()
	if err != nil {
		return false
	}
	upInStorage := make(map[string]bool, len(storageStatus.Nodes))
	for _, n := range storageStatus.Nodes {
		if n.IsUp {
			upInStorage[n.ID] = true
		}
	}
	for _, n := range gatewayStatus.Nodes {
		if !upInStorage[n.ID] {
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
	storageRefName := cluster.Spec.ConnectTo.ClusterRef.Name

	// clusterRef may name either a managed storage GarageCluster or a
	// connection-only management handle for an external Garage. The shared
	// resolver gives both shapes one canonical Admin client and layout key.
	storageClient, err := r.getStorageClusterClient(ctx, cluster)
	if err != nil {
		log.V(1).Info("Referenced storage cluster is not reachable", "error", err)
		return
	}

	// Get storage cluster status to discover nodes. Every Admin call below is
	// wrapped in a short per-call deadline so one hung peer can't pin the
	// reconcile worker on the 90s client timeout (mirrors the federation path).
	statusCtx, statusCancel := context.WithTimeout(ctx, 5*time.Second)
	storageStatus, err := storageClient.GetClusterStatus(statusCtx)
	statusCancel()
	if err != nil {
		log.V(1).Info("Failed to get storage cluster status", "error", err)
		return
	}

	// Connect gateway to each storage node (gateway → storage)
	connectedToStorage := 0
	for _, node := range storageStatus.Nodes {
		if node.Address != nil && *node.Address != "" {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, cerr := gatewayClient.ConnectNode(cctx, node.ID, *node.Address)
			cancel()
			if cerr != nil {
				log.V(1).Info("Failed to connect gateway to storage node", "nodeID", shortID(node.ID), "address", *node.Address, "error", cerr)
			} else {
				connectedToStorage++
			}
		}
	}

	// Get gateway cluster status to discover gateway nodes
	gwStatusCtx, gwStatusCancel := context.WithTimeout(ctx, 5*time.Second)
	gatewayStatus, err := gatewayClient.GetClusterStatus(gwStatusCtx)
	gwStatusCancel()
	if err != nil {
		log.V(1).Info("Failed to get gateway cluster status", "error", err)
		// Still log partial success if we connected gateway → storage
		if connectedToStorage > 0 {
			log.Info("Gateway connected to storage cluster (one-way)", "storageCluster", storageRefName, "nodesConnected", connectedToStorage)
		}
		return
	}

	// Connect storage to each gateway node (storage → gateway)
	// This ensures bidirectional connectivity, especially after gateway pod restarts
	// where the gateway has a new IP that the storage cluster doesn't know about.
	connectedToGateway := 0
	for _, node := range gatewayStatus.Nodes {
		if node.Address != nil && *node.Address != "" {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, cerr := storageClient.ConnectNode(cctx, node.ID, *node.Address)
			cancel()
			if cerr != nil {
				log.V(1).Info("Failed to connect storage to gateway node", "nodeID", shortID(node.ID), "address", *node.Address, "error", cerr)
			} else {
				connectedToGateway++
			}
		}
	}

	// Record connectivity so the next reconcile can short-circuit when converged.
	switch {
	case connectedToStorage > 0 && connectedToGateway > 0:
		log.Info("Gateway-storage bidirectional connection established",
			"storageCluster", storageRefName,
			"gatewayToStorage", connectedToStorage,
			"storageToGateway", connectedToGateway)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonGatewayConnected,
			Message:            fmt.Sprintf("bidirectional RPC established with storage cluster %s (%d→storage, %d→gateway)", storageRefName, connectedToStorage, connectedToGateway),
			ObservedGeneration: cluster.Generation,
		})
	case connectedToStorage > 0 || connectedToGateway > 0:
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayPartiallyConnected,
			Message:            fmt.Sprintf("only one direction connected to storage cluster %s (%d→storage, %d→gateway); retrying", storageRefName, connectedToStorage, connectedToGateway),
			ObservedGeneration: cluster.Generation,
		})
	default:
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayNodesOffline,
			Message:            fmt.Sprintf("no RPC connectivity established with storage cluster %s; retrying", storageRefName),
			ObservedGeneration: cluster.Generation,
		})
	}
}

// deriveGatewayExternalAddr returns the externally-routable RPC address for this gateway cluster
// as known to the operator (from publicEndpoint service status or nodePort config).
// Returns empty when the address cannot be determined — the caller should then trust whatever
// Garage itself reports. When network.rpcPublicAddr is set, Garage already advertises the correct
// address via HelloMessage, so no override is needed.
func (r *GarageClusterReconciler) deriveGatewayExternalAddr(ctx context.Context, cluster *garagev1beta2.GarageCluster) string {
	// The gateway tier's own rpcPublicAddr is the documented "preferred" address
	// for the reverse ConnectNode (external storage → gateway); honor it first so
	// the storage cluster dials a routable address rather than the pod IP.
	if cluster.Spec.Gateway != nil && cluster.Spec.Gateway.RPCPublicAddr != "" {
		return cluster.Spec.Gateway.RPCPublicAddr
	}
	if cluster.Spec.Network.RPCPublicAddr != "" {
		// Garage advertises rpcPublicAddr via HelloMessage to peers, but GetClusterStatus
		// returns an empty address for the local node itself. Return it directly so the
		// operator can pass it to the external cluster's ConnectNode call.
		return cluster.Spec.Network.RPCPublicAddr
	}
	if cluster.Spec.PublicEndpoint == nil {
		return ""
	}

	rpcPort := getRPCPort(cluster)

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
	if cluster.Spec.PublicEndpoint == nil ||
		cluster.Spec.PublicEndpoint.Type != publicEndpointTypeLoadBalancer ||
		cluster.Spec.PublicEndpoint.LoadBalancer == nil ||
		!cluster.Spec.PublicEndpoint.LoadBalancer.PerNode {
		return r.deriveGatewayExternalAddr(ctx, cluster)
	}

	rpcPort := getRPCPort(cluster)

	if node.Hostname != nil {
		if ordinal, ok := gatewayPodOrdinal(cluster, *node.Hostname); ok {
			return r.loadBalancerServiceAddr(
				ctx,
				cluster.Namespace,
				perNodeRPCServiceName(cluster.Name, ordinal),
				rpcPort,
			)
		}
	}
	return r.loadBalancerServiceAddr(ctx, cluster.Namespace, cluster.Name+"-0-rpc", rpcPort)
}

// gatewayPodOrdinal maps both the current edge-gateway StatefulSet hostname
// (<cluster>-gateway-<ordinal>) and the pre-StatefulSet/legacy hostname shape
// (<cluster>-<ordinal>) onto the stable public Service name
// (<cluster>-<ordinal>-rpc). Matching relative to the known workload names
// avoids treating an arbitrary hostname suffix as one of this cluster's pods.
func gatewayPodOrdinal(cluster *garagev1beta2.GarageCluster, hostname string) (int32, bool) {
	if cluster == nil || hostname == "" {
		return 0, false
	}
	for _, prefix := range []string{gatewayWorkloadName(cluster) + "-", cluster.Name + "-"} {
		if !strings.HasPrefix(hostname, prefix) {
			continue
		}
		raw := strings.TrimPrefix(hostname, prefix)
		ordinal, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || ordinal < 0 {
			return 0, false
		}
		return int32(ordinal), true
	}
	return 0, false
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
	rpcPort := getRPCPort(cluster)
	return rpcAddr(u.Hostname(), rpcPort)
}

// edgeGatewayReverseUnroutable reports whether an edge gateway (gateway tier +
// connectTo, no local storage) has no externally-routable RPC address the external
// cluster could ever dial back on — none of spec.gateway.rpcPublicAddr,
// spec.network.rpcPublicAddr, or spec.publicEndpoint is set. This is the bare
// Docker/TrueNAS/NAT topology in #243: the gateway runs inside Kubernetes, the
// external Garage lives outside, and the gateway's pod IP is genuinely not reachable
// from there. The reverse ConnectNode therefore can't succeed and never will —
// retrying it forever (and re-staging layout churn under autoApply) is pointless.
//
// This mirrors the admission webhook predicate that already warns on this exact
// topology (validateRPCPublicAddr): the maintainer treats it as legitimate-but-
// degraded, not invalid, so the runtime must not report it as a hard failure.
func edgeGatewayReverseUnroutable(cluster *garagev1beta2.GarageCluster) bool {
	return cluster.HasGatewayTier() && !cluster.HasStorageTier() &&
		cluster.Spec.ConnectTo != nil &&
		(cluster.Spec.Gateway == nil || cluster.Spec.Gateway.RPCPublicAddr == "") &&
		cluster.Spec.Network.RPCPublicAddr == "" &&
		cluster.Spec.PublicEndpoint == nil
}

// gatewayConnectedCondition decides the GatewayConnected condition from the two
// connection counts. Pulled out as a pure function so the #243 forward-only case is
// unit-testable without a live cluster.
//
//   - reverse established (connectedToGateway > 0): bidirectional, Connected.
//   - forward only AND reverse is genuinely unroutable (bare edge gateway, no
//     rpcPublicAddr/publicEndpoint): a gateway carries no data, so this is a healthy
//     steady state — report Connected with the ForwardOnly reason so the reconcile
//     loop converges instead of re-running connect (and churning layout) forever.
//   - forward only with a routable address configured but reverse still failing: a
//     real misconfiguration — keep PartiallyConnected so it surfaces and retries.
//   - neither direction: NodesOffline.
func gatewayConnectedCondition(cluster *garagev1beta2.GarageCluster, connectedToExternal, connectedToGateway int) metav1.Condition {
	switch {
	case connectedToGateway > 0:
		return metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonGatewayConnected,
			Message:            fmt.Sprintf("Bidirectional connection established (%d gateway→external, %d external→gateway)", connectedToExternal, connectedToGateway),
			ObservedGeneration: cluster.Generation,
		}
	case connectedToExternal > 0 && edgeGatewayReverseUnroutable(cluster):
		return metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonGatewayForwardOnly,
			Message:            fmt.Sprintf("Gateway connected to external cluster (%d gateway→external); reverse connection not configured (no rpcPublicAddr/publicEndpoint). A gateway holds no data, so forward-only is sufficient — set spec.gateway.rpcPublicAddr to make the gateway visible in the external cluster's node list", connectedToExternal),
			ObservedGeneration: cluster.Generation,
		}
	case connectedToExternal > 0:
		return metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayPartiallyConnected,
			Message:            "Gateway can reach external cluster but external cluster cannot reach gateway — check publicEndpoint or network.rpcPublicAddr",
			ObservedGeneration: cluster.Generation,
		}
	default:
		return metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayConnected,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayNodesOffline,
			Message:            "No nodes connected between gateway and external cluster",
			ObservedGeneration: cluster.Generation,
		}
	}
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

	meta.SetStatusCondition(&cluster.Status.Conditions,
		gatewayConnectedCondition(cluster, connectedToExternal, connectedToGateway))
}

// reconcileFederation connects this cluster to remote Garage clusters.
// It queries remote Admin APIs to discover node IDs and connects them.
// Errors are logged but not returned to avoid blocking reconciliation.
func (r *GarageClusterReconciler) reconcileFederation(ctx context.Context, cluster *garagev1beta2.GarageCluster) {
	log := logf.FromContext(ctx)

	if len(cluster.Spec.RemoteClusters) == 0 {
		return
	}

	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
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
			adminToken, tokenErr := mountedStaticAdminToken(ctx, r.safetyReader(), &pod)
			if tokenErr != nil {
				log.V(1).Info("Could not resolve exact local Pod Admin token for federation", "pod", pod.Name, "error", tokenErr)
				continue
			}
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
	// the same cluster listed in remoteClusters (common in templated deployments).
	// Compare against the EFFECTIVE local zone (localGatewayZone applies the same
	// empty->"default" fallback used when stamping local roles), so an empty
	// spec.zone cluster still recognizes a remote configured zone:"default" as
	// self — otherwise its imported capacity:null roles would land in the local
	// zone where the gateway reaper could mistake them for orphans (#224).
	if remote.Zone == localGatewayZone(cluster) {
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
	} else if needsConnect {
		// A routed DaemonSet Pod IP can change while this region is disconnected.
		// The local layout then carries the old rpc-address tag, but the remote
		// region's reachable Admin API has the replacement address committed in
		// its layout. Refresh role metadata before dialing so the stale address
		// cannot make a normal pod roll permanently unrecoverable.
		remoteClient = garage.NewClient(remoteEndpoint, remoteToken)
		refreshCtx, refreshCancel := context.WithTimeout(ctx, 5*time.Second)
		remoteLayout, refreshErr := remoteClient.GetClusterLayout(refreshCtx)
		refreshCancel()
		if refreshErr != nil {
			log.V(1).Info("Could not refresh remote layout metadata before reconnect; using locally replicated roles",
				"cluster", remote.Name, "error", refreshErr)
		} else {
			remoteNodes = mergeRemoteLayoutRoles(remoteNodes, remoteLayout)
		}
	}

	// Determine the effective RPC listener port.
	rpcPort := getRPCPort(cluster)

	// Connect to each node in the remote cluster unless all are already up.
	// Note: We connect to ALL nodes, including those without a role.
	// During bootstrap, nodes may not be in the layout yet but we still
	// need to establish connections so they can be discovered and added.
	connectedCount := 0
	if needsConnect {
		for _, node := range remoteNodes {
			// Garage authenticates the expected node ID during the RPC handshake. A
			// shared L4 Service cannot route by that identity and may select a
			// different pod, which then correctly fails authentication. Prefer the
			// node-specific address replicated in its layout tags. The shared admin
			// hostname remains a compatibility/bootstrap fallback for old nodes.
			addr, addressSource := remoteNodeRPCAddress(node, remoteRPCHost, rpcPort)
			if addr == "" {
				log.V(1).Info("Remote node has no address", "nodeID", node.ID[:16]+"...")
				continue
			}

			log.V(1).Info("Connecting to remote node", "nodeID", node.ID[:16]+"...", "addr", addr, "addressSource", addressSource)

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
	// parsed from its pod-name layout tag (e.g. "<cluster>-gateway-1-0" -> 1).
	if tmpl := remote.Connection.GatewayRPCEndpointTemplate; tmpl != "" {
		r.connectRemoteGatewayPods(ctx, localClient, localStatus, remote, tmpl)
	}

	// Same per-pod problem for a multi-pod remote storage tier behind a shared
	// admin hostname: dial each remote storage pod by its ordinal-stable address.
	if tmpl := remote.Connection.StorageRPCEndpointTemplate; tmpl != "" {
		r.connectRemoteStoragePods(ctx, localClient, localStatus, remote, tmpl)
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

// mergeRemoteLayoutRoles overlays freshly fetched remote role metadata onto
// the locally known NodeInfo list without changing liveness or peer-address
// observations. In particular, this refreshes an operator-owned rpc-address
// tag after a DaemonSet Pod IP changes while the regions are disconnected.
func mergeRemoteLayoutRoles(nodes []garage.NodeInfo, layout *garage.ClusterLayout) []garage.NodeInfo {
	if layout == nil || len(layout.Roles) == 0 {
		return nodes
	}
	roles := make(map[string]garage.LayoutNodeRole, len(layout.Roles))
	for i := range layout.Roles {
		roles[layout.Roles[i].ID] = layout.Roles[i]
	}
	merged := append([]garage.NodeInfo(nil), nodes...)
	for i := range merged {
		role, ok := roles[merged[i].ID]
		if !ok {
			continue
		}
		merged[i].Role = &garage.NodeAssignedRole{
			Zone:     role.Zone,
			Tags:     append([]string(nil), role.Tags...),
			Capacity: role.Capacity,
		}
	}
	return merged
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
		for _, tag := range node.Role.Tags {
			if tag == "tier:"+tierGateway {
				isGateway = true
				break
			}
		}
		if !isGateway {
			continue
		}
		if node.IsUp {
			continue
		}
		// Derive the gateway pod ordinal from the node's own pod-name layout tag.
		// Operator-managed gateways tag each pod "<cluster>-gateway-<N>-<stsOrdinal>"
		// (buildAutoModeGatewayNode); the cluster name comes from the same node's
		// "cluster:<name>/<ns>" ownership tag, NOT remote.Name (a friendly label).
		ordinalStr, ok := parseRemoteGatewayOrdinal(node.Role.Tags)
		if !ok {
			log.V(1).Info("Skipping remote gateway: could not parse pod ordinal from tags", "tags", node.Role.Tags)
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
			"nodeID", node.ID[:16]+"...", "addr", addr, "ordinal", ordinalStr)
	}
}

// connectRemoteStoragePods peers the local cluster with each STORAGE pod in a
// remote region, mirroring connectRemoteGatewayPods. The default storage↔storage
// connect loop dials every remote node at one shared admin hostname, which lands
// only one pod when a region runs multiple storage pods behind a Tailscale-style
// VIP — the rest stay "Not connected", so any partition replica on them can't
// reach quorum cross-region. StorageRPCEndpointTemplate dials each remote storage
// pod by its ordinal-stable external address (paired with that region's
// spec.storage.rpcPublicAddr {ordinal} advertise side). Best-effort; errors are
// logged and skipped.
func (r *GarageClusterReconciler) connectRemoteStoragePods(
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
		log.Info("storageRpcEndpointTemplate missing {ordinal} placeholder — all remote storage pods will share the same address",
			"remote", remote.Name, "template", template)
	}

	for _, node := range localStatus.Nodes {
		if node.Role == nil || node.Role.Zone != remote.Zone {
			continue
		}
		isStorage := false
		for _, tag := range node.Role.Tags {
			if tag == "tier:"+tierStorage {
				isStorage = true
				break
			}
		}
		if !isStorage {
			continue
		}
		if node.IsUp {
			continue
		}
		ordinalStr, ok := parseRemotePodOrdinal(node.Role.Tags, tierStorage)
		if !ok {
			log.V(1).Info("Skipping remote storage: could not parse pod ordinal from tags", "tags", node.Role.Tags)
			continue
		}
		addr := strings.ReplaceAll(template, "{ordinal}", ordinalStr)

		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		result, err := localClient.ConnectNode(connectCtx, node.ID, addr)
		cancel()
		if err != nil {
			log.V(1).Info("Failed to connect remote storage pod",
				"nodeID", node.ID[:16]+"...", "addr", addr, "error", err)
			continue
		}
		if !result.Success {
			errMsg := connectErrUnknown
			if result.Error != nil {
				errMsg = *result.Error
			}
			log.V(1).Info("ConnectNode returned failure for remote storage pod",
				"nodeID", node.ID[:16]+"...", "addr", addr, "error", errMsg)
			continue
		}
		log.Info("Connected to remote storage pod",
			"nodeID", node.ID[:16]+"...", "addr", addr, "ordinal", ordinalStr)
	}
}

// parseRemoteGatewayOrdinal extracts a gateway pod's ordinal from its layout
// tags. Operator-managed gateway nodes carry two relevant tags:
//   - a cluster-ownership tag "cluster:<name>/<namespace>"
//   - a pod-name tag "<name>-gateway-<ordinal>-<stsOrdinal>"
//
// (see buildNodeTags / buildAutoModeGatewayNode). The cluster name may contain
// hyphens, so the prefix is derived from the ownership tag's name component
// rather than guessed. The trailing "-<stsOrdinal>" (always "-0", since each
// per-node StatefulSet has replicas:1) is stripped before parsing the ordinal.
// Returns the ordinal as a string (for {ordinal} substitution) and ok=false
// when no gateway pod-name tag matches.
func parseRemoteGatewayOrdinal(tags []string) (string, bool) {
	return parseRemotePodOrdinal(tags, tierGateway)
}

// parseRemotePodOrdinal extracts a pod's ordinal from its layout tags for the
// given tier ("gateway" or "storage"). Operator-managed nodes carry a
// cluster-ownership tag "cluster:<name>/<namespace>" and a pod-name tag
// "<name>-<tier>-<ordinal>-<stsOrdinal>" (see buildNodeTags /
// buildAutoMode{Gateway,Storage}Node). The cluster name may contain hyphens, so
// the prefix is derived from the ownership tag's name component rather than
// guessed. The trailing "-<stsOrdinal>" (always "-0", since each per-node
// StatefulSet has replicas:1) is stripped before parsing the ordinal. Returns
// ok=false when no matching pod-name tag is present.
func parseRemotePodOrdinal(tags []string, tier string) (string, bool) {
	var clusterName string
	for _, tag := range tags {
		if rest, found := strings.CutPrefix(tag, "cluster:"); found {
			if name, _, ok := strings.Cut(rest, "/"); ok && name != "" {
				clusterName = name
			}
		}
	}
	if clusterName == "" {
		return "", false
	}
	prefix := clusterName + "-" + tier + "-"
	for _, tag := range tags {
		rest, found := strings.CutPrefix(tag, prefix)
		if !found {
			continue
		}
		// rest is "<ordinal>-<stsOrdinal>"; strip the trailing STS-ordinal suffix.
		ordinalStr := rest
		if i := strings.LastIndex(rest, "-"); i >= 0 {
			ordinalStr = rest[:i]
		}
		if ordinalStr == "" {
			continue
		}
		if _, err := strconv.Atoi(ordinalStr); err != nil {
			continue
		}
		return ordinalStr, true
	}
	return "", false
}

// nodeRPCAddressTagPrefix marks operator-owned layout metadata carrying the
// effective, externally routable address of one identity-bearing Garage node.
const nodeRPCAddressTagPrefix = "rpc-address:"

const nodeRPCAddressSourceLayoutTag = "layout-tag"

// remoteNodeRPCAddress chooses a routable address for an identity-authenticated
// Garage RPC connection. Layout tags are the only node-specific address data
// available before a disconnected mesh has been bootstrapped: NodeInfo.Address
// is null for disconnected peers and is merely the observed socket address for
// connected peers, not necessarily their configured rpc_public_addr.
func remoteNodeRPCAddress(node garage.NodeInfo, sharedHost string, rpcPort int32) (string, string) {
	if node.Role != nil {
		for _, tag := range node.Role.Tags {
			if addr, found := strings.CutPrefix(tag, nodeRPCAddressTagPrefix); found && strings.TrimSpace(addr) != "" {
				return strings.TrimSpace(addr), nodeRPCAddressSourceLayoutTag
			}
		}
	}
	if sharedHost != "" {
		return rpcAddr(sharedHost, rpcPort), "shared-bootstrap"
	}
	if node.Address != nil && *node.Address != "" {
		return *node.Address, "observed-peer"
	}
	return "", ""
}

// remoteImportTags preserves the source site's role metadata verbatim. Garage
// layout/status is global after federation, and only the source Kubernetes site
// can authoritatively stamp its immutable cluster-uid ownership. Rewriting its
// cluster tag to a local friendly remote name creates competing controllers and
// makes later cleanup ambiguous. The tier fallback covers legacy untagged roles.
func remoteImportTags(remote garagev1beta2.RemoteClusterConfig, namespace string, capacity *uint64, sourceTags ...[]string) []string {
	_ = remote
	_ = namespace
	tier := tierGateway
	if capacity != nil {
		tier = tierStorage
	}
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	hasTier := false
	for _, source := range sourceTags {
		for _, tag := range source {
			if tag == "" {
				continue
			}
			if strings.HasPrefix(tag, "tier:") {
				hasTier = true
			}
			if _, exists := seen[tag]; exists {
				continue
			}
			tags = append(tags, tag)
			seen[tag] = struct{}{}
		}
	}
	if !hasTier {
		tags = append(tags, "tier:"+tier)
	}
	return tags
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
	return runResolvedLayoutMutation(ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster, localClient, func() error {
		return r.addRemoteNodesToLayoutLocked(ctx, cluster, localClient, remoteClient, remoteStatus, localStatus, remote)
	})
}

func (r *GarageClusterReconciler) addRemoteNodesToLayoutLocked(
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

	// Keep committed and staged identities separate. A staged role is not yet
	// part of the layout; it may be resumed only after proving it exactly matches
	// this remote import's current desired role.
	existingNodes := make(map[string]bool)
	for _, role := range layout.Roles {
		existingNodes[role.ID] = true
	}
	localStagedRoles := make(map[string]garage.NodeRoleChange)
	for _, staged := range layout.StagedRoleChanges {
		localStagedRoles[staged.ID] = staged
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
	localGarageNodes, err := r.liveGarageNodesByID(ctx, cluster)
	if err != nil {
		return fmt.Errorf("listing local GarageNodes before federated import: %w", err)
	}
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
	intendedRoles := make([]garage.NodeRoleChange, 0, len(nodesToProcess))
	for _, node := range nodesToProcess {
		// Once the RPC mesh connects, every site's Admin API reports the same
		// global node set. During replication-factor bootstrap the local role is
		// not committed yet, so existingNodes cannot identify it. Do not import
		// that exact local GarageNode through the remote site's zone/tag policy;
		// includeLocalGarageNodeStagingIntent proves and admits it below.
		if localGarageNodes[canonicalGarageNodeID(node.ID)] != nil {
			continue
		}
		if existingNodes[node.ID] {
			continue // Already in local layout
		}
		// Don't (re-)import a node the source reports as down. A node that was just
		// orphaned and removed from the layout still briefly appears here with its old
		// role until the removal propagates; re-importing it recreates the orphan — and,
		// because the import tags it, an orphan that later loses its claim lingers (#224).
		// A genuinely-down remote node is re-imported automatically once it reports up,
		// so a false skip is self-correcting (unlike a false import, which sticks).
		if !node.IsUp {
			log.V(1).Info("Skipping down remote node during import", "nodeId", shortID(node.ID))
			continue
		}

		var role garage.NodeRoleChange

		if node.Role != nil {
			// Node has a committed role - use it
			role = garage.NodeRoleChange{
				ID:       node.ID,
				Zone:     remote.Zone, // Use configured zone from CRD
				Tags:     remoteImportTags(remote, cluster.Namespace, node.Role.Capacity, node.Role.Tags),
				Capacity: node.Role.Capacity, // nil = gateway, non-nil = storage
			}
		} else if stagedRole, ok := remoteStagedRoles[node.ID]; ok {
			// Node doesn't have a committed role but IS in staged changes
			// This handles the bootstrap race condition where remote controller
			// has staged nodes but hasn't applied the layout yet
			log.V(1).Info("Using staged role for remote node", "nodeId", node.ID[:16]+"...", "zone", remote.Zone)
			role = garage.NodeRoleChange{
				ID:       node.ID,
				Zone:     remote.Zone, // Use configured zone from CRD
				Tags:     remoteImportTags(remote, cluster.Namespace, stagedRole.Capacity, stagedRole.Tags),
				Capacity: stagedRole.Capacity, // Use capacity from staged role
			}
		} else {
			// Node has no committed or staged role - skip it
			// It will be picked up on the next reconciliation after the remote
			// controller stages/commits its local nodes
			log.V(1).Info("Skipping remote node without committed or staged role", "nodeId", node.ID[:16]+"...")
			continue
		}

		if staged, ok := localStagedRoles[node.ID]; ok {
			if !sameStagedRoleChange(staged, role) {
				return fmt.Errorf("%w: staged federated role for node %s does not match remote %q's desired import", errLayoutMutationPending, shortID(node.ID), remote.Name)
			}
			intendedRoles = append(intendedRoles, role)
			continue
		}
		newRoles = append(newRoles, role)
		intendedRoles = append(intendedRoles, role)
	}

	if len(intendedRoles) == 0 {
		log.V(1).Info("All remote nodes already in layout", "cluster", remote.Name)
		return nil
	}

	// A local GarageNode can have staged its own role before federation discovers
	// enough remote capacity to satisfy the replication factor. Garage rejects
	// that first Apply, leaving the exact local assignment in its global staging
	// area. Prove and include those sibling assignments in this transaction so
	// the remote import can complete the bootstrap without treating a known
	// operator-owned change as an arbitrary external writer's mutation.
	intendedRoles, err = r.includeLocalGarageNodeStagingIntent(ctx, cluster, layout, intendedRoles)
	if err != nil {
		return err
	}

	// Stage changes with zone redundancy parameters from cluster spec
	log.Info("Adding remote nodes to layout", "cluster", remote.Name, "count", len(newRoles))

	// Build layout update request with zone redundancy if configured.
	layoutReq := garage.UpdateClusterLayoutRequest{
		Roles: newRoles,
	}

	// Include zone redundancy from cluster spec for consistency
	if zr := buildZoneRedundancy(cluster.Spec.Replication); zr != nil {
		layoutReq.Parameters = &garage.LayoutParameters{ZoneRedundancy: zr}
		log.V(1).Info("Including zone redundancy in layout update", "zoneRedundancy", zr)
	}

	if _, err := stageAndApplyExclusiveLayout(ctx, localClient, layout, intendedRoles, layoutReq.Parameters, func() error {
		if len(newRoles) == 0 && layoutReq.Parameters == nil {
			return nil
		}
		if err := localClient.UpdateClusterLayoutWithParams(ctx, layoutReq); err != nil {
			return fmt.Errorf("failed to stage remote nodes: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to apply exclusively owned federated layout: %w", err)
	}

	log.Info("Applied federated layout", "cluster", remote.Name, "nodesAdded", len(newRoles))
	return nil
}

// includeLocalGarageNodeStagingIntent admits only exact role assignments for
// live GarageNodes owned by this GarageCluster. Federation may need to commit
// such a role together with a newly imported remote role when the local role's
// earlier Apply failed solely because the remote capacity was not present yet.
// Removals, unknown identities, and drift remain outside this transaction.
func (r *GarageClusterReconciler) includeLocalGarageNodeStagingIntent(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	intended []garage.NodeRoleChange,
) ([]garage.NodeRoleChange, error) {
	if layout == nil || len(layout.StagedRoleChanges) == 0 {
		return intended, nil
	}

	seen := make(map[string]bool, len(intended))
	for i := range intended {
		seen[intended[i].ID] = true
	}

	byID, err := r.liveGarageNodesByID(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("listing GarageNodes to validate federated bootstrap staging: %w", err)
	}

	nodeReconciler := &GarageNodeReconciler{Client: r.Client, APIReader: r.APIReader}
	for i := range layout.StagedRoleChanges {
		staged := layout.StagedRoleChanges[i]
		if seen[staged.ID] {
			continue
		}
		node := byID[canonicalGarageNodeID(staged.ID)]
		if node == nil || staged.Remove {
			return nil, fmt.Errorf(
				"%w: staged node %s is not an assignable live GarageNode owned by this federated cluster",
				errLayoutMutationPending, shortID(staged.ID),
			)
		}
		expected, err := nodeReconciler.desiredGarageNodeRoleChange(ctx, node, cluster, staged.ID)
		if err != nil || !sameStagedRoleChange(staged, expected) {
			return nil, fmt.Errorf(
				"%w: staged role for GarageNode %s does not match its desired operator state during federated bootstrap",
				errLayoutMutationPending, node.Name,
			)
		}
		intended = append(intended, expected)
		seen[expected.ID] = true
	}
	return intended, nil
}

func (r *GarageClusterReconciler) liveGarageNodesByID(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]*garagev1beta1.GarageNode, error) {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.safetyReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, err
	}
	byID := make(map[string]*garagev1beta1.GarageNode)
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			!node.DeletionTimestamp.IsZero() {
			continue
		}
		id := canonicalGarageNodeID(node.Status.NodeID)
		if id == "" {
			id = canonicalGarageNodeID(node.Spec.NodeID)
		}
		if id != "" {
			byID[id] = node
		}
	}
	return byID, nil
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
	return GetStaticAdminToken(ctx, r.Client, cluster)
}

// getAdminToken resolves the established-process control credential. Direct
// calls to a specific Pod must instead use mountedStaticAdminToken so a fresh
// metadata DB and mixed immutable-snapshot rollout authenticate correctly.
func (r *GarageClusterReconciler) getAdminToken(ctx context.Context, cluster *garagev1beta2.GarageCluster) (string, error) {
	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return "", nil
	}
	return GetAdminToken(ctx, r.Client, cluster)
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
	// Rebalance, Aliases. "Scrub" is rejected — use scrub-command.
	// ClearResyncQueue first appeared in Garage v2.1, while this operator's
	// supported floor is v2.0; use retry-block-resync instead.
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
		} else if err := runResolvedLayoutAdministrativeMutation(
			ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster,
			func() error { return garageClient.RevertClusterLayout(ctx) },
		); err != nil {
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

		// Node IDs are 64 hex chars (32-byte Ed25519 key). Reject malformed
		// annotation input before logging/slicing it or sending it to the API —
		// a value shorter than 16 chars would otherwise panic on the [:16] slice
		// below and crash-loop the reconcile (the annotation is only removed on
		// success, so the bad value would be re-read every reconcile).
		if len(nodeID) != 64 {
			log.Info("Skipping connect-nodes entry with invalid node ID length",
				"connection", conn, "nodeIdLength", len(nodeID), "expectedLength", 64)
			continue
		}
		if _, err := hex.DecodeString(nodeID); err != nil {
			log.Info("Skipping connect-nodes entry with non-hex node ID", "connection", conn)
			continue
		}

		log.Info("Connecting to external node", "nodeID", shortID(nodeID), "addr", addr)
		result, err := garageClient.ConnectNode(ctx, nodeID, addr)
		if err != nil {
			log.Error(err, "Failed to connect to node", "nodeID", shortID(nodeID), "addr", addr)
			continue
		}

		if result.Success {
			log.Info("Successfully connected to external node", "nodeID", shortID(nodeID), "addr", addr)
		} else {
			errMsg := connectErrUnknown
			if result.Error != nil {
				errMsg = *result.Error
			}
			log.Info("Connection to external node failed", "nodeID", shortID(nodeID), "addr", addr, "error", errMsg)
		}
	}

	return nil
}

// handleSkipDeadNodes performs the explicitly requested cluster-wide Garage
// recovery operation. Upstream has no target list: every peer the serving node
// currently sees as down may be force-ACKed. allow-missing-data additionally
// force-syncs all lagging trackers, so administrators must assess the complete
// layout and not only the node that prompted recovery.
func (r *GarageClusterReconciler) handleSkipDeadNodes(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	log := logf.FromContext(ctx)

	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return fmt.Errorf("resolving Garage Admin client for explicit skip-dead-nodes recovery: %w", err)
	}

	return runResolvedExplicitDeadNodeRecoveryMutation(ctx, r.safetyReader(), r.layoutMutationCoordinator(), cluster, func() error {
		// Get the version only after exclusivity is held. A Stage/Apply racing this
		// read could otherwise make skip target the wrong history version.
		layout, err := garageClient.GetClusterLayout(ctx)
		if err != nil {
			return fmt.Errorf("failed to get cluster layout: %w", err)
		}

		allowMissingData := false
		if val, ok := cluster.Annotations[garagev1beta1.AnnotationAllowMissingData]; ok && val == annotationTrue {
			allowMissingData = true
			log.Info("Explicit allow-missing-data is set; Garage may force-sync every lagging tracker in this layout version")
		}
		result, err := garageClient.ClusterLayoutSkipDeadNodes(ctx, garage.SkipDeadNodesRequest{
			Version: layout.Version, AllowMissingData: allowMissingData,
		})
		if err != nil {
			if garage.IsBadRequest(err) {
				log.Info("Skip-dead-nodes: no draining versions to process (single layout version)")
				return nil
			}
			return fmt.Errorf("failed to skip dead nodes: %w", err)
		}
		log.Info("Explicit cluster-wide skip-dead-nodes recovery completed",
			"ackUpdated", len(result.AckUpdated), "syncUpdated", len(result.SyncUpdated), "version", layout.Version)
		return nil
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *GarageClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	secretSourceMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}
		clusters := &garagev1beta2.GarageClusterList{}
		if err := r.List(ctx, clusters, client.InNamespace(secret.Namespace)); err != nil {
			return nil
		}
		var requests []reconcile.Request
		for i := range clusters.Items {
			cluster := &clusters.Items[i]
			references := garageClusterReferencesSecretName(cluster, secret.Name)
			if !references && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
				ref := cluster.Spec.ConnectTo.ClusterRef
				namespace := ref.Namespace
				if namespace == "" {
					namespace = cluster.Namespace
				}
				storage := &garagev1beta2.GarageCluster{}
				if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, storage); err == nil {
					references = secret.Name == managedRPCSecretName(storage)
				}
			}
			if references {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)})
			}
		}
		return requests
	})
	secretSourcePredicate := predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, oldOK := e.ObjectOld.(*corev1.Secret)
			newSecret, newOK := e.ObjectNew.(*corev1.Secret)
			return oldOK && newOK && (!equality.Semantic.DeepEqual(oldSecret.Data, newSecret.Data) ||
				!equality.Semantic.DeepEqual(oldSecret.Immutable, newSecret.Immutable) || oldSecret.Type != newSecret.Type)
		},
	}
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

	// EnqueueRequestsFromMapFunc evaluates both the old and new Node on Update.
	// That lets selector filtering retain removal/NotIn/DoesNotExist semantics
	// without waking every node-local GarageCluster for every Node label change.
	nodeMapper := handler.EnqueueRequestsFromMapFunc(r.clustersForKubernetesNode)

	// Managed pod handoffs are materialized only after a pod is scheduled. Pod
	// create/delete, UID, and readiness changes therefore enqueue the parent for
	// both node-local-pool DaemonSets and GarageNode-owned StatefulSets while a desired
	// or retiring pool keeps the cluster-wide OnDelete boundary active.
	managedStoragePodMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil
		}
		clusterName := obj.GetLabels()[labelCluster]
		if clusterName == "" {
			return nil
		}
		cluster := &garagev1beta2.GarageCluster{}
		key := types.NamespacedName{Name: clusterName, Namespace: obj.GetNamespace()}
		if err := r.Get(ctx, key, cluster); err != nil || !storageRolloutBoundaryActive(cluster) {
			return nil
		}
		if isStorageDaemonSetPod(cluster, pod) {
			return []reconcile.Request{{NamespacedName: key}}
		}
		owner := metav1.GetControllerOf(pod)
		if pod.Labels[labelGarageNode] == "" || owner == nil || owner.Kind != kindStatefulSet {
			return nil
		}
		return []reconcile.Request{{NamespacedName: key}}
	})

	garageNodeStatefulSetMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		statefulSet, ok := obj.(*appsv1.StatefulSet)
		if !ok || statefulSet.Labels[labelGarageNode] == "" {
			return nil
		}
		clusterName := statefulSet.Labels[labelCluster]
		if clusterName == "" {
			return nil
		}
		key := types.NamespacedName{Name: clusterName, Namespace: statefulSet.Namespace}
		cluster := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, key, cluster); err != nil || !storageRolloutBoundaryActive(cluster) {
			return nil
		}
		owner := metav1.GetControllerOf(statefulSet)
		if owner == nil || owner.Kind != kindGarageNode {
			return nil
		}
		return []reconcile.Request{{NamespacedName: key}}
	})

	// An exact Manual/SMB GarageNode workload correction is an atomic new spec
	// generation and must wake its active parent rollout immediately. Filter out
	// status-only ticks (LastSeen, Conditions, ObservedPodUID), which previously
	// caused Admin API amplification and disrupted scale-down timing, and map only
	// the immutable UID recorded as the current StatefulSet actor.
	garageNodeGenerationMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		node, ok := obj.(*garagev1beta1.GarageNode)
		if !ok {
			return nil
		}
		clusterNamespace := node.Namespace
		if node.Spec.ClusterRef.Namespace != "" {
			clusterNamespace = node.Spec.ClusterRef.Namespace
		}
		key := types.NamespacedName{Name: node.Spec.ClusterRef.Name, Namespace: clusterNamespace}
		cluster := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, key, cluster); err != nil || cluster.Status.StorageRollout == nil {
			return nil
		}
		record := cluster.Status.StorageRollout
		if record.GarageNodeName != node.Name || record.GarageNodeUID != string(node.UID) {
			return nil
		}
		return []reconcile.Request{{NamespacedName: key}}
	})

	// A replacement Pod's GarageNode status handshake is part of the durable
	// rollout protocol, but status-only updates do not pass
	// GenerationChangedPredicate. Wake the parent only when one of the exact
	// fields consumed by the layout/rollout barriers changes. While an actor is
	// persisted, restrict this to that immutable GarageNode UID; during the
	// preflight phase any managed member may be the join that unblocks rollout.
	garageNodeProgressMapper := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		node, ok := obj.(*garagev1beta1.GarageNode)
		if !ok || node.Spec.External != nil {
			return nil
		}
		clusterNamespace := node.Namespace
		if node.Spec.ClusterRef.Namespace != "" {
			clusterNamespace = node.Spec.ClusterRef.Namespace
		}
		key := types.NamespacedName{Name: node.Spec.ClusterRef.Name, Namespace: clusterNamespace}
		cluster := &garagev1beta2.GarageCluster{}
		if err := r.Get(ctx, key, cluster); err != nil || !storageRolloutBoundaryActive(cluster) {
			return nil
		}
		if record := cluster.Status.StorageRollout; record != nil &&
			(record.GarageNodeName != node.Name || record.GarageNodeUID != string(node.UID)) {
			return nil
		}
		return []reconcile.Request{{NamespacedName: key}}
	})
	garageNodeProgressPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, oldOK := e.ObjectOld.(*garagev1beta1.GarageNode)
			newNode, newOK := e.ObjectNew.(*garagev1beta1.GarageNode)
			return oldOK && newOK && garageNodeRolloutProgressChanged(oldNode, newNode)
		},
	}

	bldr := ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta2.GarageCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Watches(&corev1.PersistentVolumeClaim{}, pvcMapper).
		Watches(&appsv1.StatefulSet{}, garageNodeStatefulSetMapper).
		Watches(&garagev1beta1.GarageNode{}, garageNodeGenerationMapper, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&garagev1beta1.GarageNode{}, garageNodeProgressMapper, builder.WithPredicates(garageNodeProgressPredicate)).
		Watches(&corev1.Pod{}, managedStoragePodMapper).
		Watches(&corev1.Secret{}, secretSourceMapper, builder.WithPredicates(secretSourcePredicate))

	// Node is cluster-scoped: a namespace-scoped Role can never authorize
	// List/Watch on it (RBAC only evaluates namespaced-resource requests
	// against a Role), so registering this watch there would hang cache sync
	// and crash-loop the manager. Only safe when the manager watches all
	// namespaces (see ClusterScoped). Clusters with DaemonSet node-local pools are
	// refused with an actionable error in Reconcile when running namespace-scoped;
	// zoneFrom also requires the same cluster-scoped Node read/watch contract.
	if r.ClusterScoped {
		// LabelChangedPredicate lets Create/Delete through unconditionally
		// (node join/leave) but drops Update events unless labels changed —
		// without it, routine Node status churn (kubelet heartbeats,
		// condition/capacity updates) would trigger a full GarageClusterList +
		// reconcile of every DaemonSet-storage cluster on nearly every Node
		// update, since nodeSelector matching only depends on labels.
		bldr = bldr.Watches(&corev1.Node{}, nodeMapper, builder.WithPredicates(predicate.LabelChangedPredicate{}))
	}

	return bldr.
		Named("garagecluster").
		Complete(r)
}

func garageClusterReferencesSecretName(cluster *garagev1beta2.GarageCluster, name string) bool {
	if cluster == nil || name == "" {
		return false
	}
	selectors := []*corev1.SecretKeySelector{cluster.Spec.Network.RPCSecretRef}
	if cluster.Spec.Admin != nil {
		selectors = append(selectors, cluster.Spec.Admin.AdminTokenSecretRef, cluster.Spec.Admin.MetricsTokenSecretRef)
	}
	if cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil {
		consul := cluster.Spec.Discovery.Consul
		selectors = append(selectors, consul.CACertSecretRef, consul.ClientCertSecretRef, consul.ClientKeySecretRef, consul.TokenSecretRef)
	}
	if cluster.Spec.Security != nil && cluster.Spec.Security.TLS != nil {
		tls := cluster.Spec.Security.TLS
		selectors = append(selectors, tls.CertSecretRef, tls.KeySecretRef, tls.CASecretRef)
	}
	if cluster.Spec.ConnectTo != nil {
		selectors = append(selectors, cluster.Spec.ConnectTo.RPCSecretRef, cluster.Spec.ConnectTo.AdminTokenSecretRef)
	}
	for i := range cluster.Spec.RemoteClusters {
		selectors = append(selectors, cluster.Spec.RemoteClusters[i].Connection.AdminTokenSecretRef)
	}
	for _, selector := range selectors {
		if selector != nil && selector.Name == name {
			return true
		}
	}
	for i := range cluster.Spec.ImagePullSecrets {
		if cluster.Spec.ImagePullSecrets[i].Name == name {
			return true
		}
	}
	return false
}

// garageNodeRolloutProgressChanged contains only the status fields consumed by
// the parent storage membership and exact-Pod handoff barriers. LastSeen and
// unrelated conditions deliberately do not wake a GarageCluster reconcile.
func garageNodeRolloutProgressChanged(oldNode, newNode *garagev1beta1.GarageNode) bool {
	if oldNode == nil || newNode == nil {
		return false
	}
	return oldNode.Status.NodeID != newNode.Status.NodeID ||
		oldNode.Status.ObservedPodUID != newNode.Status.ObservedPodUID ||
		oldNode.Status.ObservedGeneration != newNode.Status.ObservedGeneration ||
		oldNode.Status.Connected != newNode.Status.Connected ||
		oldNode.Status.InLayout != newNode.Status.InLayout
}

// Tier identifiers used in labels and tags.
const (
	tierStorage           = "storage"
	tierGateway           = "gateway"
	storageGroupDefault   = "default"
	storageGroupNodeLocal = "node-local"
)

// labelTier is the operator's per-tier label key.
const labelTier = "garage.rajsingh.info/tier"

// labelGarageNode is the per-pod label written by the GarageNode controller
// onto its StatefulSet's pod template. Stable across pod restarts and
// independent of the StatefulSet's pod-name convention, so it's the right
// selector for per-pod Services (e.g. per-node LoadBalancer RPC).
const labelGarageNode = "garage.rajsingh.info/node"

// labelStorageGroup distinguishes the default StatefulSet/PVC/manual storage
// group from node-local pools. Services that provide one RPC address for the
// default group must not accidentally route a node-local-pool identity.
const labelStorageGroup = "garage.rajsingh.info/storage-group"

// labelCycleSibling marks a GarageNode that was provisioned by the graceful
// node-cycle state machine (#231) as the in-progress replacement for another
// node. While set, the cluster's Auto-mode scale loop must NOT manage the node
// as one of its ordinals — listAutoModeStorageNodes deliberately filters it out
// (the sibling carries no labelAppManagedBy=operator until it is promoted at the
// end of the cycle). Cleared when the original node is drained and the sibling
// takes over the layout slot.
const labelCycleSibling = "garage.rajsingh.info/cycle-sibling"

// labelAutoNodeSlot binds a promoted cycle replacement to the canonical Auto
// storage/gateway ordinal it satisfies. Names are only object identities and
// may be hash-bounded after repeated cycles; this controller-owned label is the
// stable membership slot contract. Parent ownership is always verified before
// the label is trusted.
const labelAutoNodeSlot = "garage.rajsingh.info/auto-node-slot"

// labelsForTier returns operator-managed labels scoped to a single tier. Use this
// when labelling tier-owned resources (StatefulSet / per-tier service /
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

// selectorLabelsForTier returns the minimal label set used in StatefulSet
// selectors and pod templates for a given tier.
func (r *GarageClusterReconciler) selectorLabelsForTier(cluster *garagev1beta2.GarageCluster, tier string) map[string]string {
	return map[string]string{
		labelAppName:     defaultAppName,
		labelAppInstance: cluster.Name,
		labelTier:        tier,
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

func nodeBelongsToClusterUID(tags []string, clusterUID string) bool {
	if clusterUID == "" {
		return false
	}
	want := nodeClusterUIDTagPrefix + clusterUID
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// buildNodeTags creates the tags list for a node including the cluster ownership tag.
// Format: ["cluster:<name>/<namespace>", "tier:<tier>" (if tier non-empty), <cluster.Spec.DefaultNodeTags...>, <podName>]
// The "tier:<tier>" tag distinguishes storage from gateway entries in the
// layout for diagnostics and per-tier reconciliation logic.
func buildNodeTags(clusterName, namespace, tier string, defaultTags []string, podName string, clusterUID ...string) []string {
	tags := make([]string, 0, 4+len(defaultTags))
	// Ownership tag for unique cluster identification
	tags = append(tags, fmt.Sprintf("cluster:%s/%s", clusterName, namespace))
	if len(clusterUID) > 0 && clusterUID[0] != "" {
		tags = append(tags, nodeClusterUIDTagPrefix+clusterUID[0])
	}
	// Tier tag so the operator can identify storage vs gateway entries in a layout
	// that mixes both (unified clusters in particular).
	if tier != "" {
		tags = append(tags, "tier:"+tier)
	}
	// User-defined tags
	tags = append(tags, userNodeLayoutTags(defaultTags)...)
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
	if !tagSetEqual(existing.Tags, desiredTags) {
		return true
	}

	return false
}

func sameRoleCapacity(left, right *uint64) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return left == nil || *left == *right
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
// trigger a workload update — without this, the update gate (which only compares
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
