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
	"encoding/base64"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

// finalizeOrphanedTimeout caps the best-effort layout-removal call made when
// the parent GarageCluster CR has already vanished. We don't want a hung
// external admin API to deadlock GarageNode finalization, so cap aggressively.
const finalizeOrphanedTimeout = 5 * time.Second

const (
	garageNodeFinalizer               = "garagenode.garage.rajsingh.info/finalizer"
	managedPVCNodeUIDAnnotation       = "garage.rajsingh.info/garage-node-uid"
	managedPVCNonceAnnotation         = "garage.rajsingh.info/pvc-reservation-nonce"
	autoModePVCHandoffNonceAnnotation = "garage.rajsingh.info/auto-mode-pvc-handoff-nonce"
	managedPVCFinalizer               = "garagenode.garage.rajsingh.info/pvc-reservation"
	nodeValue                         = "node"
)

// errUnsafeLayoutRoleRemoval marks a finalization failure that must not consume
// the generic retry budget. Dropping the finalizer after five deterministic
// replication-constraint failures would delete the GarageNode CR while leaving
// its capacity-bearing role permanently orphaned in Garage's layout.
var errUnsafeLayoutRoleRemoval = stderrors.New("unsafe Garage layout role removal")

// errLayoutRoleDraining means Garage accepted a storage role removal but an
// older active layout version still depends on that node. The pod and
// GarageNode finalizer must remain until Garage's layout-history trackers no
// longer include the identity; stopping it earlier can interrupt the block
// synchronization that makes the new layout safe.
var errLayoutRoleDraining = stderrors.New("garage layout role is still draining")

// errManagedPodAbsent distinguishes a proven workload gap from an ambiguous
// read or ownership failure. Only a proven absence may use a previously
// observed Garage identity without a current Pod UID to bind it to.
var errManagedPodAbsent = stderrors.New("managed Pod is absent")

// GarageNodeReconciler reconciles a GarageNode object
type GarageNodeReconciler struct {
	client.Client
	APIReader     client.Reader
	Scheme        *runtime.Scheme
	ClusterDomain string
	DefaultImage  string
	// ManagedPVCAdmissionDisabled must be true in production when the PVC
	// finalizer validating webhook is not installed. Such deployments may use
	// EmptyDir or explicit existingClaim volumes, but cannot safely create
	// predictable convention-named persistent claims.
	ManagedPVCAdmissionDisabled bool
	// ClusterScoped controls whether canonical rollout-source discovery may list
	// GarageClusters across namespaces. Namespace-scoped installs retain full
	// PVC/SMB support without requiring a cluster-wide List permission.
	ClusterScoped bool
	// LayoutMutations is shared with GarageClusterReconciler so Manual,
	// automatic, gateway, federation, and node-local-pool writers cannot race.
	LayoutMutations *LayoutMutationCoordinator
	// Test seams for the object-block resync quiet-period barrier.
	blockResyncObservationGetter func(context.Context, *garage.Client) (*blockResyncObservation, error)
	blockRepairLauncher          func(context.Context, *garage.Client, string) error
	clusterHealthGetter          func(context.Context, *garage.Client) (*garage.ClusterHealth, error)
	blockResyncQuietPeriod       time.Duration
	// Test seam for the exact rollout-actor lost-source transfer. Production
	// resolves the Admin client from the GarageCluster connection contract.
	lostSourceGarageClientGetter func(context.Context, *garagev1beta2.GarageCluster) (*garage.Client, error)
	// Test seam for direct, process-local identity discovery during node-local-pool
	// cold recovery. Production reads the selected DaemonSet Pod's own Admin API;
	// cluster status or a stale GarageNode status is not sufficient evidence.
	nodeLocalPoolRecoveryNodeIDGetter func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster, []string) (string, error)
	// Test seam for a managed spec.nodeId expected-pin proof. Production always
	// asks the exact owned Pod's Admin API for its self identity.
	managedNodeIDGetter func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error)
	// Test seam for the cycle replacement's per-node layout sync proof.
	cycleLayoutHistoryGetter func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error)
}

func (r *GarageNodeReconciler) nodeLocalPoolReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagenodes/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete

func (r *GarageNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	node := &garagev1beta1.GarageNode{}
	if err := r.Get(ctx, req.NamespacedName, node); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if node.DeletionTimestamp.IsZero() {
		if err := garagev1beta1.ValidateClusterReference(node.Spec.ClusterRef, "spec.clusterRef"); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, err)
		}
		if node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != node.Namespace {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf(
				"spec.clusterRef.namespace is not permitted: GarageNode requires a same-namespace GarageCluster",
			))
		}
		if node.Spec.External != nil && node.Spec.External.RemoteClusterRef != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("spec.external.remoteClusterRef is not supported"))
		}
		if err := garagev1beta1.ValidateSupportedPublicEndpoint(node.Spec.PublicEndpoint, "spec.publicEndpoint"); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, err)
		}
		if node.Spec.Storage != nil {
			if err := garageconfig.ValidateMetadataSnapshotInterval(
				node.Spec.Storage.MetadataAutoSnapshotInterval,
				"spec.storage.metadataAutoSnapshotInterval",
			); err != nil {
				return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("invalid Garage configuration: %w", err))
			}
		}
	}
	if canonicalNodeID := canonicalGarageNodeID(node.Status.NodeID); canonicalNodeID != node.Status.NodeID {
		apply := func() { node.Status.NodeID = canonicalNodeID }
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
			return ctrl.Result{}, fmt.Errorf("canonicalizing GarageNode status.nodeId: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
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
		// a dead capacity-less layout entry on the federated peer. A storage node
		// is different: without the durable parent transaction there is nowhere to
		// record or recover block-migration evidence, so retain its finalizer for
		// explicit manual recovery instead of silently orphaning positive capacity.
		if errors.IsNotFound(err) {
			if !node.DeletionTimestamp.IsZero() {
				if controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
					if !node.Spec.Gateway {
						return r.updateStatus(ctx, node, PhaseDeleting, fmt.Errorf(
							"referenced GarageCluster %q is absent; refusing to release a storage identity without its durable cluster-wide drain transaction; restore the parent or complete documented manual recovery",
							node.Spec.ClusterRef.Name,
						))
					}
					if err := r.attemptOrphanedFinalize(ctx, node); err != nil {
						log.Info("Best-effort layout cleanup against captured admin endpoint failed; releasing finalizer anyway",
							nodeValue, node.Name, "endpoint", node.Status.ClusterAdminEndpoint, "error", err.Error())
					} else if node.Status.ClusterAdminEndpoint != "" {
						log.Info("Removed node from layout via captured admin endpoint after parent cluster deletion",
							nodeValue, node.Name, "endpoint", node.Status.ClusterAdminEndpoint)
					} else {
						log.Info("Parent cluster already deleted; releasing GarageNode finalizer", nodeValue, node.Name)
					}
					// The missing parent no longer provides a retention policy. Preserve
					// claims (Retain fallback), but release any exact reservation barrier
					// so the PVC does not inherit an orphaned controller finalizer.
					retainedCluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Namespace: node.Namespace}}
					if err := r.cleanupOwnerlessManagedNodePVCs(ctx, node, retainedCluster); err != nil {
						return r.updateStatus(ctx, node, PhaseDeleting, err)
					}
					controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
					if updateErr := r.Update(ctx, node); updateErr != nil {
						return ctrl.Result{}, updateErr
					}
				}
				return ctrl.Result{}, nil
			}
			// Cluster CR absent but this node is NOT being deleted. This is a
			// transient/ordering state — e.g. a Flux apply that briefly removes
			// the cluster, or a user-owned (Manual) GarageNode whose parent
			// cluster was deleted out from under it. The node's StatefulSet,
			// pods and PVCs keep running (the STS is owned by the GarageNode, not
			// the cluster), so this is NOT a failure: surface Pending and requeue
			// so the node self-heals when the cluster reappears, rather than
			// flapping to Failed.
			log.Info("Referenced GarageCluster not found; node keeps running, requeueing",
				nodeValue, node.Name, "clusterRef", node.Spec.ClusterRef.Name)
			return r.updateStatus(ctx, node, PhasePending,
				fmt.Errorf("waiting for referenced GarageCluster %q to exist", node.Spec.ClusterRef.Name))
		}
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to get cluster: %w", err))
	}
	if node.Spec.ZoneFrom != nil && node.Spec.ZoneFrom.NodeLabel != "" &&
		node.Spec.External == nil && !r.ClusterScoped && node.DeletionTimestamp.IsZero() {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf(
			"spec.zoneFrom requires a cluster-scoped operator install because Kubernetes Node labels are the topology source; redeploy without --watch-namespaces/WATCH_NAMESPACE",
		))
	}
	// Rehydrate the process-wide exclusion before doing any spec-driven work.
	// This is required in the GarageNode controller too: after a manager restart
	// it may reconcile before the parent and must not render h2 over a persisted
	// h1 OnDelete handoff. A gateway-only parent with clusterRef mutates the
	// referenced storage GarageCluster's layout, so load that durable owner status
	// rather than trusting the gateway object's unrelated status.
	var layoutOwner *garagev1beta2.GarageCluster
	var err error
	if node.DeletionTimestamp.IsZero() {
		layoutOwner, err = resolveGarageLayoutOwner(ctx, r.nodeLocalPoolReader(), cluster)
	} else {
		layoutOwner, err = resolveGarageLayoutOwnerForCleanup(ctx, r.nodeLocalPoolReader(), cluster)
	}
	if err != nil {
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("reading canonical layout-owner GarageCluster before GarageNode reconciliation: %w", err))
	}
	coordinator := r.layoutMutationCoordinator()
	key := layoutOwnerKey(layoutOwner)
	if err := rehydrateNodeLocalPoolRolloutsForOwner(ctx, r.nodeLocalPoolReader(), coordinator, layoutOwner, r.ClusterScoped); err != nil {
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("rehydrating canonical managed-Pod rollout transactions: %w", err))
	}
	if err := rehydrateStorageDrainsForOwner(ctx, r.nodeLocalPoolReader(), coordinator, layoutOwner, r.ClusterScoped, r.APIReader != nil); err != nil {
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("rehydrating canonical storage-drain transactions: %w", err))
	}
	transferred, err := r.recoverOrTransferStorageRolloutLostSource(ctx, node, cluster, layoutOwner)
	if err != nil {
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("waiting for safe lost-source recovery of the exact storage rollout actor: %w", err))
	}
	if transferred {
		return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
	}
	// A generation-wide rollout transition starts as soon as the last converged
	// condition becomes stale. During that prepare phase GarageNodes must still
	// be able to publish their desired ConfigMaps/StatefulSets and finish additive
	// layout joins; no process has been selected for deletion yet. The narrower
	// handoff boundary starts only after status.storageRollout (or its durable
	// RollingOut condition) records one exact Pod incarnation. At that point the
	// parent owns workload publication and every non-actor layout writer freezes.
	storageRolloutTransitionActive := storageRolloutMutationBoundaryActive(cluster) ||
		storageRolloutMutationBoundaryActive(layoutOwner) || coordinator.NodeLocalPoolRolloutActive(key)
	storageRolloutHandoffActive := nodeLocalPoolRolloutConditionActive(cluster) ||
		nodeLocalPoolRolloutConditionActive(layoutOwner) || coordinator.NodeLocalPoolRolloutActive(key)
	storageDrainActor := storageDrainActorForNode(node)
	storageDrainActorActive := storageDrainActorMatches(layoutOwner.Status.StorageDrain, storageDrainActor)
	storageDrainActive := storageDrainConditionActive(layoutOwner) ||
		coordinator.StorageDrainActive(key)
	// User-created GarageNodes still require Manual layout for their tier —
	// operator-managed CRs (controllerOwnerRef on the GarageCluster, generated by
	// Auto mode in #190) are allowed regardless of policy. Storage nodes honor the
	// per-tier effective policy (spec.storage.layoutPolicy), so a cluster can be
	// Manual-storage + Auto-gateway; gateway nodes follow the cluster policy.
	//
	// A cycle sibling (#231) is operator-generated — owned by the GarageNode it is
	// replacing, not by the cluster — so it is exempt from the Manual-only gate the
	// same way an Auto ordinal is; otherwise an Auto cluster's sibling would be
	// rejected before it could ever join and sync.
	isOperatorOwned := hasExactGarageClusterControllerReference(node, cluster) || isCycleSibling(node)
	tierPolicy := effectiveStorageLayoutPolicy(cluster)
	tierName := tierStorage
	if node.Spec.Gateway {
		tierPolicy = cluster.Spec.LayoutPolicy
		tierName = tierGateway
	}
	if !isOperatorOwned && tierPolicy != LayoutPolicyManual {
		return r.updateStatus(ctx, node, PhaseFailed,
			fmt.Errorf("user-created %s GarageNode requires its tier layoutPolicy: Manual (set spec.storage.layoutPolicy for storage, spec.layoutPolicy for gateway)", tierName))
	}
	// Replication-factor migration temporarily owns the entire cluster layout.
	// This gate covers Manual and gateway GarageNodes as well as the storage
	// nodes explicitly marked operator-suspended by the migration state machine.
	if factorMigrationActive(cluster) {
		if !node.DeletionTimestamp.IsZero() {
			return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
		}
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("waiting for GarageCluster replication-factor migration to finish before reconciling the layout role"))
	}
	// A deleting canonical layout owner has already serialized the entire
	// cluster-wide drain. Nodes reached through surviving management handles are
	// not the drain actor, but must still reach the deletion handoff below so a
	// validated terminal root proof can release them.
	canonicalParentDeleting := !node.DeletionTimestamp.IsZero() && !layoutOwner.DeletionTimestamp.IsZero()
	if storageDrainActive && !storageDrainActorActive && !canonicalParentDeleting {
		actorDescription := "whose durable status is still publishing"
		if layoutOwner.Status.StorageDrain != nil {
			actorDescription = fmt.Sprintf("%+v", layoutOwner.Status.StorageDrain.Actor)
		}
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("waiting for GarageCluster storage drain actor %s before changing this GarageNode or its workload", actorDescription))
	}

	// Handle deletion
	if !node.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(node, garageNodeFinalizer) {
			// A Drain-deleting parent owns one cluster-wide transaction. Foreground
			// garbage collection may mark child GarageNodes deleting before the
			// parent finalizer has proved block migration, so keep this finalizer (and
			// therefore the identity-bearing workload) until that proof completes.
			if !layoutOwner.DeletionTimestamp.IsZero() {
				parentDrain := layoutOwner.EffectiveDeletionPolicy() == garagev1beta2.DeletionPolicyDrain && layoutOwner.HasStorageTier()
				safeParentHandoff := false
				var parentHandoffErr error
				if parentDrain {
					safeParentHandoff, parentHandoffErr = completedGarageClusterDrainAuthorizesFinalization(layoutOwner)
				}
				switch {
				case storageDrainActorActive:
					// Admission normally prevents this race. If deletion was forced or
					// admission was bypassed, let the exact node actor finish first.
				case parentDrain && parentHandoffErr != nil:
					_, _ = r.updateStatus(ctx, node, PhaseDeleting,
						fmt.Errorf("parent GarageCluster terminal drain proof is invalid: %w", parentHandoffErr))
					return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
				case parentDrain && !safeParentHandoff:
					_, _ = r.updateStatus(ctx, node, PhaseDeleting,
						fmt.Errorf("waiting for parent GarageCluster storage drain to complete before releasing this workload"))
					return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
				default:
					log.Info("Parent cluster layout cleanup is complete or Destroy was selected; releasing per-node finalizer")
					if err := r.cleanupOwnerlessManagedNodePVCs(ctx, node, cluster); err != nil {
						return r.updateStatus(ctx, node, PhaseDeleting, err)
					}
					controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
					if err := r.Update(ctx, node); err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, nil
				}
			}
			// A reversible drain removes the role and completes its durable block
			// proof before DELETE is admitted. Once that exact handoff is terminal,
			// the source Pod is expected to disappear and must never be used as a
			// fresh peer-proof prerequisite. In particular, the deletion boundary
			// can race a newer GarageNode generation past status.observedGeneration;
			// re-running peer discovery here would then deadlock a safe teardown.
			preparedWithoutLayout := garageNodePreparedWithoutLayout(node)
			preparedHandoff := preparedWithoutLayout
			if storageDrainActorActive {
				preparedHandoff, err = completedGarageNodeDrainAuthorizesFinalization(node, layoutOwner)
			}
			if err == nil && preparedHandoff {
				if preparedWithoutLayout {
					log.Info("Generation-bound no-layout drain preparation authorizes finalizer release",
						"nodeID", node.Status.NodeID)
				} else {
					log.Info("Exact terminal storage-drain handoff authorizes finalizer release",
						"nodeID", node.Status.NodeID,
						"transactionID", layoutOwner.Status.StorageDrain.TransactionID)
				}
			} else if err == nil {
				// No terminal handoff exists. This covers gateway deletion, forced or
				// admission-bypassed deletion, and an ordinary in-progress drain; keep
				// driving the existing live layout finalization state machine.
				garageClient, clientErr := r.garageNodeFinalizationClient(ctx, node, cluster)
				if clientErr != nil {
					log.Error(clientErr, "Failed to get garage client for finalization")
					err = fmt.Errorf("get Garage client for finalization: %w", clientErr)
				} else {
					mutate := func() error { return r.finalize(ctx, node, layoutOwner, garageClient) }
					if node.Spec.Gateway {
						err = runCapacitylessGarageNodeRoleRetirementMutation(
							r.layoutMutationCoordinator(), layoutOwner, node, mutate,
						)
					} else if storageDrainActorActive {
						err = runLayoutMutationIgnoringStorageDrain(
							ctx, r.layoutMutationCoordinator(), layoutOwner, storageDrainActor, garageClient, mutate,
						)
					} else {
						err = runLayoutMutation(ctx, r.layoutMutationCoordinator(), layoutOwner, garageClient, mutate)
					}
				}
			}
			if err != nil {
				if stderrors.Is(err, errLayoutMutationPending) || requiresDurableLayoutFinalization(node, err) {
					log.Info("GarageNode layout role cannot be removed safely yet; retaining finalizer",
						"error", err)
					_, _ = r.updateStatus(ctx, node, PhaseDeleting,
						fmt.Errorf("waiting for a safe Garage layout role removal: %w", err))
					return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
				}
				patch := client.MergeFrom(node.DeepCopy())
				IncrementFinalizationRetryCount(node)
				retryCount := GetFinalizationRetryCount(node)
				if patchErr := r.Patch(ctx, node, patch); patchErr != nil {
					if errors.IsNotFound(patchErr) {
						return ctrl.Result{}, nil
					}
					log.Error(patchErr, "Failed to update retry count annotation")
				}
				log.Error(err, "Failed to finalize node, retaining finalizer", "retries", retryCount)
				_, _ = r.updateStatus(ctx, node, PhaseDeleting, fmt.Errorf("finalization failed (retry %d): %w", retryCount, err))
				return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
			}
			if err := r.cleanupOwnerlessManagedNodePVCs(ctx, node, cluster); err != nil {
				return r.updateStatus(ctx, node, PhaseDeleting, err)
			}
			controllerutil.RemoveFinalizer(node, garageNodeFinalizer)
			if err := r.Update(ctx, node); err != nil {
				return ctrl.Result{}, err
			}
			if storageDrainActorActive {
				if err := r.clearCompletedNodeStorageDrain(ctx, node, layoutOwner); err != nil {
					return ctrl.Result{}, err
				}
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
	if err := validateGarageClusterRuntimeSafety(cluster); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed,
			fmt.Errorf("refusing ordinary GarageNode reconciliation for an unsafe parent GarageCluster: %w", err))
	}
	if err := validateGarageNodeRuntimeSafety(node); err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, err)
	}
	clusterGuard := &GarageClusterReconciler{
		Client: r.Client, APIReader: r.APIReader, Scheme: r.Scheme,
	}
	needsLegacyEnvironmentProof, err := clusterGuard.legacyEnvironmentMigrationNeeded(ctx, cluster, false)
	if err == nil && !needsLegacyEnvironmentProof {
		needsLegacyEnvironmentProof, err = garageNodeNeedsLegacyEnvironmentEvaluation(
			ctx, r.nodeLocalPoolReader(), node, cluster,
		)
	}
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, err)
	}
	if needsLegacyEnvironmentProof {
		migration, err := clusterGuard.evaluateLegacyEnvironmentMigration(ctx, cluster, true)
		if err != nil {
			return r.updateStatus(ctx, node, PhaseFailed,
				fmt.Errorf("released Garage environment migration is blocked: %w", err))
		}
		if migration.blocked {
			return r.updateStatus(ctx, node, PhaseFailed,
				fmt.Errorf("released Garage environment migration is waiting: %s", migration.message))
		}
	}

	// Parent-owned Auto/node-local-pool retirement is bound to the exact parent spec
	// generation that selected this node. If the user changes the parent before
	// a durable storage-drain transaction starts, cancel the metadata request
	// before ordinary drain handling can remove a still-desired role. A parent
	// that still wants the deletion will re-issue the handoff at its new
	// generation; a user-authored drain never has this status field set.
	if requestedGeneration := node.Status.ParentDeletionRequestGeneration; requestedGeneration != 0 &&
		requestedGeneration != cluster.Generation &&
		node.Annotations[garagev1beta1.AnnotationAcknowledgeLostSource] == "" {
		if node.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue {
			delete(node.Annotations, garagev1beta1.AnnotationDrain)
			if err := r.Update(ctx, node); err != nil {
				return ctrl.Result{}, fmt.Errorf("canceling stale parent-owned GarageNode drain request: %w", err)
			}
		}
		apply := func() {
			node.Status.ParentDeletionRequestGeneration = 0
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
			return ctrl.Result{}, fmt.Errorf("clearing stale parent-owned GarageNode deletion intent: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// garage.rajsingh.info/drain is a reversible prepare operation, not an
	// alias for DELETE. Keep the object, finalizer, and identity-bearing process
	// alive while removing its role and proving that its local blocks reached the
	// current destinations. The parent controller or user performs DELETE only
	// after the exact transaction is terminal.
	drainPreparationRequested := node.Annotations[garagev1beta1.AnnotationDrain] == annotationTrue
	if drainPreparationRequested {
		if storageRolloutTransitionActive {
			message := "waiting for the parent managed pod rollout to finish before preparing this GarageNode for deletion"
			if err := setGarageNodeDrainPreparedCondition(
				ctx, r.Client, node, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeDrainPreparing, message,
			); err != nil {
				return ctrl.Result{}, err
			}
			// Do not return here. A parent-owned scale-down changes the parent
			// generation before it requests this reversible drain. The existing
			// StatefulSet must still publish its exact current-generation rollout
			// input acknowledgment; otherwise the parent rollout waits for that
			// acknowledgment while this node waits for the rollout, and neither
			// state machine can advance. The rollout-prepare boundary below permits
			// workload publication and serialized no-op/current-role reconciliation,
			// but it still prevents drain preparation until the rollout converges.
		} else {
			prepared, preparedWithoutLayout, err := r.prepareGarageNodeDrain(ctx, node, cluster, layoutOwner)
			if err != nil {
				reason := garagev1beta1.ReasonNodeDrainPreparing
				if !stderrors.Is(err, errLayoutMutationPending) && !stderrors.Is(err, errLayoutRoleDraining) {
					reason = garagev1beta1.ReasonNodeDrainBlocked
				}
				if statusErr := setGarageNodeDrainPreparedCondition(
					ctx, r.Client, node, metav1.ConditionFalse, reason, err.Error(),
				); statusErr != nil {
					return ctrl.Result{}, statusErr
				}
				return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
			}
			if !prepared {
				return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
			}
			reason := garagev1beta1.ReasonNodeDrainPrepared
			message := "Garage role is absent and the exact removed-source/current-destination block proof is complete; background/default deletion is now safe"
			if preparedWithoutLayout {
				reason = garagev1beta1.ReasonNodeDrainPreparedNotInLayout
				message = "GarageNode has no live managed process or its never-committed exact identity is absent from the settled Garage layout; no block drain is required"
			}
			if err := setGarageNodeDrainPreparedCondition(
				ctx, r.Client, node, metav1.ConditionTrue, reason, message,
			); err != nil {
				return ctrl.Result{}, err
			}
			// A graceful cycle requested this same preparation and owns the final
			// promotion + Delete step. Ordinary Auto/node-local-pool/manual preparation
			// holds here until its parent or user issues the now-admissible DELETE.
			if !isCycleRequested(node) && node.Status.CyclePhase == "" {
				return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
			}
		}
	} else {
		meta.RemoveStatusCondition(&node.Status.Conditions, garagev1beta1.ConditionDrainPrepared)
	}

	// Maintenance mode: skip ALL reconciliation (STS, ConfigMap, Service, layout) so
	// operators can perform PVC swaps or hardware work without the operator fighting them.
	// Runs AFTER the deletion/finalizer block so a suspended node can still be deleted.
	//
	// Three sources of suspension, all with identical effect:
	//   - spec.maintenance.suspended  — user-facing, for manual PVC/hardware work.
	//   - parent spec.maintenance.suspended — freezes every local process and
	//     layout writer for site-wide/federated maintenance.
	//   - garage.rajsingh.info/operator-suspended annotation — INTERNAL, set by a
	//     cluster-level coordinated operation (factor migration) that needs to own
	//     this node's StatefulSet without the per-node controller fighting it.
	userSuspended := node.Spec.Maintenance != nil && node.Spec.Maintenance.Suspended
	parentSuspended := cluster.Spec.Maintenance != nil && cluster.Spec.Maintenance.Suspended
	op, operatorSuspended := node.Annotations[garagev1beta1.AnnotationOperatorSuspended]
	if userSuspended || parentSuspended || operatorSuspended {
		reason, message := "MaintenanceSuspended", "Reconciliation paused by spec.maintenance.suspended"
		if parentSuspended && !userSuspended {
			reason, message = "ClusterMaintenanceSuspended", "Reconciliation paused by parent GarageCluster spec.maintenance.suspended"
		}
		if operatorSuspended && !userSuspended && !parentSuspended {
			reason, message = "OperatorSuspended", fmt.Sprintf("Reconciliation paused by operation %q", op)
		}
		applySuspended := func() {
			meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
				Type:               "Suspended",
				Status:             metav1.ConditionTrue,
				Reason:             reason,
				Message:            message,
				ObservedGeneration: node.Generation,
			})
		}
		applySuspended()
		if err := UpdateStatusWithRetry(ctx, r.Client, node, applySuspended); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("GarageNode reconciliation paused", "reason", reason)
		return ctrl.Result{RequeueAfter: RequeueAfterLong}, nil
	}
	// Clear Suspended condition when not suspended.
	meta.RemoveStatusCondition(&node.Status.Conditions, "Suspended")

	// Graceful node cycle (#231): the garage.rajsingh.info/cycle annotation does an
	// add-before-remove swap — provision a sibling, wait for it to sync, then drain
	// + remove this node. Resumable via status.cyclePhase. When a cycle is active or
	// requested, reconcileCycle owns the rest of this reconcile (it may delete this
	// node when the swap completes), so return on its result.
	cycleActive := isCycleRequested(node) || node.Status.CyclePhase != ""
	if cycleActive &&
		(storageRolloutHandoffActive || (storageDrainActive && !storageDrainActorActive)) {
		return r.updateStatus(ctx, node, PhasePending,
			fmt.Errorf("waiting for the parent storage rollout/drain transaction to finish before cycling this GarageNode"))
	}
	// A broad rollout-prepare boundary (before an exact Pod handoff exists) must
	// pause the cycle state machine without returning from reconciliation. The
	// ordinary managed-workload path below is the only writer that can publish
	// this node's exact current-generation rollout input acknowledgment. Running
	// the cycle would cross the single-flight layout boundary; returning here
	// would make the parent rollout and cycle wait on each other forever.
	if cycleActive && !storageRolloutTransitionActive {
		return r.reconcileCycle(ctx, node, cluster, layoutOwner)
	}

	// Reconcile per-node RPC service when publicEndpoint is configured. Not
	// applicable to node-local-pool-backed nodes (webhook-rejected already, but
	// guarded here too): the Service would select on a pod label the shared
	// DaemonSet template never stamps and would sit with zero endpoints.
	if !storageRolloutHandoffActive && !storageDrainActive && node.Spec.External == nil && !isNodeLocalPoolBacked(node) && node.Spec.PublicEndpoint != nil {
		if err := r.reconcileNodeService(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("reconciling node service: %w", err))
		}
	}

	// Reconcile per-node ConfigMap when any node-specific config overrides are
	// present. Not applicable to node-local-pool-backed nodes (webhook-rejected
	// already, but guarded here too): their pods always mount the shared
	// cluster ConfigMap, never a per-node one.
	if !storageRolloutHandoffActive && !storageDrainActive && node.Spec.External == nil && !isNodeLocalPoolBacked(node) && nodeHasConfigOverrides(node) {
		if err := r.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
			return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("reconciling node config: %w", err))
		}
	}

	// For managed nodes (not external, not node-local-pool-backed), create/update the
	// StatefulSet. Node-local pool-backed nodes get their pod from a named,
	// cluster-owned node-local pool — this controller only manages the layout role
	// for them.
	if !storageRolloutHandoffActive && !storageDrainActive && node.Spec.External == nil && !isNodeLocalPoolBacked(node) {
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
	if err != nil && garageNodeCanUseExactOperatorTokenBridge(node) {
		// During additive joins (and identity-replacing recovery) a new process
		// cannot receive the FullReplication token row until it has a layout role,
		// while the cluster-wide token proof deliberately waits for that process
		// to accept the token. Break that cycle through an exact existing Pod that
		// proves it accepts the authoritative dynamic token; never send a fallback
		// credential through the load-balanced cluster Service.
		if direct, directErr := directVerifiedOperatorAdminClient(
			ctx, r.nodeLocalPoolReader(), cluster, getAdminPort(cluster),
		); directErr == nil {
			garageClient = direct
			err = nil
		} else {
			err = fmt.Errorf("%w; exact existing-Pod operator-token bridge is unavailable: %v", err, directErr)
		}
	}
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to create garage client: %w", err))
	}

	// Capture the resolved admin endpoint + token ref on status so the
	// orphaned-finalize path can still reach the right Garage admin API
	// (especially the *remote* one for edge gateways) when the parent
	// GarageCluster CR has been deleted before we get a chance to clean up.
	captureAdminEndpoint(node, cluster, r.ClusterDomain)

	// Reconcile the node layout
	mutate := func() error { return r.reconcileNode(ctx, node, cluster, garageClient, layoutOwner) }
	var layoutErr error
	switch {
	case storageDrainActorActive:
		layoutErr = runLayoutMutationIgnoringStorageDrain(
			ctx, r.layoutMutationCoordinator(), layoutOwner, storageDrainActor, garageClient, mutate,
		)
	case nodeLocalPoolRolloutCandidateMatches(cluster, node):
		layoutErr = runLayoutMutationIgnoringNodeLocalPoolRollout(
			ctx, r.layoutMutationCoordinator(), layoutOwner, garageClient, mutate,
		)
	case node.Spec.External == nil && storageRolloutTransitionActive && !storageRolloutHandoffActive:
		// Before an exact Pod UID is selected, managed GarageNodes still own the
		// joins and capacity/zone updates required to make their desired generation
		// rollout-ready. Keep these mutations serialized and history-gated while
		// the broader transition boundary freezes every unrelated writer.
		layoutErr = runLayoutMutationDuringStorageRolloutPrepare(
			ctx, r.layoutMutationCoordinator(), layoutOwner, garageClient, mutate,
		)
	case node.Spec.External == nil && storageRolloutHandoffActive:
		// A second managed pod may have been restarted manually while the
		// recorded candidate owns the rollout. It may refresh read-only
		// connectivity and exact pod-UID evidence, but it cannot stage layout
		// changes. A stale generation would require such a change, so fail closed
		// until the active candidate completes.
		if node.Status.ObservedGeneration < node.Generation {
			return r.updateStatus(ctx, node, PhasePending,
				fmt.Errorf("waiting for storage rollout actor %+v before reconciling this GarageNode generation", cluster.Status.StorageRollout))
		}
		return r.updateStatusFromGarage(ctx, node, cluster, garageClient)
	default:
		layoutErr = runLayoutMutation(ctx, r.layoutMutationCoordinator(), layoutOwner, garageClient, mutate)
	}
	if layoutErr != nil {
		if stderrors.Is(layoutErr, errLayoutMutationPending) {
			_, statusErr := r.updateStatus(ctx, node, PhasePending, layoutErr)
			if statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{RequeueAfter: RequeueAfterPending}, nil
		}
		return r.updateStatus(ctx, node, PhaseFailed, layoutErr)
	}

	result, statusErr := r.updateStatusFromGarage(ctx, node, cluster, garageClient)
	if statusErr != nil {
		return result, statusErr
	}
	if storageDrainActorActive {
		proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain)
		if proof != nil && proof.CompletedAt != nil {
			if err := r.clearCompletedNodeStorageDrain(ctx, node, layoutOwner); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	return result, nil
}

// garageNodeCanUseExactOperatorTokenBridge covers every operator-managed local
// Garage process represented by a GarageNode, including Manual edge gateways.
// Cluster-owned Auto gateway StatefulSets are not GarageNodes and therefore
// cannot enter this path; external GarageNodes have no exact local Pod endpoint.
func garageNodeCanUseExactOperatorTokenBridge(node *garagev1beta1.GarageNode) bool {
	return node != nil && node.Spec.External == nil
}

// exactManagedGarageNodeAdminClient binds a safety-critical Admin transaction
// to the exact identity-bearing Pod and the immutable startup credential that
// Pod actually mounted. A table-backed operator token is FullReplication data:
// once this actor's role is removed, that local process may stop serving the
// token even though it must remain online while layout history and block drain
// complete. A shared Service can also select that just-removed process between
// requests. Keeping one exact Pod IP plus its mounted static bearer avoids both
// failure modes without weakening Pod ownership or durable identity checks.
func (r *GarageNodeReconciler) exactManagedGarageNodeAdminClient(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	expectedNodeID string,
) (*garage.Client, error) {
	if node == nil || cluster == nil || node.Spec.External != nil {
		return nil, fmt.Errorf("exact managed GarageNode Admin client requires a local managed node and parent cluster")
	}
	expectedNodeID = canonicalGarageNodeID(expectedNodeID)
	if expectedNodeID == "" {
		return nil, fmt.Errorf("exact managed GarageNode Admin client requires a durable Garage node ID")
	}

	identity, err := r.discoverNodeIdentityDirect(ctx, node, cluster)
	if err != nil {
		return nil, fmt.Errorf("proving exact managed Garage process identity: %w", err)
	}
	if identity == nil || canonicalGarageNodeID(identity.nodeID) != expectedNodeID {
		actual := ""
		if identity != nil {
			actual = canonicalGarageNodeID(identity.nodeID)
		}
		return nil, fmt.Errorf(
			"exact managed Pod reports Garage identity %s, expected durable identity %s",
			shortID(actual), shortID(expectedNodeID),
		)
	}

	pod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		return nil, fmt.Errorf("re-reading exact managed Pod before Admin transaction: %w", err)
	}
	if pod.UID != identity.podUID {
		return nil, fmt.Errorf("managed Pod changed UID from %s to %s before Admin transaction", identity.podUID, pod.UID)
	}
	podIPs, err := managedPodIPs(pod)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(podIPs, identity.podIP) {
		return nil, fmt.Errorf("managed Pod %s/%s no longer owns authenticated IP %s", pod.Namespace, pod.Name, identity.podIP)
	}
	adminToken, err := mountedStaticAdminToken(ctx, r.nodeLocalPoolReader(), pod)
	if err != nil {
		return nil, fmt.Errorf("reading exact Pod startup Admin token: %w", err)
	}
	return garage.NewClient(adminEndpoint(identity.podIP, getAdminPort(cluster)), adminToken), nil
}

func (r *GarageNodeReconciler) garageNodeFinalizationClient(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (*garage.Client, error) {
	if node != nil && node.Spec.External == nil {
		nodeID, err := node.ResolvedGarageNodeID()
		if err != nil {
			return nil, err
		}
		if nodeID != "" && !garageNodeAcknowledgesLostSource(node, nodeID) {
			return r.exactManagedGarageNodeAdminClient(ctx, node, cluster, nodeID)
		}
	}
	return GetGarageClientForCleanup(ctx, r.Client, cluster, r.ClusterDomain)
}

// fenceManagedGarageNodeLostSource creates a durable stop boundary before the
// operator omits an acknowledged unavailable source from block verification.
// The immutable drain/lost-source annotations keep ordinary GarageNode
// reconciliation from restoring a StatefulSet replica. For node-local pools the
// parent reconciler separately suppresses activation-label restoration.
func (r *GarageNodeReconciler) fenceManagedGarageNodeLostSource(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if node == nil || cluster == nil || node.Spec.External != nil {
		return false, fmt.Errorf("managed lost-source fencing requires an operator-managed GarageNode and parent GarageCluster")
	}
	if isNodeLocalPoolBacked(node) {
		k8sNode := &corev1.Node{}
		err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Name: node.Spec.KubernetesNodeName}, k8sNode)
		if err != nil && !errors.IsNotFound(err) {
			return false, fmt.Errorf("reading Kubernetes Node before lost-source fencing: %w", err)
		}
		if err == nil {
			activationLabel := nodeLocalPoolActivationLabel(cluster, node.Spec.NodeLocalPoolName)
			recoveryAnnotation := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, node.Spec.NodeLocalPoolName)
			_, activationExists := k8sNode.Labels[activationLabel]
			if activationExists || k8sNode.Annotations[recoveryAnnotation] != "" {
				before := k8sNode.DeepCopy()
				delete(k8sNode.Labels, activationLabel)
				delete(k8sNode.Annotations, recoveryAnnotation)
				if err := r.Patch(ctx, k8sNode, client.MergeFrom(before)); err != nil {
					return false, fmt.Errorf("removing node-local-pool activation and identity records before lost-source recovery: %w", err)
				}
				return false, nil
			}
		}
		pods := &corev1.PodList{}
		if err := r.nodeLocalPoolReader().List(ctx, pods,
			client.InNamespace(node.Namespace),
			client.MatchingLabels(map[string]string{
				labelCluster:       cluster.Name,
				labelTier:          tierStorage,
				labelNodeLocalPool: node.Spec.NodeLocalPoolName,
			}),
		); err != nil {
			return false, fmt.Errorf("listing node-local-pool Pods during lost-source fencing: %w", err)
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.Spec.NodeName != node.Spec.KubernetesNodeName {
				continue
			}
			owner := metav1.GetControllerOf(pod)
			if owner == nil || owner.Kind != daemonSetKind {
				return false, fmt.Errorf("%w: refusing to fence unexpected Pod %s on lost-source Kubernetes Node %s", errLayoutMutationPending, pod.Name, node.Spec.KubernetesNodeName)
			}
			uid := pod.UID
			zero := int64(0)
			if err := r.Delete(ctx, pod, &client.DeleteOptions{
				GracePeriodSeconds: &zero,
				Preconditions:      &metav1.Preconditions{UID: &uid},
			}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
				return false, fmt.Errorf("deleting exact node-local-pool Pod %s during lost-source fencing: %w", pod.Name, err)
			}
			return false, nil
		}
		return true, nil
	}

	statefulSet := &appsv1.StatefulSet{}
	err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name}, statefulSet)
	if err != nil && !errors.IsNotFound(err) {
		return false, fmt.Errorf("reading GarageNode StatefulSet before lost-source fencing: %w", err)
	}
	if err == nil {
		if !metav1.IsControlledBy(statefulSet, node) {
			return false, fmt.Errorf("%w: StatefulSet %s is not controlled by acknowledged lost-source GarageNode %s", errLayoutMutationPending, statefulSet.Name, node.Name)
		}
		if statefulSet.Spec.Replicas == nil || *statefulSet.Spec.Replicas != 0 {
			before := statefulSet.DeepCopy()
			statefulSet.Spec.Replicas = ptr.To[int32](0)
			if err := r.Patch(ctx, statefulSet, client.MergeFrom(before)); err != nil {
				return false, fmt.Errorf("scaling GarageNode StatefulSet to zero for lost-source recovery: %w", err)
			}
			return false, nil
		}
	}
	pod := &corev1.Pod{}
	err = r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name + "-0"}, pod)
	if errors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading GarageNode Pod during lost-source fencing: %w", err)
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != kindStatefulSet || owner.Name != node.Name {
		return false, fmt.Errorf("%w: refusing to fence unexpected Pod %s for lost-source GarageNode %s", errLayoutMutationPending, pod.Name, node.Name)
	}
	uid := pod.UID
	zero := int64(0)
	if err := r.Delete(ctx, pod, &client.DeleteOptions{
		GracePeriodSeconds: &zero,
		Preconditions:      &metav1.Preconditions{UID: &uid},
	}); err != nil && !errors.IsNotFound(err) && !errors.IsConflict(err) {
		return false, fmt.Errorf("deleting exact GarageNode Pod during lost-source fencing: %w", err)
	}
	return false, nil
}

// requiresDurableLayoutFinalization keeps every known Garage identity behind
// its finalizer until the Admin API proves role retirement. Gateways carry no
// object blocks, but they do carry full-copy metadata and must stay online long
// enough to ACK the version that removes them. The explicit orphaned-parent
// recovery path remains the only bounded best-effort exception.
func requiresDurableLayoutFinalization(node *garagev1beta1.GarageNode, err error) bool {
	return err != nil && node != nil
}

// isNodeLocalPoolBacked reports whether this GarageNode's pod comes from a
// cluster-owned node-local-pool workload (spec.backing: NodeLocalPool) rather than a per-node
// StatefulSet owned by this controller.
func isNodeLocalPoolBacked(node *garagev1beta1.GarageNode) bool {
	return node.Spec.Backing == garagev1beta1.NodeBackingNodeLocalPool
}

// reconcileStatefulSet creates/updates the StatefulSet for a managed GarageNode.
// Each GarageNode creates its own StatefulSet with replica 1.
func (r *GarageNodeReconciler) reconcileStatefulSet(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	return r.reconcileStatefulSetWithRecoveryFence(ctx, node, cluster, false)
}

// reconcileStatefulSetWithRecoveryFence creates an out-of-band deleted rollout
// actor at zero replicas. The parent first CAS-adopts the new StatefulSet UID in
// status.storageRollout, then ordinary reconcileStatefulSet restores replica 1.
// No unrecorded workload incarnation can start an identity-bearing Pod.
func (r *GarageNodeReconciler) reconcileStatefulSetWithRecoveryFence(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	recoveryFence bool,
) error {
	log := logf.FromContext(ctx)
	stsName := node.Name

	// Build merged pod config (cluster defaults + node overrides)
	image := mergeNodeImage(cluster.Spec.Image, cluster.Spec.ImageRepository, node.Spec.Image, node.Spec.ImageRepository, r.DefaultImage)

	// Cluster-level fallback scheduling values come from the tier this node
	// belongs to. A gateway GarageNode (node.Spec.Gateway) inherits the gateway
	// tier's PodTemplate; a storage GarageNode inherits the storage tier's. This
	// matters in a unified cluster where BOTH tiers are declared — without the
	// gateway branch, gateway pods would wrongly inherit storage-tier scheduling
	// (resources, nodeSelector, affinity). Fallbacks cover single-tier clusters.
	var tierTemplate *garagev1beta2.PodTemplate
	switch {
	case node.Spec.Gateway && cluster.HasGatewayTier():
		tierTemplate = &cluster.Spec.Gateway.PodTemplate
	case !node.Spec.Gateway && cluster.HasStorageTier():
		tierTemplate = &cluster.Spec.Storage.PodTemplate
	case cluster.HasStorageTier():
		tierTemplate = &cluster.Spec.Storage.PodTemplate
	case cluster.HasGatewayTier():
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

	var configBody string
	configBaseName := cluster.Name + "-config"
	if nodeHasConfigOverrides(node) {
		if err := r.reconcileNodeConfigMap(ctx, node, cluster); err != nil {
			return fmt.Errorf("publishing exact GarageNode config revision: %w", err)
		}
		var err error
		configBody, err = r.renderNodeGarageConfig(ctx, node, cluster)
		if err != nil {
			return err
		}
		configBaseName = garageNodeConfigBaseName(cluster, node)
	} else {
		cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
		if err != nil {
			return fmt.Errorf("building shared Garage config context: %w", err)
		}
		configBody = generateGarageConfig(cluster, cfgCtx)
	}
	configRevision, err := garageConfigRevision(ctx, r.nodeLocalPoolReader(), cluster, configBody)
	if err != nil {
		return fmt.Errorf("deriving exact Garage config revision: %w", err)
	}
	configName := garageConfigRevisionName(configBaseName, configRevision)
	publishedConfig, configObject, err := readGarageConfigResource(
		ctx, r.nodeLocalPoolReader(), cluster.Namespace, configName, garageConfigUsesSecret(cluster),
	)
	if err != nil {
		return fmt.Errorf("reading exact immutable Garage config revision %s/%s: %w", cluster.Namespace, configName, err)
	}
	if publishedConfig != configBody {
		return fmt.Errorf("immutable Garage config revision %s/%s does not match the current rendered input", cluster.Namespace, configName)
	}
	if nodeHasConfigOverrides(node) {
		if !metav1.IsControlledBy(configObject, node) {
			return fmt.Errorf("garageNode config revision %s/%s is not controlled by GarageNode %s", cluster.Namespace, configName, node.Name)
		}
	} else if !metav1.IsControlledBy(configObject, cluster) {
		return fmt.Errorf("shared Garage config revision %s/%s is not controlled by GarageCluster %s", cluster.Namespace, configName, cluster.Name)
	}

	// Build volumes and mounts for this node
	volumes, volumeMounts := r.buildNodeVolumesAndMountsForConfig(node, cluster, configName)
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

	// Gateway nodes may carry a spec.gateway.readinessProbe override; storage
	// nodes get no probe (nil), so this is only consulted for gateway nodes.
	var gatewayReadinessProbe *corev1.Probe
	if node.Spec.Gateway && cluster.Spec.Gateway != nil {
		gatewayReadinessProbe = cluster.Spec.Gateway.ReadinessProbe
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
		ReadinessProbe:            gatewayReadinessProbe,
		Logging:                   effectiveLogging,
		Env:                       mergedEnv,
		EnvFrom:                   mergedEnvFrom,
	}, volumes, volumeMounts, containerPorts)
	if err := validateGarageCredentialFileAccess(cluster, podSpec, "GarageNode "+node.Name); err != nil {
		return err
	}

	// Merge only user-owned labels first. Operator selector/identity labels are
	// overlaid last so even a grandfathered or admission-bypassed value cannot
	// invalidate the StatefulSet selector, Service routing, or Scale projection.
	userLabels := make(map[string]string)
	for k, v := range clusterPodLabels {
		userLabels[k] = v
	}
	for k, v := range node.Spec.PodLabels {
		userLabels[k] = v
	}
	userLabels = workloadidentity.UserPodLabels(userLabels)
	podLabels := maps.Clone(userLabels)
	if podLabels == nil {
		podLabels = make(map[string]string)
	}
	maps.Copy(podLabels, r.labelsForNode(node, cluster))

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
	// Compute pod-spec-hash from the pod spec plus user-provided podAnnotations/podLabels so
	// changes to those trigger a StatefulSet update.
	podSpecHashStr := computePodSpecHash(podSpec, userAnnotations, userLabels)

	podAnnotations := make(map[string]string)
	for k, v := range userAnnotations {
		podAnnotations[k] = v
	}
	if node.Spec.Gateway {
		// Match the empty marker written by released gateway workloads so an
		// adopted or restarted metadata PVC remains byte-compatible.
		podAnnotations[annotationGatewayDataMarker] = gatewayDataMarkerLegacyContent
	}
	podAnnotations[annotationPodSpecHash] = podSpecHashStr

	// Include the mounted config resource's content hash so pods restart when config changes.
	// Per-node override resource when present (must match buildNodeVolumesAndMounts),
	// otherwise the shared cluster resource — without this, changes to cluster.spec.* never
	// roll the per-node pods.
	configAnnotationRevision, err := garageConfigAnnotationRevision(ctx, r.nodeLocalPoolReader(), cluster, configBody)
	if err != nil {
		return fmt.Errorf("deriving Garage config annotation revision: %w", err)
	}
	podAnnotations[annotationConfigHash] = configAnnotationRevision

	replicas := int32(1)
	if recoveryFence {
		replicas = 0
	}
	// Every GarageNode StatefulSet represents one durable Garage identity,
	// regardless of whether its data comes from PVC, SMB, or another mounted
	// volume. Keep it OnDelete unconditionally so a shared image/config edit
	// cannot make independent StatefulSet controllers restart every identity at
	// once. The GarageCluster StorageRollout sequencer owns each pod handoff.
	updateStrategy := appsv1.StatefulSetUpdateStrategy{Type: appsv1.OnDeleteStatefulSetStrategyType}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: cluster.Namespace,
			Labels:    r.labelsForNode(node, cluster),
			Annotations: map[string]string{
				annotationStorageRolloutInput: storageRolloutInputToken(
					cluster, node, podSpecHashStr, podAnnotations[annotationConfigHash],
				),
			},
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
			UpdateStrategy:                       updateStrategy,
			PersistentVolumeClaimRetentionPolicy: stsPVCRetentionPolicy(cluster, node),
		},
	}

	if err := controllerutil.SetControllerReference(node, sts, r.Scheme); err != nil {
		return err
	}

	existing := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		if err := r.validateConventionNamedNodePVCs(ctx, node, cluster, volumeClaimTemplates); err != nil {
			return err
		}
		if nameErr := validateManagedGarageNodeName(node); nameErr != nil {
			return fmt.Errorf("refusing to create a GarageNode StatefulSet with an unsafe derived Pod label: %w", nameErr)
		}
		log.Info("Creating StatefulSet for GarageNode", "name", stsName)
		return r.Create(ctx, sts)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(existing, node) {
		return fmt.Errorf("refusing to mutate or delete StatefulSet %s/%s because it is not controlled by GarageNode %s/%s UID %s", existing.Namespace, existing.Name, node.Namespace, node.Name, node.UID)
	}
	if err := r.validateConventionNamedNodePVCs(ctx, node, cluster, volumeClaimTemplates); err != nil {
		return err
	}

	// The StatefulSet selector is immutable. An STS created by an older operator
	// with a different selector label scheme can never be Updated in place — every
	// reconcile fails with "selector does not match template labels", wedging the
	// STS (config-hash never converges, the pod can't be rolled for config
	// changes). Heal it by orphan-deleting (PropagationPolicy: Orphan keeps the
	// running pod and its RWO metadata/data PVCs) and recreating with the current
	// spec. The new STS adopts the still-running pod in place — the pod's labels
	// are a superset of the new selector — so node_key identity and data are
	// preserved with no downtime and no PVC rebind.
	if existing.Spec.Selector != nil && existing.Spec.Selector.MatchLabels != nil &&
		!equality.Semantic.DeepEqual(existing.Spec.Selector.MatchLabels, sts.Spec.Selector.MatchLabels) {
		if nameErr := validateManagedGarageNodeName(node); nameErr != nil {
			return fmt.Errorf("refusing to recreate a GarageNode StatefulSet with an unsafe derived Pod label: %w", nameErr)
		}
		if !existing.DeletionTimestamp.IsZero() {
			// Already orphan-deleting from a prior reconcile; wait for it to clear,
			// then the create branch above (IsNotFound) recreates it.
			return nil
		}
		log.Info("StatefulSet selector scheme changed (immutable) — orphan-recreating to heal",
			"name", stsName, "oldSelector", existing.Spec.Selector.MatchLabels, "newSelector", sts.Spec.Selector.MatchLabels)
		orphan := metav1.DeletePropagationOrphan
		if err := r.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &orphan}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("orphan-deleting selector-mismatched StatefulSet %s: %w", stsName, err)
		}
		// Recreated on the next reconcile (the StatefulSet delete event re-triggers
		// this controller); the orphaned pod keeps serving until then.
		return nil
	}

	// Check if update is needed
	needsUpdate := false
	existingPodSpecHash := existing.Spec.Template.Annotations[annotationPodSpecHash]
	if existingPodSpecHash != podSpecHashStr {
		log.Info("Pod spec hash changed, updating StatefulSet", "old", existingPodSpecHash, "new", podSpecHashStr)
		needsUpdate = true
	}
	// Also detect config-only changes (e.g. LB IP assigned, fsync override toggled)
	if !needsUpdate {
		existingConfigHash := existing.Spec.Template.Annotations[annotationConfigHash]
		newConfigHash := sts.Spec.Template.Annotations[annotationConfigHash]
		if existingConfigHash != newConfigHash {
			log.Info("Config hash changed, updating StatefulSet", "old", existingConfigHash, "new", newConfigHash)
			needsUpdate = true
		}
	}
	if !needsUpdate && !equality.Semantic.DeepEqual(existing.Spec.UpdateStrategy, sts.Spec.UpdateStrategy) {
		log.Info("StatefulSet update strategy changed", "old", existing.Spec.UpdateStrategy.Type, "new", sts.Spec.UpdateStrategy.Type)
		needsUpdate = true
	}
	if !needsUpdate && !equality.Semantic.DeepEqual(
		existing.Spec.PersistentVolumeClaimRetentionPolicy,
		sts.Spec.PersistentVolumeClaimRetentionPolicy,
	) {
		log.Info("StatefulSet PVC retention policy changed")
		needsUpdate = true
	}
	if !needsUpdate && existing.Annotations[annotationStorageRolloutInput] != sts.Annotations[annotationStorageRolloutInput] {
		log.Info("StatefulSet storage rollout input acknowledgment changed")
		needsUpdate = true
	}
	// Restore replicas if the STS was scaled to 0 externally (e.g. during maintenance).
	if existing.Spec.Replicas == nil || *existing.Spec.Replicas != replicas {
		log.Info("StatefulSet replicas diverged, restoring", "current", existing.Spec.Replicas, "desired", replicas)
		needsUpdate = true
	}

	if !needsUpdate {
		return nil
	}

	existing.Spec.Template = sts.Spec.Template
	existing.Spec.Replicas = &replicas
	existing.Spec.UpdateStrategy = sts.Spec.UpdateStrategy
	existing.Spec.PersistentVolumeClaimRetentionPolicy = sts.Spec.PersistentVolumeClaimRetentionPolicy
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[annotationStorageRolloutInput] = sts.Annotations[annotationStorageRolloutInput]
	log.Info("Updating StatefulSet for GarageNode", "name", stsName)
	return r.Update(ctx, existing)
}

// validateConventionNamedNodePVCs reserves convention-named claims before a
// StatefulSet can race another namespace actor to those predictable names.
// Exact API-server UIDs are persisted in GarageNode status before workload
// creation and are the ownership authority on every later reconcile.
func (r *GarageNodeReconciler) validateConventionNamedNodePVCs(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	templates []corev1.PersistentVolumeClaim,
) error {
	if len(templates) > 0 && r.ManagedPVCAdmissionDisabled {
		return errors.NewBadRequest("managed persistent volume claims require enabled admission webhooks to protect exact PVC identity reservations")
	}
	reader := r.nodeLocalPoolReader()
	for i := range templates {
		pvc := &corev1.PersistentVolumeClaim{}
		name := fmt.Sprintf("%s-%s-0", templates[i].Name, node.Name)
		if err := reader.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				record, recorded, recordErr := managedNodePVCReservation(node, name)
				if recordErr != nil {
					return recordErr
				} else if recorded && record.UID != "" {
					return fmt.Errorf("refusing to replace missing managed PVC %s/%s with recorded UID %s", cluster.Namespace, name, record.UID)
				}
				if err := r.reserveManagedNodePVC(ctx, node, cluster, &templates[i], name); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("checking convention-named PVC %s/%s: %w", cluster.Namespace, name, err)
		}
		if err := r.ensureManagedNodePVCProvenance(ctx, pvc, node, cluster); err != nil {
			return err
		}
	}
	return nil
}

func managedNodePVCReservation(
	node *garagev1beta1.GarageNode, name string,
) (garagev1beta1.ManagedNodePVCStatus, bool, error) {
	var found *garagev1beta1.ManagedNodePVCStatus
	for i := range node.Status.ManagedPVCs {
		record := node.Status.ManagedPVCs[i]
		if record.Name != name {
			continue
		}
		if (record.UID == "") == (record.PendingReservationHash == "") {
			return garagev1beta1.ManagedNodePVCStatus{}, false, fmt.Errorf(
				"GarageNode status must set exactly one of UID or pendingReservationHash for managed PVC %q", name,
			)
		}
		if found != nil {
			return garagev1beta1.ManagedNodePVCStatus{}, false, fmt.Errorf(
				"GarageNode status has duplicate reservations for managed PVC %q", name,
			)
		}
		copy := record
		found = &copy
	}
	if found == nil {
		return garagev1beta1.ManagedNodePVCStatus{}, false, nil
	}
	return *found, true, nil
}

func newManagedNodePVCNonce() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generating managed PVC reservation nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(nonce))
	return nonce, hex.EncodeToString(digest[:]), nil
}

func managedNodePVCNonceMatches(pvc *corev1.PersistentVolumeClaim, hash string) bool {
	nonce := pvc.Annotations[managedPVCNonceAnnotation]
	if nonce == "" || hash == "" {
		return false
	}
	digest := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(digest[:]) == hash
}

func (r *GarageNodeReconciler) reserveManagedNodePVC(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	template *corev1.PersistentVolumeClaim,
	name string,
) error {
	if node.UID == "" {
		return fmt.Errorf("cannot reserve managed PVC %s/%s for a GarageNode without a UID", cluster.Namespace, name)
	}
	nonce, reservationHash, err := newManagedNodePVCNonce()
	if err != nil {
		return err
	}
	// Persist the one-way commitment before creating the predictable PVC name.
	// If the process stops after Create, the next reconcile can authenticate the
	// nonce on that exact claim and bind its API-server UID.
	if err := r.persistManagedNodePVCPendingReservation(ctx, node, name, reservationHash); err != nil {
		return err
	}
	claim := template.DeepCopy()
	claim.Name = name
	claim.Namespace = cluster.Namespace
	claim.ResourceVersion = ""
	claim.UID = ""
	claim.Status = corev1.PersistentVolumeClaimStatus{}
	if claim.Annotations == nil {
		claim.Annotations = map[string]string{}
	}
	claim.Annotations[managedPVCNodeUIDAnnotation] = string(node.UID)
	claim.Annotations[managedPVCNonceAnnotation] = nonce
	controllerutil.AddFinalizer(claim, managedPVCFinalizer)
	if err := r.Create(ctx, claim); err != nil {
		if errors.IsAlreadyExists(err) {
			return fmt.Errorf("refusing convention-named PVC %s/%s that appeared before this controller persisted its UID reservation", claim.Namespace, claim.Name)
		}
		return fmt.Errorf("reserving managed PVC %s/%s before StatefulSet creation: %w", claim.Namespace, claim.Name, err)
	}
	if claim.UID == "" {
		return fmt.Errorf("API server returned an empty UID for reserved PVC %s/%s", claim.Namespace, claim.Name)
	}
	if err := r.persistManagedNodePVCUID(ctx, node, claim); err != nil {
		// Leave the claim and its nonce in place. The durable pending hash lets a
		// later reconcile finish binding it; deleting on an ambiguous status-write
		// error could instead leave a bound UID pointing at an absent claim.
		return err
	}
	return nil
}

func (r *GarageNodeReconciler) persistManagedNodePVCPendingReservation(
	ctx context.Context, node *garagev1beta1.GarageNode, pvcName, reservationHash string,
) error {
	if node.UID == "" || reservationHash == "" {
		return fmt.Errorf("cannot persist a pending managed PVC reservation without GarageNode UID and nonce hash")
	}
	desiredConditions := slices.Clone(node.Status.Conditions)
	for attempt := 0; attempt < StatusUpdateMaxRetries; attempt++ {
		current := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), current); err != nil {
			return fmt.Errorf("reading GarageNode before reserving managed PVC %s: %w", pvcName, err)
		}
		if current.UID != node.UID {
			return fmt.Errorf("refusing to reserve managed PVC across GarageNode recreation: expected %s, got %s", node.UID, current.UID)
		}
		record, recorded, err := managedNodePVCReservation(current, pvcName)
		if err != nil {
			return err
		}
		if recorded && record.UID != "" {
			return fmt.Errorf("refusing to replace bound managed PVC %s with recorded UID %s", pvcName, record.UID)
		}
		current.Status.Conditions = slices.Clone(desiredConditions)
		updated := garagev1beta1.ManagedNodePVCStatus{Name: pvcName, PendingReservationHash: reservationHash}
		if recorded {
			for i := range current.Status.ManagedPVCs {
				if current.Status.ManagedPVCs[i].Name == pvcName {
					current.Status.ManagedPVCs[i] = updated
				}
			}
		} else {
			current.Status.ManagedPVCs = append(current.Status.ManagedPVCs, updated)
		}
		slices.SortFunc(current.Status.ManagedPVCs, func(a, b garagev1beta1.ManagedNodePVCStatus) int {
			return strings.Compare(a.Name, b.Name)
		})
		if err := r.Status().Update(ctx, current); err != nil {
			if errors.IsConflict(err) {
				continue
			}
			return fmt.Errorf("persisting pending managed PVC %s reservation: %w", pvcName, err)
		}
		*node = *current.DeepCopy()
		return nil
	}
	return fmt.Errorf("persisting pending managed PVC %s reservation exhausted conflict retries", pvcName)
}

func (r *GarageNodeReconciler) persistManagedNodePVCUID(
	ctx context.Context, node *garagev1beta1.GarageNode, pvc *corev1.PersistentVolumeClaim,
) error {
	if node.UID == "" || pvc.UID == "" {
		return fmt.Errorf("cannot persist managed PVC identity without GarageNode and PVC UIDs")
	}
	// Reconciliation may have already changed conditions in memory (for example,
	// clearing Suspended immediately before workload creation). Preserve those
	// desired condition changes while fetching the latest object for the PVC UID
	// reservation; otherwise assigning the fetched object back to node resurrects
	// stale conditions and the later status update never sees their removal.
	desiredConditions := slices.Clone(node.Status.Conditions)
	for attempt := 0; attempt < StatusUpdateMaxRetries; attempt++ {
		current := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(node), current); err != nil {
			return fmt.Errorf("reading GarageNode before persisting managed PVC %s/%s UID: %w", pvc.Namespace, pvc.Name, err)
		}
		if current.UID != node.UID {
			return fmt.Errorf("refusing to persist managed PVC UID across GarageNode recreation: expected %s, got %s", node.UID, current.UID)
		}
		record, recorded, err := managedNodePVCReservation(current, pvc.Name)
		if err != nil {
			return err
		}
		if recorded && record.UID != "" {
			if record.UID != pvc.UID {
				return fmt.Errorf("managed PVC %s/%s UID %s does not match recorded UID %s", pvc.Namespace, pvc.Name, pvc.UID, record.UID)
			}
			current.Status.Conditions = slices.Clone(desiredConditions)
			*node = *current.DeepCopy()
			return nil
		}
		if recorded {
			if pvc.Annotations[managedPVCNodeUIDAnnotation] != string(current.UID) ||
				!managedNodePVCNonceMatches(pvc, record.PendingReservationHash) {
				return fmt.Errorf("refusing to bind managed PVC %s/%s because its nonce does not match the pending GarageNode reservation", pvc.Namespace, pvc.Name)
			}
		}
		current.Status.Conditions = slices.Clone(desiredConditions)
		bound := garagev1beta1.ManagedNodePVCStatus{Name: pvc.Name, UID: pvc.UID}
		if recorded {
			for i := range current.Status.ManagedPVCs {
				if current.Status.ManagedPVCs[i].Name == pvc.Name {
					current.Status.ManagedPVCs[i] = bound
				}
			}
		} else {
			current.Status.ManagedPVCs = append(current.Status.ManagedPVCs, bound)
		}
		slices.SortFunc(current.Status.ManagedPVCs, func(a, b garagev1beta1.ManagedNodePVCStatus) int {
			return strings.Compare(a.Name, b.Name)
		})
		if err := r.Status().Update(ctx, current); err != nil {
			if errors.IsConflict(err) {
				continue
			}
			return fmt.Errorf("persisting managed PVC %s/%s UID %s: %w", pvc.Namespace, pvc.Name, pvc.UID, err)
		}
		*node = *current.DeepCopy()
		return nil
	}
	return fmt.Errorf("persisting managed PVC %s/%s UID exhausted conflict retries", pvc.Namespace, pvc.Name)
}

func validateManagedNodePVCProvenance(
	pvc *corev1.PersistentVolumeClaim,
	node *garagev1beta1.GarageNode,
	statefulSet *appsv1.StatefulSet,
) error {
	controller := metav1.GetControllerOf(pvc)
	if controller != nil {
		if statefulSet != nil && metav1.IsControlledBy(statefulSet, node) &&
			statefulSet.DeletionTimestamp.IsZero() && metav1.IsControlledBy(pvc, statefulSet) {
			return nil
		}
		return fmt.Errorf("refusing to adopt or mutate convention-named PVC %s/%s because its controller owner is not the exact GarageNode StatefulSet", pvc.Namespace, pvc.Name)
	}
	if pinnedUID, present := pvc.Annotations[managedPVCNodeUIDAnnotation]; present {
		if node.UID == "" || pinnedUID != string(node.UID) {
			return fmt.Errorf("refusing to adopt or mutate convention-named PVC %s/%s because its GarageNode UID correlation %q does not match %q", pvc.Namespace, pvc.Name, pinnedUID, node.UID)
		}
		return fmt.Errorf("refusing to adopt or mutate controllerless convention-named PVC %s/%s based only on its user-writable GarageNode UID annotation; exact live StatefulSet/Pod evidence is required", pvc.Namespace, pvc.Name)
	}
	return fmt.Errorf("refusing to adopt or mutate convention-named PVC %s/%s without strong evidence from the live exact-owned StatefulSet; labels and annotations alone are not ownership", pvc.Namespace, pvc.Name)
}

func statefulSetDeclaresPVC(statefulSet *appsv1.StatefulSet, pvcName string) bool {
	if statefulSet == nil {
		return false
	}
	for i := range statefulSet.Spec.VolumeClaimTemplates {
		if fmt.Sprintf("%s-%s-0", statefulSet.Spec.VolumeClaimTemplates[i].Name, statefulSet.Name) == pvcName {
			return true
		}
	}
	return false
}

func (r *GarageNodeReconciler) ensureManagedNodePVCProvenance(
	ctx context.Context,
	pvc *corev1.PersistentVolumeClaim,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) error {
	if !pvc.DeletionTimestamp.IsZero() {
		return fmt.Errorf("refusing terminating convention-named PVC %s/%s UID %s", pvc.Namespace, pvc.Name, pvc.UID)
	}
	record, recorded, err := managedNodePVCReservation(node, pvc.Name)
	if err != nil {
		return err
	}
	handoff, handoffErr := retainedAutoModePVCHandoff(cluster, node, pvc)
	if handoffErr != nil {
		return handoffErr
	}
	if handoff != nil {
		if recorded && record.UID != "" && record.UID != pvc.UID {
			return fmt.Errorf("refusing retained Auto-mode PVC %s/%s UID %s because replacement GarageNode status records UID %s", pvc.Namespace, pvc.Name, pvc.UID, record.UID)
		}
		if err := r.ensureManagedNodePVCReplacementBarrier(ctx, pvc, node); err != nil {
			return err
		}
		if !recorded || record.UID == "" {
			if err := r.persistManagedNodePVCUID(ctx, node, pvc); err != nil {
				return err
			}
		}
		if pvc.Annotations[managedPVCNodeUIDAnnotation] != string(node.UID) {
			patch := client.MergeFrom(pvc.DeepCopy())
			if pvc.Annotations == nil {
				pvc.Annotations = map[string]string{}
			}
			pvc.Annotations[managedPVCNodeUIDAnnotation] = string(node.UID)
			if err := r.Patch(ctx, pvc, patch); err != nil {
				return fmt.Errorf("transferring retained Auto-mode PVC %s/%s to GarageNode UID %s: %w", pvc.Namespace, pvc.Name, node.UID, err)
			}
		}
		return nil
	}
	if recorded && record.UID != "" {
		if pvc.UID == "" || pvc.UID != record.UID {
			return fmt.Errorf("refusing managed PVC %s/%s UID %s because GarageNode status records UID %s", pvc.Namespace, pvc.Name, pvc.UID, record.UID)
		}
		return r.ensureManagedNodePVCReplacementBarrier(ctx, pvc, node)
	}
	if recorded {
		if node.UID == "" || pvc.Annotations[managedPVCNodeUIDAnnotation] != string(node.UID) ||
			!managedNodePVCNonceMatches(pvc, record.PendingReservationHash) {
			return fmt.Errorf("refusing convention-named PVC %s/%s because its nonce does not match the pending GarageNode reservation", pvc.Namespace, pvc.Name)
		}
		if err := r.ensureManagedNodePVCReplacementBarrier(ctx, pvc, node); err != nil {
			return err
		}
		return r.persistManagedNodePVCUID(ctx, node, pvc)
	}
	// Legacy migration is an identity decision too. Re-read the exact
	// StatefulSet authoritatively so a deleted/replaced workload lingering in the
	// cache cannot authorize adoption of a same-name claim.
	statefulSet := &appsv1.StatefulSet{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Name: node.Name, Namespace: cluster.Namespace,
	}, statefulSet); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("reading authoritative GarageNode StatefulSet before legacy PVC migration: %w", err)
		}
		statefulSet = nil
	}
	labels := pvc.GetLabels()
	correlatedUID := pvc.Annotations[managedPVCNodeUIDAnnotation]
	legacyShape := metav1.GetControllerOf(pvc) == nil && (correlatedUID == "" || correlatedUID == string(node.UID)) &&
		labels[labelAppManagedBy] == operatorName && labels[labelAppComponent] == nodeValue &&
		labels[labelGarageNode] == node.Name && labels[labelCluster] == cluster.Name
	if legacyShape {
		if err := r.validateLegacyManagedNodePVCLivePod(ctx, pvc, node, statefulSet); err != nil {
			return err
		}
	} else if err := validateManagedNodePVCProvenance(pvc, node, statefulSet); err != nil {
		return err
	}
	// Fence deletion and same-name recreation before persisting the legacy
	// claim's UID. Otherwise a crash after the status write could leave a short
	// window in which the live-Pod proof disappears and the authenticated claim
	// is replaced before the next reconcile establishes the barrier.
	if err := r.ensureManagedNodePVCReplacementBarrier(ctx, pvc, node); err != nil {
		return err
	}
	if err := r.persistManagedNodePVCUID(ctx, node, pvc); err != nil {
		return err
	}
	if node.UID == "" || pvc.Annotations[managedPVCNodeUIDAnnotation] != "" {
		return nil
	}
	patch := client.MergeFrom(pvc.DeepCopy())
	if pvc.Annotations == nil {
		pvc.Annotations = map[string]string{}
	}
	pvc.Annotations[managedPVCNodeUIDAnnotation] = string(node.UID)
	if err := r.Patch(ctx, pvc, patch); err != nil {
		return fmt.Errorf("pinning convention-named PVC %s/%s to GarageNode UID %s: %w", pvc.Namespace, pvc.Name, node.UID, err)
	}
	return nil
}

func (r *GarageNodeReconciler) ensureManagedNodePVCReplacementBarrier(
	ctx context.Context, pvc *corev1.PersistentVolumeClaim, node *garagev1beta1.GarageNode,
) error {
	statefulSet := &appsv1.StatefulSet{}
	exactStatefulSetControl := false
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Name: node.Name, Namespace: pvc.Namespace,
	}, statefulSet); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("reading authoritative StatefulSet before updating managed PVC replacement barrier: %w", err)
		}
	} else {
		controller := metav1.GetControllerOf(pvc)
		exactStatefulSetControl = node.UID != "" && statefulSet.DeletionTimestamp.IsZero() &&
			metav1.IsControlledBy(statefulSet, node) && controller != nil &&
			controller.UID == statefulSet.UID && controller.Kind == "StatefulSet" &&
			controller.APIVersion == appsv1.SchemeGroupVersion.String()
	}

	hasBarrier := controllerutil.ContainsFinalizer(pvc, managedPVCFinalizer)
	if exactStatefulSetControl == !hasBarrier {
		return nil
	}
	if exactStatefulSetControl {
		controllerutil.RemoveFinalizer(pvc, managedPVCFinalizer)
	} else {
		controllerutil.AddFinalizer(pvc, managedPVCFinalizer)
	}
	if err := r.Update(ctx, pvc); err != nil {
		return fmt.Errorf("updating managed PVC %s/%s replacement barrier: %w", pvc.Namespace, pvc.Name, err)
	}
	if !exactStatefulSetControl {
		current := &corev1.PersistentVolumeClaim{}
		if err := r.nodeLocalPoolReader().Get(ctx, client.ObjectKeyFromObject(pvc), current); err != nil {
			return fmt.Errorf("verifying managed PVC replacement barrier: %w", err)
		}
		if current.UID != pvc.UID || !current.DeletionTimestamp.IsZero() ||
			!controllerutil.ContainsFinalizer(current, managedPVCFinalizer) {
			return fmt.Errorf("managed PVC %s/%s changed identity or began terminating while establishing its replacement barrier", pvc.Namespace, pvc.Name)
		}
		*pvc = *current
	}
	return nil
}

func (r *GarageNodeReconciler) validateLegacyManagedNodePVCLivePod(
	ctx context.Context,
	pvc *corev1.PersistentVolumeClaim,
	node *garagev1beta1.GarageNode,
	statefulSet *appsv1.StatefulSet,
) error {
	if statefulSet == nil || !metav1.IsControlledBy(statefulSet, node) ||
		!statefulSet.DeletionTimestamp.IsZero() || !statefulSetDeclaresPVC(statefulSet, pvc.Name) {
		return fmt.Errorf("refusing legacy convention-named PVC %s/%s without an exact live GarageNode-controlled StatefulSet declaration; labels alone are not ownership", pvc.Namespace, pvc.Name)
	}
	pod := &corev1.Pod{}
	podKey := types.NamespacedName{Name: statefulSet.Name + "-0", Namespace: statefulSet.Namespace}
	if err := r.nodeLocalPoolReader().Get(ctx, podKey, pod); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("refusing legacy convention-named PVC %s/%s because exact StatefulSet Pod %s is absent", pvc.Namespace, pvc.Name, podKey)
		}
		return fmt.Errorf("reading exact StatefulSet Pod %s before legacy PVC adoption: %w", podKey, err)
	}
	if !pod.DeletionTimestamp.IsZero() || !metav1.IsControlledBy(pod, statefulSet) {
		return fmt.Errorf("refusing legacy convention-named PVC %s/%s because Pod %s is deleting or is not controlled by the exact StatefulSet UID %s", pvc.Namespace, pvc.Name, podKey, statefulSet.UID)
	}
	for i := range pod.Spec.Volumes {
		claim := pod.Spec.Volumes[i].PersistentVolumeClaim
		if claim != nil && claim.ClaimName == pvc.Name {
			return nil
		}
	}
	return fmt.Errorf("refusing legacy convention-named PVC %s/%s because exact live Pod %s does not reference it", pvc.Namespace, pvc.Name, podKey)
}

// stsPVCRetentionPolicy translates the owning tier's explicit PVC policy into
// the per-GarageNode StatefulSet policy. Nil leaves Kubernetes' Retain/Retain
// default, which is the established default for both storage and unified
// per-GarageNode gateway identities.
// pvcRetentionDelete is the API string for "delete PVCs when the STS is
// deleted/scaled" — matches the enum value in the v1beta2 CRD.
const pvcRetentionDelete = "Delete"

// stsPVCRetentionPolicy returns the desired retention policy, spelling out the
// API server's own default when the user set none.
//
// Returning nil here would be silently corrosive: the API server defaults the
// stored StatefulSet to Retain/Retain, so the reconcile-time
// DeepEqual(existing, desired) compared a defaulted struct against nil, decided
// the policy had "changed", and rewrote the StatefulSet on every single pass.
// Nearly no cluster sets pvcRetentionPolicy, so that hot loop ran for nearly
// every GarageNode — burning API writes and slowing every other reconcile.
// Retain/Retain is exactly what the API server was already storing, so this is
// the same behaviour, just stated explicitly enough to compare equal.
func stsPVCRetentionPolicy(cluster *garagev1beta2.GarageCluster, node *garagev1beta1.GarageNode) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
	apiServerDefault := func() *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
		return &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
			WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
			WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
		}
	}
	if node.Spec.Gateway {
		if cluster.Spec.Gateway == nil || cluster.Spec.Gateway.PVCRetentionPolicy == nil {
			return apiServerDefault()
		}
		return translatePVCRetentionPolicy(cluster.Spec.Gateway.PVCRetentionPolicy)
	}
	if !cluster.HasStorageTier() || cluster.Spec.Storage.PVCRetentionPolicy == nil {
		return apiServerDefault()
	}
	return translatePVCRetentionPolicy(cluster.Spec.Storage.PVCRetentionPolicy)
}

func translatePVCRetentionPolicy(rp *garagev1beta2.PVCRetentionPolicy) *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy {
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

// cleanupOwnerlessManagedNodePVCs closes the gap between reserving an exact
// PVC identity and creating its StatefulSet. Kubernetes' StatefulSet retention
// policy cannot delete a claim that the StatefulSet never came to control, so
// Delete policy handles those exact controller reservations here. Retain policy
// deliberately leaves every claim untouched.
func (r *GarageNodeReconciler) cleanupOwnerlessManagedNodePVCs(
	ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster,
) error {
	policy := stsPVCRetentionPolicy(cluster, node)
	deleteOwnerless := policy != nil && policy.WhenDeleted == appsv1.DeletePersistentVolumeClaimRetentionPolicyType

	statefulSet := &appsv1.StatefulSet{}
	statefulSetExists := false
	reader := r.nodeLocalPoolReader()
	if err := reader.Get(ctx, types.NamespacedName{Name: node.Name, Namespace: cluster.Namespace}, statefulSet); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("reading GarageNode StatefulSet before managed PVC finalization: %w", err)
		}
	} else {
		statefulSetExists = metav1.IsControlledBy(statefulSet, node)
	}

	for i := range node.Status.ManagedPVCs {
		record, found, err := managedNodePVCReservation(node, node.Status.ManagedPVCs[i].Name)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		key := types.NamespacedName{Name: record.Name, Namespace: cluster.Namespace}
		if err := reader.Get(ctx, key, pvc); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("reading managed PVC %s before GarageNode finalization: %w", key, err)
		}

		exactReservation := record.UID != "" && pvc.UID == record.UID
		if record.PendingReservationHash != "" {
			exactReservation = pvc.Annotations[managedPVCNodeUIDAnnotation] == string(node.UID) &&
				managedNodePVCNonceMatches(pvc, record.PendingReservationHash)
		}
		if !exactReservation || pvc.UID == "" {
			// A same-name replacement or an unforgeable pending-reservation
			// mismatch is not ours to delete.
			continue
		}
		if controllerutil.ContainsFinalizer(pvc, managedPVCFinalizer) {
			controllerutil.RemoveFinalizer(pvc, managedPVCFinalizer)
			if err := r.Update(ctx, pvc); err != nil {
				return fmt.Errorf("releasing managed PVC %s replacement barrier during GarageNode finalization: %w", key, err)
			}
		}
		if !deleteOwnerless {
			continue
		}

		controller := metav1.GetControllerOf(pvc)
		controlledByExactStatefulSet := statefulSetExists && controller != nil &&
			controller.UID == statefulSet.UID && controller.Kind == "StatefulSet" &&
			controller.APIVersion == appsv1.SchemeGroupVersion.String()
		if controlledByExactStatefulSet {
			continue
		}

		uid := pvc.UID
		if err := r.Delete(ctx, pvc, &client.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting ownerless managed PVC %s UID %s: %w", key, uid, err)
		}
	}
	return nil
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

	reader := r.nodeLocalPoolReader()
	existingStatefulSet := &appsv1.StatefulSet{}
	if err := reader.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, existingStatefulSet); err == nil {
		if !metav1.IsControlledBy(existingStatefulSet, node) {
			return fmt.Errorf("refusing PVC expansion because StatefulSet %s/%s is not controlled by GarageNode %s/%s UID %s", existingStatefulSet.Namespace, existingStatefulSet.Name, node.Namespace, node.Name, node.UID)
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("get StatefulSet %s before PVC expansion: %w", stsName, err)
	}

	for _, w := range wants {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := reader.Get(ctx, types.NamespacedName{Name: w.name, Namespace: cluster.Namespace}, pvc); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("get PVC %s: %w", w.name, err)
		}
		if err := r.ensureManagedNodePVCProvenance(ctx, pvc, node, cluster); err != nil {
			return err
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

// lookupPVCCapacity returns a TOML-ready exact byte count for
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
		return garageBytesize(&req)
	}
	if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok && !cap.IsZero() {
		return garageBytesize(&cap)
	}
	return ""
}

// emptyDirSource builds an EmptyDir volume source, honoring an optional size as
// the medium's sizeLimit. A sized EmptyDir bounds ephemeral scratch so a runaway
// pod can't exhaust the node's ephemeral storage (#283) — this is what
// `type: EmptyDir` + `size: 10Gi` (the garage-ephemeral-limited sample) means.
// Without a size the volume is unbounded (limited only by node capacity),
// preserving prior behavior for sizeless ephemeral clusters.
func emptyDirSource(size *resource.Quantity) *corev1.EmptyDirVolumeSource {
	src := &corev1.EmptyDirVolumeSource{}
	if size != nil && !size.IsZero() {
		s := size.DeepCopy()
		src.SizeLimit = &s
	}
	return src
}

// buildNodeVolumesAndMounts returns volumes and volume mounts for a GarageNode's StatefulSet.
func (r *GarageNodeReconciler) buildNodeVolumesAndMounts(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) ([]corev1.Volume, []corev1.VolumeMount) {
	configName := cluster.Name + "-config"
	if nodeHasConfigOverrides(node) {
		configName = garageNodeConfigBaseName(cluster, node)
	}
	return r.buildNodeVolumesAndMountsForConfig(node, cluster, configName)
}

func (r *GarageNodeReconciler) buildNodeVolumesAndMountsForConfig(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	configName string,
) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
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

	volumes := []corev1.Volume{
		{
			Name:         configVolumeName,
			VolumeSource: garageConfigVolumeSource(cluster, configName),
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
				vol.VolumeSource = corev1.VolumeSource{EmptyDir: emptyDirSource(dp.Size)}
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
		// Gateway data is always EmptyDir (no size field); an EmptyDir storage
		// data volume carries its size through as the sizeLimit (#283).
		var dataSize *resource.Quantity
		if node.Spec.Storage != nil && node.Spec.Storage.Data != nil {
			dataSize = node.Spec.Storage.Data.Size
		}
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolName,
			VolumeSource: corev1.VolumeSource{EmptyDir: emptyDirSource(dataSize)},
		})
		if node.Spec.Gateway {
			volumes = append(volumes, gatewayDataMarkerVolume())
			volumeMounts = append(volumeMounts, gatewayDataMarkerMount())
		}
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
				VolumeSource: corev1.VolumeSource{EmptyDir: emptyDirSource(node.Spec.Storage.Metadata.Size)},
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

	credentialVolumes, credentialMounts := buildGarageCredentialVolumesAndMounts(cluster, node.Spec.Gateway)
	volumes = append(volumes, credentialVolumes...)
	volumeMounts = append(volumeMounts, credentialMounts...)

	return volumes, volumeMounts
}

// buildNodeVolumeClaimTemplates returns PVC templates for a GarageNode's StatefulSet.
// PVCs inherit the per-node labels so e2e selectors and observability tooling can
// filter "all PVCs of cluster X" via garage.rajsingh.info/cluster=<name>.
func (r *GarageNodeReconciler) buildNodeVolumeClaimTemplates(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) []corev1.PersistentVolumeClaim {
	var templates []corev1.PersistentVolumeClaim
	labels := r.labelsForNode(node, cluster)

	addMetadata := func(pvc corev1.PersistentVolumeClaim, volume *garagev1beta1.NodeVolumeConfig) corev1.PersistentVolumeClaim {
		if pvc.Labels == nil {
			pvc.Labels = map[string]string{}
		}
		if volume != nil {
			for k, v := range volume.Labels {
				pvc.Labels[k] = v
			}
			if len(volume.Annotations) > 0 {
				pvc.Annotations = maps.Clone(volume.Annotations)
			}
		}
		for k, v := range labels {
			pvc.Labels[k] = v
		}
		if node.UID != "" {
			if pvc.Annotations == nil {
				pvc.Annotations = map[string]string{}
			}
			pvc.Annotations[managedPVCNodeUIDAnnotation] = string(node.UID)
		}
		return pvc
	}
	applySelector := func(pvc corev1.PersistentVolumeClaim, volume *garagev1beta1.NodeVolumeConfig, volumeName string, dataPathIndex int) corev1.PersistentVolumeClaim {
		var selector *metav1.LabelSelector
		if volume != nil {
			selector = volume.Selector
		}
		if selector == nil {
			selector = inheritedManagedPVCSelector(node, cluster, volumeName, dataPathIndex)
		}
		if selector != nil {
			pvc.Spec.Selector = selector.DeepCopy()
		}
		return pvc
	}

	if node.Spec.Storage == nil {
		return templates
	}

	// Metadata PVC (if not using existingClaim and not EmptyDir)
	if meta := node.Spec.Storage.Metadata; meta != nil {
		if meta.ExistingClaim == "" && meta.Type != garagev1beta1.VolumeTypeEmptyDir && meta.Size != nil {
			pvc := addMetadata(buildBasePVC(metadataVolName, *meta.Size, meta.StorageClassName, meta.AccessModes), meta)
			templates = append(templates, applySelector(pvc, meta, metadataVolName, -1))
		}
	} else {
		// Default metadata PVC when storage is specified but metadata config is omitted
		templates = append(templates, addMetadata(buildBasePVC(metadataVolName, resource.MustParse("10Gi"), nil, nil), nil))
	}

	// Data PVC(s)
	if !node.Spec.Gateway {
		switch {
		case nodeHasMultiHDD(node):
			for i, dp := range node.Spec.Storage.DataPaths {
				if dp.ExistingClaim != "" || dp.Type == garagev1beta1.VolumeTypeEmptyDir || dp.Size == nil {
					continue
				}
				pvc := addMetadata(buildBasePVC(nodeMultiHDDDataVolName(i), *dp.Size, dp.StorageClassName, dp.AccessModes), &dp)
				templates = append(templates, applySelector(pvc, &dp, dataVolName, i))
			}
		default:
			if data := node.Spec.Storage.Data; data != nil && data.ExistingClaim == "" && data.Type != garagev1beta1.VolumeTypeEmptyDir && data.Size != nil {
				pvc := addMetadata(buildBasePVC(dataVolName, *data.Size, data.StorageClassName, data.AccessModes), data)
				templates = append(templates, applySelector(pvc, data, dataVolName, -1))
			}
		}
	}

	return templates
}

// inheritedManagedPVCSelector is a compatibility fallback for an old
// operator-generated child that predates NodeVolumeConfig.selector. It only
// affects a newly created/missing StatefulSet claim template; reconciliation
// never rewrites an existing StatefulSet or already-created PVC. Explicit
// GarageNode selectors always win, including on ordinary Manual nodes.
func inheritedManagedPVCSelector(
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	volumeName string,
	dataPathIndex int,
) *metav1.LabelSelector {
	if !garageNodeUsesManagedPVCProfile(node, cluster) {
		return nil
	}
	if node.Spec.Gateway {
		if cluster.Spec.Gateway != nil && cluster.Spec.Gateway.Metadata != nil {
			return cluster.Spec.Gateway.Metadata.Selector
		}
		return nil
	}
	if cluster.Spec.Storage == nil {
		return nil
	}
	switch volumeName {
	case metadataVolName:
		if cluster.Spec.Storage.Metadata != nil {
			return cluster.Spec.Storage.Metadata.Selector
		}
	case dataVolName:
		data := cluster.Spec.Storage.Data
		if data == nil {
			return nil
		}
		if dataPathIndex >= 0 && dataPathIndex < len(data.Paths) &&
			data.Paths[dataPathIndex].Volume != nil && data.Paths[dataPathIndex].Volume.Selector != nil {
			return data.Paths[dataPathIndex].Volume.Selector
		}
		return data.Selector
	}
	return nil
}

func garageNodeUsesManagedPVCProfile(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) bool {
	if node == nil || cluster == nil ||
		node.Spec.External != nil || isNodeLocalPoolBacked(node) ||
		node.Spec.ClusterRef.Name != cluster.Name {
		return false
	}
	refNamespace := node.Spec.ClusterRef.Namespace
	if refNamespace == "" {
		refNamespace = node.Namespace
	}
	if refNamespace != cluster.Namespace {
		return false
	}
	if node.Labels[labelAppManagedBy] != managedByOperatorValue ||
		!hasExactGarageClusterControllerReference(node, cluster) {
		return false
	}
	if node.Spec.Gateway {
		_, canonical := parseAutoModeGatewayOrdinal(autoNodeSlotForCycle(node), cluster.Name)
		return canonical && cluster.Spec.LayoutPolicy != LayoutPolicyManual &&
			cluster.HasStorageTier() && cluster.HasGatewayTier()
	}
	_, canonical := parseAutoModeOrdinal(autoNodeSlotForCycle(node), cluster.Name)
	return canonical && cluster.EffectiveStorageLayoutPolicy() != LayoutPolicyManual
}

// applyInheritedManagedPVCSelectors snapshots the parent profile into a cycle
// replacement before it stops being a direct GarageCluster child. This keeps
// old pre-selector generated nodes repairable without trusting spoofable labels
// on the sibling or mutating the original live PVC topology.
func applyInheritedManagedPVCSelectors(
	spec *garagev1beta1.GarageNodeSpec,
	source *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) {
	if spec == nil || spec.Storage == nil || !garageNodeUsesManagedPVCProfile(source, cluster) {
		return
	}
	if metadata := spec.Storage.Metadata; metadata != nil && metadata.Selector == nil {
		if selector := inheritedManagedPVCSelector(source, cluster, metadataVolName, -1); selector != nil {
			metadata.Selector = selector.DeepCopy()
		}
	}
	if data := spec.Storage.Data; data != nil && data.Selector == nil {
		if selector := inheritedManagedPVCSelector(source, cluster, dataVolName, -1); selector != nil {
			data.Selector = selector.DeepCopy()
		}
	}
	for i := range spec.Storage.DataPaths {
		if spec.Storage.DataPaths[i].Selector == nil {
			if selector := inheritedManagedPVCSelector(source, cluster, dataVolName, i); selector != nil {
				spec.Storage.DataPaths[i].Selector = selector.DeepCopy()
			}
		}
	}
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
	labels := map[string]string{
		labelAppName:      defaultAppName,
		labelAppInstance:  cluster.Name,
		labelAppComponent: nodeValue,
		labelAppManagedBy: operatorName,
		labelCluster:      cluster.Name,
		labelTier:         tier,
		labelGarageNode:   node.Name,
	}
	if tier == tierStorage && !isNodeLocalPoolBacked(node) {
		labels[labelStorageGroup] = storageGroupDefault
	}
	return labels
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

func (r *GarageNodeReconciler) reconcileNode(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	layoutOwner *garagev1beta2.GarageCluster,
) error {
	log := logf.FromContext(ctx)
	if layoutOwner == nil {
		return fmt.Errorf("canonical Garage layout owner is required")
	}

	// Discover or use the provided node ID. If a previously reconciled node is
	// currently offline, discovery from its pod is impossible; retain the
	// observed status ID so layout-only metadata (notably rpc-address) can still
	// be repaired through another healthy cluster admin endpoint. A live
	// discovery always wins, so replacing a pod's persisted identity is still
	// detected rather than masked by stale status.
	recoveryNodeID := canonicalGarageNodeID(node.Annotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID])
	var layout *garage.ClusterLayout
	var managedIdentity *managedPodIdentity
	usingObservedNodeID := false
	nodeID := canonicalGarageNodeID(node.Spec.NodeID)
	if nodeID != "" && node.Spec.External == nil && recoveryNodeID == "" {
		var liveNodeID string
		var err error
		if r.managedNodeIDGetter != nil {
			liveNodeID, err = r.managedNodeIDGetter(ctx, node, cluster)
		} else {
			managedIdentity, err = r.discoverNodeIdentityDirect(ctx, node, cluster)
			if err == nil {
				liveNodeID = managedIdentity.nodeID
			}
		}
		if err != nil {
			return fmt.Errorf("verifying managed spec.nodeId against the exact live process: %w", err)
		}
		liveNodeID = canonicalGarageNodeID(liveNodeID)
		if !isValidGarageNodeID(liveNodeID) {
			return fmt.Errorf("managed Garage process reported invalid node ID %q while verifying spec.nodeId", liveNodeID)
		}
		if liveNodeID != nodeID {
			return fmt.Errorf(
				"%w: managed spec.nodeId pins identity %s, but the exact live process reports %s; refusing every layout and status mutation",
				errLayoutMutationPending, shortID(nodeID), shortID(liveNodeID),
			)
		}
		nodeID = liveNodeID
	}
	if recoveryNodeID != "" {
		if !isNodeLocalPoolBacked(node) {
			return fmt.Errorf("annotation %s is only valid on an internal node-local-pool GarageNode", garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID)
		}
		if node.Spec.NodeID != "" {
			return fmt.Errorf("node-local-pool recovery requires live process discovery; spec.nodeId must be empty")
		}
		podIPs, err := r.getPodIPs(ctx, node, cluster)
		if err != nil {
			return fmt.Errorf("reading node-local-pool Pod addresses for identity recovery: %w", err)
		}
		liveIdentity, err := r.discoverNodeLocalPoolRecoveryNodeIdentity(ctx, node, cluster)
		if err != nil {
			return fmt.Errorf("discovering the node-local-pool process identity directly: %w", err)
		}
		managedIdentity = liveIdentity
		liveNodeID := liveIdentity.nodeID
		liveNodeID = canonicalGarageNodeID(liveNodeID)
		if !isValidGarageNodeID(liveNodeID) {
			return fmt.Errorf("node-local-pool process reported invalid Garage node ID %q", liveNodeID)
		}
		if !strings.EqualFold(liveNodeID, recoveryNodeID) {
			return fmt.Errorf(
				"%w: node-local pool %q on Kubernetes Node %q is pinned to Garage identity %s, but its live HostPath process reports %s; refusing to persist or assign the replacement identity",
				errLayoutMutationPending,
				node.Spec.NodeLocalPoolName,
				node.Spec.KubernetesNodeName,
				shortID(recoveryNodeID),
				shortID(liveNodeID),
			)
		}
		nodeID = liveNodeID

		// A directly reached cold process might not yet be visible to the
		// cluster-wide Admin endpoint. Reconnect the exact pinned identity before
		// asking that endpoint to prove its committed role.
		observedNodeID, observedErr := r.discoverNodeIDFromAdminAPI(ctx, garageClient, podIPs)
		if observedErr != nil || !strings.EqualFold(observedNodeID, liveNodeID) {
			if err := r.connectNodeToCluster(ctx, garageClient, liveNodeID, liveIdentity.podIP, cluster); err != nil {
				return fmt.Errorf("connecting pinned node-local-pool identity %s to the cluster: %w", shortID(liveNodeID), err)
			}
		}

		layout, err = garageClient.GetClusterLayout(ctx)
		if err != nil {
			return fmt.Errorf("reading committed Garage layout before node-local-pool recovery: %w", err)
		}
		expectedZone := r.effectiveNodeZone(ctx, node, cluster)
		if err := validatePinnedNodeLocalPoolRecoveryRole(
			cluster,
			layout,
			recoveryNodeID,
			node.Spec.NodeLocalPoolName,
			node.Spec.KubernetesNodeName,
			expectedZone,
		); err != nil {
			return fmt.Errorf(
				"%w: Garage identity %s is not the committed local role for node-local pool %q on Kubernetes Node %q: %v; refusing to create or repair a role from retained HostPath data",
				errLayoutMutationPending,
				shortID(liveNodeID),
				node.Spec.NodeLocalPoolName,
				node.Spec.KubernetesNodeName,
				err,
			)
		}
	} else if nodeID == "" {
		// The cluster-wide status endpoint is useful for connectivity, but it is
		// not an authoritative identity source: a replacement Pod can reuse an IP
		// while Garage still reports the previous process. Query GetNodeInfo(self)
		// on the exact ownership-proven Pod first and use the peer list only to
		// decide whether that authenticated identity needs to be connected.
		var identity *managedPodIdentity
		var discoverErr error
		if isNodeLocalPoolBacked(node) {
			identity, discoverErr = r.discoverNodeLocalPoolRecoveryNodeIdentity(ctx, node, cluster)
		} else {
			identity, discoverErr = r.discoverNodeIdentityDirect(ctx, node, cluster)
		}
		discovered := ""
		if discoverErr == nil {
			discovered = canonicalGarageNodeID(identity.nodeID)
			if !isValidGarageNodeID(discovered) {
				return fmt.Errorf("managed Garage process reported invalid node ID %q", discovered)
			}
		}
		var (
			usedObserved bool
			err          error
		)
		nodeID, usedObserved, err = nodeIDFromDiscovery(discovered, discoverErr, node.Status.NodeID)
		if err != nil {
			return fmt.Errorf("failed to discover node ID: %w", err)
		}
		if usedObserved {
			if err := r.validateManagedObservedIdentityFallback(ctx, node, cluster); err != nil {
				return fmt.Errorf(
					"%w: refusing stale status.nodeId fallback after direct managed-process discovery failed: %v (direct discovery: %v)",
					errLayoutMutationPending, err, discoverErr,
				)
			}
			usingObservedNodeID = true
			log.Info("Node unavailable; using previously observed node ID for layout reconciliation", "nodeID", nodeID)
		} else {
			managedIdentity = identity
			podIPs, err := r.getPodIPs(ctx, node, cluster)
			if err != nil {
				return fmt.Errorf("reading managed Pod addresses after direct identity discovery: %w", err)
			}
			observedNodeID, observedErr := r.discoverNodeIDFromAdminAPI(ctx, garageClient, podIPs)
			if observedErr != nil || canonicalGarageNodeID(observedNodeID) != discovered {
				log.Info("Connecting exact managed identity to cluster", "nodeID", discovered, "podIP", identity.podIP)
				if err := r.connectNodeToCluster(ctx, garageClient, discovered, identity.podIP, cluster); err != nil {
					return fmt.Errorf("connecting exact managed identity %s to the cluster: %w", shortID(discovered), err)
				}
			}
		}
	}

	if nodeID == "" {
		return fmt.Errorf("node ID not found and could not be discovered")
	}

	nodeID = canonicalGarageNodeID(nodeID)
	previousNodeID := canonicalGarageNodeID(node.Status.NodeID)
	identityChanged := previousNodeID != "" && previousNodeID != nodeID
	if err := r.validateGarageNodeIdentityOwner(ctx, node, cluster, nodeID); err != nil {
		return err
	}

	// Read and validate an existing role before persisting a first observation.
	// Otherwise copied HostPath metadata can turn another member's identity into
	// durable status and a later reconciliation may mistake its pool/node tags
	// for ordinary repairable drift.
	if layout == nil {
		var err error
		layout, err = garageClient.GetClusterLayout(ctx)
		if err != nil {
			return fmt.Errorf("failed to get cluster layout before validating Garage identity ownership: %w", err)
		}
	}
	var existingRole *garage.LayoutRole
	var previousRole *garage.LayoutRole
	for i := range layout.Roles {
		role := &layout.Roles[i]
		if canonicalGarageNodeID(role.ID) == nodeID {
			existingRole = role
		}
		if identityChanged && canonicalGarageNodeID(role.ID) == previousNodeID {
			previousRole = role
		}
	}
	if isNodeLocalPoolBacked(node) && existingRole != nil {
		expectedZone := r.effectiveNodeZone(ctx, node, cluster)
		if err := validatePinnedNodeLocalPoolRecoveryRole(
			cluster, layout, nodeID, node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName, expectedZone,
		); err != nil {
			return fmt.Errorf(
				"IdentityCollision: discovered Garage identity %s is already committed to a different owner than node-local pool %q on Kubernetes Node %q: %w",
				shortID(nodeID), node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName, err,
			)
		}
	}
	if previousNodeID == "" {
		// Persist discovery in a separate reconciliation boundary before any
		// Garage layout mutation. Besides letting sibling reconcilers authorize a
		// staged bootstrap role, this closes a deletion-safety crash window: a
		// role must never be committed while the owning GarageNode still has an
		// empty durable status.nodeId that could later be mistaken for a process
		// which never joined the layout.
		observedPodUID := ""
		if managedIdentity != nil {
			if err := r.revalidateManagedPodIdentity(ctx, node, cluster, managedIdentity); err != nil {
				return fmt.Errorf("%w: revalidating the exact managed Pod before persisting its first Garage identity: %v", errLayoutMutationPending, err)
			}
			observedPodUID = string(managedIdentity.podUID)
		}
		apply := func() {
			node.Status.NodeID = nodeID
			if observedPodUID != "" {
				node.Status.ObservedPodUID = observedPodUID
			}
		}
		apply()
		if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
			return fmt.Errorf("persisting first discovered Garage node ID before layout mutation: %w", err)
		}
		return fmt.Errorf("%w: persisted Garage node identity %s before its first layout mutation", errLayoutMutationPending, shortID(nodeID))
	}

	desiredRole, err := r.desiredGarageNodeRoleChange(ctx, node, cluster, nodeID)
	if err != nil {
		return err
	}
	capacity := desiredRole.Capacity
	desiredTags := desiredRole.Tags
	zone := desiredRole.Zone
	node.Status.Zone = zone
	if identityChanged {
		previousStoresBlocks := previousRole != nil && previousRole.Capacity != nil && *previousRole.Capacity > 0
		desiredStoresBlocks := capacity != nil && *capacity > 0
		if previousStoresBlocks || desiredStoresBlocks {
			// A replacement process is already running, but status.nodeId is the
			// durable owner of the unavailable source. Applying a role for the new
			// identity before the old one is retired would create two data-bearing
			// identities behind one GarageNode; a crash or blocked drain could then
			// orphan the replacement role. Keep the replacement unassigned and retain
			// the exact old identity so the administrator can invoke the normal
			// destination-only lost-source workflow. That workflow fences this process
			// before the old role is removed and the GarageNode is deleted/recreated.
			if err := r.invalidateManagedGarageNodeIdentityObservation(ctx, node); err != nil {
				return fmt.Errorf("invalidating stale managed-pod identity evidence: %w", err)
			}
			return fmt.Errorf(
				"%w: GarageNode %s discovered replacement storage identity %s while status still owns %s; refusing to assign the replacement before the previous positive-capacity identity is retired: atomically set %s=%q and %s=%s, then follow the lost-source drain and delete workflow",
				errLayoutMutationPending, node.Name, shortID(nodeID), shortID(previousNodeID),
				garagev1beta1.AnnotationDrain, annotationTrue,
				garagev1beta1.AnnotationAcknowledgeLostSource, previousNodeID,
			)
		}
	}
	if existingRole != nil {
		existingStoresBlocks := existingRole.Capacity != nil && *existingRole.Capacity > 0
		desiredStoresBlocks := capacity != nil && *capacity > 0
		if existingStoresBlocks != desiredStoresBlocks {
			return fmt.Errorf(
				"refusing to convert GarageNode %s identity %s between storage and gateway roles in place; delete and drain the old identity, then create a distinct node in the other tier",
				node.Name, shortID(nodeID),
			)
		}
	}
	gatewayReplacement := identityChanged && node.Spec.Gateway
	if gatewayReplacement {
		if err := r.ensureCapacitylessGarageNodeRetirementIntent(
			ctx, node, layoutOwner, []string{previousNodeID},
		); err != nil {
			return err
		}
		if err := requireStorageDrainAuthorizedTargets(
			layoutOwner, storageDrainActorForNode(node), []string{previousNodeID}, nil,
		); err != nil {
			return err
		}
	}

	// Check if update is needed
	needsUpdate := false
	var updateReason string
	if existingRole == nil {
		needsUpdate = true
		updateReason = "node not in layout"
		log.Info("Node not in layout, will add", "nodeID", nodeID)
	} else {
		if existingRole.Zone != zone {
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
		if !tagSetEqual(existingRole.Tags, desiredTags) &&
			!legacyRoleOnlyMissingClusterUID(existingRole.Tags, desiredTags, string(cluster.UID)) {
			needsUpdate = true
			updateReason = "tags changed"
			log.Info("Tag drift detected on node",
				"nodeID", nodeID,
				"existingTags", existingRole.Tags,
				"desiredTags", desiredTags)
		}
	}

	if needsUpdate {
		if storageDrainActorMatches(layoutOwner.Status.StorageDrain, storageDrainActorForNode(node)) && !gatewayReplacement {
			return fmt.Errorf(
				"%w: the active storage-drain actor may only remove its recorded target; wait for status.storageDrain to clear before adding or updating this GarageNode role",
				errLayoutMutationPending,
			)
		}
		log.Info("Updating node in layout", "nodeID", nodeID, "zone", zone, "reason", updateReason)
		if managedIdentity != nil {
			if err := r.revalidateManagedPodIdentity(ctx, node, cluster, managedIdentity); err != nil {
				return fmt.Errorf("%w: revalidating the exact managed Pod before layout mutation: %v", errLayoutMutationPending, err)
			}
		} else if usingObservedNodeID {
			if err := r.validateManagedObservedIdentityFallback(ctx, node, cluster); err != nil {
				return fmt.Errorf("%w: revalidating observed managed identity before layout mutation: %v", errLayoutMutationPending, err)
			}
		}

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

		updatesToStage := []garage.NodeRoleChange{desiredRole}
		var intended []garage.NodeRoleChange
		if gatewayReplacement {
			// Commit the replacement assignment and old capacity-less role removal
			// as one Garage layout version. This avoids an intermediate current
			// layout that contains both identities and could be permanently held by
			// the already-dead predecessor.
			if previousRole != nil {
				updatesToStage = append(updatesToStage, garage.NodeRoleChange{ID: previousNodeID, Remove: true})
			}
			intended = append([]garage.NodeRoleChange(nil), updatesToStage...)
		} else {
			intended, err = r.garageNodeStagingIntent(ctx, cluster, layout, desiredRole)
			if err != nil {
				return err
			}
		}
		_, err = stageAndApplyExclusiveLayout(ctx, garageClient, layout, intended, nil, func() error {
			if err := garageClient.UpdateClusterLayout(ctx, updatesToStage); err != nil {
				return fmt.Errorf("failed to update layout: %w", err)
			}
			return nil
		})
		if err != nil {
			if gatewayReplacement {
				return fmt.Errorf("%w: combined gateway identity replacement has a durable exact target but Garage Apply did not confirm: %v", errLayoutMutationPending, err)
			}
			if garage.IsReplicationConstraint(err) {
				return fmt.Errorf("%w: Garage is waiting for enough staged storage roles to satisfy replication constraints", errLayoutMutationPending)
			}
			return err
		}

		log.Info("Applied layout update", "nodeID", nodeID, "zone", zone, "gatewayIdentityReplacement", gatewayReplacement)
		// One successful Apply is the only topology mutation this critical
		// section may perform. A later reconcile re-acquires the coordinator and
		// proves the resulting layout history settled before handling identity
		// cleanup or another node's drift.
		return fmt.Errorf("%w: applied layout role for GarageNode %s", errLayoutMutationPending, node.Name)
	}

	// Capacity-less identities (gateways) can be replaced automatically: neither
	// role stores blocks, so assigning the replacement above and then removing the
	// stale role cannot bypass a data-migration proof. Positive-capacity identity
	// changes returned through the explicit lost-source gate above.
	if identityChanged {
		if managedIdentity != nil {
			if err := r.revalidateManagedPodIdentity(ctx, node, cluster, managedIdentity); err != nil {
				return fmt.Errorf("%w: revalidating the exact managed Pod before stale gateway-role removal: %v", errLayoutMutationPending, err)
			}
		}
		log.Info("Gateway identity changed; replacement assigned, removing stale layout role",
			nodeValue, node.Name, "previousNodeID", previousNodeID, "newNodeID", nodeID)
		if err := r.removeStaleNodeRole(ctx, node, garageClient, previousNodeID, layoutOwner); err != nil {
			return fmt.Errorf("removing stale node role %s after assigning replacement identity: %w", previousNodeID, err)
		}
		// The new identity is committed before the parent transaction is cleared;
		// this prevents a crash from forgetting which replacement completed the
		// recorded stale-role removal.
	}

	node.Status.NodeID = nodeID
	return nil
}

func (r *GarageNodeReconciler) validateGarageNodeIdentityOwner(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	nodeID string,
) error {
	if node == nil || cluster == nil || nodeID == "" {
		return nil
	}
	if r.Client == nil && r.APIReader == nil {
		// Some narrow unit tests exercise layout math without a Kubernetes
		// client. Production reconciliation always supplies at least one reader.
		return nil
	}
	siblings := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, siblings, client.InNamespace(node.Namespace)); err != nil {
		return fmt.Errorf("listing GarageNodes before claiming identity %s: %w", shortID(nodeID), err)
	}
	for i := range siblings.Items {
		sibling := &siblings.Items[i]
		if sibling.Name == node.Name || sibling.Spec.ClusterRef.Name != cluster.Name ||
			(sibling.Spec.ClusterRef.Namespace != "" && sibling.Spec.ClusterRef.Namespace != cluster.Namespace) {
			continue
		}
		siblingNodeID, err := sibling.ResolvedGarageNodeID()
		if err != nil {
			return fmt.Errorf("resolving sibling GarageNode %s/%s identity before claiming %s: %w",
				sibling.Namespace, sibling.Name, shortID(nodeID), err)
		}
		if canonicalGarageNodeID(siblingNodeID) != nodeID {
			continue
		}
		return fmt.Errorf(
			"IdentityCollision: Garage identity %s is already claimed by GarageNode %s/%s; refusing to let GarageNode %s/%s persist or mutate the same identity",
			shortID(nodeID), sibling.Namespace, sibling.Name, node.Namespace, node.Name,
		)
	}
	return nil
}

// invalidateManagedGarageNodeIdentityObservation clears the durable binding
// between a Pod UID and status.nodeId as soon as direct discovery proves that
// the same managed process now serves a different Garage identity. A later
// storage-drain peer scan must not mistake the replacement Pod for a live
// source of blocks owned by the old ID.
func (r *GarageNodeReconciler) invalidateManagedGarageNodeIdentityObservation(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
) error {
	if node == nil || (node.Status.ObservedPodUID == "" && !node.Status.Connected && node.Status.ObservedGeneration == 0) {
		return nil
	}
	apply := func() {
		node.Status.ObservedPodUID = ""
		node.Status.Connected = false
		node.Status.ObservedGeneration = 0
	}
	apply()
	return UpdateStatusWithRetry(ctx, r.Client, node, apply)
}

// legacyRoleOnlyMissingClusterUID prevents a controller upgrade from creating
// a no-op layout version solely to stamp every pre-feature role. Federated
// sites do not share a Kubernetes lock and Garage's staging area has no CAS, so
// simultaneous automatic retags would collide globally. New roles always get
// the UID, and a legacy role picks it up whenever another real role change is
// applied.
func legacyRoleOnlyMissingClusterUID(existingTags, desiredTags []string, clusterUID string) bool {
	if clusterUID == "" {
		return false
	}
	for _, tag := range existingTags {
		if strings.HasPrefix(tag, "cluster-uid:") {
			return false
		}
	}
	expectedUIDTag := "cluster-uid:" + clusterUID
	withoutUID := make([]string, 0, len(desiredTags))
	foundDesiredUID := false
	for _, tag := range desiredTags {
		if tag == expectedUIDTag {
			foundDesiredUID = true
			continue
		}
		withoutUID = append(withoutUID, tag)
	}
	return foundDesiredUID && tagSetEqual(existingTags, withoutUID)
}

func (r *GarageNodeReconciler) desiredGarageNodeRoleChange(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	nodeID string,
) (garage.NodeRoleChange, error) {
	var capacity *uint64
	if !node.Spec.Gateway {
		if node.Spec.Capacity == nil {
			return garage.NodeRoleChange{}, fmt.Errorf("capacity is required for non-gateway nodes")
		}
		nodeCapacity := uint64(node.Spec.Capacity.Value())
		if nodeCapacity < 1024 {
			return garage.NodeRoleChange{}, fmt.Errorf("capacity must be at least 1024 bytes (1 KB), got %d", nodeCapacity)
		}
		capacity = &nodeCapacity
	}
	rpcPublicAddr, err := r.effectiveNodeRPCPublicAddr(ctx, node, cluster)
	if err != nil {
		return garage.NodeRoleChange{}, fmt.Errorf("resolving node RPC public address: %w", err)
	}
	operatorTags := []string{
		fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace),
	}
	if cluster.UID != "" {
		operatorTags = append(operatorTags, nodeClusterUIDTagPrefix+string(cluster.UID))
	}
	if node.Spec.Gateway {
		operatorTags = append(operatorTags, "tier:"+tierGateway)
	} else {
		operatorTags = append(operatorTags, "tier:"+tierStorage)
	}
	if isNodeLocalPoolBacked(node) {
		operatorTags = append(operatorTags,
			nodeLocalPoolLayoutTagPrefix+node.Spec.NodeLocalPoolName,
			"kubernetes-node:"+node.Spec.KubernetesNodeName,
		)
	}
	return garage.NodeRoleChange{
		ID:       nodeID,
		Zone:     r.effectiveNodeZone(ctx, node, cluster),
		Capacity: capacity,
		Tags:     desiredNodeRoleTags(node.Spec.Tags, rpcPublicAddr, operatorTags...),
	}, nil
}

// garageNodeStagingIntent admits only exact, live sibling GarageNode role
// assignments left staged by an earlier replication-factor bootstrap attempt.
// Removals, unknown IDs, and drift are owned by other operations and block
// Apply instead of being committed opportunistically.
func (r *GarageNodeReconciler) garageNodeStagingIntent(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	layout *garage.ClusterLayout,
	desired garage.NodeRoleChange,
) ([]garage.NodeRoleChange, error) {
	intended := []garage.NodeRoleChange{desired}
	if len(layout.StagedRoleChanges) == 0 {
		return intended, nil
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, fmt.Errorf("listing GarageNodes to validate staged layout ownership: %w", err)
	}
	byID := make(map[string]*garagev1beta1.GarageNode)
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) ||
			!node.DeletionTimestamp.IsZero() {
			continue
		}
		id := node.Status.NodeID
		if id == "" {
			id = node.Spec.NodeID
		}
		if id != "" {
			byID[id] = node
		}
	}
	seen := map[string]bool{desired.ID: true}
	for i := range layout.StagedRoleChanges {
		staged := layout.StagedRoleChanges[i]
		if staged.ID == desired.ID {
			continue
		}
		node := byID[staged.ID]
		if node == nil || staged.Remove {
			return nil, fmt.Errorf("%w: staged node %s is not an assignable live GarageNode owned by this cluster", errLayoutMutationPending, shortID(staged.ID))
		}
		expected, err := r.desiredGarageNodeRoleChange(ctx, node, cluster, staged.ID)
		if err != nil || !sameStagedRoleChange(staged, expected) {
			return nil, fmt.Errorf("%w: staged role for GarageNode %s does not match its desired operator state", errLayoutMutationPending, node.Name)
		}
		if !seen[expected.ID] {
			intended = append(intended, expected)
			seen[expected.ID] = true
		}
	}
	return intended, nil
}

// desiredNodeRoleTags returns a fresh tag slice with one canonical set of
// operator-owned metadata. Reserved values from specTags are discarded even if
// admission was bypassed, so a GarageNode cannot forge another site's UID,
// tier, pool membership, or RPC address in Garage's replicated layout.
func desiredNodeRoleTags(specTags []string, rpcPublicAddr string, operatorTags ...string) []string {
	desired := make([]string, 0, len(specTags)+len(operatorTags)+1)
	desired = append(desired, operatorTags...)
	desired = append(desired, userNodeLayoutTags(specTags)...)
	if addr := strings.TrimSpace(rpcPublicAddr); addr != "" {
		desired = append(desired, nodeRPCAddressTagPrefix+addr)
	}
	return desired
}

// nodeIDFromDiscovery falls back only when live discovery failed. This keeps
// offline nodes reconcilable without masking a changed identity once the pod is
// available again.
func nodeIDFromDiscovery(discovered string, discoverErr error, observed string) (string, bool, error) {
	if discoverErr == nil {
		return canonicalGarageNodeID(discovered), false, nil
	}
	observed = canonicalGarageNodeID(observed)
	if observed == "" {
		return "", false, discoverErr
	}
	return observed, true, nil
}

// daemonSetPodForNode returns the storage DaemonSet pod scheduled on the
// Kubernetes node this node-local-pool-backed GarageNode represents. Pods are
// matched by the storage-tier labels the cluster-owned DaemonSet stamps on
// its template ({labelCluster, labelTier=storage}), the DaemonSet controller
// reference, and spec.nodeName.
func (r *GarageNodeReconciler) daemonSetPodForNode(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) (*corev1.Pod, error) {
	if node.Spec.KubernetesNodeName == "" {
		return nil, fmt.Errorf("node-local-pool-backed node %s has no spec.kubernetesNodeName", node.Name)
	}
	if node.Spec.NodeLocalPoolName == "" {
		return nil, fmt.Errorf("node-local-pool-backed node %s has no spec.nodeLocalPoolName", node.Name)
	}
	daemonSet := &appsv1.DaemonSet{}
	daemonSetKey := types.NamespacedName{
		Name:      storageDaemonSetName(cluster, node.Spec.NodeLocalPoolName),
		Namespace: cluster.Namespace,
	}
	if err := r.nodeLocalPoolReader().Get(ctx, daemonSetKey, daemonSet); err != nil {
		return nil, fmt.Errorf("getting storage DaemonSet for pool %q: %w", node.Spec.NodeLocalPoolName, err)
	}
	if !metav1.IsControlledBy(daemonSet, cluster) {
		return nil, fmt.Errorf(
			"storage DaemonSet %s is not controlled by GarageCluster %s/%s",
			daemonSet.Name,
			cluster.Namespace,
			cluster.Name,
		)
	}
	pods := &corev1.PodList{}
	if err := r.nodeLocalPoolReader().List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:       cluster.Name,
			labelTier:          tierStorage,
			labelNodeLocalPool: node.Spec.NodeLocalPoolName,
		}),
	); err != nil {
		return nil, fmt.Errorf("listing storage DaemonSet pods: %w", err)
	}
	var active *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !isStorageDaemonSetPodForPoolUID(cluster, node.Spec.NodeLocalPoolName, daemonSet.UID, pod) ||
			pod.Spec.NodeName != node.Spec.KubernetesNodeName ||
			!pod.DeletionTimestamp.IsZero() {
			continue
		}
		if active == nil || active.CreationTimestamp.Before(&pod.CreationTimestamp) {
			active = pod
		}
	}
	if active != nil {
		return active, nil
	}
	return nil, fmt.Errorf("%w for node-local pool %q on Kubernetes node %q", errManagedPodAbsent, node.Spec.NodeLocalPoolName, node.Spec.KubernetesNodeName)
}

func (r *GarageNodeReconciler) statefulSetPodForNode(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
) (*corev1.Pod, error) {
	statefulSet := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: node.Name, Namespace: node.Namespace}
	if err := r.nodeLocalPoolReader().Get(ctx, key, statefulSet); err != nil {
		return nil, fmt.Errorf("getting GarageNode StatefulSet %s: %w", node.Name, err)
	}
	if !metav1.IsControlledBy(statefulSet, node) {
		return nil, fmt.Errorf("StatefulSet %s is not controlled by GarageNode %s", statefulSet.Name, node.Name)
	}
	pod := &corev1.Pod{}
	if err := r.nodeLocalPoolReader().Get(ctx, types.NamespacedName{
		Name: node.Name + "-0", Namespace: node.Namespace,
	}, pod); err != nil {
		return nil, fmt.Errorf("getting GarageNode pod %s-0: %w", node.Name, err)
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != kindStatefulSet || owner.UID != statefulSet.UID {
		return nil, fmt.Errorf("pod %s is not controlled by the current StatefulSet %s", pod.Name, statefulSet.Name)
	}
	return pod, nil
}

// effectiveNodeZone resolves the layout zone for a GarageNode.
//
// Without spec.zoneFrom this is just spec.zone. With it, the zone is a property
// of *where the pod landed*, so it can only be read once the pod is scheduled:
// look up the pod, follow spec.nodeName to the Kubernetes Node, and take the
// configured label's value.
//
// A node must always have a zone — Garage's layout role requires one. Before
// the first successful resolution, failures fall back to spec.zone. After a
// zone has been observed, transient workload gaps retain status.zone so an
// OnDelete Pod replacement cannot manufacture two needless layout versions by
// flipping to spec.zone and back:
//
//   - Pod absent/not scheduled or Kubernetes Node temporarily unreadable: keep
//     the last observed zone, or spec.zone when there is no observation yet.
//   - Label absent on the Kubernetes Node: the cluster does not express that
//     topology any more; deliberately fall back to spec.zone.
//
// Re-resolution on every reconcile is deliberate: if a pod moves to a Kubernetes
// Node in a different failure domain, the layout should say so. Upstream
// minimizes the resulting churn (minimize_rebalance_load in ../garage
// src/rpc/layout/version.rs), so a single node's zone change reassigns only the
// partitions it must.
func (r *GarageNodeReconciler) effectiveNodeZone(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) string {
	log := logf.FromContext(ctx)

	src := node.Spec.ZoneFrom
	if src == nil || src.NodeLabel == "" {
		return node.Spec.Zone
	}
	// External nodes have no pod in this cluster (the webhook rejects the
	// combination, but a CR predating that validation could still exist).
	if node.Spec.External != nil {
		return node.Spec.Zone
	}

	fallback := func(reason string, err error, retainObserved bool) string {
		zone := node.Spec.Zone
		if retainObserved && node.Status.Zone != "" {
			zone = node.Status.Zone
		}
		log.V(1).Info("zoneFrom unresolved, using fallback zone",
			nodeValue, node.Name, "nodeLabel", src.NodeLabel, "zone", zone,
			"reason", reason, "error", err)
		return zone
	}

	var pod *corev1.Pod
	if isNodeLocalPoolBacked(node) {
		dsPod, err := r.daemonSetPodForNode(ctx, node, cluster)
		if err != nil {
			return fallback("node-local-pool pod not found", err, true)
		}
		pod = dsPod
	} else {
		podName := node.Name + "-0"
		pod = &corev1.Pod{}
		if err := r.Get(ctx, types.NamespacedName{Name: podName, Namespace: cluster.Namespace}, pod); err != nil {
			return fallback("pod not found", err, true)
		}
	}
	if pod.Spec.NodeName == "" {
		return fallback("pod not scheduled", nil, true)
	}

	k8sNode := &corev1.Node{}
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, k8sNode); err != nil {
		return fallback("kubernetes node not readable", err, true)
	}
	zone := k8sNode.Labels[src.NodeLabel]
	if zone == "" {
		return fallback("label not set on kubernetes node", nil, false)
	}
	return zone
}

// getPodIPs returns all IP addresses assigned to the node's pod.
// The first element is the primary IP (pod.Status.PodIP). On dual-stack clusters
// additional IPs (IPv4 or IPv6) are appended from pod.Status.PodIPs.
func (r *GarageNodeReconciler) managedPodForNode(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (*corev1.Pod, error) {
	if node.Spec.External != nil {
		return nil, fmt.Errorf("external nodes have no operator-managed Pod")
	}
	if isNodeLocalPoolBacked(node) {
		return r.daemonSetPodForNode(ctx, node, cluster)
	}
	return r.statefulSetPodForNode(ctx, node)
}

func (r *GarageNodeReconciler) getPodIPs(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) ([]string, error) {
	if node.Spec.External != nil {
		return nil, fmt.Errorf("external nodes must have nodeId specified")
	}
	pod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		return nil, err
	}
	return managedPodIPs(pod)
}

func managedPodIPs(pod *corev1.Pod) ([]string, error) {
	if pod == nil {
		return nil, fmt.Errorf("managed Pod is missing")
	}
	if !pod.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("managed Pod %s is deleting", pod.Name)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("managed Pod %s is not running (phase: %s)", pod.Name, pod.Status.Phase)
	}
	if pod.Status.PodIP == "" {
		return nil, fmt.Errorf("pod %s has no IP address yet", pod.Name)
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

type managedPodIdentity struct {
	nodeID string
	podIP  string
	podUID types.UID
}

func (r *GarageNodeReconciler) discoverNodeLocalPoolRecoveryNodeIdentity(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (*managedPodIdentity, error) {
	if r.nodeLocalPoolRecoveryNodeIDGetter != nil {
		pod, err := r.managedPodForNode(ctx, node, cluster)
		if err != nil {
			return nil, err
		}
		podIPs, err := managedPodIPs(pod)
		if err != nil {
			return nil, err
		}
		nodeID, err := r.nodeLocalPoolRecoveryNodeIDGetter(ctx, node, cluster, podIPs)
		if err != nil {
			return nil, err
		}
		return &managedPodIdentity{nodeID: nodeID, podIP: podIPs[0], podUID: pod.UID}, nil
	}
	return r.discoverNodeIdentityDirect(ctx, node, cluster)
}

// discoverNodeIdentityDirect resolves one exact owned Pod, uses that same
// object's primary IP and mounted startup token to query Garage's process-local
// identity, then re-resolves the managed Pod and requires its UID and selected
// IP to be unchanged. This closes Pod replacement and IP-reuse races across the
// network call.
func (r *GarageNodeReconciler) discoverNodeIdentityDirect(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) (*managedPodIdentity, error) {
	log := logf.FromContext(ctx)
	// The caller already owns an exact GarageNode identity. Resolve its exact
	// StatefulSet/DaemonSet Pod by controller UID and use that Pod's mounted
	// Secret reference. Re-listing by mutable IP and a cluster-wide label can
	// authenticate against a different incarnation that reused the address.
	pod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		return nil, fmt.Errorf("resolving exact managed Pod: %w", err)
	}
	podIPs, err := managedPodIPs(pod)
	if err != nil {
		return nil, err
	}
	adminToken, err := mountedStaticAdminToken(ctx, r.nodeLocalPoolReader(), pod)
	if err != nil {
		return nil, fmt.Errorf("failed to get exact Pod startup admin token: %w", err)
	}

	adminPort := getAdminPort(cluster)
	directEndpoint := adminEndpoint(podIPs[0], adminPort)
	directClient := garage.NewClient(directEndpoint, adminToken)

	info, err := directClient.GetSelfNodeInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get self node info from pod directly: %w", err)
	}
	freshPod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		return nil, fmt.Errorf("re-resolving exact managed Pod after identity response: %w", err)
	}
	if freshPod.UID != pod.UID {
		return nil, fmt.Errorf("managed Pod changed UID from %s to %s while its Garage identity was queried", pod.UID, freshPod.UID)
	}
	freshIPs, err := managedPodIPs(freshPod)
	if err != nil {
		return nil, err
	}
	selectedIPStillOwned := false
	for _, ip := range freshIPs {
		if ip == podIPs[0] {
			selectedIPStillOwned = true
			break
		}
	}
	if !selectedIPStillOwned {
		return nil, fmt.Errorf("managed Pod %s no longer owns queried IP %s", pod.Name, podIPs[0])
	}
	log.Info("Discovered node ID from exact direct Pod self response", "nodeID", info.NodeID, "podIP", podIPs[0], "podUID", pod.UID)
	return &managedPodIdentity{nodeID: info.NodeID, podIP: podIPs[0], podUID: pod.UID}, nil
}

// validateManagedObservedIdentityFallback permits an offline status.nodeId only
// when Kubernetes proves that no current owned Pod exists, or when the current
// Pod is the exact UID whose identity was previously observed. Read, ownership,
// and UID ambiguity fail closed because a replacement can reuse both the
// predecessor's stable Pod name and its IP address.
func (r *GarageNodeReconciler) validateManagedObservedIdentityFallback(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
) error {
	pod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		if errors.IsNotFound(err) || stderrors.Is(err, errManagedPodAbsent) {
			return nil
		}
		return fmt.Errorf("current managed Pod presence or ownership is ambiguous: %w", err)
	}
	observedPodUID := strings.TrimSpace(node.Status.ObservedPodUID)
	if observedPodUID == "" {
		return fmt.Errorf("current managed Pod %s/%s has UID %s, but status.observedPodUid is empty", pod.Namespace, pod.Name, pod.UID)
	}
	if string(pod.UID) != observedPodUID {
		return fmt.Errorf(
			"current managed Pod %s/%s has replacement UID %s, not previously authenticated UID %s",
			pod.Namespace, pod.Name, pod.UID, observedPodUID,
		)
	}
	return nil
}

// revalidateManagedPodIdentity closes the interval between a direct self query
// and a durable status or Garage layout write. The same owned Pod UID must
// still own the exact IP used for that process-local query.
func (r *GarageNodeReconciler) revalidateManagedPodIdentity(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	identity *managedPodIdentity,
) error {
	if identity == nil || identity.podUID == "" || identity.podIP == "" {
		return fmt.Errorf("direct managed-process identity has no complete Pod UID/IP binding")
	}
	pod, err := r.managedPodForNode(ctx, node, cluster)
	if err != nil {
		return err
	}
	if pod.UID != identity.podUID {
		return fmt.Errorf("managed Pod changed UID from %s to %s after direct identity discovery", identity.podUID, pod.UID)
	}
	podIPs, err := managedPodIPs(pod)
	if err != nil {
		return err
	}
	for _, podIP := range podIPs {
		if podIP == identity.podIP {
			return nil
		}
	}
	return fmt.Errorf("managed Pod %s/%s UID %s no longer owns directly queried IP %s", pod.Namespace, pod.Name, pod.UID, identity.podIP)
}

// connectNodeToCluster connects a new node to the cluster by calling ConnectNode.
// This allows the cluster to discover the new node.
func (r *GarageNodeReconciler) connectNodeToCluster(ctx context.Context, garageClient *garage.Client, nodeID, podIP string, cluster *garagev1beta2.GarageCluster) error {
	rpcPort := getRPCPort(cluster)

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
	syntheticCluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name:      node.Spec.ClusterRef.Name,
		Namespace: node.Namespace,
	}}
	return runLayoutMutation(cctx, r.layoutMutationCoordinator(), syntheticCluster, client, func() error {
		return r.removeNodeFromExternalLayout(cctx, node, client)
	})
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
	if _, err := stageAndApplyExclusiveLayout(ctx, garageClient, layout, updates, nil, func() error {
		if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
			return fmt.Errorf("stage node removal: %w", err)
		}
		return nil
	}); err != nil {
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
		adminPort := getAdminPort(cluster)
		node.Status.ClusterAdminEndpoint = "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, clusterDomain)
		ref := *cluster.Spec.Admin.AdminTokenSecretRef
		node.Status.ClusterAdminTokenSecretRef = &ref
	}
}

// removeStaleNodeRole drops a node_id's role from the layout. reconcileNode
// calls it automatically only when a managed gateway's discovered identity no
// longer matches status.NodeID: neither the old nor replacement role stores
// blocks, so that transition is safe. A positive-capacity identity replacement
// is held unassigned earlier and must use the explicit lost-source workflow.
// The storage branches below remain as a defensive boundary for in-flight
// upgrade/recovery state and fail closed unless normal source/destination proof
// can identify a live source or the administrator acknowledges one is lost.
func (r *GarageNodeReconciler) removeStaleNodeRole(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	garageClient *garage.Client,
	staleNodeID string,
	layoutOwner *garagev1beta2.GarageCluster,
) error {
	log := logf.FromContext(ctx)
	if layoutOwner == nil {
		return fmt.Errorf("canonical Garage layout owner is required")
	}

	layout, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("get cluster layout: %w", err)
	}

	var staleRole *garage.LayoutRole
	storageNodeCount := 0
	for i := range layout.Roles {
		role := &layout.Roles[i]
		if role.Capacity != nil && *role.Capacity > 0 {
			storageNodeCount++
		}
		if role.ID == staleNodeID {
			staleRole = role
		}
	}
	if staleRole == nil {
		proof := clusterStorageDrainProof(layoutOwner.Status.StorageDrain)
		if node.Spec.Gateway && proof != nil && sameStorageDrainActor(proof.Actor, storageDrainActorForNode(node)) {
			if len(proof.RemovedStorageNodeIDs) != 0 || !storageDrainRoleIntentIncludes(proof, staleNodeID) {
				return fmt.Errorf("%w: gateway identity retirement has an invalid durable role-only target", errLayoutMutationPending)
			}
			if err := requireCapacitylessGatewayRetirementSettled(ctx, garageClient); err != nil {
				return err
			}
			if proof.CompletedAt == nil {
				if err := completeRoleOnlyGarageNodeDrain(ctx, r.Client, node, layoutOwner, layout); err != nil {
					return err
				}
			}
		}
		if blockResyncIntentIncludes(proof, staleNodeID) || garageNodeStoresBlocks(node) {
			// The spec/status identity is a backwards-compatible fallback for an
			// operator upgrade that observes an already-removed role. New removals
			// always persist this exact intent before Apply below.
			if err := r.ensureNodeBlockResyncIntent(ctx, node, layoutOwner, layout, []string{staleNodeID}); err != nil {
				return fmt.Errorf("%w: recording stale storage identity removal: %v", errLayoutMutationPending, err)
			}
			if err := waitForStorageRoleDrain(ctx, garageClient, staleNodeID); err != nil {
				return fmt.Errorf("%w: waiting for stale storage identity layout history: %v", errLayoutMutationPending, err)
			}
			if err := r.requireBlockResyncQuiet(ctx, node, layoutOwner, garageClient); err != nil {
				return fmt.Errorf("%w: waiting for stale storage identity block migration: %v", errLayoutMutationPending, err)
			}
		}
		return nil
	}

	isStorageNode := staleRole.Capacity != nil && *staleRole.Capacity > 0
	if isStorageNode && storageNodeCount <= 1 {
		log.Info("Refusing to remove last storage node role even though it is stale",
			"staleNodeID", staleNodeID, "storageNodes", storageNodeCount)
		return fmt.Errorf("%w: stale node %s is the last positive-capacity storage role", errUnsafeLayoutRoleRemoval, staleNodeID)
	}
	if isStorageNode {
		if err := r.ensureNodeBlockResyncIntent(ctx, node, layoutOwner, layout, []string{staleNodeID}); err != nil {
			return err
		}
		if err := requireStorageDrainAuthorizedTargets(
			layoutOwner, storageDrainActorForNode(node), []string{staleNodeID}, []string{staleNodeID},
		); err != nil {
			return err
		}
	} else if node.Spec.Gateway {
		if err := r.ensureCapacitylessGarageNodeRetirementIntent(ctx, node, layoutOwner, []string{staleNodeID}); err != nil {
			return err
		}
		if err := requireStorageDrainAuthorizedTargets(
			layoutOwner, storageDrainActorForNode(node), []string{staleNodeID}, nil,
		); err != nil {
			return err
		}
	}

	updates := []garage.NodeRoleChange{{ID: staleNodeID, Remove: true}}
	var beforeApply func(*garage.ClusterLayout) error
	if isStorageNode {
		beforeApply = func(staged *garage.ClusterLayout) error {
			return requireStorageDrainBeforeApply(
				ctx, r.Client, r.nodeLocalPoolReader(), layoutOwner, garageClient, staged, r.clusterHealthGetter,
			)
		}
	}
	if _, err := stageAndApplyExclusiveLayoutWithCheck(ctx, garageClient, layout, updates, nil, func() error {
		if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
			return fmt.Errorf("stage stale role removal: %w", err)
		}
		return nil
	}, beforeApply); err != nil {
		if garage.IsReplicationConstraint(err) {
			log.Info("Cannot remove stale node role yet: would violate replication constraints; will retry",
				"staleNodeID", staleNodeID, "storageNodes", storageNodeCount)
			return fmt.Errorf("%w: stale role removal would violate replication constraints", errUnsafeLayoutRoleRemoval)
		}
		return fmt.Errorf("apply stale role removal: %w", err)
	}
	log.Info("Removed stale node role from layout", "staleNodeID", staleNodeID)

	// Surviving current members normally converge this removal without help;
	// Garage prunes old history from their sync acknowledgements. If another
	// current/down peer or pre-existing version blocks progress, however, the
	// recovery API is global. Automatic reconciliation must wait instead of
	// force-ACKing unrelated peers; an administrator may use the explicit
	// annotation after assessing the whole layout.
	return fmt.Errorf(
		"%w: removed stale role %s; waiting for normal layout convergence or the explicit cluster-wide skip-dead-nodes recovery annotation",
		errLayoutMutationPending, staleNodeID,
	)
}

func (r *GarageNodeReconciler) finalize(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
) error {
	log := logf.FromContext(ctx)

	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return fmt.Errorf("resolving durable GarageNode identity before finalization: %w", err)
	}
	if nodeID == "" {
		return nil
	}

	log.Info("Removing node from layout", "nodeID", nodeID)

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
		if canonicalGarageNodeID(role.ID) == nodeID {
			inLayout = true
			nodeRole = &layout.Roles[i]
		}
	}

	if !inLayout {
		proof := clusterStorageDrainProof(cluster.Status.StorageDrain)
		if node.Spec.Gateway && proof != nil && sameStorageDrainActor(proof.Actor, storageDrainActorForNode(node)) {
			if len(proof.RemovedStorageNodeIDs) != 0 || !storageDrainRoleIntentIncludes(proof, nodeID) {
				return fmt.Errorf("%w: gateway retirement has an invalid durable role-only target", errLayoutMutationPending)
			}
			if err := requireCapacitylessGatewayRetirementSettled(ctx, garageClient); err != nil {
				return err
			}
			if proof.CompletedAt == nil {
				if err := completeRoleOnlyGarageNodeDrain(ctx, r.Client, node, cluster, layout); err != nil {
					return err
				}
			}
			log.Info("Gateway node role is absent and its metadata layout history settled", "nodeID", nodeID)
			return nil
		}
		if blockResyncIntentIncludes(proof, nodeID) || garageNodeStoresBlocks(node) {
			var intentErr error
			if garageNodeAcknowledgesLostSource(node, nodeID) {
				intentErr = r.ensureNodeLostSourceIntent(ctx, node, cluster, layout, garageClient, nodeID)
			} else {
				intentErr = r.ensureNodeBlockResyncIntent(ctx, node, cluster, layout, []string{nodeID})
			}
			if intentErr != nil {
				return intentErr
			}
			if err := waitForStorageRoleDrain(ctx, garageClient, nodeID); err != nil {
				return err
			}
			if err := r.requireBlockResyncQuiet(ctx, node, cluster, garageClient); err != nil {
				return err
			}
		}
		log.Info("Node role is absent and surviving storage nodes completed the block-resync quiet period")
		return nil
	}

	isStorageNode := nodeRole != nil && nodeRole.Capacity != nil && *nodeRole.Capacity > 0
	if isStorageNode && garageNodeAcknowledgesLostSource(node, nodeID) {
		if err := requireGarageNodeLostSourceUnavailable(ctx, r.nodeLocalPoolReader(), node, cluster, garageClient, nodeID); err != nil {
			return err
		}
		return fmt.Errorf(
			"%w: lost source %s is still present in the Garage layout; first use Garage's explicit dead-node recovery to remove/apply that exact role and settle layout history, then the operator will verify surviving destinations",
			errLayoutMutationPending, shortID(nodeID),
		)
	}
	if isStorageNode && storageNodeCount <= 1 {
		log.Info("Cannot remove last storage node from layout; retaining GarageNode finalizer",
			"nodeID", nodeID, "storageNodes", storageNodeCount)
		return fmt.Errorf("%w: node %s is the last positive-capacity storage role", errUnsafeLayoutRoleRemoval, nodeID)
	}
	if isStorageNode {
		if err := r.ensureNodeBlockResyncIntent(ctx, node, cluster, layout, []string{nodeID}); err != nil {
			return err
		}
		if err := requireStorageDrainAuthorizedTargets(
			cluster, storageDrainActorForNode(node), []string{nodeID}, []string{nodeID},
		); err != nil {
			return err
		}
	} else if node.Spec.Gateway {
		if err := r.ensureCapacitylessGarageNodeRetirementIntent(ctx, node, cluster, []string{nodeID}); err != nil {
			return err
		}
		if err := requireStorageDrainAuthorizedTargets(
			cluster, storageDrainActorForNode(node), []string{nodeID}, nil,
		); err != nil {
			return err
		}
	}

	// Stage removal
	updates := []garage.NodeRoleChange{{
		ID:     nodeID,
		Remove: true,
	}}

	var beforeApply func(*garage.ClusterLayout) error
	if isStorageNode {
		beforeApply = func(staged *garage.ClusterLayout) error {
			return requireStorageDrainBeforeApply(
				ctx, r.Client, r.nodeLocalPoolReader(), cluster, garageClient, staged, r.clusterHealthGetter,
			)
		}
	}
	if _, err := stageAndApplyExclusiveLayoutWithCheck(ctx, garageClient, layout, updates, nil, func() error {
		if err := garageClient.UpdateClusterLayout(ctx, updates); err != nil {
			return fmt.Errorf("failed to stage node removal: %w", err)
		}
		return nil
	}, beforeApply); err != nil {
		recoveredErr := r.recoverNodeDrainApplyFailure(ctx, node, cluster, garageClient, updates, err)
		if stderrors.Is(recoveredErr, errLayoutMutationPending) {
			return recoveredErr
		}
		if garage.IsReplicationConstraint(err) {
			log.Info("Cannot remove node: would violate replication constraints; retaining GarageNode finalizer. "+
				"Add enough in-layout storage nodes or reduce the replication factor to continue.",
				"nodeID", nodeID, "storageNodes", storageNodeCount)
			return fmt.Errorf("%w: Garage rejected removal of node %s: %v", errUnsafeLayoutRoleRemoval, nodeID, recoveredErr)
		}
		return fmt.Errorf("failed to apply layout removal: %w", recoveredErr)
	}

	// Re-read the committed version. ApplyStagedLayoutChanges does not surface
	// the version it applied, and a concurrent writer may have advanced it past
	// our local target (V+2), so layout.Version+1 is an unreliable guess. The
	// re-read is the only authoritative source of the current version.
	appliedVersion, ok := reReadLayoutVersion(ctx, garageClient)
	if ok {
		log.Info("Removed node from layout", "version", appliedVersion)
	} else {
		log.Info("Removed node from layout (could not re-read committed version)")
	}

	// Applying a storage role removal creates a new current layout, but Garage
	// keeps the previous version active while metadata assignments synchronize.
	// Historical versions may still serve object blocks after those trackers
	// clear, so retain the finalizer, activation label, and pod until every
	// current storage node also reports a durable zero block-resync window.
	if isStorageNode {
		if err := waitForStorageRoleDrain(ctx, garageClient, nodeID); err != nil {
			return err
		}
		if err := r.requireBlockResyncQuiet(ctx, node, cluster, garageClient); err != nil {
			return err
		}
	}

	if node.Spec.Gateway {
		if err := requireCapacitylessGatewayRetirementSettled(ctx, garageClient); err != nil {
			return err
		}
		return fmt.Errorf("%w: gateway role is absent and layout history settled; recording the durable terminal handoff on the next reconcile", errLayoutMutationPending)
	}

	return nil
}

func waitForStorageRoleDrain(ctx context.Context, garageClient *garage.Client, nodeID string) error {
	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return fmt.Errorf("checking layout-history drain for storage node %s: %w", nodeID, err)
	}
	if _, stillActive := history.UpdateTrackers[nodeID]; stillActive {
		return fmt.Errorf(
			"%w: storage node %s remains in an active older layout version (current version %d)",
			errLayoutRoleDraining,
			nodeID,
			history.CurrentVersion,
		)
	}
	if len(history.GetDrainingVersions()) > 0 && history.UpdateTrackers == nil {
		// Current supported Garage versions return updateTrackers whenever more
		// than one layout version is active. If that evidence is unavailable,
		// fail closed instead of assuming the removed storage identity is safe.
		return fmt.Errorf(
			"%w: Garage reports draining layout versions but no update trackers while checking storage node %s",
			errLayoutRoleDraining,
			nodeID,
		)
	}
	return nil
}

// reReadLayoutVersion re-reads the cluster layout to obtain the authoritative
// current version after an apply, retrying once on transient error. The bool
// reports whether a version was obtained; callers MUST NOT fall back to a
// guessed version (e.g. local+1) for skip-dead-nodes, because a concurrent
// writer may have advanced the version past the local target.
func reReadLayoutVersion(ctx context.Context, garageClient *garage.Client) (uint64, bool) {
	for attempt := 0; attempt < 2; attempt++ {
		if cur, err := garageClient.GetClusterLayout(ctx); err == nil {
			return cur.Version, true
		}
	}
	return 0, false
}

func (r *GarageNodeReconciler) updateStatus(ctx context.Context, node *garagev1beta1.GarageNode, phase string, err error) (ctrl.Result, error) {
	observedGeneration := node.Generation
	apply := func() {
		node.Status.Phase = phase
		if err == nil {
			node.Status.ObservedGeneration = observedGeneration
			return
		}
		meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
			Type:               PhaseReady,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonReconcileFailed,
			Message:            err.Error(),
			ObservedGeneration: observedGeneration,
		})
	}
	apply()

	if statusErr := UpdateStatusWithRetry(ctx, r.Client, node, apply); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	if err != nil {
		return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
	}
	// Still requeue: the only nil-error caller is the identity-less branch of
	// updateStatusFromGarage, which cannot make progress until another actor
	// moves, and no longer self-wakes via its own status write.
	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

func (r *GarageNodeReconciler) updateStatusFromGarage(
	ctx context.Context,
	node *garagev1beta1.GarageNode,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
) (ctrl.Result, error) {
	if node.Status.NodeID == "" {
		return r.updateStatus(ctx, node, "Pending", nil)
	}

	// A parent-controlled storage rollout may replace a pod without
	// changing the GarageNode generation. Rediscover the identity directly from
	// the current pod and record its UID only after it agrees with the reconciled
	// node ID. The parent uses this handshake to distinguish fresh evidence from
	// the previous pod's still-cached Connected/InLayout status. Every internally
	// managed GarageNode participates: node-local-pool members use their DaemonSet pod,
	// while PVC, SMB, and unified gateway members use their owned StatefulSet pod.
	observedPodUID := ""
	if node.Spec.External == nil {
		var pod *corev1.Pod
		var err error
		if isNodeLocalPoolBacked(node) {
			pod, err = r.daemonSetPodForNode(ctx, node, cluster)
		} else {
			pod, err = r.statefulSetPodForNode(ctx, node)
		}
		if err != nil {
			return r.updateStatus(ctx, node, PhasePending, fmt.Errorf("waiting to observe current managed pod: %w", err))
		}
		// Probe this exact Pod's Admin API; matching its IP against the shared
		// peer list is insufficient because a replacement identity may reuse
		// the old process's Pod IP.
		identity, err := r.discoverNodeIdentityDirect(ctx, node, cluster)
		if err != nil {
			return r.updateStatus(ctx, node, PhasePending, fmt.Errorf("waiting to verify Garage identity directly from managed pod %s: %w", pod.Name, err))
		}
		liveNodeID := identity.nodeID
		if identity.podUID != pod.UID {
			return r.updateStatus(ctx, node, PhasePending, fmt.Errorf("managed pod %s changed UID during direct identity verification", pod.Name))
		}
		liveNodeID = canonicalGarageNodeID(liveNodeID)
		if liveNodeID != canonicalGarageNodeID(node.Status.NodeID) {
			if err := r.invalidateManagedGarageNodeIdentityObservation(ctx, node); err != nil {
				return ctrl.Result{}, fmt.Errorf("invalidating stale managed-pod identity evidence: %w", err)
			}
			return r.updateStatus(ctx, node, PhasePending, fmt.Errorf(
				"managed pod %s reports Garage identity %s while status still tracks %s",
				pod.Name, shortID(liveNodeID), shortID(node.Status.NodeID),
			))
		}
		observedPodUID = string(pod.UID)
	}

	status, err := garageClient.GetClusterStatus(ctx)
	if err != nil {
		return r.updateStatus(ctx, node, PhaseFailed, fmt.Errorf("failed to get cluster status: %w", err))
	}

	var nodeInfo *garage.NodeInfo
	for i := range status.Nodes {
		if canonicalGarageNodeID(status.Nodes[i].ID) == canonicalGarageNodeID(node.Status.NodeID) {
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
		if canonicalGarageNodeID(layout.Roles[i].ID) == canonicalGarageNodeID(node.Status.NodeID) {
			layoutRole = &layout.Roles[i]
			break
		}
	}

	inLayout := layoutRole != nil
	connected := nodeInfo != nil && nodeInfo.IsUp
	conditionStatus := metav1.ConditionTrue
	reason := "NodeReady"
	message := "Node is ready and in layout"

	if !inLayout {
		conditionStatus = metav1.ConditionFalse
		reason = "NotInLayout"
		message = "Node is not yet in the cluster layout"
	} else if !connected {
		conditionStatus = metav1.ConditionFalse
		reason = "NodeDisconnected"
		message = "Node is in layout but its identity is not currently connected"
	}
	readyCondition := metav1.Condition{
		Type:               PhaseReady,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: node.Generation,
	}

	// Capture values computed from this exact reconcile. If a concurrent spec or
	// status write causes a conflict, UpdateStatusWithRetry re-fetches the object;
	// this closure reapplies the Pod-identity handshake instead of silently
	// succeeding with the freshly fetched (stale) status.
	observedGeneration := node.Generation
	nodeID := canonicalGarageNodeID(node.Status.NodeID)
	zone := node.Status.Zone
	if layoutRole != nil && layoutRole.Zone != "" {
		zone = layoutRole.Zone
	}
	adminEndpoint := node.Status.ClusterAdminEndpoint
	var adminTokenRef *corev1.SecretKeySelector
	if node.Status.ClusterAdminTokenSecretRef != nil {
		copy := *node.Status.ClusterAdminTokenSecretRef
		adminTokenRef = &copy
	}
	var lastSeen *metav1.Time
	if connected {
		now := metav1.Now()
		lastSeen = &now
	}
	apply := func() {
		node.Status.NodeID = nodeID
		node.Status.Zone = zone
		node.Status.ClusterAdminEndpoint = adminEndpoint
		node.Status.ClusterAdminTokenSecretRef = adminTokenRef
		node.Status.Phase = PhaseReady
		node.Status.ObservedGeneration = observedGeneration
		node.Status.InLayout = inLayout
		if layoutRole != nil {
			node.Status.LayoutVersion = int64(layout.Version)
		}
		node.Status.Connected = connected
		applyGarageNodeObservations(&node.Status, nodeInfo, layoutRole)
		if lastSeen != nil {
			copy := *lastSeen
			node.Status.LastSeen = &copy
		}
		if observedPodUID != "" {
			node.Status.ObservedPodUID = observedPodUID
		}
		condition := readyCondition
		condition.ObservedGeneration = observedGeneration
		meta.SetStatusCondition(&node.Status.Conditions, condition)
	}
	apply()

	if err := UpdateStatusWithRetry(ctx, r.Client, node, apply); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: RequeueAfterShort}, nil
}

func applyGarageNodeObservations(status *garagev1beta1.GarageNodeStatus, nodeInfo *garage.NodeInfo, layoutRole *garage.LayoutRole) {
	if status == nil {
		return
	}
	status.Address = ""
	status.Hostname = ""
	status.Version = ""
	status.Tags = nil
	status.DataPartition = nil
	status.MetadataPartition = nil
	status.Partitions = 0

	if nodeInfo != nil {
		if nodeInfo.Address != nil {
			status.Address = *nodeInfo.Address
		}
		if nodeInfo.Hostname != nil {
			status.Hostname = *nodeInfo.Hostname
		}
		if nodeInfo.GarageVersion != nil {
			status.Version = *nodeInfo.GarageVersion
		}
		status.DataPartition = garageDiskPartitionStatus(nodeInfo.DataPartition)
		status.MetadataPartition = garageDiskPartitionStatus(nodeInfo.MetadataPartition)
	}
	if layoutRole != nil {
		status.Tags = append([]string(nil), layoutRole.Tags...)
		if layoutRole.StoredPartitions != nil && *layoutRole.StoredPartitions <= uint64(^uint(0)>>1) {
			status.Partitions = int(*layoutRole.StoredPartitions)
		}
	}
}

func garageDiskPartitionStatus(free *garage.FreeSpaceResp) *garagev1beta1.DiskPartitionStatus {
	if free == nil {
		return nil
	}
	available := resource.MustParse(fmt.Sprintf("%d", free.Available))
	total := resource.MustParse(fmt.Sprintf("%d", free.Total))
	usedPercent := int32(0)
	if free.Total > 0 && free.Available < free.Total {
		usedPercent = int32(float64(free.Total-free.Available) * 100 / float64(free.Total))
	}
	return &garagev1beta1.DiskPartitionStatus{
		Available:   &available,
		Total:       &total,
		UsedPercent: usedPercent,
	}
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
	svcName := boundedDNS1123LabelName(node.Name + "-rpc")

	rpcPort := getRPCPort(cluster)

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

// effectiveNodeRPCPublicAddr resolves the same address written to garage.toml
// and published in the node's replicated layout tags. An empty result means the
// node has no node-specific endpoint and may inherit cluster-level bootstrap
// configuration; shared cluster addresses are deliberately not advertised as
// identity-specific endpoints.
func (r *GarageNodeReconciler) effectiveNodeRPCPublicAddr(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) (string, error) {
	if node.Spec.Network != nil && strings.TrimSpace(node.Spec.Network.RPCPublicAddr) != "" {
		return strings.TrimSpace(node.Spec.Network.RPCPublicAddr), nil
	}
	if node.Spec.External != nil && strings.TrimSpace(node.Spec.External.Address) != "" {
		port := node.Spec.External.Port
		if port == 0 {
			port = DefaultRPCPort
		}
		return rpcAddr(strings.TrimSpace(node.Spec.External.Address), port), nil
	}
	if node.Spec.PublicEndpoint == nil {
		return "", nil
	}

	rpcPort := getRPCPort(cluster)
	switch node.Spec.PublicEndpoint.Type {
	case publicEndpointTypeLoadBalancer:
		svc := &corev1.Service{}
		svcName := effectiveNodeRPCServiceName(node, cluster)
		if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, svc); err != nil {
			if errors.IsNotFound(err) {
				return "", nil
			}
			return "", err
		}
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			addr := ing.IP
			if addr == "" {
				addr = ing.Hostname
			}
			if addr != "" {
				return rpcAddr(addr, rpcPort), nil
			}
		}
	case publicEndpointTypeNodePort:
		if ep := node.Spec.PublicEndpoint.NodePort; ep != nil && len(ep.ExternalAddresses) > 0 {
			port := ep.BasePort
			if port == 0 {
				port = 30901
			}
			return rpcAddr(ep.ExternalAddresses[0], port), nil
		}
	}
	return "", nil
}

// reconcileNodeConfigMap generates a per-node garage.toml resource by building
// a configContext with node-specific overrides and calling the shared generator.
func (r *GarageNodeReconciler) reconcileNodeConfigMap(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) error {
	nodeConfig, err := r.renderNodeGarageConfig(ctx, node, cluster)
	if err != nil {
		return err
	}
	baseName := garageNodeConfigBaseName(cluster, node)
	revision, err := garageConfigRevision(ctx, r.nodeLocalPoolReader(), cluster, nodeConfig)
	if err != nil {
		return err
	}
	name := garageConfigRevisionName(baseName, revision)
	annotations := garageConfigRevisionAnnotations(baseName, nil)
	labels := r.labelsForNode(node, cluster)
	if garageConfigUsesSecret(cluster) {
		_, err = reconcileGarageConfigSecret(
			ctx, r.Client, r.Scheme, node, cluster.Namespace, name,
			nodeConfig, revision, labels, annotations, true,
		)
		return err
	}
	_, err = reconcileGarageConfigMap(
		ctx, r.Client, r.Scheme, node, cluster.Namespace, name,
		nodeConfig, revision, labels, annotations, true,
	)
	return err
}

func (r *GarageNodeReconciler) renderNodeGarageConfig(ctx context.Context, node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) (string, error) {
	// Start with a base context (resolves Consul token, cluster-level publicEndpoint, etc.)
	// buildConfigContext only hard-errors when a configured secret (Consul token) is
	// missing/incomplete. Do NOT render on that error: an empty context drops the
	// resolved rpc_public_addr/Consul token and would roll the pod onto a degraded
	// config (re-opening the v0.5.3-class peering break) with no signal. Fail loudly
	// so the node goes PhaseFailed and requeues until the secret is present.
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		return "", fmt.Errorf("building node config context (config not ready): %w", err)
	}

	// A gateway node must never inherit the storage tier's rpc_public_addr from
	// the shared cluster config (the v0.5.3 outage). Its own address, if any,
	// still flows through NodeRPCPublicAddr below.
	if node.Spec.Gateway {
		cfgCtx.OmitClusterRPCPublicAddr = true
		cfgCtx.ForceSingleDataDir = true
	}

	// Apply node-level rpc_public_addr via NodeRPCPublicAddr — this takes highest priority
	// in writeRPCConfig, overriding even cluster.Spec.Network.RPCPublicAddr.
	rpcPublicAddr, err := r.effectiveNodeRPCPublicAddr(ctx, node, cluster)
	if err != nil {
		return "", fmt.Errorf("resolving node RPC public address: %w", err)
	}
	cfgCtx.NodeRPCPublicAddr = rpcPublicAddr

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
						p.Capacity = garageBytesize(dp.Size)
					case dp.ExistingClaim != "":
						if cap := r.lookupPVCCapacity(ctx, cluster.Namespace, dp.ExistingClaim); cap != "" {
							p.Capacity = cap
						}
					}
					// Upstream make_data_dirs (../garage src/block/layout.rs)
					// rejects any data_dir entry that is neither read_only nor
					// capacity-bearing, so Garage refuses to start and the pod
					// crashloops. Refuse to render an invalid data_dir: fail the
					// reconcile so the node goes PhaseFailed and requeues. When
					// the entry is pinned to a still-Pending PVC (no requested or
					// status capacity yet) the requeue lets capacity resolve once
					// the claim binds; when no capacity is configurable at all the
					// message tells the operator exactly which disk to fix.
					if p.Capacity == "" {
						return "", fmt.Errorf("data_dir entry %d (path %q) has no capacity: set spec.storage.dataPaths[%d].size, mark it readOnly, or wait for its existingClaim PVC to bind with a requested size", i, p.Path, i)
					}
				}
				paths = append(paths, p)
			}
			cfgCtx.NodeDataDirPaths = paths
		}
	}

	return generateGarageConfig(cluster, cfgCtx), nil
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
//   - corev1.Pod (label- and owner-gated): pods are indirectly owned by a
//     GarageNode through a StatefulSet, or by its parent GarageCluster through
//     a node-local-pool DaemonSet. Owns() does not follow either relationship.
//     Waking the exact GarageNode when one of those pods is replaced lets it
//     publish the new Pod UID and directly verified Garage identity without
//     making a healthy serialized rollout wait for the periodic safety tick.
//
//   - corev1.Node (cluster-scoped installs only, label changes only): maps the
//     managed Pods scheduled on that Kubernetes Node back to their GarageNodes.
//     This makes spec.zoneFrom update and fall back immediately when a topology
//     label changes or is removed.
//
// Both predicates are intentionally narrow — generation predicate on the CR
// + label gating in the CM mapper — to avoid waking GarageNode reconciles
// for unrelated objects.
func (r *GarageNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	clusterTemplatePredicate := predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCluster, oldOK := e.ObjectOld.(*garagev1beta2.GarageCluster)
			newCluster, newOK := e.ObjectNew.(*garagev1beta2.GarageCluster)
			if !oldOK || !newOK {
				return false
			}
			return oldCluster.Generation != newCluster.Generation ||
				currentStaticCredentialsSecretName(oldCluster) != currentStaticCredentialsSecretName(newCluster) ||
				oldCluster.Annotations[annotationStaticCredentialsRevision] != newCluster.Annotations[annotationStaticCredentialsRevision]
		},
	}
	// status.lastSeen is refreshed on every connected observation, so an
	// unfiltered primary watch re-enters Reconcile on its own status write and
	// RequeueAfterShort never paces anything. /status writes do not bump
	// generation; metadata-only edits are picked up by that periodic tick.
	bldr := ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageNode{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Watches(
			&garagev1beta2.GarageCluster{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForCluster),
			builder.WithPredicates(clusterTemplatePredicate),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForClusterConfigResource),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForClusterConfigResource),
		).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.nodeForManagedPod),
		)
	if r.ClusterScoped {
		bldr = bldr.Watches(
			&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.nodesForKubernetesNode),
			builder.WithPredicates(predicate.LabelChangedPredicate{}),
		)
	}
	return bldr.
		Named("garagenode").
		Complete(r)
}

// nodesForKubernetesNode fans a topology-label event out only to operator
// managed Pods that are currently scheduled on that exact Kubernetes Node.
// nodeForManagedPod preserves the StatefulSet/DaemonSet ownership boundary and
// derives the durable GarageNode key for both workload shapes.
func (r *GarageNodeReconciler) nodesForKubernetesNode(ctx context.Context, obj client.Object) []reconcile.Request {
	kubernetesNode, ok := obj.(*corev1.Node)
	if !ok || kubernetesNode.Name == "" {
		return nil
	}
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.MatchingLabels{labelAppManagedBy: operatorName}); err != nil {
		return nil
	}
	seen := make(map[types.NamespacedName]struct{})
	out := make([]reconcile.Request, 0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName != kubernetesNode.Name {
			continue
		}
		for _, request := range r.nodeForManagedPod(ctx, pod) {
			if _, duplicate := seen[request.NamespacedName]; duplicate {
				continue
			}
			seen[request.NamespacedName] = struct{}{}
			out = append(out, request)
		}
	}
	return out
}

// nodeForManagedPod maps both managed storage implementations back to their
// durable GarageNode identity. The map is intentionally label- and
// controller-owner-gated: a matching event only enqueues reconciliation, while
// daemonSetPodForNode/statefulSetPodForNode still prove the exact live workload
// UID before any status or layout change is accepted.
func (r *GarageNodeReconciler) nodeForManagedPod(_ context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	labels := pod.GetLabels()
	if labels[labelAppManagedBy] != operatorName {
		return nil
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil {
		return nil
	}

	// PVC, SMB, and unified gateway Pods are indirectly owned by GarageNode
	// through a same-name StatefulSet. labelGarageNode is stable across Pod
	// replacement and avoids depending on the `<node>-0` naming convention.
	if nodeName := labels[labelGarageNode]; nodeName != "" {
		if owner.Kind != kindStatefulSet {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{
			Name: nodeName, Namespace: pod.Namespace,
		}}}
	}

	// A node-local-pool Pod is directly owned by a DaemonSet and has no
	// labelGarageNode because one template represents many identities. Its
	// deterministic GarageNode name is keyed by the cluster, pool, and the
	// Kubernetes Node on which the Pod was scheduled.
	clusterName := labels[labelCluster]
	nodeLocalPoolName := labels[labelNodeLocalPool]
	if owner.Kind != daemonSetKind ||
		labels[labelTier] != tierStorage ||
		labels[labelStorageGroup] != storageGroupNodeLocal ||
		clusterName == "" || nodeLocalPoolName == "" || pod.Spec.NodeName == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Name:      nodeLocalPoolGarageNodeName(clusterName, nodeLocalPoolName, pod.Spec.NodeName),
		Namespace: pod.Namespace,
	}}}
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
// `<cluster>-gateway-config` CM (which only the edge gateway StatefulSet consumes).
func (r *GarageNodeReconciler) nodesForClusterConfigResource(ctx context.Context, obj client.Object) []reconcile.Request {
	if _, configMap := obj.(*corev1.ConfigMap); !configMap {
		if _, secret := obj.(*corev1.Secret); !secret {
			return nil
		}
	}
	if obj == nil {
		return nil
	}
	labels := obj.GetLabels()
	clusterName := labels[labelCluster]
	if clusterName == "" || labels[labelAppManagedBy] != operatorName {
		return nil
	}
	// Per-node revisions are already covered by Owns for both kinds. Fan out
	// only the exact shared base revision (plus its legacy fixed-name form); the
	// historical gateway-only resource has no GarageNode consumer.
	sharedBaseName := clusterName + "-config"
	baseName := obj.GetAnnotations()[annotationGarageConfigBaseName]
	if baseName == "" && obj.GetName() == sharedBaseName {
		baseName = sharedBaseName
	}
	if baseName != sharedBaseName {
		return nil
	}
	cluster := &garagev1beta2.GarageCluster{}
	if err := r.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: obj.GetNamespace()}, cluster); err != nil ||
		!metav1.IsControlledBy(obj, cluster) {
		return nil
	}
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.List(ctx, nodes, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range nodes.Items {
		n := &nodes.Items[i]
		if n.Spec.ClusterRef.Name != clusterName {
			continue
		}
		if n.Spec.ClusterRef.Namespace != "" && n.Spec.ClusterRef.Namespace != obj.GetNamespace() {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: n.Name, Namespace: n.Namespace}})
	}
	return out
}
