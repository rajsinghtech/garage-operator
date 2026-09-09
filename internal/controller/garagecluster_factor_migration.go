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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/factormigration"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Factor-migration phases.
const (
	fmPhaseValidating       = "Validating"
	fmPhaseScalingDown      = "ScalingDown"
	fmPhasePurging          = "Purging"
	fmPhaseVerifying        = "Verifying"
	fmPhaseRebuildingLayout = "RebuildingLayout"
	fmPhaseConverging       = "Converging"
	fmPhaseCompleted        = "Completed"
	fmPhaseFailed           = "Failed"
)

// fmPurgeInitContainerName is the name of the busybox init container that deletes
// the on-disk cluster_layout exactly once per migration (guarded by a marker file).
const fmPurgeInitContainerName = "purge-cluster-layout"

// fmStuckTimeout bounds each individual wait phase (ScalingDown, Purging,
// Verifying, RebuildingLayout) so a single stuck step can't hang the migration
// forever — past this the migration fails and tears the tier back down. The
// clock is per-phase (status.factorMigration.phaseStartedAt), not the overall
// migration duration, so an early phase consuming time doesn't shorten the
// budget of a later one.
const fmStuckTimeout = 15 * time.Minute

// fmValidateGrace is how long Validating tolerates an annotation factor that
// doesn't yet match spec.replication.factor (propagation race) before failing.
const fmValidateGrace = 2 * time.Minute

// factorMigrationActive reports whether a coordinated factor migration is in
// flight or has been requested via the purge-cluster-layout annotation.
func factorMigrationActive(cluster *garagev1beta2.GarageCluster) bool {
	if cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] != "" {
		return true
	}
	fm := cluster.Status.FactorMigration
	return fm != nil && fm.Phase != "" && fm.Phase != fmPhaseCompleted && fm.Phase != fmPhaseFailed
}

// reconcileFactorMigration drives the coordinated replication-factor migration
// state machine. It is invoked from Reconcile (after the ConfigMap is refreshed
// with the new factor, before the tier workloads) whenever a migration is active,
// and returns early so the normal per-tier reconciliation does not race the purge.
func (r *GarageClusterReconciler) reconcileFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Abort: clear suspension + status, remove annotations. Does NOT roll back a
	// purge that already deleted cluster_layout.
	if cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayoutAbort] == annotationTrue {
		log.Info("Factor migration: abort requested")
		// Full teardown (strip purge init container, scale STSes back to 1, clear
		// suspension) rather than only clearing suspension — don't rely solely on
		// the per-node controllers' hash-diff self-heal to undo the scale-down and
		// remove the init container. A purge already applied to disk cannot be
		// rolled back, but the workloads are restored.
		if err := r.teardownFactorMigration(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		r.setFactorMigration(ctx, cluster, func(fm *garagev1beta2.FactorMigrationStatus) {
			fm.Phase = fmPhaseFailed
			fm.Message = "aborted by operator"
			now := metav1.Now()
			fm.CompletedAt = &now
		})
		return ctrl.Result{}, r.removeAnnotations(ctx, cluster,
			garagev1beta1.AnnotationPurgeClusterLayout, garagev1beta1.AnnotationPurgeClusterLayoutAbort)
	}

	fm := cluster.Status.FactorMigration
	ann := cluster.Annotations[garagev1beta1.AnnotationPurgeClusterLayout]

	// A terminal migration (Completed/Failed) must NEVER restart from a lingering
	// trigger annotation. This is the regression guard for the destructive
	// re-trigger loop: if the annotation removal at start/finish ever loses a
	// race, just clear the annotation and stay terminal. Re-running a migration
	// requires clearing status.factorMigration first.
	if fm != nil && (fm.Phase == fmPhaseCompleted || fm.Phase == fmPhaseFailed) {
		if ann != "" {
			return ctrl.Result{}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
		}
		return ctrl.Result{}, nil
	}

	inFlight := fm != nil && fm.Phase != ""

	// Fresh start: a present annotation is a new request. Capture its intent into
	// status and CONSUME (remove) the annotation immediately so it can't re-trigger.
	if !inFlight {
		if ann == "" {
			return ctrl.Result{}, nil
		}
		toFactor, force, perr := parsePurgeAnnotation(ann)
		now := metav1.Now()
		if perr != nil {
			r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
				*m = garagev1beta2.FactorMigrationStatus{Phase: fmPhaseFailed, Message: perr.Error(), StartedAt: &now, CompletedAt: &now}
			})
			return ctrl.Result{}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
		}
		r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
			*m = garagev1beta2.FactorMigrationStatus{Phase: fmPhaseValidating, ToFactor: toFactor, Force: force, StartedAt: &now}
		})
		return ctrl.Result{RequeueAfter: time.Nanosecond}, r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout)
	}

	// In-flight: the annotation should already be consumed; remove it defensively
	// if a crash left it behind (idempotent).
	if ann != "" {
		if err := r.removeAnnotations(ctx, cluster, garagev1beta1.AnnotationPurgeClusterLayout); err != nil {
			return ctrl.Result{}, err
		}
	}

	switch fm.Phase {
	case fmPhaseValidating:
		return r.fmValidate(ctx, cluster)
	case fmPhaseScalingDown:
		return r.fmScaleDown(ctx, cluster)
	case fmPhasePurging:
		return r.fmPurge(ctx, cluster)
	case fmPhaseVerifying:
		return r.fmVerify(ctx, cluster)
	case fmPhaseRebuildingLayout:
		return r.fmRebuildLayout(ctx, cluster)
	case fmPhaseConverging:
		return r.fmConverge(ctx, cluster)
	}
	return ctrl.Result{}, nil
}

// fmValidate runs all hard safety guards before any destructive action. The
// target factor + force flag were captured into status when the annotation was
// consumed, so it reads them from status rather than the (now-removed) annotation.
func (r *GarageClusterReconciler) fmValidate(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	fm := cluster.Status.FactorMigration
	toFactor := fm.ToFactor
	force := fm.Force

	if cluster.Spec.Replication == nil || cluster.Spec.Replication.Factor != toFactor {
		// Admission requires factor edits to carry the matching annotation in one
		// update. Retain this grace period for an annotation-first request admitted
		// by an older webhook during a rolling operator upgrade.
		if fm != nil && fm.StartedAt != nil && time.Since(fm.StartedAt.Time) < fmValidateGrace {
			r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
				m.Message = fmt.Sprintf("waiting for spec.replication.factor to match annotation factor=%d (currently %d)",
					toFactor, replicationFactorOf(cluster))
			})
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return r.failFactorMigration(ctx, cluster,
			fmt.Sprintf("annotation factor=%d must match spec.replication.factor (%d)", toFactor, replicationFactorOf(cluster)))
	}
	if cluster.Spec.LayoutPolicy == LayoutPolicyManual {
		return r.failFactorMigration(ctx, cluster, "factor migration is only supported in Auto layout mode")
	}
	if len(cluster.Spec.RemoteClusters) > 0 {
		return r.failFactorMigration(ctx, cluster,
			"factor migration is refused while spec.remoteClusters is set (federated factor change requires a separate coordinated rollout)")
	}
	if !cluster.HasStorageTier() {
		return r.failFactorMigration(ctx, cluster, "factor migration requires a storage tier")
	}
	if hasNodeLocalPools(cluster) {
		return r.failFactorMigration(ctx, cluster,
			"factor migration is not supported while spec.storage.nodeLocalPools are present — "+
				"the coordinated purge relies on scaling per-ordinal StatefulSets to 0 and back, "+
				"which has no pool-quiescing equivalent yet; migrate the factor manually")
	}
	if !force && cluster.Spec.Replication.ConsistencyMode == consistencyModeDangerous {
		return r.failFactorMigration(ctx, cluster, "consistencyMode 'dangerous' requires ,force on the purge annotation")
	}
	if !force && len(cluster.Status.PendingGatewayTombstones) > 0 {
		return r.failFactorMigration(ctx, cluster,
			"pending gateway tombstones exist; clean them up (autoApply) or add ,force to the annotation")
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	// nongateway_nodes() >= factor is enforced by Garage at apply time; reject an
	// unappliable reduction up front (validated: src/rpc/layout/version.rs:328).
	if len(nodes) < toFactor {
		return r.failFactorMigration(ctx, cluster,
			fmt.Sprintf("%d storage nodes < requested factor %d — layout would be unappliable", len(nodes), toFactor))
	}
	// A node with per-node config overrides consumes its own <node>-config
	// ConfigMap, which ONLY the per-node controller rewrites — and the migration
	// suspends that controller before purging. The migration cannot refresh the
	// new replication_factor into those ConfigMaps, so the purged pod would boot
	// at the OLD factor and wedge the cluster in a mixed-factor state (a
	// lower-factor node std::process::exit(1)s, or the layout is discarded —
	// src/rpc/system.rs, src/rpc/layout/manager.rs). Refuse rather than corrupt.
	for _, name := range sortedFactorMigrationNodeNames(nodes) {
		n := nodes[name]
		if nodeHasConfigOverrides(n) {
			return r.failFactorMigration(ctx, cluster, fmt.Sprintf(
				"storage node %q has per-node config overrides (e.g. multi-HDD dataPaths, fsync, network, publicEndpoint, or logging); "+
					"coordinated factor migration cannot refresh the new factor into per-node ConfigMaps yet — "+
					"remove the overrides or migrate the factor manually", name))
		}
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseScalingDown
		m.PurgeID = purgeIDFromStart(m)
		m.Message = fmt.Sprintf("validated; reducing/setting replication factor to %d across %d storage nodes", toFactor, len(nodes))
	})
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

// fmScaleDown suspends the per-node controllers and scales every storage
// StatefulSet to 0, confirming zero old-factor pods remain before proceeding.
// This is the simultaneous-restart guarantee: a surviving higher-factor pod would
// std::process::exit(1) any new lower-factor pod (validated: src/rpc/system.rs).
func (r *GarageClusterReconciler) fmScaleDown(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	fm := cluster.Status.FactorMigration

	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for name, n := range nodes {
		// Suspend the per-node controller so it won't fight our STS edits.
		if n.Annotations[garagev1beta1.AnnotationOperatorSuspended] != fm.PurgeID {
			if n.Annotations == nil {
				n.Annotations = map[string]string{}
			}
			n.Annotations[garagev1beta1.AnnotationOperatorSuspended] = fm.PurgeID
			if err := r.Update(ctx, n); err != nil {
				return ctrl.Result{}, fmt.Errorf("suspending GarageNode %s: %w", name, err)
			}
		}
		if err := r.scaleStorageSTSForNode(ctx, cluster, n, 0); err != nil {
			return ctrl.Result{}, err
		}
	}

	remaining, err := r.countStoragePods(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if remaining > 0 {
		log.Info("Factor migration: waiting for all storage pods to terminate", "remaining", remaining)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhasePurging
		m.Message = "all storage pods terminated; deleting on-disk cluster_layout"
	})
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

// fmPurge prepares every storage StatefulSet while the entire tier remains at
// zero replicas, proves every template is complete, and only then begins the
// scale-up pass. This ordering is deliberately retry-safe: after a crash during
// preparation all members are still quiesced; after a crash during scale-up a
// retry verifies the already-prepared templates and resumes the idempotent
// scale pass without trying to patch a running member.
func (r *GarageClusterReconciler) fmPurge(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}
	fm := cluster.Status.FactorMigration
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	names := sortedFactorMigrationNodeNames(nodes)
	anyRunning := false
	for _, name := range names {
		running, err := r.factorMigrationStatefulSetRunning(ctx, cluster, nodes[name])
		if err != nil {
			return ctrl.Result{}, err
		}
		anyRunning = anyRunning || running
	}
	if !anyRunning {
		// Keep these as distinct all-member passes. A process death after any API
		// write leaves every StatefulSet at zero and can safely repeat either pass.
		for _, name := range names {
			if err := r.patchSTSConfigRevisionForFactorMigration(ctx, cluster, nodes[name]); err != nil {
				return ctrl.Result{}, err
			}
		}
		for _, name := range names {
			if err := r.patchSTSPurgeInitContainerForNode(ctx, cluster, nodes[name], fm.PurgeID, true); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	for _, name := range names {
		if err := r.verifyFactorMigrationPurgePreparation(ctx, cluster, nodes[name], fm.PurgeID, !anyRunning); err != nil {
			return ctrl.Result{}, err
		}
	}
	for _, name := range names {
		if err := r.scaleStorageSTSForNode(ctx, cluster, nodes[name], 1); err != nil {
			return ctrl.Result{}, err
		}
	}
	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseVerifying
		m.Message = "storage pods restarting with purged layout at the new factor"
	})
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

// patchSTSConfigRevisionForFactorMigration moves a quiesced, suspended
// GarageNode StatefulSet to the exact immutable shared garage.toml revision
// before the destructive purge restart. Fixed-name ConfigMaps used to change
// beneath the template; content-addressed publication deliberately cannot.
func (r *GarageClusterReconciler) patchSTSConfigRevisionForFactorMigration(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) error {
	if node == nil {
		return fmt.Errorf("factor-migration GarageNode is nil")
	}
	name := node.Name
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		return fmt.Errorf("building factor-migration Garage config: %w", err)
	}
	body := generateGarageConfig(cluster, cfgCtx)
	baseName := cluster.Name + "-config"
	configRevision, err := garageConfigRevision(ctx, r.safetyReader(), cluster, body)
	if err != nil {
		return fmt.Errorf("deriving factor-migration config revision: %w", err)
	}
	configName := garageConfigRevisionName(baseName, configRevision)
	published, object, err := readGarageConfigResource(
		ctx, r.safetyReader(), cluster.Namespace, configName, garageConfigUsesSecret(cluster),
	)
	if err != nil {
		return fmt.Errorf("reading factor-migration config revision %s: %w", configName, err)
	}
	if published != body || !metav1.IsControlledBy(object, cluster) {
		return fmt.Errorf("factor-migration config revision %s is not the exact GarageCluster-owned rendered input", configName)
	}
	sts := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, sts); err != nil {
		return fmt.Errorf("reading factor-migration StatefulSet %s: %w", name, err)
	}
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 0 {
		return fmt.Errorf("refusing to patch factor-migration StatefulSet %s config before it is quiesced at zero replicas", name)
	}
	if !metav1.IsControlledBy(sts, node) {
		return fmt.Errorf("factor-migration StatefulSet %s is not controlled by exact GarageNode UID %s", name, node.UID)
	}
	configAnnotationRevision, err := garageConfigAnnotationRevision(ctx, r.safetyReader(), cluster, body)
	if err != nil {
		return fmt.Errorf("deriving factor-migration config annotation revision: %w", err)
	}
	desiredVolumeSource := garageConfigVolumeSource(cluster, configName)
	configAlreadyCurrent := sts.Spec.Template.Annotations[annotationConfigHash] == configAnnotationRevision
	updated := false
	for i := range sts.Spec.Template.Spec.Volumes {
		volume := &sts.Spec.Template.Spec.Volumes[i]
		if volume.Name != configVolumeName {
			continue
		}
		configAlreadyCurrent = configAlreadyCurrent && equality.Semantic.DeepEqual(volume.VolumeSource, desiredVolumeSource)
		volume.VolumeSource = desiredVolumeSource
		updated = true
		break
	}
	if !updated {
		return fmt.Errorf("factor-migration StatefulSet %s has no %q config volume", name, configVolumeName)
	}
	if sts.Spec.Template.Annotations == nil {
		sts.Spec.Template.Annotations = make(map[string]string)
	}
	sts.Spec.Template.Annotations[annotationConfigHash] = configAnnotationRevision
	// Leave annotationStorageRolloutInput untouched. Once the migration releases
	// the GarageNode controller, its ordinary renderer recomputes the complete
	// pod-spec hash and generation-bound acknowledgment before normal rollout can
	// report convergence.
	if configAlreadyCurrent {
		return nil
	}
	if err := r.Update(ctx, sts); err != nil {
		return fmt.Errorf("patching factor-migration StatefulSet %s to config revision %s: %w", name, configName, err)
	}
	return nil
}

func sortedFactorMigrationNodeNames(nodes map[string]*garagev1beta1.GarageNode) []string {
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *GarageClusterReconciler) factorMigrationStatefulSetRunning(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) (bool, error) {
	if node == nil {
		return false, fmt.Errorf("factor-migration GarageNode is nil")
	}
	sts := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: node.Name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, sts); err != nil {
		return false, fmt.Errorf("reading factor-migration StatefulSet %s: %w", key, err)
	}
	if !metav1.IsControlledBy(sts, node) {
		return false, fmt.Errorf("factor-migration StatefulSet %s is not controlled by exact GarageNode UID %s", key, node.UID)
	}
	if sts.Spec.Replicas == nil {
		return false, fmt.Errorf("factor-migration StatefulSet %s has no explicit replica count", key)
	}
	switch *sts.Spec.Replicas {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("factor-migration StatefulSet %s has unsafe replica count %d; expected zero or one", key, *sts.Spec.Replicas)
	}
}

func (r *GarageClusterReconciler) verifyFactorMigrationPurgePreparation(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	purgeID string,
	requireQuiesced bool,
) error {
	if node == nil {
		return fmt.Errorf("factor-migration GarageNode is nil")
	}
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		return fmt.Errorf("building factor-migration Garage config proof: %w", err)
	}
	body := generateGarageConfig(cluster, cfgCtx)
	revision, err := garageConfigRevision(ctx, r.safetyReader(), cluster, body)
	if err != nil {
		return fmt.Errorf("deriving factor-migration Garage config proof: %w", err)
	}
	configName := garageConfigRevisionName(cluster.Name+"-config", revision)
	secretBacked := garageConfigUsesSecret(cluster)
	published, object, err := readGarageConfigResource(
		ctx, r.safetyReader(), cluster.Namespace, configName, secretBacked,
	)
	if err != nil {
		return fmt.Errorf("reading factor-migration config proof %s: %w", configName, err)
	}
	if published != body || !metav1.IsControlledBy(object, cluster) || !garageConfigResourceIsImmutable(object) {
		return fmt.Errorf("factor-migration config revision %s is not the exact immutable GarageCluster-owned rendered input", configName)
	}

	sts := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: node.Name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, sts); err != nil {
		return fmt.Errorf("reading prepared factor-migration StatefulSet %s: %w", key, err)
	}
	if !metav1.IsControlledBy(sts, node) {
		return fmt.Errorf("prepared factor-migration StatefulSet %s is not controlled by exact GarageNode UID %s", key, node.UID)
	}
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas < 0 || *sts.Spec.Replicas > 1 ||
		(requireQuiesced && *sts.Spec.Replicas != 0) {
		return fmt.Errorf("prepared factor-migration StatefulSet %s has unsafe replica count", key)
	}
	mountedName, mountedSecret, err := mountedGarageConfigResource(sts.Spec.Template.Spec)
	if err != nil {
		return fmt.Errorf("checking prepared factor-migration StatefulSet %s config mount: %w", key, err)
	}
	if mountedName != configName || mountedSecret != secretBacked {
		return fmt.Errorf("prepared factor-migration StatefulSet %s does not mount exact config revision %s", key, configName)
	}
	annotationRevision, err := garageConfigAnnotationRevision(ctx, r.safetyReader(), cluster, body)
	if err != nil {
		return fmt.Errorf("deriving factor-migration config annotation proof: %w", err)
	}
	if sts.Spec.Template.Annotations[annotationConfigHash] != annotationRevision {
		return fmt.Errorf("prepared factor-migration StatefulSet %s does not carry exact config annotation revision", key)
	}
	expectedInit := factorMigrationPurgeInitContainer(sts, purgeID)
	found := 0
	for i := range sts.Spec.Template.Spec.InitContainers {
		if sts.Spec.Template.Spec.InitContainers[i].Name != fmPurgeInitContainerName {
			continue
		}
		found++
		if !equality.Semantic.DeepEqual(sts.Spec.Template.Spec.InitContainers[i], expectedInit) {
			return fmt.Errorf("prepared factor-migration StatefulSet %s has a stale or altered purge init container", key)
		}
	}
	if found != 1 {
		return fmt.Errorf("prepared factor-migration StatefulSet %s has %d purge init containers; expected exactly one", key, found)
	}
	return nil
}

// fmVerify waits for every storage pod to become Ready at the new factor. A pod
// that crash-loops (factor/layout mismatch) never becomes Ready, so all-Ready is
// a sufficient proxy for "booted cleanly at the new factor".
func (r *GarageClusterReconciler) fmVerify(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	ready, err := r.countReadyStoragePods(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ready < len(nodes) {
		log.Info("Factor migration: waiting for storage pods to become Ready", "ready", ready, "want", len(nodes))
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseRebuildingLayout
		m.Message = "all storage pods Ready; rebuilding the layout from scratch"
	})
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

// fmRebuildLayout re-stages EVERY node role (purging cluster_layout wiped them
// all) and applies once, then strips the purge init containers. Node identity
// survives (the metadata PVC's node_key was untouched), so status.nodeId is still
// valid.
func (r *GarageClusterReconciler) fmRebuildLayout(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Bound this phase: every path below requeues (admin not up, node identity
	// not yet observed, staging/apply failure). Without a per-phase guard a node
	// whose status.nodeId never repopulates after the purge restart would loop
	// here forever with the tier still suspended.
	if stuck, res, err := r.fmCheckStuck(ctx, cluster); stuck {
		return res, err
	}

	// Every retry below is silent at default verbosity, so a phase that cannot
	// make progress looks identical to one that is merely slow — from the
	// outside, and from status. Record which precondition is still unmet so an
	// operator watching a destructive migration (and a CI failure dump) can see
	// what it is waiting on without a debug-level rebuild.
	waiting := func(reason string, args ...any) ctrl.Result {
		detail := "rebuilding the layout from scratch; waiting: " + fmt.Sprintf(reason, args...)
		log.V(1).Info("Factor migration: rebuild waiting", "reason", detail)
		// Only write when the reason actually changes: this path retries every 5s,
		// and setFactorMigration persists unconditionally.
		if cluster.Status.FactorMigration == nil || cluster.Status.FactorMigration.Message != detail {
			r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
				m.Message = detail
			})
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}
	}

	// Pin to one storage Pod rather than dialing the cluster Service.
	//
	// The purge deleted cluster_layout everywhere, so there is no committed layout
	// yet — which is exactly the state the shared client cannot serve. Its dynamic
	// token cannot be re-proved (that needs the admin-token table, which needs a
	// layout, which needs this client), and the load-balanced Service must never
	// carry a substituted credential: a Pod that predates the last static rotation
	// rejects it with a 403, intermittently, depending on which Pod is picked.
	//
	// staticGarageClientForPod reads the bearer out of the target Pod's own spec,
	// so it is by construction the credential that process accepted at startup.
	// This is the same bootstrap client reconcileOperatorAdminToken uses before a
	// dynamic token exists, which is the situation a purge recreates.
	podSet, err := getOperatorAdminPodSet(ctx, r.safetyReader(), cluster)
	if err != nil {
		return waiting("managed storage Pod set is not provable yet: %v", err), nil
	}
	gc, err := r.staticGarageClientForPod(ctx, &podSet.Pods[0], getAdminPort(cluster))
	if err != nil {
		return waiting("exact-Pod bootstrap Admin client unavailable: %v", err), nil
	}
	// The node-local-pool rollout exclusion cannot legitimately apply here, and
	// waiting on it deadlocks. It is asserted whenever StorageRolloutReady's
	// observedGeneration trails spec — which a factor migration guarantees, because
	// the factor edit bumps the generation and Reconcile dispatches to this state
	// machine BEFORE the rollout reconciliation that would catch the condition up.
	// Nothing it protects against can be in flight: fmValidate refuses a migration
	// outright when spec.storage.nodeLocalPools is set, and fmScaleDown suspends
	// the per-node controllers, so the migration is the only layout writer left.
	// The storage-drain exclusion still applies — that one can be real.
	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(r.layoutMutationCoordinator(), cluster)
	if err != nil {
		return waiting("layout mutation coordinator busy: %v", err), nil
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, gc); err != nil {
		return waiting("layout history not settled: %v", err), nil
	}

	changes, err := r.buildRebuildRoleChanges(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(changes) == 0 {
		return waiting("no storage node identity is observable yet; pods may still be settling"), nil
	}
	layout, err := gc.GetClusterLayout(ctx)
	if err != nil {
		return waiting("reading the rebuilt layout failed: %v", err), nil
	}
	if _, err := stageAndApplyExclusiveLayout(ctx, gc, layout, changes, nil, func() error {
		if err := gc.UpdateClusterLayout(ctx, changes); err != nil {
			return fmt.Errorf("staging rebuilt roles: %w", err)
		}
		return nil
	}); err != nil {
		return waiting("applying the rebuilt layout failed: %v", err), nil
	}

	// Strip the purge init containers so future restarts are clean (the marker
	// file also guards against re-deletion).
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, name := range sortedFactorMigrationNodeNames(nodes) {
		if err := r.patchSTSPurgeInitContainerForNode(ctx, cluster, nodes[name], "", false); err != nil {
			return ctrl.Result{}, err
		}
	}

	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseConverging
		m.Message = fmt.Sprintf("layout rebuilt at factor %d with %d storage roles", m.ToFactor, len(changes))
	})
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

// fmConverge resumes the per-node controllers and finalizes. A Tables repair is
// triggered best-effort to cover the metadata-lag caveat after a layout rebuild.
func (r *GarageClusterReconciler) fmConverge(ctx context.Context, cluster *garagev1beta2.GarageCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if err := r.clearStorageSuspension(ctx, cluster); err != nil {
		return ctrl.Result{}, err
	}

	if gc, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain); err == nil {
		if err := gc.LaunchRepair(ctx, "*", garagev1beta1.RepairTypeTables); err != nil {
			log.V(1).Info("Factor migration: best-effort Tables repair failed", "error", err)
		}
	}

	now := metav1.Now()
	r.setFactorMigration(ctx, cluster, func(m *garagev1beta2.FactorMigrationStatus) {
		m.Phase = fmPhaseCompleted
		m.CompletedAt = &now
		m.Message = fmt.Sprintf("replication factor migrated to %d; full re-replication proceeds in the background", m.ToFactor)
	})
	log.Info("Factor migration completed", "factor", cluster.Status.FactorMigration.ToFactor)
	// The trigger annotation was consumed at start, so there's nothing to remove
	// here — the terminal Completed phase prevents any re-trigger.
	return ctrl.Result{}, nil
}

// --- helpers ---------------------------------------------------------------

// parsePurgeAnnotation parses "factor=N" or "factor=N,force".
func parsePurgeAnnotation(val string) (factor int, force bool, err error) {
	request, err := factormigration.Parse(val)
	if err != nil {
		return 0, false, err
	}
	return request.Factor, request.Force, nil
}

func replicationFactorOf(cluster *garagev1beta2.GarageCluster) int {
	if cluster.Spec.Replication != nil {
		return cluster.Spec.Replication.Factor
	}
	return 0
}

func purgeIDFromStart(fm *garagev1beta2.FactorMigrationStatus) string {
	if fm != nil && fm.StartedAt != nil {
		return fmt.Sprintf("p%d", fm.StartedAt.Unix())
	}
	return "p0"
}

// fmCheckStuck transitions to Failed if the CURRENT phase has been running
// longer than fmStuckTimeout. The deadline is measured from phaseStartedAt
// (reset on every transition by setFactorMigration); it falls back to startedAt
// for a migration that began before phaseStartedAt was tracked.
func (r *GarageClusterReconciler) fmCheckStuck(ctx context.Context, cluster *garagev1beta2.GarageCluster) (bool, ctrl.Result, error) {
	fm := cluster.Status.FactorMigration
	if fm == nil {
		return false, ctrl.Result{}, nil
	}
	since := fm.PhaseStartedAt
	if since == nil {
		since = fm.StartedAt
	}
	if since == nil || time.Since(since.Time) <= fmStuckTimeout {
		return false, ctrl.Result{}, nil
	}
	res, err := r.failFactorMigration(ctx, cluster,
		fmt.Sprintf("phase %q exceeded %s; aborting — inspect pods then re-trigger or set the abort annotation", fm.Phase, fmStuckTimeout))
	return true, res, err
}

// buildRebuildRoleChanges produces the full set of role assignments to rebuild
// the wiped layout: every storage node's capacity role plus every gateway node's
// capacity=nil role.
func (r *GarageClusterReconciler) buildRebuildRoleChanges(ctx context.Context, cluster *garagev1beta2.GarageCluster) ([]garage.NodeRoleChange, error) {
	var changes []garage.NodeRoleChange

	storage, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return nil, err
	}
	capacity := r.calculateNodeCapacity(cluster)
	reserve := 0
	if cluster.HasStorageTier() {
		reserve = cluster.Spec.Storage.CapacityReservePercent
	}
	effective := calculateEffectiveCapacity(capacity, reserve)
	for _, n := range storage {
		if n.Status.NodeID == "" {
			return nil, nil // identity not yet observed; caller retries
		}
		zone := n.Spec.Zone
		tags := n.Spec.Tags
		if tags == nil {
			tags = []string{}
		}
		changes = append(changes, garage.NodeRoleChange{ID: n.Status.NodeID, Zone: zone, Capacity: ptr.To(effective), Tags: tags})
	}

	gateway, err := r.listAutoModeGatewayNodes(ctx, cluster)
	if err != nil {
		return nil, err
	}
	for _, n := range gateway {
		if n.Status.NodeID == "" {
			continue // gateway identity may lag; tombstone cleanup re-adds it later
		}
		tags := n.Spec.Tags
		if tags == nil {
			tags = []string{}
		}
		changes = append(changes, garage.NodeRoleChange{ID: n.Status.NodeID, Zone: n.Spec.Zone, Capacity: nil, Tags: tags})
	}
	return changes, nil
}

func (r *GarageClusterReconciler) scaleStorageSTSForNode(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	replicas int32,
) error {
	if node == nil {
		return fmt.Errorf("factor-migration GarageNode is nil")
	}
	sts := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: node.Name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading factor-migration StatefulSet %s: %w", key, err)
	}
	if !metav1.IsControlledBy(sts, node) {
		return fmt.Errorf("factor-migration StatefulSet %s is not controlled by exact GarageNode UID %s", key, node.UID)
	}
	if sts.Spec.Replicas != nil && *sts.Spec.Replicas == replicas {
		return nil
	}
	sts.Spec.Replicas = ptr.To(replicas)
	if err := r.Update(ctx, sts); err != nil {
		return fmt.Errorf("scaling factor-migration StatefulSet %s to %d: %w", key, replicas, err)
	}
	return nil
}

// patchSTSPurgeInitContainer adds (add=true) or removes (add=false) the
// marker-guarded busybox init container that deletes cluster_layout. The marker
// (/data/metadata/.purged-<purgeID>) ensures the delete happens exactly once even
// across extra restarts.
func (r *GarageClusterReconciler) patchSTSPurgeInitContainer(ctx context.Context, cluster *garagev1beta2.GarageCluster, name, purgeID string, add bool) error {
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Drop any existing purge init container first (idempotent).
	hadPurge := false
	filtered := sts.Spec.Template.Spec.InitContainers[:0]
	for _, c := range sts.Spec.Template.Spec.InitContainers {
		if c.Name == fmPurgeInitContainerName {
			hadPurge = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !add {
		// Removal is a no-op when no purge container is present — avoids a
		// spurious StatefulSet rollout when teardown runs on an untouched tier.
		if !hadPurge {
			return nil
		}
		sts.Spec.Template.Spec.InitContainers = filtered
		return r.Update(ctx, sts)
	}

	sts.Spec.Template.Spec.InitContainers = filtered
	init := factorMigrationPurgeInitContainer(sts, purgeID)
	sts.Spec.Template.Spec.InitContainers = append([]corev1.Container{init}, sts.Spec.Template.Spec.InitContainers...)
	return r.Update(ctx, sts)
}

func (r *GarageClusterReconciler) patchSTSPurgeInitContainerForNode(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	purgeID string,
	add bool,
) error {
	if node == nil {
		return fmt.Errorf("factor-migration GarageNode is nil")
	}
	sts := &appsv1.StatefulSet{}
	key := types.NamespacedName{Name: node.Name, Namespace: cluster.Namespace}
	if err := r.safetyReader().Get(ctx, key, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading factor-migration StatefulSet %s: %w", key, err)
	}
	if !metav1.IsControlledBy(sts, node) {
		return fmt.Errorf("factor-migration StatefulSet %s is not controlled by exact GarageNode UID %s", key, node.UID)
	}
	if add && (sts.Spec.Replicas == nil || *sts.Spec.Replicas != 0) {
		return fmt.Errorf("refusing to patch factor-migration StatefulSet %s purge init before it is quiesced at zero replicas", key)
	}

	filtered := make([]corev1.Container, 0, len(sts.Spec.Template.Spec.InitContainers))
	for i := range sts.Spec.Template.Spec.InitContainers {
		if sts.Spec.Template.Spec.InitContainers[i].Name != fmPurgeInitContainerName {
			filtered = append(filtered, sts.Spec.Template.Spec.InitContainers[i])
		}
	}
	desired := filtered
	if add {
		desired = append([]corev1.Container{factorMigrationPurgeInitContainer(sts, purgeID)}, filtered...)
	}
	if equality.Semantic.DeepEqual(sts.Spec.Template.Spec.InitContainers, desired) {
		return nil
	}
	sts.Spec.Template.Spec.InitContainers = desired
	if err := r.Update(ctx, sts); err != nil {
		return fmt.Errorf("patching factor-migration StatefulSet %s purge init: %w", key, err)
	}
	return nil
}

func factorMigrationPurgeInitContainer(sts *appsv1.StatefulSet, purgeID string) corev1.Container {
	marker := fmt.Sprintf("%s/.purged-%s", metadataPath, purgeID)
	// set -e so a failed rm (e.g. EACCES) surfaces as a non-zero init exit
	// instead of being masked — the pod then visibly stalls in Init with the
	// error rather than the migration silently never purging.
	script := fmt.Sprintf("set -e\nif [ ! -f %q ]; then\n  rm -f %s/cluster_layout\n  touch %q\nfi", marker, metadataPath, marker)
	return corev1.Container{
		Name:    fmPurgeInitContainerName,
		Image:   "busybox:1.37",
		Command: []string{"/bin/sh", "-c", script},
		VolumeMounts: []corev1.VolumeMount{
			{Name: metadataVolName, MountPath: metadataPath},
		},
		SecurityContext: purgeInitSecurityContext(sts),
		// fmValidatePreparedSTS re-reads the StatefulSet and requires the stored
		// init container to DeepEqual this value, so anything the API server
		// defaults on write must be spelled out here. Otherwise the readback
		// always differs from the freshly built expectation, every purge is
		// rejected as "stale or altered", and the migration is stranded in
		// Purging with the storage tier scaled to zero.
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
	}
}

// purgeInitSecurityContext builds the SecurityContext for the purge init
// container. cluster_layout on the metadata volume is owned by whatever user
// the Garage container runs as — root by default, since the official image is
// FROM scratch with no USER. Hardcoding RunAsUser=1000/RunAsNonRoot would make
// `rm` fail with EACCES on a root-owned file and stall the pod in Init, so the
// init container must run as the same user as the storage pod (its effective
// RunAsUser, or the image default = root when unset).
func purgeInitSecurityContext(sts *appsv1.StatefulSet) *corev1.SecurityContext {
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if uid := purgeInitRunAsUser(sts); uid != nil {
		sc.RunAsUser = uid
		sc.RunAsNonRoot = ptr.To(*uid != 0)
	}
	return sc
}

// purgeInitRunAsUser returns the UID the storage pod runs as: the pod-level
// RunAsUser if set, else the first container's RunAsUser, else nil (image
// default — root for the FROM-scratch Garage image).
func purgeInitRunAsUser(sts *appsv1.StatefulSet) *int64 {
	ps := sts.Spec.Template.Spec
	if ps.SecurityContext != nil && ps.SecurityContext.RunAsUser != nil {
		return ps.SecurityContext.RunAsUser
	}
	for i := range ps.Containers {
		if c := ps.Containers[i].SecurityContext; c != nil && c.RunAsUser != nil {
			return c.RunAsUser
		}
	}
	return nil
}

// countStoragePods / countReadyStoragePods count pods of the cluster's storage tier.
func (r *GarageClusterReconciler) countStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) (int, error) {
	pods, err := r.listStoragePods(ctx, cluster)
	if err != nil {
		return 0, err
	}
	return len(pods), nil
}

func (r *GarageClusterReconciler) countReadyStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) (int, error) {
	pods, err := r.listStoragePods(ctx, cluster)
	if err != nil {
		return 0, err
	}
	ready := 0
	for i := range pods {
		for _, c := range pods[i].Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready++
			}
		}
	}
	return ready, nil
}

func (r *GarageClusterReconciler) listStoragePods(ctx context.Context, cluster *garagev1beta2.GarageCluster) ([]corev1.Pod, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// teardownFactorMigration reverses every destructive mutation a migration may
// have applied so the storage tier recovers without manual intervention: it
// strips the purge init container, scales each storage StatefulSet back to 1,
// and clears the per-node suspension so the GarageNode controllers resume. It
// is idempotent and safe to call from any phase (including before scale-down,
// where it is a no-op). Used by both the abort path and the failure path — a
// failed destructive migration must never leave the tier suspended and scaled
// to zero with no way back.
func (r *GarageClusterReconciler) teardownFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for _, name := range sortedFactorMigrationNodeNames(nodes) {
		if err := r.patchSTSPurgeInitContainerForNode(ctx, cluster, nodes[name], "", false); err != nil {
			return err
		}
		if err := r.scaleStorageSTSForNode(ctx, cluster, nodes[name], 1); err != nil {
			return err
		}
	}
	return r.clearStorageSuspension(ctx, cluster)
}

// clearStorageSuspension removes the operator-suspended annotation from every
// operator-owned storage GarageNode so the per-node controllers resume.
func (r *GarageClusterReconciler) clearStorageSuspension(ctx context.Context, cluster *garagev1beta2.GarageCluster) error {
	nodes, err := r.listAutoModeStorageNodes(ctx, cluster)
	if err != nil {
		return err
	}
	for name, n := range nodes {
		if _, ok := n.Annotations[garagev1beta1.AnnotationOperatorSuspended]; !ok {
			continue
		}
		delete(n.Annotations, garagev1beta1.AnnotationOperatorSuspended)
		if err := r.Update(ctx, n); err != nil {
			return fmt.Errorf("resuming GarageNode %s: %w", name, err)
		}
	}
	return nil
}

// setFactorMigration mutates status.factorMigration and persists it with retry.
// It auto-stamps PhaseStartedAt whenever the mutation advances Phase, so every
// transition site gets a per-phase deadline clock for free (and can't forget to
// reset it). The stamping is computed against the phase observed at entry, so it
// stays correct across UpdateStatusWithRetry's conflict re-fetch + re-apply.
func (r *GarageClusterReconciler) setFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, mutate func(*garagev1beta2.FactorMigrationStatus)) {
	log := logf.FromContext(ctx)
	apply := func() {
		if cluster.Status.FactorMigration == nil {
			cluster.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{}
		}
		fm := cluster.Status.FactorMigration
		prevPhase := fm.Phase
		mutate(fm)
		if fm.Phase != prevPhase {
			now := metav1.Now()
			fm.PhaseStartedAt = &now
		}
	}
	apply()
	if err := UpdateStatusWithRetry(ctx, r.Client, cluster, apply); err != nil {
		log.Error(err, "Failed to update factorMigration status")
	}
}

// failFactorMigration records a terminal Failed phase. The trigger annotation
// was consumed when the migration started, so the terminal phase alone prevents
// any re-trigger — re-running requires the user to re-apply the annotation.
func (r *GarageClusterReconciler) failFactorMigration(ctx context.Context, cluster *garagev1beta2.GarageCluster, message string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Factor migration failed", "message", message)
	// Reverse any destructive mutations so the storage tier self-heals rather
	// than being stranded suspended-and-scaled-to-zero. Only commit the terminal
	// Failed phase once teardown succeeds; if it errors (transient API failure),
	// requeue so it retries — the phase stays non-terminal and the migration path
	// keeps driving recovery.
	if err := r.teardownFactorMigration(ctx, cluster); err != nil {
		log.Error(err, "Factor migration: teardown after failure incomplete, will retry")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil //nolint:nilerr // retry teardown, don't wedge
	}
	now := metav1.Now()
	r.setFactorMigration(ctx, cluster, func(fm *garagev1beta2.FactorMigrationStatus) {
		fm.Phase = fmPhaseFailed
		fm.Message = message
		fm.CompletedAt = &now
	})
	return ctrl.Result{}, nil
}

// removeAnnotations deletes the given annotations from the cluster with conflict retry.
func (r *GarageClusterReconciler) removeAnnotations(ctx context.Context, cluster *garagev1beta2.GarageCluster, keys ...string) error {
	changed := false
	for _, k := range keys {
		if _, ok := cluster.Annotations[k]; ok {
			delete(cluster.Annotations, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.Update(ctx, cluster)
}
