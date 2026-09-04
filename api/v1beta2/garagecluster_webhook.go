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

package v1beta2

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/rajsinghtech/garage-operator/internal/factormigration"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
	"github.com/rajsinghtech/garage-operator/internal/storagecontract"
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

var garageclusterlog = logf.Log.WithName("garagecluster-resource")

const (
	zoneRedundancyMaximum                = "Maximum"
	zoneRedundancyAtLeast                = "AtLeast"
	layoutPolicyAuto                     = "Auto"
	layoutPolicyManual                   = "Manual"
	storageRolloutReadyCondition         = "StorageRolloutReady"
	storageRollingOutReason              = "RollingOut"
	storageInitializingReason            = "Initializing"
	drainPreparationAnnotation           = "garage.rajsingh.info/drain"
	forceDeleteUnrevokedTokensAnnotation = "garage.rajsingh.info/force-delete-unrevoked-operator-tokens"
	storageRolloutRecoveryAnnotation     = "garage.rajsingh.info/recover-storage-rollout"
	legacyRPCSecretMigrationAnnotation   = "garage.rajsingh.info/migrate-legacy-rpc-secret"

	v1beta2OnlyAnnotation                     = "garage.rajsingh.info/v1beta2-only"
	v1beta1PoolConversionPayloadAnnotation    = "garage.rajsingh.info/v1beta2-node-local-pools"
	v1beta1PoolConversionMarker               = "node-local-pools-present"
	v1beta1GatewayConversionPayloadAnnotation = "garage.rajsingh.info/v1beta2-gateway-tier"
	v1beta1GatewayConversionMarker            = "gateway-tier-present"
	kubernetesTotalAnnotationSizeLimit        = 256 * (1 << 10)
	nodeLocalPoolDataDir                      = "/data/data"
	nodeLocalPoolLabel                        = "garage.rajsingh.info/node-local-pool"
	nodeLocalPoolKubernetesNodeLabel          = "garage.rajsingh.info/kubernetes-node"
	consistencyModeConsistent                 = "consistent"
	ownershipModeSelfOwned                    = "self-owned"
	healthStatusHealthy                       = "healthy"
	stringTrue                                = "true"
	garageRPCSecretFileEnv                    = "GARAGE_RPC_SECRET_FILE"
	garageRPCSecretEnv                        = "GARAGE_RPC_SECRET"
	garageAdminTokenEnv                       = "GARAGE_ADMIN_TOKEN"
	garageAllowWorldReadableSecretsEnv        = "GARAGE_ALLOW_WORLD_READABLE_SECRETS"
	garageConfigFileEnv                       = "GARAGE_CONFIG_FILE"
	selectorJSONField                         = "selector"
)

var operatorReservedLayoutTagPrefixes = []string{
	"cluster:",
	"cluster-uid:",
	"tier:",
	"rpc-address:",
	"node-local-pool:",
	"kubernetes-node:",
}

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageClusterDefaulter{}).
		WithValidator(&GarageClusterValidator{}).
		Complete(); err != nil {
		return err
	}
	mgr.GetWebhookServer().Register(
		garageClusterScaleValidationPath,
		&admission.Webhook{Handler: &garageClusterScaleValidator{Reader: mgr.GetAPIReader()}},
	)
	return nil
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta2-garagecluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1beta2,name=mgaragecluster.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageCluster] = &GarageClusterDefaulter{}

// GarageClusterDefaulter handles defaulting for GarageCluster.
type GarageClusterDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageClusterDefaulter) Default(ctx context.Context, obj *GarageCluster) error {
	garageclusterlog.Info("default", "name", obj.Name)

	if obj.Spec.LayoutPolicy == "" {
		obj.Spec.LayoutPolicy = layoutPolicyAuto
	}
	if obj.Spec.Replication == nil {
		obj.Spec.Replication = &ReplicationConfig{}
	}
	if obj.Spec.Replication.Factor == 0 {
		obj.Spec.Replication.Factor = 3
	}
	if obj.Spec.Replication.ConsistencyMode == "" {
		obj.Spec.Replication.ConsistencyMode = consistencyModeConsistent
	}

	if obj.Spec.LayoutManagement != nil && obj.Spec.LayoutManagement.Drain != nil &&
		obj.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy == "" {
		obj.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy = StorageDrainUnverifiedPeersBlock
	}
	if obj.Spec.Storage != nil {
		for i := range obj.Spec.Storage.NodeLocalPools {
			pool := &obj.Spec.Storage.NodeLocalPools[i]
			if pool.Metadata != nil && pool.Metadata.HostPathType == "" {
				pool.Metadata.HostPathType = corev1.HostPathDirectory
			}
			if pool.Data != nil && pool.Data.HostPathType == "" {
				pool.Data.HostPathType = corev1.HostPathDirectory
			}
			for j := range pool.DataPaths {
				if pool.DataPaths[j].HostPathType == "" {
					pool.DataPaths[j].HostPathType = corev1.HostPathDirectory
				}
			}
		}
	}

	// Default web hosting on (with a sensible per-namespace rootDomain).
	if obj.Spec.WebAPI == nil {
		enabled := true
		obj.Spec.WebAPI = &WebAPIConfig{
			Enabled:    &enabled,
			RootDomain: fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace),
		}
	} else {
		if obj.Spec.WebAPI.Enabled == nil {
			enabled := true
			obj.Spec.WebAPI.Enabled = &enabled
		}
		if *obj.Spec.WebAPI.Enabled && obj.Spec.WebAPI.RootDomain == "" {
			obj.Spec.WebAPI.RootDomain = fmt.Sprintf(".%s.%s.svc", obj.Name, obj.Namespace)
		}
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta2-garagecluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update;delete,versions=v1beta2,name=vgaragecluster.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageCluster] = &GarageClusterValidator{}

// GarageClusterValidator handles validation for GarageCluster.
type GarageClusterValidator struct{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateCreate(ctx context.Context, obj *GarageCluster) (admission.Warnings, error) {
	garageclusterlog.Info("validate create", "name", obj.Name)
	return obj.validateGarageCluster()
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageCluster) (admission.Warnings, error) {
	garageclusterlog.Info("validate update", "name", newObj.Name)
	oldDefaulted := oldObj.DeepCopy()
	if err := (&GarageClusterDefaulter{}).Default(ctx, oldDefaulted); err != nil {
		return nil, err
	}
	allowUnchangedLegacy := equality.Semantic.DeepEqual(oldDefaulted.Spec, newObj.Spec)

	grandfatherManagedName, err := validateManagedGarageClusterNameUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}
	claimTemplateWarnings, err := validateUnsupportedClaimTemplateUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}
	manualGatewayWarnings, tolerateLegacyManualGatewayMetadata := validateLegacyManualGatewayMetadataUpdate(oldObj, newObj)
	podLabelWarnings, err := validateGarageClusterPodLabelUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}
	validationObj := newObj.DeepCopy()
	if grandfatherManagedName {
		// metadata.name is immutable. The transition validator above proved that
		// this update adds no impossible managed child and does not roll a retained
		// impossible actor. Use a harmless name only to avoid re-running the strict
		// create-time name check inside the shared spec validator.
		validationObj.Name = "grandfathered"
	}
	clearUnsupportedClaimTemplates(validationObj)
	legacyVolumeWarnings, err := neutralizeLegacyGarageClusterVolumesForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyEnvironmentWarnings, err := neutralizeLegacyGarageClusterEnvironmentsForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyReplicaWarnings, err := neutralizeLegacyGarageClusterReplicaBoundsForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyShapeWarnings, err := neutralizeLegacyGarageClusterTierShapeForValidation(oldObj, newObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyConversionWarnings, allowLegacyConversionBudget, err := neutralizeLegacyConversionTransportForValidation(oldObj, newObj, validationObj)
	if err != nil {
		return nil, err
	}
	neutralizeGarageClusterReservedPodLabels(validationObj)
	if tolerateLegacyManualGatewayMetadata && validationObj.Spec.Gateway != nil {
		validationObj.Spec.Gateway.Metadata = nil
	}
	warnings, err := validationObj.validateGarageClusterWithOptions(allowLegacyConversionBudget, allowUnchangedLegacy)
	if grandfatherManagedName {
		warnings = append(warnings, "metadata.name is grandfathered for this non-expanding update; adding or rolling a managed workload remains blocked until the derived Kubernetes names are valid")
	}
	warnings = append(warnings, claimTemplateWarnings...)
	warnings = append(warnings, manualGatewayWarnings...)
	warnings = append(warnings, legacyVolumeWarnings...)
	warnings = append(warnings, legacyEnvironmentWarnings...)
	warnings = append(warnings, legacyReplicaWarnings...)
	warnings = append(warnings, legacyShapeWarnings...)
	warnings = append(warnings, legacyConversionWarnings...)
	warnings = append(warnings, podLabelWarnings...)
	if err != nil {
		return warnings, err
	}
	if err := validateAdminPortUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	oldSource, newSource := effectiveRPCIdentitySource(oldObj), effectiveRPCIdentitySource(newObj)
	attachesFirstHandleSource := oldObj.IsManagementHandle() && newObj.IsManagementHandle() && oldSource == "" && newSource != ""
	legacyRPCMigrationSourceChange := legacyRPCSecretMigrationSourceChangeAllowed(oldObj, newObj)
	if oldSource != newSource && !attachesFirstHandleSource && !legacyRPCMigrationSourceChange {
		return warnings, fmt.Errorf("RPC identity source is immutable after create (%s -> %s): Garage has no dual-secret bridge, so live rotation would partition a sequentially restarted mesh", oldSource, newSource)
	}
	if legacyRPCMigrationSourceChange {
		warnings = append(warnings, "spec.network.rpcSecretRef is changing only as part of the explicit released GARAGE_RPC_SECRET migration; the controller will keep every managed workload frozen until it proves the referenced Secret has the exact active credential bytes")
	}
	if oldObj.Status.StorageDrain != nil && !equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return warnings, fmt.Errorf("spec cannot change while status.storageDrain transaction %q is active; wait for its exact actor to complete", oldObj.Status.StorageDrain.TransactionID)
	}
	if oldObj.Status.StorageDrain != nil &&
		oldObj.Annotations[drainPreparationAnnotation] != newObj.Annotations[drainPreparationAnnotation] {
		return warnings, fmt.Errorf("annotation %s cannot change while status.storageDrain transaction %q is active", drainPreparationAnnotation, oldObj.Status.StorageDrain.TransactionID)
	}
	if garageClusterNodeLocalPoolRolloutActive(oldObj) {
		if oldObj.Annotations[storageRolloutRecoveryAnnotation] != "" &&
			newObj.Annotations[storageRolloutRecoveryAnnotation] == "" {
			return warnings, fmt.Errorf("annotation %s cannot be removed until the exact status.storageRollout actor converges", storageRolloutRecoveryAnnotation)
		}
		if !equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
			if !storageRolloutRecoverySafeSpecChange(oldObj, newObj) {
				// Name the transaction that actually froze the spec, and the exact
				// actor it owns. The recovery annotation this branch used to name is
				// usually absent, which sent the reader looking for state nobody set.
				return warnings, fmt.Errorf(
					"only workload and non-topology Garage configuration may change while the managed Pod replacement of %s is in flight; "+
						"replication, layout, membership, volume/capacity, RPC identity/public routing, federation, and service topology "+
						"stay frozen until that status.storageRollout actor converges, then retry",
					storageRolloutActorName(oldObj.Status.StorageRollout))
			}
		}
	}
	if err := validateGarageLayoutOwnershipUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	if err := validateDefaultPoolVolumeUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	// Manual → Auto is not supported: once a user has taken over node management,
	// the operator can't safely re-adopt their GarageNodes (they may have
	// custom per-node settings the cluster spec can't express). See issue #190.
	oldPolicy := oldObj.Spec.LayoutPolicy
	newPolicy := newObj.Spec.LayoutPolicy
	if oldPolicy == layoutPolicyManual && newPolicy != "" && newPolicy != layoutPolicyManual {
		return warnings, fmt.Errorf("layoutPolicy transition from Manual to Auto is not supported (one-way only) — see issue #190")
	}
	// Same one-way rule for the per-tier storage override: once storage is
	// Manual (user owns the storage GarageNodes), the operator can't safely
	// re-adopt them.
	oldStorage := oldObj.EffectiveStorageLayoutPolicy()
	newStorage := newObj.EffectiveStorageLayoutPolicy()
	if oldStorage == layoutPolicyManual && newStorage != "" && newStorage != layoutPolicyManual {
		return warnings, fmt.Errorf("spec.storage.layoutPolicy transition from Manual to Auto is not supported (one-way only) — see issue #190")
	}
	oldPools := nodeLocalPoolMap(oldObj)
	newPools := nodeLocalPoolMap(newObj)
	for name, oldPool := range oldPools {
		newPool, retained := newPools[name]
		if !retained {
			warnings = append(warnings,
				fmt.Sprintf("Removing storage.nodeLocalPools[%q] starts a one-node-at-a-time Garage layout drain; keep its hostPath data intact until the pool DaemonSet and GarageNodes are gone", name))
			continue
		}
		if oldPool.Metadata == nil || newPool.Metadata == nil ||
			oldPool.Metadata.HostPath != newPool.Metadata.HostPath {
			return warnings, fmt.Errorf(
				"spec.storage.nodeLocalPools[%q].metadata is immutable: it contains each Kubernetes Node's Garage identity; remove and fully drain the pool before recreating it with another metadata hostPath",
				name,
			)
		}
		if oldPool.Metadata.HostPathType != newPool.Metadata.HostPathType {
			if daemonSetHostPathTypeLoosens(oldPool.Metadata.HostPathType, newPool.Metadata.HostPathType) {
				return warnings, fmt.Errorf(
					"spec.storage.nodeLocalPools[%q].metadata.hostPathType cannot be loosened from Directory to DirectoryOrCreate: a missing metadata disk must fail closed instead of creating an empty node identity",
					name,
				)
			}
			warnings = append(warnings,
				fmt.Sprintf("Changing storage.nodeLocalPools[%q].metadata.hostPathType rolls the pool; verify every selected Node already has the expected metadata directory", name))
		}
		if !equality.Semantic.DeepEqual(oldPool.Selector, newPool.Selector) {
			warnings = append(warnings,
				fmt.Sprintf("Changing storage.nodeLocalPools[%q].selector uses an add-before-remove handoff: replacements must be Connected, InLayout, and fully synchronized in Garage's layout history before old nodes drain; do not remove or reuse their hostPath data until cleanup completes", name))
		}
		if err := validateNodeLocalPoolDataTransition(name, oldPool, newPool); err != nil {
			return warnings, err
		}
		if !maps.Equal(nodeLocalPoolDataHostPathMappings(oldPool), nodeLocalPoolDataHostPathMappings(newPool)) {
			warnings = append(warnings,
				fmt.Sprintf("Changing storage.nodeLocalPools[%q] data HostPath mappings may only add disks without detaching existing paths; retire and fully drain the whole pool before removing an old disk", name))
		} else if !equality.Semantic.DeepEqual(oldPool.Data, newPool.Data) ||
			!equality.Semantic.DeepEqual(oldPool.DataPaths, newPool.DataPaths) {
			warnings = append(warnings,
				fmt.Sprintf("Changing storage.nodeLocalPools[%q] data capacity, readOnly state, or hostPathType rolls the pool and updates Garage's persisted drive layout", name))
		}
		if oldPool.Capacity != nil && newPool.Capacity != nil && oldPool.Capacity.Cmp(*newPool.Capacity) != 0 {
			warnings = append(warnings,
				fmt.Sprintf("Changing storage.nodeLocalPools[%q].capacity updates every node's layout role and may trigger a large rebalance", name))
		}
	}
	if garageClusterPositiveStorageRemoval(oldObj, newObj) {
		if !garageClusterStorageRemovalIsTopologyOnly(oldObj, newObj) {
			return warnings, fmt.Errorf("positive-capacity membership removal must be a topology-only update: apply workload, Garage configuration, and retained-pool changes first, wait for StorageRolloutReady=True at that generation, then change only storage membership")
		}
		if effectiveStorageDrainConsistency(oldObj) != consistencyModeConsistent {
			return warnings, fmt.Errorf("positive-capacity removal is a two-step operation: first set spec.replication.consistencyMode: consistent and wait for StorageRolloutReady=True at that generation; remove capacity in a later update")
		}
		if effectiveStorageDrainConsistency(newObj) != consistencyModeConsistent {
			return warnings, fmt.Errorf("positive-capacity removal requires spec.replication.consistencyMode: consistent before the reversible topology edit is accepted")
		}
		if (len(oldObj.Spec.RemoteClusters) > 0 || len(newObj.Spec.RemoteClusters) > 0) &&
			(effectiveStorageDrainPeerPolicy(oldObj) != StorageDrainUnverifiedPeersAssumeConsistent ||
				effectiveStorageDrainPeerPolicy(newObj) != StorageDrainUnverifiedPeersAssumeConsistent) {
			return warnings, fmt.Errorf("federated positive-capacity removal is a two-step operation: set spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent and wait for the prepared generation to converge before removing capacity")
		}
		if err := garageClusterDrainReadiness(oldObj); err != nil {
			return warnings, fmt.Errorf("positive-capacity removal requires the old generation to be fully prepared before changing topology: %w", err)
		}
	}

	oldFactor := 0
	if oldObj.Spec.Replication != nil {
		oldFactor = oldObj.Spec.Replication.Factor
	}
	newFactor := 0
	if newObj.Spec.Replication != nil {
		newFactor = newObj.Spec.Replication.Factor
	}
	if oldFactor != 0 && newFactor != oldFactor {
		if err := factormigration.ValidateUpdate(oldFactor, newFactor, newObj.Annotations); err != nil {
			return warnings, err
		}
		warnings = append(warnings, "Changing replication factor on an existing cluster requires careful data migration")
	}

	return warnings, nil
}

func effectiveRPCIdentitySource(cluster *GarageCluster) string {
	if cluster == nil {
		return ""
	}
	selector := func(ref *corev1.SecretKeySelector) string {
		key := ref.Key
		if key == "" {
			key = "rpc-secret"
		}
		return "secret:" + cluster.Namespace + "/" + ref.Name + ":" + key
	}
	if cluster.Spec.Network.RPCSecretRef != nil {
		return selector(cluster.Spec.Network.RPCSecretRef)
	}
	if cluster.Spec.ConnectTo != nil {
		if cluster.Spec.ConnectTo.RPCSecretRef != nil {
			return selector(cluster.Spec.ConnectTo.RPCSecretRef)
		}
		if cluster.Spec.ConnectTo.ClusterRef != nil {
			namespace := cluster.Spec.ConnectTo.ClusterRef.Namespace
			if namespace == "" {
				namespace = cluster.Namespace
			}
			return "cluster:" + namespace + "/" + cluster.Spec.ConnectTo.ClusterRef.Name
		}
	}
	if cluster.IsManagementHandle() {
		// A handle with no explicit or inherited RPC source owns no Garage
		// workload identity. It may attach its first source later to enable
		// deterministic GarageKey creation; once attached, the source is immutable.
		return ""
	}
	return "secret:" + cluster.Namespace + "/" + cluster.Name + "-rpc-secret:rpc-secret"
}

// legacyRPCSecretMigrationSourceChangeAllowed permits only the staging half of
// a released GARAGE_RPC_SECRET migration. The old override remains
// byte-for-byte present, so changing the typed source cannot affect a running
// Pod; the controller independently reads and compares the credential before it
// allows the override to be removed or any workload to roll.
func legacyRPCSecretMigrationSourceChangeAllowed(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil ||
		newCluster.Annotations[legacyRPCSecretMigrationAnnotation] != stringTrue ||
		newCluster.Spec.Network.RPCSecretRef == nil ||
		!garageClusterHasOnlyRetainedLegacyRPCSecretEnvironment(oldCluster) ||
		!garageClusterHasOnlyRetainedLegacyRPCSecretEnvironment(newCluster) {
		return false
	}
	oldCopy := oldCluster.DeepCopy()
	oldCopy.Spec.Network.RPCSecretRef = newCluster.Spec.Network.RPCSecretRef.DeepCopy()
	return equality.Semantic.DeepEqual(oldCopy.Spec, newCluster.Spec)
}

func garageClusterHasOnlyRetainedLegacyRPCSecretEnvironment(cluster *GarageCluster) bool {
	if cluster == nil {
		return false
	}
	seenRPCSecret := false
	validate := func(template *PodTemplate) bool {
		if template == nil {
			return true
		}
		for i := range template.Env {
			if !garageEnvironmentNameReserved(template.Env[i].Name) {
				continue
			}
			if template.Env[i].Name != garageRPCSecretEnv {
				return false
			}
			seenRPCSecret = true
		}
		for i := range template.EnvFrom {
			if _, unsafe := garageEnvFromReservedExample(template.EnvFrom[i]); unsafe {
				return false
			}
		}
		return true
	}
	if cluster.Spec.Storage != nil && !validate(&cluster.Spec.Storage.PodTemplate) {
		return false
	}
	if cluster.Spec.Gateway != nil && !validate(&cluster.Spec.Gateway.PodTemplate) {
		return false
	}
	return seenRPCSecret
}

func validateGarageLayoutOwnershipUpdate(oldCluster, newCluster *GarageCluster) error {
	oldMode, oldTarget := garageLayoutOwnershipIdentity(oldCluster)
	newMode, newTarget := garageLayoutOwnershipIdentity(newCluster)
	if oldMode != newMode {
		return fmt.Errorf(
			"garage layout ownership mode is immutable: cannot change an existing GarageCluster from %s to %s; drain/delete it and create a distinct %s object",
			oldMode, newMode, newMode,
		)
	}
	if oldTarget != newTarget {
		return fmt.Errorf(
			"garage layout ownership target is immutable: cannot retarget an existing %s GarageCluster from %q to %q; drain/delete it against its current layout and create a distinct object for the new target",
			oldMode, oldTarget, newTarget,
		)
	}
	return nil
}

// garageLayoutOwnershipIdentity models the Admin/layout state and finalizer
// target, not merely workload shape. Credential rotation and bootstrap-peer
// updates remain possible when they do not change that target.
func garageLayoutOwnershipIdentity(cluster *GarageCluster) (mode, target string) {
	if cluster == nil {
		return ownershipModeSelfOwned, ""
	}
	if cluster.HasStorageTier() {
		return ownershipModeSelfOwned, cluster.Namespace + "/" + cluster.Name
	}
	if cluster.IsManagementHandle() {
		return "management-handle", connectedGarageLayoutTarget(cluster, true)
	}
	if cluster.IsEdgeGateway() {
		return "edge-gateway", connectedGarageLayoutTarget(cluster, false)
	}
	return ownershipModeSelfOwned, cluster.Namespace + "/" + cluster.Name
}

func connectedGarageLayoutTarget(cluster *GarageCluster, endpointFirst bool) string {
	if cluster == nil || cluster.Spec.ConnectTo == nil {
		return ""
	}
	connectTo := cluster.Spec.ConnectTo
	endpoint := strings.ToLower(strings.TrimRight(strings.TrimSpace(connectTo.AdminAPIEndpoint), "/"))
	clusterRef := func() string {
		if connectTo.ClusterRef == nil {
			return ""
		}
		namespace := connectTo.ClusterRef.Namespace
		if namespace == "" {
			namespace = cluster.Namespace
		}
		return "clusterRef:" + namespace + "/" + connectTo.ClusterRef.Name
	}
	if endpointFirst && endpoint != "" {
		return "adminApiEndpoint:" + endpoint
	}
	if ref := clusterRef(); ref != "" {
		return ref
	}
	if endpoint != "" {
		return "adminApiEndpoint:" + endpoint
	}
	if connectTo.RPCSecretRef != nil {
		key := connectTo.RPCSecretRef.Key
		if key == "" {
			key = "rpc-secret"
		}
		return "rpcSecretRef:" + cluster.Namespace + "/" + connectTo.RPCSecretRef.Name + ":" + key
	}
	// With only bootstrap peers, the operator-owned RPC secret remains attached
	// to this object; peers are discovery addresses rather than layout identity.
	return "generatedRpcSecret:" + cluster.Namespace + "/" + cluster.Name
}

// validateDefaultPoolVolumeUpdate rejects edits that the operator-managed
// default-group StatefulSets cannot reconcile and that could detach node_key or
// live block data. Manual mode owns no default-group workload: replicas and the
// cluster-level volume templates are ignored there, so they may be cleaned up
// without pretending user-owned GarageNodes are being drained. A volume
// topology may be chosen only in a separate update while both old and new
// generations have zero managed replicas. A 0->N or N->0 request cannot combine
// a template edit: retained PVCs would otherwise be silently reused with their
// old selector/class. With either side live, only non-decreasing size on the
// exact same PVC/EmptyDir source is supported. Removing a tier remains governed
// by the prepared positive-capacity drain path.
func validateDefaultPoolVolumeUpdate(oldCluster, newCluster *GarageCluster) error {
	if oldCluster == nil || newCluster == nil {
		return nil
	}
	if err := validateVolumeDataSourceRefsImmutable(oldCluster, newCluster); err != nil {
		return err
	}
	if oldCluster.Spec.Storage != nil && newCluster.Spec.Storage != nil &&
		(garageClusterHasManagedDefaultPool(oldCluster) || garageClusterHasManagedDefaultPool(newCluster)) {
		if err := validateClusterVolumeUpdate("spec.storage.metadata", oldCluster.Spec.Storage.Metadata, newCluster.Spec.Storage.Metadata); err != nil {
			return err
		}
		if err := validateClusterVolumeUpdate("spec.storage.data", oldCluster.Spec.Storage.Data, newCluster.Spec.Storage.Data); err != nil {
			return err
		}
	}
	if oldCluster.Spec.Gateway != nil && newCluster.Spec.Gateway != nil &&
		(garageClusterHasManagedGateway(oldCluster) || garageClusterHasManagedGateway(newCluster)) {
		oldGatewayMetadata := gatewayMetadataWithoutUnsupportedClaimTemplate(oldCluster.Spec.Gateway.Metadata)
		newGatewayMetadata := gatewayMetadataWithoutUnsupportedClaimTemplate(newCluster.Spec.Gateway.Metadata)
		if oldGatewayMetadata != nil && newGatewayMetadata != nil {
			if err := validateLegacyClusterVolumeIgnoredFieldTransition("spec.gateway.metadata", oldGatewayMetadata, newGatewayMetadata); err != nil {
				return err
			}
			normalizeLegacyClusterVolumeShapes(oldGatewayMetadata, oldGatewayMetadata, newGatewayMetadata)
		}
		if !oldCluster.HasStorageTier() && !newCluster.HasStorageTier() &&
			!equality.Semantic.DeepEqual(oldGatewayMetadata, newGatewayMetadata) {
			return fmt.Errorf("spec.gateway.metadata cannot change while an edge gateway has live replicas: scale spec.gateway.replicas to 0, wait for its capacity-less roles to retire, then change the metadata PVC/EmptyDir configuration")
		}
		if err := validateClusterVolumeUpdate("spec.gateway.metadata", oldCluster.Spec.Gateway.Metadata, newCluster.Spec.Gateway.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func validateClusterVolumeUpdate(field string, oldVolume, newVolume *VolumeConfig) error {
	if (oldVolume == nil) != (newVolume == nil) {
		return fmt.Errorf("%s volume topology is immutable while its default StatefulSet/PVC group has live replicas; drain the group to zero before changing volume sources", field)
	}
	if oldVolume == nil {
		return nil
	}
	if err := validateLegacyClusterVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return err
	}
	oldShape, newShape := *oldVolume, *newVolume
	oldShape.Size, newShape.Size = nil, nil
	oldShape.Paths, newShape.Paths = nil, nil
	// This legacy field was never rendered by any managed workload. Ignore it
	// when deciding whether a safe removal changes the actual PVC topology.
	oldShape.VolumeClaimTemplateSpec, newShape.VolumeClaimTemplateSpec = nil, nil
	normalizeLegacyClusterVolumeShapes(oldVolume, &oldShape, &newShape)
	if !equality.Semantic.DeepEqual(oldShape, newShape) {
		return fmt.Errorf("%s PVC/EmptyDir type, storage class, access modes, selector, labels, annotations, and claim template are immutable while replicas are live; only size growth is supported", field)
	}
	if err := validateClusterQuantityGrowth(field+".size", oldVolume.Size, newVolume.Size); err != nil {
		return err
	}
	if len(oldVolume.Paths) != len(newVolume.Paths) {
		return fmt.Errorf("%s.paths topology is immutable while replicas are live; migrate by draining/recreating the default StatefulSet/PVC group rather than changing StatefulSet claim templates", field)
	}
	for i := range oldVolume.Paths {
		oldPath, newPath := &oldVolume.Paths[i], &newVolume.Paths[i]
		if oldPath.Path != newPath.Path || oldPath.ReadOnly != newPath.ReadOnly ||
			(oldPath.Volume == nil) != (newPath.Volume == nil) {
			return fmt.Errorf("%s.paths[%d] path, readOnly state, and volume source are immutable while replicas are live", field, i)
		}
		if err := validateClusterQuantityGrowth(fmt.Sprintf("%s.paths[%d].capacity", field, i), oldPath.Capacity, newPath.Capacity); err != nil {
			return err
		}
		if oldPath.Volume == nil {
			continue
		}
		oldPathShape, newPathShape := *oldPath.Volume, *newPath.Volume
		pathField := fmt.Sprintf("%s.paths[%d].volume", field, i)
		if err := validateLegacyDataPathVolumeIgnoredFieldTransition(pathField, oldPath.Volume, newPath.Volume); err != nil {
			return err
		}
		oldPathShape.Size, newPathShape.Size = nil, nil
		oldPathShape.VolumeClaimTemplateSpec, newPathShape.VolumeClaimTemplateSpec = nil, nil
		normalizeLegacyDataPathVolumeShapes(oldPath.Volume, &oldPathShape, &newPathShape)
		if !equality.Semantic.DeepEqual(oldPathShape, newPathShape) {
			return fmt.Errorf("%s.paths[%d].volume topology is immutable while replicas are live; only size growth is supported", field, i)
		}
		if err := validateClusterQuantityGrowth(fmt.Sprintf("%s.paths[%d].volume.size", field, i), oldPath.Volume.Size, newPath.Volume.Size); err != nil {
			return err
		}
	}
	return nil
}

func validateClusterQuantityGrowth(field string, oldQuantity, newQuantity *resource.Quantity) error {
	if equality.Semantic.DeepEqual(oldQuantity, newQuantity) {
		return nil
	}
	if oldQuantity == nil || newQuantity == nil || newQuantity.Cmp(*oldQuantity) < 0 {
		return fmt.Errorf("%s may only grow while the default StatefulSet/PVC group has live replicas", field)
	}
	return nil
}

func storageRolloutRecoverySafeSpecChange(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldSpec := oldCluster.DeepCopy().Spec
	newSpec := newCluster.DeepCopy().Spec
	normalizeStorageRolloutRecoveryFields(&oldSpec)
	normalizeStorageRolloutRecoveryFields(&newSpec)
	return equality.Semantic.DeepEqual(oldSpec, newSpec)
}

func normalizeStorageRolloutRecoveryFields(spec *GarageClusterSpec) {
	if spec == nil {
		return
	}
	spec.Image = ""
	spec.ImageRepository = ""
	spec.ImagePullPolicy = ""
	spec.ImagePullSecrets = nil
	spec.ServiceAccountName = ""
	spec.S3API = nil
	spec.K2VAPI = nil
	spec.WebAPI = nil
	spec.Admin = nil
	spec.Database = nil
	spec.Blocks = nil
	spec.Discovery = nil
	spec.Security = nil
	spec.Logging = nil
	// Bind and timeout corrections can make a failed Garage process start and
	// rejoin. Keep RPC identity, bootstrap/public routing, Secrets, and Service
	// topology frozen; those require a coordinated cluster-wide migration.
	spec.Network.RPCBindPort = 0
	spec.Network.RPCBindAddress = ""
	spec.Network.RPCBindOutgoing = false
	spec.Network.RPCPingTimeout = nil
	spec.Network.RPCTimeout = nil
	if spec.Storage != nil {
		spec.Storage.MetadataSnapshotsDir = ""
		spec.Storage.MetadataAutoSnapshotInterval = ""
		spec.Storage.MetadataFsync = false
		spec.Storage.DataFsync = false
		spec.Storage.PodTemplate = PodTemplate{}
		for i := range spec.Storage.NodeLocalPools {
			spec.Storage.NodeLocalPools[i].PodTemplate = nil
		}
	}
	if spec.Gateway != nil {
		spec.Gateway.ReadinessProbe = nil
		spec.Gateway.PodTemplate = PodTemplate{}
	}
}

// storageRolloutActorName renders the actor a replacement transaction owns, so a
// denied edit says which node is mid-replacement instead of only that something
// is.
func storageRolloutActorName(rollout *StorageRolloutStatus) string {
	switch {
	case rollout == nil:
		return "an unnamed actor"
	case rollout.GarageNodeName != "":
		return "GarageNode " + rollout.GarageNodeName
	case rollout.NodeLocalPoolName != "":
		return "node-local pool " + rollout.NodeLocalPoolName + " on Kubernetes Node " + rollout.KubernetesNodeName
	default:
		return "Garage identity " + rollout.GarageNodeID
	}
}

// garageClusterNodeLocalPoolRolloutActive reports whether a concrete managed-Pod
// replacement transaction owns an actor right now.
//
// Admission keys on the transaction alone, deliberately not on
// StorageRolloutReady. That condition is a convergence signal, not a lock: it
// reads False/Waiting while a brand-new node completes its first identity
// discovery, and it reads stale whenever its observedGeneration merely trails a
// spec edit. Neither state owns an actor or has data to protect, so freezing the
// spec on them denies edits that are perfectly safe — observed as a scale-up
// making the matching scale-down unappliable, with status.storageRollout nil the
// whole time.
//
// It also breaks GitOps outright: Argo and Flux re-apply continuously, so a spec
// change during any settling period turns into a persistent sync error on a
// healthy cluster, with no action the user can take but wait and retry. When a
// transaction really is in flight, status.storageRollout is set and the freeze
// applies — which is what the annotation-removal guard below already says it
// means ("until the exact status.storageRollout actor converges").
func garageClusterNodeLocalPoolRolloutActive(cluster *GarageCluster) bool {
	return cluster != nil && cluster.Status.StorageRollout != nil
}

func effectiveStorageDrainConsistency(cluster *GarageCluster) string {
	if cluster == nil || cluster.Spec.Replication == nil || cluster.Spec.Replication.ConsistencyMode == "" {
		return consistencyModeConsistent
	}
	return strings.ToLower(cluster.Spec.Replication.ConsistencyMode)
}

func effectiveStorageDrainPeerPolicy(cluster *GarageCluster) StorageDrainUnverifiedPeersPolicy {
	if cluster == nil || cluster.Spec.LayoutManagement == nil || cluster.Spec.LayoutManagement.Drain == nil ||
		cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy == "" {
		return StorageDrainUnverifiedPeersBlock
	}
	return cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy
}

func storageDrainPolicyWarnings(cluster *GarageCluster) admission.Warnings {
	if effectiveStorageDrainPeerPolicy(cluster) != StorageDrainUnverifiedPeersAssumeConsistent {
		return nil
	}
	return admission.Warnings{
		"spec.layoutManagement.drain.unverifiedPeersPolicy=AssumeConsistent is an operator assertion the API cannot verify: every external/federated Garage process must run literal consistencyMode=consistent, S3 writes should be quiesced, and topology/Admin operations must be serialized across sites",
	}
}

func garageClusterPositiveStorageRemoval(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || oldCluster.Spec.Storage == nil {
		return false
	}
	if newCluster == nil || newCluster.Spec.Storage == nil {
		return garageClusterHasManagedDefaultPool(oldCluster) || len(oldCluster.Spec.Storage.NodeLocalPools) > 0
	}
	// Do not require the new side to have replicas > 0: N -> 0 removes the
	// entire managed PVC group and needs every positive-capacity drain gate.
	// Auto -> Manual is an ownership handoff and intentionally stays excluded.
	if garageClusterHasManagedDefaultPool(oldCluster) &&
		newCluster.EffectiveStorageLayoutPolicy() != layoutPolicyManual &&
		newCluster.Spec.Storage.Replicas < oldCluster.Spec.Storage.Replicas {
		return true
	}
	oldPools := nodeLocalPoolMap(oldCluster)
	newPools := nodeLocalPoolMap(newCluster)
	for name, oldPool := range oldPools {
		newPool, retained := newPools[name]
		if !retained || !equality.Semantic.DeepEqual(oldPool.Selector, newPool.Selector) {
			return true
		}
	}
	return false
}

// garageClusterHasManagedDefaultPool distinguishes the StatefulSet/PVC group
// from user-owned GarageNodes. storage.replicas is retained in Manual-mode API
// objects for compatibility but has no workload or membership semantics there.
func garageClusterHasManagedDefaultPool(cluster *GarageCluster) bool {
	return cluster != nil && cluster.Spec.Storage != nil &&
		cluster.Spec.Storage.Replicas > 0 &&
		cluster.EffectiveStorageLayoutPolicy() != layoutPolicyManual
}

func garageClusterHasManagedGateway(cluster *GarageCluster) bool {
	return cluster != nil && cluster.Spec.Gateway != nil &&
		cluster.Spec.Gateway.Replicas > 0 && cluster.Spec.LayoutPolicy != layoutPolicyManual
}

func gatewayMetadataWithoutUnsupportedClaimTemplate(volume *VolumeConfig) *VolumeConfig {
	if volume == nil {
		return nil
	}
	copy := volume.DeepCopy()
	copy.VolumeClaimTemplateSpec = nil
	return copy
}

// garageClusterStorageRemovalIsTopologyOnly prevents a departing process from
// being excluded from the desired rollout set in the same generation that
// changes its executable configuration. The old generation is the prepared
// drain boundary; runtime changes must converge there before membership moves.
//
// Replica count, pool additions/removals, and selectors are topology. A newly
// added pool may carry its initial definition, while every retained pool must
// keep all non-selector fields stable for the duration of the handoff.
func garageClusterStorageRemovalIsTopologyOnly(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil ||
		oldCluster.Spec.Storage == nil || newCluster.Spec.Storage == nil {
		return false
	}

	oldPools := nodeLocalPoolMap(oldCluster)
	newPools := nodeLocalPoolMap(newCluster)
	for name, oldPool := range oldPools {
		newPool, retained := newPools[name]
		if !retained {
			continue
		}
		oldDefinition := oldPool.DeepCopy()
		newDefinition := newPool.DeepCopy()
		oldDefinition.Selector = metav1.LabelSelector{}
		newDefinition.Selector = metav1.LabelSelector{}
		if !equality.Semantic.DeepEqual(oldDefinition, newDefinition) {
			return false
		}
	}

	oldSpec := oldCluster.DeepCopy().Spec
	newSpec := newCluster.DeepCopy().Spec
	oldSpec.Storage.Replicas = 0
	newSpec.Storage.Replicas = 0
	oldSpec.Storage.NodeLocalPools = nil
	newSpec.Storage.NodeLocalPools = nil
	return equality.Semantic.DeepEqual(oldSpec, newSpec)
}

func garageClusterDrainReadiness(cluster *GarageCluster) error {
	if cluster.Status.FactorMigration != nil {
		return fmt.Errorf("positive-capacity drain cannot start while status.factorMigration is active")
	}
	if cluster.Status.StorageRollout != nil {
		return fmt.Errorf("positive-capacity drain cannot start while status.storageRollout is active")
	}
	condition := findGarageClusterCondition(cluster.Status.Conditions, storageRolloutReadyCondition)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != cluster.Generation {
		return fmt.Errorf("positive-capacity drain requires StorageRolloutReady=True at generation %d before it starts", cluster.Generation)
	}
	health := cluster.Status.Health
	if health == nil || health.Status != healthStatusHealthy || !health.Healthy || !health.Available ||
		health.StorageNodes == 0 || health.StorageNodesOK != health.StorageNodes || health.Partitions == 0 ||
		health.PartitionsQuorum != health.Partitions || health.PartitionsAllOK != health.Partitions {
		return fmt.Errorf("positive-capacity drain requires cached Garage health to show every storage node up and every partition fully replicated; the controller rechecks live health immediately before Apply")
	}
	return nil
}

func findGarageClusterCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func garageClusterDeleteUsesForeground(ctx context.Context) (bool, error) {
	request, err := admission.RequestFromContext(ctx)
	if err != nil || len(request.Options.Raw) == 0 {
		return false, nil
	}
	options := &metav1.DeleteOptions{}
	if err := json.Unmarshal(request.Options.Raw, options); err != nil {
		return false, fmt.Errorf("decoding delete propagation options: %w", err)
	}
	return options.PropagationPolicy != nil && *options.PropagationPolicy == metav1.DeletePropagationForeground, nil
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateDelete(ctx context.Context, obj *GarageCluster) (admission.Warnings, error) {
	if obj == nil {
		return nil, nil
	}
	garageclusterlog.Info("validate delete", "name", obj.Name)
	if obj.HasStorageTier() && len(obj.Spec.RemoteClusters) > 0 && obj.Spec.DeletionPolicy == "" {
		return nil, fmt.Errorf("deleting a federated GarageCluster requires an explicit spec.deletionPolicy: use Drain to retire this site safely, or Destroy only when the entire Garage store is being torn down")
	}
	if obj.EffectiveDeletionPolicy() != DeletionPolicyDrain || !obj.HasStorageTier() {
		return nil, nil
	}
	if obj.Status.StorageDrain != nil && obj.Status.StorageDrain.Actor.Kind == "GarageNode" {
		return nil, fmt.Errorf("garageCluster cannot be deleted while GarageNode %s/%s owns storage-drain transaction %q", obj.Status.StorageDrain.Actor.Namespace, obj.Status.StorageDrain.Actor.Name, obj.Status.StorageDrain.TransactionID)
	}
	drain := obj.Status.StorageDrain
	if obj.Annotations[drainPreparationAnnotation] != stringTrue || drain == nil {
		return nil, fmt.Errorf(
			"deletionPolicy: Drain is a prepared deletion: set annotation %s=\"true\" and wait for StorageDrainReady=True reason Completed before deleting the GarageCluster",
			drainPreparationAnnotation,
		)
	}
	if err := storagecontract.ValidateTerminal(
		storageDrainTerminalToken(drain),
		storagecontract.Actor{
			APIVersion: GroupVersion.String(), Kind: "GarageCluster",
			Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID),
		},
		nil,
		nil,
	); err != nil {
		return nil, fmt.Errorf("deletionPolicy: Drain terminal preparation is invalid: %w", err)
	}
	if foreground, err := garageClusterDeleteUsesForeground(ctx); err != nil {
		return nil, err
	} else if foreground {
		return nil, fmt.Errorf("foreground propagation is unsafe for deletionPolicy: Drain because Kubernetes may remove identity-bearing dependents before the GarageCluster finalizer proves block migration; use background/default propagation")
	}
	if effectiveStorageDrainConsistency(obj) != consistencyModeConsistent {
		return nil, fmt.Errorf("deletionPolicy: Drain requires spec.replication.consistencyMode: consistent before deletion starts")
	}
	if len(obj.Spec.RemoteClusters) > 0 && effectiveStorageDrainPeerPolicy(obj) != StorageDrainUnverifiedPeersAssumeConsistent {
		return nil, fmt.Errorf("deleting a federated storage site with deletionPolicy: Drain requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent")
	}
	// A completed transaction with no positive-capacity source is the durable
	// proof for an empty or gateway-only local site. Its exact roles have already
	// disappeared from settled layout history, so positive-capacity health and
	// rollout gates do not apply at the later DELETE boundary.
	if len(drain.RemovedStorageNodeIDs) > 0 {
		if err := garageClusterDrainReadiness(obj); err != nil {
			return nil, err
		}
	}
	return storageDrainPolicyWarnings(obj), nil
}

func storageDrainTerminalToken(drain *StorageDrainStatus) *storagecontract.TerminalToken {
	if drain == nil {
		return nil
	}
	var completedAt *time.Time
	if drain.CompletedAt != nil {
		completed := drain.CompletedAt.Time
		completedAt = &completed
	}
	return &storagecontract.TerminalToken{
		Actor: storagecontract.Actor{
			APIVersion: drain.Actor.APIVersion,
			Kind:       drain.Actor.Kind,
			Namespace:  drain.Actor.Namespace,
			Name:       drain.Actor.Name,
			UID:        drain.Actor.UID,
		},
		TransactionID:            drain.TransactionID,
		TargetHash:               drain.TargetHash,
		StartedAt:                drain.StartedAt.Time,
		CompletedAt:              completedAt,
		RoleRemovalNodeIDs:       drain.RoleRemovalNodeIDs,
		RemovedStorageNodeIDs:    drain.RemovedStorageNodeIDs,
		UnavailableSourceNodeIDs: drain.UnavailableSourceNodeIDs,
	}
}

// validateGarageCluster validates the GarageCluster spec.
func (r *GarageCluster) validateGarageCluster() (admission.Warnings, error) {
	return r.validateGarageClusterWithOptions(false, false)
}

func (r *GarageCluster) validateGarageClusterWithOptions(allowLegacyConversionBudget, allowUnchangedLegacy bool) (admission.Warnings, error) {
	var warnings admission.Warnings
	if !allowUnchangedLegacy {
		if err := validateSupportedPublicEndpoint(r.Spec.PublicEndpoint, "spec.publicEndpoint"); err != nil {
			return warnings, err
		}
		if err := validateServiceConfig(r.Spec.Network.Service); err != nil {
			return warnings, err
		}
	}
	if err := validateManagedGarageClusterName(r); err != nil {
		return warnings, err
	}
	consulWarnings, err := validateConsulDiscoveryConfig(r.Spec.Discovery)
	warnings = append(warnings, consulWarnings...)
	if err != nil {
		return warnings, err
	}
	if r.Spec.Security != nil && r.Spec.Security.TLS != nil &&
		(r.Spec.Security.TLS.Enabled || r.Spec.Security.TLS.CertSecretRef != nil ||
			r.Spec.Security.TLS.KeySecretRef != nil || r.Spec.Security.TLS.CASecretRef != nil) {
		return warnings, fmt.Errorf("spec.security.tls is unsupported: Garage removed the rpc_tls configuration; use the shared authenticated RPC protocol over a private network or a transparent service-mesh tunnel")
	}
	if value, requested := r.Annotations[drainPreparationAnnotation]; requested {
		if value != stringTrue {
			return warnings, fmt.Errorf("annotation %s must be \"true\" when present", drainPreparationAnnotation)
		}
		if !r.HasStorageTier() || r.Spec.DeletionPolicy != DeletionPolicyDrain {
			return warnings, fmt.Errorf("annotation %s requires a storage GarageCluster with explicit spec.deletionPolicy: Drain", drainPreparationAnnotation)
		}
	}
	if value, requested := r.Annotations[forceDeleteUnrevokedTokensAnnotation]; requested && value != stringTrue {
		return warnings, fmt.Errorf("annotation %s must be \"true\" when present", forceDeleteUnrevokedTokensAnnotation)
	}
	if r.Spec.Storage != nil {
		if err := workloadidentity.ValidatePodLabels(r.Spec.Storage.PodLabels, "spec.storage.podLabels"); err != nil {
			return warnings, err
		}
		if err := validateGarageEnvironment(r.Spec.Storage.Env, r.Spec.Storage.EnvFrom, "spec.storage"); err != nil {
			return warnings, err
		}
		for i := range r.Spec.Storage.NodeLocalPools {
			pool := &r.Spec.Storage.NodeLocalPools[i]
			if pool.PodTemplate != nil {
				if err := validateGarageEnvironment(pool.PodTemplate.Env, pool.PodTemplate.EnvFrom,
					fmt.Sprintf("spec.storage.nodeLocalPools[%q].podTemplate", pool.Name)); err != nil {
					return warnings, err
				}
			}
		}
	}
	if r.Spec.Gateway != nil {
		if err := workloadidentity.ValidatePodLabels(r.Spec.Gateway.PodLabels, "spec.gateway.podLabels"); err != nil {
			return warnings, err
		}
		if err := validateGarageEnvironment(r.Spec.Gateway.Env, r.Spec.Gateway.EnvFrom, "spec.gateway"); err != nil {
			return warnings, err
		}
	}

	if err := validateNoOperatorReservedLayoutTags(r.Spec.DefaultNodeTags, "spec.defaultNodeTags"); err != nil {
		return warnings, err
	}
	if fields := unsupportedClaimTemplateFields(r); len(fields) > 0 {
		return warnings, unsupportedClaimTemplateError(fields[0])
	}
	sourceWarnings, err := validateClusterVolumeDataSources(r)
	warnings = append(warnings, sourceWarnings...)
	if err != nil {
		return warnings, err
	}

	if err := r.validateNodeLocalPoolConversionTransportWithOptions(allowLegacyConversionBudget); err != nil {
		return warnings, err
	}

	if err := r.validateTiers(); err != nil {
		return warnings, err
	}
	if err := r.validateRemoteClustersWithOptions(allowUnchangedLegacy); err != nil {
		return warnings, err
	}
	if len(r.Spec.RemoteClusters) > 0 && r.Spec.DeletionPolicy == "" {
		warnings = append(warnings,
			"spec.deletionPolicy is omitted on a federated GarageCluster: normal reconciliation remains compatible, but deletion is refused until Drain or Destroy is chosen explicitly")
	} else if len(r.Spec.RemoteClusters) > 0 && r.Spec.DeletionPolicy == DeletionPolicyDestroy {
		warnings = append(warnings,
			"spec.deletionPolicy is Destroy on a federated GarageCluster: deleting this object tears down the local store without draining its roles; set Drain before retiring one physical site")
	}
	if r.HasStorageTier() && r.Spec.DeletionPolicy == DeletionPolicyDrain {
		if len(r.Spec.RemoteClusters) == 0 {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain retires one site from a surviving federated Garage layout and requires spec.remoteClusters; use Destroy for a standalone/all-local store")
		}
		if effectiveStorageDrainConsistency(r) != consistencyModeConsistent {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain requires spec.replication.consistencyMode: consistent")
		}
		if len(r.Spec.RemoteClusters) > 0 && effectiveStorageDrainPeerPolicy(r) != StorageDrainUnverifiedPeersAssumeConsistent {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain with spec.remoteClusters requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent")
		}
	}
	warnings = append(warnings, storageDrainPolicyWarnings(r)...)

	if err := r.validateZoneRedundancy(); err != nil {
		return warnings, err
	}

	zoneFromWarnings, err := r.validateZoneFrom()
	warnings = append(warnings, zoneFromWarnings...)
	if err != nil {
		return warnings, err
	}

	if r.HasNodeLocalPools() {
		// Pool pods have non-deterministic names/IPs and their Garage layout
		// roles are created and drained through the Admin API.
		if r.Spec.Admin == nil || r.Spec.Admin.AdminTokenSecretRef == nil ||
			strings.TrimSpace(r.Spec.Admin.AdminTokenSecretRef.Name) == "" {
			return warnings, fmt.Errorf("spec.admin.adminTokenSecretRef: required with storage.nodeLocalPools so the operator can discover node IDs and manage layout membership")
		}
		if r.Spec.ZoneFrom != nil && len(r.Spec.RemoteClusters) > 0 {
			return warnings, fmt.Errorf(
				"spec.zoneFrom: not supported with node-local pools in a federated GarageCluster because remoteClusters[].zone identifies one physical site; use one static spec.zone per site",
			)
		}
		if err := r.validateNodeLocalPools(); err != nil {
			return warnings, err
		}
		if r.Spec.PublicEndpoint != nil && r.Spec.Storage.Replicas == 0 {
			if r.EffectiveStorageLayoutPolicy() != layoutPolicyManual {
				return warnings, fmt.Errorf(
					"spec.publicEndpoint cannot target a node-local-pool-only storage tier: the shared Service selects the default storage group; configure each nodeLocalPools[].network.rpcPublicAddrTemplate or network.rpcPublicAddrSubnet for RPC reachability",
				)
			}
			warnings = append(warnings,
				"spec.publicEndpoint selects only Manual/default-storage GarageNodes and never node-local-pool pods; ensure at least one Manual GarageNode exists or remove the endpoint")
		}
	}

	// Use the tier-aware effective policy, not the raw cluster-level field:
	// spec.storage.layoutPolicy can override the cluster default (e.g. Manual
	// SMB/PVC GarageNodes plus operator-managed node-local pools).
	if r.HasStorageTier() && r.EffectiveStorageLayoutPolicy() != layoutPolicyManual {
		if err := r.validateStorageTier(); err != nil {
			return warnings, err
		}
	}

	// Validate the gateway tier's metadata volume. Unlike storage, the gateway
	// metadata PVC is optional (defaults to 1Gi), so only validate when set.
	// This catches EmptyDir misconfig (storageClassName/accessModes/etc.) the
	// same way the storage tier does — the gateway-only path previously skipped
	// it entirely (issue #219).
	if r.HasGatewayTier() && r.Spec.Gateway.Metadata != nil {
		metadata := r.Spec.Gateway.Metadata
		if len(metadata.Paths) > 0 {
			return warnings, fmt.Errorf("spec.gateway.metadata.paths: paths is only valid for storage data volumes")
		}
		if metadata.VolumeClaimTemplateSpec != nil {
			return warnings, fmt.Errorf("spec.gateway.metadata.volumeClaimTemplateSpec: not supported for gateway workloads; use size, storageClassName, accessModes, selector, labels, and annotations")
		}
		if r.Spec.LayoutPolicy == layoutPolicyManual {
			return warnings, fmt.Errorf("spec.gateway.metadata is not applied when spec.layoutPolicy is Manual; configure metadata storage on each user-owned gateway GarageNode")
		}
		if err := r.validateVolumeConfig(metadata, "spec.gateway.metadata"); err != nil {
			return warnings, err
		}
	}

	if err := r.validateConnectToWithOptions(allowUnchangedLegacy); err != nil {
		return warnings, err
	}

	if !allowUnchangedLegacy {
		if err := r.validateAPIs(); err != nil {
			return warnings, err
		}
		if err := r.validateGarageConfigValues(); err != nil {
			return warnings, err
		}
	}

	if err := r.validateLayoutManagement(); err != nil {
		return warnings, err
	}

	if r.isMetadataEphemeral() {
		warnings = append(warnings, "storage.metadata.type=EmptyDir: Node identity will be lost on pod restart")
	}
	if r.isDataEphemeral() {
		warnings = append(warnings, "storage.data.type=EmptyDir: All stored data will be lost on pod restart")
	}
	if r.HasGatewayTier() && r.Spec.Gateway.Metadata != nil && r.Spec.Gateway.Metadata.Type == VolumeTypeEmptyDir {
		warnings = append(warnings, "gateway.metadata.type=EmptyDir: gateway node identity will be lost on pod restart, churning the cluster layout")
	}

	if r.Spec.Replication != nil && r.Spec.Replication.ConsistencyMode == "dangerous" {
		warnings = append(warnings, "ConsistencyMode 'dangerous' may lead to data loss. Use only for testing.")
	}

	// Federation without an externally-routable RPC address: Garage's HelloMessage
	// carries no server_addr, so remote peers infer the (unroutable) pod IP and
	// cross-cluster RPC degrades after any pod restart. Warn, don't reject — an
	// in-flight federated cluster shouldn't be blocked on update.
	hasDefaultStorageIdentities := r.Spec.Storage != nil && r.Spec.Storage.Replicas > 0 &&
		r.EffectiveStorageLayoutPolicy() != layoutPolicyManual
	if len(r.Spec.RemoteClusters) > 0 && hasDefaultStorageIdentities && r.Spec.Network.RPCPublicAddr == "" &&
		(r.Spec.Storage == nil || r.Spec.Storage.RPCPublicAddr == "") &&
		r.Spec.PublicEndpoint == nil && strings.TrimSpace(r.Spec.Network.RPCPublicAddrSubnet) == "" {
		warnings = append(warnings,
			"spec.remoteClusters is set but the default StatefulSet/PVC group has no identity-specific RPC address "+
				"(spec.network.rpcPublicAddr, spec.storage.rpcPublicAddr, spec.publicEndpoint, or network.rpcPublicAddrSubnet); "+
				"an address configured for a node-local pool cannot route default StatefulSet/PVC identities")
	}
	if len(r.Spec.RemoteClusters) > 0 && r.HasNodeLocalPools() &&
		strings.TrimSpace(r.Spec.Network.RPCPublicAddrSubnet) == "" {
		var missing []string
		for i := range r.Spec.Storage.NodeLocalPools {
			pool := &r.Spec.Storage.NodeLocalPools[i]
			if strings.TrimSpace(nodeLocalPoolRPCPublicAddrTemplate(pool)) == "" {
				missing = append(missing, pool.Name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			warnings = append(warnings,
				fmt.Sprintf("federated node-local pools %s have no identity-specific RPC address; set network.rpcPublicAddrTemplate on each pool or network.rpcPublicAddrSubnet (an address for another storage group cannot route these identities)",
					strings.Join(missing, ", ")))
		}
	}
	if len(r.Spec.RemoteClusters) > 0 && r.HasStorageTier() && r.HasGatewayTier() &&
		r.Spec.Gateway.Replicas > 0 && strings.TrimSpace(r.Spec.Network.RPCPublicAddrSubnet) == "" &&
		strings.TrimSpace(r.Spec.Network.RPCPublicAddr) == "" &&
		strings.TrimSpace(r.Spec.Gateway.RPCPublicAddr) == "" {
		warnings = append(warnings,
			"the unified gateway tier has no identity-specific RPC address; spec.storage.rpcPublicAddr, spec.publicEndpoint, and node-local-pool addresses route other identity groups")
	}

	// Edge gateway (gateway tier + connectTo, no local storage) with no routable
	// RPC address: the storage cluster's reverse ConnectNode will learn the
	// gateway's unroutable pod IP and can never dial back (the v0.5.3 outage
	// class). Warn so the operator sets one of the three accepted fields.
	if r.HasGatewayTier() && !r.HasStorageTier() && r.Spec.ConnectTo != nil &&
		(r.Spec.Gateway == nil || r.Spec.Gateway.RPCPublicAddr == "") &&
		r.Spec.Network.RPCPublicAddr == "" && r.Spec.PublicEndpoint == nil {
		warnings = append(warnings,
			"edge gateway has connectTo set but no externally-routable RPC address "+
				"(spec.gateway.rpcPublicAddr, spec.network.rpcPublicAddr, or spec.publicEndpoint): "+
				"the storage cluster will learn the unroutable pod IP and reverse connection will fail")
	}

	// A multi-pod gateway tier with one shared rpc_public_addr is only reachable at
	// a single pod by remote regions — every pod advertises the same hostname via
	// HelloMessage, so the rest show "never seen" cross-region. An {ordinal}
	// placeholder makes each pod advertise its own address (the operator substitutes
	// the pod ordinal, symmetric with remoteClusters[].gatewayRpcEndpointTemplate).
	// Scoped to unified clusters, where per-node gateway GarageNodes do that
	// substitution; an edge gateway runs a cluster-level STS and renders the address
	// verbatim, so {ordinal} would not help there.
	if r.HasStorageTier() && r.HasGatewayTier() && r.Spec.Gateway.Replicas > 1 &&
		r.Spec.Gateway.RPCPublicAddr != "" && !strings.Contains(r.Spec.Gateway.RPCPublicAddr, "{ordinal}") {
		warnings = append(warnings,
			"spec.gateway.rpcPublicAddr is a single address shared by all gateway pods; with gateway.replicas > 1 "+
				"remote regions can reach only one pod. Use an {ordinal} placeholder (e.g. gw-{ordinal}.example.ts.net:3901) "+
				"for per-pod cross-region reachability")
	}

	// Same per-pod reachability trap on the storage tier: a multi-replica storage
	// tier sharing one rpc_public_addr is reachable cross-region at only one pod.
	if r.HasStorageTier() && r.Spec.Storage.Replicas > 1 &&
		r.Spec.Storage.RPCPublicAddr != "" && !strings.Contains(r.Spec.Storage.RPCPublicAddr, "{ordinal}") {
		warnings = append(warnings,
			"spec.storage.rpcPublicAddr is a single address shared by all storage pods; with storage.replicas > 1 "+
				"remote regions can reach only one pod. Use an {ordinal} placeholder (e.g. storage-{ordinal}.example.ts.net:3901) "+
				"and set remoteClusters[].storageRpcEndpointTemplate on consuming clusters for per-pod cross-region reachability")
	}

	if r.HasStorageTier() && r.Spec.Storage.PodDisruptionBudget != nil && r.Spec.Storage.PodDisruptionBudget.Enabled &&
		r.Spec.Storage.PodDisruptionBudget.MinAvailable == nil && r.Spec.Storage.PodDisruptionBudget.MaxUnavailable == nil {
		if r.HasNodeLocalPools() || r.EffectiveStorageLayoutPolicy() == layoutPolicyManual {
			warnings = append(warnings, "storage.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to maxUnavailable=1 across dynamic Manual/node-local membership")
		} else {
			warnings = append(warnings, "storage.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
		}
	}
	if r.HasGatewayTier() && r.Spec.Gateway.PodDisruptionBudget != nil && r.Spec.Gateway.PodDisruptionBudget.Enabled &&
		r.Spec.Gateway.PodDisruptionBudget.MinAvailable == nil && r.Spec.Gateway.PodDisruptionBudget.MaxUnavailable == nil {
		if r.Spec.LayoutPolicy == layoutPolicyManual {
			warnings = append(warnings, "gateway.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to maxUnavailable=1 across dynamic Manual membership")
		} else {
			warnings = append(warnings, "gateway.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
		}
	}
	if r.HasGatewayTier() && r.Spec.Gateway.PodDisruptionBudget != nil && r.Spec.Gateway.PodDisruptionBudget.Enabled &&
		r.Spec.Gateway.Replicas == 0 && r.Spec.LayoutPolicy != layoutPolicyManual {
		warnings = append(warnings, "gateway.podDisruptionBudget is enabled but gateway.replicas is 0; no PDB will be created")
	}

	return warnings, nil
}

func validateSupportedPublicEndpoint(endpoint *PublicEndpointConfig, field string) error {
	if endpoint == nil {
		return nil
	}
	if endpoint.Type == "ExternalIP" || endpoint.ExternalIP != nil {
		return fmt.Errorf("%s.externalIP is not supported; use LoadBalancer, NodePort, or set spec.network.rpcPublicAddr", field)
	}
	if endpoint.Type == "Headless" {
		return fmt.Errorf("%s type Headless is not supported: managed pods do not have an externally resolvable per-node DNS address; use LoadBalancer, NodePort, or set spec.network.rpcPublicAddr", field)
	}
	switch endpoint.Type {
	case string(corev1.ServiceTypeLoadBalancer):
		if endpoint.NodePort != nil {
			return fmt.Errorf("%s.nodePort is only valid with type NodePort", field)
		}
	case "NodePort":
		if endpoint.LoadBalancer != nil {
			return fmt.Errorf("%s.loadBalancer is only valid with type LoadBalancer", field)
		}
		if endpoint.NodePort == nil || len(endpoint.NodePort.ExternalAddresses) == 0 {
			return fmt.Errorf("%s.nodePort.externalAddresses must contain at least one externally reachable address", field)
		}
	default:
		return fmt.Errorf("%s.type must be LoadBalancer or NodePort", field)
	}
	return nil
}

// ValidateSupportedPublicEndpoint applies the same fail-closed endpoint
// contract to reconciliation of objects that bypassed current admission.
func ValidateSupportedPublicEndpoint(endpoint *PublicEndpointConfig, field string) error {
	return validateSupportedPublicEndpoint(endpoint, field)
}

func validateServiceConfig(service *ServiceConfig) error {
	if service == nil {
		return nil
	}
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
	return nil
}

// validateManagedGarageClusterName applies only the bounds required by the
// workloads the current spec actually owns. A management handle owns no
// Kubernetes workload or Service, and node-local-only/Manual clusters do not
// synthesize default-pool GarageNode StatefulSets. Keeping the checks
// shape-aware avoids bricking safe pre-existing handles and external-member
// configurations merely because an unrelated Auto shape has a tighter name.
type managedNameViolation struct {
	actor   string
	message string
}

func validateManagedGarageClusterName(cluster *GarageCluster) error {
	violations := managedGarageClusterNameViolations(cluster)
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("%s", violations[0].message)
}

func managedGarageClusterNameViolations(cluster *GarageCluster) []managedNameViolation {
	if cluster == nil || cluster.Name == "" {
		return nil
	}
	name := cluster.Name
	violations := make([]managedNameViolation, 0)
	if errs := utilvalidation.IsDNS1035Label(name); len(errs) > 0 {
		violations = append(violations, managedNameViolation{
			actor:   "metadata.name",
			message: fmt.Sprintf("metadata.name: must be a DNS-1035 label because it is used in managed labels and resource names: %s", strings.Join(errs, "; ")),
		})
	}
	if cluster.IsManagementHandle() {
		return violations
	}
	if errs := utilvalidation.IsDNS1035Label(name + "-headless"); len(errs) > 0 {
		violations = append(violations, managedNameViolation{
			actor:   "Service/headless",
			message: fmt.Sprintf("metadata.name: %q makes the managed headless Service %q invalid: %s", name, name+"-headless", strings.Join(errs, "; ")),
		})
	}

	if garageClusterHasManagedDefaultPool(cluster) {
		violations = append(violations, autoGarageNodeNameViolations(name, "storage", cluster.Spec.Storage.Replicas)...)
	}
	if cluster.HasStorageTier() && garageClusterHasManagedGateway(cluster) {
		violations = append(violations, autoGarageNodeNameViolations(name, "gateway", cluster.Spec.Gateway.Replicas)...)
	}
	if !cluster.HasStorageTier() && garageClusterHasManagedGateway(cluster) {
		ordinal := cluster.Spec.Gateway.Replicas - 1
		podName := fmt.Sprintf("%s-gateway-%d", name, ordinal)
		if errs := utilvalidation.IsValidLabelValue(podName); len(errs) > 0 {
			violations = append(violations, managedNameViolation{
				actor:   "StatefulSet/gateway/Pod/name-bound",
				message: fmt.Sprintf("metadata.name: %q makes edge gateway StatefulSet Pod label %q invalid at spec.gateway.replicas=%d: %s", name, podName, cluster.Spec.Gateway.Replicas, strings.Join(errs, "; ")),
			})
		}
	}
	return violations
}

func autoGarageNodeNameViolations(clusterName, tier string, replicas int32) []managedNameViolation {
	if replicas <= 0 {
		return nil
	}
	ordinal := replicas - 1
	podName := fmt.Sprintf("%s-%s-%d-0", clusterName, tier, ordinal)
	if errs := utilvalidation.IsValidLabelValue(podName); len(errs) > 0 {
		return []managedNameViolation{{
			actor:   fmt.Sprintf("GarageNode/%s/name-bound", tier),
			message: fmt.Sprintf("metadata.name: %q makes Auto %s GarageNode Pod label %q invalid at replicas=%d: %s", clusterName, tier, podName, replicas, strings.Join(errs, "; ")),
		}}
	}
	return nil
}

// validateManagedGarageClusterNameUpdate grandfatheres only actors that were
// already impossible before this update. Metadata/finalizer updates and a
// monotonic retirement may proceed, but a new actor or a workload-rendering
// change against a retained impossible actor fails before any child mutation.
func validateManagedGarageClusterNameUpdate(oldCluster, newCluster *GarageCluster) (bool, error) {
	newViolations := managedGarageClusterNameViolations(newCluster)
	if len(newViolations) == 0 {
		return false, nil
	}
	oldViolations := managedGarageClusterNameViolations(oldCluster)
	oldActors := make(map[string]struct{}, len(oldViolations))
	for _, violation := range oldViolations {
		oldActors[violation.actor] = struct{}{}
	}
	for _, violation := range newViolations {
		if _, existed := oldActors[violation.actor]; !existed {
			return false, fmt.Errorf("update introduces an invalid managed child: %s", violation.message)
		}
	}
	if newCluster != nil && !newCluster.DeletionTimestamp.IsZero() {
		return true, nil
	}
	if oldCluster != nil && newCluster != nil && equality.Semantic.DeepEqual(oldCluster.Spec, newCluster.Spec) {
		return true, nil
	}
	if garageClusterNameUpdateOnlyRetiresManagedActors(oldCluster, newCluster) {
		return true, nil
	}
	return false, fmt.Errorf("metadata.name has an already-invalid managed child; only metadata/finalizer updates or a monotonic scale-down, tier removal, or Auto-to-Manual retirement may proceed until every derived workload name is valid")
}

func garageClusterNameUpdateOnlyRetiresManagedActors(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldCopy := oldCluster.DeepCopy()
	newCopy := newCluster.DeepCopy()

	if oldCopy.Spec.Storage != nil {
		switch {
		case newCopy.Spec.Storage == nil:
			oldCopy.Spec.Storage = nil
		case newCopy.Spec.Storage.Replicas <= oldCopy.Spec.Storage.Replicas:
			oldCopy.Spec.Storage.Replicas = newCopy.Spec.Storage.Replicas
			if oldCluster.EffectiveStorageLayoutPolicy() != layoutPolicyManual &&
				newCluster.EffectiveStorageLayoutPolicy() == layoutPolicyManual {
				oldCopy.Spec.Storage.LayoutPolicy = newCopy.Spec.Storage.LayoutPolicy
			}
		}
	}
	if oldCopy.Spec.Gateway != nil {
		switch {
		case newCopy.Spec.Gateway == nil:
			oldCopy.Spec.Gateway = nil
		case newCopy.Spec.Gateway.Replicas <= oldCopy.Spec.Gateway.Replicas:
			oldCopy.Spec.Gateway.Replicas = newCopy.Spec.Gateway.Replicas
		}
	}
	if oldCopy.Spec.LayoutPolicy != layoutPolicyManual && newCopy.Spec.LayoutPolicy == layoutPolicyManual {
		oldCopy.Spec.LayoutPolicy = newCopy.Spec.LayoutPolicy
	}
	return equality.Semantic.DeepEqual(oldCopy.Spec, newCopy.Spec)
}

func validateConsulDiscoveryConfig(discovery *DiscoveryConfig) (admission.Warnings, error) {
	var warnings admission.Warnings
	if discovery == nil || discovery.Consul == nil || discovery.Consul.Enabled == nil || !*discovery.Consul.Enabled {
		return warnings, nil
	}
	consul := discovery.Consul
	if strings.TrimSpace(consul.HTTPAddr) == "" {
		return warnings, fmt.Errorf("spec.discovery.consul.httpAddr is required when Consul discovery is enabled")
	}
	if strings.TrimSpace(consul.ServiceName) == "" {
		return warnings, fmt.Errorf("spec.discovery.consul.serviceName is required when Consul discovery is enabled")
	}
	if consul.CACert != "" {
		return warnings, fmt.Errorf("spec.discovery.consul.caCert cannot embed a certificate: Garage expects ca_cert to be a file path; use caCertSecretRef")
	}
	if (consul.ClientCertSecretRef == nil) != (consul.ClientKeySecretRef == nil) {
		return warnings, fmt.Errorf("spec.discovery.consul.clientCertSecretRef and clientKeySecretRef must be configured together")
	}
	api := consul.API
	if api == "" {
		api = "catalog"
	}
	if api == "agent" && consul.ClientCertSecretRef != nil {
		return warnings, fmt.Errorf("spec.discovery.consul client certificate authentication is supported only with api: catalog; Garage ignores it for api: agent")
	}
	if consul.TLSSkipVerify && consul.CACertSecretRef != nil {
		warnings = append(warnings, "spec.discovery.consul.caCertSecretRef is ignored by Garage while tlsSkipVerify is true")
	}
	if api == "catalog" && consul.TokenSecretRef != nil {
		warnings = append(warnings, "Consul catalog ACL tokens require Garage >=2.3; use api: agent when retaining compatibility with Garage 2.0-2.2")
	}
	return warnings, nil
}

func validateGarageEnvironment(env []corev1.EnvVar, envFrom []corev1.EnvFromSource, field string) error {
	if len(env) > maximumGarageEnvironmentEntries {
		return fmt.Errorf("%s.env: may contain at most %d entries", field, maximumGarageEnvironmentEntries)
	}
	for i := range env {
		if garageEnvironmentNameReserved(env[i].Name) {
			return fmt.Errorf("%s.env[%d].name: %s is operator-reserved; managed Garage processes must use the credential files and rendered TOML audited by the operator", field, i, env[i].Name)
		}
	}
	for i := range envFrom {
		if name, unsafe := garageEnvFromReservedExample(envFrom[i]); unsafe {
			return fmt.Errorf("%s.envFrom[%d].prefix: %q could inject operator-reserved Garage environment variables such as %s; use a non-empty application prefix that is not a prefix of any GARAGE credential/config variable", field, i, envFrom[i].Prefix, name)
		}
	}
	return nil
}

const maximumGarageEnvironmentEntries = 256

var operatorReservedGarageEnvironmentNames = []string{
	garageConfigFileEnv,
	garageRPCSecretEnv, garageRPCSecretFileEnv,
	garageAdminTokenEnv, "GARAGE_ADMIN_TOKEN_FILE",
	"GARAGE_METRICS_TOKEN", "GARAGE_METRICS_TOKEN_FILE",
}

func garageEnvironmentNameReserved(name string) bool {
	for _, reserved := range operatorReservedGarageEnvironmentNames {
		if name == reserved {
			return true
		}
	}
	return false
}

func garageEnvFromReservedExample(source corev1.EnvFromSource) (string, bool) {
	for _, reserved := range operatorReservedGarageEnvironmentNames {
		if source.Prefix == "" || strings.HasPrefix(reserved, source.Prefix) {
			return reserved, true
		}
	}
	return "", false
}

func neutralizeLegacyGarageEnvironmentForValidation(
	field string,
	oldEnv, newEnv []corev1.EnvVar,
	oldEnvFrom, newEnvFrom []corev1.EnvFromSource,
) ([]corev1.EnvVar, []corev1.EnvFromSource, admission.Warnings, error) {
	var warnings admission.Warnings

	oldUnsafeEnv := make([]corev1.EnvVar, 0)
	for i := range oldEnv {
		if garageEnvironmentNameReserved(oldEnv[i].Name) {
			oldUnsafeEnv = append(oldUnsafeEnv, oldEnv[i])
		}
	}
	filteredEnv := make([]corev1.EnvVar, 0, len(newEnv))
	retainedUnsafeEnv := false
	for i := range newEnv {
		if !garageEnvironmentNameReserved(newEnv[i].Name) {
			filteredEnv = append(filteredEnv, newEnv[i])
			continue
		}
		match := semanticEnvVarIndex(oldUnsafeEnv, newEnv[i])
		if match < 0 {
			return nil, nil, warnings, fmt.Errorf(
				"%s.env[%d] introduces or changes operator-reserved %s; a released unsafe entry may only remain byte-for-byte unchanged or be removed",
				field, i, newEnv[i].Name,
			)
		}
		oldUnsafeEnv = append(oldUnsafeEnv[:match], oldUnsafeEnv[match+1:]...)
		retainedUnsafeEnv = true
	}
	safeEnv := filteredEnv

	oldUnsafeEnvFrom := make([]corev1.EnvFromSource, 0)
	for i := range oldEnvFrom {
		if _, unsafe := garageEnvFromReservedExample(oldEnvFrom[i]); unsafe {
			oldUnsafeEnvFrom = append(oldUnsafeEnvFrom, oldEnvFrom[i])
		}
	}
	filteredEnvFrom := make([]corev1.EnvFromSource, 0, len(newEnvFrom))
	retainedUnsafeEnvFrom := false
	for i := range newEnvFrom {
		if _, unsafe := garageEnvFromReservedExample(newEnvFrom[i]); !unsafe {
			filteredEnvFrom = append(filteredEnvFrom, newEnvFrom[i])
			continue
		}
		match := semanticEnvFromIndex(oldUnsafeEnvFrom, newEnvFrom[i])
		if match < 0 {
			return nil, nil, warnings, fmt.Errorf(
				"%s.envFrom[%d] introduces or changes a source capable of injecting operator-reserved Garage variables; a released unsafe entry may only remain byte-for-byte unchanged or be removed",
				field, i,
			)
		}
		oldUnsafeEnvFrom = append(oldUnsafeEnvFrom[:match], oldUnsafeEnvFrom[match+1:]...)
		retainedUnsafeEnvFrom = true
	}
	safeEnvFrom := filteredEnvFrom

	grandfatherOverlong := false
	if len(newEnv) > maximumGarageEnvironmentEntries && len(oldEnv) > maximumGarageEnvironmentEntries {
		if !semanticEnvVarSubset(newEnv, oldEnv) {
			return nil, nil, warnings, fmt.Errorf(
				"%s.env exceeds the supported %d-entry limit and may only shrink by removing byte-for-byte unchanged entries",
				field, maximumGarageEnvironmentEntries,
			)
		}
		safeEnv = nil
		grandfatherOverlong = true
	}

	if retainedUnsafeEnv || retainedUnsafeEnvFrom {
		warnings = append(warnings, fmt.Sprintf(
			"%s retains unchanged released environment entries that could override operator-managed Garage config or credentials; the operator ignores them and they should be removed",
			field,
		))
	}
	if grandfatherOverlong {
		warnings = append(warnings, fmt.Sprintf(
			"%s.env exceeds the supported %d-entry limit; this non-expanding update is temporarily tolerated so entries can be removed",
			field, maximumGarageEnvironmentEntries,
		))
	}
	return safeEnv, safeEnvFrom, warnings, nil
}

func semanticEnvVarIndex(haystack []corev1.EnvVar, needle corev1.EnvVar) int {
	for i := range haystack {
		if equality.Semantic.DeepEqual(haystack[i], needle) {
			return i
		}
	}
	return -1
}

func semanticEnvFromIndex(haystack []corev1.EnvFromSource, needle corev1.EnvFromSource) int {
	for i := range haystack {
		if equality.Semantic.DeepEqual(haystack[i], needle) {
			return i
		}
	}
	return -1
}

func semanticEnvVarSubset(subset, superset []corev1.EnvVar) bool {
	remaining := append([]corev1.EnvVar(nil), superset...)
	for i := range subset {
		match := semanticEnvVarIndex(remaining, subset[i])
		if match < 0 {
			return false
		}
		remaining = append(remaining[:match], remaining[match+1:]...)
	}
	return true
}

func neutralizeLegacyGarageClusterEnvironmentsForValidation(
	oldCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	if oldCluster.Spec.Storage != nil && validationCluster.Spec.Storage != nil {
		safeEnv, safeEnvFrom, fieldWarnings, err := neutralizeLegacyGarageEnvironmentForValidation(
			"spec.storage",
			oldCluster.Spec.Storage.Env, validationCluster.Spec.Storage.Env,
			oldCluster.Spec.Storage.EnvFrom, validationCluster.Spec.Storage.EnvFrom,
		)
		if err != nil {
			return warnings, err
		}
		validationCluster.Spec.Storage.Env = safeEnv
		validationCluster.Spec.Storage.EnvFrom = safeEnvFrom
		warnings = append(warnings, fieldWarnings...)
	}
	if oldCluster.Spec.Gateway != nil && validationCluster.Spec.Gateway != nil {
		safeEnv, safeEnvFrom, fieldWarnings, err := neutralizeLegacyGarageEnvironmentForValidation(
			"spec.gateway",
			oldCluster.Spec.Gateway.Env, validationCluster.Spec.Gateway.Env,
			oldCluster.Spec.Gateway.EnvFrom, validationCluster.Spec.Gateway.EnvFrom,
		)
		if err != nil {
			return warnings, err
		}
		validationCluster.Spec.Gateway.Env = safeEnv
		validationCluster.Spec.Gateway.EnvFrom = safeEnvFrom
		warnings = append(warnings, fieldWarnings...)
	}
	return warnings, nil
}

func neutralizeLegacyGarageClusterReplicaBoundsForValidation(
	oldCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	neutralize := func(field string, oldReplicas int32, newReplicas *int32) error {
		if newReplicas == nil || oldReplicas <= maxManagedTierReplicas || *newReplicas <= maxManagedTierReplicas {
			return nil
		}
		if *newReplicas > oldReplicas {
			return fmt.Errorf(
				"%s exceeds the supported maximum %d and may only remain unchanged or decrease until it is within the bound",
				field, maxManagedTierReplicas,
			)
		}
		*newReplicas = maxManagedTierReplicas
		warnings = append(warnings, fmt.Sprintf(
			"%s exceeds the supported maximum %d; this non-expanding update is temporarily tolerated so replicas can be retired",
			field, maxManagedTierReplicas,
		))
		return nil
	}
	if oldCluster.Spec.Storage != nil && validationCluster.Spec.Storage != nil {
		if err := neutralize(
			"spec.storage.replicas", oldCluster.Spec.Storage.Replicas, &validationCluster.Spec.Storage.Replicas,
		); err != nil {
			return warnings, err
		}
	}
	if oldCluster.Spec.Gateway != nil && validationCluster.Spec.Gateway != nil {
		if err := neutralize(
			"spec.gateway.replicas", oldCluster.Spec.Gateway.Replicas, &validationCluster.Spec.Gateway.Replicas,
		); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

func neutralizeLegacyGarageClusterTierShapeForValidation(
	oldCluster, newCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || newCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings

	newHasConflictingOwnership := newCluster.Spec.Storage != nil && newCluster.Spec.ConnectTo != nil
	if newHasConflictingOwnership {
		oldHasConflictingOwnership := oldCluster.Spec.Storage != nil && oldCluster.Spec.ConnectTo != nil
		if !oldHasConflictingOwnership || !equality.Semantic.DeepEqual(oldCluster.Spec, newCluster.Spec) {
			return warnings, fmt.Errorf("legacy spec.storage together with spec.connectTo may remain only on a byte-for-byte unchanged spec while metadata/finalizers are repaired; remove one ownership model before changing the spec")
		}
		validationCluster.Spec.ConnectTo = nil
		warnings = append(warnings, "legacy spec.storage together with spec.connectTo is temporarily tolerated only for an unchanged-spec metadata/finalizer update; remove one ownership model")
	}

	if newCluster.Spec.Storage != nil && newCluster.Spec.Storage.Replicas > 0 &&
		(newCluster.Spec.Storage.Metadata == nil || newCluster.Spec.Storage.Data == nil) {
		oldMissingDefaultVolumes := oldCluster.Spec.Storage != nil && oldCluster.Spec.Storage.Replicas > 0 &&
			(oldCluster.Spec.Storage.Metadata == nil || oldCluster.Spec.Storage.Data == nil)
		if !oldMissingDefaultVolumes || !equality.Semantic.DeepEqual(oldCluster.Spec, newCluster.Spec) {
			return warnings, fmt.Errorf("legacy default storage replicas without both metadata and data may remain only on a byte-for-byte unchanged spec while metadata/finalizers are repaired; add both volumes or scale the default group to zero")
		}
		validationCluster.Spec.Storage.Replicas = 0
		warnings = append(warnings, "legacy default storage replicas without both metadata and data are temporarily tolerated only for an unchanged-spec metadata/finalizer update; add both volumes or scale the default group to zero")
	}
	return warnings, nil
}

func neutralizeLegacyConversionTransportForValidation(
	oldCluster, newCluster, validationCluster *GarageCluster,
) (admission.Warnings, bool, error) {
	if oldCluster == nil || newCluster == nil || validationCluster == nil {
		return nil, false, nil
	}
	var warnings admission.Warnings
	for _, key := range []string{
		v1beta1PoolConversionPayloadAnnotation,
		v1beta1GatewayConversionPayloadAnnotation,
	} {
		oldValue, oldPresent := oldCluster.Annotations[key]
		newValue, newPresent := newCluster.Annotations[key]
		if !oldPresent {
			continue
		}
		switch {
		case !newPresent:
			// Monotonic removal of a formerly unreserved annotation is safe.
		case newValue == oldValue:
			delete(validationCluster.Annotations, key)
			warnings = append(warnings, fmt.Sprintf(
				"metadata.annotations[%q] is now reserved for conversion; its unchanged legacy value is ignored during this update and should be removed",
				key,
			))
		default:
			return warnings, false, fmt.Errorf(
				"metadata.annotations[%q] is now reserved for conversion and a released value may only remain byte-for-byte unchanged or be removed",
				key,
			)
		}
	}

	oldMarker := oldCluster.Annotations[v1beta2OnlyAnnotation]
	newMarker, newMarkerPresent := newCluster.Annotations[v1beta2OnlyAnnotation]
	oldReserved, oldOther := splitConversionMarkerComponents(oldMarker)
	newReserved, newOther := splitConversionMarkerComponents(newMarker)
	if len(oldReserved) > 0 {
		if !newMarkerPresent {
			newReserved, newOther = nil, nil
		}
		if !stringMultisetSubset(newReserved, oldReserved) || !equality.Semantic.DeepEqual(oldOther, newOther) {
			return warnings, false, fmt.Errorf(
				"metadata.annotations[%q] contains components now reserved for conversion; reserved components may only remain unchanged or be removed while other components stay unchanged",
				v1beta2OnlyAnnotation,
			)
		}
		if len(newReserved) > 0 {
			if len(newOther) == 0 {
				delete(validationCluster.Annotations, v1beta2OnlyAnnotation)
			} else {
				validationCluster.Annotations[v1beta2OnlyAnnotation] = strings.Join(newOther, ",")
			}
			warnings = append(warnings, fmt.Sprintf(
				"metadata.annotations[%q] retains unchanged components now reserved for conversion; they are ignored during this update and should be removed",
				v1beta2OnlyAnnotation,
			))
		}
	}

	oldSize, err := oldCluster.projectedV1beta1ConversionAnnotationSize()
	if err != nil {
		return warnings, false, fmt.Errorf("projecting old v1beta1 conversion annotation size: %w", err)
	}
	newSize, err := newCluster.projectedV1beta1ConversionAnnotationSize()
	if err != nil {
		return warnings, false, fmt.Errorf("projecting new v1beta1 conversion annotation size: %w", err)
	}
	if newSize <= kubernetesTotalAnnotationSizeLimit {
		return warnings, false, nil
	}
	if oldSize <= kubernetesTotalAnnotationSizeLimit || newSize > oldSize {
		return warnings, false, fmt.Errorf(
			"v1beta2-only storage.nodeLocalPools/gateway conversion projection exceeds Kubernetes' %d-byte annotation limit and may not grow (%d -> %d)",
			kubernetesTotalAnnotationSizeLimit, oldSize, newSize,
		)
	}
	warnings = append(warnings, fmt.Sprintf(
		"v1beta1 conversion projection remains above Kubernetes' %d-byte annotation limit (%d bytes); this non-expanding update is temporarily tolerated so v1beta2-only fields or annotations can be reduced",
		kubernetesTotalAnnotationSizeLimit, newSize,
	))
	return warnings, true, nil
}

func splitConversionMarkerComponents(value string) (reserved, other []string) {
	if value == "" {
		return nil, nil
	}
	for _, component := range strings.Split(value, ",") {
		switch component {
		case v1beta1PoolConversionMarker, v1beta1GatewayConversionMarker:
			reserved = append(reserved, component)
		default:
			other = append(other, component)
		}
	}
	return reserved, other
}

func stringMultisetSubset(subset, superset []string) bool {
	remaining := append([]string(nil), superset...)
	for _, value := range subset {
		match := -1
		for i := range remaining {
			if remaining[i] == value {
				match = i
				break
			}
		}
		if match < 0 {
			return false
		}
		remaining = append(remaining[:match], remaining[match+1:]...)
	}
	return true
}

func (r *GarageCluster) validateRemoteClusters() error {
	return r.validateRemoteClustersWithOptions(false)
}

func (r *GarageCluster) validateRemoteClustersWithOptions(allowUnchangedLegacy bool) error {
	names := make(map[string]int, len(r.Spec.RemoteClusters))
	zones := make(map[string]int, len(r.Spec.RemoteClusters))
	for i := range r.Spec.RemoteClusters {
		remote := &r.Spec.RemoteClusters[i]
		if !allowUnchangedLegacy && remote.DefaultCapacity != nil {
			return fmt.Errorf("spec.remoteClusters[%d].defaultCapacity is not supported; remote role capacity is owned by the source cluster layout", i)
		}
		name := strings.TrimSpace(remote.Name)
		zone := strings.TrimSpace(remote.Zone)
		if name == "" {
			return fmt.Errorf("spec.remoteClusters[%d].name must not be empty or whitespace", i)
		}
		if previous, duplicate := names[name]; duplicate {
			return fmt.Errorf("spec.remoteClusters[%d].name %q duplicates spec.remoteClusters[%d]; remote names are cleanup ownership tags and must be unique", i, name, previous)
		}
		names[name] = i
		if zone == "" {
			return fmt.Errorf("spec.remoteClusters[%d].zone must not be empty or whitespace", i)
		}
		if previous, duplicate := zones[zone]; duplicate {
			return fmt.Errorf("spec.remoteClusters[%d].zone %q duplicates spec.remoteClusters[%d]; each physical Garage site must have a unique zone", i, zone, previous)
		}
		zones[zone] = i
		if !allowUnchangedLegacy {
			if err := garageconfig.ValidateAdminAPIEndpoint(
				remote.Connection.AdminAPIEndpoint,
				fmt.Sprintf("spec.remoteClusters[%d].connection.adminApiEndpoint", i),
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateNoOperatorReservedLayoutTags(tags []string, field string) error {
	for i, tag := range tags {
		for _, prefix := range operatorReservedLayoutTagPrefixes {
			if strings.HasPrefix(tag, prefix) {
				return fmt.Errorf(
					"%s[%d] %q uses operator-managed prefix %q; configure ownership, tier, pool, and RPC address through their typed fields",
					field, i, tag, prefix,
				)
			}
		}
	}
	return nil
}

// validateNodeLocalPoolConversionTransport reserves the annotations used to
// project v1beta2-only pools through a v1beta1 read/write and guarantees that
// the resulting annotation set stays under Kubernetes' 256KiB metadata limit.
// Without the budget check, a valid v1beta2 PodTemplate could produce a
// v1beta1 view that the API server can read but can never write back.
func (r *GarageCluster) validateNodeLocalPoolConversionTransport() error {
	return r.validateNodeLocalPoolConversionTransportWithOptions(false)
}

func (r *GarageCluster) validateNodeLocalPoolConversionTransportWithOptions(allowLegacyBudget bool) error {
	if r.Annotations != nil {
		if _, found := r.Annotations[v1beta1PoolConversionPayloadAnnotation]; found {
			return fmt.Errorf(
				"metadata.annotations[%q] is reserved for v1beta1 API conversion",
				v1beta1PoolConversionPayloadAnnotation,
			)
		}
		if _, found := r.Annotations[v1beta1GatewayConversionPayloadAnnotation]; found {
			return fmt.Errorf(
				"metadata.annotations[%q] is reserved for v1beta1 API conversion",
				v1beta1GatewayConversionPayloadAnnotation,
			)
		}
		for _, component := range strings.Split(r.Annotations[v1beta2OnlyAnnotation], ",") {
			if component == v1beta1PoolConversionMarker || component == v1beta1GatewayConversionMarker {
				return fmt.Errorf(
					"metadata.annotations[%q] component %q is reserved for v1beta1 API conversion",
					v1beta2OnlyAnnotation,
					component,
				)
			}
		}
	}
	total, err := r.projectedV1beta1ConversionAnnotationSize()
	if err != nil {
		return err
	}
	if total > kubernetesTotalAnnotationSizeLimit && !allowLegacyBudget {
		return fmt.Errorf(
			"v1beta2-only storage.nodeLocalPools/gateway data is too large to round-trip through v1beta1 conversion annotations: projected annotation size %d exceeds Kubernetes limit %d",
			total,
			kubernetesTotalAnnotationSizeLimit,
		)
	}
	return nil
}

func (r *GarageCluster) projectedV1beta1ConversionAnnotationSize() (int, error) {
	// Conversion always preserves unified gateways and also preserves an edge
	// gateway whenever it contains a v1beta2-only field. This package cannot call
	// the spoke package's exact projection predicate without an import cycle, so
	// conservatively budget the full GatewaySpec for every gateway shape. The
	// small overestimate for a fully v1beta1-representable edge gateway prevents
	// an Env/EnvFrom/readiness/RPC field from passing hub admission and then
	// overflowing Kubernetes' annotation limit on a v1beta1 read.
	if !r.HasNodeLocalPools() && r.Spec.Gateway == nil {
		return 0, nil
	}
	total := 0
	markers := make([]string, 0, 2)
	if r.HasNodeLocalPools() {
		payload, err := json.Marshal(r.Spec.Storage.NodeLocalPools)
		if err != nil {
			return 0, fmt.Errorf("serializing storage.nodeLocalPools for v1beta1 conversion: %w", err)
		}
		total += len(v1beta1PoolConversionPayloadAnnotation) + len(payload)
		markers = append(markers, v1beta1PoolConversionMarker)
	}
	if r.Spec.Gateway != nil {
		payload, err := json.Marshal(r.Spec.Gateway)
		if err != nil {
			return 0, fmt.Errorf("serializing gateway tier for v1beta1 conversion: %w", err)
		}
		total += len(v1beta1GatewayConversionPayloadAnnotation) + len(payload)
		markers = append(markers, v1beta1GatewayConversionMarker)
	}
	markerPresent := false
	for key, value := range r.Annotations {
		if key == v1beta1PoolConversionPayloadAnnotation || key == v1beta1GatewayConversionPayloadAnnotation {
			continue
		}
		if key == v1beta2OnlyAnnotation {
			markerPresent = true
			for _, marker := range markers {
				value = appendProjectedConversionComponent(value, marker)
			}
		}
		total += len(key) + len(value)
	}
	if !markerPresent {
		total += len(v1beta2OnlyAnnotation) + len(strings.Join(markers, ","))
	}
	return total, nil
}

// appendProjectedConversionComponent must remain byte-for-byte equivalent to
// v1beta1.appendAnnotationComponent. Admission budgets the annotation set that
// conversion will actually write; counting a duplicate reserved marker would
// inflate the legacy baseline and could admit later payload growth beyond the
// Kubernetes annotation limit.
func appendProjectedConversionComponent(current, component string) string {
	for _, existing := range strings.Split(current, ",") {
		if existing == component {
			return current
		}
	}
	if current == "" {
		return component
	}
	return current + "," + component
}

// validateTiers enforces the hard rules about which combination of
// storage/gateway/connectTo is allowed.
func (r *GarageCluster) validateTiers() error {
	hasStorage := r.HasStorageTier()
	hasGateway := r.HasGatewayTier()
	hasConnect := r.Spec.ConnectTo != nil

	if !hasStorage && !hasGateway && !hasConnect {
		return fmt.Errorf("at least one of spec.storage, spec.gateway, or spec.connectTo must be set")
	}

	// Gateway tier alone (no storage) requires connectTo so it knows where the data lives.
	if hasGateway && !hasStorage && !hasConnect {
		return fmt.Errorf("spec.gateway without spec.storage requires spec.connectTo (edge gateway pattern)")
	}

	// A local storage tier and connectTo have incompatible ownership semantics:
	// local storage roles belong to this cluster, while connectTo routes layout
	// and secrets to another cluster. Storage federation uses remoteClusters.
	if hasStorage && hasConnect {
		return fmt.Errorf("spec.storage and spec.connectTo are mutually exclusive; use spec.remoteClusters to federate storage sites")
	}

	// connectTo without a gateway tier is allowed in exactly one case: a pure
	// management handle (no storage, no gateway) that manages an external Garage's
	// Admin-API state only — buckets, keys, layout — while some other system owns
	// the workload (e.g. the upstream Helm chart). See issue #269.

	if hasGateway {
		gw := r.Spec.Gateway
		if err := validateManagedTierReplicas(gw.Replicas, "spec.gateway.replicas"); err != nil {
			return err
		}
	}

	if hasStorage {
		st := r.Spec.Storage
		if err := validateManagedTierReplicas(st.Replicas, "spec.storage.replicas"); err != nil {
			return err
		}
	}

	return nil
}

const maxManagedTierReplicas int32 = 50

func validateManagedTierReplicas(replicas int32, field string) error {
	if replicas < 0 {
		return fmt.Errorf("%s must be non-negative", field)
	}
	if replicas > maxManagedTierReplicas {
		return fmt.Errorf("%s must be at most %d so every managed StatefulSet Pod and GarageNode name remains a valid Kubernetes label; storage.nodeLocalPools cardinality is selector-driven and is not subject to this limit", field, maxManagedTierReplicas)
	}
	return nil
}

func (r *GarageCluster) isMetadataEphemeral() bool {
	return r.HasStorageTier() && r.Spec.Storage.Metadata != nil && r.Spec.Storage.Metadata.Type == VolumeTypeEmptyDir
}

func (r *GarageCluster) isDataEphemeral() bool {
	return r.HasStorageTier() && r.Spec.Storage.Data != nil && r.Spec.Storage.Data.Type == VolumeTypeEmptyDir
}

func (r *GarageCluster) validateConnectTo() error {
	return r.validateConnectToWithOptions(false)
}

func (r *GarageCluster) validateConnectToWithOptions(allowUnchangedLegacy bool) error {
	if r.Spec.ConnectTo == nil {
		return nil
	}
	c := r.Spec.ConnectTo
	if !allowUnchangedLegacy {
		if c.ClusterRef != nil && c.ClusterRef.KubeConfigSecretRef != nil {
			return fmt.Errorf("spec.connectTo.clusterRef.kubeConfigSecretRef is not supported; the operator can reference GarageClusters only through its configured Kubernetes client")
		}
		if c.ClusterRef != nil {
			if err := garageconfig.ValidateNamespacedObjectReference(c.ClusterRef.Name, c.ClusterRef.Namespace, "spec.connectTo.clusterRef"); err != nil {
				return err
			}
		}
		if err := garageconfig.ValidateAdminAPIEndpoint(c.AdminAPIEndpoint, "spec.connectTo.adminApiEndpoint"); err != nil {
			return err
		}
	}
	if c.ClusterRef != nil && c.ClusterRef.Namespace != "" && c.ClusterRef.Namespace != r.Namespace {
		return fmt.Errorf("connectTo.clusterRef.namespace must be empty or match metadata.namespace; cross-namespace credential and layout inheritance is not permitted")
	}
	if c.ClusterRef == nil && c.RPCSecretRef == nil && len(c.BootstrapPeers) == 0 && c.AdminAPIEndpoint == "" {
		return fmt.Errorf("connectTo must specify clusterRef, rpcSecretRef, bootstrapPeers, or adminApiEndpoint")
	}
	if r.HasGatewayTier() && r.Spec.Network.RPCSecretRef == nil && c.RPCSecretRef == nil && c.ClusterRef == nil {
		return fmt.Errorf("gateway connectTo requires clusterRef, connectTo.rpcSecretRef, or network.rpcSecretRef; bootstrapPeers and adminApiEndpoint do not provide the shared RPC identity")
	}
	// A management handle (connectTo only, no tiers) must carry an Admin-API path
	// so the operator has something to dial: an external endpoint + token, or a
	// clusterRef to a sibling GarageCluster. rpcSecretRef/bootstrapPeers alone
	// only wire RPC and give no Admin API to manage buckets/keys/layout (#269).
	if r.IsManagementHandle() {
		hasEndpoint := c.AdminAPIEndpoint != "" && c.AdminTokenSecretRef != nil
		if !hasEndpoint && c.ClusterRef == nil {
			return fmt.Errorf("management handle (spec.connectTo without storage/gateway) requires clusterRef, or adminApiEndpoint together with adminTokenSecretRef")
		}
	}
	return nil
}

func (r *GarageCluster) validateZoneRedundancy() error {
	if r.Spec.Replication == nil {
		return nil
	}
	factor := r.Spec.Replication.Factor
	if factor == 0 {
		factor = 3
	}
	mode := r.Spec.Replication.ZoneRedundancyMode

	if mode == "" || mode == zoneRedundancyMaximum {
		if r.Spec.Replication.ZoneRedundancyMinZones != nil {
			return fmt.Errorf("zoneRedundancyMinZones is only valid when zoneRedundancyMode is AtLeast")
		}
		return nil
	}

	if mode == zoneRedundancyAtLeast {
		if r.Spec.Replication.ZoneRedundancyMinZones == nil {
			return fmt.Errorf("zoneRedundancyMinZones is required when zoneRedundancyMode is AtLeast")
		}
		n := *r.Spec.Replication.ZoneRedundancyMinZones
		if n > factor {
			return fmt.Errorf("zoneRedundancyMinZones (%d) cannot exceed replication factor (%d)", n, factor)
		}
		return nil
	}

	return fmt.Errorf("invalid zoneRedundancyMode %q (expected "+zoneRedundancyMaximum+" or "+zoneRedundancyAtLeast+")", mode)
}

// validateZoneFrom checks spec.zoneFrom (#294) and warns about the two ways it
// can quietly not do what the author expects.
func (r *GarageCluster) validateZoneFrom() (admission.Warnings, error) {
	var warnings admission.Warnings
	if r.Spec.ZoneFrom == nil {
		return warnings, nil
	}

	// A typo in the label key is otherwise indistinguishable from "the label
	// isn't set", which silently degrades to the cluster-wide zone.
	if errs := utilvalidation.IsQualifiedName(r.Spec.ZoneFrom.NodeLabel); len(errs) > 0 {
		return warnings, fmt.Errorf("zoneFrom.nodeLabel %q is not a valid label key: %s",
			r.Spec.ZoneFrom.NodeLabel, strings.Join(errs, "; "))
	}

	// zoneFrom only reaches the nodes the operator generates.
	if r.HasStorageTier() && r.EffectiveStorageLayoutPolicy() == layoutPolicyManual && !r.HasNodeLocalPools() {
		warnings = append(warnings,
			"zoneFrom has no effect with layoutPolicy: Manual — set zoneFrom on each GarageNode instead")
	}
	if !r.HasStorageTier() {
		warnings = append(warnings,
			"zoneFrom has no effect without a storage tier — it is not applied to gateway nodes")
	}

	// The whole point of per-node zones is usually to satisfy zone redundancy,
	// and Maximum is the default. Nothing to reject, but AtLeast(n) with fewer
	// distinct label values than n makes every layout apply fail upstream
	// ("The number of zones with non-gateway nodes is smaller than the
	// redundancy parameter"), which is worth saying out loud.
	if r.Spec.Replication != nil && r.Spec.Replication.ZoneRedundancyMode == zoneRedundancyAtLeast &&
		r.Spec.Replication.ZoneRedundancyMinZones != nil {
		warnings = append(warnings, fmt.Sprintf(
			"zoneRedundancyMode: AtLeast(%d) requires the %q label to resolve to at least %d distinct values across scheduled storage pods, or layout apply will fail",
			*r.Spec.Replication.ZoneRedundancyMinZones, r.Spec.ZoneFrom.NodeLabel,
			*r.Spec.Replication.ZoneRedundancyMinZones))
	}

	return warnings, nil
}

func (r *GarageCluster) validateStorageTier() error {
	st := r.Spec.Storage
	if st.Replicas > 0 && st.Metadata == nil {
		return fmt.Errorf("spec.storage.metadata: required when spec.storage.replicas is greater than 0")
	}
	if st.Replicas > 0 && st.Data == nil {
		return fmt.Errorf("spec.storage.data: required when spec.storage.replicas is greater than 0")
	}

	if st.Metadata != nil {
		if err := r.validateVolumeConfig(st.Metadata, "spec.storage.metadata"); err != nil {
			return err
		}
		if len(st.Metadata.Paths) > 0 {
			return fmt.Errorf("storage.metadata.paths: paths is only valid for data volumes")
		}
	}
	if st.Data != nil {
		if err := r.validateVolumeConfig(st.Data, "spec.storage.data"); err != nil {
			return err
		}
		for i := range st.Data.Paths {
			if volume := st.Data.Paths[i].Volume; volume != nil {
				if err := validateDataPathVolumeConfig(volume, fmt.Sprintf("spec.storage.data.paths[%d].volume", i)); err != nil {
					return err
				}
			}
		}
		if st.Data.Type == VolumeTypeEmptyDir && len(st.Data.Paths) > 0 {
			return fmt.Errorf("storage.data.paths: not allowed with EmptyDir type")
		}
		if !r.isDataEphemeral() && st.Data.Size == nil && len(st.Data.Paths) == 0 {
			return fmt.Errorf("storage.data.size: must specify size for persistent data storage (or use storage.data.paths for multi-disk)")
		}
	}
	return nil
}

func validateClusterVolumeDataSources(cluster *GarageCluster) (admission.Warnings, error) {
	if cluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	if storage := cluster.Spec.Storage; storage != nil {
		if err := validateVolumeGroupDataSource(storage.Metadata, cluster.Namespace, "spec.storage.metadata"); err != nil {
			return warnings, err
		}
		if err := validateVolumeGroupDataSource(storage.Data, cluster.Namespace, "spec.storage.data"); err != nil {
			return warnings, err
		}
		if storage.Data != nil {
			for i := range storage.Data.Paths {
				field := fmt.Sprintf("spec.storage.data.paths[%d].volume", i)
				if err := validateDataPathGroupDataSource(storage.Data.Paths[i].Volume, cluster.Namespace, field); err != nil {
					return warnings, err
				}
			}
			if storage.Data.DataSourceRef != nil && len(storage.Data.Paths) > 0 {
				return warnings, fmt.Errorf("spec.storage.data.dataSourceRef: set dataSourceRef on each spec.storage.data.paths[].volume; a top-level data source cannot populate multi-disk paths")
			}
		}
		if storage.Metadata != nil && storage.Metadata.DataSourceRef != nil &&
			(storage.Data == nil || (storage.Data.DataSourceRef == nil && !dataPathsHaveDataSource(storage.Data))) {
			warnings = append(warnings, "spec.storage.metadata.dataSourceRef restores Garage identities without object-block data; layout and block-refs will not match unless data volumes are restored separately")
		}
	}
	if gateway := cluster.Spec.Gateway; gateway != nil {
		if err := validateVolumeGroupDataSource(gateway.Metadata, cluster.Namespace, "spec.gateway.metadata"); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

func dataPathsHaveDataSource(data *VolumeConfig) bool {
	if data == nil {
		return false
	}
	for i := range data.Paths {
		if data.Paths[i].Volume != nil && data.Paths[i].Volume.DataSourceRef != nil {
			return true
		}
	}
	return false
}

func validateVolumeGroupDataSource(volume *VolumeConfig, namespace, field string) error {
	if volume == nil || volume.DataSourceRef == nil {
		return nil
	}
	if volume.Type == VolumeTypeEmptyDir {
		return fmt.Errorf("%s.dataSourceRef: EmptyDir cannot be restored from a PVC data source", field)
	}
	if volume.Selector != nil {
		return fmt.Errorf("%s.dataSourceRef: a PV selector cannot be combined with a group data source", field)
	}
	return garageconfig.ValidateGroupVolumeDataSource(volume.DataSourceRef, namespace, field+".dataSourceRef")
}

func validateDataPathGroupDataSource(volume *DataPathVolumeConfig, namespace, field string) error {
	if volume == nil || volume.DataSourceRef == nil {
		return nil
	}
	if volume.Type == VolumeTypeEmptyDir {
		return fmt.Errorf("%s.dataSourceRef: EmptyDir cannot be restored from a PVC data source", field)
	}
	if volume.Selector != nil {
		return fmt.Errorf("%s.dataSourceRef: a PV selector cannot be combined with a group data source", field)
	}
	return garageconfig.ValidateGroupVolumeDataSource(volume.DataSourceRef, namespace, field+".dataSourceRef")
}

func volumeDataSourceRef(volume *VolumeConfig) *corev1.TypedObjectReference {
	if volume == nil {
		return nil
	}
	return volume.DataSourceRef
}

func validateVolumeDataSourceRefsImmutable(oldCluster, newCluster *GarageCluster) error {
	oldStorage, newStorage := (*StorageSpec)(nil), (*StorageSpec)(nil)
	if oldCluster != nil {
		oldStorage = oldCluster.Spec.Storage
	}
	if newCluster != nil {
		newStorage = newCluster.Spec.Storage
	}
	if err := rejectDataSourceRefChange("spec.storage.metadata.dataSourceRef", volumeDataSourceRef(storageVolume(oldStorage, true)), volumeDataSourceRef(storageVolume(newStorage, true))); err != nil {
		return err
	}
	if err := rejectDataSourceRefChange("spec.storage.data.dataSourceRef", volumeDataSourceRef(storageVolume(oldStorage, false)), volumeDataSourceRef(storageVolume(newStorage, false))); err != nil {
		return err
	}
	oldPaths, newPaths := storageDataPaths(oldStorage), storageDataPaths(newStorage)
	n := len(oldPaths)
	if len(newPaths) > n {
		n = len(newPaths)
	}
	for i := 0; i < n; i++ {
		var oldRef, newRef *corev1.TypedObjectReference
		if i < len(oldPaths) && oldPaths[i].Volume != nil {
			oldRef = oldPaths[i].Volume.DataSourceRef
		}
		if i < len(newPaths) && newPaths[i].Volume != nil {
			newRef = newPaths[i].Volume.DataSourceRef
		}
		if err := rejectDataSourceRefChange(fmt.Sprintf("spec.storage.data.paths[%d].volume.dataSourceRef", i), oldRef, newRef); err != nil {
			return err
		}
	}
	var oldGW, newGW *VolumeConfig
	if oldCluster != nil && oldCluster.Spec.Gateway != nil {
		oldGW = oldCluster.Spec.Gateway.Metadata
	}
	if newCluster != nil && newCluster.Spec.Gateway != nil {
		newGW = newCluster.Spec.Gateway.Metadata
	}
	return rejectDataSourceRefChange("spec.gateway.metadata.dataSourceRef", volumeDataSourceRef(oldGW), volumeDataSourceRef(newGW))
}

func storageVolume(storage *StorageSpec, metadata bool) *VolumeConfig {
	if storage == nil {
		return nil
	}
	if metadata {
		return storage.Metadata
	}
	return storage.Data
}

func storageDataPaths(storage *StorageSpec) []DataPath {
	if storage == nil || storage.Data == nil {
		return nil
	}
	return storage.Data.Paths
}

func rejectDataSourceRefChange(field string, oldRef, newRef *corev1.TypedObjectReference) error {
	if equality.Semantic.DeepEqual(oldRef, newRef) {
		return nil
	}
	return fmt.Errorf("%s is immutable after GarageCluster creation; set the restore source when creating a new cluster", field)
}

func (r *GarageCluster) validateVolumeConfig(vc *VolumeConfig, field string) error {
	if vc.Type == VolumeTypeEmptyDir {
		if vc.StorageClassName != nil {
			return fmt.Errorf("%s.storageClassName: not allowed with EmptyDir type", field)
		}
		if vc.Selector != nil {
			return fmt.Errorf("%s.selector: not allowed with EmptyDir type", field)
		}
		if vc.VolumeClaimTemplateSpec != nil {
			return fmt.Errorf("%s.volumeClaimTemplateSpec: not allowed with EmptyDir type", field)
		}
		if len(vc.AccessModes) > 0 {
			return fmt.Errorf("%s.accessModes: not allowed with EmptyDir type", field)
		}
		if len(vc.Labels) > 0 {
			return fmt.Errorf("%s.labels: not allowed with EmptyDir type", field)
		}
		if len(vc.Annotations) > 0 {
			return fmt.Errorf("%s.annotations: not allowed with EmptyDir type", field)
		}
		if vc.DataSourceRef != nil {
			return fmt.Errorf("%s.dataSourceRef: not allowed with EmptyDir type", field)
		}
	}
	if vc.Selector != nil {
		if _, err := metav1.LabelSelectorAsSelector(vc.Selector); err != nil {
			return fmt.Errorf("%s.selector: invalid PersistentVolume label selector: %w", field, err)
		}
	}
	if vc.VolumeClaimTemplateSpec != nil {
		return fmt.Errorf("%s.volumeClaimTemplateSpec: unsupported for operator-managed storage because arbitrary claim templates can violate Garage identity isolation; use size, storageClassName, accessModes, selector, labels, and annotations, or an ordinary GarageNode existingClaim", field)
	}
	return nil
}

func unsupportedClaimTemplateError(field string) error {
	return fmt.Errorf("%s: unsupported for operator-managed storage because arbitrary claim templates can violate Garage identity isolation; use size, storageClassName, accessModes, selector, labels, and annotations, or an ordinary GarageNode existingClaim", field)
}

func unsupportedClaimTemplateFields(cluster *GarageCluster) []string {
	if cluster == nil {
		return nil
	}
	var fields []string
	if storage := cluster.Spec.Storage; storage != nil {
		if storage.Metadata != nil && storage.Metadata.VolumeClaimTemplateSpec != nil {
			fields = append(fields, "spec.storage.metadata.volumeClaimTemplateSpec")
		}
		if storage.Data != nil {
			if storage.Data.VolumeClaimTemplateSpec != nil {
				fields = append(fields, "spec.storage.data.volumeClaimTemplateSpec")
			}
			for i := range storage.Data.Paths {
				if storage.Data.Paths[i].Volume != nil && storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec != nil {
					fields = append(fields, fmt.Sprintf("spec.storage.data.paths[%d].volume.volumeClaimTemplateSpec", i))
				}
			}
		}
	}
	if gateway := cluster.Spec.Gateway; gateway != nil && gateway.Metadata != nil && gateway.Metadata.VolumeClaimTemplateSpec != nil {
		fields = append(fields, "spec.gateway.metadata.volumeClaimTemplateSpec")
	}
	sort.Strings(fields)
	return fields
}

func claimTemplateSpecsByField(cluster *GarageCluster) map[string]*corev1.PersistentVolumeClaimSpec {
	out := make(map[string]*corev1.PersistentVolumeClaimSpec)
	if cluster == nil {
		return out
	}
	if storage := cluster.Spec.Storage; storage != nil {
		if storage.Metadata != nil && storage.Metadata.VolumeClaimTemplateSpec != nil {
			out["spec.storage.metadata.volumeClaimTemplateSpec"] = storage.Metadata.VolumeClaimTemplateSpec
		}
		if storage.Data != nil {
			if storage.Data.VolumeClaimTemplateSpec != nil {
				out["spec.storage.data.volumeClaimTemplateSpec"] = storage.Data.VolumeClaimTemplateSpec
			}
			for i := range storage.Data.Paths {
				if storage.Data.Paths[i].Volume != nil && storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec != nil {
					out[fmt.Sprintf("spec.storage.data.paths[%d].volume.volumeClaimTemplateSpec", i)] = storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec
				}
			}
		}
	}
	if gateway := cluster.Spec.Gateway; gateway != nil && gateway.Metadata != nil && gateway.Metadata.VolumeClaimTemplateSpec != nil {
		out["spec.gateway.metadata.volumeClaimTemplateSpec"] = gateway.Metadata.VolumeClaimTemplateSpec
	}
	return out
}

func validateUnsupportedClaimTemplateUpdate(oldCluster, newCluster *GarageCluster) (admission.Warnings, error) {
	oldFields := claimTemplateSpecsByField(oldCluster)
	newFields := claimTemplateSpecsByField(newCluster)
	unchanged := make([]string, 0, len(newFields))
	for field, newSpec := range newFields {
		oldSpec, existed := oldFields[field]
		if !existed || !equality.Semantic.DeepEqual(oldSpec, newSpec) {
			return nil, unsupportedClaimTemplateError(field)
		}
		unchanged = append(unchanged, field)
	}
	if len(unchanged) == 0 {
		return nil, nil
	}
	sort.Strings(unchanged)
	return admission.Warnings{fmt.Sprintf(
		"legacy unsupported claim template fields %s were never applied by managed workloads; unchanged values are temporarily tolerated so they can be removed, but existing claims are not retroactively changed",
		strings.Join(unchanged, ", "),
	)}, nil
}

func validateLegacyManualGatewayMetadataUpdate(oldCluster, newCluster *GarageCluster) (admission.Warnings, bool) {
	if oldCluster == nil || newCluster == nil ||
		oldCluster.Spec.LayoutPolicy != layoutPolicyManual ||
		newCluster.Spec.LayoutPolicy != layoutPolicyManual ||
		oldCluster.Spec.Gateway == nil || newCluster.Spec.Gateway == nil ||
		newCluster.Spec.Gateway.Metadata == nil ||
		!equality.Semantic.DeepEqual(
			gatewayMetadataWithoutUnsupportedClaimTemplate(oldCluster.Spec.Gateway.Metadata),
			gatewayMetadataWithoutUnsupportedClaimTemplate(newCluster.Spec.Gateway.Metadata),
		) {
		return nil, false
	}
	return admission.Warnings{
		"legacy spec.gateway.metadata is ignored in Manual layout mode; its unchanged value is temporarily tolerated so unrelated updates and field removal can proceed; configure each user-owned gateway GarageNode instead",
	}, true
}

func clearUnsupportedClaimTemplates(cluster *GarageCluster) {
	if cluster == nil {
		return
	}
	if storage := cluster.Spec.Storage; storage != nil {
		if storage.Metadata != nil {
			storage.Metadata.VolumeClaimTemplateSpec = nil
		}
		if storage.Data != nil {
			storage.Data.VolumeClaimTemplateSpec = nil
			for i := range storage.Data.Paths {
				if storage.Data.Paths[i].Volume != nil {
					storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec = nil
				}
			}
		}
	}
	if gateway := cluster.Spec.Gateway; gateway != nil && gateway.Metadata != nil {
		gateway.Metadata.VolumeClaimTemplateSpec = nil
	}
}

func neutralizeLegacyGarageClusterVolumesForValidation(oldCluster, validationCluster *GarageCluster) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	volume := func(field string, oldVolume, newVolume *VolumeConfig) error {
		legacy, err := neutralizeLegacyClusterVolumeForValidation(field, oldVolume, newVolume)
		if err != nil {
			return err
		}
		if legacy {
			warnings = append(warnings, fmt.Sprintf(
				"%s contains unchanged released PVC fields that never affected its rendered volume; they are ignored during this update and should be removed",
				field,
			))
		}
		return nil
	}
	dataPath := func(field string, oldVolume, newVolume *DataPathVolumeConfig) error {
		legacy, err := neutralizeLegacyDataPathVolumeForValidation(field, oldVolume, newVolume)
		if err != nil {
			return err
		}
		if legacy {
			warnings = append(warnings, fmt.Sprintf(
				"%s contains unchanged released PVC fields that never affected its rendered volume; they are ignored during this update and should be removed",
				field,
			))
		}
		return nil
	}

	if oldCluster.Spec.Storage != nil && validationCluster.Spec.Storage != nil {
		oldStorage, newStorage := oldCluster.Spec.Storage, validationCluster.Spec.Storage
		if err := volume("spec.storage.metadata", oldStorage.Metadata, newStorage.Metadata); err != nil {
			return warnings, err
		}
		if err := volume("spec.storage.data", oldStorage.Data, newStorage.Data); err != nil {
			return warnings, err
		}
		if oldStorage.Data != nil && newStorage.Data != nil && len(oldStorage.Data.Paths) == len(newStorage.Data.Paths) {
			for i := range oldStorage.Data.Paths {
				if err := dataPath(
					fmt.Sprintf("spec.storage.data.paths[%d].volume", i),
					oldStorage.Data.Paths[i].Volume, newStorage.Data.Paths[i].Volume,
				); err != nil {
					return warnings, err
				}
			}
		}
	}
	if oldCluster.Spec.Gateway != nil && validationCluster.Spec.Gateway != nil {
		if err := volume("spec.gateway.metadata", oldCluster.Spec.Gateway.Metadata, validationCluster.Spec.Gateway.Metadata); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

func neutralizeLegacyClusterVolumeForValidation(field string, oldVolume, newVolume *VolumeConfig) (bool, error) {
	if oldVolume == nil || newVolume == nil {
		return false, nil
	}
	if err := validateLegacyClusterVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return false, err
	}
	legacy := false
	if oldVolume.Type == VolumeTypeEmptyDir && clusterVolumeHasIgnoredPVCFields(oldVolume) {
		clearClusterVolumeIgnoredPVCFields(newVolume)
		legacy = true
	}
	if oldVolume.Type != VolumeTypeEmptyDir && invalidClusterVolumeSelector(oldVolume.Selector) {
		newVolume.Selector = nil
		legacy = true
	}
	return legacy, nil
}

func neutralizeLegacyDataPathVolumeForValidation(field string, oldVolume, newVolume *DataPathVolumeConfig) (bool, error) {
	if oldVolume == nil || newVolume == nil {
		return false, nil
	}
	if err := validateLegacyDataPathVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return false, err
	}
	legacy := false
	if oldVolume.Type == VolumeTypeEmptyDir && dataPathVolumeHasIgnoredPVCFields(oldVolume) {
		clearDataPathVolumeIgnoredPVCFields(newVolume)
		legacy = true
	}
	if oldVolume.Type != VolumeTypeEmptyDir && invalidClusterVolumeSelector(oldVolume.Selector) {
		newVolume.Selector = nil
		legacy = true
	}
	return legacy, nil
}

func validateLegacyClusterVolumeIgnoredFieldTransition(field string, oldVolume, newVolume *VolumeConfig) error {
	if oldVolume == nil || newVolume == nil {
		return nil
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		return validateLegacyClusterPVCOnlyFields(field, oldVolume.StorageClassName, newVolume.StorageClassName,
			oldVolume.Selector, newVolume.Selector, oldVolume.AccessModes, newVolume.AccessModes,
			oldVolume.Labels, newVolume.Labels, oldVolume.Annotations, newVolume.Annotations)
	}
	if invalidClusterVolumeSelector(oldVolume.Selector) {
		return validateLegacyClusterIgnoredField(field+".selector", oldVolume.Selector, newVolume.Selector)
	}
	return nil
}

func validateLegacyDataPathVolumeIgnoredFieldTransition(field string, oldVolume, newVolume *DataPathVolumeConfig) error {
	if oldVolume == nil || newVolume == nil {
		return nil
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		return validateLegacyClusterPVCOnlyFields(field, oldVolume.StorageClassName, newVolume.StorageClassName,
			oldVolume.Selector, newVolume.Selector, oldVolume.AccessModes, newVolume.AccessModes,
			oldVolume.Labels, newVolume.Labels, oldVolume.Annotations, newVolume.Annotations)
	}
	if invalidClusterVolumeSelector(oldVolume.Selector) {
		return validateLegacyClusterIgnoredField(field+".selector", oldVolume.Selector, newVolume.Selector)
	}
	return nil
}

func validateLegacyClusterPVCOnlyFields(
	field string,
	oldStorageClass, newStorageClass *string,
	oldSelector, newSelector *metav1.LabelSelector,
	oldAccessModes, newAccessModes []corev1.PersistentVolumeAccessMode,
	oldLabels, newLabels, oldAnnotations, newAnnotations map[string]string,
) error {
	for _, transition := range []struct {
		name     string
		oldValue any
		newValue any
	}{
		{name: "storageClassName", oldValue: oldStorageClass, newValue: newStorageClass},
		{name: selectorJSONField, oldValue: oldSelector, newValue: newSelector},
		{name: "accessModes", oldValue: oldAccessModes, newValue: newAccessModes},
		{name: "labels", oldValue: oldLabels, newValue: newLabels},
		{name: "annotations", oldValue: oldAnnotations, newValue: newAnnotations},
	} {
		if err := validateLegacyClusterIgnoredField(field+"."+transition.name, transition.oldValue, transition.newValue); err != nil {
			return err
		}
	}
	return nil
}

func validateLegacyClusterIgnoredField(field string, oldValue, newValue any) error {
	if equality.Semantic.DeepEqual(oldValue, newValue) || legacyClusterSemanticZero(newValue) {
		return nil
	}
	return fmt.Errorf("%s was ignored by the released renderer and may only remain unchanged or be removed", field)
}

func legacyClusterSemanticZero(value any) bool {
	switch typed := value.(type) {
	case *string:
		return typed == nil
	case *metav1.LabelSelector:
		return typed == nil
	case []corev1.PersistentVolumeAccessMode:
		return len(typed) == 0
	case map[string]string:
		return len(typed) == 0
	default:
		return value == nil
	}
}

func clusterVolumeHasIgnoredPVCFields(volume *VolumeConfig) bool {
	return volume != nil && (volume.StorageClassName != nil || volume.Selector != nil ||
		len(volume.AccessModes) > 0 || len(volume.Labels) > 0 || len(volume.Annotations) > 0)
}

func clearClusterVolumeIgnoredPVCFields(volume *VolumeConfig) {
	if volume == nil {
		return
	}
	volume.StorageClassName = nil
	volume.Selector = nil
	volume.AccessModes = nil
	volume.Labels = nil
	volume.Annotations = nil
}

func normalizeLegacyClusterVolumeShapes(oldVolume, oldShape, newShape *VolumeConfig) {
	if oldVolume == nil || oldShape == nil || newShape == nil {
		return
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		clearClusterVolumeIgnoredPVCFields(oldShape)
		clearClusterVolumeIgnoredPVCFields(newShape)
	} else if invalidClusterVolumeSelector(oldVolume.Selector) {
		oldShape.Selector = nil
		newShape.Selector = nil
	}
}

func dataPathVolumeHasIgnoredPVCFields(volume *DataPathVolumeConfig) bool {
	return volume != nil && (volume.StorageClassName != nil || volume.Selector != nil ||
		len(volume.AccessModes) > 0 || len(volume.Labels) > 0 || len(volume.Annotations) > 0)
}

func clearDataPathVolumeIgnoredPVCFields(volume *DataPathVolumeConfig) {
	if volume == nil {
		return
	}
	volume.StorageClassName = nil
	volume.Selector = nil
	volume.AccessModes = nil
	volume.Labels = nil
	volume.Annotations = nil
}

func normalizeLegacyDataPathVolumeShapes(oldVolume, oldShape, newShape *DataPathVolumeConfig) {
	if oldVolume == nil || oldShape == nil || newShape == nil {
		return
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		clearDataPathVolumeIgnoredPVCFields(oldShape)
		clearDataPathVolumeIgnoredPVCFields(newShape)
	} else if invalidClusterVolumeSelector(oldVolume.Selector) {
		oldShape.Selector = nil
		newShape.Selector = nil
	}
}

func invalidClusterVolumeSelector(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	_, err := metav1.LabelSelectorAsSelector(selector)
	return err != nil
}

func validateDataPathVolumeConfig(vc *DataPathVolumeConfig, field string) error {
	if vc.Type == VolumeTypeEmptyDir {
		if vc.StorageClassName != nil {
			return fmt.Errorf("%s.storageClassName: not allowed with EmptyDir type", field)
		}
		if vc.Selector != nil {
			return fmt.Errorf("%s.selector: not allowed with EmptyDir type", field)
		}
		if len(vc.AccessModes) > 0 {
			return fmt.Errorf("%s.accessModes: not allowed with EmptyDir type", field)
		}
		if len(vc.Labels) > 0 {
			return fmt.Errorf("%s.labels: not allowed with EmptyDir type", field)
		}
		if len(vc.Annotations) > 0 {
			return fmt.Errorf("%s.annotations: not allowed with EmptyDir type", field)
		}
		if vc.DataSourceRef != nil {
			return fmt.Errorf("%s.dataSourceRef: not allowed with EmptyDir type", field)
		}
	}
	if vc.Selector != nil {
		if _, err := metav1.LabelSelectorAsSelector(vc.Selector); err != nil {
			return fmt.Errorf("%s.selector: invalid PersistentVolume label selector: %w", field, err)
		}
	}
	if vc.VolumeClaimTemplateSpec != nil {
		return fmt.Errorf("%s.volumeClaimTemplateSpec: unsupported for operator-managed storage because arbitrary claim templates can violate Garage identity isolation; use the explicit PVC fields or an ordinary GarageNode existingClaim", field)
	}
	return nil
}

func nodeLocalPoolMap(cluster *GarageCluster) map[string]*NodeLocalPoolSpec {
	out := make(map[string]*NodeLocalPoolSpec)
	if cluster == nil || cluster.Spec.Storage == nil {
		return out
	}
	for i := range cluster.Spec.Storage.NodeLocalPools {
		pool := &cluster.Spec.Storage.NodeLocalPools[i]
		out[pool.Name] = pool
	}
	return out
}

// nodeLocalPoolDataHostPathMappings returns the container-path to host-path
// mapping. Capacity/readOnly/type edits are deliberately excluded because they
// do not change which on-disk Garage drive is mounted at a persisted data_dir
// path.
func nodeLocalPoolDataHostPathMappings(pool *NodeLocalPoolSpec) map[string]string {
	if pool == nil {
		return nil
	}
	if pool.Data != nil {
		return map[string]string{nodeLocalPoolDataDir: pool.Data.HostPath}
	}
	mappings := make(map[string]string, len(pool.DataPaths))
	for i := range pool.DataPaths {
		mappings[pool.DataPaths[i].Path] = pool.DataPaths[i].HostPath
	}
	return mappings
}

func nodeLocalPoolHostPathTypeByContainerPath(pool *NodeLocalPoolSpec) map[string]corev1.HostPathType {
	if pool == nil {
		return nil
	}
	if pool.Data != nil {
		return map[string]corev1.HostPathType{
			nodeLocalPoolDataDir: effectiveDaemonSetHostPathType(pool.Data.HostPathType),
		}
	}
	pathTypes := make(map[string]corev1.HostPathType, len(pool.DataPaths))
	for i := range pool.DataPaths {
		pathTypes[pool.DataPaths[i].Path] = effectiveDaemonSetHostPathType(pool.DataPaths[i].HostPathType)
	}
	return pathTypes
}

func effectiveDaemonSetHostPathType(value corev1.HostPathType) corev1.HostPathType {
	if value == "" {
		return corev1.HostPathDirectory
	}
	return value
}

func daemonSetHostPathTypeLoosens(oldType, newType corev1.HostPathType) bool {
	return effectiveDaemonSetHostPathType(oldType) == corev1.HostPathDirectory &&
		effectiveDaemonSetHostPathType(newType) != corev1.HostPathDirectory
}

// validateNodeLocalPoolDataTransition enforces the ordering Garage's persisted
// DataLayout requires. An existing container path may not suddenly point at a
// different disk. Paths may be added and may transition to readOnly, but cannot
// be detached in place: upstream layout-history/rebalance completion does not
// prove that the HostPath directory itself contains no remaining blocks.
//
// A single `data` directory can be migrated safely by changing to dataPaths
// while retaining `/data/data` with the same HostPath and adding the new path.
func validateNodeLocalPoolDataTransition(
	nodeLocalPoolName string,
	oldPool, newPool *NodeLocalPoolSpec,
) error {
	oldMappings := nodeLocalPoolDataHostPathMappings(oldPool)
	newMappings := nodeLocalPoolDataHostPathMappings(newPool)
	oldPathTypes := nodeLocalPoolHostPathTypeByContainerPath(oldPool)
	newPathTypes := nodeLocalPoolHostPathTypeByContainerPath(newPool)

	newContainerByHostPath := make(map[string]string, len(newMappings))
	for containerPath, hostPath := range newMappings {
		newContainerByHostPath[hostPath] = containerPath
	}
	for containerPath, oldHostPath := range oldMappings {
		if newHostPath, retained := newMappings[containerPath]; retained {
			if newHostPath != oldHostPath {
				return fmt.Errorf(
					"spec.storage.nodeLocalPools[%q] cannot remap data path %q from hostPath %q to %q in place; retain the old mapping, or remove and fully drain the whole pool before recreating it with another disk layout",
					nodeLocalPoolName, containerPath, oldHostPath, newHostPath,
				)
			}
			if daemonSetHostPathTypeLoosens(oldPathTypes[containerPath], newPathTypes[containerPath]) {
				return fmt.Errorf(
					"spec.storage.nodeLocalPools[%q] data path %q hostPathType cannot be loosened from Directory to DirectoryOrCreate: a missing data disk must fail closed",
					nodeLocalPoolName,
					containerPath,
				)
			}
			continue
		}
		if movedTo := newContainerByHostPath[oldHostPath]; movedTo != "" {
			return fmt.Errorf(
				"spec.storage.nodeLocalPools[%q] cannot move hostPath %q from container path %q to %q in one update because Garage persists drive identity by data_dir path",
				nodeLocalPoolName, oldHostPath, containerPath, movedTo,
			)
		}
		return fmt.Errorf(
			"spec.storage.nodeLocalPools[%q] cannot remove data path %q (%s) in place: Garage layout and rebalance completion do not prove the HostPath is empty; retain it (mark it readOnly before active rebalance), or drain and recreate the whole pool only after independently verifying the disk is empty",
			nodeLocalPoolName, containerPath, oldHostPath,
		)
	}
	return nil
}

func (r *GarageCluster) validateNodeLocalPools() error {
	pools := r.Spec.Storage.NodeLocalPools
	seenNames := make(map[string]struct{}, len(pools))
	for i := range pools {
		pool := &pools[i]
		field := fmt.Sprintf("spec.storage.nodeLocalPools[%q]", pool.Name)
		if pool.Name == "" {
			return fmt.Errorf("spec.storage.nodeLocalPools[%d].name: required", i)
		}
		if errs := utilvalidation.IsDNS1123Label(pool.Name); len(errs) > 0 {
			return fmt.Errorf("%s.name: %s", field, strings.Join(errs, "; "))
		}
		if _, duplicate := seenNames[pool.Name]; duplicate {
			return fmt.Errorf("spec.storage.nodeLocalPools[%d].name: duplicate pool name %q", i, pool.Name)
		}
		seenNames[pool.Name] = struct{}{}
		if pool.Capacity == nil || pool.Capacity.Sign() <= 0 || pool.Capacity.Value() < 1024 {
			return fmt.Errorf("%s.capacity: must be at least 1Ki", field)
		}
		if len(pool.Selector.MatchLabels) == 0 && len(pool.Selector.MatchExpressions) == 0 {
			return fmt.Errorf("%s.selector: a non-empty desired-membership selector is required", field)
		}
		if _, err := metav1.LabelSelectorAsSelector(&pool.Selector); err != nil {
			return fmt.Errorf("%s.selector: %w", field, err)
		}
		selectorKeys := make([]string, 0, len(pool.Selector.MatchLabels)+len(pool.Selector.MatchExpressions))
		for key := range pool.Selector.MatchLabels {
			selectorKeys = append(selectorKeys, key)
		}
		for j := range pool.Selector.MatchExpressions {
			selectorKeys = append(selectorKeys, pool.Selector.MatchExpressions[j].Key)
		}
		for _, key := range selectorKeys {
			if strings.HasPrefix(key, "garage.rajsingh.info/gc-") {
				return fmt.Errorf("%s.selector: %q is reserved for the operator's drain-safe activation labels", field, key)
			}
		}
		if pool.PodTemplate != nil && pool.PodTemplate.Affinity != nil && pool.PodTemplate.Affinity.NodeAffinity != nil &&
			pool.PodTemplate.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
			return fmt.Errorf("%s.podTemplate.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution: not supported; selector is the durable membership boundary and node affinity may only express preferences", field)
		}
		if pool.Metadata == nil {
			return fmt.Errorf("%s.metadata: required", field)
		}
		if err := validateAbsoluteHostPath(pool.Metadata.HostPath, field+".metadata.hostPath"); err != nil {
			return err
		}
		if !validHostPathType(pool.Metadata.HostPathType) {
			return fmt.Errorf("%s.metadata.hostPathType: must be Directory or DirectoryOrCreate", field)
		}
		if (pool.Data == nil) == (len(pool.DataPaths) == 0) {
			return fmt.Errorf("%s: exactly one of data or dataPaths must be set", field)
		}

		hostPaths := []namedPath{{field: field + ".metadata.hostPath", value: path.Clean(pool.Metadata.HostPath)}}
		if pool.Data != nil {
			if err := validateAbsoluteHostPath(pool.Data.HostPath, field+".data.hostPath"); err != nil {
				return err
			}
			if !validHostPathType(pool.Data.HostPathType) {
				return fmt.Errorf("%s.data.hostPathType: must be Directory or DirectoryOrCreate", field)
			}
			hostPaths = append(hostPaths, namedPath{field: field + ".data.hostPath", value: path.Clean(pool.Data.HostPath)})
		} else {
			mountPaths := make([]namedPath, 0, len(pool.DataPaths))
			hasWritablePath := false
			totalWritableCapacity := resource.Quantity{}
			for j := range pool.DataPaths {
				dataPath := &pool.DataPaths[j]
				pathField := fmt.Sprintf("%s.dataPaths[%d]", field, j)
				if err := validateAbsoluteContainerPath(dataPath.Path, pathField+".path"); err != nil {
					return err
				}
				if err := validateAbsoluteHostPath(dataPath.HostPath, pathField+".hostPath"); err != nil {
					return err
				}
				if !validHostPathType(dataPath.HostPathType) {
					return fmt.Errorf("%s.hostPathType: must be Directory or DirectoryOrCreate", pathField)
				}
				switch {
				case dataPath.ReadOnly && dataPath.Capacity != nil:
					return fmt.Errorf("%s.capacity: must be omitted when readOnly is true", pathField)
				case !dataPath.ReadOnly && (dataPath.Capacity == nil || dataPath.Capacity.Sign() <= 0):
					return fmt.Errorf("%s.capacity: a positive capacity is required unless readOnly is true", pathField)
				case !dataPath.ReadOnly:
					hasWritablePath = true
					totalWritableCapacity.Add(*dataPath.Capacity)
				}
				mountPaths = append(mountPaths, namedPath{field: pathField + ".path", value: path.Clean(dataPath.Path)})
				hostPaths = append(hostPaths, namedPath{field: pathField + ".hostPath", value: path.Clean(dataPath.HostPath)})
			}
			if !hasWritablePath {
				return fmt.Errorf("%s.dataPaths: at least one writable path with positive capacity is required", field)
			}
			if pool.Capacity.Cmp(totalWritableCapacity) > 0 {
				return fmt.Errorf("%s.capacity: %s exceeds the combined writable dataPaths capacity %s",
					field, pool.Capacity.String(), totalWritableCapacity.String())
			}
			if err := validateDistinctPaths(mountPaths); err != nil {
				return err
			}
		}
		if err := validateDistinctPaths(hostPaths); err != nil {
			return err
		}
		if err := validateNodeRPCAddressTemplate(nodeLocalPoolRPCPublicAddrTemplate(pool), field+".network.rpcPublicAddrTemplate"); err != nil {
			return err
		}
		if err := validateNodeLocalPoolPodLabels(nodeLocalPoolPodLabels(pool), field+".podTemplate.podLabels"); err != nil {
			return err
		}
		if err := validateNodeLocalPoolPodAnnotations(nodeLocalPoolPodAnnotations(pool), field+".podTemplate.podAnnotations"); err != nil {
			return err
		}
	}
	return nil
}

func nodeLocalPoolRPCPublicAddrTemplate(pool *NodeLocalPoolSpec) string {
	if pool == nil || pool.Network == nil {
		return ""
	}
	return pool.Network.RPCPublicAddrTemplate
}

func nodeLocalPoolPodLabels(pool *NodeLocalPoolSpec) map[string]string {
	if pool == nil || pool.PodTemplate == nil {
		return nil
	}
	return pool.PodTemplate.PodLabels
}

func nodeLocalPoolPodAnnotations(pool *NodeLocalPoolSpec) map[string]string {
	if pool == nil || pool.PodTemplate == nil {
		return nil
	}
	return pool.PodTemplate.PodAnnotations
}

func validateNodeRPCAddressTemplate(value, field string) error {
	if value == "" {
		return nil
	}
	if !strings.Contains(value, "{nodeName}") {
		return fmt.Errorf("%s: must contain {nodeName} so every node identity has a distinct address", field)
	}
	rendered := strings.ReplaceAll(value, "{nodeName}", "node")
	host, portText, err := net.SplitHostPort(rendered)
	if err != nil {
		return fmt.Errorf("%s: must render as host:port: %w", field, err)
	}
	dnsHost := strings.TrimSuffix(host, ".")
	if host == "" || (net.ParseIP(host) == nil && len(utilvalidation.IsDNS1123Subdomain(dnsHost)) > 0) {
		return fmt.Errorf("%s: host must render as an IP address or DNS subdomain", field)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s: port must be between 1 and 65535", field)
	}
	return nil
}

func validateNodeLocalPoolPodLabels(labels map[string]string, field string) error {
	return workloadidentity.ValidatePodLabels(labels, field)
}

func validateGarageClusterPodLabelUpdate(oldObj, newObj *GarageCluster) (admission.Warnings, error) {
	var warnings admission.Warnings
	validate := func(oldLabels, newLabels map[string]string, field string) error {
		fieldWarnings, err := workloadidentity.ValidatePodLabelUpdate(oldLabels, newLabels, field)
		warnings = append(warnings, fieldWarnings...)
		return err
	}

	var oldStorageLabels, newStorageLabels map[string]string
	if oldObj != nil && oldObj.Spec.Storage != nil {
		oldStorageLabels = oldObj.Spec.Storage.PodLabels
	}
	if newObj != nil && newObj.Spec.Storage != nil {
		newStorageLabels = newObj.Spec.Storage.PodLabels
	}
	if err := validate(oldStorageLabels, newStorageLabels, "spec.storage.podLabels"); err != nil {
		return warnings, err
	}

	var oldGatewayLabels, newGatewayLabels map[string]string
	if oldObj != nil && oldObj.Spec.Gateway != nil {
		oldGatewayLabels = oldObj.Spec.Gateway.PodLabels
	}
	if newObj != nil && newObj.Spec.Gateway != nil {
		newGatewayLabels = newObj.Spec.Gateway.PodLabels
	}
	if err := validate(oldGatewayLabels, newGatewayLabels, "spec.gateway.podLabels"); err != nil {
		return warnings, err
	}

	oldPools := make(map[string]map[string]string)
	if oldObj != nil && oldObj.Spec.Storage != nil {
		for i := range oldObj.Spec.Storage.NodeLocalPools {
			pool := &oldObj.Spec.Storage.NodeLocalPools[i]
			oldPools[pool.Name] = nodeLocalPoolPodLabels(pool)
		}
	}
	if newObj != nil && newObj.Spec.Storage != nil {
		for i := range newObj.Spec.Storage.NodeLocalPools {
			pool := &newObj.Spec.Storage.NodeLocalPools[i]
			field := fmt.Sprintf("spec.storage.nodeLocalPools[%q].podTemplate.podLabels", pool.Name)
			if err := validate(oldPools[pool.Name], nodeLocalPoolPodLabels(pool), field); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

func neutralizeGarageClusterReservedPodLabels(cluster *GarageCluster) {
	if cluster == nil {
		return
	}
	if cluster.Spec.Storage != nil {
		cluster.Spec.Storage.PodLabels = workloadidentity.UserPodLabels(cluster.Spec.Storage.PodLabels)
		for i := range cluster.Spec.Storage.NodeLocalPools {
			pool := &cluster.Spec.Storage.NodeLocalPools[i]
			if pool.PodTemplate != nil {
				pool.PodTemplate.PodLabels = workloadidentity.UserPodLabels(pool.PodTemplate.PodLabels)
			}
		}
	}
	if cluster.Spec.Gateway != nil {
		cluster.Spec.Gateway.PodLabels = workloadidentity.UserPodLabels(cluster.Spec.Gateway.PodLabels)
	}
}

func validateNodeLocalPoolPodAnnotations(annotations map[string]string, field string) error {
	reserved := map[string]struct{}{
		"garage.rajsingh.info/config-hash":                      {},
		"garage.rajsingh.info/node-id":                          {},
		"garage.rajsingh.info/pod-spec-hash":                    {},
		nodeLocalPoolKubernetesNodeLabel:                        {},
		"garage.rajsingh.info/node-local-pool-activation-label": {},
	}
	for key := range annotations {
		if errs := utilvalidation.IsQualifiedName(key); len(errs) > 0 {
			return fmt.Errorf("%s: invalid key %q: %s", field, key, strings.Join(errs, "; "))
		}
		if _, found := reserved[key]; found {
			return fmt.Errorf("%s: %q is operator-managed and cannot be overridden", field, key)
		}
	}
	return nil
}

type namedPath struct {
	field string
	value string
}

func validHostPathType(value corev1.HostPathType) bool {
	return value == "" || value == corev1.HostPathDirectory || value == corev1.HostPathDirectoryOrCreate
}

func validateAbsoluteHostPath(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	if !path.IsAbs(value) {
		return fmt.Errorf("%s: must be an absolute path", field)
	}
	clean := path.Clean(value)
	if clean == "/" {
		return fmt.Errorf("%s: mounting the host root is not allowed", field)
	}
	if clean != value {
		return fmt.Errorf("%s: must be normalized (use %q)", field, clean)
	}
	return nil
}

func validateAbsoluteContainerPath(value, field string) error {
	if value == "" || !path.IsAbs(value) {
		return fmt.Errorf("%s: must be an absolute path", field)
	}
	if strings.ContainsAny(value, "\"\\\n\r\t") {
		return fmt.Errorf("%s: quotes, backslashes, and control characters are not allowed", field)
	}
	clean := path.Clean(value)
	for _, reserved := range operatorManagedMountsForValidation {
		if clean == "/" || pathsOverlap(clean, reserved) {
			return fmt.Errorf("%s: path %q conflicts with operator-managed mount %q", field, clean, reserved)
		}
	}
	if clean != value {
		return fmt.Errorf("%s: must be normalized (use %q)", field, clean)
	}
	return nil
}

var operatorManagedMountsForValidation = []string{
	"/data/metadata",
	"/etc/garage",
	// Reserve the whole credential tree so future startup-only Secret mounts do
	// not silently collide with a user data path added in an older API object.
	"/secrets",
	"/var/run/garage-volume-markers",
}

func validateDistinctPaths(paths []namedPath) error {
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if pathsOverlap(paths[i].value, paths[j].value) {
				return fmt.Errorf("%s and %s must be distinct, non-overlapping directories", paths[i].field, paths[j].field)
			}
		}
	}
	return nil
}

func pathsOverlap(a, b string) bool {
	a = path.Clean(a)
	b = path.Clean(b)
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (r *GarageCluster) validateAPIs() error {
	if r.Spec.Network.RPCPublicAddrSubnet != "" {
		if _, _, err := net.ParseCIDR(r.Spec.Network.RPCPublicAddrSubnet); err != nil {
			return fmt.Errorf("network.rpcPublicAddrSubnet: must be a valid CIDR: %w", err)
		}
	}
	if r.IsManagementHandle() {
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
	if err := add(r.Spec.Network.RPCBindAddress, r.Spec.Network.RPCBindPort, 3901, "spec.network.rpcBindAddress"); err != nil {
		return err
	}
	if r.Spec.S3API == nil {
		listeners = append(listeners, garageconfig.ListenerPort{Field: "spec.s3Api.bindAddress", Port: 3900})
	} else if err := add(r.Spec.S3API.BindAddress, r.Spec.S3API.BindPort, 3900, "spec.s3Api.bindAddress"); err != nil {
		return err
	}
	if r.Spec.K2VAPI != nil {
		if err := add(r.Spec.K2VAPI.BindAddress, r.Spec.K2VAPI.BindPort, 3904, "spec.k2vApi.bindAddress"); err != nil {
			return err
		}
	}
	if r.Spec.WebAPI == nil {
		listeners = append(listeners, garageconfig.ListenerPort{Field: "spec.webApi.bindAddress", Port: 3902})
	} else if r.Spec.WebAPI.Enabled == nil || *r.Spec.WebAPI.Enabled {
		if err := add(r.Spec.WebAPI.BindAddress, r.Spec.WebAPI.BindPort, 3902, "spec.webApi.bindAddress"); err != nil {
			return err
		}
	}
	if r.Spec.Admin == nil {
		listeners = append(listeners, garageconfig.ListenerPort{Field: "spec.admin.bindAddress", Port: 3903})
	} else if err := add(r.Spec.Admin.BindAddress, r.Spec.Admin.BindPort, 3903, "spec.admin.bindAddress"); err != nil {
		return err
	}
	return garageconfig.ValidateDistinctListenerPorts(listeners)
}

func (r *GarageCluster) validateGarageConfigValues() error {
	if r.Spec.Network.RPCPingTimeout != nil {
		if err := garageconfig.ValidateRPCDuration(r.Spec.Network.RPCPingTimeout.Duration, "spec.network.rpcPingTimeout"); err != nil {
			return err
		}
	}
	if r.Spec.Network.RPCTimeout != nil {
		if err := garageconfig.ValidateRPCDuration(r.Spec.Network.RPCTimeout.Duration, "spec.network.rpcTimeout"); err != nil {
			return err
		}
	}
	if r.Spec.Storage != nil {
		if err := garageconfig.ValidateMetadataSnapshotInterval(
			r.Spec.Storage.MetadataAutoSnapshotInterval,
			"spec.storage.metadataAutoSnapshotInterval",
		); err != nil {
			return err
		}
	}
	if r.Spec.Database != nil {
		if err := validatePositiveQuantity(r.Spec.Database.LMDBMapSize, "spec.database.lmdbMapSize"); err != nil {
			return err
		}
		if err := validatePositiveQuantity(r.Spec.Database.FjallBlockCacheSize, "spec.database.fjallBlockCacheSize"); err != nil {
			return err
		}
	}
	if r.Spec.Blocks != nil {
		if err := validatePositiveQuantity(r.Spec.Blocks.Size, "spec.blocks.size"); err != nil {
			return err
		}
		if err := validatePositiveQuantity(r.Spec.Blocks.RAMBufferMax, "spec.blocks.ramBufferMax"); err != nil {
			return err
		}
		if r.Spec.Blocks.CompressionLevel != nil {
			if err := garageconfig.ValidateCompressionLevel(*r.Spec.Blocks.CompressionLevel, "spec.blocks.compressionLevel"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePositiveQuantity(value *resource.Quantity, field string) error {
	if value != nil && value.Sign() <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}
	return nil
}

func (r *GarageCluster) validateLayoutManagement() error {
	lm := r.Spec.LayoutManagement
	if lm == nil {
		return nil
	}
	if lm.MinNodesHealthy < 0 {
		return fmt.Errorf("layoutManagement.minNodesHealthy: must be non-negative, got %d", lm.MinNodesHealthy)
	}
	// Node-local pool cardinality is selected dynamically from Kubernetes
	// Nodes, so static replica fields cannot provide a sound admission-time
	// upper bound for mixed storage.
	if lm.MinNodesHealthy > 0 && !r.HasNodeLocalPools() {
		replicas := int(r.TotalReplicas())
		if lm.MinNodesHealthy > replicas {
			return fmt.Errorf("layoutManagement.minNodesHealthy (%d) cannot exceed total replicas (%d) — layout changes would never be applied", lm.MinNodesHealthy, replicas)
		}
	}
	return nil
}

func validateAdminBindAddress(addr string) error {
	_, err := garageconfig.ManagedBindPort(addr, 0, 3903, "admin.bindAddress")
	return err
}

func adminPortForUpdateValidation(cluster *GarageCluster) (uint16, error) {
	const defaultPort = uint16(3903)
	if cluster == nil || cluster.Spec.Admin == nil {
		return defaultPort, nil
	}
	admin := cluster.Spec.Admin
	if admin.BindAddress != "" {
		_, portText, err := net.SplitHostPort(admin.BindAddress)
		if err != nil {
			return 0, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return 0, fmt.Errorf("invalid Admin API port %q", portText)
		}
		return uint16(port), nil
	}
	if admin.BindPort != 0 {
		return uint16(admin.BindPort), nil
	}
	return defaultPort, nil
}

func validateAdminPortUpdate(oldCluster, newCluster *GarageCluster) error {
	if oldCluster == nil || newCluster == nil ||
		(oldCluster.IsManagementHandle() && newCluster.IsManagementHandle()) {
		return nil
	}
	oldPort, oldErr := adminPortForUpdateValidation(oldCluster)
	newPort, newErr := adminPortForUpdateValidation(newCluster)
	if newErr != nil {
		return fmt.Errorf("resolving new Admin API port: %w", newErr)
	}
	if oldErr != nil {
		// Permit an object admitted by an older validator to repair an invalid
		// address. Every newly valid state is immutable from that point onward.
		return nil
	}
	if oldPort != newPort {
		return fmt.Errorf("spec.admin effective TCP port is immutable after create (%d -> %d): managed Services, direct Pod probes, and immutable generated endpoints cannot switch ports ahead of an OnDelete workload rollout", oldPort, newPort)
	}
	return nil
}
