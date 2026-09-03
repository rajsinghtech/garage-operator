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

package v1beta1

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/factormigration"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

var garageclusterlog = logf.Log.WithName("garagecluster-resource")

const (
	zoneRedundancyMaximum                = "Maximum"
	zoneRedundancyAtLeast                = "AtLeast"
	layoutPolicyAuto                     = "Auto"
	layoutPolicyManual                   = "Manual"
	drainPreparationAnnotation           = "garage.rajsingh.info/drain"
	forceDeleteUnrevokedTokensAnnotation = "garage.rajsingh.info/force-delete-unrevoked-operator-tokens"
	consistencyModeConsistent            = "consistent"
	defaultRPCSecretKey                  = "rpc-secret"
	healthStatusHealthy                  = "healthy"
	garageNodeKind                       = "GarageNode"
	stringTrue                           = "true"
	gatewayValue                         = "gateway"
	garageRPCSecretFileEnv               = "GARAGE_RPC_SECRET_FILE"
	garageAdminTokenEnv                  = "GARAGE_ADMIN_TOKEN"
	garageAllowWorldReadableSecretsEnv   = "GARAGE_ALLOW_WORLD_READABLE_SECRETS"
	garageConfigFileEnv                  = "GARAGE_CONFIG_FILE"
	storageClassNameJSONField            = "storageClassName"
	selectorJSONField                    = "selector"
	publicEndpointTypeExternalIP         = "ExternalIP"
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
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageClusterDefaulter{}).
		WithValidator(&GarageClusterValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta1-garagecluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1beta1,name=mgarageclusterv1beta1.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageCluster] = &GarageClusterDefaulter{}

// GarageClusterDefaulter handles defaulting for GarageCluster.
type GarageClusterDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageClusterDefaulter) Default(ctx context.Context, obj *GarageCluster) error {
	garageclusterlog.Info("default", "name", obj.Name)

	// Set default layout policy if not specified
	if obj.Spec.LayoutPolicy == "" {
		obj.Spec.LayoutPolicy = layoutPolicyAuto
	}
	// Default replication settings
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

	// Enable website hosting by default with a sensible rootDomain
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

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagecluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update;delete,versions=v1beta1,name=vgarageclusterv1beta1.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageCluster] = &GarageClusterValidator{}

// GarageClusterValidator handles validation for GarageCluster.
type GarageClusterValidator struct{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateCreate(ctx context.Context, obj *GarageCluster) (admission.Warnings, error) {
	garageclusterlog.Info("validate create", "name", obj.Name)
	warnings, err := obj.validateGarageCluster()
	if err != nil {
		return warnings, err
	}
	_, poolPayloadAnnotationPresent := obj.Annotations[v1beta2AnnotationNodeLocalPoolsData]
	_, gatewayPayloadAnnotationPresent := obj.Annotations[v1beta2AnnotationGatewayTierData]
	if originalGarageClusterRequestVersion(ctx) == GroupVersion.Version &&
		(poolPayloadAnnotationPresent ||
			gatewayPayloadAnnotationPresent ||
			annotationContainsNodeLocalPools(
				obj.Annotations[v1beta2AnnotationGatewayTierPresent],
			) || annotationContainsGatewayTier(obj.Annotations[v1beta2AnnotationGatewayTierPresent])) {
		return warnings, fmt.Errorf(
			"v1beta2-only conversion annotations are reserved and cannot be supplied through a v1beta1 create; use the v1beta2 API",
		)
	}
	return warnings, nil
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageCluster) (admission.Warnings, error) {
	garageclusterlog.Info("validate update", "name", newObj.Name)

	// Check the lossless conversion envelope before ordinary shape validation.
	// A pool-only v1beta2 object legitimately projects to replicas=0 with no
	// default-group volumes in v1beta1. If a legacy client removes the envelope,
	// generic v1beta1 validation would otherwise fail first on that incomplete
	// projection and obscure the actual reserved-transport violation.
	if err := validateV1Beta1ConversionTransportUpdate(ctx, oldObj, newObj); err != nil {
		return nil, err
	}
	grandfatherManagedName, err := validateManagedGarageClusterNameUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}

	claimTemplateWarnings, err := validateV1Beta1UnsupportedClaimTemplateUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}
	gatewayStorageWarnings, err := validateV1Beta1IgnoredGatewayStorageUpdate(oldObj, newObj)
	if err != nil {
		return nil, err
	}
	podLabelWarnings, err := workloadidentity.ValidatePodLabelUpdate(oldObj.Spec.PodLabels, newObj.Spec.PodLabels, "spec.podLabels")
	if err != nil {
		return nil, err
	}
	validationObj := newObj.DeepCopy()
	if grandfatherManagedName {
		validationObj.Name = "grandfathered"
	}
	clearV1Beta1UnsupportedClaimTemplates(validationObj)
	clearV1Beta1IgnoredGatewayStorage(validationObj)
	legacyVolumeWarnings, err := neutralizeLegacyV1Beta1GarageClusterVolumesForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyEnvironmentWarnings, err := neutralizeLegacyV1Beta1GarageClusterEnvironmentsForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	legacyReplicaWarnings, err := neutralizeLegacyV1Beta1GarageClusterReplicaBoundForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	validationObj.Spec.PodLabels = workloadidentity.UserPodLabels(validationObj.Spec.PodLabels)
	oldDefaulted := oldObj.DeepCopy()
	_ = (&GarageClusterDefaulter{}).Default(ctx, oldDefaulted)
	allowUnchangedLegacy := equality.Semantic.DeepEqual(oldDefaulted.Spec, newObj.Spec)
	warnings, err := validationObj.validateGarageClusterWithOptions(allowUnchangedLegacy)
	if grandfatherManagedName {
		warnings = append(warnings, "metadata.name is grandfathered for this non-expanding update; adding or rolling a managed workload remains blocked until the derived Kubernetes names are valid")
	}
	warnings = append(warnings, claimTemplateWarnings...)
	warnings = append(warnings, gatewayStorageWarnings...)
	warnings = append(warnings, legacyVolumeWarnings...)
	warnings = append(warnings, legacyEnvironmentWarnings...)
	warnings = append(warnings, legacyReplicaWarnings...)
	warnings = append(warnings, podLabelWarnings...)
	if err != nil {
		return warnings, err
	}
	if err := validateAdminPortUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	oldSource, newSource := v1beta1EffectiveRPCIdentitySource(oldObj), v1beta1EffectiveRPCIdentitySource(newObj)
	attachesFirstHandleSource := oldObj.isManagementHandle() && newObj.isManagementHandle() && oldSource == "" && newSource != ""
	if oldSource != newSource && !attachesFirstHandleSource {
		return warnings, fmt.Errorf("RPC identity source is immutable after create (%s -> %s): Garage has no dual-secret bridge, so live rotation would partition a sequentially restarted mesh", oldSource, newSource)
	}
	if oldObj.Status.StorageDrain != nil && !equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return warnings, fmt.Errorf("spec cannot change while status.storageDrain transaction %q is active; wait for its exact actor to complete", oldObj.Status.StorageDrain.TransactionID)
	}
	if oldObj.Status.StorageDrain != nil &&
		oldObj.Annotations[drainPreparationAnnotation] != newObj.Annotations[drainPreparationAnnotation] {
		return warnings, fmt.Errorf("annotation %s cannot change while status.storageDrain transaction %q is active", drainPreparationAnnotation, oldObj.Status.StorageDrain.TransactionID)
	}
	if garageClusterNodeLocalPoolRolloutActive(oldObj) {
		if oldObj.Annotations[AnnotationRecoverStorageRollout] != "" &&
			newObj.Annotations[AnnotationRecoverStorageRollout] == "" {
			return warnings, fmt.Errorf("annotation %s cannot be removed until the exact status.storageRollout actor converges", AnnotationRecoverStorageRollout)
		}
		if !equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
			if !v1beta1StorageRolloutRecoverySafeSpecChange(oldObj, newObj) {
				// See the v1beta2 counterpart: this branch is gated on an in-flight
				// storage rollout, not on the recovery annotation, so naming the
				// annotation points at state that is usually absent.
				return warnings, fmt.Errorf(
					"only workload and non-topology Garage configuration may change while the managed Pod replacement of %s is in flight; "+
						"replication, layout, membership, volume/capacity, RPC identity/public routing, federation, and service topology "+
						"stay frozen until that status.storageRollout actor converges, then retry",
					v1beta1StorageRolloutActorName(oldObj.Status.StorageRollout))
			}
		}
	}
	if err := validateV1Beta1GarageLayoutOwnershipUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	if err := validateV1Beta1DefaultVolumeUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	// Manual → Auto is not supported: once a user has taken over node management,
	// the operator can't safely re-adopt their GarageNodes (they may have
	// custom per-node settings the cluster spec can't express). See issue #190.
	// Mirrored from the v1beta2 webhook — admission fires on the version the
	// caller uses, before conversion to the storage version.
	oldPolicy := oldObj.Spec.LayoutPolicy
	newPolicy := newObj.Spec.LayoutPolicy
	if oldPolicy == layoutPolicyManual && newPolicy != "" && newPolicy != layoutPolicyManual {
		return warnings, fmt.Errorf("layoutPolicy transition from Manual to Auto is not supported (one-way only) — see issue #190")
	}

	// Replication factor cannot be changed after cluster creation
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
	if v1beta1PositiveStorageRemoval(oldObj, newObj) {
		if !v1beta1StorageRemovalIsTopologyOnly(oldObj, newObj) {
			return warnings, fmt.Errorf("positive-capacity membership removal must be a topology-only update: apply workload and Garage configuration changes first, wait for StorageRolloutReady=True at that generation, then change only storage membership")
		}
		if v1beta1StorageDrainConsistency(oldObj) != consistencyModeConsistent {
			return warnings, fmt.Errorf("positive-capacity removal is a two-step operation: first set spec.replication.consistencyMode: consistent and wait for StorageRolloutReady=True at that generation; remove capacity in a later update")
		}
		if v1beta1StorageDrainConsistency(newObj) != consistencyModeConsistent {
			return warnings, fmt.Errorf("positive-capacity removal requires spec.replication.consistencyMode: consistent before the reversible topology edit is accepted")
		}
		if (len(oldObj.Spec.RemoteClusters) > 0 || len(newObj.Spec.RemoteClusters) > 0) &&
			(v1beta1StorageDrainPeerPolicy(oldObj) != StorageDrainUnverifiedPeersAssumeConsistent ||
				v1beta1StorageDrainPeerPolicy(newObj) != StorageDrainUnverifiedPeersAssumeConsistent) {
			return warnings, fmt.Errorf("federated positive-capacity removal is a two-step operation: set spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent and wait for the prepared generation to converge before removing capacity")
		}
		if err := v1beta1DrainReadiness(oldObj); err != nil {
			return warnings, fmt.Errorf("positive-capacity removal requires the old generation to be fully prepared before changing topology: %w", err)
		}
	}

	return warnings, nil
}

func v1beta1EffectiveRPCIdentitySource(cluster *GarageCluster) string {
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
	if cluster.isManagementHandle() {
		// A handle with no explicit or inherited RPC source owns no Garage
		// workload identity. It may attach its first source later to enable
		// deterministic GarageKey creation; once attached, the source is immutable.
		return ""
	}
	return "secret:" + cluster.Namespace + "/" + cluster.Name + "-rpc-secret:rpc-secret"
}

func validateV1Beta1GarageLayoutOwnershipUpdate(oldCluster, newCluster *GarageCluster) error {
	oldMode, oldTarget := v1beta1GarageLayoutOwnershipIdentity(oldCluster)
	newMode, newTarget := v1beta1GarageLayoutOwnershipIdentity(newCluster)
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

func v1beta1GarageLayoutOwnershipIdentity(cluster *GarageCluster) (mode, target string) {
	if cluster == nil {
		return "self-owned", ""
	}
	if cluster.isManagementHandle() {
		return "management-handle", v1beta1ConnectedGarageLayoutTarget(cluster, true)
	}
	if cluster.Spec.Gateway {
		return "edge-gateway", v1beta1ConnectedGarageLayoutTarget(cluster, false)
	}
	return "self-owned", cluster.Namespace + "/" + cluster.Name
}

func v1beta1ConnectedGarageLayoutTarget(cluster *GarageCluster, endpointFirst bool) string {
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
			key = defaultRPCSecretKey
		}
		return "rpcSecretRef:" + cluster.Namespace + "/" + connectTo.RPCSecretRef.Name + ":" + key
	}
	return "generatedRpcSecret:" + cluster.Namespace + "/" + cluster.Name
}

func validateV1Beta1DefaultVolumeUpdate(oldCluster, newCluster *GarageCluster) error {
	if oldCluster == nil || newCluster == nil {
		return nil
	}
	if !equality.Semantic.DeepEqual(oldCluster.Spec.Storage.DataSourceRef, newCluster.Spec.Storage.DataSourceRef) {
		return fmt.Errorf("storage.dataSourceRef is immutable after GarageCluster creation; set the restore source when creating a new cluster")
	}
	if oldCluster.Spec.Gateway && newCluster.Spec.Gateway &&
		(oldCluster.Spec.Replicas > 0 || newCluster.Spec.Replicas > 0) {
		oldGatewayMetadata := v1Beta1GatewayMetadataWithoutUnsupportedClaimTemplate(oldCluster.Spec.Storage.Metadata)
		newGatewayMetadata := v1Beta1GatewayMetadataWithoutUnsupportedClaimTemplate(newCluster.Spec.Storage.Metadata)
		if oldGatewayMetadata != nil && newGatewayMetadata != nil {
			if err := validateLegacyV1Beta1ClusterVolumeIgnoredFieldTransition(
				"spec.storage.metadata", oldGatewayMetadata, newGatewayMetadata,
			); err != nil {
				return err
			}
			normalizeLegacyV1Beta1ClusterVolumeShapes(oldGatewayMetadata, oldGatewayMetadata, newGatewayMetadata)
		}
		if !equality.Semantic.DeepEqual(oldGatewayMetadata, newGatewayMetadata) {
			return fmt.Errorf("spec.storage.metadata cannot change while an edge gateway has live replicas: scale spec.replicas to 0, wait for its capacity-less roles to retire, then change the metadata PVC/EmptyDir configuration")
		}
	}
	if !v1beta1HasManagedDefaultPool(oldCluster) && !v1beta1HasManagedDefaultPool(newCluster) {
		return nil
	}
	if err := validateV1Beta1ClusterVolumeUpdate("spec.storage.metadata", oldCluster.Spec.Storage.Metadata, newCluster.Spec.Storage.Metadata); err != nil {
		return err
	}
	if !oldCluster.Spec.Gateway && !newCluster.Spec.Gateway {
		if err := validateV1Beta1ClusterVolumeUpdate("spec.storage.data", oldCluster.Spec.Storage.Data, newCluster.Spec.Storage.Data); err != nil {
			return err
		}
	}
	return nil
}

func v1Beta1GatewayMetadataWithoutUnsupportedClaimTemplate(volume *VolumeConfig) *VolumeConfig {
	if volume == nil {
		return nil
	}
	copy := volume.DeepCopy()
	copy.VolumeClaimTemplateSpec = nil
	return copy
}

func validateV1Beta1ClusterVolumeUpdate(field string, oldVolume, newVolume *VolumeConfig) error {
	if (oldVolume == nil) != (newVolume == nil) {
		return fmt.Errorf("%s volume topology is immutable while the default StatefulSet/PVC group has live replicas; drain the group to zero before changing volume sources", field)
	}
	if oldVolume == nil {
		return nil
	}
	if err := validateLegacyV1Beta1ClusterVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return err
	}
	oldShape, newShape := *oldVolume, *newVolume
	oldShape.Size, newShape.Size = nil, nil
	oldShape.Paths, newShape.Paths = nil, nil
	oldShape.VolumeClaimTemplateSpec, newShape.VolumeClaimTemplateSpec = nil, nil
	normalizeLegacyV1Beta1ClusterVolumeShapes(oldVolume, &oldShape, &newShape)
	if !equality.Semantic.DeepEqual(oldShape, newShape) {
		return fmt.Errorf("%s PVC/EmptyDir type, storage class, access modes, selector, labels, annotations, and claim template are immutable while replicas are live; only size growth is supported", field)
	}
	if err := validateV1Beta1QuantityGrowth(field+".size", oldVolume.Size, newVolume.Size); err != nil {
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
		if err := validateV1Beta1QuantityGrowth(fmt.Sprintf("%s.paths[%d].capacity", field, i), oldPath.Capacity, newPath.Capacity); err != nil {
			return err
		}
		if oldPath.Volume == nil {
			continue
		}
		oldPathShape, newPathShape := *oldPath.Volume, *newPath.Volume
		pathField := fmt.Sprintf("%s.paths[%d].volume", field, i)
		if err := validateLegacyV1Beta1DataPathVolumeIgnoredFieldTransition(pathField, oldPath.Volume, newPath.Volume); err != nil {
			return err
		}
		oldPathShape.Size, newPathShape.Size = nil, nil
		oldPathShape.VolumeClaimTemplateSpec, newPathShape.VolumeClaimTemplateSpec = nil, nil
		normalizeLegacyV1Beta1DataPathVolumeShapes(oldPath.Volume, &oldPathShape, &newPathShape)
		if !equality.Semantic.DeepEqual(oldPathShape, newPathShape) {
			return fmt.Errorf("%s.paths[%d].volume topology is immutable while replicas are live; only size growth is supported", field, i)
		}
		if err := validateV1Beta1QuantityGrowth(fmt.Sprintf("%s.paths[%d].volume.size", field, i), oldPath.Volume.Size, newPath.Volume.Size); err != nil {
			return err
		}
	}
	return nil
}

func validateV1Beta1QuantityGrowth(field string, oldQuantity, newQuantity *resource.Quantity) error {
	if equality.Semantic.DeepEqual(oldQuantity, newQuantity) {
		return nil
	}
	if oldQuantity == nil || newQuantity == nil || newQuantity.Cmp(*oldQuantity) < 0 {
		return fmt.Errorf("%s may only grow while the default StatefulSet/PVC group has live replicas", field)
	}
	return nil
}

func v1beta1StorageRolloutRecoverySafeSpecChange(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldSpec := oldCluster.DeepCopy().Spec
	newSpec := newCluster.DeepCopy().Spec
	normalizeV1Beta1StorageRolloutRecoveryFields(&oldSpec)
	normalizeV1Beta1StorageRolloutRecoveryFields(&newSpec)
	return equality.Semantic.DeepEqual(oldSpec, newSpec)
}

func normalizeV1Beta1StorageRolloutRecoveryFields(spec *GarageClusterSpec) {
	if spec == nil {
		return
	}
	spec.Image = ""
	spec.ImageRepository = ""
	spec.ImagePullPolicy = ""
	spec.ImagePullSecrets = nil
	spec.Resources = corev1.ResourceRequirements{}
	spec.NodeSelector = nil
	spec.Tolerations = nil
	spec.Affinity = nil
	spec.PodAnnotations = nil
	spec.PodLabels = nil
	spec.PriorityClassName = ""
	spec.ServiceAccountName = ""
	spec.SecurityContext = nil
	spec.ContainerSecurityContext = nil
	spec.TopologySpreadConstraints = nil
	spec.S3API = nil
	spec.K2VAPI = nil
	spec.WebAPI = nil
	spec.Admin = nil
	spec.Database = nil
	spec.Blocks = nil
	spec.Discovery = nil
	spec.Security = nil
	spec.Network.RPCBindPort = 0
	spec.Network.RPCBindAddress = ""
	spec.Network.RPCBindOutgoing = false
	spec.Network.RPCPingTimeout = nil
	spec.Network.RPCTimeout = nil
	spec.Storage.MetadataSnapshotsDir = ""
	spec.Storage.MetadataAutoSnapshotInterval = ""
	spec.Storage.MetadataFsync = false
	spec.Storage.DataFsync = false
	spec.Storage.Env = nil
	spec.Storage.EnvFrom = nil
	spec.Logging = nil
}

// v1beta1StorageRolloutActorName renders the actor a replacement transaction owns.
// See the v1beta2 counterpart.
func v1beta1StorageRolloutActorName(rollout *StorageRolloutStatus) string {
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

// garageClusterNodeLocalPoolRolloutActive keys the admission freeze on a concrete
// replacement transaction rather than on the StorageRolloutReady convergence
// signal. See the v1beta2 counterpart for why.
func garageClusterNodeLocalPoolRolloutActive(cluster *GarageCluster) bool {
	return cluster != nil && cluster.Status.StorageRollout != nil
}

func v1beta1HasStorage(cluster *GarageCluster) bool {
	return cluster != nil && !cluster.Spec.Gateway && !cluster.isManagementHandle()
}

func v1beta1EffectiveDeletionPolicy(cluster *GarageCluster) DeletionPolicy {
	if cluster == nil {
		return DeletionPolicyDestroy
	}
	if cluster.Spec.DeletionPolicy != "" {
		return cluster.Spec.DeletionPolicy
	}
	if len(cluster.Spec.RemoteClusters) > 0 {
		return DeletionPolicyDrain
	}
	return DeletionPolicyDestroy
}

func v1beta1StorageDrainConsistency(cluster *GarageCluster) string {
	if cluster == nil || cluster.Spec.Replication == nil || cluster.Spec.Replication.ConsistencyMode == "" {
		return consistencyModeConsistent
	}
	return strings.ToLower(cluster.Spec.Replication.ConsistencyMode)
}

func v1beta1StorageDrainPeerPolicy(cluster *GarageCluster) StorageDrainUnverifiedPeersPolicy {
	if cluster == nil || cluster.Spec.LayoutManagement == nil || cluster.Spec.LayoutManagement.Drain == nil ||
		cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy == "" {
		return StorageDrainUnverifiedPeersBlock
	}
	return cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy
}

func v1beta1StorageDrainWarnings(cluster *GarageCluster) admission.Warnings {
	if v1beta1StorageDrainPeerPolicy(cluster) != StorageDrainUnverifiedPeersAssumeConsistent {
		return nil
	}
	return admission.Warnings{
		"spec.layoutManagement.drain.unverifiedPeersPolicy=AssumeConsistent is an operator assertion the API cannot verify: every external/federated Garage process must run literal consistencyMode=consistent, S3 writes should be quiesced, and topology/Admin operations must be serialized across sites",
	}
}

func v1beta1PositiveStorageRemoval(oldCluster, newCluster *GarageCluster) bool {
	if !v1beta1HasStorage(oldCluster) {
		return false
	}
	if !v1beta1HasStorage(newCluster) {
		return v1beta1HasManagedDefaultPool(oldCluster)
	}
	// The new side deliberately does not require replicas > 0: N -> 0 is the
	// most consequential default-group removal and must pass the same prepared
	// drain boundary as N -> N-1. Auto -> Manual remains an ownership handoff,
	// not an operator-driven removal.
	if v1beta1HasManagedDefaultPool(oldCluster) &&
		newCluster.Spec.LayoutPolicy != layoutPolicyManual &&
		newCluster.Spec.Replicas < oldCluster.Spec.Replicas {
		return true
	}
	return false
}

func v1beta1HasManagedDefaultPool(cluster *GarageCluster) bool {
	return v1beta1HasStorage(cluster) && cluster.Spec.Replicas > 0 &&
		cluster.Spec.LayoutPolicy != layoutPolicyManual
}

func v1beta1StorageRemovalIsTopologyOnly(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil || !v1beta1HasStorage(oldCluster) || !v1beta1HasStorage(newCluster) {
		return false
	}
	oldSpec := oldCluster.DeepCopy().Spec
	newSpec := newCluster.DeepCopy().Spec
	oldSpec.Replicas = 0
	newSpec.Replicas = 0
	return equality.Semantic.DeepEqual(oldSpec, newSpec)
}

func v1beta1DrainReadiness(cluster *GarageCluster) error {
	if cluster.Status.FactorMigration != nil {
		return fmt.Errorf("positive-capacity drain cannot start while status.factorMigration is active")
	}
	if cluster.Status.StorageRollout != nil {
		return fmt.Errorf("positive-capacity drain cannot start while status.storageRollout is active")
	}
	var rollout *metav1.Condition
	for i := range cluster.Status.Conditions {
		if cluster.Status.Conditions[i].Type == ConditionStorageRolloutReady {
			rollout = &cluster.Status.Conditions[i]
			break
		}
	}
	if rollout == nil || rollout.Status != metav1.ConditionTrue || rollout.ObservedGeneration != cluster.Generation {
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

func v1beta1DeleteUsesForeground(ctx context.Context) (bool, error) {
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

func annotationContainsNodeLocalPools(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if part == v1beta2AnnotationNodeLocalPoolsPresent {
			return true
		}
	}
	return false
}

func annotationContainsGatewayTier(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if part == v1beta2AnnotationGatewayTierComponent {
			return true
		}
	}
	return false
}

// validateV1Beta1ConversionTransportUpdate protects v1beta2-only fields carried
// through a v1beta1 read/modify/write. It intentionally runs before ordinary
// v1beta1 shape validation so a missing envelope on a pool-only projection is
// reported as the exact data-safety violation rather than as missing default-
// group storage fields.
//
// Admission webhook rules default to matchPolicy=Equivalent. Kubernetes also
// invokes this v1beta1 webhook for a v1beta2 request after converting both
// objects to v1beta1, so the invariant applies only when the client actually
// addressed v1beta1. Legitimate v1beta2 edits remain the v1beta2 webhook's job.
func validateV1Beta1ConversionTransportUpdate(ctx context.Context, oldObj, newObj *GarageCluster) error {
	if originalGarageClusterRequestVersion(ctx) != GroupVersion.Version {
		return nil
	}

	oldPoolPayload, oldPoolPayloadPresent := oldObj.Annotations[v1beta2AnnotationNodeLocalPoolsData]
	newPoolPayload, newPoolPayloadPresent := newObj.Annotations[v1beta2AnnotationNodeLocalPoolsData]
	oldPoolMarker := annotationContainsNodeLocalPools(
		oldObj.Annotations[v1beta2AnnotationGatewayTierPresent],
	)
	newPoolMarker := annotationContainsNodeLocalPools(
		newObj.Annotations[v1beta2AnnotationGatewayTierPresent],
	)
	if oldPoolPayloadPresent && newPoolPayloadPresent && newPoolPayload != oldPoolPayload {
		return fmt.Errorf(
			"%s is a reserved conversion payload for v1beta2 storage.nodeLocalPools and must be preserved; use the v1beta2 API to modify node-local pools",
			v1beta2AnnotationNodeLocalPoolsData,
		)
	}
	if oldPoolPayload != "" && !newPoolPayloadPresent {
		return fmt.Errorf(
			"%s is a reserved conversion payload for v1beta2 storage.nodeLocalPools and must be preserved; use the v1beta2 API to modify node-local pools",
			v1beta2AnnotationNodeLocalPoolsData,
		)
	}
	if oldPoolPayload != "" && !newPoolMarker {
		return fmt.Errorf(
			"%s must retain the %q marker while v1beta2 storage.nodeLocalPools are present; use the v1beta2 API to modify node-local pools",
			v1beta2AnnotationGatewayTierPresent,
			v1beta2AnnotationNodeLocalPoolsPresent,
		)
	}
	if !oldPoolPayloadPresent && newPoolPayloadPresent {
		return fmt.Errorf(
			"%s is reserved for API conversion and cannot be added through v1beta1",
			v1beta2AnnotationNodeLocalPoolsData,
		)
	}
	if !oldPoolMarker && newPoolMarker {
		return fmt.Errorf(
			"%s component %q is reserved for API conversion and cannot be added through v1beta1",
			v1beta2AnnotationGatewayTierPresent,
			v1beta2AnnotationNodeLocalPoolsPresent,
		)
	}

	oldGatewayPayload, oldGatewayPayloadPresent := oldObj.Annotations[v1beta2AnnotationGatewayTierData]
	newGatewayPayload, newGatewayPayloadPresent := newObj.Annotations[v1beta2AnnotationGatewayTierData]
	oldGatewayMarker := annotationContainsGatewayTier(oldObj.Annotations[v1beta2AnnotationGatewayTierPresent])
	newGatewayMarker := annotationContainsGatewayTier(newObj.Annotations[v1beta2AnnotationGatewayTierPresent])
	if oldGatewayPayloadPresent && (!newGatewayPayloadPresent || newGatewayPayload != oldGatewayPayload) {
		return fmt.Errorf(
			"%s is a reserved conversion payload for a v1beta2 gateway tier and must be preserved; use the v1beta2 API to modify v1beta2-only gateway fields",
			v1beta2AnnotationGatewayTierData,
		)
	}
	if oldGatewayPayload != "" && !newGatewayMarker {
		return fmt.Errorf(
			"%s must retain the %q marker while a v1beta2 gateway tier is present; use the v1beta2 API to modify v1beta2-only gateway fields",
			v1beta2AnnotationGatewayTierPresent, v1beta2AnnotationGatewayTierComponent,
		)
	}
	if !oldGatewayPayloadPresent && newGatewayPayloadPresent {
		return fmt.Errorf("%s is reserved for API conversion and cannot be added through v1beta1", v1beta2AnnotationGatewayTierData)
	}
	if !oldGatewayMarker && newGatewayMarker {
		return fmt.Errorf(
			"%s component %q is reserved for API conversion and cannot be added through v1beta1",
			v1beta2AnnotationGatewayTierPresent, v1beta2AnnotationGatewayTierComponent,
		)
	}
	return nil
}

// originalGarageClusterRequestVersion returns the API version the client
// addressed, not the version Kubernetes converted to for this webhook. Direct
// unit calls have no admission request in context and are treated as v1beta1.
func originalGarageClusterRequestVersion(ctx context.Context) string {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return GroupVersion.Version
	}
	if req.RequestKind != nil && req.RequestKind.Group == GroupVersion.Group {
		return req.RequestKind.Version
	}
	if req.Kind.Group == GroupVersion.Group && req.Kind.Version != "" {
		return req.Kind.Version
	}
	return GroupVersion.Version
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateDelete(ctx context.Context, obj *GarageCluster) (admission.Warnings, error) {
	if obj == nil {
		return nil, nil
	}
	garageclusterlog.Info("validate delete", "name", obj.Name)
	if v1beta1HasStorage(obj) && len(obj.Spec.RemoteClusters) > 0 && obj.Spec.DeletionPolicy == "" {
		return nil, fmt.Errorf("deleting a federated GarageCluster requires an explicit spec.deletionPolicy: use Drain to retire this site safely, or Destroy only when the entire Garage store is being torn down")
	}
	if v1beta1EffectiveDeletionPolicy(obj) != DeletionPolicyDrain || !v1beta1HasStorage(obj) {
		return nil, nil
	}
	if obj.Status.StorageDrain != nil && obj.Status.StorageDrain.Actor.Kind == garageNodeKind {
		return nil, fmt.Errorf("garageCluster cannot be deleted while GarageNode %s/%s owns storage-drain transaction %q", obj.Status.StorageDrain.Actor.Namespace, obj.Status.StorageDrain.Actor.Name, obj.Status.StorageDrain.TransactionID)
	}
	drain := obj.Status.StorageDrain
	if obj.Annotations[drainPreparationAnnotation] != stringTrue || drain == nil ||
		drain.Actor.Kind != "GarageCluster" || drain.Actor.Namespace != obj.Namespace ||
		drain.Actor.Name != obj.Name || drain.Actor.UID != string(obj.UID) ||
		drain.CompletedAt == nil {
		return nil, fmt.Errorf(
			"deletionPolicy: Drain is a prepared deletion: set annotation %s=\"true\" and wait for StorageDrainReady=True reason Completed before deleting the GarageCluster",
			drainPreparationAnnotation,
		)
	}
	if foreground, err := v1beta1DeleteUsesForeground(ctx); err != nil {
		return nil, err
	} else if foreground {
		return nil, fmt.Errorf("foreground propagation is unsafe for deletionPolicy: Drain because Kubernetes may remove identity-bearing dependents before the GarageCluster finalizer proves block migration; use background/default propagation")
	}
	if v1beta1StorageDrainConsistency(obj) != consistencyModeConsistent {
		return nil, fmt.Errorf("deletionPolicy: Drain requires spec.replication.consistencyMode: consistent before deletion starts")
	}
	if len(obj.Spec.RemoteClusters) > 0 && v1beta1StorageDrainPeerPolicy(obj) != StorageDrainUnverifiedPeersAssumeConsistent {
		return nil, fmt.Errorf("deleting a federated storage site with deletionPolicy: Drain requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent")
	}
	// A completed transaction with no positive-capacity source is the durable
	// proof for an empty or gateway-only local site. Its exact roles have already
	// disappeared from settled layout history, so positive-capacity health and
	// rollout gates do not apply at the later DELETE boundary.
	if len(drain.RemovedStorageNodeIDs) > 0 {
		if err := v1beta1DrainReadiness(obj); err != nil {
			return nil, err
		}
	}
	return v1beta1StorageDrainWarnings(obj), nil
}

// validateGarageCluster validates the GarageCluster spec.
func (r *GarageCluster) validateGarageCluster() (admission.Warnings, error) {
	return r.validateGarageClusterWithOptions(false)
}

func (r *GarageCluster) validateGarageClusterWithOptions(allowUnchangedLegacy bool) (admission.Warnings, error) {
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
	if err := validateManagedTierReplicas(r.Spec.Replicas, "spec.replicas"); err != nil {
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
		if !v1beta1HasStorage(r) || r.Spec.DeletionPolicy != DeletionPolicyDrain {
			return warnings, fmt.Errorf("annotation %s requires a storage GarageCluster with explicit spec.deletionPolicy: Drain", drainPreparationAnnotation)
		}
	}
	if value, requested := r.Annotations[forceDeleteUnrevokedTokensAnnotation]; requested && value != stringTrue {
		return warnings, fmt.Errorf("annotation %s must be \"true\" when present", forceDeleteUnrevokedTokensAnnotation)
	}
	if fields := v1Beta1IgnoredGatewayStorageFields(r); len(fields) > 0 {
		return warnings, v1Beta1IgnoredGatewayStorageError(fields[0])
	}
	if err := workloadidentity.ValidatePodLabels(r.Spec.PodLabels, "spec.podLabels"); err != nil {
		return warnings, err
	}
	if err := validateGarageEnvironment(r.Spec.Storage.Env, r.Spec.Storage.EnvFrom, "spec.storage"); err != nil {
		return warnings, err
	}
	if err := r.validatePreservedV1Beta2GarageEnvironments(); err != nil {
		return warnings, err
	}

	if err := validateNoOperatorReservedLayoutTags(r.Spec.DefaultNodeTags, "spec.defaultNodeTags"); err != nil {
		return warnings, err
	}
	if fields := v1Beta1UnsupportedClaimTemplateFields(r); len(fields) > 0 {
		return warnings, v1Beta1UnsupportedClaimTemplateError(fields[0])
	}
	if err := validateDataSourceRefV1Beta1(r); err != nil {
		return warnings, err
	}

	if err := r.validateZoneRedundancy(); err != nil {
		return warnings, err
	}
	if err := r.validateRemoteClusters(allowUnchangedLegacy); err != nil {
		return warnings, err
	}
	if len(r.Spec.RemoteClusters) > 0 && r.Spec.DeletionPolicy == "" {
		warnings = append(warnings,
			"spec.deletionPolicy is omitted on a federated GarageCluster: normal reconciliation remains compatible, but deletion is refused until Drain or Destroy is chosen explicitly")
	} else if len(r.Spec.RemoteClusters) > 0 && r.Spec.DeletionPolicy == DeletionPolicyDestroy {
		warnings = append(warnings,
			"spec.deletionPolicy is Destroy on a federated GarageCluster: deleting this object tears down the local store without draining its roles; set Drain before retiring one physical site")
	}
	if v1beta1HasStorage(r) && r.Spec.DeletionPolicy == DeletionPolicyDrain {
		if len(r.Spec.RemoteClusters) == 0 {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain retires one site from a surviving federated Garage layout and requires spec.remoteClusters; use Destroy for a standalone/all-local store")
		}
		if v1beta1StorageDrainConsistency(r) != consistencyModeConsistent {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain requires spec.replication.consistencyMode: consistent")
		}
		if len(r.Spec.RemoteClusters) > 0 && v1beta1StorageDrainPeerPolicy(r) != StorageDrainUnverifiedPeersAssumeConsistent {
			return warnings, fmt.Errorf("spec.deletionPolicy: Drain with spec.remoteClusters requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent")
		}
	}
	warnings = append(warnings, v1beta1StorageDrainWarnings(r)...)

	if err := r.validateGateway(allowUnchangedLegacy); err != nil {
		return warnings, err
	}

	// Storage validation applies to a real default StatefulSet/PVC group only. A
	// management handle (#269) has gateway=false but no storage tier, so skip
	// it there. v1beta2 node-local pools are additive and transported separately
	// in an annotation; the default group remains a normal v1beta1 shape.
	hasPreservedNodeLocalPools := r.Spec.Replicas == 0 && r.hasPreservedNodeLocalPools()
	if !r.Spec.Gateway && !r.isManagementHandle() &&
		r.effectiveStorageLayoutPolicy() != layoutPolicyManual &&
		!hasPreservedNodeLocalPools {
		if err := r.validateStorage(); err != nil {
			return warnings, err
		}
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

	if r.Spec.Replication != nil && r.Spec.Replication.ConsistencyMode == "dangerous" {
		warnings = append(warnings, "ConsistencyMode 'dangerous' may lead to data loss. Use only for testing.")
	}

	if r.Spec.PodDisruptionBudget != nil && r.Spec.PodDisruptionBudget.Enabled &&
		r.Spec.PodDisruptionBudget.MinAvailable == nil && r.Spec.PodDisruptionBudget.MaxUnavailable == nil {
		if r.Spec.LayoutPolicy == layoutPolicyManual {
			warnings = append(warnings, "podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to maxUnavailable=1 across dynamic Manual membership")
		} else {
			warnings = append(warnings, "podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
		}
	}

	return warnings, nil
}

func validateSupportedPublicEndpoint(endpoint *PublicEndpointConfig, field string) error {
	if endpoint == nil {
		return nil
	}
	if endpoint.Type == publicEndpointTypeExternalIP || endpoint.ExternalIP != nil {
		return fmt.Errorf("%s.externalIP is not supported; use LoadBalancer, NodePort, or set spec.network.rpcPublicAddr", field)
	}
	if endpoint.Type == "Headless" {
		return fmt.Errorf("%s type Headless is not supported: managed pods do not have an externally resolvable per-node DNS address; use LoadBalancer, NodePort, or set spec.network.rpcPublicAddr", field)
	}
	switch endpoint.Type {
	case "LoadBalancer":
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

// ValidateSupportedPublicEndpoint applies the public endpoint contract during
// reconciliation as well as admission, so directly persisted legacy objects
// cannot silently select an unimplemented exposure mode.
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

const maxManagedTierReplicas int32 = 50

func validateManagedTierReplicas(replicas int32, field string) error {
	if replicas < 0 {
		return fmt.Errorf("%s must be non-negative", field)
	}
	if replicas > maxManagedTierReplicas {
		return fmt.Errorf("%s must be at most %d so every managed StatefulSet Pod and GarageNode name remains a valid Kubernetes label; v1beta2 storage.nodeLocalPools cardinality is selector-driven and is not subject to this limit", field, maxManagedTierReplicas)
	}
	return nil
}

const maxManagedGarageNodeNameLength = 61

func validateManagedGarageClusterName(cluster *GarageCluster) error {
	violations := managedGarageClusterNameViolations(cluster)
	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("%s", violations[0].message)
}

type managedNameViolation struct {
	actor   string
	message string
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
	if cluster.isManagementHandle() {
		return violations
	}
	if errs := utilvalidation.IsDNS1035Label(name + "-headless"); len(errs) > 0 {
		violations = append(violations, managedNameViolation{
			actor:   "Service/headless",
			message: fmt.Sprintf("metadata.name: %q makes the managed headless Service %q invalid: %s", name, name+"-headless", strings.Join(errs, "; ")),
		})
	}

	if !cluster.Spec.Gateway && cluster.Spec.Replicas > 0 && cluster.effectiveStorageLayoutPolicy() != layoutPolicyManual {
		violations = append(violations, autoGarageNodeNameViolations(name, "storage", cluster.Spec.Replicas)...)
	}
	if cluster.Spec.Gateway && cluster.Spec.Replicas > 0 && cluster.Spec.LayoutPolicy != layoutPolicyManual {
		ordinal := cluster.Spec.Replicas - 1
		podName := fmt.Sprintf("%s-gateway-%d", name, ordinal)
		if errs := utilvalidation.IsValidLabelValue(podName); len(errs) > 0 {
			violations = append(violations, managedNameViolation{
				actor:   "StatefulSet/gateway/Pod/name-bound",
				message: fmt.Sprintf("metadata.name: %q makes edge gateway StatefulSet Pod label %q invalid at spec.replicas=%d: %s", name, podName, cluster.Spec.Replicas, strings.Join(errs, "; ")),
			})
		}
	}
	if !cluster.Spec.Gateway && cluster.Spec.LayoutPolicy != layoutPolicyManual &&
		annotationContainsGatewayTier(cluster.Annotations[v1beta2AnnotationGatewayTierPresent]) {
		raw := cluster.Annotations[v1beta2AnnotationGatewayTierData]
		var gateway v1beta2.GatewaySpec
		if err := json.Unmarshal([]byte(raw), &gateway); err != nil {
			violations = append(violations, managedNameViolation{
				actor:   "conversion/gateway-tier",
				message: fmt.Sprintf("decode %s for managed-name validation: %v", v1beta2AnnotationGatewayTierData, err),
			})
		} else {
			violations = append(violations, autoGarageNodeNameViolations(name, "gateway", gateway.Replicas)...)
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
	if oldCluster != nil && newCluster != nil && equality.Semantic.DeepEqual(oldCluster.Spec, newCluster.Spec) &&
		v1beta1PreservedGatewayNameProfileEqual(oldCluster, newCluster) {
		return true, nil
	}
	if v1beta1GarageClusterNameUpdateOnlyRetiresManagedActors(oldCluster, newCluster) {
		return true, nil
	}
	return false, fmt.Errorf("metadata.name has an already-invalid managed child; only metadata/finalizer updates or a monotonic scale-down, tier removal, or Auto-to-Manual retirement may proceed until every derived workload name is valid")
}

func v1beta1GarageClusterNameUpdateOnlyRetiresManagedActors(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldCopy := oldCluster.DeepCopy()
	newCopy := newCluster.DeepCopy()
	if newCopy.Spec.Replicas <= oldCopy.Spec.Replicas {
		oldCopy.Spec.Replicas = newCopy.Spec.Replicas
	}
	if oldCopy.effectiveStorageLayoutPolicy() != layoutPolicyManual &&
		newCopy.effectiveStorageLayoutPolicy() == layoutPolicyManual {
		oldCopy.Spec.Storage.LayoutPolicy = newCopy.Spec.Storage.LayoutPolicy
	}
	if oldCopy.Spec.LayoutPolicy != layoutPolicyManual && newCopy.Spec.LayoutPolicy == layoutPolicyManual {
		oldCopy.Spec.LayoutPolicy = newCopy.Spec.LayoutPolicy
	}
	if oldCopy.Spec.Gateway && !newCopy.Spec.Gateway {
		oldCopy.Spec.Gateway = false
	}
	return equality.Semantic.DeepEqual(oldCopy.Spec, newCopy.Spec) &&
		v1beta1PreservedGatewayNameUpdateOnlyRetires(oldCluster, newCluster)
}

func v1beta1PreservedGatewayNameProfileEqual(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldPresent := annotationContainsGatewayTier(oldCluster.Annotations[v1beta2AnnotationGatewayTierPresent])
	newPresent := annotationContainsGatewayTier(newCluster.Annotations[v1beta2AnnotationGatewayTierPresent])
	if oldPresent != newPresent {
		return false
	}
	return !oldPresent ||
		oldCluster.Annotations[v1beta2AnnotationGatewayTierData] == newCluster.Annotations[v1beta2AnnotationGatewayTierData]
}

func v1beta1PreservedGatewayNameUpdateOnlyRetires(oldCluster, newCluster *GarageCluster) bool {
	if oldCluster == nil || newCluster == nil {
		return false
	}
	oldPresent := annotationContainsGatewayTier(oldCluster.Annotations[v1beta2AnnotationGatewayTierPresent])
	newPresent := annotationContainsGatewayTier(newCluster.Annotations[v1beta2AnnotationGatewayTierPresent])
	if !oldPresent {
		return !newPresent
	}
	if !newPresent {
		return true
	}
	oldRaw := oldCluster.Annotations[v1beta2AnnotationGatewayTierData]
	newRaw := newCluster.Annotations[v1beta2AnnotationGatewayTierData]
	if oldRaw == newRaw {
		return true
	}
	var oldGateway, newGateway v1beta2.GatewaySpec
	if err := json.Unmarshal([]byte(oldRaw), &oldGateway); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(newRaw), &newGateway); err != nil {
		return false
	}
	if newGateway.Replicas > oldGateway.Replicas {
		return false
	}
	oldGateway.Replicas = newGateway.Replicas
	return equality.Semantic.DeepEqual(oldGateway, newGateway)
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
	"GARAGE_RPC_SECRET", garageRPCSecretFileEnv,
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

// neutralizeLegacyGarageEnvironmentForValidation lets an object admitted by a
// released schema keep or remove unsafe environment entries long enough to be
// repaired or deleted. Every retained unsafe entry must be byte-for-byte equal
// to an old entry; it is removed only from the validation copy because the
// renderer independently filters operator-reserved names. New creates and new
// unsafe entries remain strict failures.
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
		// The old object already exceeded the newly enforced bound. Suppress the
		// length check on the validation copy only; the real object and rendered
		// Pod keep the exact non-expanding list.
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

// validatePreservedV1Beta2GarageEnvironments closes a conversion-webhook
// blind spot. A v1beta1 view carries v1beta2-only node-local pools and gateway
// fields in reserved annotations, so validating only the visible v1beta1
// fields would let an unsafe Garage credential override survive a legacy
// read/write or an Equivalent-version admission request.
func (r *GarageCluster) validatePreservedV1Beta2GarageEnvironments() error {
	if r == nil || r.Annotations == nil {
		return nil
	}
	if raw := r.Annotations[v1beta2AnnotationNodeLocalPoolsData]; raw != "" {
		var pools []v1beta2.NodeLocalPoolSpec
		if err := json.Unmarshal([]byte(raw), &pools); err != nil {
			return fmt.Errorf("decode %s for environment validation: %w", v1beta2AnnotationNodeLocalPoolsData, err)
		}
		for i := range pools {
			if pools[i].PodTemplate == nil {
				continue
			}
			if err := validateGarageEnvironment(
				pools[i].PodTemplate.Env,
				pools[i].PodTemplate.EnvFrom,
				fmt.Sprintf("%s[%q].podTemplate", v1beta2AnnotationNodeLocalPoolsData, pools[i].Name),
			); err != nil {
				return err
			}
		}
	}
	if raw := r.Annotations[v1beta2AnnotationGatewayTierData]; raw != "" {
		var gateway v1beta2.GatewaySpec
		if err := json.Unmarshal([]byte(raw), &gateway); err != nil {
			return fmt.Errorf("decode %s for environment validation: %w", v1beta2AnnotationGatewayTierData, err)
		}
		if err := validateGarageEnvironment(
			gateway.Env,
			gateway.EnvFrom,
			v1beta2AnnotationGatewayTierData,
		); err != nil {
			return err
		}
	}
	return nil
}

func neutralizeLegacyV1Beta1GarageClusterEnvironmentsForValidation(
	oldCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	safeEnv, safeEnvFrom, storageWarnings, err := neutralizeLegacyGarageEnvironmentForValidation(
		"spec.storage",
		oldCluster.Spec.Storage.Env, validationCluster.Spec.Storage.Env,
		oldCluster.Spec.Storage.EnvFrom, validationCluster.Spec.Storage.EnvFrom,
	)
	if err != nil {
		return warnings, err
	}
	validationCluster.Spec.Storage.Env = safeEnv
	validationCluster.Spec.Storage.EnvFrom = safeEnvFrom
	warnings = append(warnings, storageWarnings...)

	oldRaw := oldCluster.Annotations[v1beta2AnnotationGatewayTierData]
	newRaw := validationCluster.Annotations[v1beta2AnnotationGatewayTierData]
	if oldRaw == "" || newRaw == "" {
		return warnings, nil
	}
	var oldGateway, newGateway v1beta2.GatewaySpec
	if err := json.Unmarshal([]byte(oldRaw), &oldGateway); err != nil {
		return warnings, fmt.Errorf("decode old %s for legacy environment validation: %w", v1beta2AnnotationGatewayTierData, err)
	}
	if err := json.Unmarshal([]byte(newRaw), &newGateway); err != nil {
		return warnings, fmt.Errorf("decode new %s for legacy environment validation: %w", v1beta2AnnotationGatewayTierData, err)
	}
	safeEnv, safeEnvFrom, gatewayWarnings, err := neutralizeLegacyGarageEnvironmentForValidation(
		v1beta2AnnotationGatewayTierData,
		oldGateway.Env, newGateway.Env,
		oldGateway.EnvFrom, newGateway.EnvFrom,
	)
	if err != nil {
		return warnings, err
	}
	newGateway.Env = safeEnv
	newGateway.EnvFrom = safeEnvFrom
	sanitized, err := json.Marshal(&newGateway)
	if err != nil {
		return warnings, fmt.Errorf("encode %s after legacy environment validation: %w", v1beta2AnnotationGatewayTierData, err)
	}
	if validationCluster.Annotations == nil {
		validationCluster.Annotations = map[string]string{}
	}
	validationCluster.Annotations[v1beta2AnnotationGatewayTierData] = string(sanitized)
	warnings = append(warnings, gatewayWarnings...)
	return warnings, nil
}

func neutralizeLegacyV1Beta1GarageClusterReplicaBoundForValidation(
	oldCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil ||
		oldCluster.Spec.Replicas <= maxManagedTierReplicas ||
		validationCluster.Spec.Replicas <= maxManagedTierReplicas {
		return nil, nil
	}
	if validationCluster.Spec.Replicas > oldCluster.Spec.Replicas {
		return nil, fmt.Errorf(
			"spec.replicas exceeds the supported maximum %d and may only remain unchanged or decrease until it is within the bound",
			maxManagedTierReplicas,
		)
	}
	validationCluster.Spec.Replicas = maxManagedTierReplicas
	return admission.Warnings{fmt.Sprintf(
		"spec.replicas exceeds the supported maximum %d; this non-expanding update is temporarily tolerated so replicas can be retired",
		maxManagedTierReplicas,
	)}, nil
}

func (r *GarageCluster) validateRemoteClusters(allowUnchangedLegacy ...bool) error {
	allowLegacy := len(allowUnchangedLegacy) > 0 && allowUnchangedLegacy[0]
	names := make(map[string]int, len(r.Spec.RemoteClusters))
	zones := make(map[string]int, len(r.Spec.RemoteClusters))
	for i := range r.Spec.RemoteClusters {
		remote := &r.Spec.RemoteClusters[i]
		if !allowLegacy && remote.DefaultCapacity != nil {
			return fmt.Errorf("spec.remoteClusters[%d].defaultCapacity is not supported; remote role capacity is owned by the source cluster layout", i)
		}
		name := strings.TrimSpace(remote.Name)
		zone := strings.TrimSpace(remote.Zone)
		if name == "" || zone == "" {
			return fmt.Errorf("spec.remoteClusters[%d] name and zone must not be empty or whitespace", i)
		}
		if previous, duplicate := names[name]; duplicate {
			return fmt.Errorf("spec.remoteClusters[%d].name %q duplicates spec.remoteClusters[%d]; remote names must be unique", i, name, previous)
		}
		names[name] = i
		if previous, duplicate := zones[zone]; duplicate {
			return fmt.Errorf("spec.remoteClusters[%d].zone %q duplicates spec.remoteClusters[%d]; each physical Garage site must have a unique zone", i, zone, previous)
		}
		zones[zone] = i
		if !allowLegacy {
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

func (r *GarageCluster) effectiveStorageLayoutPolicy() string {
	if r.Spec.Storage.LayoutPolicy != "" {
		return r.Spec.Storage.LayoutPolicy
	}
	return r.Spec.LayoutPolicy
}

func (r *GarageCluster) hasPreservedNodeLocalPools() bool {
	return r != nil &&
		r.Annotations[v1beta2AnnotationNodeLocalPoolsData] != "" &&
		annotationContainsNodeLocalPools(r.Annotations[v1beta2AnnotationGatewayTierPresent])
}

func (r *GarageCluster) isMetadataEphemeral() bool {
	return r.Spec.Storage.Metadata != nil && r.Spec.Storage.Metadata.Type == VolumeTypeEmptyDir
}

func (r *GarageCluster) isDataEphemeral() bool {
	return r.Spec.Storage.Data != nil && r.Spec.Storage.Data.Type == VolumeTypeEmptyDir
}

// isManagementHandle reports whether this v1beta1 view is a connection-only
// management handle (#269): no gateway, no storage tier, connectTo set. This is
// the v1beta1 projection of a tier-less v1beta2 handle (the storage version),
// surfaced here through the conversion webhook.
func (r *GarageCluster) isManagementHandle() bool {
	return !r.Spec.Gateway &&
		r.Spec.ConnectTo != nil &&
		r.Spec.Replicas == 0 &&
		r.Spec.Storage.Metadata == nil &&
		r.Spec.Storage.Data == nil
}

func (r *GarageCluster) validateGateway(allowUnchangedLegacy ...bool) error {
	allowLegacy := len(allowUnchangedLegacy) > 0 && allowUnchangedLegacy[0]
	if r.Spec.ConnectTo != nil && r.Spec.ConnectTo.ClusterRef != nil &&
		r.Spec.ConnectTo.ClusterRef.Namespace != "" && r.Spec.ConnectTo.ClusterRef.Namespace != r.Namespace {
		return fmt.Errorf("connectTo.clusterRef.namespace must be empty or match metadata.namespace; cross-namespace credential and layout inheritance is not permitted")
	}
	if r.Spec.Gateway {
		if fields := v1Beta1IgnoredGatewayStorageFields(r); len(fields) > 0 {
			return v1Beta1IgnoredGatewayStorageError(fields[0])
		}
		if r.Spec.ConnectTo == nil {
			return fmt.Errorf("connectTo is required when gateway is true")
		}
		if r.Spec.Network.RPCSecretRef == nil && r.Spec.ConnectTo.RPCSecretRef == nil && r.Spec.ConnectTo.ClusterRef == nil {
			return fmt.Errorf("gateway connectTo requires clusterRef, connectTo.rpcSecretRef, or network.rpcSecretRef; bootstrapPeers and adminApiEndpoint do not provide the shared RPC identity")
		}
		if metadata := r.Spec.Storage.Metadata; metadata != nil {
			if len(metadata.Paths) > 0 {
				return fmt.Errorf("storage.metadata.paths: paths is only valid for storage data volumes")
			}
			if err := r.validateVolumeConfig(metadata, "metadata"); err != nil {
				return err
			}
		}
	} else {
		// connectTo without a gateway is allowed only for a management handle
		// (no storage tier either): a connection-only CR that manages an external
		// Garage's Admin-API state. This is the v1beta2 shape (#269) seen here via
		// the conversion webhook (matchPolicy: Equivalent) — the storage version
		// is v1beta2, so a handle converts to a v1beta1 view with gateway=false,
		// no storage, and connectTo set. Anything else with connectTo but no
		// gateway is still rejected.
		if r.Spec.ConnectTo != nil && !r.isManagementHandle() {
			return fmt.Errorf("connectTo can only be specified when gateway is true, or on a tier-less management handle")
		}
	}

	if r.Spec.ConnectTo != nil {
		if !allowLegacy && r.Spec.ConnectTo.ClusterRef != nil {
			if err := ValidateClusterReference(*r.Spec.ConnectTo.ClusterRef, "spec.connectTo.clusterRef"); err != nil {
				return err
			}
		}
		if !allowLegacy {
			if err := garageconfig.ValidateAdminAPIEndpoint(r.Spec.ConnectTo.AdminAPIEndpoint, "spec.connectTo.adminApiEndpoint"); err != nil {
				return err
			}
		}
		// A management handle needs an Admin-API path; a gateway needs an RPC path.
		// adminApiEndpoint is a valid handle path (the common Helm-adoption case).
		if r.Spec.ConnectTo.ClusterRef == nil &&
			r.Spec.ConnectTo.RPCSecretRef == nil &&
			len(r.Spec.ConnectTo.BootstrapPeers) == 0 &&
			r.Spec.ConnectTo.AdminAPIEndpoint == "" {
			return fmt.Errorf("connectTo must specify clusterRef, rpcSecretRef, bootstrapPeers, or adminApiEndpoint")
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
		factor = 3 // webhook default
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

func (r *GarageCluster) validateStorage() error {
	if r.Spec.Storage.Metadata != nil {
		if err := r.validateVolumeConfig(r.Spec.Storage.Metadata, "metadata"); err != nil {
			return err
		}
	}

	if r.Spec.Storage.Data != nil {
		if err := r.validateVolumeConfig(r.Spec.Storage.Data, "data"); err != nil {
			return err
		}
		for i := range r.Spec.Storage.Data.Paths {
			if volume := r.Spec.Storage.Data.Paths[i].Volume; volume != nil {
				if err := validateV1Beta1DataPathVolumeConfig(volume, fmt.Sprintf("storage.data.paths[%d].volume", i)); err != nil {
					return err
				}
			}
		}
		if r.Spec.Storage.Data.Type == VolumeTypeEmptyDir && len(r.Spec.Storage.Data.Paths) > 0 {
			return fmt.Errorf("storage.data.paths: not allowed with EmptyDir type")
		}
	}
	if r.Spec.Storage.Metadata != nil && len(r.Spec.Storage.Metadata.Paths) > 0 {
		return fmt.Errorf("storage.metadata.paths: paths is only valid for data volumes")
	}

	if !r.isDataEphemeral() {
		if r.Spec.Storage.Data == nil {
			return fmt.Errorf("storage.data: must specify data storage configuration")
		}
		if r.Spec.Storage.Data.Size == nil && len(r.Spec.Storage.Data.Paths) == 0 {
			return fmt.Errorf("storage.data.size: must specify size for persistent data storage (or use storage.data.paths for multi-disk)")
		}
	}
	return nil
}

func validateDataSourceRefV1Beta1(cluster *GarageCluster) error {
	storage := cluster.Spec.Storage
	if storage.DataSourceRef == nil {
		return nil
	}
	if !storage.AllowDataSourceRef {
		return fmt.Errorf("storage.dataSourceRef: requires explicit storage.allowDataSourceRef=true acknowledgement")
	}
	if cluster.Spec.Gateway {
		return fmt.Errorf("storage.dataSourceRef: only supported for the operator-managed Auto storage group")
	}
	if cluster.effectiveStorageLayoutPolicy() != layoutPolicyAuto {
		return fmt.Errorf("storage.dataSourceRef: only supported for the operator-managed Auto storage group")
	}
	if storage.Metadata == nil || storage.Data == nil {
		return fmt.Errorf("storage.dataSourceRef: requires both storage.metadata and storage.data so the Auto group has explicit persistent identity and data volumes; only data is populated from this source")
	}
	if storage.Metadata.Type == VolumeTypeEmptyDir || storage.Data.Type == VolumeTypeEmptyDir {
		return fmt.Errorf("storage.dataSourceRef: requires persistent metadata and data volumes; EmptyDir cannot be restored from a PVC data source")
	}
	if storage.Metadata.Size == nil {
		return fmt.Errorf("storage.dataSourceRef: requires a persistent storage.metadata volume with size")
	}
	if storage.Data.Size == nil {
		return fmt.Errorf("storage.dataSourceRef: requires a persistent storage.data volume with size")
	}
	if len(storage.Data.Paths) > 0 {
		return fmt.Errorf("storage.dataSourceRef: multi-disk storage.data.paths is not supported")
	}
	if storage.Data.Selector != nil {
		return fmt.Errorf("storage.dataSourceRef: a data selector cannot be combined with a group data source")
	}
	ref := storage.DataSourceRef
	if strings.TrimSpace(ref.Name) == "" || strings.TrimSpace(ref.Kind) == "" {
		return fmt.Errorf("storage.dataSourceRef: kind and name are required")
	}
	if ref.APIGroup == nil || strings.TrimSpace(*ref.APIGroup) == "" {
		return fmt.Errorf("storage.dataSourceRef.apiGroup: a non-core group-aware populator source is required; a core PVC or single-volume source cannot safely initialize every target claim")
	}
	if strings.TrimSpace(*ref.APIGroup) != *ref.APIGroup {
		return fmt.Errorf("storage.dataSourceRef.apiGroup must not have leading or trailing whitespace")
	}
	if ref.Namespace != nil {
		if strings.TrimSpace(*ref.Namespace) == "" || *ref.Namespace == cluster.Namespace {
			return fmt.Errorf("storage.dataSourceRef.namespace: omit the namespace for a same-namespace source; explicit namespace requires a disabled cross-namespace feature gate")
		}
		return fmt.Errorf("storage.dataSourceRef.namespace: cross-namespace references are not supported")
	}
	if err := validateDataSourceObjectReference(ref, "storage.dataSourceRef"); err != nil {
		return err
	}
	return nil
}

func validateDataSourceObjectReference(ref *corev1.TypedObjectReference, field string) error {
	if ref == nil {
		return nil
	}
	namespace := ""
	if ref.Namespace != nil {
		namespace = *ref.Namespace
	}
	if err := validateNamespacedObjectReference(ref.Name, namespace, field); err != nil {
		return err
	}
	if strings.TrimSpace(ref.Kind) != ref.Kind || ref.Kind == "" {
		return fmt.Errorf("%s.kind must be a non-empty value without leading or trailing whitespace", field)
	}
	if ref.APIGroup != nil {
		if strings.TrimSpace(*ref.APIGroup) == "" {
			return fmt.Errorf("%s.apiGroup must be omitted or non-empty", field)
		}
		if strings.TrimSpace(*ref.APIGroup) != *ref.APIGroup {
			return fmt.Errorf("%s.apiGroup must not have leading or trailing whitespace", field)
		}
	}
	return nil
}

func (r *GarageCluster) validateVolumeConfig(vc *VolumeConfig, name string) error {
	if vc.Type == VolumeTypeEmptyDir {
		if vc.StorageClassName != nil {
			return fmt.Errorf("storage.%s.storageClassName: not allowed with EmptyDir type", name)
		}
		if vc.Selector != nil {
			return fmt.Errorf("storage.%s.selector: not allowed with EmptyDir type", name)
		}
		if vc.VolumeClaimTemplateSpec != nil {
			return fmt.Errorf("storage.%s.volumeClaimTemplateSpec: not allowed with EmptyDir type", name)
		}
		if len(vc.AccessModes) > 0 {
			return fmt.Errorf("storage.%s.accessModes: not allowed with EmptyDir type", name)
		}
		if len(vc.Labels) > 0 {
			return fmt.Errorf("storage.%s.labels: not allowed with EmptyDir type", name)
		}
		if len(vc.Annotations) > 0 {
			return fmt.Errorf("storage.%s.annotations: not allowed with EmptyDir type", name)
		}
	}
	if vc.Selector != nil {
		if _, err := metav1.LabelSelectorAsSelector(vc.Selector); err != nil {
			return fmt.Errorf("storage.%s.selector: invalid PersistentVolume label selector: %w", name, err)
		}
	}
	if vc.VolumeClaimTemplateSpec != nil {
		return fmt.Errorf("storage.%s.volumeClaimTemplateSpec: unsupported for operator-managed storage because arbitrary claim templates can violate Garage identity isolation; use size, storageClassName, accessModes, selector, labels, and annotations, or an ordinary GarageNode existingClaim", name)
	}
	return nil
}

func v1Beta1UnsupportedClaimTemplateError(field string) error {
	return fmt.Errorf("%s: unsupported for operator-managed storage because arbitrary claim templates can violate Garage identity isolation; use size, storageClassName, accessModes, selector, labels, and annotations, or an ordinary GarageNode existingClaim", field)
}

func v1Beta1IgnoredGatewayStorageError(field string) error {
	return fmt.Errorf(
		"%s is not represented on a v1beta1 gateway and would be discarded during conversion; use the v1beta2 API and configure gateway-specific fields under spec.gateway",
		field,
	)
}

// v1Beta1IgnoredGatewayStorageFields returns every storage-only v1beta1 field
// that ConvertTo cannot project into a gateway-only v1beta2 shape. Gateway
// metadata is deliberately excluded: it was part of the released v1beta1
// gateway contract and maps to v1beta2 spec.gateway.metadata. New ignored
// values must be rejected rather than silently discarded; rich v1beta2-only
// gateway data remains solely in the reserved conversion payload.
func v1Beta1IgnoredGatewayStorageFields(cluster *GarageCluster) []string {
	if cluster == nil || !cluster.Spec.Gateway {
		return nil
	}
	fields := make([]string, 0, 14)
	storage := cluster.Spec.Storage
	if storage.Data != nil {
		fields = append(fields, "spec.storage.data")
	}
	if storage.DataSourceRef != nil {
		fields = append(fields, "spec.storage.dataSourceRef")
	}
	if storage.AllowDataSourceRef {
		fields = append(fields, "spec.storage.allowDataSourceRef")
	}
	if storage.RPCPublicAddr != "" {
		fields = append(fields, "spec.storage.rpcPublicAddr")
	}
	if storage.LayoutPolicy != "" {
		fields = append(fields, "spec.storage.layoutPolicy")
	}
	if storage.MetadataSnapshotsDir != "" {
		fields = append(fields, "spec.storage.metadataSnapshotsDir")
	}
	if storage.MetadataAutoSnapshotInterval != "" {
		fields = append(fields, "spec.storage.metadataAutoSnapshotInterval")
	}
	if storage.MetadataFsync {
		fields = append(fields, "spec.storage.metadataFsync")
	}
	if storage.DataFsync {
		fields = append(fields, "spec.storage.dataFsync")
	}
	if len(storage.Env) > 0 {
		fields = append(fields, "spec.storage.env")
	}
	if len(storage.EnvFrom) > 0 {
		fields = append(fields, "spec.storage.envFrom")
	}
	if cluster.Spec.CapacityReservePercent != 0 {
		fields = append(fields, "spec.capacityReservePercent")
	}
	sort.Strings(fields)
	return fields
}

func v1Beta1IgnoredGatewayStorageValues(cluster *GarageCluster) map[string]any {
	out := make(map[string]any)
	if cluster == nil || !cluster.Spec.Gateway {
		return out
	}
	storage := cluster.Spec.Storage
	if storage.Data != nil {
		out["spec.storage.data"] = storage.Data
	}
	if storage.DataSourceRef != nil {
		out["spec.storage.dataSourceRef"] = storage.DataSourceRef
	}
	if storage.AllowDataSourceRef {
		out["spec.storage.allowDataSourceRef"] = storage.AllowDataSourceRef
	}
	if storage.RPCPublicAddr != "" {
		out["spec.storage.rpcPublicAddr"] = storage.RPCPublicAddr
	}
	if storage.LayoutPolicy != "" {
		out["spec.storage.layoutPolicy"] = storage.LayoutPolicy
	}
	if storage.MetadataSnapshotsDir != "" {
		out["spec.storage.metadataSnapshotsDir"] = storage.MetadataSnapshotsDir
	}
	if storage.MetadataAutoSnapshotInterval != "" {
		out["spec.storage.metadataAutoSnapshotInterval"] = storage.MetadataAutoSnapshotInterval
	}
	if storage.MetadataFsync {
		out["spec.storage.metadataFsync"] = storage.MetadataFsync
	}
	if storage.DataFsync {
		out["spec.storage.dataFsync"] = storage.DataFsync
	}
	if len(storage.Env) > 0 {
		out["spec.storage.env"] = storage.Env
	}
	if len(storage.EnvFrom) > 0 {
		out["spec.storage.envFrom"] = storage.EnvFrom
	}
	if cluster.Spec.CapacityReservePercent != 0 {
		out["spec.capacityReservePercent"] = cluster.Spec.CapacityReservePercent
	}
	return out
}

func validateV1Beta1IgnoredGatewayStorageUpdate(oldCluster, newCluster *GarageCluster) (admission.Warnings, error) {
	oldFields := v1Beta1IgnoredGatewayStorageValues(oldCluster)
	newFields := v1Beta1IgnoredGatewayStorageValues(newCluster)
	unchanged := make([]string, 0, len(newFields))
	for field, newValue := range newFields {
		oldValue, existed := oldFields[field]
		if !existed || !v1Beta1ValueIsUnchangedOrRemoval(oldValue, newValue) {
			return nil, v1Beta1IgnoredGatewayStorageError(field)
		}
		unchanged = append(unchanged, field)
	}
	if len(unchanged) == 0 {
		return nil, nil
	}
	sort.Strings(unchanged)
	return admission.Warnings{fmt.Sprintf(
		"legacy ignored v1beta1 gateway fields %s were never applied to the gateway workload; unchanged values are temporarily tolerated only so they can be removed, and v1beta2 gateway fields remain in the reserved conversion payload",
		strings.Join(unchanged, ", "),
	)}, nil
}

func v1Beta1ValueIsUnchangedOrRemoval(oldValue, newValue any) bool {
	oldJSON, err := json.Marshal(oldValue)
	if err != nil {
		return false
	}
	newJSON, err := json.Marshal(newValue)
	if err != nil {
		return false
	}
	var oldNormalized, newNormalized any
	if json.Unmarshal(oldJSON, &oldNormalized) != nil || json.Unmarshal(newJSON, &newNormalized) != nil {
		return false
	}
	return jsonValueIsUnchangedOrRemoval(oldNormalized, newNormalized)
}

func jsonValueIsUnchangedOrRemoval(oldValue, newValue any) bool {
	switch newTyped := newValue.(type) {
	case map[string]any:
		oldTyped, ok := oldValue.(map[string]any)
		if !ok {
			return false
		}
		for key, newChild := range newTyped {
			oldChild, exists := oldTyped[key]
			if !exists || !jsonValueIsUnchangedOrRemoval(oldChild, newChild) {
				return false
			}
		}
		return true
	case []any:
		// Lists have positional semantics. Clearing the complete list is a
		// removal; any retained non-empty list must remain exactly unchanged.
		oldTyped, ok := oldValue.([]any)
		return ok && (len(newTyped) == 0 || equality.Semantic.DeepEqual(oldTyped, newTyped))
	default:
		return equality.Semantic.DeepEqual(oldValue, newValue)
	}
}

func clearV1Beta1IgnoredGatewayStorage(cluster *GarageCluster) {
	if cluster == nil || !cluster.Spec.Gateway {
		return
	}
	cluster.Spec.Storage.Data = nil
	cluster.Spec.Storage.DataSourceRef = nil
	cluster.Spec.Storage.AllowDataSourceRef = false
	cluster.Spec.Storage.RPCPublicAddr = ""
	cluster.Spec.Storage.LayoutPolicy = ""
	cluster.Spec.Storage.MetadataSnapshotsDir = ""
	cluster.Spec.Storage.MetadataAutoSnapshotInterval = ""
	cluster.Spec.Storage.MetadataFsync = false
	cluster.Spec.Storage.DataFsync = false
	cluster.Spec.Storage.Env = nil
	cluster.Spec.Storage.EnvFrom = nil
	cluster.Spec.CapacityReservePercent = 0
}

func v1Beta1ClaimTemplateSpecsByField(cluster *GarageCluster) map[string]*corev1.PersistentVolumeClaimSpec {
	out := make(map[string]*corev1.PersistentVolumeClaimSpec)
	if cluster == nil {
		return out
	}
	if cluster.Spec.Storage.Metadata != nil && cluster.Spec.Storage.Metadata.VolumeClaimTemplateSpec != nil {
		out["storage.metadata.volumeClaimTemplateSpec"] = cluster.Spec.Storage.Metadata.VolumeClaimTemplateSpec
	}
	if cluster.Spec.Storage.Data != nil {
		if cluster.Spec.Storage.Data.VolumeClaimTemplateSpec != nil {
			out["storage.data.volumeClaimTemplateSpec"] = cluster.Spec.Storage.Data.VolumeClaimTemplateSpec
		}
		for i := range cluster.Spec.Storage.Data.Paths {
			if cluster.Spec.Storage.Data.Paths[i].Volume != nil && cluster.Spec.Storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec != nil {
				out[fmt.Sprintf("storage.data.paths[%d].volume.volumeClaimTemplateSpec", i)] = cluster.Spec.Storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec
			}
		}
	}
	return out
}

func v1Beta1UnsupportedClaimTemplateFields(cluster *GarageCluster) []string {
	fieldsByName := v1Beta1ClaimTemplateSpecsByField(cluster)
	fields := make([]string, 0, len(fieldsByName))
	for field := range fieldsByName {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func validateV1Beta1UnsupportedClaimTemplateUpdate(oldCluster, newCluster *GarageCluster) (admission.Warnings, error) {
	oldFields := v1Beta1ClaimTemplateSpecsByField(oldCluster)
	newFields := v1Beta1ClaimTemplateSpecsByField(newCluster)
	unchanged := make([]string, 0, len(newFields))
	for field, newSpec := range newFields {
		oldSpec, existed := oldFields[field]
		if !existed || !equality.Semantic.DeepEqual(oldSpec, newSpec) {
			return nil, v1Beta1UnsupportedClaimTemplateError(field)
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

func clearV1Beta1UnsupportedClaimTemplates(cluster *GarageCluster) {
	if cluster == nil {
		return
	}
	if cluster.Spec.Storage.Metadata != nil {
		cluster.Spec.Storage.Metadata.VolumeClaimTemplateSpec = nil
	}
	if cluster.Spec.Storage.Data != nil {
		cluster.Spec.Storage.Data.VolumeClaimTemplateSpec = nil
		for i := range cluster.Spec.Storage.Data.Paths {
			if cluster.Spec.Storage.Data.Paths[i].Volume != nil {
				cluster.Spec.Storage.Data.Paths[i].Volume.VolumeClaimTemplateSpec = nil
			}
		}
	}
}

// neutralizeLegacyV1Beta1GarageClusterVolumesForValidation preserves the
// update/delete path for released PVC fields that the managed renderer ignored.
// The persisted object is not changed: ignored values may remain byte-for-byte
// unchanged or be removed, but cannot be replaced with a different ignored
// value. Strict create validation continues rejecting every legacy shape.
func neutralizeLegacyV1Beta1GarageClusterVolumesForValidation(
	oldCluster, validationCluster *GarageCluster,
) (admission.Warnings, error) {
	if oldCluster == nil || validationCluster == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	volume := func(field string, oldVolume, newVolume *VolumeConfig) error {
		legacy, err := neutralizeLegacyV1Beta1ClusterVolumeForValidation(field, oldVolume, newVolume)
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
		legacy, err := neutralizeLegacyV1Beta1DataPathVolumeForValidation(field, oldVolume, newVolume)
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

	oldStorage, newStorage := &oldCluster.Spec.Storage, &validationCluster.Spec.Storage
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
	return warnings, nil
}

func neutralizeLegacyV1Beta1ClusterVolumeForValidation(
	field string,
	oldVolume, newVolume *VolumeConfig,
) (bool, error) {
	if oldVolume == nil || newVolume == nil {
		return false, nil
	}
	if err := validateLegacyV1Beta1ClusterVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return false, err
	}
	legacy := false
	if oldVolume.Type == VolumeTypeEmptyDir && v1Beta1ClusterVolumeHasIgnoredPVCFields(oldVolume) {
		clearV1Beta1ClusterVolumeIgnoredPVCFields(newVolume)
		legacy = true
	}
	if oldVolume.Type != VolumeTypeEmptyDir && invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		newVolume.Selector = nil
		legacy = true
	}
	return legacy, nil
}

func neutralizeLegacyV1Beta1DataPathVolumeForValidation(
	field string,
	oldVolume, newVolume *DataPathVolumeConfig,
) (bool, error) {
	if oldVolume == nil || newVolume == nil {
		return false, nil
	}
	if err := validateLegacyV1Beta1DataPathVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return false, err
	}
	legacy := false
	if oldVolume.Type == VolumeTypeEmptyDir && v1Beta1DataPathVolumeHasIgnoredPVCFields(oldVolume) {
		clearV1Beta1DataPathVolumeIgnoredPVCFields(newVolume)
		legacy = true
	}
	if oldVolume.Type != VolumeTypeEmptyDir && invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		newVolume.Selector = nil
		legacy = true
	}
	return legacy, nil
}

func validateLegacyV1Beta1ClusterVolumeIgnoredFieldTransition(
	field string,
	oldVolume, newVolume *VolumeConfig,
) error {
	if oldVolume == nil || newVolume == nil {
		return nil
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		return validateLegacyV1Beta1ClusterPVCOnlyFields(
			field,
			oldVolume.StorageClassName, newVolume.StorageClassName,
			oldVolume.Selector, newVolume.Selector,
			oldVolume.AccessModes, newVolume.AccessModes,
			oldVolume.Labels, newVolume.Labels,
			oldVolume.Annotations, newVolume.Annotations,
		)
	}
	if invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		return validateLegacyV1Beta1ClusterIgnoredField(field+".selector", oldVolume.Selector, newVolume.Selector)
	}
	return nil
}

func validateLegacyV1Beta1DataPathVolumeIgnoredFieldTransition(
	field string,
	oldVolume, newVolume *DataPathVolumeConfig,
) error {
	if oldVolume == nil || newVolume == nil {
		return nil
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		return validateLegacyV1Beta1ClusterPVCOnlyFields(
			field,
			oldVolume.StorageClassName, newVolume.StorageClassName,
			oldVolume.Selector, newVolume.Selector,
			oldVolume.AccessModes, newVolume.AccessModes,
			oldVolume.Labels, newVolume.Labels,
			oldVolume.Annotations, newVolume.Annotations,
		)
	}
	if invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		return validateLegacyV1Beta1ClusterIgnoredField(field+".selector", oldVolume.Selector, newVolume.Selector)
	}
	return nil
}

func validateLegacyV1Beta1ClusterPVCOnlyFields(
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
		{name: storageClassNameJSONField, oldValue: oldStorageClass, newValue: newStorageClass},
		{name: selectorJSONField, oldValue: oldSelector, newValue: newSelector},
		{name: "accessModes", oldValue: oldAccessModes, newValue: newAccessModes},
		{name: "labels", oldValue: oldLabels, newValue: newLabels},
		{name: "annotations", oldValue: oldAnnotations, newValue: newAnnotations},
	} {
		if err := validateLegacyV1Beta1ClusterIgnoredField(
			field+"."+transition.name, transition.oldValue, transition.newValue,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateLegacyV1Beta1ClusterIgnoredField(field string, oldValue, newValue any) error {
	if equality.Semantic.DeepEqual(oldValue, newValue) || legacyV1Beta1ClusterSemanticZero(newValue) {
		return nil
	}
	return fmt.Errorf("%s was ignored by the released renderer and may only remain unchanged or be removed", field)
}

func legacyV1Beta1ClusterSemanticZero(value any) bool {
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

func v1Beta1ClusterVolumeHasIgnoredPVCFields(volume *VolumeConfig) bool {
	return volume != nil && (volume.StorageClassName != nil || volume.Selector != nil ||
		len(volume.AccessModes) > 0 || len(volume.Labels) > 0 || len(volume.Annotations) > 0)
}

func clearV1Beta1ClusterVolumeIgnoredPVCFields(volume *VolumeConfig) {
	if volume == nil {
		return
	}
	volume.StorageClassName = nil
	volume.Selector = nil
	volume.AccessModes = nil
	volume.Labels = nil
	volume.Annotations = nil
}

func normalizeLegacyV1Beta1ClusterVolumeShapes(oldVolume, oldShape, newShape *VolumeConfig) {
	if oldVolume == nil || oldShape == nil || newShape == nil {
		return
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		clearV1Beta1ClusterVolumeIgnoredPVCFields(oldShape)
		clearV1Beta1ClusterVolumeIgnoredPVCFields(newShape)
	} else if invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		oldShape.Selector = nil
		newShape.Selector = nil
	}
}

func v1Beta1DataPathVolumeHasIgnoredPVCFields(volume *DataPathVolumeConfig) bool {
	return volume != nil && (volume.StorageClassName != nil || volume.Selector != nil ||
		len(volume.AccessModes) > 0 || len(volume.Labels) > 0 || len(volume.Annotations) > 0)
}

func clearV1Beta1DataPathVolumeIgnoredPVCFields(volume *DataPathVolumeConfig) {
	if volume == nil {
		return
	}
	volume.StorageClassName = nil
	volume.Selector = nil
	volume.AccessModes = nil
	volume.Labels = nil
	volume.Annotations = nil
}

func normalizeLegacyV1Beta1DataPathVolumeShapes(
	oldVolume, oldShape, newShape *DataPathVolumeConfig,
) {
	if oldVolume == nil || oldShape == nil || newShape == nil {
		return
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		clearV1Beta1DataPathVolumeIgnoredPVCFields(oldShape)
		clearV1Beta1DataPathVolumeIgnoredPVCFields(newShape)
	} else if invalidV1Beta1ClusterVolumeSelector(oldVolume.Selector) {
		oldShape.Selector = nil
		newShape.Selector = nil
	}
}

func invalidV1Beta1ClusterVolumeSelector(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	_, err := metav1.LabelSelectorAsSelector(selector)
	return err != nil
}

func validateV1Beta1DataPathVolumeConfig(vc *DataPathVolumeConfig, field string) error {
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

func (r *GarageCluster) validateAPIs() error {
	if r.isManagementHandle() {
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
	if err := garageconfig.ValidateMetadataSnapshotInterval(
		r.Spec.Storage.MetadataAutoSnapshotInterval,
		"spec.storage.metadataAutoSnapshotInterval",
	); err != nil {
		return err
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

// validateBindAddress is retained for focused package tests and delegates to
// the shared managed-listener contract used by every API endpoint.
func validateBindAddress(addr, field string) error {
	if addr == "" {
		return fmt.Errorf("%s.bindAddress must not be empty", field)
	}
	_, err := garageconfig.ManagedBindPort(addr, 0, 3900, field+".bindAddress")
	return err
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

	// A v1beta2 object with storage.nodeLocalPools is admitted through this equivalent
	// v1beta1 webhook after conversion. Pool cardinality comes from selected
	// Kubernetes Nodes, so the projected spec.replicas is not a sound upper bound.
	if lm.MinNodesHealthy > 0 && !r.hasPreservedNodeLocalPools() {
		replicas := int(r.Spec.Replicas)
		if lm.MinNodesHealthy > replicas {
			return fmt.Errorf("layoutManagement.minNodesHealthy (%d) cannot exceed replicas (%d) — layout changes would never be applied", lm.MinNodesHealthy, replicas)
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
		(oldCluster.isManagementHandle() && newCluster.isManagementHandle()) {
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
