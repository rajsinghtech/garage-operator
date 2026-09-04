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
	"fmt"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
	"github.com/rajsinghtech/garage-operator/internal/storagecontract"
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

const garageClusterKind = "GarageCluster"

var garagenodelog = logf.Log.WithName("garagenode-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageNode) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageNodeDefaulter{}).
		WithValidator(&GarageNodeValidator{apiReader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta1-garagenode,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update,versions=v1beta1,name=mgaragenode.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageNode] = &GarageNodeDefaulter{}

// GarageNodeDefaulter handles defaulting for GarageNode.
type GarageNodeDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageNodeDefaulter) Default(ctx context.Context, obj *GarageNode) error {
	garagenodelog.Info("default", "name", obj.Name)

	// Garage accepts case-insensitive hex input but its Admin API always emits
	// lowercase IDs. Canonicalize every writable identity boundary so explicit
	// External/Manual/PVC/SMB identities compare cleanly with discovered layout
	// and drain state.
	obj.Spec.NodeID = canonicalGarageNodeID(obj.Spec.NodeID)
	if obj.Annotations != nil {
		for _, key := range []string{AnnotationAcknowledgeLostSource, AnnotationNodeLocalPoolRecoveryNodeID} {
			if value, exists := obj.Annotations[key]; exists {
				obj.Annotations[key] = canonicalGarageNodeID(value)
			}
		}
	}
	if obj.Spec.External != nil && obj.Spec.External.Port == 0 {
		obj.Spec.External.Port = 3901
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagenode,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update;delete,versions=v1beta1,name=vgaragenode.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageNode] = &GarageNodeValidator{}

// +kubebuilder:object:generate=false

// GarageNodeValidator handles validation for GarageNode.
type GarageNodeValidator struct {
	// apiReader verifies that an internal node-local-pool-backed child carries the
	// real parent UID, rather than a user-forged owner reference. It is nil in
	// pure unit tests, where validateGarageNode still checks the structural
	// owner contract.
	apiReader client.Reader
}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateCreate(ctx context.Context, obj *GarageNode) (admission.Warnings, error) {
	garagenodelog.Info("validate create", "name", obj.Name)
	warnings, err := obj.validateGarageNode()
	if err != nil {
		return warnings, err
	}
	if _, requested := obj.Annotations[AnnotationCycle]; requested {
		return warnings, fmt.Errorf("annotation %s cannot be set when a GarageNode is created; wait for the exact StatefulSet Pod and Garage identity to be Ready, connected, and committed, then add the annotation in a separate update", AnnotationCycle)
	}
	if lostNodeID := canonicalGarageNodeID(obj.Annotations[AnnotationAcknowledgeLostSource]); lostNodeID != "" &&
		lostNodeID != canonicalGarageNodeID(obj.Spec.NodeID) {
		return warnings, fmt.Errorf("annotation %s on create requires the same exact spec.nodeId", AnnotationAcknowledgeLostSource)
	}
	if err := v.validateNodeLocalPoolControllerOwner(ctx, obj, true); err != nil {
		return warnings, err
	}
	if err := v.validateParentStorageRollout(ctx, obj, "created"); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageNode) (admission.Warnings, error) {
	garagenodelog.Info("validate update", "name", newObj.Name)
	oldSpec, newSpec := oldObj.Spec, newObj.Spec
	oldSpec.NodeID = canonicalGarageNodeID(oldSpec.NodeID)
	newSpec.NodeID = canonicalGarageNodeID(newSpec.NodeID)
	specChanged := !equality.Semantic.DeepEqual(oldSpec, newSpec)
	drainRequestChanged := oldObj.Annotations[AnnotationDrain] != newObj.Annotations[AnnotationDrain] ||
		canonicalGarageNodeID(oldObj.Annotations[AnnotationAcknowledgeLostSource]) !=
			canonicalGarageNodeID(newObj.Annotations[AnnotationAcknowledgeLostSource])
	oldCycleRequested := oldObj.Annotations[AnnotationCycle] == stringTrue
	newCycleRequested := newObj.Annotations[AnnotationCycle] == stringTrue
	cycleRequestChanged := oldObj.Annotations[AnnotationCycle] != newObj.Annotations[AnnotationCycle]
	cycleStarting := !oldCycleRequested && newCycleRequested
	if specChanged && (oldCycleRequested || oldObj.Status.CyclePhase != "" || newCycleRequested) {
		return nil, fmt.Errorf("garageNode spec cannot change while a cycle is requested or active; finish or safely cancel the exact replacement transaction first")
	}
	if oldCycleRequested && !newCycleRequested &&
		oldObj.Status.CyclePhase == CyclePhaseDraining &&
		oldObj.Annotations[AnnotationDrain] == stringTrue {
		return nil, fmt.Errorf("annotation %s cannot be removed after the cycle entered Draining and requested the one-way durable source drain", AnnotationCycle)
	}
	var layoutOwner *v1beta2.GarageCluster
	var referencedCluster *v1beta2.GarageCluster
	if v.apiReader != nil && (specChanged || drainRequestChanged || cycleRequestChanged) {
		clusterNamespace := oldObj.Namespace
		if oldObj.Spec.ClusterRef.Namespace != "" {
			clusterNamespace = oldObj.Spec.ClusterRef.Namespace
		}
		cluster := &v1beta2.GarageCluster{}
		if err := v.apiReader.Get(ctx, types.NamespacedName{
			Name: oldObj.Spec.ClusterRef.Name, Namespace: clusterNamespace,
		}, cluster); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return nil, fmt.Errorf("checking parent storage rollout before GarageNode spec update: %w", err)
			}
		} else {
			referencedCluster = cluster
			layoutOwner, err = v.resolveGarageNodeLayoutOwner(ctx, cluster)
			if err != nil {
				return nil, fmt.Errorf("resolving canonical Garage layout owner before GarageNode update: %w", err)
			}
			if v1beta2StorageRolloutActive(layoutOwner) &&
				!garageNodeStorageRolloutRecoveryAllowed(oldObj, newObj, layoutOwner, specChanged, drainRequestChanged) &&
				!validActiveStorageRolloutLostSourceEscalation(oldObj, newObj, layoutOwner, specChanged, drainRequestChanged) {
				return nil, fmt.Errorf("garageNode spec cannot change while canonical GarageCluster %s/%s has status.storageRollout active; only workload override fields on the exact persisted GarageNode UID may change to roll that actor forward", layoutOwner.Namespace, layoutOwner.Name)
			}
			if layoutOwner.Status.StorageDrain != nil &&
				(specChanged || !validActiveLostSourceEscalation(oldObj, newObj, layoutOwner.Status.StorageDrain)) {
				return nil, fmt.Errorf("garageNode spec or drain/recovery annotations cannot change while canonical GarageCluster %s/%s has status.storageDrain transaction %q active", layoutOwner.Namespace, layoutOwner.Name, layoutOwner.Status.StorageDrain.TransactionID)
			}
		}
	}
	oldBacking := effectiveNodeBacking(oldObj.Spec.Backing)
	newBacking := effectiveNodeBacking(newObj.Spec.Backing)
	if oldBacking != newBacking {
		return nil, fmt.Errorf("backing is immutable: cannot change from %s to %s on an existing GarageNode", oldBacking, newBacking)
	}
	if oldObj.Spec.Gateway != newObj.Spec.Gateway {
		return nil, fmt.Errorf("gateway is immutable: delete and drain the existing GarageNode identity before creating a node in the other storage tier")
	}
	if !sameGarageNodeClusterRef(oldObj, newObj) {
		return nil, fmt.Errorf("clusterRef is immutable: drain and delete the GarageNode from its current Garage layout before creating a distinct node in another cluster")
	}
	if canonicalGarageNodeID(oldObj.Spec.NodeID) != canonicalGarageNodeID(newObj.Spec.NodeID) {
		return nil, fmt.Errorf("nodeId is immutable: it identifies the Garage process key; drain and delete this GarageNode before managing another identity")
	}
	oldRecoveryNodeID := strings.TrimSpace(oldObj.Annotations[AnnotationNodeLocalPoolRecoveryNodeID])
	newRecoveryNodeID := strings.TrimSpace(newObj.Annotations[AnnotationNodeLocalPoolRecoveryNodeID])
	if oldRecoveryNodeID != "" && !strings.EqualFold(oldRecoveryNodeID, newRecoveryNodeID) {
		return nil, fmt.Errorf("annotation %s is immutable once set; it pins this internal child to one retained HostPath identity", AnnotationNodeLocalPoolRecoveryNodeID)
	}
	if (oldObj.Spec.External == nil) != (newObj.Spec.External == nil) {
		return nil, fmt.Errorf("external versus operator-managed process ownership is immutable: drain and delete the existing GarageNode before changing workload ownership")
	}
	if oldBacking == NodeBackingNodeLocalPool && oldObj.Spec.KubernetesNodeName != newObj.Spec.KubernetesNodeName {
		return nil, fmt.Errorf("kubernetesNodeName is immutable for a node-local-pool-backed GarageNode")
	}
	if oldBacking == NodeBackingNodeLocalPool && oldObj.Spec.NodeLocalPoolName != newObj.Spec.NodeLocalPoolName {
		return nil, fmt.Errorf("nodeLocalPoolName is immutable for a node-local-pool-backed GarageNode")
	}
	grandfatherManagedName, err := validateManagedGarageNodeNameUpdate(oldObj, newObj)
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
	legacyVolumeWarnings, err := neutralizeLegacyGarageNodeVolumesForValidation(oldObj, validationObj)
	if err != nil {
		return nil, err
	}
	safeEnv, safeEnvFrom, legacyEnvironmentWarnings, err := neutralizeLegacyGarageEnvironmentForValidation(
		"spec", oldObj.Spec.Env, validationObj.Spec.Env, oldObj.Spec.EnvFrom, validationObj.Spec.EnvFrom,
	)
	if err != nil {
		return nil, err
	}
	validationObj.Spec.Env = safeEnv
	validationObj.Spec.EnvFrom = safeEnvFrom
	validationObj.Spec.PodLabels = workloadidentity.UserPodLabels(validationObj.Spec.PodLabels)
	warnings, err := validationObj.validateGarageNode(!specChanged)
	if grandfatherManagedName {
		warnings = append(warnings, "metadata.name is grandfathered for this non-expanding update; creating or rolling a StatefulSet-backed workload remains blocked until <name>-0 is a valid Kubernetes label value")
	}
	warnings = append(warnings, legacyVolumeWarnings...)
	warnings = append(warnings, legacyEnvironmentWarnings...)
	warnings = append(warnings, podLabelWarnings...)
	if err != nil {
		return warnings, err
	}
	if cycleStarting {
		if err := newObj.ValidateCycleSourceReadiness(); err != nil {
			return warnings, fmt.Errorf("annotation %s is not eligible: %w", AnnotationCycle, err)
		}
		if referencedCluster != nil {
			if err := newObj.ValidateCycleParentNetworkProfile(referencedCluster); err != nil {
				return warnings, fmt.Errorf("annotation %s is not eligible: %w", AnnotationCycle, err)
			}
		}
		if v.apiReader != nil && layoutOwner == nil {
			return warnings, fmt.Errorf("annotation %s cannot start while the referenced GarageCluster or canonical layout owner is absent", AnnotationCycle)
		}
		if layoutOwner != nil {
			if err := v1beta2GarageNodeDrainReadiness(layoutOwner); err != nil {
				return warnings, fmt.Errorf("annotation %s cannot start before the canonical Garage layout is safe for a positive-capacity replacement: %w", AnnotationCycle, err)
			}
		}
	}
	oldLostNodeID := canonicalGarageNodeID(oldObj.Annotations[AnnotationAcknowledgeLostSource])
	newLostNodeID := canonicalGarageNodeID(newObj.Annotations[AnnotationAcknowledgeLostSource])
	if oldLostNodeID != newLostNodeID {
		if oldLostNodeID != "" {
			return warnings, fmt.Errorf("annotation %s is one-way and immutable once set; delete the prepared GarageNode after its exact lost-source transaction completes", AnnotationAcknowledgeLostSource)
		}
		if newLostNodeID != "" && newLostNodeID != canonicalGarageNodeID(oldObj.Status.NodeID) &&
			newLostNodeID != canonicalGarageNodeID(newObj.Status.NodeID) &&
			newLostNodeID != canonicalGarageNodeID(oldObj.Spec.NodeID) &&
			newLostNodeID != canonicalGarageNodeID(newObj.Spec.NodeID) &&
			newLostNodeID != canonicalGarageNodeID(oldObj.Annotations[AnnotationNodeLocalPoolRecoveryNodeID]) &&
			newLostNodeID != canonicalGarageNodeID(newObj.Annotations[AnnotationNodeLocalPoolRecoveryNodeID]) {
			return warnings, fmt.Errorf("annotation %s must equal this GarageNode's exact known status.nodeId or spec.nodeId", AnnotationAcknowledgeLostSource)
		}
	}
	// A retired pool is intentionally absent from the parent spec while its
	// GarageNodes continue receiving status/finalizer updates during drain.
	// Re-verify the live parent UID on ordinary updates, but require pool
	// declaration only at creation time. An already-deleting child may outlive
	// its parent and must remain able to remove its finalizer.
	if err := v.validateNodeLocalPoolControllerOwner(ctx, newObj, false); err != nil {
		return warnings, err
	}
	if err := validateGarageNodeStorageUpdate(oldObj, newObj); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// neutralizeLegacyReadOnlyForValidation keeps updates and deletion cleanup
// possible for objects admitted before readOnly stopped counting as a volume
// source. It mutates only a validation copy. A synthetic size prevents the old
// invalid readOnly-only shape from masking validation of the rest of the
// object; neither the persisted spec nor the rendered workload gains a PVC.
func neutralizeLegacyReadOnlyForValidation(volume *NodeVolumeConfig) {
	if volume == nil {
		return
	}
	volume.ReadOnly = false
	if volume.Type != VolumeTypeEmptyDir && volume.ExistingClaim == "" && volume.Size == nil {
		volume.Size = resource.NewQuantity(1, resource.BinarySI)
	}
}

// neutralizeLegacyGarageNodeVolumesForValidation preserves the update/delete
// path for released fields that the old renderer ignored. The persisted object
// is never mutated here. A legacy value may stay byte-for-byte unchanged or be
// removed; changing it to another ignored value is rejected. The workload
// renderer continues using the same effective source while the user repairs the
// API object.
func neutralizeLegacyGarageNodeVolumesForValidation(oldNode, validationNode *GarageNode) (admission.Warnings, error) {
	if oldNode == nil || validationNode == nil || oldNode.Spec.Storage == nil || validationNode.Spec.Storage == nil {
		return nil, nil
	}
	var warnings admission.Warnings
	neutralize := func(field string, oldVolume, newVolume *NodeVolumeConfig, readOnlyIgnored bool) error {
		legacy, err := neutralizeLegacyNodeVolumeForValidation(field, oldVolume, newVolume, readOnlyIgnored)
		if err != nil {
			return err
		}
		if legacy {
			warnings = append(warnings, fmt.Sprintf(
				"%s contains unchanged released fields that never affected the rendered Kubernetes volume; they are ignored during this update and should be removed",
				field,
			))
		}
		return nil
	}
	if err := neutralize("storage.metadata", oldNode.Spec.Storage.Metadata, validationNode.Spec.Storage.Metadata, true); err != nil {
		return warnings, err
	}
	if err := neutralize("storage.data", oldNode.Spec.Storage.Data, validationNode.Spec.Storage.Data, true); err != nil {
		return warnings, err
	}
	if len(oldNode.Spec.Storage.DataPaths) == len(validationNode.Spec.Storage.DataPaths) {
		for i := range oldNode.Spec.Storage.DataPaths {
			if err := neutralize(
				fmt.Sprintf("storage.dataPaths[%d]", i),
				&oldNode.Spec.Storage.DataPaths[i], &validationNode.Spec.Storage.DataPaths[i], false,
			); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

func neutralizeLegacyNodeVolumeForValidation(
	field string,
	oldVolume, newVolume *NodeVolumeConfig,
	readOnlyIgnored bool,
) (bool, error) {
	if oldVolume == nil || newVolume == nil {
		return false, nil
	}
	if err := validateLegacyNodeVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return false, err
	}
	legacy := false
	switch {
	case oldVolume.Type == VolumeTypeEmptyDir && nodeVolumeHasIgnoredPVCFields(oldVolume, true):
		clearNodeVolumeIgnoredPVCFields(newVolume, true)
		legacy = true
	case oldVolume.ExistingClaim != "" && nodeVolumeHasIgnoredPVCFields(oldVolume, false):
		clearNodeVolumeIgnoredPVCFields(newVolume, false)
		legacy = true
	}
	if oldVolume.Type != VolumeTypeEmptyDir && oldVolume.ExistingClaim == "" && invalidNodeVolumeSelector(oldVolume.Selector) {
		newVolume.Selector = nil
		legacy = true
	}
	if readOnlyIgnored && oldVolume.ReadOnly {
		if newVolume.ReadOnly {
			neutralizeLegacyReadOnlyForValidation(newVolume)
		}
		legacy = true
	}
	if legacyReadOnlyOnlyVolume(oldVolume) && !nodeVolumeHasRealSource(newVolume) {
		neutralizeLegacyReadOnlyForValidation(newVolume)
		legacy = true
	}
	return legacy, nil
}

func validateLegacyNodeVolumeIgnoredFieldTransition(field string, oldVolume, newVolume *NodeVolumeConfig) error {
	if oldVolume == nil || newVolume == nil {
		return nil
	}
	check := func(name string, oldValue, newValue any) error {
		if equality.Semantic.DeepEqual(oldValue, newValue) || semanticZero(newValue) {
			return nil
		}
		return fmt.Errorf("%s.%s was ignored by the released renderer and may only remain unchanged or be removed", field, name)
	}
	if oldVolume.Type == VolumeTypeEmptyDir {
		if err := check("existingClaim", oldVolume.ExistingClaim, newVolume.ExistingClaim); err != nil {
			return err
		}
		if err := validateLegacyNodePVCOnlyFieldTransition(field, oldVolume, newVolume); err != nil {
			return err
		}
	} else if oldVolume.ExistingClaim != "" {
		if err := validateLegacyNodePVCOnlyFieldTransition(field, oldVolume, newVolume); err != nil {
			return err
		}
	} else if invalidNodeVolumeSelector(oldVolume.Selector) {
		if err := check(selectorJSONField, oldVolume.Selector, newVolume.Selector); err != nil {
			return err
		}
	}
	return nil
}

func validateLegacyNodePVCOnlyFieldTransition(field string, oldVolume, newVolume *NodeVolumeConfig) error {
	check := func(name string, oldValue, newValue any) error {
		if equality.Semantic.DeepEqual(oldValue, newValue) || semanticZero(newValue) {
			return nil
		}
		return fmt.Errorf("%s.%s was ignored by the released renderer and may only remain unchanged or be removed", field, name)
	}
	for _, transition := range []struct {
		name     string
		oldValue any
		newValue any
	}{
		{name: storageClassNameJSONField, oldValue: oldVolume.StorageClassName, newValue: newVolume.StorageClassName},
		{name: selectorJSONField, oldValue: oldVolume.Selector, newValue: newVolume.Selector},
		{name: "accessModes", oldValue: oldVolume.AccessModes, newValue: newVolume.AccessModes},
		{name: "labels", oldValue: oldVolume.Labels, newValue: newVolume.Labels},
		{name: "annotations", oldValue: oldVolume.Annotations, newValue: newVolume.Annotations},
	} {
		if err := check(transition.name, transition.oldValue, transition.newValue); err != nil {
			return err
		}
	}
	return nil
}

func semanticZero(value any) bool {
	switch typed := value.(type) {
	case string:
		return typed == ""
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

func nodeVolumeHasIgnoredPVCFields(volume *NodeVolumeConfig, includeExistingClaim bool) bool {
	if volume == nil {
		return false
	}
	return (includeExistingClaim && volume.ExistingClaim != "") ||
		volume.StorageClassName != nil || volume.Selector != nil || len(volume.AccessModes) > 0 ||
		len(volume.Labels) > 0 || len(volume.Annotations) > 0
}

func clearNodeVolumeIgnoredPVCFields(volume *NodeVolumeConfig, includeExistingClaim bool) {
	if volume == nil {
		return
	}
	if includeExistingClaim {
		volume.ExistingClaim = ""
	}
	volume.StorageClassName = nil
	volume.Selector = nil
	volume.AccessModes = nil
	volume.Labels = nil
	volume.Annotations = nil
}

func invalidNodeVolumeSelector(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	_, err := metav1.LabelSelectorAsSelector(selector)
	return err != nil
}

func nodeVolumeHasRealSource(volume *NodeVolumeConfig) bool {
	return volume != nil && (volume.ExistingClaim != "" || volume.Size != nil || volume.Type == VolumeTypeEmptyDir)
}

func legacyReadOnlyOnlyVolume(volume *NodeVolumeConfig) bool {
	return volume != nil && volume.ReadOnly && !nodeVolumeHasRealSource(volume)
}

func garageNodeStorageRolloutRecoveryAllowed(
	oldNode, newNode *GarageNode,
	cluster *v1beta2.GarageCluster,
	specChanged, drainRequestChanged bool,
) bool {
	if oldNode == nil || newNode == nil || cluster == nil || cluster.Status.StorageRollout == nil ||
		!specChanged || drainRequestChanged ||
		cluster.Status.StorageRollout.GarageNodeName != oldNode.Name ||
		cluster.Status.StorageRollout.GarageNodeUID == "" ||
		cluster.Status.StorageRollout.GarageNodeUID != string(oldNode.UID) || oldNode.UID != newNode.UID {
		return false
	}
	oldSpec := oldNode.DeepCopy().Spec
	newSpec := newNode.DeepCopy().Spec
	normalizeGarageNodeStorageRolloutRecoveryFields(&oldSpec)
	normalizeGarageNodeStorageRolloutRecoveryFields(&newSpec)
	return equality.Semantic.DeepEqual(oldSpec, newSpec)
}

func normalizeGarageNodeStorageRolloutRecoveryFields(spec *GarageNodeSpec) {
	if spec == nil {
		return
	}
	spec.Image = ""
	spec.ImageRepository = ""
	spec.Resources = nil
	spec.NodeSelector = nil
	spec.Tolerations = nil
	spec.Affinity = nil
	spec.PodAnnotations = nil
	spec.PodLabels = nil
	spec.PriorityClassName = ""
	spec.ImagePullPolicy = ""
	spec.ImagePullSecrets = nil
	spec.ServiceAccountName = ""
	spec.SecurityContext = nil
	spec.ContainerSecurityContext = nil
	spec.TopologySpreadConstraints = nil
	spec.Env = nil
	spec.EnvFrom = nil
	spec.Logging = nil
	spec.NodeID = canonicalGarageNodeID(spec.NodeID)
}

// validActiveStorageRolloutLostSourceEscalation permits one monotonic escape
// from a permanently lost exact rollout actor. Both annotations must be added
// together, no spec or unrelated annotation may change, and the acknowledged
// Garage ID must be the pre-delete identity persisted by the parent transaction.
// The controller still proves that Garage already reports this ID down before
// it transfers the durable boundary or fences any workload.
func validActiveStorageRolloutLostSourceEscalation(
	oldNode, newNode *GarageNode,
	cluster *v1beta2.GarageCluster,
	specChanged, drainRequestChanged bool,
) bool {
	if oldNode == nil || newNode == nil || cluster == nil || cluster.Status.StorageRollout == nil ||
		oldNode.UID == "" || oldNode.UID != newNode.UID || specChanged || !drainRequestChanged ||
		oldNode.Annotations[AnnotationDrain] == stringTrue ||
		oldNode.Annotations[AnnotationAcknowledgeLostSource] != "" ||
		newNode.Annotations[AnnotationDrain] != stringTrue {
		return false
	}
	record := cluster.Status.StorageRollout
	lostNodeID := canonicalGarageNodeID(newNode.Annotations[AnnotationAcknowledgeLostSource])
	knownNodeID, err := oldNode.ResolvedGarageNodeID()
	if err != nil {
		return false
	}
	if lostNodeID == "" || lostNodeID != knownNodeID || lostNodeID != canonicalGarageNodeID(record.GarageNodeID) ||
		record.GarageNodeUID != string(oldNode.UID) {
		return false
	}
	actorMatches := record.GarageNodeName == oldNode.Name
	if record.GarageNodeName == "" {
		actorMatches = effectiveNodeBacking(oldNode.Spec.Backing) == NodeBackingNodeLocalPool &&
			record.NodeLocalPoolName == oldNode.Spec.NodeLocalPoolName &&
			record.KubernetesNodeName == oldNode.Spec.KubernetesNodeName
	}
	if !actorMatches {
		return false
	}
	oldAnnotations := copyStringAnnotationsWithoutRolloutEscalation(oldNode.Annotations)
	newAnnotations := copyStringAnnotationsWithoutRolloutEscalation(newNode.Annotations)
	return equality.Semantic.DeepEqual(oldAnnotations, newAnnotations)
}

func copyStringAnnotationsWithoutRolloutEscalation(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		if key != AnnotationDrain && key != AnnotationAcknowledgeLostSource {
			result[key] = value
		}
	}
	return result
}

// validActiveLostSourceEscalation permits the sole safe mutation of a live
// storage-drain transaction: monotonically acknowledging that this exact
// GarageNode actor's already-authorized source became permanently unavailable.
// The controller then advances TargetHash and discards all prior worker proof.
// Removing or changing the acknowledgement remains forbidden.
func validActiveLostSourceEscalation(
	oldNode, newNode *GarageNode,
	drain *v1beta2.StorageDrainStatus,
) bool {
	if oldNode == nil || newNode == nil || drain == nil || oldNode.UID == "" ||
		oldNode.Annotations[AnnotationDrain] != stringTrue ||
		newNode.Annotations[AnnotationDrain] != stringTrue ||
		oldNode.Annotations[AnnotationAcknowledgeLostSource] != "" {
		return false
	}
	lostNodeID := canonicalGarageNodeID(newNode.Annotations[AnnotationAcknowledgeLostSource])
	if lostNodeID == "" || drain.Actor.APIVersion != GroupVersion.String() ||
		drain.Actor.Kind != garageNodeKind || drain.Actor.Namespace != oldNode.Namespace ||
		drain.Actor.Name != oldNode.Name || drain.Actor.UID != string(oldNode.UID) {
		return false
	}
	for _, nodeID := range drain.RemovedStorageNodeIDs {
		if canonicalGarageNodeID(nodeID) == lostNodeID {
			return true
		}
	}
	return false
}

func sameGarageNodeClusterRef(oldNode, newNode *GarageNode) bool {
	if oldNode == nil || newNode == nil || oldNode.Spec.ClusterRef.Name != newNode.Spec.ClusterRef.Name {
		return false
	}
	oldNamespace := oldNode.Spec.ClusterRef.Namespace
	if oldNamespace == "" {
		oldNamespace = oldNode.Namespace
	}
	newNamespace := newNode.Spec.ClusterRef.Namespace
	if newNamespace == "" {
		newNamespace = newNode.Namespace
	}
	return oldNamespace == newNamespace
}

// validateGarageNodeStorageUpdate keeps a durable Garage identity attached to
// the same Kubernetes volume topology for its lifetime. StatefulSet
// volumeClaimTemplates cannot be reconciled in place, and switching a metadata
// or data source can either replace node_key or detach live blocks. The one
// supported mutation is non-decreasing size on the same operator-created PVC
// (or EmptyDir sizeLimit); the controller expands existing PVCs explicitly.
func validateGarageNodeStorageUpdate(oldNode, newNode *GarageNode) error {
	if oldNode == nil || newNode == nil || oldNode.Spec.External != nil ||
		effectiveNodeBacking(oldNode.Spec.Backing) == NodeBackingNodeLocalPool {
		return nil
	}
	oldStorage, newStorage := oldNode.Spec.Storage, newNode.Spec.Storage
	if (oldStorage == nil) != (newStorage == nil) {
		return fmt.Errorf("storage volume topology is immutable on an existing managed GarageNode; create a distinct replacement identity, synchronize it, then drain and retire this node (automatic cycle is only available for repeatable PVC templates or EmptyDir)")
	}
	if oldStorage == nil {
		return nil
	}
	if err := validateGarageNodeVolumeUpdate("storage.metadata", oldStorage.Metadata, newStorage.Metadata, true); err != nil {
		return err
	}
	if (oldStorage.Data == nil) != (newStorage.Data == nil) || len(oldStorage.DataPaths) != len(newStorage.DataPaths) {
		return fmt.Errorf("storage.data/storage.dataPaths topology is immutable on an existing GarageNode; create a distinct replacement identity with the intended storage, synchronize it, then drain and retire this node")
	}
	if err := validateGarageNodeVolumeUpdate("storage.data", oldStorage.Data, newStorage.Data, true); err != nil {
		return err
	}
	for i := range oldStorage.DataPaths {
		if err := validateGarageNodeVolumeUpdate(
			fmt.Sprintf("storage.dataPaths[%d]", i),
			&oldStorage.DataPaths[i], &newStorage.DataPaths[i],
			false,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateGarageNodeVolumeUpdate(field string, oldVolume, newVolume *NodeVolumeConfig, legacyReadOnlyIgnored bool) error {
	if (oldVolume == nil) != (newVolume == nil) {
		return fmt.Errorf("%s volume source is immutable on an existing GarageNode; create a distinct replacement identity, synchronize it, then drain and retire this node", field)
	}
	if oldVolume == nil {
		return nil
	}
	if err := validateLegacyNodeVolumeIgnoredFieldTransition(field, oldVolume, newVolume); err != nil {
		return err
	}
	legacySourceRepair := legacyReadOnlyOnlyVolume(oldVolume) && nodeVolumeHasRealSource(newVolume)
	oldShape, newShape := *oldVolume, *newVolume
	oldShape.Size = nil
	newShape.Size = nil
	switch {
	case oldVolume.Type == VolumeTypeEmptyDir:
		clearNodeVolumeIgnoredPVCFields(&oldShape, true)
		clearNodeVolumeIgnoredPVCFields(&newShape, true)
	case oldVolume.ExistingClaim != "":
		clearNodeVolumeIgnoredPVCFields(&oldShape, false)
		clearNodeVolumeIgnoredPVCFields(&newShape, false)
	case invalidNodeVolumeSelector(oldVolume.Selector):
		oldShape.Selector = nil
		newShape.Selector = nil
	}
	if legacyReadOnlyIgnored {
		// metadata/data readOnly was never rendered into Garage or Kubernetes.
		// Treat removal of that released-but-ignored bit as a semantic no-op;
		// setting it on a new update already failed validateStorage above.
		oldShape.ReadOnly = false
		newShape.ReadOnly = false
	}
	if legacySourceRepair {
		// A released readOnly-only entry never produced a Kubernetes Volume, so
		// supplying its first real source repairs an impossible workload rather
		// than moving an established Garage identity. Keep path/readOnly semantics
		// immutable while allowing that one source-construction transition.
		oldShape.ExistingClaim = newShape.ExistingClaim
		oldShape.Type = newShape.Type
		oldShape.StorageClassName = newShape.StorageClassName
		oldShape.Selector = newShape.Selector
		oldShape.AccessModes = newShape.AccessModes
		oldShape.Labels = newShape.Labels
		oldShape.Annotations = newShape.Annotations
		oldShape.DataSourceRef = newShape.DataSourceRef
	}
	if !equality.Semantic.DeepEqual(oldShape, newShape) {
		return fmt.Errorf("%s volume source, path, class, access modes, and readOnly state are immutable on an existing GarageNode; only size growth on the same operator-created volume is supported", field)
	}
	if legacySourceRepair {
		return nil
	}
	if equality.Semantic.DeepEqual(oldVolume.Size, newVolume.Size) {
		return nil
	}
	if oldVolume.ExistingClaim != "" {
		return fmt.Errorf("%s.size is immutable for existingClaim %q; the referenced PVC and Garage drive mapping are user-managed", field, oldVolume.ExistingClaim)
	}
	if oldVolume.Size == nil || newVolume.Size == nil || newVolume.Size.Cmp(*oldVolume.Size) < 0 {
		return fmt.Errorf("%s.size may only grow on an existing managed volume", field)
	}
	return nil
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateDelete(ctx context.Context, obj *GarageNode) (admission.Warnings, error) {
	if obj == nil {
		return nil, nil
	}
	garagenodelog.Info("validate delete", "name", obj.Name)
	if v.apiReader == nil || obj.Spec.ClusterRef.Name == "" {
		return nil, nil
	}
	clusterNamespace := obj.Namespace
	if obj.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = obj.Spec.ClusterRef.Namespace
	}
	cluster := &v1beta2.GarageCluster{}
	if err := v.apiReader.Get(ctx, types.NamespacedName{
		Name: obj.Spec.ClusterRef.Name, Namespace: clusterNamespace,
	}, cluster); err != nil {
		if client.IgnoreNotFound(err) == nil && !obj.Spec.Gateway {
			return nil, fmt.Errorf("positive-capacity GarageNode cannot be deleted while its parent GarageCluster is absent; restore the parent or complete documented manual recovery")
		}
		return nil, client.IgnoreNotFound(err)
	}
	layoutOwner, err := v.resolveGarageNodeLayoutOwner(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("resolving canonical Garage layout owner before GarageNode deletion: %w", err)
	}
	if v1beta2StorageRolloutActive(layoutOwner) {
		uid := "an unknown previous pod UID"
		if layoutOwner.Status.StorageRollout != nil {
			uid = layoutOwner.Status.StorageRollout.PreviousPodUID
		}
		return nil, fmt.Errorf(
			"garageNode %s cannot be deleted while GarageCluster %s/%s is replacing managed pod UID %s; wait for status.storageRollout to clear",
			obj.Name, layoutOwner.Namespace, layoutOwner.Name, uid,
		)
	}
	preparedWithoutLayout := garageNodeDeletePreparedWithoutLayout(obj)
	if drain := layoutOwner.Status.StorageDrain; drain != nil {
		if v1beta2StorageDrainActorMatchesNode(drain, obj) {
			nodeID, resolveErr := obj.ResolvedGarageNodeID()
			if resolveErr != nil || nodeID == "" {
				return nil, fmt.Errorf("garageNode %s terminal drain has no trusted exact identity: %v", obj.Name, resolveErr)
			}
			if obj.Spec.Gateway {
				if drain.CompletedAt == nil {
					return nil, fmt.Errorf("gateway GarageNode %s role retirement is still converging; wait for its terminal handoff before deleting it", obj.Name)
				}
				if len(drain.RemovedStorageNodeIDs) != 0 {
					return nil, fmt.Errorf("gateway GarageNode %s role-retirement proof unexpectedly contains positive-capacity targets", obj.Name)
				}
				if err := storagecontract.ValidateTerminal(
					v1beta2StorageDrainTerminalToken(drain),
					storagecontract.Actor{
						APIVersion: GroupVersion.String(), Kind: garageNodeKind,
						Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID),
					},
					[]string{nodeID}, nil,
				); err != nil {
					return nil, fmt.Errorf("gateway GarageNode %s terminal role retirement is invalid: %w", obj.Name, err)
				}
			} else {
				if obj.Annotations[AnnotationDrain] != stringTrue {
					return nil, fmt.Errorf(
						"garageNode %s drain is not prepared for deletion: set %s=\"true\" and wait for ConditionDrainPrepared=True before deleting it",
						obj.Name, AnnotationDrain,
					)
				}
				if err := storagecontract.ValidateTerminal(
					v1beta2StorageDrainTerminalToken(drain),
					storagecontract.Actor{
						APIVersion: GroupVersion.String(), Kind: garageNodeKind,
						Namespace: obj.Namespace, Name: obj.Name, UID: string(obj.UID),
					},
					[]string{nodeID},
					[]string{nodeID},
				); err != nil {
					return nil, fmt.Errorf("garageNode %s terminal drain preparation is invalid: %w", obj.Name, err)
				}
				if v1beta2StorageDrainUnavailableIncludesNode(drain, obj) {
					if canonicalGarageNodeID(obj.Annotations[AnnotationAcknowledgeLostSource]) != nodeID {
						return nil, fmt.Errorf("garageNode %s unavailable-source drain is missing the exact immutable lost-source acknowledgement", obj.Name)
					}
				} else if obj.Spec.External == nil && strings.TrimSpace(drain.ManagedPodUIDs[nodeID]) == "" {
					return nil, fmt.Errorf("garageNode %s terminal drain proof has no exact managed source Pod UID", obj.Name)
				}
			}
		} else if drain.Actor.Kind == garageClusterKind && drain.Actor.UID == string(layoutOwner.UID) && drain.CompletedAt != nil {
			// Parent deletion already proved every local role and now owns cleanup.
			if err := storagecontract.ValidateTerminal(
				v1beta2StorageDrainTerminalToken(drain),
				storagecontract.Actor{
					APIVersion: v1beta2.GroupVersion.String(), Kind: garageClusterKind,
					Namespace: layoutOwner.Namespace, Name: layoutOwner.Name, UID: string(layoutOwner.UID),
				},
				nil,
				nil,
			); err != nil {
				return nil, fmt.Errorf("parent GarageCluster terminal drain preparation is invalid: %w", err)
			}
			return nil, nil
		} else {
			return nil, fmt.Errorf("garageNode %s cannot be deleted while storage-drain transaction %q is owned by %s %s/%s", obj.Name, drain.TransactionID, drain.Actor.Kind, drain.Actor.Namespace, drain.Actor.Name)
		}
	}
	if obj.Spec.Gateway && obj.Spec.External == nil && cluster.DeletionTimestamp.IsZero() {
		if foreground, err := v1beta1DeleteUsesForeground(ctx); err != nil {
			return nil, err
		} else if foreground {
			return nil, fmt.Errorf("foreground propagation is unsafe for a managed gateway GarageNode because Kubernetes may delete its StatefulSet/pod before metadata layout convergence; use background/default propagation")
		}
	}
	if !obj.Spec.Gateway {
		if cluster.HasStorageTier() && cluster.UID == layoutOwner.UID &&
			!cluster.DeletionTimestamp.IsZero() && cluster.EffectiveDeletionPolicy() == v1beta2.DeletionPolicyDestroy {
			return nil, nil
		}
		if preparedWithoutLayout {
			if foreground, err := v1beta1DeleteUsesForeground(ctx); err != nil {
				return nil, err
			} else if foreground {
				return nil, fmt.Errorf("foreground propagation is unsafe for a prepared GarageNode because dependents may be removed before its finalizer handoff; use background/default propagation")
			}
			return nil, nil
		}
		drain := layoutOwner.Status.StorageDrain
		if drain == nil || !v1beta2StorageDrainActorMatchesNode(drain, obj) || drain.CompletedAt == nil ||
			obj.Annotations[AnnotationDrain] != stringTrue || !v1beta2StorageDrainIncludesNode(drain, obj) {
			return nil, fmt.Errorf(
				"positive-capacity GarageNode deletion is a prepared operation: set annotation %s=\"true\", keep the process live, and wait for ConditionDrainPrepared=True",
				AnnotationDrain,
			)
		}
		if v1beta2StorageDrainUnavailableIncludesNode(drain, obj) {
			if err := v.validateManagedLostSourcePodAbsent(ctx, obj); err != nil {
				return nil, err
			}
		}
		if foreground, err := v1beta1DeleteUsesForeground(ctx); err != nil {
			return nil, err
		} else if foreground {
			return nil, fmt.Errorf("foreground propagation is unsafe for a positive-capacity GarageNode because Kubernetes may delete its StatefulSet/pod before block migration is proved; use background/default propagation")
		}
		if err := v1beta2GarageNodeDrainReadiness(layoutOwner); err != nil {
			return nil, err
		}
		hasUnverifiedPeers := obj.Spec.External != nil || len(layoutOwner.Spec.RemoteClusters) > 0
		if !hasUnverifiedPeers {
			var err error
			hasUnverifiedPeers, err = v.clusterHasExternalGarageNodes(ctx, layoutOwner)
			if err != nil {
				return nil, err
			}
		}
		if hasUnverifiedPeers &&
			v1beta2GarageNodeDrainPeerPolicy(layoutOwner) != v1beta2.StorageDrainUnverifiedPeersAssumeConsistent {
			return nil, fmt.Errorf("deleting storage while the parent has external or federated Garage processes requires spec.layoutManagement.drain.unverifiedPeersPolicy: AssumeConsistent")
		}
	}
	return nil, nil
}

func (v *GarageNodeValidator) validateManagedLostSourcePodAbsent(ctx context.Context, node *GarageNode) error {
	if v == nil || v.apiReader == nil || node == nil || node.Spec.External != nil {
		return nil
	}
	if effectiveNodeBacking(node.Spec.Backing) == NodeBackingNodeLocalPool {
		pods := &corev1.PodList{}
		if err := v.apiReader.List(ctx, pods,
			client.InNamespace(node.Namespace),
			client.MatchingLabels(map[string]string{
				"garage.rajsingh.info/cluster":         node.Spec.ClusterRef.Name,
				"garage.rajsingh.info/tier":            "storage",
				"garage.rajsingh.info/node-local-pool": node.Spec.NodeLocalPoolName,
			}),
		); err != nil {
			return fmt.Errorf("listing managed node-local-pool Pods before lost-source deletion: %w", err)
		}
		for i := range pods.Items {
			if pods.Items[i].Spec.NodeName == node.Spec.KubernetesNodeName {
				return fmt.Errorf("garageNode %s acknowledged a lost source but its managed node-local-pool Pod still exists; stop or remove that workload before deletion", node.Name)
			}
		}
		return nil
	}
	pod := &corev1.Pod{}
	err := v.apiReader.Get(ctx, types.NamespacedName{Namespace: node.Namespace, Name: node.Name + "-0"}, pod)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking managed GarageNode Pod before lost-source deletion: %w", err)
	}
	return fmt.Errorf("garageNode %s acknowledged a lost source but managed Pod %s still exists; stop or remove that workload before deletion", node.Name, pod.Name)
}

func garageNodeDeletePreparedWithoutLayout(node *GarageNode) bool {
	if node == nil || node.Annotations[AnnotationDrain] != stringTrue {
		return false
	}
	// This shortcut is valid only for a GarageNode that never acquired a
	// durable identity. Any known ID may already have a committed role that was
	// momentarily absent from one asynchronously updated Admin endpoint.
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil || nodeID != "" {
		return false
	}
	for i := range node.Status.Conditions {
		condition := &node.Status.Conditions[i]
		if condition.Type == ConditionDrainPrepared && condition.Status == metav1.ConditionTrue &&
			condition.Reason == ReasonNodeDrainPreparedNotInLayout &&
			condition.ObservedGeneration == node.Generation {
			return true
		}
	}
	return false
}

func (v *GarageNodeValidator) clusterHasExternalGarageNodes(
	ctx context.Context,
	cluster *v1beta2.GarageCluster,
) (bool, error) {
	nodes := &GarageNodeList{}
	if err := v.apiReader.List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return false, fmt.Errorf("listing GarageNodes before storage deletion: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		clusterNamespace := node.Namespace
		if node.Spec.ClusterRef.Namespace != "" {
			clusterNamespace = node.Spec.ClusterRef.Namespace
		}
		if node.Spec.ClusterRef.Name == cluster.Name && clusterNamespace == cluster.Namespace &&
			node.Spec.External != nil {
			return true, nil
		}
	}
	return false, nil
}

// validateParentStorageRollout prevents a new process/layout actor from
// appearing after the parent has persisted the exact member handoff it is
// recovering. The controller also fails closed if admission is bypassed.
func (v *GarageNodeValidator) validateParentStorageRollout(
	ctx context.Context,
	obj *GarageNode,
	action string,
) error {
	if v.apiReader == nil || obj == nil || obj.Spec.ClusterRef.Name == "" {
		return nil
	}
	clusterNamespace := obj.Namespace
	if obj.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = obj.Spec.ClusterRef.Namespace
	}
	cluster := &v1beta2.GarageCluster{}
	if err := v.apiReader.Get(ctx, types.NamespacedName{
		Name: obj.Spec.ClusterRef.Name, Namespace: clusterNamespace,
	}, cluster); err != nil {
		return client.IgnoreNotFound(err)
	}
	layoutOwner, err := v.resolveGarageNodeLayoutOwner(ctx, cluster)
	if err != nil {
		return fmt.Errorf("resolving canonical Garage layout owner before GarageNode creation: %w", err)
	}
	if !v1beta2StorageRolloutActive(layoutOwner) {
		if layoutOwner.Status.StorageDrain == nil {
			return nil
		}
		return fmt.Errorf(
			"garageNode %s cannot be %s while GarageCluster %s/%s has storage-drain transaction %q active",
			obj.Name, action, layoutOwner.Namespace, layoutOwner.Name, layoutOwner.Status.StorageDrain.TransactionID,
		)
	}
	uid := "an unknown previous pod UID"
	if layoutOwner.Status.StorageRollout != nil {
		uid = layoutOwner.Status.StorageRollout.PreviousPodUID
	}
	return fmt.Errorf(
		"garageNode %s cannot be %s while GarageCluster %s/%s is replacing managed pod UID %s; wait for status.storageRollout to clear",
		obj.Name, action, layoutOwner.Namespace, layoutOwner.Name, uid,
	)
}

// resolveGarageNodeLayoutOwner follows an edge/management clusterRef chain to
// the object that owns durable layout rollout and drain status. Admission must
// use the same owner as reconciliation or a prepared delete can be rejected by
// an intermediate handle while an unprepared mutation bypasses the real lock.
func (v *GarageNodeValidator) resolveGarageNodeLayoutOwner(
	ctx context.Context,
	cluster *v1beta2.GarageCluster,
) (*v1beta2.GarageCluster, error) {
	if cluster == nil {
		return nil, fmt.Errorf("garageCluster is nil")
	}
	current := cluster
	visited := make(map[types.NamespacedName]struct{})
	for {
		key := types.NamespacedName{Namespace: current.Namespace, Name: current.Name}
		if _, seen := visited[key]; seen {
			return nil, fmt.Errorf("cyclic GarageCluster connectTo.clusterRef chain at %s", key.String())
		}
		visited[key] = struct{}{}
		if current.HasStorageTier() || current.Spec.ConnectTo == nil ||
			(current.IsManagementHandle() && current.Spec.ConnectTo.AdminAPIEndpoint != "") ||
			current.Spec.ConnectTo.ClusterRef == nil {
			return current, nil
		}
		if v.apiReader == nil {
			return nil, fmt.Errorf("kubernetes API reader is required to resolve GarageCluster connectTo.clusterRef")
		}
		ref := current.Spec.ConnectTo.ClusterRef
		nextKey := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
		if nextKey.Namespace == "" {
			nextKey.Namespace = current.Namespace
		}
		next := &v1beta2.GarageCluster{}
		if err := v.apiReader.Get(ctx, nextKey, next); err != nil {
			return nil, fmt.Errorf("reading Garage layout owner %s: %w", nextKey.String(), err)
		}
		current = next
	}
}

func v1beta2StorageRolloutActive(cluster *v1beta2.GarageCluster) bool {
	if cluster == nil {
		return false
	}
	if cluster.Status.StorageRollout != nil {
		return true
	}
	for i := range cluster.Status.Conditions {
		condition := &cluster.Status.Conditions[i]
		if condition.Type == ConditionStorageRolloutReady &&
			condition.Status == metav1.ConditionFalse &&
			condition.Reason == ReasonStorageRollingOut {
			return true
		}
	}
	return false
}

func v1beta2StorageDrainActorMatchesNode(
	drain *v1beta2.StorageDrainStatus,
	node *GarageNode,
) bool {
	return drain != nil && node != nil && node.UID != "" &&
		drain.Actor.APIVersion == GroupVersion.String() && drain.Actor.Kind == garageNodeKind &&
		drain.Actor.Namespace == node.Namespace && drain.Actor.Name == node.Name &&
		drain.Actor.UID == string(node.UID)
}

func v1beta2StorageDrainIncludesNode(
	drain *v1beta2.StorageDrainStatus,
	node *GarageNode,
) bool {
	if drain == nil || node == nil {
		return false
	}
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil || nodeID == "" {
		return false
	}
	for _, removedNodeID := range drain.RemovedStorageNodeIDs {
		if canonicalGarageNodeID(removedNodeID) == nodeID {
			return true
		}
	}
	return false
}

func v1beta2StorageDrainUnavailableIncludesNode(
	drain *v1beta2.StorageDrainStatus,
	node *GarageNode,
) bool {
	if drain == nil || node == nil {
		return false
	}
	nodeID, err := node.ResolvedGarageNodeID()
	if err != nil {
		return false
	}
	for _, unavailableNodeID := range drain.UnavailableSourceNodeIDs {
		if canonicalGarageNodeID(unavailableNodeID) == nodeID && nodeID != "" {
			return true
		}
	}
	return false
}

func v1beta2StorageDrainTerminalToken(drain *v1beta2.StorageDrainStatus) *storagecontract.TerminalToken {
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

func v1beta2GarageNodeDrainPeerPolicy(cluster *v1beta2.GarageCluster) v1beta2.StorageDrainUnverifiedPeersPolicy {
	if cluster == nil || cluster.Spec.LayoutManagement == nil || cluster.Spec.LayoutManagement.Drain == nil ||
		cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy == "" {
		return v1beta2.StorageDrainUnverifiedPeersBlock
	}
	return cluster.Spec.LayoutManagement.Drain.UnverifiedPeersPolicy
}

func v1beta2GarageNodeDrainReadiness(cluster *v1beta2.GarageCluster) error {
	if cluster == nil {
		return fmt.Errorf("positive-capacity GarageNode deletion requires a canonical GarageCluster")
	}
	if cluster.IsManagementHandle() {
		for i := range cluster.Status.Conditions {
			condition := &cluster.Status.Conditions[i]
			if condition.Type == ConditionManagementHandleReady && condition.Status == metav1.ConditionTrue &&
				condition.ObservedGeneration == cluster.Generation {
				return nil
			}
		}
		return fmt.Errorf("positive-capacity GarageNode deletion through a management handle requires ManagementHandleReady=True at generation %d", cluster.Generation)
	}
	if cluster.Status.FactorMigration != nil {
		return fmt.Errorf("positive-capacity GarageNode deletion cannot start while parent status.factorMigration is active")
	}
	mode := consistencyModeConsistent
	if cluster.Spec.Replication != nil && cluster.Spec.Replication.ConsistencyMode != "" {
		mode = strings.ToLower(cluster.Spec.Replication.ConsistencyMode)
	}
	if mode != consistencyModeConsistent {
		return fmt.Errorf("positive-capacity GarageNode deletion requires parent spec.replication.consistencyMode: consistent before deletion starts")
	}
	if cluster.Status.StorageRollout != nil {
		return fmt.Errorf("positive-capacity GarageNode deletion cannot start while parent status.storageRollout is active")
	}
	var rollout *metav1.Condition
	for i := range cluster.Status.Conditions {
		if cluster.Status.Conditions[i].Type == ConditionStorageRolloutReady {
			rollout = &cluster.Status.Conditions[i]
			break
		}
	}
	if rollout == nil || rollout.Status != metav1.ConditionTrue || rollout.ObservedGeneration != cluster.Generation {
		return fmt.Errorf("positive-capacity GarageNode deletion requires parent StorageRolloutReady=True at generation %d", cluster.Generation)
	}
	health := cluster.Status.Health
	if health == nil || health.Status != healthStatusHealthy || !health.Healthy || !health.Available ||
		health.StorageNodes == 0 || health.StorageNodesOK != health.StorageNodes || health.Partitions == 0 ||
		health.PartitionsQuorum != health.Partitions || health.PartitionsAllOK != health.Partitions {
		return fmt.Errorf("positive-capacity GarageNode deletion requires parent Garage health to show every storage node up and every partition fully replicated; the controller rechecks live health immediately before Apply")
	}
	return nil
}

// validateNodeLocalPoolControllerOwner makes "internal child" an enforceable live
// API invariant. Kubernetes accepts syntactically valid owner references whose
// UID does not identify a real object, so the structural check alone would let
// a user forge a node-local-pool-backed GarageNode that points at an operator pool.
func (v *GarageNodeValidator) validateNodeLocalPoolControllerOwner(
	ctx context.Context,
	node *GarageNode,
	requireDeclaredPool bool,
) error {
	if v.apiReader == nil || node == nil || effectiveNodeBacking(node.Spec.Backing) != NodeBackingNodeLocalPool {
		return nil
	}
	// A GarageCluster can disappear before garbage collection finishes a child.
	// DeletionTimestamp is immutable, so allowing updates to an already-deleting
	// child cannot resurrect it or introduce a new active role. Skipping the live
	// lookup here prevents a missing or same-name-recreated parent from wedging
	// the child's finalizer forever.
	if !requireDeclaredPool && !node.DeletionTimestamp.IsZero() {
		return nil
	}
	owner := metav1.GetControllerOf(node)
	if owner == nil {
		// validateGarageNode reports the more specific structural error first.
		return nil
	}
	cluster := &v1beta2.GarageCluster{}
	if err := v.apiReader.Get(ctx, types.NamespacedName{
		Name:      node.Spec.ClusterRef.Name,
		Namespace: node.Namespace,
	}, cluster); err != nil {
		return fmt.Errorf("verifying node-local-pool-backed GarageNode parent: %w", err)
	}
	if owner.UID == "" || owner.UID != cluster.UID {
		return fmt.Errorf(
			"node-local-pool-backed GarageNode controller owner UID does not match GarageCluster %s/%s",
			cluster.Namespace,
			cluster.Name,
		)
	}
	if !requireDeclaredPool {
		return nil
	}
	if cluster.Spec.Storage != nil {
		for i := range cluster.Spec.Storage.NodeLocalPools {
			if cluster.Spec.Storage.NodeLocalPools[i].Name == node.Spec.NodeLocalPoolName {
				return nil
			}
		}
	}
	return fmt.Errorf(
		"nodeLocalPoolName %q is not declared by GarageCluster %s/%s",
		node.Spec.NodeLocalPoolName,
		cluster.Namespace,
		cluster.Name,
	)
}

// validateGarageNode validates the GarageNode spec.
func (r *GarageNode) validateGarageNode(allowUnchangedLegacy ...bool) (admission.Warnings, error) {
	var warnings admission.Warnings
	allowLegacy := len(allowUnchangedLegacy) > 0 && allowUnchangedLegacy[0]
	if r.Spec.External != nil && r.Spec.External.RemoteClusterRef != nil {
		return warnings, fmt.Errorf("external.remoteClusterRef is not supported")
	}
	if err := ValidateSupportedPublicEndpoint(r.Spec.PublicEndpoint, "spec.publicEndpoint"); err != nil {
		return warnings, err
	}
	if r.Spec.Backing != "" && r.Spec.Backing != NodeBackingStatefulSet && r.Spec.Backing != NodeBackingNodeLocalPool {
		return warnings, fmt.Errorf("backing must be StatefulSet or NodeLocalPool, got %q", r.Spec.Backing)
	}
	if err := validateManagedGarageNodeName(r); err != nil {
		return warnings, err
	}
	if value, requested := r.Annotations[AnnotationDrain]; requested {
		if value != stringTrue {
			return warnings, fmt.Errorf("annotation %s must be \"true\" when present", AnnotationDrain)
		}
		if r.Spec.Gateway {
			return warnings, fmt.Errorf("annotation %s is only valid on positive-capacity storage GarageNodes", AnnotationDrain)
		}
	}
	if value, requested := r.Annotations[AnnotationCycle]; requested {
		if value != stringTrue {
			return warnings, fmt.Errorf("annotation %s must be \"true\" when present", AnnotationCycle)
		}
		if r.Spec.Backing == NodeBackingNodeLocalPool {
			return warnings, fmt.Errorf("annotation %s is not valid on an operator-generated node-local-pool member; change the parent nodeLocalPools membership through its serialized retirement workflow", AnnotationCycle)
		}
		if r.Spec.External != nil {
			return warnings, fmt.Errorf("annotation %s is not valid on an externally managed Garage process because the operator cannot provision its replacement", AnnotationCycle)
		}
	}
	if lostNodeID, requested := r.Annotations[AnnotationAcknowledgeLostSource]; requested {
		if r.Annotations[AnnotationDrain] != stringTrue {
			return warnings, fmt.Errorf("annotation %s requires %s=\"true\"", AnnotationAcknowledgeLostSource, AnnotationDrain)
		}
		if r.Spec.Gateway {
			return warnings, fmt.Errorf("annotation %s is only valid for a positive-capacity storage GarageNode", AnnotationAcknowledgeLostSource)
		}
		if err := validateNodeID(lostNodeID); err != nil {
			return warnings, fmt.Errorf("annotation %s must contain the exact lost Garage node ID: %w", AnnotationAcknowledgeLostSource, err)
		}
		warnings = append(warnings, "acknowledge-lost-source cannot recover blocks whose only copy was on the unavailable process; use it only when this exact identity is permanently down, then remove its role through Garage dead-node recovery and independently verify the surviving data")
	}
	if recoveryNodeID, requested := r.Annotations[AnnotationNodeLocalPoolRecoveryNodeID]; requested {
		if r.Spec.Backing != NodeBackingNodeLocalPool {
			return warnings, fmt.Errorf("annotation %s is only valid on an internal node-local-pool-backed GarageNode", AnnotationNodeLocalPoolRecoveryNodeID)
		}
		if err := validateNodeID(strings.TrimSpace(recoveryNodeID)); err != nil {
			return warnings, fmt.Errorf("annotation %s must contain the exact retained HostPath Garage node ID: %w", AnnotationNodeLocalPoolRecoveryNodeID, err)
		}
	}
	if err := validateGarageEnvironment(r.Spec.Env, r.Spec.EnvFrom, "spec"); err != nil {
		return warnings, err
	}
	if err := workloadidentity.ValidatePodLabels(r.Spec.PodLabels, "spec.podLabels"); err != nil {
		return warnings, err
	}

	if r.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
	}
	if !allowLegacy {
		if err := ValidateClusterReference(r.Spec.ClusterRef, "clusterRef"); err != nil {
			return warnings, err
		}
	}

	// GarageNode does not support cross-namespace cluster references.
	// Node management is an admin-only operation scoped to the cluster's namespace.
	if r.Spec.ClusterRef.Namespace != "" && r.Spec.ClusterRef.Namespace != r.Namespace {
		return warnings, fmt.Errorf(
			"clusterRef.namespace is not permitted on GarageNode: node management requires a same-namespace cluster reference",
		)
	}

	if r.Spec.Zone == "" {
		return warnings, fmt.Errorf("zone is required")
	}
	if err := r.validateLayoutTags(); err != nil {
		return warnings, err
	}

	if r.Spec.ZoneFrom != nil {
		if err := validateNodeLabelKey(r.Spec.ZoneFrom.NodeLabel); err != nil {
			return warnings, fmt.Errorf("zoneFrom.nodeLabel: %w", err)
		}
		// No pod means no Kubernetes Node to read a label from.
		if r.Spec.External != nil {
			return warnings, fmt.Errorf("zoneFrom is not valid on external nodes: there is no pod to resolve a Kubernetes Node from (set zone directly)")
		}
		// A gateway carries a zone in its layout role, and upstream counts it
		// toward ZoneRedundancy::Maximum while requiring that many zones among
		// storage nodes only — so a per-node gateway zone can make every layout
		// apply fail. See buildAutoModeGatewayNode in the controller.
		if r.Spec.Gateway {
			warnings = append(warnings,
				"zoneFrom on a gateway node can break layout apply under replication.zoneRedundancyMode: Maximum — "+
					"Garage counts gateway zones toward the redundancy target but satisfies it from storage nodes only")
		}
	}

	if !r.Spec.Gateway && r.Spec.Capacity == nil {
		return warnings, fmt.Errorf("capacity is required for storage nodes (set gateway: true for gateway-only nodes)")
	}

	if r.Spec.Gateway && r.Spec.Capacity != nil {
		warnings = append(warnings, "capacity is set but will be ignored for gateway nodes")
	}

	if r.Spec.NodeID != "" {
		if err := validateNodeID(r.Spec.NodeID); err != nil {
			return warnings, err
		}
		if r.Spec.External == nil && r.Spec.Backing != NodeBackingNodeLocalPool {
			warnings = append(warnings, "spec.nodeId on a managed GarageNode is an expected identity pin; reconciliation waits for the exact owned Pod to report the same ID before mutating layout or status")
		}
	}

	if r.Spec.Backing == NodeBackingNodeLocalPool {
		if err := r.validateNodeLocalPoolBackedNode(); err != nil {
			return warnings, err
		}
	} else if r.Spec.External != nil {
		if r.Spec.KubernetesNodeName != "" {
			return warnings, fmt.Errorf("kubernetesNodeName is only valid when backing is NodeLocalPool")
		}
		if r.Spec.NodeLocalPoolName != "" {
			return warnings, fmt.Errorf("nodeLocalPoolName is only valid when backing is NodeLocalPool")
		}
		if err := r.validateExternalNode(); err != nil {
			return warnings, err
		}
		if r.Spec.Storage != nil {
			return warnings, fmt.Errorf("storage cannot be specified for external nodes")
		}
	} else {
		if r.Spec.KubernetesNodeName != "" {
			return warnings, fmt.Errorf("kubernetesNodeName is only valid when backing is NodeLocalPool")
		}
		if r.Spec.NodeLocalPoolName != "" {
			return warnings, fmt.Errorf("nodeLocalPoolName is only valid when backing is NodeLocalPool")
		}
		if r.Spec.Storage == nil {
			return warnings, fmt.Errorf("storage is required for managed nodes (use external for externally-managed nodes)")
		}
		if err := r.validateStorage(); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}

func validateManagedGarageNodeName(node *GarageNode) error {
	if node == nil || node.Name == "" {
		return nil
	}
	nameLimit := 63
	if node.Spec.External == nil && effectiveNodeBacking(node.Spec.Backing) == NodeBackingStatefulSet {
		nameLimit = maxManagedGarageNodeNameLength
	}
	if len(node.Name) > nameLimit {
		return fmt.Errorf("metadata.name: maximum %d characters for this GarageNode backing", nameLimit)
	}
	return nil
}

func validateManagedGarageNodeNameUpdate(oldNode, newNode *GarageNode) (bool, error) {
	newErr := validateManagedGarageNodeName(newNode)
	if newErr == nil {
		return false, nil
	}
	if oldNode == nil || validateManagedGarageNodeName(oldNode) == nil {
		return false, fmt.Errorf("update introduces an invalid managed workload name: %w", newErr)
	}
	if newNode != nil && !newNode.DeletionTimestamp.IsZero() {
		return true, nil
	}
	if newNode != nil && (newNode.Spec.External != nil || effectiveNodeBacking(newNode.Spec.Backing) == NodeBackingNodeLocalPool) {
		return true, nil
	}
	if oldNode != nil && newNode != nil && equality.Semantic.DeepEqual(oldNode.Spec, newNode.Spec) {
		return true, nil
	}
	return false, fmt.Errorf("metadata.name cannot produce a valid <name>-0 StatefulSet Pod label; metadata/finalizer and drain-recovery updates may proceed, but workload-rendering spec changes require a shorter replacement GarageNode identity")
}

// validateLayoutTags permits only the canonical operator values that appear on
// generated GarageNodes. User tags cannot forge site ownership, tier, node-local-pool
// membership, or an RPC address: those values are derived again by the
// controller from the parent UID and typed spec fields before layout staging.
func (r *GarageNode) validateLayoutTags() error {
	clusterNamespace := r.Namespace
	if r.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = r.Spec.ClusterRef.Namespace
	}
	tier := "storage"
	if r.Spec.Gateway {
		tier = gatewayValue
	}
	allowed := map[string]string{
		"cluster:": fmt.Sprintf("cluster:%s/%s", r.Spec.ClusterRef.Name, clusterNamespace),
		"tier:":    "tier:" + tier,
	}
	if r.Spec.Backing == NodeBackingNodeLocalPool {
		allowed["node-local-pool:"] = "node-local-pool:" + r.Spec.NodeLocalPoolName
		allowed["kubernetes-node:"] = "kubernetes-node:" + r.Spec.KubernetesNodeName
	}
	for i, tag := range r.Spec.Tags {
		for _, prefix := range operatorReservedLayoutTagPrefixes {
			if !strings.HasPrefix(tag, prefix) {
				continue
			}
			if expected, ok := allowed[prefix]; ok && tag == expected {
				break
			}
			return fmt.Errorf(
				"tags[%d] %q uses operator-managed prefix %q; use clusterRef, gateway, backing/nodeLocalPoolName/kubernetesNodeName, or network.rpcPublicAddr instead",
				i, tag, prefix,
			)
		}
	}
	return nil
}

// validateNodeLocalPoolBackedNode validates a GarageNode whose pod comes from a
// cluster-owned node-local-pool workload (spec.backing: NodeLocalPool) rather than a
// per-node StatefulSet this GarageNode would otherwise own. It owns no
// StatefulSet, ConfigMap, Service, or PVCs — only the Garage layout role for
// the Kubernetes node named in kubernetesNodeName — so storage/external
// configuration (which describe workloads this mode doesn't create) is
// rejected, and DaemonSet storage is a storage-tier-only concept (gateways
// keep their existing StatefulSet-backed path).
func (r *GarageNode) validateNodeLocalPoolBackedNode() error {
	owner := metav1.GetControllerOf(r)
	if !isGarageClusterControllerOwner(owner, r.Spec.ClusterRef.Name) {
		return fmt.Errorf(
			"node-local-pool-backed GarageNodes are internal children and require a GarageCluster controller owner matching clusterRef.name",
		)
	}
	if r.Spec.KubernetesNodeName == "" {
		return fmt.Errorf("kubernetesNodeName is required when backing is NodeLocalPool")
	}
	if r.Spec.NodeLocalPoolName == "" {
		return fmt.Errorf("nodeLocalPoolName is required when backing is NodeLocalPool")
	}
	if r.Spec.NodeID != "" {
		return fmt.Errorf("nodeId cannot be specified when backing is NodeLocalPool; the operator must discover the exact HostPath process identity")
	}
	if r.Spec.External != nil {
		return fmt.Errorf("external cannot be specified when backing is NodeLocalPool")
	}
	if r.Spec.Storage != nil {
		return fmt.Errorf("storage cannot be specified when backing is NodeLocalPool (the cluster-owned workload provides hostPath volumes)")
	}
	if r.Spec.Gateway {
		return fmt.Errorf("gateway cannot be true when backing is NodeLocalPool (node-local pools are storage-tier-only)")
	}
	if r.Spec.PublicEndpoint != nil {
		return fmt.Errorf("publicEndpoint cannot be specified when backing is NodeLocalPool (expose a pool pod with an external Service selecting garage.rajsingh.info/kubernetes-node)")
	}
	if r.Spec.Network != nil && r.Spec.Network.RPCPublicAddr == "" {
		return fmt.Errorf("network.rpcPublicAddr must be set when network is present on a node-local-pool-backed node")
	}
	if r.Spec.Logging != nil {
		return fmt.Errorf("logging cannot be specified when backing is NodeLocalPool; configure spec.logging on the parent GarageCluster because pool workloads use a uniform parent-owned immutable config revision")
	}
	return nil
}

// validateNodeLabelKey checks that a string is usable as a Kubernetes label
// key, so a typo surfaces at admission instead of as a silent fallback to
// spec.zone hours later.
func validateNodeLabelKey(key string) error {
	if key == "" {
		return fmt.Errorf("must not be empty")
	}
	if errs := validation.IsQualifiedName(key); len(errs) > 0 {
		return fmt.Errorf("%q is not a valid label key: %s", key, strings.Join(errs, "; "))
	}
	return nil
}

func effectiveNodeBacking(backing NodeBacking) NodeBacking {
	if backing == "" {
		return NodeBackingStatefulSet
	}
	return backing
}

func validateNodeID(nodeID string) error {
	nodeIDPattern := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if !nodeIDPattern.MatchString(nodeID) {
		return fmt.Errorf("nodeId must be a 64-character hex string (Ed25519 public key)")
	}
	return nil
}

func canonicalGarageNodeID(nodeID string) string {
	return CanonicalGarageNodeID(nodeID)
}

// CanonicalGarageNodeID matches the representation returned by Garage's Admin
// API for its Ed25519 public-key node identity.
func CanonicalGarageNodeID(nodeID string) string {
	return strings.ToLower(strings.TrimSpace(nodeID))
}

// ResolvedGarageNodeID returns the durable identity known for this object. A
// retained-HostPath recovery pin is eligible only on an exact operator-owned
// node-local-pool child; treating that internal annotation as a general user
// identity source would weaken the controller-owner admission boundary.
func (r *GarageNode) ResolvedGarageNodeID() (string, error) {
	if r == nil {
		return "", nil
	}
	if nodeID := CanonicalGarageNodeID(r.Status.NodeID); nodeID != "" {
		return nodeID, nil
	}
	if nodeID := CanonicalGarageNodeID(r.Spec.NodeID); nodeID != "" {
		return nodeID, nil
	}
	return r.TrustedNodeLocalPoolRecoveryNodeID()
}

// TrustedNodeLocalPoolRecoveryNodeID validates and returns the internal
// retained-HostPath identity pin independently of status/spec precedence.
func (r *GarageNode) TrustedNodeLocalPoolRecoveryNodeID() (string, error) {
	if r == nil {
		return "", nil
	}
	recoveryNodeID := CanonicalGarageNodeID(r.Annotations[AnnotationNodeLocalPoolRecoveryNodeID])
	if recoveryNodeID == "" {
		return "", nil
	}
	owner := metav1.GetControllerOf(r)
	if effectiveNodeBacking(r.Spec.Backing) != NodeBackingNodeLocalPool ||
		!isGarageClusterControllerOwner(owner, r.Spec.ClusterRef.Name) || owner.UID == "" {
		return "", fmt.Errorf("annotation %s is not a trusted identity source on this GarageNode", AnnotationNodeLocalPoolRecoveryNodeID)
	}
	if err := validateNodeID(recoveryNodeID); err != nil {
		return "", fmt.Errorf("annotation %s contains an invalid recovery identity: %w", AnnotationNodeLocalPoolRecoveryNodeID, err)
	}
	return recoveryNodeID, nil
}

func isGarageClusterControllerOwner(owner *metav1.OwnerReference, clusterName string) bool {
	if owner == nil || owner.Kind != garageClusterKind || owner.Name != clusterName {
		return false
	}
	groupVersion, err := schema.ParseGroupVersion(owner.APIVersion)
	return err == nil && groupVersion.Group == GroupVersion.Group && groupVersion.Version != ""
}

func (r *GarageNode) validateExternalNode() error {
	ext := r.Spec.External
	if strings.TrimSpace(r.Spec.NodeID) == "" {
		return fmt.Errorf("nodeId is required for external nodes because the operator cannot discover an externally managed process identity")
	}

	if ext.Address == "" {
		return fmt.Errorf("external.address is required")
	}

	if ext.Port < 1 || ext.Port > 65535 {
		return fmt.Errorf("external.port must be between 1 and 65535")
	}

	return nil
}

func (r *GarageNode) validateStorage() error {
	storage := r.Spec.Storage
	if err := garageconfig.ValidateMetadataSnapshotInterval(
		storage.MetadataAutoSnapshotInterval,
		"spec.storage.metadataAutoSnapshotInterval",
	); err != nil {
		return err
	}

	if storage.Metadata != nil {
		if storage.Metadata.ReadOnly {
			return fmt.Errorf("storage.metadata.readOnly is not supported; readOnly applies only to multi-HDD storage.dataPaths[] entries")
		}
		if err := validateVolumeSource(storage.Metadata, "storage.metadata"); err != nil {
			return err
		}
	}

	hasData := storage.Data != nil
	hasDataPaths := len(storage.DataPaths) > 0

	if hasData && hasDataPaths {
		return fmt.Errorf("storage.data and storage.dataPaths are mutually exclusive (use one or the other)")
	}

	if hasData {
		if r.Spec.Gateway {
			return fmt.Errorf("storage.data cannot be specified for gateway nodes")
		}
		if storage.Data.ReadOnly {
			return fmt.Errorf("storage.data.readOnly is not supported; readOnly applies only to multi-HDD storage.dataPaths[] entries")
		}
		if err := validateVolumeSource(storage.Data, "storage.data"); err != nil {
			return err
		}
	}

	if hasDataPaths {
		if r.Spec.Gateway {
			return fmt.Errorf("storage.dataPaths cannot be specified for gateway nodes")
		}
		for i := range storage.DataPaths {
			if err := validateVolumeSource(&storage.DataPaths[i], fmt.Sprintf("storage.dataPaths[%d]", i)); err != nil {
				return err
			}
		}
	}

	if !r.Spec.Gateway && !hasData && !hasDataPaths {
		return fmt.Errorf("storage.data or storage.dataPaths is required for storage nodes")
	}

	return nil
}

// ValidateCycleStorageProfile verifies that cycle automation can reproduce a
// fresh, independent storage identity without guessing how to allocate or reuse
// user-managed storage. It deliberately rejects every existingClaim: PVC access
// mode does not make sharing metadata/node_key or block data between two Garage
// identities safe.
func (r *GarageNode) ValidateCycleStorageProfile() error {
	if r == nil {
		return fmt.Errorf("GarageNode is nil")
	}
	if r.Spec.Gateway {
		return fmt.Errorf("gateway identities are not supported by automatic cycle; create a distinct gateway and retire this role explicitly")
	}
	if r.Spec.External != nil {
		return fmt.Errorf("external Garage processes are not supported by automatic cycle")
	}
	if effectiveNodeBacking(r.Spec.Backing) != NodeBackingStatefulSet {
		return fmt.Errorf("automatic cycle requires a StatefulSet-backed GarageNode")
	}
	if r.Spec.Capacity == nil || r.Spec.Capacity.Sign() <= 0 {
		return fmt.Errorf("automatic cycle requires a positive-capacity storage role")
	}
	if r.Spec.Storage == nil {
		return fmt.Errorf("automatic cycle requires a repeatable storage profile")
	}
	if r.Spec.Network != nil && strings.TrimSpace(r.Spec.Network.RPCPublicAddr) != "" {
		return fmt.Errorf("automatic cycle cannot clone the identity-specific network.rpcPublicAddr %q; create a replacement with a distinct RPC endpoint", r.Spec.Network.RPCPublicAddr)
	}
	if r.Spec.PublicEndpoint != nil {
		return fmt.Errorf("automatic cycle does not support publicEndpoint handoff; create a replacement with a distinct endpoint and retire the source explicitly")
	}
	if r.Spec.Storage.Metadata != nil && r.Spec.Storage.Metadata.ExistingClaim != "" {
		return fmt.Errorf("storage.metadata.existingClaim %q requires an explicitly created replacement GarageNode with distinct metadata", r.Spec.Storage.Metadata.ExistingClaim)
	}
	if r.Spec.Storage.Data != nil && r.Spec.Storage.Data.ExistingClaim != "" {
		return fmt.Errorf("storage.data.existingClaim %q requires an explicitly created replacement GarageNode with distinct data", r.Spec.Storage.Data.ExistingClaim)
	}
	for i := range r.Spec.Storage.DataPaths {
		if claim := r.Spec.Storage.DataPaths[i].ExistingClaim; claim != "" {
			return fmt.Errorf("storage.dataPaths[%d].existingClaim %q requires an explicitly created replacement GarageNode with distinct data", i, claim)
		}
	}
	return nil
}

// ValidateCycleParentNetworkProfile rejects inherited RPC addresses that would
// make the source and replacement advertise one L4 endpoint for two distinct
// Garage public keys. Subnet discovery is intentionally allowed because each
// Pod resolves its own address.
func (r *GarageNode) ValidateCycleParentNetworkProfile(cluster *v1beta2.GarageCluster) error {
	if cluster == nil {
		return fmt.Errorf("automatic cycle requires the referenced GarageCluster")
	}
	if err := r.ValidateCycleStorageProfile(); err != nil {
		return err
	}
	if addr := strings.TrimSpace(cluster.Spec.Network.RPCPublicAddr); addr != "" {
		return fmt.Errorf("automatic cycle cannot share parent network.rpcPublicAddr %q across source and replacement identities", addr)
	}
	if cluster.Spec.Storage != nil {
		if addr := strings.TrimSpace(cluster.Spec.Storage.RPCPublicAddr); addr != "" {
			return fmt.Errorf("automatic cycle cannot share parent storage.rpcPublicAddr %q across source and replacement identities", addr)
		}
	}
	if cluster.Spec.Gateway != nil {
		if addr := strings.TrimSpace(cluster.Spec.Gateway.RPCPublicAddr); addr != "" {
			return fmt.Errorf("automatic cycle cannot share parent gateway.rpcPublicAddr %q across source and replacement identities", addr)
		}
	}
	if cluster.Spec.PublicEndpoint != nil {
		return fmt.Errorf("automatic cycle does not support inherited publicEndpoint handoff; create a replacement with a distinct endpoint and retire the source explicitly")
	}
	return nil
}

// ValidateCycleSourceReadiness verifies the durable source evidence required
// before cycle automation is allowed to provision a second identity. Runtime
// reconciliation additionally binds ObservedPodUID to the exact owned, Ready
// StatefulSet Pod immediately before creating the sibling.
func (r *GarageNode) ValidateCycleSourceReadiness() error {
	if err := r.ValidateCycleStorageProfile(); err != nil {
		return err
	}
	if !r.DeletionTimestamp.IsZero() {
		return fmt.Errorf("source GarageNode is deleting")
	}
	if r.Annotations[AnnotationDrain] != "" || r.Annotations[AnnotationAcknowledgeLostSource] != "" {
		return fmt.Errorf("source GarageNode already has a drain or lost-source request")
	}
	nodeID := canonicalGarageNodeID(r.Status.NodeID)
	if nodeID == "" {
		return fmt.Errorf("status.nodeId has not been observed from the source process")
	}
	if err := validateNodeID(nodeID); err != nil {
		return fmt.Errorf("status.nodeId is not an exact Garage identity: %w", err)
	}
	if strings.TrimSpace(r.Status.ObservedPodUID) == "" {
		return fmt.Errorf("status.observedPodUid has not been bound to the source process")
	}
	if r.Status.ObservedGeneration < r.Generation {
		return fmt.Errorf("status.observedGeneration %d is behind metadata.generation %d", r.Status.ObservedGeneration, r.Generation)
	}
	if !r.Status.Connected || !r.Status.InLayout {
		return fmt.Errorf("source must be connected and committed in the Garage layout")
	}
	return nil
}

func validateVolumeSource(vs *NodeVolumeConfig, fieldPath string) error {
	hasExistingClaim := vs.ExistingClaim != ""
	hasSize := vs.Size != nil

	// EmptyDir is a self-contained ephemeral volume source: it binds no PVC and
	// needs no provisioning size. Operator-generated ephemeral Auto-mode nodes
	// (#283) produce exactly this shape (`{type: EmptyDir}` with no size), so the
	// requirement below must accept it — otherwise the operator's own GarageNode
	// create is rejected by admission and the ephemeral cluster never starts.
	// A size, when present, is honored as the EmptyDir sizeLimit. existingClaim
	// and storageClassName are meaningless for EmptyDir (PVC-only), so reject
	// them — symmetric with the cluster webhook's EmptyDir guards.
	if vs.Type == VolumeTypeEmptyDir {
		if hasExistingClaim {
			return fmt.Errorf("%s: existingClaim cannot be used with type=EmptyDir", fieldPath)
		}
		if vs.StorageClassName != nil {
			return fmt.Errorf("%s: storageClassName cannot be used with type=EmptyDir", fieldPath)
		}
		if vs.Selector != nil {
			return fmt.Errorf("%s: selector cannot be used with type=EmptyDir", fieldPath)
		}
		if len(vs.AccessModes) > 0 || len(vs.Labels) > 0 || len(vs.Annotations) > 0 {
			return fmt.Errorf("%s: accessModes, labels, and annotations cannot be used with type=EmptyDir", fieldPath)
		}
		if vs.DataSourceRef != nil {
			return fmt.Errorf("%s: dataSourceRef cannot be used with type=EmptyDir", fieldPath)
		}
		return nil
	}

	// existingClaim + size is permitted: in multi-HDD `storage.dataPaths[]`
	// entries Size is the capacity advertised to Garage in `data_dir`, which
	// has independent semantics from PVC binding. The legacy-STS migration
	// (#205) populates both so the operator's per-node ConfigMap renderer
	// emits a complete `data_dir = [{ path = ..., capacity = ... }]` for
	// multi-HDD nodes adopted from pre-#190 layouts.
	//
	// readOnly is a Garage data_dir modifier, not a Kubernetes volume source.
	// Upstream permits a read-only data_dir entry without an advertised Garage
	// capacity, but it still needs a real mounted filesystem. Requiring a claim,
	// a dynamically provisioned size, or EmptyDir independently prevents a
	// volumeMount from referencing a Volume that the renderer never created.
	if !hasExistingClaim && !hasSize {
		return fmt.Errorf("%s: must specify existingClaim, size, or type=EmptyDir (readOnly does not provide a Kubernetes volume)", fieldPath)
	}

	if vs.StorageClassName != nil && hasExistingClaim {
		return fmt.Errorf("%s: storageClassName cannot be used with existingClaim", fieldPath)
	}
	if vs.Selector != nil && hasExistingClaim {
		return fmt.Errorf("%s: selector cannot be used with existingClaim because the referenced PVC is already bound or user-managed", fieldPath)
	}
	if hasExistingClaim && (len(vs.AccessModes) > 0 || len(vs.Labels) > 0 || len(vs.Annotations) > 0) {
		return fmt.Errorf("%s: accessModes, labels, and annotations cannot be used with existingClaim because the referenced PVC is already user-managed", fieldPath)
	}
	if hasExistingClaim && vs.DataSourceRef != nil {
		return fmt.Errorf("%s: dataSourceRef cannot be used with existingClaim because the referenced PVC is already user-managed", fieldPath)
	}
	if vs.DataSourceRef != nil {
		if vs.Selector != nil {
			return fmt.Errorf("%s.dataSourceRef: a PV selector cannot be combined with a group data source", fieldPath)
		}
		if err := garageconfig.ValidateGroupVolumeDataSource(vs.DataSourceRef, "", fieldPath+".dataSourceRef"); err != nil {
			return err
		}
	}
	if vs.Selector != nil {
		if _, err := metav1.LabelSelectorAsSelector(vs.Selector); err != nil {
			return fmt.Errorf("%s.selector: invalid PersistentVolume label selector: %w", fieldPath, err)
		}
	}

	return nil
}
