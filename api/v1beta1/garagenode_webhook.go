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

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garagenodelog = logf.Log.WithName("garagenode-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageNode) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageNodeDefaulter{}).
		WithValidator(&GarageNodeValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta1-garagenode,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update,versions=v1beta1,name=mgaragenode.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageNode] = &GarageNodeDefaulter{}

// GarageNodeDefaulter handles defaulting for GarageNode.
type GarageNodeDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageNodeDefaulter) Default(ctx context.Context, obj *GarageNode) error {
	garagenodelog.Info("default", "name", obj.Name)

	if obj.Spec.External != nil && obj.Spec.External.Port == 0 {
		obj.Spec.External.Port = 3901
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta1-garagenode,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update,versions=v1beta1,name=vgaragenode.kb.io,admissionReviewVersions=v1

var _ admission.Validator[*GarageNode] = &GarageNodeValidator{}

// GarageNodeValidator handles validation for GarageNode.
type GarageNodeValidator struct{}

// ValidateCreate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateCreate(ctx context.Context, obj *GarageNode) (admission.Warnings, error) {
	garagenodelog.Info("validate create", "name", obj.Name)
	return obj.validateGarageNode()
}

// ValidateUpdate implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *GarageNode) (admission.Warnings, error) {
	garagenodelog.Info("validate update", "name", newObj.Name)
	return newObj.validateGarageNode()
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageNodeValidator) ValidateDelete(ctx context.Context, obj *GarageNode) (admission.Warnings, error) {
	garagenodelog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

// validateGarageNode validates the GarageNode spec.
func (r *GarageNode) validateGarageNode() (admission.Warnings, error) {
	var warnings admission.Warnings

	if r.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
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
	}

	if r.Spec.External != nil {
		if err := r.validateExternalNode(); err != nil {
			return warnings, err
		}
		if r.Spec.Storage != nil {
			return warnings, fmt.Errorf("storage cannot be specified for external nodes")
		}
	} else {
		if r.Spec.Storage == nil {
			return warnings, fmt.Errorf("storage is required for managed nodes (use external for externally-managed nodes)")
		}
		if err := r.validateStorage(); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}

func validateNodeID(nodeID string) error {
	nodeIDPattern := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if !nodeIDPattern.MatchString(nodeID) {
		return fmt.Errorf("nodeId must be a 64-character hex string (Ed25519 public key)")
	}
	return nil
}

func (r *GarageNode) validateExternalNode() error {
	ext := r.Spec.External

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

	if storage.Metadata != nil {
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
		return nil
	}

	// existingClaim + size is permitted: in multi-HDD `storage.dataPaths[]`
	// entries Size is the capacity advertised to Garage in `data_dir`, which
	// has independent semantics from PVC binding. The legacy-STS migration
	// (#205) populates both so the operator's per-node ConfigMap renderer
	// emits a complete `data_dir = [{ path = ..., capacity = ... }]` for
	// multi-HDD nodes adopted from pre-#190 layouts.
	//
	// readOnly satisfies the requirement on its own — upstream Garage allows
	// `data_dir` entries with `read_only = true` and no capacity (see
	// ../garage src/block/layout.rs `make_data_dirs`).
	if !hasExistingClaim && !hasSize && !vs.ReadOnly {
		return fmt.Errorf("%s: must specify existingClaim, size, readOnly, or type=EmptyDir", fieldPath)
	}

	if vs.StorageClassName != nil && hasExistingClaim {
		return fmt.Errorf("%s: storageClassName cannot be used with existingClaim", fieldPath)
	}

	return nil
}
