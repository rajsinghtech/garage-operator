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

package v1alpha1

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

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1alpha1-garagenode,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update,versions=v1alpha1,name=mgaragenode.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageNode] = &GarageNodeDefaulter{}

// GarageNodeDefaulter handles defaulting for GarageNode.
type GarageNodeDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageNodeDefaulter) Default(ctx context.Context, obj *GarageNode) error {
	garagenodelog.Info("default", "name", obj.Name)

	// Set default external port
	if obj.Spec.External != nil && obj.Spec.External.Port == 0 {
		obj.Spec.External.Port = 3901
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1alpha1-garagenode,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garagenodes,verbs=create;update,versions=v1alpha1,name=vgaragenode.kb.io,admissionReviewVersions=v1

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

	// Validate cluster reference
	if r.Spec.ClusterRef.Name == "" {
		return warnings, fmt.Errorf("clusterRef.name is required")
	}

	// Validate zone is not empty
	if r.Spec.Zone == "" {
		return warnings, fmt.Errorf("zone is required")
	}

	// Validate capacity is required if not a gateway node
	if !r.Spec.Gateway && r.Spec.Capacity == nil {
		return warnings, fmt.Errorf("capacity is required for storage nodes (set gateway: true for gateway-only nodes)")
	}

	// Validate capacity is not set for gateway nodes (it would be ignored)
	if r.Spec.Gateway && r.Spec.Capacity != nil {
		warnings = append(warnings,
			"capacity is set but will be ignored for gateway nodes")
	}

	// Validate nodeId format if specified
	if r.Spec.NodeID != "" {
		if err := validateNodeID(r.Spec.NodeID); err != nil {
			return warnings, err
		}
	}

	// Validate external node configuration
	if r.Spec.External != nil {
		if err := r.validateExternalNode(); err != nil {
			return warnings, err
		}
		// External nodes don't need storage (they manage their own)
		if r.Spec.Storage != nil {
			return warnings, fmt.Errorf("storage cannot be specified for external nodes")
		}
	} else {
		// Non-external nodes require storage configuration
		if r.Spec.Storage == nil {
			return warnings, fmt.Errorf("storage is required for managed nodes (use external for externally-managed nodes)")
		}
		if err := r.validateStorage(); err != nil {
			return warnings, err
		}
	}

	return warnings, nil
}

// validateNodeID validates the format of a Garage node ID.
// Node IDs are Ed25519 public keys encoded as 64 hex characters.
func validateNodeID(nodeID string) error {
	// Node IDs are 64 hex characters (32 bytes = 256 bits Ed25519 public key)
	nodeIDPattern := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if !nodeIDPattern.MatchString(nodeID) {
		return fmt.Errorf("nodeId must be a 64-character hex string (Ed25519 public key)")
	}
	return nil
}

// validateExternalNode validates external node configuration.
func (r *GarageNode) validateExternalNode() error {
	ext := r.Spec.External

	if ext.Address == "" {
		return fmt.Errorf("external.address is required")
	}

	// Validate port range
	if ext.Port < 1 || ext.Port > 65535 {
		return fmt.Errorf("external.port must be between 1 and 65535")
	}

	return nil
}

// validateStorage validates storage configuration for GarageNode.
func (r *GarageNode) validateStorage() error {
	storage := r.Spec.Storage

	// Validate metadata volume source
	if storage.Metadata != nil {
		if err := validateVolumeSource(storage.Metadata, "storage.metadata"); err != nil {
			return err
		}
	}

	// Validate data volume source (only for non-gateway nodes)
	if storage.Data != nil {
		if r.Spec.Gateway {
			return fmt.Errorf("storage.data cannot be specified for gateway nodes")
		}
		if err := validateVolumeSource(storage.Data, "storage.data"); err != nil {
			return err
		}
	}

	// Non-gateway nodes require data storage
	if !r.Spec.Gateway && storage.Data == nil {
		return fmt.Errorf("storage.data is required for storage nodes")
	}

	return nil
}

// validateVolumeSource validates a NodeVolumeSource configuration.
func validateVolumeSource(vs *NodeVolumeSource, fieldPath string) error {
	hasExistingClaim := vs.ExistingClaim != ""
	hasSize := vs.Size != nil

	// Must specify exactly one of existingClaim or size
	if hasExistingClaim && hasSize {
		return fmt.Errorf("%s: cannot specify both existingClaim and size (choose one)", fieldPath)
	}

	if !hasExistingClaim && !hasSize {
		return fmt.Errorf("%s: must specify either existingClaim or size", fieldPath)
	}

	// storageClassName only makes sense with size (for dynamic provisioning)
	if vs.StorageClassName != nil && hasExistingClaim {
		return fmt.Errorf("%s: storageClassName cannot be used with existingClaim", fieldPath)
	}

	return nil
}
