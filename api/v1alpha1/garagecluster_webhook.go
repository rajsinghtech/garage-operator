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
	"strconv"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garageclusterlog = logf.Log.WithName("garagecluster-resource")

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageClusterDefaulter{}).
		WithValidator(&GarageClusterValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-garage-rajsingh-info-v1alpha1-garagecluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1alpha1,name=mgaragecluster.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageCluster] = &GarageClusterDefaulter{}

// GarageClusterDefaulter handles defaulting for GarageCluster.
type GarageClusterDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageClusterDefaulter) Default(ctx context.Context, obj *GarageCluster) error {
	garageclusterlog.Info("default", "name", obj.Name)

	// Set default layout policy if not specified
	if obj.Spec.LayoutPolicy == "" {
		obj.Spec.LayoutPolicy = "Auto"
	}

	// Set default replication factor if not specified
	if obj.Spec.Replication.Factor == 0 {
		obj.Spec.Replication.Factor = 3
	}

	// Set default consistency mode if not specified
	if obj.Spec.Replication.ConsistencyMode == "" {
		obj.Spec.Replication.ConsistencyMode = "consistent"
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-garage-garage-rajsingh-info-v1alpha1-garagecluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1alpha1,name=vgaragecluster.kb.io,admissionReviewVersions=v1

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

	warnings, err := newObj.validateGarageCluster()
	if err != nil {
		return warnings, err
	}

	// Replication factor cannot be changed after cluster creation
	if oldObj.Spec.Replication.Factor != 0 && newObj.Spec.Replication.Factor != oldObj.Spec.Replication.Factor {
		warnings = append(warnings, "Changing replication factor on an existing cluster requires careful data migration")
	}

	return warnings, nil
}

// ValidateDelete implements admission.Validator so a webhook will be registered for the type.
func (v *GarageClusterValidator) ValidateDelete(ctx context.Context, obj *GarageCluster) (admission.Warnings, error) {
	garageclusterlog.Info("validate delete", "name", obj.Name)
	return nil, nil
}

// validateGarageCluster validates the GarageCluster spec.
func (r *GarageCluster) validateGarageCluster() (admission.Warnings, error) {
	var warnings admission.Warnings

	// Validate layout policy
	if err := r.validateLayoutPolicy(); err != nil {
		return warnings, err
	}

	// Validate zone redundancy against replication factor
	if err := r.validateZoneRedundancy(); err != nil {
		return warnings, err
	}

	// Validate gateway mode
	if err := r.validateGateway(); err != nil {
		return warnings, err
	}

	// Validate storage configuration (skip for gateway clusters and Manual mode)
	// In Manual mode, storage is configured via GarageNode resources
	if !r.Spec.Gateway && r.Spec.LayoutPolicy != "Manual" {
		if err := r.validateStorage(); err != nil {
			return warnings, err
		}
	}

	// Validate API configurations
	if err := r.validateAPIs(); err != nil {
		return warnings, err
	}

	// Add warnings for non-recommended configurations
	// Note: Replication factors 2, 4, 5, 6, 7 are all valid but less common.
	// RF=1 is for testing, RF=3 is standard production. Other factors are valid
	// for specific use cases (e.g., RF=2 for 2-zone setups).
	// We don't warn on these anymore as they're all supported by Garage.

	if r.Spec.Replication.ConsistencyMode == "dangerous" {
		warnings = append(warnings, "ConsistencyMode 'dangerous' may lead to data loss. Use only for testing.")
	}

	return warnings, nil
}

// validateLayoutPolicy validates layoutPolicy configuration.
func (r *GarageCluster) validateLayoutPolicy() error {
	// In Manual mode, replicas is ignored (GarageNodes create their own StatefulSets)
	// No validation needed for Manual mode
	return nil
}

// validateGateway validates gateway mode configuration.
func (r *GarageCluster) validateGateway() error {
	if r.Spec.Gateway {
		// Gateway clusters require connectTo
		if r.Spec.ConnectTo == nil {
			return fmt.Errorf("connectTo is required when gateway is true")
		}
		// Gateway clusters cannot have storage config
		if r.Spec.Storage.Data != nil && r.Spec.Storage.Data.Size != nil {
			return fmt.Errorf("storage cannot be specified for gateway clusters")
		}
	} else {
		// Non-gateway clusters cannot have connectTo
		if r.Spec.ConnectTo != nil {
			return fmt.Errorf("connectTo can only be specified when gateway is true")
		}
	}

	// Validate connectTo config if present
	if r.Spec.ConnectTo != nil {
		if r.Spec.ConnectTo.ClusterRef == nil &&
			r.Spec.ConnectTo.RPCSecretRef == nil &&
			len(r.Spec.ConnectTo.BootstrapPeers) == 0 {
			return fmt.Errorf("connectTo must specify clusterRef, rpcSecretRef, or bootstrapPeers")
		}
	}

	return nil
}

// validateZoneRedundancy validates that zoneRedundancy doesn't exceed replication factor.
func (r *GarageCluster) validateZoneRedundancy() error {
	if r.Spec.Replication.ZoneRedundancy == "" || r.Spec.Replication.ZoneRedundancy == "Maximum" {
		return nil
	}

	// Parse AtLeast(n) pattern
	re := regexp.MustCompile(`^AtLeast\((\d+)\)$`)
	matches := re.FindStringSubmatch(r.Spec.Replication.ZoneRedundancy)
	if len(matches) != 2 {
		return fmt.Errorf("invalid zoneRedundancy format: %s (expected 'Maximum' or 'AtLeast(n)')",
			r.Spec.Replication.ZoneRedundancy)
	}

	atLeast, err := strconv.Atoi(matches[1])
	if err != nil {
		return fmt.Errorf("invalid zoneRedundancy value: %s", r.Spec.Replication.ZoneRedundancy)
	}

	if atLeast > r.Spec.Replication.Factor {
		return fmt.Errorf(
			"zoneRedundancy AtLeast(%d) cannot exceed replication factor (%d)",
			atLeast, r.Spec.Replication.Factor,
		)
	}

	if atLeast < 1 {
		return fmt.Errorf("zoneRedundancy AtLeast value must be at least 1, got %d", atLeast)
	}

	return nil
}

// validateStorage validates storage configuration.
func (r *GarageCluster) validateStorage() error {
	if r.Spec.Storage.Data == nil {
		return fmt.Errorf("storage.data: must specify data storage configuration")
	}

	// Paths-based storage is not yet implemented in the controller.
	// Only PVC-based storage (size) is supported.
	if len(r.Spec.Storage.Data.Paths) > 0 {
		return fmt.Errorf("storage.data.paths: path-based storage is not implemented; use storage.data.size instead")
	}

	// Size is required
	if r.Spec.Storage.Data.Size == nil {
		return fmt.Errorf("storage.data.size: must specify size for data storage")
	}

	return nil
}

// validateAPIs validates API configurations.
func (r *GarageCluster) validateAPIs() error {
	// Validate bind addresses if specified
	if r.Spec.S3API != nil && r.Spec.S3API.BindAddress != "" {
		if err := validateBindAddress(r.Spec.S3API.BindAddress, "s3Api"); err != nil {
			return err
		}
	}

	if r.Spec.K2VAPI != nil && r.Spec.K2VAPI.BindAddress != "" {
		if err := validateBindAddress(r.Spec.K2VAPI.BindAddress, "k2vApi"); err != nil {
			return err
		}
	}

	if r.Spec.WebAPI != nil && r.Spec.WebAPI.BindAddress != "" {
		if err := validateBindAddress(r.Spec.WebAPI.BindAddress, "webApi"); err != nil {
			return err
		}
	}

	if r.Spec.Admin != nil && r.Spec.Admin.BindAddress != "" {
		if err := validateBindAddress(r.Spec.Admin.BindAddress, "admin"); err != nil {
			return err
		}
	}

	return nil
}

// validateBindAddress validates a bind address format.
func validateBindAddress(addr, field string) error {
	// Allow unix socket paths
	if len(addr) > 7 && addr[:7] == "unix://" {
		return nil
	}

	// Allow TCP addresses (basic validation)
	// Format: [host]:port or host:port
	tcpPattern := regexp.MustCompile(`^(\[.*\]|[^:]+)?:\d+$`)
	if !tcpPattern.MatchString(addr) {
		return fmt.Errorf("%s.bindAddress: invalid format '%s' (expected '[host]:port' or 'unix:///path')", field, addr)
	}

	return nil
}
