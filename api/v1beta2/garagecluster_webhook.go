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
	"fmt"
	"regexp"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garageclusterlog = logf.Log.WithName("garagecluster-resource")

const (
	zoneRedundancyMaximum = "Maximum"
	zoneRedundancyAtLeast = "AtLeast"
)

// SetupWebhookWithManager sets up the webhook with the Manager.
func (r *GarageCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithDefaulter(&GarageClusterDefaulter{}).
		WithValidator(&GarageClusterValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-garage-rajsingh-info-v1beta2-garagecluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1beta2,name=mgaragecluster.kb.io,admissionReviewVersions=v1

var _ admission.Defaulter[*GarageCluster] = &GarageClusterDefaulter{}

// GarageClusterDefaulter handles defaulting for GarageCluster.
type GarageClusterDefaulter struct{}

// Default implements admission.Defaulter so a webhook will be registered for the type.
func (d *GarageClusterDefaulter) Default(ctx context.Context, obj *GarageCluster) error {
	garageclusterlog.Info("default", "name", obj.Name)

	if obj.Spec.LayoutPolicy == "" {
		obj.Spec.LayoutPolicy = "Auto"
	}

	if obj.Spec.Replication == nil {
		obj.Spec.Replication = &ReplicationConfig{}
	}
	if obj.Spec.Replication.Factor == 0 {
		obj.Spec.Replication.Factor = 3
	}
	if obj.Spec.Replication.ConsistencyMode == "" {
		obj.Spec.Replication.ConsistencyMode = "consistent"
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

// +kubebuilder:webhook:path=/validate-garage-rajsingh-info-v1beta2-garagecluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=garage.rajsingh.info,resources=garageclusters,verbs=create;update,versions=v1beta2,name=vgaragecluster.kb.io,admissionReviewVersions=v1

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

	oldFactor := 0
	if oldObj.Spec.Replication != nil {
		oldFactor = oldObj.Spec.Replication.Factor
	}
	newFactor := 0
	if newObj.Spec.Replication != nil {
		newFactor = newObj.Spec.Replication.Factor
	}
	if oldFactor != 0 && newFactor != oldFactor {
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

	if err := r.validateTiers(); err != nil {
		return warnings, err
	}

	if err := r.validateZoneRedundancy(); err != nil {
		return warnings, err
	}

	if r.HasStorageTier() && r.Spec.LayoutPolicy != "Manual" {
		if err := r.validateStorageTier(); err != nil {
			return warnings, err
		}
	}

	if err := r.validateConnectTo(); err != nil {
		return warnings, err
	}

	if err := r.validateAPIs(); err != nil {
		return warnings, err
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

	if r.HasStorageTier() && r.Spec.Storage.PodDisruptionBudget != nil && r.Spec.Storage.PodDisruptionBudget.Enabled &&
		r.Spec.Storage.PodDisruptionBudget.MinAvailable == nil && r.Spec.Storage.PodDisruptionBudget.MaxUnavailable == nil {
		warnings = append(warnings, "storage.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
	}

	return warnings, nil
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

	// connectTo without a gateway tier is meaningless — connectTo's only job is to wire
	// gateway pods to a remote storage backend.
	if hasConnect && !hasGateway {
		return fmt.Errorf("spec.connectTo is only valid alongside spec.gateway")
	}

	if hasGateway {
		gw := r.Spec.Gateway
		if gw.Replicas < 0 {
			return fmt.Errorf("spec.gateway.replicas must be non-negative")
		}
	}

	if hasStorage {
		st := r.Spec.Storage
		if st.Replicas < 0 {
			return fmt.Errorf("spec.storage.replicas must be non-negative")
		}
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
	if r.Spec.ConnectTo == nil {
		return nil
	}
	c := r.Spec.ConnectTo
	if c.ClusterRef == nil && c.RPCSecretRef == nil && len(c.BootstrapPeers) == 0 && c.AdminAPIEndpoint == "" {
		return fmt.Errorf("connectTo must specify clusterRef, rpcSecretRef, bootstrapPeers, or adminApiEndpoint")
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

func (r *GarageCluster) validateStorageTier() error {
	st := r.Spec.Storage
	if st.Metadata == nil {
		return fmt.Errorf("spec.storage.metadata: required when spec.storage is set")
	}
	if st.Data == nil {
		return fmt.Errorf("spec.storage.data: required when spec.storage is set")
	}

	if err := r.validateVolumeConfig(st.Metadata, "metadata"); err != nil {
		return err
	}
	if err := r.validateVolumeConfig(st.Data, "data"); err != nil {
		return err
	}
	if st.Data.Type == VolumeTypeEmptyDir && len(st.Data.Paths) > 0 {
		return fmt.Errorf("storage.data.paths: not allowed with EmptyDir type")
	}
	if len(st.Metadata.Paths) > 0 {
		return fmt.Errorf("storage.metadata.paths: paths is only valid for data volumes")
	}

	if !r.isDataEphemeral() {
		if st.Data.Size == nil && len(st.Data.Paths) == 0 {
			return fmt.Errorf("storage.data.size: must specify size for persistent data storage (or use storage.data.paths for multi-disk)")
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
	return nil
}

func (r *GarageCluster) validateAPIs() error {
	if r.Spec.Network.RPCBindAddress != "" {
		if err := validateBindAddress(r.Spec.Network.RPCBindAddress, "network.rpcBindAddress"); err != nil {
			return err
		}
	}
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

func (r *GarageCluster) validateLayoutManagement() error {
	lm := r.Spec.LayoutManagement
	if lm == nil {
		return nil
	}
	if lm.MinNodesHealthy < 0 {
		return fmt.Errorf("layoutManagement.minNodesHealthy: must be non-negative, got %d", lm.MinNodesHealthy)
	}
	if lm.MinNodesHealthy > 0 {
		replicas := int(r.TotalReplicas())
		if lm.MinNodesHealthy > replicas {
			return fmt.Errorf("layoutManagement.minNodesHealthy (%d) cannot exceed total replicas (%d) — layout changes would never be applied", lm.MinNodesHealthy, replicas)
		}
	}
	return nil
}

func validateBindAddress(addr, field string) error {
	if len(addr) > 7 && addr[:7] == "unix://" {
		return nil
	}
	tcpPattern := regexp.MustCompile(`^(\[.*\]|[^:]+)?:\d+$`)
	if !tcpPattern.MatchString(addr) {
		return fmt.Errorf("%s.bindAddress: invalid format '%s' (expected '[host]:port' or 'unix:///path')", field, addr)
	}
	return nil
}
