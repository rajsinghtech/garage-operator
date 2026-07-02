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
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var garageclusterlog = logf.Log.WithName("garagecluster-resource")

const (
	zoneRedundancyMaximum = "Maximum"
	zoneRedundancyAtLeast = "AtLeast"
	layoutPolicyAuto      = "Auto"
	layoutPolicyManual    = "Manual"
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
		obj.Spec.LayoutPolicy = layoutPolicyAuto
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

	if r.HasStorageTier() && r.Spec.LayoutPolicy != layoutPolicyManual {
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
		if err := r.validateVolumeConfig(r.Spec.Gateway.Metadata, "gateway.metadata"); err != nil {
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
	if len(r.Spec.RemoteClusters) > 0 && r.Spec.Network.RPCPublicAddr == "" && r.Spec.PublicEndpoint == nil {
		warnings = append(warnings,
			"spec.remoteClusters is set but no rpc_public_addr (spec.network.rpcPublicAddr or spec.publicEndpoint): "+
				"cross-cluster RPC will degrade after pod restarts as peers infer the unroutable pod IP")
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
		warnings = append(warnings, "storage.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
	}
	if r.HasGatewayTier() && r.Spec.Gateway.PodDisruptionBudget != nil && r.Spec.Gateway.PodDisruptionBudget.Enabled &&
		r.Spec.Gateway.PodDisruptionBudget.MinAvailable == nil && r.Spec.Gateway.PodDisruptionBudget.MaxUnavailable == nil {
		warnings = append(warnings, "gateway.podDisruptionBudget is enabled without minAvailable or maxUnavailable; defaulting to minAvailable=(replicas-1)")
	}
	if r.HasGatewayTier() && r.Spec.Gateway.PodDisruptionBudget != nil && r.Spec.Gateway.PodDisruptionBudget.Enabled &&
		r.Spec.Gateway.Replicas == 0 {
		warnings = append(warnings, "gateway.podDisruptionBudget is enabled but gateway.replicas is 0; no PDB will be created")
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

	// connectTo without a gateway tier is allowed in exactly one case: a pure
	// management handle (no storage, no gateway) that manages an external Garage's
	// Admin-API state only — buckets, keys, layout — while some other system owns
	// the workload (e.g. the upstream Helm chart). See issue #269. connectTo with a
	// storage tier but no gateway remains meaningless.
	if hasConnect && !hasGateway && hasStorage {
		return fmt.Errorf("spec.connectTo is only valid alongside spec.gateway (edge gateway) or on a tier-less management handle")
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
