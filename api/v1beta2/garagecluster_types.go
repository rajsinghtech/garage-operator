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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// GarageClusterSpec defines the desired state of a GarageCluster.
//
// A cluster has two optional tiers:
//
//   - `storage` — long-lived StatefulSet with PVCs for metadata and data blocks.
//   - `gateway` — StatefulSet with a small metadata PVC and EmptyDir for the
//     data dir. Routes S3/Admin traffic and stores no object blocks. The
//     metadata PVC preserves the Ed25519 node identity across pod restarts,
//     so rolling updates don't churn the cluster layout.
//
// Exactly one of these must hold true:
//
//  1. `storage` set (storage-only or unified with `gateway`).
//  2. `gateway` set together with `storage` (unified cluster — most common).
//  3. `gateway` set together with `connectTo` (edge gateway pattern — gateway pods
//     live in a different K8s cluster from the storage backend).
//
// +kubebuilder:validation:XValidation:rule="has(self.storage) || has(self.gateway) || has(self.connectTo)",message="at least one of spec.storage, spec.gateway, or spec.connectTo must be set"
// +kubebuilder:validation:XValidation:rule="!has(self.gateway) || has(self.storage) || has(self.connectTo)",message="spec.gateway requires either spec.storage (unified cluster) or spec.connectTo (edge gateway)"
type GarageClusterSpec struct {
	// Image specifies the Garage container image to use.
	// Takes precedence over imageRepository if both are set.
	// +kubebuilder:default="dxflrs/garage:v2.3.0"
	// +optional
	Image string `json:"image,omitempty"`

	// ImageRepository overrides just the repository portion of the default Garage image,
	// preserving the default tag for automatic version upgrades.
	// Ignored if image is set.
	// +optional
	ImageRepository string `json:"imageRepository,omitempty"`

	// ImagePullPolicy specifies the image pull policy
	// +kubebuilder:default="IfNotPresent"
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets specifies secrets for pulling images from private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// ServiceAccountName for Garage pods (shared by both tiers).
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Storage configures the long-lived storage tier (StatefulSet + PVCs).
	// Omit for gateway-only edge clusters.
	// +optional
	Storage *StorageSpec `json:"storage,omitempty"`

	// Gateway configures the gateway tier (StatefulSet + small metadata PVC).
	// Gateway pods route S3/Admin traffic and store no object blocks; the
	// metadata PVC persists their node identity across restarts.
	// May be combined with `storage` (unified cluster) or `connectTo` (edge cluster).
	// +optional
	Gateway *GatewaySpec `json:"gateway,omitempty"`

	// Replication configures data replication settings.
	// If omitted, defaults to factor: 3 and consistencyMode: consistent.
	// +optional
	Replication *ReplicationConfig `json:"replication,omitempty"`

	// Network configures RPC and API networking
	// +optional
	Network NetworkConfig `json:"network,omitempty"`

	// S3API configures the S3-compatible API endpoint
	// +optional
	S3API *S3APIConfig `json:"s3Api,omitempty"`

	// K2VAPI configures the K2V (key-value) API endpoint.
	// Omit to disable K2V.
	// +optional
	K2VAPI *K2VAPIConfig `json:"k2vApi,omitempty"`

	// WebAPI configures the static website hosting endpoint.
	// Enabled by default with rootDomain ".<name>.<namespace>.svc".
	// Set webApi.enabled: false to turn off.
	// +optional
	WebAPI *WebAPIConfig `json:"webApi,omitempty"`

	// Admin configures the admin API endpoint and metrics
	// +optional
	Admin *AdminConfig `json:"admin,omitempty"`

	// Database configures the metadata database engine
	// +optional
	Database *DatabaseConfig `json:"database,omitempty"`

	// Blocks configures block storage settings
	// +optional
	Blocks *BlockConfig `json:"blocks,omitempty"`

	// Discovery configures peer discovery mechanisms
	// +optional
	Discovery *DiscoveryConfig `json:"discovery,omitempty"`

	// Security configures security-related settings
	// +optional
	Security *SecurityConfig `json:"security,omitempty"`

	// Logging configures logging behavior for Garage nodes
	// +optional
	Logging *LoggingConfig `json:"logging,omitempty"`

	// Zone is the Garage layout zone assigned to all nodes in this cluster.
	// Each cluster in a federation must have a unique zone name.
	// +optional
	Zone string `json:"zone,omitempty"`

	// PublicEndpoint configures how remote clusters reach this cluster's nodes.
	// Used for multi-cluster federation of the storage tier.
	// +optional
	PublicEndpoint *PublicEndpointConfig `json:"publicEndpoint,omitempty"`

	// RemoteClusters lists Garage clusters in other Kubernetes clusters to federate with.
	// Applies to the storage tier. Gateways inherit reachability via the local storage peer.
	// +optional
	RemoteClusters []RemoteClusterConfig `json:"remoteClusters,omitempty"`

	// LayoutManagement controls automatic layout application behavior.
	// +optional
	LayoutManagement *LayoutManagementConfig `json:"layoutManagement,omitempty"`

	// LayoutPolicy controls whether node layouts are automatically managed or manually configured.
	// +kubebuilder:validation:Enum=Auto;Manual
	// +kubebuilder:default="Auto"
	// +optional
	LayoutPolicy string `json:"layoutPolicy,omitempty"`

	// DefaultNodeTags are tags applied to all auto-managed nodes.
	// Only used when LayoutPolicy is "Auto".
	// +optional
	DefaultNodeTags []string `json:"defaultNodeTags,omitempty"`

	// ConnectTo specifies a remote storage cluster this cluster connects to.
	// Required when `gateway` is set without `storage` (edge gateway pattern).
	// +optional
	ConnectTo *ConnectToConfig `json:"connectTo,omitempty"`

	// Monitoring configures Prometheus integration for this cluster.
	// +optional
	Monitoring *MonitoringSpec `json:"monitoring,omitempty"`

	// Maintenance configures maintenance mode for this cluster.
	// +optional
	Maintenance *MaintenanceSpec `json:"maintenance,omitempty"`

	// Workers configures Garage background worker behavior.
	// +optional
	Workers *WorkersConfig `json:"workers,omitempty"`
}

// StorageSpec configures the long-lived storage tier of a GarageCluster.
//
// Workload: StatefulSet with metadata + data PVCs.
// Pod identity: ordinal (`<cluster>-0`, `<cluster>-1`, …) — node IDs persist
// across pod restarts as long as the metadata PVC is preserved.
type StorageSpec struct {
	// Replicas is the number of storage pods to deploy. Set to 0 to keep the
	// storage tier declared (config, PVC templates) but stop all pods.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas"`

	// Metadata configures the metadata PVC (Garage node identity + index DB).
	// +required
	Metadata *VolumeConfig `json:"metadata"`

	// Data configures the data PVC (object blocks).
	// +required
	Data *VolumeConfig `json:"data"`

	// MetadataSnapshotsDir specifies directory for metadata snapshots
	// +optional
	MetadataSnapshotsDir string `json:"metadataSnapshotsDir,omitempty"`

	// MetadataAutoSnapshotInterval enables automatic metadata snapshots.
	// +kubebuilder:validation:Pattern=`^(\d+(\.\d+)?\s*(ns|us|ms|s|m|h|d|w|M|y)\s*)+$`
	// +optional
	MetadataAutoSnapshotInterval string `json:"metadataAutoSnapshotInterval,omitempty"`

	// MetadataFsync enables fsync for metadata transactions.
	// +optional
	MetadataFsync bool `json:"metadataFsync"`

	// DataFsync enables fsync for data block writes.
	// +optional
	DataFsync bool `json:"dataFsync"`

	// PVCRetentionPolicy controls PVC lifecycle when the StatefulSet is deleted or scaled down.
	// +optional
	PVCRetentionPolicy *PVCRetentionPolicy `json:"pvcRetentionPolicy,omitempty"`

	// CapacityReservePercent reserves a percentage of PVC capacity for overhead.
	// Only meaningful when LayoutPolicy is "Auto".
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=50
	// +optional
	CapacityReservePercent int `json:"capacityReservePercent,omitempty"`

	// PodDisruptionBudget configures a PDB for the storage StatefulSet.
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetConfig `json:"podDisruptionBudget,omitempty"`

	// PodTemplate carries pod scheduling and metadata for the storage tier.
	PodTemplate `json:",inline"`
}

// GatewaySpec configures the gateway tier of a GarageCluster.
//
// Workload: StatefulSet with a small metadata PVC and EmptyDir for the data
// directory. The metadata PVC persists the Ed25519 node_key Garage stores
// under metadata_dir, so each gateway pod re-joins the cluster with the
// same node identity across restarts.
//
// Data blocks are not stored on gateways, so the data dir remains EmptyDir
// — no PVC, no storage cost beyond the metadata claim.
//
// Gateway pods DO participate in the Garage cluster layout with capacity=nil
// (matching upstream `garage layout assign --gateway`). FullReplication tables
// (key_table, bucket_table, bucket_alias_table, admin_token_table) are written
// to every node in `layout.all_nodes()` — gateways included. Without a layout
// entry, the gateway's local DB never receives those writes and the S3
// sig-auth path (signature/payload.rs:413 get_local()) returns "No such key".
type GatewaySpec struct {
	// Replicas is the number of gateway pods to deploy. Set to 0 to keep the
	// gateway tier declared but stop all pods; the operator scales the
	// statefulset down and removes vacated entries from the layout.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=2
	Replicas int32 `json:"replicas"`

	// RPCPublicAddr, when set, is written into the gateway pods' garage.toml as
	// rpc_public_addr so that peers in other regions can dial gateways by hostname.
	// Purely cosmetic for federated layouts — leave unset when gateways only
	// communicate with the local storage tier.
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`

	// Metadata configures the metadata PVC for gateway pods. Only metadata_dir
	// is persisted — data_dir stays EmptyDir because gateways do not store
	// object blocks. Default size is 1Gi.
	// +optional
	Metadata *VolumeConfig `json:"metadata,omitempty"`

	// PodDisruptionBudget configures a PDB for the gateway Deployment. Gateway
	// pods serve S3/Admin traffic but hold no object data, so a PDB only
	// protects request availability during node drains — not data durability.
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetConfig `json:"podDisruptionBudget,omitempty"`

	// PodTemplate carries pod scheduling and metadata for the gateway tier.
	PodTemplate `json:",inline"`
}

// PodTemplate carries fields that affect pod scheduling, resource allocation,
// and pod-level metadata. Embedded in both StorageSpec and GatewaySpec so that
// the two tiers may be tuned independently.
type PodTemplate struct {
	// Resources specifies compute resources for the pod.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector for pod scheduling.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for pod scheduling.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity for pod scheduling.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// TopologySpreadConstraints for pod scheduling.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// PodAnnotations to add to pods.
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// PodLabels to add to pods.
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// PriorityClassName for pods.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// SecurityContext for the pod.
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// ContainerSecurityContext for the Garage container.
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// Env is a list of additional environment variables to set on the Garage
	// container. These are appended AFTER the operator's built-in vars
	// (GARAGE_NODE_HOST, RUST_LOG, etc.), so a user-supplied entry with the same
	// name as a built-in will override it. Typical use: setting
	// GARAGE_ALLOW_WORLD_READABLE_SECRETS, or any other GARAGE_* env Garage
	// honors at startup.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// EnvFrom is a list of sources to populate environment variables in the
	// Garage container, allowing injection from Secrets or ConfigMaps. These
	// sources are evaluated before the per-variable Env list, matching standard
	// Kubernetes container semantics.
	// +optional
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`
}

// MonitoringSpec configures Prometheus monitoring for the Garage cluster.
type MonitoringSpec struct {
	// Enabled creates a ServiceMonitor targeting the admin API /metrics endpoint.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Interval is the Prometheus scrape interval (e.g. "30s", "1m").
	// +optional
	Interval string `json:"interval,omitempty"`

	// AdditionalLabels are added to the ServiceMonitor metadata.
	// +optional
	AdditionalLabels map[string]string `json:"additionalLabels,omitempty"`
}

// WorkersConfig configures Garage background worker behavior.
type WorkersConfig struct {
	// ScrubTranquility controls how aggressively the block integrity scrub runs.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ScrubTranquility *int32 `json:"scrubTranquility,omitempty"`

	// ResyncWorkerCount sets the number of parallel block resync worker goroutines.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=8
	// +optional
	ResyncWorkerCount *int32 `json:"resyncWorkerCount,omitempty"`

	// ResyncTranquility controls how aggressively the block resync worker runs.
	// +kubebuilder:validation:Minimum=0
	// +optional
	ResyncTranquility *int32 `json:"resyncTranquility,omitempty"`
}

// MaintenanceSpec configures maintenance mode for the cluster.
type MaintenanceSpec struct {
	// Suspended pauses all reconciliation for this cluster.
	// +optional
	Suspended bool `json:"suspended"`
}

// PodDisruptionBudgetConfig configures PodDisruptionBudget for Garage pods.
type PodDisruptionBudgetConfig struct {
	// Enabled enables PodDisruptionBudget creation
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled"`

	// MinAvailable specifies the minimum number of pods that must be available.
	// +optional
	MinAvailable *intstr.IntOrString `json:"minAvailable,omitempty"`

	// MaxUnavailable specifies the maximum number of pods that can be unavailable.
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`
}

// ReplicationConfig configures data replication.
type ReplicationConfig struct {
	// Factor is the replication factor (1, 2, 3, 5, 7, etc.)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=7
	// +kubebuilder:default=3
	Factor int `json:"factor"`

	// ConsistencyMode controls quorum behavior for read/write operations.
	// +kubebuilder:validation:Enum=consistent;degraded;dangerous
	// +kubebuilder:default="consistent"
	// +optional
	ConsistencyMode string `json:"consistencyMode,omitempty"`

	// ZoneRedundancyMode controls how data is distributed across zones.
	// +kubebuilder:validation:Enum=Maximum;AtLeast
	// +optional
	ZoneRedundancyMode string `json:"zoneRedundancyMode,omitempty"`

	// ZoneRedundancyMinZones is the minimum number of zones required.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=7
	// +optional
	ZoneRedundancyMinZones *int `json:"zoneRedundancyMinZones,omitempty"`
}

// PVCRetentionPolicy controls PVC lifecycle for StatefulSet volumes.
type PVCRetentionPolicy struct {
	// WhenDeleted specifies what happens to PVCs when the StatefulSet is deleted.
	// +kubebuilder:validation:Enum=Retain;Delete
	// +kubebuilder:default="Retain"
	// +optional
	WhenDeleted string `json:"whenDeleted,omitempty"`

	// WhenScaled specifies what happens to PVCs when the StatefulSet is scaled down.
	// +kubebuilder:validation:Enum=Retain;Delete
	// +kubebuilder:default="Retain"
	// +optional
	WhenScaled string `json:"whenScaled,omitempty"`
}

// VolumeType specifies the type of volume to use.
// +kubebuilder:validation:Enum=PersistentVolumeClaim;EmptyDir
type VolumeType string

const (
	// VolumeTypePVC uses a PersistentVolumeClaim (default).
	VolumeTypePVC VolumeType = "PersistentVolumeClaim"
	// VolumeTypeEmptyDir uses an EmptyDir volume (ephemeral).
	VolumeTypeEmptyDir VolumeType = "EmptyDir"
)

// VolumeConfig configures a persistent volume.
type VolumeConfig struct {
	// Type specifies the volume type: PersistentVolumeClaim (default) or EmptyDir.
	// +kubebuilder:default="PersistentVolumeClaim"
	// +optional
	Type VolumeType `json:"type,omitempty"`

	// Size of the volume.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// StorageClassName for the PVC.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// AccessModes for the PVC.
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Selector to select PVs.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Labels to set on the PVC.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to set on the PVC.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// VolumeClaimTemplateSpec allows full customization of the PVC.
	// +optional
	VolumeClaimTemplateSpec *corev1.PersistentVolumeClaimSpec `json:"volumeClaimTemplateSpec,omitempty"`

	// Paths configures multiple data directories for multi-disk setups.
	// Only valid for data volumes — webhook rejects this on metadata volumes.
	// +optional
	Paths []DataPath `json:"paths,omitempty"`
}

// DataPathVolumeConfig is PVC config for a single data path.
type DataPathVolumeConfig struct {
	// Type specifies the volume type.
	// +kubebuilder:default="PersistentVolumeClaim"
	// +optional
	Type VolumeType `json:"type,omitempty"`

	// Size of the volume (storage request).
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// StorageClassName for the PVC.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// AccessModes for the PVC.
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Selector to select PVs.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Labels to set on the PVC.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to set on the PVC.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// VolumeClaimTemplateSpec allows full customization of the PVC.
	// +optional
	VolumeClaimTemplateSpec *corev1.PersistentVolumeClaimSpec `json:"volumeClaimTemplateSpec,omitempty"`
}

// DataPath specifies a data directory with capacity.
type DataPath struct {
	// Path to the data directory.
	// +required
	Path string `json:"path"`

	// Capacity of the drive (required unless readOnly).
	// +optional
	Capacity *resource.Quantity `json:"capacity,omitempty"`

	// ReadOnly marks directory as legacy read-only for migrations.
	// +optional
	ReadOnly bool `json:"readOnly"`

	// Volume configuration if using PVC.
	// +optional
	Volume *DataPathVolumeConfig `json:"volume,omitempty"`
}

// NetworkConfig configures RPC and networking.
type NetworkConfig struct {
	// RPCBindPort is the port for inter-cluster RPC.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3901
	RPCBindPort int32 `json:"rpcBindPort,omitempty"`

	// RPCBindAddress is a custom bind address for the RPC server.
	// +optional
	RPCBindAddress string `json:"rpcBindAddress,omitempty"`

	// RPCPublicAddr is the external address for storage-tier nodes to advertise.
	// Gateway tier has its own rpcPublicAddr field on `spec.gateway`.
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`

	// RPCPublicAddrSubnet filters autodiscovered IPs to specific subnet.
	// +optional
	RPCPublicAddrSubnet string `json:"rpcPublicAddrSubnet,omitempty"`

	// RPCBindOutgoing pre-binds outgoing sockets to same IP.
	// +optional
	RPCBindOutgoing bool `json:"rpcBindOutgoing"`

	// RPCSecretRef references a secret containing the shared RPC secret.
	// +optional
	RPCSecretRef *corev1.SecretKeySelector `json:"rpcSecretRef,omitempty"`

	// RPCPingTimeout sets the RPC ping timeout.
	// +optional
	RPCPingTimeout *metav1.Duration `json:"rpcPingTimeout,omitempty"`

	// RPCTimeout sets the RPC call timeout.
	// +optional
	RPCTimeout *metav1.Duration `json:"rpcTimeout,omitempty"`

	// BootstrapPeers lists initial peers for cluster formation.
	// +optional
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`

	// Service configures the Kubernetes Service for the cluster.
	// +optional
	Service *ServiceConfig `json:"service,omitempty"`
}

// ServiceMeta carries user-defined labels and annotations to apply to an operator-managed Service.
type ServiceMeta struct {
	// Labels to add to the service. Operator-managed labels take precedence on conflict.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the service.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ServiceConfig configures Kubernetes Service.
type ServiceConfig struct {
	// Type of service.
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	// +kubebuilder:default="ClusterIP"
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`

	ServiceMeta `json:",inline"`

	// LoadBalancerIP for LoadBalancer type.
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// LoadBalancerSourceRanges for LoadBalancer type.
	// +optional
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// ExternalTrafficPolicy for LoadBalancer/NodePort.
	// +optional
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`
}

// S3APIConfig configures the S3-compatible API.
type S3APIConfig struct {
	// BindPort is the port to bind for S3 API.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3900
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the S3 API.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// Region is the AWS S3 region name to use.
	// +kubebuilder:default="garage"
	Region string `json:"region"`

	// RootDomain is the root domain suffix for vhost-style S3 access.
	// +optional
	RootDomain string `json:"rootDomain,omitempty"`
}

// K2VAPIConfig configures the K2V (key-value) API.
type K2VAPIConfig struct {
	// BindPort is the port to bind for K2V API.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3904
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the K2V API.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`
}

// WebAPIConfig configures static website hosting.
type WebAPIConfig struct {
	// Enabled controls whether the web endpoint is active. Defaults to true.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// RootDomain is the root domain suffix for bucket website access.
	// +optional
	RootDomain string `json:"rootDomain,omitempty"`

	// BindPort is the port to bind for web serving.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3902
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the Web API.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// AddHostToMetrics adds the domain name to metrics labels for per-domain tracking.
	// +optional
	AddHostToMetrics bool `json:"addHostToMetrics"`
}

// AdminConfig configures the admin API and metrics.
type AdminConfig struct {
	// BindPort is the port to bind for admin API.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3903
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the Admin API.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// AdminTokenSecretRef references the secret used by the operator to authenticate
	// with Garage's Admin API.
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`

	// MetricsTokenSecretRef references a secret containing a token that protects /metrics.
	// +optional
	MetricsTokenSecretRef *corev1.SecretKeySelector `json:"metricsTokenSecretRef,omitempty"`

	// MetricsRequireToken requires Bearer token authentication for the /metrics endpoint.
	// +optional
	MetricsRequireToken bool `json:"metricsRequireToken"`

	// TraceSink is the OpenTelemetry collector address for tracing.
	// +optional
	TraceSink string `json:"traceSink,omitempty"`
}

// DatabaseConfig configures the metadata database.
type DatabaseConfig struct {
	// Engine specifies the database engine to use.
	// +kubebuilder:validation:Enum=lmdb;sqlite;fjall
	// +kubebuilder:default="lmdb"
	// +optional
	Engine string `json:"engine,omitempty"`

	// LMDBMapSize is the virtual memory region size for LMDB.
	// +optional
	LMDBMapSize *resource.Quantity `json:"lmdbMapSize,omitempty"`

	// FjallBlockCacheSize is the block cache size for Fjall.
	// +optional
	FjallBlockCacheSize *resource.Quantity `json:"fjallBlockCacheSize,omitempty"`
}

// BlockConfig configures block storage settings.
type BlockConfig struct {
	// Size is the size of data blocks (default: 1M).
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// RAMBufferMax is the maximum RAM for buffering blocks.
	// +optional
	RAMBufferMax *resource.Quantity `json:"ramBufferMax,omitempty"`

	// MaxConcurrentReads is the maximum simultaneous block file reads.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentReads *int `json:"maxConcurrentReads,omitempty"`

	// MaxConcurrentWritesPerRequest is the maximum parallel block writes per PUT request.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentWritesPerRequest *int `json:"maxConcurrentWritesPerRequest,omitempty"`

	// CompressionLevel is the zstd compression level.
	// +kubebuilder:validation:Pattern=`^(none|-?[1-9][0-9]*)$`
	// +optional
	CompressionLevel *string `json:"compressionLevel,omitempty"`

	// DisableScrub disables automatic monthly data directory scrub.
	// +optional
	DisableScrub bool `json:"disableScrub"`

	// UseLocalTZ runs lifecycle worker at midnight in local timezone.
	// +optional
	UseLocalTZ bool `json:"useLocalTZ"`
}

// DiscoveryConfig configures peer discovery mechanisms.
type DiscoveryConfig struct {
	// Kubernetes configures Kubernetes-based peer discovery.
	// +optional
	Kubernetes *KubernetesDiscoveryConfig `json:"kubernetes,omitempty"`

	// Consul configures Consul-based peer discovery.
	// +optional
	Consul *ConsulDiscoveryConfig `json:"consul,omitempty"`
}

// KubernetesDiscoveryConfig configures Kubernetes peer discovery.
type KubernetesDiscoveryConfig struct {
	// Enabled enables Kubernetes-based discovery.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Namespace for Garage custom resources.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// ServiceName label to filter custom resources.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// SkipCRD skips automatic CRD creation/patching.
	// +optional
	SkipCRD bool `json:"skipCRD"`
}

// ConsulDiscoveryConfig configures Consul peer discovery.
type ConsulDiscoveryConfig struct {
	// Enabled enables Consul-based discovery.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// API specifies the service registration API.
	// +kubebuilder:validation:Enum=catalog;agent
	// +kubebuilder:default="catalog"
	// +optional
	API string `json:"api,omitempty"`

	// HTTPAddr is the full HTTP(S) address of Consul server.
	// +optional
	HTTPAddr string `json:"httpAddr,omitempty"`

	// ServiceName for Garage RPC port registration.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// CACert is the CA certificate for TLS connection.
	// +optional
	CACert string `json:"caCert,omitempty"`

	// CACertSecretRef references a secret containing the CA certificate.
	// +optional
	CACertSecretRef *corev1.SecretKeySelector `json:"caCertSecretRef,omitempty"`

	// ClientCertSecretRef references a secret containing client TLS cert.
	// +optional
	ClientCertSecretRef *corev1.SecretKeySelector `json:"clientCertSecretRef,omitempty"`

	// ClientKeySecretRef references a secret containing client TLS key.
	// +optional
	ClientKeySecretRef *corev1.SecretKeySelector `json:"clientKeySecretRef,omitempty"`

	// TokenSecretRef references a secret containing the bearer token.
	// +optional
	TokenSecretRef *corev1.SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// TLSSkipVerify skips TLS hostname verification.
	// +optional
	TLSSkipVerify bool `json:"tlsSkipVerify"`

	// Tags are additional service tags.
	// +optional
	Tags []string `json:"tags,omitempty"`

	// Meta is service metadata key-value pairs.
	// +optional
	Meta map[string]string `json:"meta,omitempty"`

	// Datacenters for WAN federation.
	// +optional
	Datacenters []string `json:"datacenters,omitempty"`
}

// SecurityConfig configures security settings.
type SecurityConfig struct {
	// AllowInsecureSecretPermissions bypasses Garage's check that secret files
	// are not world-readable on disk.
	// +optional
	AllowInsecureSecretPermissions bool `json:"allowInsecureSecretPermissions"`

	// AllowPunycode allows punycode in bucket names.
	// +optional
	AllowPunycode bool `json:"allowPunycode"`

	// TLS configures TLS settings.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`
}

// TLSConfig configures TLS settings for Garage inter-node RPC communication.
type TLSConfig struct {
	// Enabled enables TLS for inter-node RPC communication.
	// +optional
	Enabled bool `json:"enabled"`

	// CertSecretRef references a secret containing the TLS certificate for RPC.
	// +optional
	CertSecretRef *corev1.SecretKeySelector `json:"certSecretRef,omitempty"`

	// KeySecretRef references a secret containing the TLS private key for RPC.
	// +optional
	KeySecretRef *corev1.SecretKeySelector `json:"keySecretRef,omitempty"`

	// CASecretRef references a secret containing the CA certificate.
	// +optional
	CASecretRef *corev1.SecretKeySelector `json:"caSecretRef,omitempty"`
}

// LoggingConfig configures logging behavior for Garage nodes.
type LoggingConfig struct {
	// Level sets the log level using RUST_LOG format.
	// +optional
	Level string `json:"level,omitempty"`

	// Syslog enables logging to syslog.
	// +optional
	Syslog bool `json:"syslog"`

	// Journald enables logging to systemd journald.
	// +optional
	Journald bool `json:"journald"`
}

// PublicEndpointConfig defines how this cluster's nodes are exposed to remote clusters.
type PublicEndpointConfig struct {
	// Type specifies how nodes are exposed to remote clusters for RPC.
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort;ExternalIP;Headless
	// +required
	Type string `json:"type"`

	// LoadBalancer configuration.
	// +optional
	LoadBalancer *LoadBalancerEndpointConfig `json:"loadBalancer,omitempty"`

	// NodePort configuration.
	// +optional
	NodePort *NodePortEndpointConfig `json:"nodePort,omitempty"`

	// ExternalIP configuration.
	// +optional
	ExternalIP *ExternalIPEndpointConfig `json:"externalIP,omitempty"`
}

// LoadBalancerEndpointConfig for LoadBalancer exposure.
type LoadBalancerEndpointConfig struct {
	ServiceMeta `json:",inline"`

	// PerNode creates a separate LoadBalancer service per GarageCluster pod.
	// +optional
	PerNode bool `json:"perNode"`
}

// NodePortEndpointConfig for NodePort exposure.
type NodePortEndpointConfig struct {
	ServiceMeta `json:",inline"`

	// ExternalAddresses are the externally-reachable IPs or hostnames of the Kubernetes nodes.
	// +required
	ExternalAddresses []string `json:"externalAddresses"`

	// BasePort is the starting NodePort; Garage pod N is exposed on BasePort+N.
	// +kubebuilder:validation:Minimum=30000
	// +kubebuilder:validation:Maximum=32767
	// +optional
	BasePort int32 `json:"basePort,omitempty"`
}

// ExternalIPEndpointConfig for direct external IP exposure.
type ExternalIPEndpointConfig struct {
	// Addresses maps pod names to external IPs.
	// +optional
	Addresses map[string]string `json:"addresses,omitempty"`

	// AddressTemplate uses go template to generate addresses from pod info.
	// +optional
	AddressTemplate string `json:"addressTemplate,omitempty"`
}

// RemoteClusterConfig defines a Garage cluster in another Kubernetes cluster.
type RemoteClusterConfig struct {
	// Name is a friendly name for this remote cluster.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// Zone is the zone name for nodes in this remote cluster.
	// +kubebuilder:validation:MinLength=1
	// +required
	Zone string `json:"zone"`

	// Connection defines how to connect to this remote cluster.
	// +required
	Connection RemoteClusterConnection `json:"connection"`

	// DefaultCapacity is the default storage capacity to assign to remote nodes.
	// +optional
	DefaultCapacity *resource.Quantity `json:"defaultCapacity,omitempty"`
}

// RemoteClusterConnection defines how to connect to a remote cluster.
type RemoteClusterConnection struct {
	// AdminAPIEndpoint is the admin API endpoint of the remote cluster.
	// +kubebuilder:validation:MinLength=1
	// +required
	AdminAPIEndpoint string `json:"adminApiEndpoint"`

	// AdminTokenSecretRef references the admin token for the remote cluster's API.
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`

	// GatewayRPCEndpointTemplate is a hostname:port template used by federation
	// to connect to remote gateway pods individually. The literal `{ordinal}`
	// is replaced with each remote gateway pod's ordinal (0, 1, ...) parsed
	// from the layout role's pod-name tag (e.g. `garage-gateway-0`).
	//
	// Required when the remote cluster runs gateway pods that participate in
	// the cluster layout (default since v0.5.8). FullReplication tables
	// (key_table, bucket_table, ...) need quorum across all_nodes, which
	// includes remote gateways. Without this field the operator only peers
	// storage↔storage cross-region; remote gateways appear in layout but
	// remain unreachable, blocking GetKeyInfo / DeleteKey / FullReplication
	// writes that need full quorum.
	//
	// Example: "ottawa-garage-gw-{ordinal}.keiretsu.ts.net:3901"
	// +optional
	GatewayRPCEndpointTemplate string `json:"gatewayRpcEndpointTemplate,omitempty"`
}

// ConnectToConfig specifies how a gateway cluster connects to a remote storage cluster.
type ConnectToConfig struct {
	// ClusterRef references a GarageCluster in the same namespace.
	// +optional
	ClusterRef *ClusterReference `json:"clusterRef,omitempty"`

	// RPCSecretRef references a secret containing the shared RPC secret.
	// +optional
	RPCSecretRef *corev1.SecretKeySelector `json:"rpcSecretRef,omitempty"`

	// BootstrapPeers are initial peers for cluster formation.
	// +optional
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`

	// AdminAPIEndpoint is the storage cluster's Admin API URL.
	// +optional
	AdminAPIEndpoint string `json:"adminApiEndpoint,omitempty"`

	// AdminTokenSecretRef references the storage cluster's admin token.
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`
}

// LayoutManagementConfig controls cluster layout management.
type LayoutManagementConfig struct {
	// AutoApply automatically applies staged layout changes.
	// +optional
	AutoApply bool `json:"autoApply"`

	// MinNodesHealthy is the minimum healthy nodes required before applying layout changes.
	// +optional
	MinNodesHealthy int `json:"minNodesHealthy,omitempty"`
}

// GarageClusterStatus defines the observed state of GarageCluster.
type GarageClusterStatus struct {
	// Phase represents the current phase of the cluster.
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Ready;Degraded;Updating;Deleting;Failed;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// Replicas is the total number of Garage pods targeted by this cluster
	// (storage + gateway tiers combined).
	Replicas int32 `json:"replicas"`

	// Selector is the serialized label selector for pods managed by this cluster.
	Selector string `json:"selector"`

	// ClusterID is the unique identifier of the Garage cluster.
	// +optional
	ClusterID string `json:"clusterId,omitempty"`

	// BuildInfo contains Garage build information.
	// +optional
	BuildInfo *GarageBuildInfo `json:"buildInfo,omitempty"`

	// ReadyReplicas is the number of ready Garage pods.
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// StorageReplicas is the desired storage-tier replica count.
	// +optional
	StorageReplicas int32 `json:"storageReplicas,omitempty"`

	// StorageReadyReplicas is the number of ready storage-tier pods.
	// +optional
	StorageReadyReplicas int32 `json:"storageReadyReplicas,omitempty"`

	// GatewayReplicas is the desired gateway-tier replica count.
	// +optional
	GatewayReplicas int32 `json:"gatewayReplicas,omitempty"`

	// GatewayReadyReplicas is the number of ready gateway-tier pods.
	// +optional
	GatewayReadyReplicas int32 `json:"gatewayReadyReplicas,omitempty"`

	// Nodes contains status information for each node.
	// +optional
	Nodes []NodeStatus `json:"nodes,omitempty"`

	// LayoutVersion is the current layout version.
	// +optional
	LayoutVersion int64 `json:"layoutVersion,omitempty"`

	// StagedLayoutVersion is the staged layout version pending application.
	// +optional
	StagedLayoutVersion *int64 `json:"stagedLayoutVersion,omitempty"`

	// StagedRoles is the number of roles in the staged layout.
	// +optional
	StagedRoles int32 `json:"stagedRoles,omitempty"`

	// LayoutPreview shows what would change if staged layout is applied.
	// +optional
	LayoutPreview *LayoutPreviewStatus `json:"layoutPreview,omitempty"`

	// Health contains cluster health information.
	// +optional
	Health *ClusterHealth `json:"health,omitempty"`

	// StorageStats contains cluster-wide storage statistics.
	// +optional
	StorageStats *ClusterStorageStats `json:"storageStats,omitempty"`

	// ActiveRepairs contains currently running repair operations.
	// +optional
	ActiveRepairs []RepairStatus `json:"activeRepairs,omitempty"`

	// WorkerCount is the total number of background workers.
	// +optional
	WorkerCount int32 `json:"workerCount,omitempty"`

	// WorkersFailed is the number of failed workers.
	// +optional
	WorkersFailed int32 `json:"workersFailed,omitempty"`

	// Workers contains detailed information about background workers.
	// +optional
	Workers *WorkersStatus `json:"workers,omitempty"`

	// LayoutHistory contains layout version history.
	// +optional
	LayoutHistory *LayoutHistoryStatus `json:"layoutHistory,omitempty"`

	// BlockErrors is the count of blocks with sync errors across all nodes.
	// +optional
	BlockErrors int32 `json:"blockErrors,omitempty"`

	// BlockErrorDetails provides detailed information about block errors.
	// +optional
	BlockErrorDetails *BlockErrorsStatus `json:"blockErrorDetails,omitempty"`

	// ResyncQueueLength is the total block resync queue depth across all nodes.
	// +optional
	ResyncQueueLength int64 `json:"resyncQueueLength,omitempty"`

	// ScrubStatus contains the status of data scrub operations.
	// +optional
	ScrubStatus *ScrubStatus `json:"scrubStatus,omitempty"`

	// LifecycleStatus contains the status of bucket lifecycle operations.
	// +optional
	LifecycleStatus *LifecycleStatus `json:"lifecycleStatus,omitempty"`

	// LastOperation records the result of the most recently triggered operational annotation.
	// +optional
	LastOperation *LastOperationStatus `json:"lastOperation,omitempty"`

	// Endpoints contains service endpoints.
	// +optional
	Endpoints *ClusterEndpoints `json:"endpoints,omitempty"`

	// RemoteClusters contains status of remote clusters in the federation.
	// +optional
	RemoteClusters []RemoteClusterStatus `json:"remoteClusters,omitempty"`

	// TotalNodes is the total nodes across all clusters (local + remote).
	// +optional
	TotalNodes int `json:"totalNodes,omitempty"`

	// DrainingNodes is the count of nodes that are draining data from an older layout version.
	// +optional
	DrainingNodes int `json:"drainingNodes,omitempty"`

	// PendingGatewayTombstones lists stale gateway layout entries pending removal.
	// Populated when gateway tombstone cleanup detects orphaned entries but cannot
	// remove them automatically (e.g. layoutManagement.autoApply is false).
	// +optional
	PendingGatewayTombstones []string `json:"pendingGatewayTombstones,omitempty"`

	// LayoutDiagnosis is a one-line, human-readable summary of the most severe
	// active health condition (quorum at risk, remote clusters stale, federation
	// misconfigured). Empty when the cluster is healthy. Surfaced as a printcolumn
	// so `kubectl get gc` shows the actionable problem at a glance.
	// +optional
	LayoutDiagnosis string `json:"layoutDiagnosis,omitempty"`

	// FactorMigration tracks an in-flight coordinated replication-factor migration
	// (the garage.rajsingh.info/purge-cluster-layout operation). Nil when no
	// migration has run.
	// +optional
	FactorMigration *FactorMigrationStatus `json:"factorMigration,omitempty"`

	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state of the cluster.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// WorkersStatus contains detailed information about background workers.
type WorkersStatus struct {
	// Total is the total number of background workers.
	// +optional
	Total int32 `json:"total,omitempty"`

	// Busy is the number of busy/active workers.
	// +optional
	Busy int32 `json:"busy,omitempty"`

	// Idle is the number of idle workers.
	// +optional
	Idle int32 `json:"idle,omitempty"`

	// Errored is the number of workers with errors.
	// +optional
	Errored int32 `json:"errored,omitempty"`

	// Errors contains details about worker errors.
	// +optional
	Errors []WorkerError `json:"errors,omitempty"`

	// Variables contains runtime worker configuration variables.
	// +optional
	Variables map[string]string `json:"variables,omitempty"`
}

// WorkerError contains information about a worker error.
type WorkerError struct {
	// WorkerID is the worker identifier.
	// +optional
	WorkerID int64 `json:"workerId,omitempty"`

	// Name is the worker name.
	// +optional
	Name string `json:"name,omitempty"`

	// ConsecutiveErrors is the count of consecutive errors.
	// +optional
	ConsecutiveErrors int32 `json:"consecutiveErrors,omitempty"`

	// LastError is the last error message.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastErrorSecsAgo is seconds since the last error.
	// +optional
	LastErrorSecsAgo int64 `json:"lastErrorSecsAgo,omitempty"`
}

// LayoutHistoryStatus contains layout version history information.
type LayoutHistoryStatus struct {
	// CurrentVersion is the current layout version.
	// +optional
	CurrentVersion int64 `json:"currentVersion,omitempty"`

	// MinAck is the minimum acknowledged layout version by all nodes.
	// +optional
	MinAck int64 `json:"minAck,omitempty"`

	// Versions contains the history of layout versions.
	// +optional
	Versions []LayoutVersionInfo `json:"versions,omitempty"`
}

// LayoutVersionInfo contains information about a layout version.
type LayoutVersionInfo struct {
	// Version is the layout version number.
	// +optional
	Version int64 `json:"version,omitempty"`

	// Status is the version status (Current, Draining, Historical).
	// +optional
	Status string `json:"status,omitempty"`

	// StorageNodes is the number of storage nodes in this version.
	// +optional
	StorageNodes int `json:"storageNodes,omitempty"`

	// GatewayNodes is the number of gateway nodes in this version.
	// +optional
	GatewayNodes int `json:"gatewayNodes,omitempty"`
}

// LayoutPreviewStatus shows what would change if staged layout changes are applied.
type LayoutPreviewStatus struct {
	// NodesAdded shows node IDs that would be added to the layout.
	// +optional
	NodesAdded []string `json:"nodesAdded,omitempty"`

	// NodesRemoved shows node IDs that would be removed from the layout.
	// +optional
	NodesRemoved []string `json:"nodesRemoved,omitempty"`

	// NodesModified shows node IDs with changed configuration.
	// +optional
	NodesModified []string `json:"nodesModified,omitempty"`

	// ZonesAffected shows which zones would be affected by the changes.
	// +optional
	ZonesAffected []string `json:"zonesAffected,omitempty"`

	// PartitionTransfers is the estimated number of partition transfers.
	// +optional
	PartitionTransfers int32 `json:"partitionTransfers,omitempty"`

	// DataTransferEstimate is a human-readable estimate of data movement.
	// +optional
	DataTransferEstimate string `json:"dataTransferEstimate,omitempty"`
}

// BlockErrorsStatus provides detailed information about block sync errors.
type BlockErrorsStatus struct {
	// Count is the total number of blocks with errors.
	// +optional
	Count int32 `json:"count,omitempty"`

	// LastErrorAt is when the most recent block error occurred.
	// +optional
	LastErrorAt *metav1.Time `json:"lastErrorAt,omitempty"`

	// TopErrors contains details about the most problematic blocks.
	// +optional
	TopErrors []BlockErrorDetail `json:"topErrors,omitempty"`
}

// BlockErrorDetail contains information about a specific block error.
type BlockErrorDetail struct {
	// BlockHash is the hash of the affected block.
	// +optional
	BlockHash string `json:"blockHash,omitempty"`

	// ErrorCount is the number of times this block failed to sync.
	// +optional
	ErrorCount int32 `json:"errorCount,omitempty"`

	// LastError is the most recent error message for this block.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastAttempt is when the last sync attempt occurred.
	// +optional
	LastAttempt *metav1.Time `json:"lastAttempt,omitempty"`

	// NextRetry is when the next sync retry is scheduled.
	// +optional
	NextRetry *metav1.Time `json:"nextRetry,omitempty"`
}

// ClusterStorageStats contains cluster-wide storage statistics.
type ClusterStorageStats struct {
	// TotalCapacity is the total storage capacity across all nodes.
	// +optional
	TotalCapacity *resource.Quantity `json:"totalCapacity,omitempty"`

	// UsedCapacity is the used storage across all nodes.
	// +optional
	UsedCapacity *resource.Quantity `json:"usedCapacity,omitempty"`

	// AvailableCapacity is the available storage across all nodes.
	// +optional
	AvailableCapacity *resource.Quantity `json:"availableCapacity,omitempty"`

	// TotalPartitions is the total number of partitions in the layout.
	// +optional
	TotalPartitions int32 `json:"totalPartitions,omitempty"`

	// HealthyPartitions is the number of partitions with full redundancy.
	// +optional
	HealthyPartitions int32 `json:"healthyPartitions,omitempty"`
}

// RepairStatus contains status of a repair operation.
type RepairStatus struct {
	// Type is the repair operation type (Tables, Blocks, Scrub, Rebalance, etc.)
	// +optional
	Type string `json:"type,omitempty"`

	// NodeID is the node running this repair.
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Progress is a human-readable progress description.
	// +optional
	Progress string `json:"progress,omitempty"`

	// StartedAt is when the repair started.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
}

// ScrubStatus contains the status of data scrub operations across the cluster.
type ScrubStatus struct {
	// Running indicates if a scrub is currently running on any node.
	// +optional
	Running bool `json:"running"`

	// Paused indicates if the scrub is paused.
	// +optional
	Paused bool `json:"paused"`

	// Progress is a human-readable progress description.
	// +optional
	Progress string `json:"progress,omitempty"`

	// TranquilityLevel is the current tranquility setting.
	// +optional
	TranquilityLevel int `json:"tranquilityLevel,omitempty"`

	// LastCompleted is when the last scrub completed.
	// +optional
	LastCompleted *metav1.Time `json:"lastCompleted,omitempty"`

	// NextRun is when the next scrub is scheduled to run.
	// +optional
	NextRun *metav1.Time `json:"nextRun,omitempty"`

	// CorruptedBlocks is the number of corrupted blocks found in the last scrub.
	// +optional
	CorruptedBlocks int32 `json:"corruptedBlocks,omitempty"`

	// NodeStatuses contains per-node scrub status.
	// +optional
	NodeStatuses []NodeScrubStatus `json:"nodeStatuses,omitempty"`
}

// NodeScrubStatus contains scrub status for a single node.
type NodeScrubStatus struct {
	// NodeID is the node identifier.
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Running indicates if scrub is running on this node.
	// +optional
	Running bool `json:"running"`

	// Progress percentage (0-100).
	// +optional
	Progress int `json:"progress,omitempty"`

	// ItemsChecked is the number of items checked.
	// +optional
	ItemsChecked int64 `json:"itemsChecked,omitempty"`

	// ErrorsFound is the number of errors found on this node.
	// +optional
	ErrorsFound int32 `json:"errorsFound,omitempty"`
}

// LastOperationStatus records the result of the most recently triggered operational annotation.
type LastOperationStatus struct {
	// Type is the operation type.
	// +optional
	Type string `json:"type,omitempty"`

	// TriggeredAt is when the operation was triggered.
	// +optional
	TriggeredAt *metav1.Time `json:"triggeredAt,omitempty"`

	// Succeeded indicates the operation completed without error.
	// +optional
	Succeeded bool `json:"succeeded"`

	// Error contains the error message when Succeeded is false.
	// +optional
	Error string `json:"error,omitempty"`
}

// LifecycleStatus contains the status of bucket lifecycle operations.
type LifecycleStatus struct {
	// LastCompleted is when the last lifecycle worker run completed.
	// +optional
	LastCompleted *metav1.Time `json:"lastCompleted,omitempty"`
}

// FactorMigrationStatus records the progress of a coordinated replication-factor
// migration (the garage.rajsingh.info/purge-cluster-layout operation). The
// operation is a resumable state machine — Phase advances one step per reconcile
// until Completed or Failed.
type FactorMigrationStatus struct {
	// Phase is the current migration phase.
	// +kubebuilder:validation:Enum=Validating;ScalingDown;Purging;Verifying;RebuildingLayout;Converging;Completed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// FromFactor is the replication factor before the migration.
	// +optional
	FromFactor int `json:"fromFactor,omitempty"`

	// ToFactor is the target replication factor.
	// +optional
	ToFactor int `json:"toFactor,omitempty"`

	// PurgeID uniquely identifies this migration; it is the marker-file suffix the
	// per-node init container uses so the on-disk cluster_layout is deleted exactly
	// once even across extra restarts.
	// +optional
	PurgeID string `json:"purgeId,omitempty"`

	// StartedAt is when the migration began.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CompletedAt is when the migration finished (Completed or Failed).
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// Message is a human-readable description of the current phase or failure.
	// +optional
	Message string `json:"message,omitempty"`
}

// RemoteClusterStatus is the status of a remote cluster.
type RemoteClusterStatus struct {
	// Name is the cluster name.
	// +optional
	Name string `json:"name,omitempty"`

	// Zone is the cluster's zone.
	// +optional
	Zone string `json:"zone,omitempty"`

	// Nodes is the number of nodes in this cluster.
	// +optional
	Nodes int `json:"nodes,omitempty"`

	// HealthyNodes is the number of healthy nodes.
	// +optional
	HealthyNodes int `json:"healthyNodes,omitempty"`

	// Connected indicates if we can reach this cluster.
	// +optional
	Connected bool `json:"connected"`

	// LastSeen is when we last successfully connected.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
}

// NodeStatus contains status information for a Garage node.
type NodeStatus struct {
	// NodeID is the public key of the node.
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// PodName is the name of the pod running this node.
	// +optional
	PodName string `json:"podName,omitempty"`

	// Tier is "storage" or "gateway" depending on which tier this node belongs to.
	// +optional
	Tier string `json:"tier,omitempty"`

	// Zone is the zone assignment of the node.
	// +optional
	Zone string `json:"zone,omitempty"`

	// Capacity is the storage capacity of the node.
	// +optional
	Capacity *resource.Quantity `json:"capacity,omitempty"`

	// Gateway indicates if the node is gateway-only.
	// +optional
	Gateway bool `json:"gateway"`

	// Connected indicates if the node is connected to the cluster.
	// +optional
	Connected bool `json:"connected"`

	// DataDiskAvailable is the available space on data disk.
	// +optional
	DataDiskAvailable *resource.Quantity `json:"dataDiskAvailable,omitempty"`

	// DataDiskTotal is the total space on data disk.
	// +optional
	DataDiskTotal *resource.Quantity `json:"dataDiskTotal,omitempty"`

	// MetadataDiskAvailable is the available space on metadata disk.
	// +optional
	MetadataDiskAvailable *resource.Quantity `json:"metadataDiskAvailable,omitempty"`

	// MetadataDiskTotal is the total space on metadata disk.
	// +optional
	MetadataDiskTotal *resource.Quantity `json:"metadataDiskTotal,omitempty"`

	// Version is the Garage version running on this node.
	// +optional
	Version string `json:"version,omitempty"`
}

// ClusterHealth contains cluster health information.
type ClusterHealth struct {
	// Status is the overall cluster status.
	// +optional
	Status string `json:"status,omitempty"`

	// Healthy indicates if all nodes are connected.
	// +optional
	Healthy bool `json:"healthy"`

	// Available indicates if quorum is available.
	// +optional
	Available bool `json:"available"`

	// KnownNodes is the number of nodes seen in cluster.
	// +optional
	KnownNodes int `json:"knownNodes,omitempty"`

	// ConnectedNodes is the number of currently connected nodes.
	// +optional
	ConnectedNodes int `json:"connectedNodes,omitempty"`

	// StorageNodes is the number of storage nodes in layout.
	// +optional
	StorageNodes int `json:"storageNodes,omitempty"`

	// StorageNodesOK is the number of connected storage nodes.
	// +optional
	StorageNodesOK int `json:"storageNodesOk,omitempty"`

	// Partitions is the total partitions in layout.
	// +optional
	Partitions int `json:"partitions,omitempty"`

	// PartitionsQuorum is partitions with quorum connectivity.
	// +optional
	PartitionsQuorum int `json:"partitionsQuorum,omitempty"`

	// PartitionsAllOK is partitions with all nodes connected.
	// +optional
	PartitionsAllOK int `json:"partitionsAllOk,omitempty"`
}

// ClusterEndpoints contains service endpoint information.
type ClusterEndpoints struct {
	// S3 is the S3 API endpoint.
	// +optional
	S3 string `json:"s3,omitempty"`

	// K2V is the K2V API endpoint.
	// +optional
	K2V string `json:"k2v,omitempty"`

	// Web is the web hosting endpoint.
	// +optional
	Web string `json:"web,omitempty"`

	// Admin is the admin API endpoint.
	// +optional
	Admin string `json:"admin,omitempty"`

	// Metrics is the Prometheus metrics endpoint.
	// +optional
	Metrics string `json:"metrics,omitempty"`

	// RPC is the internal RPC endpoint.
	// +optional
	RPC string `json:"rpc,omitempty"`
}

// GarageBuildInfo contains Garage version and build information.
type GarageBuildInfo struct {
	// Version is the Garage version string.
	// +optional
	Version string `json:"version,omitempty"`

	// RustVersion is the Rust compiler version used to build Garage.
	// +optional
	RustVersion string `json:"rustVersion,omitempty"`

	// Features lists enabled Cargo features.
	// +optional
	Features []string `json:"features,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:subresource:scale:specpath=.spec.storage.replicas,statuspath=.status.storageReplicas,selectorpath=.status.selector
// +kubebuilder:resource:shortName=gc
// +kubebuilder:printcolumn:name="Storage",type="integer",JSONPath=".status.storageReplicas"
// +kubebuilder:printcolumn:name="Gateway",type="integer",JSONPath=".status.gatewayReplicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Zone",type="string",JSONPath=".spec.zone"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Diagnosis",type="string",JSONPath=".status.layoutDiagnosis",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageCluster is the Schema for the garageclusters API.
type GarageCluster struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageClusterSpec `json:"spec"`

	// +optional
	Status GarageClusterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageClusterList contains a list of GarageCluster.
type GarageClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageCluster{}, &GarageClusterList{})
}
