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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageClusterSpec defines the desired state of GarageCluster
type GarageClusterSpec struct {
	// Image specifies the Garage container image to use
	// +kubebuilder:default="dxflrs/garage:v2.1.0"
	// +optional
	Image string `json:"image,omitempty"`

	// ImagePullPolicy specifies the image pull policy
	// +kubebuilder:default="IfNotPresent"
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets specifies secrets for pulling images from private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Replicas is the number of Garage nodes to deploy in this cluster
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas"`

	// Replication configures data replication settings
	// +required
	Replication ReplicationConfig `json:"replication"`

	// Storage configures storage settings for metadata and data
	// +required
	Storage StorageConfig `json:"storage"`

	// Network configures RPC and API networking
	// +required
	Network NetworkConfig `json:"network"`

	// S3API configures the S3-compatible API endpoint
	// +optional
	S3API *S3APIConfig `json:"s3Api,omitempty"`

	// K2VAPI configures the K2V (key-value) API endpoint
	// +optional
	K2VAPI *K2VAPIConfig `json:"k2vApi,omitempty"`

	// WebAPI configures the static website hosting endpoint
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

	// Resources specifies compute resources for Garage pods
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector for pod scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for pod scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity for pod scheduling
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// PodAnnotations to add to Garage pods
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// PodLabels to add to Garage pods
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// ServiceAnnotations to add to Garage services
	// +optional
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`

	// PriorityClassName for Garage pods
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// ServiceAccountName for Garage pods
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// SecurityContext for Garage pods
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// ContainerSecurityContext for Garage containers
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// TopologySpreadConstraints for pod scheduling
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Zone is the zone name for all nodes in this cluster.
	// Used for fault tolerance - Garage distributes replicas across zones.
	// Required for multi-cluster federation.
	//
	// Examples: "us-east-1", "rack-a", "dc1", "zone-a"
	// +optional
	Zone string `json:"zone,omitempty"`

	// PublicEndpoint configures how remote clusters reach this cluster's nodes
	// Required for multi-cluster federation
	// +optional
	PublicEndpoint *PublicEndpointConfig `json:"publicEndpoint,omitempty"`

	// RemoteClusters are Garage clusters in other Kubernetes clusters
	// The operator will auto-discover nodes and coordinate layout
	// +optional
	RemoteClusters []RemoteClusterConfig `json:"remoteClusters,omitempty"`

	// LayoutManagement controls how the cluster layout is managed
	// +optional
	LayoutManagement *LayoutManagementConfig `json:"layoutManagement,omitempty"`

	// LayoutPolicy controls whether node layouts are automatically managed or manually configured.
	// - "Auto": The controller automatically assigns all local pods to the layout using the
	//   cluster's zone and derives capacity from data PVC size. No GarageNode resources needed.
	// - "Manual": You must create GarageNode resources for each node you want in the layout.
	//   Use this for fine-grained control over zones, capacities, or external nodes.
	// +kubebuilder:validation:Enum=Auto;Manual
	// +kubebuilder:default="Auto"
	// +optional
	LayoutPolicy string `json:"layoutPolicy,omitempty"`

	// DefaultNodeTags are tags applied to all auto-managed nodes.
	// Only used when LayoutPolicy is "Auto".
	// For per-node tags, use LayoutPolicy "Manual" with GarageNode resources.
	// +optional
	DefaultNodeTags []string `json:"defaultNodeTags,omitempty"`

	// CapacityReservePercent reserves a percentage of PVC capacity for overhead.
	// Only used when LayoutPolicy is "Auto".
	// For example, setting this to 10 will report 90% of PVC size as node capacity.
	// This is useful to reserve headroom for filesystem overhead, snapshots, or growth.
	// Default: 0 (use full PVC size as capacity)
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=50
	// +optional
	CapacityReservePercent int `json:"capacityReservePercent,omitempty"`

	// PodDisruptionBudget configures the PodDisruptionBudget for the cluster
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetConfig `json:"podDisruptionBudget,omitempty"`

	// Workers configures background worker settings
	// These settings tune the behavior of Garage's background workers for scrubbing,
	// block resyncing, and other maintenance tasks
	// +optional
	Workers *WorkerConfig `json:"workers,omitempty"`
}

// WorkerConfig configures Garage background worker behavior
// These are applied via the Admin API SetWorkerVariable endpoint
type WorkerConfig struct {
	// ScrubTranquility sets the tranquility level for scrub operations
	// Higher values make scrub less aggressive (slower but less impact on performance)
	// Range: 0-1000, Default: 2
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +optional
	ScrubTranquility *int `json:"scrubTranquility,omitempty"`

	// ResyncTranquility sets the tranquility level for block resync operations
	// Higher values make resync less aggressive
	// Range: 0-1000, Default: 2
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +optional
	ResyncTranquility *int `json:"resyncTranquility,omitempty"`

	// ResyncWorkerCount sets the number of concurrent block resync workers
	// More workers = faster resync but higher resource usage
	// Default: 8
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	// +optional
	ResyncWorkerCount *int `json:"resyncWorkerCount,omitempty"`
}

// PodDisruptionBudgetConfig configures PodDisruptionBudget for Garage pods
type PodDisruptionBudgetConfig struct {
	// Enabled enables PodDisruptionBudget creation
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// MinAvailable specifies the minimum number of pods that must be available
	// Can be an absolute number (e.g., 2) or a percentage (e.g., "50%")
	// Mutually exclusive with MaxUnavailable
	// +optional
	MinAvailable *string `json:"minAvailable,omitempty"`

	// MaxUnavailable specifies the maximum number of pods that can be unavailable
	// Can be an absolute number (e.g., 1) or a percentage (e.g., "25%")
	// Mutually exclusive with MinAvailable
	// +optional
	MaxUnavailable *string `json:"maxUnavailable,omitempty"`
}

// ReplicationConfig configures data replication
type ReplicationConfig struct {
	// Factor is the replication factor (1, 2, 3, 5, 7, etc.)
	// Must be the same on all nodes in the cluster
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=7
	// +kubebuilder:default=3
	Factor int `json:"factor"`

	// ConsistencyMode controls quorum behavior for read/write operations.
	//
	// Values:
	// - "consistent" (default): Require quorum for both reads and writes.
	//   Safest option, ensures strong consistency.
	// - "degraded": Allow reads from single node when quorum unavailable.
	//   May return stale data during network partitions.
	// - "dangerous": Allow reads AND writes without quorum.
	//   WARNING: May lose data during failures!
	// +kubebuilder:validation:Enum=consistent;degraded;dangerous
	// +kubebuilder:default="consistent"
	// +optional
	ConsistencyMode string `json:"consistencyMode,omitempty"`

	// ZoneRedundancy controls how data is distributed across zones.
	//
	// Values:
	// - "Maximum": Maximize redundancy by placing replicas in as many zones as possible
	// - "AtLeast(n)": Require replicas to be in at least n different zones
	//
	// The value n must not exceed the replication factor.
	//
	// Examples:
	// - "Maximum" (default): Best effort zone distribution
	// - "AtLeast(1)": No zone constraint (all replicas can be in one zone)
	// - "AtLeast(2)": Survives 1 zone failure (requires 2+ zones)
	// - "AtLeast(3)": Survives 2 zone failures (requires 3+ zones)
	// +kubebuilder:validation:Pattern=`^(Maximum|AtLeast\([1-7]\))$`
	// +optional
	ZoneRedundancy string `json:"zoneRedundancy,omitempty"`
}

// StorageConfig configures storage for metadata and data
type StorageConfig struct {
	// MetadataSize is a shorthand for specifying metadata volume size
	// Use this for simple deployments. For advanced configuration, use Metadata.
	// +optional
	MetadataSize *resource.Quantity `json:"metadataSize,omitempty"`

	// MetadataStorageClassName is a shorthand for the metadata storage class
	// +optional
	MetadataStorageClassName *string `json:"metadataStorageClassName,omitempty"`

	// MetadataStorage configures metadata storage with full customization
	// Overrides MetadataSize/MetadataStorageClassName if specified
	// +optional
	MetadataStorage *VolumeConfig `json:"metadata,omitempty"`

	// DataSize is a shorthand for specifying data volume size
	// Use this for simple deployments. For advanced configuration, use Data.
	// +optional
	DataSize *resource.Quantity `json:"dataSize,omitempty"`

	// DataStorageClassName is a shorthand for the data storage class
	// +optional
	DataStorageClassName *string `json:"dataStorageClassName,omitempty"`

	// DataStorage configures data block storage with full customization
	// Overrides DataSize/DataStorageClassName if specified
	// +optional
	DataStorage *DataStorageConfig `json:"data,omitempty"`

	// MetadataSnapshotsDir specifies directory for metadata snapshots
	// +optional
	MetadataSnapshotsDir string `json:"metadataSnapshotsDir,omitempty"`

	// MetadataAutoSnapshotInterval enables automatic metadata snapshots
	// Format: "6h", "1d", etc.
	// +optional
	MetadataAutoSnapshotInterval string `json:"metadataAutoSnapshotInterval,omitempty"`

	// MetadataFsync enables fsync for metadata transactions
	// +optional
	MetadataFsync bool `json:"metadataFsync,omitempty"`

	// DataFsync enables fsync for data block writes
	// +optional
	DataFsync bool `json:"dataFsync,omitempty"`
}

// VolumeConfig configures a persistent volume
type VolumeConfig struct {
	// Size of the volume
	// +required
	Size resource.Quantity `json:"size"`

	// StorageClassName for the PVC
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// AccessModes for the PVC
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Selector to select PVs
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// ExistingClaim uses an existing PVC instead of creating a new one
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// VolumeClaimTemplateSpec allows full customization of the PVC
	// +optional
	VolumeClaimTemplateSpec *corev1.PersistentVolumeClaimSpec `json:"volumeClaimTemplateSpec,omitempty"`
}

// DataStorageConfig configures data storage with multiple paths support
type DataStorageConfig struct {
	// Size is a shorthand for specifying data volume size (creates a simple PVC)
	// Use this for simple deployments. For advanced configuration, use Volume.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// StorageClassName is a shorthand for specifying the storage class (used with Size)
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Paths specifies multiple data directories with capacities
	// For advanced multi-disk configurations
	// +optional
	Paths []DataPath `json:"paths,omitempty"`

	// Volume uses a single PVC for data storage with full customization
	// Overrides Size/StorageClassName if specified
	// +optional
	Volume *VolumeConfig `json:"volume,omitempty"`
}

// DataPath specifies a data directory with capacity
type DataPath struct {
	// Path to the data directory
	// +required
	Path string `json:"path"`

	// Capacity of the drive (required unless readOnly)
	// +optional
	Capacity *resource.Quantity `json:"capacity,omitempty"`

	// ReadOnly marks directory as legacy read-only for migrations
	// +optional
	ReadOnly bool `json:"readOnly,omitempty"`

	// Volume configuration if using PVC
	// +optional
	Volume *VolumeConfig `json:"volume,omitempty"`
}

// NetworkConfig configures RPC and networking
type NetworkConfig struct {
	// RPCBindPort is the port for inter-cluster RPC
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3901
	RPCBindPort int32 `json:"rpcBindPort,omitempty"`

	// RPCPublicAddr is the external address for other nodes to contact this node
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`

	// RPCPublicAddrSubnet filters autodiscovered IPs to specific subnet
	// +optional
	RPCPublicAddrSubnet string `json:"rpcPublicAddrSubnet,omitempty"`

	// RPCBindOutgoing pre-binds outgoing sockets to same IP
	// +optional
	RPCBindOutgoing bool `json:"rpcBindOutgoing,omitempty"`

	// RPCSecret is a reference to a secret containing the RPC secret
	// The secret must have a key 'rpc-secret' with a 32-byte hex-encoded value
	// +optional
	RPCSecretRef *corev1.SecretKeySelector `json:"rpcSecretRef,omitempty"`

	// RPCPingTimeoutMs sets the RPC ping timeout in milliseconds
	// +optional
	RPCPingTimeoutMs *int64 `json:"rpcPingTimeoutMs,omitempty"`

	// RPCTimeoutMs sets the RPC call timeout in milliseconds
	// +optional
	RPCTimeoutMs *int64 `json:"rpcTimeoutMs,omitempty"`

	// BootstrapPeers lists initial peers for cluster formation.
	//
	// Format: "<node_public_key>@<ip_or_hostname>:<port>"
	//
	// Example:
	// - "563e1ac825ee3323aa441e72c26d1030d6d4414aeb3dd25287c531e7fc2bc95d@10.0.0.1:3901"
	// - "ec79480e0ce52ae26fd00c9da684e4fa56f77571b9b8560382f859930e63571d@garage-2.example.com:3901"
	// +optional
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`

	// Service configures the Kubernetes Service for the cluster
	// +optional
	Service *ServiceConfig `json:"service,omitempty"`

	// Ingress configures Ingress for the S3 API
	// +optional
	Ingress *IngressConfig `json:"ingress,omitempty"`
}

// ServiceConfig configures Kubernetes Service
type ServiceConfig struct {
	// Type of service
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	// +kubebuilder:default="ClusterIP"
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`

	// Annotations for the service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// LoadBalancerIP for LoadBalancer type
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// LoadBalancerSourceRanges for LoadBalancer type
	// +optional
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// ExternalTrafficPolicy for LoadBalancer/NodePort
	// +optional
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`
}

// IngressConfig configures Kubernetes Ingress
type IngressConfig struct {
	// Enabled enables ingress creation
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// IngressClassName specifies the ingress class
	// +optional
	IngressClassName *string `json:"ingressClassName,omitempty"`

	// Annotations for the ingress
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Hosts for the ingress
	// +optional
	Hosts []IngressHost `json:"hosts,omitempty"`

	// TLS configuration
	// +optional
	TLS []IngressTLS `json:"tls,omitempty"`
}

// IngressHost configures a host for ingress
type IngressHost struct {
	// Host is the FQDN
	// +required
	Host string `json:"host"`

	// Paths for this host
	// +optional
	Paths []IngressPath `json:"paths,omitempty"`
}

// IngressPath configures a path for ingress
type IngressPath struct {
	// Path is the URL path
	// +kubebuilder:default="/"
	// +optional
	Path string `json:"path,omitempty"`

	// PathType specifies the path matching type
	// +kubebuilder:validation:Enum=Exact;Prefix;ImplementationSpecific
	// +kubebuilder:default="Prefix"
	// +optional
	PathType string `json:"pathType,omitempty"`
}

// IngressTLS configures TLS for ingress
type IngressTLS struct {
	// Hosts covered by this TLS certificate
	// +optional
	Hosts []string `json:"hosts,omitempty"`

	// SecretName containing the TLS certificate
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// S3APIConfig configures the S3-compatible API
type S3APIConfig struct {
	// Enabled enables the S3 API
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// BindPort is the port to bind for S3 API
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3900
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the S3 API.
	// Can be a TCP address (e.g., "0.0.0.0:3900", "[::]:3900") or
	// a Unix socket path (e.g., "unix:///run/garage/s3.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// Region is the AWS S3 region name to use
	// +kubebuilder:default="garage"
	Region string `json:"region"`

	// RootDomain is the root domain suffix for vhost-style S3 access.
	// When set, buckets can be accessed via <bucket-name>.<root-domain>.
	//
	// Examples:
	// - ".s3.garage.tld" -> Access bucket "mybucket" at "mybucket.s3.garage.tld"
	// - ".s3.example.com" -> Access bucket "data" at "data.s3.example.com"
	//
	// Note: Include the leading dot.
	// +optional
	RootDomain string `json:"rootDomain,omitempty"`
}

// K2VAPIConfig configures the K2V (key-value) API
type K2VAPIConfig struct {
	// Enabled enables the K2V API
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// BindPort is the port to bind for K2V API
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3904
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the K2V API.
	// Can be a TCP address or Unix socket path (e.g., "unix:///run/garage/k2v.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`
}

// WebAPIConfig configures static website hosting
type WebAPIConfig struct {
	// Enabled enables static website hosting
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// BindPort is the port to bind for web serving
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3902
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the Web API.
	// Can be a TCP address or Unix socket path (e.g., "unix:///run/garage/web.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// RootDomain is the root domain suffix for bucket website access.
	// When set, bucket websites are accessible via <bucket-name>.<root-domain>.
	//
	// Examples:
	// - ".web.garage.tld" -> Access bucket "site" website at "site.web.garage.tld"
	// - ".sites.example.com" -> Access bucket "blog" at "blog.sites.example.com"
	//
	// Note: Include the leading dot.
	// +optional
	RootDomain string `json:"rootDomain,omitempty"`

	// AddHostToMetrics adds the domain name to metrics labels for per-domain tracking.
	// +optional
	AddHostToMetrics bool `json:"addHostToMetrics,omitempty"`
}

// AdminConfig configures the admin API and metrics
type AdminConfig struct {
	// Enabled enables the admin API
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// BindPort is the port to bind for admin API
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3903
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom bind address for the Admin API.
	// Can be a TCP address or Unix socket path (e.g., "unix:///run/garage/admin.sock").
	// If set, this overrides BindPort.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// AdminTokenSecretRef references a secret containing the admin API token
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`

	// MetricsTokenSecretRef references a secret containing the metrics token
	// +optional
	MetricsTokenSecretRef *corev1.SecretKeySelector `json:"metricsTokenSecretRef,omitempty"`

	// MetricsRequireToken requires authentication for /metrics endpoint
	// +optional
	MetricsRequireToken bool `json:"metricsRequireToken,omitempty"`

	// TraceSink is the OpenTelemetry collector address for tracing
	// Example: "http://localhost:4317"
	// +optional
	TraceSink string `json:"traceSink,omitempty"`
}

// DatabaseConfig configures the metadata database
type DatabaseConfig struct {
	// Engine specifies the database engine to use
	// +kubebuilder:validation:Enum=lmdb;sqlite;fjall
	// +kubebuilder:default="lmdb"
	// +optional
	Engine string `json:"engine,omitempty"`

	// LMDBMapSize is the virtual memory region size for LMDB
	// +optional
	LMDBMapSize *resource.Quantity `json:"lmdbMapSize,omitempty"`

	// FjallBlockCacheSize is the block cache size for Fjall
	// +optional
	FjallBlockCacheSize *resource.Quantity `json:"fjallBlockCacheSize,omitempty"`
}

// BlockConfig configures block storage settings
type BlockConfig struct {
	// Size is the size of data blocks (default: 1M)
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// RAMBufferMax is the maximum RAM for buffering blocks
	// +optional
	RAMBufferMax *resource.Quantity `json:"ramBufferMax,omitempty"`

	// MaxConcurrentReads is the maximum simultaneous block file reads
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentReads *int `json:"maxConcurrentReads,omitempty"`

	// CompressionLevel is the zstd compression level
	// 1-19: standard, 20-22: ultra, -1 to -99: fast, "none": disabled
	// +optional
	CompressionLevel *string `json:"compressionLevel,omitempty"`

	// DisableScrub disables automatic monthly data directory scrub
	// +optional
	DisableScrub bool `json:"disableScrub,omitempty"`

	// UseLocalTZ runs lifecycle worker at midnight in local timezone
	// +optional
	UseLocalTZ bool `json:"useLocalTZ,omitempty"`
}

// DiscoveryConfig configures peer discovery mechanisms
type DiscoveryConfig struct {
	// Kubernetes configures Kubernetes-based peer discovery
	// +optional
	Kubernetes *KubernetesDiscoveryConfig `json:"kubernetes,omitempty"`

	// Consul configures Consul-based peer discovery
	// +optional
	Consul *ConsulDiscoveryConfig `json:"consul,omitempty"`
}

// KubernetesDiscoveryConfig configures Kubernetes peer discovery
type KubernetesDiscoveryConfig struct {
	// Enabled enables Kubernetes-based discovery
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Namespace for Garage custom resources
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// ServiceName label to filter custom resources
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// SkipCRD skips automatic CRD creation/patching
	// +optional
	SkipCRD bool `json:"skipCRD,omitempty"`
}

// ConsulDiscoveryConfig configures Consul peer discovery
type ConsulDiscoveryConfig struct {
	// Enabled enables Consul-based discovery
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// API specifies the service registration API ("catalog" or "agent")
	// +kubebuilder:validation:Enum=catalog;agent
	// +kubebuilder:default="catalog"
	// +optional
	API string `json:"api,omitempty"`

	// HTTPAddr is the full HTTP(S) address of Consul server
	// +optional
	HTTPAddr string `json:"httpAddr,omitempty"`

	// ServiceName for Garage RPC port registration
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// CACert is the CA certificate for TLS connection
	// +optional
	CACert string `json:"caCert,omitempty"`

	// CACertSecretRef references a secret containing the CA certificate
	// +optional
	CACertSecretRef *corev1.SecretKeySelector `json:"caCertSecretRef,omitempty"`

	// ClientCertSecretRef references a secret containing client TLS cert
	// +optional
	ClientCertSecretRef *corev1.SecretKeySelector `json:"clientCertSecretRef,omitempty"`

	// ClientKeySecretRef references a secret containing client TLS key
	// +optional
	ClientKeySecretRef *corev1.SecretKeySelector `json:"clientKeySecretRef,omitempty"`

	// TokenSecretRef references a secret containing the bearer token
	// +optional
	TokenSecretRef *corev1.SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// TLSSkipVerify skips TLS hostname verification
	// +optional
	TLSSkipVerify bool `json:"tlsSkipVerify,omitempty"`

	// Tags are additional service tags
	// +optional
	Tags []string `json:"tags,omitempty"`

	// Meta is service metadata key-value pairs
	// +optional
	Meta map[string]string `json:"meta,omitempty"`

	// Datacenters for WAN federation
	// +optional
	Datacenters []string `json:"datacenters,omitempty"`
}

// SecurityConfig configures security settings
type SecurityConfig struct {
	// AllowWorldReadableSecrets bypasses permission check for secret files
	// +optional
	AllowWorldReadableSecrets bool `json:"allowWorldReadableSecrets,omitempty"`

	// AllowPunycode allows punycode in bucket names
	// +optional
	AllowPunycode bool `json:"allowPunycode,omitempty"`

	// TLS configures TLS settings
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`
}

// TLSConfig configures TLS settings for Garage inter-node RPC communication.
//
// IMPORTANT LIMITATION: Garage does NOT natively support TLS termination for its APIs
// (S3, K2V, Web, Admin). TLS settings here only apply to RPC communication between
// Garage nodes for internal replication and cluster coordination.
//
// For TLS on the S3/Admin APIs, use one of these approaches:
// - Kubernetes Ingress with TLS termination (recommended)
// - Service mesh (Istio, Linkerd) with mTLS
// - External load balancer with TLS termination
// - Sidecar proxy (nginx, envoy) in the pod
type TLSConfig struct {
	// Enabled enables TLS for inter-node RPC communication.
	// NOTE: This does NOT enable TLS for S3/Admin APIs - use Ingress or service mesh for that.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// CertSecretRef references a secret containing the TLS certificate for RPC
	// +optional
	CertSecretRef *corev1.SecretKeySelector `json:"certSecretRef,omitempty"`

	// KeySecretRef references a secret containing the TLS private key for RPC
	// +optional
	KeySecretRef *corev1.SecretKeySelector `json:"keySecretRef,omitempty"`

	// CASecretRef references a secret containing the CA certificate for verifying peer nodes
	// +optional
	CASecretRef *corev1.SecretKeySelector `json:"caSecretRef,omitempty"`
}

// LoggingConfig configures logging behavior for Garage nodes
type LoggingConfig struct {
	// Level sets the log level using RUST_LOG format.
	//
	// Examples:
	// - "info": Default info level for all components
	// - "debug": Debug level for all components
	// - "garage=debug": Debug only for garage module
	// - "garage=debug,netapp=info": Fine-grained per-component levels
	// - "garage=trace,netapp=debug,rusoto=warn": Multiple components
	//
	// See https://docs.rs/env_logger for full syntax.
	// +optional
	Level string `json:"level,omitempty"`

	// Syslog enables logging to syslog (requires Garage built with syslog feature)
	// +optional
	Syslog bool `json:"syslog,omitempty"`

	// Journald enables logging to systemd journald (requires Garage built with journald feature)
	// +optional
	Journald bool `json:"journald,omitempty"`
}

// PublicEndpointConfig defines how the local cluster is reached from remote clusters
type PublicEndpointConfig struct {
	// Type specifies how nodes are exposed
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort;ExternalIP;Headless
	// +required
	Type string `json:"type"`

	// LoadBalancer configuration
	// +optional
	LoadBalancer *LoadBalancerEndpointConfig `json:"loadBalancer,omitempty"`

	// NodePort configuration
	// +optional
	NodePort *NodePortEndpointConfig `json:"nodePort,omitempty"`

	// ExternalIP configuration
	// +optional
	ExternalIP *ExternalIPEndpointConfig `json:"externalIP,omitempty"`
}

// LoadBalancerEndpointConfig for LoadBalancer exposure
type LoadBalancerEndpointConfig struct {
	// Annotations for the LoadBalancer service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// PerNode creates a separate LoadBalancer per node (more expensive but ensures direct routing)
	// +optional
	PerNode bool `json:"perNode,omitempty"`
}

// NodePortEndpointConfig for NodePort exposure
type NodePortEndpointConfig struct {
	// ExternalAddresses are the external IPs/hostnames of the Kubernetes nodes
	// +required
	ExternalAddresses []string `json:"externalAddresses"`

	// BasePort is the starting NodePort (each node gets BasePort + index)
	// +kubebuilder:validation:Minimum=30000
	// +kubebuilder:validation:Maximum=32767
	// +optional
	BasePort int32 `json:"basePort,omitempty"`
}

// ExternalIPEndpointConfig for direct external IP exposure
type ExternalIPEndpointConfig struct {
	// Addresses maps pod names to external IPs
	// +optional
	Addresses map[string]string `json:"addresses,omitempty"`

	// AddressTemplate uses go template to generate addresses from pod info
	// Example: "garage-{{.Index}}.example.com"
	// +optional
	AddressTemplate string `json:"addressTemplate,omitempty"`
}

// RemoteClusterConfig defines a Garage cluster in another Kubernetes cluster
type RemoteClusterConfig struct {
	// Name is a friendly name for this remote cluster
	// +required
	Name string `json:"name"`

	// Zone is the zone name for nodes in this remote cluster
	// +required
	Zone string `json:"zone"`

	// Connection defines how to connect to this remote cluster
	// +required
	Connection RemoteClusterConnection `json:"connection"`
}

// RemoteClusterConnection defines how to connect to a remote cluster
type RemoteClusterConnection struct {
	// AdminAPIEndpoint is the admin API endpoint of the remote cluster
	// This should be a reachable HTTP/HTTPS URL (e.g., via Tailscale, LoadBalancer, or port-forward)
	// Example: "http://garage-remote.tailscale:3903"
	// +required
	AdminAPIEndpoint string `json:"adminApiEndpoint"`

	// AdminTokenSecretRef references the admin token for the remote cluster's API
	// If not specified, uses the local cluster's admin token (for shared-token setups)
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`
}

// LayoutManagementConfig controls cluster layout management
type LayoutManagementConfig struct {
	// AutoApply automatically applies staged layout changes
	// +optional
	AutoApply bool `json:"autoApply,omitempty"`

	// MinNodesHealthy is the minimum healthy nodes required before applying layout changes
	// +optional
	MinNodesHealthy int `json:"minNodesHealthy,omitempty"`
}

// GarageClusterStatus defines the observed state of GarageCluster
type GarageClusterStatus struct {
	// Phase represents the current phase of the cluster
	// +optional
	Phase string `json:"phase,omitempty"`

	// ClusterID is the unique identifier of the Garage cluster
	// +optional
	ClusterID string `json:"clusterId,omitempty"`

	// BuildInfo contains Garage build information
	// +optional
	BuildInfo *GarageBuildInfo `json:"buildInfo,omitempty"`

	// ReadyReplicas is the number of ready Garage pods
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Nodes contains status information for each node
	// +optional
	Nodes []NodeStatus `json:"nodes,omitempty"`

	// LayoutVersion is the current layout version
	// +optional
	LayoutVersion int64 `json:"layoutVersion,omitempty"`

	// StagedLayoutVersion is the staged layout version pending application
	// +optional
	StagedLayoutVersion *int64 `json:"stagedLayoutVersion,omitempty"`

	// StagedRoles is the number of roles in the staged layout
	// +optional
	StagedRoles int32 `json:"stagedRoles,omitempty"`

	// LayoutPreview shows what would change if staged layout is applied
	// +optional
	LayoutPreview *LayoutPreviewStatus `json:"layoutPreview,omitempty"`

	// Health contains cluster health information
	// +optional
	Health *ClusterHealth `json:"health,omitempty"`

	// StorageStats contains cluster-wide storage statistics
	// +optional
	StorageStats *ClusterStorageStats `json:"storageStats,omitempty"`

	// ActiveRepairs contains currently running repair operations
	// +optional
	ActiveRepairs []RepairStatus `json:"activeRepairs,omitempty"`

	// WorkerCount is the total number of background workers
	// +optional
	WorkerCount int32 `json:"workerCount,omitempty"`

	// WorkersFailed is the number of failed workers
	// +optional
	WorkersFailed int32 `json:"workersFailed,omitempty"`

	// Workers contains detailed information about background workers
	// +optional
	Workers *WorkersStatus `json:"workers,omitempty"`

	// LayoutHistory contains layout version history
	// +optional
	LayoutHistory *LayoutHistoryStatus `json:"layoutHistory,omitempty"`

	// BlockErrors is the count of blocks with sync errors across all nodes
	// +optional
	BlockErrors int32 `json:"blockErrors,omitempty"`

	// BlockErrorDetails provides detailed information about block errors
	// +optional
	BlockErrorDetails *BlockErrorsStatus `json:"blockErrorDetails,omitempty"`

	// ResyncQueueLength is the total block resync queue depth across all nodes
	// +optional
	ResyncQueueLength int64 `json:"resyncQueueLength,omitempty"`

	// ScrubStatus contains the status of data scrub operations
	// +optional
	ScrubStatus *ScrubStatus `json:"scrubStatus,omitempty"`

	// LifecycleStatus contains the status of bucket lifecycle operations
	// +optional
	LifecycleStatus *LifecycleStatus `json:"lifecycleStatus,omitempty"`

	// Endpoints contains service endpoints
	// +optional
	Endpoints *ClusterEndpoints `json:"endpoints,omitempty"`

	// RemoteClusters contains status of remote clusters in the federation
	// +optional
	RemoteClusters []RemoteClusterStatus `json:"remoteClusters,omitempty"`

	// TotalNodes is the total nodes across all clusters (local + remote)
	// +optional
	TotalNodes int `json:"totalNodes,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state of the cluster
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// WorkersStatus contains detailed information about background workers
type WorkersStatus struct {
	// Total is the total number of background workers
	// +optional
	Total int32 `json:"total,omitempty"`

	// Busy is the number of busy/active workers
	// +optional
	Busy int32 `json:"busy,omitempty"`

	// Idle is the number of idle workers
	// +optional
	Idle int32 `json:"idle,omitempty"`

	// Errored is the number of workers with errors
	// +optional
	Errored int32 `json:"errored,omitempty"`

	// Errors contains details about worker errors
	// +optional
	Errors []WorkerError `json:"errors,omitempty"`

	// Variables contains runtime worker configuration variables
	// These can be adjusted through the Admin API to tune background worker behavior
	// +optional
	Variables map[string]string `json:"variables,omitempty"`
}

// WorkerError contains information about a worker error
type WorkerError struct {
	// WorkerID is the worker identifier
	// +optional
	WorkerID int64 `json:"workerId,omitempty"`

	// Name is the worker name
	// +optional
	Name string `json:"name,omitempty"`

	// ConsecutiveErrors is the count of consecutive errors
	// +optional
	ConsecutiveErrors int32 `json:"consecutiveErrors,omitempty"`

	// LastError is the last error message
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastErrorSecsAgo is seconds since the last error
	// +optional
	LastErrorSecsAgo int64 `json:"lastErrorSecsAgo,omitempty"`
}

// LayoutHistoryStatus contains layout version history information
type LayoutHistoryStatus struct {
	// CurrentVersion is the current layout version
	// +optional
	CurrentVersion int64 `json:"currentVersion,omitempty"`

	// MinAck is the minimum acknowledged layout version by all nodes
	// +optional
	MinAck int64 `json:"minAck,omitempty"`

	// Versions contains the history of layout versions
	// +optional
	Versions []LayoutVersionInfo `json:"versions,omitempty"`
}

// LayoutVersionInfo contains information about a layout version
type LayoutVersionInfo struct {
	// Version is the layout version number
	// +optional
	Version int64 `json:"version,omitempty"`

	// Status is the version status (Current, Draining, Historical)
	// +optional
	Status string `json:"status,omitempty"`

	// StorageNodes is the number of storage nodes in this version
	// +optional
	StorageNodes int `json:"storageNodes,omitempty"`

	// GatewayNodes is the number of gateway nodes in this version
	// +optional
	GatewayNodes int `json:"gatewayNodes,omitempty"`
}

// LayoutPreviewStatus shows what would change if staged layout changes are applied
type LayoutPreviewStatus struct {
	// NodesAdded shows node IDs that would be added to the layout
	// +optional
	NodesAdded []string `json:"nodesAdded,omitempty"`

	// NodesRemoved shows node IDs that would be removed from the layout
	// +optional
	NodesRemoved []string `json:"nodesRemoved,omitempty"`

	// NodesModified shows node IDs with changed configuration (zone, capacity, tags)
	// +optional
	NodesModified []string `json:"nodesModified,omitempty"`

	// ZonesAffected shows which zones would be affected by the changes
	// +optional
	ZonesAffected []string `json:"zonesAffected,omitempty"`

	// PartitionTransfers is the estimated number of partition transfers
	// +optional
	PartitionTransfers int32 `json:"partitionTransfers,omitempty"`

	// DataTransferEstimate is a human-readable estimate of data movement (e.g., "~50 GB")
	// +optional
	DataTransferEstimate string `json:"dataTransferEstimate,omitempty"`
}

// BlockErrorsStatus provides detailed information about block sync errors
type BlockErrorsStatus struct {
	// Count is the total number of blocks with errors
	// +optional
	Count int32 `json:"count,omitempty"`

	// LastErrorAt is when the most recent block error occurred
	// +optional
	LastErrorAt *metav1.Time `json:"lastErrorAt,omitempty"`

	// TopErrors contains details about the most problematic blocks
	// Limited to top 10 blocks by error count
	// +optional
	TopErrors []BlockErrorDetail `json:"topErrors,omitempty"`
}

// BlockErrorDetail contains information about a specific block error
type BlockErrorDetail struct {
	// BlockHash is the hash of the affected block
	// +optional
	BlockHash string `json:"blockHash,omitempty"`

	// ErrorCount is the number of times this block failed to sync
	// +optional
	ErrorCount int32 `json:"errorCount,omitempty"`

	// LastError is the most recent error message for this block
	// +optional
	LastError string `json:"lastError,omitempty"`

	// LastAttempt is when the last sync attempt occurred
	// +optional
	LastAttempt *metav1.Time `json:"lastAttempt,omitempty"`

	// NextRetry is when the next sync retry is scheduled
	// +optional
	NextRetry *metav1.Time `json:"nextRetry,omitempty"`
}

// ClusterStorageStats contains cluster-wide storage statistics
type ClusterStorageStats struct {
	// TotalCapacity is the total storage capacity across all nodes
	// +optional
	TotalCapacity resource.Quantity `json:"totalCapacity,omitempty"`

	// UsedCapacity is the used storage across all nodes
	// +optional
	UsedCapacity resource.Quantity `json:"usedCapacity,omitempty"`

	// AvailableCapacity is the available storage across all nodes
	// +optional
	AvailableCapacity resource.Quantity `json:"availableCapacity,omitempty"`

	// TotalPartitions is the total number of partitions in the layout
	// +optional
	TotalPartitions int32 `json:"totalPartitions,omitempty"`

	// HealthyPartitions is the number of partitions with full redundancy
	// +optional
	HealthyPartitions int32 `json:"healthyPartitions,omitempty"`
}

// RepairStatus contains status of a repair operation
type RepairStatus struct {
	// Type is the repair operation type (Tables, Blocks, Scrub, Rebalance, etc.)
	// +optional
	Type string `json:"type,omitempty"`

	// NodeID is the node running this repair
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Progress is a human-readable progress description
	// +optional
	Progress string `json:"progress,omitempty"`

	// StartedAt is when the repair started
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
}

// ScrubStatus contains the status of data scrub operations across the cluster.
// These values are read from Garage's worker variables via the Admin API.
type ScrubStatus struct {
	// Running indicates if a scrub is currently running on any node
	// +optional
	Running bool `json:"running,omitempty"`

	// Paused indicates if the scrub is paused
	// +optional
	Paused bool `json:"paused,omitempty"`

	// Progress is a human-readable progress description (e.g., "45% complete")
	// +optional
	Progress string `json:"progress,omitempty"`

	// TranquilityLevel is the current tranquility setting (higher = less aggressive)
	// +optional
	TranquilityLevel int `json:"tranquilityLevel,omitempty"`

	// LastCompleted is when the last scrub completed (from scrub-last-completed worker variable)
	// +optional
	LastCompleted *metav1.Time `json:"lastCompleted,omitempty"`

	// NextRun is when the next scrub is scheduled to run (from scrub-next-run worker variable)
	// +optional
	NextRun *metav1.Time `json:"nextRun,omitempty"`

	// CorruptedBlocks is the number of corrupted blocks found in the last scrub
	// (from scrub-corruptions_detected worker variable)
	// +optional
	CorruptedBlocks int32 `json:"corruptedBlocks,omitempty"`

	// NodeStatuses contains per-node scrub status
	// +optional
	NodeStatuses []NodeScrubStatus `json:"nodeStatuses,omitempty"`
}

// NodeScrubStatus contains scrub status for a single node
type NodeScrubStatus struct {
	// NodeID is the node identifier
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Running indicates if scrub is running on this node
	// +optional
	Running bool `json:"running,omitempty"`

	// Progress percentage (0-100)
	// +optional
	Progress int `json:"progress,omitempty"`

	// ItemsChecked is the number of items checked
	// +optional
	ItemsChecked int64 `json:"itemsChecked,omitempty"`

	// ErrorsFound is the number of errors found on this node
	// +optional
	ErrorsFound int32 `json:"errorsFound,omitempty"`
}

// LifecycleStatus contains the status of bucket lifecycle operations.
// These values are read from Garage's worker variables via the Admin API.
type LifecycleStatus struct {
	// LastCompleted is when the last lifecycle worker run completed
	// (from lifecycle-last-completed worker variable)
	// +optional
	LastCompleted *metav1.Time `json:"lastCompleted,omitempty"`
}

// RemoteClusterStatus is the status of a remote cluster
type RemoteClusterStatus struct {
	// Name is the cluster name
	// +optional
	Name string `json:"name,omitempty"`

	// Zone is the cluster's zone
	// +optional
	Zone string `json:"zone,omitempty"`

	// Nodes is the number of nodes in this cluster
	// +optional
	Nodes int `json:"nodes,omitempty"`

	// HealthyNodes is the number of healthy nodes
	// +optional
	HealthyNodes int `json:"healthyNodes,omitempty"`

	// Connected indicates if we can reach this cluster
	// +optional
	Connected bool `json:"connected,omitempty"`

	// LastSeen is when we last successfully connected
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
}

// NodeStatus contains status information for a Garage node
type NodeStatus struct {
	// NodeID is the public key of the node
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// PodName is the name of the pod running this node
	// +optional
	PodName string `json:"podName,omitempty"`

	// Zone is the zone assignment of the node
	// +optional
	Zone string `json:"zone,omitempty"`

	// Capacity is the storage capacity of the node
	// +optional
	Capacity string `json:"capacity,omitempty"`

	// Gateway indicates if the node is gateway-only
	// +optional
	Gateway bool `json:"gateway,omitempty"`

	// Connected indicates if the node is connected to the cluster
	// +optional
	Connected bool `json:"connected,omitempty"`

	// DataDiskAvailable is the available space on data disk
	// +optional
	DataDiskAvailable string `json:"dataDiskAvailable,omitempty"`

	// DataDiskTotal is the total space on data disk
	// +optional
	DataDiskTotal string `json:"dataDiskTotal,omitempty"`

	// MetadataDiskAvailable is the available space on metadata disk
	// +optional
	MetadataDiskAvailable string `json:"metadataDiskAvailable,omitempty"`

	// MetadataDiskTotal is the total space on metadata disk
	// +optional
	MetadataDiskTotal string `json:"metadataDiskTotal,omitempty"`

	// Version is the Garage version running on this node
	// +optional
	Version string `json:"version,omitempty"`
}

// ClusterHealth contains cluster health information
type ClusterHealth struct {
	// Status is the overall cluster status
	// +optional
	Status string `json:"status,omitempty"`

	// Healthy indicates if all nodes are connected
	// +optional
	Healthy bool `json:"healthy,omitempty"`

	// Available indicates if quorum is available
	// +optional
	Available bool `json:"available,omitempty"`

	// KnownNodes is the number of nodes seen in cluster
	// +optional
	KnownNodes int `json:"knownNodes,omitempty"`

	// ConnectedNodes is the number of currently connected nodes
	// +optional
	ConnectedNodes int `json:"connectedNodes,omitempty"`

	// StorageNodes is the number of storage nodes in layout
	// +optional
	StorageNodes int `json:"storageNodes,omitempty"`

	// StorageNodesOK is the number of connected storage nodes
	// +optional
	StorageNodesOK int `json:"storageNodesOk,omitempty"`

	// Partitions is the total partitions in layout
	// +optional
	Partitions int `json:"partitions,omitempty"`

	// PartitionsQuorum is partitions with quorum connectivity
	// +optional
	PartitionsQuorum int `json:"partitionsQuorum,omitempty"`

	// PartitionsAllOK is partitions with all nodes connected
	// +optional
	PartitionsAllOK int `json:"partitionsAllOk,omitempty"`
}

// ClusterEndpoints contains service endpoint information
type ClusterEndpoints struct {
	// S3 is the S3 API endpoint
	// +optional
	S3 string `json:"s3,omitempty"`

	// K2V is the K2V API endpoint
	// +optional
	K2V string `json:"k2v,omitempty"`

	// Web is the web hosting endpoint
	// +optional
	Web string `json:"web,omitempty"`

	// Admin is the admin API endpoint
	// +optional
	Admin string `json:"admin,omitempty"`

	// Metrics is the Prometheus metrics endpoint (typically Admin + /metrics)
	// +optional
	Metrics string `json:"metrics,omitempty"`

	// RPC is the internal RPC endpoint
	// +optional
	RPC string `json:"rpc,omitempty"`
}

// GarageBuildInfo contains Garage version and build information
type GarageBuildInfo struct {
	// Version is the Garage version string (e.g., "v1.0.1")
	// +optional
	Version string `json:"version,omitempty"`

	// RustVersion is the Rust compiler version used to build Garage
	// +optional
	RustVersion string `json:"rustVersion,omitempty"`

	// Features lists enabled Cargo features
	// +optional
	Features []string `json:"features,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gc
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.replicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Zone",type="string",JSONPath=".spec.zone"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageCluster is the Schema for the garageclusters API
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

// GarageClusterList contains a list of GarageCluster
type GarageClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageCluster{}, &GarageClusterList{})
}
