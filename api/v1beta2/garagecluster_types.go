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
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// DeletionPolicy controls whether deleting a GarageCluster tears down a whole
// store or first drains one site from a surviving federated Garage layout.
type DeletionPolicy string

const (
	DeletionPolicyDestroy DeletionPolicy = "Destroy"
	DeletionPolicyDrain   DeletionPolicy = "Drain"
)

// GarageClusterSpec defines the desired state of a GarageCluster.
//
// A cluster has two optional tiers:
//
//   - `storage` — long-lived storage. Its optional default group uses
//     StatefulSet/PVC nodes; nodeLocalPools add selector-driven HostPath nodes.
//   - `gateway` — routes S3/Admin traffic and stores no object blocks. Auto
//     unified clusters generate one GarageNode-owned StatefulSet per gateway
//     identity; Manual unified clusters use ordinary user-owned GarageNodes.
//     Edge clusters use one cluster-level StatefulSet. Metadata uses a small PVC
//     by default and data uses EmptyDir. Explicit EmptyDir metadata gives up
//     identity persistence and is warned at admission.
//
// Supported topology shapes are deliberately disjoint:
//
//  1. `storage` only (storage cluster).
//  2. `storage` together with `gateway` (unified cluster — most common).
//  3. `gateway` together with `connectTo` (edge gateway — pods live separately
//     from the storage backend).
//  4. `connectTo` only (management handle; no workloads).
//
// `storage` and `connectTo` are mutually exclusive. Joining independently
// managed storage sites is expressed with remoteClusters, not connectTo.
//
// +kubebuilder:validation:XValidation:rule="has(self.storage) || has(self.gateway) || has(self.connectTo)",message="at least one of spec.storage, spec.gateway, or spec.connectTo must be set"
// +kubebuilder:validation:XValidation:rule="!has(self.gateway) || has(self.storage) || has(self.connectTo)",message="spec.gateway requires either spec.storage (unified cluster) or spec.connectTo (edge gateway)"
type GarageClusterSpec struct {
	// Image specifies the Garage container image to use.
	// Takes precedence over imageRepository if both are set.
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

	// Storage configures the long-lived storage tier. The existing replicas,
	// metadata, and data fields describe the default operator-managed
	// StatefulSet/PVC member group. NodeLocalPools adds independently configured
	// node-local HostPath member sets that may coexist with that group or with
	// ordinary user-managed GarageNodes.
	// Omit for gateway-only edge clusters.
	// +optional
	Storage *StorageSpec `json:"storage,omitempty"`

	// Gateway configures the gateway tier. Auto unified clusters generate one
	// GarageNode-owned StatefulSet per replica; Manual unified clusters use
	// ordinary user-owned GarageNodes. Edge clusters use one cluster-level
	// StatefulSet. Gateway pods store no object blocks. Metadata uses a small PVC
	// by default to persist identity across restarts; callers may explicitly
	// choose EmptyDir metadata and accept identity churn.
	// May be combined with `storage` (unified cluster) or `connectTo` (edge
	// cluster), but never both.
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

	// Zone is the static Garage layout zone used by members of this cluster and
	// the fallback before a ZoneFrom Pod is scheduled or when its readable
	// Kubernetes Node does not carry the configured label.
	// When ZoneFrom is configured, one workload-owning cluster may contain roles
	// in multiple actual Garage failure-domain zones.
	// +optional
	Zone string `json:"zone,omitempty"`

	// ZoneFrom derives each storage node's layout zone from a label on the
	// Kubernetes Node its pod is scheduled to, instead of using the single
	// cluster-wide Zone above. This lets one cluster express failure domains
	// internally (racks, power circuits, switches) so replication.zoneRedundancy
	// has something to act on without splitting into a federation.
	//
	// Applies to operator-managed storage nodes only, including both default
	// StatefulSet nodes and node-local-pool nodes. Zone remains the fallback
	// when the label is missing or the pod is not scheduled yet. If the operator
	// cannot read the required Kubernetes Node, reconciliation fails closed; it
	// does not silently substitute Zone. Cluster-scoped installation is required.
	// +optional
	ZoneFrom *ZoneSource `json:"zoneFrom,omitempty"`

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

	// DeletionPolicy controls deletion-time Garage layout handling.
	// Destroy is whole-store teardown and does not attempt Garage's invalid
	// empty-layout transition. Drain retires one federated site and
	// blocks deletion until its roles migrate to surviving replicas and layout
	// history settles. HostPath data is never deleted; PVC cleanup remains
	// controlled by storage.pvcRetentionPolicy. When omitted, standalone clusters
	// retain legacy Destroy behavior. Federated deletion is refused until this is
	// set explicitly; if admission is bypassed, the controller fails closed as Drain.
	// +kubebuilder:validation:Enum=Destroy;Drain
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

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
// The default operator-managed group is backed by one single-replica StatefulSet
// per GarageNode, with PVC or EmptyDir metadata/data volumes. Node-local pools
// are additive: each contributes one persistent Garage identity per selected
// Kubernetes Node. This lets manual SMB/PVC nodes, uniform Auto-mode PVC nodes,
// and one or more node-local pools participate in the same Garage layout without
// exposing the workload implementation in the public API. Their actual
// failure-domain zones remain independently controlled by zone and zoneFrom.
type StorageSpec struct {
	// Replicas controls only the default operator-managed StatefulSet/PVC group.
	// Set it to 0 to disable that group. Ordinary Manual GarageNodes and
	// node-local-pool members remain independently declared; pool cardinality
	// follows each entry's selector.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas"`

	// Metadata configures Garage node identity + index DB storage for the
	// default StatefulSet/PVC group. It may be omitted together with data when
	// replicas is 0 and only Manual GarageNodes or node-local pools are used.
	// +optional
	Metadata *VolumeConfig `json:"metadata,omitempty"`

	// Data configures object-block storage for the default StatefulSet/PVC group.
	// It may be omitted together with metadata when replicas is 0.
	// +optional
	Data *VolumeConfig `json:"data,omitempty"`

	// DataSourceRef is the opt-in restore source for object-block data PVCs in
	// the default Auto group. Setting it copies the reference onto generated
	// data PVCs only; metadata PVCs, including unified Auto gateway metadata,
	// never receive this source because they contain the Garage node_key
	// identity. The populator must map each target data claim to its matching
	// source-group member. A single-volume clone is not a safe source for this
	// field. It is immutable after the GarageCluster is created.
	// +optional
	DataSourceRef *corev1.TypedObjectReference `json:"dataSourceRef,omitempty"`

	// RPCPublicAddr is the externally-routable rpc_public_addr advertised by
	// storage pods so peers in other regions can dial them by hostname.
	//
	// With replicas > 1 a single shared address only ever routes to one pod
	// (e.g. behind a Tailscale VIP), leaving the others unreachable
	// cross-region. Use an `{ordinal}` placeholder — the operator substitutes
	// each pod's ordinal (0, 1, ...), symmetric with the gateway tier's
	// rpcPublicAddr and with remoteClusters[].storageRpcEndpointTemplate on the
	// consuming side — so every pod advertises its own address. An address
	// without the placeholder is rendered verbatim (fine for a single-replica
	// storage tier). When a per-node publicEndpoint (LoadBalancer perNode) is in
	// effect, that address wins and this field is ignored.
	//
	// Example: "us-east-storage-{ordinal}.example.ts.net:3901"
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`

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

	// PodDisruptionBudget configures one PDB covering the storage tier,
	// including the default StatefulSet and all node-local pools.
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetConfig `json:"podDisruptionBudget,omitempty"`

	// LayoutPolicy overrides the cluster-level spec.layoutPolicy for the STORAGE
	// default StatefulSet/PVC group only. This lets a cluster hand-manage SMB/PVC
	// GarageNodes (Manual) while node-local pools remain operator-managed and
	// while the gateway tier follows the cluster policy. Defaults to
	// spec.layoutPolicy when empty. Auto->Manual is one-way for the default group.
	// +kubebuilder:validation:Enum=Auto;Manual
	// +optional
	LayoutPolicy string `json:"layoutPolicy,omitempty"`

	// NodeLocalPools adds named node-local storage member sets.
	//
	// Each entry is currently realized as one operator-managed DaemonSet. One
	// Garage Pod and one generated GarageNode identity run on every Kubernetes
	// Node selected by the entry. Metadata and block data remain tied to that
	// Node's HostPaths.
	//
	// The DaemonSet is an implementation of the node-local contract, not a
	// selectable workload mode. The operator coordinates activation, rollout,
	// Garage layout membership, draining, and retirement.
	//
	// Multiple entries produce multiple DaemonSets; one entry is the normal
	// single-DaemonSet deployment. Entries remain operator-managed even when
	// storage.layoutPolicy is Manual and are independent of the optional default
	// StatefulSet/PVC group. Across all entries, at most 255 Kubernetes Nodes may
	// be selected. Garage's global layout accepts at most 256 positive-capacity
	// roles across node-local, PVC, SMB, manual, external, and federated members;
	// those other members consume the same headroom and can make activation fail
	// below the selector ceiling. At 255 live roles, a new node-local activation
	// is eligible only for a locally proven retiring generated member. This is not
	// a reservation against independently operated federated sites.
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	// +optional
	NodeLocalPools []NodeLocalPoolSpec `json:"nodeLocalPools,omitempty"`

	// PodTemplate carries pod scheduling and metadata for the default
	// StatefulSet/PVC group. Every node-local pool has its own nested podTemplate.
	PodTemplate `json:",inline"`
}

// StorageDrainUnverifiedPeersPolicy controls whether automatic drain may
// proceed when one or more current positive-capacity Garage processes are not
// managed by this GarageCluster's Kubernetes control plane.
type StorageDrainUnverifiedPeersPolicy string

const (
	// StorageDrainUnverifiedPeersBlock is the safe default. External GarageNodes,
	// foreign/federated roles, and roles whose process incarnation cannot be
	// mapped to a locally managed pod block automatic drain.
	StorageDrainUnverifiedPeersBlock StorageDrainUnverifiedPeersPolicy = "Block"
	// StorageDrainUnverifiedPeersAssumeConsistent is an explicit operator
	// attestation that every unverified Garage process is already running literal
	// consistencyMode=consistent and that topology mutations are serialized
	// across sites. The operator still requires the strict terminal queue-empty
	// fallback, but cannot verify this assertion through Garage's Admin API.
	StorageDrainUnverifiedPeersAssumeConsistent StorageDrainUnverifiedPeersPolicy = "AssumeConsistent"
)

// StorageDrainConfig configures layout-wide positive-capacity removal safety.
type StorageDrainConfig struct {
	// UnverifiedPeersPolicy defaults to Block. AssumeConsistent is required for
	// federated or externally managed processes and is a deliberate maintenance
	// assertion, not an online safety guarantee.
	// +kubebuilder:validation:Enum=Block;AssumeConsistent
	// +kubebuilder:default=Block
	// +optional
	UnverifiedPeersPolicy StorageDrainUnverifiedPeersPolicy `json:"unverifiedPeersPolicy,omitempty"`
}

// NodeLocalPoolSpec configures a named node-local membership generator.
//
// Selector is the durable desired-membership boundary. The operator keeps an
// internal activation label on each selected Kubernetes Node so it can add
// replacements before draining old Garage roles and only stop a pod after its
// role has left every active layout version.
//
// A node-local pool is not a Garage entity, replication group, quorum, or
// failure domain. Garage replication applies globally across every
// positive-capacity layout role and its independently assigned zone. Capacity
// is advertised per generated Garage role, not divided across selected Nodes.
// The metadata HostPath containing node_key is the durable identity boundary;
// retaining or reusing only this Name does not preserve a Garage identity.
//
// +kubebuilder:validation:XValidation:rule="has(self.data) != (has(self.dataPaths) && size(self.dataPaths) > 0)",message="exactly one of data or dataPaths must be set"
type NodeLocalPoolSpec struct {
	// Name identifies this operator-managed membership set and is used in child
	// resource names, labels, and Garage layout tags. It is not a Garage identity,
	// replication group, quorum, zone, or failure domain.
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	Name string `json:"name"`

	// Selector chooses the Kubernetes Nodes that own a persistent Garage
	// identity in this pool. It is membership, not a pod scheduling hint.
	// A Node may match at most one node-local pool in a GarageCluster.
	// +required
	Selector metav1.LabelSelector `json:"selector"`

	// Capacity is the uniform effective capacity advertised to the Garage
	// layout for every generated role in this pool; it is not aggregate pool
	// capacity. HostPath volumes have no PVC request
	// from which to derive it. For multi-disk pools this may not exceed the sum
	// of writable dataPaths capacities.
	// +required
	Capacity *resource.Quantity `json:"capacity"`

	// Metadata is the node-local directory that stores Garage's durable
	// node_key and metadata database. Its hostPath is immutable after pool
	// creation because changing it changes every selected node's identity.
	// +required
	Metadata *HostPathVolumeConfig `json:"metadata"`

	// Data is the single node-local block-data directory, mounted at
	// /data/data. Mutually exclusive with dataPaths.
	// +optional
	Data *HostPathVolumeConfig `json:"data,omitempty"`

	// DataPaths configures multiple node-local Garage data directories.
	// Mutually exclusive with data. Every writable entry needs a capacity;
	// read-only entries are retained for Garage's staged disk migration flow.
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=path
	// +optional
	DataPaths []NodeLocalPoolDataPath `json:"dataPaths,omitempty"`

	// Network configures identity-specific connectivity for this pool.
	// +optional
	Network *NodeLocalPoolNetworkSpec `json:"network,omitempty"`

	// PodTemplate carries pod settings that do not change membership. Required
	// node affinity is intentionally unavailable: selector is the only durable
	// membership boundary.
	// +optional
	PodTemplate *NodeLocalPoolPodTemplate `json:"podTemplate,omitempty"`
}

// NodeLocalPoolNetworkSpec configures identity-specific RPC reachability for a
// node-local pool.
type NodeLocalPoolNetworkSpec struct {
	// RPCPublicAddrTemplate is the directly routable RPC address for each node
	// identity. {nodeName} is replaced with the Kubernetes Node name and the
	// result is stored in the Garage layout's rpc-address tag.
	//
	// Example: "{nodeName}.storage.example.net:3901"
	// +optional
	RPCPublicAddrTemplate string `json:"rpcPublicAddrTemplate,omitempty"`
}

// NodeLocalPoolPodTemplate carries pod settings for a node-local pool. NodeSelector is
// deliberately absent because NodeLocalPoolSpec.Selector alone controls durable
// Garage membership.
type NodeLocalPoolPodTemplate struct {
	// Resources specifies compute resources for the pod.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Tolerations for pod scheduling.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity for pod scheduling. Required node affinity is rejected because
	// it would create a second, hidden membership selector.
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

	// Env contains additional environment variables for the Garage container.
	// Garage config-path and RPC/Admin/metrics credential variables are
	// operator-reserved because storage-drain safety and mesh identity rely on the
	// rendered config and pinned immutable Secrets.
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(e, e.name != 'GARAGE_CONFIG_FILE')",message="GARAGE_CONFIG_FILE is operator-reserved"
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// EnvFrom contains sources used to populate Garage container environment
	// variables. A source prefix must not be capable of injecting an
	// operator-reserved Garage variable.
	// +optional
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`
}

// HostPathVolumeConfig describes one node-local directory mounted by a
// node-local pool.
type HostPathVolumeConfig struct {
	// HostPath is an absolute directory on each selected Kubernetes Node.
	// +required
	HostPath string `json:"hostPath"`

	// HostPathType controls whether Kubernetes creates a missing directory.
	// Directory (the production default) also requires a pre-provisioned
	// .garage-volume-id file inside HostPath. The pool workload mounts that
	// marker separately as HostPath type File, so an unmounted but still-present
	// root-filesystem directory cannot silently receive Garage data.
	// DirectoryOrCreate skips this marker guarantee and is intended for tests or
	// explicitly ephemeral provisioning.
	// +kubebuilder:validation:Enum=Directory;DirectoryOrCreate
	// +kubebuilder:default=Directory
	// +optional
	HostPathType corev1.HostPathType `json:"hostPathType,omitempty"`
}

// NodeLocalPoolDataPath is one hostPath-backed entry in Garage's data_dir array.
//
// +kubebuilder:validation:XValidation:rule="has(self.readOnly) && self.readOnly ? !has(self.capacity) : has(self.capacity)",message="capacity is required for writable paths and must be omitted for read-only paths"
type NodeLocalPoolDataPath struct {
	// Path is the absolute in-container mount path used in garage.toml.
	// +required
	Path string `json:"path"`

	// HostPath is the absolute directory on each selected Kubernetes Node.
	// +required
	HostPath string `json:"hostPath"`

	// HostPathType controls whether Kubernetes creates a missing directory.
	// Directory also requires a pre-provisioned .garage-volume-id file inside
	// HostPath; see HostPathVolumeConfig. DirectoryOrCreate skips that production
	// mount check and is intended for tests or explicitly ephemeral provisioning.
	// +kubebuilder:validation:Enum=Directory;DirectoryOrCreate
	// +kubebuilder:default=Directory
	// +optional
	HostPathType corev1.HostPathType `json:"hostPathType,omitempty"`

	// Capacity is the per-directory Garage capacity. Required unless readOnly.
	// +optional
	Capacity *resource.Quantity `json:"capacity,omitempty"`

	// ReadOnly removes this path from new block placement while keeping it
	// mounted for Garage's staged disk migration.
	// +optional
	ReadOnly bool `json:"readOnly,omitempty"`
}

// GatewaySpec configures the gateway tier of a GarageCluster.
//
// In Auto layout mode, a unified storage+gateway cluster generates one
// GarageNode and single-replica OnDelete StatefulSet per gateway identity. In
// Manual mode, unified gateway members are ordinary user-owned GarageNodes. An
// edge gateway+connectTo cluster uses one cluster-level StatefulSet for the
// tier. These managed shapes use a small metadata PVC by default and EmptyDir
// for data. The metadata PVC persists the Ed25519 node_key Garage stores under
// metadata_dir, so each gateway pod re-joins with the same identity across
// restarts. Setting metadata.type to EmptyDir is an explicit
// ephemeral-identity exception and produces an admission warning.
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
	// Replicas controls generated gateway identities in an Auto unified cluster,
	// or the cluster-level StatefulSet replicas in an edge cluster. Set it to 0
	// to retire those operator-managed roles and workloads. It does not control
	// ordinary user-owned gateway GarageNodes in Manual layout mode.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=2
	Replicas int32 `json:"replicas"`

	// RPCPublicAddr, when set, is written into the gateway pods' garage.toml as
	// rpc_public_addr so that peers in other regions can dial gateways by hostname.
	// It is operationally required when federated peers cannot route directly to
	// each Pod IP; leave it unset when gateways communicate only with a locally
	// routable storage tier.
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`

	// Metadata configures gateway metadata storage for Auto unified gateways and
	// edge gateways. It defaults to a 1Gi PVC; type EmptyDir explicitly gives up
	// identity persistence. Manual unified gateways are user-owned GarageNodes,
	// so this cluster-level field is rejected there. Paths and
	// volumeClaimTemplateSpec is unsupported. Selector applies to newly created
	// claims in both unified and edge gateway workloads. Change an edge gateway's
	// metadata configuration only after scaling gateway replicas to zero and
	// waiting for its capacity-less roles to retire. Data always stays EmptyDir
	// because gateways do not store object blocks.
	// +optional
	Metadata *VolumeConfig `json:"metadata,omitempty"`

	// PVCRetentionPolicy controls gateway metadata PVC lifecycle. It preserves
	// the released v1beta1 gateway storage.pvcRetentionPolicy contract. When
	// omitted, edge gateway StatefulSets keep their established Delete/Delete
	// behavior, while per-GarageNode unified gateway StatefulSets keep
	// Kubernetes' safer Retain/Retain default. An explicit value applies to both
	// managed gateway shapes.
	// +optional
	PVCRetentionPolicy *PVCRetentionPolicy `json:"pvcRetentionPolicy,omitempty"`

	// PodDisruptionBudget configures a PDB for the gateway workloads. Gateway
	// pods serve S3/Admin traffic but hold no object data, so a PDB only
	// protects request availability during node drains — not data durability.
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetConfig `json:"podDisruptionBudget,omitempty"`

	// ReadinessProbe overrides the gateway tier's readiness probe. When unset,
	// the operator uses a bind-only TCP check on the S3 port. The default is
	// deliberately NOT a serving-aware admin /health probe: /health is a
	// cluster-wide consistent write-quorum signal, so at replication.factor=2 a
	// single storage-node loss (or, for a federated cluster, the window before
	// remote peers join) makes /health return 503 on every node, which would mark
	// all gateways NotReady and — behind a publishNotReadyAddresses=false Service
	// such as the Tailscale anycast — withdraw the whole anycast and take down
	// reads too, even though read_quorum=1 means reads still work. Serving-health
	// belongs in monitoring (alert on /health), not readiness. Set this only if
	// you have a custom read-capability gate (e.g. an exec probe) that won't
	// withdraw a gateway that can still serve reads.
	// +optional
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty"`

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
	// container. Garage config-path and RPC/Admin/metrics credential variables are
	// operator-reserved. Typical use: setting GARAGE_ALLOW_WORLD_READABLE_SECRETS
	// or another non-identity Garage startup option.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// EnvFrom is a list of sources to populate environment variables in the
	// Garage container. A source prefix must not be capable of injecting an
	// operator-reserved Garage variable. Sources are evaluated before the
	// per-variable Env list, matching Kubernetes container semantics.
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

	// MetricRelabelings are applied to samples scraped from the admin /metrics
	// endpoint before ingestion (set as the ServiceMonitor endpoint's
	// metricRelabelings). Use them to drop high-cardinality series that nothing
	// queries — e.g. the per-method rpc_duration_* histograms, which dominate a
	// Garage node's metric series count.
	// +optional
	MetricRelabelings []monitoringv1.RelabelConfig `json:"metricRelabelings,omitempty"`
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

// VolumeConfig configures a PVC or EmptyDir volume.
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

	// Selector matches pre-provisioned PVs for newly created claims. Kubernetes
	// does not dynamically provision a PV when this is set; StorageClassName must
	// also match the target PV.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Labels to set on the PVC.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to set on the PVC.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// VolumeClaimTemplateSpec is retained for API compatibility but is not
	// supported by operator-managed workloads. Admission rejects new or changed
	// values; an unchanged legacy value is tolerated only so it can be removed.
	// Arbitrary claim-template dataSource or volumeName settings can clone a
	// metadata node_key or bind multiple Garage identities to one disk. Use the
	// explicit PVC fields above, or pre-provision a PVC and reference it from an
	// ordinary GarageNode storage existingClaim.
	// Deprecated: use explicit PVC fields or GarageNode existingClaim.
	// +optional
	VolumeClaimTemplateSpec *corev1.PersistentVolumeClaimSpec `json:"volumeClaimTemplateSpec,omitempty"`

	// Paths configures multiple data directories for multi-disk setups.
	// Only valid for data volumes — webhook rejects this on metadata volumes.
	// +optional
	Paths []DataPath `json:"paths,omitempty"`
}

// DataPathVolumeConfig configures the volume for a single data path.
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

	// Selector matches pre-provisioned PVs for newly created claims. Kubernetes
	// does not dynamically provision a PV when this is set; StorageClassName must
	// also match the target PV.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Labels to set on the PVC.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to set on the PVC.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// VolumeClaimTemplateSpec is retained for API compatibility but is not
	// supported by operator-managed workloads. Admission rejects new or changed
	// values; an unchanged legacy value is tolerated only so it can be removed.
	// Use the explicit PVC fields above, or pre-provision a PVC and reference it
	// from an ordinary GarageNode storage existingClaim.
	// Deprecated: use explicit PVC fields or GarageNode existingClaim.
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

	// ReadOnly marks the directory as a legacy read-only Garage data source for
	// migrations. This controls Garage's block placement; the Kubernetes mount
	// remains writable so Garage can maintain its per-directory marker file.
	// +optional
	ReadOnly bool `json:"readOnly"`

	// Volume configuration for this data path.
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

	// RPCBindAddress is a custom wildcard TCP bind address for the RPC server.
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

	// BindAddress is a custom wildcard TCP bind address for the S3 API.
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

	// BindAddress is a custom wildcard TCP bind address for the K2V API.
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

	// BindAddress is a custom wildcard TCP bind address for the Web API.
	// +optional
	BindAddress string `json:"bindAddress,omitempty"`

	// AddHostToMetrics adds the domain name to metrics labels for per-domain tracking.
	// +optional
	AddHostToMetrics bool `json:"addHostToMetrics"`
}

// AdminConfig configures the admin API and metrics.
type AdminConfig struct {
	// BindPort is the port to bind for admin API. The effective Admin API TCP
	// port is immutable after the GarageCluster is created.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3903
	BindPort int32 `json:"bindPort,omitempty"`

	// BindAddress is a custom wildcard TCP bind address for the Admin API.
	// Managed workloads accept "0.0.0.0:3903" or "[::]:3903". Unix sockets,
	// empty hosts, loopback, and specific hosts are rejected
	// because Services and direct Pod probes must reach every Garage process.
	// If set, its port overrides BindPort for all generated endpoints. The
	// effective Admin API TCP port is immutable after GarageCluster creation.
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
	// +kubebuilder:validation:Pattern=`^(none|0|-?[1-9][0-9]*)$`
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

// TLSConfig is retained for API compatibility but is rejected by admission.
// Garage removed its rpc_tls configuration; use a transparent network tunnel
// or service mesh when transport encryption beyond Garage RPC is required.
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

	// ExternalIP is retained for API compatibility but is not supported.
	// Setting it is rejected because the operator does not consume the explicit
	// address mapping or template.
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

// ExternalIPEndpointConfig is retained for API compatibility but is unsupported.
type ExternalIPEndpointConfig struct {
	// Addresses is retained for API compatibility but is unsupported.
	// +optional
	Addresses map[string]string `json:"addresses,omitempty"`

	// AddressTemplate is retained for API compatibility but is unsupported.
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

	// DefaultCapacity is retained for API compatibility but is not supported.
	// Remote role capacity is copied from the source cluster's committed or
	// staged layout and cannot be overridden by the importing cluster.
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

	// StorageRPCEndpointTemplate is a hostname:port template used by federation
	// to connect to remote STORAGE pods individually, mirroring
	// GatewayRPCEndpointTemplate. The literal `{ordinal}` is replaced with each
	// remote storage pod's ordinal (0, 1, ...) parsed from the layout role's
	// pod-name tag (e.g. `garage-storage-0`).
	//
	// Needed when a remote region runs more than one storage pod behind a single
	// admin hostname (e.g. a Tailscale VIP): the default storage↔storage connect
	// loop dials every remote node at that one shared hostname, which only ever
	// lands one pod, leaving the rest unreachable cross-region. Set this together
	// with the remote region's spec.storage.rpcPublicAddr `{ordinal}` template so
	// each storage pod is both advertised and dialed per-pod.
	//
	// Example: "ottawa-storage-{ordinal}.keiretsu.ts.net:3901"
	// +optional
	StorageRPCEndpointTemplate string `json:"storageRpcEndpointTemplate,omitempty"`
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

	// Drain configures the fail-closed boundary for positive-capacity removal
	// across the canonical Garage layout. It is deliberately independent of a
	// local storage workload: management handles, mixed PVC/SMB/node-local-pool sites,
	// external GarageNodes, scale-down, and deletionPolicy: Drain all coordinate
	// through the same policy.
	// +optional
	Drain *StorageDrainConfig `json:"drain,omitempty"`
}

// StorageRolloutStatus records the exact managed pod handoff currently owned
// by the GarageCluster controller. It is controller-maintained transaction
// state: while non-nil, every other Garage layout writer is excluded until a
// different Ready pod UID reports the desired revision and Garage is healthy
// with settled layout history.
type StorageRolloutStatus struct {
	// GarageNodeName identifies a StatefulSet-backed PVC, SMB, or gateway actor.
	// Mutually exclusive with NodeLocalPoolName and KubernetesNodeName.
	// +optional
	GarageNodeName string `json:"garageNodeName,omitempty"`

	// NodeLocalPoolName identifies a spec.storage.nodeLocalPools entry.
	// +optional
	NodeLocalPoolName string `json:"nodeLocalPoolName,omitempty"`

	// KubernetesNodeName identifies the Kubernetes Node represented by a
	// node-local-pool actor.
	// +optional
	KubernetesNodeName string `json:"kubernetesNodeName,omitempty"`

	// GarageNodeUID anchors the actor to one immutable GarageNode incarnation.
	// It is recorded for StatefulSet and node-local-pool actors alike.
	GarageNodeUID string `json:"garageNodeUid"`

	// GarageNodeID is the exact Garage identity reported by the selected actor
	// before its Pod is deleted. A replacement must rediscover this same identity;
	// a new ID under the same Kubernetes objects is never accepted as a handoff.
	GarageNodeID string `json:"garageNodeId"`

	// WorkloadUID is the exact StatefulSet or DaemonSet controller incarnation
	// authorized to create and replace this actor's Pod.
	WorkloadUID string `json:"workloadUid"`

	// RetiredWorkloadUIDs records workload-controller incarnations that were
	// replaced behind a scheduling fence. Late Pods from these exact UIDs remain
	// identifiable without trusting reused names; node-local-pool recovery waits
	// for them to disappear rather than deleting healthy non-candidate members.
	// Recovery fails closed before a 33rd retired controller incarnation so this
	// exact old-Pod exclusion set remains bounded in parent status.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	RetiredWorkloadUIDs []string `json:"retiredWorkloadUids,omitempty"`

	// PersistentVolumeClaims anchors a StatefulSet-backed actor to every exact
	// PVC mounted by the Pod selected for replacement. Recreated/deleting claims
	// fail closed so controller-incarnation recovery cannot bind empty storage or
	// silently create a new Garage identity under a reused claim name. Empty for
	// node-local-pool HostPath actors.
	// +optional
	PersistentVolumeClaims []StorageRolloutPersistentVolumeClaimStatus `json:"persistentVolumeClaims,omitempty"`

	// StatefulSetWorkloadRecreationSafe records that the selected StatefulSet's
	// volumeClaimTemplate retention policy does not delete claims when the
	// StatefulSet is deleted. It is false for node-local-pool actors and causes missing
	// StatefulSet recovery to fail closed when claim retention was unsafe.
	// +optional
	StatefulSetWorkloadRecreationSafe bool `json:"statefulSetWorkloadRecreationSafe,omitempty"`

	// KubernetesNodeUID anchors a node-local-pool actor to the Kubernetes Node
	// incarnation whose HostPath storage was validated. Empty for StatefulSets.
	// +optional
	KubernetesNodeUID string `json:"kubernetesNodeUid,omitempty"`

	// WorkloadFenced is true after a replacement StatefulSet/DaemonSet UID was
	// CAS-adopted but before that controller was allowed to schedule its first
	// Pod (replicas=0 for StatefulSet, impossible nodeSelector for DaemonSet).
	// +optional
	WorkloadFenced bool `json:"workloadFenced,omitempty"`

	// PreviousPodUID is persisted before the OnDelete pod is deleted. Recovery
	// never accepts this UID as the completed replacement.
	PreviousPodUID string `json:"previousPodUid"`

	// DesiredPodSpecHash is the operator-computed pod template revision.
	DesiredPodSpecHash string `json:"desiredPodSpecHash"`

	// DesiredConfigHash is the rendered Garage configuration revision.
	DesiredConfigHash string `json:"desiredConfigHash"`

	// ClusterGeneration is the most recent recovery-safe GarageCluster spec
	// generation published into this actor's desired workload template.
	// +optional
	ClusterGeneration int64 `json:"clusterGeneration,omitempty"`

	// GarageNodeGeneration is the exact actor's most recently published
	// workload-safe spec generation, including the generated GarageNode behind a
	// node-local-pool actor.
	// +optional
	GarageNodeGeneration int64 `json:"garageNodeGeneration,omitempty"`

	// RecoveryRequest is the last recover-storage-rollout annotation nonce the
	// controller durably consumed before deleting a failed replacement again.
	// +optional
	RecoveryRequest string `json:"recoveryRequest,omitempty"`

	// RecoveryPodName and RecoveryPodUID identify the one failed replacement
	// durably selected for retry deletion. They are written before DELETE and
	// retained until that exact UID is absent, making the operation idempotent
	// across manager and API failures. Both are empty when no retry deletion is
	// pending.
	// +optional
	RecoveryPodName string `json:"recoveryPodName,omitempty"`
	// +optional
	RecoveryPodUID string `json:"recoveryPodUid,omitempty"`
}

// StorageRolloutPersistentVolumeClaimStatus is one immutable claim-incarnation
// boundary captured before an OnDelete Pod handoff.
type StorageRolloutPersistentVolumeClaimStatus struct {
	// Name is the namespaced PVC referenced by the selected Pod.
	Name string `json:"name"`
	// UID is the exact Kubernetes PVC incarnation that contains the actor's
	// metadata/data at selection time.
	UID string `json:"uid"`
}

// AutoModePVCHandoffStatus authorizes one exact retained PVC incarnation to
// move from a deleted Auto-mode GarageNode to its replacement. The parent
// GarageCluster status is the trust boundary: predictable object names and
// user-writable labels or annotations are never sufficient to adopt a claim.
type AutoModePVCHandoffStatus struct {
	// SlotName is the stable Auto-mode slot (for example, cluster-gateway-1).
	SlotName string `json:"slotName"`

	// PVCName and PVCUID identify the exact retained claim incarnation.
	PVCName string `json:"pvcName"`
	PVCUID  string `json:"pvcUid"`

	// PreviousGarageNodeUID is the exact deleted GarageNode incarnation that
	// reserved the claim.
	PreviousGarageNodeUID string `json:"previousGarageNodeUid"`

	// ReplacementReservationHash is a one-way commitment to the nonce placed
	// on the controller-created replacement GarageNode. It closes the crash gap
	// between Create and recording the replacement object's API-server UID.
	ReplacementReservationHash string `json:"replacementReservationHash,omitempty"`

	// ReplacementGarageNodeUID is the only new GarageNode incarnation allowed
	// to consume this handoff.
	ReplacementGarageNodeUID string `json:"replacementGarageNodeUid,omitempty"`
}

// StorageDrainActorStatus identifies the one Kubernetes object authorized to
// advance a storage-drain transaction. UID is the ownership boundary: names
// and namespaces can be reused after deletion.
type StorageDrainActorStatus struct {
	// APIVersion is the actor's Kubernetes API version.
	APIVersion string `json:"apiVersion"`

	// Kind is GarageCluster for a cluster-wide Drain deletion or GarageNode for
	// one logical storage member's permanent role removal.
	// +kubebuilder:validation:Enum=GarageCluster;GarageNode
	Kind string `json:"kind"`

	// Namespace is the actor's Kubernetes namespace.
	Namespace string `json:"namespace"`

	// Name is the actor's Kubernetes object name.
	Name string `json:"name"`

	// UID is the immutable Kubernetes UID of the actor incarnation.
	UID string `json:"uid"`
}

// StorageDrainStatus is the cluster-wide, durable data-safety transaction used
// before the operator stops a positive-capacity Garage process. In literal
// consistent mode, settled Garage layout history proves quorum-safe convergence
// across every registered table, including block_ref; it does not claim that
// every replica is identical. A transaction then proves exact Blocks repair and
// delayed block-resync completion. Automatic drain is unsupported in degraded
// or dangerous mode because upstream discards the old layout before that table
// barrier. While non-nil, every ordinary writer to this Garage layout is
// excluded; only Actor may advance the transaction.
type StorageDrainStatus struct {
	// Actor is the exact object authorized to advance this transaction.
	Actor StorageDrainActorStatus `json:"actor"`

	// TransactionID distinguishes separate drains owned by the same object UID.
	TransactionID string `json:"transactionId"`

	// TargetHash fingerprints both normalized target sets. Every status
	// update compares both transactionId and targetHash so a stale reconcile
	// cannot overwrite a newer target revision owned by the same actor.
	TargetHash string `json:"targetHash"`

	// StartedAt records when the pre-Apply removal intent became durable.
	StartedAt metav1.Time `json:"startedAt"`

	// RoleRemovalNodeIDs is the sorted set of every exact Garage layout role this
	// actor is authorized to remove, including capacityless gateway roles in a
	// unified cluster Drain.
	RoleRemovalNodeIDs []string `json:"roleRemovalNodeIds"`

	// RemovedStorageNodeIDs is the sorted positive-capacity subset whose removal
	// requires block-migration proof. Recording it before Apply keeps the safety
	// gate durable across controller crashes and Admin API failures.
	RemovedStorageNodeIDs []string `json:"removedStorageNodeIds"`

	// UnavailableSourceNodeIDs is the sorted subset of removedStorageNodeIds
	// whose processes and local disks were explicitly acknowledged as
	// permanently lost. Those sources cannot run the normal Blocks scan; the
	// terminal proof instead covers every surviving positive-capacity
	// destination after an administrator removes the exact dead role through
	// Garage's recovery workflow. Data present only on a listed source may be
	// lost.
	// +optional
	UnavailableSourceNodeIDs []string `json:"unavailableSourceNodeIds,omitempty"`

	// LayoutVersion is the current Garage layout version observed with these
	// verification processes and queue counters.
	LayoutVersion uint64 `json:"layoutVersion"`

	// VerificationNodeIDs is the sorted union of removed source processes and
	// current positive-capacity destinations covered by this transaction's
	// completed block-repair scans.
	// +optional
	VerificationNodeIDs []string `json:"verificationNodeIds,omitempty"`

	// ManagedPodUIDs fingerprints the exact locally managed Garage processes
	// observed when this proof revision started. Any pod replacement invalidates
	// worker-ID baselines because Garage worker counters can restart from zero.
	// Keys are full Garage node IDs and values are Kubernetes Pod UIDs.
	// +optional
	ManagedPodUIDs map[string]string `json:"managedPodUids,omitempty"`

	// RepairBaselines records each storage node's highest worker ID before the
	// operator launches a transaction-specific Blocks repair. It is persisted
	// before launch so a crash cannot lose ownership of the resulting worker.
	RepairBaselines map[string]uint64 `json:"repairBaselines,omitempty"`

	// RepairWorkerIDs records the exact post-baseline Blocks repair worker whose
	// clean completion was observed on each source and destination process in
	// VerificationNodeIDs.
	RepairWorkerIDs map[string]uint64 `json:"repairWorkerIds,omitempty"`

	// ResyncErrorBaselines records the cumulative error counter of every exact
	// enabled block-resync worker after all repair scans complete. Any increase
	// restarts the repair transaction.
	ResyncErrorBaselines map[string]uint64 `json:"resyncErrorBaselines,omitempty"`

	// QueueLength is the observed aggregate block-resync queue depth. It is
	// informational: Garage also queues future garbage collection, so readiness
	// is based on completed repair workers and idle resync workers instead.
	QueueLength uint64 `json:"queueLength"`

	// ErrorCount is the aggregate number of block resync errors.
	ErrorCount uint64 `json:"errorCount"`

	// RequiresEmptyQueue is true when at least one verification process is not
	// proven to use this GarageCluster's authoritative RPC timeout. In that case
	// the normally informational future-work queue must also become empty.
	RequiresEmptyQueue bool `json:"requiresEmptyQueue"`

	// QuietSince starts after every exact repair worker completes without errors
	// and resync-worker error baselines are recorded. The operator waits through
	// Garage's maximum known delayed-resync interval, then requires every exact
	// resync worker idle and error-free before a process may be stopped.
	// +optional
	QuietSince *metav1.Time `json:"quietSince,omitempty"`

	// CompletedAt is set only after exact repair workers completed cleanly and
	// every enabled block-resync worker passed the terminal safety checks. The
	// transaction remains active until Actor completes its Kubernetes handoff.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
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

	// Selector is the aggregate serialized label selector for pods managed by
	// this cluster. It is not used by the scale subresource.
	Selector string `json:"selector"`

	// ScaleReplicas is the actual number of non-terminating Pods in the
	// workload projected through the requested API version's scale subresource.
	// For storage and unified clusters this is only the Auto-managed default
	// StatefulSet/PVC group; node-local pools, Manual GarageNodes, and unified
	// gateways are excluded. A gateway-only hub object carries its gateway Pod
	// count solely to preserve the legacy v1beta1 Scale projection; v1beta2
	// gateway-only Scale updates are rejected.
	// +optional
	ScaleReplicas int32 `json:"scaleReplicas,omitempty"`

	// ScaleSelector is the serialized exact selector for the Pods counted by
	// ScaleReplicas. It normally selects the default storage group; on a
	// gateway-only hub object it selects the gateway Pods for legacy v1beta1
	// Scale reads. It is kept separate from the aggregate Selector so hidden
	// workloads cannot make /scale fail to converge.
	// +optional
	ScaleSelector string `json:"scaleSelector,omitempty"`

	// ClusterID is the unique identifier of the Garage cluster.
	// +optional
	ClusterID string `json:"clusterId,omitempty"`

	// BuildInfo contains Garage build information.
	// +optional
	BuildInfo *GarageBuildInfo `json:"buildInfo,omitempty"`

	// ReadyReplicas is the number of ready Garage pods.
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// StorageReplicas is the aggregate desired/current storage identity count
	// across the default group, ordinary Manual GarageNodes, and node-local
	// pools. Use ScaleReplicas for the narrow Kubernetes Scale projection.
	// +optional
	StorageReplicas int32 `json:"storageReplicas,omitempty"`

	// StorageReadyReplicas is the aggregate number of storage identities that
	// are connected and committed in Garage's layout.
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

	// StorageDrain records the single cluster-wide positive-capacity removal and
	// block-migration proof. It excludes every other layout mutation until the
	// exact actor completes its Kubernetes handoff.
	// +optional
	StorageDrain *StorageDrainStatus `json:"storageDrain,omitempty"`

	// AutoModePVCHandoffs are controller-owned, exact-UID authorizations for
	// retained Auto-mode claims whose GarageNode slot was scaled down and later
	// recreated. Entries are removed after the replacement binds the exact PVC.
	// +optional
	// +listType=map
	// +listMapKey=pvcName
	AutoModePVCHandoffs []AutoModePVCHandoffStatus `json:"autoModePvcHandoffs,omitempty"`

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

	// UnreachablePeers lists peers that have been continuously down beyond the
	// sustained-unreachable threshold, each as "<shortNodeId> (down <duration>)".
	// Drives the PeerUnreachable condition. Empty when all peers are reachable.
	// +optional
	UnreachablePeers []string `json:"unreachablePeers,omitempty"`

	// GatewayNodesNotInLayout lists operator-owned gateway GarageNodes that report
	// status.inLayout == false — they have lost the capacity:nil layout role that
	// keeps S3 sig-auth data replicated locally (#209), so signed requests can
	// fail with "No such key".
	// Drives the GatewayLayoutDegraded condition. Empty when every gateway node
	// holds its role.
	// +optional
	GatewayNodesNotInLayout []string `json:"gatewayNodesNotInLayout,omitempty"`

	// StorageRollout is the controller-owned durable record for the single
	// managed storage/gateway pod currently being replaced. Nil when no
	// parent-controlled rollout handoff is active.
	// +optional
	StorageRollout *StorageRolloutStatus `json:"storageRollout,omitempty"`

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

	// Versions contains at most 64 current, draining, and recent historical
	// layout versions for diagnosis. Controller safety decisions read Garage's
	// complete live layout history instead of relying on this bounded projection.
	// +kubebuilder:validation:MaxItems=64
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

	// Force records whether the trigger carried the ,force flag (overriding the
	// dangerous-mode / pending-tombstone guards). Captured at start because the
	// annotation is consumed immediately.
	// +optional
	Force bool `json:"force,omitempty"`

	// PurgeID uniquely identifies this migration; it is the marker-file suffix the
	// per-node init container uses so the on-disk cluster_layout is deleted exactly
	// once even across extra restarts.
	// +optional
	PurgeID string `json:"purgeId,omitempty"`

	// StartedAt is when the migration began.
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// PhaseStartedAt is when the current Phase was entered. It is reset on every
	// phase transition and bounds each wait phase independently of the overall
	// migration duration, so a single phase that hangs (e.g. a node whose
	// status.nodeId never repopulates after restart) trips the stuck guard
	// rather than the whole migration sharing one global deadline.
	// +optional
	PhaseStartedAt *metav1.Time `json:"phaseStartedAt,omitempty"`

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
// +kubebuilder:subresource:scale:specpath=.spec.storage.replicas,statuspath=.status.scaleReplicas,selectorpath=.status.scaleSelector
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
