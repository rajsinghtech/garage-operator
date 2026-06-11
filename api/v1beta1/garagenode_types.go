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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeNetworkConfig configures per-node RPC address overrides.
// Parallel to GarageCluster's NetworkConfig but scoped to node-level settings.
// Only fields that meaningfully differ per-node are included here; all other
// network settings are inherited from the parent GarageCluster.
type NodeNetworkConfig struct {
	// RPCPublicAddr is the externally-routable RPC address for this node (host:port).
	// Overrides the cluster-level network.rpcPublicAddr for this specific node.
	// When publicEndpoint is also set to LoadBalancer and this is empty, the operator
	// derives rpc_public_addr from the assigned LoadBalancer ingress IP automatically.
	// +optional
	RPCPublicAddr string `json:"rpcPublicAddr,omitempty"`
}

// NodeStorageConfig configures storage volumes for a GarageNode.
// Parallel to GarageCluster's StorageConfig, with the addition of existingClaim
// to support pre-provisioned PVCs.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.data) && has(self.dataPaths) && size(self.dataPaths) > 0)",message="storage.data and storage.dataPaths are mutually exclusive"
type NodeStorageConfig struct {
	// Metadata volume for node identity and cluster state.
	// +optional
	Metadata *NodeVolumeConfig `json:"metadata,omitempty"`

	// Data volume for block storage. Ignored for gateway nodes.
	// Mutually exclusive with DataPaths.
	// +optional
	Data *NodeVolumeConfig `json:"data,omitempty"`

	// DataPaths configures multiple data directories for multi-HDD nodes.
	// Each entry produces a separate volume/mount/PVC at /var/lib/garage/data-<idx>
	// and the corresponding garage.toml `data_dir = [...]` array form. Use this for
	// multi-HDD nodes; mutually exclusive with .data.
	// +optional
	DataPaths []NodeVolumeConfig `json:"dataPaths,omitempty"`

	// MetadataFsync enables fsync on metadata writes for this node.
	// Overrides the cluster-level storage.metadataFsync setting.
	// +optional
	MetadataFsync *bool `json:"metadataFsync,omitempty"`

	// DataFsync enables fsync on data block writes for this node.
	// Overrides the cluster-level storage.dataFsync setting.
	// +optional
	DataFsync *bool `json:"dataFsync,omitempty"`

	// MetadataSnapshotsDir overrides the cluster-level storage.metadataSnapshotsDir
	// (garage.toml `metadata_snapshots_dir`) for this node.
	// +optional
	MetadataSnapshotsDir string `json:"metadataSnapshotsDir,omitempty"`

	// MetadataAutoSnapshotInterval overrides the cluster-level
	// storage.metadataAutoSnapshotInterval (garage.toml `metadata_auto_snapshot_interval`)
	// for this node.
	// +kubebuilder:validation:Pattern=`^(\d+(\.\d+)?\s*(ns|us|ms|s|m|h|d|w|M|y)\s*)+$`
	// +optional
	MetadataAutoSnapshotInterval string `json:"metadataAutoSnapshotInterval,omitempty"`
}

// NodeLoggingConfig overrides per-node logging behavior. Fields are independent
// of the cluster-level LoggingConfig but apply only to this node's pod.
type NodeLoggingConfig struct {
	// Level sets the log level using RUST_LOG format.
	// +optional
	Level string `json:"level,omitempty"`

	// Syslog enables logging to syslog. When nil, inherits cluster-level setting.
	// +optional
	Syslog *bool `json:"syslog,omitempty"`

	// Journald enables logging to systemd journald. When nil, inherits cluster-level setting.
	// +optional
	Journald *bool `json:"journald,omitempty"`
}

// NodeVolumeConfig defines the source of a storage volume for a GarageNode.
// Parallel to GarageCluster's VolumeConfig, extended with existingClaim for
// pre-provisioned PVCs. Either ExistingClaim or Size must be specified.
//
// ExistingClaim and Size may also be set together inside a multi-HDD
// `storage.dataPaths[]` entry — there ExistingClaim binds the PVC and Size
// is the capacity advertised to Garage in `data_dir = [{path, capacity}]`.
// Combining them on `storage.{metadata,data}` is allowed by the webhook but
// has no effect since those slots don't emit a TOML capacity field.
type NodeVolumeConfig struct {
	// ExistingClaim references a pre-existing PVC by name in the cluster namespace.
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// Size creates a dynamically provisioned PVC with this capacity. For
	// multi-HDD `storage.dataPaths[]` entries it may also be set alongside
	// `existingClaim` to declare the capacity advertised to Garage.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// StorageClassName for the dynamically provisioned PVC.
	// Uses the cluster default if not specified.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Type specifies the volume type. Defaults to PVC.
	// Use EmptyDir for ephemeral storage (e.g. testing).
	// +kubebuilder:validation:Enum=PVC;EmptyDir
	// +optional
	Type VolumeType `json:"type,omitempty"`

	// AccessModes for the dynamically provisioned PVC.
	// Defaults to [ReadWriteOnce] if not specified.
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Path is the in-container mount path for this volume. Only honored on
	// multi-HDD `storage.dataPaths[]` entries — both the K8s volumeMount and
	// the rendered garage.toml `data_dir = [{ path = ... }]` use this value.
	// Defaults to `/data/data-<i>` when unset. The legacy-STS migration
	// propagates `cluster.spec.storage.data.paths[i].path` so that on first
	// boot Garage's DataLayout sees the same paths it stored under
	// pre-migration, avoiding partition reassignment and unnecessary
	// cross-peer block refetch (../garage src/block/layout.rs).
	// +optional
	Path string `json:"path,omitempty"`

	// ReadOnly marks the entry as a legacy read-only path on multi-HDD
	// `storage.dataPaths[]`. Renders as garage.toml `read_only = true`;
	// no `capacity` is emitted. Ignored on `storage.{metadata,data}`.
	// +optional
	ReadOnly bool `json:"readOnly,omitempty"`
}

// GarageNodeSpec defines the desired state of GarageNode.
//
// GarageNode is only used when the parent GarageCluster has layoutPolicy: Manual.
// In Manual mode, the cluster StatefulSet is not created — instead, each GarageNode
// creates its own single-replica StatefulSet with independent storage configuration.
//
// Use Manual layout when you need:
//   - Heterogeneous storage (different size or storage class per node)
//   - Per-node CPU/memory resource limits
//   - Fine-grained zone assignment within a cluster
//   - External nodes (VMs, bare metal, or nodes in another K8s cluster)
//
// For uniform clusters, prefer layoutPolicy: Auto — the operator handles everything
// without creating GarageNode resources.
//
// Pod configuration fields are inherited from the parent GarageCluster and can be
// overridden per-node. Fields not specified here fall through to the cluster default.
//
// +kubebuilder:validation:XValidation:rule="self.gateway || has(self.external) || has(self.capacity)",message="capacity is required for non-gateway managed nodes"
type GarageNodeSpec struct {
	// ClusterRef references the GarageCluster this node belongs to.
	// The GarageNode inherits configuration from this cluster.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// NodeID is the public key of the Garage node.
	// If not specified, the operator will auto-discover from the pod.
	// +kubebuilder:validation:Pattern=`^[a-fA-F0-9]{64}$`
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Zone is the zone assignment for this node.
	// Used for data placement and fault tolerance.
	// +required
	Zone string `json:"zone"`

	// Capacity is the storage capacity to report to Garage for this node.
	// Required unless Gateway is true.
	// +optional
	Capacity *resource.Quantity `json:"capacity,omitempty"`

	// Gateway marks this node as a gateway-only node (no storage).
	// Gateway nodes handle API requests but don't store data blocks.
	// +optional
	Gateway bool `json:"gateway"`

	// Tags are custom tags for this node in the Garage layout.
	// +optional
	Tags []string `json:"tags,omitempty"`

	// External marks this node as an external node (not managed by this operator).
	// When set, no StatefulSet is created - the node is assumed to exist externally.
	// +optional
	External *ExternalNodeConfig `json:"external,omitempty"`

	// Storage configures storage volumes for this node's StatefulSet.
	// Required for managed nodes (not External).
	// +optional
	Storage *NodeStorageConfig `json:"storage,omitempty"`

	// ---- Pod Configuration Overrides ----
	// These fields override the defaults inherited from GarageCluster.

	// Image overrides the Garage container image.
	// If not specified, inherits from GarageCluster.
	// +optional
	Image string `json:"image,omitempty"`

	// ImageRepository overrides just the repository portion of the Garage image.
	// If not specified, inherits from GarageCluster.
	// Ignored if image is set.
	// +optional
	ImageRepository string `json:"imageRepository,omitempty"`

	// Resources overrides compute resources for the Garage container.
	// If not specified, inherits from GarageCluster.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector overrides node selection constraints.
	// If not specified, inherits from GarageCluster.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations overrides pod tolerations.
	// If not specified, inherits from GarageCluster.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity overrides pod affinity rules.
	// If not specified, inherits from GarageCluster.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// PodAnnotations are additional annotations to add to this node's pod.
	// Merged with annotations from GarageCluster (node-specific takes precedence).
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// PodLabels are additional labels to add to this node's pod.
	// Merged with labels from GarageCluster (node-specific takes precedence).
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// PriorityClassName overrides the priority class for this node's pod.
	// If not specified, inherits from GarageCluster.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// ImagePullPolicy overrides the image pull policy for this node's container.
	// If not specified, inherits from GarageCluster.
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// ImagePullSecrets overrides the image pull secrets for this node's pod.
	// If not specified, inherits from GarageCluster.
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// ServiceAccountName overrides the service account for this node's pod.
	// If not specified, inherits from GarageCluster.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// SecurityContext overrides the pod-level security context for this node.
	// If not specified, inherits from GarageCluster.
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// ContainerSecurityContext overrides the container-level security context for this node.
	// If not specified, inherits from GarageCluster.
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// TopologySpreadConstraints overrides topology spread constraints for this node's pod.
	// If not specified, inherits from GarageCluster.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Network configures per-node RPC address overrides.
	// Parallel to GarageCluster's spec.network but scoped to this node only.
	// +optional
	Network *NodeNetworkConfig `json:"network,omitempty"`

	// PublicEndpoint configures a Kubernetes Service exposing this node's RPC port.
	// Parallel to GarageCluster's spec.publicEndpoint. When set to LoadBalancer type
	// without network.rpcPublicAddr, the operator derives rpc_public_addr from the
	// assigned ingress IP automatically.
	// +optional
	PublicEndpoint *PublicEndpointConfig `json:"publicEndpoint,omitempty"`

	// Maintenance configures maintenance mode for this node.
	// +optional
	Maintenance *NodeMaintenanceSpec `json:"maintenance,omitempty"`

	// Env overrides environment variables for this node's container. Merged with
	// cluster-level env (from spec.storage.env or spec.gateway.env, depending on
	// tier); per-node entries take precedence on key collision.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// EnvFrom overrides envFrom sources for this node's container. Replaces (does
	// not merge) the cluster-level envFrom when set.
	// +optional
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Logging overrides cluster-level spec.logging for this node. A non-nil field
	// here wins over the cluster value; a nil field falls through to the cluster.
	// +optional
	Logging *NodeLoggingConfig `json:"logging,omitempty"`
}

// NodeMaintenanceSpec configures maintenance mode for a single GarageNode.
// When Suspended is true, the operator pauses ALL reconciliation for this node:
// the StatefulSet, ConfigMap, per-node Service, and layout entry are left untouched
// so cluster operators can perform PVC maintenance, hardware swaps, or other manual
// operations without the operator fighting them. The node remains in the cluster
// layout as-is.
type NodeMaintenanceSpec struct {
	// Suspended pauses operator reconciliation for this node when true.
	// +optional
	Suspended bool `json:"suspended,omitempty"`
}

// ExternalNodeConfig configures an external node
type ExternalNodeConfig struct {
	// Address is the IP or hostname of the external node
	// +kubebuilder:validation:MinLength=1
	// +required
	Address string `json:"address"`

	// Port is the RPC port of the external node
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=3901
	Port int32 `json:"port,omitempty"`

	// RemoteClusterRef references a GarageCluster in another namespace/cluster
	// +optional
	RemoteClusterRef *ClusterReference `json:"remoteClusterRef,omitempty"`
}

// GarageNodeStatus defines the observed state of GarageNode
type GarageNodeStatus struct {
	// NodeID is the discovered or assigned node ID
	// +optional
	NodeID string `json:"nodeId,omitempty"`

	// Phase represents the current phase
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Ready;Degraded;Updating;Deleting;Failed;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// InLayout indicates if this node is part of the current layout
	// +optional
	InLayout bool `json:"inLayout"`

	// LayoutVersion is the layout version when this node was added
	// +optional
	LayoutVersion int64 `json:"layoutVersion,omitempty"`

	// Connected indicates if the node is currently connected
	// +optional
	Connected bool `json:"connected"`

	// LastSeen is when the node was last seen connected
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`

	// Address is the node's address in the cluster
	// +optional
	Address string `json:"address,omitempty"`

	// Hostname is the hostname reported by this Garage node
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// Tags are the tags assigned to this node in the layout
	// +optional
	Tags []string `json:"tags,omitempty"`

	// DataPartition contains disk space info for the data partition
	// Note: Garage reports a single partition even with multiple data paths
	// +optional
	DataPartition *DiskPartitionStatus `json:"dataPartition,omitempty"`

	// MetadataPartition contains disk space info for the metadata partition
	// +optional
	MetadataPartition *DiskPartitionStatus `json:"metadataPartition,omitempty"`

	// Version is the Garage version on this node
	// +optional
	Version string `json:"version,omitempty"`

	// DBEngine is the database engine used by this node (lmdb, sqlite, fjall)
	// +optional
	DBEngine string `json:"dbEngine,omitempty"`

	// GarageFeatures lists the enabled Cargo features on this node
	// +optional
	GarageFeatures []string `json:"garageFeatures,omitempty"`

	// Partitions is the number of partitions assigned to this node
	// +optional
	Partitions int `json:"partitions,omitempty"`

	// StoredData is the amount of data stored on this node
	// +optional
	StoredData *resource.Quantity `json:"storedData,omitempty"`

	// RepairInProgress indicates if a repair operation is running
	// +optional
	RepairInProgress bool `json:"repairInProgress"`

	// RepairType is the type of repair operation in progress
	// +optional
	RepairType string `json:"repairType,omitempty"`

	// RepairProgress is a human-readable repair progress description
	// +optional
	RepairProgress string `json:"repairProgress,omitempty"`

	// BlockErrors is the count of blocks with sync errors on this node
	// +optional
	BlockErrors int32 `json:"blockErrors,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClusterAdminEndpoint is the resolved Garage Admin API endpoint last used
	// to manage this node's layout entry. Captured on each successful reconcile
	// so that a delete-time finalizer can still attempt to drop the layout
	// entry when the parent GarageCluster CR has already been deleted (edge
	// gateway pattern via spec.connectTo.adminApiEndpoint).
	// +optional
	ClusterAdminEndpoint string `json:"clusterAdminEndpoint,omitempty"`

	// ClusterAdminTokenSecretRef references the Admin API token secret last
	// used to manage this node's layout entry. The secret lives in the same
	// namespace as the GarageNode. Paired with ClusterAdminEndpoint to enable
	// best-effort finalize against an external admin API after the parent
	// GarageCluster CR is gone.
	// +optional
	ClusterAdminTokenSecretRef *corev1.SecretKeySelector `json:"clusterAdminTokenSecretRef,omitempty"`

	// CyclePhase tracks progress of a graceful node cycle triggered by the
	// garage.rajsingh.info/cycle annotation. Empty when no cycle is active.
	// Used to make the add-before-remove state machine resumable/idempotent
	// across requeues: a non-empty value means a sibling has already been
	// provisioned, so the operator continues the swap rather than re-provisioning.
	// +kubebuilder:validation:Enum=Provisioning;Syncing;Draining
	// +optional
	CyclePhase string `json:"cyclePhase,omitempty"`

	// CycleSiblingName is the name of the sibling GarageNode provisioned for an
	// in-progress cycle (the replacement that takes over this node's layout slot).
	// +optional
	CycleSiblingName string `json:"cycleSiblingName,omitempty"`

	// CycleSiblingNodeID is the discovered Garage node ID of the cycle sibling,
	// used to check its layout sync tracker before this node is removed.
	// +optional
	CycleSiblingNodeID string `json:"cycleSiblingNodeId,omitempty"`

	// Conditions represent the current state
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DiskPartitionStatus contains disk space information for a partition
type DiskPartitionStatus struct {
	// Available is the available disk space
	// +optional
	Available *resource.Quantity `json:"available,omitempty"`

	// Total is the total disk space
	// +optional
	Total *resource.Quantity `json:"total,omitempty"`

	// UsedPercent is the percentage of disk space used (0-100)
	// +optional
	UsedPercent int32 `json:"usedPercent,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gn
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Zone",type="string",JSONPath=".spec.zone"
// +kubebuilder:printcolumn:name="Capacity",type="string",JSONPath=".spec.capacity"
// +kubebuilder:printcolumn:name="Gateway",type="boolean",JSONPath=".spec.gateway"
// +kubebuilder:printcolumn:name="Connected",type="boolean",JSONPath=".status.connected"
// +kubebuilder:printcolumn:name="InLayout",type="boolean",JSONPath=".status.inLayout"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageNode is the Schema for the garagenodes API
type GarageNode struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageNodeSpec `json:"spec"`

	// +optional
	Status GarageNodeStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageNodeList contains a list of GarageNode
type GarageNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageNode `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageNode{}, &GarageNodeList{})
}
