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

// Common condition types used across all Garage CRDs
const (
	// ConditionReady indicates the resource is fully reconciled and operational
	ConditionReady = "Ready"

	// ConditionReconciling indicates the resource is being reconciled
	ConditionReconciling = "Reconciling"

	// ConditionDegraded indicates the resource is operational but not fully healthy
	ConditionDegraded = "Degraded"

	// ConditionError indicates the resource encountered an error during reconciliation
	ConditionError = "Error"
)

// GarageCluster condition types
const (
	// ConditionClusterHealthy indicates the Garage cluster is healthy
	ConditionClusterHealthy = "ClusterHealthy"

	// ConditionLayoutApplied indicates the layout has been applied
	ConditionLayoutApplied = "LayoutApplied"

	// ConditionLayoutStaged indicates there are staged layout changes
	ConditionLayoutStaged = "LayoutStaged"

	// ConditionNodesConnected indicates all nodes are connected
	ConditionNodesConnected = "NodesConnected"

	// ConditionFederationReady indicates multi-cluster federation is operational
	ConditionFederationReady = "FederationReady"

	// ConditionStatefulSetReady indicates the StatefulSet is ready
	ConditionStatefulSetReady = "StatefulSetReady"

	// ConditionServicesReady indicates all services are created and ready
	ConditionServicesReady = "ServicesReady"

	// ConditionGatewayConnected indicates a gateway cluster's connection to its storage cluster.
	// False when the admin token is missing or the connection cannot be established.
	ConditionGatewayConnected = "GatewayConnected"

	// ConditionPublicEndpointReady indicates the publicEndpoint configuration is valid and operational.
	ConditionPublicEndpointReady = "PublicEndpointReady"
)

// GarageBucket condition types
const (
	// ConditionBucketCreated indicates the bucket has been created in Garage
	ConditionBucketCreated = "BucketCreated"

	// ConditionQuotaConfigured indicates bucket quotas have been configured
	ConditionQuotaConfigured = "QuotaConfigured"

	// ConditionWebsiteConfigured indicates website hosting has been configured
	ConditionWebsiteConfigured = "WebsiteConfigured"

	// ConditionLifecycleConfigured indicates lifecycle rules have been configured
	ConditionLifecycleConfigured = "LifecycleConfigured"

	// ConditionAliasesConfigured indicates bucket aliases have been configured
	ConditionAliasesConfigured = "AliasesConfigured"
)

// GarageKey condition types
const (
	// ConditionKeyCreated indicates the key has been created in Garage
	ConditionKeyCreated = "KeyCreated"

	// ConditionSecretCreated indicates the Kubernetes secret has been created
	ConditionSecretCreated = "SecretCreated"

	// ConditionPermissionsConfigured indicates bucket permissions have been configured
	ConditionPermissionsConfigured = "PermissionsConfigured"

	// ConditionKeyExpired indicates the key has expired
	ConditionKeyExpired = "KeyExpired"
)

// GarageNode condition types
const (
	// ConditionNodeDiscovered indicates the node ID has been discovered
	ConditionNodeDiscovered = "NodeDiscovered"

	// ConditionInLayout indicates the node is part of the cluster layout
	ConditionInLayout = "InLayout"

	// ConditionNodeConnected indicates the node is connected to the cluster
	ConditionNodeConnected = "NodeConnected"

	// ConditionDraining indicates the node is being drained
	ConditionDraining = "Draining"
)

// GarageAdminToken condition types
const (
	// ConditionTokenCreated indicates the admin token has been created
	ConditionTokenCreated = "TokenCreated"

	// ConditionTokenSecretCreated indicates the token secret has been created
	ConditionTokenSecretCreated = "TokenSecretCreated"

	// ConditionTokenExpired indicates the token has expired
	ConditionTokenExpired = "TokenExpired"
)

// Common condition reasons
const (
	// ReasonReconcileSuccess indicates successful reconciliation
	ReasonReconcileSuccess = "ReconcileSuccess"

	// ReasonReconcileFailed indicates failed reconciliation
	ReasonReconcileFailed = "ReconcileFailed"

	// ReasonReconcileInProgress indicates reconciliation is in progress
	ReasonReconcileInProgress = "ReconcileInProgress"

	// ReasonAPIError indicates an error communicating with the Garage API
	ReasonAPIError = "GarageAPIError"

	// ReasonNotFound indicates a resource was not found
	ReasonNotFound = "NotFound"

	// ReasonCreating indicates a resource is being created
	ReasonCreating = "Creating"

	// ReasonUpdating indicates a resource is being updated
	ReasonUpdating = "Updating"

	// ReasonDeleting indicates a resource is being deleted
	ReasonDeleting = "Deleting"

	// ReasonWaitingForDependency indicates waiting for a dependency
	ReasonWaitingForDependency = "WaitingForDependency"

	// ReasonClusterNotReady indicates the Garage cluster is not ready
	ReasonClusterNotReady = "ClusterNotReady"

	// ReasonExpired indicates the resource has expired
	ReasonExpired = "Expired"

	// ReasonValidationFailed indicates validation failed
	ReasonValidationFailed = "ValidationFailed"

	// ReasonAdminTokenMissing indicates spec.admin.adminTokenSecretRef is required but not configured
	ReasonAdminTokenMissing = "AdminTokenMissing"

	// ReasonAdminUnreachable indicates the external cluster's admin API cannot be reached
	ReasonAdminUnreachable = "AdminUnreachable"

	// ReasonGatewayConnected indicates bidirectional RPC connectivity is established
	ReasonGatewayConnected = "Connected"

	// ReasonGatewayPartiallyConnected indicates only gateway→external is working;
	// the external cluster cannot reach the gateway (check publicEndpoint / rpcPublicAddr)
	ReasonGatewayPartiallyConnected = "PartiallyConnected"

	// ReasonGatewayNodesOffline indicates no nodes are connected in either direction
	ReasonGatewayNodesOffline = "NodesOffline"

	// ReasonPerNodeNotImplemented indicates publicEndpoint.loadBalancer.perNode is not yet supported;
	// use network.rpcPublicAddr as a workaround
	ReasonPerNodeNotImplemented = "PerNodeNotImplemented"
)

// Annotation keys for operational tasks
const (
	// AnnotationPrefix is the prefix for all garage operator annotations
	AnnotationPrefix = "garage.rajsingh.info/"

	// GarageCluster annotations

	// AnnotationTriggerSnapshot triggers a metadata snapshot on all nodes when set to "true"
	AnnotationTriggerSnapshot = AnnotationPrefix + "trigger-snapshot"

	// AnnotationPauseReconcile pauses reconciliation when set to "true".
	// Deprecated: use spec.maintenance.suspended instead.
	AnnotationPauseReconcile = AnnotationPrefix + "pause-reconcile"

	// AnnotationForceLayoutApply forces applying staged layout changes when set to "true"
	AnnotationForceLayoutApply = AnnotationPrefix + "force-layout-apply"

	// AnnotationSkipDeadNodes skips unresponsive nodes during layout changes when set to "true"
	AnnotationSkipDeadNodes = AnnotationPrefix + "skip-dead-nodes"

	// AnnotationAllowMissingData allows skipping nodes even if quorum is missing when set to "true"
	// Use with caution - this can result in data loss
	AnnotationAllowMissingData = AnnotationPrefix + "allow-missing-data"

	// AnnotationConnectNodes specifies nodes to connect to (format: "nodeId@addr:port,...")
	AnnotationConnectNodes = AnnotationPrefix + "connect-nodes"

	// GarageNode annotations

	// AnnotationDrain drains data from a node before removal when set to "true"
	AnnotationDrain = AnnotationPrefix + "drain"

	// AnnotationSkipLayout excludes a node from the layout temporarily when set to "true"
	AnnotationSkipLayout = AnnotationPrefix + "skip-layout"

	// GarageBucket annotations

	// AnnotationCleanupMPU triggers cleanup of incomplete multipart uploads when set to "true"
	AnnotationCleanupMPU = AnnotationPrefix + "cleanup-mpu"

	// AnnotationCleanupMPUOlderThan specifies the age threshold for MPU cleanup (e.g., "24h", "7d")
	AnnotationCleanupMPUOlderThan = AnnotationPrefix + "cleanup-mpu-older-than"

	// GarageCluster repair/maintenance annotations

	// AnnotationTriggerRepair triggers a repair operation on the cluster
	// Valid values: Tables, Blocks, Versions, MultipartUploads, BlockRefs, BlockRc, Rebalance, Scrub
	// For Scrub, use AnnotationScrubCommand to control the scrub operation
	AnnotationTriggerRepair = AnnotationPrefix + "trigger-repair"

	// AnnotationScrubCommand controls scrub operations
	// Valid values: start, pause, resume, cancel
	// Only used when AnnotationTriggerRepair is set to "Scrub"
	AnnotationScrubCommand = AnnotationPrefix + "scrub-command"

	// AnnotationScrubTranquility sets the tranquility level for scrub operations
	// Higher values make scrub less aggressive (more pauses between checks)
	// Valid values: integer >= 0 (default: 2)
	AnnotationScrubTranquility = AnnotationPrefix + "scrub-tranquility"

	// AnnotationRevertLayout reverts to the previous layout version when set to "true"
	AnnotationRevertLayout = AnnotationPrefix + "revert-layout"

	// AnnotationRetryBlockResync retries block resync operations
	// Set to "true" to retry all blocks, or comma-separated block hashes for specific blocks
	AnnotationRetryBlockResync = AnnotationPrefix + "retry-block-resync"

	// AnnotationPurgeBlocks triggers block purge operation to clean up corrupted or orphaned blocks
	// Set to comma-separated block hashes to purge specific blocks
	// WARNING: This permanently removes block data - use with caution
	AnnotationPurgeBlocks = AnnotationPrefix + "purge-blocks"
)

// Valid repair operation types for AnnotationTriggerRepair
const (
	RepairTypeTables           = "Tables"
	RepairTypeBlocks           = "Blocks"
	RepairTypeVersions         = "Versions"
	RepairTypeMultipartUploads = "MultipartUploads"
	RepairTypeBlockRefs        = "BlockRefs"
	RepairTypeBlockRc          = "BlockRc"
	RepairTypeRebalance        = "Rebalance"
	RepairTypeScrub            = "Scrub"
	RepairTypeClearResyncQueue = "ClearResyncQueue"
	RepairTypeAliases          = "Aliases"
)

// Valid scrub commands for AnnotationScrubCommand
const (
	ScrubCommandStart  = "start"
	ScrubCommandPause  = "pause"
	ScrubCommandResume = "resume"
	ScrubCommandCancel = "cancel"
)

// Phase constants for status fields
const (
	// PhasePending indicates the resource is pending creation
	PhasePending = "Pending"

	// PhaseCreating indicates the resource is being created
	PhaseCreating = "Creating"

	// PhaseRunning indicates the resource is running/operational
	PhaseRunning = "Running"

	// PhaseReady indicates the resource is fully ready
	PhaseReady = "Ready"

	// PhaseDegraded indicates the resource is degraded but operational
	PhaseDegraded = "Degraded"

	// PhaseUpdating indicates the resource is being updated
	PhaseUpdating = "Updating"

	// PhaseDeleting indicates the resource is being deleted
	PhaseDeleting = "Deleting"

	// PhaseFailed indicates the resource has failed
	PhaseFailed = "Failed"

	// PhaseExpired indicates the resource has expired
	PhaseExpired = "Expired"

	// PhaseUnknown indicates the resource state is unknown
	PhaseUnknown = "Unknown"
)
