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

	// ConditionGatewayTombstones indicates stale gateway-tier layout entries
	// were detected but could not be auto-removed (autoApply disabled). Surface to
	// users so they know to clean up the layout, either by enabling autoApply or by
	// setting the force-layout-apply annotation.
	ConditionGatewayTombstones = "GatewayTombstones"

	// ConditionLegacySTSMigrated indicates the one-time migration from the
	// pre-#190 cluster-level storage StatefulSet to per-GarageNode workloads.
	// Status=True with Reason=Completed means either the migration finished
	// successfully or no legacy STS was present. Status=False with
	// Reason=InProgress or Reason=Failed surfaces partial progress / errors.
	ConditionLegacySTSMigrated = "LegacySTSMigrated"

	// ConditionQuorumAtRisk is True when one or more partitions lack write
	// quorum (Garage's own PartitionsQuorum < Partitions) — i.e. object writes
	// to those partitions will block. This is the actionable write-availability
	// signal: validated against upstream, factor reduction or consistencyMode
	// changes are the levers, NOT a layout edit. The message names the reachable
	// vs total storage node counts and the remediation.
	ConditionQuorumAtRisk = "QuorumAtRisk"

	// ConditionRemoteClustersHealthy aggregates the reachability of federated
	// remote clusters. False when a remote has been unreachable past a staleness
	// threshold; the message names which cluster and for how long, so an operator
	// can decide whether a zone is permanently gone.
	ConditionRemoteClustersHealthy = "RemoteClustersHealthy"

	// ConditionFederationConfigured is False when spec.remoteClusters is set but
	// the cluster advertises no rpc_public_addr (network.rpcPublicAddr or a
	// publicEndpoint). Without it, Garage's HelloMessage carries no server_addr
	// and remote peers infer the unroutable pod IP — cross-cluster RPC degrades
	// after any pod restart. Surfaced as a webhook warning at admission too.
	ConditionFederationConfigured = "FederationConfigured"

	// ConditionPeerUnreachable is True when one or more peers have been
	// continuously down (is_up=false) beyond a sustained threshold. The operator
	// can only read is_up + lastSeenSecsAgo from the admin API — NOT Garage's
	// internal Abandoned state — so detection is duration-based. Matters most for
	// edge gateways on a single RPC link: Garage stops retrying a peer after ~10
	// failed attempts, and the operator's periodic ConnectClusterNodes nudge is
	// then the only recovery path. Transient restarts (below the threshold) do not
	// trip it.
	ConditionPeerUnreachable = "PeerUnreachable"

	// ConditionGatewayLayoutDegraded is True when one or more operator-owned
	// gateway GarageNodes report status.inLayout == false. A gateway pod is
	// supposed to hold a capacity:nil layout role so key_table/bucket_table are
	// full-replicated locally and S3 sig-auth resolves keys via get_local()
	// without a per-request quorum RPC to the storage tier (#209). When that role
	// is missing the gateway silently degrades to quorum auth — slower and coupled
	// to storage availability — with no other surfaced signal. The message names
	// the affected GarageNode(s) so an operator can force a layout reconcile.
	ConditionGatewayLayoutDegraded = "GatewayLayoutDegraded"

	// ConditionManagementHandleReady is True when a management-handle cluster
	// (spec.connectTo only, no tiers — issue #269) can reach the external Garage's
	// Admin API. The operator owns no workload for such a CR; this condition is the
	// sole readiness signal, and the cluster's Phase tracks it (Running/Pending) so
	// dependent GarageBucket/GarageKey CRs gate correctly. False with
	// Reason=AdminUnreachable when the endpoint cannot be reached.
	ConditionManagementHandleReady = "ManagementHandleReady"

	// ConditionStorageScaleDownBlocked is True when an Auto-mode storage
	// scale-down was refused because removing the over-range GarageNodes would
	// drop the count of live, positive-capacity storage nodes below
	// spec.replication.factor. Garage rejects a layout apply that would leave
	// fewer roled nodes than the factor (IsReplicationConstraint), so the
	// per-node finalizer cannot remove the layout role — deleting the CRs would
	// orphan those roles. The operator keeps the excess GarageNodes in place
	// and surfaces this until the user lowers replication.factor (or restores
	// replicas). False/cleared once the scale-down is safe.
	ConditionStorageScaleDownBlocked = "StorageScaleDownBlocked"
)

// Condition reasons for the cluster-health surface.
const (
	// ReasonQuorumOK indicates all partitions have write quorum.
	ReasonQuorumOK = "AllPartitionsQuorate"
	// ReasonQuorumLost indicates one or more partitions lack write quorum.
	ReasonQuorumLost = "PartitionsBelowQuorum"
	// ReasonAllRemotesConnected indicates every federated remote is reachable.
	ReasonAllRemotesConnected = "AllConnected"
	// ReasonRemotesStale indicates one or more remotes are unreachable/stale.
	ReasonRemotesStale = "RemotesUnreachable"
	// ReasonMissingRPCPublicAddr indicates a federated cluster has no rpc_public_addr.
	ReasonMissingRPCPublicAddr = "MissingRPCPublicAddr"
	// ReasonFederationReady indicates federation networking is configured.
	ReasonFederationReady = "Configured"
	// ReasonPeersReachable indicates all known peers are reachable.
	ReasonPeersReachable = "AllReachable"
	// ReasonPeersUnreachable indicates one or more peers are sustained-unreachable.
	ReasonPeersUnreachable = "SustainedUnreachable"
	// ReasonGatewayRolesPresent indicates every operator-owned gateway node holds its layout role.
	ReasonGatewayRolesPresent = "GatewayRolesPresent"
	// ReasonGatewayRoleMissing indicates one or more gateway nodes lack a layout role (degraded to quorum auth).
	ReasonGatewayRoleMissing = "GatewayRoleMissing"
	// ReasonScaleDownWouldBreakQuorum indicates a refused storage scale-down.
	ReasonScaleDownWouldBreakQuorum = "WouldDropBelowReplicationFactor"
	// ReasonScaleDownSafe indicates no storage scale-down is currently blocked.
	ReasonScaleDownSafe = "ScaleDownSafe"
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

	// ConditionBucketLookupStuck indicates the Garage admin API has timed out
	// repeatedly when reading this bucket's info. Almost always caused by a
	// stale entry in the bucket's authorized_keys whose RPC lookup never
	// completes (upstream netapp::try_connect has no TCP timeout). Recover by
	// triggering RepairType=Aliases on the parent GarageCluster via the
	// garage.rajsingh.info/trigger-repair annotation.
	ConditionBucketLookupStuck = "BucketLookupStuck"

	// ConditionBucketMetadataDegraded indicates Garage's admin API returned
	// an InternalError "Unable to decode entry of key" for GetBucketInfo.
	// Caused by key_table entries written by an older Garage version that the
	// running version cannot deserialize. The operator auto-triggers
	// Repair:Tables on the parent GarageCluster after BucketDecodeErrorThreshold
	// consecutive failures. Cleared on the first successful GetBucketInfo.
	ConditionBucketMetadataDegraded = "BucketMetadataDegraded"
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

	// ConditionCycling indicates a graceful node cycle (garage.rajsingh.info/cycle)
	// is in progress: a sibling GarageNode has been provisioned and the operator is
	// driving the add-before-remove swap. The message names the current cycle phase
	// and the sibling node. Cleared when the cycle completes (this node is deleted).
	ConditionCycling = "Cycling"
)

// GarageNode cycle phases recorded on status.cyclePhase to drive the
// add-before-remove replacement state machine (garage.rajsingh.info/cycle).
const (
	// CyclePhaseProvisioning indicates the sibling GarageNode has been (or is being)
	// created and is waiting for its node ID + StatefulSet to come up.
	CyclePhaseProvisioning = "Provisioning"

	// CyclePhaseSyncing indicates the sibling is in the layout and the operator is
	// waiting for its sync tracker to reach the current layout version (all the
	// partitions it owns are replicated to it).
	CyclePhaseSyncing = "Syncing"

	// CyclePhaseDraining indicates the sibling is fully synced and this node is being
	// drained and removed from the layout ahead of deletion.
	CyclePhaseDraining = "Draining"
)

// Condition reasons for the node-cycle surface.
const (
	// ReasonCycleProvisioning indicates the sibling GarageNode is being provisioned.
	ReasonCycleProvisioning = "SiblingProvisioning"
	// ReasonCycleSyncing indicates the operator is waiting for the sibling to sync.
	ReasonCycleSyncing = "SiblingSyncing"
	// ReasonCycleDraining indicates this node is being drained and removed.
	ReasonCycleDraining = "Draining"
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

	// ReasonClusterDeleting indicates the referenced Garage cluster is being deleted
	ReasonClusterDeleting = "ClusterDeleting"

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

	// ReasonGatewayForwardOnly indicates the gateway reaches the external cluster but
	// the reverse direction is not establishable because the edge gateway has no
	// externally-routable RPC address configured (no gateway/network rpcPublicAddr and
	// no publicEndpoint). A gateway holds no data, so forward-only connectivity is a
	// healthy steady state rather than a failure to retry — treated as Connected.
	ReasonGatewayForwardOnly = "ForwardOnly"

	// ReasonGatewayNodesOffline indicates no nodes are connected in either direction
	ReasonGatewayNodesOffline = "NodesOffline"

	// ReasonPerNodeNotImplemented indicates a reconciler version does not support
	// publicEndpoint.loadBalancer.perNode.
	ReasonPerNodeNotImplemented = "PerNodeNotImplemented"

	// ReasonGatewayTombstonesPending indicates stale gateway layout entries are
	// queued but not auto-applied (layoutManagement.autoApply is false).
	ReasonGatewayTombstonesPending = "PendingRemoval"

	// ReasonBucketLookupStuck indicates GetBucketInfo has timed out N
	// consecutive times for this bucket. Surfaced via the
	// ConditionBucketLookupStuck condition; manual recovery is to trigger
	// RepairType=Aliases on the parent GarageCluster.
	ReasonBucketLookupStuck = "AdminAPITimeout"

	// ReasonMetadataDecodeError indicates GetBucketInfo returned HTTP 500
	// "Unable to decode entry of key". The operator auto-triggers
	// Repair:Tables on the parent GarageCluster to re-sync key_table entries.
	ReasonMetadataDecodeError = "MetadataDecodeError"
)

// Annotation keys for operational tasks
const (
	// AnnotationPrefix is the prefix for all garage operator annotations
	AnnotationPrefix = "garage.rajsingh.info/"

	// GarageCluster annotations

	// AnnotationTriggerSnapshot triggers a metadata snapshot on all nodes when set to "true"
	AnnotationTriggerSnapshot = AnnotationPrefix + "trigger-snapshot"

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

	// AnnotationCycle triggers a graceful add-before-remove node replacement when
	// set to "true". The operator provisions a sibling GarageNode (fresh node ID +
	// PVCs, same zone/capacity/tags), waits for the sibling's layout sync tracker
	// to reach the current layout version (all partitions it owns are in sync),
	// then drains and removes this node from the layout and deletes it. The cluster
	// stays above quorum throughout — unlike a plain delete-then-recreate, which
	// dips replication. Works for both Auto-owned and Manual GarageNodes. One-shot:
	// progress is tracked on status.cyclePhase so the state machine resumes on
	// requeue instead of re-provisioning the sibling. Cleared implicitly when the
	// node is deleted at the end of the cycle.
	AnnotationCycle = AnnotationPrefix + "cycle"

	// GarageBucket annotations

	// AnnotationCleanupMPU triggers cleanup of incomplete multipart uploads when set to "true"
	AnnotationCleanupMPU = AnnotationPrefix + "cleanup-mpu"

	// AnnotationCleanupMPUOlderThan specifies the age threshold for MPU cleanup (e.g., "24h", "7d")
	AnnotationCleanupMPUOlderThan = AnnotationPrefix + "cleanup-mpu-older-than"

	// AnnotationBucketLookupTimeouts tracks consecutive GetBucketInfo timeouts
	// on this bucket. Incremented on each timeout, cleared on first success.
	// At BucketLookupStuckThreshold (3), the operator sets the
	// ConditionBucketLookupStuck status condition. Internal use only — users
	// should not set this directly.
	AnnotationBucketLookupTimeouts = AnnotationPrefix + "bucket-lookup-timeouts"

	// AnnotationBucketDecodeErrors tracks consecutive GetBucketInfo decode errors
	// ("Unable to decode entry of key") on this bucket. Incremented on each error,
	// cleared on first success. At BucketDecodeErrorThreshold (3), the operator
	// auto-triggers Repair:Tables on the parent GarageCluster. Internal use only.
	AnnotationBucketDecodeErrors = AnnotationPrefix + "bucket-decode-errors"

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

	// AnnotationRetryMigration removes the LegacySTSMigrated status condition
	// and re-runs the legacy-STS migration on the next reconcile. One-shot;
	// removed after processing. Use when the migration previously failed and
	// the underlying condition has since been resolved. Set to "true" to trigger.
	AnnotationRetryMigration = AnnotationPrefix + "retry-migration"

	// AnnotationPurgeClusterLayout triggers a coordinated replication-factor
	// migration: the ONLY way to change replication_factor is to delete the
	// on-disk cluster_layout on every storage node and rebuild the layout from
	// scratch (validated against upstream — the factor lives on the persisted
	// layout, is absent from the admin API, and a config/layout mismatch is fatal
	// at boot). DESTRUCTIVE and disruptive (full re-replication). Value is
	// "factor=N" (must match spec.replication.factor), optionally ",force" to
	// override the safety guards. The operator drives a multi-phase state machine
	// recorded on status.factorMigration. Removed on success; retained (Failed
	// phase) on a transient error so the next reconcile resumes.
	AnnotationPurgeClusterLayout = AnnotationPrefix + "purge-cluster-layout"

	// AnnotationPurgeClusterLayoutAbort aborts an in-flight purge: clears the
	// operator-suspended marks and the factorMigration status, leaving pods to be
	// restored by their per-node controllers. Set to "true". Does NOT roll back a
	// purge that has already deleted cluster_layout — it only stops the operator
	// from continuing to drive phases.
	AnnotationPurgeClusterLayoutAbort = AnnotationPrefix + "purge-cluster-layout-abort"

	// AnnotationOperatorSuspended is an INTERNAL, operator-managed mark placed on
	// a GarageNode while a cluster-level coordinated operation (factor migration)
	// owns its StatefulSet. The GarageNode controller pauses reconciliation while
	// it is set — identical effect to spec.maintenance.suspended but distinct so
	// the operator and a human can't collide. Value is the owning operation id.
	AnnotationOperatorSuspended = AnnotationPrefix + "operator-suspended"
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

	// PhaseRunning indicates the resource is running/operational
	PhaseRunning = "Running"

	// PhaseReady indicates the resource is fully ready
	PhaseReady = "Ready"

	// PhaseDeleting indicates the resource is being deleted
	PhaseDeleting = "Deleting"

	// PhaseFailed indicates the resource has failed
	PhaseFailed = "Failed"

	// PhaseExpired indicates the resource has expired
	PhaseExpired = "Expired"
)
