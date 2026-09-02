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

// Finalizers shared by the ordinary controllers and COSI shadow reservations.
// COSI must install these in the reservation's initial create so a deletion can
// never race ahead of the controller's first reconciliation and orphan the
// corresponding Garage resource.
const (
	GarageBucketFinalizer = "garagebucket.garage.rajsingh.info/finalizer"
	GarageKeyFinalizer    = "garagekey.garage.rajsingh.info/finalizer"
)

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
	// users so they know to clean up the exact roles with the Garage CLI or enable
	// autoApply. The legacy force-layout-apply bootstrap flag does not approve
	// tombstones.
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
	// without an RPC to the storage tier (#209). When that role is missing the
	// local authentication record is absent and signed requests can fail with
	// "No such key". The message names the affected GarageNode(s) so an operator
	// can force a layout reconcile.
	ConditionGatewayLayoutDegraded = "GatewayLayoutDegraded"

	// ConditionManagementHandleReady is True when a management-handle cluster
	// (spec.connectTo only, no tiers — issue #269) can reach the external Garage's
	// Admin API. The operator owns no workload for such a CR; this condition is the
	// sole readiness signal, and the cluster's Phase tracks it (Running/Pending) so
	// dependent GarageBucket/GarageKey CRs gate correctly. False with
	// Reason=AdminUnreachable when the endpoint cannot be reached.
	ConditionManagementHandleReady = "ManagementHandleReady"

	// ConditionStorageScaleDownBlocked is True when an Auto-mode storage
	// scale-down is refused because too few positive-capacity roles would remain
	// for spec.replication.factor. Transient topology progress is reported
	// separately by StorageTopologyReady.
	ConditionStorageScaleDownBlocked = "StorageScaleDownBlocked"

	// ConditionStorageTopologyReady reports whether the operator-managed
	// default StatefulSet/PVC group has reached its desired membership and Garage
	// has no older layout version still draining. False is a transient
	// progress/safety signal while members join, update, or drain.
	// Replication-factor refusals remain additionally surfaced by
	// StorageScaleDownBlocked.
	ConditionStorageTopologyReady = "StorageTopologyReady"

	// ConditionNodeLocalPoolsReady reports whether every additive node-local pool
	// has converged to its desired Kubernetes Node membership.
	// False means the operator is still adding replacement identities, draining
	// retired identities, or is refusing an unsafe drain. The node-local lifecycle
	// keeps the old pod online until its Garage layout role is removed.
	ConditionNodeLocalPoolsReady = "NodeLocalPoolsReady"

	// ConditionStorageRolloutReady reports whether every GarageNode-backed or
	// node-local-pool identity is running the desired template revision. Those
	// StatefulSets and DaemonSets use OnDelete; the parent replaces at most one
	// pod, then proves its exact replacement UID and Garage layout health before
	// selecting another. This applies equally to PVC, SMB, node-local, and
	// unified gateway GarageNodes. Cluster-level edge gateway StatefulSets retain
	// Kubernetes' ordered Ready-gated RollingUpdate behavior.
	ConditionStorageRolloutReady = "StorageRolloutReady"

	// ConditionStorageDrainReady reports the cluster-wide safety transaction
	// used before a positive-capacity role's workload may stop. False names the
	// exact actor and current repair/resync wait; True means either idle or that
	// terminal evidence is complete and the actor is finishing its handoff.
	ConditionStorageDrainReady = "StorageDrainReady"
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
	// ReasonGatewayRoleMissing indicates one or more gateway nodes lack the layout
	// role required to replicate S3 authentication data locally.
	ReasonGatewayRoleMissing = "GatewayRoleMissing"
	// ReasonScaleDownWouldBreakQuorum indicates a refused storage scale-down.
	ReasonScaleDownWouldBreakQuorum = "WouldDropBelowReplicationFactor"
	// ReasonScaleDownSafe indicates no storage scale-down is currently blocked.
	ReasonScaleDownSafe = "ScaleDownSafe"
	// ReasonStorageTopologyConverged indicates the operator-managed default
	// storage membership and Garage layout history are settled.
	ReasonStorageTopologyConverged = "Converged"
	// ReasonStorageTopologyWaitingForLayoutSync indicates another automatic or
	// user-managed GarageNode/layout transition must finish before the default
	// StatefulSet/PVC group can safely change.
	ReasonStorageTopologyWaitingForLayoutSync = "WaitingForLayoutSync"
	// ReasonStorageTopologyAdding indicates the operator created or updated a
	// batch of default StatefulSet/PVC GarageNodes and is waiting for their layout
	// roles.
	ReasonStorageTopologyAdding = "AddingMembers"
	// ReasonStorageTopologyDraining indicates one excess default StatefulSet/PVC
	// GarageNode is being drained before another removal can start.
	ReasonStorageTopologyDraining = "DrainingMember"
	// ReasonNodeLocalPoolsConverged indicates every desired node-local member is
	// connected and in the committed layout, Garage reports no draining layout
	// version, and every retired member has been drained.
	ReasonNodeLocalPoolsConverged = "Converged"
	// ReasonNodeLocalPoolWaitingForReplacement indicates new node-local members
	// must connect and enter the committed layout before an old member can be
	// drained.
	ReasonNodeLocalPoolWaitingForReplacement = "WaitingForReplacement"
	// ReasonNodeLocalPoolWaitingForMembers indicates a selector matches no
	// Kubernetes Nodes, or desired node-local Pods/connected Garage layout roles
	// have not become ready yet.
	ReasonNodeLocalPoolWaitingForMembers = "WaitingForMembers"
	// ReasonNodeLocalPoolWaitingForLayoutSync indicates desired members have
	// entered the current layout but Garage is still synchronizing an active
	// version, another storage GarageNode is finalizing, or the Admin API could
	// not prove that it is safe to start a removal.
	ReasonNodeLocalPoolWaitingForLayoutSync = "WaitingForLayoutSync"
	// ReasonNodeLocalPoolWaitingForDrainSafety means membership is otherwise ready,
	// but deletion has not started because consistency, rollout, health, or the
	// unverified-peer policy has not passed reversible preflight.
	ReasonNodeLocalPoolWaitingForDrainSafety = "WaitingForDrainSafety"
	// ReasonNodeLocalPoolMoveBlocked indicates one Kubernetes Node was moved
	// directly between pools. It must first be unselected and fully drained so
	// two DaemonSets never mount its node-local Garage directories together.
	ReasonNodeLocalPoolMoveBlocked = "DirectNodeLocalPoolMoveBlocked"
	// ReasonNodeLocalPoolWaitingForPreviousPod indicates a fully drained pool's
	// old pod is still terminating on a Node before another pool may activate.
	ReasonNodeLocalPoolWaitingForPreviousPod = "WaitingForPreviousNodeLocalPoolPod"
	// ReasonNodeLocalPoolDraining indicates one retired member is leaving the
	// committed layout while its DaemonSet pod remains online.
	ReasonNodeLocalPoolDraining = "Draining"
	// ReasonNodeLocalPoolReplicationUnsafe indicates draining the next retired
	// member would leave fewer confirmed storage roles than the replication
	// factor, so the operator keeps that member active.
	ReasonNodeLocalPoolReplicationUnsafe = "ReplicationUnsafe"
	// ReasonNodeLocalPoolIdentityCollision indicates two GarageNode CRs, at
	// least one node-local-pool-backed, report the same durable Garage node ID. They
	// are one layout identity and must not be counted as separate replicas.
	ReasonNodeLocalPoolIdentityCollision = "IdentityCollision"
	// ReasonNodeLocalPoolSelectorConflict indicates one Kubernetes Node currently
	// matches more than one node-local-pool selector. No conflicting identity is
	// activated until the selectors are made disjoint in live cluster state.
	ReasonNodeLocalPoolSelectorConflict = "SelectorConflict"
	// ReasonNodeLocalPoolHostPathConflict indicates another GarageCluster has a
	// node-local pool selecting the same Kubernetes Node with an overlapping HostPath.
	// Distinct paths on the same Node remain supported for independent clusters.
	ReasonNodeLocalPoolHostPathConflict = "HostPathConflict"
	// ReasonNodeLocalPoolUnsupportedKubernetesVersion means the API server is
	// older than the Kubernetes 1.27 minimum for node-local pools.
	ReasonNodeLocalPoolUnsupportedKubernetesVersion = "UnsupportedKubernetesVersion"
	// ReasonNodeLocalPoolSchedulingGatesUnavailable means the Kubernetes API
	// server rejected/removed the scheduling gate or kube-scheduler evaluated a
	// still-gated Pod without reporting SchedulingGated.
	ReasonNodeLocalPoolSchedulingGatesUnavailable = "SchedulingGatesUnavailable"
	// ReasonNodeLocalPoolSchedulingGateCapabilityUnknown means discovery, API
	// transport, scheduler observation, or probe cleanup was inconclusive, so the
	// operator cannot safely infer end-to-end support.
	ReasonNodeLocalPoolSchedulingGateCapabilityUnknown = "SchedulingGateCapabilityUnknown"
	// ReasonNodeLocalPoolSchedulingGateProbePending means a harmless gated Pod
	// is waiting for positive PodScheduled=False/SchedulingGated scheduler evidence.
	ReasonNodeLocalPoolSchedulingGateProbePending = "SchedulingGateProbePending"
	// ReasonNodeLocalPoolMemberLimitExceeded means live selectors exceed the
	// supported per-GarageCluster node-local identity bound.
	ReasonNodeLocalPoolMemberLimitExceeded = "MemberLimitExceeded"
	// ReasonNodeLocalPoolGarageRoleLimitExceeded means the shared Garage layout
	// has no safe positive-capacity role headroom for another identity.
	ReasonNodeLocalPoolGarageRoleLimitExceeded = "GarageRoleLimitExceeded"
	// ReasonStorageRolloutConverged indicates every managed identity-bearing pod
	// is on the desired template revision.
	ReasonStorageRolloutConverged = "Converged"
	// ReasonStorageRolloutWaiting indicates rollout cannot safely select another
	// pod yet because membership, readiness, health, or layout history is not
	// settled.
	ReasonStorageRolloutWaiting = "Waiting"
	// ReasonStorageRolloutInitializing means managed identities are still being
	// created or joining their first layout. Initial bootstrap layout writes must
	// remain possible; unlike Waiting/RollingOut, this is not a config-transition
	// exclusion boundary.
	ReasonStorageRolloutInitializing = "Initializing"
	// ReasonStorageRollingOut indicates the parent controller is replacing one
	// managed pod and waiting for the exact replacement identity before another
	// pod or layout mutation may proceed.
	ReasonStorageRollingOut = "RollingOut"
	// ReasonStorageDraining means the exact actor is still removing roles or
	// proving object-block migration on every source and destination process.
	ReasonStorageDraining = "Draining"
	// ReasonStorageDrainCompleted means terminal upstream evidence is complete;
	// the transaction remains active until its Kubernetes handoff finishes.
	ReasonStorageDrainCompleted = "Completed"
	// ReasonStorageDrainIdle means no positive-capacity removal owns the cluster.
	ReasonStorageDrainIdle = "Idle"
	// ReasonStorageDrainUnsupportedConsistency means Garage's configured mode
	// cannot provide the upstream persisted table-migration barrier required for
	// automatic positive-capacity removal.
	ReasonStorageDrainUnsupportedConsistency = "UnsupportedConsistencyMode"
	// ReasonStorageDrainWaitingForRollout means desired consistent mode is not
	// yet proven to be running on every locally managed Garage process.
	ReasonStorageDrainWaitingForRollout = "WaitingForStorageRollout"
	// ReasonStorageDrainWaitingForHealth means managed configuration converged,
	// but Garage is not yet fully healthy enough to begin a removal transaction.
	ReasonStorageDrainWaitingForHealth = "WaitingForClusterHealth"
	// ReasonStorageDrainUnverifiedPeers means at least one positive-capacity
	// Garage process is outside this Kubernetes control plane and the safe
	// default policy refuses to infer its running consistency mode.
	ReasonStorageDrainUnverifiedPeers = "UnverifiedPeersBlocked"
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

	// ConditionDeletionBlocked indicates that a resource's deletion cannot
	// complete without an explicit user action. It is deliberately separate
	// from Ready so callers can distinguish a safe data-protection hold from a
	// general reconciliation failure.
	ConditionDeletionBlocked = "DeletionBlocked"
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

	// ConditionDrainPrepared is True only after garage.rajsingh.info/drain has
	// removed this positive-capacity role while its process stayed live and the
	// cluster-wide source-to-destination block proof completed. DELETE admission
	// uses the exact parent transaction as authority; this condition is the
	// user-facing per-node summary.
	ConditionDrainPrepared = "DrainPrepared"

	// ConditionCycling indicates a graceful node cycle (garage.rajsingh.info/cycle)
	// is in progress: a fresh-PVC sibling GarageNode has been provisioned and the
	// operator is driving the add-before-remove swap through the same durable
	// cluster-wide drain proof used by ordinary positive-capacity retirement. The
	// message names the current phase and sibling. False means the request is
	// blocked without mutating either identity.
	ConditionCycling = "Cycling"
)

// GarageNode cycle phases recorded on status.cyclePhase to drive the
// add-before-remove replacement state machine (garage.rajsingh.info/cycle).
const (
	// CyclePhaseProvisioning indicates the sibling GarageNode has been (or is being)
	// created and is waiting for its node ID + StatefulSet to come up.
	CyclePhaseProvisioning = "Provisioning"

	// CyclePhaseSyncing indicates the sibling's exact current Pod is Ready,
	// connected, and committed to a settled Garage layout. The subsequent ordinary
	// drain transaction proves full replication before the source can be deleted.
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
	// ReasonCycleBlocked means the cycle failed closed before provisioning or
	// promotion because its storage source, actor identity, readiness, or durable
	// drain proof is not eligible for automatic replacement.
	ReasonCycleBlocked = "CycleBlocked"
	// ReasonCycleCancellationBlocked means a pre-drain cancellation is waiting for
	// the already-created sibling to be explicitly drained and removed first.
	ReasonCycleCancellationBlocked = "CancellationBlocked"
	// ReasonNodeDrainPreparing means the node remains live while its layout role
	// and object blocks are being drained.
	ReasonNodeDrainPreparing = "Preparing"
	// ReasonNodeDrainPrepared means the exact parent storage-drain transaction is
	// terminal and Kubernetes deletion is now safe.
	ReasonNodeDrainPrepared = "PreparedForDeletion"
	// ReasonNodeDrainPreparedNotInLayout means the annotated GarageNode has no
	// live process/identity or its never-committed exact identity is absent from a
	// settled Garage layout, so no block-migration transaction is necessary.
	ReasonNodeDrainPreparedNotInLayout = "PreparedNotInLayout"
	// ReasonNodeDrainBlocked means preparation failed closed while the GarageNode
	// remains reversible and online.
	ReasonNodeDrainBlocked = "PreparationBlocked"
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
	// ReasonBucketNotEmpty indicates Garage refused a bucket deletion because
	// objects or other bucket content remain. The operator never purges that
	// content implicitly.
	ReasonBucketNotEmpty = "BucketNotEmpty"
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

	// AnnotationSkipDeadNodes explicitly invokes Garage's cluster-wide recovery operation when set to "true".
	// Garage may force-ACK every peer the serving node sees as down; this is not scoped to one target.
	AnnotationSkipDeadNodes = AnnotationPrefix + "skip-dead-nodes"

	// AnnotationAllowMissingData allows skipping nodes even if quorum is missing when set to "true"
	// Use with caution - this can result in data loss
	AnnotationAllowMissingData = AnnotationPrefix + "allow-missing-data"

	// AnnotationForceDeleteUnrevokedOperatorTokens explicitly allows a deleting
	// federated/edge site to abandon its internally generated Admin-token table
	// rows when no surviving Admin endpoint can commit their tombstones. The
	// local one-time Secrets are deleted, but any previously copied bearer may
	// remain valid in the surviving Garage cluster. Use only after an outage
	// makes ordinary revocation impossible.
	AnnotationForceDeleteUnrevokedOperatorTokens = AnnotationPrefix + "force-delete-unrevoked-operator-tokens"

	// AnnotationConnectNodes specifies nodes to connect to (format: "nodeId@addr:port,...")
	AnnotationConnectNodes = AnnotationPrefix + "connect-nodes"

	// AnnotationMigrateLegacyRPCSecret opts a released GarageCluster into the
	// fail-closed migration from a user-supplied GARAGE_RPC_SECRET environment
	// override to spec.network.rpcSecretRef. Keep the old environment entry until
	// the controller reports that every exact managed workload, the referenced
	// Secret, and the managed RPC snapshot contain identical credential bytes;
	// then remove the environment entry. The operator never treats this
	// acknowledgement as credential equality proof.
	AnnotationMigrateLegacyRPCSecret = AnnotationPrefix + "migrate-legacy-rpc-secret"

	// AnnotationAcknowledgeLegacyConfigMigration explicitly attests that released
	// GARAGE_CONFIG_FILE or other non-RPC reserved environment overrides on the
	// exact existing Pods are semantically compatible with the operator-rendered
	// configuration. It is required after removing those fields while old Pods
	// are still running. It cannot authorize an RPC credential change.
	AnnotationAcknowledgeLegacyConfigMigration = AnnotationPrefix + "acknowledge-legacy-config-migration"

	// GarageNode annotations

	// AnnotationDrain requests a reversible positive-capacity drain when set to
	// "true". The GarageNode stays live and non-terminating until its role is
	// absent and the parent status.storageDrain proof is complete. Delete it only
	// after ConditionDrainPrepared=True.
	AnnotationDrain = AnnotationPrefix + "drain"

	// AnnotationAcknowledgeLostSource is the exact 64-hex Garage node ID whose
	// local storage is permanently unavailable. It is a high-risk, explicit
	// acknowledgement that freezes the exact GarageNode in drain mode while an
	// administrator removes that dead role through Garage's own recovery
	// workflow. The operator then verifies settled history plus clean Blocks
	// repairs on every surviving destination; it can never prove or recover
	// blocks whose only copy was on the lost source.
	AnnotationAcknowledgeLostSource = AnnotationPrefix + "acknowledge-lost-source"

	// AnnotationRecoverStorageRollout retries the exact managed Pod replacement
	// recorded in status.storageRollout without changing its desired spec (for
	// example after fixing a referenced Secret). Its value is an operator-chosen
	// nonce; change it for each retry. Workload-only GarageCluster or exact-actor
	// GarageNode spec edits use their atomic Kubernetes generation as the
	// roll-forward request and do not require this annotation.
	AnnotationRecoverStorageRollout = AnnotationPrefix + "recover-storage-rollout"

	// AnnotationNodeLocalPoolRecoveryNodeID is an operator-owned identity pin on
	// an internal node-local-pool GarageNode. It records the exact committed Garage
	// role that caused a HostPath process to be started during cold recovery, so
	// a missing or replaced disk cannot silently become a second storage role.
	AnnotationNodeLocalPoolRecoveryNodeID = AnnotationPrefix + "node-local-pool-recovery-node-id"

	// AnnotationSkipLayout excludes a node from the layout temporarily when set to "true"
	AnnotationSkipLayout = AnnotationPrefix + "skip-layout"

	// AnnotationCycle triggers a graceful add-before-remove replacement when set
	// to "true" on an established positive-capacity StatefulSet-backed storage
	// GarageNode. The operator creates a sibling with a fresh node ID and the same
	// repeatable PVC-template or EmptyDir profile, waits for its exact Pod to be
	// Ready, connected, and committed in a settled layout, then uses the ordinary
	// cluster-wide drain and block-resync proof before promoting the sibling and
	// deleting the source. ExistingClaim, identity-specific/shared fixed RPC
	// endpoints, publicEndpoint, gateway, external, and node-local-pool members
	// require an explicit distinct replacement and are rejected. A cycle
	// never reuses, snapshots, clones, or deletes an existingClaim. Before source
	// deletion, its volumeClaimTemplate PVCs are forced to Retain and detached
	// from the exact old StatefulSet/Pod owners; cleanup remains explicit. The
	// annotation is added only after creation; progress is resumable in
	// status.cyclePhase.
	AnnotationCycle = AnnotationPrefix + "cycle"

	// GarageBucket annotations

	// AnnotationCOSIBucketID pins a COSI shadow GarageBucket to the exact remote
	// Garage bucket created by the COSI provisioner.
	AnnotationCOSIBucketID = AnnotationPrefix + "cosi-bucket-id"

	// AnnotationCOSIAccountID pins a COSI shadow GarageKey to the exact remote
	// Garage access key created by the COSI provisioner.
	AnnotationCOSIAccountID = AnnotationPrefix + "cosi-account-id"

	// AnnotationCOSIProvisioningState marks the two-phase COSI shadow handoff.
	// Pending shadows are durable reservations and must not be reconciled by the
	// generic GarageBucket/GarageKey controllers until the provisioner binds them.
	AnnotationCOSIProvisioningState = AnnotationPrefix + "cosi-provisioning-state"
	COSIProvisioningStatePending    = "pending"
	COSIProvisioningStateBound      = "bound"

	// AnnotationCOSIReservationAlias records the private temporary Garage
	// alias used to recover a bucket created immediately before a process crash.
	AnnotationCOSIReservationAlias = AnnotationPrefix + "cosi-reservation-alias"

	// AnnotationCOSIRetain marks a COSI shadow GarageBucket for Kubernetes-only
	// deletion. Its UID-bound value is verified by the GarageBucket controller
	// before remote cleanup is bypassed.
	AnnotationCOSIRetain = AnnotationPrefix + "cosi-retain"

	// COSI shadow identity metadata is shared with the ordinary controllers so
	// retention can fail closed unless the object is a provisioner-owned shadow.
	LabelCOSIManaged               = AnnotationPrefix + "cosi-managed"
	AnnotationCOSIReservationOwner = AnnotationPrefix + "cosi-reservation-owner"
	AnnotationCOSIReservationReady = AnnotationPrefix + "cosi-reservation-ready"

	// AnnotationBucketReservationAlias records a private, high-entropy Garage
	// alias before an ordinary GarageBucket controller creates a remote bucket.
	// It closes the crash window between remote creation and status.bucketID.
	AnnotationBucketReservationAlias = AnnotationPrefix + "bucket-reservation-alias"

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
	// recorded on status.factorMigration. The request is consumed into status at
	// the start; that durable status resumes after transient controller failures
	// and prevents a lingering annotation from retriggering a completed purge.
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
