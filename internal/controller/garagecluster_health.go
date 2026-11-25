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

package controller

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// remoteStaleThreshold is how long a federated remote cluster may be
// unreachable before RemoteClustersHealthy flips False. Below this it's treated
// as a transient blip.
const remoteStaleThreshold = time.Hour

// peerUnreachableThreshold is how long a peer may be continuously down before
// PeerUnreachable trips. Comfortably above a normal pod restart so routine
// rollouts don't flap the condition, well under Garage's ~10-retry Abandoned
// window so the operator still gets early warning.
const peerUnreachableThreshold = 10 * time.Minute

// computeUnreachablePeers returns "<shortId> (down <duration>)" descriptions for
// peers that are not up and were last seen longer ago than the threshold. Only
// storage peers that matter are flagged: a peer that holds a capacity role in the
// CURRENT layout (n.Role != nil && n.Role.Capacity != nil) or one that is draining
// (held a capacity role in a prior layout version — Garage reports such a node with
// role==nil + draining==true). Gateway peers (capacity==nil) are excluded: dead
// gateway identities are reaped by reconcileGatewayTombstones, and ConnectClusterNodes
// can't reconnect a replaced identity anyway, so flagging them is misleading noise.
// Roleless, non-draining down peers are also excluded (discovery noise / discarded
// identity with no data responsibility).
func computeUnreachablePeers(nodes []garage.NodeInfo) []string {
	var out []string
	for _, n := range nodes {
		if n.IsUp {
			continue
		}
		if n.Role == nil && !n.Draining {
			continue // roleless and not draining: discovery noise or a discarded identity — not actionable
		}
		// Gateway peers (capacity=nil) are reaped by reconcileGatewayTombstones.
		// ConnectClusterNodes can't reconnect a replaced gateway identity, so
		// PeerUnreachable for them is actionable noise.
		if n.Role != nil && n.Role.Capacity == nil && !n.Draining {
			continue
		}
		secs := uint64(0)
		if n.LastSeenSecsAgo != nil {
			secs = *n.LastSeenSecsAgo
			if time.Duration(secs)*time.Second < peerUnreachableThreshold {
				continue // transient — not yet sustained
			}
		}
		short := n.ID
		if len(short) > 16 {
			short = short[:16]
		}
		desc := fmt.Sprintf("%s (never seen)", short)
		if n.LastSeenSecsAgo != nil {
			desc = fmt.Sprintf("%s (down %s)", short, (time.Duration(secs) * time.Second).Round(time.Minute))
		}
		out = append(out, desc)
	}
	return out
}

// clusterHasRPCPublicAddr reports whether every locally-declared identity group
// has an externally routable federation address. A route for one group must
// never mask an unaddressed group: the default PVC pool, every node-local pool, and
// the gateway tier have different identities and often different Services.
func clusterHasRPCPublicAddr(
	cluster *garagev1beta2.GarageCluster,
	garageNodeSnapshots ...[]garagev1beta1.GarageNode,
) bool {
	return len(clusterRPCAddressGaps(cluster, garageNodeSnapshots...)) == 0
}

func clusterRPCAddressGaps(
	cluster *garagev1beta2.GarageCluster,
	garageNodeSnapshots ...[]garagev1beta1.GarageNode,
) []string {
	if cluster == nil {
		return []string{rpcAddressGapCluster}
	}
	if strings.TrimSpace(cluster.Spec.Network.RPCPublicAddrSubnet) != "" {
		return nil
	}
	shared := strings.TrimSpace(cluster.Spec.Network.RPCPublicAddr) != ""
	var gaps []string

	defaultAddressed := shared || (cluster.Spec.Storage != nil && strings.TrimSpace(cluster.Spec.Storage.RPCPublicAddr) != "") ||
		cluster.Spec.PublicEndpoint != nil
	if cluster.Spec.Storage != nil && cluster.Spec.Storage.Replicas > 0 &&
		cluster.EffectiveStorageLayoutPolicy() != LayoutPolicyManual && !defaultAddressed {
		gaps = append(gaps, "default StatefulSet/PVC group")
	}
	if cluster.Spec.Storage != nil {
		for i := range cluster.Spec.Storage.NodeLocalPools {
			pool := &cluster.Spec.Storage.NodeLocalPools[i]
			if pool.Network == nil || strings.TrimSpace(pool.Network.RPCPublicAddrTemplate) == "" {
				gaps = append(gaps, "node-local pool "+pool.Name)
			}
		}
	}
	gatewayAddressed := shared || (cluster.Spec.Gateway != nil && strings.TrimSpace(cluster.Spec.Gateway.RPCPublicAddr) != "")
	if cluster.Spec.Gateway != nil && cluster.Spec.Gateway.Replicas > 0 && cluster.Spec.LayoutPolicy != LayoutPolicyManual {
		// In a gateway-only cluster publicEndpoint targets the gateway workload.
		if !cluster.HasStorageTier() && cluster.Spec.PublicEndpoint != nil {
			gatewayAddressed = true
		}
		if !gatewayAddressed {
			gaps = append(gaps, "gateway tier")
		}
	}

	// Manual GarageNodes are real local identities too. When a live snapshot is
	// available, require every user-managed identity to have either its own
	// public address or a route supplied by its tier. This is what makes a mixed
	// SMB + node-local-pool cluster diagnosable rather than silently treating replicas:
	// 0 as "no default storage identities".
	if len(garageNodeSnapshots) > 0 {
		for i := range garageNodeSnapshots[0] {
			node := &garageNodeSnapshots[0][i]
			if node.Spec.ClusterRef.Name != cluster.Name || node.Spec.Backing == garagev1beta1.NodeBackingNodeLocalPool {
				continue
			}
			nodeAddressed := node.Spec.Network != nil && strings.TrimSpace(node.Spec.Network.RPCPublicAddr) != ""
			if node.Spec.PublicEndpoint != nil {
				nodeAddressed = true
			}
			switch {
			case node.Spec.Gateway && !gatewayAddressed && (cluster.HasStorageTier() || cluster.Spec.PublicEndpoint == nil) && !nodeAddressed:
				gaps = append(gaps, "gateway GarageNode "+node.Name)
			case !node.Spec.Gateway && !defaultAddressed && !nodeAddressed:
				gaps = append(gaps, "storage GarageNode "+node.Name)
			}
		}
	}
	if !cluster.HasStorageTier() && !cluster.HasGatewayTier() && !shared && cluster.Spec.PublicEndpoint == nil {
		gaps = append(gaps, "local Garage identities")
	}
	sort.Strings(gaps)
	return gaps
}

const rpcAddressGapCluster = "cluster"

// setClusterHealthConditions derives the actionable health conditions
// (QuorumAtRisk, RemoteClustersHealthy, FederationConfigured) from already-
// populated status (Health + RemoteClusters) and writes a one-line
// LayoutDiagnosis from the most severe active problem. All signals are validated
// against upstream Garage v2.3.0: partition quorum is Garage's own computation,
// and federation reachability is the operator's recorded last-seen state.
//
// Severity order (worst first): write-quorum loss → remote-cluster loss →
// federation misconfiguration.
func setClusterHealthConditions(
	cluster *garagev1beta2.GarageCluster,
	garageNodeSnapshots ...[]garagev1beta1.GarageNode,
) {
	gen := cluster.Generation
	var diagnoses []string

	// --- QuorumAtRisk: some partition lacks write quorum -------------------
	if h := cluster.Status.Health; h != nil && h.Partitions > 0 && h.PartitionsQuorum < h.Partitions {
		atRisk := h.Partitions - h.PartitionsQuorum
		msg := fmt.Sprintf(
			"%d/%d partitions lack write quorum (%d/%d storage nodes reachable); "+
				"restore nodes, or set spec.replication.consistencyMode: dangerous to accept reduced durability",
			atRisk, h.Partitions, h.StorageNodesOK, h.StorageNodes)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionQuorumAtRisk,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonQuorumLost,
			Message:            msg,
			ObservedGeneration: gen,
		})
		diagnoses = append(diagnoses, msg)
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionQuorumAtRisk,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonQuorumOK,
			Message:            "all partitions have write quorum",
			ObservedGeneration: gen,
		})
	}

	// --- RemoteClustersHealthy: federated remote reachability --------------
	if len(cluster.Spec.RemoteClusters) > 0 {
		statusByName := make(map[string]garagev1beta2.RemoteClusterStatus, len(cluster.Status.RemoteClusters))
		for _, rc := range cluster.Status.RemoteClusters {
			statusByName[rc.Name] = rc
		}
		var stale []string
		for _, specRC := range cluster.Spec.RemoteClusters {
			rc, ok := statusByName[specRC.Name]
			if ok && rc.Connected {
				continue
			}
			if ok && rc.LastSeen != nil && time.Since(rc.LastSeen.Time) < remoteStaleThreshold {
				continue // transient blip, not yet stale
			}
			age := "never connected"
			if ok && rc.LastSeen != nil {
				age = fmt.Sprintf("unreachable for %s", time.Since(rc.LastSeen.Time).Round(time.Minute))
			}
			stale = append(stale, fmt.Sprintf("%s (%s)", specRC.Name, age))
		}
		if len(stale) > 0 {
			msg := summarizeConditionItems(
				"federated remote clusters unreachable: ", stale,
				"; if a zone is permanently gone, reduce spec.replication.factor to restore write quorum",
			)
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionRemoteClustersHealthy,
				Status:             metav1.ConditionFalse,
				Reason:             garagev1beta1.ReasonRemotesStale,
				Message:            msg,
				ObservedGeneration: gen,
			})
			diagnoses = append(diagnoses, msg)
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionRemoteClustersHealthy,
				Status:             metav1.ConditionTrue,
				Reason:             garagev1beta1.ReasonAllRemotesConnected,
				Message:            fmt.Sprintf("all %d federated remote clusters reachable", len(cluster.Spec.RemoteClusters)),
				ObservedGeneration: gen,
			})
		}
	} else {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionRemoteClustersHealthy)
	}

	// --- FederationConfigured: rpc_public_addr present when federated ------
	if len(cluster.Spec.RemoteClusters) > 0 {
		if clusterHasRPCPublicAddr(cluster, garageNodeSnapshots...) {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionFederationConfigured,
				Status:             metav1.ConditionTrue,
				Reason:             garagev1beta1.ReasonFederationReady,
				Message:            "an identity-specific RPC route is configured for cross-cluster RPC",
				ObservedGeneration: gen,
			})
		} else {
			gaps := clusterRPCAddressGaps(cluster, garageNodeSnapshots...)
			msg := summarizeConditionItems(
				"federation enabled (spec.remoteClusters) but no identity-specific RPC route for ", gaps,
				" (set the matching tier address, every nodeLocalPools[].network.rpcPublicAddrTemplate, or network.rpcPublicAddrSubnet); cross-cluster RPC will degrade after pod restarts as peers infer the unroutable pod IP",
			)
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionFederationConfigured,
				Status:             metav1.ConditionFalse,
				Reason:             garagev1beta1.ReasonMissingRPCPublicAddr,
				Message:            msg,
				ObservedGeneration: gen,
			})
			diagnoses = append(diagnoses, msg)
		}
	} else {
		meta.RemoveStatusCondition(&cluster.Status.Conditions, garagev1beta1.ConditionFederationConfigured)
	}

	// --- PeerUnreachable: sustained-down peers ----------------------------
	if len(cluster.Status.UnreachablePeers) > 0 {
		msg := summarizeConditionItems(
			fmt.Sprintf("peers unreachable beyond %s: ", peerUnreachableThreshold),
			cluster.Status.UnreachablePeers,
			"; the operator's periodic ConnectClusterNodes nudge is the recovery path (Garage stops retrying a peer after ~10 attempts)",
		)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionPeerUnreachable,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonPeersUnreachable,
			Message:            msg,
			ObservedGeneration: gen,
		})
		diagnoses = append(diagnoses, msg)
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionPeerUnreachable,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonPeersReachable,
			Message:            "all known peers are reachable",
			ObservedGeneration: gen,
		})
	}

	// --- GatewayLayoutDegraded: gateway nodes missing their layout role -----
	if len(cluster.Status.GatewayNodesNotInLayout) > 0 {
		msg := summarizeConditionItems(
			"gateway nodes not in layout: ", cluster.Status.GatewayNodesNotInLayout,
			"; they have lost the capacity:nil role that replicates S3 authentication data locally, so signed requests can fail with 403 No such key — set the garage.rajsingh.info/force-layout-apply annotation to re-stage the gateway roles",
		)
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayLayoutDegraded,
			Status:             metav1.ConditionTrue,
			Reason:             garagev1beta1.ReasonGatewayRoleMissing,
			Message:            msg,
			ObservedGeneration: gen,
		})
		diagnoses = append(diagnoses, msg)
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               garagev1beta1.ConditionGatewayLayoutDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             garagev1beta1.ReasonGatewayRolesPresent,
			Message:            "all gateway nodes hold their layout role",
			ObservedGeneration: gen,
		})
	}

	// One-line human summary = most severe active problem.
	if len(diagnoses) > 0 {
		cluster.Status.LayoutDiagnosis = diagnoses[0]
	} else {
		cluster.Status.LayoutDiagnosis = ""
	}
}
