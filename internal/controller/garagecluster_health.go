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
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// remoteStaleThreshold is how long a federated remote cluster may be
// unreachable before RemoteClustersHealthy flips False. Below this it's treated
// as a transient blip.
const remoteStaleThreshold = time.Hour

// clusterHasRPCPublicAddr reports whether the cluster advertises an
// externally-routable RPC address — either an explicit network.rpcPublicAddr or
// a publicEndpoint the operator derives one from. Federation needs this so
// Garage's HelloMessage carries a server_addr peers can dial.
func clusterHasRPCPublicAddr(cluster *garagev1beta2.GarageCluster) bool {
	if cluster.Spec.Network.RPCPublicAddr != "" {
		return true
	}
	if cluster.Spec.PublicEndpoint != nil {
		return true
	}
	if cluster.Spec.Gateway != nil && cluster.Spec.Gateway.RPCPublicAddr != "" {
		return true
	}
	return false
}

// setClusterHealthConditions derives the actionable health conditions
// (QuorumAtRisk, RemoteClustersHealthy, FederationConfigured) from already-
// populated status (Health + RemoteClusters) and writes a one-line
// LayoutDiagnosis from the most severe active problem. All signals are validated
// against upstream Garage v2.3.0: partition quorum is Garage's own computation,
// and federation reachability is the operator's recorded last-seen state.
//
// Severity order (worst first): write-quorum loss → remote-cluster loss →
// federation misconfiguration.
func setClusterHealthConditions(cluster *garagev1beta2.GarageCluster) {
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
		var stale []string
		for _, rc := range cluster.Status.RemoteClusters {
			if rc.Connected {
				continue
			}
			if rc.LastSeen != nil && time.Since(rc.LastSeen.Time) < remoteStaleThreshold {
				continue // transient blip, not yet stale
			}
			age := "never connected"
			if rc.LastSeen != nil {
				age = fmt.Sprintf("unreachable for %s", time.Since(rc.LastSeen.Time).Round(time.Minute))
			}
			stale = append(stale, fmt.Sprintf("%s (%s)", rc.Name, age))
		}
		if len(stale) > 0 {
			msg := fmt.Sprintf(
				"federated remote clusters unreachable: %s; if a zone is permanently gone, "+
					"reduce spec.replication.factor to restore write quorum",
				strings.Join(stale, ", "))
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
		if clusterHasRPCPublicAddr(cluster) {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               garagev1beta1.ConditionFederationConfigured,
				Status:             metav1.ConditionTrue,
				Reason:             garagev1beta1.ReasonFederationReady,
				Message:            "rpc_public_addr is configured for cross-cluster RPC",
				ObservedGeneration: gen,
			})
		} else {
			msg := "federation enabled (spec.remoteClusters) but no rpc_public_addr " +
				"(set spec.network.rpcPublicAddr or a publicEndpoint); cross-cluster RPC will " +
				"degrade after pod restarts as peers infer the unroutable pod IP"
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

	// One-line human summary = most severe active problem.
	if len(diagnoses) > 0 {
		cluster.Status.LayoutDiagnosis = diagnoses[0]
	} else {
		cluster.Status.LayoutDiagnosis = ""
	}
}
