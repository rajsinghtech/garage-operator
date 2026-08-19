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
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// safetyReader bypasses the informer cache when available. A stale
// "GarageNode is not changing" result could start a second layout mutation, so
// this boundary must read directly from the API server.
func (r *GarageClusterReconciler) safetyReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *GarageClusterReconciler) getClusterLayoutHistory(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (*garage.LayoutHistoryResponse, error) {
	if r.layoutHistoryGetter != nil {
		return r.layoutHistoryGetter(ctx, cluster)
	}
	garageClient, err := GetGarageClient(ctx, r.Client, cluster, r.ClusterDomain)
	if err != nil {
		return nil, fmt.Errorf("creating Garage Admin API client: %w", err)
	}
	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Garage layout history: %w", err)
	}
	return history, nil
}

// clusterLayoutReadyForMutation is the single-flight barrier for automatic
// Garage topology changes initiated by the GarageCluster controller.
//
// Garage keeps older layout versions active until their update trackers have
// acknowledged and synchronized the new assignment. Starting another add,
// update, or remove before that point can strand the older version behind a
// node that did not exist when it was created. This is especially easy to hit
// when an edge gateway is removed immediately before storage scales up.
//
// We therefore require:
//
//   - no same-cluster GarageNode (storage or gateway) is deleting;
//   - no same-cluster GarageNode is still discovering/joining its desired role;
//   - no node-local-pool activation is waiting to materialize a GarageNode; and
//   - Garage reports no layout version that still requires data
//     synchronization. A Draining version whose every node has already
//     reached the current Sync tracker is only stale sync_ack bookkeeping and
//     must not wedge the controller.
//
// ignoredNodeNames contains the one GarageNode a caller is about to delete. A
// stale identity may itself never have reached the layout, but it must not
// prevent its own cleanup. Every other in-flight identity remains a blocker.
//
// allowStorageBootstrap lets every desired initial storage identity materialize
// before Garage can accept its first layout. Garage rejects Apply until the
// staged positive-capacity roles meet the replication factor, so serializing a
// mixed default/Manual + node-local-pool topology one identity at a time would
// deadlock. Bootstrap is therefore defined by Garage's committed layout (zero
// storage roles), not by the number of GarageNode objects Kubernetes happens to
// contain. GarageNode reconcilers still admit only exact same-cluster staged
// additions and serialize Stage -> Apply through the canonical layout lock.
func (r *GarageClusterReconciler) clusterLayoutReadyForMutation(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	allowStorageBootstrap bool,
	ignoredNodeNames ...string,
) (ready bool, storageBootstrap bool, message string, err error) {
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.safetyReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return false, false, "", fmt.Errorf("listing GarageNodes for layout serialization: %w", err)
	}

	ignored := make(map[string]struct{}, len(ignoredNodeNames))
	for _, name := range ignoredNodeNames {
		ignored[name] = struct{}{}
	}

	clusterNodeCount := 0
	var deleting []string
	var joining []string
	var pendingActivations []string
	claimedActivations := make(map[string]map[string]struct{})
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name {
			continue
		}
		clusterNodeCount++
		if node.Spec.Backing == garagev1beta1.NodeBackingNodeLocalPool &&
			node.Spec.NodeLocalPoolName != "" && node.Spec.KubernetesNodeName != "" {
			activationLabel := nodeLocalPoolActivationLabel(cluster, node.Spec.NodeLocalPoolName)
			if claimedActivations[node.Spec.KubernetesNodeName] == nil {
				claimedActivations[node.Spec.KubernetesNodeName] = make(map[string]struct{})
			}
			claimedActivations[node.Spec.KubernetesNodeName][activationLabel] = struct{}{}
		}
		if _, skip := ignored[node.Name]; skip {
			continue
		}
		if !node.DeletionTimestamp.IsZero() {
			deleting = append(deleting, node.Name)
			continue
		}
		if node.Status.NodeID == "" || !node.Status.InLayout ||
			node.Status.ObservedGeneration < node.Generation {
			joining = append(joining, node.Name)
		}
	}

	if len(deleting) > 0 {
		sort.Strings(deleting)
		return false, false,
			"waiting for GarageNode " + deleting[0] + " to finish its Garage layout drain before starting another layout change",
			nil
	}
	// A pool activation label schedules the durable HostPath identity before a
	// GarageNode can be created for it. Include that short but important window
	// in the barrier so the gateway/default-pool reconcilers cannot start a
	// second topology batch in the same GarageCluster reconciliation.
	if r.ClusterScoped {
		kubernetesNodes := &corev1.NodeList{}
		if err := r.safetyReader().List(ctx, kubernetesNodes); err != nil {
			return false, false, "", fmt.Errorf("listing Kubernetes Nodes for node-local-pool layout serialization: %w", err)
		}
		activationPrefix := nodeLocalPoolActivationClusterPrefix(cluster)
		for i := range kubernetesNodes.Items {
			kubernetesNode := &kubernetesNodes.Items[i]
			for key, value := range kubernetesNode.Labels {
				if !nodeLocalPoolActivationValueIsActive(value) || !strings.HasPrefix(key, activationPrefix) {
					continue
				}
				if _, claimed := claimedActivations[kubernetesNode.Name][key]; !claimed {
					pendingActivations = append(pendingActivations, kubernetesNode.Name)
				}
			}
		}
		if len(pendingActivations) > 0 {
			sort.Strings(pendingActivations)
		}
	}

	// The first process must exist before its Admin API can report an empty
	// committed layout. This is the sole inference-based bootstrap case. Once a
	// GarageNode exists, fail closed on an unavailable or malformed history and
	// let the process become reachable before authorizing the rest of the batch.
	if allowStorageBootstrap && clusterNodeCount == 0 && len(pendingActivations) == 0 {
		return true, true, "", nil
	}

	history, err := r.getClusterLayoutHistory(ctx, cluster)
	if err != nil {
		return false, false, "", err
	}
	if history == nil {
		return false, false, "", fmt.Errorf("reading Garage layout history returned no response")
	}
	draining := history.GetDrainingVersions()
	if len(draining) == 0 && allowStorageBootstrap {
		empty, bootstrapErr := layoutHistoryHasNoCommittedStorage(history)
		if bootstrapErr != nil {
			return false, false, "", bootstrapErr
		}
		if empty {
			return true, true, "", nil
		}
	}
	if len(joining) > 0 {
		sort.Strings(joining)
		return false, false,
			"waiting for GarageNode " + joining[0] + " to discover its identity and enter the committed Garage layout before starting another layout change",
			nil
	}
	if len(pendingActivations) > 0 {
		return false, false,
			"waiting for the activated node-local-pool identity on Kubernetes Node " + pendingActivations[0] + " to materialize as a GarageNode before starting another layout change",
			nil
	}
	if len(draining) == 0 {
		return true, false, "", nil
	}
	// Garage's sync_ack tracker is housekeeping: on a single-node cluster it
	// can remain behind forever after the local full sync completes because
	// there is no peer advertisement to trigger the tracker merge. The layout
	// mutation coordinator already uses this distinction; keep the
	// cluster-level barrier consistent with it so readiness and topology
	// mutations do not livelock on bookkeeping-only Draining history.
	if history.DataMigrationSettled() {
		return true, false, "", nil
	}
	sort.Slice(draining, func(i, j int) bool {
		return draining[i].Version < draining[j].Version
	})
	versions := make([]string, 0, len(draining))
	for _, version := range draining {
		versions = append(versions, strconv.FormatUint(version.Version, 10))
	}
	return false, false,
		fmt.Sprintf(
			"waiting for Garage layout version(s) %s to finish synchronizing before starting another layout change (current version %d)",
			strings.Join(versions, ", "),
			history.CurrentVersion,
		),
		nil
}

// layoutHistoryHasNoCommittedStorage recognizes the one Garage state in which
// replication-factor bootstrap batching is necessary. Require the current
// version advertised by the response to be present exactly once; treating an
// incomplete response as empty could accidentally relax serialization on a
// live cluster.
func layoutHistoryHasNoCommittedStorage(history *garage.LayoutHistoryResponse) (bool, error) {
	if history == nil {
		return false, fmt.Errorf("reading Garage layout history returned no response")
	}
	currentCount := 0
	storageNodes := 0
	for i := range history.Versions {
		version := history.Versions[i]
		if version.Status != garage.LayoutVersionStatusCurrent || version.Version != history.CurrentVersion {
			continue
		}
		currentCount++
		storageNodes = version.StorageNodes
	}
	if currentCount != 1 {
		return false, fmt.Errorf(
			"garage layout history contained %d Current entries for advertised version %d; refusing to infer storage bootstrap state",
			currentCount, history.CurrentVersion,
		)
	}
	return storageNodes == 0, nil
}
