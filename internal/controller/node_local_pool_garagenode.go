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
	"net"
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func (r *GarageClusterReconciler) listNodeLocalPoolStorageNodes(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (map[string]*garagev1beta1.GarageNode, []string, error) {
	generated := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, generated,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelAppManagedBy: managedByOperatorValue,
		}),
	); err != nil {
		return nil, nil, err
	}
	out := make(map[string]*garagev1beta1.GarageNode)
	for i := range generated.Items {
		node := &generated.Items[i]
		if node.Labels[labelNodeLocalPool] == "" ||
			node.Spec.Backing != garagev1beta1.NodeBackingNodeLocalPool ||
			node.Spec.ClusterRef.Name != cluster.Name ||
			!metav1.IsControlledBy(node, cluster) {
			continue
		}
		out[node.Name] = node
	}

	// Manual and SMB GarageNodes need not carry operator labels. Read the wider
	// namespace inventory only for durable node_id collision detection; the
	// generated per-member reconciliation above remains label-scoped.
	list := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, list, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, nil, err
	}
	byID := make(map[string][]*garagev1beta1.GarageNode)
	for i := range list.Items {
		node := &list.Items[i]
		if node.Spec.ClusterRef.Name == cluster.Name && node.Status.NodeID != "" {
			byID[node.Status.NodeID] = append(byID[node.Status.NodeID], node)
		}
	}

	// Detect copied or concurrently mounted metadata directories. Two Garage
	// processes that load the same node_key are one authenticated identity,
	// regardless of how many Pods or GarageNode CRs Kubernetes shows.
	var collisions []string
	for nodeID, owners := range byID {
		if len(owners) < 2 {
			continue
		}
		hasDaemonSetOwner := false
		names := make([]string, 0, len(owners))
		for _, owner := range owners {
			if isNodeLocalPoolBacked(owner) {
				hasDaemonSetOwner = true
				names = append(names, fmt.Sprintf(
					"pool %s on Kubernetes Node %s",
					owner.Spec.NodeLocalPoolName,
					owner.Spec.KubernetesNodeName,
				))
				continue
			}
			names = append(names, owner.Name)
		}
		if !hasDaemonSetOwner {
			continue
		}
		sort.Strings(names)
		displayID := nodeID
		if len(displayID) > 16 {
			displayID = displayID[:16]
		}
		collisions = append(collisions, fmt.Sprintf("%s=[%s]", displayID, strings.Join(names, ", ")))
	}
	sort.Strings(collisions)
	return out, collisions, nil
}

func (r *GarageClusterReconciler) buildNodeLocalPoolStorageNode(
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	k8sNode *corev1.Node,
	pod *corev1.Pod,
) (*garagev1beta1.GarageNode, error) {
	name := nodeLocalPoolGarageNodeName(cluster.Name, pool.Name, k8sNode.Name)
	zone := cluster.Spec.Zone
	if zone == "" {
		zone = defaultZoneName
	}
	var zoneFrom *garagev1beta1.ZoneSource
	if cluster.Spec.ZoneFrom != nil {
		zoneFrom = &garagev1beta1.ZoneSource{NodeLabel: cluster.Spec.ZoneFrom.NodeLabel}
	}
	var capacity *resource.Quantity
	if pool.Capacity != nil {
		copy := pool.Capacity.DeepCopy()
		capacity = &copy
	}

	var nodeNetwork *garagev1beta1.NodeNetworkConfig
	rpcAddress := strings.TrimSpace(nodeLocalPoolRPCPublicAddrTemplate(pool))
	if rpcAddress != "" {
		var err error
		rpcAddress, err = renderDaemonSetNodeRPCAddress(rpcAddress, k8sNode.Name)
		if err != nil {
			return nil, err
		}
	} else {
		podIP, err := daemonSetPodRPCIP(cluster, pod)
		if err != nil {
			return nil, err
		}
		if podIP != "" {
			rpcPort := getRPCPort(cluster)
			rpcAddress = rpcAddr(podIP, rpcPort)
		}
	}
	if rpcAddress != "" {
		nodeNetwork = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: rpcAddress}
	}

	// GarageNode.spec.tags is the user-owned portion of the role only. Cluster,
	// UID, tier, pool, Kubernetes-node, and RPC tags are derived later from the
	// typed fields by GarageNodeReconciler. Persisting them here would violate
	// the same admission ownership boundary applied to user-authored nodes.
	tags := userNodeLayoutTags(cluster.Spec.DefaultNodeTags)
	nodeLabels := map[string]string{
		labelCluster:        cluster.Name,
		labelTier:           tierStorage,
		labelAppManagedBy:   managedByOperatorValue,
		labelNodeLocalPool:  pool.Name,
		labelKubernetesNode: kubernetesNodeLabelValue(k8sNode.Name),
	}
	nodeAnnotations := map[string]string{annotationKubernetesNode: k8sNode.Name}
	if recoveryNodeID := strings.TrimSpace(
		k8sNode.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)],
	); recoveryNodeID != "" {
		if !isValidGarageNodeID(recoveryNodeID) {
			return nil, fmt.Errorf(
				"kubernetes Node %q carries invalid recovery identity %q for node-local pool %q",
				k8sNode.Name, recoveryNodeID, pool.Name,
			)
		}
		nodeAnnotations[garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID] = recoveryNodeID
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   cluster.Namespace,
			Labels:      nodeLabels,
			Annotations: nodeAnnotations,
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:         garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			KubernetesNodeName: k8sNode.Name,
			NodeLocalPoolName:  pool.Name,
			Zone:               zone,
			ZoneFrom:           zoneFrom,
			Capacity:           capacity,
			Tags:               tags,
			Network:            nodeNetwork,
		},
	}
	if err := controllerutil.SetControllerReference(cluster, node, r.Scheme); err != nil {
		return nil, err
	}
	return node, nil
}

func renderDaemonSetNodeRPCAddress(template, nodeName string) (string, error) {
	address := strings.ReplaceAll(strings.TrimSpace(template), "{nodeName}", nodeName)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf(
			"rpcPublicAddrTemplate renders an invalid address for Kubernetes Node %q: %w",
			nodeName,
			err,
		)
	}
	dnsHost := strings.TrimSuffix(host, ".")
	if host == "" || (net.ParseIP(host) == nil && len(utilvalidation.IsDNS1123Subdomain(dnsHost)) > 0) {
		return "", fmt.Errorf(
			"rpcPublicAddrTemplate renders invalid host %q for Kubernetes Node %q",
			host,
			nodeName,
		)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf(
			"rpcPublicAddrTemplate renders invalid port %q for Kubernetes Node %q",
			portText,
			nodeName,
		)
	}
	return address, nil
}

func nodeLocalPoolStorageNodeNeedsUpdate(current, desired *garagev1beta1.GarageNode) bool {
	if current.Spec.Zone != desired.Spec.Zone || !zoneSourcesEqual(current.Spec.ZoneFrom, desired.Spec.ZoneFrom) {
		return true
	}
	if (current.Spec.Capacity == nil) != (desired.Spec.Capacity == nil) {
		return true
	}
	if current.Spec.Capacity != nil && desired.Spec.Capacity != nil && current.Spec.Capacity.Cmp(*desired.Spec.Capacity) != 0 {
		return true
	}
	if !tagSetEqual(current.Spec.Tags, desired.Spec.Tags) ||
		current.Spec.Backing != desired.Spec.Backing ||
		current.Spec.KubernetesNodeName != desired.Spec.KubernetesNodeName ||
		current.Spec.NodeLocalPoolName != desired.Spec.NodeLocalPoolName ||
		!equality.Semantic.DeepEqual(current.Spec.Network, desired.Spec.Network) {
		return true
	}
	return false
}

func nodeLocalPoolCapacityIncreaseWaitsForPodRevision(
	current, desired *garagev1beta1.GarageNode,
	pod *corev1.Pod,
	desiredPodSpecHash, desiredConfigHash string,
) bool {
	if current == nil || desired == nil || desired.Spec.Capacity == nil {
		return false
	}
	if current.Spec.Capacity != nil && desired.Spec.Capacity.Cmp(*current.Spec.Capacity) <= 0 {
		return false
	}
	return pod == nil ||
		pod.Annotations[annotationPodSpecHash] != desiredPodSpecHash ||
		pod.Annotations[annotationConfigHash] != desiredConfigHash ||
		!garageNodeLayoutReadyForPod(current, pod)
}

// updateNodeLocalPoolGarageNode retries the parent-owned spec/metadata write
// against the latest resourceVersion. GarageNode status can change immediately
// when a replacement Pod becomes Ready; treating that legitimate concurrent
// status handshake as a failed cluster reconcile would defeat the event-driven
// rollout path and can leave the next pool activation waiting on a stale spec.
func (r *GarageClusterReconciler) updateNodeLocalPoolGarageNode(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	current, desired *garagev1beta1.GarageNode,
) (*garagev1beta1.GarageNode, error) {
	if current == nil || desired == nil {
		return nil, fmt.Errorf("node-local-pool GarageNode update requires current and desired objects")
	}
	expectedUID := current.UID
	key := client.ObjectKeyFromObject(current)
	var updated *garagev1beta1.GarageNode
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &garagev1beta1.GarageNode{}
		if err := r.nodeLocalPoolReader().Get(ctx, key, fresh); err != nil {
			return err
		}
		if fresh.UID != expectedUID {
			return fmt.Errorf("garageNode %s was recreated during node-local-pool update", key)
		}
		if !metav1.IsControlledBy(fresh, cluster) ||
			fresh.Spec.Backing != garagev1beta1.NodeBackingNodeLocalPool ||
			fresh.Spec.NodeLocalPoolName != desired.Spec.NodeLocalPoolName ||
			fresh.Spec.KubernetesNodeName != desired.Spec.KubernetesNodeName {
			return fmt.Errorf("garageNode %s no longer represents the expected operator-owned node-local-pool identity", key)
		}
		metadataChanged := mergeOwnedMetadata(fresh, desired)
		if !metadataChanged && !nodeLocalPoolStorageNodeNeedsUpdate(fresh, desired) {
			updated = fresh
			return nil
		}
		fresh.Spec.Zone = desired.Spec.Zone
		fresh.Spec.ZoneFrom = desired.Spec.ZoneFrom
		fresh.Spec.Capacity = desired.Spec.Capacity
		fresh.Spec.Tags = append([]string(nil), desired.Spec.Tags...)
		fresh.Spec.Backing = desired.Spec.Backing
		fresh.Spec.KubernetesNodeName = desired.Spec.KubernetesNodeName
		fresh.Spec.NodeLocalPoolName = desired.Spec.NodeLocalPoolName
		fresh.Spec.Network = desired.Spec.Network
		if err := r.Update(ctx, fresh); err != nil {
			return err
		}
		updated = fresh
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func daemonSetPodRPCIP(cluster *garagev1beta2.GarageCluster, pod *corev1.Pod) (string, error) {
	if pod == nil {
		return "", nil
	}
	candidates := make([]string, 0, 1+len(pod.Status.PodIPs))
	seen := map[string]bool{}
	if ip := strings.TrimSpace(pod.Status.PodIP); ip != "" {
		candidates = append(candidates, ip)
		seen[ip] = true
	}
	for _, podIP := range pod.Status.PodIPs {
		if ip := strings.TrimSpace(podIP.IP); ip != "" && !seen[ip] {
			candidates = append(candidates, ip)
			seen[ip] = true
		}
	}
	subnet := strings.TrimSpace(cluster.Spec.Network.RPCPublicAddrSubnet)
	if subnet == "" {
		if len(candidates) > 0 {
			return candidates[0], nil
		}
		return "", nil
	}
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("network.rpcPublicAddrSubnet %q is invalid: %w", subnet, err)
	}
	for _, candidate := range candidates {
		if ip := net.ParseIP(candidate); ip != nil && network.Contains(ip) {
			return candidate, nil
		}
	}
	if len(candidates) > 0 {
		return "", fmt.Errorf(
			"DaemonSet pod %s/%s has IPs %s, but none match network.rpcPublicAddrSubnet %s",
			pod.Namespace,
			pod.Name,
			strings.Join(candidates, ", "),
			subnet,
		)
	}
	return "", nil
}

// isStorageDaemonSetPod validates both the controller reference and the pool
// label, preventing a foreign pod with broad storage labels from materializing
// a Garage layout role.
func isStorageDaemonSetPod(cluster *garagev1beta2.GarageCluster, pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	return isStorageDaemonSetPodForPool(cluster, pod.Labels[labelNodeLocalPool], pod)
}

func isStorageDaemonSetPodForPool(cluster *garagev1beta2.GarageCluster, nodeLocalPoolName string, pod *corev1.Pod) bool {
	if cluster == nil || pod == nil || nodeLocalPoolName == "" || pod.Labels[labelNodeLocalPool] != nodeLocalPoolName {
		return false
	}
	owner := metav1.GetControllerOf(pod)
	return owner != nil &&
		owner.APIVersion == appsv1.SchemeGroupVersion.String() &&
		owner.Kind == daemonSetKind &&
		owner.Name == storageDaemonSetName(cluster, nodeLocalPoolName)
}

func isStorageDaemonSetPodForPoolUID(
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
	daemonSetUID types.UID,
	pod *corev1.Pod,
) bool {
	if daemonSetUID == "" || !isStorageDaemonSetPodForPool(cluster, nodeLocalPoolName, pod) {
		return false
	}
	return metav1.GetControllerOf(pod).UID == daemonSetUID
}
