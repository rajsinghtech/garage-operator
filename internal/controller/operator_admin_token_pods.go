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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const annotationOperatorAdminTokenPodSet = "garage.rajsingh.info/operator-admin-token-pod-set"

type operatorAdminPodSet struct {
	Pods []corev1.Pod
	Hash string
}

// operatorAdminPodSetError marks a managed Garage Pod that is missing or not
// Ready yet, as opposed to an API, ownership, or integrity failure, so status
// can name the Pod that blocks the dynamic operator token.
type operatorAdminPodSetError struct{ err error }

func (e *operatorAdminPodSetError) Error() string { return e.err.Error() }
func (e *operatorAdminPodSetError) Unwrap() error { return e.err }

func managedPodNotReady(format string, args ...any) error {
	return &operatorAdminPodSetError{err: fmt.Errorf(format, args...)}
}

func garagePodReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" || !pod.DeletionTimestamp.IsZero() {
		return false
	}
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			return pod.Status.Conditions[i].Status == corev1.ConditionTrue
		}
	}
	return false
}

// garagePodNotReadyReason describes why garagePodReady rejected pod.
func garagePodNotReadyReason(pod *corev1.Pod) string {
	switch {
	case !pod.DeletionTimestamp.IsZero():
		return "terminating"
	case len(pod.Spec.SchedulingGates) > 0:
		gates := make([]string, 0, len(pod.Spec.SchedulingGates))
		for _, gate := range pod.Spec.SchedulingGates {
			gates = append(gates, gate.Name)
		}
		return "held at scheduling gate(s) " + strings.Join(gates, ", ")
	case pod.Status.Phase == "":
		return "phase not reported yet"
	case pod.Status.Phase != corev1.PodRunning:
		return fmt.Sprintf("phase is %s, not Running", pod.Status.Phase)
	case pod.Status.PodIP == "":
		return "no Pod IP assigned"
	default:
		return "Ready condition is not True"
	}
}

func garageNodeReferencesCluster(node *garagev1beta1.GarageNode, cluster *garagev1beta2.GarageCluster) bool {
	if node == nil || cluster == nil || node.Spec.ClusterRef.Name != cluster.Name {
		return false
	}
	namespace := node.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = node.Namespace
	}
	return namespace == cluster.Namespace
}

func operatorAdminPodRecord(pod *corev1.Pod, nodeID string) (string, error) {
	if !garagePodReady(pod) {
		return "", managedPodNotReady("managed Pod %s/%s is not Ready: %s", pod.Namespace, pod.Name, garagePodNotReadyReason(pod))
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.UID == "" {
		return "", fmt.Errorf("managed Pod %s/%s has no exact controller owner UID", pod.Namespace, pod.Name)
	}
	ref, err := mountedStaticAdminTokenRef(pod)
	if err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = DefaultAdminTokenKey
	}
	return fmt.Sprintf("%s|%s|%s|%s/%s:%s|%s",
		pod.Namespace, pod.UID, owner.UID, pod.Namespace, ref.Name, key, canonicalGarageNodeID(nodeID)), nil
}

// isLegacyClusterStorageSTS reports whether this is the pre-#190 cluster-level
// storage StatefulSet — the one migrateLegacyStorageSTSIfNeeded adopts and then
// orphan-deletes.
//
// It must be accounted even without a controller ownerReference, because the
// migration itself identifies it purely by name (a Get on <cluster> in the
// cluster's namespace) and never checks ownership. Requiring ownership here while
// the migration does not means a legacy StatefulSet the operator is willing to
// adopt is simultaneously a Pod it refuses to account for — so the static
// credential snapshot is refused, and the migration that would remove the Pod
// never gets to run. It is a Garage process of this cluster by the operator's own
// definition: it carries the cluster label, the cluster's Admin Service already
// routes to it, and the operator is about to take it over.
//
// The branch is naturally transient: once the migration completes, the
// StatefulSet is gone.
func isLegacyClusterStorageSTS(sts *appsv1.StatefulSet, cluster *garagev1beta2.GarageCluster) bool {
	return sts != nil && cluster != nil &&
		sts.Name == cluster.Name && sts.Namespace == cluster.Namespace
}

// expectedOperatorAdminPodSet proves the complete set behind the shared local
// Admin Service. It starts from durable GarageNode identities, then accounts
// for cluster-owned edge/legacy workloads, and finally rejects any additional
// nonterminating label-selected Pod that the Service could route to.
func expectedOperatorAdminPodSet(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
) (*operatorAdminPodSet, error) {
	return expectedOperatorAdminPodSetAllowEmpty(ctx, reader, cluster, false)
}

func expectedOperatorAdminPodSetAllowEmpty(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	allowEmpty bool,
) (*operatorAdminPodSet, error) {
	if cluster == nil {
		return nil, fmt.Errorf("garageCluster is nil")
	}
	allNodes := &garagev1beta1.GarageNodeList{}
	// GarageNode cluster references are namespace-local and every process behind
	// this GarageCluster's shared Admin Service lives in the cluster namespace.
	// Keeping this list namespaced is also required for the supported
	// namespace-scoped operator install, whose safety reader cannot list custom
	// resources cluster-wide.
	if err := reader.List(ctx, allNodes, client.InNamespace(cluster.Namespace)); err != nil {
		return nil, fmt.Errorf("listing GarageNodes for operator token readiness: %w", err)
	}

	accounted := make(map[types.UID]corev1.Pod)
	records := make(map[types.UID]string)
	account := func(pod *corev1.Pod, nodeID string) error {
		if pod == nil || pod.UID == "" {
			return fmt.Errorf("managed Garage Pod has no immutable UID")
		}
		record, err := operatorAdminPodRecord(pod, nodeID)
		if err != nil {
			return err
		}
		if existing, ok := records[pod.UID]; ok && existing != record {
			return fmt.Errorf("managed Pod %s/%s was associated with conflicting identity records", pod.Namespace, pod.Name)
		}
		accounted[pod.UID] = *pod
		records[pod.UID] = record
		return nil
	}

	for i := range allNodes.Items {
		node := &allNodes.Items[i]
		if !garageNodeReferencesCluster(node, cluster) || node.Spec.External != nil {
			continue
		}
		if isNodeLocalPoolBacked(node) {
			ds := &appsv1.DaemonSet{}
			dsKey := types.NamespacedName{Name: storageDaemonSetName(cluster, node.Spec.NodeLocalPoolName), Namespace: cluster.Namespace}
			if err := reader.Get(ctx, dsKey, ds); err != nil {
				if errors.IsNotFound(err) {
					return nil, managedPodNotReady("expected node-local-pool DaemonSet for GarageNode %s/%s: %w", node.Namespace, node.Name, err)
				}
				return nil, fmt.Errorf("expected node-local-pool DaemonSet for GarageNode %s/%s: %w", node.Namespace, node.Name, err)
			}
			if !metav1.IsControlledBy(ds, cluster) {
				return nil, fmt.Errorf("node-local-pool DaemonSet %s is not controlled by GarageCluster %s/%s", dsKey, cluster.Namespace, cluster.Name)
			}
			pods := &corev1.PodList{}
			if err := reader.List(ctx, pods,
				client.InNamespace(cluster.Namespace),
				client.MatchingLabels(map[string]string{
					labelCluster: cluster.Name, labelNodeLocalPool: node.Spec.NodeLocalPoolName,
				}),
			); err != nil {
				return nil, err
			}
			var exact *corev1.Pod
			for j := range pods.Items {
				pod := &pods.Items[j]
				owner := metav1.GetControllerOf(pod)
				if owner == nil || owner.Kind != daemonSetKind || owner.UID != ds.UID ||
					pod.Spec.NodeName != node.Spec.KubernetesNodeName || !pod.DeletionTimestamp.IsZero() {
					continue
				}
				if exact != nil {
					return nil, fmt.Errorf("multiple active Pods represent node-local-pool GarageNode %s/%s", node.Namespace, node.Name)
				}
				exact = pod
			}
			if exact == nil {
				return nil, managedPodNotReady("waiting for exact node-local-pool Pod for GarageNode %s/%s", node.Namespace, node.Name)
			}
			if err := account(exact, node.Status.NodeID); err != nil {
				return nil, err
			}
			continue
		}

		sts := &appsv1.StatefulSet{}
		stsKey := types.NamespacedName{Name: node.Name, Namespace: node.Namespace}
		if err := reader.Get(ctx, stsKey, sts); err != nil {
			if errors.IsNotFound(err) {
				return nil, managedPodNotReady("expected StatefulSet for GarageNode %s: %w", stsKey, err)
			}
			return nil, fmt.Errorf("expected StatefulSet for GarageNode %s: %w", stsKey, err)
		}
		if !metav1.IsControlledBy(sts, node) {
			return nil, fmt.Errorf("StatefulSet %s is not controlled by GarageNode %s/%s", stsKey, node.Namespace, node.Name)
		}
		if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 1 {
			return nil, fmt.Errorf("garageNode StatefulSet %s must desire exactly one Pod before operator token activation", stsKey)
		}
		pod := &corev1.Pod{}
		podKey := types.NamespacedName{Name: node.Name + "-0", Namespace: node.Namespace}
		if err := reader.Get(ctx, podKey, pod); err != nil {
			if errors.IsNotFound(err) {
				return nil, managedPodNotReady("expected Pod for GarageNode %s/%s: %w", node.Namespace, node.Name, err)
			}
			return nil, fmt.Errorf("expected Pod for GarageNode %s/%s: %w", node.Namespace, node.Name, err)
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != kindStatefulSet || owner.UID != sts.UID {
			return nil, fmt.Errorf("pod %s is not controlled by exact GarageNode StatefulSet UID %s", podKey, sts.UID)
		}
		if err := account(pod, node.Status.NodeID); err != nil {
			return nil, err
		}
	}

	clusterPods := &corev1.PodList{}
	if err := reader.List(ctx, clusterPods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return nil, fmt.Errorf("listing cluster-labelled Pods for operator token readiness: %w", err)
	}
	podsByOwner := make(map[types.UID][]*corev1.Pod)
	for i := range clusterPods.Items {
		pod := &clusterPods.Items[i]
		if !pod.DeletionTimestamp.IsZero() {
			continue
		}
		owner := metav1.GetControllerOf(pod)
		if owner != nil {
			podsByOwner[owner.UID] = append(podsByOwner[owner.UID], pod)
		}
	}

	statefulSets := &appsv1.StatefulSetList{}
	if err := reader.List(ctx, statefulSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return nil, err
	}
	// Note the legacy StatefulSet is accounted alongside owned ones below; see
	// isLegacyClusterStorageSTS for why ownership alone is the wrong test here.
	for i := range statefulSets.Items {
		sts := &statefulSets.Items[i]
		if !metav1.IsControlledBy(sts, cluster) && !isLegacyClusterStorageSTS(sts, cluster) {
			continue
		}
		desired := int32(1)
		if sts.Spec.Replicas != nil {
			desired = *sts.Spec.Replicas
		}
		owned := podsByOwner[sts.UID]
		if int32(len(owned)) < desired {
			return nil, managedPodNotReady("cluster-owned StatefulSet %s/%s desires %d Pods but only %d exact nonterminating Pods exist", sts.Namespace, sts.Name, desired, len(owned))
		}
		ownedByName := make(map[string]*corev1.Pod, len(owned))
		for _, pod := range owned {
			ownedByName[pod.Name] = pod
		}
		for ordinal := int32(0); ordinal < desired; ordinal++ {
			expectedName := fmt.Sprintf("%s-%d", sts.Name, ordinal)
			if ownedByName[expectedName] == nil {
				return nil, managedPodNotReady("cluster-owned StatefulSet %s/%s is missing exact desired Pod %s; refusing a non-contiguous or incomplete ordinal set", sts.Namespace, sts.Name, expectedName)
			}
		}
		for _, pod := range owned {
			if _, ok := accounted[pod.UID]; ok {
				continue
			}
			if err := account(pod, ""); err != nil {
				return nil, err
			}
		}
	}

	daemonSets := &appsv1.DaemonSetList{}
	if err := reader.List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return nil, err
	}
	for i := range daemonSets.Items {
		ds := &daemonSets.Items[i]
		if !metav1.IsControlledBy(ds, cluster) {
			continue
		}
		owned := podsByOwner[ds.UID]
		if int32(len(owned)) != ds.Status.DesiredNumberScheduled {
			return nil, managedPodNotReady("cluster-owned DaemonSet %s/%s desires %d Pods but has %d exact nonterminating Pods", ds.Namespace, ds.Name, ds.Status.DesiredNumberScheduled, len(owned))
		}
		for _, pod := range owned {
			if _, ok := accounted[pod.UID]; ok {
				continue
			}
			if err := account(pod, ""); err != nil {
				return nil, err
			}
		}
	}

	for i := range clusterPods.Items {
		pod := &clusterPods.Items[i]
		if !pod.DeletionTimestamp.IsZero() {
			continue
		}
		if _, ok := accounted[pod.UID]; !ok {
			return nil, fmt.Errorf("cluster Admin Service can route to unaccounted Pod %s/%s (UID %s)", pod.Namespace, pod.Name, pod.UID)
		}
	}
	if len(accounted) == 0 && !allowEmpty {
		return nil, managedPodNotReady("waiting for at least one complete managed Garage process")
	}

	sortedRecords := make([]string, 0, len(records))
	pods := make([]corev1.Pod, 0, len(accounted))
	for uid, record := range records {
		sortedRecords = append(sortedRecords, record)
		pods = append(pods, accounted[uid])
	}
	sort.Strings(sortedRecords)
	sort.Slice(pods, func(i, j int) bool {
		return strings.Compare(string(pods[i].UID), string(pods[j].UID)) < 0
	})
	digest := sha256.Sum256([]byte(strings.Join(sortedRecords, "\n")))
	return &operatorAdminPodSet{Pods: pods, Hash: hex.EncodeToString(digest[:])}, nil
}

func getOperatorAdminPodSet(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
) (*operatorAdminPodSet, error) {
	set, err := expectedOperatorAdminPodSet(ctx, reader, cluster)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("managed Garage process set is incomplete: %w", err)
		}
		return nil, err
	}
	return set, nil
}
