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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// A DaemonSet node-local pool is additive to the default StatefulSet/PVC group. The
// cluster owns one DaemonSet and content-addressed ConfigMap revisions per
// named pool; a GarageNode per selected Kubernetes Node owns only that
// identity's Garage layout role.
//
// Membership is deliberately not wired straight to the user's selector.
// The operator translates desired membership into a pool-specific activation
// label on Kubernetes Nodes:
//
//   - add: label Node -> schedule pod -> create GarageNode -> wait InLayout
//     and wait for Garage's layout history to finish synchronizing
//   - remove: delete GarageNode while pod remains online -> finalizer drains
//     the role -> remove Node label -> DaemonSet terminates the pod
//
// This preserves Garage's add-before-remove invariant and prevents a selector
// edit from taking the only copy of a role offline before its partitions have
// moved.

const (
	daemonSetKind = "DaemonSet"

	labelNodeLocalPool  = "garage.rajsingh.info/node-local-pool"
	labelKubernetesNode = "garage.rajsingh.info/kubernetes-node"

	annotationKubernetesNode                 = "garage.rajsingh.info/kubernetes-node"
	annotationNodeLocalPoolActivationLabel   = "garage.rajsingh.info/node-local-pool-activation-label"
	annotationNodeLocalPoolActivationValue   = "garage.rajsingh.info/node-local-pool-activation-value"
	annotationStorageDiskLayout              = "garage.rajsingh.info/storage-disk-layout"
	annotationStorageRolloutInput            = "garage.rajsingh.info/storage-rollout-input"
	annotationRolloutAdoptionFence           = "garage.rajsingh.info/rollout-adoption-fence"
	annotationNodeLocalPoolMembershipFence   = "garage.rajsingh.info/node-local-pool-membership-fence"
	annotationNodeLocalPoolMembershipStaging = "garage.rajsingh.info/node-local-pool-membership-staging"
	AnnotationNodeLocalOutOfService          = garagev1beta1.AnnotationNodeLocalOutOfService
	AnnotationNodeLocalReplaceIdentity       = garagev1beta1.AnnotationNodeLocalReplaceIdentity
	nodeLocalPoolActivationLabelValue        = "true"
	nodeLocalPoolActivationFenceValue        = "rollout-adoption-fenced"
	nodeLocalPoolActivationQuarantineValue   = "rollout-adoption-quarantine"
	nodeLocalPoolActivationLabelDomain       = "garage.rajsingh.info/"
	nodeLocalPoolActivationLabelNamePrefix   = "gc-"
	nodeLocalPoolLayoutTagPrefix             = "node-local-pool:"
	storageVolumeMarkerFile                  = ".garage-volume-id"
	storageVolumeMarkerMountRoot             = "/var/run/garage-volume-markers"
	storageVolumeMarkerNamePrefix            = "verify-"
	storageDiskLayoutVersion                 = 1
	nodeLocalPoolHostPathClaimVersion        = 1
	nodeLocalPoolHostPathClaimSuffix         = "-hostpath-claim"
	storageConfigRevisionLength              = 12
	storageRolloutPVCFinalizerPrefix         = "storage-rollout-"
	maximumStorageRolloutRetiredWorkloadUIDs = 32
	kubernetesNodeNameFieldPath              = "metadata.name"
	nodeLocalPoolSchedulingGateName          = "garage.rajsingh.info/node-local-pool-activation"
)

type nodeLocalPoolState struct {
	pool               *garagev1beta2.NodeLocalPoolSpec
	activationLabel    string
	activationValue    string
	configHash         string
	desiredPodSpecHash string
	workloadUID        types.UID
	expectedNodeIDs    map[string]string
	desiredNodes       map[string]*corev1.Node
	activePods         map[string]*corev1.Pod
	terminatingPods    map[string]*corev1.Pod
}

type nodeLocalPoolRolloutGarageState struct {
	history *garage.LayoutHistoryResponse
	health  *garage.ClusterHealth
	status  *garage.ClusterStatus
}

// nodeLocalPoolRolloutRecord is the status transaction owned by the single
// GarageNode actor allowed to update layout during an asynchronous OnDelete
// replacement. Status survives manager restarts and API conversion; all other
// layout writers remain blocked.
type nodeLocalPoolRolloutRecord = garagev1beta2.StorageRolloutStatus

var errStorageRolloutWorkloadMissing = stderrors.New("persisted storage rollout workload is missing")

// nodeLocalPoolDiskLayout is the safety record for the host directories mounted
// by a pool DaemonSet. It lives on the DaemonSet rather than only in the
// GarageCluster so it survives removal of a pool from the desired list while
// that pool's GarageNodes are still draining.
//
// Garage persists a DataLayout keyed by the in-container data_dir path. A
// writable path therefore cannot disappear or point at another host directory
// in one rollout. MetadataHostPath is stricter: it contains node_key and may
// never change while this DaemonSet identity exists.
type nodeLocalPoolDiskLayout struct {
	Version              int                     `json:"version"`
	MetadataHostPath     string                  `json:"metadataHostPath"`
	MetadataHostPathType corev1.HostPathType     `json:"metadataHostPathType"`
	DataPaths            []nodeLocalPoolDiskPath `json:"dataPaths"`
}

type nodeLocalPoolDiskPath struct {
	Path         string              `json:"path"`
	HostPath     string              `json:"hostPath"`
	HostPathType corev1.HostPathType `json:"hostPathType"`
	ReadOnly     bool                `json:"readOnly"`
}

// nodeLocalPoolHostPathClaim is the durable, per-Kubernetes-Node ownership
// record serialized with activation. Unlike the UID-scoped scheduling label,
// it survives same-name GarageCluster recreation and retains enough path
// information to reject an overlapping cluster even if the old DaemonSet,
// child GarageNode, or private activation label was removed out of band.
type nodeLocalPoolHostPathClaim struct {
	Version           int      `json:"version"`
	ClusterNamespace  string   `json:"clusterNamespace"`
	ClusterName       string   `json:"clusterName"`
	NodeLocalPoolName string   `json:"nodeLocalPoolName"`
	HostPaths         []string `json:"hostPaths"`
	GarageNodeID      string   `json:"garageNodeId,omitempty"`
	Retiring          bool     `json:"retiring,omitempty"`
}

// hasNodeLocalPools reports whether the cluster currently declares any
// additive node-local pools.
func hasNodeLocalPools(cluster *garagev1beta2.GarageCluster) bool {
	return cluster != nil && cluster.HasNodeLocalPools()
}

// nodeLocalPoolReader returns live API state for decisions that can start or
// stop a HostPath-backed Garage process. Informer lag is acceptable for
// ordinary convergence, but it must never turn a recently created GarageNode,
// old rollout Pod, or retained config revision into a false "does not exist"
// answer at a durable-identity boundary.
func (r *GarageClusterReconciler) nodeLocalPoolReader() client.Reader {
	return r.safetyReader()
}

func storageDaemonSetName(cluster *garagev1beta2.GarageCluster, nodeLocalPoolName string) string {
	return cluster.Name + "-storage-" + nodeLocalPoolName
}

func storageDaemonSetConfigMapName(cluster *garagev1beta2.GarageCluster, nodeLocalPoolName string) string {
	return storageDaemonSetName(cluster, nodeLocalPoolName) + "-config"
}

func storageDaemonSetConfigMapRevisionName(
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName,
	configHash string,
) string {
	return garageConfigRevisionName(storageDaemonSetConfigMapName(cluster, nodeLocalPoolName), configHash)
}

func nodeLocalPoolConfigResourceRevision(pool *garagev1beta2.NodeLocalPoolSpec, configHash string) string {
	diskLayout, _ := json.Marshal(storageDiskLayoutForPool(pool))
	sum := sha256.Sum256([]byte(configHash + "\x00" + string(diskLayout)))
	return hex.EncodeToString(sum[:])
}

func storageDaemonSetConfigResourceName(
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	configHash string,
) string {
	if pool == nil {
		return storageDaemonSetConfigMapRevisionName(cluster, "unknown", configHash)
	}
	return garageConfigRevisionName(
		storageDaemonSetConfigMapName(cluster, pool.Name),
		nodeLocalPoolConfigResourceRevision(pool, configHash),
	)
}

func isStorageDaemonSetConfigMapName(
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName,
	name string,
) bool {
	baseName := storageDaemonSetConfigMapName(cluster, nodeLocalPoolName)
	if name == baseName {
		// The unversioned name was used by the initial node-local-pool
		// implementation and remains part of the safety/cleanup boundary.
		return true
	}
	if len(name) <= storageConfigRevisionLength || name[len(name)-storageConfigRevisionLength-1] != '-' {
		return false
	}
	revision := name[len(name)-storageConfigRevisionLength:]
	if len(revision) != storageConfigRevisionLength {
		return false
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return false
	}
	return name == garageConfigRevisionName(baseName, revision)
}
