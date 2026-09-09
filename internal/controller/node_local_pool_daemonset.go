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
	"path"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/workloadidentity"
)

func (r *GarageClusterReconciler) reconcileNodeLocalPoolDaemonSet(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	activationLabel,
	configHash string,
) error {
	return r.reconcileNodeLocalPoolDaemonSetWithRecoveryFence(
		ctx, cluster, pool, activationLabel, configHash, false,
	)
}

// reconcileNodeLocalPoolDaemonSetWithRecoveryFence recreates a deleted rollout
// workload with an impossible activation-label value in its Pod nodeSelector.
// The desired (unfenced) hashes remain on the template; status first CAS-adopts
// the new DaemonSet UID, then an ordinary reconcile removes the fence and lets
// Pods schedule.
func (r *GarageClusterReconciler) reconcileNodeLocalPoolDaemonSetWithRecoveryFence(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	activationLabel,
	configHash string,
	recoveryFence bool,
) error {
	log := logf.FromContext(ctx)
	if err := r.assertNodeLocalPoolPrerequisites(ctx, cluster); err != nil {
		return err
	}
	podTemplate := nodeLocalPoolPodTemplate(pool)
	name := storageDaemonSetName(cluster, pool.Name)
	key := types.NamespacedName{Name: name, Namespace: cluster.Namespace}
	existing := &appsv1.DaemonSet{}
	existingErr := r.nodeLocalPoolReader().Get(ctx, key, existing)
	if existingErr != nil && !errors.IsNotFound(existingErr) {
		return existingErr
	}
	activationValue := nodeLocalPoolActivationLabelValue
	ordinaryActivationBootstrap := !recoveryFence && errors.IsNotFound(existingErr)
	if ordinaryActivationBootstrap {
		activationValue = nodeLocalPoolActivationFenceValue
	} else if existingErr == nil {
		activationValue = nodeLocalPoolActivationValueForDaemonSet(existing)
	}
	if recoveryFence {
		activationValue = nodeLocalPoolActivationFenceValue
	} else if existingErr == nil && existing.Annotations[annotationRolloutAdoptionFence] == annotationTrue {
		return fmt.Errorf("DaemonSet %s is behind a rollout-adoption fence and may only be enabled by its persisted storage rollout transaction", name)
	} else if existingErr == nil && activationValue == nodeLocalPoolActivationFenceValue {
		// Recover a create whose fenced object reached the API server but whose
		// UID-derived activation update did not. Nodes remain quarantined until
		// this exact controller incarnation publishes its own token.
		ordinaryActivationBootstrap = true
		uid := existing.UID
		if uid == "" {
			uid = uuid.NewUUID()
		}
		activationValue = nodeLocalPoolActivationValueForWorkloadUID(uid)
	}
	if ordinaryActivationBootstrap {
		if err := r.fenceNodeLocalPoolActivationNodes(
			ctx, cluster, pool.Name, nodeLocalPoolActivationQuarantineValue,
		); err != nil {
			return fmt.Errorf("quarantining node-local pool %q before workload activation: %w", pool.Name, err)
		}
		if err := r.ensureNoPreviousNodeLocalPoolPods(
			ctx, cluster, pool.Name, key, errors.IsNotFound(existingErr),
		); err != nil {
			return err
		}
	}
	desiredDiskLayout := storageDiskLayoutForPool(pool)
	diskLayoutAnnotation, err := marshalStorageDiskLayout(desiredDiskLayout)
	if err != nil {
		return fmt.Errorf("building storage disk layout safety record: %w", err)
	}
	image := resolveGarageImage(cluster.Spec.Image, cluster.Spec.ImageRepository, r.DefaultImage)
	volumes, volumeMounts := buildStorageDaemonSetVolumesAndMounts(cluster, pool, configHash)
	podSpec := buildGaragePodSpec(PodSpecConfig{
		Image:                     image,
		ImagePullPolicy:           cluster.Spec.ImagePullPolicy,
		ImagePullSecrets:          cluster.Spec.ImagePullSecrets,
		Resources:                 podTemplate.Resources,
		NodeSelector:              map[string]string{activationLabel: activationValue},
		Tolerations:               podTemplate.Tolerations,
		Affinity:                  podTemplate.Affinity,
		PriorityClassName:         podTemplate.PriorityClassName,
		ServiceAccountName:        cluster.Spec.ServiceAccountName,
		SecurityContext:           podTemplate.SecurityContext,
		ContainerSecurityContext:  podTemplate.ContainerSecurityContext,
		TopologySpreadConstraints: podTemplate.TopologySpreadConstraints,
		Logging:                   cluster.Spec.Logging,
		Env:                       podTemplate.Env,
		EnvFrom:                   podTemplate.EnvFrom,
	}, volumes, volumeMounts, buildContainerPorts(cluster))
	// Every pool Pod starts behind a scheduler-enforced gate. The cluster
	// reconciler removes it only from a Pod owned by the exact current DaemonSet
	// UID, after re-reading the Node activation token and all older pool Pods.
	// A late create from a retired DaemonSet therefore remains unscheduled even
	// if the scheduler observed an older Node-label snapshot.
	podSpec.SchedulingGates = append(podSpec.SchedulingGates, corev1.PodSchedulingGate{
		Name: nodeLocalPoolSchedulingGateName,
	})
	if err := validateGarageCredentialFileAccess(
		cluster, podSpec, fmt.Sprintf("spec.storage.nodeLocalPools[%q].podTemplate", pool.Name),
	); err != nil {
		return err
	}

	selector := r.selectorLabelsForTier(cluster, tierStorage)
	selector[labelNodeLocalPool] = pool.Name
	selector[labelStorageGroup] = storageGroupNodeLocal
	resourceLabels := r.labelsForTier(cluster, tierStorage)
	resourceLabels[labelNodeLocalPool] = pool.Name
	resourceLabels[labelStorageGroup] = storageGroupNodeLocal
	userPodLabels := workloadidentity.UserPodLabels(podTemplate.PodLabels)
	podLabels := make(map[string]string, len(userPodLabels)+len(resourceLabels))
	for key, value := range userPodLabels {
		podLabels[key] = value
	}
	for key, value := range resourceLabels {
		podLabels[key] = value
	}

	// The activation token is an internal workload-incarnation fence. Normalize
	// it out of the public desired-revision hash so recreating an otherwise
	// identical DaemonSet does not manufacture a second user-visible rollout.
	hashPodSpec := podSpec.DeepCopy()
	hashPodSpec.NodeSelector[activationLabel] = nodeLocalPoolActivationLabelValue
	podSpecHash := computePodSpecHash(*hashPodSpec, podTemplate.PodAnnotations, userPodLabels)
	podAnnotations := make(map[string]string, len(podTemplate.PodAnnotations)+3)
	for key, value := range podTemplate.PodAnnotations {
		podAnnotations[key] = value
	}
	podAnnotations[annotationConfigHash] = configHash
	podAnnotations[annotationPodSpecHash] = podSpecHash
	podAnnotations[annotationNodeLocalPoolActivationLabel] = activationLabel
	podAnnotations[annotationNodeLocalPoolActivationValue] = activationValue

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    resourceLabels,
			Annotations: map[string]string{
				annotationNodeLocalPoolActivationLabel: activationLabel,
				annotationNodeLocalPoolActivationValue: activationValue,
				annotationStorageDiskLayout:            diskLayoutAnnotation,
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.OnDeleteDaemonSetStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
		},
	}
	if recoveryFence {
		ds.Annotations[annotationRolloutAdoptionFence] = annotationTrue
	}
	if existingErr == nil && existing.Annotations[annotationNodeLocalPoolMembershipFence] != "" {
		ds.Annotations[annotationNodeLocalPoolMembershipFence] = existing.Annotations[annotationNodeLocalPoolMembershipFence]
	}
	if err := controllerutil.SetControllerReference(cluster, ds, r.Scheme); err != nil {
		return err
	}

	err = existingErr
	if errors.IsNotFound(err) {
		log.Info("Creating node-local pool DaemonSet", "name", name, "pool", pool.Name)
		if err := r.Create(ctx, ds); err != nil {
			return err
		}
		if !recoveryFence {
			uid := ds.UID
			if uid == "" {
				// The Kubernetes API always assigns a UID. This fallback keeps
				// controller-runtime fake clients faithful to the same unique-token
				// contract in unit tests.
				uid = uuid.NewUUID()
			}
			activationValue = nodeLocalPoolActivationValueForWorkloadUID(uid)
			ds.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
			ds.Spec.Template.Annotations[annotationNodeLocalPoolActivationValue] = activationValue
			ds.Spec.Template.Spec.NodeSelector[activationLabel] = activationValue
			if err := r.Update(ctx, ds); err != nil {
				return fmt.Errorf("publishing node-local pool %q workload activation token: %w", pool.Name, err)
			}
		}
		return r.cleanupObsoleteNodeLocalPoolConfigMaps(
			ctx,
			cluster,
			pool.Name,
			storageDaemonSetConfigResourceName(cluster, pool, configHash),
		)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(existing, cluster) {
		return fmt.Errorf(
			"existing DaemonSet %s is not controlled by GarageCluster %s/%s; refusing to adopt a colliding workload",
			name, cluster.Namespace, cluster.Name,
		)
	}
	existingDiskLayout, err := storageDiskLayoutFromDaemonSet(existing)
	if err != nil {
		return fmt.Errorf("reading existing DaemonSet %s disk layout: %w", name, err)
	}
	if err := validateStorageDiskLayoutTransition(pool.Name, existingDiskLayout, desiredDiskLayout); err != nil {
		return err
	}
	if !equality.Semantic.DeepEqual(existing.Spec.Selector, ds.Spec.Selector) {
		return fmt.Errorf("existing DaemonSet %s has an incompatible immutable selector; delete the stale resource after confirming its GarageNodes are drained", name)
	}
	needsUpdate := mergeOwnedMetadata(existing, ds) ||
		!equality.Semantic.DeepEqual(existing.Spec.Template, ds.Spec.Template) ||
		!equality.Semantic.DeepEqual(existing.Spec.UpdateStrategy, ds.Spec.UpdateStrategy)
	if !needsUpdate {
		return r.cleanupObsoleteNodeLocalPoolConfigMaps(
			ctx,
			cluster,
			pool.Name,
			storageDaemonSetConfigResourceName(cluster, pool, configHash),
		)
	}
	existing.Spec.Template = ds.Spec.Template
	existing.Spec.UpdateStrategy = ds.Spec.UpdateStrategy
	existing.OwnerReferences = ds.OwnerReferences
	log.Info("Updating node-local pool DaemonSet", "name", name, "pool", pool.Name)
	if err := r.Update(ctx, existing); err != nil {
		return err
	}
	return r.cleanupObsoleteNodeLocalPoolConfigMaps(
		ctx,
		cluster,
		pool.Name,
		storageDaemonSetConfigResourceName(cluster, pool, configHash),
	)
}

func nodeLocalPoolPodTemplate(pool *garagev1beta2.NodeLocalPoolSpec) garagev1beta2.NodeLocalPoolPodTemplate {
	if pool == nil || pool.PodTemplate == nil {
		return garagev1beta2.NodeLocalPoolPodTemplate{}
	}
	return *pool.PodTemplate
}

func nodeLocalPoolRPCPublicAddrTemplate(pool *garagev1beta2.NodeLocalPoolSpec) string {
	if pool == nil || pool.Network == nil {
		return ""
	}
	return pool.Network.RPCPublicAddrTemplate
}

// ensureNoPreviousNodeLocalPoolPods closes the delete/recreate race for the
// durable node-local identity. Kubernetes normally garbage-collects a
// DaemonSet's pods in the background, so the DaemonSet object can be NotFound
// while an old Garage process still has the pool's node_key and data HostPaths
// mounted. A replacement DaemonSet must not start until every such pod object
// is gone.
//
// Use the uncached reader when available. Seeing a controller deletion before
// a pod deletion in the informer cache is exactly the ordering this guard must
// not mistake for a completed shutdown.
func (r *GarageClusterReconciler) ensureNoPreviousNodeLocalPoolPods(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
	daemonSetKey types.NamespacedName,
	expectDaemonSetAbsent bool,
) error {
	reader := client.Reader(r.Client)
	if r.APIReader != nil && expectDaemonSetAbsent {
		reader = r.APIReader

		// Confirm the cached NotFound against live state before attempting a
		// same-name create. This is normally only a short cache-ordering window.
		liveDaemonSet := &appsv1.DaemonSet{}
		if err := reader.Get(ctx, daemonSetKey, liveDaemonSet); err == nil {
			return fmt.Errorf(
				"node-local pool DaemonSet %s still exists in live API state; waiting for the controller cache before recreating it",
				daemonSetKey.Name,
			)
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf(
				"confirming node-local pool DaemonSet %s deletion: %w",
				daemonSetKey.Name,
				err,
			)
		}
	}

	pods := &corev1.PodList{}
	if err := reader.List(
		ctx,
		pods,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{
			labelCluster:       cluster.Name,
			labelTier:          tierStorage,
			labelNodeLocalPool: nodeLocalPoolName,
		}),
	); err != nil {
		return fmt.Errorf(
			"checking for previous pods before recreating node-local pool DaemonSet %s: %w",
			daemonSetKey.Name,
			err,
		)
	}
	names := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if isStorageDaemonSetPodForPool(cluster, nodeLocalPoolName, pod) {
			names = append(names, pod.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf(
		"refusing to recreate node-local pool DaemonSet %s while previous pool pod(s) still exist: %s; wait for every old pod to terminate so two Garage processes cannot mount the same node-local identity",
		daemonSetKey.Name,
		strings.Join(names, ", "),
	)
}

// cleanupObsoleteNodeLocalPoolConfigMaps removes an old content-addressed
// garage.toml only after the DaemonSet controller has observed the desired
// template, every desired pod is available on that revision, and no remaining
// pod object references the old resource. The status gate also prevents a stale
// controller-runtime cache from deleting the config resource of an in-flight pod
// created from the previous DaemonSet generation.
func (r *GarageClusterReconciler) cleanupObsoleteNodeLocalPoolConfigMaps(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName,
	desiredName string,
) error {
	daemonSet := &appsv1.DaemonSet{}
	daemonSetKey := types.NamespacedName{
		Name:      storageDaemonSetName(cluster, nodeLocalPoolName),
		Namespace: cluster.Namespace,
	}
	if err := r.nodeLocalPoolReader().Get(ctx, daemonSetKey, daemonSet); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting pool DaemonSet %s for ConfigMap cleanup: %w", daemonSetKey.Name, err)
	}
	if !metav1.IsControlledBy(daemonSet, cluster) {
		return nil
	}
	templateConfigName, templateSecretBacked, err := mountedGarageConfigResource(daemonSet.Spec.Template.Spec)
	if err != nil {
		return fmt.Errorf("reading pool DaemonSet %s config resource for cleanup: %w", daemonSet.Name, err)
	}
	if templateConfigName != desiredName || templateSecretBacked != garageConfigUsesSecret(cluster) ||
		daemonSet.Status.ObservedGeneration < daemonSet.Generation ||
		daemonSet.Status.UpdatedNumberScheduled != daemonSet.Status.DesiredNumberScheduled ||
		daemonSet.Status.NumberAvailable != daemonSet.Status.DesiredNumberScheduled {
		return nil
	}

	referenced, err := garageConfigResourcesReferencedByPods(ctx, r.nodeLocalPoolReader(), cluster.Namespace)
	if err != nil {
		return fmt.Errorf("listing pool %q pods for config-resource cleanup: %w", nodeLocalPoolName, err)
	}
	referenced[garageConfigResourceReference{name: desiredName, secretBacked: templateSecretBacked}] = struct{}{}

	configMaps := &corev1.ConfigMapList{}
	if err := r.nodeLocalPoolReader().List(ctx, configMaps, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing pool %q ConfigMap revisions for cleanup: %w", nodeLocalPoolName, err)
	}
	log := logf.FromContext(ctx)
	for i := range configMaps.Items {
		configMap := &configMaps.Items[i]
		if !isStorageDaemonSetConfigMapName(cluster, nodeLocalPoolName, configMap.Name) ||
			!metav1.IsControlledBy(configMap, cluster) {
			continue
		}
		if _, keep := referenced[garageConfigResourceReference{name: configMap.Name}]; keep {
			continue
		}
		log.Info(
			"Deleting obsolete node-local pool ConfigMap revision",
			"name",
			configMap.Name,
			"pool",
			nodeLocalPoolName,
		)
		if err := r.Delete(ctx, configMap); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf(
				"deleting obsolete node-local pool ConfigMap %s: %w",
				configMap.Name,
				err,
			)
		}
	}
	secrets := &corev1.SecretList{}
	if err := r.nodeLocalPoolReader().List(ctx, secrets, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing pool %q Secret revisions for cleanup: %w", nodeLocalPoolName, err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if !isStorageDaemonSetConfigMapName(cluster, nodeLocalPoolName, secret.Name) ||
			!metav1.IsControlledBy(secret, cluster) {
			continue
		}
		if _, keep := referenced[garageConfigResourceReference{name: secret.Name, secretBacked: true}]; keep {
			continue
		}
		log.Info("Deleting obsolete node-local pool Secret config revision", "name", secret.Name, "pool", nodeLocalPoolName)
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting obsolete node-local pool Secret %s: %w", secret.Name, err)
		}
	}
	return nil
}

// cleanupObsoleteNodeLocalPoolConfigMapsForDeployedDaemonSet releases revisions
// from a completed previous rollout before validating the next disk-layout
// phase. Without this preflight, an early readOnly-path removal could remain
// blocked forever by the old writable revision because ConfigMap reconciliation
// runs before DaemonSet reconciliation.
func (r *GarageClusterReconciler) cleanupObsoleteNodeLocalPoolConfigMapsForDeployedDaemonSet(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	nodeLocalPoolName string,
) error {
	daemonSet := &appsv1.DaemonSet{}
	key := types.NamespacedName{
		Name:      storageDaemonSetName(cluster, nodeLocalPoolName),
		Namespace: cluster.Namespace,
	}
	if err := r.nodeLocalPoolReader().Get(ctx, key, daemonSet); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting deployed pool DaemonSet %s: %w", key.Name, err)
	}
	if !metav1.IsControlledBy(daemonSet, cluster) {
		return fmt.Errorf(
			"existing DaemonSet %s is not controlled by GarageCluster %s/%s; refusing to inspect a colliding workload",
			daemonSet.Name,
			cluster.Namespace,
			cluster.Name,
		)
	}
	configName, _, err := mountedGarageConfigResource(daemonSet.Spec.Template.Spec)
	if err != nil {
		return fmt.Errorf("deployed pool DaemonSet %s has no valid %q config volume: %w", daemonSet.Name, configVolumeName, err)
	}
	return r.cleanupObsoleteNodeLocalPoolConfigMaps(ctx, cluster, nodeLocalPoolName, configName)
}

// buildStorageDaemonSetVolumesAndMounts builds pool-specific HostPath mounts.
func buildStorageDaemonSetVolumesAndMounts(
	cluster *garagev1beta2.GarageCluster,
	pool *garagev1beta2.NodeLocalPoolSpec,
	configHash string,
) ([]corev1.Volume, []corev1.VolumeMount) {
	mounts := []corev1.VolumeMount{
		{Name: configVolumeName, MountPath: configMountPath, ReadOnly: true},
		{Name: metadataVolName, MountPath: metadataPath},
	}
	metadataType := effectivePoolHostPathType(pool.Metadata.HostPathType)
	volumes := []corev1.Volume{
		{
			Name: configVolumeName,
			VolumeSource: garageConfigVolumeSource(
				cluster,
				storageDaemonSetConfigResourceName(cluster, pool, configHash),
			),
		},
		{
			Name: metadataVolName,
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
				Path: pool.Metadata.HostPath,
				Type: &metadataType,
			}},
		},
	}
	if metadataType == corev1.HostPathDirectory {
		volumes, mounts = appendStorageVolumeMarker(
			volumes, mounts, metadataVolName, pool.Metadata.HostPath,
		)
	}

	if pool.Data != nil {
		dataType := effectivePoolHostPathType(pool.Data.HostPathType)
		volumes = append(volumes, corev1.Volume{
			Name: dataVolName,
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
				Path: pool.Data.HostPath,
				Type: &dataType,
			}},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: dataVolName, MountPath: dataPath})
		if dataType == corev1.HostPathDirectory {
			volumes, mounts = appendStorageVolumeMarker(
				volumes, mounts, dataVolName, pool.Data.HostPath,
			)
		}
	} else {
		dataPaths := sortedNodeLocalPoolDataPaths(pool)
		for i := range dataPaths {
			entry := &dataPaths[i]
			volumeName := nodeMultiHDDDataVolName(i)
			hostPathType := effectivePoolHostPathType(entry.HostPathType)
			volumes = append(volumes, corev1.Volume{
				Name: volumeName,
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
					Path: entry.HostPath,
					Type: &hostPathType,
				}},
			})
			// Garage still writes its marker file on read_only data_dir entries.
			mounts = append(mounts, corev1.VolumeMount{Name: volumeName, MountPath: entry.Path})
			if hostPathType == corev1.HostPathDirectory {
				volumes, mounts = appendStorageVolumeMarker(
					volumes, mounts, volumeName, entry.HostPath,
				)
			}
		}
	}

	credentialVolumes, credentialMounts := buildGarageCredentialVolumesAndMounts(cluster, false)
	volumes = append(volumes, credentialVolumes...)
	mounts = append(mounts, credentialMounts...)
	return volumes, mounts
}

// appendStorageVolumeMarker adds a second HostPath for the fixed marker file
// inside a production Directory mount. A HostPath Directory check alone only
// proves that the mountpoint directory exists on the node's root filesystem;
// it still succeeds after the intended disk is unmounted. Requiring the marker
// itself as HostPath type File makes kubelet fail volume setup before Garage
// starts in that fallback directory. The operator never creates this file.
func appendStorageVolumeMarker(
	volumes []corev1.Volume,
	mounts []corev1.VolumeMount,
	volumeName,
	hostPath string,
) ([]corev1.Volume, []corev1.VolumeMount) {
	markerName := storageVolumeMarkerNamePrefix + volumeName
	markerType := corev1.HostPathFile
	volumes = append(volumes, corev1.Volume{
		Name: markerName,
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
			Path: path.Join(hostPath, storageVolumeMarkerFile),
			Type: &markerType,
		}},
	})
	mounts = append(mounts, corev1.VolumeMount{
		Name:      markerName,
		MountPath: path.Join(storageVolumeMarkerMountRoot, volumeName),
		ReadOnly:  true,
	})
	return volumes, mounts
}

func effectivePoolHostPathType(value corev1.HostPathType) corev1.HostPathType {
	if value != "" {
		return value
	}
	return corev1.HostPathDirectory
}
