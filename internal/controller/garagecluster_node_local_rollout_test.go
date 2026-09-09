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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	testPreviousPodUID                = "previous-pod-uid"
	testGateMutationClaimIdentity     = "claim-identity"
	testGateMutationDaemonSetIdentity = "mutate-daemonset-uid"
)

func TestNodeLocalPoolPrivateKeysAreValidQualifiedNames(t *testing.T) {
	t.Parallel()
	cluster := nodeLocalPoolActivationTestCluster("qualified-keys", "a")
	poolName := cluster.Spec.Storage.NodeLocalPools[0].Name
	for _, key := range []string{
		nodeLocalPoolActivationLabel(cluster, poolName),
		nodeLocalPoolRecoveryNodeIDAnnotation(cluster, poolName),
		nodeLocalPoolHostPathClaimAnnotation(cluster, poolName),
		nodeLocalPoolSchedulingGateName,
	} {
		if errs := validation.IsQualifiedName(key); len(errs) != 0 {
			t.Fatalf("private node-local pool key %q is invalid: %v", key, errs)
		}
	}
}

func TestStatefulSetWorkloadRecreationSafetyTracksOnlyGeneratedClaims(t *testing.T) {
	t.Parallel()
	deletePolicy := &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
		WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
	}
	tests := []struct {
		name string
		sts  *appsv1.StatefulSet
		want bool
	}{
		{name: "missing workload", want: true},
		{
			name: "manual SMB or existingClaim workload has no generated claims",
			sts: &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{
				PersistentVolumeClaimRetentionPolicy: deletePolicy,
			}},
			want: true,
		},
		{
			name: "generated PVC is at risk under Delete",
			sts: &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
					ObjectMeta: metav1.ObjectMeta{Name: metadataVolName},
				}},
				PersistentVolumeClaimRetentionPolicy: deletePolicy,
			}},
			want: false,
		},
		{
			name: "generated gateway PVC is safe under Retain",
			sts: &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
					ObjectMeta: metav1.ObjectMeta{Name: metadataVolName},
				}},
				PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
					WhenDeleted: appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
				},
			}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := statefulSetWorkloadRecreationSafe(tt.sts); got != tt.want {
				t.Fatalf("statefulSetWorkloadRecreationSafe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetiredNodeLocalPoolTeardownObservesFenceAndPodAbsenceBeforeConfigDeletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: "retired-pool", Namespace: testGarageValue, UID: types.UID("retired-pool-uid"), Generation: 2,
	}}
	nodeLocalPoolName := testPoolA
	activationLabel := nodeLocalPoolActivationLabel(cluster, nodeLocalPoolName)
	oldActivationValue := nodeLocalPoolActivationValueForWorkloadUID("old-daemonset-uid")
	clusterOwner := *metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: cluster.Namespace,
			UID: types.UID("old-daemonset-uid"), Generation: 1,
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName,
			},
			Annotations: map[string]string{
				annotationNodeLocalPoolActivationLabel: activationLabel,
				annotationNodeLocalPoolActivationValue: oldActivationValue,
			},
			OwnerReferences: []metav1.OwnerReference{clusterOwner},
		},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{annotationNodeLocalPoolActivationValue: oldActivationValue}},
			Spec:       corev1.PodSpec{NodeSelector: map[string]string{activationLabel: oldActivationValue}},
		}},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA, Labels: map[string]string{activationLabel: oldActivationValue},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "retired-pool-pod", Namespace: cluster.Namespace, UID: types.UID("retired-pod-uid"),
		Labels: map[string]string{
			labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName,
			labelStorageGroup: storageGroupNodeLocal, labelAppManagedBy: operatorName,
		},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(daemonSet, appsv1.SchemeGroupVersion.WithKind(daemonSetKind))},
	}, Spec: corev1.PodSpec{NodeName: node.Name}}
	configName := storageDaemonSetConfigMapName(cluster, nodeLocalPoolName)
	configLabels := map[string]string{labelCluster: cluster.Name, labelNodeLocalPool: nodeLocalPoolName}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: configName, Namespace: cluster.Namespace, UID: types.UID("retired-configmap-uid"),
		Labels: configLabels, OwnerReferences: []metav1.OwnerReference{clusterOwner},
	}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: configName, Namespace: cluster.Namespace, UID: types.UID("retired-secret-uid"),
		Labels: configLabels, OwnerReferences: []metav1.OwnerReference{clusterOwner},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&appsv1.DaemonSet{}).
		WithObjects(cluster, daemonSet, node, pod, configMap, secret).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient}
	emptyStates := map[string]*nodeLocalPoolState{}
	emptyGarageNodes := map[string]*garagev1beta1.GarageNode{}

	cleanup, err := reconciler.cleanupNodeLocalPoolActivationState(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.workloadTeardownBlocked {
		t.Fatal("first pass did not wait for the rotated DaemonSet generation")
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), &appsv1.DaemonSet{}); err != nil {
		t.Fatalf("DaemonSet deleted before its membership fence was observed: %v", err)
	}
	freshNode := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if _, present := freshNode.Labels[activationLabel]; !present {
		t.Fatal("Node activation was removed before the rotated generation was observed")
	}

	freshDaemonSet := &appsv1.DaemonSet{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), freshDaemonSet); err != nil {
		t.Fatal(err)
	}
	freshDaemonSet.Status.ObservedGeneration = freshDaemonSet.Generation
	if err := kubeClient.Status().Update(ctx, freshDaemonSet); err != nil {
		t.Fatal(err)
	}
	cleanup, err = reconciler.cleanupNodeLocalPoolActivationState(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.workloadTeardownBlocked {
		t.Fatal("label-removal pass did not require a subsequent direct observation")
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if _, present := freshNode.Labels[activationLabel]; present {
		t.Fatal("retired activation label remained after the generation barrier")
	}

	cleanup, err = reconciler.cleanupNodeLocalPoolActivationState(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.workloadTeardownBlocked {
		t.Fatal("settled scheduling fence still blocked workload teardown")
	}
	pending, err := reconciler.cleanupRetiredNodeLocalPoolResources(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("DaemonSet deletion was not reported as an incomplete teardown phase")
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), &appsv1.DaemonSet{}); !apierrors.IsNotFound(err) {
		t.Fatalf("retired DaemonSet still exists: %v", err)
	}
	for _, object := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}} {
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: configName, Namespace: cluster.Namespace}, object); err != nil {
			t.Fatalf("config was deleted in the DaemonSet deletion pass: %v", err)
		}
	}

	pending, err = reconciler.cleanupRetiredNodeLocalPoolResources(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("lingering pool Pod did not hold config cleanup")
	}
	if err := kubeClient.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pending, err = reconciler.cleanupRetiredNodeLocalPoolResources(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("config deletion was not reported as an incomplete observation phase")
	}
	for _, object := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}} {
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: configName, Namespace: cluster.Namespace}, object); !apierrors.IsNotFound(err) {
			t.Fatalf("retired config resource still exists: %T %v", object, err)
		}
	}
	pending, err = reconciler.cleanupRetiredNodeLocalPoolResources(ctx, cluster, emptyStates, emptyGarageNodes)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("fully observed retired-pool teardown remained pending")
	}
}

type nodeLocalPoolNodeUpdateRaceClient struct {
	client.Client
	beforeNodeUpdate func(context.Context) error
}

type nodeLocalPoolGateMutationReader struct {
	client.Reader
	beforeGet func(context.Context, client.ObjectKey, client.Object) error
}

func (r *nodeLocalPoolGateMutationReader) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if r.beforeGet != nil {
		if err := r.beforeGet(ctx, key, obj); err != nil {
			return err
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (c *nodeLocalPoolNodeUpdateRaceClient) Update(
	ctx context.Context,
	obj client.Object,
	opts ...client.UpdateOption,
) error {
	if _, isNode := obj.(*corev1.Node); isNode && c.beforeNodeUpdate != nil {
		hook := c.beforeNodeUpdate
		c.beforeNodeUpdate = nil
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func nodeLocalPoolActivationTestCluster(name, selectorValue string) *garagev1beta2.GarageCluster {
	capacity := resource.MustParse("100Gi")
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: testGarageValue, UID: types.UID(name + "-uid"), Generation: 1,
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Zone: testZone,
			Storage: &garagev1beta2.StorageSpec{NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
				Name:     testPoolA,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{testStorageOwnerLabelKey: selectorValue}},
				Capacity: &capacity,
				Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/shared/metadata"},
				Data:     &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/shared/data"},
			}}},
		},
	}
}

func TestNodeLocalPoolSchedulingGateRejectsLateRetiredWorkloadPod(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name              string
		retiredPodIsGated bool
		wantReleased      bool
	}{
		{name: "retired Pod keeps its immutable scheduling gate", retiredPodIsGated: true, wantReleased: true},
		{name: "ungated retired Pod may still mount the HostPath", retiredPodIsGated: false, wantReleased: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			scheme := deletionTestScheme(t)
			cluster := nodeLocalPoolActivationTestCluster("scheduling-gate-"+strings.ReplaceAll(test.name, " ", "-"), "a")
			pool := &cluster.Spec.Storage.NodeLocalPools[0]
			nodeName := testKubernetesWorkerA
			activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
			daemonSetUID := types.UID("current-daemonset-uid")
			activationValue := nodeLocalPoolActivationValueForWorkloadUID(daemonSetUID)
			desiredPodSpecHash := "current-pod-spec-hash"
			desiredConfigHash := "current-config-hash"
			claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, "")
			if err != nil {
				t.Fatal(err)
			}
			claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
			if err != nil {
				t.Fatal(err)
			}
			clusterOwner := *metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))
			daemonSet := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace,
					UID: daemonSetUID,
					Annotations: map[string]string{
						annotationNodeLocalPoolActivationValue: activationValue,
					},
					OwnerReferences: []metav1.OwnerReference{clusterOwner},
				},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
						annotationPodSpecHash: desiredPodSpecHash,
						annotationConfigHash:  desiredConfigHash,
					}},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{activationLabel: activationValue},
						SchedulingGates: []corev1.PodSchedulingGate{{
							Name: nodeLocalPoolSchedulingGateName,
						}},
					},
				}},
			}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName, UID: types.UID("current-kubernetes-node-uid"),
				Labels: map[string]string{
					testStorageOwnerLabelKey: "a",
					activationLabel:          activationValue,
				},
				Annotations: map[string]string{
					nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name): claimValue,
				},
			}}
			podLabels := map[string]string{
				labelCluster:       cluster.Name,
				labelTier:          tierStorage,
				labelNodeLocalPool: pool.Name,
				labelStorageGroup:  storageGroupNodeLocal,
				labelAppManagedBy:  operatorName,
			}
			targetAffinity := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
						Key: kubernetesNodeNameFieldPath, Operator: corev1.NodeSelectorOpIn, Values: []string{nodeName},
					}}}},
				},
			}}
			newPod := func(name string, uid, ownerUID types.UID, gated bool) *corev1.Pod {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: name, Namespace: cluster.Namespace, UID: uid,
						Labels: maps.Clone(podLabels),
						Annotations: map[string]string{
							annotationNodeLocalPoolActivationValue: activationValue,
							annotationPodSpecHash:                  desiredPodSpecHash,
							annotationConfigHash:                   desiredConfigHash,
						},
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
							Name: daemonSet.Name, UID: ownerUID, Controller: ptr.To(true),
						}},
					},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{activationLabel: activationValue},
						Affinity:     targetAffinity.DeepCopy(),
					},
				}
				if gated {
					pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}}
				}
				return pod
			}
			currentPod := newPod("current-pool-pod", types.UID("current-pod-uid"), daemonSetUID, true)
			retiredPod := newPod(
				"late-retired-pool-pod", types.UID("retired-pod-uid"), types.UID("retired-daemonset-uid"),
				test.retiredPodIsGated,
			)
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				cluster, daemonSet, node, currentPod, retiredPod,
			).Build()
			reconciler := &GarageClusterReconciler{
				Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
			}
			states := map[string]*nodeLocalPoolState{pool.Name: {
				pool: pool, activationLabel: activationLabel, activationValue: activationValue,
				workloadUID: daemonSetUID, desiredPodSpecHash: desiredPodSpecHash, configHash: desiredConfigHash,
				desiredNodes: map[string]*corev1.Node{nodeName: node},
			}}
			released, blocked, err := reconciler.releaseNodeLocalPoolPodSchedulingGates(ctx, cluster, states)
			if err != nil {
				t.Fatal(err)
			}

			freshCurrent := &corev1.Pod{}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(currentPod), freshCurrent); err != nil {
				t.Fatal(err)
			}
			freshRetired := &corev1.Pod{}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(retiredPod), freshRetired); err != nil {
				t.Fatal(err)
			}
			if test.wantReleased {
				if len(released) != 1 || released[0] != pool.Name+"/"+nodeName || len(blocked) != 0 {
					t.Fatalf("gate release = %v, blocked = %v", released, blocked)
				}
				if nodeLocalPoolPodHasSchedulingGate(freshCurrent) {
					t.Fatal("current workload Pod remained scheduler-gated")
				}
				if !nodeLocalPoolPodHasSchedulingGate(freshRetired) {
					t.Fatal("late retired workload Pod lost its permanent scheduling gate")
				}
				return
			}
			if len(released) != 0 || len(blocked) != 1 || !strings.Contains(blocked[0], retiredPod.Name) {
				t.Fatalf("unsafe retired Pod was not a hard gate: released = %v, blocked = %v", released, blocked)
			}
			if !nodeLocalPoolPodHasSchedulingGate(freshCurrent) {
				t.Fatal("current workload Pod was released while a retired Pod could schedule")
			}
		})
	}
}

func TestNodeLocalPoolSchedulingGateRevalidatesPersistedActorAtFinalPatch(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		mutation string
	}{
		{name: "HostPath claim identity changes", mutation: testGateMutationClaimIdentity},
		{name: "HostPath claim loses a desired path", mutation: "claim-paths"},
		{name: "DaemonSet desired revision changes", mutation: "daemonset-revision"},
		{name: "DaemonSet UID changes", mutation: testGateMutationDaemonSetIdentity},
		{name: "replacement Pod desired revision changes", mutation: "pod-revision"},
		{name: "GarageCluster generation and selector change", mutation: "cluster-spec"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			scheme := deletionTestScheme(t)
			cluster := nodeLocalPoolActivationTestCluster("final-gate-"+test.mutation, "a")
			pool := &cluster.Spec.Storage.NodeLocalPools[0]
			nodeName := testKubernetesWorkerA
			garageNodeID := strings.Repeat("a", 64)
			otherGarageNodeID := strings.Repeat("b", 64)
			daemonSetUID := types.UID("persisted-daemonset-uid")
			activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
			activationValue := nodeLocalPoolActivationValueForWorkloadUID(daemonSetUID)
			desiredPodSpecHash := "persisted-pod-spec-hash"
			desiredConfigHash := "persisted-config-hash"
			claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, garageNodeID)
			if err != nil {
				t.Fatal(err)
			}
			claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
			if err != nil {
				t.Fatal(err)
			}
			clusterOwner := *metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))
			daemonSet := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace, UID: daemonSetUID,
					Annotations: map[string]string{
						annotationNodeLocalPoolActivationValue: activationValue,
					},
					OwnerReferences: []metav1.OwnerReference{clusterOwner},
				},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
						annotationPodSpecHash: desiredPodSpecHash,
						annotationConfigHash:  desiredConfigHash,
					}},
					Spec: corev1.PodSpec{
						NodeSelector:    map[string]string{activationLabel: activationValue},
						SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
					},
				}},
			}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName, UID: types.UID("persisted-kubernetes-node-uid"),
				Labels: map[string]string{
					testStorageOwnerLabelKey: "a",
					activationLabel:          activationValue,
				},
				Annotations: map[string]string{
					nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name):  claimValue,
					nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name): garageNodeID,
				},
			}}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "persisted-replacement", Namespace: cluster.Namespace, UID: types.UID("persisted-replacement-uid"),
					Labels: map[string]string{
						labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
						labelStorageGroup: storageGroupNodeLocal, labelAppManagedBy: operatorName,
					},
					Annotations: map[string]string{
						annotationNodeLocalPoolActivationValue: activationValue,
						annotationPodSpecHash:                  desiredPodSpecHash,
						annotationConfigHash:                   desiredConfigHash,
					},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
						Name: daemonSet.Name, UID: daemonSetUID, Controller: ptr.To(true),
					}},
				},
				Spec: corev1.PodSpec{
					NodeSelector:    map[string]string{activationLabel: activationValue},
					SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
					Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
								Key: kubernetesNodeNameFieldPath, Operator: corev1.NodeSelectorOpIn, Values: []string{nodeName},
							}}}},
						},
					}},
				},
			}
			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, node, pod).Build()
			reader := &nodeLocalPoolGateMutationReader{Reader: baseClient}
			var daemonSetGets int
			var clusterGets int
			reader.beforeGet = func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
				switch obj.(type) {
				case *garagev1beta2.GarageCluster:
					clusterGets++
					if test.mutation != "cluster-spec" || clusterGets != 2 {
						return nil
					}
					fresh := &garagev1beta2.GarageCluster{}
					if err := baseClient.Get(ctx, key, fresh); err != nil {
						return err
					}
					fresh.Generation++
					fresh.Spec.Storage.NodeLocalPools[0].Selector.MatchLabels[testStorageOwnerLabelKey] = "b"
					return baseClient.Update(ctx, fresh)
				case *appsv1.DaemonSet:
					daemonSetGets++
					if daemonSetGets != 2 {
						return nil
					}
					fresh := &appsv1.DaemonSet{}
					if err := baseClient.Get(ctx, key, fresh); err != nil {
						return err
					}
					switch test.mutation {
					case "daemonset-revision":
						fresh.Spec.Template.Annotations[annotationConfigHash] = "changed-config-hash"
						return baseClient.Update(ctx, fresh)
					case testGateMutationDaemonSetIdentity:
						if err := baseClient.Delete(ctx, fresh); err != nil {
							return err
						}
						fresh.ResourceVersion = ""
						fresh.UID = types.UID("replacement-daemonset-uid")
						return baseClient.Create(ctx, fresh)
					}
				case *corev1.Node:
					if test.mutation != testGateMutationClaimIdentity && test.mutation != "claim-paths" {
						return nil
					}
					fresh := &corev1.Node{}
					if err := baseClient.Get(ctx, key, fresh); err != nil {
						return err
					}
					currentClaim, err := decodeNodeLocalPoolHostPathClaim(
						fresh.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)],
					)
					if err != nil {
						return err
					}
					if test.mutation == testGateMutationClaimIdentity {
						currentClaim.GarageNodeID = otherGarageNodeID
						fresh.Annotations[nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)] = otherGarageNodeID
					} else {
						currentClaim.HostPaths = append([]string(nil), currentClaim.HostPaths[:1]...)
					}
					encoded, err := encodeNodeLocalPoolHostPathClaim(*currentClaim)
					if err != nil {
						return err
					}
					fresh.Annotations[nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)] = encoded
					return baseClient.Update(ctx, fresh)
				case *corev1.Pod:
					if test.mutation != "pod-revision" || key.Name != pod.Name {
						return nil
					}
					fresh := &corev1.Pod{}
					if err := baseClient.Get(ctx, key, fresh); err != nil {
						return err
					}
					fresh.Annotations[annotationConfigHash] = "changed-pod-config-hash"
					return baseClient.Update(ctx, fresh)
				}
				return nil
			}
			reconciler := &GarageClusterReconciler{
				Client: baseClient, APIReader: reader, Scheme: scheme, ClusterScoped: true,
			}
			states := map[string]*nodeLocalPoolState{pool.Name: {
				pool: pool, activationLabel: activationLabel, activationValue: activationValue,
				workloadUID: daemonSetUID, desiredPodSpecHash: desiredPodSpecHash, configHash: desiredConfigHash,
				expectedNodeIDs: map[string]string{nodeName: garageNodeID},
				desiredNodes:    map[string]*corev1.Node{nodeName: node},
			}}
			released, blocked, err := reconciler.releaseNodeLocalPoolPodSchedulingGates(ctx, cluster, states)
			if err != nil {
				t.Fatal(err)
			}
			if len(released) != 0 || len(blocked) == 0 {
				t.Fatalf("changed persisted actor was authorized: released=%v blocked=%v", released, blocked)
			}
			freshPod := &corev1.Pod{}
			if err := baseClient.Get(ctx, client.ObjectKeyFromObject(pod), freshPod); err != nil {
				t.Fatal(err)
			}
			if !nodeLocalPoolPodHasSchedulingGate(freshPod) {
				t.Fatal("changed persisted actor lost its scheduling gate")
			}
		})
	}
}

func TestStorageRolloutRecoveryReleasesValidatedDaemonSetReplacementGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("rollout-gate-recovery", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	workerName := testKubernetesWorkerA
	workerUID := types.UID("rollout-worker-uid")
	garageNodeID := strings.Repeat("a", 64)
	daemonSetUID := types.UID("rollout-daemonset-uid")
	garageNodeUID := types.UID("rollout-garage-node-uid")
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	activationValue := nodeLocalPoolActivationValueForWorkloadUID(daemonSetUID)
	configBody := "rollout gate recovery config"
	desiredConfigHash := garageConfigHash(configBody)
	diskLayout, err := marshalStorageDiskLayout(storageDiskLayoutForPool(pool))
	if err != nil {
		t.Fatal(err)
	}
	volumes, volumeMounts := buildStorageDaemonSetVolumesAndMounts(cluster, pool, desiredConfigHash)

	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, garageNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	worker := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: workerName,
		UID:  workerUID,
		Labels: map[string]string{
			testStorageOwnerLabelKey: "a",
			activationLabel:          activationValue,
		},
		Annotations: map[string]string{
			nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name):  claimValue,
			nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name): garageNodeID,
		},
	}}
	clusterOwner := *metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      storageDaemonSetName(cluster, pool.Name),
			Namespace: cluster.Namespace,
			UID:       daemonSetUID,
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
			},
			Annotations: map[string]string{
				annotationNodeLocalPoolActivationLabel: activationLabel,
				annotationNodeLocalPoolActivationValue: activationValue,
				annotationStorageDiskLayout:            diskLayout,
			},
			OwnerReferences: []metav1.OwnerReference{clusterOwner},
		},
		Spec: appsv1.DaemonSetSpec{
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					annotationPodSpecHash: testNewSpecHash,
					annotationConfigHash:  desiredConfigHash,
				}},
				Spec: corev1.PodSpec{
					NodeSelector:    map[string]string{activationLabel: activationValue},
					SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
					Volumes:         volumes,
					Containers: []corev1.Container{{
						Name: defaultAppName, VolumeMounts: volumeMounts,
					}},
				},
			},
		},
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetConfigResourceName(cluster, pool, desiredConfigHash), Namespace: cluster.Namespace,
			Labels: map[string]string{labelCluster: cluster.Name, labelNodeLocalPool: pool.Name},
			Annotations: garageConfigRevisionAnnotations(
				storageDaemonSetConfigMapName(cluster, pool.Name),
				map[string]string{annotationStorageDiskLayout: diskLayout},
			),
			OwnerReferences: []metav1.OwnerReference{clusterOwner},
		},
		Immutable: ptr.To(true),
		Data:      map[string]string{configFileName: configBody},
	}
	garageNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            nodeLocalPoolGarageNodeName(cluster.Name, pool.Name, workerName),
			Namespace:       cluster.Namespace,
			UID:             garageNodeUID,
			Generation:      1,
			OwnerReferences: []metav1.OwnerReference{clusterOwner},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			NodeLocalPoolName:  pool.Name,
			KubernetesNodeName: workerName,
			ClusterRef:         garagev1beta1.ClusterReference{Name: cluster.Name},
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: garageNodeID, Connected: true, InLayout: true, ObservedGeneration: 1,
			ObservedPodUID: "rollout-previous-pod-uid",
		},
	}
	replacement := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rollout-replacement",
			Namespace: cluster.Namespace,
			UID:       "rollout-replacement-uid",
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
				labelStorageGroup: storageGroupNodeLocal, labelAppManagedBy: operatorName,
			},
			Annotations: map[string]string{
				annotationNodeLocalPoolActivationValue: activationValue,
				annotationPodSpecHash:                  testNewSpecHash,
				annotationConfigHash:                   desiredConfigHash,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
				Name: daemonSet.Name, UID: daemonSet.UID, Controller: ptr.To(true),
			}},
		},
		Spec: corev1.PodSpec{
			NodeSelector:    map[string]string{activationLabel: activationValue},
			SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
						Key: kubernetesNodeNameFieldPath, Operator: corev1.NodeSelectorOpIn, Values: []string{workerName},
					}}}},
				},
			}},
		},
	}
	previousPod := replacement.DeepCopy()
	previousPod.Name = "rollout-previous"
	previousPod.UID = types.UID("rollout-previous-pod-uid")
	previousPod.Spec.NodeName = workerName
	previousPod.Spec.SchedulingGates = nil
	previousPod.Annotations[annotationPodSpecHash] = "previous-spec-hash"
	previousPod.Annotations[annotationConfigHash] = "previous-config-hash"
	previousPod.Status = corev1.PodStatus{
		Phase: corev1.PodRunning,
		Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
		}},
	}
	cluster.Status.StorageRollout = &garagev1beta2.StorageRolloutStatus{
		NodeLocalPoolName: pool.Name, KubernetesNodeName: workerName,
		GarageNodeUID: string(garageNodeUID), GarageNodeID: garageNodeID,
		WorkloadUID: string(daemonSetUID), KubernetesNodeUID: string(workerUID),
		PreviousPodUID:     "rollout-previous-pod-uid",
		DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: desiredConfigHash,
		ClusterGeneration: cluster.Generation, GarageNodeGeneration: garageNode.Generation,
	}
	cluster.Status.Conditions = []metav1.Condition{{
		Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
		Reason: garagev1beta1.ReasonStorageRollingOut, ObservedGeneration: cluster.Generation,
	}}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}, &corev1.Pod{}).
		WithObjects(cluster, daemonSet, garageNode, worker, previousPod, configMap).Build()
	if err := kubeClient.Delete(ctx, previousPod); err != nil {
		t.Fatalf("deleting exact previous rollout Pod before manager restart: %v", err)
	}
	if err := kubeClient.Create(ctx, replacement); err != nil {
		t.Fatalf("creating gated DaemonSet replacement before manager restart: %v", err)
	}
	ambiguousPod := previousPod.DeepCopy()
	ambiguousPod.Name = "rollout-ambiguous-old"
	ambiguousPod.UID = types.UID("rollout-ambiguous-old-uid")
	ambiguousPod.ResourceVersion = ""
	if err := kubeClient.Create(ctx, ambiguousPod); err != nil {
		t.Fatalf("creating ambiguous old Pod for negative recovery case: %v", err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	restartedCoordinator := NewLayoutMutationCoordinator()
	if err := rehydrateNodeLocalPoolRolloutsForOwner(
		ctx, kubeClient, restartedCoordinator, cluster, true,
	); err != nil {
		t.Fatalf("rehydrating persisted rollout after manager restart: %v", err)
	}
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations: restartedCoordinator,
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			return healthyNodeLocalPoolRolloutState(garageNodeID), nil
		},
	}
	existing := map[string]*garagev1beta1.GarageNode{garageNode.Name: garageNode}
	blocked, err := reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
	if err != nil || !blocked {
		t.Fatalf("ambiguous old Pod should keep replacement gated: blocked=%v err=%v", blocked, err)
	}
	freshPod := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(replacement), freshPod); err != nil {
		t.Fatal(err)
	}
	if !nodeLocalPoolPodHasSchedulingGate(freshPod) {
		t.Fatal("replacement gate was released while an ambiguous old Pod could mount the same HostPaths")
	}
	if err := kubeClient.Delete(ctx, ambiguousPod); err != nil {
		t.Fatalf("removing ambiguous old Pod before positive recovery: %v", err)
	}
	blocked, err = reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
	if err != nil || !blocked {
		t.Fatalf("rollout gate recovery should release then wait: blocked=%v err=%v", blocked, err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(replacement), freshPod); err != nil {
		t.Fatal(err)
	}
	if nodeLocalPoolPodHasSchedulingGate(freshPod) {
		t.Fatal("persisted DaemonSet replacement remained scheduler-gated during rollout recovery")
	}
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
	if condition == nil || !strings.Contains(condition.Message, "released validated node-local-pool replacement") {
		t.Fatalf("rollout recovery did not report its gate handoff: %#v", condition)
	}

	// Model the scheduler and GarageNode controller observing the exact released
	// replacement. A second recovery reconcile must accept that UID and complete
	// the durable handoff without requiring ordinary pool reconciliation.
	freshPod.Spec.NodeName = workerName
	if err := kubeClient.Update(ctx, freshPod); err != nil {
		t.Fatalf("scheduling exact replacement Pod: %v", err)
	}
	freshPod.Status = corev1.PodStatus{
		Phase: corev1.PodRunning,
		Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
		}},
	}
	if err := kubeClient.Status().Update(ctx, freshPod); err != nil {
		t.Fatalf("publishing exact replacement Pod readiness: %v", err)
	}
	freshGarageNode := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(garageNode), freshGarageNode); err != nil {
		t.Fatal(err)
	}
	freshGarageNode.Status.ObservedPodUID = string(freshPod.UID)
	if err := kubeClient.Status().Update(ctx, freshGarageNode); err != nil {
		t.Fatalf("publishing exact replacement Pod UID: %v", err)
	}
	observedPod := &corev1.Pod{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(replacement), observedPod); err != nil {
		t.Fatal(err)
	}
	if !podReady(observedPod) || observedPod.Spec.NodeName != workerName {
		t.Fatalf("replacement Pod observation was not Ready on the exact Node: %+v", observedPod.Status)
	}
	observedGarageNode := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(garageNode), observedGarageNode); err != nil {
		t.Fatal(err)
	}
	if observedGarageNode.Status.ObservedPodUID != string(observedPod.UID) {
		t.Fatalf("GarageNode observed Pod UID %q, want %q", observedGarageNode.Status.ObservedPodUID, observedPod.UID)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	existing = map[string]*garagev1beta1.GarageNode{observedGarageNode.Name: observedGarageNode}
	blocked, err = reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
	if err != nil || blocked {
		t.Fatalf("ready exact replacement did not complete rollout recovery: blocked=%v err=%v conditions=%+v", blocked, err, cluster.Status.Conditions)
	}
	if cluster.Status.StorageRollout != nil {
		t.Fatalf("completed rollout retained persisted actor: %+v", cluster.Status.StorageRollout)
	}
	if restartedCoordinator.NodeLocalPoolRolloutActive(layoutOwnerKey(cluster)) {
		t.Fatal("completed rollout retained the rehydrated layout-coordinator marker")
	}
}

func TestNodeLocalPoolActivationCASClosesCrossClusterSelectorRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	clusterA := nodeLocalPoolActivationTestCluster("cluster-a", "a")
	clusterB := nodeLocalPoolActivationTestCluster("cluster-b", "b")
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA, Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clusterA, clusterB, node).Build()
	raceClient := &nodeLocalPoolNodeUpdateRaceClient{Client: baseClient}
	raceClient.beforeNodeUpdate = func(ctx context.Context) error {
		fresh := &corev1.Node{}
		if err := baseClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
			return err
		}
		fresh.Labels[testStorageOwnerLabelKey] = "b"
		return baseClient.Update(ctx, fresh)
	}
	reconciler := &GarageClusterReconciler{
		Client: raceClient, APIReader: baseClient, Scheme: scheme, ClusterScoped: true,
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	poolA := &clusterA.Spec.Storage.NodeLocalPools[0]
	err := reconciler.ensureNodeLocalPoolActivation(
		ctx,
		clusterA,
		poolA,
		node,
		nodeLocalPoolActivationLabel(clusterA, poolA.Name),
		nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(clusterA, poolA.Name),
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "activation CAS") {
		t.Fatalf("stale selector activation did not fail its Node CAS: %v", err)
	}

	freshNode := &corev1.Node{}
	if err := baseClient.Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if _, active := freshNode.Labels[nodeLocalPoolActivationLabel(clusterA, poolA.Name)]; active {
		t.Fatal("stale cluster activated after the Node selector changed")
	}
	if _, claimed := freshNode.Annotations[nodeLocalPoolHostPathClaimAnnotation(clusterA, poolA.Name)]; claimed {
		t.Fatal("stale cluster persisted a HostPath claim after losing the Node CAS")
	}

	poolB := &clusterB.Spec.Storage.NodeLocalPools[0]
	if err := reconciler.ensureNodeLocalPoolActivation(
		ctx,
		clusterB,
		poolB,
		freshNode,
		nodeLocalPoolActivationLabel(clusterB, poolB.Name),
		nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(clusterB, poolB.Name),
		"",
	); err != nil {
		t.Fatalf("current selector owner could not activate: %v", err)
	}
	if err := baseClient.Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if freshNode.Labels[nodeLocalPoolActivationLabel(clusterB, poolB.Name)] != nodeLocalPoolActivationLabelValue {
		t.Fatal("current selector owner was not activated")
	}
	if freshNode.Annotations[nodeLocalPoolHostPathClaimAnnotation(clusterB, poolB.Name)] == "" {
		t.Fatal("activation and durable HostPath claim were not written atomically")
	}
}

func TestNodeLocalPoolActivationRetainedClaimSurvivesLostPrivateLabel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	clusterA := nodeLocalPoolActivationTestCluster("claim-a", "a")
	clusterB := nodeLocalPoolActivationTestCluster("claim-b", "b")
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-claim", Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clusterA, clusterB, node).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	poolA := &clusterA.Spec.Storage.NodeLocalPools[0]
	if err := reconciler.ensureNodeLocalPoolActivation(
		ctx, clusterA, poolA, node,
		nodeLocalPoolActivationLabel(clusterA, poolA.Name), nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(clusterA, poolA.Name), "",
	); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	delete(node.Labels, nodeLocalPoolActivationLabel(clusterA, poolA.Name))
	node.Labels[testStorageOwnerLabelKey] = "b"
	if err := kubeClient.Update(ctx, node); err != nil {
		t.Fatal(err)
	}
	poolB := &clusterB.Spec.Storage.NodeLocalPools[0]
	err := reconciler.ensureNodeLocalPoolActivation(
		ctx, clusterB, poolB, node,
		nodeLocalPoolActivationLabel(clusterB, poolB.Name), nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(clusterB, poolB.Name), "",
	)
	if err == nil || !strings.Contains(err.Error(), "durable claim") {
		t.Fatalf("overlapping activation ignored retained HostPath claim: %v", err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	if _, active := node.Labels[nodeLocalPoolActivationLabel(clusterB, poolB.Name)]; active {
		t.Fatal("second cluster activated an overlapping retained HostPath")
	}
}

func TestNodeLocalPoolActivationRejectsRetiringClaimForReselectedNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster := nodeLocalPoolActivationTestCluster("retiring-reselect", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claim.Retiring = true
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	recoveryKey := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   testKubernetesWorkerA,
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
		Annotations: map[string]string{
			claimKey:    claimValue,
			recoveryKey: testTerminalNodeID,
		},
	}}
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            NewLayoutMutationCoordinator(),
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}

	err = reconciler.ensureNodeLocalPoolActivation(
		ctx, cluster, pool, node,
		activationLabel, nodeLocalPoolActivationLabelValue,
		recoveryKey, testTerminalNodeID,
	)
	if err == nil || !strings.Contains(err.Error(), "persisted retirement") {
		t.Fatalf("reselected Node bypassed its persisted retirement: %v", err)
	}

	fresh := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
		t.Fatal(err)
	}
	if _, active := fresh.Labels[activationLabel]; active {
		t.Fatal("reselected Node was activated while its HostPath claim remained retiring")
	}
	if fresh.Annotations[claimKey] != claimValue || fresh.Annotations[recoveryKey] != testTerminalNodeID {
		t.Fatalf("blocked activation changed durable retirement evidence: %#v", fresh.Annotations)
	}
}

func TestNodeLocalPoolRetirementCASRejectsPrePersistenceReselection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("retirement-cas-reselect", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   testKubernetesWorkerA,
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
		Annotations: map[string]string{
			claimKey: claimValue,
		},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient}

	err = reconciler.markNodeLocalPoolClaimRetiring(ctx, cluster, pool.Name, node.Name)
	if err == nil || !strings.Contains(err.Error(), "again matches") {
		t.Fatalf("retirement ignored selector restoration before the durable CAS: %v", err)
	}
	fresh := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
		t.Fatal(err)
	}
	gotClaim, err := decodeNodeLocalPoolHostPathClaim(fresh.Annotations[claimKey])
	if err != nil {
		t.Fatal(err)
	}
	if gotClaim.Retiring {
		t.Fatal("selector restoration before the durable boundary still committed one-way retirement")
	}
}

func TestNodeLocalPoolRetirementCASRejectsParentGenerationChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("retirement-cas-generation", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:        testKubernetesWorkerA,
		Labels:      map[string]string{testStorageOwnerLabelKey: "not-selected"},
		Annotations: map[string]string{claimKey: claimValue},
	}}
	liveCluster := cluster.DeepCopy()
	liveCluster.Generation++
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(liveCluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient}

	err = reconciler.markNodeLocalPoolClaimRetiring(ctx, cluster, pool.Name, node.Name)
	if err == nil || !strings.Contains(err.Error(), "changed before") {
		t.Fatalf("retirement ignored a parent spec generation change before the durable CAS: %v", err)
	}
	fresh := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
		t.Fatal(err)
	}
	gotClaim, err := decodeNodeLocalPoolHostPathClaim(fresh.Annotations[claimKey])
	if err != nil {
		t.Fatal(err)
	}
	if gotClaim.Retiring {
		t.Fatal("parent generation race still committed one-way retirement")
	}
}

func TestNodeLocalPoolActivationExpandsSameOwnerHostPathClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("claim-expand", "a")
	oldPool := cluster.Spec.Storage.NodeLocalPools[0].DeepCopy()
	pathCapacity := resource.MustParse("50Gi")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	pool.Data = nil
	pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
		{Path: "/data/data", HostPath: oldPool.Data.HostPath, Capacity: &pathCapacity},
		{Path: "/data/disk-2", HostPath: testSecondDiskHostPath, Capacity: &pathCapacity},
	}
	oldClaim, err := newNodeLocalPoolHostPathClaim(cluster, oldPool, "")
	if err != nil {
		t.Fatal(err)
	}
	oldClaimValue, err := encodeNodeLocalPoolHostPathClaim(oldClaim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-expand",
		Labels: map[string]string{
			testStorageOwnerLabelKey: "a",
		},
		Annotations: map[string]string{claimKey: oldClaimValue},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	if err := reconciler.ensureNodeLocalPoolActivation(
		ctx, cluster, pool, node,
		nodeLocalPoolActivationLabel(cluster, pool.Name), nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name), "",
	); err != nil {
		t.Fatalf("append-only HostPath expansion was blocked: %v", err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	expanded, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[claimKey])
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := nodeLocalPoolHostPaths(pool)
	if !equality.Semantic.DeepEqual(expanded.HostPaths, wantPaths) {
		t.Fatalf("claim paths were not atomically expanded: got %v want %v", expanded.HostPaths, wantPaths)
	}
}

func TestNodeLocalPoolDiskExpansionClaimsBeforeWorkloadPublication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("claim-before-workload", "a")
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-claim-order", Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	baseReconciler := &GarageClusterReconciler{
		Client: baseClient, APIReader: baseClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            NewLayoutMutationCoordinator(),
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	oldPool := cluster.Spec.Storage.NodeLocalPools[0].DeepCopy()
	activationLabel := nodeLocalPoolActivationLabel(cluster, oldPool.Name)
	if err := baseReconciler.reconcileNodeLocalPoolDaemonSet(
		ctx, cluster, oldPool, activationLabel, "old-config-hash",
	); err != nil {
		t.Fatal(err)
	}
	daemonSet := &appsv1.DaemonSet{}
	if err := baseClient.Get(ctx, types.NamespacedName{
		Name: storageDaemonSetName(cluster, oldPool.Name), Namespace: cluster.Namespace,
	}, daemonSet); err != nil {
		t.Fatal(err)
	}
	oldLayout, err := storageDiskLayoutFromDaemonSet(daemonSet)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := newNodeLocalPoolHostPathClaim(cluster, oldPool, "")
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseClient.Get(ctx, client.ObjectKeyFromObject(node), node); err != nil {
		t.Fatal(err)
	}
	node.Labels[activationLabel] = nodeLocalPoolActivationValueForDaemonSet(daemonSet)
	node.Annotations = map[string]string{
		nodeLocalPoolHostPathClaimAnnotation(cluster, oldPool.Name): claimValue,
	}
	if err := baseClient.Update(ctx, node); err != nil {
		t.Fatal(err)
	}

	if err := baseClient.Get(ctx, client.ObjectKeyFromObject(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	cluster.Generation++
	pathCapacity := resource.MustParse("50Gi")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	pool.Data = nil
	pool.DataPaths = []garagev1beta2.NodeLocalPoolDataPath{
		{Path: "/data/data", HostPath: oldPool.Data.HostPath, Capacity: &pathCapacity},
		{Path: "/data/disk-2", HostPath: testSecondDiskHostPath, Capacity: &pathCapacity},
	}
	if err := baseClient.Update(ctx, cluster); err != nil {
		t.Fatal(err)
	}

	foreign := nodeLocalPoolActivationTestCluster("foreign-claim-winner", "b")
	foreign.Spec.Storage.NodeLocalPools[0].Metadata.HostPath = "/var/lib/garage/foreign/meta"
	foreign.Spec.Storage.NodeLocalPools[0].Data.HostPath = testSecondDiskHostPath
	foreignClaim, err := newNodeLocalPoolHostPathClaim(foreign, &foreign.Spec.Storage.NodeLocalPools[0], "")
	if err != nil {
		t.Fatal(err)
	}
	foreignValue, err := encodeNodeLocalPoolHostPathClaim(foreignClaim)
	if err != nil {
		t.Fatal(err)
	}
	raceClient := &nodeLocalPoolNodeUpdateRaceClient{Client: baseClient}
	raceClient.beforeNodeUpdate = func(ctx context.Context) error {
		fresh := &corev1.Node{}
		if err := baseClient.Get(ctx, client.ObjectKeyFromObject(node), fresh); err != nil {
			return err
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string)
		}
		fresh.Annotations[nodeLocalPoolHostPathClaimAnnotation(foreign, foreign.Spec.Storage.NodeLocalPools[0].Name)] = foreignValue
		return baseClient.Update(ctx, fresh)
	}
	reconciler := &GarageClusterReconciler{
		Client: raceClient, APIReader: baseClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            NewLayoutMutationCoordinator(),
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	err = reconciler.reconcileNodeLocalPools(ctx, cluster, map[string]string{oldPool.Name: "new-config-hash"})
	if err == nil || !strings.Contains(err.Error(), "before workload update") {
		t.Fatalf("lost claim CAS did not stop workload publication: %v", err)
	}
	if err := baseClient.Get(ctx, client.ObjectKeyFromObject(daemonSet), daemonSet); err != nil {
		t.Fatal(err)
	}
	currentLayout, err := storageDiskLayoutFromDaemonSet(daemonSet)
	if err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(currentLayout, oldLayout) {
		t.Fatalf("DaemonSet mounted expanded paths before winning their claim: got %+v want %+v", currentLayout, oldLayout)
	}
}

func TestNodeLocalPoolActivationRechecksDeletionAndDrainState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	for _, test := range []struct {
		name   string
		mutate func(*garagev1beta2.GarageCluster)
	}{
		{name: "deleting", mutate: func(cluster *garagev1beta2.GarageCluster) {
			now := metav1.Now()
			cluster.DeletionTimestamp = &now
			cluster.Finalizers = []string{garageClusterFinalizer}
		}},
		{name: "drain requested", mutate: func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationDrain: annotationTrue}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := nodeLocalPoolActivationTestCluster("final-gate-"+strings.ReplaceAll(test.name, " ", "-"), "a")
			stale := cluster.DeepCopy()
			test.mutate(cluster)
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: "worker-final-gate", Labels: map[string]string{testStorageOwnerLabelKey: "a"},
			}}
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
			reconciler := &GarageClusterReconciler{
				Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
				NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
			}
			pool := &stale.Spec.Storage.NodeLocalPools[0]
			err := reconciler.ensureNodeLocalPoolActivation(
				ctx, stale, pool, node,
				nodeLocalPoolActivationLabel(stale, pool.Name), nodeLocalPoolActivationLabelValue,
				nodeLocalPoolRecoveryNodeIDAnnotation(stale, pool.Name), "",
			)
			if err == nil || !strings.Contains(err.Error(), "deletion or storage-drain") {
				t.Fatalf("final activation gate accepted changed cluster state: %v", err)
			}
		})
	}
}

func TestNodeLocalPoolActivationCanPrepareStaleRolloutGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("stale-rollout-prepare", "a")
	cluster.Generation = 2
	cluster.Status.Conditions = []metav1.Condition{{
		Type:               garagev1beta1.ConditionStorageRolloutReady,
		Status:             metav1.ConditionTrue,
		Reason:             garagev1beta1.ReasonStorageRolloutConverged,
		ObservedGeneration: 1,
	}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-stale-rollout", Labels: map[string]string{testStorageOwnerLabelKey: "a"},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            NewLayoutMutationCoordinator(),
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	if err := reconciler.ensureNodeLocalPoolActivation(
		ctx, cluster, pool, node,
		nodeLocalPoolActivationLabel(cluster, pool.Name), nodeLocalPoolActivationLabelValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name), "",
	); err != nil {
		t.Fatalf("stale converged rollout condition blocked pre-handoff activation preparation: %v", err)
	}
}

func TestNodeLocalPoolActivationOwnRolloutAllowsOnlyReadOnlyRevalidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("rollout-read-only", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	activationValue := nodeLocalPoolActivationValueForWorkloadUID("daemonset-uid")
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, "")
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA,
		UID:  types.UID("kubernetes-node-uid"),
		Labels: map[string]string{
			testStorageOwnerLabelKey: "a",
			activationLabel:          activationValue,
		},
		Annotations: map[string]string{
			nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name): claimValue,
		},
	}}
	cluster.Status.StorageRollout = &garagev1beta2.StorageRolloutStatus{
		ClusterGeneration:    cluster.Generation,
		GarageNodeGeneration: 1,
		GarageNodeUID:        "garage-node-uid",
		GarageNodeID:         strings.Repeat("a", 64),
		NodeLocalPoolName:    pool.Name,
		KubernetesNodeName:   node.Name,
		KubernetesNodeUID:    string(node.UID),
		WorkloadUID:          "daemonset-uid",
		PreviousPodUID:       testPreviousPodUID,
		DesiredPodSpecHash:   "desired-pod-spec-hash",
		DesiredConfigHash:    "desired-config-hash",
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	coordinator := NewLayoutMutationCoordinator()
	key := layoutOwnerKey(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(
		key, cluster.UID, client.ObjectKeyFromObject(cluster), cluster.UID,
	) || !coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) {
		t.Fatal("could not establish exact persisted rollout marker")
	}
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            coordinator,
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}

	if err := reconciler.ensureNodeLocalPoolActivation(
		ctx, cluster, pool, node, activationLabel, activationValue,
		nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name), "",
	); err != nil {
		t.Fatalf("exact rollout could not revalidate its unchanged activation: %v", err)
	}

	err = reconciler.ensureNodeLocalPoolActivation(
		ctx, cluster, pool, node, activationLabel,
		nodeLocalPoolActivationValueForWorkloadUID("different-daemonset-uid"),
		nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name), "",
	)
	if err == nil || !strings.Contains(err.Error(), "requires a Node mutation") {
		t.Fatalf("active rollout allowed an activation mutation: %v", err)
	}
	freshNode := &corev1.Node{}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(node), freshNode); err != nil {
		t.Fatal(err)
	}
	if freshNode.Labels[activationLabel] != activationValue {
		t.Fatalf("blocked rollout mutation changed the activation token to %q", freshNode.Labels[activationLabel])
	}
}

func TestNodeLocalPoolRecoveryClaimsPreferCurrentUIDAndConstrainLegacyBySite(t *testing.T) {
	t.Parallel()
	const (
		localID   = "1111111111111111111111111111111111111111111111111111111111111111"
		foreignID = "2222222222222222222222222222222222222222222222222222222222222222"
		legacyID  = "3333333333333333333333333333333333333333333333333333333333333333"
	)
	capacity := uint64(100)
	cluster := nodeLocalPoolActivationTestCluster("shared-name", "a")
	cluster.UID = "local-site-uid"
	key := nodeLocalPoolKey(testPoolA, "worker")
	baseTags := []string{
		"cluster:" + cluster.Name + "/" + cluster.Namespace,
		"tier:" + tierStorage,
		nodeLocalPoolLayoutTagPrefix + testPoolA,
		"kubernetes-node:worker",
	}
	withUID := func(uid string) []string {
		return append(append([]string(nil), baseTags...), nodeClusterUIDTagPrefix+uid)
	}
	layout := &garage.ClusterLayout{Roles: []garage.LayoutNodeRole{
		{ID: foreignID, Zone: "remote-site", Capacity: &capacity, Tags: withUID("foreign-site-uid")},
		{ID: legacyID, Zone: testZone, Capacity: &capacity, Tags: withUID("previous-local-incarnation")},
		{ID: localID, Zone: "unexpected-zone", Capacity: &capacity, Tags: withUID(string(cluster.UID))},
	}}
	claims, err := nodeLocalPoolRecoveryRoleClaims(cluster, layout, map[string]string{key: testZone})
	if err != nil {
		t.Fatal(err)
	}
	if claims[key] != localID {
		t.Fatalf("exact current cluster UID did not win: got %q want %q", claims[key], localID)
	}
	importedTags := withUID(string(cluster.UID))
	importedTags[0] = "cluster:rewritten-remote/" + cluster.Namespace
	layout.Roles = []garage.LayoutNodeRole{{
		ID: localID, Zone: "remote-import-zone", Capacity: &capacity, Tags: importedTags,
	}}
	claims, err = nodeLocalPoolRecoveryRoleClaims(cluster, layout, map[string]string{key: testZone})
	if err != nil {
		t.Fatal(err)
	}
	if claims[key] != localID {
		t.Fatalf("federated import lost exact UID ownership: got %q want %q", claims[key], localID)
	}
	if err := validatePinnedNodeLocalPoolRecoveryRole(
		cluster, layout, localID, testPoolA, "worker", testZone,
	); err != nil {
		t.Fatalf("exact UID pin was rejected after federation rewrote its name ownership tag: %v", err)
	}

	layout.Roles = []garage.LayoutNodeRole{
		{ID: foreignID, Zone: "remote-site", Capacity: &capacity, Tags: withUID("foreign-site-uid")},
		{ID: legacyID, Zone: testZone, Capacity: &capacity, Tags: withUID("previous-local-incarnation")},
	}
	claims, err = nodeLocalPoolRecoveryRoleClaims(cluster, layout, map[string]string{key: testZone})
	if err != nil {
		t.Fatal(err)
	}
	if claims[key] != legacyID {
		t.Fatalf("same-site legacy recovery was not selected: got %q want %q", claims[key], legacyID)
	}
	if err := validatePinnedNodeLocalPoolRecoveryRole(
		cluster, layout, legacyID, testPoolA, "worker", testZone,
	); err != nil {
		t.Fatalf("exact local durable pin was made ambiguous by a same-key foreign site: %v", err)
	}
	layout.Roles[1].Tags = append(layout.Roles[1].Tags, nodeLocalPoolLayoutTagPrefix+"another-pool")
	if err := validatePinnedNodeLocalPoolRecoveryRole(
		cluster, layout, legacyID, testPoolA, "worker", testZone,
	); err == nil || !strings.Contains(err.Error(), "multiple node-local pools") {
		t.Fatalf("durable pin accepted an identity with conflicting pool tags: %v", err)
	}
	layout.Roles[1].Tags = layout.Roles[1].Tags[:len(layout.Roles[1].Tags)-1]
	if err := validatePinnedNodeLocalPoolRecoveryRole(
		cluster, layout, foreignID, testPoolA, "worker", testZone,
	); err == nil || !strings.Contains(err.Error(), "expected site zone") {
		t.Fatalf("foreign-site durable identity passed local recovery validation: %v", err)
	}
}

func TestNodeLocalPoolRecoveryPinsRejectOneIdentityAcrossTwoMembers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("duplicate-recovery", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	const nodeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	recoveryKey := nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name)
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	nodeA := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA, Annotations: map[string]string{recoveryKey: nodeID},
	}}
	nodeB := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "worker-b", Annotations: map[string]string{claimKey: claimValue},
	}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, nodeA, nodeB).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme}
	states := map[string]*nodeLocalPoolState{
		pool.Name: {
			pool: pool,
			desiredNodes: map[string]*corev1.Node{
				nodeA.Name: nodeA,
				nodeB.Name: nodeB,
			},
		},
	}
	_, err = reconciler.resolveNodeLocalPoolRecoveryPins(ctx, cluster, states, nil)
	if err == nil || !strings.Contains(err.Error(), "is claimed by node-local pool") {
		t.Fatalf("duplicate durable recovery identity was not rejected: %v", err)
	}
}

func TestGarageNodeStatusObservesStatefulSetPodWithoutNodeLocalPools(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		storage *garagev1beta1.NodeStorageConfig
	}{
		{
			name: "PVC",
			storage: &garagev1beta1.NodeStorageConfig{Data: &garagev1beta1.NodeVolumeConfig{
				Size: ptrTo(resourceMustParse(t, "10Gi")),
			}},
		},
		{
			name: "SMB existing claim",
			storage: &garagev1beta1.NodeStorageConfig{Data: &garagev1beta1.NodeVolumeConfig{
				ExistingClaim: "garage-data-smb",
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const (
				namespace = testGarageValue
				nodeID    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			)
			scheme := runtime.NewScheme()
			if err := appsv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := garagev1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := garagev1beta2.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}

			name := "storage-" + strings.ToLower(strings.ReplaceAll(tc.name, " ", "-"))
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "pvc-smb-only", Namespace: namespace},
			}
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(name + "-uid"), Generation: 1},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
					Storage:    tc.storage,
				},
				Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
			}
			statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: namespace, UID: types.UID(name + "-sts-uid"),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
					Name: node.Name, UID: node.UID, Controller: ptrTo(true),
				}},
			}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: name + "-0", Namespace: namespace, UID: types.UID(name + "-pod-uid"),
				Annotations: map[string]string{"garage.rajsingh.info/node-id": strings.Repeat("f", 64)},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
					Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
				}},
			}, Status: corev1.PodStatus{
				Phase: corev1.PodRunning, PodIP: testLoopbackPodIP,
				PodIPs: []corev1.PodIP{{IP: testLoopbackPodIP}},
			}}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case testGetNodeInfoPath:
					_ = json.NewEncoder(w).Encode(map[string]any{
						testHTTPSuccessKey: map[string]any{nodeID: map[string]any{testNodeIDJSONKey: nodeID}},
						testHTTPErrorKey:   map[string]string{},
					})
				case pathGetClusterStatus:
					_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{
						ID: nodeID, Address: ptrTo(testLoopbackPodIP + ":3901"), IsUp: true,
					}}})
				case pathGetClusterLayout:
					_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 7, Roles: []garage.LayoutNodeRole{{ID: nodeID}}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			cluster.Spec.Admin = &garagev1beta2.AdminConfig{BindPort: int32(server.Listener.Addr().(*net.TCPAddr).Port)}
			pod.Spec.Containers = []corev1.Container{{
				Name: defaultAppName,
				Env: []corev1.EnvVar{{
					Name: envGarageAdminToken,
					ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey}, Key: DefaultAdminTokenKey,
					}},
				}},
			}}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: DefaultAdminTokenKey, Namespace: namespace},
				Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&garagev1beta1.GarageNode{}).
				WithObjects(node, statefulSet, pod, secret).Build()

			reconciler := &GarageNodeReconciler{Client: fakeClient, Scheme: scheme}
			if _, err := reconciler.updateStatusFromGarage(
				context.Background(), node, cluster, garage.NewClient(server.URL, "token"),
			); err != nil {
				t.Fatal(err)
			}

			updated := &garagev1beta1.GarageNode{}
			if err := fakeClient.Get(context.Background(), clientKey(node), updated); err != nil {
				t.Fatal(err)
			}
			if updated.Status.ObservedPodUID != string(pod.UID) {
				t.Fatalf("ObservedPodUID = %q, want %q", updated.Status.ObservedPodUID, pod.UID)
			}
			if !updated.Status.Connected || !updated.Status.InLayout {
				t.Fatalf("fresh pod handshake did not preserve ready state: %+v", updated.Status)
			}
		})
	}
}

func TestGarageNodeStatusDiscoversUnannotatedPodDirectly(t *testing.T) {
	const (
		namespace = "direct-status"
		nodeID    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case testGetNodeInfoPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				testHTTPSuccessKey: map[string]any{nodeID: map[string]any{testNodeIDJSONKey: nodeID}},
				testHTTPErrorKey:   map[string]string{},
			})
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{ID: nodeID, IsUp: true}}})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 7, Roles: []garage.LayoutNodeRole{{ID: nodeID}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()
	adminPort := int32(server.Listener.Addr().(*net.TCPAddr).Port)

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "direct-cluster", Namespace: namespace},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort: adminPort,
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey},
				Key:                  DefaultAdminTokenKey,
			},
		}},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "direct-node", Namespace: namespace, UID: "direct-node-uid", Generation: 1},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: namespace, UID: "direct-sts-uid",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
			Name: node.Name, UID: node.UID, Controller: ptrTo(true),
		}},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: namespace, UID: "direct-pod-uid",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  testLoopbackPodIP,
			PodIPs: []corev1.PodIP{{IP: testLoopbackPodIP}},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultAdminTokenKey, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, statefulSet, pod, secret).Build()
	reconciler := &GarageNodeReconciler{Client: fakeClient, Scheme: scheme}
	if _, err := reconciler.updateStatusFromGarage(
		context.Background(), node, cluster, garage.NewClient(server.URL, "token"),
	); err != nil {
		t.Fatal(err)
	}

	updated := &garagev1beta1.GarageNode{}
	if err := fakeClient.Get(context.Background(), clientKey(node), updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.ObservedPodUID != string(pod.UID) || !updated.Status.Connected || !updated.Status.InLayout {
		t.Fatalf("direct identity handshake did not make the unannotated pod ready: %+v", updated.Status)
	}
}

func TestDirectManagedIdentityRejectsPodReplacementAcrossSelfQuery(t *testing.T) {
	const (
		namespace = "direct-identity-race"
		nodeID    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	var (
		kubeClient  client.Client
		oldPod      *corev1.Pod
		mutationErr error
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testGetNodeInfoPath || r.URL.Query().Get("node") != "self" {
			http.NotFound(w, r)
			return
		}
		if err := kubeClient.Delete(r.Context(), oldPod); err != nil {
			mutationErr = err
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		replacement := oldPod.DeepCopy()
		replacement.ResourceVersion = ""
		replacement.UID = types.UID("replacement-pod-uid")
		if err := kubeClient.Create(r.Context(), replacement); err != nil {
			mutationErr = err
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			testHTTPSuccessKey: map[string]any{nodeID: map[string]any{testNodeIDJSONKey: nodeID}},
			testHTTPErrorKey:   map[string]string{},
		})
	}))
	defer server.Close()

	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "direct-cluster", Namespace: namespace},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort: int32(server.Listener.Addr().(*net.TCPAddr).Port),
		}},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "direct-node", Namespace: namespace, UID: types.UID("direct-node-uid")},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: namespace, UID: types.UID("direct-sts-uid"),
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(node, garagev1beta1.GroupVersion.WithKind(kindGarageNode))},
	}}
	oldPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: namespace, UID: types.UID("original-pod-uid"),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(statefulSet, appsv1.SchemeGroupVersion.WithKind(kindStatefulSet))},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey}, Key: DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testLoopbackPodIP},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultAdminTokenKey, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	kubeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, statefulSet, oldPod, secret).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, APIReader: kubeClient}
	identity, err := reconciler.discoverNodeIdentityDirect(context.Background(), node, cluster)
	if mutationErr != nil {
		t.Fatalf("injecting Pod replacement: %v", mutationErr)
	}
	if err == nil || !strings.Contains(err.Error(), "changed UID") {
		t.Fatalf("Pod replacement was accepted: identity=%+v err=%v", identity, err)
	}
}

func TestGarageNodeRolloutProgressChangedIgnoresHeartbeatOnlyStatus(t *testing.T) {
	oldNode := &garagev1beta1.GarageNode{
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:             "node-id",
			ObservedPodUID:     "pod-uid",
			ObservedGeneration: 4,
			Connected:          true,
			InLayout:           true,
		},
	}
	newNode := oldNode.DeepCopy()
	now := metav1.Now()
	newNode.Status.LastSeen = &now
	if garageNodeRolloutProgressChanged(oldNode, newNode) {
		t.Fatal("LastSeen-only status tick must not wake the parent storage rollout")
	}

	newNode.Status.ObservedPodUID = testReplacementPodUID
	if !garageNodeRolloutProgressChanged(oldNode, newNode) {
		t.Fatal("replacement Pod UID must wake the parent storage rollout")
	}

	newNode = oldNode.DeepCopy()
	newNode.Status.ObservedGeneration++
	if !garageNodeRolloutProgressChanged(oldNode, newNode) {
		t.Fatal("layout generation convergence must wake the parent storage rollout")
	}
}

func resourceMustParse(t *testing.T, value string) resource.Quantity {
	t.Helper()
	quantity, err := resource.ParseQuantity(value)
	if err != nil {
		t.Fatal(err)
	}
	return quantity
}

func readyNodeLocalPoolPod(namespace, name, nodeName, hash, configHash, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID(uid),
			Annotations: map[string]string{
				annotationPodSpecHash: hash,
				annotationConfigHash:  configHash,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
				Name: "pool-" + nodeName, UID: types.UID("daemonset-" + nodeName), Controller: ptrTo(true),
			}},
		},
		Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: fmGarageContainer}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}},
		},
	}
}

func readyNodeLocalPoolGarageNode(name, nodeLocalPoolName, kubernetesNode, nodeID string, pod *corev1.Pod) *garagev1beta1.GarageNode {
	return &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: pod.Namespace, UID: types.UID(name + "-uid"), Generation: 1},
		Spec: garagev1beta1.GarageNodeSpec{
			Backing:            garagev1beta1.NodeBackingNodeLocalPool,
			NodeLocalPoolName:  nodeLocalPoolName,
			KubernetesNodeName: kubernetesNode,
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:             nodeID,
			Connected:          true,
			InLayout:           true,
			ObservedGeneration: 1,
			ObservedPodUID:     string(pod.UID),
		},
	}
}

func healthyNodeLocalPoolRolloutState(nodeIDs ...string) *nodeLocalPoolRolloutGarageState {
	nodes := make([]garage.NodeInfo, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodes = append(nodes, garage.NodeInfo{
			ID: nodeID, IsUp: true, Role: &garage.NodeAssignedRole{Zone: testSiteA},
		})
	}
	return &nodeLocalPoolRolloutGarageState{
		history: &garage.LayoutHistoryResponse{
			CurrentVersion: 1,
			Versions:       []garage.LayoutVersion{{Version: 1, Status: garage.LayoutVersionStatusCurrent}},
		},
		health: &garage.ClusterHealth{
			Status: healthStatusHealthy, StorageNodes: len(nodeIDs), StorageNodesUp: len(nodeIDs),
			Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
		},
		status: &garage.ClusterStatus{Nodes: nodes},
	}
}

func TestNodeLocalPoolRolloutDeletesOnlyOnePodAcrossPools(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const namespace = testGarageValue
	configBody := "desired pool config"
	desiredConfigHash := garageConfigHash(configBody)
	podA := readyNodeLocalPoolPod(namespace, "pool-a-node-a", testKubernetesNodeA, "old", "old-config", "pod-a")
	podB := readyNodeLocalPoolPod(namespace, "pool-b-node-b", testKubernetesNodeB, "old", "old-config", "pod-b")
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: namespace, UID: testClusterUID, Generation: 1},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{
			{Name: testPoolA, Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-a/meta"}, Data: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-a/data"}},
			{Name: testPoolB, Metadata: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-b/meta"}, Data: &garagev1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-b/data"}},
		}}},
	}
	nodeA := readyNodeLocalPoolGarageNode("gn-a", testPoolA, testKubernetesNodeA, testGarageNodeID, podA)
	nodeB := readyNodeLocalPoolGarageNode("gn-b", testPoolB, testKubernetesNodeB, "garage-b", podB)
	nodeA.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: cluster.Name}
	nodeB.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: cluster.Name}
	kubernetesNodeA := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testKubernetesNodeA, UID: "k8s-node-a"}}
	kubernetesNodeB := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testKubernetesNodeB, UID: "k8s-node-b"}}
	poolObjects := make([]client.Object, 0, 6)
	for _, fixture := range []struct {
		pool string
		node *corev1.Node
		pod  *corev1.Pod
	}{
		{pool: testPoolA, node: kubernetesNodeA, pod: podA},
		{pool: testPoolB, node: kubernetesNodeB, pod: podB},
	} {
		pool := nodeLocalPoolSpecByName(cluster, fixture.pool)
		if pool == nil {
			t.Fatalf("missing fixture pool %s", fixture.pool)
		}
		activationLabel := nodeLocalPoolActivationLabel(cluster, fixture.pool)
		fixture.node.Labels = map[string]string{activationLabel: nodeLocalPoolActivationLabelValue}
		diskLayout, err := marshalStorageDiskLayout(storageDiskLayoutForPool(pool))
		if err != nil {
			t.Fatal(err)
		}
		volumes, volumeMounts := buildStorageDaemonSetVolumesAndMounts(cluster, pool, desiredConfigHash)
		daemonSet := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: storageDaemonSetName(cluster, fixture.pool), Namespace: namespace,
				UID: types.UID("daemonset-" + fixture.node.Name),
				Annotations: map[string]string{
					annotationNodeLocalPoolActivationLabel: activationLabel,
					annotationNodeLocalPoolActivationValue: nodeLocalPoolActivationLabelValue,
					annotationStorageDiskLayout:            diskLayout,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
					Name: cluster.Name, UID: cluster.UID, Controller: ptrTo(true),
				}},
			},
			Spec: appsv1.DaemonSetSpec{
				UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
						annotationPodSpecHash: testNewValue,
						annotationConfigHash:  desiredConfigHash,
					}},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{activationLabel: nodeLocalPoolActivationLabelValue},
						Volumes:      volumes,
						Containers: []corev1.Container{{
							Name: defaultAppName, VolumeMounts: volumeMounts,
						}},
					},
				},
			},
		}
		fixture.pod.OwnerReferences[0].Name = daemonSet.Name
		fixture.pod.OwnerReferences[0].UID = daemonSet.UID
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: storageDaemonSetConfigResourceName(cluster, pool, desiredConfigHash), Namespace: namespace,
				Labels: map[string]string{labelCluster: cluster.Name, labelNodeLocalPool: fixture.pool},
				Annotations: garageConfigRevisionAnnotations(
					storageDaemonSetConfigMapName(cluster, fixture.pool),
					map[string]string{annotationStorageDiskLayout: diskLayout},
				),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
					Name: cluster.Name, UID: cluster.UID, Controller: ptrTo(true),
				}},
			},
			Immutable: ptrTo(true),
			Data:      map[string]string{configFileName: configBody},
		}
		poolObjects = append(poolObjects, fixture.node, daemonSet, configMap)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(append([]client.Object{cluster, nodeA, nodeB, podA, podB}, poolObjects...)...).Build()
	if err := client.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	states := map[string]*nodeLocalPoolState{
		testPoolA: {
			desiredPodSpecHash: testNewValue,
			configHash:         desiredConfigHash,
			desiredNodes:       map[string]*corev1.Node{testKubernetesNodeA: kubernetesNodeA},
			activePods:         map[string]*corev1.Pod{testKubernetesNodeA: podA},
			terminatingPods:    map[string]*corev1.Pod{},
		},
		testPoolB: {
			desiredPodSpecHash: testNewValue,
			configHash:         desiredConfigHash,
			desiredNodes:       map[string]*corev1.Node{testKubernetesNodeB: kubernetesNodeB},
			activePods:         map[string]*corev1.Pod{testKubernetesNodeB: podB},
			terminatingPods:    map[string]*corev1.Pod{},
		},
	}
	existing := map[string]*garagev1beta1.GarageNode{
		nodeLocalPoolKey(testPoolA, testKubernetesNodeA): nodeA,
		nodeLocalPoolKey(testPoolB, testKubernetesNodeB): nodeB,
	}
	reconciler := &GarageClusterReconciler{
		Client:          client,
		LayoutMutations: NewLayoutMutationCoordinator(),
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			return healthyNodeLocalPoolRolloutState(testGarageNodeID, "garage-b"), nil
		},
	}

	complete, _, err := reconciler.reconcileNodeLocalPoolRollout(ctx, cluster, states, existing)
	if err != nil {
		t.Fatalf("rollout failed: %v", err)
	}
	if complete {
		t.Fatal("rollout reported complete after deleting an outdated pod")
	}
	if err := client.Get(ctx, clientKey(podA), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("alphabetically first pool pod was not deleted: %v", err)
	}
	if err := client.Get(ctx, clientKey(podB), &corev1.Pod{}); err != nil {
		t.Fatalf("second pool pod must remain online: %v", err)
	}

	// A persisted actor is safe to delete only while the Kubernetes Node still
	// carries the exact active workload token. A quarantine/fence must invalidate
	// the snapshot even if the DaemonSet and GarageNode identities still match.
	if err := client.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	record, err := nodeLocalPoolRolloutRecordForCluster(cluster)
	if err != nil || record == nil {
		t.Fatalf("missing persisted rollout actor: record=%+v err=%v", record, err)
	}
	if _, err := reconciler.readStorageRolloutActorSnapshot(ctx, cluster, *record); err != nil {
		t.Fatalf("active persisted node-local-pool actor was not readable before quarantine: %v", err)
	}
	actorNode := &corev1.Node{}
	if err := client.Get(ctx, types.NamespacedName{Name: record.KubernetesNodeName}, actorNode); err != nil {
		t.Fatal(err)
	}
	actorNode.Labels[nodeLocalPoolActivationLabel(cluster, record.NodeLocalPoolName)] = nodeLocalPoolActivationQuarantineValue
	if err := client.Update(ctx, actorNode); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.readStorageRolloutActorSnapshot(ctx, cluster, *record); err == nil {
		t.Fatalf("inactive node-local-pool rollout actor did not fail closed: %v", err)
	}
}

func TestReconcileNodeUsesExactSelfIdentityBeforeClusterStatusIP(t *testing.T) {
	const (
		namespace   = "exact-self-identity"
		clusterName = "exact-self-cluster"
		nodeName    = "exact-self-node"
		selfID      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		staleID     = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	)
	ctx := context.Background()
	connected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case testGetNodeInfoPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				testHTTPSuccessKey: map[string]any{selfID: map[string]any{testNodeIDJSONKey: selfID}},
				testHTTPErrorKey:   map[string]string{},
			})
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{Nodes: []garage.NodeInfo{{
				ID: staleID, Address: ptrTo(testLoopbackPodIP + ":3901"), IsUp: true,
			}}})
		case pathConnectNodes:
			connected = true
			_ = json.NewEncoder(w).Encode([]garage.ConnectNodeResult{{Success: true}})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme, corev1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: namespace, UID: testClusterUID},
		Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
			BindPort: int32(server.Listener.Addr().(*net.TCPAddr).Port),
		}},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: namespace, UID: testGarageNodeUID, Generation: 1},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: namespace, UID: testStatefulSetUID,
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
			node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
		)},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: namespace, UID: testSourcePodUID,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				statefulSet, appsv1.SchemeGroupVersion.WithKind(kindStatefulSet),
			)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testLoopbackPodIP},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultAdminTokenKey, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, statefulSet, pod, secret).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, Scheme: scheme}
	err := reconciler.reconcileNode(ctx, node, cluster, garage.NewClient(server.URL, "token"), cluster)
	if !errors.Is(err, errLayoutMutationPending) {
		t.Fatalf("expected first-observation boundary, got %v", err)
	}
	stored := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(ctx, clientKey(node), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.NodeID != selfID {
		t.Fatalf("persisted node ID %q, want exact self identity %q (cluster status advertised stale %q)", stored.Status.NodeID, selfID, staleID)
	}
	if stored.Status.ObservedPodUID != string(pod.UID) {
		t.Fatalf("persisted pod UID %q, want exact authenticated UID %q", stored.Status.ObservedPodUID, pod.UID)
	}
	if !connected {
		t.Fatal("exact self identity was not connected after cluster status mapped the Pod IP to a stale peer")
	}
}

func TestReconcileNodeRejectsStaleIdentityFallbackForReplacementPod(t *testing.T) {
	const (
		namespace   = "replacement-fallback"
		clusterName = "replacement-cluster"
		nodeName    = "replacement-node"
		oldID       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	ctx := context.Background()
	fakeLayout := newFakeGarageLayout()
	fakeLayout.selfStatus = http.StatusServiceUnavailable
	server := fakeLayout.server()
	defer server.Close()

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme, corev1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: namespace, UID: testClusterUID},
		Spec: garagev1beta2.GarageClusterSpec{
			Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			Admin: &garagev1beta2.AdminConfig{
				BindPort: int32(server.Listener.Addr().(*net.TCPAddr).Port),
			},
		},
	}
	capacity := resource.MustParse("100Gi")
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: namespace, UID: testGarageNodeUID, Generation: 1},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Zone:       testNodeZone,
			Capacity:   &capacity,
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: oldID, ObservedPodUID: testOldPodUID, Connected: true, InLayout: true,
		},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: namespace, UID: testStatefulSetUID,
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
			node, garagev1beta1.GroupVersion.WithKind(kindGarageNode),
		)},
	}}
	replacement := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name + "-0", Namespace: namespace, UID: testReplacementPodUID,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				statefulSet, appsv1.SchemeGroupVersion.WithKind(kindStatefulSet),
			)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: DefaultAdminTokenKey},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testLoopbackPodIP},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultAdminTokenKey, Namespace: namespace},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, statefulSet, replacement, secret).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, Scheme: scheme}
	err := reconciler.reconcileNode(ctx, node, cluster, garage.NewClient(server.URL, "token"), cluster)
	if !errors.Is(err, errLayoutMutationPending) || !strings.Contains(err.Error(), testReplacementPodUID) {
		t.Fatalf("replacement Pod did not fail closed at stale identity fallback: %v", err)
	}
	fakeLayout.mu.Lock()
	staged := len(fakeLayout.staged)
	applied := len(fakeLayout.applies)
	fakeLayout.mu.Unlock()
	if staged != 0 || applied != 0 {
		t.Fatalf("stale identity fallback mutated layout: staged=%d applied=%d", staged, applied)
	}
	stored := &garagev1beta1.GarageNode{}
	if err := kubeClient.Get(ctx, clientKey(node), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.NodeID != oldID || stored.Status.ObservedPodUID != testOldPodUID || !stored.Status.Connected || !stored.Status.InLayout {
		t.Fatalf("replacement fallback mutated durable identity status: %+v", stored.Status)
	}
}

func TestNodeLocalPoolRolloutWaitsForReplacementPodIdentityObservation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const namespace = testGarageValue
	oldPod := readyNodeLocalPoolPod(namespace, "old", testKubernetesNodeA, "old", "config", testOldPodUID)
	replacement := readyNodeLocalPoolPod(namespace, "replacement", testKubernetesNodeA, testNewValue, "config", "replacement-pod")
	node := readyNodeLocalPoolGarageNode("gn-a", testPoolA, testKubernetesNodeA, testGarageNodeID, oldPod)
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: namespace}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	states := map[string]*nodeLocalPoolState{
		testPoolA: {
			desiredPodSpecHash: testNewValue,
			configHash:         "config",
			desiredNodes:       map[string]*corev1.Node{testKubernetesNodeA: {ObjectMeta: metav1.ObjectMeta{Name: testKubernetesNodeA, UID: "k8s-node-a"}}},
			activePods:         map[string]*corev1.Pod{testKubernetesNodeA: replacement},
			terminatingPods:    map[string]*corev1.Pod{},
		},
	}
	existing := map[string]*garagev1beta1.GarageNode{nodeLocalPoolKey(testPoolA, testKubernetesNodeA): node}
	reconciler := &GarageClusterReconciler{Client: fakeClient}

	complete, message, err := reconciler.reconcileNodeLocalPoolRollout(
		ctx,
		cluster,
		states,
		existing,
	)
	if err != nil {
		t.Fatalf("rollout wait failed: %v", err)
	}
	if complete || node.Status.ObservedPodUID == string(replacement.UID) {
		t.Fatal("stale GarageNode status was accepted for the replacement pod")
	}
	if message == "" {
		t.Fatal("rollout wait did not explain the replacement identity handshake")
	}

	node.Status.ObservedPodUID = string(replacement.UID)
	complete, _, err = reconciler.reconcileNodeLocalPoolRollout(
		ctx,
		cluster,
		states,
		existing,
	)
	if err != nil || !complete {
		t.Fatalf("current replacement identity did not complete rollout: complete=%v err=%v", complete, err)
	}
}

func TestStorageRolloutSelectsStatefulSetActorWithoutNodeLocalPools(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: testGarageValue, UID: testClusterUID, Generation: 1}}
	configBody := "desired garage config"
	configRevision := garageConfigHash(configBody)
	desiredConfigHash := configRevision[:16]
	configName := garageConfigRevisionName(cluster.Name+"-config", configRevision)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testSMBNodeName, Namespace: cluster.Namespace, UID: testNodeUID, Generation: 1},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testGarageNodeID, Connected: true, InLayout: true,
			ObservedGeneration: 1, ObservedPodUID: testOldPodUID,
		},
	}
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name, Namespace: node.Namespace, UID: "sts-uid",
			Annotations: map[string]string{annotationStorageRolloutInput: storageRolloutInputToken(cluster, node, testNewSpecHash, desiredConfigHash)},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: node.Name, UID: node.UID, Controller: ptrTo(true),
			}},
		},
		Spec: appsv1.StatefulSetSpec{
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.OnDeleteStatefulSetStrategyType},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					annotationPodSpecHash: testNewSpecHash,
					annotationConfigHash:  desiredConfigHash,
				}},
				Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
					Name: configVolumeName, VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configName}},
					},
				}}},
			},
		},
	}
	pod := readyNodeLocalPoolPod(cluster.Namespace, node.Name+"-0", testKubernetesWorkerA, "old-spec", "old-config", testOldPodUID)
	pod.Annotations[annotationConfigHash] = "old-config"
	pod.Spec.Volumes = []corev1.Volume{{
		Name: metadataVolName, VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: testSMBMetadataPVC},
		},
	}}
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
		Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, node, statefulSet, pod, &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: testSMBMetadataPVC, Namespace: cluster.Namespace, UID: testPVCUID},
		}, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configName, Namespace: cluster.Namespace,
				Annotations: garageConfigRevisionAnnotations(cluster.Name+"-config", nil),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
					Name: cluster.Name, UID: cluster.UID, Controller: ptrTo(true),
				}},
			},
			Immutable: ptrTo(true),
			Data:      map[string]string{configFileName: configBody},
		}).Build()
	if err := fakeClient.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{
		Client: fakeClient, LayoutMutations: NewLayoutMutationCoordinator(),
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			return healthyNodeLocalPoolRolloutState(testGarageNodeID), nil
		},
	}
	complete, _, err := reconciler.reconcileNodeLocalPoolRollout(
		ctx, cluster, map[string]*nodeLocalPoolState{}, map[string]*garagev1beta1.GarageNode{},
	)
	if err != nil {
		t.Fatalf("PVC/SMB-only storage rollout failed: %v", err)
	}
	if complete {
		t.Fatal("outdated StatefulSet actor was reported converged")
	}
	if err := fakeClient.Get(ctx, clientKey(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("outdated StatefulSet pod was not deleted: %v", err)
	}
	if cluster.Status.StorageRollout == nil || cluster.Status.StorageRollout.GarageNodeName != node.Name ||
		cluster.Status.StorageRollout.NodeLocalPoolName != "" {
		t.Fatalf("wrong generic rollout actor persisted: %#v", cluster.Status.StorageRollout)
	}
	if claims := cluster.Status.StorageRollout.PersistentVolumeClaims; len(claims) != 1 ||
		claims[0].Name != testSMBMetadataPVC || claims[0].UID != testPVCUID {
		t.Fatalf("exact StatefulSet PVC identity was not persisted before Pod DELETE: %#v", claims)
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: cluster.Namespace, Name: testSMBMetadataPVC}, claim); err != nil {
		t.Fatal(err)
	}
	finalizer := storageRolloutPVCFinalizer(cluster)
	if finalizer == "" || !controllerutil.ContainsFinalizer(claim, finalizer) || claim.Labels[labelAppManagedBy] != operatorName {
		t.Fatalf("exact PVC was not protected before Pod DELETE: finalizers=%v labels=%v", claim.Finalizers, claim.Labels)
	}
	// Model an administrator overriding the transaction protection so the
	// same-name recreation defense is exercised independently of the finalizer.
	controllerutil.RemoveFinalizer(claim, finalizer)
	if err := fakeClient.Update(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if err := fakeClient.Delete(ctx, claim); err != nil {
		t.Fatal(err)
	}
	recreated := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: claim.Name, Namespace: claim.Namespace, UID: "recreated-pvc-uid",
	}}
	if err := fakeClient.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reconciler.readStorageRolloutActorIdentity(ctx, cluster, *cluster.Status.StorageRollout); err == nil ||
		!strings.Contains(err.Error(), "recreated or is deleting") {
		t.Fatalf("recreated same-name PVC did not fail closed during StatefulSet recovery: %v", err)
	}
}

func TestStorageRolloutRefusesUnsafeMissingStatefulSetRecreation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testSiteA, Namespace: testGarageValue, UID: testClusterUID,
	}}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: cluster.Namespace, UID: testGarageNodeUID},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: testGarageNodeID},
	}
	record := nodeLocalPoolRolloutRecord{
		GarageNodeName: testStorageNodeName, GarageNodeUID: testGarageNodeUID, GarageNodeID: testGarageNodeID,
		WorkloadUID: "deleted-statefulset-uid", PreviousPodUID: testOldPodUID,
		DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
		PersistentVolumeClaims: []garagev1beta2.StorageRolloutPersistentVolumeClaimStatus{{
			Name: testStorageMetadataPVC, UID: testPVCUID,
		}},
		StatefulSetWorkloadRecreationSafe: false,
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: testStorageMetadataPVC, Namespace: cluster.Namespace, UID: testPVCUID,
		Finalizers: []string{storageRolloutPVCFinalizer(cluster)},
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, claim).Build()
	reconciler := &GarageClusterReconciler{Client: fakeClient}
	pending, err := reconciler.ensureStorageRolloutWorkload(ctx, cluster, record)
	if err == nil || pending || !strings.Contains(err.Error(), "whenDeleted PVC retention policy was Delete") {
		t.Fatalf("unsafe missing StatefulSet was not rejected: pending=%v err=%v", pending, err)
	}
}

func TestStorageRolloutRetiredWorkloadHistoryIsBoundedBeforeDaemonSetRecreation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := deletionTestScheme(t)
	cluster := nodeLocalPoolActivationTestCluster("rollout-history-cap", "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	kubernetesNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: testKubernetesWorkerA, UID: types.UID("rollout-history-kubernetes-node-uid"),
		Labels: map[string]string{
			testStorageOwnerLabelKey:                         "a",
			nodeLocalPoolActivationLabel(cluster, pool.Name): nodeLocalPoolActivationLabelValue,
		},
	}}
	garageNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeLocalPoolGarageNodeName(cluster.Name, pool.Name, kubernetesNode.Name),
			Namespace: cluster.Namespace, UID: types.UID("rollout-history-garage-node-uid"),
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
			)},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef:        garagev1beta1.ClusterReference{Name: cluster.Name},
			Backing:           garagev1beta1.NodeBackingNodeLocalPool,
			NodeLocalPoolName: pool.Name, KubernetesNodeName: kubernetesNode.Name,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: testGarageNodeID},
	}
	retired := make([]string, maximumStorageRolloutRetiredWorkloadUIDs)
	for i := range retired {
		retired[i] = fmt.Sprintf("retired-workload-%02d", i)
	}
	record := garagev1beta2.StorageRolloutStatus{
		NodeLocalPoolName: pool.Name, KubernetesNodeName: kubernetesNode.Name,
		GarageNodeUID: string(garageNode.UID), GarageNodeID: testGarageNodeID,
		KubernetesNodeUID: string(kubernetesNode.UID), WorkloadUID: "deleted-current-daemonset-uid",
		RetiredWorkloadUIDs: retired, PreviousPodUID: testPreviousPodUID,
		DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
	}
	cluster.Status.StorageRollout = &record
	if parsed, err := nodeLocalPoolRolloutRecordForCluster(cluster); err != nil || parsed == nil {
		t.Fatalf("exact rollout-history boundary was rejected: record=%+v err=%v", parsed, err)
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, kubernetesNode, garageNode).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
	}
	pending, err := reconciler.ensureStorageRolloutWorkload(ctx, cluster, record)
	if err == nil || pending || !strings.Contains(err.Error(), "maximum of 32 excluded controller incarnations") {
		t.Fatalf("33rd retired workload UID was not refused before creation: pending=%v err=%v", pending, err)
	}
	daemonSets := &appsv1.DaemonSetList{}
	if err := kubeClient.List(ctx, daemonSets, client.InNamespace(cluster.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(daemonSets.Items) != 0 {
		t.Fatalf("history-cap refusal created %d DaemonSet(s)", len(daemonSets.Items))
	}
	configMaps := &corev1.ConfigMapList{}
	if err := kubeClient.List(ctx, configMaps, client.InNamespace(cluster.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(configMaps.Items) != 0 {
		t.Fatalf("history-cap refusal published %d config resource(s)", len(configMaps.Items))
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(ctx, clientKey(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.StorageRollout == nil ||
		len(stored.Status.StorageRollout.RetiredWorkloadUIDs) != maximumStorageRolloutRetiredWorkloadUIDs {
		t.Fatalf("history-cap refusal did not retain the exact transaction: %#v", stored.Status.StorageRollout)
	}

	// A manager restart must reject an already-oversized status record before
	// any recovery state machine can act on an incomplete exclusion history.
	oversized := cluster.DeepCopy()
	oversized.Status.StorageRollout.RetiredWorkloadUIDs = append(
		append([]string(nil), retired...), "retired-workload-32",
	)
	if parsed, err := nodeLocalPoolRolloutRecordForCluster(oversized); err == nil || parsed != nil ||
		!strings.Contains(err.Error(), "above the supported maximum") {
		t.Fatalf("restart accepted oversized rollout history: record=%+v err=%v", parsed, err)
	}
}

func TestStorageRolloutRejectsReplacementGarageIdentityForGatewayActor(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testSiteA, Namespace: testGarageValue, UID: testClusterUID,
	}}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testGatewayNodeID, Namespace: cluster.Namespace, UID: testGarageNodeUID},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Gateway: true,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: "new-empty-gateway-id"},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: fakeClient}
	record := nodeLocalPoolRolloutRecord{
		GarageNodeName: testGatewayNodeID, GarageNodeUID: testGarageNodeUID, GarageNodeID: "original-gateway-id",
		WorkloadUID: testStatefulSetUID, PreviousPodUID: testOldPodUID,
		DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
	}
	if _, _, err := reconciler.readStorageRolloutActorIdentity(ctx, cluster, record); err == nil ||
		!strings.Contains(err.Error(), "changed Garage identity") {
		t.Fatalf("replacement gateway Garage identity was accepted: %v", err)
	}
}

func TestGarageNodeLayoutReadyRequiresFreshCommittedIdentity(t *testing.T) {
	node := &garagev1beta1.GarageNode{ObjectMeta: metav1.ObjectMeta{Generation: 2}}
	node.Status.Connected = true
	if garageNodeLayoutReady(node) {
		t.Fatal("Connected alone must not count a Manual GarageNode as ready")
	}
	node.Status.NodeID = "garage-node"
	node.Status.InLayout = true
	node.Status.ObservedGeneration = 1
	if garageNodeLayoutReady(node) {
		t.Fatal("stale status must not count a GarageNode as ready")
	}
	node.Status.ObservedGeneration = 2
	if !garageNodeLayoutReady(node) {
		t.Fatal("fresh NodeID/Connected/InLayout evidence should count as ready")
	}
}

func TestStorageRolloutRecoveryCompletesStatefulSetHandoffAfterRestart(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const namespace = testGarageValue
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: namespace, UID: testClusterUID},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				GarageNodeName: testSMBNodeName, PreviousPodUID: testOldPodUID,
				GarageNodeUID: testGarageNodeUID, GarageNodeID: testGarageNodeID, WorkloadUID: testStatefulSetUID,
				DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
				StatefulSetWorkloadRecreationSafe: true,
				PersistentVolumeClaims: []garagev1beta2.StorageRolloutPersistentVolumeClaimStatus{{
					Name: testSMBMetadataPVC, UID: testPVCUID,
				}},
			},
			Conditions: []metav1.Condition{{
				Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
				Reason: garagev1beta1.ReasonStorageRollingOut,
			}},
		},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testSMBNodeName, Namespace: namespace, UID: testGarageNodeUID, Generation: 1},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testGarageNodeID, Connected: true, InLayout: true,
			ObservedGeneration: 1, ObservedPodUID: "new-pod",
		},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: testSMBNodeName, Namespace: namespace, UID: testStatefulSetUID,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
			Name: node.Name, UID: node.UID, Controller: ptrTo(true),
		}},
	}, Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
		// Model an operator upgrade that already computes h2 while durable
		// recovery still owns h1. The recorded transaction must finish h1 first;
		// normal reconciliation can then select h2 as the next handoff.
		Annotations: map[string]string{
			annotationPodSpecHash: "later-h2",
			annotationConfigHash:  "later-config-h2",
		},
	}}}}
	pod := readyNodeLocalPoolPod(namespace, "smb-a-0", testKubernetesWorkerA, testNewSpecHash, testNewConfigHash, "new-pod")
	pod.Annotations[annotationConfigHash] = testNewConfigHash
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
		Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
	}}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: testSMBMetadataPVC, Namespace: namespace, UID: testPVCUID,
		Finalizers: []string{storageRolloutPVCFinalizer(cluster)},
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, node, statefulSet, pod, claim).Build()
	if err := fakeClient.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{
		Client:          fakeClient,
		LayoutMutations: NewLayoutMutationCoordinator(),
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			return healthyNodeLocalPoolRolloutState(testGarageNodeID), nil
		},
	}
	if err := rehydrateNodeLocalPoolRolloutsForOwner(
		ctx, fakeClient, reconciler.LayoutMutations, cluster, true,
	); err != nil {
		t.Fatalf("rehydrating StatefulSet rollout after restart: %v", err)
	}

	blocked, err := reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, map[string]*garagev1beta1.GarageNode{})
	if err != nil || blocked {
		t.Fatalf("StatefulSet replacement handoff did not recover: blocked=%v err=%v", blocked, err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(ctx, clientKey(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.StorageRollout != nil {
		t.Fatalf("completed handoff retained transaction state: %+v", stored.Status.StorageRollout)
	}
	if err := fakeClient.Get(ctx, clientKey(claim), claim); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(claim, storageRolloutPVCFinalizer(cluster)) {
		t.Fatalf("completed handoff retained PVC transaction protection: %v", claim.Finalizers)
	}
}

func TestGatewayObserverCannotClearReferencedStorageRolloutMarker(t *testing.T) {
	coordinator := NewLayoutMutationCoordinator()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	storage := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: tierStorage, Namespace: testGarageValue, UID: "storage-cluster-uid",
	}}
	gateway := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testEdgeValue, Namespace: testGarageValue, UID: "edge-cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			ClusterRef: &garagev1beta2.ClusterReference{Name: tierStorage},
		}},
	}
	key := layoutOwnerKey(gateway)
	coordinator.BeginNodeLocalPoolRollout(
		key, storage.UID, clientKey(storage), storage.UID,
	)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(storage, gateway).Build()
	reconciler := &GarageClusterReconciler{Client: fakeClient, APIReader: fakeClient, LayoutMutations: coordinator}
	if err := reconciler.finishNodeLocalPoolRolloutExclusion(context.Background(), gateway); err != nil {
		t.Fatalf("gateway observer finishing its empty local rollout: %v", err)
	}
	if !coordinator.NodeLocalPoolRolloutActive(key) {
		t.Fatal("gateway observer cleared the referenced storage owner's rollout marker")
	}
}

func TestStorageRolloutRecoveryClearsOnlyConfirmedStatusClearTail(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: testSiteA, Namespace: testGarageValue, UID: "site-a-uid",
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	coordinator := NewLayoutMutationCoordinator()
	key := layoutOwnerKey(cluster)
	if !coordinator.BeginNodeLocalPoolRollout(key, cluster.UID, clientKey(cluster), cluster.UID) ||
		!coordinator.ConfirmNodeLocalPoolRollout(key, cluster.UID) {
		t.Fatal("failed to construct confirmed status-clear crash tail")
	}
	reconciler := &GarageClusterReconciler{
		Client: fakeClient, APIReader: fakeClient, LayoutMutations: coordinator,
	}
	blocked, err := reconciler.recoverStorageRollout(ctx, cluster)
	if err != nil || blocked {
		t.Fatalf("confirmed status-clear tail did not self-heal: blocked=%v err=%v", blocked, err)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) {
		t.Fatal("confirmed marker remained after live source status proved the actor was clear")
	}

	if !coordinator.BeginNodeLocalPoolRollout(key, cluster.UID, clientKey(cluster), cluster.UID) {
		t.Fatal("failed to construct marker-before-status publication head")
	}
	blocked, err = reconciler.recoverStorageRollout(ctx, cluster)
	if err != nil || !blocked {
		t.Fatalf("unconfirmed marker publication head was mistaken for a clear tail: blocked=%v err=%v", blocked, err)
	}
	if !coordinator.NodeLocalPoolRolloutActive(key) {
		t.Fatal("unconfirmed publication marker was cleared by a concurrent reconcile")
	}
}

func TestStorageRolloutRecoveryFailsClosedWithoutPersistedActor(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: tierStorage, Namespace: testGarageValue},
		Status: garagev1beta2.GarageClusterStatus{Conditions: []metav1.Condition{{
			Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonStorageRollingOut,
		}}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster).Build()
	reconciler := &GarageClusterReconciler{Client: fakeClient, LayoutMutations: NewLayoutMutationCoordinator()}
	if err := fakeClient.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	blocked, err := reconciler.recoverStorageRollout(ctx, cluster)
	if err != nil {
		t.Fatalf("condition-only recovery returned an API error: %v", err)
	}
	if !blocked {
		t.Fatal("condition-only recovery released a handoff without previousPodUid evidence")
	}
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		!strings.Contains(condition.Message, "missing status.storageRollout") {
		t.Fatalf("condition-only recovery did not explain fail-closed state: %#v", condition)
	}
}

func TestStorageRolloutRecoveryRedrivesPreparedUnreadyStatefulSetDelete(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const namespace = testGarageValue
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: namespace, UID: testClusterUID},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				GarageNodeName: testSMBNodeName, PreviousPodUID: testOldPodUID,
				GarageNodeUID: testGarageNodeUID, GarageNodeID: testGarageNodeID, WorkloadUID: testStatefulSetUID,
				DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
			},
		},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testSMBNodeName, Namespace: namespace, UID: testGarageNodeUID, Generation: 1},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testGarageNodeID, InLayout: true, ObservedGeneration: 1, ObservedPodUID: testOldPodUID,
		},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: testSMBNodeName, Namespace: namespace, UID: testStatefulSetUID,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
			Name: node.Name, UID: node.UID, Controller: ptrTo(true),
		}},
	}}
	pod := readyNodeLocalPoolPod(namespace, "smb-a-0", testKubernetesWorkerA, "old-spec", "old-config", testOldPodUID)
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
		Name: statefulSet.Name, UID: statefulSet.UID, Controller: ptrTo(true),
	}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, node, statefulSet, pod).Build()
	if err := fakeClient.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{
		Client:          fakeClient,
		LayoutMutations: NewLayoutMutationCoordinator(),
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			state := healthyNodeLocalPoolRolloutState()
			state.health.Status = testDegradedMode
			return state, nil
		},
	}
	if err := rehydrateNodeLocalPoolRolloutsForOwner(
		ctx, fakeClient, reconciler.LayoutMutations, cluster, true,
	); err != nil {
		t.Fatalf("rehydrating prepared StatefulSet rollout after restart: %v", err)
	}

	blocked, err := reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, map[string]*garagev1beta1.GarageNode{})
	if err != nil || !blocked {
		t.Fatalf("prepared Delete was not safely re-driven: blocked=%v err=%v", blocked, err)
	}
	if err := fakeClient.Get(ctx, clientKey(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("exact prepared old pod UID was not deleted: %v", err)
	}
}

func TestStorageRolloutRecoveryAllowsDeletingNonCandidateWithExactReadyPod(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme,
		corev1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	const (
		namespace         = testGarageValue
		nodeLocalPoolName = testTagLocal
	)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testSiteA, Namespace: namespace, UID: testClusterUID},
		Status: garagev1beta2.GarageClusterStatus{
			StorageRollout: &garagev1beta2.StorageRolloutStatus{
				NodeLocalPoolName: nodeLocalPoolName, KubernetesNodeName: testKubernetesNodeA, PreviousPodUID: "old-pod-a",
				GarageNodeUID: "gn-a-uid", GarageNodeID: testGarageNodeID, WorkloadUID: testDaemonSetUID, KubernetesNodeUID: "node-a-uid",
				DesiredPodSpecHash: testNewSpecHash, DesiredConfigHash: testNewConfigHash,
			},
		},
	}
	daemonSet := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name: storageDaemonSetName(cluster, nodeLocalPoolName), Namespace: namespace, UID: testDaemonSetUID,
		Labels: map[string]string{labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
			Name: cluster.Name, UID: cluster.UID, Controller: ptrTo(true),
		}},
	}}
	podA := readyNodeLocalPoolPod(namespace, "pool-node-a", testKubernetesNodeA, testNewSpecHash, testNewConfigHash, "new-pod-a")
	podB := readyNodeLocalPoolPod(namespace, "pool-node-b", testKubernetesNodeB, "current-spec", "current-config", "pod-b")
	for _, pod := range []*corev1.Pod{podA, podB} {
		pod.Labels = map[string]string{labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: nodeLocalPoolName}
		pod.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: appsv1.SchemeGroupVersion.String(), Kind: daemonSetKind,
			Name: daemonSet.Name, UID: daemonSet.UID, Controller: ptrTo(true),
		}}
	}
	podA.Annotations[annotationConfigHash] = testNewConfigHash
	podB.Annotations[annotationConfigHash] = "current-config"
	nodeA := readyNodeLocalPoolGarageNode("gn-a", nodeLocalPoolName, testKubernetesNodeA, testGarageNodeID, podA)
	nodeB := readyNodeLocalPoolGarageNode("gn-b", nodeLocalPoolName, testKubernetesNodeB, "garage-b", podB)
	nodeA.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: cluster.Name}
	nodeB.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: cluster.Name}
	deletingAt := metav1.Now()
	nodeB.DeletionTimestamp = &deletingAt
	nodeB.Finalizers = []string{garageNodeFinalizer}
	kubernetesNodeA := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testKubernetesNodeA, UID: "node-a-uid"}}
	kubernetesNodeB := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: testKubernetesNodeB, UID: "node-b-uid"}}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster, daemonSet, podA, podB, nodeA, nodeB, kubernetesNodeA, kubernetesNodeB).Build()
	if err := fakeClient.Get(ctx, clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{
		Client: fakeClient, LayoutMutations: NewLayoutMutationCoordinator(),
		nodeLocalPoolRolloutStateGetter: func(context.Context, *garagev1beta2.GarageCluster) (*nodeLocalPoolRolloutGarageState, error) {
			return healthyNodeLocalPoolRolloutState(testGarageNodeID, "garage-b"), nil
		},
	}
	if err := rehydrateNodeLocalPoolRolloutsForOwner(
		ctx, fakeClient, reconciler.LayoutMutations, cluster, true,
	); err != nil {
		t.Fatalf("rehydrating node-local rollout with deleting non-candidate: %v", err)
	}
	existing := map[string]*garagev1beta1.GarageNode{
		nodeLocalPoolKey(nodeLocalPoolName, testKubernetesNodeA): nodeA,
		nodeLocalPoolKey(nodeLocalPoolName, testKubernetesNodeB): nodeB,
	}

	blocked, err := reconciler.recoverNodeLocalPoolRolloutExclusion(ctx, cluster, existing)
	if err != nil || blocked {
		t.Fatalf("deleting Ready non-candidate deadlocked rollout recovery: blocked=%v err=%v", blocked, err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := fakeClient.Get(ctx, clientKey(cluster), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.StorageRollout != nil {
		t.Fatalf("completed rollout retained actor while another GarageNode waits to drain: %+v", stored.Status.StorageRollout)
	}
	if err := fakeClient.Get(ctx, clientKey(podB), &corev1.Pod{}); err != nil {
		t.Fatalf("non-candidate deleting GarageNode pod should stay online until its finalizer drains next: %v", err)
	}
}

func ptrTo[T any](value T) *T { return &value }

func clientKey(object client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
}
