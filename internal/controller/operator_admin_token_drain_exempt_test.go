package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestGarageNodeExemptFromAdminAndRolloutProof(t *testing.T) {
	t.Parallel()

	base := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Annotations: map[string]string{}},
		Status:     garagev1beta1.GarageNodeStatus{InLayout: true},
	}
	if garageNodeExemptFromAdminAndRolloutProof(base) {
		t.Fatal("ordinary InLayout node must not be exempt")
	}

	drainingOut := base.DeepCopy()
	drainingOut.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
	drainingOut.Status.InLayout = false
	if !garageNodeExemptFromAdminAndRolloutProof(drainingOut) {
		t.Fatal("drain-annotated out-of-layout node must be exempt (#544)")
	}

	drainPrepared := base.DeepCopy()
	drainPrepared.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
	drainPrepared.Status.InLayout = true
	drainPrepared.Status.Conditions = []metav1.Condition{{
		Type: garagev1beta1.ConditionDrainPrepared, Status: metav1.ConditionTrue,
	}}
	if !garageNodeExemptFromAdminAndRolloutProof(drainPrepared) {
		t.Fatal("DrainPrepared node must be exempt even if InLayout is stale (#544)")
	}

	suspendedOut := base.DeepCopy()
	suspendedOut.Spec.Maintenance = &garagev1beta1.NodeMaintenanceSpec{Suspended: true}
	suspendedOut.Status.InLayout = false
	if !garageNodeExemptFromAdminAndRolloutProof(suspendedOut) {
		t.Fatal("maintenance-suspended out-of-layout node must be exempt (#544)")
	}

	drainStillInLayout := base.DeepCopy()
	drainStillInLayout.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
	if garageNodeExemptFromAdminAndRolloutProof(drainStillInLayout) {
		t.Fatal("drain-annotated node still InLayout (pre-role-removal) must stay in the proof set")
	}
}

// TestExpectedOperatorAdminPodSetExemptsDrainingOutOfLayoutNode ensures a
// drain-annotated GarageNode that has left the layout does not poison the
// operator Admin Pod-set (replicas!=1 or 403-only Pod) while its Pod remains
// accounted so strangers cannot join the shared Service (#544).
func TestExpectedOperatorAdminPodSetExemptsDrainingOutOfLayoutNode(t *testing.T) {
	t.Parallel()
	scheme := operatorPodSetTestScheme(t)
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage", Namespace: testOperatorPodSetNamespace, UID: types.UID("cluster-uid"),
		},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{}},
	}

	keep := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage-0", Namespace: cluster.Namespace, UID: types.UID("keep-node"),
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Zone: "a",
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: testTerminalNodeID, Connected: true, InLayout: true,
		},
	}
	keepSTS := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: keep.Name, Namespace: keep.Namespace, UID: types.UID("keep-sts"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: keep.Name, UID: keep.UID, Controller: &controller,
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
	}
	keepPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: keep.Name + "-0", Namespace: keep.Namespace, UID: types.UID("keep-pod"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: keepSTS.Name, UID: keepSTS.UID, Controller: &controller,
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: defaultAppName,
			Env: []corev1.EnvVar{{
				Name: envGarageAdminToken,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: testStaticRevisionSecret},
					Key:                  DefaultAdminTokenKey,
				}},
			}},
		}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.0.0.1",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}

	drain := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage-1", Namespace: cluster.Namespace, UID: types.UID("drain-node"),
			Annotations: map[string]string{garagev1beta1.AnnotationDrain: annotationTrue},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}, Zone: "a",
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			InLayout: false,
		},
	}
	drainSTS := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: drain.Name, Namespace: drain.Namespace, UID: types.UID("drain-sts"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(), Kind: kindGarageNode,
				Name: drain.Name, UID: drain.UID, Controller: &controller,
			}},
		},
		// Scaled to 0 by a lost-source fence — must not fail the pod-set (#544).
		Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(int32(0))},
	}
	drainPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: drain.Name + "-0", Namespace: drain.Namespace, UID: types.UID("drain-pod"),
			Labels: map[string]string{labelCluster: cluster.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(), Kind: kindStatefulSet,
				Name: drainSTS.Name, UID: drainSTS.UID, Controller: &controller,
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.0.0.2",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}

	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		cluster, keep, keepSTS, keepPod, drain, drainSTS, drainPod,
	).Build()

	set, err := expectedOperatorAdminPodSet(context.Background(), kube, cluster)
	if err != nil {
		t.Fatalf("pod set with draining out-of-layout node: %v", err)
	}
	if len(set.Pods) != 1 || set.Pods[0].UID != keepPod.UID {
		t.Fatalf("expected only the InLayout Pod in the proof set, got %+v", set.Pods)
	}

	// A foreign cluster-labelled Pod must still be rejected.
	if err := kube.Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stranger", Namespace: cluster.Namespace, UID: types.UID("stranger"),
			Labels: map[string]string{labelCluster: cluster.Name},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := expectedOperatorAdminPodSet(context.Background(), kube, cluster); err == nil {
		t.Fatal("unaccounted stranger Pod was accepted")
	}
}
