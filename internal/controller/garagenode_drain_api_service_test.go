package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func drainAPIServiceTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("core scheme: %v", err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("v1beta1 scheme: %v", err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("v1beta2 scheme: %v", err)
	}
	return scheme
}

func TestGarageNodeExcludedFromAPIService(t *testing.T) {
	t.Parallel()

	storage := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Annotations: map[string]string{}},
	}
	if garageNodeExcludedFromAPIService(storage) {
		t.Fatal("storage without drain annotation must stay in the API Service")
	}

	storage.Annotations[garagev1beta1.AnnotationDrain] = annotationTrue
	if !garageNodeExcludedFromAPIService(storage) {
		t.Fatal("drain-annotated storage node must leave the API Service (#535)")
	}

	gateway := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "gw",
			Annotations: map[string]string{garagev1beta1.AnnotationDrain: annotationTrue},
		},
		Spec: garagev1beta1.GarageNodeSpec{Gateway: true},
	}
	if garageNodeExcludedFromAPIService(gateway) {
		t.Fatal("gateway pods must keep tier=gateway even when drain-annotated")
	}

	external := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ext",
			Annotations: map[string]string{garagev1beta1.AnnotationDrain: annotationTrue},
		},
		Spec: garagev1beta1.GarageNodeSpec{External: &garagev1beta1.ExternalNodeConfig{Address: "10.0.0.1"}},
	}
	if garageNodeExcludedFromAPIService(external) {
		t.Fatal("external nodes have no managed Pod to exclude")
	}
}

// TestReconcileDrainAPIServiceExclusion patches the live Pod's tier label while
// the StatefulSet reconcile path is frozen during an annotated drain (#535).
func TestReconcileDrainAPIServiceExclusion(t *testing.T) {
	t.Parallel()
	scheme := drainAPIServiceTestScheme(t)
	const (
		ns   = "drain-api-ns"
		name = "drain-api-storage-0"
	)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "drain-api", Namespace: ns, UID: types.UID("cluster-uid")},
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID("node-uid"),
			Annotations: map[string]string{
				garagev1beta1.AnnotationDrain: annotationTrue,
			},
		},
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID("sts-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta1.GroupVersion.String(),
				Kind:       kindGarageNode,
				Name:       node.Name,
				UID:        node.UID,
				Controller: ptr.To(true),
			}},
		},
		Spec: appsv1.StatefulSetSpec{Replicas: ptr.To[int32](1)},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-0",
			Namespace: ns,
			UID:       types.UID("pod-uid"),
			Labels: map[string]string{
				labelCluster: cluster.Name,
				labelTier:    tierStorage,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       kindStatefulSet,
				Name:       sts.Name,
				UID:        sts.UID,
				Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: defaultAppName, Image: "garage:test"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.1.0.5"},
	}

	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, node, sts, pod).Build()
	r := &GarageNodeReconciler{Client: kube, Scheme: scheme}

	if err := r.reconcileDrainAPIServiceExclusion(context.Background(), node, cluster); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	got := &corev1.Pod{}
	if err := kube.Get(context.Background(), types.NamespacedName{Name: pod.Name, Namespace: ns}, got); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if got.Labels[labelTier] != tierDraining {
		t.Fatalf("tier after drain exclude = %q, want %q", got.Labels[labelTier], tierDraining)
	}

	// Clearing the drain annotation must restore tier=storage so the Pod re-enters
	// the API Service selector.
	delete(node.Annotations, garagev1beta1.AnnotationDrain)
	if err := r.reconcileDrainAPIServiceExclusion(context.Background(), node, cluster); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(pod), got); err != nil {
		t.Fatalf("get restored pod: %v", err)
	}
	if got.Labels[labelTier] != tierStorage {
		t.Fatalf("tier after drain clear = %q, want %q", got.Labels[labelTier], tierStorage)
	}
}
