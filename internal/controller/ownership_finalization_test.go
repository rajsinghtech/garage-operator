package controller

import (
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestFinalizeNeverReadyClusterSkipsForeignSameNameResources(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		appsv1.AddToScheme,
		policyv1.AddToScheme,
		monitoringv1.AddToScheme,
		garagev1beta1.AddToScheme,
		garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	const (
		name      = "foreign-collision"
		namespace = "default"
	)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			UID:        types.UID("cluster-uid"),
			Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			DeletionPolicy: garagev1beta2.DeletionPolicyDestroy,
			Replication:    &garagev1beta2.ReplicationConfig{Factor: 1},
			Storage:        &garagev1beta2.StorageSpec{Replicas: 1},
		},
	}
	foreignLabels := map[string]string{"foreign-owner": "true"}
	objects := []client.Object{
		cluster,
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: foreignLabels}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: foreignLabels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: foreignLabels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-gateway", Namespace: namespace, Labels: foreignLabels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-ready", Namespace: namespace, Labels: foreignLabels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-headless", Namespace: namespace, Labels: foreignLabels}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: foreignLabels}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name + "-gateway", Namespace: namespace, Labels: foreignLabels}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{Name: name + "-garage", Namespace: namespace, Labels: foreignLabels}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	stored := &garagev1beta2.GarageCluster{}
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(t.Context(), key, stored); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), stored); err != nil {
		t.Fatal(err)
	}

	r := &GarageClusterReconciler{
		Client:          c,
		APIReader:       c,
		Scheme:          scheme,
		WatchNamespaces: []string{namespace},
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("finalize never-ready cluster: %v", err)
	}
	remaining := &garagev1beta2.GarageCluster{}
	if err := c.Get(t.Context(), key, remaining); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	} else if controllerutil.ContainsFinalizer(remaining, garageClusterFinalizer) {
		t.Fatalf("GarageCluster finalizer was not removed: %v", remaining.Finalizers)
	}

	for _, object := range objects[1:] {
		fresh := object.DeepCopyObject().(client.Object)
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(object), fresh); err != nil {
			t.Errorf("foreign %T %s was deleted: %v", object, client.ObjectKeyFromObject(object), err)
			continue
		}
		if fresh.GetLabels()["foreign-owner"] != "true" || len(fresh.GetOwnerReferences()) != 0 {
			t.Errorf("foreign %T %s was mutated: labels=%v owners=%v", object, client.ObjectKeyFromObject(object), fresh.GetLabels(), fresh.GetOwnerReferences())
		}
	}
}
