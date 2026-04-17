package controller

import (
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestMonitoringCRDExists(t *testing.T) {
	t.Run("returns false when ServiceMonitor CRD not installed", func(t *testing.T) {
		s := runtime.NewScheme()
		_ = garagev1alpha1.AddToScheme(s)
		rm := meta.NewDefaultRESTMapper(nil)
		fakeClient := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(rm).Build()
		r := &GarageClusterReconciler{Client: fakeClient, Scheme: s}
		if r.monitoringCRDExists() {
			t.Error("monitoringCRDExists() = true, want false when CRD not installed")
		}
	})

	t.Run("returns true when ServiceMonitor CRD installed", func(t *testing.T) {
		s := runtime.NewScheme()
		_ = garagev1alpha1.AddToScheme(s)
		_ = monitoringv1.AddToScheme(s)
		rm := meta.NewDefaultRESTMapper([]schema.GroupVersion{monitoringv1.SchemeGroupVersion})
		rm.Add(monitoringv1.SchemeGroupVersion.WithKind("ServiceMonitor"), meta.RESTScopeNamespace)
		fakeClient := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(rm).Build()
		r := &GarageClusterReconciler{Client: fakeClient, Scheme: s}
		if !r.monitoringCRDExists() {
			t.Error("monitoringCRDExists() = false, want true when CRD installed")
		}
	})
}
