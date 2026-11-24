package controller

import (
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestMonitoringCRDExists(t *testing.T) {
	t.Run("returns false when ServiceMonitor CRD not installed", func(t *testing.T) {
		s := runtime.NewScheme()
		_ = garagev1beta1.AddToScheme(s)
		_ = garagev1beta2.AddToScheme(s)
		rm := meta.NewDefaultRESTMapper(nil)
		fakeClient := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(rm).Build()
		r := &GarageClusterReconciler{Client: fakeClient, Scheme: s}
		if r.monitoringCRDExists() {
			t.Error("monitoringCRDExists() = true, want false when CRD not installed")
		}
	})

	t.Run("returns true when ServiceMonitor CRD installed", func(t *testing.T) {
		s := runtime.NewScheme()
		_ = garagev1beta1.AddToScheme(s)
		_ = garagev1beta2.AddToScheme(s)
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

func TestServiceMonitorSelectorExcludesReadyAPIService(t *testing.T) {
	s := runtime.NewScheme()
	if err := garagev1beta2.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := monitoringv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	r := &GarageClusterReconciler{Scheme: s}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: "default"},
		Spec: garagev1beta2.GarageClusterSpec{
			Monitoring: &garagev1beta2.MonitoringSpec{Enabled: ptr.To(true)},
			Storage:    &garagev1beta2.StorageSpec{Replicas: 3},
			Gateway:    &garagev1beta2.GatewaySpec{Replicas: 2},
		},
	}

	sm := r.buildServiceMonitor(cluster, cluster.Name+"-garage", cluster.Namespace)
	selector, err := metav1.LabelSelectorAsSelector(&sm.Spec.Selector)
	if err != nil {
		t.Fatalf("LabelSelectorAsSelector: %v", err)
	}

	primary := r.labelsForCluster(cluster)
	ready := r.labelsForCluster(cluster)
	ready[labelServiceRole] = serviceRoleReadyAPI
	gateway := r.labelsForTier(cluster, tierGateway)

	cases := []struct {
		name      string
		labels    map[string]string
		wantMatch bool
	}{
		{name: "<cr>", labels: primary, wantMatch: true},
		{name: "<cr>-gateway", labels: gateway, wantMatch: true},
		{name: "<cr>-ready", labels: ready, wantMatch: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched := selector.Matches(labels.Set(tc.labels))
			if matched != tc.wantMatch {
				t.Fatalf("selector.Matches(%s) = %v, want %v (labels=%v selector=%s)",
					tc.name, matched, tc.wantMatch, tc.labels, selector)
			}
		})
	}
}
