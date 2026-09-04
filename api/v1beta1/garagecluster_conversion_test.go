/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"context"
	"reflect"
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func ptrQuantity(q resource.Quantity) *resource.Quantity { return &q }

// Test fixtures shared across the conversion tests. Centralized to keep goconst happy.
const (
	testZone          = "us-east-1"
	testImage         = "dxflrs/garage:v2.3.0"
	testNS            = "ns"
	testRole          = "role"
	testStorage       = "storage"
	testStoreCR       = "store"
	test10Gi          = "10Gi"
	testConsist       = consistencyModeConsistent
	testRelabel       = "rpc_duration_.*"
	testAdminEndpoint = "http://garage.garage.svc:3903"
	testHandleName    = "handle"
	testAdminSecret   = "admin"
)

// TestConvertTo_StorageCluster: v1beta1 storage CR -> v1beta2 storage tier.
func TestConvertTo_StorageCluster(t *testing.T) {
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Image:    testImage,
			Replicas: 3,
			Zone:     testZone,
			Replication: &ReplicationConfig{
				Factor: 3, ConsistencyMode: testConsist,
			},
			Storage: StorageConfig{
				Metadata:      &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:          &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				MetadataFsync: true,
			},
			Network: NetworkConfig{
				RPCBindPort: 3901,
			},
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{"cpu": resource.MustParse("2")},
			},
			NodeSelector: map[string]string{testRole: testStorage},
			Gateway:      false,
		},
	}

	dst := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(dst); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}

	if dst.Spec.Storage == nil {
		t.Fatalf("expected storage tier set on v1beta2")
	}
	if dst.Spec.Gateway != nil {
		t.Fatalf("did not expect gateway tier on storage-only CR")
	}
	if dst.Spec.Storage.Replicas != 3 {
		t.Errorf("storage.replicas: got %d want 3", dst.Spec.Storage.Replicas)
	}
	if dst.Spec.Storage.Metadata == nil || dst.Spec.Storage.Metadata.Size == nil ||
		dst.Spec.Storage.Metadata.Size.String() != test10Gi {
		t.Errorf("storage.metadata.size not copied")
	}
	if dst.Spec.Storage.Data == nil || dst.Spec.Storage.Data.Size == nil ||
		dst.Spec.Storage.Data.Size.String() != "100Gi" {
		t.Errorf("storage.data.size not copied")
	}
	if !dst.Spec.Storage.MetadataFsync {
		t.Errorf("storage.metadataFsync not copied")
	}
	if dst.Spec.Network.RPCBindPort != 3901 {
		t.Errorf("network.rpcBindPort not copied")
	}
	if got := dst.Spec.Storage.NodeSelector[testRole]; got != testStorage {
		t.Errorf("storage.podTemplate.nodeSelector: got %q want storage", got)
	}
	if dst.Spec.Storage.Resources.Limits.Cpu().String() != "2" {
		t.Errorf("storage.podTemplate.resources not copied")
	}
}

func TestConvert_DataSourceRefRoundTrip(t *testing.T) {
	group := "kopiur.example.io"
	ref := &corev1.TypedObjectReference{
		APIGroup: &group,
		Kind:     "Restore",
		Name:     "restore",
	}
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi")), DataSourceRef: ref},
			},
		},
	}

	hub := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(hub); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if hub.Spec.Storage == nil {
		t.Fatalf("ConvertTo lost storage: %#v", hub.Spec.Storage)
	}
	if !reflect.DeepEqual(hub.Spec.Storage.Data.DataSourceRef, ref) {
		t.Fatalf("ConvertTo changed dataSourceRef: got %#v want %#v", hub.Spec.Storage.Data.DataSourceRef, ref)
	}

	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if !reflect.DeepEqual(spoke.Spec.Storage.Data.DataSourceRef, ref) {
		t.Fatalf("ConvertFrom changed dataSourceRef: got %#v want %#v", spoke.Spec.Storage.Data.DataSourceRef, ref)
	}
}

// TestConvert_StorageRPCPublicAddrRoundTrip: spec.storage.rpcPublicAddr must
// survive a v1beta1 -> v1beta2 -> v1beta1 round-trip (lossless invariant).
func TestConvert_StorageRPCPublicAddrRoundTrip(t *testing.T) {
	const addr = "stg-{ordinal}.example.ts.net:3901"
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Zone:     testZone,
			Storage: StorageConfig{
				Metadata:      &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:          &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				RPCPublicAddr: addr,
				LayoutPolicy:  layoutPolicyManual,
			},
		},
	}

	up := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if up.Spec.Storage == nil {
		t.Fatalf("v1beta2 storage tier missing after ConvertTo")
	}
	if up.Spec.Storage.RPCPublicAddr != addr {
		t.Fatalf("v1beta2 storage.rpcPublicAddr: got %q want %q", up.Spec.Storage.RPCPublicAddr, addr)
	}
	if up.Spec.Storage.LayoutPolicy != layoutPolicyManual {
		t.Fatalf("v1beta2 storage.layoutPolicy: got %q want Manual", up.Spec.Storage.LayoutPolicy)
	}

	down := &GarageCluster{}
	if err := down.ConvertFrom(up); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Spec.Storage.RPCPublicAddr != addr {
		t.Fatalf("round-trip lost storage.rpcPublicAddr: got %q want %q", down.Spec.Storage.RPCPublicAddr, addr)
	}
	if down.Spec.Storage.LayoutPolicy != layoutPolicyManual {
		t.Fatalf("round-trip lost storage.layoutPolicy: got %q want Manual", down.Spec.Storage.LayoutPolicy)
	}
}

// TestConvert_MonitoringMetricRelabelingsRoundTrip: monitoring.metricRelabelings
// must survive a v1beta1 -> v1beta2 -> v1beta1 round-trip (the JSON-copy
// conversion preserves it because both versions carry the field).
func TestConvert_MonitoringMetricRelabelingsRoundTrip(t *testing.T) {
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Zone:     testZone,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
			Monitoring: &MonitoringSpec{
				Enabled: ptrBool(true),
				MetricRelabelings: []monitoringv1.RelabelConfig{{
					Action:       "drop",
					SourceLabels: []monitoringv1.LabelName{"__name__"},
					Regex:        testRelabel,
				}},
			},
		},
	}

	up := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if up.Spec.Monitoring == nil || len(up.Spec.Monitoring.MetricRelabelings) != 1 {
		t.Fatalf("v1beta2 monitoring.metricRelabelings missing after ConvertTo")
	}
	if up.Spec.Monitoring.MetricRelabelings[0].Regex != testRelabel {
		t.Fatalf("v1beta2 metricRelabelings regex: got %q", up.Spec.Monitoring.MetricRelabelings[0].Regex)
	}

	down := &GarageCluster{}
	if err := down.ConvertFrom(up); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Spec.Monitoring == nil || len(down.Spec.Monitoring.MetricRelabelings) != 1 {
		t.Fatalf("round-trip lost monitoring.metricRelabelings")
	}
	if down.Spec.Monitoring.MetricRelabelings[0].Regex != testRelabel {
		t.Errorf("round-trip metricRelabelings regex: got %q want rpc_duration_.*", down.Spec.Monitoring.MetricRelabelings[0].Regex)
	}
}

// TestConvertTo_GatewayCluster: v1beta1 gateway=true CR with connectTo -> v1beta2 edge gateway.
func TestConvertTo_GatewayCluster(t *testing.T) {
	metadataSize := resource.MustParse("2Gi")
	storageClass := "gateway-fast"
	minAvailable := intstr.FromInt32(1)
	metadata := &VolumeConfig{
		Size:             &metadataSize,
		StorageClassName: &storageClass,
		AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
			testDiskNameLabelKey: testEdgeMetadataValue,
		}},
		Labels:      map[string]string{"claim.example.com/tier": gatewayValue},
		Annotations: map[string]string{"claim.example.com/owner": testEdgeValue},
	}
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: GarageClusterSpec{
			Gateway:  true,
			Replicas: 2,
			Storage: StorageConfig{
				Metadata: metadata,
				PVCRetentionPolicy: &PVCRetentionPolicy{
					WhenDeleted: testRetainValue, WhenScaled: testDeleteValue,
				},
			},
			PodDisruptionBudget: &PodDisruptionBudgetConfig{
				Enabled: true, MinAvailable: &minAvailable,
			},
			ConnectTo: &ConnectToConfig{
				ClusterRef: &ClusterReference{Name: testStoreCR, Namespace: testNS},
			},
		},
	}
	dst := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(dst); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if dst.Spec.Gateway == nil {
		t.Fatalf("expected gateway tier set")
	}
	if dst.Spec.Storage != nil {
		t.Fatalf("did not expect storage tier on gateway-only CR")
	}
	if dst.Spec.Gateway.Replicas != 2 {
		t.Errorf("gateway.replicas: got %d want 2", dst.Spec.Gateway.Replicas)
	}
	expectedMetadata := &v1beta2.VolumeConfig{}
	if err := copyJSON(metadata, expectedMetadata); err != nil {
		t.Fatalf("building expected gateway metadata: %v", err)
	}
	if !reflect.DeepEqual(dst.Spec.Gateway.Metadata, expectedMetadata) {
		t.Fatalf("released v1beta1 gateway metadata contract was not projected:\n got: %#v\nwant: %#v", dst.Spec.Gateway.Metadata, expectedMetadata)
	}
	if dst.Spec.Gateway.PodDisruptionBudget == nil || !dst.Spec.Gateway.PodDisruptionBudget.Enabled ||
		dst.Spec.Gateway.PodDisruptionBudget.MinAvailable == nil ||
		dst.Spec.Gateway.PodDisruptionBudget.MinAvailable.IntVal != 1 {
		t.Fatalf("v1beta1 gateway PodDisruptionBudget was not projected: %#v", dst.Spec.Gateway.PodDisruptionBudget)
	}
	if dst.Spec.Gateway.PVCRetentionPolicy == nil ||
		dst.Spec.Gateway.PVCRetentionPolicy.WhenDeleted != testRetainValue ||
		dst.Spec.Gateway.PVCRetentionPolicy.WhenScaled != testDeleteValue {
		t.Fatalf("released v1beta1 gateway PVC retention policy was not projected: %#v", dst.Spec.Gateway.PVCRetentionPolicy)
	}
	if dst.Spec.ConnectTo == nil || dst.Spec.ConnectTo.ClusterRef == nil ||
		dst.Spec.ConnectTo.ClusterRef.Name != testStoreCR {
		t.Errorf("connectTo not copied")
	}
}

// TestConvertFrom_StorageCluster: v1beta2 storage-only CR -> v1beta1.
func TestConvertFrom_StorageCluster(t *testing.T) {
	src := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Image: testImage,
			Storage: &v1beta2.StorageSpec{
				Replicas:      3,
				Metadata:      &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:          &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				MetadataFsync: true,
				PodTemplate: v1beta2.PodTemplate{
					NodeSelector: map[string]string{testRole: testStorage},
				},
			},
			Zone: testZone,
		},
	}
	dst := &GarageCluster{}
	if err := dst.ConvertFrom(src); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if dst.Spec.Gateway {
		t.Fatalf("expected gateway=false on storage-only CR")
	}
	if dst.Spec.Replicas != 3 {
		t.Errorf("replicas: got %d want 3", dst.Spec.Replicas)
	}
	if dst.Spec.Storage.Metadata == nil || dst.Spec.Storage.Metadata.Size.String() != test10Gi {
		t.Errorf("storage.metadata not copied")
	}
	if dst.Spec.NodeSelector[testRole] != testStorage {
		t.Errorf("nodeSelector not lifted from podTemplate")
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Errorf("annotated lossy-conversion on non-lossy round-trip")
	}
}

// TestConvertFrom_GatewayOnlyCluster: v1beta2 edge gateway -> v1beta1.
func TestConvertFrom_GatewayOnlyCluster(t *testing.T) {
	metadataSize := resource.MustParse("2Gi")
	storageClass := "gateway-fast"
	maxUnavailable := intstr.FromString("25%")
	src := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Gateway: &v1beta2.GatewaySpec{
				Replicas: 2,
				Metadata: &v1beta2.VolumeConfig{
					Size:             &metadataSize,
					StorageClassName: &storageClass,
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
						testDiskNameLabelKey: testEdgeMetadataValue,
					}},
					Labels:      map[string]string{"claim.example.com/tier": gatewayValue},
					Annotations: map[string]string{"claim.example.com/owner": testEdgeValue},
				},
				PodDisruptionBudget: &v1beta2.PodDisruptionBudgetConfig{
					Enabled: true, MaxUnavailable: &maxUnavailable,
				},
				PVCRetentionPolicy: &v1beta2.PVCRetentionPolicy{
					WhenDeleted: testRetainValue, WhenScaled: testDeleteValue,
				},
			},
			ConnectTo: &v1beta2.ConnectToConfig{
				ClusterRef: &v1beta2.ClusterReference{Name: testStoreCR},
			},
		},
	}
	dst := &GarageCluster{}
	if err := dst.ConvertFrom(src); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if !dst.Spec.Gateway {
		t.Fatalf("expected gateway=true")
	}
	if dst.Spec.Replicas != 2 {
		t.Errorf("replicas: got %d want 2", dst.Spec.Replicas)
	}
	if dst.Spec.ConnectTo == nil || dst.Spec.ConnectTo.ClusterRef == nil {
		t.Errorf("connectTo not preserved")
	}
	if dst.Spec.Storage.Metadata == nil || dst.Spec.Storage.Metadata.Selector == nil ||
		dst.Spec.Storage.Metadata.Selector.MatchLabels[testDiskNameLabelKey] != testEdgeMetadataValue {
		t.Fatalf("v1beta2 gateway metadata was not projected into the released v1beta1 field: %#v", dst.Spec.Storage.Metadata)
	}
	if dst.Spec.PodDisruptionBudget == nil || dst.Spec.PodDisruptionBudget.MaxUnavailable == nil ||
		dst.Spec.PodDisruptionBudget.MaxUnavailable.StrVal != "25%" {
		t.Fatalf("gateway PDB was not projected into v1beta1: %#v", dst.Spec.PodDisruptionBudget)
	}
	if dst.Spec.Storage.PVCRetentionPolicy == nil ||
		dst.Spec.Storage.PVCRetentionPolicy.WhenDeleted != testRetainValue ||
		dst.Spec.Storage.PVCRetentionPolicy.WhenScaled != testDeleteValue {
		t.Fatalf("gateway PVC retention was not projected into v1beta1: %#v", dst.Spec.Storage.PVCRetentionPolicy)
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] != "" ||
		dst.Annotations[v1beta2AnnotationGatewayTierData] != "" {
		t.Fatalf("plain v1beta1-representable edge gateway received reserved conversion payload: %#v", dst.Annotations)
	}
	roundTripped := &v1beta2.GarageCluster{}
	if err := dst.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Gateway, src.Spec.Gateway) {
		t.Fatalf("plain edge gateway changed after payload-free round trip:\n got: %#v\nwant: %#v", roundTripped.Spec.Gateway, src.Spec.Gateway)
	}
}

func TestConvertRoundTrip_RichEdgeGatewayPreservesV1Beta2OnlyFields(t *testing.T) {
	original := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "rich-edge", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Gateway: &v1beta2.GatewaySpec{
				Replicas:      2,
				RPCPublicAddr: "edge.example.net:3901",
				Metadata:      &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("2Gi"))},
				PodDisruptionBudget: &v1beta2.PodDisruptionBudgetConfig{
					Enabled: true,
				},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt32(3903)},
				}},
				PodTemplate: v1beta2.PodTemplate{
					NodeSelector:   map[string]string{testWorkloadLabelKey: testEdgeValue},
					PodAnnotations: map[string]string{"example.net/gateway": stringTrue},
					Env:            []corev1.EnvVar{{Name: garageAllowWorldReadableSecretsEnv, Value: stringTrue}},
					EnvFrom: []corev1.EnvFromSource{{
						ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "gateway-env"}},
					}},
				},
			},
			ConnectTo: &v1beta2.ConnectToConfig{
				ClusterRef: &v1beta2.ClusterReference{Name: testStoreCR},
			},
		},
	}

	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(original); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if spoke.Annotations[v1beta2AnnotationGatewayTierData] == "" {
		t.Fatal("rich edge gateway did not receive its lossless conversion payload")
	}
	if spoke.Spec.Storage.Metadata == nil || spoke.Spec.Storage.Metadata.Size == nil ||
		spoke.Spec.Storage.Metadata.Size.Cmp(resource.MustParse("2Gi")) != 0 {
		t.Fatalf("rich edge metadata was not exposed through the released v1beta1 field: %#v", spoke.Spec.Storage.Metadata)
	}
	spoke.Spec.Replicas = 3
	spoke.Spec.NodeSelector = map[string]string{testWorkloadLabelKey: "edge-edited"}
	spoke.Spec.Storage.Metadata.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
		testDiskNameLabelKey: "edited-through-v1",
	}}
	maxUnavailable := intstr.FromInt32(1)
	spoke.Spec.PodDisruptionBudget = &PodDisruptionBudgetConfig{Enabled: true, MaxUnavailable: &maxUnavailable}

	roundTripped := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	expected := original.Spec.Gateway.DeepCopy()
	expected.Replicas = 3
	expected.NodeSelector = map[string]string{testWorkloadLabelKey: "edge-edited"}
	expected.Metadata.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
		testDiskNameLabelKey: "edited-through-v1",
	}}
	expected.PodDisruptionBudget = &v1beta2.PodDisruptionBudgetConfig{Enabled: true, MaxUnavailable: &maxUnavailable}
	if !reflect.DeepEqual(roundTripped.Spec.Gateway, expected) {
		t.Fatalf("rich edge gateway changed:\n got: %#v\nwant: %#v", roundTripped.Spec.Gateway, expected)
	}
	if roundTripped.Annotations[v1beta2AnnotationGatewayTierData] != "" ||
		roundTripped.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Fatalf("gateway conversion transport annotations leaked into hub: %#v", roundTripped.Annotations)
	}
}

// TestConvertFrom_UnifiedCluster: v1beta2 unified CR (storage + gateway both
// set) renders an editable storage view and carries the gateway losslessly in
// reserved conversion annotations.
func TestConvertFrom_UnifiedCluster_PreservesGatewayPayload(t *testing.T) {
	src := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "uni", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Storage: &v1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
			Gateway: &v1beta2.GatewaySpec{Replicas: 2},
		},
	}
	dst := &GarageCluster{}
	if err := dst.ConvertFrom(src); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if dst.Spec.Gateway {
		t.Fatalf("expected v1beta1 gateway=false (storage-form rendering)")
	}
	if dst.Spec.Replicas != 3 {
		t.Errorf("replicas should come from editable storage tier; got %d want 3", dst.Spec.Replicas)
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] == "" {
		t.Errorf("expected gateway conversion marker to be set")
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierData] == "" {
		t.Errorf("expected gateway conversion payload to be set")
	}
}

// TestRoundTrip_StorageCluster ensures v1beta1 storage CR -> v1beta2 -> v1beta1
// is lossless for the field set v1beta1 owns.
func TestRoundTrip_StorageCluster(t *testing.T) {
	original := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "rt", Namespace: testNS},
		Spec: GarageClusterSpec{
			Image:    testImage,
			Replicas: 3,
			Zone:     testZone,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
			NodeSelector: map[string]string{testRole: testStorage},
			Gateway:      false,
		},
	}

	intermediate := &v1beta2.GarageCluster{}
	if err := original.ConvertTo(intermediate); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}

	roundTripped := &GarageCluster{}
	if err := roundTripped.ConvertFrom(intermediate); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}

	if roundTripped.Spec.Replicas != original.Spec.Replicas {
		t.Errorf("replicas round-trip lost: got %d want %d", roundTripped.Spec.Replicas, original.Spec.Replicas)
	}
	if roundTripped.Spec.Gateway != original.Spec.Gateway {
		t.Errorf("gateway round-trip lost")
	}
	if roundTripped.Spec.Zone != original.Spec.Zone {
		t.Errorf("zone round-trip lost")
	}
	if roundTripped.Spec.NodeSelector[testRole] != testStorage {
		t.Errorf("nodeSelector round-trip lost")
	}
	if roundTripped.Spec.Storage.Metadata == nil ||
		roundTripped.Spec.Storage.Metadata.Size == nil ||
		roundTripped.Spec.Storage.Metadata.Size.String() != test10Gi {
		t.Errorf("storage.metadata round-trip lost")
	}
}

// TestRoundTrip_GatewayCluster verifies v1beta1 gateway+connectTo round-trip.
func TestRoundTrip_GatewayCluster(t *testing.T) {
	original := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: GarageClusterSpec{
			Gateway:  true,
			Replicas: 2,
			ConnectTo: &ConnectToConfig{
				ClusterRef: &ClusterReference{Name: testStoreCR},
			},
		},
	}
	intermediate := &v1beta2.GarageCluster{}
	if err := original.ConvertTo(intermediate); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	roundTripped := &GarageCluster{}
	if err := roundTripped.ConvertFrom(intermediate); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if !roundTripped.Spec.Gateway {
		t.Errorf("gateway round-trip lost")
	}
	if roundTripped.Spec.Replicas != 2 {
		t.Errorf("replicas round-trip lost")
	}
	if roundTripped.Spec.ConnectTo == nil ||
		roundTripped.Spec.ConnectTo.ClusterRef == nil ||
		roundTripped.Spec.ConnectTo.ClusterRef.Name != testStoreCR {
		t.Errorf("connectTo round-trip lost")
	}
}

// TestConvertTo_ManualLayoutGarageNodeUser reproduces the v1beta1 CR shape
// from issue #173 (Manual layout with a separate GarageNode CR) and asserts
// that every pod-level field and the PodDisruptionBudget land in the
// v1beta2 storage tier where the MIGRATION.md walkthrough says they do.
// If this test fails, the migration documentation is out of sync with the
// conversion webhook.
func TestConvertTo_ManualLayoutGarageNodeUser(t *testing.T) {
	runAsUser := int64(65532)
	allowEsc := false
	oneZone := 1
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage-tank", Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas:     1,
			LayoutPolicy: layoutPolicyManual,
			Replication: &ReplicationConfig{
				Factor:                 1,
				ConsistencyMode:        testConsist,
				ZoneRedundancyMode:     zoneRedundancyAtLeast,
				ZoneRedundancyMinZones: &oneZone,
			},
			Network: NetworkConfig{
				RPCBindPort: 3901,
				Service:     &ServiceConfig{Type: corev1.ServiceTypeClusterIP},
			},
			Database: &DatabaseConfig{Engine: "lmdb"},
			Security: &SecurityConfig{AllowInsecureSecretPermissions: true},
			Storage: StorageConfig{
				MetadataAutoSnapshotInterval: "6h",
			},
			Monitoring:          &MonitoringSpec{Enabled: ptrBool(true), Interval: "30s"},
			PodDisruptionBudget: &PodDisruptionBudgetConfig{Enabled: false},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					"cpu":    resource.MustParse("100m"),
					"memory": resource.MustParse("512Mi"),
				},
				Limits: corev1.ResourceList{"memory": resource.MustParse("2Gi")},
			},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptrBool(true),
				RunAsUser:    &runAsUser,
			},
			ContainerSecurityContext: &corev1.SecurityContext{
				RunAsNonRoot:             ptrBool(true),
				AllowPrivilegeEscalation: &allowEsc,
			},
		},
	}

	dst := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(dst); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}

	if dst.Spec.LayoutPolicy != layoutPolicyManual {
		t.Errorf("layoutPolicy: got %q want Manual", dst.Spec.LayoutPolicy)
	}
	if dst.Spec.Storage == nil {
		t.Fatalf("expected storage tier set on v1beta2 (Manual still requires spec.storage in the schema)")
	}
	if dst.Spec.Storage.Replicas != 1 {
		t.Errorf("storage.replicas: got %d want 1 (Manual ignores the value but conversion must preserve it)", dst.Spec.Storage.Replicas)
	}
	if dst.Spec.Storage.MetadataAutoSnapshotInterval != "6h" {
		t.Errorf("storage.metadataAutoSnapshotInterval: got %q want 6h", dst.Spec.Storage.MetadataAutoSnapshotInterval)
	}
	if dst.Spec.Storage.PodDisruptionBudget == nil || dst.Spec.Storage.PodDisruptionBudget.Enabled {
		t.Errorf("storage.podDisruptionBudget: got %+v want {Enabled:false}", dst.Spec.Storage.PodDisruptionBudget)
	}
	if dst.Spec.Storage.Resources.Requests.Cpu().String() != "100m" {
		t.Errorf("storage.podTemplate.resources.requests.cpu not copied")
	}
	if dst.Spec.Storage.Resources.Limits.Memory().String() != "2Gi" {
		t.Errorf("storage.podTemplate.resources.limits.memory not copied")
	}
	if dst.Spec.Storage.SecurityContext == nil || dst.Spec.Storage.SecurityContext.RunAsUser == nil ||
		*dst.Spec.Storage.SecurityContext.RunAsUser != 65532 {
		t.Errorf("storage.podTemplate.securityContext not copied")
	}
	if dst.Spec.Storage.ContainerSecurityContext == nil ||
		dst.Spec.Storage.ContainerSecurityContext.AllowPrivilegeEscalation == nil ||
		*dst.Spec.Storage.ContainerSecurityContext.AllowPrivilegeEscalation {
		t.Errorf("storage.podTemplate.containerSecurityContext not copied")
	}
	if dst.Spec.Network.Service == nil || dst.Spec.Network.Service.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("network.service.type not copied")
	}

	// Validate that the resulting v1beta2 form passes the v1beta2 webhook
	// validator. Manual layout skips validateStorageTier (no metadata/data
	// PVC required at the cluster level), so the absence of those fields is
	// expected and intentional.
	v := &v1beta2.GarageClusterValidator{}
	if _, err := v.ValidateCreate(context.Background(), dst); err != nil {
		t.Errorf("v1beta2 webhook rejected the converted Manual-layout CR: %v", err)
	}
}

func ptrBool(b bool) *bool { return &b }

// TestConvert_NilHubArg ensures the type assertion guards return errors not
// panics when callers pass the wrong hub type.
func TestConvert_NilHubArg(t *testing.T) {
	src := &GarageCluster{}
	if err := src.ConvertTo(nil); err == nil {
		t.Errorf("ConvertTo(nil): expected error")
	}
	if err := src.ConvertFrom(nil); err == nil {
		t.Errorf("ConvertFrom(nil): expected error")
	}
}

// A v1beta2 management handle (#269) must project to a v1beta1 handle view
// (gateway=false, no storage tier, connectTo preserved) and round-trip back to
// a v1beta2 handle (Storage/Gateway nil), so the operator still sees a handle.
func TestConvert_ManagementHandleRoundTrip(t *testing.T) {
	hub := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			ConnectTo: &v1beta2.ConnectToConfig{
				AdminAPIEndpoint:    testAdminEndpoint,
				AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: testAdminSecret}, Key: garageAdminTokenDefaultKey},
			},
		},
	}

	down := &GarageCluster{}
	if err := down.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Spec.Gateway {
		t.Error("v1beta1 view of a handle must have gateway=false")
	}
	if !down.isManagementHandle() {
		t.Errorf("v1beta1 view is not recognized as a management handle: %+v", down.Spec)
	}
	if down.Spec.ConnectTo == nil || down.Spec.ConnectTo.AdminAPIEndpoint != testAdminEndpoint {
		t.Errorf("connectTo not preserved in v1beta1 view: %+v", down.Spec.ConnectTo)
	}

	up := &v1beta2.GarageCluster{}
	if err := down.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if up.Spec.Storage != nil {
		t.Errorf("round-tripped handle must not gain a storage tier, got %+v", up.Spec.Storage)
	}
	if up.Spec.Gateway != nil {
		t.Errorf("round-tripped handle must not gain a gateway tier, got %+v", up.Spec.Gateway)
	}
	if !up.IsManagementHandle() {
		t.Error("round-tripped object is no longer a v1beta2 management handle")
	}
}

func TestConvert_AutoModePVCHandoffStatusRoundTrip(t *testing.T) {
	original := &v1beta2.GarageCluster{
		Status: v1beta2.GarageClusterStatus{AutoModePVCHandoffs: []v1beta2.AutoModePVCHandoffStatus{{
			SlotName:                   "store-gateway-1",
			PVCName:                    "metadata-store-gateway-1-0",
			PVCUID:                     "pvc-uid",
			PreviousGarageNodeUID:      "old-node-uid",
			ReplacementReservationHash: "nonce-hash",
			ReplacementGarageNodeUID:   "new-node-uid",
		}}},
	}
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(original); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	roundTripped := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if !reflect.DeepEqual(roundTripped.Status.AutoModePVCHandoffs, original.Status.AutoModePVCHandoffs) {
		t.Fatalf("Auto-mode PVC handoff status changed across conversion: got %#v, want %#v", roundTripped.Status.AutoModePVCHandoffs, original.Status.AutoModePVCHandoffs)
	}
}

// TestConvert_ZoneFromRoundTrip: spec.zoneFrom (#294) exists on both versions,
// so a cluster using per-node zones must survive v1beta1 -> v1beta2 -> v1beta1
// with no annotation and no loss. Serving it on the deprecated version too is
// what keeps the round-trip lossless.
func TestConvert_ZoneFromRoundTrip(t *testing.T) {
	const rackLabel = "example.com/rack"
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Zone:     testZone,
			ZoneFrom: &ZoneSource{NodeLabel: rackLabel},
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
		},
	}

	up := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if up.Spec.ZoneFrom == nil || up.Spec.ZoneFrom.NodeLabel != rackLabel {
		t.Fatalf("v1beta2 zoneFrom: got %+v want nodeLabel %q", up.Spec.ZoneFrom, rackLabel)
	}
	if up.Spec.Zone != testZone {
		t.Fatalf("v1beta2 zone: got %q want %q (fallback must survive alongside zoneFrom)", up.Spec.Zone, testZone)
	}

	down := &GarageCluster{}
	if err := down.ConvertFrom(up); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Spec.ZoneFrom == nil || down.Spec.ZoneFrom.NodeLabel != rackLabel {
		t.Fatalf("round-trip lost zoneFrom: got %+v", down.Spec.ZoneFrom)
	}
	if down.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Fatalf("zoneFrom must not be reported as v1beta2-only, got annotation %q",
			down.Annotations[v1beta2AnnotationGatewayTierPresent])
	}
}

// A cluster without zoneFrom must not gain one through conversion.
func TestConvert_ZoneFromAbsent(t *testing.T) {
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 1,
			Zone:     testZone,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
			},
		},
	}
	up := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if up.Spec.ZoneFrom != nil {
		t.Fatalf("zoneFrom should stay nil, got %+v", up.Spec.ZoneFrom)
	}
	down := &GarageCluster{}
	if err := down.ConvertFrom(up); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Spec.ZoneFrom != nil {
		t.Fatalf("zoneFrom should stay nil, got %+v", down.Spec.ZoneFrom)
	}
}
