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
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func ptrQuantity(q resource.Quantity) *resource.Quantity { return &q }

// Test fixtures shared across the conversion tests. Centralized to keep goconst happy.
const (
	testZone    = "us-east-1"
	testImage   = "dxflrs/garage:v2.3.0"
	testNS      = "ns"
	testRole    = "role"
	testStorage = "storage"
	testStoreCR = "store"
	test10Gi    = "10Gi"
	testConsist = "consistent"
	testRelabel = "rpc_duration_.*"
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
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: GarageClusterSpec{
			Gateway:  true,
			Replicas: 2,
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
	src := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Gateway: &v1beta2.GatewaySpec{Replicas: 2},
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
}

// TestConvertFrom_UnifiedCluster: v1beta2 unified CR (storage + gateway both set)
// -> v1beta1 must be lossy and annotated.
func TestConvertFrom_UnifiedCluster_Lossy(t *testing.T) {
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
		t.Errorf("replicas should come from storage tier on lossy convert; got %d want 3", dst.Spec.Replicas)
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] == "" {
		t.Errorf("expected lossy-conversion annotation to be set")
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
