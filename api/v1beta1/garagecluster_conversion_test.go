/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"testing"

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
