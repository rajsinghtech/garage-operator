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

package v1beta1

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	testVACMetadata = "meta-class"
	testVACData     = "data-class"
	testVACPath     = "path-class"
	testVACGateway  = "gateway-class"
)

// TestConvert_VolumeAttributesClassRoundTrip: volumeAttributesClassName on
// storage.metadata, storage.data and storage.data.paths[].volume must survive
// v1beta1 -> v1beta2 -> v1beta1. Conversion is a JSON copy, so a field missing
// from either version would be silently dropped on every v1beta1 write.
func TestConvert_VolumeAttributesClassRoundTrip(t *testing.T) {
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{
					Size:                      ptrQuantity(resource.MustParse("2Gi")),
					VolumeAttributesClassName: ptr.To(testVACMetadata),
				},
				Data: &VolumeConfig{
					Size:                      ptrQuantity(resource.MustParse("100Gi")),
					VolumeAttributesClassName: ptr.To(testVACData),
					Paths: []DataPath{
						{Path: "/data/a", Volume: &DataPathVolumeConfig{
							Size:                      ptrQuantity(resource.MustParse("10Gi")),
							VolumeAttributesClassName: ptr.To(testVACPath),
						}},
						{Path: "/data/b", Volume: &DataPathVolumeConfig{
							Size: ptrQuantity(resource.MustParse("10Gi")),
						}},
					},
				},
			},
		},
	}

	hub := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(hub); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if got := ptr.Deref(hub.Spec.Storage.Metadata.VolumeAttributesClassName, ""); got != testVACMetadata {
		t.Errorf("hub metadata class = %q, want %q", got, testVACMetadata)
	}
	if got := ptr.Deref(hub.Spec.Storage.Data.VolumeAttributesClassName, ""); got != testVACData {
		t.Errorf("hub data class = %q, want %q", got, testVACData)
	}
	if got := ptr.Deref(hub.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName, ""); got != testVACPath {
		t.Errorf("hub paths[0].volume class = %q, want %q", got, testVACPath)
	}
	if hub.Spec.Storage.Data.Paths[1].Volume.VolumeAttributesClassName != nil {
		t.Errorf("hub paths[1].volume class should stay nil, got %q", *hub.Spec.Storage.Data.Paths[1].Volume.VolumeAttributesClassName)
	}

	back := &GarageCluster{}
	if err := back.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if !equality.Semantic.DeepEqual(src.Spec.Storage, back.Spec.Storage) {
		t.Fatalf("v1beta1 -> hub -> v1beta1 changed storage:\n got %#v\nwant %#v", back.Spec.Storage, src.Spec.Storage)
	}
}

// TestConvert_VolumeAttributesClassEdgeGatewayRoundTrip: a v1beta1 edge gateway
// (gateway: true) keeps its metadata volume in spec.storage.metadata; the class
// must reach v1beta2 spec.gateway.metadata and come back.
func TestConvert_VolumeAttributesClassEdgeGatewayRoundTrip(t *testing.T) {
	src := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNS},
		Spec: GarageClusterSpec{
			Gateway:   true,
			Replicas:  2,
			ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStoreCR}},
			Storage: StorageConfig{
				Metadata: &VolumeConfig{
					Size:                      ptrQuantity(resource.MustParse("1Gi")),
					VolumeAttributesClassName: ptr.To(testVACGateway),
				},
			},
		},
	}
	hub := &v1beta2.GarageCluster{}
	if err := src.ConvertTo(hub); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if hub.Spec.Gateway == nil || hub.Spec.Gateway.Metadata == nil ||
		ptr.Deref(hub.Spec.Gateway.Metadata.VolumeAttributesClassName, "") != testVACGateway {
		t.Fatalf("hub gateway.metadata lost the class: %#v", hub.Spec.Gateway)
	}
	back := &GarageCluster{}
	if err := back.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if !back.Spec.Gateway || back.Spec.Storage.Metadata == nil ||
		ptr.Deref(back.Spec.Storage.Metadata.VolumeAttributesClassName, "") != testVACGateway {
		t.Fatalf("v1beta1 edge gateway lost the class: %#v", back.Spec.Storage.Metadata)
	}
}

// TestConvert_VolumeAttributesClassUnifiedGatewayRoundTrip: for a unified
// (storage + gateway) cluster the gateway tier has no v1beta1 form and travels
// in the v1beta2-gateway-tier annotation. A cluster whose ONLY gateway
// difference is the VAC must still round-trip hub -> v1beta1 -> hub intact.
func TestConvert_VolumeAttributesClassUnifiedGatewayRoundTrip(t *testing.T) {
	newHub := func(class *string) *v1beta2.GarageCluster {
		return &v1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "uni", Namespace: testNS},
			Spec: v1beta2.GarageClusterSpec{
				Storage: &v1beta2.StorageSpec{
					Replicas: 3,
					Metadata: &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
					Data:     &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				},
				Gateway: &v1beta2.GatewaySpec{
					Replicas: 2,
					Metadata: &v1beta2.VolumeConfig{
						Size:                      ptrQuantity(resource.MustParse("1Gi")),
						VolumeAttributesClassName: class,
					},
				},
			},
		}
	}
	for name, class := range map[string]*string{"set": ptr.To(testVACGateway), "absent": nil} {
		t.Run(name, func(t *testing.T) {
			hub := newHub(class)
			spoke := &GarageCluster{}
			if err := spoke.ConvertFrom(hub); err != nil {
				t.Fatalf("ConvertFrom: %v", err)
			}
			if spoke.Annotations[v1beta2AnnotationGatewayTierData] == "" {
				t.Fatalf("unified cluster must carry the gateway tier payload annotation")
			}
			back := &v1beta2.GarageCluster{}
			if err := spoke.ConvertTo(back); err != nil {
				t.Fatalf("ConvertTo: %v", err)
			}
			if !equality.Semantic.DeepEqual(hub.Spec.Gateway, back.Spec.Gateway) {
				t.Fatalf("hub -> v1beta1 -> hub changed gateway:\n got %#v\nwant %#v", back.Spec.Gateway, hub.Spec.Gateway)
			}
			if !reflect.DeepEqual(class, back.Spec.Gateway.Metadata.VolumeAttributesClassName) {
				t.Fatalf("gateway class = %v, want %v", back.Spec.Gateway.Metadata.VolumeAttributesClassName, class)
			}
		})
	}
}

// TestGatewayTierRequiresV1Beta2Payload_VolumeAttributesClass proves a
// VAC-only difference between the projected and the real GatewaySpec is
// detected, so the payload annotation (and therefore the class) is not lost,
// while an identical class on both sides needs no payload.
func TestGatewayTierRequiresV1Beta2Payload_VolumeAttributesClass(t *testing.T) {
	view := &GarageCluster{Spec: GarageClusterSpec{
		Gateway:  true,
		Replicas: 2,
		Storage: StorageConfig{Metadata: &VolumeConfig{
			Size:                      ptrQuantity(resource.MustParse("1Gi")),
			VolumeAttributesClassName: ptr.To(testVACGateway),
		}},
	}}
	same := &v1beta2.GatewaySpec{Replicas: 2, Metadata: &v1beta2.VolumeConfig{
		Size:                      ptrQuantity(resource.MustParse("1Gi")),
		VolumeAttributesClassName: ptr.To(testVACGateway),
	}}
	if gatewayTierRequiresV1Beta2Payload(same, view) {
		t.Errorf("identical VAC on both sides must not require the payload")
	}
	different := same.DeepCopy()
	different.Metadata.VolumeAttributesClassName = ptr.To("other")
	if !gatewayTierRequiresV1Beta2Payload(different, view) {
		t.Errorf("a VAC-only difference must require the payload")
	}
	removed := same.DeepCopy()
	removed.Metadata.VolumeAttributesClassName = nil
	if !gatewayTierRequiresV1Beta2Payload(removed, view) {
		t.Errorf("a hub gateway without the class vs a projected view with it must require the payload")
	}
}

// TestConvert_VolumeAttributesClassAbsenceIsPreserved: nil stays nil in both
// directions and nothing serialises a volumeAttributesClassName key.
func TestConvert_VolumeAttributesClassAbsenceIsPreserved(t *testing.T) {
	hub := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Storage: &v1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("2Gi"))},
				Data: &v1beta2.VolumeConfig{
					Size: ptrQuantity(resource.MustParse("100Gi")),
					Paths: []v1beta2.DataPath{{Path: "/data/a", Volume: &v1beta2.DataPathVolumeConfig{
						Size: ptrQuantity(resource.MustParse("10Gi")),
					}}},
				},
			},
		},
	}
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if spoke.Spec.Storage.Metadata.VolumeAttributesClassName != nil ||
		spoke.Spec.Storage.Data.VolumeAttributesClassName != nil ||
		spoke.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName != nil {
		t.Fatalf("absent class appeared on v1beta1: %#v", spoke.Spec.Storage)
	}
	back := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(back); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if back.Spec.Storage.Metadata.VolumeAttributesClassName != nil ||
		back.Spec.Storage.Data.VolumeAttributesClassName != nil ||
		back.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName != nil {
		t.Fatalf("absent class appeared on hub: %#v", back.Spec.Storage)
	}
}
