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
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func nodeLocalPoolHub() *v1beta2.GarageCluster {
	capacity := resource.MustParse("500Gi")
	return &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "mixed", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			LayoutPolicy: "Manual",
			ZoneFrom:     &v1beta2.ZoneSource{NodeLabel: "topology.example.net/garage-zone"},
			Storage: &v1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				NodeLocalPools: []v1beta2.NodeLocalPoolSpec{{
					Name:     "local-500",
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"storage.example.com/garage-pool": "local-500"}},
					Capacity: &capacity,
					Metadata: &v1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/meta"},
					Data:     &v1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/data"},
					Network: &v1beta2.NodeLocalPoolNetworkSpec{
						RPCPublicAddrTemplate: "{nodeName}.storage.example.net:3901",
					},
				}},
			},
		},
	}
}

func TestConvertFrom_NodeLocalPools_PreservesNormalDefaultPoolView(t *testing.T) {
	dst := &GarageCluster{}
	if err := dst.ConvertFrom(nodeLocalPoolHub()); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] == "" {
		t.Errorf("v1beta1 view must carry the %s marker", v1beta2AnnotationGatewayTierPresent)
	}
	if dst.Annotations[v1beta2AnnotationNodeLocalPoolsData] == "" {
		t.Errorf("v1beta1 view must preserve the v1beta2 pool payload")
	}
	if dst.Annotations["garage.rajsingh.info/v1beta2-storage-pools"] != "" ||
		strings.Contains(dst.Annotations[v1beta2AnnotationGatewayTierPresent], "storage-pools-present") {
		t.Fatalf("conversion emitted an obsolete unreleased node-local pool transport alias: %#v", dst.Annotations)
	}
	if dst.Spec.Gateway {
		t.Errorf("mixed storage must project as a storage cluster")
	}
	if dst.Spec.Storage.Metadata == nil || dst.Spec.Storage.Metadata.Size == nil ||
		dst.Spec.Storage.Metadata.Size.String() != test10Gi {
		t.Errorf("default storage metadata was elided: %+v", dst.Spec.Storage.Metadata)
	}
	if dst.Spec.Storage.Data == nil || dst.Spec.Storage.Data.Size == nil ||
		dst.Spec.Storage.Data.Size.String() != "100Gi" {
		t.Errorf("default storage data was elided: %+v", dst.Spec.Storage.Data)
	}
}

func TestConversionDoesNotReadUnreleasedStoragePoolPayloadAliases(t *testing.T) {
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(nodeLocalPoolHub()); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	oldPayload := spoke.Annotations[v1beta2AnnotationNodeLocalPoolsData]
	delete(spoke.Annotations, v1beta2AnnotationNodeLocalPoolsData)
	spoke.Annotations[v1beta2AnnotationGatewayTierPresent] = "storage-pools-present"
	spoke.Annotations["garage.rajsingh.info/v1beta2-storage-pools"] = oldPayload

	hub := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(hub); err != nil {
		t.Fatalf("ConvertTo with obsolete aliases: %v", err)
	}
	if hub.Spec.Storage == nil {
		t.Fatal("default storage projection disappeared")
	}
	if len(hub.Spec.Storage.NodeLocalPools) != 0 {
		t.Fatalf("obsolete conversion aliases created node-local workloads: %#v", hub.Spec.Storage.NodeLocalPools)
	}
}

func TestConvertRoundTrip_NodeLocalPools_PreservesV1Beta2OnlyFields(t *testing.T) {
	original := nodeLocalPoolHub()
	original.Status.ScaleReplicas = 2
	original.Status.ScaleSelector = "garage.rajsingh.info/cluster=mixed,garage.rajsingh.info/storage-group=default,garage.rajsingh.info/tier=storage"
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(original); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}

	// A legacy client may still intentionally edit the default pool.
	spoke.Spec.Replicas = 4
	roundTripped := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Storage.NodeLocalPools, original.Spec.Storage.NodeLocalPools) {
		t.Fatalf("node-local pools changed across conversion:\n got: %#v\nwant: %#v",
			roundTripped.Spec.Storage.NodeLocalPools, original.Spec.Storage.NodeLocalPools)
	}
	if roundTripped.Spec.Storage.Replicas != 4 {
		t.Fatalf("editable default pool field did not round-trip: replicas=%d", roundTripped.Spec.Storage.Replicas)
	}
	if !reflect.DeepEqual(roundTripped.Spec.ZoneFrom, original.Spec.ZoneFrom) {
		t.Fatalf("zoneFrom changed: got %#v, want %#v", roundTripped.Spec.ZoneFrom, original.Spec.ZoneFrom)
	}
	if spoke.Status.ScaleReplicas != original.Status.ScaleReplicas ||
		spoke.Status.ScaleSelector != original.Status.ScaleSelector ||
		roundTripped.Status.ScaleReplicas != original.Status.ScaleReplicas ||
		roundTripped.Status.ScaleSelector != original.Status.ScaleSelector {
		t.Fatalf("scale status did not round-trip through v1beta1: spoke=%d %q hub=%d %q",
			spoke.Status.ScaleReplicas, spoke.Status.ScaleSelector,
			roundTripped.Status.ScaleReplicas, roundTripped.Status.ScaleSelector)
	}
	if roundTripped.Annotations[v1beta2AnnotationNodeLocalPoolsData] != "" {
		t.Errorf("conversion transport annotation leaked into hub object")
	}
	if roundTripped.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Errorf("v1beta2-only pool marker leaked into hub object")
	}
}

func TestConvertRoundTrip_UnifiedMultiPoolDeletionAndRolloutState(t *testing.T) {
	original := nodeLocalPoolHub()
	original.Spec.DeletionPolicy = v1beta2.DeletionPolicyDrain
	original.Spec.Gateway = &v1beta2.GatewaySpec{
		Replicas:      2,
		RPCPublicAddr: "gateway.example.net:3901",
		PodTemplate: v1beta2.PodTemplate{
			NodeSelector:   map[string]string{testWorkloadLabelKey: gatewayValue},
			PodAnnotations: map[string]string{"example.net/tier": gatewayValue},
		},
	}
	secondCapacity := resource.MustParse("2Ti")
	original.Spec.Storage.NodeLocalPools = append(original.Spec.Storage.NodeLocalPools, v1beta2.NodeLocalPoolSpec{
		Name:     testArchiveName,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"storage.example.com/garage-pool": testArchiveName}},
		Capacity: &secondCapacity,
		Metadata: &v1beta2.HostPathVolumeConfig{HostPath: "/mnt/archive/meta"},
		Data:     &v1beta2.HostPathVolumeConfig{HostPath: "/mnt/archive/data"},
		PodTemplate: &v1beta2.NodeLocalPoolPodTemplate{
			PriorityClassName: "storage-critical",
		},
	})
	original.Status.StorageRollout = &v1beta2.StorageRolloutStatus{
		GarageNodeName: "smb-a",
		GarageNodeUID:  "garage-node", GarageNodeID: "garage-id", WorkloadUID: "statefulset",
		PreviousPodUID: "old-pod", DesiredPodSpecHash: "new-spec", DesiredConfigHash: "new-config",
		RecoveryPodName: "archive-abc", RecoveryPodUID: "failed-pod",
		PersistentVolumeClaims: []v1beta2.StorageRolloutPersistentVolumeClaimStatus{{
			Name: "metadata-smb-a-0", UID: "pvc-uid",
		}},
	}

	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(original); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if spoke.Annotations[v1beta2AnnotationGatewayTierData] == "" ||
		spoke.Annotations[v1beta2AnnotationNodeLocalPoolsData] == "" {
		t.Fatalf("unified multi-pool conversion payloads missing: %#v", spoke.Annotations)
	}
	spoke.Spec.Replicas = 4 // a v1beta1-representable storage edit remains allowed

	roundTripped := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if roundTripped.Spec.Storage == nil || roundTripped.Spec.Storage.Replicas != 4 {
		t.Fatalf("editable storage view did not round-trip: %#v", roundTripped.Spec.Storage)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Storage.NodeLocalPools, original.Spec.Storage.NodeLocalPools) {
		t.Fatalf("multi-pool payload changed:\n got: %#v\nwant: %#v", roundTripped.Spec.Storage.NodeLocalPools, original.Spec.Storage.NodeLocalPools)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Gateway, original.Spec.Gateway) {
		t.Fatalf("unified gateway payload changed:\n got: %#v\nwant: %#v", roundTripped.Spec.Gateway, original.Spec.Gateway)
	}
	if roundTripped.Spec.DeletionPolicy != v1beta2.DeletionPolicyDrain {
		t.Fatalf("deletionPolicy = %q, want Drain", roundTripped.Spec.DeletionPolicy)
	}
	if !reflect.DeepEqual(roundTripped.Status.StorageRollout, original.Status.StorageRollout) {
		t.Fatalf("storage rollout transaction changed:\n got: %#v\nwant: %#v", roundTripped.Status.StorageRollout, original.Status.StorageRollout)
	}
	if roundTripped.Annotations[v1beta2AnnotationGatewayTierData] != "" ||
		roundTripped.Annotations[v1beta2AnnotationNodeLocalPoolsData] != "" ||
		roundTripped.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Fatalf("conversion transport annotations leaked into hub: %#v", roundTripped.Annotations)
	}
}

func TestConvertFrom_StorageWithoutNodeLocalPools_NotAnnotated(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.Storage.NodeLocalPools = nil
	dst := &GarageCluster{}
	if err := dst.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if dst.Annotations[v1beta2AnnotationGatewayTierPresent] != "" {
		t.Errorf("plain storage cluster wrongly annotated as v1beta2-only")
	}
}

func TestNodeLocalPoolsConversion_ZeroReplicaDefaultPoolNeedsNoDummyVolumes(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.LayoutPolicy = layoutPolicyAuto
	hub.Spec.Storage.LayoutPolicy = layoutPolicyManual
	hub.Spec.Storage.Replicas = 0
	hub.Spec.Storage.Metadata = nil
	hub.Spec.Storage.Data = nil

	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if _, err := spoke.validateGarageCluster(); err != nil {
		t.Fatalf("v1beta1 projection rejected pool-only storage: %v", err)
	}

	roundTripped := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(roundTripped); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if roundTripped.Spec.Storage.Metadata != nil || roundTripped.Spec.Storage.Data != nil {
		t.Fatalf("conversion invented default-pool volumes: %#v", roundTripped.Spec.Storage)
	}
	if len(roundTripped.Spec.Storage.NodeLocalPools) != 1 {
		t.Fatalf("conversion lost node-local pool: %#v", roundTripped.Spec.Storage.NodeLocalPools)
	}
}

func TestV1Beta1Update_NodeLocalPoolConversionPayloadMustBePreserved(t *testing.T) {
	oldObj := &GarageCluster{}
	if err := oldObj.ConvertFrom(nodeLocalPoolHub()); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	newObj := oldObj.DeepCopy()
	delete(newObj.Annotations, v1beta2AnnotationNodeLocalPoolsData)

	_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil || !strings.Contains(err.Error(), "reserved conversion payload") {
		t.Fatalf("expected removal of conversion payload to be rejected, got: %v", err)
	}

	newObj = oldObj.DeepCopy()
	newObj.Annotations[v1beta2AnnotationNodeLocalPoolsData] = "[]"
	_, err = (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil || !strings.Contains(err.Error(), "reserved conversion payload") {
		t.Fatalf("expected mutation of conversion payload to be rejected, got: %v", err)
	}

	newObj = oldObj.DeepCopy()
	newObj.Annotations[v1beta2AnnotationGatewayTierPresent] = "gateway-tier-present"
	_, err = (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil || !strings.Contains(err.Error(), "must retain") {
		t.Fatalf("expected removal of conversion marker to be rejected, got: %v", err)
	}

	plain := &GarageCluster{}
	plainHub := nodeLocalPoolHub()
	plainHub.Spec.Storage.NodeLocalPools = nil
	if err := plain.ConvertFrom(plainHub); err != nil {
		t.Fatalf("ConvertFrom plain hub: %v", err)
	}
	newObj = plain.DeepCopy()
	newObj.Annotations = map[string]string{
		v1beta2AnnotationGatewayTierPresent: v1beta2AnnotationNodeLocalPoolsPresent,
	}
	_, err = (&GarageClusterValidator{}).ValidateUpdate(context.Background(), plain, newObj)
	if err == nil || !strings.Contains(err.Error(), "reserved for API conversion") {
		t.Fatalf("expected addition of reserved conversion marker to be rejected, got: %v", err)
	}

	newObj = plain.DeepCopy()
	newObj.Annotations = map[string]string{
		v1beta2AnnotationNodeLocalPoolsData: "",
	}
	_, err = (&GarageClusterValidator{}).ValidateUpdate(context.Background(), plain, newObj)
	if err == nil || !strings.Contains(err.Error(), "reserved for API conversion") {
		t.Fatalf("expected addition of an empty reserved conversion payload to be rejected, got: %v", err)
	}
}

func TestV1Beta1EquivalentUpdate_GrandfathersReleasedGatewayEnvironmentPayload(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.Storage.NodeLocalPools = nil
	hub.Spec.Gateway = &v1beta2.GatewaySpec{
		Replicas: 1,
		PodTemplate: v1beta2.PodTemplate{
			Env:     []corev1.EnvVar{{Name: garageConfigFileEnv, Value: "/tmp/released.toml"}},
			EnvFrom: []corev1.EnvFromSource{{Prefix: ""}},
		},
	}
	oldObj := &GarageCluster{}
	if err := oldObj.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom old hub: %v", err)
	}
	newObj := oldObj.DeepCopy()
	newObj.Finalizers = []string{"example.test/cleanup"}
	warnings, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, newObj)
	if err != nil {
		t.Fatalf("equivalent v1beta1 finalizer update stranded released gateway env: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "operator ignores them") {
		t.Fatalf("released gateway conversion payload lacked a migration warning: %v", warnings)
	}

	var gateway v1beta2.GatewaySpec
	if err := json.Unmarshal([]byte(oldObj.Annotations[v1beta2AnnotationGatewayTierData]), &gateway); err != nil {
		t.Fatal(err)
	}
	gateway.Env[0].Value = testDifferentConfig
	mutatedRaw, err := json.Marshal(&gateway)
	if err != nil {
		t.Fatal(err)
	}
	mutated := oldObj.DeepCopy()
	mutated.Annotations[v1beta2AnnotationGatewayTierData] = string(mutatedRaw)
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, mutated); err == nil ||
		!strings.Contains(err.Error(), "reserved conversion payload") {
		t.Fatalf("legacy client mutation of gateway conversion payload was accepted: %v", err)
	}
}

func TestV1Beta1Update_PoolOnlyTransportViolationPrecedesProjectedShapeValidation(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.Storage.Replicas = 0
	hub.Spec.Storage.Metadata = nil
	hub.Spec.Storage.Data = nil

	oldObj := &GarageCluster{}
	if err := oldObj.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*GarageCluster)
		want   string
	}{
		{
			name: "payload removal",
			mutate: func(obj *GarageCluster) {
				delete(obj.Annotations, v1beta2AnnotationNodeLocalPoolsData)
			},
			want: "reserved conversion payload",
		},
		{
			name: "marker removal",
			mutate: func(obj *GarageCluster) {
				delete(obj.Annotations, v1beta2AnnotationGatewayTierPresent)
			},
			want: "must retain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newObj := oldObj.DeepCopy()
			tc.mutate(newObj)
			_, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldObj, newObj)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected exact conversion-transport rejection containing %q, got: %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "storage.data") {
				t.Fatalf("generic projected-shape validation obscured the conversion safety boundary: %v", err)
			}
		})
	}
}

func TestV1Beta1Create_NodeLocalPoolConversionPayloadIsReserved(t *testing.T) {
	obj := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "forged-pools",
			Namespace: testNS,
			Annotations: map[string]string{
				v1beta2AnnotationNodeLocalPoolsData: "[]",
				v1beta2AnnotationGatewayTierPresent: v1beta2AnnotationNodeLocalPoolsPresent,
			},
		},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyManual,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{},
			},
		},
	}
	if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), obj); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected forged conversion annotations on a v1beta1 create to be rejected, got: %v", err)
	}

	emptyPayload := obj.DeepCopy()
	emptyPayload.Annotations = map[string]string{
		v1beta2AnnotationNodeLocalPoolsData: "",
	}
	if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), emptyPayload); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected an empty reserved conversion annotation on a v1beta1 create to be rejected, got: %v", err)
	}
}

func TestV1Beta1EquivalentWebhook_AllowsV1Beta2PoolAddition(t *testing.T) {
	oldHub := nodeLocalPoolHub()
	oldHub.Spec.Storage.NodeLocalPools = nil
	oldObj := &GarageCluster{}
	if err := oldObj.ConvertFrom(oldHub); err != nil {
		t.Fatalf("ConvertFrom old hub: %v", err)
	}
	newObj := &GarageCluster{}
	if err := newObj.ConvertFrom(nodeLocalPoolHub()); err != nil {
		t.Fatalf("ConvertFrom new hub: %v", err)
	}

	v1beta2Kind := metav1.GroupVersionKind{
		Group:   GroupVersion.Group,
		Version: v1beta2.GroupVersion.Version,
		Kind:    garageClusterKind,
	}
	ctx := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   GroupVersion.Group,
				Version: GroupVersion.Version,
				Kind:    garageClusterKind,
			},
			RequestKind: &v1beta2Kind,
		},
	})
	if _, err := (&GarageClusterValidator{}).ValidateCreate(ctx, newObj); err != nil {
		t.Fatalf("equivalent v1beta1 webhook rejected a legitimate v1beta2 pool create: %v", err)
	}
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(ctx, oldObj, newObj); err != nil {
		t.Fatalf("equivalent v1beta1 webhook rejected a legitimate v1beta2 pool addition: %v", err)
	}
}

func TestV1Beta1EquivalentWebhook_AllowsDynamicNodeLocalPoolMinHealthy(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.Storage.Replicas = 0
	hub.Spec.Storage.Metadata = nil
	hub.Spec.Storage.Data = nil
	hub.Spec.LayoutManagement = &v1beta2.LayoutManagementConfig{MinNodesHealthy: 2} //nolint:staticcheck
	projected := &GarageCluster{}
	if err := projected.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}

	v1beta2Kind := metav1.GroupVersionKind{
		Group: GroupVersion.Group, Version: v1beta2.GroupVersion.Version, Kind: garageClusterKind,
	}
	ctx := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group: GroupVersion.Group, Version: GroupVersion.Version, Kind: garageClusterKind,
			},
			RequestKind: &v1beta2Kind,
		},
	})
	if _, err := (&GarageClusterValidator{}).ValidateCreate(ctx, projected); err != nil {
		t.Fatalf("equivalent v1beta1 webhook rejected dynamic node-local-pool minNodesHealthy: %v", err)
	}
}
