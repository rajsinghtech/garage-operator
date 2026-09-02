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
	"fmt"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/storagecontract"
)

const (
	testSourceNS           = "ns-a"
	testTargetNS           = "ns-b"
	testCluster            = "cluster"
	testBucket             = "my-bucket"
	testValidBucketAlias   = "valid-bucket"
	testKey                = "my-key"
	testWebhookNS          = "ns"
	testField              = "s3Api"
	kindGarageKey          = "GarageKey"
	testStorageClusterName = "storage-cluster"
	testWorkloadLabelKey   = "workload"
	testArchiveName        = "archive"
	testNodeUID            = "node-uid"
	testRemovedNodeID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testGarageNamespace    = "garage"
	testLocalZone          = "local"
	testClusterUID         = "cluster-uid"
	testStorageNodeName    = "storage-a"
	testDefaultNamespace   = "default"
	testCleanupFinalizer   = "example.test/cleanup"
	testMetadataValue      = "metadata"
	testDataValue          = "data"
	testDiskSelectorKey    = "disk"
	testDiskNameLabelKey   = "disk.example.com/name"
	testOldValue           = "old"
	testNewValue           = "new"
	testEdgeMetadataValue  = "edge-metadata"
	testEdgeValue          = "edge"
	testDeleteValue        = "Delete"
	testRetainValue        = "Retain"
	testDifferentConfig    = "/tmp/different.toml"
	testLegacyVolumeKey    = "example.com/legacy"
	testSSDValue           = "ssd"
)

var testKeyRef = KeyRef{Name: "key1"}

func TestValidateManagedTierReplicasBoundsDerivedNames(t *testing.T) {
	if err := validateManagedTierReplicas(50, "spec.replicas"); err != nil {
		t.Fatalf("supported maximum rejected: %v", err)
	}
	if err := validateManagedTierReplicas(51, "spec.replicas"); err == nil || !strings.Contains(err.Error(), "at most 50") {
		t.Fatalf("replica count that can overflow derived names accepted: %v", err)
	}
}

func TestGarageClusterNameBoundsFollowOwnedWorkloadShape(t *testing.T) {
	auto := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 50)},
		Spec:       GarageClusterSpec{Replicas: 50},
	}
	if err := validateManagedGarageClusterName(auto); err != nil {
		t.Fatalf("50-character Auto cluster name rejected: %v", err)
	}
	auto.Name = strings.Repeat("a", 51)
	if err := validateManagedGarageClusterName(auto); err == nil || !strings.Contains(err.Error(), "Auto storage GarageNode") {
		t.Fatalf("cluster name that overflows <cluster>-storage-49-0 accepted: %v", err)
	}
	auto.Spec.Replicas = 10
	if err := validateManagedGarageClusterName(auto); err != nil {
		t.Fatalf("51-character Auto name with a one-digit highest ordinal rejected: %v", err)
	}
	auto.Spec.Replicas = 11
	if err := validateManagedGarageClusterName(auto); err == nil {
		t.Fatal("51-character Auto name with a two-digit highest ordinal was accepted")
	}

	manual := auto.DeepCopy()
	manual.Name = strings.Repeat("m", 54)
	manual.Spec.LayoutPolicy = layoutPolicyAuto
	manual.Spec.Storage.LayoutPolicy = layoutPolicyManual
	if err := validateManagedGarageClusterName(manual); err != nil {
		t.Fatalf("54-character per-tier Manual cluster name rejected by an Auto-only bound: %v", err)
	}
	manual.Name = strings.Repeat("m", 55)
	if err := validateManagedGarageClusterName(manual); err == nil || !strings.Contains(err.Error(), "headless") {
		t.Fatalf("workload-owning cluster with an invalid headless Service name accepted: %v", err)
	}

	handle := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("h", 63)},
		Spec:       GarageClusterSpec{ConnectTo: &ConnectToConfig{}},
	}
	if err := validateManagedGarageClusterName(handle); err != nil {
		t.Fatalf("workload-free management handle was rejected by a managed-child bound: %v", err)
	}
	handle.Name = strings.Repeat("h", 64)
	if err := validateManagedGarageClusterName(handle); err == nil {
		t.Fatal("management handle exceeding its label-value contract was accepted")
	}

	storageOverrideAuto := manual.DeepCopy()
	storageOverrideAuto.Name = strings.Repeat("s", 51)
	storageOverrideAuto.Spec.LayoutPolicy = layoutPolicyManual
	storageOverrideAuto.Spec.Storage.LayoutPolicy = layoutPolicyAuto
	storageOverrideAuto.Spec.Replicas = 11
	if err := validateManagedGarageClusterName(storageOverrideAuto); err == nil {
		t.Fatal("per-tier Auto storage escaped the derived GarageNode Pod-name check")
	}

	edge := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("e", 53)},
		Spec: GarageClusterSpec{
			Gateway: true, Replicas: 10, LayoutPolicy: layoutPolicyAuto,
		},
	}
	if err := validateManagedGarageClusterName(edge); err != nil {
		t.Fatalf("53-character edge gateway with one-digit highest ordinal rejected: %v", err)
	}
	edge.Spec.Replicas = 11
	if err := validateManagedGarageClusterName(edge); err == nil {
		t.Fatal("53-character edge gateway with a two-digit highest ordinal was accepted")
	}
}

func TestGarageClusterNameUpdateGrandfathersOnlyNonExpandingTransitions(t *testing.T) {
	oldCluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 51), Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 11},
	}
	unchanged := oldCluster.DeepCopy()
	unchanged.Finalizers = []string{testCleanupFinalizer}
	grandfather, err := validateManagedGarageClusterNameUpdate(oldCluster, unchanged)
	if err != nil || !grandfather {
		t.Fatalf("metadata-only update was not grandfathered: grandfather=%v err=%v", grandfather, err)
	}

	rollout := oldCluster.DeepCopy()
	rollout.Spec.Image = "garage:v-next"
	if _, err := validateManagedGarageClusterNameUpdate(oldCluster, rollout); err == nil || !strings.Contains(err.Error(), "already-invalid managed child") {
		t.Fatalf("rollout of an impossible retained actor was accepted: %v", err)
	}

	scaleDown := oldCluster.DeepCopy()
	scaleDown.Spec.Replicas = 10
	if grandfather, err := validateManagedGarageClusterNameUpdate(oldCluster, scaleDown); err != nil || grandfather {
		t.Fatalf("scale-down to a valid shape should pass strict validation: grandfather=%v err=%v", grandfather, err)
	}

	scaleUp := oldCluster.DeepCopy()
	scaleUp.Spec.Replicas = 12
	if _, err := validateManagedGarageClusterNameUpdate(oldCluster, scaleUp); err == nil {
		t.Fatalf("scale-up introducing another impossible actor was accepted: %v", err)
	}

	deleting := oldCluster.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if grandfather, err := validateManagedGarageClusterNameUpdate(oldCluster, deleting); err != nil || !grandfather {
		t.Fatalf("deletion of an existing long object was blocked: grandfather=%v err=%v", grandfather, err)
	}
}

func TestV1Beta1ManagedNameValidationIncludesPreservedUnifiedGateway(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.Repeat("u", 51), Namespace: testWebhookNS,
			Annotations: map[string]string{
				v1beta2AnnotationGatewayTierPresent: v1beta2AnnotationGatewayTierComponent,
			},
		},
		Spec: GarageClusterSpec{Replicas: 0},
	}
	gateway := v1beta2.GatewaySpec{Replicas: 10}
	raw, err := json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	cluster.Annotations[v1beta2AnnotationGatewayTierData] = string(raw)
	if err := validateManagedGarageClusterName(cluster); err != nil {
		t.Fatalf("one-digit hidden unified gateway ordinal rejected: %v", err)
	}

	gateway.Replicas = 11
	raw, err = json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	cluster.Annotations[v1beta2AnnotationGatewayTierData] = string(raw)
	if err := validateManagedGarageClusterName(cluster); err == nil || !strings.Contains(err.Error(), "Auto gateway GarageNode") {
		t.Fatalf("hidden unified gateway escaped managed-name validation: %v", err)
	}

	unchanged := cluster.DeepCopy()
	unchanged.Finalizers = []string{testCleanupFinalizer}
	if grandfather, err := validateManagedGarageClusterNameUpdate(cluster, unchanged); err != nil || !grandfather {
		t.Fatalf("unchanged v1beta1 projection was not grandfathered: grandfather=%v err=%v", grandfather, err)
	}

	scaleUp := cluster.DeepCopy()
	gateway.Replicas = 12
	raw, err = json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	scaleUp.Annotations[v1beta2AnnotationGatewayTierData] = string(raw)
	if _, err := validateManagedGarageClusterNameUpdate(cluster, scaleUp); err == nil {
		t.Fatal("hidden unified gateway scale-up escaped the grandfather transition check")
	}

	scaleDownSource := scaleUp.DeepCopy()
	scaleDown := cluster.DeepCopy()
	if grandfather, err := validateManagedGarageClusterNameUpdate(scaleDownSource, scaleDown); err != nil || !grandfather {
		t.Fatalf("hidden unified gateway monotonic scale-down was rejected: grandfather=%v err=%v", grandfather, err)
	}
}

func TestGarageNodeNameLeavesRoomForStatefulSetPodLabel(t *testing.T) {
	size := resource.MustParse("1Gi")
	valid := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("n", 61), Namespace: testWebhookNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			Zone:       testLocalZone,
			Gateway:    true,
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Size: &size},
			},
		},
	}
	if _, err := valid.validateGarageNode(); err != nil {
		t.Fatalf("61-character GarageNode name rejected: %v", err)
	}
	invalid := valid.DeepCopy()
	invalid.Name = strings.Repeat("n", 62)
	if _, err := invalid.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "maximum 61") {
		t.Fatalf("GarageNode name producing a 64-character StatefulSet Pod label accepted: %v", err)
	}

	external := invalid.DeepCopy()
	external.Name = strings.Repeat("e", 63)
	external.Spec.Storage = nil
	external.Spec.NodeID = testRemovedNodeID
	external.Spec.External = &ExternalNodeConfig{Address: "smb-member.example.test", Port: 3901}
	if _, err := external.validateGarageNode(); err != nil {
		t.Fatalf("external GarageNode with no StatefulSet was rejected by the Pod-name bound: %v", err)
	}

	controller := true
	nodeLocal := invalid.DeepCopy()
	nodeLocal.Name = strings.Repeat("n", 63)
	nodeLocal.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1beta2.GroupVersion.String(), Kind: garageClusterKind, Name: testCluster,
		Controller: &controller,
	}}
	nodeLocal.Spec.Storage = nil
	nodeLocal.Spec.Backing = NodeBackingNodeLocalPool
	nodeLocal.Spec.Gateway = false
	nodeLocal.Spec.Capacity = &size
	nodeLocal.Spec.KubernetesNodeName = "worker-a"
	nodeLocal.Spec.NodeLocalPoolName = "local"
	if _, err := nodeLocal.validateGarageNode(); err != nil {
		t.Fatalf("node-local GarageNode with no StatefulSet was rejected by the Pod-name bound: %v", err)
	}
}

func TestGarageNodeNameUpdateGrandfathersRetirementButBlocksRollout(t *testing.T) {
	size := resource.MustParse("1Gi")
	oldNode := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("n", 62), Namespace: testWebhookNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			Zone:       testLocalZone,
			Gateway:    true,
			Storage:    &NodeStorageConfig{Metadata: &NodeVolumeConfig{Size: &size}},
		},
	}
	retirement := oldNode.DeepCopy()
	retirement.Finalizers = []string{testCleanupFinalizer}
	grandfather, err := validateManagedGarageNodeNameUpdate(oldNode, retirement)
	if err != nil || !grandfather {
		t.Fatalf("metadata/finalizer update was not grandfathered: grandfather=%v err=%v", grandfather, err)
	}

	rollout := oldNode.DeepCopy()
	rollout.Spec.Image = "garage:v-next"
	if _, err := validateManagedGarageNodeNameUpdate(oldNode, rollout); err == nil || !strings.Contains(err.Error(), "workload-rendering") {
		t.Fatalf("unsafe StatefulSet rollout was accepted: %v", err)
	}

	deleting := oldNode.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if grandfather, err := validateManagedGarageNodeNameUpdate(oldNode, deleting); err != nil || !grandfather {
		t.Fatalf("deletion was not grandfathered: grandfather=%v err=%v", grandfather, err)
	}
}

func TestGarageClusterValidator_RemoteClusterOwnershipIsUnambiguous(t *testing.T) {
	cluster := &GarageCluster{Spec: GarageClusterSpec{
		Zone: testLocalZone,
		RemoteClusters: []RemoteClusterConfig{
			{Name: "site-b", Zone: "remote-b"},
			{Name: "site-b", Zone: "remote-c"},
		},
	}}
	if err := cluster.validateRemoteClusters(); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("duplicate remote name accepted: %v", err)
	}
	cluster.Spec.RemoteClusters[1].Name = "site-c"
	cluster.Spec.RemoteClusters[1].Zone = "remote-b"
	if err := cluster.validateRemoteClusters(); err == nil || !strings.Contains(err.Error(), "zone") {
		t.Fatalf("duplicate remote zone accepted: %v", err)
	}
	cluster.Spec.RemoteClusters[1].Zone = testLocalZone
	if err := cluster.validateRemoteClusters(); err != nil {
		t.Fatalf("all-sites inventory with one local-zone entry rejected: %v", err)
	}
}

func TestValidateGarageEnvironmentRejectsEveryCredentialOverridePath(t *testing.T) {
	reserved := []string{
		garageConfigFileEnv,
		"GARAGE_RPC_SECRET", garageRPCSecretFileEnv,
		garageAdminTokenEnv, "GARAGE_ADMIN_TOKEN_FILE",
		"GARAGE_METRICS_TOKEN", "GARAGE_METRICS_TOKEN_FILE",
	}
	for _, name := range reserved {
		t.Run("literal_"+name, func(t *testing.T) {
			if err := validateGarageEnvironment([]corev1.EnvVar{{Name: name}}, nil, "spec.storage"); err == nil {
				t.Fatalf("reserved environment variable %s was accepted", name)
			}
		})
	}
	for _, prefix := range []string{"", "G", "GARAGE_", "GARAGE_RPC_", "GARAGE_ADMIN_TOKEN"} {
		t.Run("unsafe_prefix_"+prefix, func(t *testing.T) {
			if err := validateGarageEnvironment(nil, []corev1.EnvFromSource{{Prefix: prefix}}, "spec.storage"); err == nil {
				t.Fatalf("unsafe envFrom prefix %q was accepted", prefix)
			}
		})
	}
	if err := validateGarageEnvironment(
		[]corev1.EnvVar{{Name: garageAllowWorldReadableSecretsEnv, Value: stringTrue}},
		[]corev1.EnvFromSource{{Prefix: "CUSTOM_"}},
		"spec.storage",
	); err != nil {
		t.Fatalf("ordinary Garage env and a disjoint envFrom prefix were rejected: %v", err)
	}
	overlong := make([]corev1.EnvVar, maximumGarageEnvironmentEntries+1)
	for i := range overlong {
		overlong[i] = corev1.EnvVar{Name: fmt.Sprintf("APP_%03d", i), Value: "ok"}
	}
	if err := validateGarageEnvironment(overlong, nil, "spec.storage"); err == nil || !strings.Contains(err.Error(), "at most 256") {
		t.Fatalf("overlong environment was accepted: %v", err)
	}
}

func TestV1Beta1GarageClusterValidator_GrandfathersOnlyMonotonicLegacyEnvironmentCleanup(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-env", Namespace: testWebhookNS},
			Spec: GarageClusterSpec{
				Replicas: 1,
				Storage: StorageConfig{
					Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi},
					Env:     []corev1.EnvVar{{Name: garageConfigFileEnv, Value: "/tmp/legacy.toml"}},
					EnvFrom: []corev1.EnvFromSource{{Prefix: ""}},
				},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	validator := &GarageClusterValidator{}
	oldCluster := base()
	finalizerUpdate := oldCluster.DeepCopy()
	finalizerUpdate.Finalizers = []string{testCleanupFinalizer}
	warnings, err := validator.ValidateUpdate(context.Background(), oldCluster, finalizerUpdate)
	if err != nil {
		t.Fatalf("finalizer update with unchanged released environment was rejected: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "operator ignores them") {
		t.Fatalf("legacy environment update lacked a migration warning: %v", warnings)
	}

	mutated := oldCluster.DeepCopy()
	mutated.Spec.Storage.Env[0].Value = testDifferentConfig
	if _, err := validator.ValidateUpdate(context.Background(), oldCluster, mutated); err == nil ||
		!strings.Contains(err.Error(), "byte-for-byte unchanged") {
		t.Fatalf("operator-reserved legacy environment mutation was accepted: %v", err)
	}

	cleaned := oldCluster.DeepCopy()
	cleaned.Spec.Storage.Env = nil
	cleaned.Spec.Storage.EnvFrom = nil
	if _, err := validator.ValidateUpdate(context.Background(), oldCluster, cleaned); err != nil {
		t.Fatalf("removal of released unsafe environment entries was rejected: %v", err)
	}

	overlong := base()
	overlong.Spec.Storage.Env = make([]corev1.EnvVar, maximumGarageEnvironmentEntries+2)
	for i := range overlong.Spec.Storage.Env {
		overlong.Spec.Storage.Env[i] = corev1.EnvVar{Name: fmt.Sprintf("APP_%03d", i), Value: "ok"}
	}
	metadataUpdate := overlong.DeepCopy()
	metadataUpdate.Finalizers = []string{testCleanupFinalizer}
	if warnings, err := validator.ValidateUpdate(context.Background(), overlong, metadataUpdate); err != nil {
		t.Fatalf("metadata update on an unchanged overlong released environment was rejected: %v", err)
	} else if !strings.Contains(strings.Join(warnings, " "), "non-expanding") {
		t.Fatalf("overlong environment update lacked a non-expansion warning: %v", warnings)
	}
	changedOverlong := overlong.DeepCopy()
	changedOverlong.Spec.Storage.Env[len(changedOverlong.Spec.Storage.Env)-1].Value = "changed"
	if _, err := validator.ValidateUpdate(context.Background(), overlong, changedOverlong); err == nil ||
		!strings.Contains(err.Error(), "may only shrink") {
		t.Fatalf("mutation within an overlong released environment was accepted: %v", err)
	}
}

func TestV1Beta1GarageClusterValidator_GrandfathersReleasedReplicaBound(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	oldCluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-replicas", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:    51,
			Storage:     StorageConfig{Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	validator := &GarageClusterValidator{}
	metadataUpdate := oldCluster.DeepCopy()
	metadataUpdate.Finalizers = []string{testCleanupFinalizer}
	if warnings, err := validator.ValidateUpdate(context.Background(), oldCluster, metadataUpdate); err != nil {
		t.Fatalf("metadata update on released over-bound replicas was rejected: %v", err)
	} else if !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
		t.Fatalf("over-bound replica update lacked a migration warning: %v", warnings)
	}
	increase := oldCluster.DeepCopy()
	increase.Spec.Replicas = 52
	if _, err := validator.ValidateUpdate(context.Background(), oldCluster, increase); err == nil ||
		!strings.Contains(err.Error(), "may only remain unchanged or decrease") {
		t.Fatalf("growth above the released replica bound was accepted: %v", err)
	}
	decrease := oldCluster.DeepCopy()
	decrease.Spec.Replicas = 50
	if _, err := neutralizeLegacyV1Beta1GarageClusterReplicaBoundForValidation(oldCluster, decrease); err != nil {
		t.Fatalf("monotonic reduction into the replica bound was rejected: %v", err)
	}
}

func TestGarageNodeValidator_GrandfathersOnlyMonotonicLegacyEnvironmentCleanup(t *testing.T) {
	oldNode := readyCycleTestNode()
	oldNode.Finalizers = []string{testCleanupFinalizer}
	oldNode.Spec.Env = []corev1.EnvVar{{Name: garageConfigFileEnv, Value: "/tmp/legacy.toml"}}
	oldNode.Spec.EnvFrom = []corev1.EnvFromSource{{Prefix: ""}}
	validator := &GarageNodeValidator{}

	finalizerUpdate := oldNode.DeepCopy()
	finalizerUpdate.Finalizers = nil
	warnings, err := validator.ValidateUpdate(context.Background(), oldNode, finalizerUpdate)
	if err != nil {
		t.Fatalf("GarageNode finalizer cleanup with unchanged released environment was rejected: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "operator ignores them") {
		t.Fatalf("GarageNode legacy environment lacked a migration warning: %v", warnings)
	}

	mutated := oldNode.DeepCopy()
	mutated.Spec.Env[0].Value = testDifferentConfig
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, mutated); err == nil ||
		!strings.Contains(err.Error(), "byte-for-byte unchanged") {
		t.Fatalf("GarageNode operator-reserved environment mutation was accepted: %v", err)
	}

	cleaned := oldNode.DeepCopy()
	cleaned.Spec.Env = nil
	cleaned.Spec.EnvFrom = nil
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, cleaned); err != nil {
		t.Fatalf("GarageNode released unsafe environment cleanup was rejected: %v", err)
	}
}

func TestPreservedV1Beta2EnvironmentsCannotBypassV1Beta1Validation(t *testing.T) {
	tests := []struct {
		name       string
		annotation string
		payload    any
	}{
		{
			name:       "node-local pool literal",
			annotation: v1beta2AnnotationNodeLocalPoolsData,
			payload: []v1beta2.NodeLocalPoolSpec{{
				Name: "pool-a",
				PodTemplate: &v1beta2.NodeLocalPoolPodTemplate{Env: []corev1.EnvVar{{
					Name: garageRPCSecretFileEnv, Value: "/tmp/other",
				}}},
			}},
		},
		{
			name:       "gateway envFrom",
			annotation: v1beta2AnnotationGatewayTierData,
			payload: v1beta2.GatewaySpec{PodTemplate: v1beta2.PodTemplate{
				EnvFrom: []corev1.EnvFromSource{{Prefix: "GARAGE_"}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			cluster := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				tt.annotation: string(raw),
			}}}
			if err := cluster.validatePreservedV1Beta2GarageEnvironments(); err == nil || !strings.Contains(err.Error(), "operator-reserved") {
				t.Fatalf("unsafe preserved environment was accepted: %v", err)
			}
		})
	}

	safePools, err := json.Marshal([]v1beta2.NodeLocalPoolSpec{{
		Name: "pool-a",
		PodTemplate: &v1beta2.NodeLocalPoolPodTemplate{
			Env:     []corev1.EnvVar{{Name: garageAllowWorldReadableSecretsEnv, Value: stringTrue}},
			EnvFrom: []corev1.EnvFromSource{{Prefix: "CUSTOM_"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cluster := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		v1beta2AnnotationNodeLocalPoolsData: string(safePools),
	}}}
	if err := cluster.validatePreservedV1Beta2GarageEnvironments(); err != nil {
		t.Fatalf("safe preserved pool environment was rejected: %v", err)
	}
}

// fakeScheme builds a minimal scheme with v1beta1 types registered.
func fakeScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// grant builds a GarageReferenceGrant in namespace testTargetNS for test use.
func grant(fromKind, fromNS, toKind, toName string) *GarageReferenceGrant {
	g := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grant",
			Namespace: testTargetNS,
		},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: fromKind, Namespace: fromNS}},
		},
	}
	if toKind != "" {
		g.Spec.To = []ReferenceGrantTo{{Kind: toKind, Name: toName}}
	}
	return g
}

// ── ReferenceGrant check ──────────────────────────────────────────────────────

func TestCheckReferenceGrant_SameNamespace(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testSourceNS, "my-cluster")
	if err != nil {
		t.Errorf("same-namespace reference should always be allowed, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "my-cluster")
	if err == nil {
		t.Error("cross-namespace reference without a grant should be denied")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WithMatchingGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, garageClusterKind, "my-cluster")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "my-cluster")
	if err != nil {
		t.Errorf("should be allowed with matching grant, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_WildcardTo(t *testing.T) {
	// Grant with no To entries preserves the historical cluster/bucket wildcard.
	g := grant(kindGarageKey, testSourceNS, "", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "any-cluster")
	if err != nil {
		t.Errorf("wildcard To should allow any resource, got: %v", err)
	}
}

func TestCheckReferenceGrant_EmptyToDoesNotAuthorizeGarageKey(t *testing.T) {
	g := grant("GarageBucket", testSourceNS, "", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, "GarageBucket", testSourceNS, "GarageKey", testTargetNS, "key")
	if err == nil {
		t.Fatal("historical empty-to grant unexpectedly authorized newly referenceable GarageKey kind")
	}

	explicit := grant("GarageBucket", testSourceNS, "GarageKey", "")
	explicitClient := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(explicit).Build()
	if err := checkReferenceGrant(context.Background(), explicitClient, "GarageBucket", testSourceNS, "GarageKey", testTargetNS, "key"); err != nil {
		t.Fatalf("explicit GarageKey target rejected: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongFromKind(t *testing.T) {
	g := grant("GarageBucket", testSourceNS, garageClusterKind, "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for GarageBucket should not satisfy GarageKey reference")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongFromNamespace(t *testing.T) {
	g := grant(kindGarageKey, "ns-c", garageClusterKind, "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for ns-c should not satisfy reference from ns-a")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WrongToName(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, garageClusterKind, "other-cluster")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "my-cluster")
	if err == nil {
		t.Error("grant for 'other-cluster' should not satisfy reference to 'my-cluster'")
	}
}

func TestCheckReferenceGrant_CrossNamespace_WildcardToName(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, garageClusterKind, "") // Name="" means all clusters
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, "any-cluster")
	if err != nil {
		t.Errorf("wildcard name in To should allow any cluster, got: %v", err)
	}
}

func TestCheckReferenceGrant_BucketRef(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, "GarageBucket", "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, "GarageBucket", testTargetNS, "my-bucket")
	if err != nil {
		t.Errorf("should be allowed for bucket cross-ns ref with grant, got: %v", err)
	}
}

func TestCheckReferenceGrant_CrossNamespace_WithMatchingNamespaceSelector(t *testing.T) {
	grant := grant(kindGarageKey, "", garageClusterKind, testCluster)
	grant.Spec.From[0].NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{
		"garage.example.com/application": "app01",
	}}
	sourceNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: testSourceNS,
		Labels: map[string]string{
			"garage.example.com/application": "app01",
		},
	}}
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(grant, sourceNamespace).Build()

	if err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, testCluster); err != nil {
		t.Fatalf("matching namespace selector denied reference: %v", err)
	}
}

func TestGrantPermitsForNamespace_MatchExpressions(t *testing.T) {
	grant := grant(kindGarageKey, "", garageClusterKind, testCluster)
	grant.Spec.From[0].NamespaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      "garage.example.com/environment",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"prod", "dr"},
	}}}

	if !GrantPermitsForNamespace(grant, kindGarageKey, testSourceNS, garageClusterKind, testCluster, map[string]string{
		"garage.example.com/environment": "prod",
	}) {
		t.Fatal("matching matchExpressions selector did not authorize reference")
	}
	if GrantPermitsForNamespace(grant, kindGarageKey, testSourceNS, garageClusterKind, testCluster, map[string]string{
		"garage.example.com/environment": "stage",
	}) {
		t.Fatal("non-matching matchExpressions selector authorized reference")
	}
}

func TestCheckReferenceGrant_NamespaceSelectorFailsClosed(t *testing.T) {
	selectorGrant := grant(kindGarageKey, "", garageClusterKind, testCluster)
	selectorGrant.Spec.From[0].NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{
		"garage.example.com/application": "app01",
	}}

	tests := []struct {
		name    string
		objects []runtime.Object
	}{
		{
			name: "source namespace labels do not match",
			objects: []runtime.Object{selectorGrant, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: testSourceNS,
				Labels: map[string]string{
					"garage.example.com/application": "other",
				},
			}}},
		},
		{
			name:    "source namespace is missing",
			objects: []runtime.Object{selectorGrant},
		},
		{
			name: "persisted invalid selector",
			objects: []runtime.Object{func() *GarageReferenceGrant {
				invalid := selectorGrant.DeepCopy()
				invalid.Spec.From[0].NamespaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "garage.example.com/application",
					Operator: metav1.LabelSelectorOperator("not-a-selector-operator"),
				}}}
				return invalid
			}(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: testSourceNS,
				Labels: map[string]string{
					"garage.example.com/application": "app01",
				},
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithRuntimeObjects(tt.objects...).Build()
			err := checkReferenceGrant(context.Background(), c, kindGarageKey, testSourceNS, garageClusterKind, testTargetNS, testCluster)
			if err == nil || !strings.Contains(err.Error(), "not permitted") {
				t.Fatalf("selector grant unexpectedly authorized reference: %v", err)
			}
		})
	}
}

func TestGarageReferenceGrantValidatorNamespaceSelector(t *testing.T) {
	newGrant := func(from ReferenceGrantFrom) *GarageReferenceGrant {
		return &GarageReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: testTargetNS},
			Spec: GarageReferenceGrantSpec{
				From: []ReferenceGrantFrom{from},
			},
		}
	}

	t.Run("valid selector", func(t *testing.T) {
		_, err := validateReferenceGrant(newGrant(ReferenceGrantFrom{
			Kind: kindGarageKey,
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"garage.example.com/application": "app01",
			}},
		}))
		if err != nil {
			t.Fatalf("valid namespace selector rejected: %v", err)
		}
	})

	for _, tt := range []struct {
		name string
		from ReferenceGrantFrom
	}{
		{name: "neither namespace nor selector", from: ReferenceGrantFrom{Kind: kindGarageKey}},
		{name: "both namespace and selector", from: ReferenceGrantFrom{
			Kind:      kindGarageKey,
			Namespace: testSourceNS,
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				"garage.example.com/application": "app01",
			}},
		}},
		{name: "invalid selector", from: ReferenceGrantFrom{
			Kind: kindGarageKey,
			NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "garage.example.com/application",
				Operator: metav1.LabelSelectorOperator("not-a-selector-operator"),
			}}},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateReferenceGrant(newGrant(tt.from))
			if err == nil {
				t.Fatal("invalid namespace selector grant was accepted")
			}
		})
	}

	t.Run("empty selector warns", func(t *testing.T) {
		warnings, err := validateReferenceGrant(newGrant(ReferenceGrantFrom{
			Kind:              kindGarageKey,
			NamespaceSelector: &metav1.LabelSelector{},
		}))
		if err != nil {
			t.Fatalf("empty selector rejected: %v", err)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "matches every namespace") {
			t.Fatalf("warnings = %v, want broad-selector warning", warnings)
		}
	})
}

// ── GarageKeyValidator ────────────────────────────────────────────────────────

func TestGarageKeyValidator_SameNamespaceClusterRef(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("same-namespace clusterRef should be allowed: %v", err)
	}
}

func TestGarageKeyValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageKeyValidator_CrossNamespaceClusterRef_WithGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, garageClusterKind, testCluster)
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("cross-namespace clusterRef with grant should be allowed: %v", err)
	}
}

func TestRevokedClusterGrantAllowsOnlyUnchangedDependentCleanupUpdates(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	t.Run("GarageKey", func(t *testing.T) {
		clusterGrant := grant(kindGarageKey, testSourceNS, garageClusterKind, testCluster)
		bucketGrant := grant(kindGarageKey, testSourceNS, "GarageBucket", testBucket)
		bucketGrant.Name = "bucket-grant"
		c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(clusterGrant, bucketGrant).Build()
		validator := &GarageKeyValidator{Client: c}
		key := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
				BucketPermissions: []BucketPermission{{
					BucketRef: &BucketRef{Name: testBucket, Namespace: testTargetNS}, Read: true,
				}},
			},
		}
		if err := (&GarageKeyDefaulter{}).Default(ctx, key); err != nil {
			t.Fatalf("default: %v", err)
		}
		if _, err := validator.ValidateCreate(ctx, key); err != nil {
			t.Fatalf("create with grant: %v", err)
		}
		if err := c.Delete(ctx, clusterGrant); err != nil {
			t.Fatalf("revoke cluster grant: %v", err)
		}
		if err := c.Delete(ctx, bucketGrant); err != nil {
			t.Fatalf("revoke bucket grant: %v", err)
		}

		key.DeletionTimestamp = &now
		key.Finalizers = []string{testCleanupFinalizer}
		cleanup := key.DeepCopy()
		cleanup.Finalizers = nil
		cleanup.Labels = map[string]string{"repair": "true"}
		if _, err := validator.ValidateUpdate(ctx, key, cleanup); err != nil {
			t.Fatalf("unchanged cross-namespace finalizer/metadata cleanup after grant revocation: %v", err)
		}

		changed := cleanup.DeepCopy()
		changed.Spec.BucketPermissions[0].Write = true
		if _, err := validator.ValidateUpdate(ctx, key, changed); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("spec change after grant revocation was not denied: %v", err)
		}
		createAfterRevocation := key.DeepCopy()
		createAfterRevocation.DeletionTimestamp = nil
		createAfterRevocation.Finalizers = nil
		if _, err := validator.ValidateCreate(ctx, createAfterRevocation); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("create after grant revocation was not denied: %v", err)
		}
	})

	t.Run("GarageBucket", func(t *testing.T) {
		g := grant("GarageBucket", testSourceNS, garageClusterKind, testCluster)
		c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
		validator := &GarageBucketValidator{Client: c}
		bucket := &GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
			Spec: GarageBucketSpec{
				ClusterRef:  ClusterReference{Name: testCluster, Namespace: testTargetNS},
				GlobalAlias: testValidBucketAlias,
			},
		}
		if err := (&GarageBucketDefaulter{}).Default(ctx, bucket); err != nil {
			t.Fatalf("default: %v", err)
		}
		if _, err := validator.ValidateCreate(ctx, bucket); err != nil {
			t.Fatalf("create with grant: %v", err)
		}
		if err := c.Delete(ctx, g); err != nil {
			t.Fatalf("revoke grant: %v", err)
		}

		bucket.DeletionTimestamp = &now
		bucket.Finalizers = []string{testCleanupFinalizer}
		cleanup := bucket.DeepCopy()
		cleanup.Finalizers = nil
		cleanup.Annotations = map[string]string{"repair": "true"}
		if _, err := validator.ValidateUpdate(ctx, bucket, cleanup); err != nil {
			t.Fatalf("unchanged cross-namespace finalizer/metadata cleanup after grant revocation: %v", err)
		}

		changed := cleanup.DeepCopy()
		changed.Spec.GlobalAlias = "changed-bucket"
		if _, err := validator.ValidateUpdate(ctx, bucket, changed); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("spec change after grant revocation was not denied: %v", err)
		}
		createAfterRevocation := bucket.DeepCopy()
		createAfterRevocation.DeletionTimestamp = nil
		createAfterRevocation.Finalizers = nil
		if _, err := validator.ValidateCreate(ctx, createAfterRevocation); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("create after grant revocation was not denied: %v", err)
		}
	})
}

func TestGarageBucketDeletionPolicy(t *testing.T) {
	ctx := context.Background()
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}},
	}
	if err := (&GarageBucketDefaulter{}).Default(ctx, bucket); err != nil {
		t.Fatalf("default: %v", err)
	}
	if bucket.Spec.EffectiveDeletionPolicy() != BucketDeletionPolicyDelete {
		t.Fatalf("effective deletionPolicy = %q, want Delete", bucket.Spec.EffectiveDeletionPolicy())
	}
	for _, policy := range []BucketDeletionPolicy{BucketDeletionPolicyDelete, BucketDeletionPolicyRetain} {
		bucket.Spec.DeletionPolicy = policy
		if err := ValidateGarageBucketSpec(bucket); err != nil {
			t.Fatalf("validate %q: %v", policy, err)
		}
	}
	bucket.Spec.DeletionPolicy = "Invalid"
	if err := ValidateGarageBucketSpec(bucket); err == nil || !strings.Contains(err.Error(), "deletionPolicy") {
		t.Fatalf("invalid deletionPolicy error = %v", err)
	}
}

func TestGarageBucketEffectiveDeletionPolicyDefaultsToDelete(t *testing.T) {
	if got := (&GarageBucketSpec{}).EffectiveDeletionPolicy(); got != BucketDeletionPolicyDelete {
		t.Fatalf("effective policy = %q, want Delete", got)
	}
	if got := (&GarageBucketSpec{DeletionPolicy: BucketDeletionPolicyRetain}).EffectiveDeletionPolicy(); got != BucketDeletionPolicyRetain {
		t.Fatalf("effective policy = %q, want Retain", got)
	}
}

func TestGarageKeyValidatorAllowsOnlyUnchangedLegacyAliasCleanup(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	old := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: testKey, Namespace: testSourceNS, DeletionTimestamp: &now,
			Finalizers: []string{testCleanupFinalizer},
		},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{{
				GlobalAlias: "127.0.0.1", Read: true,
			}},
		},
	}
	if err := (&GarageKeyDefaulter{}).Default(ctx, old); err != nil {
		t.Fatalf("default legacy key: %v", err)
	}
	cleanup := old.DeepCopy()
	cleanup.Finalizers = nil
	cleanup.Labels = map[string]string{"repair": "true"}
	if _, err := validator.ValidateUpdate(ctx, old, cleanup); err != nil {
		t.Fatalf("unchanged legacy alias blocked finalizer cleanup: %v", err)
	}

	changed := cleanup.DeepCopy()
	changed.Spec.BucketPermissions[0].GlobalAlias = "127.0.0.2"
	if _, err := validator.ValidateUpdate(ctx, old, changed); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("changed invalid legacy alias was not rejected: %v", err)
	}
	create := old.DeepCopy()
	create.DeletionTimestamp = nil
	create.Finalizers = nil
	if _, err := validator.ValidateCreate(ctx, create); err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("new invalid alias was not rejected: %v", err)
	}
}

func TestBucketAndKeyValidatorsAllowOnlyUnchangedLegacyReferenceCleanup(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()

	t.Run("GarageKey bucketRef", func(t *testing.T) {
		validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
		old := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: testKey, Namespace: testSourceNS, DeletionTimestamp: &now,
				Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: testCluster},
				BucketPermissions: []BucketPermission{{
					BucketRef: &BucketRef{Name: "Bad_Bucket"}, Read: true,
				}},
			},
		}
		if err := (&GarageKeyDefaulter{}).Default(ctx, old); err != nil {
			t.Fatalf("default legacy key: %v", err)
		}
		cleanup := old.DeepCopy()
		cleanup.Finalizers = nil
		if _, err := validator.ValidateUpdate(ctx, old, cleanup); err != nil {
			t.Fatalf("unchanged invalid bucketRef blocked finalizer cleanup: %v", err)
		}
		changed := cleanup.DeepCopy()
		changed.Spec.BucketPermissions[0].BucketRef.Name = "Other_Bad_Bucket"
		if _, err := validator.ValidateUpdate(ctx, old, changed); err == nil || !strings.Contains(err.Error(), "is invalid") {
			t.Fatalf("changed invalid bucketRef was accepted: %v", err)
		}
	})

	t.Run("GarageBucket keyRef", func(t *testing.T) {
		validator := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
		old := &GarageBucket{
			ObjectMeta: metav1.ObjectMeta{
				Name: testBucket, Namespace: testSourceNS, DeletionTimestamp: &now,
				Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageBucketSpec{
				ClusterRef:  ClusterReference{Name: testCluster},
				GlobalAlias: testValidBucketAlias,
				KeyPermissions: []KeyPermission{{
					KeyRef: KeyRef{Name: "Bad_Key"}, Read: true,
				}},
			},
		}
		cleanup := old.DeepCopy()
		cleanup.Finalizers = nil
		if _, err := validator.ValidateUpdate(ctx, old, cleanup); err != nil {
			t.Fatalf("unchanged invalid keyRef blocked finalizer cleanup: %v", err)
		}
		changed := cleanup.DeepCopy()
		changed.Spec.KeyPermissions[0].KeyRef.Name = "Other_Bad_Key"
		if _, err := validator.ValidateUpdate(ctx, old, changed); err == nil || !strings.Contains(err.Error(), "is invalid") {
			t.Fatalf("changed invalid keyRef was accepted: %v", err)
		}
	})

	t.Run("GarageKey equivalent bucketRefs", func(t *testing.T) {
		validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
		old := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: testKey, Namespace: testSourceNS, DeletionTimestamp: &now,
				Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: testCluster},
				BucketPermissions: []BucketPermission{
					{BucketRef: &BucketRef{Name: testBucket}, Read: true},
					{BucketRef: &BucketRef{Name: testBucket, Namespace: testSourceNS}, Write: true},
				},
			},
		}
		if err := (&GarageKeyDefaulter{}).Default(ctx, old); err != nil {
			t.Fatalf("default legacy key: %v", err)
		}
		cleanup := old.DeepCopy()
		cleanup.Finalizers = nil
		if _, err := validator.ValidateUpdate(ctx, old, cleanup); err != nil {
			t.Fatalf("unchanged equivalent bucketRefs blocked finalizer cleanup: %v", err)
		}
	})

	t.Run("GarageBucket equivalent keyRefs", func(t *testing.T) {
		validator := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
		old := &GarageBucket{
			ObjectMeta: metav1.ObjectMeta{
				Name: testBucket, Namespace: testSourceNS, DeletionTimestamp: &now,
				Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageBucketSpec{
				ClusterRef:  ClusterReference{Name: testCluster},
				GlobalAlias: testValidBucketAlias,
				KeyPermissions: []KeyPermission{
					{KeyRef: KeyRef{Name: testKey}, Read: true},
					{KeyRef: KeyRef{Name: testKey, Namespace: testSourceNS}, Write: true},
				},
			},
		}
		cleanup := old.DeepCopy()
		cleanup.Finalizers = nil
		if _, err := validator.ValidateUpdate(ctx, old, cleanup); err != nil {
			t.Fatalf("unchanged equivalent keyRefs blocked finalizer cleanup: %v", err)
		}
	})
}

func TestValidateGarageKeySpecNormalizesBucketRefNamespaceForDuplicates(t *testing.T) {
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: testBucket}, Read: true},
				{BucketRef: &BucketRef{Name: testBucket, Namespace: testSourceNS}, Write: true},
			},
		},
	}
	if err := ValidateGarageKeySpec(key); err == nil || !strings.Contains(err.Error(), "duplicate bucket reference") {
		t.Fatalf("empty and explicit object namespace were not treated as the same bucketRef: %v", err)
	}
}

func TestValidateGarageBucketSpecNormalizesKeyRefNamespaceForDuplicates(t *testing.T) {
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec: GarageBucketSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			KeyPermissions: []KeyPermission{
				{KeyRef: KeyRef{Name: testKey}, Read: true},
				{KeyRef: KeyRef{Name: testKey, Namespace: testSourceNS}, Write: true},
			},
		},
	}
	if err := ValidateGarageBucketSpec(bucket); err == nil || !strings.Contains(err.Error(), "duplicate keyRef") {
		t.Fatalf("empty and explicit object namespace were not treated as the same keyRef: %v", err)
	}
}

func TestReferencedObjectNamesAndNamespacesMustBeValid(t *testing.T) {
	tests := []struct {
		name string
		err  func() error
	}{
		{
			name: "GarageKey bucketRef name",
			err: func() error {
				return ValidateGarageKeySpec(&GarageKey{
					ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
					Spec: GarageKeySpec{
						ClusterRef:        ClusterReference{Name: testCluster},
						BucketPermissions: []BucketPermission{{BucketRef: &BucketRef{Name: "Bad_Bucket"}, Read: true}},
					},
				})
			},
		},
		{
			name: "GarageKey bucketRef namespace",
			err: func() error {
				return ValidateGarageKeySpec(&GarageKey{
					ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
					Spec: GarageKeySpec{
						ClusterRef:        ClusterReference{Name: testCluster},
						BucketPermissions: []BucketPermission{{BucketRef: &BucketRef{Name: testBucket, Namespace: "Bad_Namespace"}, Read: true}},
					},
				})
			},
		},
		{
			name: "GarageBucket keyRef name",
			err: func() error {
				return ValidateGarageBucketSpec(&GarageBucket{
					ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
					Spec: GarageBucketSpec{
						ClusterRef:     ClusterReference{Name: testCluster},
						KeyPermissions: []KeyPermission{{KeyRef: KeyRef{Name: "Bad_Key"}, Read: true}},
					},
				})
			},
		},
		{
			name: "GarageBucket keyRef namespace",
			err: func() error {
				return ValidateGarageBucketSpec(&GarageBucket{
					ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
					Spec: GarageBucketSpec{
						ClusterRef:     ClusterReference{Name: testCluster},
						KeyPermissions: []KeyPermission{{KeyRef: KeyRef{Name: testKey, Namespace: "Bad_Namespace"}, Read: true}},
					},
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.err(); err == nil || !strings.Contains(err.Error(), "is invalid") {
				t.Fatalf("invalid reference was accepted: %v", err)
			}
		})
	}
}

func TestEveryClusterReferenceConsumerRejectsMalformedReferences(t *testing.T) {
	size := resource.MustParse("1Gi")
	consumers := []struct {
		name     string
		validate func(ClusterReference) error
	}{
		{
			name: "GarageKey",
			validate: func(ref ClusterReference) error {
				return ValidateGarageKeySpec(&GarageKey{ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS}, Spec: GarageKeySpec{
					ClusterRef: ref, AllBuckets: &AllBucketsPermission{Read: true},
				}})
			},
		},
		{
			name: "GarageBucket",
			validate: func(ref ClusterReference) error {
				return ValidateGarageBucketSpec(&GarageBucket{ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS}, Spec: GarageBucketSpec{
					ClusterRef: ref, GlobalAlias: testValidBucketAlias,
				}})
			},
		},
		{
			name: "GarageAdminToken",
			validate: func(ref ClusterReference) error {
				_, err := (&GarageAdminTokenValidator{}).validateGarageAdminTokenWithOptions(t.Context(), &GarageAdminToken{
					ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS}, Spec: GarageAdminTokenSpec{ClusterRef: ref},
				}, false)
				return err
			},
		},
		{
			name: "GarageNode",
			validate: func(ref ClusterReference) error {
				_, err := (&GarageNode{ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: testSourceNS}, Spec: GarageNodeSpec{
					ClusterRef: ref, Zone: testZone, Gateway: true,
					Storage: &NodeStorageConfig{Metadata: &NodeVolumeConfig{Size: &size}},
				}}).validateGarageNode()
				return err
			},
		},
		{
			name: "v1beta1 GarageCluster connectTo",
			validate: func(ref ClusterReference) error {
				return (&GarageCluster{ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS}, Spec: GarageClusterSpec{
					Gateway: true, ConnectTo: &ConnectToConfig{ClusterRef: &ref},
				}}).validateGateway()
			},
		},
	}
	for _, consumer := range consumers {
		for _, ref := range []ClusterReference{
			{Name: "Bad_Cluster"},
			{Name: testCluster, Namespace: "Bad_Namespace"},
		} {
			t.Run(consumer.name+"/"+ref.Name+"/"+ref.Namespace, func(t *testing.T) {
				if err := consumer.validate(ref); err == nil {
					t.Fatal("malformed cluster reference was accepted")
				}
			})
		}
	}
}

func TestMalformedLegacyClusterReferencesAreCleanableButNotChangeable(t *testing.T) {
	ctx := t.Context()
	size := resource.MustParse("1Gi")
	tests := []struct {
		name     string
		validate func() (cleanupErr, changedErr error)
	}{
		{
			name: "GarageAdminToken",
			validate: func() (error, error) {
				old := &GarageAdminToken{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: testSourceNS, Finalizers: []string{testCleanupFinalizer}}, Spec: GarageAdminTokenSpec{
					ClusterRef: ClusterReference{Name: "Bad_Cluster"},
				}}
				cleanup := old.DeepCopy()
				cleanup.Finalizers = nil
				cleanup.Labels = map[string]string{"repair": "true"}
				_, cleanupErr := (&GarageAdminTokenValidator{}).ValidateUpdate(ctx, old, cleanup)
				changed := cleanup.DeepCopy()
				changed.Spec.ClusterRef.Name = "Other_Bad_Cluster"
				_, changedErr := (&GarageAdminTokenValidator{}).ValidateUpdate(ctx, old, changed)
				return cleanupErr, changedErr
			},
		},
		{
			name: "GarageNode",
			validate: func() (error, error) {
				old := &GarageNode{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: testSourceNS, Finalizers: []string{testCleanupFinalizer}}, Spec: GarageNodeSpec{
					ClusterRef: ClusterReference{Name: "Bad_Cluster"}, Zone: testZone, Gateway: true,
					Storage: &NodeStorageConfig{Metadata: &NodeVolumeConfig{Size: &size}},
				}}
				cleanup := old.DeepCopy()
				cleanup.Finalizers = nil
				cleanup.Labels = map[string]string{"repair": "true"}
				validator := &GarageNodeValidator{}
				_, cleanupErr := validator.ValidateUpdate(ctx, old, cleanup)
				changed := cleanup.DeepCopy()
				changed.Spec.ClusterRef.Name = "Other_Bad_Cluster"
				_, changedErr := validator.ValidateUpdate(ctx, old, changed)
				return cleanupErr, changedErr
			},
		},
		{
			name: "v1beta1 GarageCluster",
			validate: func() (error, error) {
				old := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: testSourceNS, Finalizers: []string{testCleanupFinalizer}}, Spec: GarageClusterSpec{
					ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "Bad_Cluster"}},
				}}
				cleanup := old.DeepCopy()
				cleanup.Finalizers = nil
				cleanup.Labels = map[string]string{"repair": "true"}
				if err := (&GarageClusterDefaulter{}).Default(ctx, cleanup); err != nil {
					return err, err
				}
				validator := &GarageClusterValidator{}
				_, cleanupErr := validator.ValidateUpdate(ctx, old, cleanup)
				changed := cleanup.DeepCopy()
				changed.Spec.ConnectTo.ClusterRef.Name = "Other_Bad_Cluster"
				_, changedErr := validator.ValidateUpdate(ctx, old, changed)
				return cleanupErr, changedErr
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanupErr, changedErr := test.validate()
			if cleanupErr != nil {
				t.Fatalf("metadata/finalizer cleanup was rejected: %v", cleanupErr)
			}
			if changedErr == nil {
				t.Fatal("changed malformed cluster reference was accepted")
			}
		})
	}
}

func TestGarageAuthorizationWebhooksIgnoreStaleCachedGrants(t *testing.T) {
	ctx := context.Background()
	scheme := fakeScheme(t)
	authoritative := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("GarageKey", func(t *testing.T) {
		cached := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(grant(kindGarageKey, testSourceNS, garageClusterKind, testCluster)).Build()
		validator := &GarageKeyValidator{Client: cached, AuthorizationReader: authoritative}
		key := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
				AllBuckets: &AllBucketsPermission{Read: true},
			},
		}
		if _, err := validator.ValidateCreate(ctx, key); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("stale cached GarageKey grant authorized create: %v", err)
		}
	})

	t.Run("GarageBucket", func(t *testing.T) {
		cached := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(grant("GarageBucket", testSourceNS, garageClusterKind, testCluster)).Build()
		validator := &GarageBucketValidator{Client: cached, AuthorizationReader: authoritative}
		bucket := &GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
			Spec: GarageBucketSpec{
				ClusterRef:  ClusterReference{Name: testCluster, Namespace: testTargetNS},
				GlobalAlias: testValidBucketAlias,
			},
		}
		if _, err := validator.ValidateCreate(ctx, bucket); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
			t.Fatalf("stale cached GarageBucket grant authorized create: %v", err)
		}
	})
}

func TestGarageKeyValidator_CrossNamespaceBucketRef_NoGrant(t *testing.T) {
	g := grant(kindGarageKey, testSourceNS, garageClusterKind, "") // only cluster grant, no bucket grant
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: "my-bucket", Namespace: testTargetNS}, Read: true},
			},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err == nil {
		t.Error("cross-namespace bucketRef without bucket grant should be denied")
	}
	if err != nil && !strings.Contains(err.Error(), "bucketPermissions[0]") {
		t.Errorf("error should mention bucketPermissions[0], got: %v", err)
	}
}

func TestGarageKeyValidator_CrossNamespaceBucketRef_WithGrant(t *testing.T) {
	clusterGrant := grant(kindGarageKey, testSourceNS, garageClusterKind, "")
	bucketGrant := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-grant", Namespace: testTargetNS},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
			To:   []ReferenceGrantTo{{Kind: "GarageBucket"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(clusterGrant, bucketGrant).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: "my-bucket", Namespace: testTargetNS}, Read: true},
			},
		},
	}
	_, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("cross-namespace bucketRef with grant should be allowed: %v", err)
	}
}

func TestGarageKey_BucketPermission_BucketRefObject_Valid(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{
					BucketRef: &BucketRef{Name: testBucket},
					Read:      true,
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid BucketRef object should pass, got: %v", err)
	}
}

func TestGarageKey_BucketPermission_NoRef_Rejected(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			BucketPermissions: []BucketPermission{
				{Read: true},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "must specify") {
		t.Errorf("expected must-specify error, got: %v", err)
	}
}

// ── GarageBucketValidator ─────────────────────────────────────────────────────

func TestGarageBucketValidator_SameNamespaceClusterRef(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err != nil {
		t.Errorf("same-namespace clusterRef should be allowed: %v", err)
	}
}

func TestGarageBucketValidator_RejectsNegativeQuotas(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageBucketValidator{Client: c}
	negativeObjects := int64(-1)
	negativeSize := resource.MustParse("-1Gi")
	for name, quotas := range map[string]*BucketQuotas{
		"maxObjects": {MaxObjects: &negativeObjects},
		"maxSize":    {MaxSize: &negativeSize},
	} {
		t.Run(name, func(t *testing.T) {
			bucket := &GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
				Spec: GarageBucketSpec{
					ClusterRef: ClusterReference{Name: testCluster},
					Quotas:     quotas,
				},
			}
			_, err := v.ValidateCreate(context.Background(), bucket)
			if err == nil || !strings.Contains(err.Error(), "must be >= 0") {
				t.Fatalf("negative quota should be rejected, got %v", err)
			}
		})
	}
}

func TestGarageBucketValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageBucketValidator_CrossNamespaceClusterRef_WithGrant(t *testing.T) {
	g := grant("GarageBucket", testSourceNS, garageClusterKind, testCluster)
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageBucketValidator{Client: c}
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageBucket(context.Background(), bucket)
	if err != nil {
		t.Errorf("cross-namespace clusterRef with grant should be allowed: %v", err)
	}
}

// ── GarageAdminTokenValidator ─────────────────────────────────────────────────

func TestGarageAdminTokenValidator_CrossNamespaceClusterRef_NoGrant(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageAdminTokenValidator{Client: c}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec:       GarageAdminTokenSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageAdminToken(context.Background(), token)
	if err == nil {
		t.Error("cross-namespace clusterRef without grant should be denied")
	}
}

func TestGarageAdminTokenValidator_CrossNamespaceClusterRef_GrantCannotMakeStaticSecretConsumable(t *testing.T) {
	g := grant("GarageAdminToken", testSourceNS, garageClusterKind, "")
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(g).Build()
	v := &GarageAdminTokenValidator{Client: c}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS},
		Spec:       GarageAdminTokenSpec{ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS}},
	}
	_, err := v.validateGarageAdminToken(context.Background(), token)
	if err == nil || !strings.Contains(err.Error(), "must match") {
		t.Errorf("cross-namespace static bootstrap source should be rejected even with a grant: %v", err)
	}
}

func TestGarageAdminTokenValidator_RejectsFakeDynamicSemantics(t *testing.T) {
	v := &GarageAdminTokenValidator{}
	for _, token := range []*GarageAdminToken{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "named", Namespace: testSourceNS},
			Spec: GarageAdminTokenSpec{
				ClusterRef: ClusterReference{Name: testCluster}, Name: "not-a-server-side-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "expiring", Namespace: testSourceNS},
			Spec: GarageAdminTokenSpec{
				ClusterRef: ClusterReference{Name: testCluster}, ExpiresAt: &metav1.Time{Time: time.Now().Add(time.Hour)},
			},
		},
	} {
		if _, err := v.validateGarageAdminToken(context.Background(), token); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("misleading static-token semantics were accepted: %v", err)
		}
	}
}

func TestGarageAdminTokenValidator_DeleteRequiresClusterDereference(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testCluster, Namespace: testSourceNS},
		Spec: v1beta2.GarageClusterSpec{Admin: &v1beta2.AdminConfig{
			AdminTokenSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "bootstrap"},
				Key:                  garageAdminTokenDefaultKey,
			},
		}},
	}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: testSourceNS},
		Spec: GarageAdminTokenSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			SecretTemplate: &AdminTokenSecretTemplate{
				Name: "bootstrap", TokenKey: garageAdminTokenDefaultKey,
			},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	validator := &GarageAdminTokenValidator{Client: client}
	if _, err := validator.ValidateDelete(context.Background(), token); err == nil || !strings.Contains(err.Error(), "still references") {
		t.Fatalf("deletion removed a live cluster's static bootstrap source: %v", err)
	}

	cluster.Spec.Admin.AdminTokenSecretRef.Name = "replacement"
	if err := client.Update(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ValidateDelete(context.Background(), token); err != nil {
		t.Fatalf("deletion remained blocked after exact cluster dereference: %v", err)
	}
}

func TestGarageAdminTokenValidator_UsesEffectiveDefaultKeys(t *testing.T) {
	v := &GarageAdminTokenValidator{}
	token := &GarageAdminToken{
		ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: testSourceNS},
		Spec: GarageAdminTokenSpec{
			ClusterRef:     ClusterReference{Name: testCluster},
			SecretTemplate: &AdminTokenSecretTemplate{TokenKey: "admin-endpoint"},
		},
	}
	if _, err := v.validateGarageAdminToken(context.Background(), token); err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("token key collided with the effective default endpoint key: %v", err)
	}
}

// ── GarageNodeValidator: cross-namespace always blocked ───────────────────────

func TestGarageNodeValidator_CrossNamespaceBlocked(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testTargetNS},
			Zone:       testZone,
			Capacity:   func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }(),
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
			},
		},
	}
	_, err := node.validateGarageNode()
	if err == nil {
		t.Error("cross-namespace clusterRef on GarageNode should always be blocked")
	}
	if err != nil && !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGarageNodeValidator_SameNamespaceExplicit(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS}, // explicit but same NS
			Zone:       testZone,
			Capacity:   func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }(),
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{Size: func() *resource.Quantity { q := resource.MustParse("100Gi"); return &q }()},
			},
		},
	}
	_, err := node.validateGarageNode()
	if err != nil {
		t.Errorf("same-namespace explicit clusterRef on GarageNode should be allowed: %v", err)
	}
}

func TestGarageNodeValidator_RejectsUnsupportedRemoteClusterRef(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			Zone:       testZone,
			Gateway:    true,
			External: &ExternalNodeConfig{
				Address:          "garage.example.test",
				Port:             3901,
				RemoteClusterRef: &ClusterReference{Name: "remote"},
			},
		},
	}
	_, err := node.validateGarageNode()
	if err == nil || !strings.Contains(err.Error(), "external.remoteClusterRef is not supported") {
		t.Fatalf("unsupported external remoteClusterRef should be rejected, got %v", err)
	}
}

func TestGarageNodeValidator_DeleteRequiresExactCompletedPreparation(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 to scheme: %v", err)
	}
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testCluster, Namespace: testSourceNS, UID: testClusterUID, Generation: 5,
		},
		Spec: v1beta2.GarageClusterSpec{
			Storage:     &v1beta2.StorageSpec{},
			Replication: &v1beta2.ReplicationConfig{Factor: 2, ConsistencyMode: consistencyModeConsistent},
		},
		Status: v1beta2.GarageClusterStatus{
			Conditions: []metav1.Condition{{
				Type: ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
				Reason: "Converged", ObservedGeneration: 5,
			}},
			Health: &v1beta2.ClusterHealth{
				Status: healthStatusHealthy, Healthy: true, Available: true,
				StorageNodes: 2, StorageNodesOK: 2,
				Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
			},
		},
	}
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: testSourceNS, UID: testNodeUID,
			Annotations: map[string]string{AnnotationDrain: stringTrue},
		},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster}, Zone: testZone,
			Capacity: mustQty("100Gi"),
			Storage:  &NodeStorageConfig{Data: &NodeVolumeConfig{Size: mustQty("100Gi")}},
		},
		Status: GarageNodeStatus{NodeID: testRemovedNodeID},
	}

	validator := func(c *v1beta2.GarageCluster) *GarageNodeValidator {
		reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(c).Build()
		return &GarageNodeValidator{apiReader: reader}
	}
	if _, err := validator(cluster.DeepCopy()).ValidateDelete(context.Background(), node); err == nil ||
		!strings.Contains(err.Error(), "prepared operation") {
		t.Fatalf("unprepared positive-capacity delete was accepted: %v", err)
	}

	prepared := cluster.DeepCopy()
	prepared.Status.StorageDrain = &v1beta2.StorageDrainStatus{
		Actor: v1beta2.StorageDrainActorStatus{
			APIVersion: GroupVersion.String(), Kind: garageNodeKind,
			Namespace: node.Namespace, Name: node.Name, UID: string(node.UID),
		},
		TransactionID: "txn",
		TargetHash: storagecontract.TargetHash(
			[]string{testRemovedNodeID}, []string{testRemovedNodeID},
		),
		StartedAt:          metav1.Now(),
		RoleRemovalNodeIDs: []string{testRemovedNodeID}, RemovedStorageNodeIDs: []string{testRemovedNodeID},
		ManagedPodUIDs: map[string]string{testRemovedNodeID: "source-pod-uid"},
	}
	if _, err := validator(prepared.DeepCopy()).ValidateDelete(context.Background(), node); err == nil ||
		!strings.Contains(err.Error(), "terminal drain preparation is invalid") {
		t.Fatalf("incomplete storage-drain transaction authorized delete: %v", err)
	}

	completedAt := metav1.Now()
	prepared.Status.StorageDrain.CompletedAt = &completedAt
	if _, err := validator(prepared).ValidateDelete(context.Background(), node); err != nil {
		t.Fatalf("exact completed drain preparation was rejected: %v", err)
	}
}

func TestGarageNodeValidator_DeleteHandlesNilObject(t *testing.T) {
	if warnings, err := (&GarageNodeValidator{}).ValidateDelete(context.Background(), nil); err != nil || warnings != nil {
		t.Fatalf("nil delete object should be ignored safely, got warnings=%v err=%v", warnings, err)
	}
}

func TestGarageNodeValidator_ManagedGatewayRejectsDirectForegroundDelete(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 to scheme: %v", err)
	}
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testCluster, Namespace: testSourceNS, UID: testClusterUID},
		Spec:       v1beta2.GarageClusterSpec{Storage: &v1beta2.StorageSpec{}},
	}
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-a", Namespace: testSourceNS, UID: testNodeUID},
		Spec: GarageNodeSpec{
			Gateway: true, ClusterRef: ClusterReference{Name: cluster.Name},
		},
		Status: GarageNodeStatus{NodeID: testRemovedNodeID},
	}
	deleteOptions, err := json.Marshal(metav1.DeleteOptions{PropagationPolicy: ptrDeletePropagation(metav1.DeletePropagationForeground)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Options: runtime.RawExtension{Raw: deleteOptions},
	}})
	validator := func(owner *v1beta2.GarageCluster) *GarageNodeValidator {
		reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(owner).Build()
		return &GarageNodeValidator{apiReader: reader}
	}
	if _, err := validator(cluster.DeepCopy()).ValidateDelete(ctx, node); err == nil || !strings.Contains(err.Error(), "managed gateway GarageNode") {
		t.Fatalf("direct foreground gateway deletion was not rejected: %v", err)
	}
	if _, err := validator(cluster.DeepCopy()).ValidateDelete(context.Background(), node); err != nil {
		t.Fatalf("background/default gateway deletion was rejected: %v", err)
	}
	parentDeleting := cluster.DeepCopy()
	now := metav1.Now()
	parentDeleting.DeletionTimestamp = &now
	parentDeleting.Finalizers = []string{"test-parent-finalizer"}
	if _, err := validator(parentDeleting).ValidateDelete(ctx, node); err != nil {
		t.Fatalf("parent-owned foreground gateway deletion was rejected after parent finalization took ownership: %v", err)
	}

	storageNode := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testStorageNodeName, Namespace: testSourceNS, UID: "storage-node-uid"},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: cluster.Name}, Zone: testZone,
			Capacity: mustQty("1Gi"),
			Storage:  &NodeStorageConfig{Data: &NodeVolumeConfig{Size: mustQty("1Gi")}},
		},
		Status: GarageNodeStatus{NodeID: testRemovedNodeID},
	}
	destroying := parentDeleting.DeepCopy()
	destroying.Spec.DeletionPolicy = v1beta2.DeletionPolicyDestroy
	if _, err := validator(destroying).ValidateDelete(ctx, storageNode); err != nil {
		t.Fatalf("parent Destroy foreground cascade of a positive-capacity child was rejected: %v", err)
	}

	drained := parentDeleting.DeepCopy()
	drained.Spec.DeletionPolicy = v1beta2.DeletionPolicyDrain
	completedAt := metav1.Now()
	drained.Status.StorageDrain = &v1beta2.StorageDrainStatus{
		Actor: v1beta2.StorageDrainActorStatus{
			APIVersion: v1beta2.GroupVersion.String(), Kind: garageClusterKind,
			Namespace: drained.Namespace, Name: drained.Name, UID: string(drained.UID),
		},
		TransactionID: "parent-drain-txn",
		TargetHash:    storagecontract.TargetHash(nil, nil),
		StartedAt:     metav1.Now(),
		CompletedAt:   &completedAt,
	}
	if _, err := validator(drained).ValidateDelete(ctx, storageNode); err != nil {
		t.Fatalf("parent terminal Drain foreground cascade of a positive-capacity child was rejected: %v", err)
	}
}

func ptrDeletePropagation(value metav1.DeletionPropagation) *metav1.DeletionPropagation {
	return &value
}

func TestGarageNodeValidator_DrainAnnotationIsExplicit(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "n", Namespace: testSourceNS,
			Annotations: map[string]string{AnnotationDrain: "yes"},
		},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster}, Zone: testZone,
			Capacity: mustQty("100Gi"),
			Storage:  &NodeStorageConfig{Data: &NodeVolumeConfig{Size: mustQty("100Gi")}},
		},
	}
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "must be \"true\"") {
		t.Fatalf("ambiguous drain annotation was accepted: %v", err)
	}
	node.Annotations[AnnotationDrain] = stringTrue
	node.Spec.Gateway = true
	node.Spec.Capacity = nil
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "only valid") {
		t.Fatalf("gateway drain preparation was accepted: %v", err)
	}
}

// ── GarageNodeValidator: EmptyDir volumes (#283) ──────────────────────────────

func mustQty(s string) *resource.Quantity { q := resource.MustParse(s); return &q }

// TestGarageNodeValidator_EmptyDirNoSize verifies the operator's own ephemeral
// Auto-mode shape — metadata+data of type EmptyDir with no size — passes
// admission. Before #283 validateVolumeSource rejected it ("must specify
// existingClaim, size, or readOnly"), so the operator could not create the
// GarageNode it generated for an EmptyDir cluster.
func TestGarageNodeValidator_EmptyDirNoSize(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Type: VolumeTypeEmptyDir},
				Data:     &NodeVolumeConfig{Type: VolumeTypeEmptyDir},
			},
		},
	}
	if _, err := node.validateGarageNode(); err != nil {
		t.Errorf("EmptyDir metadata+data with no size should be valid: %v", err)
	}
}

// TestGarageNodeValidator_EmptyDirWithSize verifies a sized EmptyDir (the
// garage-ephemeral-limited shape) is accepted — the size becomes the tmpfs
// sizeLimit at render time.
func TestGarageNodeValidator_EmptyDirWithSize(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Type: VolumeTypeEmptyDir, Size: mustQty("1Gi")},
				Data:     &NodeVolumeConfig{Type: VolumeTypeEmptyDir, Size: mustQty("10Gi")},
			},
		},
	}
	if _, err := node.validateGarageNode(); err != nil {
		t.Errorf("EmptyDir metadata+data with size should be valid: %v", err)
	}
}

// TestGarageNodeValidator_BareVolumeStillRejected guards the relaxation: a
// volume with no type, no size, or claim is still an error (this
// is the invalid shape #283 accidentally produced before the Type fix).
func TestGarageNodeValidator_BareVolumeStillRejected(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{}, // bare {}
			},
		},
	}
	if _, err := node.validateGarageNode(); err == nil {
		t.Error("bare storage.data (no type/size/claim) should be rejected")
	}
}

func TestGarageNodeValidator_ReadOnlyDoesNotProvideVolumeSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		storage *NodeStorageConfig
		want    string
	}{
		{
			name: testMetadataValue,
			storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{ReadOnly: true},
				Data:     &NodeVolumeConfig{Size: mustQty("10Gi")},
			},
			want: "readOnly applies only to multi-HDD",
		},
		{
			name: "single data",
			storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{ReadOnly: true},
			},
			want: "readOnly applies only to multi-HDD",
		},
		{
			name: "data path",
			storage: &NodeStorageConfig{
				DataPaths: []NodeVolumeConfig{{ReadOnly: true}},
			},
			want: "readOnly does not provide a Kubernetes volume",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := &GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
				Spec: GarageNodeSpec{
					ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
					Zone:       testZone,
					Capacity:   mustQty("100Gi"),
					Storage:    tc.storage,
				},
			}
			_, err := node.validateGarageNode()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("readOnly-only %s source was accepted: %v", tc.name, err)
			}
		})
	}
}

func TestGarageNodeValidator_ReadOnlyDataPathWithClaimIsValid(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				DataPaths: []NodeVolumeConfig{{ExistingClaim: "legacy-disk", ReadOnly: true}},
			},
		},
	}
	if _, err := node.validateGarageNode(); err != nil {
		t.Fatalf("read-only dataPath with a real claim should remain valid: %v", err)
	}
}

func TestGarageNodeValidator_GrandfathersOnlyUnchangedLegacyReadOnlyVolumes(t *testing.T) {
	validator := &GarageNodeValidator{}
	for _, tc := range []struct {
		name   string
		legacy func(*NodeStorageConfig) *NodeVolumeConfig
	}{
		{
			name: testMetadataValue,
			legacy: func(storage *NodeStorageConfig) *NodeVolumeConfig {
				storage.Metadata = &NodeVolumeConfig{ReadOnly: true}
				storage.Data = &NodeVolumeConfig{Size: mustQty("10Gi")}
				return storage.Metadata
			},
		},
		{
			name: "single data",
			legacy: func(storage *NodeStorageConfig) *NodeVolumeConfig {
				storage.Metadata = &NodeVolumeConfig{Size: mustQty("1Gi")}
				storage.Data = &NodeVolumeConfig{ReadOnly: true}
				return storage.Data
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := &GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "legacy-read-only", Namespace: testSourceNS,
					Finalizers: []string{"legacy.example.com/finalizer"},
				},
				Spec: GarageNodeSpec{
					ClusterRef: ClusterReference{Name: testCluster}, Zone: testZone,
					Capacity: mustQty("100Gi"), Storage: &NodeStorageConfig{},
				},
			}
			tc.legacy(oldNode.Spec.Storage)

			cleanup := oldNode.DeepCopy()
			cleanup.Finalizers = nil
			warnings, err := validator.ValidateUpdate(context.Background(), oldNode, cleanup)
			if err != nil {
				t.Fatalf("finalizer cleanup with unchanged legacy readOnly was rejected: %v", err)
			}
			if !strings.Contains(strings.Join(warnings, " "), "never affected") {
				t.Fatalf("legacy readOnly cleanup lacked a migration warning: %v", warnings)
			}

			retainedRepair := oldNode.DeepCopy()
			retainedRepairVolume := tc.legacy(retainedRepair.Spec.Storage)
			retainedRepairVolume.Size = mustQty("2Gi")
			if _, err := validator.ValidateUpdate(context.Background(), oldNode, retainedRepair); err != nil {
				t.Fatalf("readOnly-only legacy volume could not acquire its first real PVC source: %v", err)
			}

			cleanRepair := oldNode.DeepCopy()
			cleanRepairVolume := tc.legacy(cleanRepair.Spec.Storage)
			cleanRepairVolume.ReadOnly = false
			cleanRepairVolume.Size = mustQty("2Gi")
			if _, err := validator.ValidateUpdate(context.Background(), oldNode, cleanRepair); err != nil {
				t.Fatalf("readOnly-only legacy volume could not remove the ignored bit while adding its first real source: %v", err)
			}

			oldWithSource := oldNode.DeepCopy()
			oldWithSourceVolume := tc.legacy(oldWithSource.Spec.Storage)
			oldWithSourceVolume.Size = mustQty("2Gi")
			removed := oldWithSource.DeepCopy()
			removedVolume := tc.legacy(removed.Spec.Storage)
			removedVolume.Size = mustQty("2Gi")
			removedVolume.ReadOnly = false
			if _, err := validator.ValidateUpdate(context.Background(), oldWithSource, removed); err != nil {
				t.Fatalf("removing ignored legacy readOnly from an unchanged real PVC source was rejected: %v", err)
			}
		})
	}
}

func TestGarageNodeValidator_GrandfathersReadOnlyOnlyDataPath(t *testing.T) {
	validator := &GarageNodeValidator{}
	oldNode := readyCycleTestNode()
	oldNode.Finalizers = []string{testCleanupFinalizer}
	oldNode.Spec.Storage.Data = nil
	oldNode.Spec.Storage.DataPaths = []NodeVolumeConfig{{Path: "/data/archive", ReadOnly: true}}

	finalizerUpdate := oldNode.DeepCopy()
	finalizerUpdate.Finalizers = nil
	warnings, err := validator.ValidateUpdate(context.Background(), oldNode, finalizerUpdate)
	if err != nil {
		t.Fatalf("finalizer cleanup with an unchanged readOnly-only dataPath was rejected: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "storage.dataPaths[0]") {
		t.Fatalf("readOnly-only dataPath lacked an exact migration warning: %v", warnings)
	}

	repaired := oldNode.DeepCopy()
	repaired.Spec.Storage.DataPaths[0].Size = mustQty("100Gi")
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, repaired); err != nil {
		t.Fatalf("readOnly-only dataPath could not acquire its first real PVC source: %v", err)
	}

	mutated := repaired.DeepCopy()
	mutated.Spec.Storage.DataPaths[0].Path = "/data/different"
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, mutated); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Fatalf("dataPath source repair also changed its Garage path: %v", err)
	}
}

func TestGarageNodeValidator_GrandfathersOnlyMonotonicRemovalOfIgnoredVolumeFields(t *testing.T) {
	badSelector := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: testDiskSelectorKey, Operator: metav1.LabelSelectorOperator("LegacyInvalid"), Values: []string{testSSDValue},
	}}}
	storageClass := "ignored-class"
	base := func(volume *NodeVolumeConfig) *GarageNode {
		node := readyCycleTestNode()
		node.Finalizers = []string{testCleanupFinalizer}
		node.Spec.Storage.Data = volume
		return node
	}
	for _, tc := range []struct {
		name    string
		old     *GarageNode
		cleanup func(*NodeVolumeConfig)
		mutate  func(*NodeVolumeConfig)
	}{
		{
			name: "EmptyDir PVC-only fields",
			old: base(&NodeVolumeConfig{
				Type: VolumeTypeEmptyDir, ExistingClaim: "ignored-claim", StorageClassName: &storageClass,
				Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}},
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
				Labels:      map[string]string{testLegacyVolumeKey: testOldValue}, Annotations: map[string]string{testLegacyVolumeKey: testOldValue},
			}),
			cleanup: func(volume *NodeVolumeConfig) {
				volume.ExistingClaim, volume.StorageClassName, volume.Selector = "", nil, nil
				volume.AccessModes, volume.Labels, volume.Annotations = nil, nil, nil
			},
			mutate: func(volume *NodeVolumeConfig) { volume.Labels[testLegacyVolumeKey] = testNewValue },
		},
		{
			name: "existingClaim PVC-template fields",
			old: base(&NodeVolumeConfig{
				ExistingClaim: "user-claim", StorageClassName: &storageClass,
				Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}},
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
				Labels:      map[string]string{testLegacyVolumeKey: testOldValue}, Annotations: map[string]string{testLegacyVolumeKey: testOldValue},
			}),
			cleanup: func(volume *NodeVolumeConfig) {
				volume.StorageClassName, volume.Selector = nil, nil
				volume.AccessModes, volume.Labels, volume.Annotations = nil, nil, nil
			},
			mutate: func(volume *NodeVolumeConfig) {
				volume.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testNewValue}}
			},
		},
		{
			name: "malformed dynamic PVC selector",
			old:  base(&NodeVolumeConfig{Size: mustQty("100Gi"), Selector: badSelector}),
			cleanup: func(volume *NodeVolumeConfig) {
				volume.Selector = nil
			},
			mutate: func(volume *NodeVolumeConfig) {
				volume.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testNewValue}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator := &GarageNodeValidator{}
			finalizerUpdate := tc.old.DeepCopy()
			finalizerUpdate.Finalizers = nil
			warnings, err := validator.ValidateUpdate(context.Background(), tc.old, finalizerUpdate)
			if err != nil {
				t.Fatalf("finalizer update with unchanged released fields was rejected: %v", err)
			}
			if !strings.Contains(strings.Join(warnings, " "), "never affected") {
				t.Fatalf("released ignored fields lacked a migration warning: %v", warnings)
			}

			cleaned := tc.old.DeepCopy()
			tc.cleanup(cleaned.Spec.Storage.Data)
			if _, err := validator.ValidateUpdate(context.Background(), tc.old, cleaned); err != nil {
				t.Fatalf("monotonic cleanup of ignored fields was rejected: %v", err)
			}

			mutated := tc.old.DeepCopy()
			tc.mutate(mutated.Spec.Storage.Data)
			if _, err := validator.ValidateUpdate(context.Background(), tc.old, mutated); err == nil ||
				!strings.Contains(err.Error(), "may only remain unchanged or be removed") {
				t.Fatalf("mutation of a released ignored field was accepted: %v", err)
			}
		})
	}
}

func readyCycleTestNode() *GarageNode {
	return &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: testSourceNS, UID: testNodeUID, Generation: 1,
		},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Size: mustQty("10Gi")},
				Data:     &NodeVolumeConfig{Size: mustQty("100Gi")},
			},
		},
		Status: GarageNodeStatus{
			NodeID: testRemovedNodeID, ObservedPodUID: "source-pod-uid",
			ObservedGeneration: 1, Connected: true, InLayout: true,
		},
	}
}

func TestPodLabelOwnershipIsReservedAndLegacyUpdatesRemainRepairable(t *testing.T) {
	const reserved = "garage.rajsingh.info/storage-group"
	validator := &GarageNodeValidator{}
	created := readyCycleTestNode()
	created.UID = ""
	created.Spec.PodLabels = map[string]string{reserved: "create-hostile"}
	if _, err := validator.ValidateCreate(context.Background(), created); err == nil || !strings.Contains(err.Error(), "operator-managed") {
		t.Fatalf("GarageNode create accepted an operator-owned pod label: %v", err)
	}

	oldNode := readyCycleTestNode()
	oldNode.Spec.PodLabels = map[string]string{reserved: "node-hostile", "legacy invalid node key": "node-legacy"}
	finalizerUpdate := oldNode.DeepCopy()
	finalizerUpdate.Finalizers = append(finalizerUpdate.Finalizers, testCleanupFinalizer)
	warnings, err := validator.ValidateUpdate(context.Background(), oldNode, finalizerUpdate)
	if err != nil {
		t.Fatalf("GarageNode finalizer update was stranded by unchanged legacy pod labels: %v", err)
	}
	if got := strings.Join(warnings, " "); !strings.Contains(got, "ignored") {
		t.Fatalf("GarageNode legacy pod labels did not emit an ignored-value warning: %v", warnings)
	}
	mutated := oldNode.DeepCopy()
	mutated.Spec.PodLabels[reserved] = "different"
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, mutated); err == nil {
		t.Fatal("GarageNode operator-owned pod label mutation was accepted")
	}
	cleaned := oldNode.DeepCopy()
	cleaned.Spec.PodLabels = map[string]string{"example.com/media": "nvme"}
	if _, err := validator.ValidateUpdate(context.Background(), oldNode, cleaned); err != nil {
		t.Fatalf("GarageNode legacy pod label cleanup was rejected: %v", err)
	}

	clusterValidator := &GarageClusterValidator{}
	oldCluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testDefaultNamespace},
		Spec: GarageClusterSpec{
			ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStoreCR}},
			PodLabels: map[string]string{reserved: "cluster-hostile", "legacy invalid cluster key": "cluster-legacy"},
		},
	}
	createCluster := oldCluster.DeepCopy()
	delete(createCluster.Spec.PodLabels, "legacy invalid cluster key")
	if _, err := clusterValidator.ValidateCreate(context.Background(), createCluster); err == nil || !strings.Contains(err.Error(), "operator-managed") {
		t.Fatalf("v1beta1 GarageCluster create accepted an operator-owned pod label: %v", err)
	}
	clusterFinalizerUpdate := oldCluster.DeepCopy()
	clusterFinalizerUpdate.Finalizers = []string{testCleanupFinalizer}
	warnings, err = clusterValidator.ValidateUpdate(context.Background(), oldCluster, clusterFinalizerUpdate)
	if err != nil {
		t.Fatalf("v1beta1 GarageCluster finalizer update was stranded by unchanged legacy pod labels: %v", err)
	}
	if got := strings.Join(warnings, " "); !strings.Contains(got, "ignored") {
		t.Fatalf("v1beta1 GarageCluster legacy pod labels did not emit a warning: %v", warnings)
	}
	clusterCleaned := oldCluster.DeepCopy()
	clusterCleaned.Spec.PodLabels = nil
	if _, err := clusterValidator.ValidateUpdate(context.Background(), oldCluster, clusterCleaned); err != nil {
		t.Fatalf("v1beta1 GarageCluster legacy pod label cleanup was rejected: %v", err)
	}
}

func TestGarageNodeValidator_CycleCannotStartOnCreate(t *testing.T) {
	node := readyCycleTestNode()
	node.Annotations = map[string]string{AnnotationCycle: stringTrue}
	_, err := (&GarageNodeValidator{}).ValidateCreate(context.Background(), node)
	if err == nil || !strings.Contains(err.Error(), "cannot be set when a GarageNode is created") {
		t.Fatalf("cycle-on-create was accepted: %v", err)
	}
}

func TestGarageNodeValidator_CycleRejectsEveryExistingClaimShape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*GarageNode)
		want   string
	}{
		{
			name: "metadata claim only",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Metadata = &NodeVolumeConfig{ExistingClaim: "meta"}
			},
			want: "storage.metadata.existingClaim",
		},
		{
			name: "metadata claim plus size",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Metadata = &NodeVolumeConfig{ExistingClaim: "meta", Size: mustQty("10Gi")}
			},
			want: "storage.metadata.existingClaim",
		},
		{
			name: "data claim only",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Data = &NodeVolumeConfig{ExistingClaim: testDataValue}
			},
			want: "storage.data.existingClaim",
		},
		{
			name: "data claim plus size",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Data = &NodeVolumeConfig{ExistingClaim: testDataValue, Size: mustQty("100Gi")}
			},
			want: "storage.data.existingClaim",
		},
		{
			name: "indexed data path claim",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Data = nil
				node.Spec.Storage.DataPaths = []NodeVolumeConfig{
					{Size: mustQty("50Gi")},
					{ExistingClaim: "disk-1", Size: mustQty("50Gi")},
				}
			},
			want: "storage.dataPaths[1].existingClaim",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := readyCycleTestNode()
			tc.mutate(oldNode)
			newNode := oldNode.DeepCopy()
			newNode.Annotations = map[string]string{AnnotationCycle: stringTrue}
			_, err := (&GarageNodeValidator{}).ValidateUpdate(context.Background(), oldNode, newNode)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("existing-claim cycle was accepted or lacked exact path: %v", err)
			}
			ordinary := oldNode.DeepCopy()
			ordinary.Labels = map[string]string{"metadata-only": "update"}
			if _, err := (&GarageNodeValidator{}).ValidateUpdate(context.Background(), oldNode, ordinary); err != nil {
				t.Fatalf("existingClaim must remain supported outside cycle: %v", err)
			}
		})
	}
}

func TestGarageNodeValidator_CycleRejectsEndpointReuse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*GarageNode)
		want   string
	}{
		{
			name: "fixed RPC address",
			mutate: func(node *GarageNode) {
				node.Spec.Network = &NodeNetworkConfig{RPCPublicAddr: "storage-a.example.net:3901"}
			},
			want: "distinct RPC endpoint",
		},
		{
			name: "fixed NodePort",
			mutate: func(node *GarageNode) {
				node.Spec.PublicEndpoint = &PublicEndpointConfig{
					Type: "NodePort",
					NodePort: &NodePortEndpointConfig{
						ExternalAddresses: []string{"worker.example.net"}, BasePort: 31001,
					},
				}
			},
			want: "publicEndpoint handoff",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := readyCycleTestNode()
			tc.mutate(oldNode)
			newNode := oldNode.DeepCopy()
			newNode.Annotations = map[string]string{AnnotationCycle: stringTrue}
			_, err := (&GarageNodeValidator{}).ValidateUpdate(context.Background(), oldNode, newNode)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("cycle endpoint reuse was accepted or lacked a precise error: %v", err)
			}
		})
	}
}

func TestGarageNodeValidator_CycleRejectsGatewayOnlyParentAddress(t *testing.T) {
	node := readyCycleTestNode()
	parent := &v1beta2.GarageCluster{
		Spec: v1beta2.GarageClusterSpec{
			Gateway: &v1beta2.GatewaySpec{Replicas: 1, RPCPublicAddr: "edge.example.net:3901"},
		},
	}
	if err := node.ValidateCycleParentNetworkProfile(parent); err == nil ||
		!strings.Contains(err.Error(), "parent gateway.rpcPublicAddr") {
		t.Fatalf("gateway-only parent address was accepted for a positive-capacity cycle: %v", err)
	}
}

func TestGarageNodeValidator_CycleAcceptsOnlyReadyRepeatableStorage(t *testing.T) {
	validator := &GarageNodeValidator{}
	for _, tc := range []struct {
		name   string
		mutate func(*GarageNode)
	}{
		{name: "dynamic PVC templates", mutate: func(*GarageNode) {}},
		{
			name: "EmptyDir",
			mutate: func(node *GarageNode) {
				node.Spec.Storage.Metadata = &NodeVolumeConfig{Type: VolumeTypeEmptyDir}
				node.Spec.Storage.Data = &NodeVolumeConfig{Type: VolumeTypeEmptyDir}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := readyCycleTestNode()
			tc.mutate(oldNode)
			newNode := oldNode.DeepCopy()
			newNode.Annotations = map[string]string{AnnotationCycle: stringTrue}
			if _, err := validator.ValidateUpdate(context.Background(), oldNode, newNode); err != nil {
				t.Fatalf("eligible cycle rejected: %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*GarageNode)
		want   string
	}{
		{name: gatewayValue, mutate: func(node *GarageNode) {
			node.Spec.Gateway, node.Spec.Capacity = true, nil
			node.Spec.Storage.Data = nil
		}, want: "gateway identities"},
		{name: "unobserved pod", mutate: func(node *GarageNode) { node.Status.ObservedPodUID = "" }, want: "observedPodUid"},
		{name: "disconnected", mutate: func(node *GarageNode) { node.Status.Connected = false }, want: "connected and committed"},
		{name: "not in layout", mutate: func(node *GarageNode) { node.Status.InLayout = false }, want: "connected and committed"},
		{name: "stale generation", mutate: func(node *GarageNode) { node.Status.ObservedGeneration = 0 }, want: "observedGeneration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldNode := readyCycleTestNode()
			tc.mutate(oldNode)
			newNode := oldNode.DeepCopy()
			newNode.Annotations = map[string]string{AnnotationCycle: stringTrue}
			_, err := validator.ValidateUpdate(context.Background(), oldNode, newNode)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ineligible cycle was accepted: %v", err)
			}
		})
	}
}

func TestGarageNodeValidator_CycleRequiresCanonicalConsistentReadyLayoutOwner(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 scheme: %v", err)
	}
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testCluster, Namespace: testSourceNS, UID: testClusterUID, Generation: 5},
		Spec: v1beta2.GarageClusterSpec{
			Storage:     &v1beta2.StorageSpec{},
			Replication: &v1beta2.ReplicationConfig{Factor: 2, ConsistencyMode: consistencyModeConsistent},
		},
		Status: v1beta2.GarageClusterStatus{
			Conditions: []metav1.Condition{{
				Type: ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
				Reason: ReasonStorageRolloutConverged, ObservedGeneration: 5,
			}},
			Health: &v1beta2.ClusterHealth{
				Status: healthStatusHealthy, Healthy: true, Available: true,
				StorageNodes: 2, StorageNodesOK: 2,
				Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
			},
		},
	}
	validate := func(owner *v1beta2.GarageCluster) error {
		reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(owner).Build()
		oldNode := readyCycleTestNode()
		newNode := oldNode.DeepCopy()
		newNode.Annotations = map[string]string{AnnotationCycle: stringTrue}
		_, err := (&GarageNodeValidator{apiReader: reader}).ValidateUpdate(context.Background(), oldNode, newNode)
		return err
	}
	if err := validate(cluster.DeepCopy()); err != nil {
		t.Fatalf("ready consistent layout owner rejected cycle start: %v", err)
	}
	degraded := cluster.DeepCopy()
	degraded.Spec.Replication.ConsistencyMode = "degraded"
	if err := validate(degraded); err == nil || !strings.Contains(err.Error(), "requires parent spec.replication.consistencyMode: consistent") {
		t.Fatalf("degraded layout owner accepted cycle start: %v", err)
	}
	unhealthy := cluster.DeepCopy()
	unhealthy.Status.Health.PartitionsAllOK = 255
	if err := validate(unhealthy); err == nil || !strings.Contains(err.Error(), "fully replicated") {
		t.Fatalf("unhealthy layout owner accepted cycle start: %v", err)
	}
}

// TestGarageNodeValidator_EmptyDirContradictions verifies EmptyDir combined
// with PVC-only fields (existingClaim / storageClassName) is rejected.
func TestGarageNodeValidator_EmptyDirContradictions(t *testing.T) {
	sc := "fast"
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: "fast"}}
	cases := map[string]*NodeVolumeConfig{
		"existingClaim":           {Type: VolumeTypeEmptyDir, ExistingClaim: "some-pvc"},
		storageClassNameJSONField: {Type: VolumeTypeEmptyDir, StorageClassName: &sc},
		selectorJSONField:         {Type: VolumeTypeEmptyDir, Selector: selector},
		"pvcMetadata":             {Type: VolumeTypeEmptyDir, Labels: map[string]string{"backup": "true"}},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			node := &GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
				Spec: GarageNodeSpec{
					ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
					Zone:       testZone,
					Capacity:   mustQty("100Gi"),
					Storage:    &NodeStorageConfig{Data: data},
				},
			}
			if _, err := node.validateGarageNode(); err == nil {
				t.Errorf("EmptyDir + %s should be rejected", name)
			}
		})
	}
}

func TestGarageNodeValidator_SelectorCannotBeIgnoredByExistingClaim(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-existing", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testLocalZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{Data: &NodeVolumeConfig{
				ExistingClaim: "already-managed",
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
					testDiskNameLabelKey: "ignored",
				}},
			}},
		},
	}
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "already bound or user-managed") {
		t.Fatalf("selector + existingClaim was not rejected explicitly: %v", err)
	}
}

func TestGarageNodeValidator_SelectorIsImmutableForLiveIdentity(t *testing.T) {
	old := &GarageNode{Spec: GarageNodeSpec{Storage: &NodeStorageConfig{Data: &NodeVolumeConfig{
		Size:     mustQty("100Gi"),
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: "a"}},
	}}}}
	newer := old.DeepCopy()
	newer.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: "b"}}
	if err := validateGarageNodeStorageUpdate(old, newer); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("live PVC selector mutation was accepted: %v", err)
	}
}

func TestGarageNodeValidator_RejectsInvalidPersistentVolumeSelectors(t *testing.T) {
	badKey := &metav1.LabelSelector{MatchLabels: map[string]string{"not a label key": testDiskSelectorKey}}
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-selector", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:       testLocalZone,
			Capacity:   mustQty("100Gi"),
			Storage: &NodeStorageConfig{Data: &NodeVolumeConfig{
				Size: mustQty("100Gi"), Selector: badKey,
			}},
		},
	}
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "storage.data.selector") {
		t.Fatalf("invalid GarageNode PVC selector was not rejected with its field path: %v", err)
	}

	badOperator := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "disk.example.com/type", Operator: metav1.LabelSelectorOperator("Invalid"), Values: []string{testSSDValue},
	}}}
	node.Spec.Storage.Data = nil
	node.Spec.Storage.DataPaths = []NodeVolumeConfig{{
		Size: mustQty("100Gi"), Path: "/data/data-0", Selector: badOperator,
	}}
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "storage.dataPaths[0].selector") {
		t.Fatalf("invalid GarageNode data-path selector operator was not rejected: %v", err)
	}
}

// ── Ported tests from v1alpha1 ────────────────────────────────────────────────

func TestValidateBindAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		field   string
		wantErr bool
	}{
		{"invalid port only", ":3900", testField, true},
		{"valid host:port", "0.0.0.0:3900", testField, false},
		{"valid IPv6", "[::]:3900", testField, false},
		{"invalid unix socket", "unix:///run/garage/s3.sock", testField, true},
		{"invalid loopback", "127.0.0.1:3900", testField, true},
		{"invalid - no port", "localhost", testField, true},
		{"invalid - empty", "", testField, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindAddress(tt.addr, tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBindAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAdminBindAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "empty host", addr: ":4903", wantErr: true},
		{name: "IPv4 wildcard", addr: "0.0.0.0:4903"},
		{name: "IPv6 wildcard", addr: "[::]:4903"},
		{name: "Unix socket", addr: "unix:///run/garage/admin.sock", wantErr: true},
		{name: "loopback", addr: "127.0.0.1:4903", wantErr: true},
		{name: "specific host", addr: "garage.example:4903", wantErr: true},
		{name: "zero port", addr: ":0", wantErr: true},
		{name: "out of range port", addr: ":65536", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdminBindAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAdminBindAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAdminPortUpdate(t *testing.T) {
	oldCluster := &GarageCluster{Spec: GarageClusterSpec{Admin: &AdminConfig{BindPort: 3903}}}
	for _, tt := range []struct {
		name    string
		admin   *AdminConfig
		wantErr bool
	}{
		{name: "same BindPort", admin: &AdminConfig{BindPort: 3903}},
		{name: "same effective explicit port", admin: &AdminConfig{BindPort: 4903, BindAddress: "[::]:3903"}},
		{name: "changed BindPort", admin: &AdminConfig{BindPort: 4903}, wantErr: true},
		{name: "changed bindAddress port", admin: &AdminConfig{BindPort: 3903, BindAddress: "[::]:4903"}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newCluster := oldCluster.DeepCopy()
			newCluster.Spec.Admin = tt.admin
			err := validateAdminPortUpdate(oldCluster, newCluster)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAdminPortUpdate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "immutable after create") {
				t.Fatalf("immutable Admin port error is not actionable: %v", err)
			}
		})
	}
}

func TestGarageCluster_ValidateZoneRedundancy(t *testing.T) {
	ptr := func(n int) *int { return &n }
	tests := []struct {
		name        string
		mode        string
		minZones    *int
		replication int
		wantErr     bool
	}{
		{"empty mode is valid", "", nil, 3, false},
		{"Maximum is valid", zoneRedundancyMaximum, nil, 3, false},
		{"AtLeast(1) with RF3", zoneRedundancyAtLeast, ptr(1), 3, false},
		{"AtLeast(3) with RF3", zoneRedundancyAtLeast, ptr(3), 3, false},
		{"AtLeast(4) exceeds RF3", zoneRedundancyAtLeast, ptr(4), 3, true},
		{"AtLeast without minZones is invalid", zoneRedundancyAtLeast, nil, 3, true},
		{"Maximum with minZones is invalid", zoneRedundancyMaximum, ptr(2), 3, true},
		{"invalid mode", "Invalid", nil, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{
				Spec: GarageClusterSpec{
					Replication: &ReplicationConfig{
						Factor:                 tt.replication,
						ZoneRedundancyMode:     tt.mode,
						ZoneRedundancyMinZones: tt.minZones,
					},
				},
			}
			err := cluster.validateZoneRedundancy()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateZoneRedundancy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageClusterValidator_RejectsReservedDefaultNodeTags(t *testing.T) {
	for _, tag := range []string{
		"cluster:other/ns",
		"cluster-uid:forged",
		"tier:gateway",
		"rpc-address:other.example:3901",
		"node-local-pool:other",
		"kubernetes-node:worker-9",
	} {
		t.Run(tag, func(t *testing.T) {
			cluster := &GarageCluster{Spec: GarageClusterSpec{
				LayoutPolicy:    layoutPolicyManual,
				DefaultNodeTags: []string{"rack:a", tag},
			}}
			if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "operator-managed prefix") {
				t.Fatalf("reserved defaultNodeTags value %q was accepted: %v", tag, err)
			}
		})
	}
}

func TestGarageCluster_ValidateStorage(t *testing.T) {
	size := resource.MustParse("100Gi")
	tests := []struct {
		name    string
		storage StorageConfig
		wantErr bool
	}{
		{"valid size config", StorageConfig{Data: &VolumeConfig{Size: &size}}, false},
		{"valid paths config", StorageConfig{Data: &VolumeConfig{Paths: []DataPath{{Path: "/data"}}}}, false},
		{"invalid - no size or paths", StorageConfig{Data: &VolumeConfig{}}, true},
		{"invalid - no data config", StorageConfig{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{Spec: GarageClusterSpec{Storage: tt.storage}}
			err := cluster.validateStorage()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStorage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageCluster_RejectsUnsupportedDefaultStorageClaimTemplates(t *testing.T) {
	claimTemplate := &corev1.PersistentVolumeClaimSpec{}
	cluster := &GarageCluster{}

	for _, tc := range []struct {
		name  string
		field string
		check func() error
	}{
		{
			name:  testMetadataValue,
			field: "storage.metadata.volumeClaimTemplateSpec",
			check: func() error {
				return cluster.validateVolumeConfig(&VolumeConfig{VolumeClaimTemplateSpec: claimTemplate}, testMetadataValue)
			},
		},
		{
			name:  testDataValue,
			field: "storage.data.volumeClaimTemplateSpec",
			check: func() error {
				return cluster.validateVolumeConfig(&VolumeConfig{VolumeClaimTemplateSpec: claimTemplate}, testDataValue)
			},
		},
		{
			name:  "data path",
			field: "storage.data.paths[0].volume.volumeClaimTemplateSpec",
			check: func() error {
				return validateV1Beta1DataPathVolumeConfig(
					&DataPathVolumeConfig{VolumeClaimTemplateSpec: claimTemplate},
					"storage.data.paths[0].volume",
				)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.check()
			if err == nil || !strings.Contains(err.Error(), tc.field) ||
				!strings.Contains(err.Error(), "identity isolation") {
				t.Fatalf("unsupported claim template was not rejected clearly: %v", err)
			}
		})
	}
}

func TestGarageCluster_RejectsInvalidPersistentVolumeSelectors(t *testing.T) {
	badKey := &metav1.LabelSelector{MatchLabels: map[string]string{"not a label key": testDiskSelectorKey}}
	if err := (&GarageCluster{}).validateVolumeConfig(
		&VolumeConfig{Selector: badKey}, testMetadataValue,
	); err == nil || !strings.Contains(err.Error(), "storage.metadata.selector") {
		t.Fatalf("invalid v1beta1 storage selector was not rejected with its field path: %v", err)
	}

	badOperator := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "disk.example.com/type", Operator: metav1.LabelSelectorOperator("Invalid"), Values: []string{testSSDValue},
	}}}
	if err := validateV1Beta1DataPathVolumeConfig(
		&DataPathVolumeConfig{Selector: badOperator}, "storage.data.paths[0].volume",
	); err == nil || !strings.Contains(err.Error(), "storage.data.paths[0].volume.selector") {
		t.Fatalf("invalid v1beta1 data-path selector was not rejected with its field path: %v", err)
	}
}

func TestGarageCluster_GrandfathersOnlyUnchangedClaimTemplates(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	legacyTemplate := &corev1.PersistentVolumeClaimSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
	}
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-template", Namespace: testSourceNS},
			Spec: GarageClusterSpec{
				Replicas: 1,
				Storage: StorageConfig{
					Metadata: &VolumeConfig{Size: &oneGi, VolumeClaimTemplateSpec: legacyTemplate.DeepCopy()},
					Data:     &VolumeConfig{Size: &oneGi},
				},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	validator := &GarageClusterValidator{}

	old := base()
	unchanged := old.DeepCopy()
	unchanged.Spec.ImagePullPolicy = corev1.PullAlways
	warnings, err := validator.ValidateUpdate(context.Background(), old, unchanged)
	if err != nil {
		t.Fatalf("unrelated update with unchanged legacy field rejected: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
		t.Fatalf("unchanged legacy field did not emit migration warning: %v", warnings)
	}

	mutated := old.DeepCopy()
	mutated.Spec.Storage.Metadata.VolumeClaimTemplateSpec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
	if _, err := validator.ValidateUpdate(context.Background(), old, mutated); err == nil ||
		!strings.Contains(err.Error(), "identity isolation") {
		t.Fatalf("legacy claim template mutation accepted: %v", err)
	}

	removed := old.DeepCopy()
	removed.Spec.Storage.Metadata.VolumeClaimTemplateSpec = nil
	if _, err := validator.ValidateUpdate(context.Background(), old, removed); err != nil {
		t.Fatalf("safe removal of never-applied legacy field rejected: %v", err)
	}

	manualCreate := base()
	manualCreate.Spec.LayoutPolicy = layoutPolicyManual
	if _, err := manualCreate.validateGarageCluster(); err == nil ||
		!strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("new Manual shape bypassed claim-template rejection: %v", err)
	}
}

func TestGarageCluster_GrandfathersOnlyMonotonicRemovalOfIgnoredVolumeFields(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	storageClass := "ignored-class"
	badSelector := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: testDiskSelectorKey, Operator: metav1.LabelSelectorOperator("LegacyInvalid"), Values: []string{testSSDValue},
	}}}
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "legacy-volume", Namespace: testSourceNS, Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageClusterSpec{
				Replicas: 1,
				Storage: StorageConfig{
					Metadata: &VolumeConfig{Size: &oneGi},
					Data:     &VolumeConfig{Size: &oneGi},
				},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	for _, tc := range []struct {
		name    string
		old     *GarageCluster
		cleanup func(*GarageCluster)
		mutate  func(*GarageCluster)
		field   string
	}{
		{
			name: "top-level EmptyDir PVC-only fields",
			old: func() *GarageCluster {
				cluster := base()
				cluster.Spec.Storage.Metadata = &VolumeConfig{
					Type: VolumeTypeEmptyDir, StorageClassName: &storageClass,
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}},
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
					Labels:      map[string]string{testLegacyVolumeKey: testOldValue},
					Annotations: map[string]string{testLegacyVolumeKey: testOldValue},
				}
				return cluster
			}(),
			cleanup: func(cluster *GarageCluster) {
				volume := cluster.Spec.Storage.Metadata
				volume.StorageClassName, volume.Selector = nil, nil
				volume.AccessModes, volume.Labels, volume.Annotations = nil, nil, nil
			},
			mutate: func(cluster *GarageCluster) {
				cluster.Spec.Storage.Metadata.Labels[testLegacyVolumeKey] = testNewValue
			},
			field: "spec.storage.metadata",
		},
		{
			name: "nested EmptyDir PVC-only fields",
			old: func() *GarageCluster {
				cluster := base()
				cluster.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{{
					Path: "/data/archive", Capacity: &oneGi,
					Volume: &DataPathVolumeConfig{
						Type: VolumeTypeEmptyDir, StorageClassName: &storageClass,
						Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}},
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
						Labels:      map[string]string{testLegacyVolumeKey: testOldValue},
						Annotations: map[string]string{testLegacyVolumeKey: testOldValue},
					},
				}}}
				return cluster
			}(),
			cleanup: func(cluster *GarageCluster) {
				volume := cluster.Spec.Storage.Data.Paths[0].Volume
				volume.StorageClassName, volume.Selector = nil, nil
				volume.AccessModes, volume.Labels, volume.Annotations = nil, nil, nil
			},
			mutate: func(cluster *GarageCluster) {
				cluster.Spec.Storage.Data.Paths[0].Volume.Annotations[testLegacyVolumeKey] = testNewValue
			},
			field: "spec.storage.data.paths[0].volume",
		},
		{
			name: "malformed dynamic PVC selector",
			old: func() *GarageCluster {
				cluster := base()
				cluster.Spec.Storage.Data.Selector = badSelector
				return cluster
			}(),
			cleanup: func(cluster *GarageCluster) { cluster.Spec.Storage.Data.Selector = nil },
			mutate: func(cluster *GarageCluster) {
				cluster.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testNewValue}}
			},
			field: "spec.storage.data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator := &GarageClusterValidator{}
			finalizerUpdate := tc.old.DeepCopy()
			finalizerUpdate.Finalizers = nil
			warnings, err := validator.ValidateUpdate(context.Background(), tc.old, finalizerUpdate)
			if err != nil {
				t.Fatalf("finalizer update with unchanged released fields was rejected: %v", err)
			}
			if got := strings.Join(warnings, " "); !strings.Contains(got, tc.field) || !strings.Contains(got, "never affected") {
				t.Fatalf("released ignored fields lacked an exact migration warning: %v", warnings)
			}

			cleaned := tc.old.DeepCopy()
			tc.cleanup(cleaned)
			if _, err := validator.ValidateUpdate(context.Background(), tc.old, cleaned); err != nil {
				t.Fatalf("monotonic cleanup of ignored fields was rejected: %v", err)
			}

			mutated := tc.old.DeepCopy()
			tc.mutate(mutated)
			if _, err := validator.ValidateUpdate(context.Background(), tc.old, mutated); err == nil ||
				!strings.Contains(err.Error(), "may only remain unchanged or be removed") {
				t.Fatalf("mutation of a released ignored field was accepted: %v", err)
			}
		})
	}
}

func TestV1Beta1DefaultStorageVolumeTopologyCannotChangeDuringZeroToLiveTransition(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	oldSelector := &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testOldValue}}
	newSelector := &metav1.LabelSelector{MatchLabels: map[string]string{testDiskSelectorKey: testNewValue}}
	old := &GarageCluster{Spec: GarageClusterSpec{
		Replicas: 0,
		Storage: StorageConfig{
			Metadata: &VolumeConfig{Size: &oneGi, Selector: oldSelector},
			Data:     &VolumeConfig{Size: &oneGi},
		},
	}}
	newer := old.DeepCopy()
	newer.Spec.Replicas = 1
	newer.Spec.Storage.Metadata.Selector = newSelector
	if err := validateV1Beta1DefaultVolumeUpdate(old, newer); err == nil || !strings.Contains(err.Error(), selectorJSONField) {
		t.Fatalf("0->N plus selector change was accepted: %v", err)
	}

	atZero := old.DeepCopy()
	atZero.Spec.Storage.Metadata.Selector = newSelector
	if err := validateV1Beta1DefaultVolumeUpdate(old, atZero); err != nil {
		t.Fatalf("separate zero-replica template edit was rejected: %v", err)
	}
}

func TestGarageCluster_ValidateGateway(t *testing.T) {
	size := resource.MustParse("100Gi")
	tests := []struct {
		name    string
		cluster GarageCluster
		wantErr bool
		errMsg  string
	}{
		{
			name:    "reject gateway without connectTo",
			cluster: GarageCluster{Spec: GarageClusterSpec{Gateway: true}},
			wantErr: true, errMsg: "connectTo is required",
		},
		{
			name: "reject connectTo without gateway",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Storage:   StorageConfig{Data: &VolumeConfig{Size: &size}},
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "other"}},
			}},
			wantErr: true, errMsg: "connectTo can only be specified",
		},
		{
			name: "reject gateway with data storage",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage:   StorageConfig{Data: &VolumeConfig{Size: &size}},
			}},
			wantErr: true, errMsg: "spec.storage.data is not represented on a v1beta1 gateway",
		},
		{
			name: "reject empty connectTo",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{},
			}},
			wantErr: true, errMsg: "gateway connectTo requires",
		},
		{
			name: "accept gateway with clusterRef",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
			}},
			wantErr: false,
		},
		{
			name: "accept released v1beta1 gateway metadata contract",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage: StorageConfig{Metadata: &VolumeConfig{
					Size: &size,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
						testDiskNameLabelKey: gatewayValue,
					}},
				}},
			}},
			wantErr: false,
		},
		{
			name: "accept gateway with rpcSecretRef",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway: true,
				ConnectTo: &ConnectToConfig{RPCSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: defaultRPCSecretKey},
					Key:                  defaultRPCSecretKey,
				}},
			}},
			wantErr: false,
		},
		{
			name: "reject gateway with only bootstrapPeers because it has no shared RPC identity",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{BootstrapPeers: []string{"abc123@192.168.1.1:3901"}},
			}},
			wantErr: true, errMsg: "bootstrapPeers and adminApiEndpoint do not provide the shared RPC identity",
		},
		{
			name: "accept gateway with network rpcSecretRef and bootstrapPeers",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway: true,
				Network: NetworkConfig{RPCSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: defaultRPCSecretKey},
					Key:                  defaultRPCSecretKey,
				}},
				ConnectTo: &ConnectToConfig{BootstrapPeers: []string{"abc123@192.168.1.1:3901"}},
			}},
			wantErr: false,
		},
		{
			name: "reject cross-namespace clusterRef",
			cluster: GarageCluster{ObjectMeta: metav1.ObjectMeta{Namespace: testLocalZone}, Spec: GarageClusterSpec{
				Gateway: true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{
					Name: testStorageClusterName, Namespace: "remote",
				}},
			}},
			wantErr: true, errMsg: "cross-namespace credential and layout inheritance is not permitted",
		},
		{
			name: "reject gateway with storage.metadataFsync (dropped on conversion #219)",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage:   StorageConfig{MetadataFsync: true},
			}},
			wantErr: true, errMsg: "spec.storage.metadataFsync is not represented on a v1beta1 gateway",
		},
		{
			name: "reject gateway with storage.dataFsync (dropped on conversion #219)",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage:   StorageConfig{DataFsync: true},
			}},
			wantErr: true, errMsg: "spec.storage.dataFsync is not represented on a v1beta1 gateway",
		},
		{
			name: "reject gateway with storage.metadataSnapshotsDir (dropped on conversion #219)",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage:   StorageConfig{MetadataSnapshotsDir: "/snapshots"},
			}},
			wantErr: true, errMsg: "spec.storage.metadataSnapshotsDir is not represented on a v1beta1 gateway",
		},
		{
			name: "reject gateway with storage.metadataAutoSnapshotInterval (dropped on conversion #219)",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:   true,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Storage:   StorageConfig{MetadataAutoSnapshotInterval: "6h"},
			}},
			wantErr: true, errMsg: "spec.storage.metadataAutoSnapshotInterval is not represented on a v1beta1 gateway",
		},
		{
			name: "reject gateway with capacityReservePercent (dropped on conversion #219)",
			cluster: GarageCluster{Spec: GarageClusterSpec{
				Gateway:                true,
				ConnectTo:              &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				CapacityReservePercent: 10,
			}},
			wantErr: true, errMsg: "spec.capacityReservePercent is not represented on a v1beta1 gateway",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cluster.validateGateway()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGateway() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateGateway() error = %v, want containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestGarageClusterV1Beta1GatewayRejectsAndGrandfathersOnlyActuallyIgnoredStorageFields(t *testing.T) {
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "edge-legacy", Namespace: testWebhookNS},
			Spec: GarageClusterSpec{
				Gateway:     true,
				Replicas:    1,
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	tests := []struct {
		name      string
		field     string
		set       func(*GarageCluster, string)
		canMutate bool
	}{
		{
			name: testDataValue, field: "spec.storage.data", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				if value == "" {
					cluster.Spec.Storage.Data = nil
					return
				}
				size := resource.MustParse(map[string]string{testOldValue: "1Gi", testNewValue: "2Gi"}[value])
				cluster.Spec.Storage.Data = &VolumeConfig{Size: &size}
			},
		},
		{
			name: "rpc public address", field: "spec.storage.rpcPublicAddr", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				cluster.Spec.Storage.RPCPublicAddr = map[string]string{"": "", testOldValue: "old.example:3901", testNewValue: "new.example:3901"}[value]
			},
		},
		{
			name: "layout policy", field: "spec.storage.layoutPolicy", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				cluster.Spec.Storage.LayoutPolicy = map[string]string{"": "", testOldValue: layoutPolicyAuto, testNewValue: layoutPolicyManual}[value]
			},
		},
		{
			name: "snapshot directory", field: "spec.storage.metadataSnapshotsDir", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				cluster.Spec.Storage.MetadataSnapshotsDir = map[string]string{"": "", testOldValue: "/old", testNewValue: "/new"}[value]
			},
		},
		{
			name: "snapshot interval", field: "spec.storage.metadataAutoSnapshotInterval", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				cluster.Spec.Storage.MetadataAutoSnapshotInterval = map[string]string{"": "", testOldValue: "6h", testNewValue: "12h"}[value]
			},
		},
		{
			name: "metadata fsync", field: "spec.storage.metadataFsync",
			set: func(cluster *GarageCluster, value string) { cluster.Spec.Storage.MetadataFsync = value != "" },
		},
		{
			name: "data fsync", field: "spec.storage.dataFsync",
			set: func(cluster *GarageCluster, value string) { cluster.Spec.Storage.DataFsync = value != "" },
		},
		{
			name: "environment", field: "spec.storage.env", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				if value == "" {
					cluster.Spec.Storage.Env = nil
					return
				}
				cluster.Spec.Storage.Env = []corev1.EnvVar{{Name: "GARAGE_TEST_VALUE", Value: value}}
			},
		},
		{
			name: "environment sources", field: "spec.storage.envFrom", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				if value == "" {
					cluster.Spec.Storage.EnvFrom = nil
					return
				}
				cluster.Spec.Storage.EnvFrom = []corev1.EnvFromSource{{
					ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: value}},
				}}
			},
		},
		{
			name: "capacity reserve", field: "spec.capacityReservePercent", canMutate: true,
			set: func(cluster *GarageCluster, value string) {
				cluster.Spec.CapacityReservePercent = map[string]int{"": 0, testOldValue: 10, testNewValue: 20}[value]
			},
		},
	}
	validator := &GarageClusterValidator{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			created := base()
			tc.set(created, testOldValue)
			if _, err := validator.ValidateCreate(context.Background(), created); err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "v1beta2") {
				t.Fatalf("new ignored gateway field was not rejected clearly: %v", err)
			}

			old := base()
			tc.set(old, testOldValue)
			unchanged := old.DeepCopy()
			unchanged.Spec.ImagePullPolicy = corev1.PullAlways
			warnings, err := validator.ValidateUpdate(context.Background(), old, unchanged)
			if err != nil {
				t.Fatalf("unchanged legacy ignored field rejected: %v", err)
			}
			if !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
				t.Fatalf("unchanged legacy ignored field lacked migration warning: %v", warnings)
			}

			removed := old.DeepCopy()
			tc.set(removed, "")
			if _, err := validator.ValidateUpdate(context.Background(), old, removed); err != nil {
				t.Fatalf("safe removal of ignored field rejected: %v", err)
			}

			if tc.canMutate {
				mutated := old.DeepCopy()
				tc.set(mutated, testNewValue)
				if _, err := validator.ValidateUpdate(context.Background(), old, mutated); err == nil || !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("legacy ignored field mutation accepted: %v", err)
				}
			}
		})
	}
}

func TestGarageClusterV1Beta1EdgeGatewayMetadataChangesRequireZeroReplicas(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	twoGi := resource.MustParse("2Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testEdgeMetadataValue, Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Gateway:  true,
			Replicas: 1,
			Storage: StorageConfig{Metadata: &VolumeConfig{
				Size: &oneGi,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
					testDiskNameLabelKey: testOldValue,
				}},
			}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	validator := &GarageClusterValidator{}
	changed := old.DeepCopy()
	changed.Spec.Storage.Metadata.Size = &twoGi
	if _, err := validator.ValidateUpdate(context.Background(), old, changed); err == nil || !strings.Contains(err.Error(), "scale spec.replicas to 0") {
		t.Fatalf("live v1beta1 edge metadata change was accepted: %v", err)
	}

	combined := changed.DeepCopy()
	combined.Spec.Replicas = 0
	if _, err := validator.ValidateUpdate(context.Background(), old, combined); err == nil || !strings.Contains(err.Error(), "scale spec.replicas to 0") {
		t.Fatalf("combined N->0 plus metadata change was accepted: %v", err)
	}

	zeroOld := old.DeepCopy()
	zeroOld.Spec.Replicas = 0
	zeroChanged := changed.DeepCopy()
	zeroChanged.Spec.Replicas = 0
	if _, err := validator.ValidateUpdate(context.Background(), zeroOld, zeroChanged); err != nil {
		t.Fatalf("separate zero-replica metadata edit was rejected: %v", err)
	}

	activateChanged := zeroChanged.DeepCopy()
	activateChanged.Spec.Replicas = 1
	activateChanged.Spec.Storage.Metadata.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
		testDiskNameLabelKey: testNewValue,
	}}
	if _, err := validator.ValidateUpdate(context.Background(), zeroOld, activateChanged); err == nil || !strings.Contains(err.Error(), "scale spec.replicas to 0") {
		t.Fatalf("combined 0->N plus metadata change was accepted: %v", err)
	}
}

func TestGarageClusterV1Beta1EdgeGatewayGrandfathersOnlyUnchangedMetadataClaimTemplate(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-template", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Gateway:  true,
			Replicas: 1,
			Storage: StorageConfig{Metadata: &VolumeConfig{
				Size: &oneGi,
				VolumeClaimTemplateSpec: &corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				},
			}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: testStorageClusterName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	validator := &GarageClusterValidator{}
	unchanged := old.DeepCopy()
	unchanged.Spec.ImagePullPolicy = corev1.PullAlways
	warnings, err := validator.ValidateUpdate(context.Background(), old, unchanged)
	if err != nil || !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
		t.Fatalf("unchanged legacy gateway claim template was not grandfathered: warnings=%v err=%v", warnings, err)
	}
	removed := old.DeepCopy()
	removed.Spec.Storage.Metadata.VolumeClaimTemplateSpec = nil
	if _, err := validator.ValidateUpdate(context.Background(), old, removed); err != nil {
		t.Fatalf("legacy gateway claim-template removal rejected: %v", err)
	}
	mutated := old.DeepCopy()
	mutated.Spec.Storage.Metadata.VolumeClaimTemplateSpec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
	if _, err := validator.ValidateUpdate(context.Background(), old, mutated); err == nil || !strings.Contains(err.Error(), "identity isolation") {
		t.Fatalf("legacy gateway claim-template mutation accepted: %v", err)
	}
}

func TestValidateAllBuckets(t *testing.T) {
	tests := []struct {
		name       string
		allBuckets *AllBucketsPermission
		wantErr    bool
	}{
		{"nil is valid", nil, false},
		{"read only", &AllBucketsPermission{Read: true}, false},
		{"write only", &AllBucketsPermission{Write: true}, false},
		{"owner only", &AllBucketsPermission{Owner: true}, false},
		{"all permissions", &AllBucketsPermission{Read: true, Write: true, Owner: true}, false},
		{"no permissions", &AllBucketsPermission{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllBuckets(tt.allBuckets)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAllBuckets() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageKeyValidator_AllBucketsDefaultedEmptyAllowsScopedMigration(t *testing.T) {
	old := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true, Write: true},
		},
	}
	newObj := old.DeepCopy()
	newObj.Spec.AllBuckets = &AllBucketsPermission{}
	newObj.Spec.BucketPermissions = []BucketPermission{{
		BucketID: "scoped-bucket",
		Read:     true,
	}}

	validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	if _, err := validator.ValidateUpdate(context.Background(), old, newObj); err != nil {
		t.Fatalf("defaulted allBuckets object blocked scoped migration: %v", err)
	}
}

func TestGarageKeyValidator_NoBucketPermissionsWarning(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}

	// allBuckets set — no warning expected
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
		},
	}
	warnings, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings when allBuckets is set, got: %v", warnings)
	}

	// no permissions at all — warning expected
	key2 := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey + "2", Namespace: testWebhookNS},
		Spec:       GarageKeySpec{ClusterRef: ClusterReference{Name: testCluster}},
	}
	warnings2, err := v.validateGarageKey(context.Background(), key2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warnings2) == 0 {
		t.Error("expected warning when no bucket permissions defined")
	}
}

func TestGarageKeyValidator_AllBucketsAndBucketPermissionsBothSet_Warning(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
	v := &GarageKeyValidator{Client: c}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			AllBuckets: &AllBucketsPermission{Read: true},
			BucketPermissions: []BucketPermission{
				{BucketRef: &BucketRef{Name: testBucket}, Write: true},
			},
		},
	}
	warnings, err := v.validateGarageKey(context.Background(), key)
	if err != nil {
		t.Errorf("both set is not an error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected a warning when both allBuckets and bucketPermissions are set")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "allBuckets") && strings.Contains(w, "bucketPermissions") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning mentioning allBuckets and bucketPermissions, got: %v", warnings)
	}
}

func TestValidateKeyPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []KeyPermission
		wantErr     bool
	}{
		{"nil", nil, false},
		{"empty", []KeyPermission{}, false},
		{"valid read", []KeyPermission{{KeyRef: testKeyRef, Read: true}}, false},
		{"valid write", []KeyPermission{{KeyRef: testKeyRef, Write: true}}, false},
		{"valid owner", []KeyPermission{{KeyRef: testKeyRef, Owner: true}}, false},
		{"missing keyRef", []KeyPermission{{Read: true}}, true},
		{"no permissions granted", []KeyPermission{{KeyRef: testKeyRef}}, true},
		{"duplicate keyRef", []KeyPermission{{KeyRef: KeyRef{Name: "k"}, Read: true}, {KeyRef: KeyRef{Name: "k"}, Write: true}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyPermissions(testWebhookNS, tt.permissions, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeyPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGarageKey_ExpiresAt_Valid(t *testing.T) {
	d := &GarageKeyDefaulter{}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			ExpiresAt:  &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
		},
	}
	if err := d.Default(context.Background(), key); err != nil {
		t.Fatalf("Default: %v", err)
	}
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	_, err := v.ValidateCreate(context.Background(), key)
	if err != nil {
		t.Errorf("valid expiresAt should pass, got: %v", err)
	}
}

func TestGarageKeyDefaulter_DefaultsCredentialsFileFields(t *testing.T) {
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef:     ClusterReference{Name: testCluster},
			SecretTemplate: &SecretTemplate{IncludeCredentialsFile: ptrBool(true)},
		},
	}
	if err := (&GarageKeyDefaulter{}).Default(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if got := key.Spec.SecretTemplate.CredentialsFileKey; got != "credentials" {
		t.Fatalf("credentialsFileKey = %q, want credentials", got)
	}
	if got := key.Spec.SecretTemplate.CredentialsFileProfile; got != "default" {
		t.Fatalf("credentialsFileProfile = %q, want default", got)
	}
}

func TestGarageBucketValidator_RejectsInvalidAndDuplicateAliases(t *testing.T) {
	v := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	for name, bucket := range map[string]*GarageBucket{
		"uppercase global": {
			ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
			Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}, GlobalAlias: "Bad-Alias"},
		},
		"ip global": {
			ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
			Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}, GlobalAlias: "127.0.0.1"},
		},
		"duplicate local": {
			ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
			Spec: GarageBucketSpec{ClusterRef: ClusterReference{Name: testCluster}, GlobalAlias: testValidBucketAlias, LocalAliases: []LocalAlias{
				{KeyRef: testKey, Alias: "local-alias"}, {KeyRef: testKey, Alias: "local-alias"},
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.ValidateCreate(context.Background(), bucket); err == nil {
				t.Fatalf("invalid aliases accepted: %+v", bucket.Spec)
			}
		})
	}
}

func TestGarageBucketValidator_CrossNamespaceKeyRefRequiresGrant(t *testing.T) {
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS},
		Spec: GarageBucketSpec{
			ClusterRef:  ClusterReference{Name: testCluster},
			GlobalAlias: testValidBucketAlias,
			KeyPermissions: []KeyPermission{{
				KeyRef: KeyRef{Name: testKey, Namespace: testTargetNS}, Read: true,
			}},
		},
	}
	withoutGrant := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	if _, err := withoutGrant.ValidateCreate(context.Background(), bucket); err == nil {
		t.Fatal("cross-namespace GarageKey reference accepted without GarageReferenceGrant")
	}
	keyGrant := grant("GarageBucket", testSourceNS, "GarageKey", testKey)
	withGrant := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(keyGrant).Build()}
	if _, err := withGrant.ValidateCreate(context.Background(), bucket); err != nil {
		t.Fatalf("valid cross-namespace GarageKey grant rejected: %v", err)
	}
}

func TestGarageBucketAndKeyValidator_ClusterRefIsImmutable(t *testing.T) {
	bucketValidator := &GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	oldBucket := &GarageBucket{ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS}, Spec: GarageBucketSpec{
		ClusterRef: ClusterReference{Name: "cluster-a"}, GlobalAlias: testValidBucketAlias,
	}}
	newBucket := oldBucket.DeepCopy()
	newBucket.Spec.ClusterRef.Name = "cluster-b"
	if _, err := bucketValidator.ValidateUpdate(context.Background(), oldBucket, newBucket); err == nil {
		t.Fatal("GarageBucket clusterRef mutation accepted")
	}

	keyValidator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	oldKey := &GarageKey{ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS}, Spec: GarageKeySpec{
		ClusterRef: ClusterReference{Name: "cluster-a"}, AllBuckets: &AllBucketsPermission{Read: true},
	}}
	newKey := oldKey.DeepCopy()
	newKey.Spec.ClusterRef.Name = "cluster-b"
	if _, err := keyValidator.ValidateUpdate(context.Background(), oldKey, newKey); err == nil {
		t.Fatal("GarageKey clusterRef mutation accepted")
	}
}

func TestGarageKeyValidator_RejectsUnsafeImportAndSecretTemplates(t *testing.T) {
	foreignNS := testTargetNS
	for name, spec := range map[string]GarageKeySpec{
		"empty import": {
			ClusterRef: ClusterReference{Name: testCluster}, ImportKey: &ImportKeyConfig{},
		},
		"cross namespace import secret": {
			ClusterRef: ClusterReference{Name: testCluster}, ImportKey: &ImportKeyConfig{SecretRef: &corev1.SecretReference{Name: "credentials", Namespace: foreignNS}},
		},
		"missing import secret name": {
			ClusterRef: ClusterReference{Name: testCluster}, ImportKey: &ImportKeyConfig{SecretRef: &corev1.SecretReference{}},
		},
		"generated key collision": {
			ClusterRef: ClusterReference{Name: testCluster}, SecretTemplate: &SecretTemplate{AccessKeyIDKey: "same", SecretAccessKeyKey: "same"},
		},
		"additional data collision": {
			ClusterRef: ClusterReference{Name: testCluster}, SecretTemplate: &SecretTemplate{AdditionalData: map[string]string{"access-key-id": "overwrite"}},
		},
		"invalid data key": {
			ClusterRef: ClusterReference{Name: testCluster}, SecretTemplate: &SecretTemplate{AccessKeyIDKey: "bad key"},
		},
		"credentials file collision": {
			ClusterRef: ClusterReference{Name: testCluster}, SecretTemplate: &SecretTemplate{
				IncludeCredentialsFile: ptrBool(true), CredentialsFileKey: "access-key-id",
			},
		},
		"invalid credentials file profile": {
			ClusterRef: ClusterReference{Name: testCluster}, SecretTemplate: &SecretTemplate{
				IncludeCredentialsFile: ptrBool(true), CredentialsFileProfile: "default]\n[other",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
			key := &GarageKey{ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS}, Spec: spec}
			if _, err := v.ValidateCreate(context.Background(), key); err == nil {
				t.Fatalf("unsafe key spec accepted: %+v", spec)
			}
		})
	}
}

func TestGarageKeyValidator_ImportKeyIsImmutable(t *testing.T) {
	validator := &GarageKeyValidator{}
	importKey := &ImportKeyConfig{AccessKeyID: "GKoriginal", SecretAccessKey: "original-secret"}
	for name, pair := range map[string][2]*ImportKeyConfig{
		"credential mutation": {importKey, &ImportKeyConfig{AccessKeyID: "GKoriginal", SecretAccessKey: "replacement-secret"}},
		"removal":             {importKey, nil},
		"addition":            {nil, importKey},
	} {
		t.Run(name, func(t *testing.T) {
			oldKey := &GarageKey{Spec: GarageKeySpec{ClusterRef: ClusterReference{Name: testCluster}, ImportKey: pair[0]}}
			newKey := oldKey.DeepCopy()
			newKey.Spec.ImportKey = pair[1]
			if _, err := validator.ValidateUpdate(context.Background(), oldKey, newKey); err == nil || !strings.Contains(err.Error(), "importKey is immutable") {
				t.Fatalf("importKey mutation accepted: %v", err)
			}
		})
	}
}

func TestBucketAndKeyValidators_RejectUnsupportedKubeConfigReference(t *testing.T) {
	selector := &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "remote-kubeconfig"}}
	bucket := &GarageBucket{ObjectMeta: metav1.ObjectMeta{Name: testBucket, Namespace: testSourceNS}, Spec: GarageBucketSpec{
		ClusterRef: ClusterReference{Name: testCluster, KubeConfigSecretRef: selector}, GlobalAlias: testValidBucketAlias,
	}}
	if _, err := (&GarageBucketValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}).ValidateCreate(context.Background(), bucket); err == nil {
		t.Fatal("GarageBucket accepted unsupported kubeConfigSecretRef")
	}
	key := &GarageKey{ObjectMeta: metav1.ObjectMeta{Name: testKey, Namespace: testSourceNS}, Spec: GarageKeySpec{
		ClusterRef: ClusterReference{Name: testCluster, KubeConfigSecretRef: selector}, AllBuckets: &AllBucketsPermission{Read: true},
	}}
	if _, err := (&GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}).ValidateCreate(context.Background(), key); err == nil {
		t.Fatal("GarageKey accepted unsupported kubeConfigSecretRef")
	}
}

func TestGarageKey_ExpiresAt_MutuallyExclusiveWithNeverExpires(t *testing.T) {
	v := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	key := &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: testWebhookNS},
		Spec: GarageKeySpec{
			ClusterRef:   ClusterReference{Name: testCluster},
			ExpiresAt:    &metav1.Time{Time: time.Now().Add(24 * time.Hour)},
			NeverExpires: true,
		},
	}
	_, err := v.ValidateCreate(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", err)
	}
}

func TestValidateReferenceGrant(t *testing.T) {
	tests := []struct {
		name     string
		grant    *GarageReferenceGrant
		wantErr  bool
		wantWarn bool
	}{
		{
			name: "valid cross-namespace grant",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty from is invalid",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec:       GarageReferenceGrantSpec{},
			},
			wantErr: true,
		},
		{
			name: "same-namespace from produces warning",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey, Namespace: testSourceNS}},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
		{
			name: "missing from namespace is invalid",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testTargetNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{{Kind: kindGarageKey}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty namespace after same-namespace entry is still caught",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{
						{Kind: kindGarageKey, Namespace: testSourceNS},
						{Kind: kindGarageKey},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "multiple same-namespace entries all produce warnings",
			grant: &GarageReferenceGrant{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSourceNS},
				Spec: GarageReferenceGrantSpec{
					From: []ReferenceGrantFrom{
						{Kind: kindGarageKey, Namespace: testSourceNS},
						{Kind: "GarageBucket", Namespace: testSourceNS},
					},
				},
			},
			wantErr:  false,
			wantWarn: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := validateReferenceGrant(tt.grant)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateReferenceGrant() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantWarn && len(warnings) == 0 {
				t.Error("expected a warning but got none")
			}
		})
	}
}

func TestGarageCluster_RPCTimeout_DurationField(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Network: NetworkConfig{
				RPCPingTimeout: &metav1.Duration{Duration: 10 * time.Second},
				RPCTimeout:     &metav1.Duration{Duration: 30 * time.Second},
			},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Network.RPCPingTimeout.Duration != 10*time.Second {
		t.Errorf("expected 10s ping timeout, got %v", cluster.Spec.Network.RPCPingTimeout)
	}
	if cluster.Spec.Network.RPCTimeout.Duration != 30*time.Second {
		t.Errorf("expected 30s rpc timeout, got %v", cluster.Spec.Network.RPCTimeout)
	}
}

func TestGarageClusterDefaulter_PreservesOmittedDeletionPolicy(t *testing.T) {
	cluster := &GarageCluster{}
	if err := (&GarageClusterDefaulter{}).Default(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if cluster.Spec.DeletionPolicy != "" {
		t.Fatalf("deletionPolicy = %q, want omission preserved", cluster.Spec.DeletionPolicy)
	}
	explicit := &GarageCluster{Spec: GarageClusterSpec{DeletionPolicy: DeletionPolicyDrain}}
	if err := (&GarageClusterDefaulter{}).Default(context.Background(), explicit); err != nil {
		t.Fatal(err)
	}
	if explicit.Spec.DeletionPolicy != DeletionPolicyDrain {
		t.Fatalf("explicit Drain defaulted to %q", explicit.Spec.DeletionPolicy)
	}
}

func TestGarageClusterDeepCopyDoesNotAliasStorageRollout(t *testing.T) {
	original := &GarageCluster{Status: GarageClusterStatus{StorageRollout: &StorageRolloutStatus{
		GarageNodeName: "node-a", GarageNodeUID: testNodeUID, WorkloadUID: "sts-uid",
		PreviousPodUID: "old", DesiredPodSpecHash: "hash",
	}}}
	copy := original.DeepCopy()
	copy.Status.StorageRollout.GarageNodeName = "node-b"
	if original.Status.StorageRollout.GarageNodeName != "node-a" {
		t.Fatal("DeepCopy aliased status.storageRollout")
	}
}

func TestActiveStorageRolloutAllowsOnlyExactLostSourceEscalation(t *testing.T) {
	const nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	oldNode := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: testStorageNodeName, Namespace: testGarageNamespace, UID: testNodeUID,
			Annotations: map[string]string{"example.com/retained": stringTrue},
		},
		Spec:   GarageNodeSpec{ClusterRef: ClusterReference{Name: testGarageNamespace}},
		Status: GarageNodeStatus{NodeID: nodeID},
	}
	cluster := &v1beta2.GarageCluster{Status: v1beta2.GarageClusterStatus{
		StorageRollout: &v1beta2.StorageRolloutStatus{
			GarageNodeName: oldNode.Name, GarageNodeUID: string(oldNode.UID), GarageNodeID: nodeID,
		},
	}}
	requested := oldNode.DeepCopy()
	requested.Annotations[AnnotationDrain] = stringTrue
	requested.Annotations[AnnotationAcknowledgeLostSource] = nodeID
	if !validActiveStorageRolloutLostSourceEscalation(oldNode, requested, cluster, false, true) {
		t.Fatal("exact monotonic rollout lost-source escalation was rejected")
	}

	wrongID := requested.DeepCopy()
	wrongID.Annotations[AnnotationAcknowledgeLostSource] = strings.Repeat("f", 64)
	if validActiveStorageRolloutLostSourceEscalation(oldNode, wrongID, cluster, false, true) {
		t.Fatal("wrong Garage ID was accepted for active rollout recovery")
	}
	unrelatedMutation := requested.DeepCopy()
	unrelatedMutation.Annotations["example.com/retained"] = "changed"
	if validActiveStorageRolloutLostSourceEscalation(oldNode, unrelatedMutation, cluster, false, true) {
		t.Fatal("unrelated annotation mutation was accepted with lost-source escalation")
	}
	if validActiveStorageRolloutLostSourceEscalation(oldNode, requested, cluster, true, true) {
		t.Fatal("spec mutation was accepted with lost-source escalation")
	}
}

func TestGarageCluster_ZoneRedundancy_AtLeast_RequiresMinZones(t *testing.T) {
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{Factor: 3, ZoneRedundancyMode: zoneRedundancyAtLeast},
			// ZoneRedundancyMinZones intentionally absent
		},
	}
	err := cluster.validateZoneRedundancy()
	if err == nil || !strings.Contains(err.Error(), "zoneRedundancyMinZones") {
		t.Errorf("expected zoneRedundancyMinZones required error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_AtLeast_CannotExceedFactor(t *testing.T) {
	minZones := 5
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{
				Factor:                 3,
				ZoneRedundancyMode:     zoneRedundancyAtLeast,
				ZoneRedundancyMinZones: &minZones,
			},
		},
	}
	err := cluster.validateZoneRedundancy()
	if err == nil || !strings.Contains(err.Error(), "cannot exceed") {
		t.Errorf("expected exceed-factor error, got: %v", err)
	}
}

func TestGarageCluster_ZoneRedundancy_Maximum_Valid(t *testing.T) {
	cluster := &GarageCluster{
		Spec: GarageClusterSpec{
			Replication: &ReplicationConfig{
				Factor:             3,
				ZoneRedundancyMode: "Maximum",
			},
		},
	}
	if err := cluster.validateZoneRedundancy(); err != nil {
		t.Errorf("Maximum should be valid, got: %v", err)
	}
}

func TestGarageCluster_Replication_OmittedDefaultsToFactor3(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3}, // no Replication field
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.Replication == nil {
		t.Fatal("expected Replication to be defaulted, got nil")
	}
	if cluster.Spec.Replication.Factor != 3 {
		t.Errorf("expected factor 3, got %d", cluster.Spec.Replication.Factor)
	}
	if cluster.Spec.Replication.ConsistencyMode != consistencyModeConsistent {
		t.Errorf("expected consistencyMode consistent, got %q", cluster.Spec.Replication.ConsistencyMode)
	}
}

func TestGarageClusterValidator_FactorChangeRequiresAtomicPurgeRequest(t *testing.T) {
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "factor", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 2,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Type: VolumeTypeEmptyDir},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	validator := &GarageClusterValidator{}
	withoutRequest := old.DeepCopy()
	withoutRequest.Spec.Replication.Factor = 2
	if _, err := validator.ValidateUpdate(context.Background(), old, withoutRequest); err == nil || !strings.Contains(err.Error(), "same API update") {
		t.Fatalf("factor-only update error = %v, want atomic-request rejection", err)
	}

	atomic := withoutRequest.DeepCopy()
	atomic.Annotations = map[string]string{AnnotationPurgeClusterLayout: "factor=2"}
	if _, err := validator.ValidateUpdate(context.Background(), old, atomic); err != nil {
		t.Fatalf("matching atomic factor migration request rejected: %v", err)
	}
}

func TestGarageCluster_WebAPI_EnabledFalse_DisablesWebAPI(t *testing.T) {
	d := &GarageClusterDefaulter{}
	disabled := false
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			WebAPI:   &WebAPIConfig{Enabled: &disabled},
		},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.WebAPI.Enabled == nil || *cluster.Spec.WebAPI.Enabled != false {
		t.Error("expected WebAPI.Enabled to remain false")
	}
}

func TestGarageCluster_WebAPI_NilEnabled_DefaultsToTrue(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec:       GarageClusterSpec{Replicas: 3},
	}
	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if cluster.Spec.WebAPI == nil {
		t.Fatal("expected WebAPI to be defaulted")
	}
	if cluster.Spec.WebAPI.Enabled == nil || !*cluster.Spec.WebAPI.Enabled {
		t.Error("expected WebAPI.Enabled to default to true")
	}
}

func TestBucketRef_UnmarshalJSON_StringForm(t *testing.T) {
	// v1alpha1 stored bucketRef as a plain string. The informer crashes on LIST
	// if the Go type can't handle it, so we accept the string and map it to Name.
	var ref BucketRef
	if err := json.Unmarshal([]byte(`"`+testBucket+`"`), &ref); err != nil {
		t.Fatalf("unexpected error unmarshaling string bucketRef: %v", err)
	}
	if ref.Name != testBucket {
		t.Errorf("expected Name=my-bucket, got %q", ref.Name)
	}
	if ref.Namespace != "" {
		t.Errorf("expected empty Namespace, got %q", ref.Namespace)
	}
}

func TestBucketRef_UnmarshalJSON_ObjectForm(t *testing.T) {
	var ref BucketRef
	if err := json.Unmarshal([]byte(`{"name":"`+testBucket+`","namespace":"ns"}`), &ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Name != testBucket || ref.Namespace != "ns" {
		t.Errorf("unexpected value: %+v", ref)
	}
}

func TestBucketRef_UnmarshalJSON_InGarageKeyList(t *testing.T) {
	// Simulate what the informer sees when a legacy resource is in etcd.
	raw := `{
		"apiVersion": "garage.rajsingh.info/v1beta1",
		"kind": "GarageKey",
		"metadata": {"name": "test", "namespace": "default"},
		"spec": {
			"clusterRef": {"name": "garage"},
			"bucketPermissions": [{"bucketRef": "` + testBucket + `", "read": true}]
		}
	}`
	var key GarageKey
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		t.Fatalf("expected no error for legacy string bucketRef, got: %v", err)
	}
	if len(key.Spec.BucketPermissions) != 1 {
		t.Fatal("expected 1 bucket permission")
	}
	ref := key.Spec.BucketPermissions[0].BucketRef
	if ref == nil || ref.Name != testBucket {
		t.Errorf("expected BucketRef.Name=%s, got %+v", testBucket, ref)
	}
}

func TestGarageCluster_ValidateLayoutManagement(t *testing.T) {
	tests := []struct {
		name     string
		replicas int32
		lm       *LayoutManagementConfig
		wantErr  bool
		errMsg   string
	}{
		{"nil layoutManagement is valid", 3, nil, false, ""},
		{"minNodesHealthy=0 is valid", 3, &LayoutManagementConfig{MinNodesHealthy: 0}, false, ""},
		{"minNodesHealthy equals replicas is valid", 3, &LayoutManagementConfig{MinNodesHealthy: 3}, false, ""},
		{"minNodesHealthy less than replicas is valid", 5, &LayoutManagementConfig{MinNodesHealthy: 3}, false, ""},
		{"minNodesHealthy exceeds replicas is rejected", 3, &LayoutManagementConfig{MinNodesHealthy: 4}, true, "cannot exceed replicas"},
		{"minNodesHealthy=1 with explicit replicas=0 is rejected", 0, &LayoutManagementConfig{MinNodesHealthy: 1}, true, "cannot exceed replicas"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := &GarageCluster{
				Spec: GarageClusterSpec{
					Replicas:         tt.replicas,
					LayoutManagement: tt.lm,
				},
			}
			err := cluster.validateLayoutManagement()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLayoutManagement() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateLayoutManagement() error = %v, want containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestGarageCluster_Storage_PathsOnMetadataRejected(t *testing.T) {
	v := &GarageClusterValidator{}
	size := resource.MustParse("10Gi")
	dataSize := resource.MustParse("100Gi")
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 3,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{
					Size:  &size,
					Paths: []DataPath{{Path: "/meta1"}},
				},
				Data: &VolumeConfig{Size: &dataSize},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "paths is only valid for data volumes") {
		t.Errorf("expected paths-on-metadata error, got: %v", err)
	}
}

func TestGarageClusterValidator_RejectsManualToAutoTransition_v1beta1(t *testing.T) {
	v := &GarageClusterValidator{}
	size := resource.MustParse("10Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tx", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas:     1,
			LayoutPolicy: layoutPolicyManual,
			Storage: StorageConfig{
				Data: &VolumeConfig{Size: &size},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	newer := old.DeepCopy()
	newer.Spec.LayoutPolicy = layoutPolicyAuto

	if _, err := v.ValidateUpdate(context.Background(), old, newer); err == nil {
		t.Fatalf("ValidateUpdate accepted Manual→Auto transition on v1beta1, want error")
	}

	// Manual→Manual is fine.
	sameManual := old.DeepCopy()
	if _, err := v.ValidateUpdate(context.Background(), old, sameManual); err != nil {
		t.Fatalf("ValidateUpdate rejected Manual→Manual on v1beta1: %v", err)
	}

	manualCleanup := old.DeepCopy()
	manualCleanup.Spec.Replicas = 0
	manualCleanup.Spec.Storage.Data = nil
	if v1beta1PositiveStorageRemoval(old, manualCleanup) {
		t.Fatal("ignored Manual replicas were classified as positive-capacity removal on v1beta1")
	}
	if _, err := v.ValidateUpdate(context.Background(), old, manualCleanup); err != nil {
		t.Fatalf("cleaning ignored Manual default-pool fields was rejected on v1beta1: %v", err)
	}

	// Auto→Manual is fine.
	autoStart := old.DeepCopy()
	autoStart.Generation = 1
	autoStart.Spec.LayoutPolicy = layoutPolicyAuto
	autoStart.Status.Conditions = []metav1.Condition{{
		Type: ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
		Reason: "Converged", ObservedGeneration: autoStart.Generation,
	}}
	autoStart.Status.Health = &ClusterHealth{
		Status: healthStatusHealthy, Healthy: true, Available: true,
		StorageNodes: 1, StorageNodesOK: 1,
		Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
	}
	autoToManual := autoStart.DeepCopy()
	autoToManual.Spec.LayoutPolicy = layoutPolicyManual
	if _, err := v.ValidateUpdate(context.Background(), autoStart, autoToManual); err != nil {
		t.Fatalf("ValidateUpdate rejected Auto→Manual on v1beta1: %v", err)
	}

	autoToZeroWithConfigDrift := autoStart.DeepCopy()
	autoToZeroWithConfigDrift.Spec.Replicas = 0
	autoToZeroWithConfigDrift.Spec.Storage.MetadataFsync = !autoStart.Spec.Storage.MetadataFsync
	if !v1beta1PositiveStorageRemoval(autoStart, autoToZeroWithConfigDrift) {
		t.Fatal("managed default-pool N -> 0 was not classified as positive-capacity removal on v1beta1")
	}
	if _, err := v.ValidateUpdate(context.Background(), autoStart, autoToZeroWithConfigDrift); err == nil || !strings.Contains(err.Error(), "topology-only update") {
		t.Fatalf("managed default-pool N -> 0 bypassed the v1beta1 prepared drain boundary: %v", err)
	}
}

// A v1beta1 view of a management handle (#269) — gateway=false, no storage
// tier, connectTo set — must be accepted (it reaches this webhook via the
// conversion webhook for a v1beta2 handle, matchPolicy: Equivalent).
func TestGarageClusterV1beta1_AcceptsManagementHandle(t *testing.T) {
	// clusterRef form
	h := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testDefaultNamespace},
		Spec: GarageClusterSpec{
			ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "store"}},
		},
	}
	if _, err := h.validateGarageCluster(); err != nil {
		t.Fatalf("v1beta1 rejected clusterRef management handle: %v", err)
	}

	// adminApiEndpoint form (the Helm-adoption path)
	h.Spec.ConnectTo = &ConnectToConfig{
		AdminAPIEndpoint:    testAdminEndpoint,
		AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: testAdminSecret}, Key: garageAdminTokenDefaultKey},
	}
	if _, err := h.validateGarageCluster(); err != nil {
		t.Fatalf("v1beta1 rejected adminApiEndpoint management handle: %v", err)
	}
}

func TestGarageClusterV1beta1_ManagementHandleRPCSourceCanAttachOnce(t *testing.T) {
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testDefaultNamespace},
		Spec: GarageClusterSpec{ConnectTo: &ConnectToConfig{
			AdminAPIEndpoint:    testAdminEndpoint,
			AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: testAdminSecret}},
		}},
	}
	if got := v1beta1EffectiveRPCIdentitySource(old); got != "" {
		t.Fatalf("Admin-only handle RPC identity source = %q, want empty", got)
	}
	attached := old.DeepCopy()
	attached.Spec.ConnectTo.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "external-rpc"}, Key: "mesh",
	}
	validator := &GarageClusterValidator{}
	if _, err := validator.ValidateUpdate(context.Background(), old, attached); err != nil {
		t.Fatalf("first management-handle RPC identity source was rejected: %v", err)
	}
	if got, want := v1beta1EffectiveRPCIdentitySource(attached), "secret:"+testDefaultNamespace+"/external-rpc:mesh"; got != want {
		t.Fatalf("attached handle RPC identity source = %q, want %q", got, want)
	}
	rotated := attached.DeepCopy()
	rotated.Spec.ConnectTo.RPCSecretRef.Name = "different-rpc"
	if _, err := validator.ValidateUpdate(context.Background(), attached, rotated); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("management-handle RPC identity rotation error = %v, want immutable rejection", err)
	}
}

// connectTo without gateway AND with a storage tier is still rejected — only a
// tier-less handle earns the exception.
func TestGarageClusterV1beta1_RejectsConnectToWithStorageNoGateway(t *testing.T) {
	c := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: testDefaultNamespace},
		Spec: GarageClusterSpec{
			Replicas:  1, // a storage tier (replicas>0) => not a handle => rejected
			ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: "store"}},
		},
	}
	if _, err := c.validateGarageCluster(); err == nil {
		t.Fatal("v1beta1 accepted connectTo with a storage tier and no gateway, want error")
	}
}

// ── GarageNodeValidator: node-local-pool-backed nodes ──

const (
	testDSK8sNodeName       = "worker-1"
	testDSNodeLocalPoolName = "local"
)

func daemonSetGarageNodeTestMeta(name, clusterName string) metav1.ObjectMeta {
	controller := true
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: testSourceNS,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: GroupVersion.String(),
			Kind:       garageClusterKind,
			Name:       clusterName,
			Controller: &controller,
		}},
	}
}

func TestGarageNodeValidator_DaemonSetBacked_Valid(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			ZoneFrom:           &ZoneSource{NodeLabel: "topology.kubernetes.io/zone"},
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	if _, err := node.validateGarageNode(); err != nil {
		t.Errorf("DaemonSet-backed node with kubernetesNodeName set should be valid: %v", err)
	}
}

func TestGarageNodeValidator_NodeLocalPoolRecoveryIdentityPin(t *testing.T) {
	nodeID := strings.Repeat("a", 64)
	base := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}

	pinned := base.DeepCopy()
	pinned.Annotations = map[string]string{AnnotationNodeLocalPoolRecoveryNodeID: nodeID}
	if _, err := pinned.validateGarageNode(); err != nil {
		t.Fatalf("valid internal node-local-pool recovery pin rejected: %v", err)
	}

	invalid := base.DeepCopy()
	invalid.Annotations = map[string]string{AnnotationNodeLocalPoolRecoveryNodeID: "not-a-node-id"}
	if _, err := invalid.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "exact retained HostPath") {
		t.Fatalf("invalid recovery pin accepted: %v", err)
	}

	providedNodeID := base.DeepCopy()
	providedNodeID.Spec.NodeID = nodeID
	if _, err := providedNodeID.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "must discover") {
		t.Fatalf("node-local-pool spec.nodeId bypass was accepted: %v", err)
	}

	ordinary := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ordinary",
			Namespace:   testSourceNS,
			Annotations: map[string]string{AnnotationNodeLocalPoolRecoveryNodeID: nodeID},
		},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: testCluster},
			Zone:       testZone,
			Capacity:   mustQty("100Gi"),
			Storage:    &NodeStorageConfig{Data: &NodeVolumeConfig{Size: mustQty("100Gi")}},
		},
	}
	if _, err := ordinary.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "only valid") {
		t.Fatalf("recovery pin on ordinary GarageNode accepted: %v", err)
	}

	validator := &GarageNodeValidator{}
	if _, err := validator.ValidateUpdate(context.Background(), base, pinned); err != nil {
		t.Fatalf("one-way operator recovery pin addition rejected: %v", err)
	}
	changed := pinned.DeepCopy()
	changed.Annotations[AnnotationNodeLocalPoolRecoveryNodeID] = strings.Repeat("b", 64)
	if _, err := validator.ValidateUpdate(context.Background(), pinned, changed); err == nil ||
		!strings.Contains(err.Error(), "immutable once set") {
		t.Fatalf("recovery pin replacement accepted: %v", err)
	}
	removed := pinned.DeepCopy()
	delete(removed.Annotations, AnnotationNodeLocalPoolRecoveryNodeID)
	if _, err := validator.ValidateUpdate(context.Background(), pinned, removed); err == nil ||
		!strings.Contains(err.Error(), "immutable once set") {
		t.Fatalf("recovery pin removal accepted: %v", err)
	}
}

func TestGarageNodeTrustedNodeLocalPoolRecoveryNodeIDAcceptsHubGarageClusterOwner(t *testing.T) {
	nodeID := strings.Repeat("a", 64)
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster},
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	node.Annotations = map[string]string{AnnotationNodeLocalPoolRecoveryNodeID: nodeID}
	owner := metav1.GetControllerOf(node)
	owner.APIVersion = v1beta2.GroupVersion.String()
	owner.UID = testClusterUID
	node.OwnerReferences[0] = *owner

	got, err := node.TrustedNodeLocalPoolRecoveryNodeID()
	if err != nil || got != nodeID {
		t.Fatalf("v1beta2 GarageCluster owner did not authorize its recovery pin: got=%q err=%v", got, err)
	}

	node.OwnerReferences[0].APIVersion = "unrelated.example/v1"
	if _, err := node.TrustedNodeLocalPoolRecoveryNodeID(); err == nil || !strings.Contains(err.Error(), "not a trusted identity source") {
		t.Fatalf("unrelated controller group authorized a recovery pin: %v", err)
	}

	node.OwnerReferences[0].APIVersion = GroupVersion.Group + "/"
	if _, err := node.TrustedNodeLocalPoolRecoveryNodeID(); err == nil || !strings.Contains(err.Error(), "not a trusted identity source") {
		t.Fatalf("malformed same-group controller version authorized a recovery pin: %v", err)
	}
}

func TestGarageNodeValidator_LayoutTagOwnership(t *testing.T) {
	base := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
			Tags: []string{
				"cluster:" + testCluster + "/" + testSourceNS,
				"tier:storage",
				"node-local-pool:" + testDSNodeLocalPoolName,
				"kubernetes-node:" + testDSK8sNodeName,
				"rack:a",
			},
		},
	}
	if _, err := base.validateGarageNode(); err != nil {
		t.Fatalf("canonical generated layout tags rejected: %v", err)
	}

	for _, tag := range []string{
		"cluster:other/ns",
		"cluster-uid:forged",
		"tier:gateway",
		"rpc-address:other.example:3901",
		"node-local-pool:other",
		"kubernetes-node:worker-9",
	} {
		t.Run(tag, func(t *testing.T) {
			node := base.DeepCopy()
			node.Spec.Tags = append(node.Spec.Tags, tag)
			if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "operator-managed prefix") {
				t.Fatalf("forged GarageNode tag %q was accepted: %v", tag, err)
			}
		})
	}
}

func TestGarageNodeValidator_DaemonSetBacked_AllowsLayoutRPCAddress(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
			Network:            &NodeNetworkConfig{RPCPublicAddr: "worker-1.example.net:3901"},
		},
	}
	if _, err := node.validateGarageNode(); err != nil {
		t.Errorf("DaemonSet-backed layout RPC address should be valid: %v", err)
	}
}

func TestGarageNodeValidator_DaemonSetBackingAndKubernetesNodeAreImmutable(t *testing.T) {
	validator := &GarageNodeValidator{}
	old := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("ds-node", testGarageNamespace),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testGarageNamespace},
			Zone:               "zone-a",
			Capacity:           resource.NewQuantity(100<<30, resource.BinarySI),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}

	changedBacking := old.DeepCopy()
	changedBacking.Spec.Backing = NodeBackingStatefulSet
	if _, err := validator.ValidateUpdate(context.Background(), old, changedBacking); err == nil ||
		!strings.Contains(err.Error(), "backing is immutable") {
		t.Fatalf("expected backing immutability rejection, got: %v", err)
	}

	changedNode := old.DeepCopy()
	changedNode.Spec.KubernetesNodeName = "worker-b"
	if _, err := validator.ValidateUpdate(context.Background(), old, changedNode); err == nil ||
		!strings.Contains(err.Error(), "kubernetesNodeName is immutable") {
		t.Fatalf("expected kubernetesNodeName immutability rejection, got: %v", err)
	}

	changedPool := old.DeepCopy()
	changedPool.Spec.NodeLocalPoolName = testArchiveName
	if _, err := validator.ValidateUpdate(context.Background(), old, changedPool); err == nil ||
		!strings.Contains(err.Error(), "nodeLocalPoolName is immutable") {
		t.Fatalf("expected nodeLocalPoolName immutability rejection, got: %v", err)
	}
}

func TestGarageNodeValidator_GatewayTierIsImmutable(t *testing.T) {
	validator := &GarageNodeValidator{}
	old := &GarageNode{Spec: GarageNodeSpec{
		ClusterRef: ClusterReference{Name: testGarageNamespace},
		Zone:       "zone-a",
		Capacity:   resource.NewQuantity(100<<30, resource.BinarySI),
	}}
	changed := old.DeepCopy()
	changed.Spec.Gateway = true
	changed.Spec.Capacity = nil
	if _, err := validator.ValidateUpdate(context.Background(), old, changed); err == nil ||
		!strings.Contains(err.Error(), "gateway is immutable") {
		t.Fatalf("expected gateway-tier immutability rejection, got: %v", err)
	}
}

func TestGarageNodeValidator_DaemonSetBacked_RequiresKubernetesNodeName(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:        ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:              testZone,
			Capacity:          mustQty("100Gi"),
			Backing:           NodeBackingNodeLocalPool,
			NodeLocalPoolName: testDSNodeLocalPoolName,
		},
	}
	if _, err := node.validateGarageNode(); err == nil {
		t.Fatal("DaemonSet-backed node without kubernetesNodeName should be rejected")
	}
}

func TestGarageNodeValidator_DaemonSetBacked_RejectsStorage(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
			Storage: &NodeStorageConfig{
				Data: &NodeVolumeConfig{Size: mustQty("100Gi")},
			},
		},
	}
	if _, err := node.validateGarageNode(); err == nil {
		t.Fatal("DaemonSet-backed node with storage set should be rejected (no PVCs/StatefulSet owned in this mode)")
	}
}

func TestGarageNodeValidator_DaemonSetBacked_RejectsExternal(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
			External:           &ExternalNodeConfig{Address: "1.2.3.4", Port: 3901},
		},
	}
	if _, err := node.validateGarageNode(); err == nil {
		t.Fatal("DaemonSet-backed node with external set should be rejected")
	}
}

func TestGarageNodeValidator_DaemonSetBacked_RejectsGateway(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster, Namespace: testSourceNS},
			Zone:               testZone,
			Gateway:            true,
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	if _, err := node.validateGarageNode(); err == nil {
		t.Fatal("DaemonSet-backed node with gateway:true should be rejected (storage-tier-only workload)")
	}
}

func TestGarageNodeValidator_DaemonSetBacked_RequiresClusterOwner(t *testing.T) {
	node := &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	if _, err := node.validateGarageNode(); err == nil || !strings.Contains(err.Error(), "internal children") {
		t.Fatalf("DaemonSet-backed node without matching GarageCluster controller owner should be rejected, got: %v", err)
	}
}

func TestGarageNodeValidator_DaemonSetBacked_VerifiesLiveClusterOwner(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 to scheme: %v", err)
	}
	clusterUID := types.UID("real-cluster-uid")
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testCluster,
			Namespace: testSourceNS,
			UID:       clusterUID,
		},
		Spec: v1beta2.GarageClusterSpec{
			Storage: &v1beta2.StorageSpec{
				NodeLocalPools: []v1beta2.NodeLocalPoolSpec{{Name: testDSNodeLocalPoolName}},
			},
		},
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	validator := &GarageNodeValidator{apiReader: reader}
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	node.OwnerReferences[0].UID = clusterUID

	if _, err := validator.ValidateCreate(context.Background(), node); err != nil {
		t.Fatalf("valid internal DaemonSet child rejected: %v", err)
	}
	validUpdate := node.DeepCopy()
	validUpdate.Spec.Capacity = mustQty("200Gi")
	if _, err := validator.ValidateUpdate(context.Background(), node, validUpdate); err != nil {
		t.Fatalf("valid internal DaemonSet child update rejected: %v", err)
	}

	forged := node.DeepCopy()
	forged.OwnerReferences[0].UID = types.UID("forged")
	if _, err := validator.ValidateCreate(context.Background(), forged); err == nil ||
		!strings.Contains(err.Error(), "owner UID does not match") {
		t.Fatalf("expected forged controller UID to be rejected, got: %v", err)
	}
	if _, err := validator.ValidateUpdate(context.Background(), node, forged); err == nil ||
		!strings.Contains(err.Error(), "owner UID does not match") {
		t.Fatalf("expected forged controller UID on update to be rejected, got: %v", err)
	}

	unknownPool := node.DeepCopy()
	unknownPool.Spec.NodeLocalPoolName = testArchiveName
	if _, err := validator.ValidateCreate(context.Background(), unknownPool); err == nil ||
		!strings.Contains(err.Error(), "is not declared") {
		t.Fatalf("expected undeclared pool to be rejected, got: %v", err)
	}

	cluster.Spec.Storage.NodeLocalPools = nil
	if err := reader.Update(context.Background(), cluster); err != nil {
		t.Fatalf("retire pool in fake API: %v", err)
	}
	retiringUpdate := node.DeepCopy()
	retiringUpdate.Spec.Capacity = mustQty("300Gi")
	if _, err := validator.ValidateUpdate(context.Background(), node, retiringUpdate); err != nil {
		t.Fatalf("retired pool must still allow child drain updates: %v", err)
	}
}

func TestGarageNodeValidator_DaemonSetBacked_AllowsFinalizerUpdateAfterParentGone(t *testing.T) {
	scheme := fakeScheme(t)
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 to scheme: %v", err)
	}
	validator := &GarageNodeValidator{
		apiReader: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}
	deletionTime := metav1.Now()
	node := &GarageNode{
		ObjectMeta: daemonSetGarageNodeTestMeta("n", testCluster),
		Spec: GarageNodeSpec{
			ClusterRef:         ClusterReference{Name: testCluster},
			Zone:               testZone,
			Capacity:           mustQty("100Gi"),
			Backing:            NodeBackingNodeLocalPool,
			KubernetesNodeName: testDSK8sNodeName,
			NodeLocalPoolName:  testDSNodeLocalPoolName,
		},
	}
	node.OwnerReferences[0].UID = types.UID("deleted-parent-uid")
	node.DeletionTimestamp = &deletionTime
	node.Finalizers = []string{"garagenode.garage.rajsingh.info/finalizer"}

	finalized := node.DeepCopy()
	finalized.Finalizers = nil
	if _, err := validator.ValidateUpdate(context.Background(), node, finalized); err != nil {
		t.Fatalf("finalizer update for an already-deleting orphan must succeed: %v", err)
	}
}

// ── GarageNodeValidator: zoneFrom (#294) ──────────────────────────────────────

func TestGarageNodeValidator_ZoneFrom(t *testing.T) {
	qty := func(s string) *resource.Quantity { q := resource.MustParse(s); return &q }
	base := func(mutate func(*GarageNode)) *GarageNode {
		n := &GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: testSourceNS},
			Spec: GarageNodeSpec{
				ClusterRef: ClusterReference{Name: testCluster},
				Zone:       testZone,
				ZoneFrom:   &ZoneSource{NodeLabel: "example.com/rack"},
				Capacity:   qty("100Gi"),
				Storage:    &NodeStorageConfig{Data: &NodeVolumeConfig{Size: qty("100Gi")}},
			},
		}
		if mutate != nil {
			mutate(n)
		}
		return n
	}

	t.Run("accepted alongside the required zone fallback", func(t *testing.T) {
		warnings, err := base(nil).validateGarageNode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "zoneFrom") {
				t.Fatalf("unexpected zoneFrom warning: %v", warnings)
			}
		}
	})

	t.Run("rejects an invalid label key", func(t *testing.T) {
		_, err := base(func(n *GarageNode) { n.Spec.ZoneFrom.NodeLabel = "bad key" }).validateGarageNode()
		if err == nil || !strings.Contains(err.Error(), "not a valid label key") {
			t.Fatalf("expected an invalid-label-key error, got %v", err)
		}
	})

	// An external node has no pod, so there is no Kubernetes Node to read.
	t.Run("rejects zoneFrom on external nodes", func(t *testing.T) {
		_, err := base(func(n *GarageNode) {
			n.Spec.External = &ExternalNodeConfig{Address: "10.0.0.1", Port: 3901}
			n.Spec.Storage = nil
		}).validateGarageNode()
		if err == nil || !strings.Contains(err.Error(), "not valid on external nodes") {
			t.Fatalf("expected an external-node rejection, got %v", err)
		}
	})

	// Legal but hazardous: Garage counts gateway zones toward
	// ZoneRedundancy::Maximum while satisfying it from storage nodes only.
	t.Run("warns on gateway nodes", func(t *testing.T) {
		warnings, err := base(func(n *GarageNode) {
			n.Spec.Gateway = true
			n.Spec.Capacity = nil
			n.Spec.Storage = &NodeStorageConfig{Metadata: &NodeVolumeConfig{Size: qty("1Gi")}}
		}).validateGarageNode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "zoneRedundancyMode: Maximum") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a gateway zoneFrom warning, got %v", warnings)
		}
	})
}
